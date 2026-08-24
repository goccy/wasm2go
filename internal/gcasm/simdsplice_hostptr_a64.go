package gcasm

// Host-pointer carry for fused-loop splices, arm64.
//
// The generated loops address every memory operand as
// mBase + scalar + const, re-materializing the effective address in
// scratch for each access. Native kernels instead keep a HOST
// pointer (mBase + scalar) in a register and use immediate-offset
// loads. Measured on the q8_0 SDOT decode kernel (hand patch first,
// per the asm-first rule), the pointer-carried form is worth ~5% —
// the win is shorter address dependencies on a load-bound loop, not
// instruction count (a pure MOVD+ADD fold measured neutral).
//
// The loop splicer recomputes each carried pointer at the top of
// every unroll copy (one ADD; no bias bookkeeping across copies) and
// the load emitters keep a running immediate bias inside the copy,
// stepping the pointer when an offset walks out of the signed-9-bit
// immediate range.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// a64HostPtr is one carried host pointer: reg holds
// mBase + scalar + bias while a body copy is being emitted.
type a64HostPtr struct {
	scalar int
	reg    string
	bias   int64
	// hoisted marks a pointer whose loads are covered by ONE
	// whole-loop range check in the loop prologue (see
	// a64HoistLoopChecks): the per-load checks are then skipped.
	hoisted bool
}

// a64LoopHostPtrs picks the loop's bump-carried address scalars that
// profit from pointer carry: constant-delta bumps whose scalar
// appears as the variable part of at least two memory addresses.
// Address width is immaterial: the carried pointer is recomputed
// from the live scalar each copy, and the folded range compare
// performs the same reassociation the coalesced checks already do.
func a64LoopHostPtrs(loop *simdfuse.Loop, freeRegs []string) map[int]*a64HostPtr {
	tree := loop.Tree
	bumped := map[int]bool{}
	for _, bp := range loop.Bumps {
		if bp.DeltaScalar < 0 && bp.Delta > 0 {
			bumped[bp.Scalar] = true
		}
	}
	if len(bumped) == 0 {
		return nil
	}
	addrUses := map[int]int{}
	count := func(a simdfuse.Arg) {
		if (a.Kind == simdfuse.ArgScalar || a.Kind == simdfuse.ArgSum) && bumped[a.Index] {
			addrUses[a.Index]++
		}
	}
	for i := range tree.Nodes {
		n := &tree.Nodes[i]
		if _, isMem := fusedMemOpsA64[n.Op]; isMem && len(n.Args) > 0 {
			count(n.Args[0])
		}
		if n.Op == "scalar_i32_load16_u" && len(n.Args) == 1 {
			count(n.Args[0])
		}
	}
	// Assign registers in scalar order: map iteration order would
	// make the register choice (and thus the emitted bytes) differ
	// between otherwise identical runs.
	var sis []int
	for si, uses := range addrUses {
		if uses >= 2 {
			sis = append(sis, si)
		}
	}
	sort.Ints(sis)
	ptrs := map[int]*a64HostPtr{}
	for _, si := range sis {
		if len(freeRegs) == 0 {
			break
		}
		ptrs[si] = &a64HostPtr{scalar: si, reg: freeRegs[0]}
		freeRegs = freeRegs[1:]
	}
	if len(ptrs) == 0 {
		return nil
	}
	return ptrs
}

// a64HostPtrArg resolves an address argument against the carried
// pointers, returning the pointer and its constant displacement.
func a64HostPtrArg(hostPtrs map[int]*a64HostPtr, a simdfuse.Arg) (*a64HostPtr, int64, bool) {
	if hostPtrs == nil {
		return nil, 0, false
	}
	var c int64
	switch a.Kind {
	case simdfuse.ArgScalar:
	case simdfuse.ArgSum:
		c = int64(a.Const)
	default:
		return nil, 0, false
	}
	if c < 0 {
		return nil, 0, false
	}
	hp, ok := hostPtrs[a.Index]
	if !ok {
		return nil, 0, false
	}
	return hp, c, true
}

// a64SortedHostPtrs returns the carried pointers in scalar order for
// deterministic emission.
func a64SortedHostPtrs(hostPtrs map[int]*a64HostPtr) []*a64HostPtr {
	var out []*a64HostPtr
	for _, hp := range hostPtrs {
		out = append(out, hp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].scalar < out[j].scalar })
	return out
}

// a64HostPtrLoad emits one vector load through a carried host
// pointer: the range check folds into a single compare off the guest
// scalar and the load itself is an immediate-offset form. Returns
// false (emitting nothing) when the node does not qualify — the
// caller falls back to the effective-address path.
func a64HostPtrLoad(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string,
	dst int, addr64 bool, hostPtrs map[int]*a64HostPtr) bool {
	if len(n.Args) < 2 || n.Args[1].Kind != simdfuse.ArgConst || n.Args[1].Const < 0 {
		return false
	}
	_ = addr64
	hp, c, ok := a64HostPtrArg(hostPtrs, n.Args[0])
	if !ok {
		return false
	}
	total := c + int64(n.Args[1].Const)
	var size, checkSpan int64
	post := ""
	switch n.Op {
	case "v128_load":
		size, checkSpan = 16, total+16
	case "v128_load_nc":
		// Covered by a preceding coalesced range check (see the
		// SSA-level bounds coalescing) — no check of its own.
		size, checkSpan = 16, -1
	case "v128_load_rng":
		if len(n.Args) < 4 || n.Args[2].Kind != simdfuse.ArgConst || n.Args[2].Const < 0 ||
			n.Args[3].Kind != simdfuse.ArgConst || n.Args[3].Const < 0 {
			return false
		}
		size, checkSpan = 16, total+int64(n.Args[2].Const)+int64(n.Args[3].Const)
	case "v128_load64_zero":
		size, checkSpan = 8, total+8
	case "v128_load32_zero":
		size, checkSpan = 4, total+4
	case "v128_load32_splat":
		size, checkSpan = 4, total+4
		post = "dup"
	case "v128_load16x4_u":
		size, checkSpan = 8, total+8
		post = "ushll"
	default:
		return false
	}
	if checkSpan >= 4096 {
		return false
	}
	imm, stepped := hp.imm(b, total, size)
	if !stepped {
		return false
	}
	if checkSpan >= 0 && !hp.hoisted {
		fmt.Fprintf(b, "\tADD $%d, %s, R27\n", checkSpan, scalarReg(n.Args[0]))
		b.WriteString("\tCMP R27, R21\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	}
	switch size {
	case 16:
		fmt.Fprintf(b, "\tFMOVQ %d(%s), F%d\n", imm, hp.reg, dst)
	case 8:
		fmt.Fprintf(b, "\tFMOVD %d(%s), F%d\n", imm, hp.reg, dst)
	case 4:
		fmt.Fprintf(b, "\tFMOVS %d(%s), F%d\n", imm, hp.reg, dst)
	}
	switch post {
	case "dup":
		enc := 0x4E040400 | uint32(dst)<<5 | uint32(dst)
		fmt.Fprintf(b, "\tWORD $0x%08x // dup v%d.4s, v%d.s[0]\n", enc, dst, dst)
	case "ushll":
		enc := 0x2F10A400 | uint32(dst)<<5 | uint32(dst)
		fmt.Fprintf(b, "\tWORD $0x%08x // ushll v%d.4s, v%d.4h, #0\n", enc, dst, dst)
	}
	return true
}

// a64HoistLoopChecks replaces the per-load range checks of a
// STORE-FREE do-while fused loop with one whole-loop check per
// carried pointer, emitted in the loop prologue.
//
// Soundness: every covered load reads pointer + const, the pointer
// advances by a constant positive delta, and the loop runs a trip
// count fixed at entry — so the per-iteration extents are monotone
// increasing and the FINAL iteration's extent bounds them all. The
// hoisted check traps if and only if some per-load check would have
// (possibly earlier); with no stores in the region, no observable
// effect precedes the trap either way. The do-while forms fix the
// trip count as: counter (zero-exit; callers guarantee counter >= 1,
// the same contract the unroll fast lane already relies on) or
// max(1, counter - ExitThresh) (floor-exit, body-first). Pre-tested
// loops may run ZERO trips and are excluded. Marked pointers skip
// their per-load checks (hp.hoisted).
func a64HoistLoopChecks(b *strings.Builder, loop *simdfuse.Loop, hostPtrs map[int]*a64HostPtr,
	counterReg string, addr64 bool) bool {
	if loop.PreTest || loop.Dec != 1 || len(hostPtrs) == 0 {
		return false
	}
	tree := loop.Tree
	for _, n := range tree.Nodes {
		if simdfuse.IsStore(n.Op) {
			return false
		}
	}
	// Per carried pointer: every vector load through it must have a
	// wholly-constant span; track the maximum.
	span := map[int]int64{}
	eligible := map[int]bool{}
	for si := range hostPtrs {
		eligible[si] = true
	}
	for i := range tree.Nodes {
		n := &tree.Nodes[i]
		if _, isMem := fusedMemOpsA64[n.Op]; !isMem || len(n.Args) == 0 {
			continue
		}
		var c int64
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgScalar:
		case simdfuse.ArgSum:
			c = int64(a.Const)
		default:
			continue // computed address: not through a carried pointer
		}
		si := n.Args[0].Index
		if _, tracked := hostPtrs[si]; !tracked {
			continue
		}
		if c < 0 || len(n.Args) < 2 || n.Args[1].Kind != simdfuse.ArgConst || n.Args[1].Const < 0 {
			eligible[si] = false
			continue
		}
		total := c + int64(n.Args[1].Const)
		switch n.Op {
		case "v128_load", "v128_load_nc":
			total += 16
		case "v128_load_rng":
			if len(n.Args) < 4 || n.Args[2].Kind != simdfuse.ArgConst || n.Args[2].Const < 0 ||
				n.Args[3].Kind != simdfuse.ArgConst || n.Args[3].Const < 0 {
				eligible[si] = false
				continue
			}
			total += int64(n.Args[2].Const) + int64(n.Args[3].Const)
		case "v128_load64_zero", "v128_load16x4_u":
			total += 8
		case "v128_load32_zero", "v128_load32_splat":
			total += 4
		default:
			eligible[si] = false
			continue
		}
		if total > span[si] {
			span[si] = total
		}
	}
	delta := map[int]int64{}
	for _, bp := range loop.Bumps {
		if bp.DeltaScalar < 0 && bp.Delta > 0 {
			delta[bp.Scalar] = int64(bp.Delta)
		}
	}
	hoisted := false
	for _, hp := range a64SortedHostPtrs(hostPtrs) {
		si := hp.scalar
		d, hasD := delta[si]
		// Bounded factors keep (trips-1)*delta + span below 2^49:
		// no wrap in the 64-bit extent math.
		if !eligible[si] || span[si] == 0 || !hasD || d >= 1<<16 || span[si] >= 1<<30 {
			continue
		}
		// R27 = trips-1 (64-bit; the counter is signed at its width).
		if loop.CounterWide {
			fmt.Fprintf(b, "\tMOVD %s, R27\n", counterReg)
		} else {
			fmt.Fprintf(b, "\tMOVW %s, R27\n", counterReg)
		}
		if loop.ExitGT {
			fmt.Fprintf(b, "\tSUBS $%d, R27, R27\n", int64(loop.ExitThresh)+1)
			b.WriteString("\tCSEL GE, R27, ZR, R27\n")
		} else {
			b.WriteString("\tSUB $1, R27, R27\n")
		}
		fmt.Fprintf(b, "\tMOVD $%d, R26\n", d)
		b.WriteString("\tMUL R26, R27, R27\n")
		if addr64 {
			fmt.Fprintf(b, "\tMOVD %s, R26\n", a64FusedArgReg(1+si))
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, R26\n", a64FusedArgReg(1+si))
		}
		b.WriteString("\tADD R26, R27, R27\n")
		if span[si] < 4096 {
			fmt.Fprintf(b, "\tADD $%d, R27, R27\n", span[si])
		} else {
			fmt.Fprintf(b, "\tMOVD $%d, R26\n", span[si])
			b.WriteString("\tADD R26, R27, R27\n")
		}
		b.WriteString("\tCMP R27, R21\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
		hp.hoisted = true
		hoisted = true
	}
	return hoisted
}

// a64HostPtrImm steps the carried pointer so that total lands inside
// the unscaled-immediate window and returns the immediate to use.
// size guards the top of the window so the whole access stays
// addressable.
func (hp *a64HostPtr) imm(b *strings.Builder, total, size int64) (int64, bool) {
	d := total - hp.bias
	if d >= -256 && d+size <= 255 {
		return d, true
	}
	step := total - hp.bias
	if step <= 0 || step >= 4096 {
		return 0, false
	}
	fmt.Fprintf(b, "\tADD $%d, %s, %s\n", step, hp.reg, hp.reg)
	hp.bias = total
	return 0, true
}
