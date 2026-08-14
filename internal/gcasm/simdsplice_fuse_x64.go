package gcasm

// Fused-region splicing, amd64 — the SSE twin of
// simdsplice_fuse_a64.go. Same synthesis: table bodies verbatim
// (operands in X0..X2, result in X0; scratch reaches up to X7 in the
// wider bodies), operand builds and result moves replaced by MOVOU
// register copies, parked values in X4..X14 (X15 is the ABI zero
// register) — any park still live when a canned body is pasted is
// first relocated above that body's measured reach. Fused arguments
// ride AX,BX,CX,DI,SI,R8,R9 (fusedMaxIntRegs=7 exists exactly so the
// load scratch R10–R12 stays free); m is saved to R13 because table
// cores stage scalars through AX.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

var x64FusedArgRegs = []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}

// x64XRegRe matches vector-register operands in canned op lines; the
// fused emitter uses the highest mention to size an op's scratch reach.
var x64XRegRe = regexp.MustCompile(`\bX(\d+)\b`)

// x64FusedResultRegs is the full ABIInternal integer RESULT sequence:
// results run past the argument cap because the epilogue is the last
// thing in the splice, when every scratch register is dead.
var x64FusedResultRegs = []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}

// x64FusedIntArg names integer-argument slot pos: a register, or the
// ABIInternal stack-sequence operand. Overflow slots here are always
// 8-byte pair halves — scalars, the counter and stride deltas are
// register-resident by the codegen caps — so the sequence is uniform.
// maxOut is the transform's outgoing-area shift (stack operands sit
// above it after the frame rewrite).
func x64FusedIntArg(pos, maxOut int) string {
	if pos < len(x64FusedArgRegs) {
		return x64FusedArgRegs[pos]
	}
	return fmt.Sprintf("%d(SP)", 8*(pos-len(x64FusedArgRegs))+maxOut)
}

// x64FusedResultLoc names integer-result slot pos (sizes sz in bytes,
// natural alignment). The stack results area follows the stack
// arguments, pointer-aligned.
func x64FusedResultLocs(sizes []int, argStackBytes, maxOut int) []string {
	locs := make([]string, len(sizes))
	seq := (argStackBytes + 7) &^ 7
	intN := 0
	for i, sz := range sizes {
		if intN < len(x64FusedResultRegs) {
			locs[i] = x64FusedResultRegs[intN]
			intN++
			continue
		}
		al := sz
		seq = (seq + al - 1) &^ (al - 1)
		locs[i] = fmt.Sprintf("%d(SP)", seq+maxOut)
		seq += sz
	}
	return locs
}

var (
	x64BuildLoRe  = regexp.MustCompile(`^MOVQ ([A-Z0-9]+), X(\d+)$`)
	x64BuildHiRe  = regexp.MustCompile(`^PINSRQ \$1, ([A-Z0-9]+), X(\d+)$`)
	x64StagingRe  = regexp.MustCompile(`^MOVQ [A-Z][A-Z0-9]*, AX$`)
	x64OutHiRe    = regexp.MustCompile(`^PEXTRQ \$1, X0, BX$`)
	x64OutLoRe    = regexp.MustCompile(`^MOVQ X0, AX$`)
	x64CoreGprRe  = regexp.MustCompile(`\b(AX|BX|CX|DX|DI|SI|BP|R\d+)\b`)
	x64ConstRefRe = regexp.MustCompile(`·simdConst`)
)

func x64VecCopy(b *strings.Builder, dst, src int) {
	if dst != src {
		fmt.Fprintf(b, "\tMOVOU X%d, X%d\n", src, dst)
	}
}

// x64ClassifyPair splits an amd64 pair-table body like the arm64
// twin, arity-driven: exactly nV128 operand builds (MOVQ+PINSRQ
// pairs), an optional scalar staging move into AX (dropped — the
// fused emitter stages scalars itself), core, with the trailing
// result moves dropped.
func x64ClassifyPair(lines []string, nV128 int) (opTargets []int, core []string, err error) {
	i := 0
	for ; i < len(lines) && len(opTargets) < nV128; i++ {
		l := strings.TrimSpace(lines[i])
		m := x64BuildLoRe.FindStringSubmatch(l)
		if m == nil || x64ConstRefRe.MatchString(l) {
			return nil, nil, fmt.Errorf("fuse classify: expected %d operand builds, found %d before %q", nV128, len(opTargets), l)
		}
		xk := pfNum(m[2])
		if xk < 0 {
			return nil, nil, fmt.Errorf("fuse classify: bad register capture in %q", l)
		}
		if i+1 >= len(lines) || x64BuildHiRe.FindStringSubmatch(strings.TrimSpace(lines[i+1])) == nil {
			return nil, nil, fmt.Errorf("fuse classify: build-lo without PINSRQ: %q", l)
		}
		opTargets = append(opTargets, xk)
		i++
	}
	if i < len(lines) && x64StagingRe.MatchString(strings.TrimSpace(lines[i])) {
		i++ // the fused emitter stages the scalar into AX itself
	}
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if x64OutHiRe.MatchString(l) || x64OutLoRe.MatchString(l) {
			continue
		}
		// Live fused arguments sit in BX..R9; only AX (scalar staging)
		// may appear in a core. See the arm64 twin for why this is a
		// hard error rather than a silent clobber.
		for _, g := range x64CoreGprRe.FindAllStringSubmatch(l, -1) {
			if g[1] != "AX" {
				return nil, nil, fmt.Errorf("fuse classify: core line touches %s: %q", g[1], l)
			}
		}
		core = append(core, l)
	}
	return opTargets, core, nil
}

// x64SpliceFused synthesizes the inline amd64 body of a fused-region
// call. Results in (AX, BX).
func x64SpliceFused(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets, portable bool, maxOut int) (bool, bool, error) {
	tree, usedAVX := x64Dot8Rewrite(tree, portable)
	// Scalars (addresses the body indexes with) must be
	// register-resident here; only pair halves may ride the stack
	// sequence. A wider window keeps the helper CALL.
	if 1+tree.NumScalars > len(x64FusedArgRegs) {
		return false, false, fmt.Errorf("fused splice %s: %w: scalars past the register file", tree.Name, errFusedCapacity)
	}
	loc, needsTrap, err := x64SpliceFusedCore(b, tree, pool, offs, nil, nil, 0, false, maxOut)
	if err != nil {
		return false, false, err
	}
	for k, r := range tree.RootList() {
		src := 0
		if !loc[r].chained {
			src = loc[r].pool
		}
		fmt.Fprintf(b, "\tMOVQ X%d, %s\n", src, x64FusedResultRegs[2*k])
		fmt.Fprintf(b, "\tPEXTRQ $1, X%d, %s\n", src, x64FusedResultRegs[2*k+1])
	}
	if usedAVX {
		// The block dots dirtied ymm upper halves; clear them before
		// control returns to gc-emitted legacy-SSE code.
		b.WriteString("\tVZEROUPPER\n")
	}
	return true, needsTrap, nil
}

// x64FusedProlog emits the shared prologue: m saved to R13 and the
// leaf float arguments packed into X14 lanes.
func x64FusedProlog(b *strings.Builder, tree *simdfuse.Tree, offs *ModuleOffsets) error {
	if tree.NeedsMem && offs == nil {
		return fmt.Errorf("fused splice %s: no Module offsets", tree.Name)
	}
	b.WriteString("\tMOVQ AX, R13\n")
	if tree.NumFloats > 0 {
		b.WriteString("\tMOVOU X0, X14\n")
		for i := 1; i < tree.NumFloats; i++ {
			fmt.Fprintf(b, "\tINSERTPS $%d, X%d, X14\n", i<<4, i)
		}
	}
	return nil
}

// x64SpliceFusedCore is the parameterized node-body emitter; see the
// arm64 twin for the carried/reserve/extraIntArgs contract.
func x64SpliceFusedCore(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets,
	carried map[int]int, reserve []int, extraIntArgs int, skipProlog bool, maxOut int) ([]fusedLoc, bool, error) {
	if !skipProlog {
		if err := x64FusedProlog(b, tree, offs); err != nil {
			return nil, false, err
		}
	} else if tree.NeedsMem && offs == nil {
		return nil, false, fmt.Errorf("fused splice %s: no Module offsets", tree.Name)
	}
	uses := make([]int, len(tree.Nodes))
	for _, n := range tree.Nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	// Each root is one extra consumer (the result epilogue); see the
	// arm64 twin.
	roots := tree.RootList()
	for _, r := range roots {
		uses[r]++
	}

	scalarReg := func(a simdfuse.Arg) string {
		return x64FusedArgRegs[1+a.Index]
	}
	pairRegs := func(a simdfuse.Arg) (string, string) {
		base := 1 + tree.NumScalars + extraIntArgs + 2*a.Index
		return x64FusedIntArg(base, maxOut), x64FusedIntArg(base+1, maxOut)
	}

	loc := make([]fusedLoc, len(tree.Nodes))
	var freePool []int
	poolTop := 14
	if tree.NumFloats > 0 {
		poolTop = 13 // X14 holds the packed float lanes
	}
	reservedX := map[int]bool{}
	for _, r := range reserve {
		reservedX[r] = true
	}
	// Canned pair-table op bodies (pasted verbatim by the ClassV128
	// default arm below) use X0–X7 as inputs and scratch, so a pool
	// value parked there is silently clobbered by the next canned op
	// — visible as corrupt vectors whenever a window keeps a value
	// live across a shuffle. The arm64 twin pools V16–V30 above its
	// canned v0–v4 scratch; amd64 has no such headroom, so X4–X7 stay
	// in the pool for capacity and any value still live when a canned
	// op is pasted is relocated to X8+ first (see relocateForCanned).
	for x := poolTop; x >= 4; x-- {
		if !reservedX[x] {
			freePool = append(freePool, x)
		}
	}
	// Loop-carried accumulators are live across every canned op and
	// are never relocated; they reserve downward from the pool top, so
	// reaching the canned-scratch range means the window is over
	// budget, not silently corrupt.
	for _, r := range reserve {
		if r < 8 {
			return nil, false, fmt.Errorf("fused splice %s: %w: carried value in canned-scratch range", tree.Name, errFusedCapacity)
		}
	}
	needsTrap := false

	chains := newX64ScalarChain(b, tree, scalarReg, offs, uses)

	// memAddrReg: see the arm64 twin — hands a chain-computed address
	// terminal to the memory emitters.
	memAddrReg := func(n simdfuse.Node) (string, error) {
		if len(n.Args) == 0 || n.Args[0].Kind != simdfuse.ArgNode {
			return "", nil
		}
		return chains.takeAddrSource(n.Args[0].Index)
	}

	for i, n := range tree.Nodes {
		if n.Op == a64OpElided {
			// Absorbed into a synthetic AVX2 block dot: nothing to emit,
			// nothing referenced, nothing to free.
			loc[i] = fusedLoc{chained: true}
			continue
		}
		if n.Class() != simdfuse.ClassV128 {
			// Inline scalar-chain node (see the arm64 twin).
			if err := chains.emitNode(i, &tree.Nodes[i]); err != nil {
				return nil, false, err
			}
			loc[i] = fusedLoc{chained: true}
			continue
		}
		// Placement first; see the arm64 twin.
		for _, a := range n.Args {
			if a.Kind != simdfuse.ArgNode {
				continue
			}
			uses[a.Index]--
			if uses[a.Index] == 0 && !loc[a.Index].chained {
				freePool = append(freePool, loc[a.Index].pool)
			}
		}
		if simdfuse.IsStore(n.Op) {
			areg, aerr := memAddrReg(n)
			if aerr != nil {
				return nil, false, aerr
			}
			if err := x64FusedStore(b, n, scalarReg, pairRegs, offs, pool, tree.Addr64, dst0Src(loc, n), areg); err != nil {
				return nil, false, err
			}
			needsTrap = true
			loc[i] = fusedLoc{chained: true}
			continue
		}
		willChain := i == len(tree.Nodes)-1 || (uses[i] == 1 && a64ChainsIntoNext(tree, i))
		dst := 0
		if !willChain {
			if len(freePool) == 0 {
				return nil, false, fmt.Errorf("fused splice %s: %w: vector pool exhausted", tree.Name, errFusedCapacity)
			}
			dst = freePool[len(freePool)-1]
			freePool = freePool[:len(freePool)-1]
		}
		if n.Op == "v128_load32_lane" {
			if src := dst0Src(loc, n); src < 0 {
				lo, hi := pairRegs(n.Args[3])
				fmt.Fprintf(b, "\tMOVQ %s, X%d\n", lo, dst)
				fmt.Fprintf(b, "\tPINSRQ $1, %s, X%d\n", hi, dst)
			} else {
				x64VecCopy(b, dst, src)
			}
			if n.Args[2].Kind != simdfuse.ArgConst {
				return nil, false, fmt.Errorf("fused splice %s: non-constant lane", tree.Name)
			}
			areg, aerr := memAddrReg(n)
			if aerr != nil {
				return nil, false, aerr
			}
			if err := x64FusedLaneAddr(b, n, scalarReg, offs, tree.Addr64, areg); err != nil {
				return nil, false, err
			}
			fmt.Fprintf(b, "\tPINSRD $%d, (AX)(R12*1), X%d\n", uint32(n.Args[2].Const)&3, dst)
			needsTrap = true
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		}
		if _, isMem := fusedMemOpsA64[n.Op]; isMem {
			areg, aerr := memAddrReg(n)
			if aerr != nil {
				return nil, false, aerr
			}
			if err := x64FusedLoad(b, n, scalarReg, offs, dst, tree.Addr64, areg); err != nil {
				return nil, false, err
			}
			needsTrap = true
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == "f16x4_cvt" {
			// Four f16 values in the low 16 bits of each i32 lane -> f32
			// lanes, computed with the SSE2 bit trick (no F16C at the
			// x86-64-v2 baseline): f = as_float(mag<<13) * 0x1p+112 is
			// exact for normals and denormals; inf/NaN lanes blend in
			// sh|0x70000000 (exponent forced to 0xFF, payload<<13
			// preserved); the sign rides (h<<16)&0x80000000. Bit-exact
			// against the verified conversion table.
			var src int
			switch a := n.Args[0]; a.Kind {
			case simdfuse.ArgNode:
				if loc[a.Index].chained {
					src = 0
				} else {
					src = loc[a.Index].pool
				}
			case simdfuse.ArgPairIn:
				// A loop-carried pair lives in its reserved register
				// across iterations (the tail writes it there); the
				// incoming argument registers only hold the first
				// iteration's value. Read the reserved register so
				// later iterations see the accumulated value.
				if cr, isCarried := carried[a.Index]; isCarried {
					src = cr
				} else {
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tMOVQ %s, X1\n", lo)
					fmt.Fprintf(b, "\tPINSRQ $1, %s, X1\n", hi)
					src = 1
				}
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
			}
			if pool == nil {
				return nil, false, fmt.Errorf("fused splice %s: %s needs a const pool", tree.Name, n.Op)
			}
			c4 := func(w uint32) string {
				blob := make([]byte, 16)
				for i := 0; i < 4; i++ {
					blob[i*4] = byte(w)
					blob[i*4+1] = byte(w >> 8)
					blob[i*4+2] = byte(w >> 16)
					blob[i*4+3] = byte(w >> 24)
				}
				return pool.addBlob(blob)
			}
			fmt.Fprintf(b, "\tMOVOU X%d, X3\n", src)
			b.WriteString("\tPSLLL $16, X3\n")
			fmt.Fprintf(b, "\tPAND \u00b7%s(SB), X3\n", c4(0x80000000))
			fmt.Fprintf(b, "\tMOVOU X%d, X1\n", src)
			fmt.Fprintf(b, "\tPAND \u00b7%s(SB), X1\n", c4(0x7FFF))
			b.WriteString("\tMOVOU X1, X2\n")
			fmt.Fprintf(b, "\tPCMPGTL \u00b7%s(SB), X2\n", c4(0x7BFF))
			b.WriteString("\tPSLLL $13, X1\n")
			fmt.Fprintf(b, "\tMOVOU X1, X%d\n", dst)
			fmt.Fprintf(b, "\tMULPS \u00b7%s(SB), X%d\n", c4(0x77800000), dst)
			fmt.Fprintf(b, "\tPOR \u00b7%s(SB), X1\n", c4(0x70000000))
			b.WriteString("\tPAND X2, X1\n")
			fmt.Fprintf(b, "\tPANDN X%d, X2\n", dst)
			b.WriteString("\tPOR X1, X2\n")
			b.WriteString("\tPOR X3, X2\n")
			fmt.Fprintf(b, "\tMOVOU X2, X%d\n", dst)
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == "f32x4_splat" {
			// Broadcast a lane of the packed float register: a leaf
			// float argument's lane, or a computed scalar terminal's.
			switch {
			case len(n.Args) == 1 && n.Args[0].Kind == simdfuse.ArgFloat:
				fmt.Fprintf(b, "\tPSHUFD $%d, X14, X%d\n", n.Args[0].Index*0x55, dst)
			case len(n.Args) == 1 && n.Args[0].Kind == simdfuse.ArgNode && tree.Nodes[n.Args[0].Index].Class() == simdfuse.ClassF32:
				f, err := chains.takeSplatSource(n.Args[0].Index)
				if err != nil {
					return nil, false, err
				}
				fmt.Fprintf(b, "\tPSHUFD $0, X%d, X%d\n", f, dst)
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed f32x4_splat args", tree.Name)
			}
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == x64OpBlockDot {
			// AVX2 8-bit block dot (see x64Dot8Rewrite): sign-extend both
			// 16-byte byte sources to i16 across a ymm, VPMADDWD into 8
			// i32 lanes (0..3 = low-half dot, 4..7 = high-half), then fold
			// the high 128 onto the low with VPADDD to yield the four i32
			// sums. Y2/Y3 (X2/X3) are scratch the vector pool never
			// occupies. BOTH sources are staged before either extend runs:
			// X2 is Y2's own low half, so writing a staging register after
			// Y2 is produced would corrupt it. Every source is read before
			// dst is written, so dst may safely alias a source register.
			// The "// avx2 dot" marker triggers the dual-body dispatch
			// (see the amd64 archSpec entry): a non-AVX2 host runs the
			// portable SSE twin.
			blockDotSrc := func(a simdfuse.Arg, stage int) (string, error) {
				switch a.Kind {
				case simdfuse.ArgNode:
					if loc[a.Index].chained {
						return "X0", nil
					}
					return fmt.Sprintf("X%d", loc[a.Index].pool), nil
				case simdfuse.ArgPairIn:
					if cr, isCarried := carried[a.Index]; isCarried {
						return fmt.Sprintf("X%d", cr), nil
					}
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tMOVQ %s, X%d\n", lo, stage)
					fmt.Fprintf(b, "\tPINSRQ $1, %s, X%d\n", hi, stage)
					return fmt.Sprintf("X%d", stage), nil
				default:
					return "", fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
				}
			}
			ra, err := blockDotSrc(n.Args[0], 2)
			if err != nil {
				return nil, false, err
			}
			rb, err := blockDotSrc(n.Args[1], 3)
			if err != nil {
				return nil, false, err
			}
			fmt.Fprintf(b, "\tVPMOVSXBW %s, Y2\n", ra)
			fmt.Fprintf(b, "\tVPMOVSXBW %s, Y3\n", rb)
			b.WriteString("\tVPMADDWD Y3, Y2, Y2\n")
			b.WriteString("\tVEXTRACTI128 $1, Y2, X3\n")
			fmt.Fprintf(b, "\tVPADDD X3, X2, X%d\n", dst)
			b.WriteString("\t// avx2 dot\n")
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else {
			lines, ok := x64SimdPairSpliceTab[n.Op]
			if !ok {
				return nil, false, fmt.Errorf("fused splice %s: no pair table entry for %q", tree.Name, n.Op)
			}
			lines, ok = simdSpliceRewriteConsts(lines, pool)
			if !ok {
				return nil, false, fmt.Errorf("fused splice %s: unknown const reference in %q", tree.Name, n.Op)
			}
			vArgs := make([]simdfuse.Arg, 0, len(n.Args))
			var sArg *simdfuse.Arg
			for ai := range n.Args {
				a := n.Args[ai]
				if a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn {
					vArgs = append(vArgs, a)
				} else {
					aa := a
					sArg = &aa
				}
			}
			opTargets, core, err := x64ClassifyPair(lines, len(vArgs))
			if err != nil {
				return nil, false, fmt.Errorf("fused splice %s, op %q: %w", tree.Name, n.Op, err)
			}
			for k, a := range vArgs {
				dst := opTargets[k]
				switch a.Kind {
				case simdfuse.ArgNode:
					src := loc[a.Index]
					if src.chained {
						if dst != 0 || k != 0 {
							return nil, false, fmt.Errorf("fused splice %s: chained value consumed at operand %d", tree.Name, k)
						}
						continue
					}
					x64VecCopy(b, dst, src.pool)
				case simdfuse.ArgPairIn:
					// Loop-carried pair: copy from its reserved
					// register (the tail wrote the running value
					// there); only the first iteration's value ever
					// reaches the argument registers.
					if cr, isCarried := carried[a.Index]; isCarried {
						x64VecCopy(b, dst, cr)
					} else {
						lo, hi := pairRegs(a)
						fmt.Fprintf(b, "\tMOVQ %s, X%d\n", lo, dst)
						fmt.Fprintf(b, "\tPINSRQ $1, %s, X%d\n", hi, dst)
					}
				}
			}
			if sArg != nil {
				if sArg.Kind == simdfuse.ArgConst {
					fmt.Fprintf(b, "\tMOVQ $%d, AX\n", int64(sArg.Const))
				} else {
					fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(*sArg))
				}
			}
			// Relocate pool values that must survive this op out of
			// the canned core's reach before it is pasted; every
			// later consumer reads the updated loc. The reach differs
			// per op — a plain PADDW touches only its X0/X1 inputs
			// while the shuffle body scratches up to X5 — so scan the
			// core for the highest register it mentions and move only
			// what that range would corrupt. This runs after the
			// input copies above: registers freed by this op's own
			// consumption are dead by now and safe to hand out as
			// relocation homes.
			maxX := 1
			for _, l := range core {
				for _, m := range x64XRegRe.FindAllStringSubmatch(l, -1) {
					if x, aerr := strconv.Atoi(m[1]); aerr == nil && x > maxX {
						maxX = x
					}
				}
			}
			for j := range loc {
				// pool < 4: not parked (chained through X0, inline
				// scalar chain, or not yet emitted).
				if loc[j].chained || loc[j].pool < 4 || loc[j].pool > maxX || uses[j] <= 0 {
					continue
				}
				moved := -1
				for k := range freePool {
					if freePool[k] > maxX {
						moved = freePool[k]
						freePool = append(freePool[:k], freePool[k+1:]...)
						break
					}
				}
				if moved < 0 {
					return nil, false, fmt.Errorf("fused splice %s: %w: no register outside canned scratch", tree.Name, errFusedCapacity)
				}
				x64VecCopy(b, moved, loc[j].pool)
				freePool = append(freePool, loc[j].pool)
				loc[j].pool = moved
			}
			for _, l := range core {
				fmt.Fprintf(b, "\t%s\n", l)
			}
		}
		if !willChain {
			x64VecCopy(b, dst, 0)
		}
		loc[i] = fusedLoc{chained: willChain, pool: dst}
	}
	return loc, needsTrap, nil
}

// x64FusedLoad emits one member load, result in X0. m lives in R13;
// scratch is R12 plus AX (free once m is saved) so every integer
// argument register stays live. The bounds compare runs against the
// END address accumulated in R12 (add, compare, subtract back) to
// avoid a third scratch register; non-constant rlo/span windows fall
// back to AX between address steps.
func x64FusedLoad(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, dst int, addr64 bool, addrReg string) error {
	want := fusedMemOpsA64[n.Op]
	if len(n.Args) != want {
		return fmt.Errorf("fused load %s: %d args, want %d", n.Op, len(n.Args), want)
	}
	arg := func(i int) (reg string, c int32, isConst bool) {
		a := n.Args[i]
		if a.Kind == simdfuse.ArgConst {
			return "", a.Const, true
		}
		return scalarReg(a), 0, false
	}
	// The address materializes into R12 as u32 — or full-width with
	// carry-checked sums on a memory64 tree (whose addr/offset are
	// always opaque scalars; a wrapped u64 ea could land back inside
	// bounds, so every sum traps on carry there).
	addOffErr := error(nil)
	if addrReg != "" {
		// Chain-computed address: move the terminal into the address
		// register first (see the arm64 twin). MOVL re-zero-extends
		// the i32-wrapped chain result on wasm32.
		if addr64 {
			fmt.Fprintf(b, "\tMOVQ %s, R12\n", addrReg)
		} else {
			fmt.Fprintf(b, "\tMOVL %s, R12\n", addrReg)
		}
	} else if addr64 {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgScalar:
			fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(a))
		case simdfuse.ArgSum:
			// base+const at full width: the descriptor constant is a
			// small reassociated memarg delta added as i64 — no wrap
			// semantics needed under the 2^48 memory cap.
			fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(a))
			if a.Const != 0 {
				fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(a.Const))
			}
		default:
			return fmt.Errorf("fused addr64 load %s: folded address form", n.Op)
		}
	} else {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(b, "\tMOVQ $%d, R12\n", int64(uint32(a.Const)))
		case simdfuse.ArgSum:
			// MOVL zero-extends and ADDL wraps in 32 bits with the upper
			// half staying zero — exactly Add32.
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
			if a.Const != 0 {
				fmt.Fprintf(b, "\tADDL $%d, R12\n", a.Const)
			}
		default:
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
		}
	}
	addOff := func(i int) {
		if addr64 {
			// Add the memarg offset (small const, or a scalar) into the
			// effective address; same arithmetic as wasm32, no wrap
			// guard (see x64FusedMemCheck).
			a := n.Args[i]
			switch a.Kind {
			case simdfuse.ArgConst:
				if a.Const != 0 {
					fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(a.Const))
				}
			case simdfuse.ArgScalar:
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(a))
				b.WriteString("\tADDQ AX, R12\n")
			default:
				addOffErr = fmt.Errorf("fused addr64 load %s: bad offset form", n.Op)
			}
			return
		}
		reg, c, isConst := arg(i)
		if isConst {
			if c != 0 {
				fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(uint32(c)))
			}
			return
		}
		fmt.Fprintf(b, "\tMOVL %s, AX\n", reg)
		b.WriteString("\tADDQ AX, R12\n")
	}
	loadMemSize := func() {
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
		b.WriteString("\tMOVQ (AX), AX\n")
	}
	checked := func(size int) {
		fmt.Fprintf(b, "\tADDQ $%d, R12\n", size)
		loadMemSize()
		b.WriteString("\tCMPQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tSUBQ $%d, R12\n", size)
	}
	switch n.Op {
	case "v128_load":
		addOff(1)
		checked(16)
	case "v128_load32_zero":
		addOff(1)
		checked(4)
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
		fmt.Fprintf(b, "\tMOVSS (AX)(R12*1), X%d\n", dst)
		return addOffErr
	case "v128_load32_splat":
		addOff(1)
		checked(4)
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
		fmt.Fprintf(b, "\tMOVSS (AX)(R12*1), X%d\n", dst)
		fmt.Fprintf(b, "\tPSHUFD $0x00, X%d, X%d\n", dst, dst)
		return addOffErr
	case "v128_load16x4_u":
		addOff(1)
		checked(8)
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
		fmt.Fprintf(b, "\tMOVQ (AX)(R12*1), X%d\n", dst)
		fmt.Fprintf(b, "\tPMOVZXWD X%d, X%d\n", dst, dst)
		return addOffErr
	case "v128_load_nc":
		addOff(1)
	case "v128_load_rng":
		// start/end accumulate in R12 and are undone afterwards, so
		// the address survives without a third register. The window is
		// constant by the walker's contract (checked before emitting
		// anything).
		_, rloC, rloConst := arg(2)
		_, spanC, spanConst := arg(3)
		if !rloConst || !spanConst {
			return fmt.Errorf("fused load %s: non-constant rng window (walker contract violated)", n.Op)
		}
		// A non-negative rlo cannot make start negative (the base is
		// ≥ 0 either as a u32 or under the 2^48 memory64 cap), so the
		// sign trap is emitted only for a negative rlo.
		undo := int64(uint32(spanC))
		if rloC != 0 {
			fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(rloC))
			undo += int64(rloC)
		}
		if rloC < 0 {
			fmt.Fprintf(b, "\tJS %s\n", x64SimdMemTrapLabel)
		}
		fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(uint32(spanC)))
		loadMemSize()
		b.WriteString("\tCMPQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tSUBQ $%d, R12\n", undo)
		addOff(1)
	}
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
	b.WriteString("\tADDQ AX, R12\n")
	fmt.Fprintf(b, "\tMOVOU (R12), X%d\n", dst)
	return addOffErr
}

// x64FusedLaneAddr materializes a lane load's checked address:
// R12 = u32 effective address bounds-checked against a 4-byte window,
// AX = the memory base, ready for an indexed lane insert.
// x64FusedEA64 materializes a memory64 member's checked effective
// address into R12 (base pointer + memarg offset, then the ea+size
// range check against memSize) and leaves the M base in AX. The
// arithmetic and range check are identical to the wasm32 fused-store
// path; the only difference is the full-width base load. No wrap guard
// is needed — see a64FusedMemCheck's note (the arm64 twin).
func x64FusedEA64(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, size int, addrReg string) error {
	if addrReg != "" {
		fmt.Fprintf(b, "\tMOVQ %s, R12\n", addrReg)
	} else {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgScalar:
			fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(a))
		case simdfuse.ArgSum:
			// base+const at full width (see x64FusedLoad's addr64 arm).
			fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(a))
			if a.Const != 0 {
				fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(a.Const))
			}
		default:
			return fmt.Errorf("fused addr64 %s: folded base form", n.Op)
		}
	}
	switch off := n.Args[1]; off.Kind {
	case simdfuse.ArgConst:
		if off.Const != 0 {
			fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(off.Const))
		}
	case simdfuse.ArgScalar:
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(off))
		b.WriteString("\tADDQ AX, R12\n")
	default:
		return fmt.Errorf("fused addr64 %s: bad offset form", n.Op)
	}
	fmt.Fprintf(b, "\tADDQ $%d, R12\n", size)
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
	b.WriteString("\tMOVQ (AX), AX\n")
	b.WriteString("\tCMPQ AX, R12\n")
	fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
	fmt.Fprintf(b, "\tSUBQ $%d, R12\n", size)
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
	return nil
}

func x64FusedLaneAddr(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, addr64 bool, addrReg string) error {
	if addr64 {
		return x64FusedEA64(b, n, scalarReg, offs, 4, addrReg)
	}
	if addrReg != "" {
		// Chain-computed address (see x64FusedLoad).
		fmt.Fprintf(b, "\tMOVL %s, R12\n", addrReg)
	} else {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(b, "\tMOVQ $%d, R12\n", int64(uint32(a.Const)))
		case simdfuse.ArgSum:
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
			if a.Const != 0 {
				fmt.Fprintf(b, "\tADDL $%d, R12\n", a.Const)
			}
		default:
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
		}
	}
	if off := n.Args[1]; off.Kind == simdfuse.ArgConst {
		if off.Const != 0 {
			fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(uint32(off.Const)))
		}
	} else {
		fmt.Fprintf(b, "\tMOVL %s, AX\n", scalarReg(n.Args[1]))
		b.WriteString("\tADDQ AX, R12\n")
	}
	b.WriteString("\tADDQ $4, R12\n")
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
	b.WriteString("\tMOVQ (AX), AX\n")
	b.WriteString("\tCMPQ AX, R12\n")
	fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
	b.WriteString("\tSUBQ $4, R12\n")
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
	return nil
}

// x64FusedStore emits one member store: checked address in R12, value
// from X0/pool/a pair build into X1 (dead between node bodies), then
// the indexed MOVOU store.
func x64FusedStore(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string,
	pairRegs func(simdfuse.Arg) (string, string), offs *ModuleOffsets, pool *ConstPool, addr64 bool, src int, addrReg string) error {
	if len(n.Args) != 3 {
		return fmt.Errorf("fused store: %d args, want 3", len(n.Args))
	}
	if addr64 {
		span := 16
		if n.Op == "v128_f16x4_cvt_store" {
			span = 8
		}
		if err := x64FusedEA64(b, n, scalarReg, offs, span, addrReg); err != nil {
			return err
		}
		return x64FusedStoreTail(b, n, pairRegs, offs, pool, src)
	}
	if addrReg != "" {
		// Chain-computed address (see x64FusedLoad).
		fmt.Fprintf(b, "\tMOVL %s, R12\n", addrReg)
	} else {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(b, "\tMOVQ $%d, R12\n", int64(uint32(a.Const)))
		case simdfuse.ArgSum:
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
			if a.Const != 0 {
				fmt.Fprintf(b, "\tADDL $%d, R12\n", a.Const)
			}
		default:
			fmt.Fprintf(b, "\tMOVL %s, R12\n", scalarReg(a))
		}
	}
	if off := n.Args[1]; off.Kind == simdfuse.ArgConst {
		if off.Const != 0 {
			fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(uint32(off.Const)))
		}
	} else {
		fmt.Fprintf(b, "\tMOVL %s, AX\n", scalarReg(n.Args[1]))
		b.WriteString("\tADDQ AX, R12\n")
	}
	span := 16
	if n.Op == "v128_f16x4_cvt_store" {
		span = 8
	}
	fmt.Fprintf(b, "\tADDQ $%d, R12\n", span)
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
	b.WriteString("\tMOVQ (AX), AX\n")
	b.WriteString("\tCMPQ AX, R12\n")
	fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
	fmt.Fprintf(b, "\tSUBQ $%d, R12\n", span)
	return x64FusedStoreTail(b, n, pairRegs, offs, pool, src)
}

// x64FusedStoreTail stages the store's v128 value and performs the
// store proper (the f16 conversion chain included); the caller has
// already materialized the checked effective address in R12. Shared by
// the wasm32 and memory64 address paths.
func x64FusedStoreTail(b *strings.Builder, n simdfuse.Node,
	pairRegs func(simdfuse.Arg) (string, string), offs *ModuleOffsets, pool *ConstPool, src int) error {
	if src < 0 {
		lo, hi := pairRegs(n.Args[2])
		fmt.Fprintf(b, "\tMOVQ %s, X1\n", lo)
		fmt.Fprintf(b, "\tPINSRQ $1, %s, X1\n", hi)
		src = 1
	}
	if n.Op == "v128_f16x4_cvt_store" {
		// f32x4 -> packed f16x4 with the software idiom's semantics
		// (see simd_f16x4_cvt_bits_scalar): NaN forces sign|0x7E00,
		// non-NaN goes through the bias/multiply rounding chain the
		// wasm code performs, reproduced lane-wise in SSE. Scratch
		// X0..X3; w lives in X0 (copied there when the source sits
		// elsewhere).
		if pool == nil {
			return fmt.Errorf("fused store: %s needs a const pool", n.Op)
		}
		c4 := func(w uint32) string {
			blob := make([]byte, 16)
			for i := 0; i < 4; i++ {
				blob[i*4] = byte(w)
				blob[i*4+1] = byte(w >> 8)
				blob[i*4+2] = byte(w >> 16)
				blob[i*4+3] = byte(w >> 24)
			}
			return pool.addBlob(blob)
		}
		if src != 0 {
			fmt.Fprintf(b, "\tMOVOU X%d, X0\n", src)
		}
		// NaN mask: |w| >u 0x7F800000, via the signed-compare bias trick.
		b.WriteString("\tMOVOU X0, X1\n")
		fmt.Fprintf(b, "\tPAND ·%s(SB), X1\n", c4(0x7FFFFFFF))
		fmt.Fprintf(b, "\tPXOR ·%s(SB), X1\n", c4(0x80000000))
		fmt.Fprintf(b, "\tMOVOU ·%s(SB), X2\n", c4(0xFF800000))
		b.WriteString("\tPCMPGTL X2, X1\n")
		// A = sign | (mask & 0x7E00)
		b.WriteString("\tMOVOU X0, X2\n")
		b.WriteString("\tPSRLL $16, X2\n")
		fmt.Fprintf(b, "\tPAND ·%s(SB), X2\n", c4(0x8000))
		b.WriteString("\tMOVOU X1, X3\n")
		fmt.Fprintf(b, "\tPAND ·%s(SB), X3\n", c4(0x7E00))
		b.WriteString("\tPOR X3, X2\n")
		// bias = max(shl1 & 0xFF000000, 0x71000000)>>1 + 0x07800000
		b.WriteString("\tMOVOU X0, X3\n")
		b.WriteString("\tPSLLL $1, X3\n")
		fmt.Fprintf(b, "\tPAND ·%s(SB), X3\n", c4(0xFF000000))
		fmt.Fprintf(b, "\tPMAXUD ·%s(SB), X3\n", c4(0x71000000))
		b.WriteString("\tPSRLL $1, X3\n")
		fmt.Fprintf(b, "\tPADDL ·%s(SB), X3\n", c4(0x07800000))
		// f = |w| * 0x1p+112 * 0x1p-110 + as_float(bias)
		fmt.Fprintf(b, "\tPAND ·%s(SB), X0\n", c4(0x7FFFFFFF))
		fmt.Fprintf(b, "\tMULPS ·%s(SB), X0\n", c4(0x77800000))
		fmt.Fprintf(b, "\tMULPS ·%s(SB), X0\n", c4(0x08800000))
		b.WriteString("\tADDPS X3, X0\n")
		// h_nonnan = ((fbits>>13) & 0x7C00) + (fbits & 0xFFF)
		b.WriteString("\tMOVOU X0, X3\n")
		b.WriteString("\tPSRLL $13, X3\n")
		fmt.Fprintf(b, "\tPAND ·%s(SB), X3\n", c4(0x7C00))
		fmt.Fprintf(b, "\tPAND ·%s(SB), X0\n", c4(0xFFF))
		b.WriteString("\tPADDL X0, X3\n")
		// h = A | (~mask & h_nonnan); pack to 4 u16; 8-byte store.
		b.WriteString("\tPANDN X3, X1\n")
		b.WriteString("\tPOR X1, X2\n")
		b.WriteString("\tPACKUSDW X2, X2\n")
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
		b.WriteString("\tMOVQ X2, (AX)(R12*1)\n")
		return nil
	}
	fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
	fmt.Fprintf(b, "\tMOVOU X%d, (AX)(R12*1)\n", src)
	return nil
}

// x64SpliceLoop is the amd64 fused-loop synthesizer; see the arm64
// twin for the structure.
func x64SpliceLoop(b *strings.Builder, loop *simdfuse.Loop, pool *ConstPool, offs *ModuleOffsets, site string, portable bool, maxOut int) (bool, bool, error) {
	// Scalars, the counter, and stride deltas must be
	// register-resident (the loop indexes and bumps them in place);
	// a wider signature keeps the helper CALL.
	if 1+loop.Tree.NumScalars+1+loop.NumDeltas > len(x64FusedArgRegs) {
		return false, false, fmt.Errorf("fused loop %s: %w: scalars past the register file", loop.Tree.Name, errFusedCapacity)
	}
	// x64Dot8Rewrite preserves node indices (absorbed nodes become
	// elided placeholders), so CarriedPairs/roots/bumps stay valid.
	tree, usedAVX := x64Dot8Rewrite(loop.Tree, portable)
	if err := x64FusedProlog(b, tree, offs); err != nil {
		return false, false, err
	}
	if loop.Dec <= 0 {
		return false, false, fmt.Errorf("fused loop %s: bad dec %d", tree.Name, loop.Dec)
	}
	poolTop := 14
	if tree.NumFloats > 0 {
		poolTop = 13
	}
	carried := map[int]int{}
	var reserve []int
	for j, cp := range loop.CarriedPairs {
		r := poolTop - j
		carried[cp[0]] = r
		reserve = append(reserve, r)
		base := 1 + tree.NumScalars + 1 + loop.NumDeltas + 2*cp[0]
		fmt.Fprintf(b, "\tMOVQ %s, X%d\n", x64FusedIntArg(base, maxOut), r)
		fmt.Fprintf(b, "\tPINSRQ $1, %s, X%d\n", x64FusedIntArg(base+1, maxOut), r)
	}
	counterReg := x64FusedArgRegs[1+loop.CounterScalar]
	cmpOp, subOp := "CMPL", "SUBL"
	if loop.CounterWide {
		cmpOp, subOp = "CMPQ", "SUBQ"
	}
	loopLabel := "gcasmfxl" + site
	exitLabel := "gcasmfxlx" + site
	fmt.Fprintf(b, "%s:\n", loopLabel)
	if loop.PreTest {
		fmt.Fprintf(b, "\t%s %s, $%d\n", cmpOp, counterReg, loop.Dec)
		fmt.Fprintf(b, "\tJB %s\n", exitLabel)
	}
	loc, needsTrap, err := x64SpliceFusedCore(b, tree, pool, offs, carried, reserve, 1+loop.NumDeltas, true, maxOut)
	if err != nil {
		return false, false, err
	}
	for j, cp := range loop.CarriedPairs {
		src := 0
		if !loc[cp[1]].chained {
			src = loc[cp[1]].pool
		}
		x64VecCopy(b, poolTop-j, src)
	}
	// Bumps wrap mod 2^32 on wasm32; an Addr64 loop's pointer scalars
	// advance at full width (the body's per-node bounds checks keep a
	// runaway pointer from being dereferenced).
	bumpAdd := "ADDL"
	if tree.Addr64 {
		bumpAdd = "ADDQ"
	}
	for _, bump := range loop.Bumps {
		if bump.DeltaScalar >= 0 {
			fmt.Fprintf(b, "\t%s %s, %s\n", bumpAdd,
				x64FusedArgRegs[1+tree.NumScalars+1+bump.DeltaScalar], x64FusedArgRegs[1+bump.Scalar])
			continue
		}
		fmt.Fprintf(b, "\t%s $%d, %s\n", bumpAdd, bump.Delta, x64FusedArgRegs[1+bump.Scalar])
	}
	fmt.Fprintf(b, "\t%s $%d, %s\n", subOp, loop.Dec, counterReg)
	if loop.PreTest {
		fmt.Fprintf(b, "\tJMP %s\n", loopLabel)
		fmt.Fprintf(b, "%s:\n", exitLabel)
	} else {
		fmt.Fprintf(b, "\tJNE %s\n", loopLabel)
	}
	roots := tree.RootList()
	moves := map[int]int{}
	for j, xs := range loop.ExitScalars {
		moves[2*len(roots)+j] = 1 + xs
	}
	wideDst := map[int]bool{}
	for j, xs := range loop.ExitScalars {
		if (xs == loop.CounterScalar && loop.CounterWide) || (tree.Addr64 && xs != loop.CounterScalar) {
			// Addr64 exit scalars are the int64 pointer parameters
			// (the counter keeps its own declared width).
			wideDst[2*len(roots)+j] = true
		}
	}
	movFor := func(dst int) string {
		if wideDst[dst] {
			return "MOVQ"
		}
		return "MOVL"
	}
	// Result slot locations: root pair halves (8 bytes each), then the
	// exit scalars (4, or 8 for a wide counter). Slots past the
	// register file land in the stack results area, which follows the
	// integer argument overflow.
	var resSizes []int
	for range roots {
		resSizes = append(resSizes, 8, 8)
	}
	for j := range loop.ExitScalars {
		if wideDst[2*len(roots)+j] {
			resSizes = append(resSizes, 8)
		} else {
			resSizes = append(resSizes, 4)
		}
	}
	totalIntArgs := 1 + tree.NumScalars + 1 + loop.NumDeltas + 2*tree.NumPairs
	argStackBytes := 0
	if over := totalIntArgs - len(x64FusedArgRegs); over > 0 {
		argStackBytes = 8 * over
	}
	resLocs := x64FusedResultLocs(resSizes, argStackBytes, maxOut)
	emitParallelMoves(b, moves, func(dst, src int) string {
		return fmt.Sprintf("\t%s %s, %s\n", movFor(dst), x64FusedArgRegs[src], resLocs[dst])
	}, func(dst, src int) (string, string) {
		return fmt.Sprintf("\t%s %s, R12\n", movFor(dst), x64FusedArgRegs[src]),
			fmt.Sprintf("\t%s R12, %s\n", movFor(dst), resLocs[dst])
	})
	carriedOf := map[int]int{}
	for j, cp := range loop.CarriedPairs {
		carriedOf[cp[1]] = poolTop - j
	}
	for k, r := range roots {
		src, ok := carriedOf[r]
		if !ok {
			src = 0
			if !loc[r].chained {
				src = loc[r].pool
			}
		}
		fmt.Fprintf(b, "\tMOVQ X%d, %s\n", src, resLocs[2*k])
		if lo := resLocs[2*k+1]; strings.HasSuffix(lo, "(SP)") {
			fmt.Fprintf(b, "\tPEXTRQ $1, X%d, R12\n", src)
			fmt.Fprintf(b, "\tMOVQ R12, %s\n", lo)
		} else {
			fmt.Fprintf(b, "\tPEXTRQ $1, X%d, %s\n", src, lo)
		}
	}
	if usedAVX {
		// The block dots dirtied ymm upper halves; clear them once on the
		// loop-exit path before control returns to gc-emitted SSE code.
		b.WriteString("\tVZEROUPPER\n")
	}
	return true, needsTrap, nil
}
