package gcasm

// Fused-region splicing, arm64 (see internal/simdfuse for the
// descriptor and internal/codegen/simd_fuse.go for the producer).
//
// A fused call replaces a whole tree of SIMD ops with one splice whose
// internal edges never leave the vector register file. The synthesis
// reuses the pair tables VERBATIM: every table body reads its v128
// operands from v0..v2, keeps scratch within v0..v3, and leaves its
// result in v0 — so composing bodies only needs the operand-building
// prefix and result-moving suffix replaced by vector copies. Values
// that outlive the immediate chain are parked in v16..v30: the Go ABI
// makes every float/vector register caller-saved, so within the one
// CALL being replaced the whole file is scratch.
//
// GPR budget inside the body: R0 (staging for table cores that read a
// scalar in w0/x0), R22 (constant staging), R23 (the saved m pointer),
// R24–R27 (memory-preamble scratch). Fused-signature arguments occupy
// R0..R6 at entry (see fusedMaxIntRegs) and are never clobbered before
// their last read except R0=m, which is saved to R23 first.

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// a64FusedArgReg is the ABIInternal integer register holding fused
// argument i (0 = m).
func a64FusedArgReg(i int) string { return fmt.Sprintf("R%d", i) }

// a64VecCopy emits `mov v<dst>.16b, v<src>.16b` (ORR).
func a64VecCopy(b *strings.Builder, dst, src int) {
	if dst == src {
		return
	}
	enc := 0x4EA01C00 | uint32(src)<<16 | uint32(src)<<5 | uint32(dst)
	fmt.Fprintf(b, "\tWORD $0x%08x // mov v%d.16b, v%d.16b (fuse)\n", enc, dst, src)
}

// errFusedCapacity marks a fused splice that exceeded this
// architecture's register capacity: the transform keeps the helper
// CALL instead of failing the build (the pure body is always
// correct). Planned capacity normally prevents this; the arm64-pool
// budget opt-in makes it expected on amd64.
var errFusedCapacity = fmt.Errorf("fused splice capacity")

// fusedLoc says where a node's result currently lives.
type fusedLoc struct {
	chained bool // still in v0, immediately consumed by the next node
	pool    int  // pool V register otherwise
}

// a64ClassifyPair splits a pair-table body into the operand-building
// prefix (per-operand target V registers) and the core, dropping the
// trailing result moves. nV128 is the member's v128 operand count —
// classification is arity-DRIVEN because a splat's scalar staging is
// textually indistinguishable from a build prefix. An optional
// standalone scalar-staging move (`mov x0, x<n>`) after the builds is
// dropped too: the fused emitter stages scalars itself. The line
// shapes are this generator's own output contract (WORD lines carry
// their disassembly), the same one the forwarding passes read.
func a64ClassifyPair(lines []string, nV128 int) (opTargets []int, core []string, err error) {
	i := 0
	for ; i < len(lines) && len(opTargets) < nV128; i++ {
		dis := a64WordDis(lines[i])
		m := pfBuildLoRe.FindStringSubmatch(dis)
		if m == nil {
			return nil, nil, fmt.Errorf("fuse classify: expected %d operand builds, found %d before %q", nV128, len(opTargets), lines[i])
		}
		vk := pfNum(m[1])
		if vk < 0 {
			return nil, nil, fmt.Errorf("fuse classify: bad register capture in %q", lines[i])
		}
		// The matching build-hi follows; require and skip it.
		if i+1 >= len(lines) || pfBuildHiRe.FindStringSubmatch(a64WordDis(lines[i+1])) == nil {
			return nil, nil, fmt.Errorf("fuse classify: build-lo without build-hi: %q", lines[i])
		}
		opTargets = append(opTargets, vk)
		i++
	}
	if i < len(lines) {
		if dis := a64WordDis(lines[i]); strings.HasPrefix(dis, "mov x0, x") {
			i++ // the fused emitter stages the scalar into x0 itself
		}
	}
	for ; i < len(lines); i++ {
		dis := a64WordDis(lines[i])
		if pfOutLoRe.MatchString(dis) || pfOutHiRe.MatchString(dis) {
			continue // result moves: the fused body keeps results in v0
		}
		// The fused frame keeps live arguments in R1.. — a core that
		// touches any GPR beyond the sanctioned x0/w0 staging register
		// would clobber them. Today only the (unfusable) bitmask ops
		// do; make drift a build error, not a silent clobber.
		for _, g := range pfGprTokRe.FindAllStringSubmatch(dis, -1) {
			if g[1] != "0" {
				return nil, nil, fmt.Errorf("fuse classify: core line touches R%s: %q", g[1], lines[i])
			}
		}
		core = append(core, lines[i])
	}
	return opTargets, core, nil
}

// a64WordDis extracts the disassembly comment of a WORD line, or
// returns the line itself for plain Go-asm lines.
func a64WordDis(l string) string {
	if m := pfWordRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
		return m[1]
	}
	return strings.TrimSpace(l)
}

// a64SpliceFused synthesizes the inline body of a fused-region call.
// Arguments ride R0..R6 per fusedMaxIntRegs; results in (R0, R1).
func a64SpliceFused(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets, portable bool) (bool, bool, error) {
	loc, needsTrap, err := a64SpliceFusedCore(b, tree, pool, offs, nil, nil, 0, false, portable)
	if err != nil {
		return false, false, err
	}
	// Result epilogue: two uint64s per root, in ABI result order.
	for k, r := range tree.RootList() {
		src := 0
		if !loc[r].chained {
			src = loc[r].pool
		}
		fmt.Fprintf(b, "\tFMOVD F%d, R%d\n", src, 2*k)
		fmt.Fprintf(b, "\tVMOV V%d.D[1], R%d\n", src, 2*k+1)
	}
	return true, needsTrap, nil
}

// a64FusedProlog emits the shared region prologue: m saved, the
// memory bounds hoisted, leaf float arguments packed into their
// homes.
func a64FusedProlog(b *strings.Builder, tree *simdfuse.Tree, offs *ModuleOffsets) error {
	if tree.NeedsMem && offs == nil {
		return fmt.Errorf("fused splice %s: no Module offsets", tree.Name)
	}
	b.WriteString("\tMOVD R0, R23\n") // m survives R0 staging clobbers
	if tree.NeedsMem {
		fmt.Fprintf(b, "\tMOVD %d(R23), R21\n", offs.MemSize)
		b.WriteString("\tMOVD (R21), R21\n")
		fmt.Fprintf(b, "\tMOVD %d(R23), R20\n", offs.M)
	}
	for i := 0; i < tree.NumFloats; i++ {
		a64VecCopy(b, 15-i, i) // v15 downward: float homes
	}
	return nil
}

// a64SpliceFusedCore emits the node body. carried maps ArgPairIn
// indexes to FIXED vector registers holding loop-carried values (read
// in place, never rebuilt from GPRs); reserve excludes registers from
// the parking pool; extraIntArgs shifts the pair-argument register
// base (the fused LOOP signature inserts its counter after the
// scalars); skipProlog omits the prologue (the caller emitted it
// outside its loop).
func a64SpliceFusedCore(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets,
	carried map[int]int, reserve []int, extraIntArgs int, skipProlog bool, portable bool) ([]fusedLoc, bool, error) {
	return a64SpliceFusedCoreLut(b, tree, pool, offs, carried, reserve, extraIntArgs, skipProlog, nil, -1, portable, nil)
}

// a64DualAcc splits a fused loop's serial FMLA accumulator across two
// registers (fast-math only): FMLA's 4-cycle latency on a single
// register LENGTHENS the chain the fusion was meant to shorten;
// alternating two accumulators halves it — the native kernels'
// structure. The loop epilogue adds the halves back together.
type a64DualAcc struct {
	primary int // the carried accumulator register
	second  int // the zero-initialized partner
	n       int // fmla alternation counter
}

// a64EmitSdotIdx materializes the TBL permutation constant for SDOT
// selection (see a64OpSdot16) into V<reg>. R22 is the sanctioned
// constant-staging scratch.
func a64EmitSdotIdx(b *strings.Builder, reg int) {
	fmt.Fprintf(b, "\tMOVD $0x0b0a030209080100, R22\n")
	fmt.Fprintf(b, "\tFMOVD R22, F%d\n", reg)
	fmt.Fprintf(b, "\tMOVD $0x0f0e07060d0c0504, R22\n")
	fmt.Fprintf(b, "\tVMOV R22, V%d.D[1]\n", reg)
}

// a64SpliceFusedCoreLut additionally accepts hoisted table-base
// registers for the scale-lookup peephole (fused loops hoist them
// once, outside the loop).
func a64SpliceFusedCoreLut(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets,
	carried map[int]int, reserve []int, extraIntArgs int, skipProlog bool, lutBase map[int]string, sdotIdx int, portable bool, dual *a64DualAcc) ([]fusedLoc, bool, error) {
	tree = a64Dot8Rewrite(tree, portable, offs.fastMath())
	if !skipProlog {
		if err := a64FusedProlog(b, tree, offs); err != nil {
			return nil, false, err
		}
	} else if tree.NeedsMem && offs == nil {
		return nil, false, fmt.Errorf("fused splice %s: no Module offsets", tree.Name)
	}
	// Consumer counts drive pool lifetimes; the walk below relies on
	// post-order (every ArgNode refers backward).
	uses := make([]int, len(tree.Nodes))
	for _, n := range tree.Nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	// Each root is one extra consumer (the result epilogue), which also
	// keeps its pool register alive to the end.
	roots := tree.RootList()
	for _, r := range roots {
		uses[r]++
	}
	floatHome := make([]int, tree.NumFloats)
	for i := 0; i < tree.NumFloats; i++ {
		floatHome[i] = 15 - i // v15 downward: float homes (see prolog)
	}

	scalarReg := func(a simdfuse.Arg) string {
		return a64FusedArgReg(1 + a.Index)
	}
	// Arguments are confined to R0..R15, the arm64 ABIInternal
	// integer-argument registers — gc passes any further argument on
	// the stack, which this register-only splice cannot see (R16/R17
	// are the linker temporaries, R18 the platform register). The
	// producer enforces this at the intern point; re-check here so a
	// miscounted signature degrades to the helper call instead of
	// emitting a garbage-reading body.
	pairErr := error(nil)
	pairRegs := func(a simdfuse.Arg) (string, string) {
		base := 1 + tree.NumScalars + extraIntArgs + 2*a.Index
		if base+1 > 15 && pairErr == nil {
			pairErr = fmt.Errorf("fused splice %s: %w: pair argument past R15 (scalars=%d pairs=%d extra=%d pair#%d)",
				tree.Name, errFusedCapacity, tree.NumScalars, tree.NumPairs, extraIntArgs, a.Index)
		}
		return a64FusedArgReg(base), a64FusedArgReg(base + 1)
	}

	loc := make([]fusedLoc, len(tree.Nodes))
	reserved := map[int]bool{}
	for _, r := range reserve {
		reserved[r] = true
	}
	var freePool []int
	for v := 30; v >= 16; v-- {
		if !reserved[v] {
			freePool = append(freePool, v)
		}
	}
	needsTrap := false

	// TBL permutation register for SDOT selection: loop callers hoist
	// it (sdotIdx >= 0); straight-line regions materialize it lazily
	// at the first SDOT node, from the pool, and never free it.
	ensureSdotIdx := func() (int, error) {
		if sdotIdx >= 0 {
			return sdotIdx, nil
		}
		if len(freePool) == 0 {
			return 0, fmt.Errorf("fused splice %s: %w: vector pool exhausted", tree.Name, errFusedCapacity)
		}
		sdotIdx = freePool[len(freePool)-1]
		freePool = freePool[:len(freePool)-1]
		a64EmitSdotIdx(b, sdotIdx)
		return sdotIdx, nil
	}

	chains := newA64ScalarChain(b, tree, scalarReg, uses, lutBase)

	for i, n := range tree.Nodes {
		if n.Op == a64OpElided {
			// Absorbed into a synthetic 8-bit dot: nothing to emit,
			// nothing referenced, nothing to free.
			loc[i] = fusedLoc{chained: true}
			continue
		}
		if n.Class() != simdfuse.ClassV128 {
			// Inline scalar-chain node: evaluated here, right before its
			// vector consumer, in scratch that never touches v0 or the
			// pool.
			if err := chains.emitNode(i, &tree.Nodes[i]); err != nil {
				return nil, false, err
			}
			loc[i] = fusedLoc{chained: true} // never freed into the pool
			continue
		}
		// Placement first: freeing dying operands before allocating
		// this node's destination lets their registers be reused, and
		// loads/splats can then write their pool register DIRECTLY
		// instead of parking a copy out of v0.
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
			if err := a64FusedStore(b, n, scalarReg, pairRegs, loc, dst0Src(loc, n), tree.Addr64); err != nil {
				return nil, false, err
			}
			needsTrap = true
			loc[i] = fusedLoc{chained: true} // nothing to park or free
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
			// The lane inserts into the value operand: place it in dst
			// first, then ld1 straight from memory into the lane.
			if src := dst0Src(loc, n); src < 0 {
				lo, hi := pairRegs(n.Args[3])
				fmt.Fprintf(b, "\tFMOVD %s, F%d\n", lo, dst)
				fmt.Fprintf(b, "\tVMOV %s, V%d.D[1]\n", hi, dst)
			} else {
				a64VecCopy(b, dst, src)
			}
			if n.Args[2].Kind != simdfuse.ArgConst {
				return nil, false, fmt.Errorf("fused splice %s: non-constant lane", tree.Name)
			}
			if err := a64FusedLaneAddr(b, n, scalarReg, tree.Addr64); err != nil {
				return nil, false, err
			}
			lane := uint32(n.Args[2].Const) & 3
			enc := 0x0D408000 | (lane>>1)<<30 | (lane&1)<<12 | uint32(27)<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // ld1 {v%d.s}[%d], [x27]\n", enc, dst, lane)
			needsTrap = true
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		}
		if _, isMem := fusedMemOpsA64[n.Op]; isMem {
			if err := a64FusedLoad(b, n, scalarReg, offs, dst, tree.Addr64); err != nil {
				return nil, false, err
			}
			needsTrap = true
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == "f32x4_splat" {
			// dup v<dst>.4s, v<src>.s[0] — a leaf float argument's home,
			// or a computed scalar terminal still in chain scratch.
			var home int
			switch {
			case len(n.Args) == 1 && n.Args[0].Kind == simdfuse.ArgFloat:
				home = floatHome[n.Args[0].Index]
			case len(n.Args) == 1 && n.Args[0].Kind == simdfuse.ArgNode && tree.Nodes[n.Args[0].Index].Class() == simdfuse.ClassF32:
				f, err := chains.takeSplatSource(n.Args[0].Index)
				if err != nil {
					return nil, false, err
				}
				home = f
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed f32x4_splat args", tree.Name)
			}
			enc := 0x4E040400 | uint32(home)<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // dup v%d.4s, v%d.s[0]\n", enc, dst, home)
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == a64OpMulLane {
			// FMUL by element: vector operand times lane 0 of the
			// scalar source's register (a float home or chain scratch).
			var va int
			switch a := n.Args[0]; a.Kind {
			case simdfuse.ArgNode:
				if loc[a.Index].chained {
					va = 0
				} else {
					va = loc[a.Index].pool
				}
			case simdfuse.ArgPairIn:
				if cr, isCarried := carried[a.Index]; isCarried {
					va = cr
				} else {
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tFMOVD %s, F1\n", lo)
					fmt.Fprintf(b, "\tVMOV %s, V1.D[1]\n", hi)
					va = 1
				}
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
			}
			var home int
			switch s := n.Args[1]; {
			case s.Kind == simdfuse.ArgFloat:
				home = floatHome[s.Index]
			case s.Kind == simdfuse.ArgNode && tree.Nodes[s.Index].Class() == simdfuse.ClassF32:
				f, err := chains.takeSplatSource(s.Index)
				if err != nil {
					return nil, false, err
				}
				home = f
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s source", tree.Name, n.Op)
			}
			enc := 0x4F809000 | uint32(home)<<16 | uint32(va)<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // fmul v%d.4s, v%d.4s, v%d.s[0]\n", enc, dst, va, home)
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == a64OpFmlaLane {
			// acc += vec * scalar.s[0], single rounding (fast-math).
			// The accumulator dies here; claim its register like the
			// other accumulate ops.
			var va int
			switch a := n.Args[1]; a.Kind {
			case simdfuse.ArgNode:
				if loc[a.Index].chained {
					va = 0
				} else {
					va = loc[a.Index].pool
				}
			case simdfuse.ArgPairIn:
				if cr, isCarried := carried[a.Index]; isCarried {
					va = cr
				} else {
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tFMOVD %s, F1\n", lo)
					fmt.Fprintf(b, "\tVMOV %s, V1.D[1]\n", hi)
					va = 1
				}
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
			}
			var home int
			switch sc := n.Args[2]; {
			case sc.Kind == simdfuse.ArgFloat:
				home = floatHome[sc.Index]
			case sc.Kind == simdfuse.ArgNode && tree.Nodes[sc.Index].Class() == simdfuse.ClassF32:
				f, err := chains.takeSplatSource(sc.Index)
				if err != nil {
					return nil, false, err
				}
				home = f
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s source", tree.Name, n.Op)
			}
			var acc int
			switch a := n.Args[0]; a.Kind {
			case simdfuse.ArgNode:
				if loc[a.Index].chained {
					acc = 0
				} else {
					acc = loc[a.Index].pool
				}
			case simdfuse.ArgPairIn:
				if cr, isCarried := carried[a.Index]; isCarried {
					acc = cr
				} else {
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tFMOVD %s, F2\n", lo)
					fmt.Fprintf(b, "\tVMOV %s, V2.D[1]\n", hi)
					acc = 2
				}
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s acc", tree.Name, n.Op)
			}
			tgt := acc
			if dual != nil && acc == dual.primary {
				if dual.n%2 == 1 {
					tgt = dual.second
				}
				dual.n++
			}
			enc := 0x4F801000 | uint32(home)<<16 | uint32(va)<<5 | uint32(tgt)
			fmt.Fprintf(b, "\tWORD $0x%08x // fmla v%d.4s, v%d.4s, v%d.s[0]\n", enc, tgt, va, home)
			// The accumulate stays IN PLACE: no chain copy, no park —
			// per-block copies on the serial accumulator chain are what
			// a fused multiply-add is supposed to remove. Consumers read
			// the accumulator's register through the pool location; the
			// staging registers (v0-v2) are stable until the next node.
			if acc >= 16 {
				// Reclaim acc's register as this node's home (it was
				// freed when arg0 died); return the pre-allocated dst.
				if !willChain {
					for fi, fr := range freePool {
						if fr == acc {
							freePool[fi] = dst
							dst = acc
							break
						}
					}
					if dst != acc {
						// acc not in the pool (carried register):
						// results live there; hand back dst.
						freePool = append(freePool, dst)
					}
				}
				loc[i] = fusedLoc{chained: false, pool: acc}
			} else {
				// Accumulator was rebuilt into scratch (v0-v2): park it.
				a64VecCopy(b, dst, acc)
				loc[i] = fusedLoc{chained: willChain, pool: dst}
			}
			continue
		} else if n.Op == a64OpDot8Acc {
			// sadalp: accumulate pairwise sums of arg1's int16 products
			// into arg0's int32 value. Both die here (rewrite
			// guarantee), so accumulating in arg0's register and
			// parking the result is clobber-safe.
			var srcs [2]int
			for k := 0; k < 2; k++ {
				a := n.Args[k]
				if a.Kind != simdfuse.ArgNode {
					return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
				}
				if loc[a.Index].chained {
					if k != 0 {
						return nil, false, fmt.Errorf("fused splice %s: chained value consumed at operand %d", tree.Name, k)
					}
					srcs[k] = 0
				} else {
					srcs[k] = loc[a.Index].pool
				}
			}
			// The accumulator dies here, so its register is back in the
			// pool: claim it as the destination and the accumulation
			// happens fully in place, no vector copy.
			if !willChain && srcs[0] != 0 && dst != srcs[0] {
				for fi, fr := range freePool {
					if fr == srcs[0] {
						freePool[fi] = dst
						dst = srcs[0]
						break
					}
				}
			}
			enc := 0x4E606800 | uint32(srcs[1])<<5 | uint32(srcs[0])
			fmt.Fprintf(b, "\tWORD $0x%08x // sadalp v%d.4s, v%d.8h\n", enc, srcs[0], srcs[1])
			a64VecCopy(b, dst, srcs[0])
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == "f16x4_cvt" {
			// Four f16 values in the low 16 bits of each i32 lane -> f32
			// lanes: narrow, then widening convert. Bit-exact against the
			// verified conversion table (see pass.RecognizeF16Gather).
			var src int
			switch a := n.Args[0]; a.Kind {
			case simdfuse.ArgNode:
				if loc[a.Index].chained {
					src = 0
				} else {
					src = loc[a.Index].pool
				}
			case simdfuse.ArgPairIn:
				if cr, isCarried := carried[a.Index]; isCarried {
					src = cr
				} else {
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tFMOVD %s, F1\n", lo)
					fmt.Fprintf(b, "\tVMOV %s, V1.D[1]\n", hi)
					src = 1
				}
			default:
				return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
			}
			enc := 0x0E612800 | uint32(src)<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // xtn v%d.4h, v%d.4s\n", enc, dst, src)
			enc = 0x0E217800 | uint32(dst)<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // fcvtl v%d.4s, v%d.4h\n", enc, dst, dst)
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == a64OpSdot16 || n.Op == a64OpSdotAcc {
			// Full 16-byte dot via TBL-permuted SDOT (see the rewrite for
			// the bit-identity argument). Byte sources are the last two
			// args; a64OpSdotAcc's arg0 is the int32 accumulator.
			base := 0
			if n.Op == a64OpSdotAcc {
				base = 1
			}
			var srcs [2]int
			scratch := 1 // v1/v2: body temp space, dead across nodes
			for k := 0; k < 2; k++ {
				a := n.Args[base+k]
				switch a.Kind {
				case simdfuse.ArgNode:
					if loc[a.Index].chained {
						if base+k != 0 {
							return nil, false, fmt.Errorf("fused splice %s: chained value consumed at operand %d", tree.Name, base+k)
						}
						srcs[k] = 0
					} else {
						srcs[k] = loc[a.Index].pool
					}
				case simdfuse.ArgPairIn:
					if cr, isCarried := carried[a.Index]; isCarried {
						srcs[k] = cr
					} else {
						lo, hi := pairRegs(a)
						fmt.Fprintf(b, "\tFMOVD %s, F%d\n", lo, scratch)
						fmt.Fprintf(b, "\tVMOV %s, V%d.D[1]\n", hi, scratch)
						srcs[k] = scratch
						scratch++
					}
				default:
					return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
				}
			}
			dotN, dotM := 1, 2
			if offs.fastMath() {
				// Lane grouping is unobservable without bit-exactness:
				// feed SDOT the raw byte sources (the native selection).
				dotN, dotM = srcs[0], srcs[1]
			} else {
				idx, err := ensureSdotIdx()
				if err != nil {
					return nil, false, err
				}
				// TBL outputs live in v1/v2. When operand 1 was built into
				// v1 (operand 0 needed no scratch), permute it first so
				// the operand-0 TBL does not clobber it.
				emitTbl := func(d, s int) {
					enc := 0x4E000000 | uint32(idx)<<16 | uint32(s)<<5 | uint32(d)
					fmt.Fprintf(b, "\tWORD $0x%08x // tbl v%d.16b, {v%d.16b}, v%d.16b\n", enc, d, s, idx)
				}
				if srcs[1] == 1 {
					emitTbl(2, srcs[1])
					emitTbl(1, srcs[0])
				} else {
					emitTbl(1, srcs[0])
					emitTbl(2, srcs[1])
				}
			}
			acc := dst
			if n.Op == a64OpSdot16 {
				if acc == dotN || acc == dotM {
					// Fast mode feeds SDOT the raw sources; a freed
					// source register can be re-allocated as dst. Zero a
					// scratch accumulator instead and move at the end.
					acc = 3
				}
				enc := 0x4F000400 | uint32(acc)
				fmt.Fprintf(b, "\tWORD $0x%08x // movi v%d.4s, #0\n", enc, acc)
			} else {
				// arg0's accumulator dies here (rewrite guarantee):
				// accumulate in its register and park, clobber-safe. Same
				// register-claiming trick as the sadalp case.
				a := n.Args[0]
				if a.Kind != simdfuse.ArgNode {
					return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
				}
				if loc[a.Index].chained {
					acc = 0
				} else {
					acc = loc[a.Index].pool
				}
				if !willChain && acc != 0 && dst != acc {
					for fi, fr := range freePool {
						if fr == acc {
							freePool[fi] = dst
							dst = acc
							break
						}
					}
				}
			}
			enc := 0x4E809400 | uint32(dotM)<<16 | uint32(dotN)<<5 | uint32(acc)
			fmt.Fprintf(b, "\tWORD $0x%08x // sdot v%d.4s, v%d.16b, v%d.16b\n", enc, acc, dotN, dotM)
			a64VecCopy(b, dst, acc)
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else if n.Op == a64OpDot8Low || n.Op == a64OpDot8High ||
			n.Op == a64OpDot8MulLow || n.Op == a64OpDot8MulHigh {
			// smull (smull2) multiplies the int8 lanes into exact int16
			// products; saddlp widens adjacent pairs into the dot's
			// int32 sums. Bit-identical to extend+dot (see the rewrite).
			var srcs [2]int
			scratch := 1 // v1/v2: body temp space, dead across nodes
			for k := 0; k < 2; k++ {
				a := n.Args[k]
				switch a.Kind {
				case simdfuse.ArgNode:
					if loc[a.Index].chained {
						if k != 0 {
							return nil, false, fmt.Errorf("fused splice %s: chained value consumed at operand %d", tree.Name, k)
						}
						srcs[k] = 0
					} else {
						srcs[k] = loc[a.Index].pool
					}
				case simdfuse.ArgPairIn:
					if cr, isCarried := carried[a.Index]; isCarried {
						srcs[k] = cr
					} else {
						lo, hi := pairRegs(a)
						fmt.Fprintf(b, "\tFMOVD %s, F%d\n", lo, scratch)
						fmt.Fprintf(b, "\tVMOV %s, V%d.D[1]\n", hi, scratch)
						srcs[k] = scratch
						scratch++
					}
				default:
					return nil, false, fmt.Errorf("fused splice %s: malformed %s args", tree.Name, n.Op)
				}
			}
			mul := uint32(0x0E20C000) // smull vD.8h, vN.8b, vM.8b
			mnem, half := "smull", "8b"
			if n.Op == a64OpDot8High || n.Op == a64OpDot8MulHigh {
				mul = 0x4E20C000 // smull2 vD.8h, vN.16b, vM.16b
				mnem, half = "smull2", "16b"
			}
			enc := mul | uint32(srcs[1])<<16 | uint32(srcs[0])<<5 | uint32(dst)
			fmt.Fprintf(b, "\tWORD $0x%08x // %s v%d.8h, v%d.%s, v%d.%s\n",
				enc, mnem, dst, srcs[0], half, srcs[1], half)
			if n.Op == a64OpDot8Low || n.Op == a64OpDot8High {
				enc = 0x4E602800 | uint32(dst)<<5 | uint32(dst)
				fmt.Fprintf(b, "\tWORD $0x%08x // saddlp v%d.4s, v%d.8h\n", enc, dst, dst)
			}
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		} else {
			lines, ok := a64SimdPairSpliceTab[n.Op]
			if !ok {
				return nil, false, fmt.Errorf("fused splice %s: no pair table entry for %q", tree.Name, n.Op)
			}
			lines, ok = simdSpliceRewriteConsts(lines, pool)
			if !ok {
				return nil, false, fmt.Errorf("fused splice %s: unknown const reference in %q", tree.Name, n.Op)
			}
			// Route operands into the body's expected registers. A
			// chained value already sits in v0 and may only feed
			// operand 0 (codegen guarantees the chain shape).
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
			opTargets, core, err := a64ClassifyPair(lines, len(vArgs))
			if err != nil {
				return nil, false, fmt.Errorf("fused splice %s, op %q: %w", tree.Name, n.Op, err)
			}
			// Resolve each operand's physical register. Pair inputs
			// still build into their classify target; node values are
			// read in place when the body renumbers.
			srcs := make([]int, len(vArgs))
			renumberable := true
			for k, a := range vArgs {
				switch a.Kind {
				case simdfuse.ArgNode:
					src := loc[a.Index]
					if src.chained {
						if k != 0 {
							return nil, false, fmt.Errorf("fused splice %s: chained value consumed at operand %d", tree.Name, k)
						}
						srcs[k] = 0
					} else {
						srcs[k] = src.pool
					}
				case simdfuse.ArgPairIn:
					if cr, isCarried := carried[a.Index]; isCarried {
						// Loop-carried value: read in place from its
						// fixed register, exactly like a parked node.
						srcs[k] = cr
						break
					}
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tFMOVD %s, F%d\n", lo, opTargets[k])
					fmt.Fprintf(b, "\tVMOV %s, V%d.D[1]\n", hi, opTargets[k])
					srcs[k] = opTargets[k]
				}
				if opTargets[k] != k {
					// The dataflow map keys operands by position; a
					// body whose builds land off-position keeps copies.
					renumberable = false
				}
			}
			if sArg != nil {
				if sArg.Kind == simdfuse.ArgConst {
					fmt.Fprintf(b, "\tMOVD $%d, R0\n", int64(sArg.Const))
				} else {
					fmt.Fprintf(b, "\tMOVD %s, R0\n", scalarReg(*sArg))
				}
				// Scalar-consuming bodies stage through w0/x0 and often
				// dup into a vector; their logical v0 is NOT operand 0.
				renumberable = renumberable && len(vArgs) == 0
			}
			if renumberable {
				if renum, ok := a64RenumberBody(core, srcs, dst); ok {
					for _, l := range renum {
						fmt.Fprintf(b, "\t%s\n", l)
					}
					loc[i] = fusedLoc{chained: willChain, pool: dst}
					continue
				}
			}
			// Copy path: route operands into the body's expected
			// registers, run it verbatim, park the result.
			for k, a := range vArgs {
				if a.Kind == simdfuse.ArgPairIn {
					if cr, isCarried := carried[a.Index]; isCarried {
						a64VecCopy(b, opTargets[k], cr)
					}
					continue // non-carried pair inputs already built in place
				}
				if a.Kind != simdfuse.ArgNode {
					continue
				}
				src := loc[a.Index]
				if src.chained {
					continue // already in v0
				}
				a64VecCopy(b, opTargets[k], src.pool)
			}
			for _, l := range core {
				fmt.Fprintf(b, "\t%s\n", strings.TrimSpace(l))
			}
		}
		// Pure table bodies on the copy path leave their result in v0;
		// park it when the placement chose a pool register. (The
		// renumbered path continues before reaching here.)
		if !willChain {
			a64VecCopy(b, dst, 0)
		}
		loc[i] = fusedLoc{chained: willChain, pool: dst}
	}
	if pairErr != nil {
		return nil, false, pairErr
	}
	return loc, needsTrap, nil
}

// a64ChainsIntoNext reports whether node i's value is the FIRST v128
// operand of node i+1 (the only place a value can ride v0 across).
func a64ChainsIntoNext(tree *simdfuse.Tree, i int) bool {
	next := tree.Nodes[i+1]
	for _, a := range next.Args {
		if a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn {
			return a.Kind == simdfuse.ArgNode && a.Index == i
		}
	}
	return false
}

// fusedMemOpsA64 maps fused memory ops to their argument layout:
// (addr, offset) or (addr, offset, rlo, span), all after the m the
// descriptor omits.
var fusedMemOpsA64 = map[string]int{
	"v128_load":         2,
	"v128_load_nc":      2,
	"v128_load_rng":     4,
	"v128_load32_zero":  2,
	"v128_load32_splat": 2,
	"v128_load16x4_u":   2,
	"v128_load32_lane":  3, // + the v128 operand the lane inserts into
}

// dst0Src resolves a store's v128 VALUE operand register: a chained
// value sits in v0, a parked one in its pool register. Pair inputs
// return -1 (the store builds them into scratch itself).
func dst0Src(loc []fusedLoc, n simdfuse.Node) int {
	a := n.Args[len(n.Args)-1]
	if a.Kind != simdfuse.ArgNode {
		return -1
	}
	if loc[a.Index].chained {
		return 0
	}
	return loc[a.Index].pool
}

// a64FusedStore emits one member store: address like a checked load,
// value from v0/pool/a pair build into v1 (dead between nodes), then
// the register-offset str.
// a64FusedMemCheck materializes a member's checked effective address
// into R25: the base plus the memarg offset (a small bounded constant,
// or rarely a scalar), then the ea+size ≤ memSize range check. The
// wasm32 and memory64 paths share the SAME arithmetic and bounds
// check; the ONLY difference is how the base is loaded — a
// zero-extended i32 (MOVWU, in the caller) versus a full i64 (MOVD).
//
// No wrap guard is needed on either width: a memory64's linear memory
// is capped at 2^48 bytes (mem64HardCap), so every valid address is
// well below 2^63, the offset/size are small, and the ea+size ≤
// memSize comparison catches every out-of-range access. The only
// address that could wrap a u64 is one the guest deliberately computes
// near 2^64, which real (wasi-sdk-compiled) code never produces and
// which — even then — resolves within the module's own memory slice,
// never outside it. This matches wasm2go's existing bounds model.
func a64FusedMemCheck(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, span int, addr64 bool) error {
	if addr64 {
		if n.Args[0].Kind != simdfuse.ArgScalar {
			return fmt.Errorf("fused addr64 %s: folded base form", n.Op)
		}
		fmt.Fprintf(b, "\tMOVD %s, R25\n", scalarReg(n.Args[0]))
	} else {
		fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(n.Args[0]))
	}
	switch off := n.Args[1]; off.Kind {
	case simdfuse.ArgConst:
		if off.Const != 0 {
			if off.Const > 0 && off.Const < 4096 {
				fmt.Fprintf(b, "\tADD $%d, R25, R25\n", off.Const)
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(off.Const))
				b.WriteString("\tADD R26, R25, R25\n")
			}
		}
	case simdfuse.ArgScalar:
		if addr64 {
			fmt.Fprintf(b, "\tMOVD %s, R26\n", scalarReg(off))
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, R26\n", scalarReg(off))
		}
		b.WriteString("\tADD R26, R25, R25\n")
	default:
		return fmt.Errorf("fused %s: bad offset form", n.Op)
	}
	fmt.Fprintf(b, "\tADD $%d, R25, R27\n", span)
	b.WriteString("\tCMP R27, R21\n")
	fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	return nil
}

func a64FusedStore(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string,
	pairRegs func(simdfuse.Arg) (string, string), loc []fusedLoc, src int, addr64 bool) error {
	if len(n.Args) != 3 {
		return fmt.Errorf("fused store: %d args, want 3", len(n.Args))
	}
	span := 16
	if n.Op == "v128_f16x4_cvt_store" {
		span = 8
	}
	if addr64 {
		if err := a64FusedMemCheck(b, n, scalarReg, span, true); err != nil {
			return err
		}
	} else {
		// Address into R25 (same forms as a64FusedLoad).
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(b, "\tMOVD $%d, R25\n", int64(uint32(a.Const)))
		case simdfuse.ArgSum:
			if a.Const == 0 {
				fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
			} else if a.Const > 0 && a.Const < 4096 {
				fmt.Fprintf(b, "\tADDW $%d, %s, R25\n", a.Const, scalarReg(a))
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R22\n", int64(uint32(a.Const)))
				fmt.Fprintf(b, "\tADDW R22, %s, R25\n", scalarReg(a))
			}
		default:
			fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
		}
		if off := n.Args[1]; off.Kind == simdfuse.ArgConst {
			if off.Const != 0 {
				if off.Const > 0 && off.Const < 4096 {
					fmt.Fprintf(b, "\tADD $%d, R25, R25\n", off.Const)
				} else {
					fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(uint32(off.Const)))
					b.WriteString("\tADD R26, R25, R25\n")
				}
			}
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, R26\n", scalarReg(n.Args[1]))
			b.WriteString("\tADD R26, R25, R25\n")
		}
		fmt.Fprintf(b, "\tADD $%d, R25, R27\n", span)
		b.WriteString("\tCMP R27, R21\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	}
	if src < 0 {
		// Pair input: build into v1, which is dead between node bodies.
		lo, hi := pairRegs(n.Args[2])
		fmt.Fprintf(b, "\tFMOVD %s, F1\n", lo)
		fmt.Fprintf(b, "\tVMOV %s, V1.D[1]\n", hi)
		src = 1
	}
	if n.Op == "v128_f16x4_cvt_store" {
		// Convert the four f32 lanes to f16 with the software idiom's
		// exact semantics (hardware rounding for non-NaN; NaN forced
		// to sign|0x7E00) and store the packed 8 bytes. Scratch:
		// v1 conv, v2 non-NaN mask, v3 forced arm, v0 constants —
		// v0 is written only after its (possible) source reads.
		if src >= 1 && src <= 3 {
			a64VecCopy(b, 0, src)
			src = 0
		}
		word := func(enc uint32, dis string) {
			fmt.Fprintf(b, "\tWORD $0x%08x // %s\n", enc, dis)
		}
		word(0x0E216800|uint32(src)<<5|1, fmt.Sprintf("fcvtn v1.4h, v%d.4s", src))
		word(0x4E20E400|uint32(src)<<16|uint32(src)<<5|2, fmt.Sprintf("fcmeq v2.4s, v%d.4s, v%d.4s", src, src))
		word(0x6F300400|uint32(src)<<5|3, fmt.Sprintf("ushr v3.4s, v%d.4s, #16", src))
		word(0x4F042400, "movi v0.4s, #0x80, lsl #8")
		word(0x4E201C63, "and v3.16b, v3.16b, v0.16b")
		word(0x4F0327C0, "movi v0.4s, #0x7e, lsl #8")
		word(0x4EA01C63, "orr v3.16b, v3.16b, v0.16b")
		word(0x0E612842, "xtn v2.4h, v2.4s")
		word(0x0E612863, "xtn v3.4h, v3.4s")
		word(0x2E631C22, "bsl v2.8b, v1.8b, v3.8b")
		b.WriteString("\tADD R25, R20, R27\n")
		word(0xFC000000|uint32(27)<<5|2, "stur d2, [x27]")
		return nil
	}
	enc := 0x3CA06800 | uint32(25)<<16 | uint32(20)<<5 | uint32(src)
	fmt.Fprintf(b, "\tWORD $0x%08x // str q%d, [x20, x25]\n", enc, src)
	return nil
}

// a64FusedLaneAddr materializes a lane load's checked address:
// R25 = u32 effective address, bounds against a 4-byte window, and
// R27 = M-base plus address for the structure load (ld1 has no
// register-offset form).
func a64FusedLaneAddr(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, addr64 bool) error {
	if addr64 {
		if err := a64FusedMemCheck(b, n, scalarReg, 4, true); err != nil {
			return err
		}
		b.WriteString("\tADD R25, R20, R27\n")
		return nil
	}
	switch a := n.Args[0]; a.Kind {
	case simdfuse.ArgConst:
		fmt.Fprintf(b, "\tMOVD $%d, R25\n", int64(uint32(a.Const)))
	case simdfuse.ArgSum:
		if a.Const == 0 {
			fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
		} else if a.Const > 0 && a.Const < 4096 {
			fmt.Fprintf(b, "\tADDW $%d, %s, R25\n", a.Const, scalarReg(a))
		} else {
			fmt.Fprintf(b, "\tMOVD $%d, R22\n", int64(uint32(a.Const)))
			fmt.Fprintf(b, "\tADDW R22, %s, R25\n", scalarReg(a))
		}
	default:
		fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
	}
	if off := n.Args[1]; off.Kind == simdfuse.ArgConst {
		if off.Const != 0 {
			if off.Const > 0 && off.Const < 4096 {
				fmt.Fprintf(b, "\tADD $%d, R25, R25\n", off.Const)
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(uint32(off.Const)))
				b.WriteString("\tADD R26, R25, R25\n")
			}
		}
	} else {
		fmt.Fprintf(b, "\tMOVWU %s, R26\n", scalarReg(n.Args[1]))
		b.WriteString("\tADD R26, R25, R25\n")
	}
	b.WriteString("\tADD $4, R25, R27\n")
	b.WriteString("\tCMP R27, R21\n")
	fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	b.WriteString("\tADD R25, R20, R27\n")
	return nil
}

// a64FusedLoad emits one member load, result in v<dst>. The region
// prologue holds memSize in R21 and the M base in R20; scratch R22,
// R24–R27.
func a64FusedLoad(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, dst int, addr64 bool) error {
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
	// The address materializes into R25 as u32 — or full-width with a
	// carry-checked sum on a memory64 tree (whose addr/offset are
	// always opaque scalars; see a64FusedEA64). An ArgSum folds its
	// descriptor constant with one W-form add: ADDW wraps mod 2^32 and
	// zero-extends, exactly Add32.
	if addr64 {
		if n.Args[0].Kind != simdfuse.ArgScalar {
			return fmt.Errorf("fused addr64 load %s: folded address form", n.Op)
		}
		fmt.Fprintf(b, "\tMOVD %s, R25\n", scalarReg(n.Args[0]))
	} else {
		switch a := n.Args[0]; a.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(b, "\tMOVD $%d, R25\n", int64(uint32(a.Const)))
		case simdfuse.ArgSum:
			if a.Const == 0 {
				fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
			} else if a.Const > 0 && a.Const < 4096 {
				fmt.Fprintf(b, "\tADDW $%d, %s, R25\n", a.Const, scalarReg(a))
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R22\n", int64(uint32(a.Const)))
				fmt.Fprintf(b, "\tADDW R22, %s, R25\n", scalarReg(a))
			}
		default:
			fmt.Fprintf(b, "\tMOVWU %s, R25\n", scalarReg(a))
		}
	}
	// Add the memarg offset into the effective address in R25. Both
	// widths share this: a small bounded constant is a plain ADD; a
	// scalar offset is materialized then added. A memory64 base rides
	// in a full-width register (MOVD, above); the arithmetic is the
	// same as wasm32's. See a64FusedMemCheck for why no wrap guard is
	// needed.
	addOffErr := error(nil)
	addOff := func(i int) {
		if addr64 {
			a := n.Args[i]
			switch a.Kind {
			case simdfuse.ArgConst:
				if a.Const == 0 {
					return
				}
				if a.Const > 0 && a.Const < 4096 {
					fmt.Fprintf(b, "\tADD $%d, R25, R25\n", a.Const)
				} else {
					fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(a.Const))
					b.WriteString("\tADD R26, R25, R25\n")
				}
			case simdfuse.ArgScalar:
				fmt.Fprintf(b, "\tMOVD %s, R26\n", scalarReg(a))
				b.WriteString("\tADD R26, R25, R25\n")
			default:
				addOffErr = fmt.Errorf("fused addr64 load %s: bad offset form", n.Op)
			}
			return
		}
		reg, c, isConst := arg(i)
		if isConst {
			if c == 0 {
				return
			}
			if c > 0 && c < 4096 {
				fmt.Fprintf(b, "\tADD $%d, R25, R25\n", c)
				return
			}
			fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(uint32(c)))
			b.WriteString("\tADD R26, R25, R25\n")
			return
		}
		fmt.Fprintf(b, "\tMOVWU %s, R26\n", reg)
		b.WriteString("\tADD R26, R25, R25\n")
	}
	// The single bounds check, identical for both widths: trap unless
	// ea+size ≤ memSize. See a64FusedMemCheck's note on why memory64
	// needs no additional wrap guard here.
	checked := func(size int) {
		fmt.Fprintf(b, "\tADD $%d, R25, R27\n", size)
		b.WriteString("\tCMP R27, R21\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	}
	switch n.Op {
	case "v128_load":
		addOff(1)
		checked(16)
	case "v128_load32_zero":
		// ldr s<dst>, [x20, x25]: loads 4 bytes, upper lanes zeroed —
		// exactly the wasm op.
		addOff(1)
		checked(4)
		fmt.Fprintf(b, "\tFMOVS (R20)(R25), F%d\n", dst)
		return addOffErr
	case "v128_load32_splat":
		// 4-byte load broadcast to every lane: ldr s + dup.
		addOff(1)
		checked(4)
		fmt.Fprintf(b, "\tFMOVS (R20)(R25), F%d\n", dst)
		enc := 0x4E040400 | uint32(dst)<<5 | uint32(dst)
		fmt.Fprintf(b, "\tWORD $0x%08x // dup v%d.4s, v%d.s[0]\n", enc, dst, dst)
		return addOffErr
	case "v128_load16x4_u":
		// 8-byte load into the low half, then unsigned widen in place.
		// immh=0b0010 selects the 4h -> 4s widen (0x2F10A400, matching
		// the pair table); 0x2F08A400 is the 8b -> 8h form.
		addOff(1)
		checked(8)
		fmt.Fprintf(b, "\tFMOVD (R20)(R25), F%d\n", dst)
		enc := 0x2F10A400 | uint32(dst)<<5 | uint32(dst)
		fmt.Fprintf(b, "\tWORD $0x%08x // ushll v%d.4s, v%d.4h, #0\n", enc, dst, dst)
		return addOffErr
	case "v128_load_nc":
		addOff(1)
	case "v128_load_rng":
		if addr64 {
			// R25 = addr (full width). start = addr + rlo (rlo a small
			// signed const), trap on start<0 or start+span > memSize;
			// then ea = addr + offset. A NON-NEGATIVE rlo can never
			// make start negative (addr ≥ 0 under the 2^48 cap), so the
			// sign trap is emitted only for a negative rlo.
			_, rloC, rloConst := arg(2)
			_, spanC, spanConst := arg(3)
			if !rloConst || !spanConst {
				return fmt.Errorf("fused addr64 load %s: non-const rng window", n.Op)
			}
			startReg := "R26"
			switch {
			case rloC == 0:
				startReg = "R25"
			case rloC > 0 && rloC < 4096:
				fmt.Fprintf(b, "\tADD $%d, R25, R26\n", rloC)
			default:
				fmt.Fprintf(b, "\tMOVD $%d, R27\n", int64(rloC))
				b.WriteString("\tADD R27, R25, R26\n")
				if rloC < 0 {
					fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
				}
			}
			if spanC >= 0 && spanC < 4096 {
				fmt.Fprintf(b, "\tADD $%d, %s, R27\n", spanC, startReg)
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R27\n", int64(uint32(spanC)))
				fmt.Fprintf(b, "\tADD %s, R27, R27\n", startReg)
			}
			b.WriteString("\tCMP R27, R21\n")
			fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
			addOff(1)
			break
		}
		// start = u32(addr) + sxtw(rlo); trap on start<0 or
		// start+span > memSize; then ea = u32(addr)+u32(offset).
		// A non-negative constant rlo cannot make start negative
		// (u32(addr) >= 0), so the sign trap drops out and small
		// constants fold into the adds as immediates.
		rloReg, rloC, rloConst := arg(2)
		startReg := "R26"
		switch {
		case rloConst && rloC == 0:
			startReg = "R25"
		case rloConst && rloC > 0 && rloC < 4096:
			fmt.Fprintf(b, "\tADD $%d, R25, R26\n", rloC)
		case rloConst:
			fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(rloC))
			b.WriteString("\tADD R26, R25, R26\n")
			if rloC < 0 {
				fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
			}
		default:
			fmt.Fprintf(b, "\tMOVW %s, R26\n", rloReg)
			b.WriteString("\tADD R26, R25, R26\n")
			fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
		}
		spanReg, spanC, spanConst := arg(3)
		if spanConst && spanC >= 0 && spanC < 4096 {
			fmt.Fprintf(b, "\tADD $%d, %s, R27\n", spanC, startReg)
		} else if spanConst {
			fmt.Fprintf(b, "\tMOVD $%d, R27\n", int64(uint32(spanC)))
			fmt.Fprintf(b, "\tADD %s, R27, R27\n", startReg)
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, R27\n", spanReg)
			fmt.Fprintf(b, "\tADD %s, R27, R27\n", startReg)
		}
		b.WriteString("\tCMP R27, R21\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
		addOff(1)
	}
	// ldr q<dst>, [x20, x25] — the register-offset form the Go
	// assembler has no mnemonic for; one instruction instead of
	// ADD+FMOVQ.
	enc := 0x3CE06800 | uint32(25)<<16 | uint32(20)<<5 | uint32(dst)
	fmt.Fprintf(b, "\tWORD $0x%08x // ldr q%d, [x20, x25]\n", enc, dst)
	return addOffErr
}

// a64SpliceLoop synthesizes a whole fused countdown loop: prologue,
// carried values seeded into fixed registers, the region body under a
// local label, bumps and the counter test, then the exit epilogue.
// site disambiguates labels between splice sites in one function.
func a64SpliceLoop(b *strings.Builder, loop *simdfuse.Loop, pool *ConstPool, offs *ModuleOffsets, site string, portable bool) (bool, bool, error) {
	tree := loop.Tree
	if err := a64FusedProlog(b, tree, offs); err != nil {
		return false, false, err
	}
	if loop.Dec <= 0 || loop.Dec >= 4096 {
		return false, false, fmt.Errorf("fused loop %s: bad dec %d", tree.Name, loop.Dec)
	}
	carried := map[int]int{}
	var reserve []int
	pairBase := func(idx int) (string, string) {
		base := 1 + tree.NumScalars + 1 + loop.NumDeltas + 2*idx
		return a64FusedArgReg(base), a64FusedArgReg(base + 1)
	}
	for j, cp := range loop.CarriedPairs {
		r := 30 - j
		carried[cp[0]] = r
		reserve = append(reserve, r)
		lo, hi := pairBase(cp[0])
		fmt.Fprintf(b, "\tFMOVD %s, F%d\n", lo, r)
		fmt.Fprintf(b, "\tVMOV %s, V%d.D[1]\n", hi, r)
	}
	// Hoist the SDOT TBL-permutation constant: loop-invariant, one
	// fixed register below the carried block. If the carried block is
	// implausibly deep, fall back to lazy in-body materialization.
	// Fast math feeds SDOT raw sources — no permutation constant.
	sdotIdx := -1
	if r := 30 - len(loop.CarriedPairs); r >= 16 && !offs.fastMath() && a64TreeHasSdot(tree, portable, false) {
		sdotIdx = r
		reserve = append(reserve, r)
		a64EmitSdotIdx(b, r)
	}
	// Fast math: split the serial FMLA accumulator across two
	// registers (see a64DualAcc). Only the single-accumulator kernel
	// shape qualifies; the partner register takes the slot the SDOT
	// constant would have used.
	var dual *a64DualAcc
	if r := 30 - len(loop.CarriedPairs); r >= 16 && offs.fastMath() &&
		len(loop.CarriedPairs) == 1 && a64TreeFmlaCount(tree, portable, true) >= 2 {
		dual = &a64DualAcc{primary: 30, second: r}
		reserve = append(reserve, r)
		fmt.Fprintf(b, "\tWORD $0x%08x // movi v%d.4s, #0 (dual acc)\n", 0x4F000400|uint32(r), r)
	}
	counterReg := a64FusedArgReg(1 + loop.CounterScalar)
	// Counter width: an int64 counter uses the X-form compare,
	// subtract and branch (W forms otherwise).
	cmpOp, subOp, cbzOp, cbnzOp := "CMPW", "SUBW", "CBZW", "CBNZW"
	if loop.CounterWide {
		cmpOp, subOp, cbzOp, cbnzOp = "CMP", "SUB", "CBZ", "CBNZ"
	}
	// Hoist scale-table HOST bases (memory base + table offset) for
	// the lookup peephole: loop-invariant, one register each. R17/R19
	// are free inside the splice (every GPR is call-clobbered; R18 is
	// the platform register and stays untouched).
	lutHoist := map[int]string{}
	hoistRegs := []string{"R19", "R17"}
	for _, n := range tree.Nodes {
		if n.Op != "scalar_i32_add" || n.Args[1].Kind != simdfuse.ArgScalar {
			continue
		}
		si := n.Args[1].Index
		if _, done := lutHoist[si]; done || len(hoistRegs) == 0 {
			continue
		}
		r := hoistRegs[0]
		hoistRegs = hoistRegs[1:]
		// The table-base scalar is int64 on a memory64 tree; widen with
		// MOVD instead of the u32 MOVWU.
		if tree.Addr64 {
			fmt.Fprintf(b, "\tMOVD %s, %s\n", a64FusedArgReg(1+si), r)
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, %s\n", a64FusedArgReg(1+si), r)
		}
		fmt.Fprintf(b, "\tADD R20, %s, %s\n", r, r)
		lutHoist[si] = r
	}
	// One iteration step: the region body, carried write-back, bumps
	// and the counter decrement. Emitted once per unroll copy — the
	// order of every memory operation is exactly the sequential
	// program's, so a trap mid-copy leaves precisely the effects the
	// original would have committed.
	var loc []fusedLoc
	needsTrap := false
	step := func() error {
		var err error
		var trap bool
		loc, trap, err = a64SpliceFusedCoreLut(b, tree, pool, offs, carried, reserve, 1+loop.NumDeltas, true, lutHoist, sdotIdx, portable, dual)
		if err != nil {
			return err
		}
		needsTrap = needsTrap || trap
		for j, cp := range loop.CarriedPairs {
			src := 0
			if !loc[cp[1]].chained {
				src = loc[cp[1]].pool
			}
			a64VecCopy(b, 30-j, src)
		}
		// Bumps wrap mod 2^32 on wasm32 (W-form adds); an Addr64
		// loop's pointer scalars advance at full width instead. The
		// per-iteration bounds checks inside the body keep a runaway
		// pointer from ever being dereferenced.
		bumpAdd, bumpImm := "ADDW", "ADDW"
		if tree.Addr64 {
			bumpAdd, bumpImm = "ADD", "ADD"
		}
		for _, bump := range loop.Bumps {
			reg := a64FusedArgReg(1 + bump.Scalar)
			if bump.DeltaScalar >= 0 {
				dreg := a64FusedArgReg(1 + tree.NumScalars + 1 + bump.DeltaScalar)
				fmt.Fprintf(b, "\t%s %s, %s, %s\n", bumpAdd, dreg, reg, reg)
			} else if bump.Delta >= 0 && bump.Delta < 4096 {
				fmt.Fprintf(b, "\t%s $%d, %s, %s\n", bumpImm, bump.Delta, reg, reg)
			} else {
				fmt.Fprintf(b, "\tMOVD $%d, R22\n", int64(uint32(bump.Delta)))
				fmt.Fprintf(b, "\t%s R22, %s, %s\n", bumpAdd, reg, reg)
			}
		}
		fmt.Fprintf(b, "\t%s $%d, %s, %s\n", subOp, loop.Dec, counterReg, counterReg)
		return nil
	}
	unroll := offs.fuseLoopUnroll()
	loopLabel := "gcasmfxl" + site
	exitLabel := "gcasmfxlx" + site
	if unroll > 1 && loop.Dec < 4096/int32(unroll) {
		// Fast lane: process `unroll` iterations per branch while the
		// counter allows, then finish one at a time. Both lanes use
		// the same step emission, so semantics are the sequential
		// program's.
		mainLabel := "gcasmfxlm" + site
		tailLabel := "gcasmfxlt" + site
		fmt.Fprintf(b, "%s:\n", mainLabel)
		fmt.Fprintf(b, "\t%s $%d, %s\n", cmpOp, loop.Dec*int32(unroll), counterReg)
		fmt.Fprintf(b, "\tBLO %s\n", tailLabel)
		for k := 0; k < unroll; k++ {
			if err := step(); err != nil {
				return false, false, err
			}
		}
		fmt.Fprintf(b, "\tB %s\n", mainLabel)
		fmt.Fprintf(b, "%s:\n", tailLabel)
		if loop.PreTest {
			fmt.Fprintf(b, "\t%s $%d, %s\n", cmpOp, loop.Dec, counterReg)
			fmt.Fprintf(b, "\tBLO %s\n", exitLabel)
		} else {
			// Do-while callers guarantee a non-zero multiple of Dec, so
			// the fast lane may have consumed everything.
			fmt.Fprintf(b, "\t%s %s, %s\n", cbzOp, counterReg, exitLabel)
		}
		if err := step(); err != nil {
			return false, false, err
		}
		fmt.Fprintf(b, "\tB %s\n", tailLabel)
		fmt.Fprintf(b, "%s:\n", exitLabel)
	} else {
		fmt.Fprintf(b, "%s:\n", loopLabel)
		if loop.PreTest {
			fmt.Fprintf(b, "\t%s $%d, %s\n", cmpOp, loop.Dec, counterReg)
			fmt.Fprintf(b, "\tBLO %s\n", exitLabel)
		}
		if err := step(); err != nil {
			return false, false, err
		}
		if loop.PreTest {
			fmt.Fprintf(b, "\tB %s\n", loopLabel)
			fmt.Fprintf(b, "%s:\n", exitLabel)
		} else {
			fmt.Fprintf(b, "\t%s %s, %s\n", cbnzOp, counterReg, loopLabel)
		}
	}
	if dual != nil {
		enc := 0x4E20D400 | uint32(dual.second)<<16 | uint32(dual.primary)<<5 | uint32(dual.primary)
		fmt.Fprintf(b, "\tWORD $0x%08x // fadd v%d.4s, v%d.4s, v%d.4s (dual acc join)\n", enc, dual.primary, dual.primary, dual.second)
	}
	// Exit epilogue: final scalar values first (their result registers
	// sit above every source register — verified — so no move
	// clobbers a pending source), then the carried roots.
	roots := tree.RootList()
	moves := map[int]int{} // dst reg index -> src reg index
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
			return "MOVD"
		}
		return "MOVW"
	}
	emitParallelMoves(b, moves, func(dst, src int) string {
		return fmt.Sprintf("\t%s %s, %s\n", movFor(dst), a64FusedArgReg(src), a64FusedArgReg(dst))
	}, func(dst, src int) (string, string) {
		return fmt.Sprintf("\t%s %s, R22\n", movFor(dst), a64FusedArgReg(src)),
			fmt.Sprintf("\t%s R22, %s\n", movFor(dst), a64FusedArgReg(dst))
	})
	carriedOf := map[int]int{}
	for j, cp := range loop.CarriedPairs {
		carriedOf[cp[1]] = 30 - j
	}
	for k, r := range roots {
		src, ok := carriedOf[r]
		if !ok {
			src = 0
			if !loc[r].chained {
				src = loc[r].pool
			}
		}
		fmt.Fprintf(b, "\tFMOVD F%d, R%d\n", src, 2*k)
		fmt.Fprintf(b, "\tVMOV V%d.D[1], R%d\n", src, 2*k+1)
	}
	return true, needsTrap, nil
}

// emitParallelMoves realizes a register permutation/shuffle without
// clobbering pending sources: ready moves (destination not needed as
// any remaining source) first, one temp-register break per cycle.
func emitParallelMoves(b *strings.Builder, moves map[int]int,
	emit func(dst, src int) string, viaTemp func(dst, src int) (string, string)) {
	pending := map[int]int{}
	var order []int // sorted destinations: map order must not reach the output
	for d, s := range moves {
		if d != s {
			pending[d] = s
			order = append(order, d)
		}
	}
	sortInts(order)
	free := func(d int) bool {
		for _, os := range pending {
			if os == d {
				return false
			}
		}
		return true
	}
	// Emit every move whose destination no other pending move still
	// reads; repeat until only cycles remain.
	drain := func() {
		for progress := true; progress; {
			progress = false
			for _, d := range order {
				s, ok := pending[d]
				if !ok || !free(d) {
					continue
				}
				b.WriteString(emit(d, s))
				delete(pending, d)
				progress = true
			}
		}
	}
	drain()
	for len(pending) > 0 {
		// A cycle: break it through the temp register, starting from
		// the lowest pending destination.
		for _, d := range order {
			s, ok := pending[d]
			if !ok {
				continue
			}
			save, restore := viaTemp(d, s)
			b.WriteString(save)
			// Everything reading s now reads the temp; realize the rest
			// of the cycle, then land the temp.
			delete(pending, d)
			drain()
			b.WriteString(restore)
			break
		}
	}
}
