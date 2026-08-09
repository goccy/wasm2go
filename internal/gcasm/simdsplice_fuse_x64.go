package gcasm

// Fused-region splicing, amd64 — the SSE twin of
// simdsplice_fuse_a64.go. Same synthesis: table bodies verbatim
// (operands in X0..X2, scratch within X0..X3, result in X0), operand
// builds and result moves replaced by MOVOU register copies, parked
// values in X8..X14 (X15 is the ABI zero register). Fused arguments
// ride AX,BX,CX,DI,SI,R8,R9 (fusedMaxIntRegs=7 exists exactly so the
// load scratch R10–R12 stays free); m is saved to R13 because table
// cores stage scalars through AX.

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

var x64FusedArgRegs = []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}

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
func x64SpliceFused(b *strings.Builder, tree *simdfuse.Tree, pool *ConstPool, offs *ModuleOffsets, maxOut int) (bool, bool, error) {
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
	for x := poolTop; x >= 4; x-- {
		if !reservedX[x] {
			freePool = append(freePool, x)
		}
	}
	needsTrap := false

	chains := newX64ScalarChain(b, tree, scalarReg, offs, uses)

	for i, n := range tree.Nodes {
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
			if err := x64FusedStore(b, n, scalarReg, pairRegs, offs, pool, tree.Addr64, dst0Src(loc, n)); err != nil {
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
			if err := x64FusedLaneAddr(b, n, scalarReg, offs, tree.Addr64); err != nil {
				return nil, false, err
			}
			fmt.Fprintf(b, "\tPINSRD $%d, (AX)(R12*1), X%d\n", uint32(n.Args[2].Const)&3, dst)
			needsTrap = true
			loc[i] = fusedLoc{chained: willChain, pool: dst}
			continue
		}
		if _, isMem := fusedMemOpsA64[n.Op]; isMem {
			if err := x64FusedLoad(b, n, scalarReg, offs, dst, tree.Addr64); err != nil {
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
				lo, hi := pairRegs(a)
				fmt.Fprintf(b, "\tMOVQ %s, X1\n", lo)
				fmt.Fprintf(b, "\tPINSRQ $1, %s, X1\n", hi)
				src = 1
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
					lo, hi := pairRegs(a)
					fmt.Fprintf(b, "\tMOVQ %s, X%d\n", lo, dst)
					fmt.Fprintf(b, "\tPINSRQ $1, %s, X%d\n", hi, dst)
				}
			}
			if sArg != nil {
				if sArg.Kind == simdfuse.ArgConst {
					fmt.Fprintf(b, "\tMOVQ $%d, AX\n", int64(sArg.Const))
				} else {
					fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(*sArg))
				}
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
func x64FusedLoad(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, dst int, addr64 bool) error {
	if addr64 && (n.Op == "v128_load_rng" || n.Op == "v128_load_nc") {
		// Bounds coalescing is wasm32-only; these split forms cannot
		// reach a memory64 tree.
		return fmt.Errorf("fused addr64 load %s: coalesced form", n.Op)
	}
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
	if addr64 {
		if n.Args[0].Kind != simdfuse.ArgScalar {
			return fmt.Errorf("fused addr64 load %s: folded address form", n.Op)
		}
		fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(n.Args[0]))
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
			if n.Args[i].Kind != simdfuse.ArgScalar {
				addOffErr = fmt.Errorf("fused addr64 load %s: folded offset form", n.Op)
				return
			}
			fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(n.Args[i]))
			b.WriteString("\tADDQ AX, R12\n")
			fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
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
		if addr64 {
			fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		}
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
		fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(rloC))
		fmt.Fprintf(b, "\tJS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tADDQ $%d, R12\n", int64(uint32(spanC)))
		loadMemSize()
		b.WriteString("\tCMPQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tSUBQ $%d, R12\n", int64(rloC)+int64(uint32(spanC)))
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
func x64FusedLaneAddr(b *strings.Builder, n simdfuse.Node, scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, addr64 bool) error {
	if addr64 {
		if n.Args[0].Kind != simdfuse.ArgScalar || n.Args[1].Kind != simdfuse.ArgScalar {
			return fmt.Errorf("fused addr64 lane %s: folded address form", n.Op)
		}
		fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(n.Args[0]))
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(n.Args[1]))
		b.WriteString("\tADDQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		b.WriteString("\tADDQ $4, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
		b.WriteString("\tMOVQ (AX), AX\n")
		b.WriteString("\tCMPQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		b.WriteString("\tSUBQ $4, R12\n")
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.M)
		return nil
	}
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
	pairRegs func(simdfuse.Arg) (string, string), offs *ModuleOffsets, pool *ConstPool, addr64 bool, src int) error {
	if len(n.Args) != 3 {
		return fmt.Errorf("fused store: %d args, want 3", len(n.Args))
	}
	if addr64 {
		if n.Args[0].Kind != simdfuse.ArgScalar || n.Args[1].Kind != simdfuse.ArgScalar {
			return fmt.Errorf("fused addr64 store %s: folded address form", n.Op)
		}
		span := 16
		if n.Op == "v128_f16x4_cvt_store" {
			span = 8
		}
		fmt.Fprintf(b, "\tMOVQ %s, R12\n", scalarReg(n.Args[0]))
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", scalarReg(n.Args[1]))
		b.WriteString("\tADDQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tADDQ $%d, R12\n", span)
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tMOVQ %d(R13), AX\n", offs.MemSize)
		b.WriteString("\tMOVQ (AX), AX\n")
		b.WriteString("\tCMPQ AX, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		fmt.Fprintf(b, "\tSUBQ $%d, R12\n", span)
		return x64FusedStoreTail(b, n, pairRegs, offs, pool, src)
	}
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
	return nil}

// x64SpliceLoop is the amd64 fused-loop synthesizer; see the arm64
// twin for the structure.
func x64SpliceLoop(b *strings.Builder, loop *simdfuse.Loop, pool *ConstPool, offs *ModuleOffsets, site string, maxOut int) (bool, bool, error) {
	tree := loop.Tree
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
	return true, needsTrap, nil
}
