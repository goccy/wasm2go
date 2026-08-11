package gcasm

// Pair-form SIMD splicing, arm64.
//
// The scalarized emitter carries v128 values as two uint64 locals and
// calls the simd_p_<op> wrappers, whose arguments therefore ride the
// register ABI: uint64 halves and int scalars in x0.., float scalars
// in s0/d0, results in (x0, x1) or a scalar register. Nothing touches
// the stack at all, which is the point — the splice tables' sequences
// move the pairs straight between GPRs and V registers around the op.
//
// The splice fires BEFORE callee resolution: a pair call that survived
// to a real CALL could not be marshalled (two results do not fit the
// single-result marshalling), so the emitter only produces pair calls
// for ops these tables cover (the simdPairOps contract, generated from
// the same source). A table miss here is therefore a build bug, and is
// reported as one rather than silently falling back.

import (
	"fmt"
	"strings"
)

// a64SplicePairOp reports whether sym is a pair-form SIMD helper call
// and returns the op name ("p_" stripped) plus the memory64 address
// width (see simdSpliceOp).
func a64SplicePairOp(sym string) (op string, addr64, ok bool) {
	op, addr64, ok = simdSpliceOp(sym) // strips Simd_/simd_ and m64_
	if !ok {
		return "", false, false
	}
	op, ok = strings.CutPrefix(op, "p_")
	return op, addr64, ok
}

// a64SplicePair emits the inline body for a pair-form SIMD call.
// Returns (spliced, needsTrap, err); a table miss is an error by the
// contract above.
func a64SplicePair(b *strings.Builder, op string, addr64 bool, pool *ConstPool, offs *ModuleOffsets) (bool, bool, error) {
	// The bounds-coalescing split forms have dedicated bodies: the
	// group-leading load carries the whole window's range check, the
	// other members drop theirs. On a memory64 module the args ride at
	// full width (MOVD) with a signed 64-bit start; wasm32 uses the
	// zero-extended MOVWU forms.
	switch op {
	case "v128_load_rng":
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets", op)
		}
		// (m, addr, offset, rlo, span) in R0..R4 → trap unless
		// [addr+rlo, addr+rlo+span) fits; pair of addr+offset in
		// (R0, R1). rlo is signed; a negative start means a group
		// member wrapped and must trap, matching the helper.
		if addr64 {
			b.WriteString("\tMOVD R1, R25\n")
			b.WriteString("\tADD R3, R25, R26\n")
			fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tADD R4, R26, R27\n")
			fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.MemSize)
			b.WriteString("\tMOVD (R26), R26\n")
			b.WriteString("\tCMP R27, R26\n")
			fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tADD R2, R25, R25\n")
			fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.M)
			b.WriteString("\tADD R25, R26, R27\n")
			b.WriteString("\tWORD $0xa9400760 // ldp x0, x1, [x27]\n")
			return true, true, nil
		}
		b.WriteString("\tMOVWU R1, R25\n")
		b.WriteString("\tMOVW R3, R26\n")
		b.WriteString("\tADD R26, R25, R26\n")
		fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
		b.WriteString("\tMOVWU R4, R27\n")
		b.WriteString("\tADD R27, R26, R27\n")
		fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.MemSize)
		b.WriteString("\tMOVD (R26), R26\n")
		b.WriteString("\tCMP R27, R26\n")
		fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
		b.WriteString("\tMOVWU R2, R26\n")
		b.WriteString("\tADD R26, R25, R25\n")
		fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.M)
		b.WriteString("\tADD R25, R26, R27\n")
		b.WriteString("\tWORD $0xa9400760 // ldp x0, x1, [x27]\n")
		return true, true, nil
	case "v128_load_nc":
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets", op)
		}
		// (m, addr, offset) in R0..R2 → pair in (R0, R1), no check.
		if addr64 {
			b.WriteString("\tADD R2, R1, R25\n")
			fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.M)
			b.WriteString("\tADD R25, R26, R27\n")
			b.WriteString("\tWORD $0xa9400760 // ldp x0, x1, [x27]\n")
			return true, false, nil
		}
		b.WriteString("\tMOVWU R1, R25\n")
		b.WriteString("\tMOVWU R2, R26\n")
		b.WriteString("\tADD R26, R25, R25\n")
		fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.M)
		b.WriteString("\tADD R25, R26, R27\n")
		b.WriteString("\tWORD $0xa9400760 // ldp x0, x1, [x27]\n")
		return true, false, nil
	}
	if lines, ok := a64SimdPairSpliceTab[op]; ok {
		lines, ok := simdSpliceRewriteConsts(lines, pool)
		if !ok {
			return false, false, fmt.Errorf("simd pair splice %s: unknown const reference", op)
		}
		for _, l := range lines {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		return true, false, nil
	}
	if ent, ok := a64SimdPairMemSpliceTab[op]; ok {
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets (probe missing from capture)", op)
		}
		for _, l := range ent.Pre {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		a64MemPreamble(b, ent.Size, offs, addr64)
		for _, l := range ent.Lines {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		return true, true, nil
	}
	return false, false, fmt.Errorf("simd pair splice: no table entry for %q", op)
}
