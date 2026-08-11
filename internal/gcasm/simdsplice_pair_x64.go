package gcasm

// Pair-form SIMD splicing, amd64 — the SSE twin of
// simdsplice_pair_a64.go. Same contract: the scalarized emitter's
// simd_p_<op> calls arrive with everything in registers (uint64 halves
// and int scalars in AX, BX, CX, DI, SI, R8...; float scalars in X0),
// results in (AX, BX) or a scalar register, and the tables carry the
// complete inline body. The splice fires before callee resolution
// because a surviving two-result call has no marshalling.

import (
	"fmt"
	"strings"
)

// x64SimdMemTrapLabel is the per-function out-of-bounds stub label.
const x64SimdMemTrapLabel = "gcasmsimdoob"

// x64MemPreamble emits the effective-address computation and bounds
// check, leaving the checked HOST address in R11. m/addr/offset arrive
// in AX/BX/CX (ABIInternal). Clobbers R10–R12 and the flags — all dead
// at a call site — and preserves DI/SI/R8 (value and lane arguments).
// The ONLY width difference is the address/offset move: MOVL
// (zero-extend i32) on wasm32, MOVQ (full i64) on memory64. The
// arithmetic and bounds check are identical, and neither needs a wrap
// guard — see a64MemPreambleRegs (the arm64 twin).
func x64MemPreamble(b *strings.Builder, size int, offs *ModuleOffsets, addr64 bool) {
	movAddr := "MOVL"
	if addr64 {
		movAddr = "MOVQ"
	}
	fmt.Fprintf(b, "\t%s BX, R10\n", movAddr)
	fmt.Fprintf(b, "\t%s CX, R11\n", movAddr)
	b.WriteString("\tADDQ R11, R10\n")
	// if ea+size > m.memSize.Load() → trap. A plain aligned 64-bit
	// load is single-copy atomic on amd64; reading a pre-grow value
	// only fails MORE accesses.
	fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.MemSize)
	b.WriteString("\tMOVQ (R11), R11\n")
	fmt.Fprintf(b, "\tLEAQ %d(R10), R12\n", size)
	// amd64 Go asm compares first-minus-second: flags of
	// memSize-(ea+size); carry (unsigned borrow) ⇔ memSize < ea+size
	// ⇔ out of bounds.
	b.WriteString("\tCMPQ R11, R12\n")
	fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
	fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.M)
	b.WriteString("\tADDQ R10, R11\n")
}

// x64SplicePair emits the inline amd64 body for a pair-form SIMD call.
// Same contract as the arm64 twin: a table miss is a build error.
func x64SplicePair(b *strings.Builder, op string, addr64 bool, pool *ConstPool, offs *ModuleOffsets) (bool, bool, error) {
	// Bounds-coalescing split forms; see the arm64 twin. On a memory64
	// module the args ride at full width (MOVQ) with a signed 64-bit
	// start; wasm32 uses the zero-extended MOVL forms.
	switch op {
	case "v128_load_rng":
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets", op)
		}
		// (m, addr, offset, rlo, span) in AX, BX, CX, DI, SI → trap
		// unless [addr+rlo, addr+rlo+span) fits; pair of addr+offset
		// in (AX, BX). rlo is signed; ADDQ's sign flag catches a
		// negative start (a wrapped group member), matching the helper.
		if addr64 {
			b.WriteString("\tMOVQ BX, R10\n")
			b.WriteString("\tMOVQ DI, R11\n")
			b.WriteString("\tADDQ R10, R11\n")
			fmt.Fprintf(b, "\tJS %s\n", x64SimdMemTrapLabel)
			b.WriteString("\tMOVQ SI, R12\n")
			b.WriteString("\tADDQ R11, R12\n")
			fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.MemSize)
			b.WriteString("\tMOVQ (R11), R11\n")
			b.WriteString("\tCMPQ R11, R12\n")
			fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
			b.WriteString("\tADDQ CX, R10\n")
			fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.M)
			b.WriteString("\tADDQ R10, R11\n")
			b.WriteString("\tMOVQ (R11), AX\n")
			b.WriteString("\tMOVQ 8(R11), BX\n")
			return true, true, nil
		}
		b.WriteString("\tMOVL BX, R10\n")
		b.WriteString("\tMOVLQSX DI, R11\n")
		b.WriteString("\tADDQ R10, R11\n")
		fmt.Fprintf(b, "\tJS %s\n", x64SimdMemTrapLabel)
		b.WriteString("\tMOVL SI, R12\n")
		b.WriteString("\tADDQ R11, R12\n")
		fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.MemSize)
		b.WriteString("\tMOVQ (R11), R11\n")
		b.WriteString("\tCMPQ R11, R12\n")
		fmt.Fprintf(b, "\tJCS %s\n", x64SimdMemTrapLabel)
		b.WriteString("\tMOVL CX, R11\n")
		b.WriteString("\tADDQ R11, R10\n")
		fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.M)
		b.WriteString("\tADDQ R10, R11\n")
		b.WriteString("\tMOVQ (R11), AX\n")
		b.WriteString("\tMOVQ 8(R11), BX\n")
		return true, true, nil
	case "v128_load_nc":
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets", op)
		}
		// (m, addr, offset) in AX, BX, CX → pair in (AX, BX), no check.
		if addr64 {
			b.WriteString("\tMOVQ BX, R10\n")
			b.WriteString("\tADDQ CX, R10\n")
			fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.M)
			b.WriteString("\tADDQ R10, R11\n")
			b.WriteString("\tMOVQ (R11), AX\n")
			b.WriteString("\tMOVQ 8(R11), BX\n")
			return true, false, nil
		}
		b.WriteString("\tMOVL BX, R10\n")
		b.WriteString("\tMOVL CX, R11\n")
		b.WriteString("\tADDQ R11, R10\n")
		fmt.Fprintf(b, "\tMOVQ %d(AX), R11\n", offs.M)
		b.WriteString("\tADDQ R10, R11\n")
		b.WriteString("\tMOVQ (R11), AX\n")
		b.WriteString("\tMOVQ 8(R11), BX\n")
		return true, false, nil
	}
	if lines, ok := x64SimdPairSpliceTab[op]; ok {
		lines, ok := simdSpliceRewriteConsts(lines, pool)
		if !ok {
			return false, false, fmt.Errorf("simd pair splice %s: unknown const reference", op)
		}
		for _, l := range lines {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		return true, false, nil
	}
	if ent, ok := x64SimdPairMemSpliceTab[op]; ok {
		if offs == nil {
			return false, false, fmt.Errorf("simd pair splice %s: no Module offsets (probe missing from capture)", op)
		}
		for _, l := range ent.Pre {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		x64MemPreamble(b, ent.Size, offs, addr64)
		for _, l := range ent.Lines {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		return true, true, nil
	}
	return false, false, fmt.Errorf("simd pair splice: no amd64 table entry for %q", op)
}
