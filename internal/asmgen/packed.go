package asmgen

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Packed outlined boundaries: the caller writes each boundary value
// into the Module's outline-pack scratch array and passes only the
// module pointer; the callee prologue drains the slots. The array's
// byte offset within the Module struct is pinned by construction the
// same way moduleMOffset is — the codegen translator declares
// memory / maxMem / M / outlinePack as the leading fields precisely
// so generated assembly can hardcode them.
const packedSlotBase = moduleMOffset + 8

// packedParamValue finds the OpParam value for index idx, or nil when
// the body never reads that parameter (the load is then skipped; the
// pack slot still advances).
func packedParamValue(f *ssa.Func, idx int) *ssa.Value {
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if v.Op == ssa.OpParam && int(v.AuxInt) == idx {
				return v
			}
		}
	}
	return nil
}

// packedSlotWords returns how many pack words a parameter type
// occupies (v128 rides as two).
func packedSlotWords(t ssa.Type) int {
	if t == ssa.TypeV128 {
		return 2
	}
	return 1
}

func (archAMD64) EmitPackedPrologue(b *strings.Builder, f *ssa.Func, plan *funcPlan) error {
	// m stays in AX through the whole prologue: no calls, no other
	// emitters run in between.
	fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
	slot := 0
	for idx, t := range plan.packedParams {
		pv := packedParamValue(f, idx)
		words := packedSlotWords(t)
		if pv == nil {
			slot += words
			continue
		}
		base := packedSlotBase + 8*slot
		dst := plan.offsets[pv.ID]
		switch t {
		case ssa.TypeI32, ssa.TypeF32:
			// The pack word holds the value bits zero-extended; the
			// low 4 bytes are the value (floats as raw bits).
			fmt.Fprintf(b, "\tMOVL %d(AX), CX\n", base)
			fmt.Fprintf(b, "\tMOVL CX, %d(SP)\n", dst)
		case ssa.TypeI64, ssa.TypeF64:
			fmt.Fprintf(b, "\tMOVQ %d(AX), CX\n", base)
			fmt.Fprintf(b, "\tMOVQ CX, %d(SP)\n", dst)
		case ssa.TypeV128:
			fmt.Fprintf(b, "\tMOVQ %d(AX), CX\n", base)
			fmt.Fprintf(b, "\tMOVQ CX, %d(SP)\n", dst)
			fmt.Fprintf(b, "\tMOVQ %d(AX), CX\n", base+8)
			fmt.Fprintf(b, "\tMOVQ CX, %d(SP)\n", dst+8)
		default:
			return fmt.Errorf("packed param %d type %v not supported", idx, t)
		}
		slot += words
	}
	return nil
}

func (archARM64) EmitPackedPrologue(b *strings.Builder, f *ssa.Func, plan *funcPlan) error {
	fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
	slot := 0
	for idx, t := range plan.packedParams {
		pv := packedParamValue(f, idx)
		words := packedSlotWords(t)
		if pv == nil {
			slot += words
			continue
		}
		base := packedSlotBase + 8*slot
		dst := plan.offsets[pv.ID]
		switch t {
		case ssa.TypeI32, ssa.TypeF32:
			fmt.Fprintf(b, "\tMOVWU %d(R0), R1\n", base)
			fmt.Fprintf(b, "\tMOVW R1, %d(RSP)\n", dst)
		case ssa.TypeI64, ssa.TypeF64:
			fmt.Fprintf(b, "\tMOVD %d(R0), R1\n", base)
			fmt.Fprintf(b, "\tMOVD R1, %d(RSP)\n", dst)
		case ssa.TypeV128:
			fmt.Fprintf(b, "\tMOVD %d(R0), R1\n", base)
			fmt.Fprintf(b, "\tMOVD R1, %d(RSP)\n", dst)
			fmt.Fprintf(b, "\tMOVD %d(R0), R1\n", base+8)
			fmt.Fprintf(b, "\tMOVD R1, %d(RSP)\n", dst+8)
		default:
			return fmt.Errorf("packed param %d type %v not supported", idx, t)
		}
		slot += words
	}
	return nil
}
