package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// buildF16IdiomFunc constructs the software fp32→fp16 idiom the way
// the wasm lowering produces it: two branch diamonds with phis, float
// arithmetic as f32_* helper calls, reinterprets as helper calls.
func buildF16IdiomFunc(t *testing.T) (*ssa.Func, *ssa.Value, *ssa.Value) {
	b := ssa.NewFuncBuilder("Fn5", ssa.FuncSig{Params: []ssa.Type{ssa.TypeF32}, Results: []ssa.Type{ssa.TypeI32}})
	f := b.Func()
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	bIf1 := b.NewBlock(ssa.BlockIf)
	arm1a := b.NewBlock(ssa.BlockPlain)
	arm1b := b.NewBlock(ssa.BlockPlain)
	join1 := b.NewBlock(ssa.BlockIf)
	arm2a := b.NewBlock(ssa.BlockPlain)
	arm2b := b.NewBlock(ssa.BlockPlain)
	join2 := b.NewBlock(ssa.BlockRet)

	b.SetCurrent(entry)
	fv := b.NewValueAuxInt(ssa.OpParam, ssa.TypeF32, 0)
	c1 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 1)
	c71 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x71000000)
	w := b.NewValueAux(ssa.OpHelperCall, ssa.TypeI32, "i32_reinterpret_f32", fv)
	shl1 := b.NewValue(ssa.OpShl32, ssa.TypeI32, w, c1)
	cond1 := b.NewValue(ssa.OpLeU32, ssa.TypeBool, shl1, c71)
	_ = cond1

	bIf1.Control = cond1

	b.SetCurrent(join1)
	bias := b.NewValue(ssa.OpPhi, ssa.TypeI32, c71, shl1)

	cSh1 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 1)
	cExpM := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x7F800000)
	cBias := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x07800000)
	cInf := b.NewValueAux(ssa.OpConstF32, ssa.TypeF32, float32(5.192296858534828e+33))
	cInf.AuxInt = 0x77800000
	cZero := b.NewValueAux(ssa.OpConstF32, ssa.TypeF32, float32(7.703719777548943e-34))
	cZero.AuxInt = 0x08800000
	abs := b.NewValueAux(ssa.OpHelperCall, ssa.TypeF32, "f32_abs", fv)
	m1 := b.NewValueAux(ssa.OpHelperCall, ssa.TypeF32, "f32_mul", abs, cInf)
	m2 := b.NewValueAux(ssa.OpHelperCall, ssa.TypeF32, "f32_mul", m1, cZero)
	biasBits := b.NewValue(ssa.OpAdd32, ssa.TypeI32,
		b.NewValue(ssa.OpAnd32, ssa.TypeI32,
			b.NewValue(ssa.OpShrU32, ssa.TypeI32, bias, cSh1), cExpM), cBias)
	biasF := b.NewValueAux(ssa.OpHelperCall, ssa.TypeF32, "f32_reinterpret_i32", biasBits)
	base := b.NewValueAux(ssa.OpHelperCall, ssa.TypeF32, "f32_add", m2, biasF)
	v := b.NewValueAux(ssa.OpHelperCall, ssa.TypeI32, "i32_reinterpret_f32", base)
	cM16m := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, -16777216)
	cond2 := b.NewValue(ssa.OpLtU32, ssa.TypeBool, cM16m, shl1)
	join1.Control = cond2

	c13 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 13)
	c7C := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x7C00)
	cFFF := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0xFFF)
	nonsign := b.NewValue(ssa.OpAdd32, ssa.TypeI32,
		b.NewValue(ssa.OpAnd32, ssa.TypeI32,
			b.NewValue(ssa.OpShrU32, ssa.TypeI32, v, c13), c7C),
		b.NewValue(ssa.OpAnd32, ssa.TypeI32, v, cFFF))
	c7E := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x7E00)

	b.SetCurrent(join2)
	phi2 := b.NewValue(ssa.OpPhi, ssa.TypeI32, c7E, nonsign)
	c16 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 16)
	c8000 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x8000)
	sign := b.NewValue(ssa.OpAnd32, ssa.TypeI32,
		b.NewValue(ssa.OpShrU32, ssa.TypeI32, w, c16), c8000)
	root := b.NewValue(ssa.OpOr32, ssa.TypeI32, phi2, sign)

	ssa.AddEdge(entry, bIf1)
	ssa.AddEdge(bIf1, arm1a)
	ssa.AddEdge(bIf1, arm1b)
	ssa.AddEdge(arm1a, join1)
	ssa.AddEdge(arm1b, join1)
	ssa.AddEdge(join1, arm2a)
	ssa.AddEdge(join1, arm2b)
	ssa.AddEdge(arm2a, join2)
	ssa.AddEdge(arm2b, join2)
	return f, root, phi2
}

func TestRecognizeF32ToF16Rewrites(t *testing.T) {
	f, _, phi2 := buildF16IdiomFunc(t)
	if !RecognizeF32ToF16(f) {
		t.Fatal("idiom not recognized")
	}
	// The non-NaN phi arm must now be helper&0x7FFF.
	var arm *ssa.Value
	for _, a := range phi2.Args {
		if a.Op != ssa.OpConst32 {
			arm = a
		}
	}
	if arm == nil || arm.Op != ssa.OpAnd32 {
		t.Fatalf("phi arm not rewritten: %v", arm)
	}
	foundHelper := false
	for _, a := range arm.Args {
		if a.Op == ssa.OpHelperCall {
			if name, _ := a.Aux.(string); name == "f32_to_f16_bits" {
				foundHelper = true
			}
		}
	}
	if !foundHelper {
		t.Fatal("rewritten arm does not call f32_to_f16_bits")
	}
}

func TestRecognizeF32ToF16RejectsWrongConst(t *testing.T) {
	f, root, _ := buildF16IdiomFunc(t)
	// Perturb the sign mask: no longer the idiom.
	for _, a := range root.Args {
		if a.Op == ssa.OpAnd32 {
			for _, aa := range a.Args {
				if aa.Op == ssa.OpConst32 && aa.AuxInt == 0x8000 {
					aa.AuxInt = 0x4000
				}
			}
		}
	}
	if RecognizeF32ToF16(f) {
		t.Fatal("perturbed graph was still rewritten")
	}
}
