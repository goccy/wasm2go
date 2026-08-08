package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// buildF16StoreFunc constructs four lanes of the software fp32->fp16
// idiom, each fed by an extract_lane of one vector W and consumed by
// an i32.store16 — the store-side shape RecognizeF16Store matches.
// lanes selects which lane indices get a store (normally 0..3).
func buildF16StoreFunc(t *testing.T, lanes []int) (*ssa.Func, []*ssa.Value) {
	t.Helper()
	b := ssa.NewFuncBuilder("Fn7", ssa.FuncSig{Params: []ssa.Type{ssa.TypeV128}, Results: nil})
	f := b.Func()
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	W := b.NewValueAuxInt(ssa.OpParam, ssa.TypeV128, 0)

	prev := entry
	ors := make([]*ssa.Value, 0, len(lanes))
	for _, ln := range lanes {
		bIf1 := b.NewBlock(ssa.BlockIf)
		arm1a := b.NewBlock(ssa.BlockPlain)
		arm1b := b.NewBlock(ssa.BlockPlain)
		join1 := b.NewBlock(ssa.BlockIf)
		arm2a := b.NewBlock(ssa.BlockPlain)
		arm2b := b.NewBlock(ssa.BlockPlain)
		join2 := b.NewBlock(ssa.BlockPlain)

		b.SetCurrent(bIf1)
		laneC := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, int64(ln))
		fv := b.NewValueAux(ssa.OpSimdCall, ssa.TypeF32, "simd_f32x4_extract_lane", W, laneC)
		c1 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 1)
		c71 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0x71000000)
		w := b.NewValueAux(ssa.OpHelperCall, ssa.TypeI32, "i32_reinterpret_f32", fv)
		shl1 := b.NewValue(ssa.OpShl32, ssa.TypeI32, w, c1)
		cond1 := b.NewValue(ssa.OpLeU32, ssa.TypeBool, shl1, c71)
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
		ors = append(ors, b.NewValue(ssa.OpOr32, ssa.TypeI32, phi2, sign))

		ssa.AddEdge(prev, bIf1)
		ssa.AddEdge(bIf1, arm1a)
		ssa.AddEdge(bIf1, arm1b)
		ssa.AddEdge(arm1a, join1)
		ssa.AddEdge(arm1b, join1)
		ssa.AddEdge(join1, arm2a)
		ssa.AddEdge(join1, arm2b)
		ssa.AddEdge(arm2a, join2)
		ssa.AddEdge(arm2b, join2)
		prev = join2
	}

	last := b.NewBlock(ssa.BlockRet)
	ssa.AddEdge(prev, last)
	b.SetCurrent(last)
	stores := make([]*ssa.Value, 0, len(lanes))
	for i, or := range ors {
		addr := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, int64(1000+2*i))
		stores = append(stores, b.NewValue(ssa.OpStore16, ssa.TypeMem, addr, or))
	}
	return f, stores
}

func TestRecognizeF16StoreMergesContiguous(t *testing.T) {
	f, stores := buildF16StoreFunc(t, []int{0, 1, 2, 3})
	if !RecognizeF16Store(f) {
		t.Fatal("store idiom not recognized")
	}
	if !MergeF16Stores(f) {
		t.Fatal("contiguous group not merged")
	}
	// Contiguous lanes collapse into ONE 64-bit store of the packed
	// conversion at the anchor position; the other three stores leave
	// the block.
	var bits *ssa.Value
	live := map[*ssa.Value]bool{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			live[v] = true
			if v.Op == ssa.OpSimdCall {
				if n, _ := v.Aux.(string); n == "simd_f16x4_cvt_bits" {
					bits = v
				}
			}
		}
	}
	if bits == nil {
		t.Fatal("no simd_f16x4_cvt_bits inserted")
	}
	var merged *ssa.Value
	nLive := 0
	for k := 0; k < 4; k++ {
		if live[stores[k]] {
			nLive++
			merged = stores[k]
		}
	}
	if nLive != 1 {
		t.Fatalf("%d group stores live after merge, want 1", nLive)
	}
	if merged.Op != ssa.OpStore64 {
		t.Fatalf("merged op = %s, want Store64", merged.Op)
	}
	if merged.Args[1] != bits {
		t.Fatal("merged store must write the packed word")
	}
	if merged.Args[0] != stores[0].Args[0] {
		t.Fatal("merged store must use lane 0's address")
	}
}

func TestRecognizeF16StoreKeepsNonContiguous(t *testing.T) {
	f, stores := buildF16StoreFunc(t, []int{0, 1, 2, 3})
	// Spread the store addresses so the merge cannot fire; the
	// per-lane shift rewrite must still happen.
	for k, st := range stores {
		st.Args[0].AuxInt = int64(1000 + 16*k)
	}
	if !RecognizeF16Store(f) {
		t.Fatal("store idiom not recognized")
	}
	if MergeF16Stores(f) {
		t.Fatal("non-contiguous group must not merge")
	}
	if got := stores[0].Args[1].Op; got != ssa.OpTrunc64To32 {
		t.Errorf("lane0 value op = %s, want Trunc64To32", got)
	}
	if got := stores[1].Args[1].Op; got != ssa.OpShrU32 {
		t.Errorf("lane1 value op = %s, want ShrU32", got)
	}
	if stores[1].Args[1].Args[0] != stores[0].Args[1] {
		t.Error("lane1 must shift the low half")
	}
	for k, st := range stores {
		if st.Op != ssa.OpStore16 {
			t.Errorf("lane %d op = %s, want Store16 (no merge)", k, st.Op)
		}
	}
}

func TestRecognizeF16StoreNeedsAllLanes(t *testing.T) {
	f, _ := buildF16StoreFunc(t, []int{0, 1, 2})
	if RecognizeF16Store(f) {
		t.Fatal("incomplete lane group must not rewrite")
	}
}

func TestRecognizeF16StoreRejectsDuplicateLane(t *testing.T) {
	f, _ := buildF16StoreFunc(t, []int{0, 1, 2, 2})
	if RecognizeF16Store(f) {
		t.Fatal("duplicate lane must not rewrite")
	}
}

func TestFuseF16CvtStores(t *testing.T) {
	f, stores := buildF16StoreFunc(t, []int{0, 1, 2, 3})
	if !RecognizeF16Store(f) || !MergeF16Stores(f) {
		t.Fatal("prerequisite phases did not fire")
	}
	DCE(f) // the orphaned per-lane shifts still hold uses of the packed word
	if !FuseF16CvtStores(f) {
		t.Fatal("cvt-store fusion did not fire")
	}
	var merged *ssa.Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, st := range stores {
				if v == st {
					merged = v
				}
			}
		}
	}
	if merged == nil {
		t.Fatal("merged store vanished")
	}
	if merged.Op != ssa.OpSimdMemCall {
		t.Fatalf("op = %s, want SimdMemCall", merged.Op)
	}
	if n, _ := merged.Aux.(string); n != "simd_v128_f16x4_cvt_store" {
		t.Fatalf("aux = %v", merged.Aux)
	}
	if len(merged.Args) != 3 || merged.Args[2].Type != ssa.TypeV128 {
		t.Fatalf("args = %d, want [addr, off, W]", len(merged.Args))
	}
}
