package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// buildF16GatherFunc constructs the scalar-load form of the f16
// table-gather idiom the way the llama module carries it: four
// i32.load16_u at base+0/2/4/6 (the +2k as explicit adds), each
// shifted by 2, offset by the table base (lane 0's table rides the
// zero-load's memarg), rebuilt into an f32x4 by lane loads.
func buildF16GatherFunc() (*ssa.Func, *ssa.Value, [3]*ssa.Value, [4]*ssa.Value) {
	b := ssa.NewFuncBuilder("Fn7", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}})
	f := b.Func()
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)

	base := b.NewValueAuxInt(ssa.OpParam, ssa.TypeI32, 0)
	c2 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 2)
	tbl := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 9013200)
	zero := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0)

	var lds [4]*ssa.Value
	var addrs [4]*ssa.Value
	for k := int64(0); k < 4; k++ {
		a := base
		if k > 0 {
			off := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 2*k)
			a = b.NewValue(ssa.OpAdd32, ssa.TypeI32, base, off)
		}
		lds[k] = b.NewValueAuxInt(ssa.OpLoad16U, ssa.TypeI32, 0, a)
		shl := b.NewValue(ssa.OpShl32, ssa.TypeI32, lds[k], c2)
		if k == 0 {
			addrs[k] = shl // table rides the zero-load's memarg
		} else {
			addrs[k] = b.NewValue(ssa.OpAdd32, ssa.TypeI32, shl, tbl)
		}
	}
	var loads [3]*ssa.Value
	loads[0] = b.NewValueAux(ssa.OpSimdMemCall, ssa.TypeV128, "simd_v128_load32_zero", addrs[0], tbl)
	prev := loads[0]
	var lanes [3]*ssa.Value
	for k := int64(1); k <= 3; k++ {
		lane := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, k)
		v := b.NewValueAux(ssa.OpSimdMemCall, ssa.TypeV128, "simd_v128_load32_lane", addrs[k], zero, lane, prev)
		if k < 3 {
			loads[k] = v
		} else {
			lanes[2] = v
		}
		prev = v
	}
	tail := prev
	// Keep the tail alive: extract a lane as the return value.
	l3 := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 3)
	res := b.NewValueAux(ssa.OpSimdCall, ssa.TypeI32, "simd_i32x4_extract_lane", tail, l3)
	entry.Control = res
	return f, tail, loads, lds
}

func TestRecognizeF16Gather(t *testing.T) {
	f, tail, loads, lds := buildF16GatherFunc()
	verified := 0
	ok := RecognizeF16Gather(f, func(base uint32) bool {
		verified++
		return base == 9013200
	})
	if !ok {
		t.Fatal("gather not recognized")
	}
	if verified == 0 {
		t.Error("table verification not consulted")
	}
	if tail.Op != ssa.OpSimdCall {
		t.Fatalf("tail op = %s, want OpSimdCall", tail.Op)
	}
	if n, _ := tail.Aux.(string); n != "simd_f16x4_cvt" {
		t.Fatalf("tail aux = %q, want simd_f16x4_cvt", tail.Aux)
	}
	if len(tail.Args) != 1 {
		t.Fatalf("tail args = %d, want 1", len(tail.Args))
	}
	v := tail.Args[0]
	if v.Op != ssa.OpSimdMemCall {
		t.Fatalf("source op = %s, want the synthesized widening load", v.Op)
	}
	if n, _ := v.Aux.(string); n != "simd_v128_load16x4_u" {
		t.Fatalf("source aux = %q, want simd_v128_load16x4_u", v.Aux)
	}
	// The inner lane loads are neutered to constants (they are pinned
	// mem ops DCE would otherwise keep), and the consumed scalar loads
	// become dead constants too.
	for i, l := range loads {
		if l.Op != ssa.OpSimdConst {
			t.Errorf("inner load %d: op = %s, want OpSimdConst", i, l.Op)
		}
	}
	for i, l := range lds {
		if l.Op != ssa.OpConst32 {
			t.Errorf("scalar load %d: op = %s, want OpConst32", i, l.Op)
		}
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("post-rewrite verify: %v", err)
	}
}

func TestRecognizeF16GatherUnverifiedTable(t *testing.T) {
	f, tail, _, _ := buildF16GatherFunc()
	if RecognizeF16Gather(f, func(uint32) bool { return false }) {
		t.Fatal("rewrite happened without table verification")
	}
	if tail.Op != ssa.OpSimdMemCall {
		t.Fatalf("tail mutated: %s", tail.Op)
	}
}
