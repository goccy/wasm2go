package pass

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestConstPropFoldsAdd builds an SSA function that adds two constants
// and verifies ConstProp collapses the OpAdd32 into a single OpConst32.
func TestConstPropFoldsAdd(t *testing.T) {
	sig := ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("addconst", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Const32(7)
	y := b.Const32(35)
	sum := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, y)
	b.FinishRet(sum)
	f := b.Func()

	if !ConstProp(f) {
		t.Fatalf("ConstProp returned false; expected a change")
	}

	dump := ssa.FuncString(f)
	if !strings.Contains(dump, "v3 = OpConst32 [42]") {
		t.Errorf("expected v3 folded to OpConst32 [42], got:\n%s", dump)
	}
	// Second run should be a no-op.
	if ConstProp(f) {
		t.Errorf("ConstProp should be idempotent at fixpoint")
	}
}

// TestConstPropFoldsComparison verifies that a comparison of two
// constants becomes a bool constant.
func TestConstPropFoldsComparison(t *testing.T) {
	sig := ssa.FuncSig{Results: []ssa.Type{ssa.TypeBool}}
	b := ssa.NewFuncBuilder("cmp", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Const32(5)
	y := b.Const32(10)
	lt := b.NewValue(ssa.OpLtS32, ssa.TypeBool, x, y)
	b.FinishRet(lt)
	f := b.Func()

	if !ConstProp(f) {
		t.Fatalf("expected ConstProp to change function")
	}
	dump := ssa.FuncString(f)
	if !strings.Contains(dump, "v3 = OpConst32 [1]") {
		t.Errorf("expected v3 to fold to bool=1; got:\n%s", dump)
	}
}

// TestConstPropLeavesUnknownAlone ensures values without all-constant
// arguments are left unchanged.
func TestConstPropLeavesUnknownAlone(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("partial", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p := b.Param(0, ssa.TypeI32)
	c := b.Const32(1)
	sum := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p, c)
	b.FinishRet(sum)
	f := b.Func()

	if ConstProp(f) {
		t.Errorf("ConstProp shouldn't fold a param + const")
	}
	dump := ssa.FuncString(f)
	if !strings.Contains(dump, "v3 = OpAdd32") {
		t.Errorf("OpAdd32 disappeared:\n%s", dump)
	}
}

// TestConstPropFoldsWidthConversions pins the unary folds: extends
// and truncations of integer constants become constants. The shapes
// rarely survive the wasm frontend alone but appear as soon as any
// pass substitutes a constant into an existing expression — and the
// amd64 emitter cannot encode `MOVLQSX $imm, reg`, so the fold
// doubles as a correctness backstop.
func TestConstPropFoldsWidthConversions(t *testing.T) {
	cases := []struct {
		op   ssa.Op
		in   int64
		out  int64
		outT ssa.Type
	}{
		{ssa.OpExtend32To64S, -1, -1, ssa.TypeI64},
		{ssa.OpExtend32To64S, 0x7FFFFFFF, 0x7FFFFFFF, ssa.TypeI64},
		{ssa.OpExtend32To64U, -1, 0xFFFFFFFF, ssa.TypeI64},
		{ssa.OpTrunc64To32, 0x1_0000_0005, 5, ssa.TypeI32},
		{ssa.OpTrunc64To32, -1, -1, ssa.TypeI32},
	}
	for _, tc := range cases {
		bb := ssa.NewFuncBuilder("f", ssa.FuncSig{Results: []ssa.Type{tc.outT}})
		b0 := bb.NewBlock(ssa.BlockRet)
		bb.SetEntry(b0)
		bb.SetCurrent(b0)
		var c *ssa.Value
		if tc.op == ssa.OpTrunc64To32 {
			c = bb.Const64(tc.in)
		} else {
			c = bb.Const32(int32(tc.in))
		}
		conv := bb.NewValue(tc.op, tc.outT, c)
		bb.FinishRet(conv)
		f := bb.Func()
		if !ConstProp(f) {
			t.Errorf("%v(%d): no fold", tc.op, tc.in)
			continue
		}
		if conv.Op != ssa.OpConst32 && conv.Op != ssa.OpConst64 {
			t.Errorf("%v(%d): folded to %v, want a constant", tc.op, tc.in, conv.Op)
			continue
		}
		got := conv.AuxInt
		if conv.Op == ssa.OpConst32 {
			got = int64(int32(got))
		}
		want := tc.out
		if tc.outT == ssa.TypeI32 {
			want = int64(int32(want))
		}
		if got != want {
			t.Errorf("%v(%d) = %d, want %d", tc.op, tc.in, got, want)
		}
	}
}
