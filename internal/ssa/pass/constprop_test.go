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
