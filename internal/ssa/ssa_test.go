package ssa

import (
	"strings"
	"testing"
)

// TestBuildSimple is the round-trip smoke test for the SSA package: build
// a tiny "add the two params and return" function, then assert the IR
// dump matches the expected canonical form. This is the foundation for
// every future pass golden test.
func TestBuildSimple(t *testing.T) {
	sig := FuncSig{Params: []Type{TypeI32, TypeI32}, Results: []Type{TypeI32}}
	b := NewFuncBuilder("add", sig)
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, TypeI32)
	p1 := b.Param(1, TypeI32)
	sum := b.NewValue(OpAdd32, TypeI32, p0, p1)
	b.FinishRet(sum)

	got := FuncString(b.Func())
	want := `func add(p0 i32, p1 i32) i32 {
  b0:
    v1 = OpParam [0] : i32
    v2 = OpParam [1] : i32
    v3 = OpAdd32 v1 v2 : i32
    v4 = OpCopy v3 : i32
    Ret
}
`
	if got != want {
		t.Errorf("FuncString mismatch.\n--want--\n%s\n--got--\n%s", want, got)
	}
}

// TestBuildCFG covers two-block + conditional branch, exercising
// Edge wiring and the If block dump.
func TestBuildCFG(t *testing.T) {
	sig := FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}}
	b := NewFuncBuilder("clamp_nonneg", sig)

	entry := b.NewBlock(BlockIf)
	thenBlk := b.NewBlock(BlockRet)
	elseBlk := b.NewBlock(BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	x := b.Param(0, TypeI32)
	zero := b.Const32(0)
	isNeg := b.NewValue(OpLtS32, TypeBool, x, zero)
	b.LinkIf(isNeg, thenBlk, elseBlk)

	b.SetCurrent(thenBlk)
	b.FinishRet(zero)

	b.SetCurrent(elseBlk)
	b.FinishRet(x)

	got := FuncString(b.Func())
	if !strings.Contains(got, "If v3 → b1, b2") {
		t.Errorf("missing If terminator in dump:\n%s", got)
	}
	if !strings.Contains(got, "preds= b0") {
		t.Errorf("missing preds in dump:\n%s", got)
	}
}
