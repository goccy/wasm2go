package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// buildMaskDiamond constructs
//
//	entry: If p0 -> thenB, elseB
//	thenB: -> join        (phi arg thenVal)
//	elseB: -> join        (phi arg elseVal)
//	join:  m = phi(...); If m -> retA, retB
//
// and returns the function pieces the assertions need.
func buildMaskDiamond(t *testing.T, thenVal, elseVal int32) (f *ssa.Func, entry, join *ssa.Block, cond *ssa.Value) {
	t.Helper()
	b := ssa.NewFuncBuilder("cmp", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry = b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockPlain)
	elseB := b.NewBlock(ssa.BlockPlain)
	join = b.NewBlock(ssa.BlockIf)
	retA := b.NewBlock(ssa.BlockRet)
	retB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	cond = b.Param(0, ssa.TypeI32)
	tv := b.Const32(thenVal)
	ev := b.Const32(elseVal)
	b.LinkIf(cond, thenB, elseB)

	b.SetCurrent(thenB)
	b.LinkPlain(join)
	b.SetCurrent(elseB)
	b.LinkPlain(join)

	b.SetCurrent(join)
	m := b.NewValue(ssa.OpPhi, ssa.TypeI32, tv, ev)
	b.LinkIf(m, retA, retB)

	b.SetCurrent(retA)
	b.FinishRet(b.Const32(10))
	b.SetCurrent(retB)
	b.FinishRet(b.Const32(20))
	return b.Func(), entry, join, cond
}

// TestFoldCondMaskPhi_MaskThenNonzero: If(phi(-1, 0)) branches on the
// diamond's own condition afterwards — the shape perl 5.44 produces that
// the Go arm64 backend cannot assemble.
func TestFoldCondMaskPhi_MaskThenNonzero(t *testing.T) {
	f, _, join, cond := buildMaskDiamond(t, -1, 0)
	if !FoldCondMaskPhi(f) {
		t.Fatal("FoldCondMaskPhi reported no change")
	}
	if join.Control != cond {
		t.Errorf("join.Control = %v, want the diamond condition", join.Control)
	}
	if err := ssa.Verify(f); err != nil {
		t.Errorf("verify after fold: %v", err)
	}
}

// TestFoldCondMaskPhi_OneZeroMask: the 1/0 flavor folds the same way.
func TestFoldCondMaskPhi_OneZeroMask(t *testing.T) {
	f, _, join, cond := buildMaskDiamond(t, 1, 0)
	if !FoldCondMaskPhi(f) {
		t.Fatal("FoldCondMaskPhi reported no change")
	}
	if join.Control != cond {
		t.Errorf("join.Control = %v, want the diamond condition", join.Control)
	}
}

// TestFoldCondMaskPhi_InvertedMaskSkipped: then=0/else=-1 would need a
// negated condition; the pass must leave it alone.
func TestFoldCondMaskPhi_InvertedMaskSkipped(t *testing.T) {
	f, _, join, cond := buildMaskDiamond(t, 0, -1)
	if FoldCondMaskPhi(f) {
		t.Fatal("FoldCondMaskPhi changed an inverted mask")
	}
	if join.Control == cond {
		t.Errorf("inverted mask must not branch on the raw condition")
	}
}

// TestFoldCondMaskPhi_NonConstArmSkipped: a phi with a non-constant arm
// is not a mask.
func TestFoldCondMaskPhi_NonConstArmSkipped(t *testing.T) {
	b := ssa.NewFuncBuilder("cmp2", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockPlain)
	elseB := b.NewBlock(ssa.BlockPlain)
	join := b.NewBlock(ssa.BlockIf)
	retA := b.NewBlock(ssa.BlockRet)
	retB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	cond := b.Param(0, ssa.TypeI32)
	other := b.Param(1, ssa.TypeI32)
	zero := b.Const32(0)
	b.LinkIf(cond, thenB, elseB)
	b.SetCurrent(thenB)
	b.LinkPlain(join)
	b.SetCurrent(elseB)
	b.LinkPlain(join)
	b.SetCurrent(join)
	m := b.NewValue(ssa.OpPhi, ssa.TypeI32, other, zero)
	b.LinkIf(m, retA, retB)
	b.SetCurrent(retA)
	b.FinishRet(b.Const32(10))
	b.SetCurrent(retB)
	b.FinishRet(b.Const32(20))

	if FoldCondMaskPhi(b.Func()) {
		t.Fatal("FoldCondMaskPhi changed a non-constant mask")
	}
}

// TestFoldCondMaskPhi_TriangleForm: one phi input arrives straight from
// the head (no arm block) — the else edge here — and still folds.
func TestFoldCondMaskPhi_TriangleForm(t *testing.T) {
	b := ssa.NewFuncBuilder("cmp3", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockPlain)
	join := b.NewBlock(ssa.BlockIf)
	retA := b.NewBlock(ssa.BlockRet)
	retB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	cond := b.Param(0, ssa.TypeI32)
	tv := b.Const32(-1)
	ev := b.Const32(0)
	b.LinkIf(cond, thenB, join) // else edge goes straight to the join

	b.SetCurrent(thenB)
	b.LinkPlain(join)

	b.SetCurrent(join)
	// Preds order: entry (else edge) first, thenB second.
	m := b.NewValue(ssa.OpPhi, ssa.TypeI32, ev, tv)
	b.LinkIf(m, retA, retB)
	b.SetCurrent(retA)
	b.FinishRet(b.Const32(10))
	b.SetCurrent(retB)
	b.FinishRet(b.Const32(20))
	f := b.Func()

	if !FoldCondMaskPhi(f) {
		t.Fatal("FoldCondMaskPhi reported no change for triangle form")
	}
	if join.Control != cond {
		t.Errorf("join.Control = %v, want the diamond condition", join.Control)
	}
	if err := ssa.Verify(f); err != nil {
		t.Errorf("verify after fold: %v", err)
	}
}
