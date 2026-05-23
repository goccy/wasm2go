package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestBranchFold_ConstTrue: an `if (1)` keeps the then-branch, drops the
// else-branch, and leaves the now-unreachable else block removed.
func TestBranchFold_ConstTrue(t *testing.T) {
	b := ssa.NewFuncBuilder("bf", ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockRet)
	elseB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	cond := b.Const32(1)
	entry.Control = cond
	ssa.AddEdge(entry, thenB) // Succs[0] = then
	ssa.AddEdge(entry, elseB) // Succs[1] = else

	b.SetCurrent(thenB)
	b.FinishRet(b.Const32(10))
	b.SetCurrent(elseB)
	b.FinishRet(b.Const32(20))
	f := b.Func()

	if !BranchFold(f) {
		t.Fatal("BranchFold reported no change for if(1)")
	}
	if entry.Kind != ssa.BlockPlain {
		t.Errorf("entry kind = %v, want BlockPlain", entry.Kind)
	}
	if entry.Control != nil {
		t.Errorf("entry.Control not cleared")
	}
	if len(entry.Succs) != 1 || entry.Succs[0].Block != thenB {
		t.Errorf("entry should jump only to the then-block")
	}
	for _, blk := range f.Blocks {
		if blk == elseB {
			t.Errorf("unreachable else block was not removed")
		}
	}
	if err := ssa.Verify(f); err != nil {
		t.Errorf("verify after BranchFold: %v", err)
	}
}

// TestBranchFold_ConstFalse_PhiFixup: an `if (0)` into a merge block must
// drop the taken-from-then phi argument so the merge's phi still has one
// argument per surviving predecessor.
func TestBranchFold_ConstFalse_PhiFixup(t *testing.T) {
	b := ssa.NewFuncBuilder("bf2", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockPlain)
	elseB := b.NewBlock(ssa.BlockPlain)
	merge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	cond := b.Const32(0) // false → else taken
	entry.Control = cond
	ssa.AddEdge(entry, thenB)
	ssa.AddEdge(entry, elseB)

	b.SetCurrent(thenB)
	tv := b.Const32(1)        // value flowing from the then-branch
	ssa.AddEdge(thenB, merge) // merge.Preds[0] = then

	b.SetCurrent(elseB)
	ssa.AddEdge(elseB, merge) // merge.Preds[1] = else

	b.SetCurrent(merge)
	phi := b.NewValue(ssa.OpPhi, ssa.TypeI32, tv, p0) // phi(then, else)
	b.FinishRet(phi)
	f := b.Func()

	if !BranchFold(f) {
		t.Fatal("BranchFold reported no change for if(0)")
	}
	if entry.Kind != ssa.BlockPlain || len(entry.Succs) != 1 || entry.Succs[0].Block != elseB {
		t.Errorf("entry should jump only to the else-block")
	}
	for _, blk := range f.Blocks {
		if blk == thenB {
			t.Errorf("unreachable then block was not removed")
		}
	}
	if len(merge.Preds) != 1 {
		t.Fatalf("merge.Preds = %d, want 1", len(merge.Preds))
	}
	if len(phi.Args) != 1 || phi.Args[0] != p0 {
		t.Errorf("phi not fixed up: args=%d want [p0]", len(phi.Args))
	}
	if err := ssa.Verify(f); err != nil {
		t.Errorf("verify after BranchFold: %v", err)
	}
}
