package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestSplitCriticalEdgesNoOp confirms the pass is a no-op when no
// critical edge exists. We build a single-block function (entry is
// BlockRet) and check the split count is 0 and Blocks is unchanged.
func TestSplitCriticalEdgesNoOp(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("noop", fsig)
	b0 := b.NewBlock(ssa.BlockRet)
	b.SetEntry(b0)
	b.SetCurrent(b0)
	x := b.Param(0, ssa.TypeI32)
	b.FinishRet(x)

	f := b.Func()
	before := len(f.Blocks)
	if got := SplitCriticalEdges(f); got != 0 {
		t.Errorf("SplitCriticalEdges on a single-block func returned %d splits, want 0", got)
	}
	if len(f.Blocks) != before {
		t.Errorf("Blocks count changed: %d → %d", before, len(f.Blocks))
	}
}

// TestSplitCriticalEdgesSimpleDiamond covers the canonical no-critical
// case: a 4-block diamond `if x { then } else { else }` joining at a
// merge. The then and else blocks each have one pred (the test block,
// which has 2 succs) and one succ (the merge, which has 2 preds). No
// edge is critical — the test→then edge has src.Succs=2, dst.Preds=1
// (the then block); the then→merge edge has src.Succs=1, dst.Preds=2.
// Neither qualifies.
func TestSplitCriticalEdgesSimpleDiamond(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("diamond", fsig)
	bIf := b.NewBlock(ssa.BlockIf)
	bThen := b.NewBlock(ssa.BlockPlain)
	bElse := b.NewBlock(ssa.BlockPlain)
	bMerge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(bIf)

	b.SetCurrent(bIf)
	x := b.Param(0, ssa.TypeI32)
	b.LinkIf(x, bThen, bElse)

	b.SetCurrent(bThen)
	b.LinkPlain(bMerge)
	b.SetCurrent(bElse)
	b.LinkPlain(bMerge)

	b.SetCurrent(bMerge)
	b.FinishRet(x)

	f := b.Func()
	if got := SplitCriticalEdges(f); got != 0 {
		t.Errorf("simple diamond should have NO critical edges, got %d splits", got)
	}
}

// TestSplitCriticalEdgesIfDirectToMerge is the classic critical-edge
// case. Source: BlockIf with two successors, one of which IS the merge
// block (no intermediate then/else). The edge BlockIf → merge has
// src.Succs=2 AND dst.Preds=2, so it's critical and must be split.
func TestSplitCriticalEdgesIfDirectToMerge(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("crit", fsig)
	bIf := b.NewBlock(ssa.BlockIf)
	bThen := b.NewBlock(ssa.BlockPlain)
	bMerge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(bIf)

	b.SetCurrent(bIf)
	x := b.Param(0, ssa.TypeI32)
	// Then arm goes through bThen; else arm goes DIRECTLY to bMerge.
	b.LinkIf(x, bThen, bMerge)

	b.SetCurrent(bThen)
	b.LinkPlain(bMerge)

	b.SetCurrent(bMerge)
	b.FinishRet(x)

	f := b.Func()
	beforeBlocks := len(f.Blocks)
	got := SplitCriticalEdges(f)
	if got != 1 {
		t.Errorf("expected exactly 1 critical edge to split (bIf → bMerge), got %d", got)
	}
	if len(f.Blocks) != beforeBlocks+1 {
		t.Errorf("expected Blocks to grow by 1 (the synthetic block), got %d → %d", beforeBlocks, len(f.Blocks))
	}

	// Structural check: bIf's else successor (Succs[1]) should now
	// point at a synthetic BlockPlain, and that synthetic block's
	// single successor should be bMerge.
	if bIf.Succs[1].Block == bMerge {
		t.Errorf("bIf.Succs[1] still points at bMerge directly — split didn't take effect")
	}
	syn := bIf.Succs[1].Block
	if syn.Kind != ssa.BlockPlain {
		t.Errorf("inserted block kind = %v, want BlockPlain", syn.Kind)
	}
	if len(syn.Preds) != 1 || syn.Preds[0].Block != bIf {
		t.Errorf("inserted block.Preds = %v, want exactly bIf", syn.Preds)
	}
	if len(syn.Succs) != 1 || syn.Succs[0].Block != bMerge {
		t.Errorf("inserted block.Succs = %v, want exactly bMerge", syn.Succs)
	}
	if len(syn.Values) != 0 {
		t.Errorf("inserted block should have NO values, got %d", len(syn.Values))
	}

	// Re-running should be a no-op now.
	if got := SplitCriticalEdges(f); got != 0 {
		t.Errorf("re-running SplitCriticalEdges should split nothing, got %d", got)
	}
}

// TestSplitCriticalEdgesPredIndicesPreserved confirms that the
// per-edge Index fields are updated correctly so phi.Args[i]
// indexing stays consistent. Before split: bIf is bMerge.Preds[1]
// (assuming the then-pred occupies index 0). After split: the synthetic
// block is bMerge.Preds[1] and the IfBlock's else-succ Edge.Index
// points into the synthetic block's Preds (index 0).
func TestSplitCriticalEdgesPredIndicesPreserved(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("predidx", fsig)
	bIf := b.NewBlock(ssa.BlockIf)
	bThen := b.NewBlock(ssa.BlockPlain)
	bMerge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(bIf)

	b.SetCurrent(bIf)
	x := b.Param(0, ssa.TypeI32)
	b.LinkIf(x, bThen, bMerge)
	b.SetCurrent(bThen)
	b.LinkPlain(bMerge)
	b.SetCurrent(bMerge)
	b.FinishRet(x)

	f := b.Func()
	// Pre-split: bMerge.Preds should be [bThen, bIf].
	if len(bMerge.Preds) != 2 {
		t.Fatalf("expected bMerge.Preds == 2, got %d", len(bMerge.Preds))
	}
	preBMergePredOfBIf := -1
	for i, p := range bMerge.Preds {
		if p.Block == bIf {
			preBMergePredOfBIf = i
			break
		}
	}
	if preBMergePredOfBIf == -1 {
		t.Fatalf("bIf not found in bMerge.Preds")
	}

	SplitCriticalEdges(f)

	// The bMerge.Preds entry that used to be bIf should now be the
	// synthetic block; bIf is no longer a direct pred.
	for _, p := range bMerge.Preds {
		if p.Block == bIf {
			t.Errorf("after split, bMerge still has bIf in Preds: %v", p)
		}
	}
	// The synthetic block's Succs[0].Index should equal the position
	// in bMerge.Preds where it sits.
	syn := bIf.Succs[1].Block
	wantIdx := -1
	for i, p := range bMerge.Preds {
		if p.Block == syn {
			wantIdx = i
			break
		}
	}
	if wantIdx == -1 {
		t.Fatalf("synthetic block not present in bMerge.Preds")
	}
	if got := syn.Succs[0].Index; got != wantIdx {
		t.Errorf("synthetic.Succs[0].Index = %d, want %d (its position in bMerge.Preds)", got, wantIdx)
	}
}

// TestSplitCriticalEdgesPhiArgsStable ensures phi nodes in the merge
// block keep referring to the same value through the same pred index
// after the split. The phi's Args[i] is keyed on the position in
// b.Preds; we just need to preserve the value that came from "the
// pred that used to be the BlockIf" no matter what its new pred name
// is.
func TestSplitCriticalEdgesPhiArgsStable(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("phi", fsig)
	bIf := b.NewBlock(ssa.BlockIf)
	bThen := b.NewBlock(ssa.BlockPlain)
	bMerge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(bIf)

	b.SetCurrent(bIf)
	x := b.Param(0, ssa.TypeI32)
	one := b.Const32(1)
	b.LinkIf(x, bThen, bMerge)

	b.SetCurrent(bThen)
	thenVal := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	b.LinkPlain(bMerge)

	b.SetCurrent(bMerge)
	// Phi: two args, [thenVal from bThen, x from bIf-direct].
	// Pre-split, bMerge.Preds is [bThen, bIf]. So phi.Args[0] = thenVal,
	// phi.Args[1] = x.
	phi := b.NewValue(ssa.OpPhi, ssa.TypeI32, thenVal, x)
	b.FinishRet(phi)

	f := b.Func()

	// Remember which arg corresponds to which pred-side value.
	// bMerge.Preds order is deterministic from construction order.
	predIdxOfBIf := -1
	for i, p := range bMerge.Preds {
		if p.Block == bIf {
			predIdxOfBIf = i
		}
	}
	if predIdxOfBIf == -1 {
		t.Fatalf("bIf not in bMerge.Preds")
	}
	preBIfPhiArg := phi.Args[predIdxOfBIf]

	SplitCriticalEdges(f)

	// After the split, bMerge.Preds at position predIdxOfBIf is the
	// synthetic block. The phi's args list length is unchanged, and
	// phi.Args[predIdxOfBIf] still equals the original incoming value
	// (we don't rewrite phi args — the split is transparent).
	if len(phi.Args) != 2 {
		t.Errorf("phi args count changed after split: %d", len(phi.Args))
	}
	if phi.Args[predIdxOfBIf] != preBIfPhiArg {
		t.Errorf("phi.Args[%d] changed: was %v, now %v", predIdxOfBIf, preBIfPhiArg, phi.Args[predIdxOfBIf])
	}
}
