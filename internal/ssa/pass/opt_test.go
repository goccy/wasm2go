package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// These tests drive the optimization passes from minimal,
// hand-constructed SSA functions with known-good expected outcomes.
// Each pass is proven on a small example before it is ever pointed at
// real generated code; the instruction-count assertions make the
// "folding reduces instruction count" claim concrete.

// --- DCE --------------------------------------------------------------

// TestDCE_RemovesDeadValue:
//
//	dead = p0 + p1   (no users)
//	live = p0 + p1   (returned)
//
// DCE must remove `dead` and keep `live`.
func TestDCE_RemovesDeadValue(t *testing.T) {
	b := ssa.NewFuncBuilder("dcetest", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	p1 := b.Param(1, ssa.TypeI32)
	dead := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	live := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	b.FinishRet(live)
	f := b.Func()

	before := ssa.CountValues(f) // p0,p1,dead,live,ret-marker = 5
	if before != 5 {
		t.Fatalf("setup: CountValues=%d, want 5", before)
	}
	DCE(f)
	if dead.Op != ssa.OpInvalid {
		t.Errorf("dead value not removed: op=%v", dead.Op)
	}
	if live.Op != ssa.OpAdd32 {
		t.Errorf("live value wrongly removed: op=%v", live.Op)
	}
	ssa.Compact(f)
	if got := ssa.CountValues(f); got != 4 {
		t.Errorf("after DCE+Compact CountValues=%d, want 4", got)
	}
}

// TestDCE_KeepsSideEffects: a store with no users must NOT be removed.
func TestDCE_KeepsSideEffects(t *testing.T) {
	b := ssa.NewFuncBuilder("dceside", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	st := b.NewValueAuxInt(ssa.OpStore32, ssa.TypeMem, 0, p0, p0)
	DCE(f4(b))
	if st.Op != ssa.OpStore32 {
		t.Errorf("store wrongly DCE'd: op=%v", st.Op)
	}
}

// f4 is a tiny helper: returns the builder's Func.
func f4(b *ssa.FuncBuilder) *ssa.Func { return b.Func() }

// --- Simplify: copy propagation --------------------------------------

// TestSimplify_CopyPropagation:
//
//	c = copy(p0)
//	v = c + c
//
// Simplify must rewrite v's args to p0 and mark the copy dead.
func TestSimplify_CopyPropagation(t *testing.T) {
	b := ssa.NewFuncBuilder("copytest", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	c := b.NewValue(ssa.OpCopy, ssa.TypeI32, p0)
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, c, c)
	b.FinishRet(v)
	f := b.Func()

	Simplify(f)
	if v.Args[0] != p0 || v.Args[1] != p0 {
		t.Errorf("copy not propagated: v.Args=%v,%v want p0,p0", v.Args[0].ID, v.Args[1].ID)
	}
	if c.Op != ssa.OpInvalid {
		t.Errorf("copy not marked dead: op=%v", c.Op)
	}
}

// --- Simplify: trivial-phi elimination -------------------------------

// TestSimplify_TrivialPhi: a phi whose two incoming values are the
// SAME value collapses to that value.
//
//	   entry (If cond)
//	  /              \
//	b1               b2
//	  \              /
//	   merge: phi(x, x);  v = phi + 1
func TestSimplify_TrivialPhi(t *testing.T) {
	b := ssa.NewFuncBuilder("phitest", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	b1 := b.NewBlock(ssa.BlockPlain)
	b2 := b.NewBlock(ssa.BlockPlain)
	merge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)

	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	x := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p0) // the shared value
	entry.Control = p0
	ssa.AddEdge(entry, b1)
	ssa.AddEdge(entry, b2)

	ssa.AddEdge(b1, merge)
	ssa.AddEdge(b2, merge)

	b.SetCurrent(merge)
	phi := b.NewValue(ssa.OpPhi, ssa.TypeI32, x, x) // phi(x, x) — trivial
	one := b.Const32(1)
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, phi, one)
	b.FinishRet(v)
	f := b.Func()

	Simplify(f)
	if v.Args[0] != x {
		t.Errorf("trivial phi not collapsed: v.Args[0]=v%d want v%d", v.Args[0].ID, x.ID)
	}
	if phi.Op != ssa.OpInvalid {
		t.Errorf("trivial phi not marked dead: op=%v", phi.Op)
	}
}

// TestSimplify_LoopHeaderPhi: a loop-header phi `phi(entryVal, self)`
// — self-reference plus one real value — collapses to the real value.
func TestSimplify_LoopHeaderPhi(t *testing.T) {
	b := ssa.NewFuncBuilder("loopphi", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	hdr := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	ssa.AddEdge(entry, hdr)
	ssa.AddEdge(hdr, hdr) // self back-edge

	b.SetCurrent(hdr)
	phi := b.NewValue(ssa.OpPhi, ssa.TypeI32, p0, nil) // arg1 filled below
	phi.Args[1] = phi                                  // self-reference
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, phi, p0)
	b.FinishRet(v)
	f := b.Func()

	Simplify(f)
	if v.Args[0] != p0 {
		t.Errorf("loop-header phi not collapsed: v.Args[0]=v%d want v%d (p0)", v.Args[0].ID, p0.ID)
	}
}

// --- CSE --------------------------------------------------------------

// TestCSE_MergesDuplicates:
//
//	a = p0 + p1
//	b = p0 + p1   (identical)
//	v = a + b
//
// CSE must merge b into a so v becomes a + a; b is dead.
func TestCSE_MergesDuplicates(t *testing.T) {
	bld := ssa.NewFuncBuilder("csetest", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := bld.NewBlock(ssa.BlockPlain)
	bld.SetEntry(entry)
	bld.SetCurrent(entry)
	p0 := bld.Param(0, ssa.TypeI32)
	p1 := bld.Param(1, ssa.TypeI32)
	a := bld.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	dup := bld.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	v := bld.NewValue(ssa.OpAdd32, ssa.TypeI32, a, dup)
	bld.FinishRet(v)
	f := bld.Func()

	CSE(f)
	if v.Args[0] != a || v.Args[1] != a {
		t.Errorf("CSE did not merge: v.Args=v%d,v%d want v%d,v%d", v.Args[0].ID, v.Args[1].ID, a.ID, a.ID)
	}
	if dup.Op != ssa.OpInvalid {
		t.Errorf("duplicate not marked dead: op=%v", dup.Op)
	}
}

// TestCSE_KeepsDistinct: different expressions must NOT be merged.
func TestCSE_KeepsDistinct(t *testing.T) {
	bld := ssa.NewFuncBuilder("csedistinct", ssa.FuncSig{
		Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32},
	})
	entry := bld.NewBlock(ssa.BlockPlain)
	bld.SetEntry(entry)
	bld.SetCurrent(entry)
	p0 := bld.Param(0, ssa.TypeI32)
	p1 := bld.Param(1, ssa.TypeI32)
	add := bld.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	sub := bld.NewValue(ssa.OpSub32, ssa.TypeI32, p0, p1)
	v := bld.NewValue(ssa.OpAdd32, ssa.TypeI32, add, sub)
	bld.FinishRet(v)
	f := bld.Func()

	CSE(f)
	if add.Op == ssa.OpInvalid || sub.Op == ssa.OpInvalid {
		t.Errorf("CSE wrongly merged distinct ops")
	}
	if v.Args[0] != add || v.Args[1] != sub {
		t.Errorf("CSE corrupted distinct args")
	}
}
