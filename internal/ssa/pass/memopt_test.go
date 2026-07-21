package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// load emits a linear-memory load of the given op at base+off.
func load(b *ssa.FuncBuilder, op ssa.Op, typ ssa.Type, base *ssa.Value, off int64) *ssa.Value {
	return b.NewValueAuxInt(op, typ, off, base)
}

// store emits a linear-memory store of the given op at base+off.
func store(b *ssa.FuncBuilder, op ssa.Op, base *ssa.Value, off int64, val *ssa.Value) *ssa.Value {
	return b.NewValueAuxInt(op, ssa.TypeMem, off, base, val)
}

// TestMemOptRedundantLoad merges two identical loads with nothing
// between them: the second becomes dead and its users point at the first.
func TestMemOptRedundantLoad(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("rle", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l1 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 8)
	l2 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 8)
	add := b.NewValue(ssa.OpAdd32, ssa.TypeI32, l1, l2)
	b.FinishRet(add)
	f := b.Func()

	if !MemOpt(f) {
		t.Fatalf("MemOpt returned false; expected the duplicate load to merge")
	}
	if l2.Op != ssa.OpInvalid {
		t.Errorf("expected l2 (v%d) to be invalidated, still %v", l2.ID, l2.Op)
	}
	if add.Args[0] != l1 || add.Args[1] != l1 {
		t.Errorf("expected both add operands rewritten to l1 (v%d), got v%d, v%d",
			l1.ID, add.Args[0].ID, add.Args[1].ID)
	}
	if MemOpt(f) {
		t.Errorf("MemOpt should be idempotent at fixpoint")
	}
}

// TestMemOptStoreToLoadForward forwards a full-width store's value
// operand to a later load of the same address, deleting the load.
func TestMemOptStoreToLoadForward(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("fwd", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	val := b.Const32(99)
	store(b, ssa.OpStore32, base, 16, val)
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 16)
	use := b.NewValue(ssa.OpAdd32, ssa.TypeI32, l, val)
	b.FinishRet(use)
	f := b.Func()

	if !MemOpt(f) {
		t.Fatalf("MemOpt returned false; expected store-to-load forwarding")
	}
	if l.Op != ssa.OpInvalid {
		t.Errorf("expected load (v%d) to be invalidated, still %v", l.ID, l.Op)
	}
	if use.Args[0] != val {
		t.Errorf("expected forwarded operand to be the stored value v%d, got v%d",
			val.ID, use.Args[0].ID)
	}
}

// TestMemOptAliasingStoreBlocks keeps a load live when an overlapping,
// non-forwardable store (a sub-width write) sits between two reads.
func TestMemOptAliasingStoreBlocks(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("alias", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	sv := b.Const32(1)
	load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	// store8 at base+1 overlaps the [0,4) load range → invalidates it,
	// and a sub-width store is never forwardable to a load32.
	store(b, ssa.OpStore8, base, 1, sv)
	l2 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l2)
	f := b.Func()

	MemOpt(f)
	if l2.Op != ssa.OpLoad32 {
		t.Errorf("expected l2 to survive an aliasing store, got %v", l2.Op)
	}
}

// TestMemOptDisjointStorePreservesLoad keeps a load available across a
// store to a provably-disjoint address (same base, non-overlapping
// constant byte ranges).
func TestMemOptDisjointStorePreservesLoad(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("disjoint", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	sv := b.Const32(1)
	l1 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	// store32 at base+8: [8,12) is disjoint from the [0,4) load.
	store(b, ssa.OpStore32, base, 8, sv)
	l2 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l2)
	f := b.Func()

	if !MemOpt(f) {
		t.Fatalf("expected l2 to reuse l1 across a disjoint store")
	}
	if l2.Op != ssa.OpInvalid {
		t.Errorf("expected l2 merged into l1 (v%d), still %v", l1.ID, l2.Op)
	}
}

// TestMemOptCallIsBarrier keeps a load live across a real call, which may
// write linear memory at an unknown location.
func TestMemOptCallIsBarrier(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("callbar", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.NewValueAux(ssa.OpCallDirect, ssa.TypeI32, "fn", base)
	l2 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l2)
	f := b.Func()

	MemOpt(f)
	if l2.Op != ssa.OpLoad32 {
		t.Errorf("expected l2 to survive a call barrier, got %v", l2.Op)
	}
}

// TestMemOptHelperNotBarrier confirms a pure helper call (which never
// touches linear memory) does not invalidate availability.
func TestMemOptHelperNotBarrier(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("helperbar", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l1 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.NewValueAux(ssa.OpHelperCall, ssa.TypeI32, "i32_clz", l1)
	l2 := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l2)
	f := b.Func()

	if !MemOpt(f) {
		t.Fatalf("expected l2 to reuse l1 across a pure helper call")
	}
	if l2.Op != ssa.OpInvalid {
		t.Errorf("expected l2 merged into l1 (v%d), still %v", l1.ID, l2.Op)
	}
}

// TestMemOptSameOpDifferentTypeNotMerged guards the i32.load8_s vs
// i64.load8_s hazard: both lower to OpLoad8S but yield different result
// types, so they must not be merged even at the same address.
func TestMemOptSameOpDifferentTypeNotMerged(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}}
	b := ssa.NewFuncBuilder("sameop", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l32 := load(b, ssa.OpLoad8S, ssa.TypeI32, base, 0) // i32.load8_s
	l64 := load(b, ssa.OpLoad8S, ssa.TypeI64, base, 0) // i64.load8_s
	_ = l32
	b.FinishRet(l64)
	f := b.Func()

	MemOpt(f)
	if l64.Op != ssa.OpLoad8S || l64.Type != ssa.TypeI64 {
		t.Errorf("i64 load must not be merged into the i32 load; got %v/%v", l64.Op, l64.Type)
	}
}

// TestMemOptWidthMismatchNoForward does not forward a store to a load of
// a different width at the same address.
func TestMemOptWidthMismatchNoForward(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("widthmismatch", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	sv := b.Const32(1)
	// store64 then load32 at the same base: overlapping (so RLE from the
	// store is disallowed) but not a forwardable exact-width pair.
	store(b, ssa.OpStore64, base, 0, b.NewValue(ssa.OpExtend32To64U, ssa.TypeI64, sv))
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l)
	f := b.Func()

	MemOpt(f)
	if l.Op != ssa.OpLoad32 {
		t.Errorf("expected load32 to survive a width-mismatched store64, got %v", l.Op)
	}
}
