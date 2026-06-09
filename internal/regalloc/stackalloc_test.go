package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestAllocateSlotsEmpty: no values marked SpillNeeded → 0 slots,
// frame size = baseOffset.
func TestAllocateSlotsEmpty(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("none", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	bb.FinishRet(x)

	r := &Result{Home: map[ssa.ValueID]string{}, SpillNeeded: map[ssa.ValueID]bool{}}
	sa := AllocateSlots(bb.Func(), ArchAMD64, r, 32)
	if len(sa.Offset) != 0 {
		t.Errorf("expected 0 slot assignments, got %d", len(sa.Offset))
	}
	if sa.FrameSize != 32 {
		t.Errorf("expected FrameSize = baseOffset (32), got %d", sa.FrameSize)
	}
}

// TestAllocateSlotsNonOverlappingShare: two values with non-
// overlapping live ranges should share the same slot.
//
// We build a function with two independent values v1 and v2 defined
// in separate blocks with no overlap, both marked SpillNeeded, and
// check they get the same offset.
func TestAllocateSlotsNonOverlappingShare(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("share", fsig)
	b0 := bb.NewBlock(ssa.BlockPlain)
	b1 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)

	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	v1 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.LinkPlain(b1)

	bb.SetCurrent(b1)
	two := bb.Const32(2)
	// v2 doesn't use v1; v1 is dead by the time we get here.
	v2 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, two)
	bb.FinishRet(v2)

	r := &Result{
		Home: map[ssa.ValueID]string{},
		SpillNeeded: map[ssa.ValueID]bool{
			v1.ID: true,
			v2.ID: true,
		},
	}
	sa := AllocateSlots(bb.Func(), ArchAMD64, r, 0)
	if sa.Offset[v1.ID] != sa.Offset[v2.ID] {
		t.Errorf("v1 (offset %d) and v2 (offset %d) should SHARE a slot — their live ranges don't overlap",
			sa.Offset[v1.ID], sa.Offset[v2.ID])
	}
	// FrameSize should be 8 (one 4-byte slot, padded to 8).
	if sa.FrameSize != 8 {
		t.Errorf("expected FrameSize = 8 (one shared 4-byte slot, 8-aligned), got %d", sa.FrameSize)
	}
}

// TestAllocateSlotsOverlappingSeparate: two values whose live ranges
// overlap must get separate slots.
func TestAllocateSlotsOverlappingSeparate(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("overlap", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	v1 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	two := bb.Const32(2)
	v2 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, two)
	// Final result uses BOTH v1 and v2, so both are live simultaneously.
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, v1, v2)
	bb.FinishRet(sum)

	r := &Result{
		Home: map[ssa.ValueID]string{},
		SpillNeeded: map[ssa.ValueID]bool{
			v1.ID: true,
			v2.ID: true,
		},
	}
	sa := AllocateSlots(bb.Func(), ArchAMD64, r, 0)
	if sa.Offset[v1.ID] == sa.Offset[v2.ID] {
		t.Errorf("v1 and v2 should get SEPARATE slots — they're live together; both got %d",
			sa.Offset[v1.ID])
	}
}

// TestAllocateSlotsDifferentTypes: i32 and i64 values must NOT share
// a slot (different sizes / alignments).
func TestAllocateSlotsDifferentTypes(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI64}, Results: []ssa.Type{ssa.TypeI64}}
	bb := ssa.NewFuncBuilder("types", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x32 := bb.Param(0, ssa.TypeI32)
	x64 := bb.Param(1, ssa.TypeI64)
	// Make x32 and x64 non-overlapping by defining one then the
	// other and using neither past its definition. Actually use both
	// in FinishRet to keep them alive — but they're DIFFERENT types,
	// so the per-type pool keeps them separate even with overlap.
	_ = x32
	bb.FinishRet(x64)

	r := &Result{
		Home: map[ssa.ValueID]string{},
		SpillNeeded: map[ssa.ValueID]bool{
			x32.ID: true,
			x64.ID: true,
		},
	}
	sa := AllocateSlots(bb.Func(), ArchAMD64, r, 0)
	if sa.Offset[x32.ID] == sa.Offset[x64.ID] {
		t.Errorf("i32 and i64 values must use different slots (size/align mismatch); both got %d",
			sa.Offset[x32.ID])
	}
}

// TestSlotSizeFor exercises the type → slot-size helper.
func TestSlotSizeFor(t *testing.T) {
	tests := []struct {
		typ  ssa.Type
		want int
	}{
		{ssa.TypeI32, 4},
		{ssa.TypeF32, 4},
		{ssa.TypeBool, 4},
		{ssa.TypeI64, 8},
		{ssa.TypeF64, 8},
		{ssa.TypeMem, 0},
		{ssa.TypeInvalid, 0},
	}
	for _, tt := range tests {
		if got := slotSizeFor(tt.typ); got != tt.want {
			t.Errorf("slotSizeFor(%v) = %d, want %d", tt.typ, got, tt.want)
		}
	}
}

// TestAlignUp covers the bit-twiddle alignment helper.
func TestAlignUp(t *testing.T) {
	tests := []struct {
		n, a, want int
	}{
		{0, 4, 0},
		{1, 4, 4},
		{3, 4, 4},
		{4, 4, 4},
		{5, 4, 8},
		{7, 8, 8},
		{8, 8, 8},
		{9, 8, 16},
	}
	for _, tt := range tests {
		if got := alignUp(tt.n, tt.a); got != tt.want {
			t.Errorf("alignUp(%d, %d) = %d, want %d", tt.n, tt.a, got, tt.want)
		}
	}
}
