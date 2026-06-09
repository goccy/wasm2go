package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestAllocateStraightLineFitsInRegs covers the simplest case: a
// function with only a few values, all of which should land in
// registers. We build f(x) { return x + 1 } and assert the Add result
// has a register home.
func TestAllocateStraightLineFitsInRegs(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("simple", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(sum)

	r := Allocate(bb.Func(), ArchAMD64)
	if r == nil {
		t.Fatal("Allocate returned nil")
	}
	// The Add's output should have a register home. Const and Param
	// are rematerialisable / inlineable; the allocator may or may
	// not assign them a home (rematerialise wiring pins the policy).
	if home := r.Home[sum.ID]; home == "" {
		t.Errorf("Add result has no register home (expected one, got SpillNeeded=%v)",
			r.SpillNeeded[sum.ID])
	}
	// No spill should be needed for this micro-function.
	if r.SpillNeeded[sum.ID] {
		t.Errorf("Add result marked SpillNeeded — register pool is plenty large")
	}
}

// TestAllocateMultiBlockSharesRegisters is a regression for the
// cross-block aspect: a value defined in b0 should retain its
// register through b1 (single-pred chain), not be re-loaded.
func TestAllocateMultiBlockSharesRegisters(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("twoblock", fsig)
	b0 := bb.NewBlock(ssa.BlockPlain)
	b1 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)

	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.LinkPlain(b1)

	bb.SetCurrent(b1)
	bb.FinishRet(sum)

	r := Allocate(bb.Func(), ArchAMD64)
	// sum should have a register home (defined in b0, used in b1).
	if home := r.Home[sum.ID]; home == "" {
		t.Errorf("sum should have a register home spanning b0→b1, got Home=%q SpillNeeded=%v",
			home, r.SpillNeeded[sum.ID])
	}
	// EndRegs[b0] should mention sum.
	found := false
	for _, er := range r.EndRegs[b0.ID] {
		if er.V == sum.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("EndRegs[b0] should contain sum (carried across b0→b1), got %v", r.EndRegs[b0.ID])
	}
}

// TestAllocateShiftPicksCX checks that the hint plumbing actually
// influences allocation: SHL pins its shift count to CX, so the
// allocator should land the count value in CX.
func TestAllocateShiftPicksCX(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("shift", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	k := bb.Param(1, ssa.TypeI32)
	shl := bb.NewValue(ssa.OpShl32, ssa.TypeI32, x, k)
	bb.FinishRet(shl)

	r := Allocate(bb.Func(), ArchAMD64)
	if home := r.Home[k.ID]; home != "CX" {
		t.Errorf("shift count k should be in CX (SHL pins it there), got Home=%q",
			home)
	}
}

// TestAllocateBranchKeepsRegisters checks that a value used on both
// sides of a BlockIf retains its register through the branch (no
// unnecessary spill). We build `if x { return x + 1 } else { return
// x + 2 }` and assert x has a register home that's preserved.
func TestAllocateBranchKeepsRegisters(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("br", fsig)
	bIf := bb.NewBlock(ssa.BlockIf)
	bThen := bb.NewBlock(ssa.BlockRet)
	bElse := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(bIf)

	bb.SetCurrent(bIf)
	x := bb.Param(0, ssa.TypeI32)
	bb.LinkIf(x, bThen, bElse)

	bb.SetCurrent(bThen)
	one := bb.Const32(1)
	t1 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(t1)

	bb.SetCurrent(bElse)
	two := bb.Const32(2)
	t2 := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, two)
	bb.FinishRet(t2)

	r := Allocate(bb.Func(), ArchAMD64)
	if home := r.Home[x.ID]; home == "" {
		t.Errorf("x should retain a register across the branch, got Home=%q SpillNeeded=%v",
			home, r.SpillNeeded[x.ID])
	}
}

// TestAllocateRunsOnArm64 confirms the Allocator runs end-to-end on
// arm64 too. We don't check specific register assignments (arm64's
// 26-GP pool means choices differ from amd64's 11) — just that the
// pipeline produces a non-empty Home map without panicking.
func TestAllocateRunsOnArm64(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("arm", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(sum)

	r := Allocate(bb.Func(), ArchARM64)
	if home := r.Home[sum.ID]; home == "" {
		t.Errorf("arm64 allocator should give sum a register home, got %q", home)
	}
}
