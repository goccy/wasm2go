package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestComputeDesiredShiftHintsCX covers the SHL case: the second arg
// is pinned to CX, so the producer of that arg should get CX as its
// preferred register. We build `f(x, k) { return x << k }` and check
// that k gets a CX hint in the block where SHL lives.
func TestComputeDesiredShiftHintsCX(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("shifthint", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	k := bb.Param(1, ssa.TypeI32)
	shl := bb.NewValue(ssa.OpShl32, ssa.TypeI32, x, k)
	bb.FinishRet(shl)

	r := ComputeDesired(bb.Func(), ArchAMD64)
	if r.Hints[b0.ID] == nil {
		t.Fatal("expected hints map for b0, got nil")
	}
	ent := r.Hints[b0.ID][k.ID]
	if ent == nil {
		t.Fatalf("expected hint entry for k (v%d), got nil", k.ID)
	}
	if ent.Regs[0] != amd64CX {
		t.Errorf("k's first hint = %v (%s), want amd64CX (%s)",
			ent.Regs[0], ArchAMD64.RegName(ent.Regs[0]), ArchAMD64.RegName(amd64CX))
	}
}

// TestComputeDesiredAvoidSet checks that the avoid mask accumulates
// the registers other values want. After the SHL test fixture's walk,
// CX should appear in Avoid[b0] (because k wants it).
func TestComputeDesiredAvoidSet(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("avoid", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	k := bb.Param(1, ssa.TypeI32)
	_ = bb.NewValue(ssa.OpShl32, ssa.TypeI32, x, k)
	bb.FinishRet(x)

	r := ComputeDesired(bb.Func(), ArchAMD64)
	if r.Avoid[b0.ID]&(1<<amd64CX) == 0 {
		t.Errorf("Avoid[b0] should contain amd64CX (k wants it), got %#x", r.Avoid[b0.ID])
	}
}

// TestComputeDesiredNoHintsForFreeOps covers the negative case: an
// op with no fixed-register inputs (a plain Add) generates no hints
// for its args.
func TestComputeDesiredNoHintsForFreeOps(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("noh", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	y := bb.Param(1, ssa.TypeI32)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, y)
	bb.FinishRet(sum)

	r := ComputeDesired(bb.Func(), ArchAMD64)
	// No hints should be recorded for x, y, or sum — Add accepts any
	// GP register on both inputs and the output, so no single-bit
	// mask hints get added. The Hints map may be nil entirely.
	if h := r.Hints[b0.ID]; h != nil {
		for id := range h {
			t.Errorf("unexpected hint for v%d in plain Add fixture: %v", id, h[id])
		}
	}
}

// TestComputeDesiredResultInArg0Propagation checks that when an op
// is IsResultInArg0 (e.g. Add on amd64) and has a downstream hint,
// the hint propagates to arg0. We build:
//
//	f(a, b) { sum = a + b; <SHL uses sum as shift count> }
//
// Actually we use a simpler test: build a fixture where sum is
// consumed by an op with a fixed-register input. The sum's hint
// should propagate to a (sum's arg0).
func TestComputeDesiredResultInArg0Propagation(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("propa", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	a := bb.Param(0, ssa.TypeI32)
	b := bb.Param(1, ssa.TypeI32)
	// sum = a + b; sum becomes the shift COUNT for `x << sum`.
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, a, b)
	x := bb.Param(0, ssa.TypeI32) // re-use the input (any value works)
	shl := bb.NewValue(ssa.OpShl32, ssa.TypeI32, x, sum)
	bb.FinishRet(shl)

	r := ComputeDesired(bb.Func(), ArchAMD64)
	// sum should get a CX hint (from being SHL's shift count).
	ent := r.Hints[b0.ID][sum.ID]
	if ent == nil {
		t.Fatalf("expected hint entry for sum (v%d), got nil. Hints: %v", sum.ID, r.Hints[b0.ID])
	}
	if ent.Regs[0] != amd64CX {
		t.Errorf("sum's first hint = %s, want CX", ArchAMD64.RegName(ent.Regs[0]))
	}
	// a (sum's arg0, IsResultInArg0 for OpAdd32) should also get CX
	// as a hint — biasing a to CX lets `MOV a, sum; ADD b, sum`
	// land sum in CX with one fewer reg-to-reg shuffle.
	aEnt := r.Hints[b0.ID][a.ID]
	if aEnt == nil {
		t.Fatalf("expected hint entry for a (v%d) via IsResultInArg0 propagation", a.ID)
	}
	foundCX := false
	for _, hr := range aEnt.Regs {
		if hr == amd64CX {
			foundCX = true
		}
	}
	if !foundCX {
		t.Errorf("a's hints = %v, expected to include CX", aEnt.Regs)
	}
}

// TestAddHintRespectsMaxDesired confirms the priority list never
// overflows. We hammer addHint with five distinct registers and check
// the entry caps at MaxDesiredHints.
func TestAddHintRespectsMaxDesired(t *testing.T) {
	hints := map[ssa.ValueID]*desiredEntry{}
	for _, r := range []register{amd64AX, amd64BX, amd64CX, amd64DX, amd64DI, amd64SI} {
		addHint(hints, 1, r)
	}
	ent := hints[1]
	if ent == nil {
		t.Fatal("hint entry not created")
	}
	filled := 0
	for _, r := range ent.Regs {
		if r != noRegister {
			filled++
		}
	}
	if filled != MaxDesiredHints {
		t.Errorf("expected %d filled hint slots, got %d", MaxDesiredHints, filled)
	}
}

// TestSingleBitRegister covers the helper that detects single-bit
// masks for fixed-reg hints.
func TestSingleBitRegister(t *testing.T) {
	if got := singleBitRegister(0); got != noRegister {
		t.Errorf("singleBitRegister(0) = %v, want noRegister", got)
	}
	if got := singleBitRegister(1 << amd64AX); got != amd64AX {
		t.Errorf("singleBitRegister(1<<AX) = %v, want AX", got)
	}
	if got := singleBitRegister(1<<amd64AX | 1<<amd64BX); got != noRegister {
		t.Errorf("singleBitRegister(AX|BX) = %v, want noRegister (multi-bit)", got)
	}
	if got := singleBitRegister(1 << amd64R13); got != amd64R13 {
		t.Errorf("singleBitRegister(1<<R13) = %v, want R13", got)
	}
}
