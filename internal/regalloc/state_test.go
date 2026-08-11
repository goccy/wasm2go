package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestTrailingZero64 covers the bit-scan helper used by allocReg's
// "pick the lowest free register" path. Edge cases:
//   - empty mask → noRegister
//   - first bit set → 0
//   - bit at position N set → N
//   - top bit (within uint64) → 63 (we don't go that high in practice)
func TestTrailingZero64(t *testing.T) {
	if got := trailingZero64(0); got != noRegister {
		t.Errorf("trailingZero64(0) = %v, want noRegister", got)
	}
	if got := trailingZero64(1); got != 0 {
		t.Errorf("trailingZero64(1) = %v, want 0", got)
	}
	if got := trailingZero64(1 << amd64R12); got != amd64R12 {
		t.Errorf("trailingZero64(1<<R12) = %v, want R12", got)
	}
	if got := trailingZero64(1<<amd64BX | 1<<amd64R8); got != amd64BX {
		t.Errorf("trailingZero64(BX|R8) = %v, want BX (lowest)", got)
	}
}

// TestStateAssignAndFreeReg confirms the bookkeeping in
// assign/freeReg keeps used and the per-value Regs mask in sync.
func TestStateAssignAndFreeReg(t *testing.T) {
	f := newDummyFunc(t)
	s := newState(f, ArchAMD64)

	// Pretend value ID 1 is going into BX.
	s.assignReg(amd64BX, 1)
	if s.used&(1<<amd64BX) == 0 {
		t.Errorf("after assignReg(BX, 1), used should contain BX; got %#x", s.used)
	}
	if s.values[1].Regs&(1<<amd64BX) == 0 {
		t.Errorf("after assignReg(BX, 1), values[1].Regs should contain BX; got %#x", s.values[1].Regs)
	}
	if s.regs[amd64BX].V != 1 {
		t.Errorf("regs[BX].V = %d, want 1", s.regs[amd64BX].V)
	}

	// Free it.
	s.freeReg(amd64BX)
	if s.used&(1<<amd64BX) != 0 {
		t.Errorf("after freeReg, used should NOT contain BX; got %#x", s.used)
	}
	if s.values[1].Regs&(1<<amd64BX) != 0 {
		t.Errorf("after freeReg, values[1].Regs should NOT contain BX; got %#x", s.values[1].Regs)
	}
	if s.regs[amd64BX].V != 0 {
		t.Errorf("after freeReg, regs[BX].V should be 0, got %d", s.regs[amd64BX].V)
	}
}

// TestAllocRegFreeRegistersPickedLowest checks the simplest pick:
// no registers used, mask offers many — allocator picks the lowest.
func TestAllocRegFreeRegistersPickedLowest(t *testing.T) {
	f := newDummyFunc(t)
	s := newState(f, ArchAMD64)

	mask := amd64AllocGP
	got := s.allocReg(mask, 1)
	// Lowest GP allocatable on amd64 is AX (index 0).
	if got != amd64AX {
		t.Errorf("allocReg with full GP free pool = %s, want AX",
			ArchAMD64.RegName(got))
	}
}

// TestAllocRegSkipsNospill checks the nospill mask exclusion: even if
// a register is in `mask`, allocReg won't pick it if it's in nospill.
func TestAllocRegSkipsNospill(t *testing.T) {
	f := newDummyFunc(t)
	s := newState(f, ArchAMD64)
	s.nospill |= 1 << amd64AX
	mask := amd64AllocGP
	got := s.allocReg(mask, 1)
	if got == amd64AX {
		t.Errorf("allocReg picked AX even though it's in nospill")
	}
}

// TestAllocRegSkipsReserved checks the allocatable mask exclusion:
// even if `mask` includes R11 (m-cache reservation on amd64), the
// allocator won't pick it.
func TestAllocRegSkipsReserved(t *testing.T) {
	f := newDummyFunc(t)
	s := newState(f, ArchAMD64)
	// Try to ask for R11 specifically.
	got := s.allocReg(1<<amd64R11, 1)
	if got != noRegister {
		t.Errorf("allocReg(1<<R11) = %s, want noRegister (R11 is reserved)",
			ArchAMD64.RegName(got))
	}
}

// TestAllocRegBeladyPicksFarthest stresses the eviction case. We fill
// all 11 allocatable GP regs with distinct values, then ask for a
// register from the same pool. The pick should be the register whose
// value has the farthest next-use distance.
//
// We simulate that by pinning one value (say, the one in BX) as
// "live-out with large dist" via the LiveOut map, and another (in CX)
// as "live-out with small dist". The allocator should evict BX.
func TestAllocRegBeladyPicksFarthest(t *testing.T) {
	// Build a function with enough values to populate the regs.
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("belady", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	bb.FinishRet(x)

	f := bb.Func()
	s := newState(f, ArchAMD64)
	s.curBlock = b0

	// Fill every allocatable GP with a fake value ID. We use the
	// real x's ID for BX; ID 100 (synthetic) for CX. The LiveOut
	// map gets updated to give BX-resident value a HIGH dist and
	// CX-resident value a low dist.
	idBX := x.ID
	idCX := ssa.ValueID(100)
	// Grow values slice to fit id 100.
	for ssa.ValueID(len(s.values)) <= idCX {
		s.values = append(s.values, valState{})
	}
	s.values[idCX].NeedReg = true
	// Pre-fill regs[BX] and regs[CX].
	s.assignReg(amd64BX, idBX)
	s.assignReg(amd64CX, idCX)
	// Fill the rest of allocatable GP with a sentinel ID (200+r) so
	// nothing else is free.
	for r := register(0); r < register(len(s.regs)); r++ {
		if amd64AllocGP&(1<<r) == 0 {
			continue // not allocatable
		}
		if r == amd64BX || r == amd64CX {
			continue
		}
		id := ssa.ValueID(200 + int(r))
		for ssa.ValueID(len(s.values)) <= id {
			s.values = append(s.values, valState{})
		}
		s.values[id].NeedReg = true
		s.assignReg(r, id)
	}

	// Inject live-out data: BX-resident (idBX = x) has dist 1000;
	// CX-resident (idCX) has dist 1. Every other resident also has
	// a small dist (let's say 50) so neither of them wins by
	// accident.
	live := []liveInfo{{ID: idBX, Dist: 1000}, {ID: idCX, Dist: 1}}
	for r := register(0); r < register(len(s.regs)); r++ {
		if amd64AllocGP&(1<<r) == 0 {
			continue
		}
		if r == amd64BX || r == amd64CX {
			continue
		}
		id := ssa.ValueID(200 + int(r))
		live = append(live, liveInfo{ID: id, Dist: 50})
	}
	s.live.LiveOut[b0.ID] = live
	s.curIdx = 0

	// Ask for any GP register from the full pool. allocReg should
	// evict BX (its value's next-use dist is highest).
	got := s.allocReg(amd64AllocGP, 999)
	if got != amd64BX {
		t.Errorf("Belady eviction should have picked BX (dist 1000), got %s",
			ArchAMD64.RegName(got))
	}
}

// newDummyFunc builds a minimal Func that ComputeLive / ComputeDesired
// can chew on without crashing. Used by the simpler state tests that
// don't care about the function content.
func newDummyFunc(t *testing.T) *ssa.Func {
	t.Helper()
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("dummy", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	bb.FinishRet(x)
	return bb.Func()
}
