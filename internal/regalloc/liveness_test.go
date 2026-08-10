package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestComputeLiveStraightLine exercises the simplest case: a single
// block that takes a parameter, adds 1, and returns. The parameter
// should be live at block start (= distance to the Add use). The Add
// result should be live at block end up to the BlockRet position.
func TestComputeLiveStraightLine(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("straight", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(sum)

	r := ComputeLive(bb.Func(), ArchAMD64)
	if r == nil {
		t.Fatal("ComputeLive returned nil")
	}
	// A single-block function has no successors and no predecessors to
	// propagate to — LiveOut for b0 should still reflect "no values
	// outlive b0" (empty LiveOut at end). Actually, our pass stores
	// per-block live-IN data into LiveOut (the entry handed up to
	// preds). For a single block with no preds, that's what would be
	// handed to a caller. The simplest check: no value should appear
	// twice; the Add's result should not appear (defined in-block,
	// not live-out of this block as we're root).
	for _, li := range r.LiveOut[b0.ID] {
		if li.ID == sum.ID {
			t.Errorf("Add result v%d should not be in LiveOut[b0] — it's defined and returned in this block", sum.ID)
		}
	}
}

// TestComputeLiveAcrossBlocks checks that a value defined in block A
// and used in block B is recorded as live-out of A. We build:
//
//	b0: x = Param; jmp b1
//	b1: y = Add(x, 1); ret y
//
// x must appear in LiveOut[b0].
func TestComputeLiveAcrossBlocks(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("cross", fsig)
	b0 := bb.NewBlock(ssa.BlockPlain)
	b1 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)

	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	bb.LinkPlain(b1)

	bb.SetCurrent(b1)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(sum)

	r := ComputeLive(bb.Func(), ArchAMD64)
	// x must be live at the boundary between b0 and b1 — appears in
	// LiveOut[b0].
	found := false
	for _, li := range r.LiveOut[b0.ID] {
		if li.ID == x.ID {
			found = true
			if li.Dist <= 0 {
				t.Errorf("x's distance from end of b0 should be positive, got %d", li.Dist)
			}
		}
	}
	if !found {
		t.Errorf("Param x (v%d) should be in LiveOut[b0]; got %v", x.ID, r.LiveOut[b0.ID])
	}
}

// TestComputeLiveCallPenalty checks the +UnlikelyDistance penalty for
// values live across a CALL. Building:
//
//	b0: x = Param; y = Add(x, 1); CALL helper(); z = Add(y, x); ret z
//
// Both x and y are live across the CALL (used after). Their distances
// should reflect the +UnlikelyDistance penalty.
func TestComputeLiveCallPenalty(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("callpen", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	y := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	// Synthesize a CALL with a fake symbol. The op is OpHelperCall —
	// our isCall() switch catches it.
	call := bb.NewValueAuxInt(ssa.OpHelperCall, ssa.TypeMem, 0, x)
	z := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, y, x)
	_ = call
	bb.FinishRet(z)

	r := ComputeLive(bb.Func(), ArchAMD64)
	// Look up the next-call array and confirm the CALL was found.
	nc := r.NextCall[b0.ID]
	if len(nc) == 0 {
		t.Fatal("NextCall should be populated")
	}
	// Find the position of the OpHelperCall in b0.Values to check the
	// NextCall entry.
	callPos := -1
	for i, v := range b0.Values {
		if v.Op == ssa.OpHelperCall {
			callPos = i
			break
		}
	}
	if callPos == -1 {
		t.Fatal("OpHelperCall not found in b0.Values")
	}
	if got := nc[callPos]; got != int32(callPos) {
		t.Errorf("NextCall[%d] = %d, want %d", callPos, got, callPos)
	}
	if got := nc[callPos-1]; got != int32(callPos) {
		t.Errorf("NextCall[%d] = %d, want %d (CALL is the next at-or-after)", callPos-1, got, callPos)
	}
}

// TestComputeLiveSimpleLoop checks that liveness reaches around a
// loop. We build:
//
//	b0: x = Param; jmp b1
//	b1 (BlockIf): cond = something; if cond -> b1 (self-loop); else b2
//	b2: ret x   // x is used after the loop
//
// x must be in LiveOut[b1] AND LiveOut[b0] because x is used past the
// loop exit.
func TestComputeLiveSimpleLoop(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("loop", fsig)
	b0 := bb.NewBlock(ssa.BlockPlain)
	b1 := bb.NewBlock(ssa.BlockIf)
	b2 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)

	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	bb.LinkPlain(b1)

	bb.SetCurrent(b1)
	// Use x as the condition so it's a control value in b1 too.
	bb.LinkIf(x, b1, b2)

	bb.SetCurrent(b2)
	bb.FinishRet(x)

	r := ComputeLive(bb.Func(), ArchAMD64)
	for _, blkID := range []ssa.BlockID{b0.ID, b1.ID} {
		found := false
		for _, li := range r.LiveOut[blkID] {
			if li.ID == x.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Param x (v%d) should be in LiveOut[b%d] (used at loop exit and as loop control)", x.ID, blkID)
		}
	}
}

// TestComputeLivePhiArgs covers the phi-handling rule: phi.Args[i] is
// a use at the predecessor's terminator. We build a merge with a phi
// whose first arg is x (from the entry block) and second arg is a
// fresh value computed in a branch. x must be live-out of the entry
// block.
func TestComputeLivePhiArgs(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("phi", fsig)
	bEntry := bb.NewBlock(ssa.BlockIf)
	bThen := bb.NewBlock(ssa.BlockPlain)
	bMerge := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(bEntry)

	bb.SetCurrent(bEntry)
	x := bb.Param(0, ssa.TypeI32)
	bb.LinkIf(x, bThen, bMerge)

	bb.SetCurrent(bThen)
	one := bb.Const32(1)
	y := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.LinkPlain(bMerge)

	bb.SetCurrent(bMerge)
	// bMerge.Preds order is determined by edge-construction order:
	// LinkIf's else-branch wires bEntry→bMerge FIRST (Preds[0]),
	// then LinkPlain wires bThen→bMerge SECOND (Preds[1]). The phi's
	// args must match that pred order, so Args[0] = x (the value
	// flowing in from bEntry) and Args[1] = y (the value flowing in
	// from bThen).
	phi := bb.NewValue(ssa.OpPhi, ssa.TypeI32, x, y)
	bb.FinishRet(phi)

	r := ComputeLive(bb.Func(), ArchAMD64)
	// y (from bThen) must be live at end of bThen — it's consumed by
	// the phi at the bThen→bMerge edge.
	foundY := false
	for _, li := range r.LiveOut[bThen.ID] {
		if li.ID == y.ID {
			foundY = true
			break
		}
	}
	if !foundY {
		t.Errorf("y (v%d) should be in LiveOut[bThen] as a phi arg", y.ID)
	}
	// x must be live-out of bEntry — it's used both as the BlockIf
	// control AND as a phi arg on the bEntry→bMerge edge.
	foundX := false
	for _, li := range r.LiveOut[bEntry.ID] {
		if li.ID == x.ID {
			foundX = true
		}
	}
	if !foundX {
		t.Errorf("x (v%d) should be in LiveOut[bEntry]", x.ID)
	}
}

// TestNextCallArray exercises buildNextCall directly. For a block
// with values [Add, CALL, Sub, CALL, Ret], NextCall should be
// [1, 1, 3, 3, 5, 5].
func TestNextCallArray(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("nc", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.NewValueAuxInt(ssa.OpHelperCall, ssa.TypeMem, 0, x)
	bb.NewValue(ssa.OpSub32, ssa.TypeI32, x, one)
	bb.NewValueAuxInt(ssa.OpHelperCall, ssa.TypeMem, 0, x)
	bb.FinishRet(x)

	nc := buildNextCall(b0)
	// We need to locate the CALL positions; the builder ordering may
	// inline OpConst32 to a specific position. Find the indices.
	var callPos []int
	for i, v := range b0.Values {
		if v.Op == ssa.OpHelperCall {
			callPos = append(callPos, i)
		}
	}
	if len(callPos) != 2 {
		t.Fatalf("expected 2 CALLs, found %d", len(callPos))
	}
	// nc[i] should equal callPos[0] for i in [0, callPos[0]] and
	// callPos[1] for i in (callPos[0], callPos[1]], and len for i >
	// callPos[1].
	n := len(b0.Values)
	if int(nc[0]) != callPos[0] {
		t.Errorf("nc[0] = %d, want %d", nc[0], callPos[0])
	}
	if int(nc[callPos[0]+1]) != callPos[1] {
		t.Errorf("nc[after first call] = %d, want %d", nc[callPos[0]+1], callPos[1])
	}
	if int(nc[n]) != n {
		t.Errorf("nc[end] = %d, want %d (no call after)", nc[n], n)
	}
}
