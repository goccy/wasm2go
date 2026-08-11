package regalloc

import (
	"testing"
)

// TestSolveEdgeNoMoves: pred and succ agree on every register —
// no moves needed.
func TestSolveEdgeNoMoves(t *testing.T) {
	src := []endReg{{R: amd64AX, V: 1}, {R: amd64BX, V: 2}}
	dst := []startReg{{R: amd64AX, V: 1}, {R: amd64BX, V: 2}}
	moves := solveEdge(ArchAMD64, src, dst)
	if len(moves) != 0 {
		t.Errorf("expected 0 moves when states agree, got %d: %v", len(moves), moves)
	}
}

// TestSolveEdgeSimpleSwap: pred has v1 in AX; succ wants v1 in BX.
// One move: AX → BX.
func TestSolveEdgeSimpleSwap(t *testing.T) {
	src := []endReg{{R: amd64AX, V: 1}}
	dst := []startReg{{R: amd64BX, V: 1}}
	moves := solveEdge(ArchAMD64, src, dst)
	if len(moves) != 1 {
		t.Fatalf("expected 1 move, got %d: %v", len(moves), moves)
	}
	m := moves[0]
	if m.V != 1 || m.SrcReg != amd64AX || m.DstReg != amd64BX {
		t.Errorf("move = %+v, want {V:1, AX→BX}", m)
	}
}

// TestSolveEdgeReloadFromSlot: succ expects a value that pred doesn't
// hold in any register — needs a reload from a slot (SrcReg ==
// noRegister).
func TestSolveEdgeReloadFromSlot(t *testing.T) {
	// pred has v1 in AX. succ wants v2 in BX. v2 must come from a slot.
	src := []endReg{{R: amd64AX, V: 1}}
	dst := []startReg{{R: amd64BX, V: 2}}
	moves := solveEdge(ArchAMD64, src, dst)
	if len(moves) != 1 {
		t.Fatalf("expected 1 move, got %d: %v", len(moves), moves)
	}
	m := moves[0]
	if m.SrcReg != noRegister {
		t.Errorf("expected SrcReg=noRegister (reload from slot), got %v", m.SrcReg)
	}
	if m.DstReg != amd64BX || m.V != 2 {
		t.Errorf("move = %+v, want {V:2, slot→BX}", m)
	}
}

// TestSolveEdgeCycleTwoReg: classic 2-cycle. pred has v1 in AX and
// v2 in BX; succ wants v1 in BX and v2 in AX. The solver must use a
// temp register.
func TestSolveEdgeCycleTwoReg(t *testing.T) {
	src := []endReg{{R: amd64AX, V: 1}, {R: amd64BX, V: 2}}
	dst := []startReg{{R: amd64AX, V: 2}, {R: amd64BX, V: 1}}
	moves := solveEdge(ArchAMD64, src, dst)
	if len(moves) < 3 {
		t.Fatalf("expected at least 3 moves for a 2-cycle (temp + 2 main), got %d: %v",
			len(moves), moves)
	}
	// At end, AX should hold v2 and BX should hold v1. We don't
	// pin the exact temp register or order — just that the moves
	// achieve the right final state.
	regs := map[register]int{amd64AX: 1, amd64BX: 2} // initial state
	for _, m := range moves {
		if m.SrcReg != noRegister {
			delete(regs, m.SrcReg)
		}
		regs[m.DstReg] = int(m.V)
	}
	if regs[amd64AX] != 2 {
		t.Errorf("after shuffle: AX should hold v2, got v%d", regs[amd64AX])
	}
	if regs[amd64BX] != 1 {
		t.Errorf("after shuffle: BX should hold v1, got v%d", regs[amd64BX])
	}
}

// TestSolveEdgeThreeRegChain: pred has v1 in AX, v2 in BX, v3 in CX;
// succ wants v1 in BX, v2 in CX, v3 in AX. Chain that becomes a
// cycle once two moves complete (or never directly resolvable).
func TestSolveEdgeThreeRegChain(t *testing.T) {
	src := []endReg{{R: amd64AX, V: 1}, {R: amd64BX, V: 2}, {R: amd64CX, V: 3}}
	dst := []startReg{{R: amd64BX, V: 1}, {R: amd64CX, V: 2}, {R: amd64AX, V: 3}}
	moves := solveEdge(ArchAMD64, src, dst)
	// Validate final state by simulating.
	regs := map[register]int{amd64AX: 1, amd64BX: 2, amd64CX: 3}
	for _, m := range moves {
		if m.SrcReg != noRegister {
			delete(regs, m.SrcReg)
		}
		regs[m.DstReg] = int(m.V)
	}
	if regs[amd64AX] != 3 || regs[amd64BX] != 1 || regs[amd64CX] != 2 {
		t.Errorf("after shuffle: regs = %v, want {AX:3, BX:1, CX:2}", regs)
	}
}

// TestSolveEdgeAlreadyInPlace: a destination's value is already in
// the wanted register — solver skips it (no move emitted).
func TestSolveEdgeAlreadyInPlace(t *testing.T) {
	src := []endReg{{R: amd64AX, V: 1}, {R: amd64BX, V: 2}}
	dst := []startReg{{R: amd64AX, V: 1}, {R: amd64CX, V: 2}} // BX → CX needed; AX already right
	moves := solveEdge(ArchAMD64, src, dst)
	if len(moves) != 1 {
		t.Fatalf("expected 1 move (BX→CX), got %d: %v", len(moves), moves)
	}
	m := moves[0]
	if m.V != 2 || m.SrcReg != amd64BX || m.DstReg != amd64CX {
		t.Errorf("move = %+v, want {V:2, BX→CX}", m)
	}
}
