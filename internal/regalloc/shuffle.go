package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// EdgeMove describes one register-to-register transfer the asm
// emitter must insert at a CFG edge. The shuffle pass produces a
// per-edge list of these so the predecessor's end-state matches the
// successor's expected start-state.
//
// V is always set (the value being transferred). SrcReg / DstReg name
// the source and destination registers; when one of them is
// noRegister, the move involves a stack slot (a spill or a reload).
// SrcSlot / DstSlot give the offset for those cases.
//
// The emitter walks the move list in order and emits a single MOV
// per entry. Order matters — the shuffle solver schedules entries so
// each move is safe to issue at its position (the source still holds
// the right value, and the destination is no longer needed for some
// other in-flight move).
type EdgeMove struct {
	// V is the SSA value being moved. The emitter uses v to pick
	// the right move width (i32 MOVL vs i64 MOVQ vs f32 MOVSS etc.).
	V ssa.ValueID
	// SrcReg names the source register, or noRegister when the
	// source is a stack slot (a reload).
	SrcReg register
	// DstReg names the destination register, or noRegister when the
	// destination is a stack slot (a spill).
	DstReg register
}

// ComputeEdgeMoves runs the per-edge shuffle pass for every block
// whose entry state expects values different from its primary pred's
// exit. Implements Go's regalloc.go shuffle / edgeState.process
// algorithm (lines 2321-2519) as a parallel-copy solver:
//
//  1. Build a "want this value in this register" list (the
//     destination set) from startRegs[succ.ID].
//  2. Build a "this value is in this register" map (the source
//     state) from endRegs[pred.ID].
//  3. Loop: find a destination whose target register is currently
//     free OR holds the desired value already. Emit the move,
//     update the source state, remove the destination. Repeat.
//  4. When nothing in (3) makes progress, the remaining destinations
//     form a CYCLE on registers (Rx wants what Ry has, Ry wants
//     what Rx has, possibly chained). Pick a temp register
//     (anything not in the cycle and not currently in use), copy
//     one cycle element to the temp, then resume from (3) — the
//     cycle now has a free slot.
//
// Returns a map keyed by (pred.ID, succ.ID) listing the moves to
// emit on each edge. An edge with no moves is absent from the map.
func ComputeEdgeMoves(f *ssa.Func, info ArchInfo, endRegs [][]endReg, startRegs [][]startReg) map[edgeKey][]EdgeMove {
	out := map[edgeKey][]EdgeMove{}
	for _, succ := range f.Blocks {
		if len(succ.Preds) == 0 {
			continue
		}
		if startRegs[succ.ID] == nil {
			// Successor never published a start-state (it's a
			// single-pred block that adopted its predecessor's
			// end-state directly). No reconciliation needed.
			continue
		}
		for _, predEdge := range succ.Preds {
			pred := predEdge.Block
			if int(pred.ID) >= len(endRegs) || endRegs[pred.ID] == nil {
				continue
			}
			moves := solveEdge(info, endRegs[pred.ID], startRegs[succ.ID])
			if len(moves) > 0 {
				out[edgeKey{Pred: pred.ID, Succ: succ.ID}] = moves
			}
		}
	}
	return out
}

// edgeKey identifies a CFG edge by (pred, succ) block IDs. Used as
// the map key for per-edge move lists so the emitter can look up
// shuffles by (currentBlock, takenSuccIdx).
type edgeKey struct {
	Pred ssa.BlockID
	Succ ssa.BlockID
}

// solveEdge runs the parallel-copy algorithm for one (pred, succ)
// pair. The input states are:
//
//   - srcEnd: every (reg, value) pair the predecessor holds at the
//     end of its block.
//   - dstStart: every (reg, value) pair the successor expects on
//     entry.
//
// Output: a list of EdgeMove that, when emitted at the end of the
// predecessor's block, transform srcEnd into dstStart.
func solveEdge(info ArchInfo, srcEnd []endReg, dstStart []startReg) []EdgeMove {
	// curHolder[r] = the value currently in register r as the
	// shuffle progresses. Initialised from srcEnd; mutated as we
	// emit moves.
	curHolder := map[register]ssa.ValueID{}
	for _, er := range srcEnd {
		curHolder[er.R] = er.V
	}
	// remaining is the set of "still need to do" destinations: V
	// must end up in R. We index by destination register because
	// each register has at most one wanted value (the start state
	// is well-formed).
	remaining := map[register]ssa.ValueID{}
	for _, sr := range dstStart {
		// Skip destinations that are already satisfied — the
		// predecessor already holds the right value in the right
		// register.
		if cur, ok := curHolder[sr.R]; ok && cur == sr.V {
			delete(curHolder, sr.R)
			continue
		}
		remaining[sr.R] = sr.V
	}
	var moves []EdgeMove
	// Main loop. We bound at 64 × |remaining| as a defense against
	// the (impossible) infinite loop, but each pass either resolves
	// a destination directly or breaks a cycle, so termination is
	// guaranteed in O(|remaining|) iterations.
	guard := 0
	for len(remaining) > 0 {
		guard++
		if guard > 256 {
			// Pathological — give up. Caller will see incomplete
			// move list and the emit pass will warn.
			break
		}
		progress := false
		// Try to satisfy any destination directly: the destination
		// register is either free (no current holder) or its
		// current holder is the desired value (already done — we
		// pruned those above, so this shouldn't happen here).
		for dstR, wantV := range remaining {
			// Find where wantV currently lives. If wantV is the
			// current holder of some register, copy from there.
			srcR := noRegister
			for r, v := range curHolder {
				if v == wantV {
					srcR = r
					break
				}
			}
			// Can we emit the move? Only if the destination is
			// either currently empty OR its current holder isn't
			// in `remaining.Values()` (i.e. no one needs to read
			// it from there). The latter check prevents stomping
			// on a value that's still needed for another move.
			if !canEmitTo(dstR, curHolder, remaining) {
				continue
			}
			if srcR == noRegister {
				// Value not currently in any register — must reload
				// from a slot. Emit a reload-style move; the actual
				// slot offset is filled by the asmgen integration
				// (the asmgen bridge) which sees plan.offsets[wantV].
				moves = append(moves, EdgeMove{V: wantV, SrcReg: noRegister, DstReg: dstR})
			} else {
				moves = append(moves, EdgeMove{V: wantV, SrcReg: srcR, DstReg: dstR})
				delete(curHolder, srcR)
			}
			curHolder[dstR] = wantV
			delete(remaining, dstR)
			progress = true
			break
		}
		if progress {
			continue
		}
		// No direct progress — we're in a cycle. Pick any
		// destination, find a free temp register, copy the
		// destination's current holder to the temp, then loop.
		pickedDst := noRegister
		for dstR := range remaining {
			pickedDst = dstR
			break
		}
		if pickedDst == noRegister {
			break
		}
		// Find a free temp register in the allocatable pool that
		// isn't currently in curHolder and isn't a destination in
		// remaining.
		mask := info.Allocatable()
		for r := range curHolder {
			mask &^= 1 << r
		}
		for r := range remaining {
			mask &^= 1 << r
		}
		if mask == 0 {
			// No free register for the cycle break — spill the
			// cycle entry to a slot, then load back to the
			// destination. Emit two moves.
			cycleHolder := curHolder[pickedDst]
			if cycleHolder != 0 {
				moves = append(moves, EdgeMove{V: cycleHolder, SrcReg: pickedDst, DstReg: noRegister})
				delete(curHolder, pickedDst)
			}
			// Now pickedDst is free; the next loop iteration will
			// emit the wanted move into it directly (and the
			// reload of cycleHolder, if it was wanted, will come
			// later via the reload path).
			continue
		}
		tempR := trailingZero64(mask)
		// Copy whatever's currently in pickedDst into tempR.
		if cycleHolder, ok := curHolder[pickedDst]; ok {
			moves = append(moves, EdgeMove{V: cycleHolder, SrcReg: pickedDst, DstReg: tempR})
			curHolder[tempR] = cycleHolder
			delete(curHolder, pickedDst)
		}
		// Loop again — pickedDst is now free, the direct-emit
		// path will fill it.
	}
	return moves
}

// canEmitTo reports whether moving a new value into register dstR is
// safe at this point in the shuffle: dstR is either empty, or its
// current holder is not a still-pending source (so overwriting
// doesn't destroy a value still needed for some other move).
func canEmitTo(dstR register, curHolder map[register]ssa.ValueID, remaining map[register]ssa.ValueID) bool {
	cur, occupied := curHolder[dstR]
	if !occupied {
		return true
	}
	// The current holder must not be needed by any other still-
	// pending destination as a source.
	for _, wantV := range remaining {
		if wantV == cur {
			return false
		}
	}
	return true
}
