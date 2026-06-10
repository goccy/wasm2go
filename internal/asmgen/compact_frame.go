package asmgen

import (
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// compactFrame re-packs plan.offsets after computeRegHomes
// has decided which SSA values stay in a register. Pass 2 allocated a
// slot for every value with a non-zero scalar size; for values that
// end up regHome'd those slots are dead — the emit path resolves
// reads through plan.regHome and never touches the slot. The compact
// pass:
//
//  1. Walks every SSA value once and collects the (old offset, size,
//     align) of slots that are STILL live — i.e. owned by at least
//     one non-regHome'd value. Reg-only slots are reclaimed.
//
//  2. Re-allocates each surviving offset densely starting at
//     plan.calleeArea. Slots that share an offset under the
//     linear-scan slot-reuse pass stay sharing the same new offset
//     — the seen
//     map keys on the old offset so the mapping is one-to-one in
//     each direction.
//
//  3. Updates plan.offsets so every entry — including the ones owned
//     by regHome'd values — points at the new offset (or 0 if the
//     old offset was reg-only and has no successor). Touching the
//     regHome'd entries is harmless: those entries are never read by
//     the emit path, and the rewrite keeps the map self-consistent
//     for any inspector / debug dumper.
//
//  4. Recomputes plan.frameSize as the new high-water mark, padded
//     to 8-byte alignment to match Pass 2's invariant.
//
// The pass is idempotent — running it twice on the same plan produces
// the same offsets — and a no-op when plan.regHome is empty (the
// "still live" set is the whole offset map, so compaction reproduces
// the input).
func compactFrame(f *ssa.Func, plan *funcPlan) {
	// Step 1: collect surviving offsets. For values that share a
	// slot via the reuse pass, only the first owner contributes —
	// the same old offset would otherwise show up multiple times
	// and remap to multiple new offsets.
	type slot struct {
		off, size, align int
	}
	var slots []slot
	seenOff := map[int]bool{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if plan.regHome[v.ID] != "" {
				continue
			}
			size, align := slotSize(v.Type)
			if size == 0 {
				continue
			}
			off, ok := plan.offsets[v.ID]
			if !ok {
				continue
			}
			if seenOff[off] {
				continue
			}
			seenOff[off] = true
			slots = append(slots, slot{off, size, align})
		}
	}

	// Step 2: re-allocate densely. Sort by old offset so the new
	// layout preserves the relative order Pass 2 chose — this keeps
	// the cross-block / multi-slot reuse decisions stable across
	// compactions and makes diffing the asm before/after easier.
	sort.Slice(slots, func(i, j int) bool { return slots[i].off < slots[j].off })

	oldToNew := make(map[int]int, len(slots))
	newOff := plan.calleeArea
	for _, s := range slots {
		newOff = alignUp(newOff, s.align)
		oldToNew[s.off] = newOff
		newOff += s.size
	}

	// Step 3: rewrite every plan.offsets entry. Entries owned by a
	// regHome'd value whose slot is no longer live (no
	// oldToNew[old] mapping) collapse to 0 — they were going to
	// reference a hole in the new layout, and the emit code never
	// reads those entries so the value is irrelevant. We could
	// leave the old offset in place but that would leave dangling
	// references to past-end-of-frame memory in any debug dump.
	for vid, old := range plan.offsets {
		if n, ok := oldToNew[old]; ok {
			plan.offsets[vid] = n
		} else {
			plan.offsets[vid] = 0
		}
	}

	// Step 4: relocate non-value slots that lived ABOVE the old
	// plan.frameSize. The only such category today is plan.phiTemp,
	// staging temps for parallel phi copies that live OUTSIDE
	// Pass 2's value-slot region. If we left them at their old
	// offsets the shrunken frame would no longer cover them and
	// the emit path's `<old phiTemp off>(SP)` would read past the
	// bottom of the function's stack window. Re-pack them densely
	// starting at the new value-slot high-water mark.
	if len(plan.phiTemp) > 0 {
		// Collect phiTemp entries with stable iteration order — map
		// iteration is random, and a non-deterministic offset choice
		// would produce different asm bytes from one regen to the
		// next, breaking goldens.
		ids := make([]ssa.ValueID, 0, len(plan.phiTemp))
		for id := range plan.phiTemp {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			return plan.phiTemp[ids[i]] < plan.phiTemp[ids[j]]
		})
		// Look up each phi value's type — phiTemp is keyed by the
		// phi value's own ID, and its slot must match the phi's
		// SSA type. Build a quick (id -> type) lookup so we can
		// pick the right size / align.
		phiType := map[ssa.ValueID]ssa.Type{}
		for _, blk := range f.Blocks {
			for _, v := range blk.Values {
				if v.Op == ssa.OpPhi {
					phiType[v.ID] = v.Type
				}
			}
		}
		for _, id := range ids {
			size, align := slotSize(phiType[id])
			if size == 0 {
				continue
			}
			newOff = alignUp(newOff, align)
			plan.phiTemp[id] = newOff
			newOff += size
		}
	}

	// Step 5: frame size = high-water mark, 8-byte aligned to match
	// Pass 2's invariant.
	plan.frameSize = alignUp(newOff, 8)
}
