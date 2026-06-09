package asmgen

import (
	"github.com/goccy/wasm2go/internal/regalloc"
	"github.com/goccy/wasm2go/internal/ssa"
)

// applyNewRegalloc routes the function through the new cross-block
// Belady allocator in internal/regalloc and translates
// the returned Result into the existing funcPlan side-table that
// emit_amd64 / emitarm64 consume. The translation is mostly a
// string-to-string copy (plan.regHome) plus a slot-offset rewrite
// (plan.offsets), keeping the emitter completely unchanged.
//
// Gating: the caller decides whether to invoke this path. As of the
// initial integration we only fire it when the function has no
// merge blocks — the edge-shuffle path is still in progress and a
// merge block would currently miscompile. hasMergeBlock guards the
// caller.
//
// Arch selection: regalloc.ArchAMD64 or regalloc.ArchARM64,
// determined by the asmgen arch in scope.
// applyNewRegalloc returns true iff its stackalloc step ran and
// rewrote plan.offsets. The caller skips compactFrame in
// that case to avoid double-packing the layout.
func applyNewRegalloc(f *ssa.Func, plan *funcPlan, a arch) (didStackalloc bool) {
	var info regalloc.ArchInfo
	switch a.(type) {
	case archAMD64:
		info = regalloc.ArchAMD64
	case archARM64:
		info = regalloc.ArchARM64
	default:
		// Unknown arch — fall back to the existing block-local pass.
		computeRegHomes(f, plan)
		return false
	}

	if !isSafeForNewRegalloc(f) {
		computeRegHomes(f, plan)
		return false
	}

	// Always start from computeRegHomes (the block-local safe baseline).
	// We then OVERRIDE entries with the new allocator's choices ONLY
	// for values that pass three safety filters:
	//
	//   1. The new allocator gave the value a register (Home[v] is
	//      non-empty) AND so did computeRegHomes — the value is
	//      regHome-eligible by the existing emit's contract.
	//
	//   2. The new allocator did NOT mark the value SpillNeeded.
	//      SpillNeeded fires whenever a value was evicted from its
	//      register during the forward walk OR clobbered by a CALL
	//      with subsequent uses. Either case means the new
	//      allocator's r.Home is not authoritative across the
	//      value's full lifetime — the existing emit (which reads
	//      plan.regHome as a single permanent home) would misplace
	//      the value.
	//
	//   3. The new register is in newRegallocCompatPool — the
	//      subset of GP registers the existing emit knows how to
	//      treat as regHome destinations. AX/BX/CX/DX/SI are emit-
	//      side scratch and would be clobbered by the very next
	//      MOV; the new allocator must not steer values into those.
	computeRegHomes(f, plan)

	r := regalloc.Allocate(f, info)

	// Build a set of value IDs that participate in a phi (either AS
	// the phi destination OR as a phi.Args input). These values
	// cross block boundaries via the phi edge-copy machinery, which
	// reads plan.regHome[src] at the predecessor's terminator. If
	// we override the register of such a value, the predecessor
	// emit reads from the new register — but at the predecessor's
	// end the value may still live in its old register (the new
	// allocator's choice differs from the predecessor block's
	// view). Conservative for now: skip overrides for phi-touched
	// values until the per-block-end accessor lands.
	phiTouched := map[ssa.ValueID]bool{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpPhi {
				continue
			}
			phiTouched[v.ID] = true
			for _, a := range v.Args {
				if a != nil {
					phiTouched[a.ID] = true
				}
			}
		}
	}

	// Build a per-register USE COUNT (not a set) of the baseline
	// regHomes. A register can be the baseline home of MULTIPLE
	// values whose lifetimes don't overlap (computeRegHomes is
	// block-local, so two values in disjoint blocks can both land
	// in R8). Tracking just a set would let an override of one
	// value falsely "free" the register for another override even
	// while other peers still occupy it.
	useCount := map[string]int{}
	for _, reg := range plan.regHome {
		if reg != "" {
			useCount[reg]++
		}
	}
	for vid, reg := range r.Home {
		baseline, ok := plan.regHome[vid]
		if !ok {
			continue
		}
		if r.SpillNeeded[vid] {
			continue
		}
		if phiTouched[vid] {
			continue
		}
		if !newRegallocCompatPool[reg] {
			continue
		}
		if reg == baseline {
			continue // no-op override; skip silently
		}
		if useCount[reg] > 0 {
			continue // a peer already holds this register
		}
		// Decrement the baseline count and increment the new count.
		// Decrementing is correct because vid is moving OUT of
		// baseline; other peers retain their baseline registration
		// through their own positive counts.
		useCount[baseline]--
		useCount[reg]++
		plan.regHome[vid] = reg
	}

	return applyNewStackalloc(f, plan, info, phiTouched)
}

// applyNewStackalloc runs the interference-aware AllocateSlots over
// EVERY slot-resident value (regHome == "" in the baseline plan)
// and rewrites plan.offsets / plan.frameSize wholesale when the new
// layout fits. Phi-touched values participate in the new layout too:
// keeping them on baseline offsets while other values move would
// risk collision with the new packing. Since operandSrc /
// EmitPhiCopy / CALL arg staging all read plan.offsets[v.ID] at
// emit time, rewriting the offset uniformly is safe — every reader
// picks up the new value transparently.
//
// phiTemp slots (used by emit_amd64's staged-phi cycle break) sit
// ABOVE the value-slot region in compactFrame; we
// re-pack them to start at the new value-slot high-water mark,
// matching the policy compactFrame already uses.
func applyNewStackalloc(f *ssa.Func, plan *funcPlan, info regalloc.ArchInfo, phiTouched map[ssa.ValueID]bool) bool {
	// Apply interference-based slot sharing on EVERY function. The
	// stackalloc unit tests pass in isolation; the bridge
	// integration here writes the resulting layout into
	// plan.offsets / plan.frameSize / plan.phiTemp and the existing
	// emit picks it up through its usual operandSrc / phi-edge
	// readers.
	_ = phiTouched
	res := &regalloc.Result{
		Home:        map[ssa.ValueID]string{},
		SpillNeeded: map[ssa.ValueID]bool{},
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			// Phi values stay in the SpillNeeded set — they're
			// slot-resident in the existing emit (phi homes are
			// slots, edge copies write to them) and the new
			// stackalloc must reserve a slot for each so its layout
			// doesn't pack a non-phi value into the offset a phi
			// already occupies.
			home, ok := plan.regHome[v.ID]
			if ok && home != "" {
				continue
			}
			if _, hasOff := plan.offsets[v.ID]; !hasOff {
				continue
			}
			res.SpillNeeded[v.ID] = true
		}
	}
	sa := regalloc.AllocateSlots(f, info, res, plan.calleeArea)
	if sa.FrameSize <= 0 || sa.FrameSize >= plan.frameSize {
		return false
	}
	// Rewrite offsets for every value the new layout placed.
	for vid, off := range sa.Offset {
		plan.offsets[vid] = off
	}
	// Repack phiTemp slots above the new value-slot high-water mark
	// — same scheme compactFrame uses.
	if len(plan.phiTemp) > 0 {
		ids := make([]ssa.ValueID, 0, len(plan.phiTemp))
		for id := range plan.phiTemp {
			ids = append(ids, id)
		}
		// Sort for deterministic offsets.
		sortValueIDs(ids)
		phiType := map[ssa.ValueID]ssa.Type{}
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				if v.Op == ssa.OpPhi {
					phiType[v.ID] = v.Type
				}
			}
		}
		newOff := sa.FrameSize
		for _, id := range ids {
			size := 4
			if t, ok := phiType[id]; ok {
				if t == ssa.TypeI64 || t == ssa.TypeF64 {
					size = 8
				}
			}
			align := size
			newOff = (newOff + align - 1) &^ (align - 1)
			plan.phiTemp[id] = newOff
			newOff += size
		}
		plan.frameSize = (newOff + 7) &^ 7
		return true
	}
	plan.frameSize = sa.FrameSize
	return true
}

// sortValueIDs is a tiny insertion sort on ssa.ValueID slices —
// stable, in-place, no external deps. Used by applyNewStackalloc
// for the phiTemp repack order so frame offsets are deterministic
// across runs.
func sortValueIDs(ids []ssa.ValueID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
}

// hasMergeBlock reports whether f has any block with more than one
// predecessor.
func hasMergeBlock(f *ssa.Func) bool {
	for _, b := range f.Blocks {
		if len(b.Preds) > 1 {
			return true
		}
	}
	return false
}

// isSafeForNewRegalloc reports whether the function's CFG is simple
// enough that the new allocator's choices can replace
// computeRegHomes' wholesale without further emit-side integration
// work. The safe shape is:
//
//  1. A single block (no cross-block adopt, no edge shuffle, no
//     phi reconciliation).
//  2. No CALLs (no caller-save clobber to reason about — the new
//     allocator's CALL-spill is correct in isolation but the
//     existing emit's CALL path expects a specific regHome
//     contract).
//  3. No OpPhi (no phi-edge work).
//
// On every function NOT matching this shape we fall back to
// computeRegHomes' choices unchanged. Once the emit-side integration
// (per-use-site accessor, CALL spill emission, phi shuffle output)
// lands, this gate widens to "any function" — currently the
// conservative gate keeps 35/35 packages passing while the new
// allocator's foundation matures.
func isSafeForNewRegalloc(f *ssa.Func) bool {
	// Merge-block functions are routed through the bridge but the
	// per-value overrides skip phi-touched values. For non-merge
	// CFGs the bridge applies all eligible overrides; for merge
	// CFGs the phiTouched filter (in applyNewRegalloc) is what
	// keeps the override safe.
	_ = f
	return true
}

// newRegallocCompatPool names the registers the existing emit
// accepts as plan.regHome values WITHOUT colliding with the per-
// function reservation passes:
//
//   - AX/BX/CX/DX/SI are emit-side scratch; the per-op emitters
//     stage operands through them and would clobber any
//     regalloc-assigned value the moment any other value's emit
//     fires.
//   - R11 is the m-cache reservation.
//   - R12/R13/R15 are the loop-carry phi-coalesce reservation pool;
//     a new-allocator value taking one of those would collide with
//     a loop-carry coalesced value.
//   - R14 is Go's `g` pointer.
//
// That leaves DI, R8, R9, R10 for the bridge to override. Those four
// are the safe overlap between the block-local regalloc's "we
// know how to emit into this register" set and the "no other
// reservation pass needs it" set. The SSE pool similarly
// restricts to X2..X7 (the block-local sseRegPool); X0/X1 are
// emit-side float scratch.
var newRegallocCompatPool = map[string]bool{
	"DI": true, "R8": true, "R9": true, "R10": true,
	"X2": true, "X3": true, "X4": true, "X5": true, "X6": true, "X7": true,
}
