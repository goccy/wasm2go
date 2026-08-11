package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// Result is the side-table the asmgen reads to know where each value
// lives during emit. Populated by Allocate; consumed by the per-arch
// emitter.
type Result struct {
	// Home[v.ID] is the register name (e.g. "AX", "X3", "R12") the
	// value lives in, or "" if it spills to a stack slot. The string
	// form is what asmgen's existing plan.regHome expects, so the
	// integration step is a direct rename.
	Home map[ssa.ValueID]string
	// SpillNeeded[v.ID] is true when a stack slot must back the
	// value (it survives a CALL, gets evicted, or is consumed cross-
	// block via a slot reload). The slot itself is assigned by
	// stackalloc.
	SpillNeeded map[ssa.ValueID]bool
	// EndRegs[blockID] and StartRegs[blockID] are the per-block I/O
	// the shuffle pass reads. EndRegs[b] is the register state at the
	// end of b; StartRegs[b] is what b expects on entry.
	EndRegs   [][]endReg
	StartRegs [][]startReg
}

// Allocate runs the cross-block linear-scan register allocator on f
// and returns the side-table the asm emitter consumes. The pipeline:
//
//  1. Split critical edges.
//  2. Build state, run computeLive + computeDesired.
//  3. Forward walk blocks in natural order:
//     - Set start register state (from primary predecessor's end
//     state when applicable).
//     - For each value, allocate input registers (3-pass: pin /
//     pin-free / free-pick), allocate output register, mark
//     CALL clobbers as free.
//     - Snapshot end register state.
//  4. Spill placement (TODO — currently inserts at def site for
//     everything that needs a slot).
//  5. Edge shuffle (TODO — the current Result populates EndRegs /
//     StartRegs but the asmgen integration pass writes the actual
//     MOVs at emit time).
//
// The Allocate function is intentionally a single entry point so the
// asmgen integration code only knows about Result, not the internal
// state. An asmgen-side bridge walks Result and
// populates plan.regHome / plan.spillSlot.
func Allocate(f *ssa.Func, info ArchInfo) *Result {
	SplitCriticalEdges(f)
	s := newState(f, info)
	r := &Result{
		Home:        map[ssa.ValueID]string{},
		SpillNeeded: map[ssa.ValueID]bool{},
		EndRegs:     s.endRegs,
		StartRegs:   s.startRegs,
	}
	for _, b := range f.Blocks {
		s.curBlock = b
		s.usedSinceBlockStart = 0
		s.adoptStartState(b)
		for i, v := range b.Values {
			s.curIdx = i
			if v.Op == ssa.OpPhi {
				// Phi homes are decided when entering the block —
				// either inherited from a primary pred's end state
				// or spilled to a slot. The forward walk skips them.
				continue
			}
			if !s.values[v.ID].NeedReg {
				continue
			}
			s.allocateInputs(v)
			s.allocateOutput(v, r)
			if isCall(v.Op) {
				// Free every register held by a still-live value
				// (its next-use distance was already bumped by the
				// CALL penalty in liveness, so future allocations
				// naturally prefer non-evicted regs). Mark each
				// clobbered value as SpillNeeded so the bridge knows
				// its "Home" is no longer authoritative — the value
				// went to memory during the CALL, and any post-CALL
				// reload would land it in a (possibly different)
				// register that the existing emit doesn't know
				// about.
				spec := info.RegSpec(v)
				for rr := register(0); rr < register(len(s.regs)); rr++ {
					if spec.Clobbers&(1<<rr) == 0 {
						continue
					}
					if held := s.regs[rr].V; held != 0 {
						r.SpillNeeded[held] = true
					}
				}
				s.freeRegs(spec.Clobbers)
			}
			s.nospill = 0
			s.tmpused = 0
		}
		// Record end state. EndRegs[b.ID] is the set of (reg, value)
		// pairs that the successor block (if it's a single-pred or
		// the primary pred) can adopt verbatim.
		var end []endReg
		for r2 := register(0); r2 < register(len(s.regs)); r2++ {
			if v := s.regs[r2].V; v != 0 {
				end = append(end, endReg{R: r2, V: v})
			}
		}
		s.endRegs[b.ID] = end
		// Mark any live-out value that didn't end up in a register
		// as needing a spill slot — the spill-placement and
		// stackalloc passes assign actual offsets, but the home
		// decision is made here.
		for _, li := range s.live.LiveOut[b.ID] {
			if s.values[li.ID].Regs == 0 {
				r.SpillNeeded[li.ID] = true
			}
		}
	}
	r.EndRegs = s.endRegs
	r.StartRegs = s.startRegs
	return r
}

// adoptStartState sets the register state at entry to block b. Three
// cases:
//
//   - b is the entry block: no incoming state, every register starts
//     free.
//
//   - b has exactly one predecessor that's already been walked: we
//     inherit that predecessor's EndRegs verbatim (any values not in
//     b's live-in get freed). This is the "free" cross-block case
//     and the reason cross-block regalloc dramatically beats per-
//     block regalloc: most CFG edges in straight-line code have
//     single preds, and their start state is "whatever the pred
//     ended with."
//
//   - b is a merge block (>1 preds): we adopt one predecessor's end
//     state as a starting point and rely on the edge-shuffle pass
//     to fix up the other preds to match. Picking the primary pred
//     is currently "first visited pred"; the Go allocator picks by
//     smallest spillLive size — that refinement lands as part of
//     primary-pred selection.
func (s *state) adoptStartState(b *ssa.Block) {
	// Zero out the regs / used / values[*].Regs bookkeeping.
	for r := register(0); r < register(len(s.regs)); r++ {
		s.regs[r].V = 0
	}
	for i := range s.values {
		s.values[i].Regs = 0
	}
	s.used = 0
	if b == s.f.Entry {
		return
	}
	// Build the live-in set so we can drop adopted values that
	// aren't live here. LiveOut[b] was populated by computeLive as
	// the live-in-from-successors set; LiveOut[pred] is what we want
	// here — values live at the END of the pred, which IS live-in
	// for this block (modulo edge-specific phi work).
	liveIn := map[ssa.ValueID]bool{}
	for _, li := range s.live.LiveOut[b.ID] {
		liveIn[li.ID] = true
	}
	if len(b.Preds) == 1 {
		pred := b.Preds[0].Block
		for _, er := range s.endRegs[pred.ID] {
			if !liveIn[er.V] {
				continue
			}
			s.assignReg(er.R, er.V)
		}
		return
	}
	// Merge block: adopt the first predecessor's state. The shuffle
	// pass will reconcile the others.
	var primary *ssa.Block
	for _, p := range b.Preds {
		if p.Block == nil {
			continue
		}
		// Skip preds that haven't been visited yet (back-edges).
		// We detect this by checking whether their endRegs slot has
		// been populated. Block IDs are dense so the slice check is
		// safe.
		if int(p.Block.ID) < len(s.endRegs) && s.endRegs[p.Block.ID] != nil {
			primary = p.Block
			break
		}
	}
	if primary == nil {
		// First merge-pred is a back-edge (loop header). Start
		// empty — the shuffle pass + spill machinery will load
		// whatever's needed.
		return
	}
	var start []startReg
	for _, er := range s.endRegs[primary.ID] {
		if !liveIn[er.V] {
			continue
		}
		s.assignReg(er.R, er.V)
		start = append(start, startReg(er))
	}
	s.startRegs[b.ID] = start
}

// allocateInputs implements the 3-pass input register allocation
// from Go's regalloc.go:1580-1656:
//
//	Pass 1 — pin args already in their required single-reg slot.
//	Pass 2 — allocate must-be-in-X args while X is free, looping
//	         until no progress (each allocation may free up another
//	         input's preferred register).
//	Pass 3 — allocate remaining inputs, biased toward desired regs
//	         and away from the per-block avoid mask.
//
// Each input that ends up in a register sets a bit in s.nospill so
// later inputs in the same op can't evict it. The CALL clobber
// sweep (back in Allocate) clears nospill once the op finishes.
func (s *state) allocateInputs(v *ssa.Value) {
	spec := s.info.RegSpec(v)
	// Pass 1: pin args already where they need to be.
	for _, in := range spec.Inputs {
		if in.Idx >= len(v.Args) {
			continue
		}
		a := v.Args[in.Idx]
		if a == nil {
			continue
		}
		r := singleBitRegister(in.Regs)
		if r == noRegister {
			continue
		}
		if s.regs[r].V == a.ID {
			s.nospill |= 1 << r
		}
	}
	// Pass 2 + 3 collapsed: iterate inputs and allocate each. For
	// must-be-in-X args we use the exact register; for any-of-N we
	// honour the desired hint when possible.
	hintMap := s.desired.Hints[s.curBlock.ID]
	for _, in := range spec.Inputs {
		if in.Idx >= len(v.Args) {
			continue
		}
		a := v.Args[in.Idx]
		if a == nil {
			continue
		}
		// Already in the right register from Pass 1? Skip.
		if s.values[a.ID].Regs&in.Regs != 0 {
			r := trailingZero64(s.values[a.ID].Regs & in.Regs)
			s.nospill |= 1 << r
			continue
		}
		mask := in.Regs
		// Bias mask toward a's hint, if one exists.
		if hintMap != nil {
			if ent := hintMap[a.ID]; ent != nil {
				for _, hr := range ent.Regs {
					if hr != noRegister && mask&(1<<hr) != 0 {
						mask = 1 << hr
						break
					}
				}
			}
		}
		r := s.allocReg(mask, a.ID)
		if r == noRegister {
			// Couldn't pick a register — mark for spill. The actual
			// reload-insertion happens in the emit integration; for
			// the side-table here we record "no home, needs slot".
			s.values[a.ID].SpillNeeded = true
			continue
		}
		// If r was holding a different value, that value gets
		// implicitly evicted. The spill-placement pass will track
		// this and place the spill instruction; for now we just
		// rewrite the mapping.
		if old := s.regs[r].V; old != 0 && old != a.ID {
			s.values[old].SpillNeeded = true
			s.freeReg(r)
		}
		s.assignReg(r, a.ID)
		s.nospill |= 1 << r
	}
}

// allocateOutput picks a register for v's output and records the
// per-value home in the Result map. Honours hints from the desired
// table and steers clear of registers in the avoid set.
func (s *state) allocateOutput(v *ssa.Value, r *Result) {
	spec := s.info.RegSpec(v)
	if len(spec.Outputs) == 0 {
		return
	}
	out := spec.Outputs[0]
	mask := out.Regs
	hintMap := s.desired.Hints[s.curBlock.ID]
	if hintMap != nil {
		if ent := hintMap[v.ID]; ent != nil {
			for _, hr := range ent.Regs {
				if hr != noRegister && mask&(1<<hr) != 0 {
					mask = 1 << hr
					break
				}
			}
		}
	}
	// Avoid registers other defs want. If the bias would leave us
	// with no candidates, fall back to the full mask.
	if avoid := s.desired.Avoid[s.curBlock.ID]; avoid != 0 {
		if mask&^avoid != 0 {
			mask &^= avoid
		}
	}
	reg := s.allocReg(mask, v.ID)
	if reg == noRegister {
		// Output couldn't find a register — spill placement and
		// stackalloc will allocate a slot. We record "spill needed" so the emit
		// side can resolve through plan.offsets.
		r.SpillNeeded[v.ID] = true
		return
	}
	// Evict whatever's in `reg` if it's a different value.
	if old := s.regs[reg].V; old != 0 && old != v.ID {
		s.values[old].SpillNeeded = true
		s.freeReg(reg)
	}
	s.assignReg(reg, v.ID)
	r.Home[v.ID] = s.info.RegName(reg)
}
