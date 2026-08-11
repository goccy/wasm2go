package regalloc

import "github.com/goccy/wasm2go/internal/ssa"

// state is the mutable allocator state during the forward walk over a
// function. One state instance is created per function and shared by
// every block-processing step; per-block ABI (start/end register
// state) is published via the EndRegs / StartRegs side maps.
//
// Field-by-field mirror of Go's regAllocState (regalloc.go:247-342),
// trimmed to what wasm2go's lowering and emit path actually consume:
//
//   - No GC-bitmap reservations (wasm2go doesn't run a GC pass).
//   - No tuple/multi-result wiring (every SSA op produces 0 or 1
//     results; the Select / SelectN machinery is absent).
//   - No "doClobber" experiment harness.
//   - No `g` register tracking (the per-arch ArchInfo's Allocatable
//     mask already excludes it).
//
// What stays:
//   - regs[r] : value currently held in register r (per-walk).
//   - values[id] : per-value mutable state (where v is right now).
//   - used / nospill / tmpused : mask flags the input/output passes
//     consult.
//   - liveness + desired : precomputed once per function.
//   - endRegs[bID] / startRegs[bID] : per-block boundary state.
type state struct {
	f    *ssa.Func
	info ArchInfo

	// Precomputed per-function data.
	live    *LivenessResult
	desired *DesiredResult

	// values[v.ID] is the per-value mutable state. Indexed densely by
	// ID; index 0 is the SSA sentinel and stays zero.
	values []valState

	// regs[r] is the per-register mutable state. Indexed by register;
	// regs[r].V == 0 means the register is free.
	regs []regState

	// used is the set of registers currently holding some live value
	// (== union of bit r for each regs[r].V != 0). Tracked as a mask
	// to make "is this register free" a one-op check.
	used regMask
	// nospill is the set of registers pinned by the current op's
	// input-allocation pass; the input-side machinery flips these on
	// while it's walking V's args so a later input doesn't evict an
	// earlier one. Cleared after each op.
	nospill regMask
	// tmpused is the set of registers reserved as temporaries for the
	// current op (e.g. for ops that need a scratch register beyond
	// their inputs / outputs). Cleared after each op.
	tmpused regMask
	// usedSinceBlockStart is the union of registers that have been
	// occupied since the current block's start state was set. Used at
	// block end to trim startRegs entries that turned out unused.
	usedSinceBlockStart regMask

	// curBlock points at the block currently being walked.
	curBlock *ssa.Block
	// curIdx is the index inside curBlock.Values of the value being
	// processed. The advanceUses path reads this to consult
	// nextCall[curIdx].
	curIdx int

	// endRegs[blockID] is the end-state snapshot recorded after each
	// block is fully walked. EveryRegister mapped to a value at that
	// moment becomes an entry — successors inherit this set.
	endRegs [][]endReg
	// startRegs[blockID] is the start-state snapshot for merge
	// blocks: which values the block expects in which registers on
	// entry. The shuffle pass reads this on every predecessor edge.
	startRegs [][]startReg
}

// newState builds the allocator state and runs the precomputations
// (liveness + desired). Critical-edge splitting MUST already have run.
func newState(f *ssa.Func, info ArchInfo) *state {
	live := ComputeLive(f, info)
	desired := ComputeDesired(f, info)
	maxBlockID := ssa.BlockID(0)
	for _, b := range f.Blocks {
		if b.ID > maxBlockID {
			maxBlockID = b.ID
		}
	}
	maxVID := ssa.ValueID(len(f.Values))
	s := &state{
		f:         f,
		info:      info,
		live:      live,
		desired:   desired,
		values:    make([]valState, maxVID+1),
		regs:      make([]regState, info.NumRegs()),
		endRegs:   make([][]endReg, int(maxBlockID)+1),
		startRegs: make([][]startReg, int(maxBlockID)+1),
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			s.values[v.ID].NeedReg = info.ClassFor(v.Type) != ClassFlags
			s.values[v.ID].Rematerializeable = info.IsRematerializeable(v)
		}
	}
	return s
}

// assignReg records that register r now holds value v. Updates the
// reg ↔ value mapping in both directions, the used mask, and the
// usedSinceBlockStart counter.
func (s *state) assignReg(r register, v ssa.ValueID) {
	s.regs[r].V = v
	s.values[v].Regs |= 1 << r
	s.used |= 1 << r
	s.usedSinceBlockStart |= 1 << r
}

// freeReg releases register r. Used by both the natural "value died"
// path (advanceUses drops it) and the CALL-clobber sweep.
func (s *state) freeReg(r register) {
	v := s.regs[r].V
	if v == 0 {
		return
	}
	s.regs[r].V = 0
	s.values[v].Regs &^= 1 << r
	s.used &^= 1 << r
}

// freeRegs releases every register in mask. Used at CALL sites and
// when the start-state from a predecessor includes more values than
// the successor's live-in.
func (s *state) freeRegs(mask regMask) {
	for r := register(0); r < register(len(s.regs)); r++ {
		if mask&(1<<r) != 0 {
			s.freeReg(r)
		}
	}
}

// allocReg picks a register from `mask` for value v. The pick uses
// Go's Belady-with-copy strategy:
//
//  1. mask &= s.info.Allocatable() — never touch reserved regs.
//  2. mask &^= s.nospill — leave currently-pinned regs alone.
//  3. If `mask &^ s.used` has any bit (a free register), pick the
//     lowest one. (Go uses TrailingZeros — same here.)
//  4. Otherwise, walk every register in mask and pick the one
//     whose currently-resident value has the LARGEST next-use
//     distance. That's the Belady choice: evict the value whose
//     reuse is farthest in the future, since it'll be cheapest to
//     reload (the other values are about to be reused).
//
// The chosen register's previous occupant is NOT evicted by allocReg
// itself — the caller decides whether to insert a spill / copy /
// reload at that point. allocReg only returns the picked register.
//
// Returns noRegister when mask filters to 0 — that's a "no
// acceptable register exists" error that the caller must handle
// (typically by widening the mask or falling through to a spill).
func (s *state) allocReg(mask regMask, v ssa.ValueID) register {
	mask &= s.info.Allocatable()
	mask &^= s.nospill
	if mask == 0 {
		return noRegister
	}
	// Prefer an unused register.
	if free := mask &^ s.used; free != 0 {
		return trailingZero64(free)
	}
	// All in mask are used. Belady: pick the one whose value has the
	// farthest next use.
	pick := noRegister
	var bestDist int32 = -1
	for r := register(0); r < register(len(s.regs)); r++ {
		if mask&(1<<r) == 0 {
			continue
		}
		victim := s.regs[r].V
		if victim == 0 {
			// Shouldn't happen — mask says register has a user, but
			// regs map says it's free. Treat as free.
			return r
		}
		// nextUseDistance walks the value's use list; without a
		// per-value use list yet (state.go is scaffolding for the
		// input-allocation pass), fall back to a constant. The
		// input-allocation patch in walk.go wires this up to actual
		// use distances.
		d := s.nextUseDistance(victim)
		if d > bestDist {
			bestDist = d
			pick = r
		}
	}
	return pick
}

// nextUseDistance returns the distance to the next use of value v in
// the current block (or a large constant if v is live-out / has no
// further in-block use). The Belady eviction calls this for every
// register holder when choosing a spill victim.
//
// For now (state.go scaffolding), we approximate by reading
// LiveOut: if v appears there, its dist is the live-out distance
// plus the instructions remaining in the current block. Otherwise
// v is dead-from-here and gets a sentinel of 0.
//
// The input-allocation pass in walk.go will replace this with a
// per-block use list built at block top, which carries finer-
// grained in-block use distances.
func (s *state) nextUseDistance(v ssa.ValueID) int32 {
	if s.curBlock == nil {
		return 0
	}
	for _, li := range s.live.LiveOut[s.curBlock.ID] {
		if li.ID == v {
			// Distance from CURRENT position to end of block, plus
			// the live-out distance to the actual use.
			remaining := int32(len(s.curBlock.Values) - s.curIdx)
			return remaining + li.Dist
		}
	}
	// Not live-out and we've walked past its def — counts as dead.
	return 0
}

// trailingZero64 returns the index of the lowest set bit in m. We
// inline it instead of pulling math/bits to keep the package's
// dependency surface minimal; the function is hot, so the manual
// loop's bound-step matters less than avoiding the import here.
func trailingZero64(m regMask) register {
	r := register(0)
	if m == 0 {
		return noRegister
	}
	for m&1 == 0 {
		m >>= 1
		r++
	}
	return r
}
