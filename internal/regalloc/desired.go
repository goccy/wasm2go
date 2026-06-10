package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// DesiredResult is the output of ComputeDesired: per-block affinity
// hints for the allocator. Each entry says "value V would prefer to
// live in one of these registers (priority-ordered)" — the allocator
// biases its choice toward the first slot whose register is currently
// free.
//
// Hints come from two sources:
//
//  1. Single-bit input masks on downstream consumers. When an op
//     requires its arg in a specific register (CALL ABI args, IDIV's
//     AX, SHL's CL), the producer would save a reg-to-reg copy by
//     landing in that register up front.
//
//  2. Two-address (IsResultInArg0) ops. The output must share arg0's
//     register; if arg0 wants register R for its NEXT use as well,
//     biasing the output to R lets the whole `MOV arg0, dst; OP src,
//     dst` chain collapse.
//
// avoid[b.ID] is the set of registers other values in this block want
// — the allocator deprioritises them when assigning a new output to
// avoid "stealing" a register a peer was saving. (Go's regalloc:
// desiredState.avoid at regalloc.go:3270-3289.)
type DesiredResult struct {
	// Hints[b.ID] is a (sparse) map from ValueID to its hint list.
	// Keys are values that have at least one usable hint; values not
	// in the map have no specific preference and accept any
	// allocatable register.
	Hints []map[ssa.ValueID]*desiredEntry
	// Avoid[b.ID] is the union of registers preferred by OTHER values
	// in this block — used to break ties when picking a new output
	// register so we don't steal from a peer.
	Avoid []regMask
}

// ComputeDesired walks the function once per block (in reverse) and
// computes register affinity hints. Mirrors Go's computeDesired at
// regalloc.go:3142-3197, simplified to skip the iterative loop-nest
// propagation (our use cases don't show measurable win from the
// extra pass).
//
// Walk order per block: backwards over values. For each value V:
//  1. Remove V's own desired entry — V is being DEFINED here, its
//     output goes wherever the allocator picks, not where downstream
//     consumers said.
//  2. Clobber the op's clobber-mask out of Avoid (those registers
//     are no longer "wanted" past this point — the op trashes them).
//  3. For each input position with countRegs(regs) == 1 (a fixed-
//     reg input), record "V.Args[i] wants this register". This is
//     what gives CALL args their AX/BX/CX/DX hints up front and
//     what makes the SHL's count arg prefer CX.
//  4. For IsResultInArg0 ops, propagate V's own hints (the
//     consumer-driven ones we already recorded) back to arg0 — so
//     `dst = arg0 OP arg1` ends up choosing arg0's register
//     consistently and the leading `MOV arg0, dst` shrinks to
//     nothing.
func ComputeDesired(f *ssa.Func, info ArchInfo) *DesiredResult {
	maxBlockID := ssa.BlockID(0)
	for _, b := range f.Blocks {
		if b.ID > maxBlockID {
			maxBlockID = b.ID
		}
	}
	r := &DesiredResult{
		Hints: make([]map[ssa.ValueID]*desiredEntry, int(maxBlockID)+1),
		Avoid: make([]regMask, int(maxBlockID)+1),
	}
	for _, b := range f.Blocks {
		// hints accumulates "what would value V want?" — keyed by
		// the value's ID. snapshot is the per-value state captured AT
		// the moment V is defined (its consumer-driven preferences),
		// which is what the forward walk reads when picking V's
		// register. Walking backwards means hints[V] grows over the
		// course of the loop until we hit V's def site; at that
		// moment we snapshot, then delete (V is allocated, its slot
		// in the running map is no longer relevant for the args of
		// values defined ABOVE V).
		hints := map[ssa.ValueID]*desiredEntry{}
		snapshot := map[ssa.ValueID]*desiredEntry{}
		var avoid regMask
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]
			spec := info.RegSpec(v)

			// Step 1: snapshot V's current hint state (built up by
			// downstream consumers we already processed) — that's
			// what V would prefer when the forward walk reaches its
			// def site.
			if ent, ok := hints[v.ID]; ok {
				snapshot[v.ID] = ent
			}

			// Step 2: V is being defined here. Remove its entry
			// from the running map so values defined ABOVE V (in
			// reverse order, i.e. EARLIER source positions) don't
			// see "this register is reserved for a later V".
			delete(hints, v.ID)

			// Step 3: clobbers no longer apply past V's def site —
			// V trashes those regs, so anything below was already
			// going to spill.
			avoid &^= spec.Clobbers

			// Step 4: IsResultInArg0 — propagate V's own (now
			// snapshot) hints to arg0. Reading the snapshot covers
			// the case where V had hints from downstream consumers
			// AND its output position is fixed to arg0's register.
			if info.IsResultInArg0(v.Op) && len(v.Args) > 0 && v.Args[0] != nil {
				if ent, ok := snapshot[v.ID]; ok {
					for _, hr := range ent.Regs {
						if hr == noRegister {
							continue
						}
						addHint(hints, v.Args[0].ID, hr)
					}
				}
			}

			// Step 5: V's spec inputs may pin specific registers.
			// Any input position with a single-bit mask becomes a
			// hint for that arg.
			for _, in := range spec.Inputs {
				if in.Idx >= len(v.Args) {
					continue
				}
				a := v.Args[in.Idx]
				if a == nil {
					continue
				}
				if r := singleBitRegister(in.Regs); r != noRegister {
					addHint(hints, a.ID, r)
					avoid |= 1 << r
				}
			}
		}
		// Publish per-block hints. The snapshot map captures one
		// entry per value with downstream-driven preferences; values
		// not in the map can be assigned freely.
		if len(snapshot) > 0 {
			r.Hints[b.ID] = snapshot
		}
		r.Avoid[b.ID] = avoid
	}
	return r
}

// singleBitRegister reports the register encoded by a single-bit
// mask, or noRegister if the mask has zero or more than one bit set.
// Used to detect "this position must be in EXACTLY this register" —
// the only shape that turns into a hint.
func singleBitRegister(m regMask) register {
	if m == 0 || m&(m-1) != 0 {
		return noRegister
	}
	// Find the bit position. We don't pull math/bits here to keep
	// the package's dependency surface minimal; the manual loop is
	// fine since it runs at most once per RegSpec input check.
	for r := register(0); r < 64; r++ {
		if m == 1<<r {
			return r
		}
	}
	return noRegister
}

// addHint inserts a register hint into the per-value priority list.
// If the entry doesn't exist, it's created; if the register is
// already present, it stays at its current position (we don't
// promote — Go's allocator doesn't either). If all MaxDesiredHints
// slots are filled, the new hint is dropped silently — anything
// beyond the 4th hint is rarely consulted.
func addHint(hints map[ssa.ValueID]*desiredEntry, id ssa.ValueID, r register) {
	e, ok := hints[id]
	if !ok {
		e = &desiredEntry{}
		for i := range e.Regs {
			e.Regs[i] = noRegister
		}
		hints[id] = e
	}
	for i, cur := range e.Regs {
		if cur == r {
			return // already present
		}
		if cur == noRegister {
			e.Regs[i] = r
			return
		}
	}
	// All slots full; drop. (Hints beyond MaxDesiredHints are rarely
	// consulted.)
}
