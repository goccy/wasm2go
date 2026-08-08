package pass

import "github.com/goccy/wasm2go/internal/ssa"

// CoalesceSimdBounds replaces the per-access bounds checks of runs of
// v128 loads with one range check.
//
// Every SIMD memory helper carries its own bounds check, and in ggml's
// kernels — the code this exists for — a single loop iteration loads
// several v128s at small constant offsets from one base. Each check
// costs more instructions than the load it guards. A wasm JIT pays
// nothing at all here (guard pages); an AOT translation cannot use
// guard pages, but it CAN see, ahead of time, that eight checks against
// the same base collapse into one.
//
//	load(base+0) load(base+16) ... load(base+112)
//	  =>  load_rng(base, 0, lo=0, span=128) load_nc(base+16) ...
//
// The group's first load carries the whole range check (the _rng form:
// trap unless [base+lo, base+lo+span) is in bounds, then load at its
// own offset); the rest use the unchecked _nc form. Fusing check into
// load matters because real kernels interleave two streams (x and y
// blocks) with only two loads each: a separate check call would cost
// as much as the checks it replaces.
//
// Soundness is about traps, since in-bounds behaviour is identical:
//
//   - A group contains LOADS only, and loads have no side effects, so
//     evaluating a later load's bounds condition at the group's first
//     load cannot lose or reorder any observable effect: if any access
//     in the group would trap, the group traps before anything else
//     happens. Other loads sitting between group members (from another
//     stream's group) are equally unaffected — a load either traps
//     (and nothing was written anyway) or has no effect.
//   - Any value with a side effect or a trap of its own — stores of
//     every kind, calls (which can also grow memory), scalar memory
//     writes, division — is a barrier: every open group closes there.
//     Checks never move across barriers, so trap ORDER against other
//     trapping operations is preserved.
//   - Grouping keys on the syntactic base: the address value minus a
//     small constant addend. Members must lie within a small window
//     (their u32 address arithmetic then cannot wrap differently from
//     the check's, because the coalesced check proves ea+span fits in
//     the memory size, which is ≤ 2^32).
//
// Only plain v128.load participates for now: it dominates the profile,
// and the extend/splat variants can join later with their own _nc
// forms.
func CoalesceSimdBounds(f *ssa.Func) bool {
	changed := false
	for _, b := range f.Blocks {
		changed = coalesceBlock(f, b) || changed
	}
	return changed
}

// simdBoundsWindow bounds the constant spread inside one group. Small
// enough that combined offsets stay far from u32 wraparound, large
// enough for any real kernel's working set.
const simdBoundsWindow = 1 << 16

type simdLoadRef struct {
	idx   int        // index in b.Values
	v     *ssa.Value // the OpSimdMemCall
	total int64      // constant displacement from the group's base
}

type simdLoadGroup struct {
	base *ssa.Value
	refs []simdLoadRef
}

func coalesceBlock(f *ssa.Func, b *ssa.Block) bool {
	var groups []simdLoadGroup
	// Concurrently open groups, one per distinct base, in first-seen
	// order: kernels interleave streams (x block, y block), so a
	// different-base load must not close the other stream's group.
	var open []simdLoadGroup

	flushAll := func() {
		for _, g := range open {
			if len(g.refs) >= 2 {
				groups = append(groups, g)
			}
		}
		open = open[:0]
	}

	for i := 0; i < len(b.Values); i++ {
		v := b.Values[i]
		if v == nil || v.Op == ssa.OpInvalid {
			continue
		}
		if v.Op == ssa.OpSimdMemCall && v.Aux == "simd_v128_load" {
			base, off, ok := splitSimdAddr(v)
			if !ok {
				continue // opaque address: not groupable, but no barrier either
			}
			ref := simdLoadRef{idx: i, v: v, total: off}
			placed := false
			for gi := range open {
				if open[gi].base != base {
					continue
				}
				if fitsWindow(open[gi].refs, off) {
					open[gi].refs = append(open[gi].refs, ref)
				} else {
					// Window overflow: close this base's group and
					// reopen with the new member.
					if len(open[gi].refs) >= 2 {
						groups = append(groups, open[gi])
					}
					open[gi] = simdLoadGroup{base: base, refs: []simdLoadRef{ref}}
				}
				placed = true
				break
			}
			if !placed {
				open = append(open, simdLoadGroup{base: base, refs: []simdLoadRef{ref}})
			}
			continue
		}
		if simdBoundsBarrier(v) {
			flushAll()
		}
	}
	flushAll()

	// Emit in descending first-load index: each rewrite inserts two
	// constants at its group's first-load index, which shifts every
	// later index — earlier collected indices stay valid only in this
	// order. Groups never share a first-load index.
	for gi := 0; gi < len(groups); gi++ {
		for gj := gi + 1; gj < len(groups); gj++ {
			if groups[gj].refs[0].idx > groups[gi].refs[0].idx {
				groups[gi], groups[gj] = groups[gj], groups[gi]
			}
		}
	}
	for _, g := range groups {
		emitCoalesced(f, b, g.base, g.refs)
	}
	return len(groups) > 0
}

// splitSimdAddr decomposes a load's effective address into (base value,
// constant displacement): the memarg offset plus any constant addend
// peeled off the address. A fully-constant address uses a nil-like
// zero base by keeping the constant as the base (no peeling); those
// still group when the same constant value is shared (CSE has run).
func splitSimdAddr(v *ssa.Value) (*ssa.Value, int64, bool) {
	if len(v.Args) < 2 {
		return nil, 0, false
	}
	addr := v.Args[0]
	offV := v.Args[1]
	if offV.Op != ssa.OpConst32 {
		return nil, 0, false
	}
	off := int64(uint32(int32(offV.AuxInt)))
	if addr.Op == ssa.OpAdd32 && len(addr.Args) == 2 && addr.Args[1].Op == ssa.OpConst32 {
		// Peel only NON-NEGATIVE addends: the exactness argument in
		// the package doc needs every member displacement ≥ 0, so a
		// member's u32 address can only wrap UPWARD past 2^32 relative
		// to the base, never downward past 0.
		c := int64(int32(addr.Args[1].AuxInt))
		if c >= 0 && c < simdBoundsWindow {
			return addr.Args[0], off + c, true
		}
	}
	return addr, off, true
}

func fitsWindow(refs []simdLoadRef, off int64) bool {
	lo, hi := off, off
	for _, r := range refs {
		if r.total < lo {
			lo = r.total
		}
		if r.total > hi {
			hi = r.total
		}
	}
	return hi-lo < simdBoundsWindow && lo > -simdBoundsWindow && hi < simdBoundsWindow
}

// simdBoundsBarrier reports whether v closes every open group: anything
// with a side effect or a trap of its own. Pure computation passes
// through. Value.HasSideEffect encodes exactly this boundary — calls,
// stores, atomics and trapping helpers report true — except that it is
// conservative about SIMD calls, whose pure forms never trap.
func simdBoundsBarrier(v *ssa.Value) bool {
	if v.Op == ssa.OpSimdCall {
		return false
	}
	return v.HasSideEffect()
}

// emitCoalesced rewrites the group's first load into the range-checked
// _rng form covering the whole group and every other member into the
// unchecked _nc form.
//
// The first load keeps its own position and offset (its result is
// still that address's bytes); it additionally receives (rlo, span)
// constant arguments describing the group window RELATIVE TO ITS addr
// ARGUMENT: the helper checks [addr+rlo, addr+rlo+span). The group's
// minimum displacement lo is relative to the peeled base, and addr
// already carries the first load's peeled addend c1, so rlo = lo - c1
// — which can be negative when the first load is not the group's
// lowest address (the helper takes rlo signed for exactly this).
func emitCoalesced(f *ssa.Func, b *ssa.Block, base *ssa.Value, refs []simdLoadRef) {
	lo, hi := refs[0].total, refs[0].total
	for _, r := range refs {
		if r.total < lo {
			lo = r.total
		}
		if r.total > hi {
			hi = r.total
		}
	}
	span := hi + 16 - lo
	first := refs[0]
	firstOff := int64(uint32(int32(first.v.Args[1].AuxInt)))
	c1 := first.total - firstOff // the peeled addend
	rlo := lo - c1
	if rlo < -(1<<31) || rlo >= 1<<31 || span >= 1<<31 {
		return // huge memarg offsets pushed the window out of i32; keep per-load checks
	}
	loC := b.NewValueBefore(f, first.idx, ssa.OpConst32, ssa.TypeI32, int64(int32(rlo)), nil)
	spanC := b.NewValueBefore(f, first.idx+1, ssa.OpConst32, ssa.TypeI32, int64(int32(uint32(span))), nil)
	first.v.Aux = "simd_v128_load_rng"
	first.v.Args = append(first.v.Args, loC, spanC)
	for _, r := range refs[1:] {
		r.v.Aux = "simd_v128_load_nc"
	}
}
