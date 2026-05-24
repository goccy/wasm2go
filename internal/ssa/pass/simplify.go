package pass

import "github.com/goccy/wasm2go/internal/ssa"

// Simplify performs copy propagation and trivial-phi elimination.
//
//   - OpCopy: a value `c = copy(x)` is equivalent to x. Every
//     reference to c is rewritten to x (transitively, following copy
//     and trivial-phi chains).
//   - trivial phi: a phi whose arguments, ignoring self-references,
//     are all the same value V is equivalent to V; references to it
//     are likewise rewritten.
//
// The dissolved copies / phis are marked dead (OpInvalid) for Compact;
// DCE is not needed to clean them, though running it afterwards also
// reclaims anything that became unused.
//
// The Ret-tail OpCopy markers — the canonical return-value slots the
// emit stage relies on — are preserved: their *arguments* are still
// forwarded, but the marker value itself is never dissolved.
//
// Returns true if anything changed.
func Simplify(f *ssa.Func) bool {
	ret := retMarkerSet(f)

	// canon memoises each value's ultimate representative. A value
	// maps to itself unless it is a (non-Ret) copy or a trivial phi.
	canon := make(map[ssa.ValueID]*ssa.Value)
	var resolve func(v *ssa.Value) *ssa.Value
	resolve = func(v *ssa.Value) *ssa.Value {
		if v == nil {
			return nil
		}
		if r, ok := canon[v.ID]; ok {
			return r
		}
		canon[v.ID] = v // tentative self-map breaks cycles
		var next *ssa.Value
		switch {
		case v.Op == ssa.OpCopy && !ret[v.ID] && len(v.Args) == 1:
			next = v.Args[0]
		case v.Op == ssa.OpPhi:
			next = trivialPhiArg(v)
		}
		if next != nil && next != v {
			r := resolve(next)
			canon[v.ID] = r
			return r
		}
		return v
	}

	changed := false
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ssa.OpInvalid {
				continue
			}
			for i, a := range v.Args {
				if a == nil {
					continue
				}
				if r := resolve(a); r != a {
					v.Args[i] = r
					changed = true
				}
			}
		}
		if b.Control != nil {
			if r := resolve(b.Control); r != b.Control {
				b.Control = r
				changed = true
			}
		}
	}
	// Mark every dissolved value (a non-Ret copy or trivial phi whose
	// representative is not itself) dead.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ssa.OpInvalid || ret[v.ID] {
				continue
			}
			if resolve(v) != v {
				v.Op = ssa.OpInvalid
				v.Args = nil
				changed = true
			}
		}
	}
	return changed
}

// trivialPhiArg returns the single distinct non-self argument of a phi,
// or nil when the phi has two or more distinct real arguments (so it is
// a genuine merge and must stay).
func trivialPhiArg(v *ssa.Value) *ssa.Value {
	if v.Op != ssa.OpPhi {
		return nil
	}
	var uniq *ssa.Value
	for _, a := range v.Args {
		if a == nil || a == v {
			continue // self-reference contributes nothing
		}
		if uniq == nil {
			uniq = a
			continue
		}
		if a != uniq {
			return nil
		}
	}
	return uniq
}

// retMarkerSet returns the IDs of the Ret-tail return markers — the
// last len(Results) values of each BlockRet, which emit relies on
// staying as OpCopy.
func retMarkerSet(f *ssa.Func) map[ssa.ValueID]bool {
	set := map[ssa.ValueID]bool{}
	for _, b := range f.Blocks {
		if b.Kind != ssa.BlockRet {
			continue
		}
		n := len(b.Values)
		for i := n - len(f.Sig.Results); i < n; i++ {
			if i >= 0 {
				set[b.Values[i].ID] = true
			}
		}
	}
	return set
}
