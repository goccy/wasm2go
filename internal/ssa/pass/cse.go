package pass

import (
	"fmt"

	"github.com/goccy/wasm2go/internal/ssa"
)

// CSE is common-subexpression elimination. Within a block, two pure
// values that compute the same thing — same op, type, immediates, and
// (canonicalised) operands — are merged: the later one is marked dead
// and every reference to it is rewritten to the earlier one.
//
// Scope is intentionally intra-block: cross-block CSE needs dominance
// information and is deferred. Side-effecting values, phis and the
// Ret-tail markers are never merged.
//
// Returns true if anything changed.
func CSE(f *ssa.Func) bool {
	ret := retMarkerSet(f)
	// canon maps a merged-away value to its surviving equivalent.
	canon := make(map[ssa.ValueID]*ssa.Value)
	resolve := func(v *ssa.Value) *ssa.Value {
		for v != nil {
			r, ok := canon[v.ID]
			if !ok || r == v {
				return v
			}
			v = r
		}
		return v
	}

	changed := false
	for _, b := range f.Blocks {
		seen := make(map[string]*ssa.Value)
		for _, v := range b.Values {
			if v.Op == ssa.OpInvalid || ret[v.ID] {
				continue
			}
			if !cseEligible(v) {
				continue
			}
			key := cseKey(v, resolve)
			if prev, ok := seen[key]; ok {
				canon[v.ID] = prev
				changed = true
			} else {
				seen[key] = v
			}
		}
	}
	if !changed {
		return false
	}
	// Rewrite all references through the merge map, then bury the
	// merged-away values.
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
				}
			}
		}
		if b.Control != nil {
			b.Control = resolve(b.Control)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ssa.OpInvalid {
				continue
			}
			if r, ok := canon[v.ID]; ok && r != v {
				v.Op = ssa.OpInvalid
				v.Args = nil
			}
		}
	}
	return true
}

// cseEligible reports whether v is a candidate for merging: a pure,
// deterministic value. Memory loads are excluded — without a Mem token
// two textually-identical loads may observe different memory.
func cseEligible(v *ssa.Value) bool {
	if v.Op == ssa.OpPhi || v.Op == ssa.OpParam || v.HasSideEffect() {
		return false
	}
	switch v.Op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64, ssa.OpGlobalGet,
		// OpLocalGet reads a mutable local var (EH mutable-locals mode);
		// two identical reads separated by an OpLocalSet differ.
		ssa.OpLocalGet:
		return false
	}
	return true
}

// cseKey builds the value-numbering key for v: op, type, immediates and
// the (canonicalised) operand IDs. Operands of a commutative op are
// sorted so `a+b` and `b+a` hash equal.
func cseKey(v *ssa.Value, resolve func(*ssa.Value) *ssa.Value) string {
	ids := make([]int64, 0, len(v.Args))
	for _, a := range v.Args {
		if a == nil {
			ids = append(ids, -1)
			continue
		}
		ids = append(ids, int64(resolve(a).ID))
	}
	if v.Op.IsCommutative() && len(ids) == 2 {
		if ids[0] > ids[1] {
			ids[0], ids[1] = ids[1], ids[0]
		}
	}
	return fmt.Sprintf("%d/%d/%d/%v/%v", v.Op, v.Type, v.AuxInt, v.Aux, ids)
}
