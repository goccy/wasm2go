package pass

import "github.com/goccy/wasm2go/internal/ssa"

// DCE is dead-code elimination: any value that is never used and has no
// side effect is marked dead (Op = OpInvalid) for Compact to sweep.
//
// Liveness is computed by marking from the roots and following Args:
//
//   - roots: side-effecting values (stores, calls, global.set, traps),
//     each block's Control value, and the Ret-tail return markers.
//   - a value is live iff it is a root or an argument of a live value.
//
// Returns true if anything was newly marked dead.
func DCE(f *ssa.Func) bool {
	live := make(map[ssa.ValueID]bool)
	var work []*ssa.Value
	mark := func(v *ssa.Value) {
		if v != nil && v.Op != ssa.OpInvalid && !live[v.ID] {
			live[v.ID] = true
			work = append(work, v)
		}
	}

	for _, b := range f.Blocks {
		mark(b.Control)
		nRes := 0
		switch b.Kind {
		case ssa.BlockRet:
			nRes = len(f.Sig.Results)
		case ssa.BlockThrow:
			// A BlockThrow's tail markers are its thrown operands.
			nRes = b.ThrowArgc
		}
		retStart := len(b.Values) - nRes
		for i, v := range b.Values {
			if v.Op == ssa.OpInvalid {
				continue
			}
			if v.HasSideEffect() {
				mark(v)
			}
			if i >= retStart { // Ret-tail return marker
				mark(v)
			}
		}
	}
	for len(work) > 0 {
		v := work[len(work)-1]
		work = work[:len(work)-1]
		for _, a := range v.Args {
			mark(a)
		}
	}

	changed := false
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpInvalid && !live[v.ID] {
				v.Op = ssa.OpInvalid
				v.Args = nil
				changed = true
			}
		}
	}
	return changed
}
