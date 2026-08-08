package pass

import "github.com/goccy/wasm2go/internal/ssa"

// FoldEmptyDiamonds collapses BlockIf diamonds whose arms compute
// nothing: both successor paths reach the same join immediately —
// either directly or through an empty single-entry BlockPlain — and
// the join keeps no phi. The If becomes a BlockPlain falling through
// to the join; the detached arm is dropped and the condition value
// dies in ordinary DCE afterwards.
//
// This shape appears when a value-selection idiom is rewritten away
// at the SSA level (e.g. the packed f16 store conversion): the phi
// that justified the diamond is deleted by DCE, but the branch — a
// side-effect-free control structure — survives, still evaluating
// its condition every iteration. Folding it is not speculation: with
// empty arms and no phi, both paths are observably identical.
//
// Run in a fixpoint with DCE: folding an inner diamond empties the
// enclosing arm, exposing the outer diamond to the next round.
func FoldEmptyDiamonds(f *ssa.Func) bool {
	changed := false
	for _, b := range f.Blocks {
		if b.Kind != ssa.BlockIf || len(b.Succs) != 2 {
			continue
		}
		join0, _ := diamondPath(b, b.Succs[0].Block)
		join1, arm1 := diamondPath(b, b.Succs[1].Block)
		if join0 == nil || join0 != join1 || join0 == b {
			continue
		}
		if hasPhi(join0) {
			continue
		}
		// Detach the second path; the first becomes the fall-through.
		if arm1 != nil {
			removeEdge(b, arm1)
		} else {
			removeEdge(b, join1)
		}
		b.Kind = ssa.BlockPlain
		b.Control = nil
		changed = true
	}
	if changed {
		removeUnreachable(f)
	}
	return changed
}

// diamondPath resolves one If successor to the diamond's join block:
// either the successor IS the join (triangle form, arm == nil), or it
// is an empty single-pred single-succ BlockPlain leading to the join.
func diamondPath(from, s *ssa.Block) (join, arm *ssa.Block) {
	if s.Kind == ssa.BlockPlain && len(s.Values) == 0 &&
		len(s.Preds) == 1 && len(s.Succs) == 1 && s != from {
		return s.Succs[0].Block, s
	}
	return s, nil
}

func hasPhi(b *ssa.Block) bool {
	for _, v := range b.Values {
		if v.Op == ssa.OpPhi {
			return true
		}
	}
	return false
}
