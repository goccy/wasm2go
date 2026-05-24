package pass

import "github.com/goccy/wasm2go/internal/ssa"

// BranchFold rewrites every BlockIf whose condition is a known constant
// into a BlockPlain that jumps unconditionally to the taken successor.
//
// The not-taken edge is deleted — including the phi argument it
// contributed to the successor — and any block left unreachable from the
// entry is dropped. ConstProp must run first so a constant condition is
// actually an OpConst* value; running BranchFold in the same fixpoint
// loop lets a fold expose a constant branch that the next pass folds
// again.
//
// A malformed rewrite is not a correctness hazard: the caller re-runs
// ssa.Verify after the pipeline and falls back to the legacy compiler on
// any violation.
func BranchFold(f *ssa.Func) bool {
	changed := false
	for _, b := range f.Blocks {
		if b.Kind != ssa.BlockIf || b.Control == nil || len(b.Succs) != 2 {
			continue
		}
		c := b.Control
		if c.Op != ssa.OpConst32 && c.Op != ssa.OpConst64 {
			continue
		}
		// BlockIf: Succs[0] = then, Succs[1] = else; a non-zero
		// condition takes the then-edge.
		notTaken := 1
		if c.AuxInt == 0 {
			notTaken = 0
		}
		removeEdge(b, b.Succs[notTaken].Block)
		b.Kind = ssa.BlockPlain
		b.Control = nil
		changed = true
	}
	if changed {
		removeUnreachable(f)
	}
	return changed
}

// removeEdge deletes the first src→dst CFG edge. It drops the phi
// argument dst held for that predecessor, removes the pred/succ entries
// on both blocks, and repairs the Edge.Index back-references that the
// removal shifted.
func removeEdge(src, dst *ssa.Block) {
	p := -1
	for i := range dst.Preds {
		if dst.Preds[i].Block == src {
			p = i
			break
		}
	}
	if p < 0 {
		return
	}
	for _, v := range dst.Values {
		if v.Op == ssa.OpPhi && p < len(v.Args) {
			v.Args = append(v.Args[:p], v.Args[p+1:]...)
		}
	}
	dst.Preds = append(dst.Preds[:p], dst.Preds[p+1:]...)
	for i := p; i < len(dst.Preds); i++ {
		e := dst.Preds[i]
		e.Block.Succs[e.Index].Index = i
	}

	s := -1
	for i := range src.Succs {
		if src.Succs[i].Block == dst {
			s = i
			break
		}
	}
	if s < 0 {
		return
	}
	src.Succs = append(src.Succs[:s], src.Succs[s+1:]...)
	for i := s; i < len(src.Succs); i++ {
		e := src.Succs[i]
		e.Block.Preds[e.Index].Index = i
	}
}

// removeUnreachable drops every block not reachable from f.Entry,
// detaching their outgoing edges first so phi nodes in surviving
// successors stay consistent.
func removeUnreachable(f *ssa.Func) {
	reach := map[*ssa.Block]bool{f.Entry: true}
	work := []*ssa.Block{f.Entry}
	for len(work) > 0 {
		b := work[len(work)-1]
		work = work[:len(work)-1]
		for _, e := range b.Succs {
			if !reach[e.Block] {
				reach[e.Block] = true
				work = append(work, e.Block)
			}
		}
	}
	for _, b := range f.Blocks {
		if reach[b] {
			continue
		}
		for len(b.Succs) > 0 {
			removeEdge(b, b.Succs[0].Block)
		}
	}
	kept := f.Blocks[:0]
	for _, b := range f.Blocks {
		if reach[b] {
			kept = append(kept, b)
		}
	}
	f.Blocks = kept
}
