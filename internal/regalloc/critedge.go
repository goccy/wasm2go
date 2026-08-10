package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// SplitCriticalEdges removes every critical edge from f's CFG by
// inserting an empty BlockPlain on each one. A critical edge is one
// whose source block has >1 successors AND whose destination has >1
// predecessors — the per-edge shuffle the allocator emits at the
// source can't be made specific to a single outgoing arm if the source
// branches to multiple destinations, and can't be merged with another
// pred's shuffle if the destination has multiple incoming arms.
//
// The fix Go uses (cmd/compile/internal/ssa/critical.go) is to insert
// a no-op block in the middle: src → newBlock → dst. After the split,
// newBlock has exactly 1 predecessor (src) and exactly 1 successor
// (dst), so any per-edge shuffle lives unambiguously inside newBlock.
//
// The transformation is shape-preserving for everything else in the
// SSA — phi nodes in `dst` keep the same args (we patch their Edge
// indices, not their value list) and no new values get created.
//
// f must already have a populated f.Entry and Preds/Succs for every
// block. Calling SplitCriticalEdges on a function that's been through
// SSA construction once is safe and idempotent (a second call finds
// no remaining critical edges and returns the function unchanged).
//
// Returns the count of edges split — useful for tests and for
// diagnostics.
func SplitCriticalEdges(f *ssa.Func) int {
	split := 0
	// Snapshot the block list because we'll be appending new blocks.
	// The split has to consider only edges that existed before the
	// pass started; the new blocks have a single pred and single succ
	// by construction, so they can never themselves be critical.
	original := append([]*ssa.Block(nil), f.Blocks...)
	for _, src := range original {
		if len(src.Succs) < 2 {
			// A block with at most one outgoing edge can't be the
			// source side of a critical edge — even if the successor
			// has many predecessors, the source's single fall-through
			// can hold edge-specific code.
			continue
		}
		// Walk a copy of the successors. We mutate src.Succs in
		// place, so iterating the live slice would visit new entries
		// (impossible here — we only replace, never append — but
		// keeping the snapshot makes the invariant explicit).
		succs := make([]ssa.Edge, len(src.Succs))
		copy(succs, src.Succs)
		for i, succEdge := range succs {
			dst := succEdge.Block
			if len(dst.Preds) < 2 {
				// Single-predecessor destinations are safe — any
				// shuffle the allocator wants on this edge can go at
				// the end of `src` directly.
				continue
			}
			// Critical edge found. Insert a synthetic BlockPlain
			// between src and dst, replacing the src→dst edge with
			// src→new→dst. The new block has no Values (the shuffle
			// pass will add per-edge moves later if needed).
			newBlock := f.NewBlock(ssa.BlockPlain)

			// Rewire src's outgoing edge at index i to point at newBlock.
			// The Index field is the position in newBlock.Preds we'll
			// occupy — which is 0 since newBlock has no other preds.
			src.Succs[i] = ssa.Edge{Block: newBlock, Index: 0}
			newBlock.Preds = []ssa.Edge{{Block: src, Index: i}}

			// Rewire dst's incoming edge: find the entry that
			// referenced src (by Edge.Block identity) and rewrite it
			// to reference newBlock. The Edge.Index on dst's side is
			// the position in newBlock.Succs — also 0.
			for j := range dst.Preds {
				if dst.Preds[j].Block == src && dst.Preds[j].Index == i {
					dst.Preds[j] = ssa.Edge{Block: newBlock, Index: 0}
					break
				}
			}
			newBlock.Succs = []ssa.Edge{{Block: dst, Index: indexInPreds(dst, newBlock)}}
			split++
		}
	}
	return split
}

// indexInPreds locates b's position in dst.Preds after the rewire.
// Called once per split; the linear walk is fine because the typical
// pred count is 2–3.
func indexInPreds(dst, b *ssa.Block) int {
	for j, p := range dst.Preds {
		if p.Block == b {
			return j
		}
	}
	// Shouldn't happen — the caller just put `b` into dst.Preds.
	return -1
}
