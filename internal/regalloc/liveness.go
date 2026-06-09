package regalloc

import (
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// LivenessResult is the output of computeLive: per-block live-out
// information with next-use distances, plus per-block nextCall data
// the allocator's forward walk consults when deciding whether to
// proactively drop values from registers in front of a CALL.
type LivenessResult struct {
	// LiveOut[b.ID] lists the (ID, dist) pairs live at the END of
	// block b. dist measures the number of instructions from the end
	// of b to the next use of the value (the "next use distance" the
	// Belady eviction heuristic compares). Sorted by ID for
	// deterministic iteration.
	LiveOut [][]liveInfo
	// NextCall[b.ID][i] is the index inside block b of the next CALL
	// at or after position i, or len(b.Values) if no CALL follows.
	// advanceUses (in the main walk) reads this to drop values from
	// registers when their next use lies past a CALL — pointless to
	// keep resident if a clobber is coming anyway.
	NextCall [][]int32

	// liveIn[b.ID] is the live-IN set after the most recent fixpoint
	// pass — values still alive at the START of block b. The seed-
	// from-successors step of the next pass reads it; not exposed
	// externally because the allocator works off live-OUT.
	liveIn [][]liveInfo
}

// ComputeLive runs backward iterative dataflow over f, producing
// LiveOut and NextCall. Mirrors Go's regalloc.go:2836–2952 modulo the
// Rastello loop-extension (which we approximate by iterating until
// fixpoint over reverse-postorder, picking up loop-carry values via
// the back-edge pass that naturally re-visits headers).
//
// The dataflow rules per block b (processed backwards):
//
//  1. Initial live set = union over b.Succs of LiveOut[s.ID] with
//     each entry's distance bumped by branchDistance(b, s) (the
//     instruction count from the end of b to the start of s) plus
//     len(b.Values) (the in-block traversal cost).
//  2. Walk b.Values from last to first:
//     - Remove v.ID from live (it's defined here, not consumed past).
//     - If v is a CALL, bump every still-live entry's distance by
//     UnlikelyDistance (= 100) to deprioritise call-survivors.
//     - For each arg a of v that needs a register, add (a.ID, i) to
//     live (i = position within b).
//  3. Record the resulting live set as LiveOut[p.ID] for every pred
//     p of b. Repeat until no change.
//
// Iteration order: blocks in reverse natural order each pass. The
// fixpoint typically converges in 2–3 passes for acyclic CFGs and
// 4–5 passes for loop-bearing ones. We cap at f.Blocks-count + 4
// passes to defend against pathological inputs.
func ComputeLive(f *ssa.Func, info ArchInfo) *LivenessResult {
	maxBlockID := ssa.BlockID(0)
	for _, b := range f.Blocks {
		if b.ID > maxBlockID {
			maxBlockID = b.ID
		}
	}
	r := &LivenessResult{
		LiveOut:  make([][]liveInfo, int(maxBlockID)+1),
		NextCall: make([][]int32, int(maxBlockID)+1),
		liveIn:   make([][]liveInfo, int(maxBlockID)+1),
	}
	// Per-block NextCall is independent of liveness — compute it once.
	for _, b := range f.Blocks {
		r.NextCall[b.ID] = buildNextCall(b)
	}
	// Build a quick "needs register" predicate per value ID. SSA value
	// IDs are dense — Func.Values is indexed by ID — so we size the
	// slice to len(f.Values) and key on ID directly.
	maxID := ssa.ValueID(len(f.Values))
	needReg := make([]bool, maxID+1)
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if int(v.ID) > len(needReg)-1 {
				continue
			}
			// Phis ARE consumers (their args get a use site at the
			// predecessor's edge) and also producers — but for the
			// purpose of "does this value's slot get read by an
			// emit?" the answer is yes if not flags-class.
			needReg[v.ID] = info.ClassFor(v.Type) != ClassFlags
		}
	}
	// Walk to fixpoint. We use a per-block working slice rebuilt at
	// every visit; the per-ID record uses map[ssa.ValueID]int32 so
	// merging successor sets is O(succ count + result size). Both are
	// small.
	maxPasses := len(f.Blocks) + 4
	for pass := 0; pass < maxPasses; pass++ {
		changed := false
		// We need both live-IN and live-OUT per block. Live-OUT is the
		// seed-from-successors value set BEFORE we walk b's own values
		// backwards; live-IN is what remains AFTER. The allocator's
		// cross-block machinery (endRegs / startRegs) consumes
		// live-OUT, so that's what we publish as r.LiveOut.
		liveInMap := map[ssa.ValueID]ssa.ValueID{} // dummy to silence
		_ = liveInMap
		for i := len(f.Blocks) - 1; i >= 0; i-- {
			b := f.Blocks[i]
			liveMap := map[ssa.ValueID]int32{}
			// Seed from successors: union of each succ's LIVE-IN
			// (which the prior iteration stashed in r.liveIn[s.ID])
			// PLUS the phi-input contributions on each succ's edge.
			// The block-distance adjustment (+= len(b.Values)) lives
			// down below in the "blkLen bump" step, so we keep the
			// seed distances measured "from end of succ" until then.
			for _, e := range b.Succs {
				s := e.Block
				bd := branchDistance(b, s)
				for _, li := range r.liveIn[s.ID] {
					d := li.Dist + bd
					if old, ok := liveMap[li.ID]; !ok || d < old {
						liveMap[li.ID] = d
					}
				}
				// Phi inputs at the successor are uses on this edge,
				// at distance bd. They count toward b's live-OUT.
				for _, v := range s.Values {
					if v.Op != ssa.OpPhi {
						break // phis come first in Block.Values
					}
					if e.Index >= len(v.Args) {
						continue
					}
					a := v.Args[e.Index]
					if a == nil || int(a.ID) >= len(needReg) || !needReg[a.ID] {
						continue
					}
					d := bd
					if old, ok := liveMap[a.ID]; !ok || d < old {
						liveMap[a.ID] = d
					}
				}
			}
			// Snapshot the live-OUT set BEFORE the backward walk
			// removes values defined in this block. r.LiveOut is what
			// downstream passes (block adopt, shuffle, etc.) consume.
			outSnap := make([]liveInfo, 0, len(liveMap))
			for id, d := range liveMap {
				outSnap = append(outSnap, liveInfo{ID: id, Dist: d})
			}
			sort.Slice(outSnap, func(i, j int) bool { return outSnap[i].ID < outSnap[j].ID })
			r.LiveOut[b.ID] = outSnap
			// Bump every distance by len(b.Values) — the cost of
			// walking through b's in-block instructions before
			// reaching the successor frontier.
			blkLen := int32(len(b.Values))
			for id := range liveMap {
				liveMap[id] += blkLen
			}
			// Block control (BlockIf) reads a value at the end of the
			// block — treat it as a use at distance len(b.Values).
			if b.Control != nil && needReg[b.Control.ID] {
				if old, ok := liveMap[b.Control.ID]; !ok || blkLen < old {
					liveMap[b.Control.ID] = blkLen
				}
			}
			// BlockRet's last K values (K = result count) are uses at
			// the terminator (distance == len(b.Values)).
			if b.Kind == ssa.BlockRet {
				k := len(f.Sig.Results)
				n := len(b.Values)
				if k > 0 && k <= n {
					for j := n - k; j < n; j++ {
						v := b.Values[j]
						if v == nil || !needReg[v.ID] {
							continue
						}
						if old, ok := liveMap[v.ID]; !ok || blkLen < old {
							liveMap[v.ID] = blkLen
						}
					}
				}
			}
			// Walk values backward.
			for j := len(b.Values) - 1; j >= 0; j-- {
				v := b.Values[j]
				// Remove v's own entry — it's defined here, not used
				// past this point in the same block.
				delete(liveMap, v.ID)
				// Phis are special: their inputs were already counted
				// at the predecessor side via the successor-loop
				// above. Don't re-add them.
				if v.Op == ssa.OpPhi {
					continue
				}
				// CALL penalty: every value still live across this
				// call gets its next-use distance bumped by
				// UnlikelyDistance. The Belady eviction picks the
				// largest distance, so bumped values become preferred
				// spill victims — exactly what we want, since the
				// CALL will trash them anyway.
				if isCall(v.Op) {
					for id := range liveMap {
						liveMap[id] += UnlikelyDistance
					}
				}
				// Add v's args as uses at position j.
				for _, a := range v.Args {
					if a == nil || !needReg[a.ID] {
						continue
					}
					d := int32(j)
					if old, ok := liveMap[a.ID]; !ok || d < old {
						liveMap[a.ID] = d
					}
				}
			}
			// Build the sorted liveInfo slice for stable comparison.
			next := make([]liveInfo, 0, len(liveMap))
			for id, d := range liveMap {
				next = append(next, liveInfo{ID: id, Dist: d})
			}
			sort.Slice(next, func(i, j int) bool { return next[i].ID < next[j].ID })
			// r.liveIn[b.ID] is what flows BACK to predecessors next
			// pass — values still alive at the START of block b.
			// Compare to the previous pass to detect fixpoint.
			prev := r.liveIn[b.ID]
			if !sameLive(prev, next) {
				r.liveIn[b.ID] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return r
}

// buildNextCall fills nextCall[i] for block b: index of the next CALL
// at or after position i, or len(b.Values) if no CALL follows. The
// allocator uses this in advanceUses to decide whether a value's next
// use is past a CALL barrier and the register can be freed early.
func buildNextCall(b *ssa.Block) []int32 {
	n := len(b.Values)
	out := make([]int32, n+1)
	out[n] = int32(n)
	for i := n - 1; i >= 0; i-- {
		if isCall(b.Values[i].Op) {
			out[i] = int32(i)
		} else {
			out[i] = out[i+1]
		}
	}
	return out
}

// isCall reports whether an op clobbers all caller-save registers
// when emitted. The allocator's CALL handling depends on this: every
// such op's value loses register residency unless explicitly held
// past, and the liveness pass applies the UnlikelyDistance penalty.
func isCall(op ssa.Op) bool {
	switch op {
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpHelperCall,
		ssa.OpMemGrow, ssa.OpMemoryCopy, ssa.OpMemoryFill,
		ssa.OpGlobalGet, ssa.OpGlobalSet:
		return true
	}
	return false
}

// branchDistance returns the per-edge weight from b to s. Without
// likelihood hints (our SSA doesn't yet carry them), every edge gets
// NormalDistance. The infrastructure stays in place for later — once
// the lowering propagates branch hints from wasm br_if's likely/
// unlikely attribute we plug them in here.
func branchDistance(b, s *ssa.Block) int32 {
	_ = b
	_ = s
	return NormalDistance
}

// sameLive reports whether two sorted liveInfo slices represent the
// same live set with the same distances. Used to detect fixpoint
// convergence — a quick element-wise scan is enough since both slices
// are sorted by ID.
func sameLive(a, b []liveInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Dist != b[i].Dist {
			return false
		}
	}
	return true
}
