package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// SlotAssignment maps each SpillNeeded value to a per-function stack
// slot. Two values whose live ranges don't overlap share a slot,
// dramatically shrinking the frame compared to the per-value allocation
// asmgen's slot-reuse pass does today. Modeled on Go's stackalloc.go interference-
// graph approach.
//
// Layout: slot 0 is the lowest offset above the callee-arg staging
// area. Slots are sized by the value's type:
//   - i32 / bool / f32: 4 bytes, 4-byte align
//   - i64 / f64       : 8 bytes, 8-byte align
type SlotAssignment struct {
	// Offset[v.ID] is the byte offset (from SP after frame prologue)
	// where the value's spill slot lives. Filled only for values
	// that have SpillNeeded == true in the regalloc Result; absent
	// entries indicate "no slot allocated".
	Offset map[ssa.ValueID]int
	// FrameSize is the total bytes of stack used by all spill slots
	// after sharing. Asmgen adds the callee-arg area and rounds up
	// for ABI alignment.
	FrameSize int
}

// AllocateSlots walks the function and assigns a slot to every value
// the regalloc marked SpillNeeded. Non-overlapping live ranges share
// a slot via a simple interference-graph check.
//
// Algorithm (per type-class — i32/f32 and i64/f64 use separate pools
// because slot sizes differ):
//
//  1. Build the interference graph: walk each block backwards,
//     maintaining a live set; when a value v is defined and the
//     live set still contains u, mark u <-> v as interfering.
//  2. Walk SpillNeeded values in ID order. For each v, find the
//     lowest-index slot from its type's pool whose existing
//     occupants don't interfere with v. If none qualifies,
//     allocate a fresh slot.
//
// The interference test is one walk per value (we don't
// reconstruct the full graph as a separate data structure — we
// just track per-slot occupants and check pairwise). For Fn39262
// with ~800 SpillNeeded values, the cost is O(800 × avg-occupants
// × 2 type pools) — small enough not to matter.
func AllocateSlots(f *ssa.Func, info ArchInfo, result *Result, baseOffset int) *SlotAssignment {
	// Type-pooled slot bank. Each pool's entries are []ssa.ValueID
	// listing the values that share that slot.
	type pool struct {
		entries [][]ssa.ValueID
	}
	var p32, p64 pool

	// Build the interference adjacency once. We use a map[ValueID]
	// map[ValueID]bool — sparse, since most pairs don't interfere.
	interfere := computeInterference(f, info, result)

	out := &SlotAssignment{Offset: map[ssa.ValueID]int{}}

	// Iterate values in ID order so the slot layout is deterministic.
	type sval struct {
		ID   ssa.ValueID
		Size int // 4 or 8
	}
	var todo []sval
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if !result.SpillNeeded[v.ID] {
				continue
			}
			size := slotSizeFor(v.Type)
			if size == 0 {
				continue
			}
			todo = append(todo, sval{ID: v.ID, Size: size})
		}
	}
	// Sort by ID so we walk deterministically.
	// (Slice already in encounter order, which is BlockID then
	// in-block index — stable across runs.)

	// Pass 1: assign each value to a slot INDEX in its type pool.
	// Don't compute byte offsets yet — the offset of an 8-byte slot
	// depends on the FINAL size of the 4-byte pool, which we only
	// know after every value has been placed. Mixing the
	// allocations in encounter order without that two-pass
	// structure produces colliding offsets (a v1:i64 placed early
	// gets offset 0; a v2:i32 placed later also gets offset 0).
	slotIdx := map[ssa.ValueID]int{}
	for _, sv := range todo {
		p := &p32
		if sv.Size == 8 {
			p = &p64
		}
		slot := -1
		for i, occupants := range p.entries {
			conflict := false
			for _, u := range occupants {
				if interfere[sv.ID] != nil && interfere[sv.ID][u] {
					conflict = true
					break
				}
			}
			if !conflict {
				slot = i
				p.entries[i] = append(occupants, sv.ID)
				break
			}
		}
		if slot == -1 {
			slot = len(p.entries)
			p.entries = append(p.entries, []ssa.ValueID{sv.ID})
		}
		slotIdx[sv.ID] = slot
	}
	// Pass 2: translate slot index to byte offset using the final
	// pool sizes. The 4-byte pool starts at baseOffset; the 8-byte
	// pool starts at the next 8-aligned offset after the entire
	// 4-byte pool.
	pool32Base := baseOffset
	pool64Base := alignUp(pool32Base+len(p32.entries)*4, 8)
	for _, sv := range todo {
		idx := slotIdx[sv.ID]
		var offset int
		if sv.Size == 4 {
			offset = pool32Base + idx*4
		} else {
			offset = pool64Base + idx*8
		}
		out.Offset[sv.ID] = offset
	}
	// Frame size is the end of the 8-byte pool, padded to 8.
	frameEnd := pool64Base + len(p64.entries)*8
	out.FrameSize = alignUp(frameEnd, 8)
	return out
}

// computeInterference builds a sparse adjacency map: interfere[a][b]
// is true iff values a and b have overlapping live ranges and so
// cannot share a stack slot. Walks each block backwards once.
func computeInterference(f *ssa.Func, info ArchInfo, result *Result) map[ssa.ValueID]map[ssa.ValueID]bool {
	add := func(g map[ssa.ValueID]map[ssa.ValueID]bool, a, b ssa.ValueID) {
		if a == b {
			return
		}
		if g[a] == nil {
			g[a] = map[ssa.ValueID]bool{}
		}
		if g[b] == nil {
			g[b] = map[ssa.ValueID]bool{}
		}
		g[a][b] = true
		g[b][a] = true
	}
	g := map[ssa.ValueID]map[ssa.ValueID]bool{}
	live := ComputeLive(f, info)
	// Build a quick value lookup table so we can resolve OpCopy
	// chains in the interference walk. operandSrc on the emit side
	// also walks OpCopy chains, so a slot read through an OpCopy
	// alias actually reads the underlying value's slot — the
	// interference graph must therefore keep the underlying value
	// alive as long as any alias is.
	byID := map[ssa.ValueID]*ssa.Value{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			byID[v.ID] = v
		}
	}
	resolve := func(id ssa.ValueID) ssa.ValueID {
		v := byID[id]
		for hop := 0; v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 && hop < 16; hop++ {
			if v.Args[0] == nil || v.Args[0] == v {
				break
			}
			v = v.Args[0]
		}
		if v == nil {
			return id
		}
		return v.ID
	}
	for _, b := range f.Blocks {
		// Seed the live set with this block's live-OUT values that
		// need a slot. Resolve through OpCopy so the live underlying
		// value is what's tracked, not the alias.
		liveSet := map[ssa.ValueID]bool{}
		for _, li := range live.LiveOut[b.ID] {
			id := resolve(li.ID)
			if result.SpillNeeded[id] {
				liveSet[id] = true
			}
		}
		// BlockRet's last K values are USED at the return point —
		// they're consumed by the implicit "write to result slot"
		// emit, which doesn't appear as a separate SSA op. Without
		// adding them to the live set seed, the backward walk
		// would treat them as dead the moment their def-site is
		// processed, and miss interference with any value still
		// live at the BlockRet position. Same shape for
		// BlockIf.Control (the comparison value the conditional
		// reads at the terminator).
		if b.Kind == ssa.BlockRet {
			k := len(f.Sig.Results)
			n := len(b.Values)
			if k > 0 && k <= n {
				for j := n - k; j < n; j++ {
					rv := b.Values[j]
					if rv != nil && result.SpillNeeded[rv.ID] {
						liveSet[rv.ID] = true
					}
				}
			}
		}
		if b.Control != nil && result.SpillNeeded[b.Control.ID] {
			liveSet[b.Control.ID] = true
		}
		// Walk backwards. When v is defined and v needs a slot,
		// every value currently in liveSet interferes with v.
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]
			if result.SpillNeeded[v.ID] {
				for u := range liveSet {
					add(g, v.ID, u)
				}
				delete(liveSet, v.ID)
			}
			for _, a := range v.Args {
				if a == nil {
					continue
				}
				id := resolve(a.ID)
				if result.SpillNeeded[id] {
					liveSet[id] = true
				}
			}
		}
	}
	return g
}

// slotSizeFor returns the slot-byte-size for a wasm SSA type. 4 for
// i32/f32/bool, 8 for i64/f64. Memory / Invalid types return 0 —
// the allocator never spills them.
func slotSizeFor(t ssa.Type) int {
	switch t {
	case ssa.TypeI32, ssa.TypeF32, ssa.TypeBool:
		return 4
	case ssa.TypeI64, ssa.TypeF64:
		return 8
	}
	return 0
}

// alignUp rounds n up to the next multiple of a (a must be a power
// of two). Used for slot pool alignment.
func alignUp(n, a int) int {
	return (n + a - 1) &^ (a - 1)
}
