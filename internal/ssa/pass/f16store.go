package pass

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// RecognizeF16Store vectorizes the f16 STORE side of ggml's kernels:
// four lanes of an f32x4 each run the software fp32->fp16 rounding
// idiom (the same one RecognizeF32ToF16 matches) and are stored with
// i32.store16. The four conversions collapse into one packed op,
//
//	bits = f16x4_cvt_bits(W)   // u64: 16 bits per lane, LE
//
// (arm64: FCVTN + a NaN blend forcing sign|0x7E00, exactly the idiom
// semantics), and each store's VALUE becomes a shift of the packed
// word. The stores themselves — addresses, order, memory effects —
// are untouched, so the rewrite has no trap or ordering concerns;
// the orphaned per-lane idiom subgraphs die in DCE.
// lane16 is one recognized 16-bit store of a packed group.
type lane16 struct {
	store *ssa.Value
	blk   *ssa.Block
	idx   int // position of the store in its block
}

func RecognizeF16Store(f *ssa.Func) bool {
	uses := map[*ssa.Value]int{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				uses[a]++
			}
		}
	}

	// One group per source vector W, collected function-wide: each
	// lane's conversion diamond joins in its own block, so the four
	// stores usually sit in a chain of blocks.
	groups := map[*ssa.Value]*[4]lane16{}
	order := []*ssa.Value{}
	for _, b := range f.Blocks {
		for i, v := range b.Values {
			if v.Op != ssa.OpStore16 || len(v.Args) < 2 {
				continue
			}
			or := v.Args[1]
			if or.Op != ssa.OpOr32 || len(or.Args) != 2 || uses[or] != 1 {
				f16dbg("store16 value: %s uses=%d", or.Op, uses[or])
				continue
			}
			var fv, w *ssa.Value
			for k := 0; k < 2; k++ {
				if gotF, gotW, ok := matchF16IdiomBits(or.Args[k], or.Args[1-k]); ok {
					fv, w = gotF, gotW
					break
				}
			}
			if w == nil {
				f16dbg("or32 idiom no-match: [%s | %s]", or.Args[0].Op, or.Args[1].Op)
				continue
			}
			// The lane arrives as an f32 extract, an i32 bits extract
			// (i32x4.extract_lane of the float vector), or an i32 bits
			// extract reinterpreted to f32.
			ex := w
			if fv != nil {
				ex = fv
				if ex.Op == ssa.OpHelperCall && len(ex.Args) == 1 {
					if n, _ := ex.Aux.(string); n == "f32_reinterpret_i32" {
						ex = ex.Args[0]
					}
				}
			}
			if ex.Op != ssa.OpSimdCall || len(ex.Args) != 2 {
				f16dbg("fv not extract call: %s aux=%v args=%d", ex.Op, ex.Aux, len(ex.Args))
				continue
			}
			if n, _ := ex.Aux.(string); n != "simd_f32x4_extract_lane" && n != "simd_i32x4_extract_lane" {
				f16dbg("fv helper name: %q", n)
				continue
			}
			fv = ex
			ln, ok := constOf(fv.Args[1])
			if !ok || ln < 0 || ln > 3 {
				continue
			}
			W := fv.Args[0]
			g := groups[W]
			if g == nil {
				g = &[4]lane16{}
				groups[W] = g
				order = append(order, W)
			}
			if g[ln].store != nil {
				g[ln].store = nil // duplicate lane: poison the slot
				continue
			}
			g[ln] = lane16{store: v, blk: b, idx: i}
		}
	}
	if len(groups) == 0 {
		return false
	}
	idom := ssa.Dominators(f)
	dominates := func(a, b *ssa.Block) bool {
		for b != nil {
			if b == a {
				return true
			}
			p := idom[b.ID]
			if p == b {
				return false
			}
			b = p
		}
		return false
	}
	changed := false
	for _, W := range order {
		g := groups[W]
		ok := true
		anchor := -1 // lane whose store dominates the other three
		for k := 0; k < 4 && ok; k++ {
			if g[k].store == nil {
				ok = false
				break
			}
			dom := true
			for j := 0; j < 4; j++ {
				if j == k {
					continue
				}
				if g[j].store == nil {
					dom = false
					break
				}
				if g[k].blk == g[j].blk {
					if g[k].idx > g[j].idx {
						dom = false
					}
				} else if !dominates(g[k].blk, g[j].blk) {
					dom = false
				}
			}
			if dom {
				anchor = k
			}
		}
		if !ok || anchor == -1 {
			f16dbg("store group incomplete or no dominating anchor")
			continue
		}
		b, first := g[anchor].blk, g[anchor].idx
		bits := b.NewValueBefore(f, first, ssa.OpSimdCall, ssa.TypeI64, 0, "simd_f16x4_cvt_bits", W)
		c32 := b.NewValueBefore(f, first+1, ssa.OpConst64, ssa.TypeI64, 32, nil)
		hi64 := b.NewValueBefore(f, first+2, ssa.OpShrU64, ssa.TypeI64, 0, nil, bits, c32)
		lo := b.NewValueBefore(f, first+3, ssa.OpTrunc64To32, ssa.TypeI32, 0, nil, bits)
		hi := b.NewValueBefore(f, first+4, ssa.OpTrunc64To32, ssa.TypeI32, 0, nil, hi64)
		c16 := b.NewValueBefore(f, first+5, ssa.OpConst32, ssa.TypeI32, 16, nil)
		shift := map[int]*ssa.Value{}
		for k := 0; k < 4; k++ {
			half := lo
			if k >= 2 {
				half = hi
			}
			v := half
			if k&1 == 1 {
				sv, okS := shift[k/2]
				if !okS {
					sv = b.NewValueBefore(f, first+6, ssa.OpShrU32, ssa.TypeI32, 0, nil, half, c16)
					shift[k/2] = sv
				}
				v = sv
			}
			// store16 truncates to 16 bits, so no masking needed.
			g[k].store.Args[1] = v
		}
		changed = true
	}
	return changed
}

// MergeF16Stores collapses each packed-conversion store group —
// four 16-bit stores whose values are shift/truncate selections of
// one simd_f16x4_cvt_bits word (the shape RecognizeF16Store leaves
// behind) — into a single 64-bit store of that word. It runs AFTER
// the empty-diamond fold: the group's stores sit in a straight-line
// block chain only once the orphaned NaN-select diamonds between
// them are gone. Conditions: lane addresses contiguous
// (base+0/2/4/6) and nothing memory-like between the stores in
// execution order. The merged store lands at the LAST group store's
// position (every operand dominates it); an out-of-bounds tail then
// traps with none of the four writes landed, where the unmerged form
// would have written the in-bounds lanes first — the same
// earlier-trap/no-partial-write relaxation the bounds-coalescing
// pass applies to SIMD spans.
func MergeF16Stores(f *ssa.Func) bool {
	type packGroup struct {
		lanes [4]lane16
		bits  *ssa.Value
	}
	groups := map[*ssa.Value]*packGroup{}
	order := []*ssa.Value{}
	for _, b := range f.Blocks {
		for i, v := range b.Values {
			if v.Op != ssa.OpStore16 || len(v.Args) < 2 {
				continue
			}
			bits, ln := f16PackedLane(v.Args[1])
			if bits == nil {
				continue
			}
			g := groups[bits]
			if g == nil {
				g = &packGroup{bits: bits}
				groups[bits] = g
				order = append(order, bits)
			}
			if g.lanes[ln].store != nil {
				g.lanes[ln].store = nil // duplicate: poison
				continue
			}
			g.lanes[ln] = lane16{store: v, blk: b, idx: i}
		}
	}
	changed := false
	for _, bits := range order {
		g := groups[bits]
		ok := true
		for k := 0; k < 4; k++ {
			ok = ok && g.lanes[k].store != nil
		}
		if !ok {
			continue
		}
		if mergeF16StoreGroup(&g.lanes, bits) {
			changed = true
		}
	}
	return changed
}

// f16PackedLane classifies a store value as lane k of a packed
// f16x4_cvt_bits word, or returns nil.
func f16PackedLane(v *ssa.Value) (*ssa.Value, int) {
	lane := 0
	if v.Op == ssa.OpShrU32 && len(v.Args) == 2 {
		if c, ok := constOf(v.Args[1]); ok && c == 16 {
			lane++
			v = v.Args[0]
		}
	}
	if v.Op != ssa.OpTrunc64To32 || len(v.Args) != 1 {
		return nil, 0
	}
	v = v.Args[0]
	if v.Op == ssa.OpShrU64 && len(v.Args) == 2 {
		c := v.Args[1]
		if (c.Op == ssa.OpConst64 || c.Op == ssa.OpConst32) && c.AuxInt == 32 {
			lane += 2
			v = v.Args[0]
		}
	}
	if v.Op != ssa.OpSimdCall {
		return nil, 0
	}
	if n, _ := v.Aux.(string); n != "simd_f16x4_cvt_bits" {
		return nil, 0
	}
	return v, lane
}

// mergeF16StoreGroup performs the walk and rewrite for one group; the
// entry point is the first-executed store, found by trying each lane
// as the walk start (the chain is short, the walk cheap).
func mergeF16StoreGroup(g *[4]lane16, bits *ssa.Value) bool {
	root0, off0 := f16StoreAddr(g[0].store)
	for k := 1; k < 4; k++ {
		r, o := f16StoreAddr(g[k].store)
		if r != root0 || o != off0+int64(2*k) {
			f16dbg("store merge: lane %d addr root=%v off=%d vs lane0 root=%v off=%d", k, r, o, root0, off0)
			return false
		}
	}
	inGroup := func(v *ssa.Value) int {
		for k := 0; k < 4; k++ {
			if g[k].store == v {
				return k
			}
		}
		return -1
	}
	for start := 0; start < 4; start++ {
		cur, i := g[start].blk, g[start].idx
		var last *lane16
		seen := 0
		for hops := 0; hops < 64; hops++ {
			bail := false
			for ; i < len(cur.Values); i++ {
				v := cur.Values[i]
				if k := inGroup(v); k >= 0 {
					if k != start && seen == 0 {
						// A group store precedes this start: wrong entry.
						bail = true
						break
					}
					seen++
					last = &g[k]
					if seen == 4 {
						last.store.Op = ssa.OpStore64
						last.store.Args[0] = g[0].store.Args[0]
						last.store.Args[1] = bits
						last.store.AuxInt = g[0].store.AuxInt
						for k := 0; k < 4; k++ {
							if &g[k] != last {
								removeValue(g[k].blk, g[k].store)
							}
						}
						return true
					}
					continue
				}
				if f16MemLike(v, nil, nil) {
					if seen > 0 {
						f16dbg("store merge: intervening %s after %d/4 stores", v.Op, seen)
						return false
					}
					bail = true
					break
				}
			}
			if bail {
				break
			}
			if len(cur.Succs) != 1 {
				// Chain ends before completing the group: wrong start
				// (walking from a non-first store hits the region's
				// exit or loop branch first). Try the next start.
				break
			}
			cur, i = cur.Succs[0].Block, 0
		}
	}
	f16dbg("store merge: no straight-line order found")
	return false
}

// FuseF16CvtStores rewrites store64(addr, f16x4_cvt_bits(W)) — the
// shape MergeF16Stores leaves — into the single fused memory op
//
//	simd_v128_f16x4_cvt_store(addr, off, W)
//
// so the conversion AND the store ride inside a fused region (and a
// fused loop) instead of round-tripping the vector through a GPR
// pair at the region boundary. Runs after MergeF16Stores; requires
// the packed word to have no other use.
func FuseF16CvtStores(f *ssa.Func) bool {
	uses := map[*ssa.Value]int{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				uses[a]++
			}
		}
	}
	changed := false
	for _, b := range f.Blocks {
		for i, v := range b.Values {
			if v.Op != ssa.OpStore64 || len(v.Args) < 2 {
				continue
			}
			bits := v.Args[1]
			if bits.Op != ssa.OpSimdCall || uses[bits] != 1 {
				continue
			}
			if n, _ := bits.Aux.(string); n != "simd_f16x4_cvt_bits" {
				continue
			}
			W := bits.Args[0]
			off := b.NewValueBefore(f, i, ssa.OpConst32, ssa.TypeI32, v.AuxInt, nil)
			v.Op = ssa.OpSimdMemCall
			v.Type = ssa.TypeI32
			v.Aux = "simd_v128_f16x4_cvt_store"
			v.AuxInt = 0
			v.Args = []*ssa.Value{v.Args[0], off, W}
			changed = true
		}
	}
	return changed
}

// f16StoreAddr is memRoot with constant leaves folded into the
// offset (root nil): two stores at literal addresses compare by the
// address value, not by which OpConst32 spells it.
func f16StoreAddr(st *ssa.Value) (*ssa.Value, int64) {
	root, off := memRoot(st)
	if c, ok := constOf(root); ok {
		return nil, off + c
	}
	return root, off
}

// f16PureHelpers are the arithmetic helper calls of the software
// f32->f16 idiom: pure value computations that the store rewrite
// orphans and DCE later deletes. The merge walk runs BEFORE that DCE,
// so it must see through them; every other helper call blocks the
// merge.
var f16PureHelpers = map[string]bool{
	"i32_reinterpret_f32": true,
	"f32_reinterpret_i32": true,
	"f32_abs":             true,
	"f32_mul":             true,
	"f32_add":             true,
}

// f16MemLike reports whether v touches memory or transfers control —
// anything the store merge must not move a write across.
func f16MemLike(v *ssa.Value, exclude1, exclude2 *ssa.Value) bool {
	if v == exclude1 || v == exclude2 {
		return false
	}
	switch v.Op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64,
		ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpStoreF32, ssa.OpStoreF64,
		ssa.OpCallDirect, ssa.OpCallIndirect, ssa.OpCallImport,
		ssa.OpMemGrow, ssa.OpSimdMemCall:
		return true
	case ssa.OpHelperCall:
		name, _ := v.Aux.(string)
		return !f16PureHelpers[name]
	}
	return false
}

// removeValue drops v from b.Values.
func removeValue(b *ssa.Block, v *ssa.Value) {
	for i, x := range b.Values {
		if x == v {
			b.Values = append(b.Values[:i], b.Values[i+1:]...)
			return
		}
	}
}
