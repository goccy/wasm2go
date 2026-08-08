package pass

import "github.com/goccy/wasm2go/internal/ssa"

// RecognizeF16Gather rewrites the ggml f16->f32 table-gather idiom.
// The wasm loads four contiguous f16 values widened into i32x4 lanes,
// then rebuilds an f32x4 by looking each lane up in a module-resident
// conversion table:
//
//	V  = v128_load16x4_u(addr, off)
//	e_k = i32x4_extract_lane(V, k)
//	L0 = v128_load32_zero(e_0<<2, T)            // T may ride the
//	L_k = v128_load32_lane(e_k<<2 + T, 0, k, L_{k-1})  // memarg or addr
//
// tableOK reports whether the table at T is byte-for-byte the IEEE
// binary16->binary32 conversion (the caller verifies the module's
// initial data image). When it is, the whole chain equals a pure lane
// conversion of V — the arm64 splicer emits XTN + FCVTL — and the
// rewrite is bit-exact for every input including NaN payloads.
//
// The tail load is rewritten in place to the pure op; the inner loads
// are neutered to zero constants (they are pinned as potentially
// trapping, but their addresses lie inside the verified table region,
// which sits in the initial data image and therefore inside memory
// forever), and the extracts and shifts die in DCE. V itself and its
// trap behavior are untouched.
func RecognizeF16Gather(f *ssa.Func, tableOK func(base uint32) bool) bool {
	if tableOK == nil {
		return false
	}
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
		for i := 0; i < len(b.Values); i++ {
			if rewriteF16Gather(f, b, i, uses, tableOK) {
				changed = true
			}
		}
	}
	return changed
}

// f16Effectful reports ops that may write memory or transfer control —
// the barrier set for reordering the scalar loads into one widening
// load. Loads are not barriers (loads cannot conflict with loads).
func f16Effectful(v *ssa.Value) bool {
	switch v.Op {
	case ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpCallDirect, ssa.OpCallIndirect, ssa.OpCallImport,
		ssa.OpMemGrow, ssa.OpHelperCall:
		return true
	case ssa.OpSimdMemCall:
		return true // conservatively: includes SIMD stores
	}
	return false
}

func rewriteF16Gather(f *ssa.Func, blk *ssa.Block, tailIdx int, uses map[*ssa.Value]int, tableOK func(base uint32) bool) bool {
	tail := blk.Values[tailIdx]
	if !isSimdMem(tail, "simd_v128_load32_lane") || len(tail.Args) != 4 ||
		!isConst32(tail.Args[2], 3) {
		return false
	}
	var loads [3]*ssa.Value
	var srcs [4]f16Src
	var offs [4]int64
	tOff, ok := constOf(tail.Args[1])
	if !ok {
		return false
	}
	offs[3] = tOff
	s3, ok := matchF16LaneAddr(tail.Args[0], 3)
	if !ok {
		return false
	}
	srcs[3] = s3
	cur := tail.Args[3]
	for lane := int64(2); lane >= 1; lane-- {
		if !isSimdMem(cur, "simd_v128_load32_lane") || len(cur.Args) != 4 ||
			!isConst32(cur.Args[2], lane) || uses[cur] != 1 {
			return false
		}
		if offs[lane], ok = constOf(cur.Args[1]); !ok {
			return false
		}
		sk, ok := matchF16LaneAddr(cur.Args[0], lane)
		if !ok {
			return false
		}
		srcs[lane] = sk
		loads[lane] = cur
		cur = cur.Args[3]
	}
	if !isSimdMem(cur, "simd_v128_load32_zero") || len(cur.Args) != 2 || uses[cur] != 1 {
		return false
	}
	s0, ok := matchF16LaneAddr(cur.Args[0], 0)
	if !ok {
		return false
	}
	if offs[0], ok = constOf(cur.Args[1]); !ok {
		return false
	}
	srcs[0] = s0
	loads[0] = cur
	// One table constant everywhere: each lane's effective address is
	// (h<<2) + table, with the table addend split arbitrarily between
	// the address expression and the memarg offset.
	table := srcs[3].table + offs[3]
	if table == 0 {
		return false
	}
	for k := 0; k < 4; k++ {
		if srcs[k].table+offs[k] != table {
			return false
		}
	}
	if table < 0 || !tableOK(uint32(table)) {
		return false
	}
	var V *ssa.Value
	switch {
	case srcs[0].vec != nil:
		// Widening-load variant: all lanes extract from one
		// v128_load16x4_u.
		V = srcs[0].vec
		if srcs[1].vec != V || srcs[2].vec != V || srcs[3].vec != V ||
			!isSimdMem(V, "simd_v128_load16x4_u") {
			return false
		}
	case srcs[0].ld != nil:
		// Scalar-load variant: four i32.load16_u at base+c+2k. The +2k
		// may ride the load's AuxInt or explicit Add32-with-constant
		// address arithmetic; normalize each address to (root, total).
		root0, c := memRoot(srcs[0].ld)
		for k := int64(0); k < 4; k++ {
			ld := srcs[k].ld
			if ld == nil {
				return false
			}
			rk, ck := memRoot(ld)
			if rk != root0 || ck != c+2*k || ld.Block != blk || uses[ld] != 1 {
				return false
			}
		}
		first := tailIdx
		involved := map[*ssa.Value]bool{tail: true, loads[0]: true, loads[1]: true, loads[2]: true}
		for k := 0; k < 4; k++ {
			involved[srcs[k].ld] = true
		}
		for i := 0; i < tailIdx; i++ {
			if involved[blk.Values[i]] && i < first {
				first = i
			}
		}
		for i := first; i < tailIdx; i++ {
			v := blk.Values[i]
			if !involved[v] && f16Effectful(v) {
				return false
			}
		}
		cst := blk.NewValueBefore(f, tailIdx, ssa.OpConst32, ssa.TypeI32, srcs[0].ld.AuxInt, nil)
		V = blk.NewValueBefore(f, tailIdx+1, ssa.OpSimdMemCall, ssa.TypeV128, 0, "simd_v128_load16x4_u", srcs[0].ld.Args[0], cst)
		for k := 0; k < 4; k++ {
			ld := srcs[k].ld
			ld.Op = ssa.OpConst32
			ld.AuxInt = 0
			ld.Aux = nil
			ld.Args = nil
		}
	default:
		return false
	}
	// Rewrite the tail into the pure conversion and neuter the inner
	// loads (see the function comment for why that is sound).
	tail.Op = ssa.OpSimdCall
	tail.Aux = "simd_f16x4_cvt"
	tail.AuxInt = 0
	tail.Args = []*ssa.Value{V}
	for _, l := range loads {
		l.Op = ssa.OpSimdConst
		l.AuxInt = 0
		l.Aux = [2]uint64{0, 0}
		l.Args = nil
	}
	return true
}

// f16Src is one matched lane source: either an extract from a
// widening v128 load (vec) or a scalar i32.load16_u (ld).
type f16Src struct {
	vec   *ssa.Value // load16x4_u the lane extracts from
	ld    *ssa.Value // OpLoad16U feeding the lane directly
	table int64
}

// matchF16LaneAddr matches `SRC << 2 [+ T]` where SRC is
// `i32x4_extract_lane(V, lane)` or a scalar `i32.load16_u`.
func matchF16LaneAddr(a *ssa.Value, lane int64) (f16Src, bool) {
	var out f16Src
	if a.Op == ssa.OpAdd32 && len(a.Args) == 2 {
		x, c := a.Args[0], a.Args[1]
		if _, isC := constOf(x); isC {
			x, c = c, x
		}
		t, isC := constOf(c)
		if !isC {
			return out, false
		}
		out.table = t
		a = x
	}
	if a.Op != ssa.OpShl32 || len(a.Args) != 2 || !isConst32(a.Args[1], 2) {
		return out, false
	}
	ex := a.Args[0]
	if ex.Op == ssa.OpLoad16U && len(ex.Args) == 1 && ex.Type == ssa.TypeI32 {
		out.ld = ex
		return out, true
	}
	if ex.Op != ssa.OpSimdCall || len(ex.Args) != 2 || !isConst32(ex.Args[1], lane) {
		return out, false
	}
	if n, _ := ex.Aux.(string); n != "simd_i32x4_extract_lane" {
		return out, false
	}
	out.vec = ex.Args[0]
	return out, true
}

func isSimdMem(v *ssa.Value, name string) bool {
	if v.Op != ssa.OpSimdMemCall {
		return false
	}
	n, _ := v.Aux.(string)
	return n == name
}

func constOf(v *ssa.Value) (int64, bool) {
	if v.Op != ssa.OpConst32 {
		return 0, false
	}
	return v.AuxInt, true
}

// memRoot normalizes a load's address to (root value, total constant
// offset): the AuxInt memarg plus any Add32-with-constant chain in
// the address expression.
func memRoot(ld *ssa.Value) (*ssa.Value, int64) {
	total := ld.AuxInt
	a := ld.Args[0]
	for a.Op == ssa.OpAdd32 && len(a.Args) == 2 {
		x, c := a.Args[0], a.Args[1]
		if _, isC := constOf(x); isC {
			x, c = c, x
		}
		cv, isC := constOf(c)
		if !isC {
			break
		}
		total += cv
		a = x
	}
	return a, total
}
