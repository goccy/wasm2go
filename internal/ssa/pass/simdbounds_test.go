package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// simdLoad builds an OpSimdMemCall v128.load of base with the given
// memarg offset, the exact shape the wasm lowering produces (offset as
// a Const32 second argument).
func simdLoad(b *ssa.FuncBuilder, base *ssa.Value, off int32) *ssa.Value {
	return b.NewValueAux(ssa.OpSimdMemCall, ssa.TypeV128, "simd_v128_load", base, b.Const32(off))
}

// countAux counts block values carrying the given OpSimdMemCall aux.
func countAux(vals []*ssa.Value, aux string) int {
	n := 0
	for _, v := range vals {
		if v != nil && v.Op == ssa.OpSimdMemCall && v.Aux == aux {
			n++
		}
	}
	return n
}

// findAux returns the first block value carrying the given aux.
func findAux(vals []*ssa.Value, aux string) *ssa.Value {
	for _, v := range vals {
		if v != nil && v.Op == ssa.OpSimdMemCall && v.Aux == aux {
			return v
		}
	}
	return nil
}

// rngWindow extracts the (rlo, span) constant arguments of a rewritten
// group-leading load.
func rngWindow(t *testing.T, v *ssa.Value) (int64, int64) {
	t.Helper()
	if len(v.Args) != 4 {
		t.Fatalf("load_rng arg count = %d, want 4 (addr, offset, rlo, span)", len(v.Args))
	}
	if v.Args[2].Op != ssa.OpConst32 || v.Args[3].Op != ssa.OpConst32 {
		t.Fatalf("load_rng rlo/span are %v/%v, want Const32", v.Args[2].Op, v.Args[3].Op)
	}
	return int64(int32(v.Args[2].AuxInt)), int64(int32(v.Args[3].AuxInt))
}

// TestCoalesceSimdBoundsGroup collapses same-base loads at small
// constant offsets — the ggml kernel inner-loop shape — into one
// range-checked leader plus unchecked members, and verifies the check
// covers exactly [lo, hi+16).
func TestCoalesceSimdBoundsGroup(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l0 := simdLoad(b, base, 0)
	l1 := simdLoad(b, base, 16)
	l2 := simdLoad(b, base, 48)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	sum = b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", sum, l2)
	b.FinishRet(sum)
	f := b.Func()

	if !CoalesceSimdBounds(f) {
		t.Fatalf("CoalesceSimdBounds returned false; expected the 3-load group to coalesce")
	}
	vals := f.Entry.Values
	if got := countAux(vals, "simd_v128_load_rng"); got != 1 {
		t.Fatalf("load_rng count = %d, want 1", got)
	}
	if got := countAux(vals, "simd_v128_load_nc"); got != 2 {
		t.Errorf("unchecked load count = %d, want 2", got)
	}
	if got := countAux(vals, "simd_v128_load"); got != 0 {
		t.Errorf("checked load count = %d, want 0", got)
	}
	rng := findAux(vals, "simd_v128_load_rng")
	if rng != l0 {
		t.Errorf("group leader is v%d, want the FIRST load v%d", rng.ID, l0.ID)
	}
	if rlo, span := rngWindow(t, rng); rlo != 0 || span != 64 {
		t.Errorf("check window = [%d, %d+%d), want [0, 0+64)", rlo, rlo, span)
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("verify after coalesce: %v", err)
	}
}

// TestCoalesceSimdBoundsPeelsAddend groups loads whose addresses are
// OpAdd32(base, Const32) at different non-negative addends with the
// shared base, rebasing the window onto the leader's own address.
func TestCoalesceSimdBoundsPeelsAddend(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	a1 := b.NewValue(ssa.OpAdd32, ssa.TypeI32, base, b.Const32(32))
	l0 := simdLoad(b, base, 0)
	l1 := simdLoad(b, a1, 8)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	b.FinishRet(sum)
	f := b.Func()

	if !CoalesceSimdBounds(f) {
		t.Fatalf("CoalesceSimdBounds returned false; expected addend peel to group both loads")
	}
	rng := findAux(f.Entry.Values, "simd_v128_load_rng")
	if rng == nil {
		t.Fatal("no load_rng emitted")
	}
	if rng != l0 {
		t.Errorf("group leader is v%d, want v%d", rng.ID, l0.ID)
	}
	// Leader's peeled addend is 0, group covers [0, 40+16): rlo 0,
	// span 56.
	if rlo, span := rngWindow(t, rng); rlo != 0 || span != 32+8+16 {
		t.Errorf("check window = [%d, +%d), want [0, +%d)", rlo, span, 32+8+16)
	}
}

// TestCoalesceSimdBoundsLeaderNotLowest rebases the window when the
// group's FIRST load is not its lowest address: rlo goes negative,
// which the signed helper accepts.
func TestCoalesceSimdBoundsLeaderNotLowest(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	hiAddr := b.NewValue(ssa.OpAdd32, ssa.TypeI32, base, b.Const32(48))
	l0 := simdLoad(b, hiAddr, 0) // total 48, leader
	l1 := simdLoad(b, base, 0)   // total 0
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	b.FinishRet(sum)
	f := b.Func()

	if !CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds returned false; expected out-of-order group to coalesce")
	}
	rng := findAux(f.Entry.Values, "simd_v128_load_rng")
	if rng != l0 {
		t.Fatalf("group leader is not the first load")
	}
	// Window relative to the leader's addr (base+48): [−48, −48+80).
	if rlo, span := rngWindow(t, rng); rlo != -48 || span != 48+16 {
		t.Errorf("check window = [%d, +%d), want [-48, +64)", rlo, span)
	}
}

// TestCoalesceSimdBoundsBarrier keeps groups from crossing a store:
// the store's own trap must stay ordered against the loads' checks.
func TestCoalesceSimdBoundsBarrier(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l0 := simdLoad(b, base, 0)
	b.NewValueAux(ssa.OpSimdMemCall, ssa.TypeI32, "simd_v128_store", base, b.Const32(64), l0)
	l1 := simdLoad(b, base, 16)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	b.FinishRet(sum)
	f := b.Func()

	if CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds coalesced across a v128.store barrier")
	}
	if got := countAux(f.Entry.Values, "simd_v128_load"); got != 2 {
		t.Errorf("checked load count = %d, want 2 (both must keep their own checks)", got)
	}
}

// TestCoalesceSimdBoundsInterleaved groups two independent streams
// whose loads alternate — the ggml dot-kernel shape (x+2, y+2, x+18,
// y+18): a different-base load must not close the other stream's
// group.
func TestCoalesceSimdBoundsInterleaved(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	y := b.Param(1, ssa.TypeI32)
	x0 := simdLoad(b, x, 2)
	y0 := simdLoad(b, y, 2)
	x1 := simdLoad(b, x, 18)
	y1 := simdLoad(b, y, 18)
	s0 := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", x0, y0)
	s1 := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", x1, y1)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", s0, s1)
	b.FinishRet(sum)
	f := b.Func()

	if !CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds returned false; expected both interleaved streams to coalesce")
	}
	vals := f.Entry.Values
	if got := countAux(vals, "simd_v128_load_rng"); got != 2 {
		t.Fatalf("load_rng count = %d, want 2 (one per stream)", got)
	}
	if got := countAux(vals, "simd_v128_load_nc"); got != 2 {
		t.Errorf("unchecked load count = %d, want 2", got)
	}
	if x0.Aux != "simd_v128_load_rng" || y0.Aux != "simd_v128_load_rng" {
		t.Errorf("stream leaders are (%v, %v), want the first load of each stream", x0.Aux, y0.Aux)
	}
	// The window is relative to the leader's addr argument (x): the
	// lowest access is x+2 and the group covers [x+2, x+18+16).
	if rlo, span := rngWindow(t, x0); rlo != 2 || span != 32 {
		t.Errorf("x window = [%d, +%d), want [2, +32)", rlo, span)
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("verify after coalesce: %v", err)
	}
}

// TestCoalesceSimdBoundsMultipleGroups exercises two barrier-separated
// group regions in one block: the second region's collected indices
// must survive the first region's insertions, including when its base
// is defined after the first region (a stale insertion index would
// plant constants before the definition and fail the verifier).
func TestCoalesceSimdBoundsMultipleGroups(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	p1 := b.Param(1, ssa.TypeI32)
	a0 := simdLoad(b, p0, 0)
	a1 := simdLoad(b, p0, 16)
	s0 := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", a0, a1)
	b.NewValueAux(ssa.OpSimdMemCall, ssa.TypeI32, "simd_v128_store", p0, b.Const32(256), s0)
	base2 := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1)
	b0 := simdLoad(b, base2, 0)
	b1 := simdLoad(b, base2, 16)
	s1 := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", b0, b1)
	b.FinishRet(s1)
	f := b.Func()

	if !CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds returned false; expected both groups to coalesce")
	}
	vals := f.Entry.Values
	if got := countAux(vals, "simd_v128_load_rng"); got != 2 {
		t.Fatalf("load_rng count = %d, want 2", got)
	}
	if got := countAux(vals, "simd_v128_load_nc"); got != 2 {
		t.Errorf("unchecked load count = %d, want 2", got)
	}
	// Def-before-use over the whole block: every value's args must
	// appear earlier (params live outside the slice).
	seen := map[*ssa.Value]bool{p0: true, p1: true}
	for _, v := range vals {
		if v == nil {
			continue
		}
		for _, a := range v.Args {
			if a.Block == f.Entry && !seen[a] && a.Op != ssa.OpParam {
				t.Fatalf("v%d uses v%d before its definition", v.ID, a.ID)
			}
		}
		seen[v] = true
	}
}

// TestCoalesceSimdBoundsWindow refuses to group loads whose constant
// spread exceeds the wrap-safety window.
func TestCoalesceSimdBoundsWindow(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	l0 := simdLoad(b, base, 0)
	l1 := simdLoad(b, base, 1<<17)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	b.FinishRet(sum)
	f := b.Func()

	if CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds grouped loads 128 KiB apart; window must refuse")
	}
}

// TestCoalesceSimdBoundsNegativePeel refuses to peel a negative
// addend: member displacements must stay non-negative for the wrap
// exactness argument.
func TestCoalesceSimdBoundsNegativePeel(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeV128}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.Param(0, ssa.TypeI32)
	below := b.NewValue(ssa.OpAdd32, ssa.TypeI32, base, b.Const32(-16))
	l0 := simdLoad(b, base, 0)
	l1 := simdLoad(b, below, 0)
	sum := b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_add", l0, l1)
	b.FinishRet(sum)
	f := b.Func()

	// The negative-addend load keeps its own base identity (no peel),
	// so the two loads have different bases: two singleton groups,
	// nothing coalesces.
	if CoalesceSimdBounds(f) {
		t.Fatal("CoalesceSimdBounds grouped across a negative peeled addend")
	}
	if got := countAux(f.Entry.Values, "simd_v128_load"); got != 2 {
		t.Errorf("checked load count = %d, want 2", got)
	}
}
