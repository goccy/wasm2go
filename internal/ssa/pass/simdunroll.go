package pass

import "github.com/goccy/wasm2go/internal/ssa"

// UnrollSimdLoops unrolls counted self-loop blocks containing SIMD
// memory accesses by factor k.
//
// The point is not classical unrolling gains but what the passes
// DOWNSTREAM can then do: k iterations' loads land in one straight-
// line block with constant-offset addresses (the reassociation rule
// below folds the pointer-bump chains), so bounds-check coalescing
// covers them with one range check per stream, and the scalarizer's
// window fusion merges the whole k-block body into one fused region —
// amortizing the per-iteration costs gc imposes from outside
// (argument staging, accumulator round-trips, loop control) over k
// blocks of work.
//
// The transformation is PURE DUPLICATION plus trip-count routing —
// values are never reordered, so it introduces no new trap or
// side-effect semantics of its own. The routing is exact for every
// initial counter value including wasm's mod-2^32 arithmetic (an
// initial counter of zero means 2^32 iterations in the original
// do-while; that case routes to the untouched remainder loop):
//
//	     preheader
//	         │
//	     G0: init == 0 ?──yes──────────────┐
//	         │ no                          │
//	┌───▶G1: rem == 0 ?──yes──▶ E (exit join)
//	│        │ no                          ▲
//	│    G2: rem < k ?──yes────────────────┤
//	│        │ no                          │
//	└─── U: k body copies            R: original loop
//	         (falls back to G1)      (self-loop, untouched) ──▶ E
//
// G1's phis carry the counter and every loop-carried value; E's phis
// merge every value the loop defines that is used outside it. The
// unrolled path U needs no per-copy exit checks because G2 admitted it
// only with rem ≥ k: the original loop, which exits exactly when the
// decremented counter hits zero, could not have exited during those k
// iterations.
type unrollShape struct {
	b        *ssa.Block
	preIdx   int        // b.Preds index of the preheader edge
	backIdx  int        // b.Preds index of the self edge
	exitSucc int        // b.Succs index of the exit edge
	backSucc int        // b.Succs index of the back edge
	counter  *ssa.Value // the countdown phi
	update   *ssa.Value // Sub(counter, 1) at the counter's width
	wide     bool       // the counter is i64 (memory64 modules promote it)
}

// UnrollSimdLoops applies the transform to every matching loop. wide
// additionally admits i64-countdown loops — the shape memory64 modules
// produce, where LP64 promotes the induction variable. It is an
// explicit opt-in per module width because unrolling is only a win
// when the downstream window fusion consumes the unrolled body; on
// wasm32 the i64-counter loops are exactly the ones that do NOT fuse
// (measured: admitting them cost ~40% prompt throughput), while on
// memory64 they are the hot SIMD kernels themselves.
func UnrollSimdLoops(f *ssa.Func, k int, wide bool) bool {
	if k < 2 {
		return false
	}
	changed := false
	// Collect first: the transform adds blocks while iterating.
	var shapes []unrollShape
	for _, b := range f.Blocks {
		if sh, ok := analyzeUnrollLoop(b, wide); ok {
			shapes = append(shapes, sh)
		}
	}
	for _, sh := range shapes {
		unrollOne(f, sh, k)
		changed = true
	}
	return changed
}

// analyzeUnrollLoop matches the countdown do-while self-loop the wasm
// lowering produces for ggml-style inner loops.
func analyzeUnrollLoop(b *ssa.Block, wide bool) (unrollShape, bool) {
	var sh unrollShape
	sh.b = b
	if b.Kind != ssa.BlockIf || len(b.Succs) != 2 || len(b.Preds) != 2 || b.Control == nil {
		return sh, false
	}
	sh.backSucc = -1
	for i, s := range b.Succs {
		if s.Block == b {
			sh.backSucc = i
		} else {
			sh.exitSucc = i
		}
	}
	if sh.backSucc != 0 {
		// The lowering emits `if u != 0 { continue }`: the TRUE arm is
		// the back edge. Other shapes stay untouched in v1.
		return sh, false
	}
	sh.backIdx = -1
	for i, p := range b.Preds {
		if p.Block == b {
			sh.backIdx = i
		} else {
			sh.preIdx = i
		}
	}
	if sh.backIdx == -1 {
		return sh, false
	}
	// Control: the countdown update used as the branch condition —
	// either the raw i32 (`If u`, the shape the lowering produces for
	// br_if) or wrapped as Ne(u, 0) at the counter's width. u =
	// Sub(counterPhi, 1), and the counter phi's back-edge argument is
	// u. Memory64 modules promote the counter to i64 (LP64 induction
	// variables), so both widths must match.
	u := b.Control
	if len(u.Args) == 2 && (u.Op == ssa.OpNe32 || (wide && u.Op == ssa.OpNe64)) {
		wide := u.Op == ssa.OpNe64
		a, zero := u.Args[0], u.Args[1]
		if !isConstInt(zero, 0, wide) {
			a, zero = zero, a
		}
		if !isConstInt(zero, 0, wide) {
			return sh, false
		}
		u = a
		sh.wide = wide
	}
	subOp := ssa.OpSub32
	if sh.wide {
		subOp = ssa.OpSub64
	}
	if u.Op != subOp || len(u.Args) != 2 || u.Block != b || !isConstInt(u.Args[1], 1, sh.wide) {
		return sh, false
	}
	p := u.Args[0]
	if p.Op != ssa.OpPhi || p.Block != b || len(p.Args) != 2 || p.Args[sh.backIdx] != u {
		return sh, false
	}
	sh.counter, sh.update = p, u
	// Gate: only loops whose body touches SIMD memory benefit enough
	// to pay the code growth.
	hasSimdMem := false
	for _, v := range b.Values {
		if v.Op == ssa.OpSimdMemCall {
			hasSimdMem = true
			break
		}
	}
	if !hasSimdMem {
		return sh, false
	}
	// Every value must be clonable bookkeeping-wise; blocks with
	// nested control (impossible in one block) or exotic ops that the
	// cloner cannot copy are rejected. Cloning copies Op/Type/AuxInt/
	// Aux/Args wholesale, which is valid for every op.
	return sh, true
}

func isConst32(v *ssa.Value, want int64) bool {
	return v != nil && v.Op == ssa.OpConst32 && v.AuxInt == want
}

// isConstInt is isConst32 at a selectable width.
func isConstInt(v *ssa.Value, want int64, wide bool) bool {
	if wide {
		return v != nil && v.Op == ssa.OpConst64 && v.AuxInt == want
	}
	return isConst32(v, want)
}

// ReassocConstAdds folds Add(Add(x, c1), c2) into Add(x, c1+c2)
// (mod 2^32 / mod 2^64, exactly wasm's adds). Unrolled pointer-bump
// chains produce exactly this shape — i32 addresses on wasm32, i64 on
// memory64 — and the memory-addend and bounds passes peel only one
// constant level: without reassociation the unrolled loads would not
// share a base. The i64 arm is memory64-only (wide): on wasm32 the
// i64 adds are ordinary scalar arithmetic, and rewriting them shifts
// downstream code shapes for no addressing benefit.
func ReassocConstAdds(f *ssa.Func, wide bool) bool {
	changed := false
	for _, b := range f.Blocks {
		for i, v := range b.Values {
			if v == nil || len(v.Args) != 2 {
				continue
			}
			var constOp ssa.Op
			var typ ssa.Type
			var wrap func(a, b int64) int64
			switch v.Op {
			case ssa.OpAdd32:
				constOp, typ = ssa.OpConst32, ssa.TypeI32
				wrap = func(a, b int64) int64 { return int64(int32(uint32(a) + uint32(b))) }
			case ssa.OpAdd64:
				if !wide {
					continue
				}
				constOp, typ = ssa.OpConst64, ssa.TypeI64
				wrap = func(a, b int64) int64 { return int64(uint64(a) + uint64(b)) }
			default:
				continue
			}
			inner, c2 := v.Args[0], v.Args[1]
			if c2 == nil || c2.Op != constOp {
				inner, c2 = c2, inner
			}
			if c2 == nil || c2.Op != constOp || inner == nil || inner.Op != v.Op || len(inner.Args) != 2 {
				continue
			}
			x, c1 := inner.Args[0], inner.Args[1]
			if c1 == nil || c1.Op != constOp {
				x, c1 = c1, x
			}
			if c1 == nil || c1.Op != constOp {
				continue
			}
			sumC := b.NewValueBefore(f, i, constOp, typ, wrap(c1.AuxInt, c2.AuxInt), nil)
			v.Args[0] = x
			v.Args[1] = sumC
			changed = true
		}
	}
	return changed
}

func unrollOne(f *ssa.Func, sh unrollShape, k int) {
	b := sh.b
	oldExit := b.Succs[sh.exitSucc].Block
	oldExitPredIdx := b.Succs[sh.exitSucc].Index

	// Loop phis and their inits/updates.
	var phis []*ssa.Value
	for _, v := range b.Values {
		if v.Op == ssa.OpPhi {
			phis = append(phis, v)
		}
	}
	// Values defined in b and used outside it (including by the old
	// exit block's phis through the b edge). Phis count too: an
	// outside use of a phi observes its final-iteration value.
	outside := map[*ssa.Value]bool{}
	for _, ob := range f.Blocks {
		if ob == b {
			continue
		}
		for _, v := range ob.Values {
			for _, a := range v.Args {
				if a != nil && a.Block == b {
					outside[a] = true
				}
			}
		}
		if ob.Control != nil && ob.Control.Block == b {
			outside[ob.Control] = true
		}
	}
	var liveouts []*ssa.Value
	for _, v := range b.Values {
		if outside[v] {
			liveouts = append(liveouts, v)
		}
	}

	g0 := f.NewBlock(ssa.BlockIf)
	g1 := f.NewBlock(ssa.BlockIf)
	g2 := f.NewBlock(ssa.BlockIf)
	u := f.NewBlock(ssa.BlockPlain)
	e := f.NewBlock(ssa.BlockPlain)

	newV := func(blk *ssa.Block, op ssa.Op, typ ssa.Type, auxInt int64, aux interface{}, args ...*ssa.Value) *ssa.Value {
		return blk.NewValueBefore(f, len(blk.Values), op, typ, auxInt, aux, args...)
	}

	// The guard arithmetic runs at the counter's own width; every
	// comparison below uses this op family. Routing stays exact at
	// both widths (an initial counter of zero means 2^32 — or 2^64 —
	// iterations and takes the untouched remainder loop).
	ctrConstOp, ctrType, ctrNeOp, ctrLtUOp := ssa.OpConst32, ssa.TypeI32, ssa.OpNe32, ssa.OpLtU32
	if sh.wide {
		ctrConstOp, ctrType, ctrNeOp, ctrLtUOp = ssa.OpConst64, ssa.TypeI64, ssa.OpNe64, ssa.OpLtU64
	}

	// --- Rewire the preheader to G0. ---
	pre := b.Preds[sh.preIdx].Block
	preSuccIdx := b.Preds[sh.preIdx].Index
	pre.Succs[preSuccIdx] = ssa.Edge{Block: g0, Index: 0}
	g0.Preds = []ssa.Edge{{Block: pre, Index: preSuccIdx}}

	inits := make([]*ssa.Value, len(phis))
	for i, p := range phis {
		inits[i] = p.Args[sh.preIdx]
	}

	// --- G0: init == 0 → R (original loop handles the 2^32 case), else G1. ---
	// Succs[0] = TRUE arm to match the lowering convention used here:
	// control Ne(init, 0), TRUE → G1.
	var initCounter *ssa.Value
	for i, p := range phis {
		if p == sh.counter {
			initCounter = inits[i]
		}
	}
	zeroC := newV(g0, ctrConstOp, ctrType, 0, nil)
	// Typed zero placeholders for carrier-phi arguments along the G0
	// edge. Those arguments are never OBSERVED (G1's exit arm cannot be
	// taken on the first entry: init != 0 there), but the verifier
	// rightly demands a dominating definition for every phi argument.
	zeroOf := map[ssa.Type]*ssa.Value{ctrType: zeroC}
	typedZero := func(t ssa.Type) *ssa.Value {
		if z, ok := zeroOf[t]; ok {
			return z
		}
		var z *ssa.Value
		switch t {
		case ssa.TypeI64:
			z = newV(g0, ssa.OpConst64, t, 0, nil)
		case ssa.TypeF32:
			z = newV(g0, ssa.OpConstF32, t, 0, nil)
		case ssa.TypeF64:
			z = newV(g0, ssa.OpConstF64, t, 0, nil)
		case ssa.TypeV128:
			z = newV(g0, ssa.OpSimdConst, t, 0, [2]uint64{})
		default:
			z = newV(g0, ssa.OpConst32, ssa.TypeI32, 0, nil)
		}
		zeroOf[t] = z
		return z
	}
	g0.Control = newV(g0, ctrNeOp, ssa.TypeBool, 0, nil, initCounter, zeroC)
	// G0's TRUE arm goes to G1; the FALSE arm re-enters the untouched
	// loop through its ORIGINAL preheader slot (init phi arguments stay
	// valid there), wired manually below.
	ssa.AddEdge(g0, g1) // TRUE: init != 0; g1.Preds[0] = g0

	// --- G1 phis: one per loop phi (preds: G0, U — U's args filled after cloning),
	// plus one carrier per liveout (the G0-edge argument is never
	// observed: G1→E is unreachable on the first entry since init≠0). ---
	g1Phi := make(map[*ssa.Value]*ssa.Value, len(phis)+len(liveouts))
	for i, p := range phis {
		g1Phi[p] = newV(g1, ssa.OpPhi, p.Type, 0, nil, inits[i], nil)
	}
	for _, lv := range liveouts {
		if lv.Op == ssa.OpPhi {
			continue // covered above
		}
		g1Phi[lv] = newV(g1, ssa.OpPhi, lv.Type, 0, nil, typedZero(lv.Type), nil)
	}
	// G1 is the unrolled loop's header with a SINGLE exit — the
	// structured emitter turns single-exit loops into clean `for`
	// bodies, where a two-target exit forces the flat goto form (and
	// goto emission flattens expressions, killing tree fusion).
	// TRUE: rem < k → leave for the tail guard. FALSE: full stride.
	rem := g1Phi[sh.counter]
	kC := newV(g1, ctrConstOp, ctrType, int64(k), nil)
	g1.Control = newV(g1, ctrLtUOp, ssa.TypeBool, 0, nil, rem, kC)
	ssa.AddEdge(g1, g2) // TRUE arm: tail guard (g2 plays T0)
	// FALSE arm to U is wired after the clones exist (below).

	// --- T0 (g2): rem != 0 → R (remainder loop), else E. ---
	zeroC1 := newV(g2, ctrConstOp, ctrType, 0, nil)
	g2.Control = newV(g2, ctrNeOp, ssa.TypeBool, 0, nil, rem, zeroC1)

	// --- U: k straight-line clones of the body. ---
	running := map[*ssa.Value]*ssa.Value{}
	for _, p := range phis {
		running[p] = g1Phi[p]
	}
	mapArg := func(clones map[*ssa.Value]*ssa.Value, a *ssa.Value) *ssa.Value {
		if a == nil {
			return nil
		}
		if c, ok := clones[a]; ok {
			return c
		}
		if r, ok := running[a]; ok {
			return r
		}
		return a
	}
	lastClone := map[*ssa.Value]*ssa.Value{}
	for iter := 0; iter < k; iter++ {
		clones := map[*ssa.Value]*ssa.Value{}
		for _, v := range b.Values {
			if v.Op == ssa.OpPhi {
				continue
			}
			args := make([]*ssa.Value, len(v.Args))
			for i, a := range v.Args {
				args[i] = mapArg(clones, a)
			}
			clones[v] = newV(u, v.Op, v.Type, v.AuxInt, v.Aux, args...)
		}
		for _, p := range phis {
			running[p] = mapArg(clones, p.Args[sh.backIdx])
		}
		if iter == k-1 {
			for _, lv := range liveouts {
				if lv.Op == ssa.OpPhi {
					lastClone[lv] = running[lv]
				} else {
					lastClone[lv] = clones[lv]
				}
			}
		}
	}
	ssa.AddEdge(g1, u) // FALSE arm of G1: full stride
	ssa.AddEdge(u, g1)
	// Fill G1 phis' U-edge arguments (index 1: preds are [G0, U]).
	for _, p := range phis {
		g1Phi[p].Args[1] = running[p]
	}
	for _, lv := range liveouts {
		if lv.Op == ssa.OpPhi {
			continue
		}
		g1Phi[lv].Args[1] = lastClone[lv]
	}

	// --- Rewire b (the remainder loop). The G0 FALSE edge and the G2
	// TRUE edge both target b; phi arguments must distinguish them, so
	// b gains a THIRD pred. Slot preIdx now belongs to G0 (init phi
	// arguments unchanged); the G2 entry appends with current values. ---
	b.Preds[sh.preIdx] = ssa.Edge{Block: g0, Index: 1}
	g0.Succs = append(g0.Succs, ssa.Edge{Block: b, Index: sh.preIdx})    // FALSE arm
	g2.Succs = append(g2.Succs, ssa.Edge{Block: b, Index: len(b.Preds)}) // TRUE arm of T0
	b.Preds = append(b.Preds, ssa.Edge{Block: g2, Index: 0})
	for _, p := range phis {
		p.Args = append(p.Args, g1Phi[p])
	}

	// --- E: exit join. Preds are [T0 (done; the phi arguments are
	// G1's phis, which dominate T0), b (remainder exit)]. ---
	ssa.AddEdge(g2, e) // FALSE arm of T0: e.Preds[0] = g2
	b.Succs[sh.exitSucc] = ssa.Edge{Block: e, Index: len(e.Preds)}
	e.Preds = append(e.Preds, ssa.Edge{Block: b, Index: sh.exitSucc})
	ePhi := make(map[*ssa.Value]*ssa.Value, len(liveouts))
	for _, lv := range liveouts {
		ePhi[lv] = newV(e, ssa.OpPhi, lv.Type, 0, nil, g1Phi[lv], lv)
	}
	// E falls through to the old exit, taking over b's pred slot there.
	e.Succs = append(e.Succs, ssa.Edge{Block: oldExit, Index: oldExitPredIdx})
	oldExit.Preds[oldExitPredIdx] = ssa.Edge{Block: e, Index: 0}

	// --- Rewrite outside uses of b's values to E's phis. ---
	newBlocks := map[*ssa.Block]bool{b: true, g0: true, g1: true, g2: true, u: true, e: true}
	for _, ob := range f.Blocks {
		if newBlocks[ob] {
			continue
		}
		for _, v := range ob.Values {
			for i, a := range v.Args {
				if a != nil && a.Block == b {
					if np, ok := ePhi[a]; ok {
						v.Args[i] = np
					}
				}
			}
		}
		if ob.Control != nil && ob.Control.Block == b {
			if np, ok := ePhi[ob.Control]; ok {
				ob.Control = np
			}
		}
	}
	// E's own phi args intentionally reference b's values; G1's phi
	// args reference U's clones; both were skipped above via newBlocks.
}
