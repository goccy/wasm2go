package codegen

// Runtime-table detection: derive the f16->f32 table's address from
// the module's own initialization code instead of trusting an external
// assertion.
//
// ggml-style engines build the 65536-entry f16->f32 lookup table at
// runtime (ggml_init), so the module's data image holds zeros and the
// static byte-check in hasIEEEF16TableAt can never see it. An
// externally-asserted address used to bridge that gap, but proved a
// liability: the table MOVES with every layout shift (source
// changes, even build-cache state), and a stale assertion silently
// disabled the table-verified rewrites — or worse, blessed whatever
// now lived at the old address.
//
// The initialization loop itself is the in-module proof this pass
// extracts: a loop that streams constant-strided stores from a
// constant base, covering the table's whole range before any use.
// Detection is structural over the SSA form — a loop-carried pointer
// phi with a constant start and constant per-iteration advance, a
// loop-carried counter phi with a computable trip count, and stores
// through the pointer — so it does not depend on how the compiler
// vectorized the conversion arithmetic inside the loop.

import (
	"fmt"
	"os"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
)

// initStoreRegion is one byte interval a detected init loop provably
// writes: [lo, hi).
type initStoreRegion struct {
	lo, hi uint64
}

// f16TableBytes is the size of an IEEE f16->f32 table: 65536 entries
// of 4 bytes.
const f16TableBytes = 1 << 18

// detectRuntimeTables scans every function body for init-loop store
// regions. Lowering failures are skipped silently here — the main
// translation pass surfaces them as build errors with full context.
func (t *translator) detectRuntimeTables() {
	if t.runtimeTables != nil {
		return
	}
	t.runtimeTables = []initStoreRegion{}
	for i := range t.mod.Functions {
		idx := uint32(len(t.mod.Imports)) + uint32(i)
		fn, err := lower.LowerFunction(t.mod, idx, t.funcName(idx), t.throwSet)
		if err != nil || fn == nil {
			continue
		}
		t.runtimeTables = append(t.runtimeTables, detectInitStoreRegions(fn)...)
	}
}

// runtimeInitCovered reports whether some detected init loop writes
// the entire f16 table range starting at base.
func (t *translator) runtimeInitCovered(base uint32) bool {
	lo, hi := uint64(base), uint64(base)+f16TableBytes
	for _, r := range t.runtimeTables {
		if r.lo <= lo && hi <= r.hi {
			return true
		}
	}
	return false
}

// detectInitStoreRegions finds the store intervals of one function's
// constant-based streaming loops.
func detectInitStoreRegions(f *ssa.Func) []initStoreRegion {
	var out []initStoreRegion
	for _, header := range f.Blocks {
		// Loop-carried linear variables present themselves as phis in
		// one header block: pointer candidates (constant init) and
		// counter candidates (computable trip count) live side by side.
		type linear struct {
			phi        *ssa.Value
			init, step int64
		}
		var ptrs, ctrs []linear
		for _, v := range header.Values {
			if v.Op != ssa.OpPhi {
				continue
			}
			init, step, ok := linearPhi(v)
			if !ok || step == 0 {
				continue
			}
			ptrs = append(ptrs, linear{v, init, step})
			ctrs = append(ctrs, linear{v, init, step})
		}
		if len(ptrs) == 0 {
			continue
		}
		// Trip count from any counter phi whose next value feeds a
		// zero compare that controls a branch (clang's canonical
		// countdown: q starts negative, steps up, exits at zero).
		trips := int64(0)
		for _, c := range ctrs {
			if n := tripCount(f, c.phi, c.init, c.step); n > 0 {
				trips = n
				break
			}
		}
		if trips <= 0 {
			continue
		}
		for _, p := range ptrs {
			if p.init <= 0 || p.step <= 0 {
				continue
			}
			minOff, maxEnd, found := storeExtent(f, p.phi)
			if !found {
				continue
			}
			lo := uint64(p.init) + uint64(minOff)
			hi := uint64(p.init) + uint64(trips-1)*uint64(p.step) + uint64(maxEnd)
			if hi > lo {
				out = append(out, initStoreRegion{lo: lo, hi: hi})
			}
		}
	}
	return out
}

// linearPhi matches phi(init=const, next=phi+const...) in either arg
// order, folding a chain of constant adds (a pointer bumped twice per
// iteration still resolves, with the step totalled).
func linearPhi(p *ssa.Value) (init, step int64, ok bool) {
	if len(p.Args) != 2 {
		return 0, 0, false
	}
	for i := 0; i < 2; i++ {
		c, cok := constOf(p.Args[i])
		if !cok {
			continue
		}
		s, sok := addChainStep(p.Args[1-i], p)
		if !sok {
			continue
		}
		return c, s, true
	}
	return 0, 0, false
}

// addChainStep resolves v as root+const (through a chain of adds with
// constant operands) and returns the summed constant.
func addChainStep(v, root *ssa.Value, hops ...int) (int64, bool) {
	if len(hops) > 0 && hops[0] > 8 {
		return 0, false
	}
	depth := 0
	if len(hops) > 0 {
		depth = hops[0]
	}
	if v == root {
		return 0, true
	}
	if v.Op != ssa.OpAdd32 && v.Op != ssa.OpAdd64 {
		return 0, false
	}
	if len(v.Args) != 2 {
		return 0, false
	}
	for i := 0; i < 2; i++ {
		c, cok := constOf(v.Args[i])
		if !cok {
			continue
		}
		rest, rok := addChainStep(v.Args[1-i], root, depth+1)
		if !rok {
			continue
		}
		return c + rest, true
	}
	return 0, false
}

func constOf(v *ssa.Value) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch v.Op {
	case ssa.OpConst32, ssa.OpConst64:
		return v.AuxInt, true
	}
	return 0, false
}

// tripCount derives how many iterations execute before the loop-
// carried counter's next value reaches its bound. Two shapes cover
// the emitted countdowns: exit on zero (init and step of opposite
// sign) via eq/ne-with-zero controls, and exit on an unsigned
// less-than bound.
func tripCount(f *ssa.Func, q *ssa.Value, init, step int64) int64 {
	if step == 0 {
		return 0
	}
	// The "next" value: the phi arg that is not the constant init.
	var next *ssa.Value
	for _, a := range q.Args {
		if _, isConst := constOf(a); !isConst {
			next = a
		}
	}
	if next == nil {
		return 0
	}
	for _, b := range f.Blocks {
		ctl := b.Control
		if ctl == nil || len(ctl.Args) != 2 {
			continue
		}
		var other *ssa.Value
		switch {
		case ctl.Args[0] == next || ctl.Args[0] == q:
			other = ctl.Args[1]
		case ctl.Args[1] == next || ctl.Args[1] == q:
			other = ctl.Args[0]
		default:
			continue
		}
		bound, ok := constOf(other)
		if !ok {
			continue
		}
		switch ctl.Op {
		case ssa.OpNe32, ssa.OpNe64, ssa.OpEq32, ssa.OpEq64:
			// Exit when next == bound: iterations = (bound-init)/step.
			d := bound - init
			if step != 0 && d%step == 0 && d/step > 0 {
				return d / step
			}
		case ssa.OpLtU32, ssa.OpLtU64, ssa.OpLtS32, ssa.OpLtS64:
			// Count-up i < N with unit-ish steps.
			d := bound - init
			if step > 0 && d > 0 {
				n := d / step
				if d%step != 0 {
					n++
				}
				return n
			}
		}
	}
	return 0
}

// storeExtent scans the function for stores addressed through ptr
// (directly or ptr+const) and returns the smallest store offset and
// the largest offset+width per iteration.
func storeExtent(f *ssa.Func, ptr *ssa.Value) (minOff, maxEnd int64, found bool) {
	consider := func(base *ssa.Value, off int64, width int64) {
		rel, ok := addChainStep(base, ptr)
		if !ok {
			return
		}
		o := rel + off
		if !found || o < minOff {
			minOff = o
		}
		if e := o + width; !found || e > maxEnd {
			maxEnd = e
		}
		found = true
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			switch v.Op {
			case ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
				ssa.OpStoreF32, ssa.OpStoreF64:
				if len(v.Args) < 1 {
					continue
				}
				consider(v.Args[0], v.AuxInt, storeWidth(v.Op))
			case ssa.OpSimdMemCall:
				name, _ := v.Aux.(string)
				w := simdStoreWidth(name)
				if w == 0 || len(v.Args) < 2 {
					continue
				}
				off, ok := constOf(v.Args[1])
				if !ok {
					continue
				}
				consider(v.Args[0], off, w)
			}
		}
	}
	return minOff, maxEnd, found
}

func storeWidth(op ssa.Op) int64 {
	switch op {
	case ssa.OpStore8:
		return 1
	case ssa.OpStore16:
		return 2
	case ssa.OpStore32, ssa.OpStoreF32:
		return 4
	case ssa.OpStore64, ssa.OpStoreF64:
		return 8
	}
	return 0
}

// simdStoreWidth maps the SIMD store helper names to bytes written;
// zero means "not a store".
func simdStoreWidth(helper string) int64 {
	switch helper {
	case "simd_v128_store", "simd_m64_v128_store":
		return 16
	case "simd_v128_store64_lane", "simd_m64_v128_store64_lane":
		return 8
	case "simd_v128_store32_lane", "simd_m64_v128_store32_lane":
		return 4
	case "simd_v128_store16_lane", "simd_m64_v128_store16_lane":
		return 2
	case "simd_v128_store8_lane", "simd_m64_v128_store8_lane":
		return 1
	}
	return 0
}

// noteF16TableDetection logs the auto-detected verification once per
// base, so pipelines see which address the rewrites keyed on.
func (t *translator) noteF16TableDetection(base uint32) {
	if t.f16Announced == nil {
		t.f16Announced = map[uint32]bool{}
	}
	if t.f16Announced[base] {
		return
	}
	t.f16Announced[base] = true
	fmt.Fprintf(os.Stderr, "wasm2go: f16 table auto-detected at %d (runtime init-loop coverage)\n", base)
}
