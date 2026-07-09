// Package emit holds the backend-neutral analyses that an SSA-driven
// code emitter needs: usage counting, hoisting decisions, phi staging,
// and the trivial SSA-only predicates those decisions rely on.
//
// Anything Go-syntax specific (Go-AST construction, identifier names,
// type spellings) stays in internal/codegen. Per-architecture assembly
// generation is the internal/gcasm backend (which captures gc's `-S`
// output and transforms it). emit is the analysis layer they share.
package emit

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// ComputeValueUsage returns a map ValueID → number of times the value
// is referenced as an argument (across all blocks) plus once per Block
// Control that references it. Used to decide when to hoist a value
// into a local variable vs inline it at the use site.
func ComputeValueUsage(f *ssa.Func) map[ssa.ValueID]int {
	uses := map[ssa.ValueID]int{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			for _, a := range v.Args {
				if a == nil {
					continue
				}
				uses[a.ID]++
			}
		}
		if blk.Control != nil {
			uses[blk.Control.ID]++
		}
	}
	return uses
}

// ComputeHoist decides which values need a hoisted local. A value is
// hoisted when:
//   - it is a phi (assigned on predecessor edges, read elsewhere);
//   - it is a side-effecting value that yields a usable scalar (a call
//     returning a value) — must be emitted once, not re-inlined;
//   - it is a memory load — the IR has no Mem token, so a load relies
//     on statement order; inlining a single-use load could float it
//     past an intervening store;
//   - it is referenced two or more times.
//
// Params are never hoisted (they are bound to the parameter names /
// argument slots provided by the calling convention).
//
// Additionally, the value-side argument of every narrowing store is
// force-hoisted. The Go emitter renders narrowing stores as
// `*(*uint8)(...) = uint8(vN)` and the truncating cast must be a
// runtime conversion — an inlined constant operand would trip Go's
// compile-time constant-overflow check. Force-hoisting args[1]
// guarantees the operand is always a typed local variable. The asm
// emitter does not face the constant-overflow constraint, but
// hoisting these values is harmless there (and keeps the two
// backends' hoist sets identical, which simplifies golden tests).
func ComputeHoist(f *ssa.Func, usage map[ssa.ValueID]int) map[ssa.ValueID]bool {
	hoist := map[ssa.ValueID]bool{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			switch {
			case v.Op == ssa.OpPhi:
				hoist[v.ID] = true
			case v.Op == ssa.OpParam:
				// never hoisted
			case v.HasSideEffect():
				if IsScalarType(v.Type) {
					hoist[v.ID] = true
				}
			case IsLoadOp(v.Op):
				hoist[v.ID] = true
			case usage[v.ID] >= 2:
				hoist[v.ID] = true
			}
		}
	}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if !IsNarrowingStore(v) {
				continue
			}
			if len(v.Args) >= 2 && v.Args[1] != nil {
				hoist[v.Args[1].ID] = true
			}
		}
	}
	return hoist
}

// ComputeStagedPhis returns the phis whose edge-copies must go through
// a parallel-copy staging temp. A phi P needs staging iff, on some
// incoming edge, the right-hand side of P (or of a sibling phi
// assigned on the same edge) reads a phi that is itself a target on
// that edge — the loop-back-edge swap hazard. if/else merges, where
// the only target on an edge is the merge phi itself and the RHS
// comes from outside, never trip this and get a plain direct copy.
func ComputeStagedPhis(f *ssa.Func, hoist map[ssa.ValueID]bool) map[ssa.ValueID]bool {
	staged := map[ssa.ValueID]bool{}
	for _, succ := range f.Blocks {
		var phis []*ssa.Value
		targets := map[ssa.ValueID]bool{}
		for _, v := range succ.Values {
			if v.Op == ssa.OpPhi {
				phis = append(phis, v)
				targets[v.ID] = true
			}
		}
		if len(phis) == 0 {
			continue
		}
		for predIdx := range succ.Preds {
			conflict := false
			for _, phi := range phis {
				if predIdx >= len(phi.Args) {
					continue
				}
				src := phi.Args[predIdx]
				if src == nil || src == phi {
					continue
				}
				refs := map[ssa.ValueID]bool{}
				CollectHoistedRefs(src, hoist, refs)
				for id := range refs {
					// Self-reference (phi A's RHS reads phi A's
					// own value through its iter chain — the
					// canonical loop carry shape) is NOT a swap
					// hazard. The phi's old value flows through
					// the iter slot which is already computed
					// and stored before this edge-copy runs; we
					// then overwrite the phi's slot with the
					// iter value with no need for a temp.
					//
					// Cross-phi reference (phi A's RHS reads phi
					// B with B != A) IS a hazard: writing B
					// first changes what A's read sees, and
					// vice versa. That's the case that needs
					// staging.
					if targets[id] && id != phi.ID {
						conflict = true
					}
				}
			}
			if conflict {
				for _, phi := range phis {
					staged[phi.ID] = true
				}
				break
			}
		}
	}
	return staged
}

// CollectHoistedRefs walks v and gathers the IDs of every hoisted
// value the emitted expression for v would reference. A hoisted value
// is emitted by name, so recursion stops there; a non-hoisted value
// is inlined, so its operands are walked.
func CollectHoistedRefs(v *ssa.Value, hoist map[ssa.ValueID]bool, out map[ssa.ValueID]bool) {
	if v == nil {
		return
	}
	if hoist[v.ID] {
		out[v.ID] = true
		return
	}
	for _, a := range v.Args {
		CollectHoistedRefs(a, hoist, out)
	}
}

// IsScalarType reports whether t is an emittable scalar value type
// (a real Go value, not the Mem state token, Tuple, or Invalid).
func IsScalarType(t ssa.Type) bool {
	switch t {
	case ssa.TypeI32, ssa.TypeI64, ssa.TypeF32, ssa.TypeF64, ssa.TypeBool:
		return true
	}
	return false
}

// IsLoadOp reports whether op is a memory-or-global read that must be
// preserved in statement order. Loads are not flagged HasSideEffect
// (they don't write state) but must still be ordered relative to
// stores/calls; ComputeHoist force-hoists them so they emit as
// in-order statements.
//
// Note: a similar predicate exists in internal/ssa for the
// memory-classification pass. That one tracks only true linear-memory
// loads (no OpGlobalGet) because globals don't participate in the
// memory model it analyzes. This predicate, used by the hoist
// decision, must include OpGlobalGet because globals are observable
// across calls and the emitter relies on statement-order semantics
// to keep them sound.
func IsLoadOp(op ssa.Op) bool {
	switch op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64,
		ssa.OpGlobalGet,
		// OpLocalGet reads a mutable local var (EH mutable-locals mode); it
		// must emit as an in-order statement, not be reused across an
		// intervening OpLocalSet.
		ssa.OpLocalGet:
		return true
	}
	return false
}

// IsNarrowingStore reports whether v is a memory store that writes
// strictly fewer bits than its value argument carries. Such stores
// need their value operand hoisted into a typed local so a backend
// that lowers the narrowing as a typed cast (e.g. the Go backend's
// `uint8(vN)`) sees a runtime conversion rather than a literal that
// would trigger compile-time overflow checks.
func IsNarrowingStore(v *ssa.Value) bool {
	if v == nil || len(v.Args) < 2 || v.Args[1] == nil {
		return false
	}
	var elemBits int
	switch v.Op {
	case ssa.OpStore8:
		elemBits = 8
	case ssa.OpStore16:
		elemBits = 16
	case ssa.OpStore32:
		elemBits = 32
	case ssa.OpStore64:
		elemBits = 64
	case ssa.OpStoreF32:
		elemBits = 32
	case ssa.OpStoreF64:
		elemBits = 64
	default:
		return false
	}
	return elemBits < v.Args[1].Type.Bits()
}
