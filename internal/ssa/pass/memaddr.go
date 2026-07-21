package pass

import "github.com/goccy/wasm2go/internal/ssa"

// FoldMemAddend folds a large constant addend of a memory-access base
// into the access's static AuxInt offset:
//
//	Load  [off] (Add32 x (Const32 [c]))  =>  Load  [off + uint32(c)] x
//	Store [off] (Add32 x (Const32 [c]))  =>  Store [off + uint32(c)] x
//
// Why: the emitter routes a LARGE AuxInt offset on a runtime base
// through the package-level `_consts` table (a runtime memory load) so
// the gc ARM64 backend never folds a multi-MB constant into a
// load/store addressing immediate — out-of-range immediates on fused
// pair loads (LDP/LDPSW) fail to assemble with "constant is not in
// pool". That guard only sees the AuxInt; a constant that instead
// arrives as an SSA addend (`base = x + 27325896`) bypasses it, gc
// re-associates `(x + c) + off` at the deref site, and the same
// assembler failure surfaces. Normalising the addend into AuxInt
// puts every large constant back on the guarded path.
//
// Soundness: the emitter computes the effective address in uint32
// (`uint32(base) + uint32(off)`), matching wasm's mod-2^32 address
// arithmetic; uint32 addition is associative, so moving the constant
// from the base sum into the offset cannot change the address. This
// holds for shared memories too — the rewrite touches only address
// arithmetic, never the access itself — so the pass stays on even
// when MemOpt is gated off.
//
// Only addends that would need the `_consts` detour are folded
// (positive totals >= threshold, negative addends of magnitude >=
// threshold — a negative constant sign-extends into a huge addressing
// immediate just the same). Small addends stay in the base sum where
// they fold into an in-range immediate, which is both smaller and
// faster than a table load. threshold is the emitter's
// largeConstThreshold, passed in by the caller so the single source
// of truth stays with the emit layer.
//
// MUST run after the optimization fixpoint, not inside it. The fold
// assumes the remaining base x stays a RUNTIME value, whose emit path
// wraps the address to uint32 (mod-2^32, exact for wasm). If a later
// ConstProp iteration revealed x to be a constant, the emitter's
// pure-constant-base path would compute the unwrapped u33 total
// `uint32(x) + AuxInt` — like a genuine memarg offset — and any folded
// sum that relied on i32 wraparound would mis-address. Post-fixpoint
// nothing can constify x, so the hazard is structurally excluded
// (the pass also skips bases whose peeled operand is already a
// constant: a two-constant add is ConstProp's job).
//
// The rewrite may leave the Add32 without users; DCE reclaims it, and
// even without DCE a usage-0 pure value is never emitted.
// Returns true if anything changed.
func FoldMemAddend(f *ssa.Func, threshold uint64) bool {
	changed := false
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v == nil || v.Op == ssa.OpInvalid {
				continue
			}
			if !isLinearLoad(v.Op) && !isLinearStore(v.Op) {
				continue
			}
			if len(v.Args) == 0 || v.Args[0] == nil {
				continue
			}
			base := peelCopies(v.Args[0])
			if base == nil || base.Op != ssa.OpAdd32 || len(base.Args) != 2 {
				continue
			}
			x := peelCopies(base.Args[0])
			c := peelCopies(base.Args[1])
			if x == nil || c == nil {
				continue
			}
			if c.Op != ssa.OpConst32 {
				x, c = c, x
			}
			// Exactly one constant operand: a two-constant add is
			// ConstProp's job (it folds the add itself), and with no
			// constant there is nothing to move.
			if c.Op != ssa.OpConst32 || x.Op == ssa.OpConst32 {
				continue
			}
			c32 := int32(c.AuxInt)
			total := uint64(v.AuxInt) + uint64(uint32(c32))
			if c32 >= 0 {
				if total < threshold {
					continue
				}
			} else if uint64(-int64(c32)) < threshold {
				continue
			}
			v.Args[0] = x
			v.AuxInt = int64(total)
			changed = true
		}
	}
	return changed
}

// peelCopies follows OpCopy chains to the underlying value. Simplify
// dissolves most copies before this pass runs, but the fixpoint order
// does not guarantee it, so match through them.
func peelCopies(v *ssa.Value) *ssa.Value {
	for v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 {
		v = v.Args[0]
	}
	return v
}
