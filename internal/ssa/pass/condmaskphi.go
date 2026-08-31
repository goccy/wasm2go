package pass

import "github.com/goccy/wasm2go/internal/ssa"

// FoldCondMaskPhi rewrites a BlockIf whose condition is a diamond-produced
// constant mask back to the diamond's own condition:
//
//	head:  If c -> then, else
//	then:  ...                     // arms may hold arbitrary values;
//	else:  ...                     // only the phi's args must be consts
//	join:  m = phi(K, 0)           // K != 0 on the then edge
//	...
//	b:     If m -> x, y            // ==> If c -> x, y
//
// m != 0 holds exactly when the head took its then edge, i.e. when
// c != 0, so branching on c is an exact replacement (c dominates the
// head, the head dominates the join, and SSA guarantees the join
// dominates every use of m — so c is available at b). The mask value
// itself is left alone for its other uses and dies in DCE when the
// rewritten branch was the last one.
//
// Besides being a real simplification, this unblocks a code shape the
// Go arm64 backend cannot assemble: a CSETM-materialized mask (an if
// assigning -1/0) consumed as another conditional's operand makes the
// compiler emit CSEL with an always-true condition, which the assembler
// rejects ("illegal combination"). perl 5.44's charclass code produces
// exactly that shape.
func FoldCondMaskPhi(f *ssa.Func) bool {
	changed := false
	for _, b := range f.Blocks {
		if b.Kind != ssa.BlockIf || b.Control == nil {
			continue
		}
		phi := b.Control
		if phi.Op != ssa.OpPhi || len(phi.Args) != 2 || phi.Block == nil {
			continue
		}
		a0, a1 := phi.Args[0], phi.Args[1]
		if a0 == nil || a1 == nil ||
			a0.Op != ssa.OpConst32 || a1.Op != ssa.OpConst32 {
			continue
		}
		if (a0.AuxInt == 0) == (a1.AuxInt == 0) {
			continue // need exactly one zero arm
		}
		join := phi.Block
		if len(join.Preds) != 2 {
			continue
		}
		h0, s0 := maskDiamondHead(join, 0)
		h1, s1 := maskDiamondHead(join, 1)
		if h0 == nil || h0 != h1 || s0 == s1 || h0.Control == nil {
			continue
		}
		// The phi arg riding the head's then edge (Succs[0]): nonzero
		// there means the mask is truthy exactly when the condition is.
		thenArg := phi.Args[0]
		if s1 == 0 {
			thenArg = phi.Args[1]
		}
		if thenArg.AuxInt == 0 {
			continue // inverted mask: would need a negation value
		}
		b.Control = h0.Control
		changed = true
	}
	return changed
}

// maskDiamondHead resolves join.Preds[i] to the BlockIf heading the
// diamond and the index of the head successor edge (0 = then) that path
// came through: either the predecessor IS the head (triangle form), or
// it is a single-entry single-exit arm block under it. Arm contents do
// not matter — the fold never touches them.
func maskDiamondHead(join *ssa.Block, i int) (*ssa.Block, int) {
	e := join.Preds[i]
	p := e.Block
	if p.Kind == ssa.BlockIf {
		return p, e.Index
	}
	if len(p.Preds) == 1 && len(p.Succs) == 1 {
		pe := p.Preds[0]
		if pe.Block.Kind == ssa.BlockIf {
			return pe.Block, pe.Index
		}
	}
	return nil, 0
}
