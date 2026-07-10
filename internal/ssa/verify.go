package ssa

import (
	"fmt"
	"strings"
)

// Verify checks structural invariants of a constructed Func and returns
// a non-nil error describing the first violation found. It is the
// primary debugging tool for the wasm-to-SSA lowering: a lowering bug
// that produces a malformed CFG (mismatched pred/succ edges, a phi
// whose arg count doesn't match its block's predecessor count, a Plain
// block with the wrong successor count, an unreachable block, ...) is
// caught here instead of silently emitting wrong Go.
//
// Verify is intentionally strict. Any deviation is a lowering bug.
func Verify(f *Func) error {
	if f.Entry == nil {
		return fmt.Errorf("verify %s: no entry block", f.Name)
	}

	blockByID := map[BlockID]*Block{}
	for _, b := range f.Blocks {
		if _, dup := blockByID[b.ID]; dup {
			return fmt.Errorf("verify %s: duplicate block id b%d", f.Name, b.ID)
		}
		blockByID[b.ID] = b
	}

	for _, b := range f.Blocks {
		// Pred/Succ symmetry: for every succ edge b→s, s must list b
		// as a predecessor at the recorded index.
		for si, e := range b.Succs {
			s := e.Block
			if s == nil {
				return fmt.Errorf("verify %s: b%d succ %d is nil", f.Name, b.ID, si)
			}
			if e.Index < 0 || e.Index >= len(s.Preds) {
				return fmt.Errorf("verify %s: b%d→b%d succ edge index %d out of range (b%d has %d preds)",
					f.Name, b.ID, s.ID, e.Index, s.ID, len(s.Preds))
			}
			if s.Preds[e.Index].Block != b {
				return fmt.Errorf("verify %s: b%d→b%d edge asymmetric: b%d.Preds[%d] is b%d",
					f.Name, b.ID, s.ID, s.ID, e.Index, s.Preds[e.Index].Block.ID)
			}
		}
		for pi, e := range b.Preds {
			p := e.Block
			if p == nil {
				return fmt.Errorf("verify %s: b%d pred %d is nil", f.Name, b.ID, pi)
			}
			if e.Index < 0 || e.Index >= len(p.Succs) {
				return fmt.Errorf("verify %s: b%d pred-edge from b%d index %d out of range",
					f.Name, b.ID, p.ID, e.Index)
			}
			if p.Succs[e.Index].Block != b {
				return fmt.Errorf("verify %s: b%d pred from b%d asymmetric", f.Name, b.ID, p.ID)
			}
		}

		// Terminator shape.
		switch b.Kind {
		case BlockPlain:
			if len(b.Succs) != 1 {
				return fmt.Errorf("verify %s: Plain b%d has %d successors (want 1)", f.Name, b.ID, len(b.Succs))
			}
		case BlockIf:
			if len(b.Succs) != 2 {
				return fmt.Errorf("verify %s: If b%d has %d successors (want 2)", f.Name, b.ID, len(b.Succs))
			}
			if b.Control == nil {
				return fmt.Errorf("verify %s: If b%d has nil Control", f.Name, b.ID)
			}
		case BlockRet:
			if len(b.Succs) != 0 {
				return fmt.Errorf("verify %s: Ret b%d has %d successors (want 0)", f.Name, b.ID, len(b.Succs))
			}
		case BlockUnreachable:
			// no constraint
		case BlockThrow:
			if len(b.Succs) != 0 {
				return fmt.Errorf("verify %s: Throw b%d has %d successors (want 0)", f.Name, b.ID, len(b.Succs))
			}
		case BlockBrTable:
			if len(b.Succs) == 0 {
				return fmt.Errorf("verify %s: BrTable b%d has no successors", f.Name, b.ID)
			}
			if b.Control == nil {
				return fmt.Errorf("verify %s: BrTable b%d has nil Control", f.Name, b.ID)
			}
			if b.Control.Type != TypeI32 {
				return fmt.Errorf("verify %s: BrTable b%d selector v%d has type %v (want i32)",
					f.Name, b.ID, b.Control.ID, b.Control.Type)
			}
			if len(b.TableCases) != len(b.Succs) {
				return fmt.Errorf("verify %s: BrTable b%d has %d case lists for %d successors",
					f.Name, b.ID, len(b.TableCases), len(b.Succs))
			}
			if b.TableDefault < 0 || b.TableDefault >= len(b.Succs) {
				return fmt.Errorf("verify %s: BrTable b%d default index %d out of range (%d succs)",
					f.Name, b.ID, b.TableDefault, len(b.Succs))
			}
			seenCase := map[int32]bool{}
			seenSucc := map[BlockID]bool{}
			for si, vals := range b.TableCases {
				if seenSucc[b.Succs[si].Block.ID] {
					return fmt.Errorf("verify %s: BrTable b%d successor b%d appears twice (targets must be deduped)",
						f.Name, b.ID, b.Succs[si].Block.ID)
				}
				seenSucc[b.Succs[si].Block.ID] = true
				for _, cv := range vals {
					if seenCase[cv] {
						return fmt.Errorf("verify %s: BrTable b%d selector value %d routed twice", f.Name, b.ID, cv)
					}
					seenCase[cv] = true
				}
			}
		default:
			return fmt.Errorf("verify %s: b%d has invalid kind %v", f.Name, b.ID, b.Kind)
		}

		// Phi arity: a phi must have exactly one arg per predecessor.
		// Phis must also come before any non-phi value in the block.
		seenNonPhi := false
		for _, v := range b.Values {
			if v.Op == OpPhi {
				if seenNonPhi {
					return fmt.Errorf("verify %s: b%d phi v%d appears after a non-phi value", f.Name, b.ID, v.ID)
				}
				if len(v.Args) != len(b.Preds) {
					return fmt.Errorf("verify %s: b%d phi v%d has %d args but block has %d preds",
						f.Name, b.ID, v.ID, len(v.Args), len(b.Preds))
				}
			} else {
				seenNonPhi = true
			}
			for ai, a := range v.Args {
				if a == nil {
					return fmt.Errorf("verify %s: v%d (%s) arg %d is nil", f.Name, v.ID, v.Op, ai)
				}
			}
			if v.Block != b {
				return fmt.Errorf("verify %s: v%d listed in b%d but Block is b%d",
					f.Name, v.ID, b.ID, blockID(v.Block))
			}
		}
	}

	// Reachability: every block must be reachable from Entry. An
	// unreachable block with no preds (other than Entry) signals that
	// a branch target was created but never wired — a lowering bug.
	reached := map[BlockID]bool{}
	stack := []*Block{f.Entry}
	// EH catch/catch_all handler blocks are landing pads: they are entered by
	// the runtime unwinding into the try, not by a CFG edge, so they are
	// legitimate reachability roots even with zero predecessors.
	for _, tr := range f.TryRegions {
		for _, h := range tr.Handlers {
			if h.Block != nil {
				stack = append(stack, h.Block)
			}
		}
	}
	for len(stack) > 0 {
		b := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if reached[b.ID] {
			continue
		}
		reached[b.ID] = true
		for _, e := range b.Succs {
			stack = append(stack, e.Block)
		}
	}
	var unreached []string
	for _, b := range f.Blocks {
		if !reached[b.ID] {
			unreached = append(unreached, fmt.Sprintf("b%d", b.ID))
		}
	}
	if len(unreached) > 0 {
		return fmt.Errorf("verify %s: blocks unreachable from entry: %s",
			f.Name, strings.Join(unreached, ","))
	}

	// Use-dominance: every value an instruction reads must be defined
	// on every path that reaches that instruction. For a non-phi value
	// in block B, each argument's defining block must dominate B. For a
	// phi, the i-th argument must dominate the i-th predecessor (the
	// value flows along that edge). A violation here is a lowering bug
	// — typically a stack value snapshotted from the wrong branch.
	if err := verifyUseDominance(f); err != nil {
		return err
	}
	return nil
}

// verifyUseDominance checks SSA use-before-def / dominance invariants.
func verifyUseDominance(f *Func) error {
	idom, rpoNum := computeDominators(f)
	// defBlock maps each value to the block it is defined in.
	defBlock := map[ValueID]*Block{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			defBlock[v.ID] = b
		}
	}
	// dominates reports whether block a dominates block b.
	dominates := func(a, b *Block) bool {
		for x := b; x != nil; x = idom[x.ID] {
			if x == a {
				return true
			}
			if x == idom[x.ID] {
				break // reached entry's self-idom
			}
		}
		return false
	}

	for _, b := range f.Blocks {
		// Position of each value within b for intra-block ordering.
		posInBlock := map[ValueID]int{}
		for i, v := range b.Values {
			posInBlock[v.ID] = i
		}
		for vi, v := range b.Values {
			for ai, a := range v.Args {
				db := defBlock[a.ID]
				if db == nil {
					// Param values / constants synthesised outside the
					// block list shouldn't happen — every value is
					// listed in some block.
					return fmt.Errorf("verify %s: v%d arg %d (v%d) has no defining block",
						f.Name, v.ID, ai, a.ID)
				}
				if v.Op == OpPhi {
					// Phi arg ai must dominate the END of pred ai.
					if ai >= len(b.Preds) {
						return fmt.Errorf("verify %s: phi v%d arg index %d exceeds preds", f.Name, v.ID, ai)
					}
					pred := b.Preds[ai].Block
					if db != pred && !dominates(db, pred) {
						return fmt.Errorf("verify %s: phi v%d in b%d: arg %d (v%d, def in b%d) does not dominate pred b%d",
							f.Name, v.ID, b.ID, ai, a.ID, db.ID, pred.ID)
					}
					continue
				}
				if db == b {
					// Same-block def must precede the use.
					if posInBlock[a.ID] >= vi {
						return fmt.Errorf("verify %s: v%d uses v%d defined later in same block b%d",
							f.Name, v.ID, a.ID, b.ID)
					}
					continue
				}
				if !dominates(db, b) {
					return fmt.Errorf("verify %s: v%d in b%d uses v%d whose def block b%d does not dominate b%d",
						f.Name, v.ID, b.ID, a.ID, db.ID, b.ID)
				}
			}
		}
		// The block's Control value (If condition) is used at block
		// end; its def block must dominate b.
		if b.Control != nil {
			db := defBlock[b.Control.ID]
			if db != nil && db != b && !dominates(db, b) {
				return fmt.Errorf("verify %s: b%d control v%d def block b%d does not dominate b%d",
					f.Name, b.ID, b.Control.ID, db.ID, b.ID)
			}
		}
	}
	_ = rpoNum
	return nil
}

// computeDominators returns the immediate-dominator map (idom) and a
// reverse-postorder numbering, using the Cooper-Harvey-Kennedy
// iterative algorithm. idom[entry] == entry.
func computeDominators(f *Func) (idom map[BlockID]*Block, rpoNum map[BlockID]int) {
	// Reverse-postorder via iterative DFS.
	var post []*Block
	seen := map[BlockID]bool{}
	type frame struct {
		b *Block
		i int
	}
	stack := []frame{{f.Entry, 0}}
	seen[f.Entry.ID] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.i < len(top.b.Succs) {
			s := top.b.Succs[top.i].Block
			top.i++
			if !seen[s.ID] {
				seen[s.ID] = true
				stack = append(stack, frame{s, 0})
			}
			continue
		}
		post = append(post, top.b)
		stack = stack[:len(stack)-1]
	}
	// rpo = reverse of post.
	rpo := make([]*Block, len(post))
	for i, b := range post {
		rpo[len(post)-1-i] = b
	}
	rpoNum = map[BlockID]int{}
	for i, b := range rpo {
		rpoNum[b.ID] = i
	}

	idom = map[BlockID]*Block{}
	idom[f.Entry.ID] = f.Entry

	intersect := func(a, b *Block) *Block {
		for a != b {
			for rpoNum[a.ID] > rpoNum[b.ID] {
				a = idom[a.ID]
			}
			for rpoNum[b.ID] > rpoNum[a.ID] {
				b = idom[b.ID]
			}
		}
		return a
	}

	changed := true
	for changed {
		changed = false
		for _, b := range rpo {
			if b == f.Entry {
				continue
			}
			var newIdom *Block
			for _, pe := range b.Preds {
				p := pe.Block
				if idom[p.ID] == nil {
					continue // pred not yet processed
				}
				if newIdom == nil {
					newIdom = p
				} else {
					newIdom = intersect(p, newIdom)
				}
			}
			if newIdom != nil && idom[b.ID] != newIdom {
				idom[b.ID] = newIdom
				changed = true
			}
		}
	}
	return idom, rpoNum
}

func blockID(b *Block) BlockID {
	if b == nil {
		return -1
	}
	return b.ID
}

// PruneDeadBlocks removes blocks that are fully isolated — zero
// predecessors and zero successors — and are not the entry block or an
// EH catch landing pad.
//
// Such blocks arise legitimately during structured-control lowering:
// e.g. a `loop` whose body always branches (br 0 back-edge or br N
// out) and never falls through its own `end` leaves the
// pre-allocated loop-post block with no edges at all. The lowering
// can't easily know up-front whether the post block will be needed,
// so it always allocates one and prunes here.
//
// This is safe precisely because — given how the lowering wires
// edges (every AddEdge source is the current, reachable block) — an
// unreachable block can never have acquired a successor edge either.
// So an isolated block carries no values anyone depends on.
//
// A catch landing pad breaks that reasoning: it is entered by unwinding,
// not by a CFG edge, so it has no predecessors. Usually it also has a
// successor (the `end` of the try falls through to the region's Post),
// which is why the pruner did not notice — but a handler that ends in
// `return`, `unreachable` or a `throw` has neither. Removing it leaves
// the TryRegion pointing at a block nobody emits: the recover
// trampoline still generates the `case <id>: goto L<id>` that resumes
// into the handler, and the resulting Go does not compile
// ("label L3 not defined"). The structured emitter fares no better —
// its block-count check fails and the whole function falls back.
//
// Run before Verify.
func PruneDeadBlocks(f *Func) {
	roots := map[BlockID]bool{}
	for _, tr := range f.TryRegions {
		for _, h := range tr.Handlers {
			if h.Block != nil {
				roots[h.Block.ID] = true
			}
		}
	}
	for {
		removed := false
		kept := f.Blocks[:0]
		for _, b := range f.Blocks {
			if b != f.Entry && !roots[b.ID] && len(b.Preds) == 0 && len(b.Succs) == 0 {
				removed = true
				continue
			}
			kept = append(kept, b)
		}
		f.Blocks = kept
		if !removed {
			return
		}
	}
}
