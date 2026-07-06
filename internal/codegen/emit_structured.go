package codegen

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/ssa"
)

// emit_structured.go reconstructs structured Go control flow
// (`if {} else {}`, `for {}`, straight-line) from the SSA CFG,
// replacing the goto/label baseline of emitMultiBlock. The goto
// emitter remains the fallback: emitStructured returns ok=false for
// any CFG shape it cannot prove cleanly structurable, and emitFuncBody
// then routes the function through emitMultiBlock.
//
// Supported shapes: straight-line, if/else, and single (non-nested)
// natural loops with one exit. Nested loops, multi-exit loops and
// irreducible CFGs fall back to the goto emitter.

// loopInfo describes one natural loop.
type loopInfo struct {
	header *ssa.Block
	body   map[ssa.BlockID]bool
	// follow is the single block control flows to on loop exit, or
	// nil when the loop is left only by `return` from inside.
	follow *ssa.Block
	// bad marks a loop the structured emitter cannot handle (more
	// than one exit target).
	bad bool
}

// loopFrame is one entry on the enclosing-loop stack during emission.
type loopFrame struct {
	header *ssa.Block
	follow *ssa.Block
}

// structEmitter holds the per-function state for structured emission.
type structEmitter struct {
	em        *ssaEmitter
	f         *ssa.Func
	hoist     map[ssa.ValueID]bool
	usage     map[ssa.ValueID]int
	stagedPhi map[ssa.ValueID]bool
	emitExpr  func(*ssa.Value) (ast.Expr, error)
	postdom   map[ssa.BlockID]*ssa.Block
	loops     map[ssa.BlockID]*loopInfo
	// ctx is the stack of enclosing loops, innermost last.
	ctx []loopFrame
	// emitted guards against emitting a block twice.
	emitted map[ssa.BlockID]bool
}

// emitStructured renders f as structured Go when the CFG permits.
// Returns ok=false to signal a fallback to emitMultiBlock.
func (em *ssaEmitter) emitStructured(f *ssa.Func) (body *ast.BlockStmt, ok bool) {
	if f.Entry == nil || !ssa.IsReducible(f) {
		return nil, false
	}
	defer func() {
		if r := recover(); r != nil {
			body, ok = nil, false
		}
	}()

	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)
	stagedPhi := emit.ComputeStagedPhis(f, hoist)
	var emitExpr func(*ssa.Value) (ast.Expr, error)
	emitExpr = func(v *ssa.Value) (ast.Expr, error) {
		if v == nil {
			return nil, fmt.Errorf("ssa emit: nil value")
		}
		if hoist[v.ID] {
			return newID(varNameForValue(v)), nil
		}
		return em.emitOp(v, emitExpr)
	}

	se := &structEmitter{
		em: em, f: f, hoist: hoist, usage: usage, stagedPhi: stagedPhi,
		emitExpr: emitExpr, postdom: ssa.PostDominators(f),
		loops:   analyzeLoops(f),
		emitted: map[ssa.BlockID]bool{},
	}
	for _, li := range se.loops {
		if li.bad {
			return nil, false // multi-exit loop — let the goto path handle it
		}
	}
	stmts, regionOK := se.region(f.Entry, nil)
	if !regionOK {
		return nil, false
	}
	if len(se.emitted) != len(f.Blocks) {
		return nil, false // a join was mis-identified; output incomplete
	}

	out := &ast.BlockStmt{}
	out.List = append(out.List, se.decls()...)
	out.List = append(out.List, stmts...)
	return out, true
}

// analyzeLoops computes the natural loop for every loop header.
func analyzeLoops(f *ssa.Func) map[ssa.BlockID]*loopInfo {
	loops := map[ssa.BlockID]*loopInfo{}
	for _, e := range ssa.BackEdges(f) {
		src, hdr := e[0], e[1]
		li := loops[hdr.ID]
		if li == nil {
			li = &loopInfo{header: hdr, body: map[ssa.BlockID]bool{hdr.ID: true}}
			loops[hdr.ID] = li
		}
		// Natural loop body: hdr plus every block that reaches the
		// back-edge source without passing through hdr.
		work := []*ssa.Block{src}
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			if li.body[b.ID] {
				continue
			}
			li.body[b.ID] = true
			for _, pe := range b.Preds {
				work = append(work, pe.Block)
			}
		}
	}
	// Exit analysis: the blocks outside the body that body blocks
	// branch to. Exactly one ⇒ a clean `for {}` + follow; zero ⇒ the
	// loop is left only via return; more than one ⇒ unstructurable.
	for _, li := range loops {
		exits := map[ssa.BlockID]*ssa.Block{}
		for id := range li.body {
			b := blockByID(f, id)
			for _, se := range b.Succs {
				if !li.body[se.Block.ID] {
					exits[se.Block.ID] = se.Block
				}
			}
		}
		switch len(exits) {
		case 0:
			li.follow = nil
		case 1:
			for _, b := range exits {
				li.follow = b
			}
		default:
			li.bad = true
		}
	}
	return loops
}

func blockByID(f *ssa.Func, id ssa.BlockID) *ssa.Block {
	for _, b := range f.Blocks {
		if b.ID == id {
			return b
		}
	}
	return nil
}

// region emits the structured statements for the CFG region starting
// at b and stopping just before `stop` (nil ⇒ to the function exit).
func (se *structEmitter) region(b, stop *ssa.Block) ([]ast.Stmt, bool) {
	var out []ast.Stmt
	for b != nil && b != stop {
		// Open a `for {}` when b heads a loop we are not already in.
		if li := se.loops[b.ID]; li != nil && !se.insideLoop(b) {
			se.ctx = append(se.ctx, loopFrame{header: b, follow: li.follow})
			forBody, ok := se.region(b, nil)
			se.ctx = se.ctx[:len(se.ctx)-1]
			if !ok {
				return nil, false
			}
			out = append(out, &ast.ForStmt{Body: &ast.BlockStmt{List: forBody}})
			b = li.follow
			continue
		}
		if se.emitted[b.ID] {
			return nil, false // re-entry — not a clean tree
		}
		se.emitted[b.ID] = true

		vs, err := se.blockValues(b)
		if err != nil {
			return nil, false
		}
		out = append(out, vs...)

		switch b.Kind {
		case ssa.BlockRet:
			rs, err := se.retStmt(b)
			if err != nil {
				return nil, false
			}
			out = append(out, rs)
			b = nil
		case ssa.BlockUnreachable:
			// Out-of-line trap helper, matching the multi-block
			// emitter: keeps the cold panic constructor out of hot
			// function bodies.
			out = append(out, &ast.ExprStmt{X: &ast.CallExpr{
				Fun: se.em.helperRef("wasm_trap_unreachable"),
			}})
			// The helper never returns, but Go's termination analysis
			// only trusts panic/for{} — keep the function well-formed.
			out = append(out, &ast.ForStmt{Body: &ast.BlockStmt{}})
			b = nil
		case ssa.BlockPlain:
			if len(b.Succs) != 1 {
				return nil, false
			}
			s := b.Succs[0].Block
			st, next, ok := se.goTo(s, b, b.Succs[0].Index, stop)
			if !ok {
				return nil, false
			}
			out = append(out, st...)
			b = next
		case ssa.BlockIf:
			if len(b.Succs) != 2 || b.Control == nil {
				return nil, false
			}
			thenBlk := b.Succs[0].Block
			elseBlk := b.Succs[1].Block
			if thenBlk == elseBlk {
				return nil, false
			}
			join := se.postdom[b.ID]
			cond, err := se.em.emitBoolCond(b.Control, se.emitExpr)
			if err != nil {
				return nil, false
			}
			thenStmts, ok := se.branch(b, thenBlk, b.Succs[0].Index, join)
			if !ok {
				return nil, false
			}
			elseStmts, ok := se.branch(b, elseBlk, b.Succs[1].Index, join)
			if !ok {
				return nil, false
			}
			out = append(out, &ast.IfStmt{
				Cond: cond,
				Body: &ast.BlockStmt{List: thenStmts},
				Else: &ast.BlockStmt{List: elseStmts},
			})
			// Continue past the join. The join may itself be a
			// continue/break target of an enclosing loop.
			if join == nil {
				b = nil
			} else if js, ok := se.jump(join); ok {
				out = append(out, js...)
				b = nil
			} else {
				b = join
			}
		default:
			return nil, false
		}
	}
	return out, true
}

// branch emits one arm of an If: phi copies on the fromIf→target edge,
// then the region from target up to the join (or a continue/break when
// target is an enclosing loop's header/follow).
func (se *structEmitter) branch(fromIf, target *ssa.Block, predIdx int, join *ssa.Block) ([]ast.Stmt, bool) {
	st, next, ok := se.goTo(target, fromIf, predIdx, join)
	if !ok {
		return nil, false
	}
	if next == nil {
		return st, true
	}
	rest, ok := se.region(next, join)
	if !ok {
		return nil, false
	}
	return append(st, rest...), true
}

// goTo emits the transition pred→target: the phi edge-copies, then a
// `continue` / `break` when target is an enclosing loop's header /
// follow. Returns (stmts, next, ok): next is the block the caller
// should continue the region with, or nil when a continue/break/stop
// terminated the path.
func (se *structEmitter) goTo(target, pred *ssa.Block, predIdx int, stop *ssa.Block) ([]ast.Stmt, *ssa.Block, bool) {
	ph, ok := se.phiCopies(pred, target, predIdx)
	if !ok {
		return nil, nil, false
	}
	if js, ok := se.jump(target); ok {
		return append(ph, js...), nil, true
	}
	if target == stop {
		return ph, nil, true
	}
	return ph, target, true
}

// jump returns the `continue` / `break` statement when `target` is the
// header or follow of an enclosing loop. ok=false means it is an
// ordinary block. Only the INNERMOST enclosing loop is handled with a
// bare continue/break; a jump to an outer loop returns ok=false so the
// whole function falls back to the goto emitter (labelled loops are a
// follow-up).
func (se *structEmitter) jump(target *ssa.Block) ([]ast.Stmt, bool) {
	if len(se.ctx) == 0 {
		return nil, false
	}
	inner := se.ctx[len(se.ctx)-1]
	if target == inner.header {
		return []ast.Stmt{&ast.BranchStmt{Tok: token.CONTINUE}}, true
	}
	if inner.follow != nil && target == inner.follow {
		return []ast.Stmt{&ast.BranchStmt{Tok: token.BREAK}}, true
	}
	// A jump to an outer loop's header/follow would need a labelled
	// continue/break. Signal "not handled" so emitStructured bails.
	for i := 0; i < len(se.ctx)-1; i++ {
		if target == se.ctx[i].header || target == se.ctx[i].follow {
			panic("structured emit: jump to outer loop needs a label")
		}
	}
	return nil, false
}

// insideLoop reports whether block h is an enclosing loop header on
// the current context stack.
func (se *structEmitter) insideLoop(h *ssa.Block) bool {
	for _, fr := range se.ctx {
		if fr.header == h {
			return true
		}
	}
	return false
}

// phiCopies returns the phi edge-assignment statements for the
// pred→succ edge at predIdx.
func (se *structEmitter) phiCopies(pred, succ *ssa.Block, predIdx int) ([]ast.Stmt, bool) {
	tmp := &ast.BlockStmt{}
	if err := emitPhiAssignsFor(tmp, pred, succ, predIdx, se.emitExpr, se.stagedPhi); err != nil {
		return nil, false
	}
	return tmp.List, true
}

// blockValues emits a block's value-computation statements: hoisted
// assignments and side-effecting statements, skipping phis (assigned
// on edges) and the Ret-tail return markers.
func (se *structEmitter) blockValues(blk *ssa.Block) ([]ast.Stmt, error) {
	var out []ast.Stmt
	valuesEnd := len(blk.Values)
	if blk.Kind == ssa.BlockRet {
		valuesEnd -= len(se.f.Sig.Results)
		if valuesEnd < 0 {
			valuesEnd = 0
		}
	}
	for i := 0; i < valuesEnd; i++ {
		v := blk.Values[i]
		if v.Op == ssa.OpPhi {
			continue
		}
		if se.hoist[v.ID] {
			rhs, err := se.em.emitOp(v, se.emitExpr)
			if err != nil {
				return nil, err
			}
			out = append(out, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID(varNameForValue(v))},
				Rhs: []ast.Expr{rhs},
			})
		} else if v.HasSideEffect() {
			stmt, err := se.em.emitSideEffectStmt(v, se.emitExpr)
			if err != nil {
				return nil, err
			}
			out = append(out, stmt)
		}
		out = se.em.maybeMemBaseRefresh(out, v)
	}
	return out, nil
}

// retStmt builds the return statement for a BlockRet.
func (se *structEmitter) retStmt(blk *ssa.Block) (ast.Stmt, error) {
	nRes := len(se.f.Sig.Results)
	if nRes == 0 {
		return &ast.ReturnStmt{}, nil
	}
	if len(blk.Values) < nRes {
		return nil, fmt.Errorf("ssa emit: Ret block has %d values, need %d", len(blk.Values), nRes)
	}
	retVals := blk.Values[len(blk.Values)-nRes:]
	results := make([]ast.Expr, nRes)
	for i, rv := range retVals {
		if rv.Op != ssa.OpCopy {
			return nil, fmt.Errorf("ssa emit: expected OpCopy at Ret tail, got %v", rv.Op)
		}
		e, err := se.emitExpr(rv.Args[0])
		if err != nil {
			return nil, err
		}
		results[i] = e
	}
	return &ast.ReturnStmt{Results: results}, nil
}

// decls emits the function-top `var` declarations for hoisted values
// and parallel-copy staging temps. Every hoisted variable is followed
// by a blank-use read so Go's "declared and not used" check never
// fires when a value's SSA-side users all land in pruned blocks
// (e.g. a phi whose only consumer sits in a panic-terminated branch
// the emitter omits). The blank-use is free at runtime.
func (se *structEmitter) decls() []ast.Stmt {
	var out []ast.Stmt
	for _, id := range sortedValueIDs(se.hoist) {
		v := se.f.Values[id]
		out = append(out, &ast.DeclStmt{Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{newID(varNameForValue(v))},
				Type:  goTypeForSSAType(v.Type),
			}},
		}})
		out = append(out, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID("_")},
			Rhs: []ast.Expr{newID(varNameForValue(v))},
		})
		if v.Op == ssa.OpPhi && se.stagedPhi[v.ID] {
			out = append(out, &ast.DeclStmt{Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{
					Names: []*ast.Ident{newID(phiTempName(v))},
					Type:  goTypeForSSAType(v.Type),
				}},
			}})
			out = append(out, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID("_")},
				Rhs: []ast.Expr{newID(phiTempName(v))},
			})
		}
	}
	return out
}
