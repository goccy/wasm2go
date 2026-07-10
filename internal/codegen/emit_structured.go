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
// Supported shapes: straight-line, if/else, br_table (as a Go switch), and
// nested natural loops each with a single exit. Shared forward joins whose
// convergence point is not a clean post-dominator are handled by bounded block
// duplication (see the re-entry path in region). Multi-exit loops and
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
	// switchDepth is se.switchDepth as it stood when the loop was opened. A
	// `break` emitted while se.switchDepth is deeper than this sits lexically
	// inside a `switch` that the loop does not contain, so a bare `break` would
	// leave the switch and fall to the bottom of the loop body instead of
	// exiting the loop. Such a break must name the loop.
	switchDepth int
	// label is the loop's Go label, assigned lazily by jump() the first time a
	// break needs to name it. Empty means the `for` is emitted unlabelled —
	// which it must be, because Go rejects a label that nothing uses.
	//
	// The name comes from a per-function counter, not from the header block's
	// ID: region() duplicates a shared forward join into each path that reaches
	// it, so one loop header can be emitted more than once in a function, and
	// two `for`s carrying the same label do not compile.
	label string
	// tryDepth is se.inTryDepth as it stood when the loop was opened. A
	// break/continue emitted while se.inTryDepth is deeper than this would have
	// to jump out of an EH try-region closure (emitTryRegion wraps the protected
	// body in a `func() *wasmExc { ... }()`), but Go labels are function-scoped
	// and `break`/`continue` cannot cross a func literal — so such a jump bails
	// to the goto emitter instead (see jump()).
	tryDepth int
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
	// switchDepth counts the `switch` statements currently open around the
	// emission point — one per br_table, one per exception dispatch. Go's
	// `break` binds to the innermost for/switch/select, so a loop-exit break
	// emitted at a deeper switch depth than its loop has to be labelled.
	switchDepth int
	// labelSeq names those labels. It is per function and monotonic, so a loop
	// emitted twice (block duplication) gets two distinct labels.
	labelSeq int
	// emitted guards against emitting a block twice.
	emitted map[ssa.BlockID]bool
	// tryOpened marks try-region entry blocks already wrapped, so the
	// recursive region() call for the protected body does not re-trigger the
	// try wrapper on its own entry block.
	tryOpened map[ssa.BlockID]bool
	// emitCount counts block emissions; dupCap bounds duplication of shared
	// forward-join blocks (see the re-entry handling in region). Exceeding it
	// aborts structured emission (fall back to the goto emitter) rather than
	// risk an exponential blow-up on a pathological CFG.
	emitCount int
	dupCap    int
	// inTryDepth is >0 while emitting the protected BODY of a try region into
	// its `func() *wasmExc { ... }` closure. A function-level BlockRet cannot be
	// rendered as a plain `return <vals>` there — the closure returns *wasmExc,
	// so `return v` (an i32/…) is a type error, and the real return must escape
	// the closure. The structured emitter has no escape protocol, so a Ret
	// reached at depth>0 bails to the recover-trampoline emitter, which threads
	// returns out of try bodies via return flags.
	inTryDepth int
	// depth tracks the current region() nesting (one level per if/else arm,
	// loop body, or try body). nestCap bounds it: a CFG whose structured form
	// would nest deeper — e.g. a long chain of non-reconverging conditionals,
	// as clang emits for some CPython dispatch — aborts structured emission and
	// falls back to the flat goto emitter. Go's own go/parser (and the protobuf
	// protogen post-parse the plugin runs) cap identifier resolution at
	// maxScopeDepth=1000; emitting past that produces source no downstream tool
	// can re-parse. The cap sits well under 1000 to leave headroom for the extra
	// scopes gofmt/blocks introduce per level.
	depth   int
	nestCap int
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
		loops:     analyzeLoops(f),
		emitted:   map[ssa.BlockID]bool{},
		tryOpened: map[ssa.BlockID]bool{},
		dupCap:    8*len(f.Blocks) + 64,
		nestCap:   200,
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

// ehVirtualPreds returns, per EH catch-handler block, the protected-body blocks
// that reach it via the (non-CFG) exceptional edge. A `throw` anywhere in a try
// body unwinds to the handler, so for loop analysis the handler is reachable
// from every block of its protected region. Without this, an exception-resume
// loop (the shape clang emits for setjmp/longjmp — the catch handler branches
// back to the loop header) has its body mis-computed to just {header, handler}.
func ehVirtualPreds(f *ssa.Func) map[ssa.BlockID][]*ssa.Block {
	if len(f.TryRegions) == 0 {
		return nil
	}
	byID := map[ssa.BlockID]*ssa.Block{}
	for _, b := range f.Blocks {
		byID[b.ID] = b
	}
	out := map[ssa.BlockID][]*ssa.Block{}
	for _, tr := range f.TryRegions {
		// Protected body = forward-reachable from Entry, not crossing Post or
		// any handler block.
		stop := map[ssa.BlockID]bool{}
		if tr.Post != nil {
			stop[tr.Post.ID] = true
		}
		for _, h := range tr.Handlers {
			if h.Block != nil {
				stop[h.Block.ID] = true
			}
		}
		body := map[ssa.BlockID]bool{}
		var work []*ssa.Block
		if tr.Entry != nil {
			work = append(work, tr.Entry)
		}
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			if b == nil || body[b.ID] || stop[b.ID] {
				continue
			}
			body[b.ID] = true
			for _, e := range b.Succs {
				work = append(work, e.Block)
			}
		}
		var bodyBlocks []*ssa.Block
		for id := range body {
			bodyBlocks = append(bodyBlocks, byID[id])
		}
		for _, h := range tr.Handlers {
			if h.Block != nil {
				out[h.Block.ID] = append(out[h.Block.ID], bodyBlocks...)
			}
		}
	}
	return out
}

// blocksReachingRet returns the set of blocks that can reach a BlockRet by
// following CFG successors. A loop exit to a block NOT in this set is a
// trap/throw dead-end (BlockUnreachable / BlockThrow), not a real structured
// exit, so exit analysis ignores it.
func blocksReachingRet(f *ssa.Func) map[ssa.BlockID]bool {
	reach := map[ssa.BlockID]bool{}
	changed := true
	for changed {
		changed = false
		for _, b := range f.Blocks {
			if reach[b.ID] {
				continue
			}
			if b.Kind == ssa.BlockRet {
				reach[b.ID] = true
				changed = true
				continue
			}
			for _, e := range b.Succs {
				if reach[e.Block.ID] {
					reach[b.ID] = true
					changed = true
					break
				}
			}
		}
	}
	return reach
}

// analyzeLoops computes the natural loop for every loop header.
func analyzeLoops(f *ssa.Func) map[ssa.BlockID]*loopInfo {
	loops := map[ssa.BlockID]*loopInfo{}
	vpreds := ehVirtualPreds(f)
	reachRet := blocksReachingRet(f)
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
			// Exceptional edge: a catch handler is reachable from its
			// protected body, so those body blocks are loop-body preds too.
			work = append(work, vpreds[b.ID]...)
		}
	}
	// Exit analysis: the blocks outside the body that body blocks branch to.
	// Exactly one ⇒ a clean `for {}` + follow; zero ⇒ the loop is left only via
	// return; more than one ⇒ unstructurable. A successor that cannot reach a
	// Ret is a trap/throw dead-end (BlockUnreachable / BlockThrow), not a
	// structured exit — it is emitted inline where it is branched to, so it
	// does not count toward the exit set.
	for _, li := range loops {
		exits := map[ssa.BlockID]*ssa.Block{}
		for id := range li.body {
			b := blockByID(f, id)
			for _, se := range b.Succs {
				if li.body[se.Block.ID] {
					continue
				}
				if !reachRet[se.Block.ID] {
					continue // trap/throw dead-end, not a real exit
				}
				exits[se.Block.ID] = se.Block
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
// tryRegionAt returns the TryRegion whose protected body starts at b, or nil.
func (se *structEmitter) tryRegionAt(b *ssa.Block) *ssa.TryRegion {
	for _, tr := range se.f.TryRegions {
		if tr.Entry == b {
			return tr
		}
	}
	return nil
}

// emitTryRegion renders one EH try/catch region:
//
//	__excN := func() (c *wasmExc) {
//	    defer func() { c = wasm_catch(recover()) }()
//	    <body region — assigns the post phi var on normal fall-through>
//	    return nil
//	}()
//	if __excN != nil {
//	    switch {
//	    case __excN.Tag == <tag0>: <handler0 region>
//	    ...
//	    default: <catch_all region>   // or: panic(__excN)
//	    }
//	}
//
// Function-scope locals (`lN`) and the hoisted post-phi var are captured by the
// closure by reference, so a local written in the body before a throw is
// observed at its throw-time value in the handler (wasm EH semantics).
func (se *structEmitter) emitTryRegion(tr *ssa.TryRegion) ([]ast.Stmt, bool) {
	if se.em.t != nil {
		se.em.t.usesWasmExc = true
		se.em.useHelper("wasm_catch")
	}
	excVar := fmt.Sprintf("__exc%d", tr.Entry.ID)

	// Body region, emitted inside the closure. A function return reached inside
	// the body cannot be represented in the *wasmExc closure (see inTryDepth);
	// region() bails when it hits one, routing the whole function to the
	// trampoline.
	se.inTryDepth++
	bodyStmts, ok := se.region(tr.Entry, tr.Post)
	se.inTryDepth--
	if !ok {
		return nil, false
	}
	deferStmt := &ast.DeferStmt{Call: &ast.CallExpr{Fun: &ast.FuncLit{
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID("c")},
				Rhs: []ast.Expr{&ast.CallExpr{
					Fun:  se.em.helperRef("wasm_catch"),
					Args: []ast.Expr{&ast.CallExpr{Fun: newID("recover")}},
				}},
			},
		}},
	}}}
	closureBody := append([]ast.Stmt{deferStmt}, bodyStmts...)
	closureBody = append(closureBody, &ast.ReturnStmt{Results: []ast.Expr{newID("nil")}})
	closure := &ast.FuncLit{
		Type: &ast.FuncType{
			Params: &ast.FieldList{},
			Results: &ast.FieldList{List: []*ast.Field{{
				Names: []*ast.Ident{newID("c")},
				Type:  &ast.StarExpr{X: se.em.wasmExcType()},
			}}},
		},
		Body: &ast.BlockStmt{List: closureBody},
	}
	out := []ast.Stmt{&ast.AssignStmt{
		Tok: token.DEFINE,
		Lhs: []ast.Expr{newID(excVar)},
		Rhs: []ast.Expr{&ast.CallExpr{Fun: closure}},
	}}

	// Dispatch a caught exception to its handler.
	var clauses []ast.Stmt
	hasCatchAll := false
	// Handler bodies land inside the dispatch switch below, so a loop-exit break
	// in one of them must name its loop (see jump).
	se.switchDepth++
	defer func() { se.switchDepth-- }()
	for _, h := range tr.Handlers {
		se.em.catchExcVar = excVar
		hStmts, ok := se.region(h.Block, tr.Post)
		se.em.catchExcVar = ""
		if !ok {
			return nil, false
		}
		if h.CatchAll {
			hasCatchAll = true
			clauses = append(clauses, &ast.CaseClause{Body: hStmts})
			continue
		}
		cond := &ast.BinaryExpr{
			X:  &ast.SelectorExpr{X: newID(excVar), Sel: newID("Tag")},
			Op: token.EQL,
			Y:  &ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(h.TagIndex)},
		}
		clauses = append(clauses, &ast.CaseClause{List: []ast.Expr{cond}, Body: hStmts})
	}
	if !hasCatchAll {
		// No catch_all: an unmatched exception propagates to the enclosing
		// handler (or out of the function).
		clauses = append(clauses, &ast.CaseClause{Body: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{newID(excVar)}}},
		}})
	}
	out = append(out, &ast.IfStmt{
		Cond: &ast.BinaryExpr{X: newID(excVar), Op: token.NEQ, Y: newID("nil")},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.SwitchStmt{Body: &ast.BlockStmt{List: clauses}},
		}},
	})
	return out, true
}

func (se *structEmitter) region(b, stop *ssa.Block) ([]ast.Stmt, bool) {
	// Bound structured nesting: past nestCap levels, abort to the goto emitter,
	// whose output is flat (labels + goto) and so never trips the go/parser /
	// protogen maxScopeDepth=1000 re-parse limit.
	se.depth++
	defer func() { se.depth-- }()
	if se.depth > se.nestCap {
		return nil, false
	}
	var out []ast.Stmt
	for b != nil && b != stop {
		// EH try region: emit the protected body in a closure with
		// defer/recover, then dispatch a caught wasmExc to its handler, then
		// continue after the try at Post.
		if tr := se.tryRegionAt(b); tr != nil && !se.tryOpened[b.ID] {
			se.tryOpened[b.ID] = true
			stmts, ok := se.emitTryRegion(tr)
			if !ok {
				return nil, false
			}
			out = append(out, stmts...)
			// Continue after the try at Post only when Post is a live join
			// (the body / a handler falls through to it, having already
			// emitted its phi edge-copies). If every path through the try
			// throws, branches away (a setjmp-resume loop), or returns, Post
			// has no preds (was pruned) — nothing follows the try.
			if tr.Post != nil && len(tr.Post.Preds) > 0 {
				b = tr.Post
			} else {
				b = nil
			}
			continue
		}
		// Open a `for {}` when b heads a loop we are not already in.
		if li := se.loops[b.ID]; li != nil && !se.insideLoop(b) {
			se.ctx = append(se.ctx, loopFrame{header: b, follow: li.follow, switchDepth: se.switchDepth, tryDepth: se.inTryDepth})
			forBody, ok := se.region(b, nil)
			// Read the frame back before popping: jump() names the loop lazily,
			// from arbitrarily deep inside the body it just emitted.
			label := se.ctx[len(se.ctx)-1].label
			se.ctx = se.ctx[:len(se.ctx)-1]
			if !ok {
				return nil, false
			}
			var loop ast.Stmt = &ast.ForStmt{Body: &ast.BlockStmt{List: forBody}}
			if label != "" {
				loop = &ast.LabeledStmt{Label: newID(label), Stmt: loop}
			}
			out = append(out, loop)
			b = li.follow
			continue
		}
		// A block re-entered here is a shared FORWARD join: two branches (e.g.
		// arms of a br_table whose targets do not reconverge at its post-
		// dominator) both flow through it. Loops are already lifted out (the
		// for{} + jump machinery turns back-edges into continue/break), so the
		// residual CFG walked here is a DAG — duplicating the block into each
		// path is correct (each path executes its own copy exactly once) and
		// terminates. dupCap bounds the total emission so a pathological CFG
		// that would duplicate exponentially aborts to the goto emitter instead.
		se.emitted[b.ID] = true
		se.emitCount++
		if se.emitCount > se.dupCap {
			return nil, false
		}

		vs, err := se.blockValues(b)
		if err != nil {
			return nil, false
		}
		out = append(out, vs...)

		switch b.Kind {
		case ssa.BlockRet:
			// A function return inside a try body cannot be a plain return in
			// the *wasmExc closure — bail to the trampoline (see inTryDepth).
			if se.inTryDepth > 0 {
				return nil, false
			}
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
		case ssa.BlockThrow:
			ts, err := se.em.throwStmt(b, se.emitExpr)
			if err != nil {
				return nil, false
			}
			out = append(out, ts)
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
		case ssa.BlockBrTable:
			// N-way branch: the structured analogue of BlockIf. Each unique
			// target becomes a Go switch clause carrying that edge's phi copies
			// and the sub-region up to the common post-dominator join (via
			// se.branch, exactly like an If arm — so a target that is an
			// enclosing loop's header/follow lowers to continue/break, and a
			// shared forward join is duplicated per arm). The wasm default
			// label's target is the `default:` clause.
			if len(b.Succs) == 0 || b.Control == nil || len(b.TableCases) != len(b.Succs) {
				return nil, false
			}
			join := se.postdom[b.ID]
			sel, err := se.emitExpr(b.Control)
			if err != nil {
				return nil, false
			}
			// The arms are emitted inside the switch, so a loop-exit break in one
			// of them must name its loop (see jump).
			se.switchDepth++
			swBody := &ast.BlockStmt{}
			for si, e := range b.Succs {
				arm, ok := se.branch(b, e.Block, e.Index, join)
				if !ok {
					se.switchDepth--
					return nil, false
				}
				var caseExprs []ast.Expr
				if si != b.TableDefault {
					caseExprs = make([]ast.Expr, len(b.TableCases[si]))
					for ci, cv := range b.TableCases[si] {
						caseExprs[ci] = &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", cv)}
					}
				}
				swBody.List = append(swBody.List, &ast.CaseClause{List: caseExprs, Body: arm})
			}
			se.switchDepth--
			out = append(out, &ast.SwitchStmt{Tag: sel, Body: swBody})
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
// continue/break; a jump to an outer loop returns ok=false so the
// whole function falls back to the goto emitter (labelled loops are a
// follow-up).
//
// A break is labelled when the emission point is inside a `switch` the loop
// does not contain. Go binds a bare `break` to the innermost for/switch/select,
// so a bare break under a br_table's switch would leave only the switch and
// then fall to the bottom of the loop body — silently turning the loop's exit
// into a back-edge. The induction variable is updated on the OTHER arm, so what
// results is not a slow loop but a stuck one. `continue` needs no label: it
// binds to the innermost for regardless of any switch in between.
func (se *structEmitter) jump(target *ssa.Block) ([]ast.Stmt, bool) {
	if len(se.ctx) == 0 {
		return nil, false
	}
	inner := &se.ctx[len(se.ctx)-1]
	// The jump target is a loop opened outside the try-region closure we are
	// currently emitting into. A `break`/`continue` — even a labelled one —
	// cannot leave the `func() *wasmExc { ... }()` the try body lives in, so
	// abort structured emission and let the goto emitter (which threads control
	// out of try bodies via return flags, not lexical break) handle this
	// function. Mirrors the BlockRet-inside-try bail in region().
	if se.inTryDepth > inner.tryDepth {
		return nil, false
	}
	if target == inner.header {
		return []ast.Stmt{&ast.BranchStmt{Tok: token.CONTINUE}}, true
	}
	if inner.follow != nil && target == inner.follow {
		br := &ast.BranchStmt{Tok: token.BREAK}
		if se.switchDepth > inner.switchDepth {
			if inner.label == "" {
				se.labelSeq++
				inner.label = fmt.Sprintf("wl%d", se.labelSeq)
			}
			br.Label = newID(inner.label)
		}
		return []ast.Stmt{br}, true
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
