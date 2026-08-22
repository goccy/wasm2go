package codegen

import (
	"fmt"
	"go/ast"
	"go/token"
	"math"
	"sort"
	"strconv"

	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/ssa"
)

// ssaEmitter carries the codegen state needed during SSA emission
// (helper registration into translator.helpers, multi-package vs
// single-package qualifier choice, etc).
type ssaEmitter struct {
	// mem64: the module memory uses 64-bit addressing; memory access
	// emission casts addresses to uint64 instead of uint32 and the
	// size/grow/bulk helpers switch to their 64-bit variants.
	mem64 bool
	t     *translator
	// packedPrologue, when set, holds the packed-boundary unpack
	// statements of an outlined function; emitFuncBody prepends them
	// BEFORE scalarization and clears the field.
	packedPrologue []ast.Stmt
	// memBaseHoisted is set (per function) when the function contains
	// wasm memory loads/stores: memBasePtrExpr then resolves to the
	// hoisted `mBase` local instead of the `m.M` field, and the
	// emitters insert `mBase = m.M` refreshes after every value whose
	// evaluation could run memory.grow. See emitFuncBody.
	memBaseHoisted bool

	// catchExcVar is the Go variable holding the *wasmExc currently being
	// handled, set while the structured emitter renders an EH catch handler
	// region so OpCatchArg can read its operand slots. Empty outside a
	// handler.
	catchExcVar string

	// excVarOfRegion maps a try region to the Go variable holding its caught
	// *wasmExc. Handlers nest, so a `rethrow l` can name an OUTER region's
	// exception while an inner handler's catchExcVar is current; throwStmt
	// resolves Block.RethrowRegion through this map. Both emit paths register
	// their per-region variables here (structured: __exc<entryID>; trampoline:
	// __excR<entryID>). Reset per function.
	excVarOfRegion map[*ssa.TryRegion]string

	// simdCalls / simdConsts mark the AST nodes carrying v128 values for
	// the scalarization pass (simd_scalarize.go). Recorded from the SSA
	// types at emission — the pass itself never guesses from names.
	// Reset per function.
	simdCalls  map[*ast.CallExpr]simdCallMark
	simdConsts map[*ast.CompositeLit]bool
}

// simdCallMark records, for one emitted SIMD helper call, which
// argument positions carry a v128 value and whether the result does.
type simdCallMark struct {
	name    string // helper name as emitted (simd_<op>)
	resV128 bool
	mem     bool // OpSimdMemCall: touches linear memory (load/store/lane)
	args    []bool
	// val is the SSA value this call was emitted from. The fusion pass
	// uses it to report each fused window's member/root values back to
	// direct-asm retention, so the asm emitter can splice the same
	// windows straight from the retained SSA (see recordFusedWindow).
	val *ssa.Value
}

// newSSAEmitter constructs an emitter bound to a translator. nil t
// is allowed for unit tests that don't need helper registration.
func newSSAEmitter(t *translator) *ssaEmitter {
	em := &ssaEmitter{t: t}
	if t != nil && t.mod != nil {
		em.mem64 = t.mod.Memory64()
	}
	return em
}

// emitSSAFuncBody converts an ssa.Func into the Go-AST body for one
// translated function.
//
// Strategy (baseline goto/label form; the structured reconstruction in
// emitStructured runs first and is preferred when applicable):
//
//   - Hoist every multiply-referenced value into a `var vN T` declared
//     at function top, assigned where the value is computed. Single-use
//     values are inlined into the user site.
//   - Each block becomes a labeled section. Plain transitions emit a
//     `goto LN`. If blocks emit `if <cond> { goto Lthen } else { goto Lelse }`.
//     Ret blocks emit `return <vals...>`. Unreachable blocks are skipped.
//   - Phis at block entry lower to assignments at the END of each
//     predecessor block, BEFORE the goto / branch. Phi result is the
//     pre-declared variable; argument is the predecessor-specific value.
//
// Returns an error if the function uses an SSA feature this emitter
// can't yet handle; Translate surfaces that as a build failure.
func emitSSAFuncBody(f *ssa.Func) (*ast.BlockStmt, error) {
	return newSSAEmitter(nil).emitFuncBody(f)
}

// emitFuncBody is the method form that accepts a translator pointer.
// Callers pass t so helper registrations (e.g. mload32) propagate to
// the output's import / helper list.
func (em *ssaEmitter) emitFuncBody(f *ssa.Func) (*ast.BlockStmt, error) {
	// The SIMD marks are per-function state for the scalarization pass.
	em.simdCalls = nil
	em.simdConsts = nil
	// Hoist the linear-memory base pointer into a function-level local
	// when the function touches memory at all. `m.M` is a Module FIELD,
	// so the Go compiler must conservatively reload it after every
	// unsafe store (any store may alias the field) and every call; as a
	// LOCAL whose address never escapes, `mBase` stays in a register
	// across stores, and only the sites that can actually run
	// memory.grow — calls and memory.grow itself, the only operations
	// that ever relocate the backing array — re-read it. The refresh
	// statements are inserted by both block emitters right after each
	// such value; see maybeMemBaseRefresh.
	// Shared memories route plain accesses through module-aware helpers
	// (no raw base pointer at the access site), so hoisting mBase would
	// only leave an unused local behind.
	em.memBaseHoisted = funcTouchesMemory(f)

	// EH in multi-package output: the wasmExc type + wasm_catch helper live in
	// the base package (exported as WasmExc / Wasm_catch); the generated body
	// references them cross-package (base.WasmExc, base.Wasm_catch). Wired via
	// wasmExcTypeExpr / helperRef, so no gate here.

	// Prefer structured reconstruction (if/else, straight-line — no
	// goto/label). emitStructured returns ok=false for any CFG shape
	// it cannot cleanly structure (loops, irreducible, ambiguous
	// joins); those fall through to the goto-based emitMultiBlock,
	// which handles every shape and is the proven baseline.
	body, err := func() (*ast.BlockStmt, error) {
		if body, ok := em.emitStructured(f); ok {
			if em.t != nil && em.t.memMetrics != nil {
				em.t.memMetrics.StructuredFuncs++
			}
			return body, nil
		}
		if em.t != nil && em.t.memMetrics != nil {
			em.t.memMetrics.GotoFuncs++
		}
		return em.emitMultiBlock(f)
	}()
	if err != nil {
		return nil, err
	}
	if em.memBaseHoisted {
		decl := &ast.AssignStmt{
			Tok: token.DEFINE,
			Lhs: []ast.Expr{newID(memBaseLocal)},
			Rhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID("M")}},
		}
		// The scalarizer's chases may consume EVERY inline access (a
		// fused loop internalizes whole scale chains), leaving the
		// hoisted base otherwise unused.
		keep := &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID("_")},
			Rhs: []ast.Expr{newID(memBaseLocal)},
		}
		body.List = append([]ast.Stmt{decl, keep}, body.List...)
	}
	// In mutable-locals mode (try functions), declared (non-param) locals are
	// mutable Go vars `lN`, zero-initialised to match wasm's zeroed locals.
	// Params already exist as function arguments `l0..`.
	if f.MutableLocals {
		nParams := len(f.Sig.Params)
		var decls []ast.Stmt
		for i := nParams; i < len(f.LocalTypes); i++ {
			name := fmt.Sprintf("l%d", i)
			decls = append(decls, &ast.DeclStmt{Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{
					Names: []*ast.Ident{newID(name)},
					Type:  goTypeForSSAType(f.LocalTypes[i]),
				}},
			}})
			// Blank-use so a write-only or unused local does not trip Go's
			// "declared and not used" (matches the hoisted-var handling).
			decls = append(decls, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID("_")},
				Rhs: []ast.Expr{newID(name)},
			})
		}
		body.List = append(decls, body.List...)
	}
	// Carry v128 values as scalar pairs so they ride the register ABI —
	// see simd_scalarize.go. Function parameters of v128 type (fallback
	// functions only) stay arrays and are bridged at each use.
	paramsV128 := map[string]bool{}
	if em.packedPrologue == nil {
		for i, p := range f.Sig.Params {
			if p == ssa.TypeV128 {
				paramsV128[fmt.Sprintf("l%d", i)] = true
			}
		}
	} else {
		body.List = append(append([]ast.Stmt{}, em.packedPrologue...), body.List...)
		em.packedPrologue = nil
	}
	em.scalarizeSimd(body, paramsV128)
	return body, nil
}

// memBaseLocal is the name of the per-function hoisted copy of m.M.
// It cannot collide with generated value names (v<N>), parameters
// (l<N>), or phi temps (t<N>_...).
const memBaseLocal = "mBase"

// funcTouchesMemory reports whether f contains any linear-memory load
// or store — the ops whose emission goes through memBasePtrExpr. Any
// such op is force-hoisted (loads) or emitted as its own statement
// (stores), so a true here guarantees the hoisted local is used and a
// false guarantees it is not declared.
func funcTouchesMemory(f *ssa.Func) bool {
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			switch v.Op {
			case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
				ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
				ssa.OpLoadF32, ssa.OpLoadF64,
				ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
				ssa.OpStoreF32, ssa.OpStoreF64:
				return true
			}
		}
	}
	return false
}

// opCanGrowMemory reports whether evaluating v can run memory.grow —
// the ONLY operation that relocates the linear-memory backing array
// and rewrites m.M. Guest calls (direct/indirect) can grow
// transitively; import calls can re-enter the module from host code;
// OpMemGrow is the grow itself. Everything else — loads, stores,
// arithmetic, pure helpers (div/rot/float), memory.size, and the
// memory.copy/fill builtins (which move bytes but never resize) —
// cannot.
func opCanGrowMemory(op ssa.Op) bool {
	switch op {
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpMemGrow:
		return true
	}
	return false
}

// maybeMemBaseRefresh appends `mBase = m.M` to stmts when the just-
// emitted value can have grown (and therefore relocated) the linear
// memory. No-op when the function has no hoisted base.
func (em *ssaEmitter) maybeMemBaseRefresh(stmts []ast.Stmt, v *ssa.Value) []ast.Stmt {
	if !em.memBaseHoisted || !opCanGrowMemory(v.Op) {
		return stmts
	}
	return append(stmts, &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{newID(memBaseLocal)},
		Rhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID("M")}},
	})
}

// emitMultiBlock handles multi-block CFGs using a goto/label form.
//
// Algorithm:
//  1. Walk blocks in reverse-postorder (entry first, then successors
//     before predecessors-of-merge). For simplicity we use block-id
//     order, which matches construction order in lower.go.
//  2. For each value with ≥1 use OR side-effecting OR a phi, declare a
//     `var vN T` hoisted to function top, and assign at definition site
//     (or at predecessor-block-end for phis).
//  3. For each block: emit `L<id>:` followed by a do-nothing statement
//     (Go's `;`), each value's assignment, the phi-assign hooks for
//     each successor's phis where this block is the pred, and the
//     terminator (`goto`, `if/goto/goto`, `return`).
func (em *ssaEmitter) emitMultiBlock(f *ssa.Func) (*ast.BlockStmt, error) {
	if f.Entry == nil {
		return nil, fmt.Errorf("ssa emit: func %s has no entry block", f.Name)
	}
	// EH catch handlers are landing pads entered by unwinding, not by a CFG
	// edge, so they cannot be laid out flat. A function with try regions is
	// emitted as a recover-trampoline (see the len(f.TryRegions) > 0 branch
	// after the value-decl setup below).

	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)

	body := &ast.BlockStmt{}

	// stagedPhi is the subset of phis whose edge-copies need a
	// parallel-copy staging temp (because on some incoming edge a
	// sibling phi's right-hand side reads a phi assigned on that same
	// edge — the classic loop back-edge swap hazard). Phis NOT in this
	// set get a plain direct `vN = rhs` copy with no temp.
	stagedPhi := emit.ComputeStagedPhis(f, hoist)

	// 1. var declarations for every hoisted value. A trailing
	// `_ = vN` is emitted only when the value has no reader at all
	// (genuinely the unreachable-branch corner case) so the common
	// path stays free of that noise — the emitted Go then faithfully
	// mirrors the optimised SSA. Phis that need staging additionally
	// get a `__phiN` temp declared at function scope (declaring it
	// here, not via inline `:=`, keeps it legal across the goto
	// layout).
	for _, id := range sortedValueIDs(hoist) {
		v := f.Values[id]
		body.List = append(body.List, &ast.DeclStmt{Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{newID(varNameForValue(v))},
				Type:  goTypeForSSAType(v.Type),
			}},
		}})
		// Force a blank-use read on every hoisted var. Without it, Go's
		// "declared and not used" check fires for values whose SSA-side
		// users all happen to land in unreachable / pruned blocks
		// (e.g. a phi whose only consumer is in a panic-terminated
		// branch the emitter omits). The blank-use is free at runtime
		// — the Go compiler folds it away — and trades a tiny bit of
		// source noise for a generator that's robust against every
		// post-opt CFG shape.
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID("_")},
			Rhs: []ast.Expr{newID(varNameForValue(v))},
		})
		if v.Op == ssa.OpPhi && stagedPhi[v.ID] {
			body.List = append(body.List, &ast.DeclStmt{Decl: &ast.GenDecl{
				Tok: token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{
					Names: []*ast.Ident{newID(phiTempName(v))},
					Type:  goTypeForSSAType(v.Type),
				}},
			}})
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID("_")},
				Rhs: []ast.Expr{newID(phiTempName(v))},
			})
		}
	}

	// 2. Emit each block.
	// Use a recursive expression-emit helper that returns an
	// expression for any value (inlined sub-expression for non-hoisted,
	// variable reference for hoisted).
	var emitExpr func(v *ssa.Value) (ast.Expr, error)
	emitExpr = func(v *ssa.Value) (ast.Expr, error) {
		if v == nil {
			return nil, fmt.Errorf("ssa emit: nil value")
		}
		if hoist[v.ID] {
			return newID(varNameForValue(v)), nil
		}
		return em.emitOp(v, emitExpr)
	}

	// Precompute the set of blocks that are referenced as goto targets
	// from another block. The entry block is reached by function
	// invocation, not goto, so its label is omitted to avoid Go's
	// "label defined and not used" error.
	gotoTargets := map[ssa.BlockID]bool{}
	for _, blk := range f.Blocks {
		for _, e := range blk.Succs {
			gotoTargets[e.Block.ID] = true
		}
	}

	flatEc := &emitCtx{
		f: f, hoist: hoist, stagedPhi: stagedPhi,
		emitExpr: emitExpr, labelSet: gotoTargets,
	}

	for _, blk := range f.Blocks {
		if err := em.emitBlockInto(blk, &body.List, flatEc); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// emitCtx carries the shared per-function goto-emitter state, plus (when `tramp`
// is set) the recover-trampoline exit protocol used while emitting blocks inside
// the trampoline closure.
type emitCtx struct {
	f         *ssa.Func
	hoist     map[ssa.ValueID]bool
	stagedPhi map[ssa.ValueID]bool
	emitExpr  func(*ssa.Value) (ast.Expr, error)
	labelSet  map[ssa.BlockID]bool // blocks that get a Go label

	tramp *trampCtx
}

// trampCtx is the recover-trampoline protocol (see emitTrampoline): a BlockRet
// records the function return in flags and exits the closure with `return nil`;
// entering a try body sets its __inTryN flag; any edge LEAVING a try's body
// clears it. Exit edges — not just edges to the try's Post — matter: a br out
// of a protected body (a break crossing the try, which is exactly what routes
// a function to the trampoline) must drop the flag, or a later unrelated
// throw would misroute into this try's handler.
type trampCtx struct {
	retVar   string
	rvVars   []string
	entrySet map[ssa.BlockID]string // try-entry block → __inTryN var to set true
	// edgeClears returns the __inTryN vars to clear on the pred→succ edge
	// (the trys whose body contains pred but not succ). Nil outside
	// emitTrampoline.
	edgeClears func(pred, succ ssa.BlockID) []string
}

// edge emits the pred→succ transition: phi edge-copies, the __inTryN clears
// for every try body this edge leaves (trampoline), then the goto.
func (ec *emitCtx) edge(pred, succ *ssa.Block, predIdx int) ([]ast.Stmt, error) {
	tmp := &ast.BlockStmt{}
	if err := emitPhiAssignsFor(tmp, pred, succ, predIdx, ec.emitExpr, ec.stagedPhi); err != nil {
		return nil, err
	}
	out := tmp.List
	if ec.tramp != nil && ec.tramp.edgeClears != nil {
		for _, v := range ec.tramp.edgeClears(pred.ID, succ.ID) {
			out = append(out, assignBool(v, false))
		}
	}
	out = append(out, &ast.BranchStmt{Tok: token.GOTO, Label: newID(labelForBlock(succ))})
	return out, nil
}

// ret emits a BlockRet terminator: a plain `return <vals>` at function level, or
// — in the trampoline — a flag-set + `return nil` so the return escapes the
// closure and is re-issued by the trampoline loop.
func (ec *emitCtx) ret(blk *ssa.Block) ([]ast.Stmt, error) {
	nRes := len(ec.f.Sig.Results)
	results := make([]ast.Expr, nRes)
	if nRes > 0 {
		retVals := blk.Values[len(blk.Values)-nRes:]
		for i, rv := range retVals {
			if rv.Op != ssa.OpCopy {
				return nil, fmt.Errorf("ssa emit: expected OpCopy at Ret tail, got %v", rv.Op)
			}
			e, err := ec.emitExpr(rv.Args[0])
			if err != nil {
				return nil, err
			}
			results[i] = e
		}
	}
	if ec.tramp == nil {
		return []ast.Stmt{&ast.ReturnStmt{Results: results}}, nil
	}
	out := []ast.Stmt{assignBool(ec.tramp.retVar, true)}
	for i := range results {
		out = append(out, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(ec.tramp.rvVars[i])},
			Rhs: []ast.Expr{results[i]},
		})
	}
	out = append(out, &ast.ReturnStmt{Results: []ast.Expr{newID("nil")}})
	return out, nil
}

func assignBool(name string, v bool) ast.Stmt {
	lit := "false"
	if v {
		lit = "true"
	}
	return &ast.AssignStmt{Tok: token.ASSIGN, Lhs: []ast.Expr{newID(name)}, Rhs: []ast.Expr{newID(lit)}}
}

// emitBlockInto emits one block (label, an optional __inTryN set, values,
// terminator) into out. It is the single per-block emission path shared by the
// flat function-level loop and the trampoline closure; ec.tramp selects the exit
// protocol.
func (em *ssaEmitter) emitBlockInto(blk *ssa.Block, out *[]ast.Stmt, ec *emitCtx) error {
	if ec.labelSet[blk.ID] {
		*out = append(*out, &ast.LabeledStmt{
			Label: newID(labelForBlock(blk)),
			Stmt:  &ast.EmptyStmt{Implicit: true},
		})
	}
	if ec.tramp != nil {
		if v := ec.tramp.entrySet[blk.ID]; v != "" {
			*out = append(*out, assignBool(v, true))
		}
	}

	valuesEnd := len(blk.Values)
	if blk.Kind == ssa.BlockRet {
		valuesEnd -= len(ec.f.Sig.Results)
		if valuesEnd < 0 {
			valuesEnd = 0
		}
	}
	for i := 0; i < valuesEnd; i++ {
		v := blk.Values[i]
		if v.Op == ssa.OpPhi {
			continue
		}
		if pre, err := em.callPrelude(v, ec.emitExpr); err != nil {
			return err
		} else if len(pre) > 0 {
			*out = append(*out, pre...)
		}
		if ec.hoist[v.ID] {
			rhs, err := em.emitOp(v, ec.emitExpr)
			if err != nil {
				return err
			}
			*out = append(*out, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID(varNameForValue(v))},
				Rhs: []ast.Expr{rhs},
			})
		} else if v.HasSideEffect() {
			stmt, err := em.emitSideEffectStmt(v, ec.emitExpr)
			if err != nil {
				return err
			}
			*out = append(*out, stmt)
		}
		*out = em.maybeMemBaseRefresh(*out, v)
	}

	switch blk.Kind {
	case ssa.BlockPlain:
		if len(blk.Succs) != 1 {
			return fmt.Errorf("ssa emit: Plain block b%d has %d successors", blk.ID, len(blk.Succs))
		}
		s, err := ec.edge(blk, blk.Succs[0].Block, blk.Succs[0].Index)
		if err != nil {
			return err
		}
		*out = append(*out, s...)
	case ssa.BlockIf:
		if len(blk.Succs) != 2 || blk.Control == nil {
			return fmt.Errorf("ssa emit: malformed If block b%d", blk.ID)
		}
		condExpr, err := em.emitBoolCond(blk.Control, ec.emitExpr)
		if err != nil {
			return err
		}
		thenS, err := ec.edge(blk, blk.Succs[0].Block, blk.Succs[0].Index)
		if err != nil {
			return err
		}
		elseS, err := ec.edge(blk, blk.Succs[1].Block, blk.Succs[1].Index)
		if err != nil {
			return err
		}
		*out = append(*out, &ast.IfStmt{
			Cond: condExpr,
			Body: &ast.BlockStmt{List: thenS},
			Else: &ast.BlockStmt{List: elseS},
		})
	case ssa.BlockBrTable:
		if blk.Control == nil || len(blk.Succs) == 0 || len(blk.TableCases) != len(blk.Succs) {
			return fmt.Errorf("ssa emit: malformed BrTable block b%d", blk.ID)
		}
		selExpr, err := ec.emitExpr(blk.Control)
		if err != nil {
			return err
		}
		swBody := &ast.BlockStmt{}
		for si, e := range blk.Succs {
			arm, err := ec.edge(blk, e.Block, e.Index)
			if err != nil {
				return err
			}
			var caseExprs []ast.Expr
			if si != blk.TableDefault {
				caseExprs = make([]ast.Expr, len(blk.TableCases[si]))
				for ci, cv := range blk.TableCases[si] {
					caseExprs[ci] = &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", cv)}
				}
			}
			swBody.List = append(swBody.List, &ast.CaseClause{List: caseExprs, Body: arm})
		}
		*out = append(*out, &ast.SwitchStmt{Tag: selExpr, Body: swBody})
	case ssa.BlockRet:
		s, err := ec.ret(blk)
		if err != nil {
			return err
		}
		*out = append(*out, s...)
	case ssa.BlockUnreachable:
		*out = append(*out, &ast.ExprStmt{X: &ast.CallExpr{
			Fun: em.helperRef("wasm_trap_unreachable"),
		}})
		*out = append(*out, &ast.ForStmt{Body: &ast.BlockStmt{}})
	case ssa.BlockThrow:
		ts, err := em.throwStmt(blk, ec.emitExpr)
		if err != nil {
			return err
		}
		*out = append(*out, ts)
	default:
		return fmt.Errorf("ssa emit: unknown block kind %v on b%d", blk.Kind, blk.ID)
	}
	return nil
}

// emitPhiAssignsFor appends, at the end of predecessor block `pred`,
// the assignments that move each phi in `succ` to its incoming value
// along the pred→succ edge. predIdx is the position of that edge in
// succ.Preds.
//
// CRITICAL — parallel-copy semantics. SSA phis at a join all take
// effect simultaneously on the edge. A naive sequential lowering
//
//	v5 = v5 + 1      // phi for i
//	v6 = v6 + v5     // phi for acc — wrongly sees the *new* v5
//
// computes acc using the post-increment i. The fix is needed ONLY when
// such a hazard is present. emitMultiBlock pre-computes stagedPhi: the
// phis that genuinely need it. For those, every RHS is evaluated into a
// `__phiN` temp first and the phi vars assigned from the temps. Phis
// not in stagedPhi (the common if/else merge) get a plain, direct
// `vN = rhs` copy — so the emitted Go mirrors the SSA without noise.
func emitPhiAssignsFor(dst *ast.BlockStmt, pred, succ *ssa.Block, predIdx int, emitExpr func(*ssa.Value) (ast.Expr, error), stagedPhi map[ssa.ValueID]bool) error {
	type copyPair struct {
		phi    *ssa.Value
		rhs    ast.Expr
		staged bool
	}
	var copies []copyPair
	for _, v := range succ.Values {
		if v.Op != ssa.OpPhi {
			continue
		}
		if predIdx >= len(v.Args) {
			return fmt.Errorf("ssa emit: phi v%d has %d args, pred index %d", v.ID, len(v.Args), predIdx)
		}
		src := v.Args[predIdx]
		// Skip the trivial self-copy `phi = phi` (a loop-invariant
		// local whose back-edge value is the phi itself).
		if src == v {
			continue
		}
		rhs, err := emitExpr(src)
		if err != nil {
			return err
		}
		copies = append(copies, copyPair{phi: v, rhs: rhs, staged: stagedPhi[v.ID]})
	}
	if len(copies) == 0 {
		return nil
	}
	// Staged phis: RHS → temp first (captures pre-edge values).
	for _, c := range copies {
		if !c.staged {
			continue
		}
		dst.List = append(dst.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(phiTempName(c.phi))},
			Rhs: []ast.Expr{c.rhs},
		})
	}
	// Assign each phi var: from its temp (staged) or directly (not).
	for _, c := range copies {
		rhs := c.rhs
		if c.staged {
			rhs = newID(phiTempName(c.phi))
		}
		dst.List = append(dst.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(varNameForValue(c.phi))},
			Rhs: []ast.Expr{rhs},
		})
	}
	return nil
}

// phiTempName is the staging-temp identifier for a phi's edge copy.
func phiTempName(phi *ssa.Value) string { return fmt.Sprintf("__phi%d", phi.ID) }

// emitBoolCond turns a TypeBool SSA value into a Go boolean expression.
// Bool values are produced only by comparison ops; if v is a comparison
// we inline its operator on the operands.
func (em *ssaEmitter) emitBoolCond(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	switch v.Op {
	case ssa.OpEq32, ssa.OpEq64, ssa.OpNe32, ssa.OpNe64,
		ssa.OpLtS32, ssa.OpLtS64, ssa.OpLeS32, ssa.OpLeS64,
		ssa.OpLtU32, ssa.OpLtU64, ssa.OpLeU32, ssa.OpLeU64:
		lhs, err := emitExpr(v.Args[0])
		if err != nil {
			return nil, err
		}
		rhs, err := emitExpr(v.Args[1])
		if err != nil {
			return nil, err
		}
		tok, _, ok := binarySSAOp(v.Op)
		if !ok {
			return nil, fmt.Errorf("emitBoolCond: no token for %v", v.Op)
		}
		// Unsigned compares route the operands through ui32 / ui64
		// helpers (function-call boundary) so the type-checker
		// doesn't reject constant operands.
		switch v.Op {
		case ssa.OpLtU32, ssa.OpLeU32:
			em.useHelper("ui32")
			lhs = &ast.CallExpr{Fun: em.helperRef("ui32"), Args: []ast.Expr{lhs}}
			rhs = &ast.CallExpr{Fun: em.helperRef("ui32"), Args: []ast.Expr{rhs}}
		case ssa.OpLtU64, ssa.OpLeU64:
			em.useHelper("ui64")
			lhs = &ast.CallExpr{Fun: em.helperRef("ui64"), Args: []ast.Expr{lhs}}
			rhs = &ast.CallExpr{Fun: em.helperRef("ui64"), Args: []ast.Expr{rhs}}
		}
		return &ast.BinaryExpr{X: lhs, Op: tok, Y: rhs}, nil
	}
	// Fallback: compare value's i32 form to 0.
	expr, err := emitExpr(v)
	if err != nil {
		return nil, err
	}
	return &ast.BinaryExpr{X: expr, Op: token.NEQ, Y: intLit(0)}, nil
}

// sortedValueIDs returns the keys of m in ascending order.
func sortedValueIDs(m map[ssa.ValueID]bool) []ssa.ValueID {
	out := make([]ssa.ValueID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func varNameForValue(v *ssa.Value) string { return fmt.Sprintf("v%d", v.ID) }
func labelForBlock(b *ssa.Block) string   { return fmt.Sprintf("L%d", b.ID) }

// throwStmt renders a BlockThrow terminator as `panic(&wasmExc{Tag, Vals})`.
// The `panic` builtin is recognised by Go's termination analysis, so no
// trailing for{} is needed. The thrown operands are the block's last ThrowArgc
// OpCopy markers (mirroring BlockRet), widened to the wasmExc uint64 slots.
func (em *ssaEmitter) throwStmt(blk *ssa.Block, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Stmt, error) {
	if em.t != nil {
		em.t.usesWasmExc = true
	}
	// rethrow: re-raise the exception caught by the handler the rethrow's
	// label resolved to. panic(<caught exc>) — no fresh wasmExc is built.
	// RethrowRegion picks the right exception when handlers nest (`rethrow 1`
	// inside an inner catch re-raises the OUTER try's exception); a nil
	// region falls back to the lexically-current handler variable.
	if blk.IsRethrow {
		excVar := ""
		if blk.RethrowRegion != nil {
			excVar = em.excVarOfRegion[blk.RethrowRegion]
		}
		if excVar == "" {
			excVar = em.catchExcVar
		}
		if excVar == "" {
			return nil, fmt.Errorf("ssa emit: rethrow outside a catch handler")
		}
		return &ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{newID(excVar)}}}, nil
	}
	n := blk.ThrowArgc
	if len(blk.Values) < n {
		return nil, fmt.Errorf("ssa emit: Throw block has %d values, need %d operands", len(blk.Values), n)
	}
	ops := blk.Values[len(blk.Values)-n:]
	vals := make([]ast.Expr, 0, n)
	for _, o := range ops {
		if o.Op != ssa.OpCopy {
			return nil, fmt.Errorf("ssa emit: expected OpCopy at Throw tail, got %v", o.Op)
		}
		e, err := emitExpr(o.Args[0])
		if err != nil {
			return nil, err
		}
		vals = append(vals, em.widenToExcSlot(e, o.Args[0].Type))
	}
	lit := &ast.UnaryExpr{Op: token.AND, X: &ast.CompositeLit{
		Type: em.wasmExcType(),
		Elts: []ast.Expr{
			&ast.KeyValueExpr{Key: newID("Tag"), Value: &ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(blk.TagIndex)}},
			&ast.KeyValueExpr{Key: newID("Vals"), Value: &ast.CompositeLit{
				Type: &ast.ArrayType{Elt: newID("uint64")},
				Elts: vals,
			}},
		},
	}}
	return &ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{lit}}}, nil
}

// narrowExcSlot converts a wasmExc uint64 operand slot back to its wasm type.
func (em *ssaEmitter) narrowExcSlot(slot ast.Expr, t ssa.Type) ast.Expr {
	call := func(fn string, arg ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID(fn), Args: []ast.Expr{arg}}
	}
	switch t {
	case ssa.TypeI64:
		return call("int64", slot)
	case ssa.TypeF32:
		if em.t != nil {
			em.t.UsePackage("math")
		}
		return &ast.CallExpr{
			Fun:  &ast.SelectorExpr{X: newID("math"), Sel: newID("Float32frombits")},
			Args: []ast.Expr{call("uint32", slot)},
		}
	case ssa.TypeF64:
		if em.t != nil {
			em.t.UsePackage("math")
		}
		// The uint64 conversion is required, not cosmetic: OpCatchArg
		// narrows the dispatch's int64-typed snapshot, and
		// Float64frombits does not accept int64.
		return &ast.CallExpr{
			Fun:  &ast.SelectorExpr{X: newID("math"), Sel: newID("Float64frombits")},
			Args: []ast.Expr{call("uint64", slot)},
		}
	default: // i32 / bool
		return call("int32", slot)
	}
}

// widenToExcSlot converts a wasm value expression to the uint64 operand slot
// used by wasmExc (the inverse of narrowExcSlot).
func (em *ssaEmitter) widenToExcSlot(expr ast.Expr, t ssa.Type) ast.Expr {
	u64 := func(arg ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{arg}}
	}
	switch t {
	case ssa.TypeI64:
		return u64(expr)
	case ssa.TypeF32:
		if em.t != nil {
			em.t.UsePackage("math")
		}
		return u64(&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{
			&ast.CallExpr{Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float32bits")}, Args: []ast.Expr{expr}},
		}})
	case ssa.TypeF64:
		if em.t != nil {
			em.t.UsePackage("math")
		}
		return &ast.CallExpr{Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float64bits")}, Args: []ast.Expr{expr}}
	default: // i32 / bool: zero-extend the 32-bit value
		return u64(&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{expr}})
	}
}

func goTypeForSSAType(t ssa.Type) ast.Expr {
	switch t {
	case ssa.TypeI32:
		return newID("int32")
	case ssa.TypeI64:
		return newID("int64")
	case ssa.TypeF32:
		return newID("float32")
	case ssa.TypeF64:
		return newID("float64")
	case ssa.TypeBool:
		// Bool values are stored as i32(0/1) when hoisted (matches
		// wasm comparison result semantics).
		return newID("int32")
	case ssa.TypeV128:
		// v128 lanes, little-endian: [0] = lanes 0-7, [1] = lanes 8-15.
		return &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")}
	}
	return newID("int32")
}

// emitOp lowers a single SSA value to a Go expression. Pure values
// lower inline; OpCopy folds to its argument. Memory ops call the
// generated helper functions (mload32, mstore32, ...) and register
// them with the translator's helper set so they're emitted in the
// output file's helper section.
func (em *ssaEmitter) emitOp(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	switch v.Op {
	case ssa.OpParam:
		return newID(fmt.Sprintf("l%d", v.AuxInt)), nil
	case ssa.OpConst32:
		return goConstI32(int32(v.AuxInt)), nil
	case ssa.OpConst64:
		return goConstI64(v.AuxInt), nil
	case ssa.OpTrunc64To32:
		// wasm i32.wrap_i64 semantics: low 32 bits.
		a, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{
			&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{
				&ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{a}}}}}}, nil
	case ssa.OpExtend32To64U:
		a, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{
			&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{a}}}}, nil
	case ssa.OpConstF32:
		f := math.Float32frombits(uint32(v.AuxInt))
		if floatNeedsBitsEmission(float64(f)) && em.t != nil {
			em.t.UsePackage("math")
		}
		return goConstF32(f), nil
	case ssa.OpConstF64:
		f := math.Float64frombits(uint64(v.AuxInt))
		if floatNeedsBitsEmission(f) && em.t != nil {
			em.t.UsePackage("math")
		}
		return goConstF64(f), nil
	case ssa.OpCopy:
		return emit(v.Args[0])
	case ssa.OpPhi:
		return newID(varNameForValue(v)), nil
	case ssa.OpLocalGet:
		// Mutable-locals mode: read the local variable `lN` (params and
		// declared locals share the same naming).
		return newID(fmt.Sprintf("l%d", v.AuxInt)), nil
	case ssa.OpCatchArg:
		// The i-th operand of the exception this handler caught: a copy of
		// the value the dispatch snapshotted, narrowed to the operand type.
		if len(v.Args) != 1 {
			return nil, fmt.Errorf("ssa emit: OpCatchArg without its saved slot")
		}
		slot, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return em.narrowExcSlot(slot, v.Type), nil
	}
	switch v.Op {
	case ssa.OpGlobalGet:
		return em.fieldRef(fmt.Sprintf("g%d", v.AuxInt)), nil
	case ssa.OpCallDirect:
		return em.emitCallDirect(v, emit)
	case ssa.OpCallImport:
		return em.emitCallImport(v, emit)
	case ssa.OpCallIndirect:
		return em.emitCallIndirect(v, emit)
	case ssa.OpHelperCall:
		return em.emitHelperCall(v, emit)
	case ssa.OpAtomicCall:
		// Module-aware helper: helper(m, args...). The helpers live with
		// memoryCopy et al and go through useHelper/helperRef.
		name, ok := v.Aux.(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("ssa emit: OpAtomicCall without name aux")
		}
		// Full-width aligned loads/stores skip the helper chain and
		// emit sync/atomic intrinsics directly; see emit_memops.go.
		if expr, done, err := em.emitAtomicInline(v, name, emit); err != nil {
			return nil, err
		} else if done {
			return expr, nil
		}
		em.useHelper(name)
		args := []ast.Expr{newID("m")}
		for _, a := range v.Args {
			e, err := emit(a)
			if err != nil {
				return nil, err
			}
			args = append(args, e)
		}
		return &ast.CallExpr{Fun: em.helperRef(name), Args: args}, nil
	case ssa.OpExcPending:
		return em.fieldRef("excPending"), nil
	case ssa.OpExcTag:
		return &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{em.fieldRef("excTag")}}, nil
	case ssa.OpExcVal:
		slot := &ast.IndexExpr{X: em.fieldRef("excVals"), Index: intLit(v.AuxInt)}
		return em.narrowExcSlot(slot, v.Type), nil
	case ssa.OpSimdConst:
		lanes, ok := v.Aux.([2]uint64)
		if !ok {
			return nil, fmt.Errorf("ssa emit: OpSimdConst without [2]uint64 aux")
		}
		lit := &ast.CompositeLit{
			Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
			Elts: []ast.Expr{
				&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("0x%x", lanes[0])},
				&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("0x%x", lanes[1])},
			},
		}
		em.markSimdConst(lit)
		return lit, nil
	case ssa.OpSimdCall:
		// Pure SIMD helper: helper(args...).
		name, ok := v.Aux.(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("ssa emit: OpSimdCall without name aux")
		}
		em.useHelper(name)
		var args []ast.Expr
		for _, a := range v.Args {
			e, err := emit(a)
			if err != nil {
				return nil, err
			}
			args = append(args, e)
		}
		call := &ast.CallExpr{Fun: em.helperRef(name), Args: args}
		em.markSimdCall(call, name, v, 0)
		return call, nil
	case ssa.OpSimdMemCall:
		// Module-aware SIMD memory helper: helper(m, args...).
		name, ok := v.Aux.(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("ssa emit: OpSimdMemCall without name aux")
		}
		em.useHelper(name)
		args := []ast.Expr{newID("m")}
		for _, a := range v.Args {
			e, err := emit(a)
			if err != nil {
				return nil, err
			}
			args = append(args, e)
		}
		call := &ast.CallExpr{Fun: em.helperRef(name), Args: args}
		em.markSimdCall(call, name, v, 1)
		return call, nil
	case ssa.OpMemSize:
		name := "memorySize"
		if em.mem64 {
			name = "memorySize64"
		}
		em.useHelper(name)
		return &ast.CallExpr{Fun: em.helperRef(name), Args: []ast.Expr{newID("m")}}, nil
	case ssa.OpMemGrow:
		name := "memoryGrow"
		if em.mem64 {
			name = "memoryGrow64"
		}
		em.useHelper(name)
		delta, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.CallExpr{Fun: em.helperRef(name), Args: []ast.Expr{newID("m"), delta}}, nil
	}
	// Inline memory loads: emit the unsafe deref expression directly
	// rather than calling a helper. See emit_memops.go for the per-
	// function PC-budget rationale. Both structured and goto-form
	// paths reach here through emitOp, so the inline form is uniform
	// across the whole transpiler output.
	if _, ok := loadSpec(v); ok {
		return em.emitMemLoadExpr(v, emit)
	}
	if tok, mode, ok := binarySSAOp(v.Op); ok {
		lhs, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		rhs, err := emit(v.Args[1])
		if err != nil {
			return nil, err
		}
		if mode&(1<<4) != 0 { // unsigned compare; register the helper.
			helper := "ui32"
			if v.Args[0].Type == ssa.TypeI64 {
				helper = "ui64"
			}
			em.useHelper(helper)
			return em.wrapBinaryUnsignedCmp(lhs, rhs, tok, v, helper), nil
		}
		if v.Op == ssa.OpShrU32 || v.Op == ssa.OpShrU64 {
			return em.emitShrU(lhs, rhs, v), nil
		}
		return em.wrapBinary(mode, lhs, rhs, tok, v), nil
	}
	return nil, fmt.Errorf("ssa emit: unsupported op %v", v.Op)
}

// emitSideEffectStmt dispatches a side-effecting SSA value to its
// statement form: inline memory store, global assignment, or call
// statement.
func (em *ssaEmitter) emitSideEffectStmt(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Stmt, error) {
	if _, ok := storeSpec(v); ok {
		// Inline store, one-liner: `*(*T)(unsafe.Add(...)) = T(vN)`.
		// emit.ComputeHoist guarantees narrowing-store values are hoisted
		// so the cast is always runtime-safe. See emit_memops.go.
		return em.emitMemStoreStmt(v, emit)
	}
	switch v.Op {
	case ssa.OpLocalSet:
		// Mutable-locals mode: assign the local variable `lN = <value>`.
		rhs, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(fmt.Sprintf("l%d", v.AuxInt))},
			Rhs: []ast.Expr{rhs},
		}, nil
	case ssa.OpGlobalSet:
		return em.emitGlobalSetStmt(v, emit)
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect:
		expr, err := em.emitOp(v, emit)
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: expr}, nil
	case ssa.OpUnreachable:
		// Same out-of-line trap shape as BlockUnreachable above.
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun: em.helperRef("wasm_trap_unreachable"),
		}}, nil
	case ssa.OpMemGrow:
		// memory.grow value typically discarded; still emit as expr stmt.
		expr, err := em.emitOp(v, emit)
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: expr}, nil
	case ssa.OpMemoryCopy:
		helperName := "memoryCopy"
		if em.mem64 {
			helperName = "memoryCopy64"
		}
		em.useHelper(helperName)
		dst, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		src, err := emit(v.Args[1])
		if err != nil {
			return nil, err
		}
		n, err := emit(v.Args[2])
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  em.helperRef(helperName),
			Args: []ast.Expr{newID("m"), dst, src, n},
		}}, nil
	case ssa.OpMemoryFill:
		helperName := "memoryFill"
		if em.mem64 {
			helperName = "memoryFill64"
		}
		em.useHelper(helperName)
		dst, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		val, err := emit(v.Args[1])
		if err != nil {
			return nil, err
		}
		n, err := emit(v.Args[2])
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  em.helperRef(helperName),
			Args: []ast.Expr{newID("m"), dst, val, n},
		}}, nil
	case ssa.OpMemoryInit:
		initName := "memoryInit"
		if em.mem64 {
			initName = "memoryInit64"
		}
		em.useHelper(initName)
		dst, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		src, err := emit(v.Args[1])
		if err != nil {
			return nil, err
		}
		n, err := emit(v.Args[2])
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  em.helperRef(initName),
			Args: []ast.Expr{newID("m"), intLit(v.AuxInt), dst, src, n},
		}}, nil
	case ssa.OpExcRaise:
		// Store tag and operands, then set the flag. The block branches to
		// a handler or to a propagating return right after.
		if len(v.Args) == 0 {
			return nil, fmt.Errorf("ssa emit: OpExcRaise without a tag arg")
		}
		tagExpr, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		stmts := []ast.Stmt{&ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{em.fieldRef("excTag")},
			Rhs: []ast.Expr{&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{tagExpr}}},
		}}
		for i, a := range v.Args[1:] {
			e, err := emit(a)
			if err != nil {
				return nil, err
			}
			stmts = append(stmts, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{&ast.IndexExpr{X: em.fieldRef("excVals"), Index: intLit(int64(i))}},
				Rhs: []ast.Expr{em.widenToExcSlot(e, a.Type)},
			})
		}
		stmts = append(stmts, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{em.fieldRef("excPending")},
			Rhs: []ast.Expr{intLit(1)},
		})
		return &ast.BlockStmt{List: stmts}, nil
	case ssa.OpExcRearm:
		return &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{em.fieldRef("excPending")},
			Rhs: []ast.Expr{intLit(1)},
		}, nil
	case ssa.OpExcClear:
		return &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{em.fieldRef("excPending")},
			Rhs: []ast.Expr{intLit(0)},
		}, nil
	case ssa.OpDataDrop:
		em.useHelper("dataDrop")
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  em.helperRef("dataDrop"),
			Args: []ast.Expr{newID("m"), intLit(v.AuxInt)},
		}}, nil
	}
	expr, err := em.emitOp(v, emit)
	if err != nil {
		return nil, err
	}
	return &ast.ExprStmt{X: expr}, nil
}

// emitGlobalSetStmt handles OpGlobalSet as a statement (assigns to
// `m.gN`).
func (em *ssaEmitter) emitGlobalSetStmt(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Stmt, error) {
	val, err := emit(v.Args[0])
	if err != nil {
		return nil, err
	}
	return &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{em.fieldRef(fmt.Sprintf("g%d", v.AuxInt))},
		Rhs: []ast.Expr{val},
	}, nil
}

// fieldRef returns the AST expression `m.<field>` honoring single- vs
// multi-package field capitalisation.
func (em *ssaEmitter) fieldRef(field string) ast.Expr {
	if em.t != nil {
		return em.t.fieldRef(field)
	}
	return &ast.SelectorExpr{X: newID("m"), Sel: newID(field)}
}

// emitCallDirect produces a call expression `Fn<N>(m, args...)` for a
// direct call to a defined wasm function.
func (em *ssaEmitter) emitCallDirect(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	// A synthetic callee (an outlined loop) with a packed boundary
	// reads its arguments from the per-module scratch slots that
	// callPrelude filled right before this statement; the call itself
	// carries only the module pointer.
	synthName, _ := v.Aux.(string)
	if synthName != "" && em.t != nil && em.t.outlinedSigs[synthName].Packed {
		return &ast.CallExpr{Fun: newID(synthName), Args: []ast.Expr{newID("m")}}, nil
	}
	args := []ast.Expr{newID("m")}
	for _, a := range v.Args {
		ae, err := emit(a)
		if err != nil {
			return nil, err
		}
		args = append(args, ae)
	}
	var fun ast.Expr
	if synthName != "" {
		// Same package, called by name; AuxInt carries no function
		// index then.
		fun = newID(synthName)
	} else if em.t != nil {
		fun = em.t.funcRef(uint32(v.AuxInt))
	} else {
		fun = newID(fmt.Sprintf("Fn%d", v.AuxInt))
	}
	return &ast.CallExpr{Fun: fun, Args: args}, nil
}

// callPrelude returns the statements a value's emission must be
// preceded by: a packed outlined call fills the per-module scratch
// slots with its boundary values here, immediately before the call
// statement, so nothing can overwrite them in between.
func (em *ssaEmitter) callPrelude(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) ([]ast.Stmt, error) {
	if v.Op != ssa.OpCallDirect || em.t == nil {
		return nil, nil
	}
	name, _ := v.Aux.(string)
	if name == "" || !em.t.outlinedSigs[name].Packed {
		return nil, nil
	}
	var fills []ast.Stmt
	slot := 0
	for _, a := range v.Args {
		ae, err := emit(a)
		if err != nil {
			return nil, err
		}
		if a.Type == ssa.TypeV128 {
			for half := 0; half < 2; half++ {
				fills = append(fills, &ast.AssignStmt{
					Tok: token.ASSIGN,
					Lhs: []ast.Expr{em.t.packSlot(slot)},
					Rhs: []ast.Expr{&ast.IndexExpr{X: ae, Index: &ast.BasicLit{
						Kind: token.INT, Value: strconv.Itoa(half)}}},
				})
				slot++
			}
			continue
		}
		fills = append(fills, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{em.t.packSlot(slot)},
			Rhs: []ast.Expr{em.t.packSlotWrite(ae, a.Type)},
		})
		slot++
	}
	return fills, nil
}

// emitCallImport produces `m.<modField>.<MethodName>(m, args...)` for
// a wasm import call.
func (em *ssaEmitter) emitCallImport(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	if em.t == nil {
		return nil, fmt.Errorf("ssa emit: CallImport needs translator binding")
	}
	imp := em.t.Module().Imports[v.AuxInt]
	// wasi-threads: thread-spawn is not a host call at all — a wasm thread is
	// a goroutine, so it lowers to the threadSpawn helper, which starts the
	// guest's own wasi_thread_start on one. Keeping it out of the host
	// interface means an embedder gets threads without implementing anything.
	if imp.Module == "wasi" && imp.Name == "thread-spawn" ||
		imp.Module == "wasi_snapshot_preview1" && imp.Name == "thread_spawn" {
		// On a memory64 module the start_arg is an i64 linear-memory
		// pointer, so the spawn routes to the i64-arg helper twin (which
		// reads the threadStart64 field the mem64 Module struct declares).
		helper := "threadSpawn"
		if em.mem64 {
			helper = "threadSpawn_m64"
		}
		em.useHelper(helper)
		args := []ast.Expr{newID("m")}
		for _, a := range v.Args {
			ae, err := emit(a)
			if err != nil {
				return nil, err
			}
			args = append(args, ae)
		}
		return &ast.CallExpr{Fun: em.helperRef(helper), Args: args}, nil
	}
	args := []ast.Expr{newID("m")}
	for _, a := range v.Args {
		ae, err := emit(a)
		if err != nil {
			return nil, err
		}
		args = append(args, ae)
	}
	return &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X: &ast.SelectorExpr{
				X:   newID("m"),
				Sel: newID(em.t.FieldName(MangleModuleField(imp.Module))),
			},
			Sel: newID(em.t.ImportMethodName(imp)),
		},
		Args: args,
	}, nil
}

// emitCallIndirect produces a call via table dispatch:
//
//	table[idx].(func(*Module, args...) ret)(m, args...)
func (em *ssaEmitter) emitCallIndirect(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	if em.t == nil {
		return nil, fmt.Errorf("ssa emit: CallIndirect needs translator binding")
	}
	// args[0] = table index, args[1..] = call params
	tableIdx, err := emit(v.Args[0])
	if err != nil {
		return nil, err
	}
	ft := em.t.Module().Types[v.AuxInt]
	// Construct typed function type for the assertion.
	fnType := em.t.funcSignatureUnnamed(ft, true)
	// Default to table 0 — multi-table modules will need a future
	// AuxInt extension carrying the table index.
	tableField := em.t.fieldRef("t0")
	indexed := &ast.IndexExpr{X: tableField, Index: tableIdx}
	asserted := &ast.TypeAssertExpr{X: indexed, Type: fnType}
	args := []ast.Expr{newID("m")}
	for _, a := range v.Args[1:] {
		ae, err := emit(a)
		if err != nil {
			return nil, err
		}
		args = append(args, ae)
	}
	return &ast.CallExpr{Fun: asserted, Args: args}, nil
}

// useHelper registers a helper name with the translator (if bound) so
// the helper's source is included in the output's helpers section.
// nil translator (unit tests) silently no-ops.
func (em *ssaEmitter) useHelper(name string) {
	if em.t == nil {
		return
	}
	em.t.UseHelper(name)
}

// useImport registers a Go import package with the translator (if
// bound). nil translator (unit tests) silently no-ops.
func (em *ssaEmitter) useImport(pkg string) {
	if em.t == nil {
		return
	}
	em.t.UsePackage(pkg)
}

// helperRef returns the AST expression naming the helper, qualified for
// multi-package mode (base.Mload32) or bare for single-package mode.
// Falls back to bare identifier when translator is nil (tests).
func (em *ssaEmitter) helperRef(name string) ast.Expr {
	if em.t == nil {
		return newID(name)
	}
	return em.t.helperRef(name)
}

// wasmExcType returns the type-name expression for the wasmExc exception struct,
// qualified for the current package in multi-package mode (base.WasmExc).
func (em *ssaEmitter) wasmExcType() ast.Expr {
	if em.t == nil {
		return newID("wasmExc")
	}
	return em.t.wasmExcTypeExpr()
}

func goConstI32(n int32) ast.Expr {
	return &ast.CallExpr{
		Fun:  newID("int32"),
		Args: []ast.Expr{intLitSigned(int64(n))},
	}
}

func goConstI64(n int64) ast.Expr {
	return &ast.CallExpr{
		Fun:  newID("int64"),
		Args: []ast.Expr{intLitSigned(n)},
	}
}

// goConstF32 renders an f32 constant. Finite values are emitted as
// float32(<lit>); NaN/Inf/-0 bits go through math.Float32frombits because
// Go has no literal for them (`float32(-0)` is +0).
func goConstF32(v float32) ast.Expr {
	bits := math.Float32bits(v)
	if floatNeedsBitsEmission(float64(v)) {
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float32frombits")},
			Args: []ast.Expr{
				&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{
					&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("0x%08x", bits)},
				}},
			},
		}
	}
	return &ast.CallExpr{
		Fun: newID("float32"),
		Args: []ast.Expr{
			&ast.BasicLit{Kind: token.FLOAT, Value: strconv.FormatFloat(float64(v), 'g', -1, 32)},
		},
	}
}

// goConstF64 renders an f64 constant. Same NaN/Inf/-0 consideration as
// goConstF32.
func goConstF64(v float64) ast.Expr {
	bits := math.Float64bits(v)
	if floatNeedsBitsEmission(v) {
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{X: newID("math"), Sel: newID("Float64frombits")},
			Args: []ast.Expr{
				&ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{
					&ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("0x%016x", bits)},
				}},
			},
		}
	}
	return &ast.CallExpr{
		Fun: newID("float64"),
		Args: []ast.Expr{
			&ast.BasicLit{Kind: token.FLOAT, Value: strconv.FormatFloat(v, 'g', -1, 64)},
		},
	}
}

// emitHelperCall renders an OpHelperCall as `helper(args...)`. The
// helper name lives in v.Aux; arguments are emitted in order. The
// helper is registered with the translator so its source is included.
func (em *ssaEmitter) emitHelperCall(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	name, ok := v.Aux.(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("ssa emit: OpHelperCall without name aux")
	}
	em.useHelper(name)
	args := make([]ast.Expr, len(v.Args))
	for i, a := range v.Args {
		e, err := emit(a)
		if err != nil {
			return nil, err
		}
		args[i] = e
	}
	return &ast.CallExpr{Fun: em.helperRef(name), Args: args}, nil
}

// intLitSigned renders a signed integer literal AST node. Negative
// values are wrapped in a unary-minus on the positive magnitude so the
// resulting Go constant lifecycle (untyped int → cast) preserves
// correctness in contexts like `uint32(int32(-N))` — a bare
// `&ast.BasicLit{Kind: INT, Value: "-N"}` is treated by the
// type-checker as the unsigned representation directly and fails to
// fit narrower types.
func intLitSigned(n int64) ast.Expr {
	if n >= 0 {
		return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(n, 10)}
	}
	// math.MinInt64 cannot be negated within int64 range. Express it
	// as `-9223372036854775807 - 1` so the parse tree stays valid Go.
	if n == -1<<63 {
		return &ast.BinaryExpr{
			X:  &ast.UnaryExpr{Op: token.SUB, X: &ast.BasicLit{Kind: token.INT, Value: "9223372036854775807"}},
			Op: token.SUB,
			Y:  &ast.BasicLit{Kind: token.INT, Value: "1"},
		}
	}
	return &ast.UnaryExpr{
		Op: token.SUB,
		X:  &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(-n, 10)},
	}
}

// binaryMode tells wrapBinary how to bridge wasm semantics to Go.
type binaryMode int

const (
	binaryDirect binaryMode = iota
	binaryUnsigned
	binaryShift
	binaryBoolCmp
)

func binarySSAOp(op ssa.Op) (token.Token, binaryMode, bool) {
	switch op {
	case ssa.OpAdd32, ssa.OpAdd64:
		return token.ADD, binaryDirect, true
	case ssa.OpSub32, ssa.OpSub64:
		return token.SUB, binaryDirect, true
	case ssa.OpMul32, ssa.OpMul64:
		return token.MUL, binaryDirect, true
	case ssa.OpAnd32, ssa.OpAnd64:
		return token.AND, binaryDirect, true
	case ssa.OpOr32, ssa.OpOr64:
		return token.OR, binaryDirect, true
	case ssa.OpXor32, ssa.OpXor64:
		return token.XOR, binaryDirect, true
	case ssa.OpShl32, ssa.OpShl64, ssa.OpShrS32, ssa.OpShrS64:
		return tokenShift(op), binaryShift, true
	case ssa.OpShrU32, ssa.OpShrU64:
		return token.SHR, binaryShift, true
	case ssa.OpEq32, ssa.OpEq64:
		return token.EQL, binaryBoolCmp, true
	case ssa.OpNe32, ssa.OpNe64:
		return token.NEQ, binaryBoolCmp, true
	case ssa.OpLtS32, ssa.OpLtS64:
		return token.LSS, binaryBoolCmp, true
	case ssa.OpLeS32, ssa.OpLeS64:
		return token.LEQ, binaryBoolCmp, true
	case ssa.OpLtU32, ssa.OpLtU64:
		return token.LSS, binaryBoolCmp | binaryMode(1<<4), true
	case ssa.OpLeU32, ssa.OpLeU64:
		return token.LEQ, binaryBoolCmp | binaryMode(1<<4), true
	}
	return token.ILLEGAL, 0, false
}

// emitShrU renders an unsigned shift-right (i32.shr_u / i64.shr_u) as
// `int32(ui32(lhs) >> (uint(rhs) % width))` (or the i64 analogue). The
// `ui32`/`ui64` helper boundary is required to avoid Go's "typed
// constant overflows" check on negative i32 literals — the bare
// `uint32(int32(-1))` form is rejected by the type-checker.
func (em *ssaEmitter) emitShrU(lhs, rhs ast.Expr, v *ssa.Value) ast.Expr {
	width := int64(32)
	helper := "ui32"
	castOut := "int32"
	if v.Type == ssa.TypeI64 {
		width = 64
		helper, castOut = "ui64", "int64"
	}
	em.useHelper(helper)
	amt := &ast.BinaryExpr{
		X:  &ast.CallExpr{Fun: newID("uint"), Args: []ast.Expr{rhs}},
		Op: token.REM,
		Y:  &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(width, 10)},
	}
	ul := &ast.CallExpr{Fun: em.helperRef(helper), Args: []ast.Expr{lhs}}
	shifted := &ast.BinaryExpr{X: ul, Op: token.SHR, Y: amt}
	return &ast.CallExpr{Fun: newID(castOut), Args: []ast.Expr{shifted}}
}

func tokenShift(op ssa.Op) token.Token {
	switch op {
	case ssa.OpShl32, ssa.OpShl64:
		return token.SHL
	case ssa.OpShrS32, ssa.OpShrS64:
		return token.SHR
	case ssa.OpShrU32, ssa.OpShrU64:
		return token.SHR
	}
	return token.ILLEGAL
}

func (em *ssaEmitter) wrapBinary(mode binaryMode, lhs, rhs ast.Expr, tok token.Token, v *ssa.Value) ast.Expr {
	isUnsigned := mode&(1<<4) != 0
	pureMode := mode &^ binaryMode(1<<4)
	switch pureMode {
	case binaryDirect:
		return &ast.BinaryExpr{X: lhs, Op: tok, Y: rhs}
	case binaryShift:
		var width int64 = 32
		if v.Type == ssa.TypeI64 {
			width = 64
		}
		amt := &ast.BinaryExpr{
			X:  &ast.CallExpr{Fun: newID("uint"), Args: []ast.Expr{rhs}},
			Op: token.REM,
			Y:  &ast.BasicLit{Kind: token.INT, Value: strconv.FormatInt(width, 10)},
		}
		return &ast.BinaryExpr{X: lhs, Op: tok, Y: amt}
	case binaryBoolCmp:
		var compared ast.Expr
		if isUnsigned {
			// Use the helper functions ui32 / ui64 (function-call
			// boundary) rather than the bare uint32 / uint64 type
			// conversion, so Go's constant-folding doesn't reject
			// constants like int32(-N) that don't fit uint32 as a
			// typed-constant conversion.
			helper := "ui32"
			if v.Args[0].Type == ssa.TypeI64 {
				helper = "ui64"
			}
			compared = &ast.BinaryExpr{
				X:  &ast.CallExpr{Fun: newID(helper), Args: []ast.Expr{lhs}},
				Op: tok,
				Y:  &ast.CallExpr{Fun: newID(helper), Args: []ast.Expr{rhs}},
			}
		} else {
			compared = &ast.BinaryExpr{X: lhs, Op: tok, Y: rhs}
		}
		return em.boolToI32(compared)
	}
	return &ast.BinaryExpr{X: lhs, Op: tok, Y: rhs}
}

// wrapBinaryUnsignedCmp builds an unsigned-compare binary expression
// using the named helper (ui32 or ui64) for the operand casts. The
// helper goes through em.helperRef so it qualifies correctly in
// multi-package mode (base.Ui32).
func (em *ssaEmitter) wrapBinaryUnsignedCmp(lhs, rhs ast.Expr, tok token.Token, v *ssa.Value, helper string) ast.Expr {
	hl := em.helperRef(helper)
	hr := em.helperRef(helper)
	compared := &ast.BinaryExpr{
		X:  &ast.CallExpr{Fun: hl, Args: []ast.Expr{lhs}},
		Op: tok,
		Y:  &ast.CallExpr{Fun: hr, Args: []ast.Expr{rhs}},
	}
	return em.boolToI32(compared)
}

// boolToI32 turns a Go bool expression into the wasm i32 (0 or 1) a comparison
// leaves on the stack, via the b2i32 helper. It must not emit a func literal:
// see b2i32's comment in helpers/helpers.go for why an inline IIFE breaks the
// gcasm backend on large functions.
func (em *ssaEmitter) boolToI32(cond ast.Expr) ast.Expr {
	em.useHelper("b2i32")
	return &ast.CallExpr{Fun: em.helperRef("b2i32"), Args: []ast.Expr{cond}}
}

var _ = binaryUnsigned // not yet used; reserved for future ops

// markSimdCall records a SIMD helper call's v128 positions for the
// scalarization pass. skip counts synthetic leading args (the Module
// receiver of a memory helper) that are never v128.
func (em *ssaEmitter) markSimdCall(call *ast.CallExpr, name string, v *ssa.Value, skip int) {
	if em.simdCalls == nil {
		em.simdCalls = map[*ast.CallExpr]simdCallMark{}
	}
	mark := simdCallMark{name: name, resV128: v.Type == ssa.TypeV128, mem: skip == 1, args: make([]bool, skip+len(v.Args)), val: v}
	for i, a := range v.Args {
		mark.args[skip+i] = a.Type == ssa.TypeV128
	}
	em.simdCalls[call] = mark
}

// markSimdConst records a v128 constant literal for the scalarization pass.
func (em *ssaEmitter) markSimdConst(lit *ast.CompositeLit) {
	if em.simdConsts == nil {
		em.simdConsts = map[*ast.CompositeLit]bool{}
	}
	em.simdConsts[lit] = true
}
