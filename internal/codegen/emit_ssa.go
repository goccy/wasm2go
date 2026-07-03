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
	t *translator
	// memBaseHoisted is set (per function) when the function contains
	// wasm memory loads/stores: memBasePtrExpr then resolves to the
	// hoisted `mBase` local instead of the `m.M` field, and the
	// emitters insert `mBase = m.M` refreshes after every value whose
	// evaluation could run memory.grow. See emitFuncBody.
	memBaseHoisted bool
}

// newSSAEmitter constructs an emitter bound to a translator. nil t
// is allowed for unit tests that don't need helper registration.
func newSSAEmitter(t *translator) *ssaEmitter { return &ssaEmitter{t: t} }

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
	em.memBaseHoisted = funcTouchesMemory(f)

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
		body.List = append([]ast.Stmt{decl}, body.List...)
	}
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

	for _, blk := range f.Blocks {
		// Emit a label only when the block is a goto target. Entry
		// block (and any other un-referenced block, which shouldn't
		// normally exist) is just an inline starting point.
		if gotoTargets[blk.ID] {
			body.List = append(body.List, &ast.LabeledStmt{
				Label: newID(labelForBlock(blk)),
				Stmt:  &ast.EmptyStmt{Implicit: true},
			})
		}

		// Values defined in this block (excluding the trailing OpCopy
		// markers for Ret blocks — those are handled in the terminator).
		valuesEnd := len(blk.Values)
		if blk.Kind == ssa.BlockRet {
			valuesEnd -= len(f.Sig.Results)
			if valuesEnd < 0 {
				valuesEnd = 0
			}
		}
		for i := 0; i < valuesEnd; i++ {
			v := blk.Values[i]
			// Phis are assigned by the predecessor block, not here.
			if v.Op == ssa.OpPhi {
				continue
			}
			if hoist[v.ID] {
				rhs, err := em.emitOp(v, emitExpr)
				if err != nil {
					return nil, err
				}
				body.List = append(body.List, &ast.AssignStmt{
					Tok: token.ASSIGN,
					Lhs: []ast.Expr{newID(varNameForValue(v))},
					Rhs: []ast.Expr{rhs},
				})
			} else if v.HasSideEffect() {
				stmt, err := em.emitSideEffectStmt(v, emitExpr)
				if err != nil {
					return nil, err
				}
				body.List = append(body.List, stmt)
			}
			// Non-hoisted pure values are folded into uses; no
			// statement here.
			body.List = em.maybeMemBaseRefresh(body.List, v)
		}

		// 3. Terminator.
		switch blk.Kind {
		case ssa.BlockPlain:
			if len(blk.Succs) != 1 {
				return nil, fmt.Errorf("ssa emit: Plain block b%d has %d successors", blk.ID, len(blk.Succs))
			}
			succ := blk.Succs[0].Block
			predIdx := blk.Succs[0].Index
			if err := emitPhiAssignsFor(body, blk, succ, predIdx, emitExpr, stagedPhi); err != nil {
				return nil, err
			}
			body.List = append(body.List, &ast.BranchStmt{
				Tok:   token.GOTO,
				Label: newID(labelForBlock(succ)),
			})
		case ssa.BlockIf:
			if len(blk.Succs) != 2 || blk.Control == nil {
				return nil, fmt.Errorf("ssa emit: malformed If block b%d", blk.ID)
			}
			thenBlk := blk.Succs[0].Block
			elseBlk := blk.Succs[1].Block
			thenPredIdx := blk.Succs[0].Index
			elsePredIdx := blk.Succs[1].Index

			// Build the cond expression. SSA stores it as a Bool
			// value; bring it down to a Go bool expression.
			condExpr, err := em.emitBoolCond(blk.Control, emitExpr)
			if err != nil {
				return nil, err
			}
			// Then branch: emit phi assigns for thenBlk, then goto.
			thenBody := &ast.BlockStmt{}
			if err := emitPhiAssignsFor(thenBody, blk, thenBlk, thenPredIdx, emitExpr, stagedPhi); err != nil {
				return nil, err
			}
			thenBody.List = append(thenBody.List, &ast.BranchStmt{
				Tok:   token.GOTO,
				Label: newID(labelForBlock(thenBlk)),
			})
			// Else branch: emit phi assigns then goto.
			elseBody := &ast.BlockStmt{}
			if err := emitPhiAssignsFor(elseBody, blk, elseBlk, elsePredIdx, emitExpr, stagedPhi); err != nil {
				return nil, err
			}
			elseBody.List = append(elseBody.List, &ast.BranchStmt{
				Tok:   token.GOTO,
				Label: newID(labelForBlock(elseBlk)),
			})
			body.List = append(body.List, &ast.IfStmt{
				Cond: condExpr,
				Body: thenBody,
				Else: elseBody,
			})
		case ssa.BlockBrTable:
			if blk.Control == nil || len(blk.Succs) == 0 || len(blk.TableCases) != len(blk.Succs) {
				return nil, fmt.Errorf("ssa emit: malformed BrTable block b%d", blk.ID)
			}
			selExpr, err := emitExpr(blk.Control)
			if err != nil {
				return nil, err
			}
			// One switch STATEMENT, not an if-chain: the Go compiler
			// lowers dense integer switches to jump tables (O(1)
			// dispatch) but never recovers a switch from a cascade of
			// ifs. Each clause carries the per-edge phi assigns and a
			// goto, exactly like an If arm. The default clause also
			// absorbs any TableCases values routed to the same block
			// as the wasm default label — they need no explicit case
			// literals because default reaches the same target.
			swBody := &ast.BlockStmt{}
			for si, e := range blk.Succs {
				clauseBody := &ast.BlockStmt{}
				if err := emitPhiAssignsFor(clauseBody, blk, e.Block, e.Index, emitExpr, stagedPhi); err != nil {
					return nil, err
				}
				clauseBody.List = append(clauseBody.List, &ast.BranchStmt{
					Tok:   token.GOTO,
					Label: newID(labelForBlock(e.Block)),
				})
				var caseExprs []ast.Expr
				if si != blk.TableDefault {
					caseExprs = make([]ast.Expr, len(blk.TableCases[si]))
					for ci, cv := range blk.TableCases[si] {
						caseExprs[ci] = &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", cv)}
					}
				}
				swBody.List = append(swBody.List, &ast.CaseClause{
					List: caseExprs, // nil = default
					Body: clauseBody.List,
				})
			}
			body.List = append(body.List, &ast.SwitchStmt{Tag: selExpr, Body: swBody})
		case ssa.BlockRet:
			nRes := len(f.Sig.Results)
			if nRes == 0 {
				body.List = append(body.List, &ast.ReturnStmt{})
				break
			}
			retVals := blk.Values[len(blk.Values)-nRes:]
			results := make([]ast.Expr, nRes)
			for i, rv := range retVals {
				if rv.Op != ssa.OpCopy {
					return nil, fmt.Errorf("ssa emit: expected OpCopy at Ret tail, got %v", rv.Op)
				}
				e, err := emitExpr(rv.Args[0])
				if err != nil {
					return nil, err
				}
				results[i] = e
			}
			body.List = append(body.List, &ast.ReturnStmt{Results: results})
		case ssa.BlockUnreachable:
			body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
				Fun:  newID("panic"),
				Args: []ast.Expr{stringLit("wasm: unreachable")},
			}})
		default:
			return nil, fmt.Errorf("ssa emit: unknown block kind %v on b%d", blk.Kind, blk.ID)
		}
	}
	return body, nil
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
	case ssa.OpConstF32:
		f := math.Float32frombits(uint32(v.AuxInt))
		if (math.IsNaN(float64(f)) || math.IsInf(float64(f), 0)) && em.t != nil {
			em.t.UsePackage("math")
		}
		return goConstF32(f), nil
	case ssa.OpConstF64:
		f := math.Float64frombits(uint64(v.AuxInt))
		if (math.IsNaN(f) || math.IsInf(f, 0)) && em.t != nil {
			em.t.UsePackage("math")
		}
		return goConstF64(f), nil
	case ssa.OpCopy:
		return emit(v.Args[0])
	case ssa.OpPhi:
		return newID(varNameForValue(v)), nil
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
	case ssa.OpMemSize:
		em.useHelper("memorySize")
		return &ast.CallExpr{Fun: em.helperRef("memorySize"), Args: []ast.Expr{newID("m")}}, nil
	case ssa.OpMemGrow:
		em.useHelper("memoryGrow")
		delta, err := emit(v.Args[0])
		if err != nil {
			return nil, err
		}
		return &ast.CallExpr{Fun: em.helperRef("memoryGrow"), Args: []ast.Expr{newID("m"), delta}}, nil
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
		return wrapBinary(mode, lhs, rhs, tok, v), nil
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
	case ssa.OpGlobalSet:
		return em.emitGlobalSetStmt(v, emit)
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect:
		expr, err := em.emitOp(v, emit)
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: expr}, nil
	case ssa.OpUnreachable:
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  newID("panic"),
			Args: []ast.Expr{stringLit("wasm: unreachable")},
		}}, nil
	case ssa.OpMemGrow:
		// memory.grow value typically discarded; still emit as expr stmt.
		expr, err := em.emitOp(v, emit)
		if err != nil {
			return nil, err
		}
		return &ast.ExprStmt{X: expr}, nil
	case ssa.OpMemoryCopy:
		em.useHelper("memoryCopy")
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
			Fun:  em.helperRef("memoryCopy"),
			Args: []ast.Expr{newID("m"), dst, src, n},
		}}, nil
	case ssa.OpMemoryFill:
		em.useHelper("memoryFill")
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
			Fun:  em.helperRef("memoryFill"),
			Args: []ast.Expr{newID("m"), dst, val, n},
		}}, nil
	case ssa.OpMemoryInit, ssa.OpDataDrop:
		// Bulk-memory data-segment ops are not yet implemented; the
		// generator emits a panic-stub so any caller hitting this at
		// runtime fails loudly rather than silently producing wrong
		// behaviour.
		return &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  newID("panic"),
			Args: []ast.Expr{stringLit(fmt.Sprintf("wasm2go: %v not implemented", v.Op))},
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
	args := []ast.Expr{newID("m")}
	for _, a := range v.Args {
		ae, err := emit(a)
		if err != nil {
			return nil, err
		}
		args = append(args, ae)
	}
	var fun ast.Expr
	if em.t != nil {
		fun = em.t.funcRef(uint32(v.AuxInt))
	} else {
		fun = newID(fmt.Sprintf("Fn%d", v.AuxInt))
	}
	return &ast.CallExpr{Fun: fun, Args: args}, nil
}

// emitCallImport produces `m.<modField>.<MethodName>(m, args...)` for
// a wasm import call.
func (em *ssaEmitter) emitCallImport(v *ssa.Value, emit func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	if em.t == nil {
		return nil, fmt.Errorf("ssa emit: CallImport needs translator binding")
	}
	imp := em.t.Module().Imports[v.AuxInt]
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
// float32(<lit>); NaN/Inf bits go through math.Float32frombits because
// Go has no NaN/Inf literal.
func goConstF32(v float32) ast.Expr {
	bits := math.Float32bits(v)
	if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
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

// goConstF64 renders an f64 constant. Same NaN/Inf consideration as goConstF32.
func goConstF64(v float64) ast.Expr {
	bits := math.Float64bits(v)
	if math.IsNaN(v) || math.IsInf(v, 0) {
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

func wrapBinary(mode binaryMode, lhs, rhs ast.Expr, tok token.Token, v *ssa.Value) ast.Expr {
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
		return boolToI32(compared)
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
	return boolToI32(compared)
}

func boolToI32(cond ast.Expr) ast.Expr {
	return &ast.CallExpr{
		Fun: &ast.FuncLit{
			Type: &ast.FuncType{
				Params:  &ast.FieldList{},
				Results: &ast.FieldList{List: []*ast.Field{{Type: newID("int32")}}},
			},
			Body: &ast.BlockStmt{List: []ast.Stmt{
				&ast.IfStmt{
					Cond: cond,
					Body: &ast.BlockStmt{List: []ast.Stmt{
						&ast.ReturnStmt{Results: []ast.Expr{intLit(1)}},
					}},
				},
				&ast.ReturnStmt{Results: []ast.Expr{intLit(0)}},
			}},
		},
	}
}

var _ = binaryUnsigned // not yet used; reserved for future ops
