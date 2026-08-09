package codegen

// v128 scalarization.
//
// The emitter's natural lowering of a v128 value is a [2]uint64 — and Go's
// ABI stack-assigns arrays, unconditionally. Every SIMD op then reads its
// operands from stack slots and writes its result back to one, so vector
// code runs at the speed of the stack, not of the register file. A wasm
// JIT never pays this: its v128 values live in vector registers.
//
// This pass rewrites one emitted function body so each v128 value is TWO
// uint64 locals (v7 → v7, v7__h). Scalars ride Go's register ABI, so the
// values stay in registers, spills disappear, and the gcasm splice
// receives its operands in GPRs instead of memory. Helper calls switch to
// their scalar-pair forms (simd_<op> → simd_p_<op>), which take and
// return the halves directly.
//
// The pass is driven entirely by structure: the emitter marks every
// SIMD call and v128 literal it produces (simdCalls / simdConsts, typed
// from the SSA), and variables become PAIR CANDIDATES only by provable
// data flow from those marks — a declaration with the [2]uint64 type, or
// an assignment whose RHS is already known to carry a v128. A variable
// with any use the pass does not recognize is dropped from the candidate
// set, and expressions that stay in array form are bridged exactly where
// they meet pair form: indexed (arr[0], arr[1]) going in, packed
// (simd_p_pack) coming out. Correctness never depends on a variable
// being scalarized.

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// pairName returns the identifier of the high half of a scalarized
// variable; the low half keeps the original name.
func pairName(name string) string { return name + "__h" }

type simdScalarizer struct {
	em *ssaEmitter
	// identCount is the per-name count of SEMANTIC uses in the whole
	// function body: identifiers inside declarations and blank-use
	// assignments do not count. Window fusion uses it to prove a
	// variable is consumed entirely inside a window (LHS write plus
	// in-window reads account for every occurrence), making it
	// internal — no root slot, no assignment, only its declaration's
	// blank use keeping it legal.
	identCount map[string]int
	// readCount counts semantic READ occurrences (assignment left-hand
	// identifiers excluded); carryLoopReads counts, per name, the
	// reads that sit inside a for-statement whose body also WRITES the
	// name (each read attributed once, innermost qualifying loop).
	// A name every read of which lives inside such self-carrying loops
	// cannot observe a fused loop's eliminated per-iteration state
	// from outside: the pair drives clone-tolerant carry escape
	// checks in the loop fuser.
	readCount      map[string]int
	carryLoopReads map[string]int
	// constBind maps single-assignment locals to their constant int32
	// value — the emitter CSEs multi-use constants (memarg offsets
	// above all) into locals, and window fusion resolves them back to
	// immediates so they cost no argument register. Sound because SSA
	// lowering guarantees def-before-use on every path and the one
	// static assignment always stores the same literal.
	constBind map[string]int32
	// pairs is the candidate set: variables carried as two uint64s.
	pairs map[string]bool
	// arrays are v128-typed variables that must STAY arrays (function
	// parameters, and any candidate that lost eligibility).
	arrays map[string]bool
	// tmp numbers hoisted nested-call temporaries. The temporaries are
	// declared at function top and ASSIGNED at their hoist site: a
	// `:=` there would be jumped over by the goto-emitter's labels,
	// which Go forbids.
	tmp        int
	hoistPairs []string // pair temps (__svN)
	hoistArrs  []string // array temps (__saN)
}

// scalarizeSimd rewrites body in place. Functions with v128 PARAMETERS
// are skipped entirely: those are the fallback functions (v128 in a
// wasm signature routes the whole function to the pure fallback), their
// parameters arrive boxed as `any`, and nothing about them is
// performance-relevant.
func (em *ssaEmitter) scalarizeSimd(body *ast.BlockStmt, paramsV128 map[string]bool) {
	if len(em.simdCalls) == 0 && len(em.simdConsts) == 0 {
		return
	}
	if len(paramsV128) > 0 {
		return
	}
	sc := &simdScalarizer{em: em, pairs: map[string]bool{}, arrays: map[string]bool{}}
	sc.identCount = countSemanticIdents(body)
	sc.readCount, sc.carryLoopReads = countCarryLoopReads(body)
	sc.constBind = collectConstBindings(body, em.mem64)
	sc.collect(body)
	sc.audit(body)
	body.List = sc.rewriteStmts(body.List)
	// Hoisted temporaries are declared once at function top (see the
	// tmp field for why), with a blank use so a temp on a path the
	// compiler proves unreachable does not trip "declared and not used".
	var decls []ast.Stmt
	if len(sc.hoistPairs) > 0 {
		var blanks, refs []ast.Expr
		var idents []*ast.Ident
		for _, n := range sc.hoistPairs {
			idents = append(idents, newID(n), newID(pairName(n)))
			blanks = append(blanks, newID("_"), newID("_"))
			refs = append(refs, newID(n), newID(pairName(n)))
		}
		decls = append(decls, &ast.DeclStmt{Decl: &ast.GenDecl{
			Tok:   token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{Names: idents, Type: newID("uint64")}},
		}}, &ast.AssignStmt{Tok: token.ASSIGN, Lhs: blanks, Rhs: refs})
	}
	for _, n := range sc.hoistArrs {
		decls = append(decls, &ast.DeclStmt{Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{newID(n)},
				Type:  &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
			}},
		}}, &ast.AssignStmt{Tok: token.ASSIGN, Lhs: []ast.Expr{newID("_")}, Rhs: []ast.Expr{newID(n)}})
	}
	if len(decls) > 0 {
		body.List = append(decls, body.List...)
	}
}

// countSemanticIdents counts identifier uses that carry meaning:
// declaration name lists and blank-use assignments (`_ = v`, emitted
// solely to keep declared-but-conditionally-unused locals legal) are
// excluded on both sides.
func countSemanticIdents(body *ast.BlockStmt) map[string]int {
	counts := map[string]int{}
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for _, v := range x.Values {
				walk(v)
			}
			return
		case *ast.AssignStmt:
			allBlank := true
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
					allBlank = false
				}
			}
			if allBlank {
				return
			}
		case *ast.Ident:
			if x.Name != "_" {
				counts[x.Name]++
			}
			return
		}
		if n != nil {
			ast.Inspect(n, func(c ast.Node) bool {
				if c == n {
					return true
				}
				walk(c)
				return false
			})
		}
	}
	walk(body)
	return counts
}

// countCarryLoopReads returns (readCount, carryLoopReads): semantic
// read occurrences per name, and the subset that sits inside a
// for-statement whose body also writes the name. Assignment LHS
// identifiers are definitions, not reads (destinations that are
// index/star expressions read their operands); declaration lists and
// blank-use assignments are excluded like countSemanticIdents.
func countCarryLoopReads(body *ast.BlockStmt) (map[string]int, map[string]int) {
	reads := map[string]int{}
	inCarry := map[string]int{}
	type forFrame struct {
		writes  map[string]bool
		defSeen map[string]bool
	}
	var frames []*forFrame
	read := func(name string) {
		if name == "_" {
			return
		}
		reads[name]++
		for i := len(frames) - 1; i >= 0; i-- {
			if frames[i].writes[name] && frames[i].defSeen[name] {
				inCarry[name]++
				return
			}
		}
	}
	var walkExpr func(n ast.Node)
	walkExpr = func(n ast.Node) {
		if n == nil {
			return
		}
		if id, ok := n.(*ast.Ident); ok {
			read(id.Name)
			return
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n {
				return true
			}
			walkExpr(c)
			return false
		})
	}
	var walkStmt func(st ast.Stmt, direct *forFrame)
	walkList := func(list []ast.Stmt, direct *forFrame) {
		for _, s := range list {
			walkStmt(s, direct)
		}
	}
	walkStmt = func(st ast.Stmt, direct *forFrame) {
		switch x := st.(type) {
		case nil:
		case *ast.BlockStmt:
			walkList(x.List, nil)
		case *ast.AssignStmt:
			allBlank := true
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
					allBlank = false
				}
			}
			if allBlank {
				return
			}
			for _, r := range x.Rhs {
				walkExpr(r)
			}
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					// A definition counts toward defSeen only when it
					// executes unconditionally at the for-body's own
					// level: reads attributed to a frame then have a
					// same-iteration definition preceding them.
					if direct != nil {
						direct.defSeen[id.Name] = true
					}
				} else {
					walkExpr(l)
				}
			}
		case *ast.IfStmt:
			walkExpr(x.Cond)
			walkList(x.Body.List, nil)
			if x.Else != nil {
				walkStmt(x.Else, nil)
			}
		case *ast.ForStmt:
			fr := &forFrame{writes: identWrites(x.Body.List), defSeen: map[string]bool{}}
			frames = append(frames, fr)
			if x.Cond != nil {
				walkExpr(x.Cond)
			}
			walkList(x.Body.List, fr)
			frames = frames[:len(frames)-1]
		case *ast.LabeledStmt:
			walkStmt(x.Stmt, direct)
		case *ast.ExprStmt:
			walkExpr(x.X)
		case *ast.DeclStmt:
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				walkExpr(r)
			}
		case *ast.BranchStmt:
		case *ast.SwitchStmt:
			if x.Tag != nil {
				walkExpr(x.Tag)
			}
			for _, c := range x.Body.List {
				if cc, ok := c.(*ast.CaseClause); ok {
					for _, e := range cc.List {
						walkExpr(e)
					}
					walkList(cc.Body, nil)
				}
			}
		default:
			walkExpr(st)
		}
	}
	walkList(body.List, nil)
	return reads, inCarry
}

// collectConstBindings finds SSA value locals assigned exactly once,
// from an int32-representable literal. Only the emitter's single-def
// value locals (v<n>, its own naming contract) qualify: wasm locals
// (l<n>) are MUTABLE and default to zero, so a read can legitimately
// precede their one assignment.
func collectConstBindings(body *ast.BlockStmt, wide bool) map[string]int32 {
	assigns := map[string]int{}
	val := map[string]int32{}
	isConst := map[string]bool{}
	// On a memory64 function the emitter spells its constant locals
	// int64(...)/uint64(...); bind those too when the value fits the
	// int32 descriptor width. Every consumer folds by VALUE (memarg
	// offsets, coalesced windows, shift amounts), so a fitting wide
	// literal is exactly as safe as a narrow one. wasm32 functions
	// keep the narrow-only matcher, byte-identical output.
	constOf := intConstValue
	if wide {
		constOf = func(e ast.Expr) (int32, bool) {
			if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
				if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "int64" || id.Name == "uint64") {
					return intConstValue(c.Args[0])
				}
			}
			return intConstValue(e)
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.IncDecStmt:
			if id, ok := st.X.(*ast.Ident); ok {
				assigns[id.Name]++
			}
		case *ast.AssignStmt:
			for i, l := range st.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				assigns[id.Name]++
				if len(st.Lhs) == len(st.Rhs) && st.Tok == token.ASSIGN {
					if c, ok := constOf(st.Rhs[i]); ok {
						val[id.Name] = c
						isConst[id.Name] = true
					}
				}
			}
		}
		return true
	})
	out := map[string]int32{}
	for name, c := range val {
		if assigns[name] == 1 && isConst[name] && isSSAValueLocal(name) {
			out[name] = c
		}
	}
	return out
}

// isSSAValueLocal matches the emitter's own v<n> value-local names.
func isSSAValueLocal(name string) bool {
	if len(name) < 2 || name[0] != 'v' {
		return false
	}
	for _, r := range name[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isV128ArrayType matches the emitted `[2]uint64` type node.
func isV128ArrayType(e ast.Expr) bool {
	at, ok := e.(*ast.ArrayType)
	if !ok || at.Len == nil {
		return false
	}
	l, ok := at.Len.(*ast.BasicLit)
	if !ok || l.Value != "2" {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "uint64"
}

// carriesV128 reports whether an expression yields a v128 under the
// pass's knowledge: a marked call with v128 result, a marked literal, or
// a variable already known to be v128 (pair or array form).
func (sc *simdScalarizer) carriesV128(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CallExpr:
		m, ok := sc.em.simdCalls[x]
		return ok && m.resV128
	case *ast.CompositeLit:
		return sc.em.simdConsts[x]
	case *ast.Ident:
		return sc.pairs[x.Name] || sc.arrays[x.Name]
	}
	return false
}

// collect grows the candidate set to a fixed point: declarations with
// the v128 array type, and assignment targets fed from v128 sources.
func (sc *simdScalarizer) collect(body *ast.BlockStmt) {
	for {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch st := n.(type) {
			case *ast.DeclStmt:
				gd, ok := st.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return true
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || vs.Type == nil || !isV128ArrayType(vs.Type) {
						continue
					}
					for _, name := range vs.Names {
						if !sc.pairs[name.Name] && !sc.arrays[name.Name] {
							sc.pairs[name.Name] = true
							changed = true
						}
					}
				}
			case *ast.AssignStmt:
				if len(st.Lhs) != 1 || len(st.Rhs) != 1 {
					return true
				}
				lhs, ok := st.Lhs[0].(*ast.Ident)
				if !ok || lhs.Name == "_" {
					return true
				}
				if sc.pairs[lhs.Name] || sc.arrays[lhs.Name] {
					return true
				}
				if sc.carriesV128(st.Rhs[0]) {
					sc.pairs[lhs.Name] = true
					changed = true
				}
			}
			return true
		})
		if !changed {
			return
		}
	}
}

// audit demotes candidates with any use the rewriter does not handle:
// everything except appearing alone on either side of an assignment, as
// a v128 argument of a marked call, in a blank-use, or in its own
// declaration. Demotion moves the variable to array form, which every
// bridge site handles.
func (sc *simdScalarizer) audit(body *ast.BlockStmt) {
	ok := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.AssignStmt:
			if len(st.Lhs) == 1 && len(st.Rhs) == 1 {
				if id, isID := st.Lhs[0].(*ast.Ident); isID {
					ok[id] = true
				}
				if id, isID := st.Rhs[0].(*ast.Ident); isID {
					ok[id] = true
				}
			}
			// Blank uses `_ = v` arrive here too (Lhs `_`, Rhs ident).
		case *ast.CallExpr:
			m, marked := sc.em.simdCalls[st]
			if !marked {
				return true
			}
			for i, a := range st.Args {
				if i < len(m.args) && m.args[i] {
					if id, isID := a.(*ast.Ident); isID {
						ok[id] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, name := range st.Names {
				ok[name] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		id, isID := n.(*ast.Ident)
		if !isID || !sc.pairs[id.Name] {
			return true
		}
		if !ok[id] {
			delete(sc.pairs, id.Name)
			sc.arrays[id.Name] = true
		}
		return true
	})
}

// pairExprs returns the two half-expressions of a v128-carrying
// expression, hoisting nested calls into prelude statements.
func (sc *simdScalarizer) pairExprs(e ast.Expr, prelude *[]ast.Stmt) (lo, hi ast.Expr) {
	switch x := e.(type) {
	case *ast.Ident:
		if sc.pairs[x.Name] {
			return newID(x.Name), newID(pairName(x.Name))
		}
		// Array form: bridge by indexing.
		return &ast.IndexExpr{X: newID(x.Name), Index: intLit(0)},
			&ast.IndexExpr{X: newID(x.Name), Index: intLit(1)}
	case *ast.CompositeLit:
		if sc.em.simdConsts[x] {
			return x.Elts[0], x.Elts[1]
		}
	case *ast.CallExpr:
		if m, marked := sc.em.simdCalls[x]; marked && m.resV128 && sc.pairable(m) {
			sc.tmp++
			l := fmt.Sprintf("__sv%d", sc.tmp)
			h := pairName(l)
			sc.hoistPairs = append(sc.hoistPairs, l)
			*prelude = append(*prelude, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{newID(l), newID(h)},
				Rhs: []ast.Expr{sc.rewriteCall(x, prelude)},
			})
			return newID(l), newID(h)
		}
	}
	// Unrecognized v128 source: hoist to an array temp and index it.
	sc.tmp++
	t := fmt.Sprintf("__sa%d", sc.tmp)
	sc.hoistArrs = append(sc.hoistArrs, t)
	*prelude = append(*prelude, &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{newID(t)},
		Rhs: []ast.Expr{sc.rewriteExpr(e, prelude)},
	})
	return &ast.IndexExpr{X: newID(t), Index: intLit(0)},
		&ast.IndexExpr{X: newID(t), Index: intLit(1)}
}

// pairable reports whether a marked call's op has a pair-form splice.
// The scalarizer must not emit a pair call the backend cannot take
// over: two results cannot be marshalled if the CALL survives.
// A memory64 helper ("simd_m64_v128_load") shares its wasm32 twin's
// table entry — the splice bodies are identical, only the
// effective-address glue widens (the backend strips the m64_ marker
// the same way; see gcasm's simdSpliceOp).
func (sc *simdScalarizer) pairable(m simdCallMark) bool {
	op := m.name[len("simd_"):]
	op = strings.TrimPrefix(op, "m64_")
	return simdPairOps[op]
}

// rewriteCall converts a marked SIMD call to its scalar-pair form:
// simd_p_<op> with every v128 argument expanded into two halves.
// Callers must have checked pairable().
func (sc *simdScalarizer) rewriteCall(call *ast.CallExpr, prelude *[]ast.Stmt) *ast.CallExpr {
	// A nested tree of fusable calls becomes ONE fused region call:
	// its intermediates then never exist as Go values at all (see
	// simd_fuse.go). Falls through to per-call rewriting when the
	// tree is trivial or over the signature caps.
	if sc.em.t != nil {
		if fused, ok := sc.tryFuse(call, prelude); ok {
			return fused
		}
	}
	m := sc.em.simdCalls[call]
	pname := "simd_p_" + m.name[len("simd_"):]
	sc.em.useHelper(pname)
	var args []ast.Expr
	for i, a := range call.Args {
		if i < len(m.args) && m.args[i] {
			lo, hi := sc.pairExprs(a, prelude)
			args = append(args, lo, hi)
			continue
		}
		args = append(args, sc.rewriteExpr(a, prelude))
	}
	return &ast.CallExpr{Fun: sc.em.helperRef(pname), Args: args}
}

// rewriteArrayCall keeps a non-pairable SIMD call in array form,
// bridging any pair-carried argument back into a composite literal.
func (sc *simdScalarizer) rewriteArrayCall(call *ast.CallExpr, prelude *[]ast.Stmt) *ast.CallExpr {
	m := sc.em.simdCalls[call]
	for i, a := range call.Args {
		if i < len(m.args) && m.args[i] {
			if id, ok := a.(*ast.Ident); ok && sc.pairs[id.Name] {
				call.Args[i] = &ast.CompositeLit{
					Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
					Elts: []ast.Expr{newID(id.Name), newID(pairName(id.Name))},
				}
				continue
			}
			call.Args[i] = sc.rewriteExpr(a, prelude)
			continue
		}
		call.Args[i] = sc.rewriteExpr(a, prelude)
	}
	return call
}

// packCall wraps a pair-producing rewritten call back into array form
// via simd_p_pack, for sites that must keep the array (returns, array
// variables).
func (sc *simdScalarizer) packCall(inner *ast.CallExpr) *ast.CallExpr {
	sc.em.useHelper("simd_p_pack")
	return &ast.CallExpr{Fun: sc.em.helperRef("simd_p_pack"), Args: []ast.Expr{inner}}
}

// rewriteExpr rewrites marked SIMD calls nested inside an arbitrary
// (scalar-valued) expression tree. v128-RESULT calls in scalar context
// do not occur (the emitter types them), but scalar-result SIMD calls
// (extract_lane, bitmask, ...) appear anywhere an int can.
func (sc *simdScalarizer) rewriteExpr(e ast.Expr, prelude *[]ast.Stmt) ast.Expr {
	switch x := e.(type) {
	case *ast.CallExpr:
		if m, marked := sc.em.simdCalls[x]; marked {
			if !sc.pairable(m) {
				return sc.rewriteArrayCall(x, prelude)
			}
			nc := sc.rewriteCall(x, prelude)
			if m.resV128 {
				return sc.packCall(nc)
			}
			return nc
		}
		for i, a := range x.Args {
			x.Args[i] = sc.rewriteExpr(a, prelude)
		}
	case *ast.BinaryExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
		x.Y = sc.rewriteExpr(x.Y, prelude)
	case *ast.UnaryExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
	case *ast.ParenExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
	case *ast.IndexExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
		x.Index = sc.rewriteExpr(x.Index, prelude)
	case *ast.StarExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
	case *ast.SelectorExpr:
		x.X = sc.rewriteExpr(x.X, prelude)
	case *ast.FuncLit:
		x.Body.List = sc.rewriteStmts(x.Body.List)
	}
	return e
}

// rewriteStmts rewrites a statement list, expanding pair assignments
// and splitting declarations.
func (sc *simdScalarizer) rewriteStmts(list []ast.Stmt) []ast.Stmt {
	var out []ast.Stmt
	for i := 0; i < len(list); i++ {
		var prelude []ast.Stmt
		// A run of pair assignments sharing values can fuse into one
		// multi-root region call (see tryFuseWindow); otherwise the
		// statement rewrites alone.
		if repl, consumed, ok := sc.tryFuseWindow(list, i, &prelude); ok {
			out = append(out, prelude...)
			out = append(out, repl)
			i += consumed - 1
			continue
		}
		st := sc.rewriteStmt(list[i], &prelude)
		out = append(out, prelude...)
		if st != nil {
			out = append(out, st)
		}
	}
	return out
}

func (sc *simdScalarizer) rewriteStmt(st ast.Stmt, prelude *[]ast.Stmt) ast.Stmt {
	switch s := st.(type) {
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			return st
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil || !isV128ArrayType(vs.Type) {
				continue
			}
			// Split each scalarized name into two uint64s; names that
			// stayed arrays keep the spec.
			var keep []*ast.Ident
			var split []*ast.Ident
			for _, name := range vs.Names {
				if sc.pairs[name.Name] {
					split = append(split, name)
				} else {
					keep = append(keep, name)
				}
			}
			if len(split) == 0 {
				continue
			}
			var names []*ast.Ident
			for _, name := range split {
				names = append(names, newID(name.Name), newID(pairName(name.Name)))
			}
			*prelude = append(*prelude, &ast.DeclStmt{Decl: &ast.GenDecl{
				Tok:   token.VAR,
				Specs: []ast.Spec{&ast.ValueSpec{Names: names, Type: newID("uint64")}},
			}})
			if len(keep) == 0 {
				// The whole spec was scalarized; drop the statement by
				// clearing it to an empty declaration.
				vs.Names = nil
			} else {
				vs.Names = keep
			}
		}
		// Drop a declaration whose every spec emptied.
		empty := true
		for _, spec := range gd.Specs {
			if vs, ok := spec.(*ast.ValueSpec); !ok || len(vs.Names) > 0 {
				empty = false
			}
		}
		if empty {
			return nil
		}
		return st
	case *ast.AssignStmt:
		return sc.rewriteAssign(s, prelude)
	case *ast.ReturnStmt:
		for i, r := range s.Results {
			if sc.carriesV128(r) {
				if call, ok := r.(*ast.CallExpr); ok {
					if m := sc.em.simdCalls[call]; m.resV128 {
						if sc.pairable(m) {
							s.Results[i] = sc.packCall(sc.rewriteCall(call, prelude))
						} else {
							s.Results[i] = sc.rewriteArrayCall(call, prelude)
						}
						continue
					}
				}
				if id, ok := r.(*ast.Ident); ok && sc.pairs[id.Name] {
					s.Results[i] = &ast.CompositeLit{
						Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
						Elts: []ast.Expr{newID(id.Name), newID(pairName(id.Name))},
					}
					continue
				}
			}
			s.Results[i] = sc.rewriteExpr(r, prelude)
		}
		return st
	case *ast.LabeledStmt:
		s.Stmt = sc.rewriteStmt(s.Stmt, prelude)
		return st
	case *ast.BlockStmt:
		s.List = sc.rewriteStmts(s.List)
		return st
	case *ast.IfStmt:
		s.Cond = sc.rewriteExpr(s.Cond, prelude)
		s.Body.List = sc.rewriteStmts(s.Body.List)
		if s.Else != nil {
			s.Else = sc.rewriteStmt(s.Else, prelude)
		}
		return st
	case *ast.ForStmt:
		if repl, ok := sc.tryFuseLoop(s, prelude); ok {
			return repl
		}
		if s.Cond != nil {
			// A condition with a SIMD call would need per-iteration
			// hoisting; the emitter never produces one, so any marked
			// call here keeps its array form (rewriteExpr handles the
			// scalar-result ones inline).
			s.Cond = sc.rewriteExpr(s.Cond, prelude)
		}
		s.Body.List = sc.rewriteStmts(s.Body.List)
		return st
	case *ast.SwitchStmt:
		if s.Tag != nil {
			s.Tag = sc.rewriteExpr(s.Tag, prelude)
		}
		for _, c := range s.Body.List {
			if cc, ok := c.(*ast.CaseClause); ok {
				cc.Body = sc.rewriteStmts(cc.Body)
			}
		}
		return st
	case *ast.ExprStmt:
		s.X = sc.rewriteExpr(s.X, prelude)
		return st
	}
	return st
}

// rewriteAssign handles the four shapes an emitted assignment takes
// once v128 values are involved.
func (sc *simdScalarizer) rewriteAssign(s *ast.AssignStmt, prelude *[]ast.Stmt) ast.Stmt {
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		for i := range s.Lhs {
			if _, isID := s.Lhs[i].(*ast.Ident); !isID {
				s.Lhs[i] = sc.rewriteExpr(s.Lhs[i], prelude)
			}
		}
		for i := range s.Rhs {
			s.Rhs[i] = sc.rewriteExpr(s.Rhs[i], prelude)
		}
		return s
	}
	lhs, lhsIsID := s.Lhs[0].(*ast.Ident)
	rhs := s.Rhs[0]
	if !lhsIsID {
		// A memory store: the destination expression can nest
		// scalar-result SIMD calls (an extract_lane inside the address
		// arithmetic).
		s.Lhs[0] = sc.rewriteExpr(s.Lhs[0], prelude)
	}

	// Pair-form destination.
	if lhsIsID && sc.pairs[lhs.Name] {
		lo := newID(lhs.Name)
		hi := newID(pairName(lhs.Name))
		if call, ok := rhs.(*ast.CallExpr); ok {
			if m := sc.em.simdCalls[call]; m.resV128 && sc.pairable(m) {
				return &ast.AssignStmt{Tok: s.Tok, Lhs: []ast.Expr{lo, hi},
					Rhs: []ast.Expr{sc.rewriteCall(call, prelude)}}
			}
		}
		rlo, rhi := sc.pairExprs(rhs, prelude)
		return &ast.AssignStmt{Tok: s.Tok, Lhs: []ast.Expr{lo, hi}, Rhs: []ast.Expr{rlo, rhi}}
	}

	// Blank use of a pair variable.
	if lhsIsID && lhs.Name == "_" {
		if id, ok := rhs.(*ast.Ident); ok && sc.pairs[id.Name] {
			return &ast.AssignStmt{Tok: s.Tok,
				Lhs: []ast.Expr{newID("_"), newID("_")},
				Rhs: []ast.Expr{newID(id.Name), newID(pairName(id.Name))}}
		}
	}

	// Array-form (or scalar) destination fed from pair sources.
	if sc.carriesV128(rhs) {
		if call, ok := rhs.(*ast.CallExpr); ok {
			if m := sc.em.simdCalls[call]; m.resV128 {
				if sc.pairable(m) {
					s.Rhs[0] = sc.packCall(sc.rewriteCall(call, prelude))
				} else {
					s.Rhs[0] = sc.rewriteArrayCall(call, prelude)
				}
				return s
			}
		}
		if id, ok := rhs.(*ast.Ident); ok && sc.pairs[id.Name] {
			s.Rhs[0] = &ast.CompositeLit{
				Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
				Elts: []ast.Expr{newID(id.Name), newID(pairName(id.Name))},
			}
			return s
		}
	}
	s.Rhs[0] = sc.rewriteExpr(rhs, prelude)
	return s
}
