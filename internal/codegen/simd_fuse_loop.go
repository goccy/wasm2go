package codegen

// Loop-level fusion: a countdown loop whose whole body already fuses
// into one region is upgraded to a single fused-LOOP call. The
// window path leaves one boundary per iteration — arguments
// re-materialize, the carried accumulator round-trips v128 → GPR
// pair → frame → GPR pair → v128, and gc reloads every loop local
// around the splice; measurement puts that boundary (latency on the
// carried chain plus the reload traffic, not instruction count) at
// the top of the remaining profile. Owning the loop moves the
// carried state into registers for the loop's entire lifetime.
//
// The upgrade is conservative and total: the emitted countdown
// shapes are this package's own output contract, the body must fuse
// into ONE region consuming every candidate, leftover interveners
// must be loop-invariant (they hoist above the loop), and any
// escape the descriptor cannot represent rejects the upgrade — the
// loop then emits exactly as the window path would have.

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// countdownLoop is the matched surface form of an emitted loop.
type countdownLoop struct {
	body    []ast.Stmt        // candidate/intervener statements, in order
	counter *ast.Ident        // the loop-carried counter variable
	decVar  *ast.Ident        // do-while form: `decVar = counter - dec` (nil for header form)
	decEx   []ast.Expr        // per-iteration decrement terms (const or const-local)
	wide    bool              // the counter is int64 (constants spelled int64(...))
	eqHead  bool              // header form tested `c == 0` (valid only for a unit decrement)
	bumps   []*ast.AssignStmt // `p = p + const`
	carries []*ast.AssignStmt // `accPrev = accNext` (array form)
	consts  []*ast.AssignStmt // tail constant defs (bump deltas); hoisted
}

// matchCountdownLoop recognizes the two countdown shapes the emitter
// produces (see the structured emitter): the do-while form
//
//	for { body...; d = c - K; if d != 0 { bumps/carries; c = d; continue } else { break }; break }
//
// and the unrolled-header form
//
//	for { if Ui32(c) < Ui32(K) { break } else { body...; bumps/carries; c = c - K } }
func matchCountdownLoop(sc *simdScalarizer, f *ast.ForStmt) (*countdownLoop, bool) {
	if f.Init != nil || f.Cond != nil || f.Post != nil {
		return nil, false
	}
	list := f.Body.List
	// A redundant trailing `break` follows both emitted forms.
	if n := len(list); n >= 2 {
		if br, ok := list[n-1].(*ast.BranchStmt); ok && br.Tok == token.BREAK {
			if _, isIf := list[n-2].(*ast.IfStmt); isIf && n == 2 {
				list = list[:1]
			}
		}
	}
	if len(list) == 1 {
		// Header form: one IfStmt{cond -> break; else -> body}.
		ifs, ok := list[0].(*ast.IfStmt)
		if !ok || ifs.Else == nil || len(ifs.Body.List) != 1 {
			return nil, false
		}
		if _, ok := ifs.Body.List[0].(*ast.BranchStmt); !ok {
			return nil, false
		}
		counter, ok := matchUiLt(ifs.Cond, sc.wideCounters())
		eqHead := false
		if !ok {
			// Third emitted shape: a head-tested while,
			// `for { if c == 0 { break } else { body; c = c - 1 } }`.
			// With a UNIT decrement, `c == 0` and `Ui(c) < Ui(1)` exit
			// at exactly the same counter values, so the loop reuses
			// the pre-tested descriptor; tryFuseLoop rejects any other
			// decrement under this head.
			counter, ok = matchEqZero(ifs.Cond, sc.wideCounters())
			eqHead = ok
		}
		if !ok {
			return nil, false
		}
		blk, ok := ifs.Else.(*ast.BlockStmt)
		if !ok || len(blk.List) < 2 {
			return nil, false
		}
		cl := &countdownLoop{counter: counter, eqHead: eqHead}
		if !cl.splitTail(sc, blk.List, counter) {
			return nil, false
		}
		return cl, true
	}
	// Do-while form: trailing `break`, before it an IfStmt with
	// continue/break arms, before that the counter decrement.
	if len(list) < 3 {
		return nil, false
	}
	if br, ok := list[len(list)-1].(*ast.BranchStmt); !ok || br.Tok != token.BREAK {
		return nil, false
	}
	ifs, ok := list[len(list)-2].(*ast.IfStmt)
	if !ok || ifs.Else == nil {
		return nil, false
	}
	dec, ok := list[len(list)-3].(*ast.AssignStmt)
	if !ok || len(dec.Lhs) != 1 || len(dec.Rhs) != 1 {
		return nil, false
	}
	decVar, ok := dec.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, false
	}
	bin, ok := dec.Rhs[0].(*ast.BinaryExpr)
	if !ok || bin.Op != token.SUB {
		return nil, false
	}
	counter, ok := bin.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	wide := false
	if _, cok, w := loopConstValue(bin.Y); cok {
		wide = w
	} else if _, iok := bin.Y.(*ast.Ident); !iok {
		return nil, false
	}
	// Condition `decVar != 0 { tail; continue } else { break }` or the
	// inverted `decVar == 0 { break } else { tail; continue }`.
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || (cond.Op != token.NEQ && cond.Op != token.EQL) {
		return nil, false
	}
	if id, ok := cond.X.(*ast.Ident); !ok || id.Name != decVar.Name {
		return nil, false
	}
	if c, ok, w := loopConstValue(cond.Y); !ok || c != 0 {
		return nil, false
	} else if w {
		wide = true
	}
	var contArm []ast.Stmt
	var brkBlk *ast.BlockStmt
	if cond.Op == token.NEQ {
		contArm = ifs.Body.List
		brkBlk, _ = ifs.Else.(*ast.BlockStmt)
	} else {
		if els, eok := ifs.Else.(*ast.BlockStmt); eok {
			contArm = els.List
		}
		brkBlk = ifs.Body
	}
	if brkBlk == nil || len(brkBlk.List) != 1 {
		return nil, false
	}
	if br, ok := brkBlk.List[0].(*ast.BranchStmt); !ok || br.Tok != token.BREAK {
		return nil, false
	}
	arm := contArm
	if len(arm) < 2 {
		return nil, false
	}
	if br, ok := arm[len(arm)-1].(*ast.BranchStmt); !ok || br.Tok != token.CONTINUE {
		return nil, false
	}
	cl := &countdownLoop{counter: counter, decVar: decVar, decEx: []ast.Expr{bin.Y}, wide: wide}
	cl.body = list[:len(list)-3]
	// The continue arm holds bumps, carries, and `c = decVar`.
	sawReset := false
	for _, st := range arm[:len(arm)-1] {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			return nil, false
		}
		if err := cl.classifyTailAssign(sc, as, counter, decVar, &sawReset); err != nil {
			return nil, false
		}
	}
	if !sawReset {
		return nil, false
	}
	return cl, true
}

// unwrapWidth strips the int64()/uint64() conversion the memory64
// fused-call sites wrap their scalar arguments in, so slot and bump
// matching sees the same identifiers on both widths.
func unwrapWidth(e ast.Expr) ast.Expr {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
		if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "int64" || id.Name == "uint64") {
			return c.Args[0]
		}
	}
	return e
}

// matchEqZero matches the head-tested while's break condition
// `c == 0` (either operand order; the zero spelled at the counter's
// width on memory64).
func matchEqZero(e ast.Expr, wide bool) (*ast.Ident, bool) {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return nil, false
	}
	x, y := bin.X, bin.Y
	if _, isID := x.(*ast.Ident); !isID {
		x, y = y, x
	}
	id, ok := x.(*ast.Ident)
	if !ok {
		return nil, false
	}
	if wide {
		if c, cok, _ := loopConstValue(y); !cok || c != 0 {
			return nil, false
		}
	} else if c, cok := intConstValue(y); !cok || c != 0 {
		return nil, false
	}
	return id, true
}

// wideCounters reports whether the scalarizer's module carries
// promoted i64 loop counters (memory64). Nil-safe: the matcher tests
// drive matchCountdownLoop without a scalarizer.
func (sc *simdScalarizer) wideCounters() bool {
	return sc != nil && sc.em != nil && sc.em.mem64
}

// loopReject logs a fused-loop upgrade refusal under WASM2GO_FUSE_DEBUG
// (tagged by the rejecting source line) and returns the not-upgraded
// result. Diagnostics only; the caller emits the loop as the window
// path would have.
func (sc *simdScalarizer) loopReject(tag string) (ast.Stmt, bool) {
	fuseDebugf("FUSELOOP reject %s", tag)
	return nil, false
}

// blankFor returns n blank identifiers for a keep-alive assignment.
func blankFor(n int) []ast.Expr {
	out := make([]ast.Expr, n)
	for i := range out {
		out[i] = newID("_")
	}
	return out
}

// splitTail (header form) walks the else-block backwards, peeling
// bumps, carries and the counter decrement off the tail; the rest is
// the body.
func (cl *countdownLoop) splitTail(sc *simdScalarizer, list []ast.Stmt, counter *ast.Ident) bool {
	i := len(list)
	// A trailing `continue` may close the arm.
	if i > 0 {
		if br, ok := list[i-1].(*ast.BranchStmt); ok && br.Tok == token.CONTINUE {
			i--
		}
	}
	sawDec := false
	for i > 0 {
		as, ok := list[i-1].(*ast.AssignStmt)
		if !ok {
			break
		}
		if lhs, ok := as.Lhs[0].(*ast.Ident); ok && len(as.Lhs) == 1 && lhs.Name == counter.Name {
			// `c = c - K` (possibly a reassociated chain of subtractions).
			terms, ok := matchCounterDec(as, counter, sc.wideCounters())
			if !ok {
				return false
			}
			cl.decEx = terms
			// An int64-spelled decrement marks the promoted i64 counter
			// a memory64 module's unrolled header carries.
			for _, term := range terms {
				if _, cok, w := loopConstValue(term); cok && w {
					cl.wide = true
				}
			}
			sawDec = true
			i--
			continue
		}
		var sawReset bool
		if cl.classifyTailAssign(sc, as, counter, nil, &sawReset) != nil {
			break
		}
		i--
	}
	cl.body = list[:i]
	return sawDec && len(cl.body) >= 1
}

// classifyTailAssign sorts a tail assignment into bump / carry /
// counter-reset, or returns an error for anything else.
func (cl *countdownLoop) classifyTailAssign(sc *simdScalarizer, as *ast.AssignStmt, counter, decVar *ast.Ident, sawReset *bool) error {
	if len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return fmt.Errorf("unrecognized tail arity")
	}
	lhs, ok := as.Lhs[0].(*ast.Ident)
	if !ok {
		return fmt.Errorf("tail store")
	}
	if decVar != nil && lhs.Name == counter.Name {
		if rid, ok := as.Rhs[0].(*ast.Ident); ok && rid.Name == decVar.Name {
			*sawReset = true
			return nil
		}
		return fmt.Errorf("unrecognized counter reset")
	}
	if _, ok := intConstValue(as.Rhs[0]); ok {
		// A constant local defined at the tail (the emitter's const CSE
		// places bump deltas here). Loop-invariant by construction:
		// hoisted above the loop.
		cl.consts = append(cl.consts, as)
		return nil
	}
	if rid, ok := as.Rhs[0].(*ast.Ident); ok {
		// A plain alias at the tail is a carry candidate: the values
		// are still in [2]uint64 array form here (the pair split
		// happens at rewrite), so `accPrev = accNext` is one assign.
		// Whether both sides really are v128 pairs is proven at
		// upgrade time against the fused call's argument/root sets.
		_ = rid
		cl.carries = append(cl.carries, as)
		return nil
	}
	if bin, ok := as.Rhs[0].(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		if base, ok := bin.X.(*ast.Ident); ok && base.Name == lhs.Name {
			if constishExpr(bin.Y, sc.wideCounters()) {
				cl.bumps = append(cl.bumps, as)
				return nil
			}
		}
	}
	return fmt.Errorf("unrecognized tail assign")
}

// matchUiLt matches the unrolled header guard
// `base.Ui32(c) < base.Ui32(int32(K))` (either helper-qualified or
// plain), returning the counter.
func matchUiLt(e ast.Expr, wide bool) (*ast.Ident, bool) {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.LSS {
		return nil, false
	}
	// Both counter widths: wasm32 spells the guard Ui32(c) < Ui32(K);
	// a memory64 module's promoted i64 counter spells it
	// Ui64(c) < Ui64(int64(K)).
	unwrap := func(x ast.Expr) ast.Expr {
		if c, ok := x.(*ast.CallExpr); ok && len(c.Args) == 1 {
			switch n := helperName(c.Fun); {
			case strings.HasSuffix(n, "i32"), n == "Ui32", n == "ui32":
				return c.Args[0]
			case wide && (strings.HasSuffix(n, "i64") || n == "Ui64" || n == "ui64"):
				return c.Args[0]
			}
		}
		return x
	}
	id, ok := unwrap(bin.X).(*ast.Ident)
	if !ok {
		return nil, false
	}
	c := unwrap(bin.Y)
	if wide {
		if _, ok, _ := loopConstValue(c); !ok {
			return nil, false
		}
	} else if _, ok := intConstValue(c); !ok {
		return nil, false
	}
	return id, ok
}

// matchCounterDec matches `c = c - K` and reassociated chains
// `c = c - k1 - k2 ...`, returning the decrement terms for later
// resolution.
func matchCounterDec(as *ast.AssignStmt, counter *ast.Ident, wide bool) ([]ast.Expr, bool) {
	var terms []ast.Expr
	e := as.Rhs[0]
	for {
		bin, ok := e.(*ast.BinaryExpr)
		if !ok || bin.Op != token.SUB {
			break
		}
		if !constishExpr(bin.Y, wide) {
			return nil, false
		}
		terms = append(terms, bin.Y)
		e = bin.X
	}
	if id, ok := e.(*ast.Ident); ok && id.Name == counter.Name && len(terms) > 0 {
		return terms, true
	}
	return nil, false
}

// loopConstValue is intConstValue extended with the 64-bit constant
// spellings (`int64(<lit>)`), reporting wideness — used ONLY for the
// loop counter's decrement and zero-compare, never for window
// argument classification.
func loopConstValue(e ast.Expr) (int32, bool, bool) {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
		if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "int64" || id.Name == "uint64") {
			c32, cok := intConstValue(c.Args[0])
			return c32, cok, true
		}
	}
	c32, cok := intConstValue(e)
	return c32, cok, false
}

// constishExpr accepts a literal or a plain identifier (a possible
// constant local, resolved at upgrade time once the hoisted
// interveners are known).
func constishExpr(e ast.Expr, wide bool) bool {
	if wide {
		if _, ok, _ := loopConstValue(e); ok {
			return true
		}
	} else if _, ok := intConstValue(e); ok {
		return true
	}
	_, ok := e.(*ast.Ident)
	return ok
}

// identWrites collects every identifier the statements assign.
func identWrites(stmts []ast.Stmt) map[string]bool {
	w := map[string]bool{}
	for _, st := range stmts {
		if as, ok := st.(*ast.AssignStmt); ok {
			for _, l := range as.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					w[id.Name] = true
				}
			}
		}
	}
	return w
}

// identUses counts semantic identifier reads inside the statements
// (assign LHS targets excluded).
func identUses(stmts []ast.Stmt) map[string]int {
	u := map[string]int{}
	for _, st := range stmts {
		var rhs []ast.Node
		if as, ok := st.(*ast.AssignStmt); ok {
			for _, r := range as.Rhs {
				rhs = append(rhs, r)
			}
		} else {
			rhs = append(rhs, st)
		}
		for _, n := range rhs {
			ast.Inspect(n, func(x ast.Node) bool {
				if id, ok := x.(*ast.Ident); ok && id.Name != "_" {
					u[id.Name]++
				}
				return true
			})
		}
	}
	return u
}

// tryFuseLoop attempts the loop upgrade. On success it returns the
// hoisted invariant statements plus the single fused-loop call that
// replaces the entire ForStmt. On failure the caller proceeds with
// the normal per-statement rewrite (which itself window-fuses the
// body), so a refused upgrade costs nothing.
func (sc *simdScalarizer) tryFuseLoop(f *ast.ForStmt, prelude *[]ast.Stmt) (ast.Stmt, bool) {
	// Opt-in while the splicer support matures; the retranspile
	// pipeline enables it explicitly.
	if sc.em.t == nil || !sc.em.t.opts.FuseLoops {
		return sc.loopReject("L421")
	}
	cl, ok := matchCountdownLoop(sc, f)
	if !ok {
		return sc.loopReject("L425")
	}
	// Fuse the whole body into one region. Leading interveners join
	// the window; the trial must consume every statement.
	var wpre []ast.Stmt
	stmt, span, ok := sc.tryFuseWindowEx(cl.body, 0, &wpre, true)
	if !ok {
		return sc.loopReject("L432")
	}
	for _, st := range cl.body[span:] {
		// Statements after the last candidate: constant defs (bump
		// deltas the emitter's CSE placed late) hoist with the rest;
		// anything else refuses the upgrade.
		as, aok := st.(*ast.AssignStmt)
		if aok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if _, cok := sc.fuseConstOf(as.Rhs[0]); cok {
				cl.consts = append(cl.consts, as)
				continue
			}
		}
		return sc.loopReject("L445")
	}
	call, rootVars, ok := fusedCallParts(stmt)
	if !ok {
		return sc.loopReject("L449")
	}
	fxName := helperName(call.Fun)
	if strings.HasPrefix(fxName, "Simd_") {
		// The multi-package export rename capitalizes the reference;
		// the intern table keys the emitted (lowercase) name.
		fxName = "s" + fxName[1:]
	}
	tree := sc.em.t.FusedTrees()[fxName]
	if tree == nil {
		return sc.loopReject("L459")
	}
	// Locate argument slots by name: scalars start after m, pairs
	// after scalars+floats (two slots each).
	scalarSlot := map[string]int{}
	for i := 0; i < tree.NumScalars; i++ {
		if id, ok := unwrapWidth(call.Args[1+i]).(*ast.Ident); ok {
			scalarSlot[id.Name] = i
		}
	}
	pairSlot := map[string]int{}
	pairBase := 1 + tree.NumScalars + tree.NumFloats
	for i := 0; i < tree.NumPairs; i++ {
		if id, ok := call.Args[pairBase+2*i].(*ast.Ident); ok {
			pairSlot[id.Name] = i
		}
	}
	rootIdx := map[string]int{}
	for i, rv := range rootVars {
		rootIdx[rv] = i
	}
	// Resolve constant locals now that every hoisted definition is
	// known (tail consts plus leftover invariant interveners).
	constMap := map[string]int32{}
	addConst := func(st ast.Stmt) {
		if as, aok := st.(*ast.AssignStmt); aok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, iok := as.Lhs[0].(*ast.Ident); iok {
				if c, cok := intConstValue(as.Rhs[0]); cok {
					constMap[id.Name] = c
				}
			}
		}
	}
	for _, st := range cl.consts {
		addConst(st)
	}
	for _, st := range wpre {
		addConst(st)
	}
	resolveC := func(e ast.Expr) (int32, bool) {
		if c, ok, _ := loopConstValue(e); ok {
			return c, true
		}
		if c, ok := sc.fuseConstOf(e); ok {
			return c, true
		}
		if id, ok := e.(*ast.Ident); ok {
			c, ok := constMap[id.Name]
			return c, ok
		}
		return 0, false
	}
	var dec int32
	for _, t := range cl.decEx {
		c, cok := resolveC(t)
		if !cok {
			return sc.loopReject("L515")
		}
		dec += c
	}
	if dec <= 0 {
		return sc.loopReject("L520")
	}
	if cl.eqHead && dec != 1 {
		// `c == 0` only equals the `< dec` pre-test when dec is 1.
		return sc.loopReject("eq-head-nonunit-dec")
	}
	loop := &simdfuse.Loop{Tree: tree, Dec: dec, PreTest: cl.decVar == nil, CounterWide: cl.wide}
	// Carries: `prev = next` with prev a pair argument and next a
	// root is loop-carried state; prev NOT an argument is an
	// EXIT-COPY (the unroller's after-loop phi carrier), reassigned
	// once after the fused call instead of every iteration.
	roots := tree.RootList()
	type exitCopy struct{ dst, src string }
	var exitCopies []exitCopy
	for _, ca := range cl.carries {
		prev := ca.Lhs[0].(*ast.Ident).Name
		next := ca.Rhs[0].(*ast.Ident).Name
		ri, rok := rootIdx[next]
		if !rok {
			return sc.loopReject("L535")
		}
		if pi, pok := pairSlot[prev]; pok {
			loop.CarriedPairs = append(loop.CarriedPairs, [2]int{pi, roots[ri]})
			continue
		}
		exitCopies = append(exitCopies, exitCopy{dst: prev, src: next})
	}
	// Bumps: `p = p + c` — p must be a scalar argument. c is a
	// constant, or a loop-invariant variable (a runtime stride):
	// those join the fused signature as delta parameters after the
	// counter.
	bodyWrites := identWrites(f.Body.List)
	inLoop := identUses(f.Body.List)
	deltaOf := map[string]int{}
	var deltaArgs []ast.Expr
	// bumpLhs parallels loop.Bumps: the variable receiving the slot's
	// final value after the loop. A REASSOCIATED bump (the slot's
	// argument is a derived expression `target + invariant`) receives
	// a fresh temp, and the target's exact final is reconstructed
	// after the call as `target = temp - invariant` — no liveness
	// analysis needed.
	var bumpLhs []string
	type bumpFix struct {
		target string
		temp   string
		addend ast.Expr
	}
	var bumpFixes []bumpFix
	// droppedBump targets stop being written by the fused form: their
	// pre-loop value is the correct base for every hoisted initial.
	droppedBump := map[string]bool{}
	addBump := func(si int, lhsName string, y ast.Expr) bool {
		if c, cok := resolveC(y); cok {
			loop.Bumps = append(loop.Bumps, simdfuse.LoopBump{Scalar: si, Delta: c, DeltaScalar: -1})
			bumpLhs = append(bumpLhs, lhsName)
			return true
		}
		id, iok := y.(*ast.Ident)
		if !iok || bodyWrites[id.Name] {
			return false
		}
		di, seen := deltaOf[id.Name]
		if !seen {
			di = len(deltaArgs)
			deltaOf[id.Name] = di
			deltaArgs = append(deltaArgs, newID(id.Name))
		}
		loop.Bumps = append(loop.Bumps, simdfuse.LoopBump{Scalar: si, DeltaScalar: di})
		bumpLhs = append(bumpLhs, lhsName)
		return true
	}
	// derivedOf reports whether e is `target + invariant` (either
	// operand order), for bump reassociation: bumping the derived
	// argument by the target's delta preserves its value at every
	// iteration, since the addend never changes inside the loop.
	derivedOf := func(e ast.Expr, target string) (ast.Expr, bool) {
		bin, ok := e.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			fuseDebugf("FUSELOOP reject derived-bump-shape")
			return nil, false
		}
		x, y := bin.X, bin.Y
		if id, ok := y.(*ast.Ident); ok && id.Name == target {
			x, y = y, x
		}
		id, ok := x.(*ast.Ident)
		if !ok || id.Name != target {
			fuseDebugf("FUSELOOP reject derived-bump-target")
			return nil, false
		}
		if _, cok := resolveC(y); cok {
			return y, true
		}
		if yid, ok := y.(*ast.Ident); ok && !bodyWrites[yid.Name] {
			return y, true
		}
		fuseDebugf("FUSELOOP reject derived-bump-delta")
		return nil, false
	}
	wpreDef := func(name string) *ast.AssignStmt {
		for _, st := range wpre {
			if as, ok := st.(*ast.AssignStmt); ok && len(as.Lhs) == 1 {
				if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == name {
					return as
				}
			}
		}
		return nil
	}
	for _, b := range cl.bumps {
		name := b.Lhs[0].(*ast.Ident).Name
		y := b.Rhs[0].(*ast.BinaryExpr).Y
		if si, sok := scalarSlot[name]; sok {
			if !addBump(si, name, y) {
				return sc.loopReject("L627")
			}
			continue
		}
		// Reassociation: bump every scalar slot whose argument (or
		// hoisted defining statement) is `name + invariant` instead.
		// The target itself is then never advanced by the fused form,
		// so it must be dead after the loop.
		matched := 0
		for i := 0; i < tree.NumScalars; i++ {
			arg := unwrapWidth(call.Args[1+i])
			addend, ok := derivedOf(arg, name)
			if !ok {
				if id, iok := arg.(*ast.Ident); iok {
					if def := wpreDef(id.Name); def != nil {
						addend, ok = derivedOf(def.Rhs[0], name)
					}
				}
			}
			if !ok {
				continue
			}
			lhsName := "_"
			if matched == 0 {
				// The first derived slot's final reconstructs the
				// target exactly: final = slotFinal - addend (the
				// addend is loop-invariant).
				lhsName = fmt.Sprintf("%s_fin", name)
				bumpFixes = append(bumpFixes, bumpFix{target: name, temp: lhsName, addend: addend})
			}
			if !addBump(i, lhsName, y) {
				return sc.loopReject("L658")
			}
			matched++
		}
		if matched == 0 {
			return sc.loopReject("L663")
		}
		droppedBump[name] = true
	}
	loop.NumDeltas = len(deltaArgs)
	// The counter joins as one extra scalar (slot NumScalars); its
	// final value and the bump pointers' final values return as extra
	// int32 results.
	loop.CounterScalar = tree.NumScalars
	for _, b := range loop.Bumps {
		loop.ExitScalars = append(loop.ExitScalars, b.Scalar)
	}
	loop.ExitScalars = append(loop.ExitScalars, loop.CounterScalar)
	if 1+tree.NumScalars+1+loop.NumDeltas > fusedMaxIntRegs ||
		1+tree.NumScalars+1+loop.NumDeltas+2*tree.NumPairs > fusedMaxIntSlots ||
		2*len(roots)+len(loop.ExitScalars) > fusedMaxIntSlots {
		return sc.loopReject("L679")
	}
	// Escape checks: values the loop produces per-iteration but does
	// not return must be dead after the loop. The carried PREVIOUS
	// values and the do-while decrement variable fall out of the
	// register form entirely.
	escape := func(name string) bool {
		if sc.identCount[name] <= inLoop[name]+1 {
			return false // every semantic use sits in this loop
		}
		// Clone-tolerant form: reads confined to self-carrying loop
		// bodies (this loop and its emitter-duplicated copies) can
		// never observe the eliminated per-iteration state from
		// outside any copy.
		return sc.readCount[name] > sc.carryLoopReads[name]
	}
	exitCopied := map[string]bool{}
	for _, ec := range exitCopies {
		exitCopied[ec.dst] = true
	}
	for _, ca := range cl.carries {
		name := ca.Lhs[0].(*ast.Ident).Name
		if exitCopied[name] {
			continue // reassigned after the loop instead
		}
		if escape(name) {
			if loop.PreTest {
				// In the while-form the carry variable's final value IS
				// the last root value (the arm runs to completion on
				// every taken iteration), so an after-loop reader is
				// satisfied by one post-call copy.
				exitCopies = append(exitCopies, exitCopy{dst: name, src: ca.Rhs[0].(*ast.Ident).Name})
				exitCopied[name] = true
				continue
			}
			return sc.loopReject("L714")
		}
	}
	if cl.decVar != nil && escape(cl.decVar.Name) {
		return sc.loopReject("L718")
	}
	// Remaining interveners hoist above the loop: they must be
	// loop-invariant, reading nothing the loop writes.
	writes := identWrites(f.Body.List)
	for _, rv := range rootVars {
		writes[rv] = true
	}
	for name := range droppedBump {
		// The fused form no longer advances a reassociated bump
		// target inside the loop; a hoisted initial reading it sees
		// the correct pre-loop value.
		delete(writes, name)
	}
	for _, st := range wpre {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			return sc.loopReject("L735")
		}
		bad := false
		for _, r := range as.Rhs {
			ast.Inspect(r, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && writes[id.Name] {
					bad = true
				}
				return true
			})
		}
		if bad {
			return sc.loopReject("L747")
		}
	}
	name, ok := sc.em.t.internFusedLoop(loop)
	if !ok {
		return sc.loopReject("L752")
	}
	sc.em.useHelper(name)
	// Assemble the replacement: hoisted interveners, then one call.
	// Arguments: the window call's args with the counter's initial
	// value inserted after the scalars; results: roots, then the
	// bump pointers' and counter's final values.
	for _, cs := range cl.consts {
		*prelude = append(*prelude, cs)
	}
	*prelude = append(*prelude, wpre...)
	args := make([]ast.Expr, 0, len(call.Args)+1)
	args = append(args, call.Args[:1+tree.NumScalars]...)
	args = append(args, newID(cl.counter.Name))
	args = append(args, deltaArgs...)
	args = append(args, call.Args[1+tree.NumScalars:]...)
	var lhs []ast.Expr
	for _, rv := range rootVars {
		lhs = append(lhs, newID(rv), newID(pairName(rv)))
	}
	for _, bn := range bumpLhs {
		lhs = append(lhs, newID(bn))
	}
	lhs = append(lhs, newID(cl.counter.Name))
	callStmt := &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: lhs,
		Rhs: []ast.Expr{&ast.CallExpr{Fun: sc.em.helperRef(name), Args: args}},
	}
	var post []ast.Stmt
	for _, bf := range bumpFixes {
		post = append(post, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(bf.target)},
			Rhs: []ast.Expr{&ast.BinaryExpr{X: newID(bf.temp), Op: token.SUB, Y: bf.addend}},
		})
	}
	if len(bumpFixes) > 0 {
		// The temps need declarations: hoist them as int32 zeros.
		var names []ast.Expr
		var zeros []ast.Expr
		zeroType := "int32"
		if tree.Addr64 {
			zeroType = "int64"
		}
		for _, bf := range bumpFixes {
			names = append(names, newID(bf.temp))
			zeros = append(zeros, &ast.CallExpr{Fun: newID(zeroType), Args: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "0"}}})
		}
		*prelude = append(*prelude, &ast.AssignStmt{Tok: token.DEFINE, Lhs: names, Rhs: zeros},
			&ast.AssignStmt{Tok: token.ASSIGN, Lhs: append([]ast.Expr{}, blankFor(len(names))...), Rhs: names})
	}
	if len(exitCopies) == 0 && len(post) == 0 {
		return callStmt, true
	}
	out := []ast.Stmt{callStmt}
	out = append(out, post...)
	for _, ec := range exitCopies {
		out = append(out, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(ec.dst), newID(pairName(ec.dst))},
			Rhs: []ast.Expr{newID(ec.src), newID(pairName(ec.src))},
		})
	}
	return &ast.BlockStmt{List: out}, true
}

// fusedCallParts extracts the call and root variable names from a
// committed window statement.
func fusedCallParts(st ast.Stmt) (*ast.CallExpr, []string, bool) {
	as, ok := st.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return nil, nil, false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil, nil, false
	}
	var roots []string
	for i := 0; i < len(as.Lhs); i += 2 {
		id, ok := as.Lhs[i].(*ast.Ident)
		if !ok {
			return nil, nil, false
		}
		roots = append(roots, id.Name)
	}
	return call, roots, true
}

// fuseConstOf resolves a literal or bound-constant expression.
func (sc *simdScalarizer) fuseConstOf(e ast.Expr) (int32, bool) {
	if c, ok := intConstValue(e); ok {
		return c, true
	}
	if id, ok := e.(*ast.Ident); ok {
		c, ok := sc.constBind[id.Name]
		return c, ok
	}
	return 0, false
}

// fusedLoopDecl builds the loop helper's Go declaration by wrapping
// the region body (reused verbatim from the tree's helper decl) in a
// real for loop: carried pair parameters reassign from their mapped
// nodes, bump scalars advance, the counter decrements, and the final
// values return after the roots.
func fusedLoopDecl(name string, loop *simdfuse.Loop, multiPackage bool) *ast.FuncDecl {
	base := fusedHelperDecl(loop.Tree, multiPackage)
	nodeStmts := base.Body.List[:len(base.Body.List)-1]
	tree := loop.Tree
	sName := func(i int) string { return fmt.Sprintf("s%d", i) }

	params := base.Type.Params.List
	ctrType := "int32"
	if loop.CounterWide {
		ctrType = "int64"
	}
	insertFields := []*ast.Field{{Names: []*ast.Ident{newID(sName(loop.CounterScalar))}, Type: newID(ctrType)}}
	dType := "int32"
	if tree.Addr64 {
		// Addr64 loops bump int64 pointer scalars; the loop-invariant
		// strides ride at the same width.
		dType = "int64"
	}
	for i := 0; i < loop.NumDeltas; i++ {
		insertFields = append(insertFields, &ast.Field{
			Names: []*ast.Ident{newID(fmt.Sprintf("d%d", i))}, Type: newID(dType)})
	}
	insert := 1 + tree.NumScalars
	params = append(params[:insert:insert], append(insertFields, params[insert:]...)...)

	iter := make([]ast.Stmt, 0, len(nodeStmts)+len(loop.CarriedPairs)+len(loop.Bumps)+1)
	iter = append(iter, nodeStmts...)
	for _, cp := range loop.CarriedPairs {
		root := fmt.Sprintf("n%d", cp[1])
		iter = append(iter, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(fmt.Sprintf("p%d", cp[0])), newID(fmt.Sprintf("p%dh", cp[0]))},
			Rhs: []ast.Expr{&ast.IndexExpr{X: newID(root), Index: intLit(0)}, &ast.IndexExpr{X: newID(root), Index: intLit(1)}},
		})
	}
	for _, b := range loop.Bumps {
		step := ast.Expr(intLitSigned(int64(b.Delta)))
		if b.DeltaScalar >= 0 {
			step = newID(fmt.Sprintf("d%d", b.DeltaScalar))
		}
		iter = append(iter, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(sName(b.Scalar))},
			Rhs: []ast.Expr{&ast.BinaryExpr{X: newID(sName(b.Scalar)), Op: token.ADD, Y: step}},
		})
	}
	ctr := newID(sName(loop.CounterScalar))
	iter = append(iter, &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{ctr},
		Rhs: []ast.Expr{&ast.BinaryExpr{X: newID(ctr.Name), Op: token.SUB, Y: intLitSigned(int64(loop.Dec))}},
	})

	uwrap := "uint32"
	if loop.CounterWide {
		uwrap = "uint64"
	}
	u32 := func(e ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID(uwrap), Args: []ast.Expr{e}}
	}
	var forStmt ast.Stmt
	if loop.PreTest {
		forStmt = &ast.ForStmt{
			Cond: &ast.BinaryExpr{X: u32(newID(ctr.Name)), Op: token.GEQ, Y: u32(intLitSigned(int64(loop.Dec)))},
			Body: &ast.BlockStmt{List: iter},
		}
	} else {
		iter = append(iter, &ast.IfStmt{
			Cond: &ast.BinaryExpr{X: newID(ctr.Name), Op: token.EQL, Y: intLit(0)},
			Body: &ast.BlockStmt{List: []ast.Stmt{&ast.BranchStmt{Tok: token.BREAK}}},
		})
		forStmt = &ast.ForStmt{Body: &ast.BlockStmt{List: iter}}
	}

	// Roots must survive the loop: predeclare their carriers and copy
	// on every iteration exit is unnecessary — the node names are
	// loop-scoped, so return values are staged into outer variables.
	var pre, rets []ast.Stmt
	var retVals []ast.Expr
	var results []*ast.Field
	for ri := range tree.RootList() {
		out := fmt.Sprintf("out%d", ri)
		pre = append(pre, &ast.DeclStmt{Decl: &ast.GenDecl{Tok: token.VAR, Specs: []ast.Spec{
			&ast.ValueSpec{Names: []*ast.Ident{newID(out)}, Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")}},
		}}})
		retVals = append(retVals,
			&ast.IndexExpr{X: newID(out), Index: intLit(0)},
			&ast.IndexExpr{X: newID(out), Index: intLit(1)})
		results = append(results, &ast.Field{Type: newID("uint64")}, &ast.Field{Type: newID("uint64")})
	}
	// Place the out-copies inside the iteration (after node stmts).
	var iterList []ast.Stmt
	iterList = append(iterList, iter[:len(nodeStmts)]...)
	for ri, r := range tree.RootList() {
		iterList = append(iterList, &ast.AssignStmt{Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID(fmt.Sprintf("out%d", ri))}, Rhs: []ast.Expr{newID(fmt.Sprintf("n%d", r))}})
	}
	iterList = append(iterList, iter[len(nodeStmts):]...)
	switch fs := forStmt.(type) {
	case *ast.ForStmt:
		fs.Body.List = iterList
	}

	for _, xs := range loop.ExitScalars {
		retVals = append(retVals, newID(sName(xs)))
		rt := "int32"
		if xs == loop.CounterScalar {
			if loop.CounterWide {
				rt = "int64"
			}
		} else if tree.Addr64 {
			// Addr64 exit scalars are the int64 pointer parameters.
			rt = "int64"
		}
		results = append(results, &ast.Field{Type: newID(rt)})
	}
	rets = append(rets, &ast.ReturnStmt{Results: retVals})

	body := append(pre, forStmt)
	body = append(body, rets...)
	return &ast.FuncDecl{
		Doc:  &ast.CommentGroup{List: []*ast.Comment{{Text: "//go:noinline"}}},
		Name: newID(name),
		Type: &ast.FuncType{Params: &ast.FieldList{List: params}, Results: &ast.FieldList{List: results}},
		Body: &ast.BlockStmt{List: body},
	}
}
