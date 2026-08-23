package codegen

// Batched-rows companion for the verified vec_dot (see
// Options.VecDotRows). The mul_mat drivers call the vec_dot once per
// output row through the indirect table; the per-call machinery
// (frame, module-state reloads, reduction epilogue) measures ~20% of
// single-thread decode on the reference workload. The translator
// therefore emits a companion that runs the whole row loop inside
// one call frame:
//
//	func fnNrows(m, a0, a1..a6, rows, xstride) {
//	    for ; rows > 0; rows-- {
//	        l0..l7 := a0..a6, 1     // fresh per-row copies
//	        { <the vec_dot's own emitted body> }
//	        a1 += 4                 // dst advances one float
//	        a3 += xstride           // x advances one row
//	    }
//	}
//
// and rewrites matching driver row loops into one GUARDED companion
// call per chunk; the original loop remains as the guard-miss branch,
// so the transform is semantics-preserving for every runtime type.
// The body is cloned AFTER full emission, so downstream stages (the
// listing transform, SIMD splices, fused loops) treat the companion
// like any other function.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// rowsCompanionName is the companion's Go identifier.
func (t *translator) rowsCompanionName() string {
	return t.funcName(t.nrc2.funcIdx) + "rows"
}

// cloneBlockStmt deep-clones an emitted block via a serialization
// round-trip: print the tree, re-parse it as a function literal.
// Lossless for emitted bodies (they are printed into the bundle
// anyway) and total over every node kind the emitter produces.
func cloneBlockStmt(b *ast.BlockStmt) (*ast.BlockStmt, error) {
	var buf bytes.Buffer
	buf.WriteString("func() ")
	if err := printer.Fprint(&buf, token.NewFileSet(), b); err != nil {
		return nil, fmt.Errorf("clone print: %w", err)
	}
	e, err := parser.ParseExpr(buf.String())
	if err != nil {
		return nil, fmt.Errorf("clone parse: %w", err)
	}
	fl, ok := e.(*ast.FuncLit)
	if !ok {
		return nil, fmt.Errorf("clone: reparse produced %T", e)
	}
	return fl.Body, nil
}

// rewriteReturnsToGoto replaces every return in the statement tree
// with `goto label` and reports whether any replacement happened.
func rewriteReturnsToGoto(list []ast.Stmt, label string) bool {
	used := false
	var walkStmt func(s ast.Stmt) ast.Stmt
	var walkList func(list []ast.Stmt)
	walkStmt = func(s ast.Stmt) ast.Stmt {
		switch x := s.(type) {
		case *ast.ReturnStmt:
			used = true
			return &ast.BranchStmt{Tok: token.GOTO, Label: newID(label)}
		case *ast.BlockStmt:
			walkList(x.List)
		case *ast.LabeledStmt:
			x.Stmt = walkStmt(x.Stmt)
		case *ast.IfStmt:
			walkList(x.Body.List)
			if x.Else != nil {
				x.Else = walkStmt(x.Else)
			}
		case *ast.ForStmt:
			walkList(x.Body.List)
		case *ast.RangeStmt:
			walkList(x.Body.List)
		case *ast.SwitchStmt:
			for _, cc := range x.Body.List {
				if c, ok := cc.(*ast.CaseClause); ok {
					walkList(c.Body)
				}
			}
		}
		return s
	}
	walkList = func(list []ast.Stmt) {
		for i, s := range list {
			list[i] = walkStmt(s)
		}
	}
	walkList(list)
	return used
}

// vecDotRowLoop is one matched driver row loop.
type vecDotRowLoop struct {
	labelIdx int // index of the LabeledStmt in the list
	call     *ast.CallExpr
	idx      *ast.Ident // table index local
	nrc      *ast.Ident // nrc local (call arg, step and bump amounts)
	iter     *ast.Ident // row counter
	iterNext *ast.Ident
	end      *ast.Ident
	x, dst   *ast.Ident // bumped pointer args (args[4] / args[2])
	stride   ast.Expr   // x bump per row with nrc==1
	exit     *ast.Ident // exit label
}

// rewriteVecDotRowLoops walks every statement list in the body and
// rewrites matching row loops with the guarded companion fast path.
func (t *translator) rewriteVecDotRowLoops(body *ast.BlockStmt) {
	var walk func(list []ast.Stmt) []ast.Stmt
	walk = func(list []ast.Stmt) []ast.Stmt {
		for i := 0; i < len(list); i++ {
			switch x := list[i].(type) {
			case *ast.BlockStmt:
				x.List = walk(x.List)
				continue
			case *ast.IfStmt:
				x.Body.List = walk(x.Body.List)
				if eb, ok := x.Else.(*ast.BlockStmt); ok {
					eb.List = walk(eb.List)
				}
				continue
			case *ast.ForStmt:
				x.Body.List = walk(x.Body.List)
				continue
			}
			m, ok := t.matchVecDotRowLoop(list, i)
			if !ok {
				continue
			}
			guard := t.vecDotRowsFastPath(m)
			// Insert the guard right after the label; the original
			// loop statements remain as the guard-miss branch.
			rest := append([]ast.Stmt{guard}, list[i+1:]...)
			list = append(list[:i+1:i+1], rest...)
			i++ // past the inserted guard
		}
		return list
	}
	body.List = walk(body.List)
}

// matchVecDotRowLoop matches the emitted goto-form row loop at
// list[i]:
//
//	LX: m.T0[idx].(sig)(m, n, dst, bs, x, bx, y, by, wrap(nrc))
//	    mBase = m.M
//	    iterNext = iter + nrc
//	    if iterNext < end { iter = iterNext
//	                        x = x + stride*nrc
//	                        dst = dst + nrc<<2
//	                        goto LX } else { goto LEXIT }
func (t *translator) matchVecDotRowLoop(list []ast.Stmt, i int) (*vecDotRowLoop, bool) {
	if i+4 >= len(list) {
		return nil, false
	}
	lab, ok := list[i].(*ast.LabeledStmt)
	if !ok {
		return nil, false
	}
	if _, empty := lab.Stmt.(*ast.EmptyStmt); !empty {
		return nil, false
	}
	// The indirect call.
	es, ok := list[i+1].(*ast.ExprStmt)
	if !ok {
		return nil, false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 9 {
		return nil, false
	}
	ta, ok := call.Fun.(*ast.TypeAssertExpr)
	if !ok {
		return nil, false
	}
	ix, ok := ta.X.(*ast.IndexExpr)
	if !ok {
		return nil, false
	}
	sel, ok := ix.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T0" {
		return nil, false
	}
	idx, ok := ix.Index.(*ast.Ident)
	if !ok {
		return nil, false
	}
	if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "m" {
		return nil, false
	}
	nrc := vecDotUnwrapNrc(call.Args[8])
	dst, dok := call.Args[2].(*ast.Ident)
	x, xok := call.Args[4].(*ast.Ident)
	if nrc == nil || !dok || !xok {
		return nil, false
	}
	// mBase = m.M
	if !isSimpleAssign(list[i+2], "mBase") {
		return nil, false
	}
	// iterNext = iter + nrc
	an, ok := list[i+3].(*ast.AssignStmt)
	if !ok || len(an.Lhs) != 1 || len(an.Rhs) != 1 || an.Tok != token.ASSIGN {
		return nil, false
	}
	iterNext, ok := an.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, false
	}
	step, ok := an.Rhs[0].(*ast.BinaryExpr)
	if !ok || step.Op != token.ADD {
		return nil, false
	}
	iter, ok := step.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	if id, ok := step.Y.(*ast.Ident); !ok || id.Name != nrc.Name {
		return nil, false
	}
	// The backedge if.
	ifs, ok := list[i+4].(*ast.IfStmt)
	if !ok || len(ifs.Body.List) != 4 || ifs.Else == nil {
		return nil, false
	}
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.LSS {
		return nil, false
	}
	if id, ok := cond.X.(*ast.Ident); !ok || id.Name != iterNext.Name {
		return nil, false
	}
	end, ok := cond.Y.(*ast.Ident)
	if !ok {
		return nil, false
	}
	// iter = iterNext
	a0, ok := ifs.Body.List[0].(*ast.AssignStmt)
	if !ok || !identAssignOf(a0, iter.Name, iterNext.Name) {
		return nil, false
	}
	// x = x + stride*nrc
	stride := vecDotBumpStride(ifs.Body.List[1], x.Name, nrc.Name)
	if stride == nil {
		return nil, false
	}
	// dst = dst + nrc<<2
	if !vecDotBumpShl2(ifs.Body.List[2], dst.Name, nrc.Name) {
		return nil, false
	}
	// goto LX / else goto LEXIT
	br, ok := ifs.Body.List[3].(*ast.BranchStmt)
	if !ok || br.Tok != token.GOTO || br.Label.Name != lab.Label.Name {
		return nil, false
	}
	eb, ok := ifs.Else.(*ast.BlockStmt)
	if !ok || len(eb.List) != 1 {
		return nil, false
	}
	ebr, ok := eb.List[0].(*ast.BranchStmt)
	if !ok || ebr.Tok != token.GOTO {
		return nil, false
	}
	// Distinct mutable state keeps the invariance argument sound.
	names := map[string]bool{}
	for _, id := range []*ast.Ident{iter, iterNext, x, dst} {
		if names[id.Name] {
			return nil, false
		}
		names[id.Name] = true
	}
	if names[idx.Name] || names[nrc.Name] || names[end.Name] {
		return nil, false
	}
	return &vecDotRowLoop{
		labelIdx: i, call: call, idx: idx, nrc: nrc,
		iter: iter, iterNext: iterNext, end: end,
		x: x, dst: dst, stride: stride, exit: ebr.Label,
	}, true
}

// rowsCompanionSig is the companion's Go signature (shared by the
// declaration and the cross-chunk linkname forward).
// The boundary is PACKED: m + nine scalars exceeds the amd64
// register ABI, so the arguments ride the per-module outline
// scratch (slots 0..8) and the signature carries only m.
func (t *translator) rowsCompanionSig() *ast.FuncType {
	return &ast.FuncType{Params: &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()},
	}}}
}

// rowsPtrSSAType is the boundary type of the pointer/size_t slots.
func (t *translator) rowsPtrSSAType() ssa.Type {
	if t.mod.Memory64() {
		return ssa.TypeI64
	}
	return ssa.TypeI32
}

// vecDotRowsFastPath builds the guarded one-call replacement.
func (t *translator) vecDotRowsFastPath(m *vecDotRowLoop) ast.Stmt {
	ptrTy := "int32"
	if t.mod.Memory64() {
		ptrTy = "int64"
	}
	conv := func(name string) ast.Expr {
		if ptrTy == "int64" {
			return newID(name)
		}
		return &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{newID(name)}}
	}
	rows := "gcasmRows"
	one := &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{intLit(1)}}
	onePtr := &ast.CallExpr{Fun: newID(ptrTy), Args: []ast.Expr{intLit(1)}}
	pty := t.rowsPtrSSAType()
	slotW := func(i int, arg ast.Expr, typ ssa.Type) ast.Stmt {
		return &ast.AssignStmt{
			Lhs: []ast.Expr{t.packSlot(i)}, Tok: token.ASSIGN,
			Rhs: []ast.Expr{t.packSlotWrite(arg, typ)},
		}
	}
	body := []ast.Stmt{
		// gcasmRows := int64(end - iter)
		&ast.AssignStmt{Lhs: []ast.Expr{newID(rows)}, Tok: token.DEFINE,
			Rhs: []ast.Expr{&ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{
				&ast.BinaryExpr{X: newID(m.end.Name), Op: token.SUB, Y: newID(m.iter.Name)},
			}}}},
		&ast.IfStmt{
			Cond: &ast.BinaryExpr{X: newID(rows), Op: token.LSS, Y: one},
			Body: &ast.BlockStmt{List: []ast.Stmt{
				&ast.AssignStmt{Lhs: []ast.Expr{newID(rows)}, Tok: token.ASSIGN, Rhs: []ast.Expr{one}},
			}},
		},
		slotW(0, m.call.Args[1], ssa.TypeI32),
		slotW(1, m.call.Args[2], pty),
		slotW(2, m.call.Args[3], pty),
		slotW(3, m.call.Args[4], pty),
		slotW(4, m.call.Args[5], pty),
		slotW(5, m.call.Args[6], pty),
		slotW(6, m.call.Args[7], pty),
		slotW(7, newID(rows), ssa.TypeI64),
		slotW(8, m.stride, pty),
		&ast.ExprStmt{X: &ast.CallExpr{Fun: newID(t.rowsCompanionName()), Args: []ast.Expr{newID("m")}}},
		&ast.AssignStmt{Lhs: []ast.Expr{newID("mBase")}, Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID("M")}}},
		// iterNext = iter + rows; iter = iterNext - 1
		&ast.AssignStmt{Lhs: []ast.Expr{newID(m.iterNext.Name)}, Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.BinaryExpr{X: newID(m.iter.Name), Op: token.ADD, Y: conv(rows)}}},
		&ast.AssignStmt{Lhs: []ast.Expr{newID(m.iter.Name)}, Tok: token.ASSIGN,
			Rhs: []ast.Expr{&ast.BinaryExpr{X: newID(m.iterNext.Name), Op: token.SUB, Y: onePtr}}},
		// x += (rows-1)*stride; dst += (rows-1)*4
		&ast.AssignStmt{Lhs: []ast.Expr{newID(m.x.Name)}, Tok: token.ADD_ASSIGN,
			Rhs: []ast.Expr{&ast.BinaryExpr{
				X:  &ast.ParenExpr{X: &ast.BinaryExpr{X: conv(rows), Op: token.SUB, Y: onePtr}},
				Op: token.MUL, Y: &ast.ParenExpr{X: m.stride}}}},
		&ast.AssignStmt{Lhs: []ast.Expr{newID(m.dst.Name)}, Tok: token.ADD_ASSIGN,
			Rhs: []ast.Expr{&ast.BinaryExpr{
				X:  &ast.ParenExpr{X: &ast.BinaryExpr{X: conv(rows), Op: token.SUB, Y: onePtr}},
				Op: token.MUL, Y: &ast.CallExpr{Fun: newID(ptrTy), Args: []ast.Expr{intLit(4)}}}}},
		&ast.BranchStmt{Tok: token.GOTO, Label: newID(m.exit.Name)},
	}
	guard := &ast.BinaryExpr{
		X: &ast.BinaryExpr{X: newID(m.idx.Name), Op: token.EQL,
			Y: &ast.CallExpr{Fun: newID(ptrTy), Args: []ast.Expr{intLit(int64(t.nrc2.tableIdx))}}},
		Op: token.LAND,
		Y:  &ast.BinaryExpr{X: newID(m.nrc.Name), Op: token.EQL, Y: onePtr},
	}
	// Cross-chunk callers need a linkname forward for the synthetic
	// companion (it has no wasm function index of its own).
	if t.multiPackage && t.plan != nil {
		if targetChunk, ok := t.plan.FuncToChunk[t.nrc2.funcIdx]; ok && targetChunk != t.currentChunk {
			t.registerLinknameSymbol(t.currentChunk, t.rowsCompanionName(), targetChunk, t.rowsCompanionSig())
		}
	}
	return &ast.IfStmt{Cond: guard, Body: &ast.BlockStmt{List: body}}
}

// vecDotUnwrapNrc extracts the nrc local from the call's last
// argument (optionally wrapped by the i32 truncation helper).
func vecDotUnwrapNrc(e ast.Expr) *ast.Ident {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
		if helperName(c.Fun) == "I32_wrap_i64" {
			e = c.Args[0]
		}
	}
	id, _ := e.(*ast.Ident)
	return id
}

// isSimpleAssign matches `<name> = m.M`.
func isSimpleAssign(s ast.Stmt, name string) bool {
	a, ok := s.(*ast.AssignStmt)
	if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Tok != token.ASSIGN {
		return false
	}
	l, ok := a.Lhs[0].(*ast.Ident)
	if !ok || l.Name != name {
		return false
	}
	sel, ok := a.Rhs[0].(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "M" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "m"
}

// identAssignOf matches `<lhs> = <rhs>` between plain idents.
func identAssignOf(a *ast.AssignStmt, lhs, rhs string) bool {
	if len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Tok != token.ASSIGN {
		return false
	}
	l, lok := a.Lhs[0].(*ast.Ident)
	r, rok := a.Rhs[0].(*ast.Ident)
	return lok && rok && l.Name == lhs && r.Name == rhs
}

// vecDotBumpStride matches `x = x + stride*nrc` (mul either order)
// and returns the stride expression.
func vecDotBumpStride(s ast.Stmt, x, nrc string) ast.Expr {
	a, ok := s.(*ast.AssignStmt)
	if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Tok != token.ASSIGN {
		return nil
	}
	if l, ok := a.Lhs[0].(*ast.Ident); !ok || l.Name != x {
		return nil
	}
	add, ok := a.Rhs[0].(*ast.BinaryExpr)
	if !ok || add.Op != token.ADD {
		return nil
	}
	if l, ok := add.X.(*ast.Ident); !ok || l.Name != x {
		return nil
	}
	mul, ok := add.Y.(*ast.BinaryExpr)
	if !ok || mul.Op != token.MUL {
		return nil
	}
	lm, lok := mul.X.(*ast.Ident)
	rm, rok := mul.Y.(*ast.Ident)
	switch {
	case lok && lm.Name == nrc:
		return mul.Y
	case rok && rm.Name == nrc:
		return mul.X
	}
	return nil
}

// vecDotBumpShl2 matches `dst = dst + nrc<<2` with the emitter's
// masked shift-count spelling.
func vecDotBumpShl2(s ast.Stmt, dst, nrc string) bool {
	a, ok := s.(*ast.AssignStmt)
	if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Tok != token.ASSIGN {
		return false
	}
	if l, ok := a.Lhs[0].(*ast.Ident); !ok || l.Name != dst {
		return false
	}
	add, ok := a.Rhs[0].(*ast.BinaryExpr)
	if !ok || add.Op != token.ADD {
		return false
	}
	if l, ok := add.X.(*ast.Ident); !ok || l.Name != dst {
		return false
	}
	shl, ok := add.Y.(*ast.BinaryExpr)
	if !ok || shl.Op != token.SHL {
		return false
	}
	if l, ok := shl.X.(*ast.Ident); !ok || l.Name != nrc {
		return false
	}
	c, ok := vecDotShiftConst(shl.Y)
	return ok && c == 2
}

// vecDotShiftConst reduces the emitter's shift-count spellings
// (`uint(int64(2))%64`, `uint(2)%32`, bare literals) to a constant.
func vecDotShiftConst(e ast.Expr) (int64, bool) {
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.REM {
		e = b.X
	}
	for {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			break
		}
		id, ok := c.Fun.(*ast.Ident)
		if !ok {
			break
		}
		switch id.Name {
		case "uint", "uint32", "uint64", "int32", "int64":
			e = c.Args[0]
		default:
			return 0, false
		}
	}
	if v, ok := intConstValue(e); ok {
		return int64(v), true
	}
	return 0, false
}

// rowsCompanion builds the companion declaration around a clone of
// the vec_dot's emitted body.
func (t *translator) rowsCompanion(bodyClone *ast.BlockStmt) *ast.FuncDecl {
	ptrTy := "int32"
	if t.mod.Memory64() {
		ptrTy = "int64"
	}
	sig := t.rowsCompanionSig()
	pty := t.rowsPtrSSAType()
	var unpack []ast.Stmt
	def := func(name string, e ast.Expr) {
		unpack = append(unpack, &ast.AssignStmt{
			Lhs: []ast.Expr{newID(name)}, Tok: token.DEFINE, Rhs: []ast.Expr{e},
		})
	}
	def("a0", t.packSlotRead(0, ssa.TypeI32))
	for i := 1; i <= 6; i++ {
		def(fmt.Sprintf("a%d", i), t.packSlotRead(i, pty))
	}
	def("rows", t.packSlotRead(7, ssa.TypeI64))
	def("xstride", t.packSlotRead(8, pty))

	const contLabel = "gcasmRowsCont"
	returned := rewriteReturnsToGoto(bodyClone.List, contLabel)

	// Per-row parameter copies: the body may mutate its locals, and
	// wasm locals re-initialize per call, so every row gets fresh
	// copies (the body's own var decls sit inside the loop block and
	// re-zero the same way).
	var lhs, rhs []ast.Expr
	for i := 0; i <= 6; i++ {
		lhs = append(lhs, newID(fmt.Sprintf("l%d", i)))
		rhs = append(rhs, newID(fmt.Sprintf("a%d", i)))
	}
	lhs = append(lhs, newID("l7"))
	rhs = append(rhs, &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{intLit(1)}})
	loopBody := []ast.Stmt{
		&ast.AssignStmt{Lhs: lhs, Tok: token.DEFINE, Rhs: rhs},
	}
	for i := 0; i <= 7; i++ {
		loopBody = append(loopBody, &ast.AssignStmt{
			Lhs: []ast.Expr{newID("_")}, Tok: token.ASSIGN,
			Rhs: []ast.Expr{newID(fmt.Sprintf("l%d", i))},
		})
	}
	loopBody = append(loopBody, bodyClone)
	if returned {
		loopBody = append(loopBody, &ast.LabeledStmt{
			Label: newID(contLabel), Stmt: &ast.EmptyStmt{},
		})
	}
	dstStep := &ast.CallExpr{Fun: newID(ptrTy), Args: []ast.Expr{intLit(4)}}
	loopBody = append(loopBody,
		&ast.AssignStmt{Lhs: []ast.Expr{newID("a1")}, Tok: token.ADD_ASSIGN, Rhs: []ast.Expr{dstStep}},
		&ast.AssignStmt{Lhs: []ast.Expr{newID("a3")}, Tok: token.ADD_ASSIGN, Rhs: []ast.Expr{newID("xstride")}},
	)

	loop := &ast.ForStmt{
		Cond: &ast.BinaryExpr{
			X: newID("rows"), Op: token.GTR,
			Y: &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{intLit(0)}},
		},
		Post: &ast.IncDecStmt{X: newID("rows"), Tok: token.DEC},
		Body: &ast.BlockStmt{List: loopBody},
	}
	// Ride the synthetic-signature channel so the asm bundle captures
	// and transforms the companion like an outlined function (SIMD
	// splices and fused loops then apply inside the row loop).
	ptrVT := wasm.ValI32
	if t.mod.Memory64() {
		ptrVT = wasm.ValI64
	}
	sigParams := []wasm.ValType{wasm.ValI32}
	for i := 0; i < 6; i++ {
		sigParams = append(sigParams, ptrVT)
	}
	sigParams = append(sigParams, wasm.ValI64, ptrVT)
	if t.outlinedSigs == nil {
		t.outlinedSigs = map[string]OutlinedSig{}
	}
	t.outlinedSigs[t.rowsCompanionName()] = OutlinedSig{Params: sigParams, Packed: true}
	return &ast.FuncDecl{
		Name: newID(t.rowsCompanionName()),
		Type: sig,
		Body: &ast.BlockStmt{List: append(unpack, loop)},
	}
}
