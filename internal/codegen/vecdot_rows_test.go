package codegen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func mustStmts(t *testing.T, body string) []ast.Stmt {
	t.Helper()
	e, err := parser.ParseExpr("func() {\n" + body + "\n}")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	list := e.(*ast.FuncLit).Body.List
	unparenStmts(list)
	return list
}

// unparenStmts strips the grouping ParenExpr nodes the parser
// introduces; the emitter's ASTs never contain them.
func unparenStmts(list []ast.Stmt) {
	for _, s := range list {
		switch x := s.(type) {
		case *ast.ExprStmt:
			x.X = unparen(x.X)
		case *ast.AssignStmt:
			for i := range x.Rhs {
				x.Rhs[i] = unparen(x.Rhs[i])
			}
		case *ast.IfStmt:
			x.Cond = unparen(x.Cond)
			unparenStmts(x.Body.List)
			if eb, ok := x.Else.(*ast.BlockStmt); ok {
				unparenStmts(eb.List)
			}
		case *ast.ForStmt:
			unparenStmts(x.Body.List)
		}
	}
}

func TestMatchVecDotRowLoop(t *testing.T) {
	tr := &translator{}
	src := `
L269:
	;
	m.T0[v3176].(func(*base.Module, int32, int64, int64, int64, int64, int64, int64, int32))(m, v3131, v3549, v3251, v3547, v3248, v3538+v3231, v3246, base.I32_wrap_i64(v3170))
	mBase = m.M
	v3624 = v3546 + v3170
	if v3624 < v3430 {
		v3546 = v3624
		v3547 = v3547 + v3127*v3170
		v3549 = v3549 + v3170<<(uint(int64(2))%64)
		goto L269
	} else {
		goto L271
	}`
	list := mustStmts(t, src)
	m, ok := tr.matchVecDotRowLoop(list, 0)
	if !ok {
		t.Fatal("row loop not matched")
	}
	if m.idx.Name != "v3176" || m.nrc.Name != "v3170" || m.iter.Name != "v3546" ||
		m.iterNext.Name != "v3624" || m.end.Name != "v3430" ||
		m.x.Name != "v3547" || m.dst.Name != "v3549" || m.exit.Name != "L271" {
		t.Fatalf("wrong extraction: %+v", m)
	}
	if id, ok := m.stride.(*ast.Ident); !ok || id.Name != "v3127" {
		t.Fatalf("wrong stride: %v", m.stride)
	}

	// A loop whose x bump does not scale by nrc must not match.
	bad := mustStmts(t, `
L1:
	;
	m.T0[v1].(func(*base.Module, int32, int64, int64, int64, int64, int64, int64, int32))(m, v2, v3, v4, v5, v6, v7, v8, base.I32_wrap_i64(v9))
	mBase = m.M
	v10 = v11 + v9
	if v10 < v12 {
		v11 = v10
		v5 = v5 + v13*v14
		v3 = v3 + v9<<(uint(int64(2))%64)
		goto L1
	} else {
		goto L2
	}`)
	if _, ok := tr.matchVecDotRowLoop(bad, 0); ok {
		t.Fatal("non-nrc stride matched")
	}
	// A dst bump with a different shift must not match.
	bad2 := mustStmts(t, `
L1:
	;
	m.T0[v1].(func(*base.Module, int32, int64, int64, int64, int64, int64, int64, int32))(m, v2, v3, v4, v5, v6, v7, v8, base.I32_wrap_i64(v9))
	mBase = m.M
	v10 = v11 + v9
	if v10 < v12 {
		v11 = v10
		v5 = v5 + v13*v9
		v3 = v3 + v9<<(uint(int64(3))%64)
		goto L1
	} else {
		goto L2
	}`)
	if _, ok := tr.matchVecDotRowLoop(bad2, 0); ok {
		t.Fatal("shl3 dst bump matched")
	}
}

func TestRewriteReturnsToGoto(t *testing.T) {
	list := mustStmts(t, `
	if v1 == 0 {
		return
	}
	v2 = v1
	for {
		if v2 > 3 {
			return
		}
		v2++
	}`)
	if !rewriteReturnsToGoto(list, "cont") {
		t.Fatal("no returns rewritten")
	}
	count := 0
	ast.Inspect(&ast.BlockStmt{List: list}, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ReturnStmt:
			t.Fatal("return survived")
		case *ast.BranchStmt:
			if x.Tok == token.GOTO && x.Label.Name == "cont" {
				count++
			}
		}
		return true
	})
	if count != 2 {
		t.Fatalf("got %d gotos, want 2", count)
	}
	// No returns → no label needed.
	if rewriteReturnsToGoto(mustStmts(t, "v1 = v2"), "cont") {
		t.Fatal("phantom rewrite")
	}
}

func TestVecDotShiftConst(t *testing.T) {
	for src, want := range map[string]int64{
		"uint(int64(2)) % 64": 2,
		"uint(2) % 32":        2,
		"2":                   2,
	} {
		e, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		got, ok := vecDotShiftConst(e)
		if !ok || got != want {
			t.Fatalf("%q: got %d/%v want %d", src, got, ok, want)
		}
	}
}
