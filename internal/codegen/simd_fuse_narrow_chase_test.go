package codegen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// parseExprT parses a single Go expression.
func parseExprT(t *testing.T, src string) ast.Expr {
	t.Helper()
	e, err := parser.ParseExpr(src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return e
}

// parseStmts parses a function body into its statement list.
func parseStmts(t *testing.T, body string) []ast.Stmt {
	t.Helper()
	src := "package p\nfunc f() {\n" + body + "\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return file.Decls[0].(*ast.FuncDecl).Body.List
}

// narrowFB builds a builder with one intervener definition: a 64-bit
// linear-memory load of the pointer local p.
func narrowFB(t *testing.T) *fusedTreeBuilder {
	t.Helper()
	def := parseStmts(t, "v = *(*int64)(unsafe.Add(mBase, uint64(p)))")[0].(*ast.AssignStmt)
	return &fusedTreeBuilder{
		sc:        &simdScalarizer{},
		wideChase: true,
		interDef:  map[string]*ast.AssignStmt{"v": def},
	}
}

func loadNodeOf(t *testing.T, fb *fusedTreeBuilder, arg simdfuse.Arg) simdfuse.Node {
	t.Helper()
	if arg.Kind != simdfuse.ArgNode {
		t.Fatalf("want node arg, got kind=%d", arg.Kind)
	}
	n := fb.nodes[arg.Index]
	if n.Op != "scalar_i32_load16_u" {
		t.Fatalf("want scalar_i32_load16_u, got %s", n.Op)
	}
	return n
}

func TestChaseNarrowExtract16LowHalfword(t *testing.T) {
	fb := narrowFB(t)
	arg, ok := fb.chaseNarrowExtract16(parseExprT(t, "v & 65535").(*ast.BinaryExpr))
	if !ok {
		t.Fatal("low-halfword extract not narrowed")
	}
	n := loadNodeOf(t, fb, arg)
	if a := n.Args[0]; a.Kind != simdfuse.ArgScalar || a.Const != 0 {
		t.Fatalf("addr arg: %+v", a)
	}
	if fb.chaseUses["v"] != 1 {
		t.Fatalf("intervener consumption not recorded: %v", fb.chaseUses)
	}
}

func TestChaseNarrowExtract16ShiftedLanes(t *testing.T) {
	for _, tc := range []struct {
		src string
		off int32
	}{
		{"(v >> 16) & 65535", 2},
		{"(v >> 32) & 65535", 4},
		{"(v >> 48) & 65535", 6},
		// The pointer-width conversion wrapper around the mask and the
		// swapped operand order both appear in emitted code.
		{"(v >> 16) & int64(65535)", 2},
		{"int64(65535) & (v >> 16)", 2},
	} {
		fb := narrowFB(t)
		arg, ok := fb.chaseNarrowExtract16(parseExprT(t, tc.src).(*ast.BinaryExpr))
		if !ok {
			t.Fatalf("%s: not narrowed", tc.src)
		}
		n := loadNodeOf(t, fb, arg)
		if a := n.Args[0]; a.Kind != simdfuse.ArgSum || a.Const != tc.off {
			t.Fatalf("%s: addr arg %+v, want sum +%d", tc.src, a, tc.off)
		}
	}
}

func TestChaseNarrowExtract16Rejections(t *testing.T) {
	for _, src := range []string{
		"v & 255",           // mask narrower than a halfword
		"v & 131071",        // mask wider than a halfword
		"(v >> 15) & 65535", // not byte-aligned
		"(v >> 56) & 65535", // extract crosses the load's top
		"w & 65535",         // base is not a chaseable definition
		"(v >> s) & 65535",  // variable shift amount
	} {
		fb := narrowFB(t)
		if _, ok := fb.chaseNarrowExtract16(parseExprT(t, src).(*ast.BinaryExpr)); ok {
			t.Fatalf("%s: unexpectedly narrowed", src)
		}
		if len(fb.chaseUses) != 0 {
			t.Fatalf("%s: rejection leaked consumption: %v", src, fb.chaseUses)
		}
	}
}

func TestIdentWritesSeesNestedAssignments(t *testing.T) {
	w := identWrites(parseStmts(t, `
	a = 1
	if cond {
		b = 2
		if deeper {
			c = 3
		}
	} else {
		d = 4
	}
	for {
		e = 5
	}`))
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		if !w[name] {
			t.Fatalf("write to %s not seen: %v", name, w)
		}
	}
	if w["cond"] || w["deeper"] {
		t.Fatalf("reads misclassified as writes: %v", w)
	}
}
