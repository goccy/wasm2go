package codegen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseFor extracts the first ForStmt from a function body source.
func parseFor(t *testing.T, body string) *ast.ForStmt {
	t.Helper()
	src := "package p\nfunc f() {\n" + body + "\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out *ast.ForStmt
	ast.Inspect(file, func(n ast.Node) bool {
		if f, ok := n.(*ast.ForStmt); ok && out == nil {
			out = f
		}
		return out == nil
	})
	if out == nil {
		t.Fatal("no for statement")
	}
	return out
}

func TestMatchCountdownLoopDoWhile(t *testing.T) {
	f := parseFor(t, `
	for {
		acc = acc + x
		d = c - 1
		if d != 0 {
			p = p + 16
			c = d
			continue
		} else {
			break
		}
		break
	}`)
	cl, ok := matchCountdownLoop(nil, f)
	if !ok {
		t.Fatal("do-while countdown not matched")
	}
	if cl.counter.Name != "c" || cl.decVar.Name != "d" || cl.wide {
		t.Fatalf("bound wrong: counter=%s dec=%s wide=%v", cl.counter.Name, cl.decVar.Name, cl.wide)
	}
	if len(cl.bumps) != 1 || len(cl.body) != 1 {
		t.Fatalf("bumps=%d body=%d", len(cl.bumps), len(cl.body))
	}
}

func TestMatchCountdownLoopDoWhileWide(t *testing.T) {
	f := parseFor(t, `
	for {
		acc = acc + x
		d = c - int64(1)
		if d != int64(0) {
			c = d
			continue
		} else {
			break
		}
		break
	}`)
	cl, ok := matchCountdownLoop(nil, f)
	if !ok {
		t.Fatal("int64 countdown not matched")
	}
	if !cl.wide {
		t.Fatal("wide counter not detected")
	}
}

func TestMatchCountdownLoopHeaderForm(t *testing.T) {
	f := parseFor(t, `
	for {
		if Ui32(c) < Ui32(4) {
			break
		} else {
			sink(acc)
			p = p + 16
			c = c - 1
			continue
		}
	}`)
	cl, ok := matchCountdownLoop(nil, f)
	if !ok {
		t.Fatal("header-form countdown not matched")
	}
	if cl.decVar != nil || cl.counter.Name != "c" {
		t.Fatalf("bound wrong: %+v", cl)
	}
}

func TestMatchCountdownLoopDoWhileFloor(t *testing.T) {
	// Rotated count-down-to-K source loops exit on `K < d` (or the
	// mirrored `d > K`) instead of `d != 0`; the floor rides the
	// descriptor as a signed threshold.
	for name, src := range map[string]string{
		"const lit floor": `
	for {
		acc = acc + x
		d = c - 1
		if 1 < d {
			p = p + 16
			c = d
			continue
		} else {
			break
		}
		break
	}`,
		"const local floor": `
	for {
		acc = acc + x
		k = 1
		d = c - k
		if k < d {
			p = p + 16
			c = d
			continue
		} else {
			break
		}
		break
	}`,
		"mirrored gtr floor": `
	for {
		acc = acc + x
		d = c - 1
		if d > 1 {
			p = p + 16
			c = d
			continue
		} else {
			break
		}
		break
	}`,
	} {
		cl, ok := matchCountdownLoop(nil, parseFor(t, src))
		if !ok {
			t.Errorf("%s: floor countdown not matched", name)
			continue
		}
		if cl.thresh == nil {
			t.Errorf("%s: threshold not recorded", name)
		}
		if cl.counter.Name != "c" || cl.decVar.Name != "d" {
			t.Errorf("%s: bound wrong: counter=%s dec=%s", name, cl.counter.Name, cl.decVar.Name)
		}
	}
}

func TestMatchCountdownLoopRejections(t *testing.T) {
	cases := map[string]string{
		"three-part for": `for i = 0; i < n; i = i + 1 { acc = acc + x }`,
		"no counter reset": `
	for {
		acc = acc + x
		d = c - 1
		if d != 0 {
			p = p + 16
			continue
		} else {
			break
		}
		break
	}`,
		"call in continue arm": `
	for {
		acc = acc + x
		d = c - 1
		if d != 0 {
			g()
			c = d
			continue
		} else {
			break
		}
		break
	}`,
		"non-sub decrement": `
	for {
		acc = acc + x
		d = c + 1
		if d != 0 {
			c = d
			continue
		} else {
			break
		}
		break
	}`,
		"header guard shape": `
	for {
		if c == 0 {
			break
		} else {
			acc = acc + x
			c = c - 1
		}
	}`,
		"count-up guard (decVar left of lss)": `
	for {
		acc = acc + x
		d = c - 1
		if d < 8 {
			c = d
			continue
		} else {
			break
		}
		break
	}`,
	}
	for name, src := range cases {
		if _, ok := matchCountdownLoop(nil, parseFor(t, src)); ok {
			t.Errorf("%s: unexpectedly matched", name)
		}
	}
}

func TestBlankFor(t *testing.T) {
	out := blankFor(3)
	if len(out) != 3 {
		t.Fatalf("len=%d", len(out))
	}
	for _, e := range out {
		if id, ok := e.(*ast.Ident); !ok || id.Name != "_" {
			t.Fatalf("not a blank ident: %#v", e)
		}
	}
}
