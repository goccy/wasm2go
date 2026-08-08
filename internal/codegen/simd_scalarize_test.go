package codegen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestCountCarryLoopReads(t *testing.T) {
	src := `package p

func f() {
	a := 0
	b := 0
	for {
		x := a + 1
		y := x + b
		b = y
		a = a + 4
	}
	sink(b)
	for {
		x := a + 2
		_ = x
	}
}`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "t.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := file.Decls[0].(*ast.FuncDecl).Body
	reads, inCarry := countCarryLoopReads(body)
	// x: defined then read inside a loop that writes it → confined
	// (the clone-internality precondition).
	if reads["x"] != inCarry["x"] {
		t.Errorf("x: reads=%d inCarry=%d, want equal (clone-confined)", reads["x"], inCarry["x"])
	}
	// b: read after the loop (sink) → NOT confined.
	if reads["b"] == inCarry["b"] {
		t.Errorf("b: reads=%d inCarry=%d, want a free read (post-loop sink)", reads["b"], inCarry["b"])
	}
	// a: the second loop reads it but does not write it → those reads
	// must not be attributed.
	if reads["a"] == inCarry["a"] {
		t.Errorf("a: reads=%d inCarry=%d, want unattributed reads (second loop does not write a)", reads["a"], inCarry["a"])
	}
}

func TestCountCarryLoopReadsReadBeforeDef(t *testing.T) {
	// A read that precedes the same iteration's definition (first
	// iteration observes the outside value) must NOT be attributed:
	// internalizing elsewhere would change what it observes.
	src := `package p

func f() {
	v := 0
	for {
		u := v + 1
		v = u
	}
}`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "t.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := file.Decls[0].(*ast.FuncDecl).Body
	reads, inCarry := countCarryLoopReads(body)
	if inCarry["v"] != 0 {
		t.Errorf("v: inCarry=%d, want 0 (read precedes the iteration's def)", inCarry["v"])
	}
	if reads["v"] == 0 {
		t.Error("v: expected reads counted")
	}
}
