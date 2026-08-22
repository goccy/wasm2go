package codegen

import (
	"go/ast"
	"go/parser"
	"strconv"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

func mustExpr(t *testing.T, src string) ast.Expr {
	t.Helper()
	e, err := parser.ParseExpr(src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return unparen(e)
}

// unparen removes ParenExpr nodes the parser introduces for grouping;
// the emitter's ASTs never contain them (precedence is structural).
func unparen(e ast.Expr) ast.Expr {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return unparen(x.X)
	case *ast.BinaryExpr:
		x.X, x.Y = unparen(x.X), unparen(x.Y)
	case *ast.CallExpr:
		for i := range x.Args {
			x.Args[i] = unparen(x.Args[i])
		}
	case *ast.StarExpr:
		x.X = unparen(x.X)
	case *ast.UnaryExpr:
		x.X = unparen(x.X)
	}
	return e
}

func TestF16WordLaneMatch(t *testing.T) {
	fb := &fusedTreeBuilder{sc: &simdScalarizer{constBind: map[string]int32{}}}

	// Lane 0: (w & 0xffff) << 2, in the emitter's masked-shift spelling.
	name, tadd, ok := fb.f16WordLane(mustExpr(t, "int64(v9&65535<<(uint(2)%64))"), 0)
	if !ok || name != "v9" || tadd != 0 {
		t.Fatalf("lane0: got name=%q tadd=%d ok=%v", name, tadd, ok)
	}

	// Lanes 1..3: ((w >>u (16k-2)) & 0x3fffc) + table, with the
	// unsigned-view helper around the word.
	for lane, shift := range map[int]int{1: 14, 2: 30, 3: 46} {
		src := "int64(int64(base.Ui64(v9)>>(uint(" + strconv.Itoa(shift) + ")%64))&262140 + 8798416)"
		name, tadd, ok := fb.f16WordLane(mustExpr(t, src), lane)
		if !ok || name != "v9" || tadd != 8798416 {
			t.Fatalf("lane%d: got name=%q tadd=%d ok=%v", lane, name, tadd, ok)
		}
	}

	// Wrong shift for the lane must not match.
	if _, _, ok := fb.f16WordLane(mustExpr(t, "int64(int64(base.Ui64(v9)>>(uint(30)%64))&262140+8798416)"), 1); ok {
		t.Fatal("lane1 with lane2's shift matched")
	}
	// A mask that does not select exactly halfword*4 must not match.
	if _, _, ok := fb.f16WordLane(mustExpr(t, "int64(int64(base.Ui64(v9)>>(uint(14)%64))&262136+8798416)"), 1); ok {
		t.Fatal("wrong mask matched")
	}
	// Lane 0 with a short mask must not match.
	if _, _, ok := fb.f16WordLane(mustExpr(t, "int64(v9&32767<<(uint(2)%64))"), 0); ok {
		t.Fatal("short lane0 mask matched")
	}
	// Lane 0 with a wrong shift must not match.
	if _, _, ok := fb.f16WordLane(mustExpr(t, "int64(v9&65535<<(uint(3)%64))"), 0); ok {
		t.Fatal("lane0 shl3 matched")
	}
}

func TestArgOffsetByAddPeel(t *testing.T) {
	// Node 0: an opaque load; node 1: node0 + 4; node 2: node0 + 6.
	fb := &fusedTreeBuilder{}
	fb.nodes = []simdfuse.Node{
		{Op: "scalar_i32_load16_u", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 0}}},
		{Op: "scalar_i32_add", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: 0}, {Kind: simdfuse.ArgConst, Const: 4}}},
		{Op: "scalar_i32_add", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: 0}, {Kind: simdfuse.ArgConst, Const: 6}}},
	}
	bare := simdfuse.Arg{Kind: simdfuse.ArgNode, Index: 0}
	plus4 := simdfuse.Arg{Kind: simdfuse.ArgNode, Index: 1}
	plus6 := simdfuse.Arg{Kind: simdfuse.ArgNode, Index: 2}

	// Bare base vs peeled add: node/node with differing ops.
	if !fb.argOffsetBy(bare, plus4, 4) {
		t.Fatal("bare vs base+4 with delta 4 not proven")
	}
	if fb.argOffsetBy(bare, plus4, 2) {
		t.Fatal("bare vs base+4 with delta 2 wrongly proven")
	}
	// Two peeled adds against each other: both sides peel.
	if !fb.argOffsetBy(plus4, plus6, 2) {
		t.Fatal("base+4 vs base+6 with delta 2 not proven")
	}
	// Reverse direction carries a negative delta.
	if !fb.argOffsetBy(plus6, plus4, -2) {
		t.Fatal("base+6 vs base+4 with delta -2 not proven")
	}
	// Scalar vs peeled-node forms.
	sc := simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: 0}
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: "scalar_i32_add", Args: []simdfuse.Arg{
		{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 2}}})
	scPlus2 := simdfuse.Arg{Kind: simdfuse.ArgNode, Index: 3}
	if !fb.argOffsetBy(sc, scPlus2, 2) {
		t.Fatal("scalar vs scalar+2 node with delta 2 not proven")
	}
	if !fb.argOffsetBy(scPlus2, sc, -2) {
		t.Fatal("scalar+2 node vs scalar with delta -2 not proven")
	}
}

func TestWordOperandIdent(t *testing.T) {
	if n, ok := wordOperandIdent(mustExpr(t, "v3140")); !ok || n != "v3140" {
		t.Fatalf("plain ident: %q %v", n, ok)
	}
	if n, ok := wordOperandIdent(mustExpr(t, "base.Ui64(v3140)")); !ok || n != "v3140" {
		t.Fatalf("Ui64 wrap: %q %v", n, ok)
	}
	if n, ok := wordOperandIdent(mustExpr(t, "uint64(int64(v7))")); !ok || n != "v7" {
		t.Fatalf("conversion wraps: %q %v", n, ok)
	}
	if _, ok := wordOperandIdent(mustExpr(t, "v1+v2")); ok {
		t.Fatal("binary expr accepted as word operand")
	}
}

