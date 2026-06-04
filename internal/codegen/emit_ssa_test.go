package codegen

import (
	"bytes"
	"go/format"
	"go/token"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestEmitSSAFuncBody round-trips the arith.wasm "add" function through
// LowerFunction + emitSSAFuncBody and renders the result. The expected
// Go source is small enough to spell out as a golden literal.
func TestEmitSSAFuncBody(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	addIdx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "add" {
			addIdx = e.Index
			break
		}
	}
	if addIdx == ^uint32(0) {
		t.Fatalf("missing add export")
	}
	ssaFn, err := lower.LowerFunction(mod, addIdx, "add")
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	body, err := emitSSAFuncBody(ssaFn)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	// Render to source with go/format for stable output.
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, body); err != nil {
		t.Fatalf("format: %v", err)
	}
	got := buf.String()

	// add: return l0 + l1 (params materialise as l0, l1).
	if !strings.Contains(got, "return l0 + l1") {
		t.Errorf("emitted body does not contain `return l0 + l1`:\n%s", got)
	}
}

// TestEmitSSAComparison checks that the lt_u export (an unsigned
// comparison) emits the uint-cast + boolean-to-int32 idiom.
func TestEmitSSAComparison(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "lt_u" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Skip("lt_u not exported")
	}
	ssaFn, err := lower.LowerFunction(mod, idx, "lt_u")
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	body, err := emitSSAFuncBody(ssaFn)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, body); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// Unsigned comparison routes through the ui32 helper (function-call
	// boundary) so Go's constant rules don't reject negative i32 const
	// operands cast to uint32 directly.
	if !strings.Contains(got, "ui32(l0) < ui32(l1)") {
		t.Errorf("lt_u missing ui32 helper cast:\n%s", got)
	}
	if !strings.Contains(got, "return 1") || !strings.Contains(got, "return 0") {
		t.Errorf("lt_u missing bool→i32 wrapping:\n%s", got)
	}
}
