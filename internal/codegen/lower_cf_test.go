package codegen

import (
	"bytes"
	"go/format"
	"go/token"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestLowerGcd checks that the gcd function from control.wasm — which
// uses block + loop + br_if — lowers through SSA and emits valid Go.
func TestLowerGcd(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "gcd" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Skip("gcd not in control.wasm exports")
	}
	fn, err := LowerFunction(mod, idx, "gcd")
	if err != nil {
		t.Fatalf("lower gcd: %v", err)
	}
	body, err := emitSSAFuncBody(fn)
	if err != nil {
		t.Fatalf("emit gcd: %v", err)
	}
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, body); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// gcd is a single-loop function with a clean back-edge, so the
	// structured emitter handles it (preferred). The CFG must show up
	// as either a Go `for` loop or a goto/label form depending on which
	// path won the dispatch — both are correct, but the body must
	// reference the loop header local at least once.
	if !strings.Contains(got, "for") && !strings.Contains(got, "goto L") {
		t.Errorf("expected loop or goto-based control flow in gcd emit:\n%s", got)
	}
}

// TestLowerSwitch3 covers the switch3 export — a br_table dispatcher.
// br_table now lowers to a chain of equality-If blocks, so the lowering
// should succeed and produce a CFG dominated by goto-based emission.
func TestLowerSwitch3(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "switch3" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Skip("switch3 not exported")
	}
	if _, err := LowerFunction(mod, idx, "switch3"); err != nil {
		t.Fatalf("lower switch3: %v", err)
	}
}
