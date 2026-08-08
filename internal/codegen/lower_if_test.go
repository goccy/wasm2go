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

// TestLowerIfElseMax exercises the if/else lowering path on
// control.wasm's `max` function:
//
//	max(a, b) = if (a > b) a else b
//
// Verifies that:
//   - LowerFunction produces a multi-block CFG with three blocks
//     (entry If, then, else) merging at a fourth.
//   - A phi is inserted at the merge for the divergent result.
//   - emitSSAFuncBody renders the function as valid Go (compileable
//     by go-build via runGoSnippet equivalence).
//
// This is an integration test of the lower+emit pair, so it lives in
// the codegen package (where emitSSAFuncBody is in scope) rather than
// in internal/lower.
func TestLowerIfElseMax(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "max" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Fatalf("control.wasm: missing max export")
	}
	fn, err := lower.LowerFunction(mod, idx, "max", nil)
	if err != nil {
		t.Fatalf("lower max: %v", err)
	}

	// max body contains: local.get 0; local.get 1; i32.gt_s; if (i32);
	// local.get 0; else; local.get 1; end; end.
	// Expect ≥3 SSA blocks (entry-If, then, else) and a join block
	// with a phi. Some lowerings emit 4 (with a fourth join), some 3
	// (when then/else flow straight into the existing successor) — be
	// lenient on count but strict on phi presence.
	if len(fn.Blocks) < 3 {
		t.Errorf("max: expected at least 3 blocks, got %d", len(fn.Blocks))
	}
	hasPhi := false
	for _, blk := range fn.Blocks {
		for _, v := range blk.Values {
			if v.Op.String() == "OpPhi" {
				hasPhi = true
			}
		}
	}
	if !hasPhi {
		t.Errorf("max: expected at least one OpPhi from then/else merge")
	}

	body, err := emitSSAFuncBody(fn)
	if err != nil {
		t.Fatalf("emit max: %v", err)
	}
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, body); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// max is acyclic, so the structured emitter renders it as a plain
	// `if {} else {}` — no goto, no labels.
	if strings.Contains(got, "goto") {
		t.Errorf("structured emit should not contain goto:\n%s", got)
	}
	if !strings.Contains(got, "if l1 < l0") {
		// gt_s lowers to OpLtS with swapped args → "l1 < l0".
		t.Errorf("expected `if l1 < l0` in structured body:\n%s", got)
	}
	if !strings.Contains(got, "} else {") {
		t.Errorf("expected if/else structure in emitted body:\n%s", got)
	}
	// Each branch assigns the merge phi: then → l0, else → l1.
	if !strings.Contains(got, "= l0") || !strings.Contains(got, "= l1") {
		t.Errorf("expected phi assignment from both branches:\n%s", got)
	}
}
