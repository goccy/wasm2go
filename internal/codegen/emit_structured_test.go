package codegen

import (
	"bytes"
	"go/format"
	"go/token"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/ssa/pass"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestStructuredEmit verifies that acyclic (loop-free) functions are
// rendered by the structured emitter as goto-free `if {} else {}` Go,
// while functions with a loop fall back to the goto emitter. Runtime
// correctness for all of these is covered separately by
// TestSSAControlFlow; here we only assert the emitted SHAPE.
func TestStructuredEmit(t *testing.T) {
	bin := testfixture.Wasm(t, "ssa_cf")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	// All these exports — acyclic and single-loop — must now emit
	// structured (no goto): if/else for branches, for {} for loops.
	structured := []string{"abs", "clamp_if", "early", "deadnest", "ret_nested",
		"deep", "brblock", "fold_arith", "fold_cse", "fold_dead",
		"count", "sum", "mul2"}
	// loopExports must additionally contain a `for` loop.
	loopExports := map[string]bool{"count": true, "sum": true, "mul2": true}

	// emitOne lowers + optimises an export and runs the structured
	// emitter. ok2 is false when the function could not be SSA-lowered
	// at all (an unsupported opcode → whole-function legacy fallback).
	emitOne := func(export string) (src string, structured, lowered bool) {
		idx := ^uint32(0)
		for _, e := range mod.Exports {
			if e.Kind == wasm.ExportFunc && e.Name == export {
				idx = e.Index
			}
		}
		if idx == ^uint32(0) {
			t.Fatalf("export %q not found", export)
		}
		fn, err := lower.LowerFunction(mod, idx, export)
		if err != nil {
			return "", false, false
		}
		for i := 0; i < 8; i++ {
			ch := false
			if pass.ConstProp(fn) {
				ch = true
			}
			if pass.Simplify(fn) {
				ch = true
			}
			if pass.CSE(fn) {
				ch = true
			}
			if pass.DCE(fn) {
				ch = true
			}
			if !ch {
				break
			}
		}
		ssa.Compact(fn)
		em := newSSAEmitter(nil)
		body, ok := em.emitStructured(fn)
		if !ok {
			return "", false, true
		}
		fset := token.NewFileSet()
		var buf bytes.Buffer
		if err := format.Node(&buf, fset, body); err != nil {
			t.Fatalf("format %s: %v", export, err)
		}
		return buf.String(), true, true
	}

	for _, export := range structured {
		got, isStruct, lowered := emitOne(export)
		if !lowered {
			t.Logf("%s: not SSA-lowerable, skipped", export)
			continue
		}
		if !isStruct {
			t.Errorf("%s: expected structured emit, fell back to goto", export)
			continue
		}
		if strings.Contains(got, "goto") {
			t.Errorf("%s: structured emit contains goto:\n%s", export, got)
		}
		if loopExports[export] && !strings.Contains(got, "for {") {
			t.Errorf("%s: loop function should emit a `for {}`:\n%s", export, got)
		}
	}
}
