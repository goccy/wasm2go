package codegen

import (
	"bytes"
	"errors"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestLowerArith feeds the arith.wasm fixture (already a happy-path
// integer-arith-only module) through LowerFunction and asserts that
// every exported function lowers cleanly. The dump of one
// representative function is checked against a golden string so
// regressions in op selection or value-id assignment show up loudly.
func TestLowerArith(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Find a function we know is straight-line arith: "add".
	addFnIdx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "add" {
			addFnIdx = e.Index
			break
		}
	}
	if addFnIdx == ^uint32(0) {
		t.Fatalf("arith.wasm: missing add export")
	}

	fn, err := LowerFunction(mod, addFnIdx, "add")
	if err != nil {
		t.Fatalf("lower add: %v", err)
	}
	got := dumpSSAFunc(fn)
	// add: (i32, i32) -> i32 { return p0 + p1 }
	want := `func add(p0 i32, p1 i32) i32 {
  b0:
    v1 = OpParam [0] : i32
    v2 = OpParam [1] : i32
    v3 = OpAdd32 v1 v2 : i32
    v4 = OpCopy v3 : i32
    Ret
}
`
	if got != want {
		t.Errorf("add lowering mismatch.\n--want--\n%s\n--got--\n%s", want, got)
	}

	// Spot-check a few others we expect to lower cleanly: arithmetic,
	// shifts, comparisons, rotation, and trapping division.
	tryLower := func(t *testing.T, name string, wantUnsupported bool) {
		t.Helper()
		idx := ^uint32(0)
		for _, e := range mod.Exports {
			if e.Kind == wasm.ExportFunc && e.Name == name {
				idx = e.Index
				break
			}
		}
		if idx == ^uint32(0) {
			t.Fatalf("missing export %q", name)
		}
		_, err := LowerFunction(mod, idx, name)
		switch {
		case err == nil && wantUnsupported:
			t.Fatalf("%s: expected ErrSSAUnsupported, got nil", name)
		case err != nil && !wantUnsupported:
			t.Fatalf("%s: unexpected error: %v", name, err)
		case err != nil && wantUnsupported && !errors.Is(err, ErrSSAUnsupported):
			t.Fatalf("%s: expected ErrSSAUnsupported, got %v", name, err)
		}
	}
	tryLower(t, "sub", false)
	tryLower(t, "mul64", false)
	tryLower(t, "shifts", false)
	tryLower(t, "lt_s", false)
	tryLower(t, "lt_u", false)
	tryLower(t, "rotl", false)
	tryLower(t, "div_s", false)
}

// dumpSSAFunc is a thin wrapper around ssa.FuncString so tests don't
// need to import the ssa package directly.
func dumpSSAFunc(f interface{}) string {
	type stringer interface{ String() string }
	if s, ok := f.(stringer); ok {
		return s.String()
	}
	// f is *ssa.Func; call via reflection-free path through the
	// codegen package's helper.
	return ssaFuncString(f)
}

// ssaFuncString is implemented in lower.go as a thin wrapper around
// ssa.FuncString so we keep the dependency on internal/ssa internal to
// this file pair (no test-side import of internal/ssa).
var _ = ssaFuncString // referenced by dumpSSAFunc
