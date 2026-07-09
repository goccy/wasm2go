package lower

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

// TestLowerThrow lowers the $throwing function of eh_trycatch.wat
// (`i32.const 7; throw $e`) and checks it seals the block as BlockThrow
// carrying the tag index and the i32 operand — the EH/SjLj `throw` lowering.
func TestLowerThrow(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_trycatch")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// $throwing is the first defined function (no imports in the fixture).
	fn, err := LowerFunction(mod, 0, "throwing")
	if err != nil {
		t.Fatalf("lower throwing: %v", err)
	}
	dump := dumpSSAFunc(fn)
	if !bytes.Contains([]byte(dump), []byte("Throw tag=0")) {
		t.Errorf("expected a `Throw tag=0` terminator, got:\n%s", dump)
	}
	// The thrown i32 operand (const 7) must survive as a trailing OpCopy.
	if !bytes.Contains([]byte(dump), []byte("OpCopy")) {
		t.Errorf("expected the thrown operand as an OpCopy marker, got:\n%s", dump)
	}
}

// TestLowerTryCatch lowers $catching (try/catch/catch_all with an i32 result)
// and checks the TryRegion metadata: a protected body plus two handlers (a
// tagged catch and a catch_all), all merging into a post block.
func TestLowerTryCatch(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_trycatch")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fn, err := LowerFunction(mod, 1, "catching") // $catching
	if err != nil {
		t.Fatalf("lower catching: %v", err)
	}
	if len(fn.TryRegions) != 1 {
		t.Fatalf("TryRegions: got %d, want 1", len(fn.TryRegions))
	}
	tr := fn.TryRegions[0]
	if tr.Entry == nil || tr.Post == nil {
		t.Fatalf("TryRegion Entry/Post must be set: %+v", tr)
	}
	if len(tr.Handlers) != 2 {
		t.Fatalf("handlers: got %d, want 2 (catch + catch_all)", len(tr.Handlers))
	}
	if tr.Handlers[0].CatchAll {
		t.Errorf("handler[0] should be a tagged catch, got catch_all")
	}
	if tr.Handlers[0].NumArgs != 1 {
		t.Errorf("handler[0] (catch $e) NumArgs: got %d, want 1", tr.Handlers[0].NumArgs)
	}
	if !tr.Handlers[1].CatchAll {
		t.Errorf("handler[1] should be catch_all")
	}
	// The tagged handler must materialise the exception operand as OpCatchArg.
	dump := dumpSSAFunc(fn)
	if !bytes.Contains([]byte(dump), []byte("OpCatchArg")) {
		t.Errorf("expected OpCatchArg for the catch operand, got:\n%s", dump)
	}
}

// TestLowerMutableLocalsTry lowers $withlocal, a try-function that sets a local
// before the try and reads it in the body and the catch handler. Try-functions
// use mutable-locals mode: local.get/set stay as OpLocalGet/OpLocalSet (mutable
// Go vars) rather than being promoted to SSA + phi'd.
func TestLowerMutableLocalsTry(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_trycatch")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fn, err := LowerFunction(mod, 4, "withlocal") // $withlocal
	if err != nil {
		t.Fatalf("lower withlocal: %v", err)
	}
	dump := dumpSSAFunc(fn)
	if !bytes.Contains([]byte(dump), []byte("OpLocalGet")) {
		t.Errorf("mutable-locals mode should retain OpLocalGet, got:\n%s", dump)
	}
	if !bytes.Contains([]byte(dump), []byte("OpLocalSet")) {
		t.Errorf("mutable-locals mode should retain OpLocalSet, got:\n%s", dump)
	}
	if len(fn.TryRegions) != 1 {
		t.Errorf("TryRegions: got %d, want 1", len(fn.TryRegions))
	}
}
