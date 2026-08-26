package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// translateSpinguard translates the spinguard fixture and returns the
// primary source, the concatenation of every emitted file (function
// bodies land in sidecar files), and the Translate result.
func translateSpinguard(t *testing.T) (string, string, codegen.Result) {
	t.Helper()
	bin := testfixture.Wasm(t, "spinguard.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	all := buf.String()
	for _, data := range res.Files {
		all += "\n" + string(data)
	}
	return buf.String(), all, res
}

// TestSpinGuardInjection pins where the bare-atomic-spin preemption
// guard lands: exactly the two bare spin loops (i32 and i64 waits with
// no call in the body) get a spinRelax call and the counter local; the
// same wait with a direct call in the body, and a loop spinning on a
// plain (non-atomic) load, must stay untouched.
func TestSpinGuardInjection(t *testing.T) {
	_, all, _ := translateSpinguard(t)
	if got := strings.Count(all, "spinRelax(&__spinGuard)"); got != 2 {
		t.Errorf("spinRelax guard sites = %d, want 2 (bare_spin, bare_spin64)", got)
	}
	if got := strings.Count(all, "var __spinGuard uint32"); got != 2 {
		t.Errorf("__spinGuard declarations = %d, want 2", got)
	}
	if !strings.Contains(all, "func spinRelax(") {
		t.Error("spinRelax helper source not included")
	}
}

// TestSpinGuardRuns compiles and runs the guarded output: the wait
// condition fails on the first check (memory is zeroed, the argument is
// nonzero), so each spin executes its guard once and returns. This is
// the compile-level assertion that the injected statements are legal Go
// in both loop shapes.
func TestSpinGuardRuns(t *testing.T) {
	src, _, res := translateSpinguard(t)
	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.BareSpin(1), m.BareSpin64(1), m.SpinWithCall(1), m.PlainLoop(1))
}
`
	got := runGoSnippetNoRace(t, src, main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "0 0 0 0" {
		t.Errorf("guarded spins: got %q, want \"0 0 0 0\"", got)
	}
}
