package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// runEHFixture translates fixture (which must export "run" () -> i32), builds
// the generated module with the default backend, executes it, and compares
// run()'s printed result. Shared by the C++-shaped EH pattern tests below.
func runEHFixture(t *testing.T, fixture, want string) {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "ehtest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module ehtest\n\ngo 1.25.0\n"))
	writeFile("pkg/gen.go", buf.Bytes())
	for rel, data := range res.Files {
		writeFile("pkg/"+rel, data)
	}
	for name, data := range res.Sidecars {
		writeFile("pkg/"+name, data)
	}
	writeFile("main.go", []byte(`package main

import (
	"fmt"

	"ehtest/pkg"
)

func main() {
	fmt.Println(pkg.New().Run())
}
`))

	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("run() printed %q, want %s\n%s", got, want, out)
	}
}

// TestTranspileEHMultiCatch: one try with catch $a / catch $b / catch_all —
// the clause dispatch must select by tag, in clause order, with catch_all as
// the final default.
func TestTranspileEHMultiCatch(t *testing.T) {
	runEHFixture(t, "eh_multi_catch", "132")
}

// TestTranspileEHMultiCatchTrampoline is the same dispatch through the
// recover-trampoline path (a return inside the try body forces it).
func TestTranspileEHMultiCatchTrampoline(t *testing.T) {
	runEHFixture(t, "eh_multi_catch_tramp", "139")
}

// TestTranspileEHCatchAllRethrow: catch_all + rethrow 0 — the C++ cleanup-
// during-unwind shape. The rethrown exception keeps tag and payload.
func TestTranspileEHCatchAllRethrow(t *testing.T) {
	runEHFixture(t, "eh_catch_all_rethrow", "42")
}

// TestTranspileEHDelegateSkip: delegate 1 forwards past the middle try's
// catch_all straight to the outer catch $a. The middle handler must not run.
func TestTranspileEHDelegateSkip(t *testing.T) {
	runEHFixture(t, "eh_delegate_skip", "42")
}

// TestTranspileEHRethrowOuter: rethrow 1 inside an inner catch_all re-raises
// the OUTER catch's exception (42), not the inner one (99).
func TestTranspileEHRethrowOuter(t *testing.T) {
	runEHFixture(t, "eh_rethrow_outer", "42")
}

// TestTranspileEHTryExitFlag: a br out of a protected body must deactivate the
// try — a later throw outside it propagates to the caller instead of being
// caught by the exited try's handler.
func TestTranspileEHTryExitFlag(t *testing.T) {
	runEHFixture(t, "eh_try_exit_flag", "222")
}
