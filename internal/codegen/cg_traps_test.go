package codegen_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestTrapOpsArePreservedThroughDCE drives the cg_traps fixture: every
// export performs a trapping op, drops its result, then returns a
// constant. A correct translation must still trap at runtime —
// dead-code elimination must NOT remove the trapping op just because
// the result is unused. We compile each export through wasm2go, run
// it in a child process, and assert the process panicked (non-zero
// exit) with the expected wasm trap message.
func TestTrapOpsArePreservedThroughDCE(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_traps")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		export    string
		wantPanic string
	}{
		{"div_s32_drop_then_42", "wasm: integer divide by zero"},
		{"div_u32_drop_then_42", "wasm: integer divide by zero"},
		{"rem_s32_drop_then_42", "wasm: integer divide by zero"},
		{"rem_u32_drop_then_42", "wasm: integer divide by zero"},
		{"div_s64_drop_then_42", "wasm: integer divide by zero"},
		{"trunc_f32_s_nan_drop_then_42", "wasm: invalid conversion to integer"},
	}

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	generated := buf.String()

	for _, tc := range cases {
		t.Run(tc.export, func(t *testing.T) {
			method := codegen.ExportMethodName(tc.export)
			main := fmt.Sprintf(`package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	m := pkg.New()
	v := m.%s()
	fmt.Printf("no-trap got=%%d\n", v)
}
`, method)
			out, ok := runGoSnippetExpectPanic(t, generated, main, res.Sidecars, res.Files)
			if ok {
				t.Fatalf("expected panic for %s, got clean exit:\n%s", tc.export, out)
			}
			if !strings.Contains(out, tc.wantPanic) {
				t.Errorf("expected panic with %q for %s, got:\n%s", tc.wantPanic, tc.export, out)
			}
			if strings.Contains(out, "no-trap got=") {
				t.Errorf("%s returned cleanly — trap was DCE'd away:\n%s", tc.export, out)
			}
		})
	}
}

// TestMemGrowDropEmitsOnceNotTwice asserts that an `(memory.grow ...)
// drop` sequence emits exactly one call to memoryGrow across the whole
// generated package. The earlier risk was that a side-effecting scalar
// whose result is dropped would emit both the hoisted assignment and
// a fresh side-effect statement; that would surface as two
// memoryGrow calls. The fixture has a single `(drop (memory.grow ...))`
// so exactly one call is correct.
func TestMemGrowDropEmitsOnceNotTwice(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_traps")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	src := buf.String()
	// Count call-site invocations: `memoryGrow(m,` (the host pattern
	// for an emitted helper call) — distinct from the helper's
	// definition line `func memoryGrow(m *Module, n int32) int32 {`.
	got := strings.Count(src, "memoryGrow(m,")
	if got != 1 {
		t.Errorf("memoryGrow emitted %d times in generated package; want 1.\nsource:\n%s",
			got, src)
	}
}

// runGoSnippetExpectPanic is the panic-tolerant variant of
// runGoSnippet: it does NOT call t.Fatal on a non-zero exit. Returns
// (combined output, processExitedSuccessfully).
func runGoSnippetExpectPanic(t *testing.T, generated, mainSrc string, extraFiles ...map[string][]byte) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "gen.go"), []byte(generated), 0644); err != nil {
		t.Fatal(err)
	}
	for _, files := range extraFiles {
		for name, data := range files {
			p := filepath.Join(dir, "pkg", name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}
