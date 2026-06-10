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
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	// Asm-always-on ships TWO emit paths in the same
	// package — the per-arch asm sidecar (a `CALL ·memoryGrow(SB)`
	// per arch.s file) and the pure-Go fallback (a
	// `memoryGrow(m, ...)` call in pkg_pure.go) — chosen at build
	// time by build constraints. The pre-asm-always-on shape was
	// just one Go call in gen.go.
	//
	// The regression this test guards is "side-effecting op whose
	// result is dropped emits its CALL twice in the SAME emit path".
	// So we count per path and assert each path emits at most one.
	goSrc := buf.String()
	mainGoCalls := strings.Count(goSrc, "memoryGrow(m,")
	pureGoCalls := 0
	asmCallsPerArch := map[string]int{}
	sweep := func(name string, data []byte) {
		switch {
		case strings.HasSuffix(name, ".s"):
			asmCallsPerArch[name] = strings.Count(string(data), "CALL ·memoryGrow(SB)")
		default:
			pureGoCalls += strings.Count(string(data), "memoryGrow(m,")
		}
	}
	for name, data := range res.Sidecars {
		sweep(name, data)
	}
	for name, data := range res.Files {
		sweep(name, data)
	}
	if mainGoCalls > 1 {
		t.Errorf("memoryGrow emitted %d times in gen.go; want at most 1.\nsource:\n%s",
			mainGoCalls, goSrc)
	}
	if pureGoCalls > 1 {
		t.Errorf("memoryGrow emitted %d times in pkg_pure.go (or other Go file); want at most 1.",
			pureGoCalls)
	}
	for name, n := range asmCallsPerArch {
		if n > 1 {
			t.Errorf("memoryGrow emitted %d times in %s; want at most 1.", n, name)
		}
	}
	// Sanity: at least one of the emit paths must carry the call,
	// otherwise the export's body is silently empty.
	total := mainGoCalls + pureGoCalls
	for _, n := range asmCallsPerArch {
		total += n
	}
	if total == 0 {
		t.Errorf("memoryGrow not emitted in any path — the export body is empty.")
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
