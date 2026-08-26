package codegen_test

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// minimalAddWasm returns a hand-crafted wasm module exporting "add" as
// (i32, i32) -> i32 with body returning 0.
func minimalAddWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		// type section: 1 type (i32, i32) -> i32
		0x01, 0x07, 0x01,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
		// function section: 1 func, type 0
		0x03, 0x02, 0x01, 0x00,
		// export section: 1 export "add" -> func 0
		0x07, 0x07, 0x01,
		0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
		// code section: 1 body, returns 0
		0x0a, 0x06, 0x01,
		0x04, 0x00, 0x41, 0x00, 0x0b,
	}
}

// realAddWasm returns a wasm module that actually computes a + b.
func realAddWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		// type section: 1 type (i32, i32) -> i32
		0x01, 0x07, 0x01,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
		// function section
		0x03, 0x02, 0x01, 0x00,
		// export section
		0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
		// code section
		0x0a, 0x09, 0x01,
		0x07,       // body size
		0x00,       // 0 local decls
		0x20, 0x00, // local.get 0
		0x20, 0x01, // local.get 1
		0x6a, // i32.add
		0x0b, // end
	}
}

func TestTranslateMinimal(t *testing.T) {
	m, err := wasm.Parse(bytes.NewReader(minimalAddWasm()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m.Functions) != 1 || len(m.Exports) != 1 || m.Exports[0].Name != "add" {
		t.Fatalf("unexpected parsed module: %+v", m)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, m, codegen.Options{Package: "addmod", OutputImportPath: "gentest/addmod"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	src := buf.String()
	t.Logf("emitted source:\n%s", src)
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "out.go", src, parser.ParseComments); err != nil {
		t.Fatalf("output is not valid Go: %v\n%s", err, src)
	}
	for _, expect := range []string{"package addmod", "type Module struct", "func New(", "func (m *Module) Add("} {
		if !strings.Contains(src, expect) {
			t.Errorf("output missing %q", expect)
		}
	}
}

// runGoSnippet writes pkg under a temp module dir, then compiles+runs main.go
// next to it. Returns combined stdout/stderr.
func runGoSnippet(t *testing.T, generated string, mainSrc string, sidecars ...map[string][]byte) string {
	t.Helper()
	return runGoSnippetWithAux(t, generated, mainSrc, sidecars, nil)
}

// pureGuardRe matches codegen's pure-Go fallback build constraint.
var pureGuardRe = regexp.MustCompile(`(?m)^//go:build !amd64 && !arm64\n`)

// stripPureGuard removes the `//go:build !amd64 && !arm64` constraint from
// a generated file so codegen's pure-Go function bodies compile and run on
// the amd64/arm64 test host. In production the gcasm backend supplies the
// per-arch asm for those GOARCHs (see transpile.Translate); codegen alone
// now emits only the pure bodies, so these codegen tests — which exercise
// that output directly and cannot import transpile (import cycle) — must
// activate the pure path on the host. No-op on files without the guard.
func stripPureGuard(data []byte) []byte {
	return pureGuardRe.ReplaceAll(data, nil)
}

// runGoSnippetWithAux is the auxFiles-aware variant of runGoSnippet. The
// auxFiles map carries raw Go-source files (typically the WASI per-
// platform companions) that must land alongside gen.go without going
// through //go:embed.
func runGoSnippetWithAux(t *testing.T, generated, mainSrc string, sidecars []map[string][]byte, auxFiles map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	gomod := "module gentest\n\ngo 1.25.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "gen.go"), []byte(generated), 0644); err != nil {
		t.Fatal(err)
	}
	for _, sc := range sidecars {
		for name, data := range sc {
			p := filepath.Join(dir, "pkg", name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, data := range auxFiles {
		p := filepath.Join(dir, "pkg", name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\noutput:\n%s\ngenerated:\n%s\nmain:\n%s", err, out, generated, mainSrc)
	}
	return string(out)
}

func TestEndToEndAdd(t *testing.T) {
	bin := realAddWasm()

	// Reference: run via wazero.
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	mod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mod.ExportedFunction("add").Call(ctx, 7, 35)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 42 {
		t.Fatalf("wazero add(7,35)=%d want 42", got[0])
	}

	// wasm2go path.
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, parsed, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	main := `package main
import (
	"fmt"
	"gentest/pkg"
)
func main() {
	m := pkg.New()
	v := m.Add(7, 35)
	fmt.Println(v)
}
`
	out := runGoSnippet(t, buf.String(), main, res.Sidecars, filesWithAux(res))
	if got := strings.TrimSpace(out); got != "42" {
		t.Fatalf("wasm2go add(7,35) printed %q want %q\n--generated--\n%s", got, "42", buf.String())
	}
}
