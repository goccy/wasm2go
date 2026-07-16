package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/goccy/wasm2go/transpile"
)

// TestGcasmMutexHandoff is TestThreadsMutexHandoff through the FULL backend:
// transpile.Translate emits the gcasm asm bundle (amd64/arm64), which is what
// real deployments execute. The pure-Go twin in internal/codegen passing while
// this one wedges would pin a lost futex wake inside the asm transform.
func TestGcasmMutexHandoff(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_threads_mutex.wasm")
	m, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(dir, "pkg")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 0 {
		if err := os.WriteFile(filepath.Join(pkgDir, "gen.go"), buf.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, set := range []map[string][]byte{res.Files, res.Sidecars} {
		for name, data := range set {
			p := filepath.Join(pkgDir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mainSrc := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "100000" {
		t.Errorf("gcasm mutex handoff: got %q, want 100000", got)
	}
}
