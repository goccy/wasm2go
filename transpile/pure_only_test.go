package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestPureOnlySingleFile pins the PureOnly contract in single-file
// mode: the emitted source carries no arch build gates and Translate
// produces no asm bundle (no .s, no decls files) — the pure bodies
// compile on every GOARCH.
func TestPureOnlySingleFile(t *testing.T) {
	m, err := transpile.Parse(bytes.NewReader(realAddWasm()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	restore := transpile.SetMultiPackageThreshold(1 << 30)
	defer restore()
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		PureOnly:         true,
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	assertNoAsmArtifacts(t, buf.Bytes(), res)
}

// TestPureOnlyMultiPackageEndToEnd forces the multi-package layout
// with PureOnly and runs the generated bundle natively. On amd64/arm64
// this only works when the pure bodies are emitted WITHOUT the
// `!amd64 && !arm64` dormancy gate — i.e. it proves the pure backend
// is buildable and correct on the asm-target GOARCHs, which is the
// whole point of the flag (the ABIInternal benchmarking reference).
func TestPureOnlyMultiPackageEndToEnd(t *testing.T) {
	m, err := transpile.Parse(bytes.NewReader(realAddWasm()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	restore := transpile.SetMultiPackageThreshold(0)
	defer restore()
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		PureOnly:         true,
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	assertNoAsmArtifacts(t, buf.Bytes(), res)

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
	writeFile("go.mod", []byte("module gentest\n\ngo 1.25.0\n"))
	if buf.Len() > 0 {
		writeFile("pkg/gen.go", buf.Bytes())
	}
	for rel, data := range res.Files {
		writeFile("pkg/"+rel, data)
	}
	for name, data := range res.Sidecars {
		writeFile("pkg/"+name, data)
	}
	// Multi-package exports are top-level funcs taking the *base.Module.
	writeFile("main.go", []byte(`package main

import (
	"fmt"

	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(pkg.Add(m, 7, 35))
}
`))

	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "42" {
		t.Fatalf("Add(7,35) printed %q, want 42\n%s", got, out)
	}
}

// assertNoAsmArtifacts checks that a PureOnly translation contains no
// asm bundle files and no arch-gating build tags anywhere.
func assertNoAsmArtifacts(t *testing.T, main []byte, res transpile.Result) {
	t.Helper()
	check := func(name string, data []byte) {
		if strings.HasSuffix(name, ".s") {
			t.Errorf("PureOnly emitted an asm file: %s", name)
		}
		if strings.Contains(filepath.Base(name), "decls_") {
			t.Errorf("PureOnly emitted a gcasm decls file: %s", name)
		}
		src := string(data)
		if strings.Contains(src, "!amd64") || strings.Contains(src, "amd64 || arm64") {
			t.Errorf("PureOnly output %s still carries an arch build gate", name)
		}
	}
	check("main", main)
	for name, data := range res.Files {
		check(name, data)
	}
}
