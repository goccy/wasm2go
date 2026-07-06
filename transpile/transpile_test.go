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

// TestPublicAPI exercises the library entry points — Parse then
// Translate, and the Transpile convenience wrapper — the same way an
// external caller would, without touching any internal package.
func TestPublicAPI(t *testing.T) {
	bin := testfixture.Wasm(t, "wexports")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var buf bytes.Buffer
	if _, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "genwasm",
		OutputImportPath: "example.com/test/genwasm",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("Translate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "package genwasm") {
		t.Errorf("output does not look like generated Go:\n%.200s", out)
	}
	if !strings.Contains(out, "func Inv_0_0(") {
		t.Errorf("BulkExportPrefix option not honored through the public API")
	}

	// Transpile should be byte-identical to Parse+Translate for the
	// same input and options.
	var oneShot bytes.Buffer
	if _, err := transpile.Transpile(bytes.NewReader(bin), &oneShot, transpile.Options{
		Package:          "genwasm",
		OutputImportPath: "example.com/test/genwasm",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if oneShot.String() != out {
		t.Errorf("Transpile output differs from Parse+Translate")
	}

	// A malformed input must surface as a Parse error through Transpile,
	// without invoking Translate.
	if _, err := transpile.Transpile(bytes.NewReader([]byte("not a wasm")), &bytes.Buffer{}, transpile.Options{
		Package:          "x",
		OutputImportPath: "example.com/x",
	}); err == nil {
		t.Errorf("Transpile: expected error on malformed input")
	}
}

// TestSetMultiPackageThreshold verifies the package-mode override
// flips the resulting layout. We compare two translations of the
// same wasm: one with a very high threshold (forces single-file
// Go output, no `base/`) and one with threshold=0 (forces the
// multi-package split).
func TestSetMultiPackageThresholdAPI(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Single-file: high threshold cannot be exceeded by a small
	// fixture, so the multi-package layout must NOT trigger.
	restoreHigh := transpile.SetMultiPackageThreshold(1 << 30)
	resHigh, err := transpile.Translate(&bytes.Buffer{}, m, transpile.Options{
		Package: "x", OutputImportPath: "example.com/x",
	})
	restoreHigh()
	if err != nil {
		t.Fatalf("Translate high-threshold: %v", err)
	}
	if _, ok := resHigh.Files["base/base.go"]; ok {
		t.Errorf("high threshold should keep single-file mode but produced base/base.go")
	}

	// Threshold 0: every module exceeds and lands in multi-package mode.
	restoreZero := transpile.SetMultiPackageThreshold(0)
	resZero, err := transpile.Translate(&bytes.Buffer{}, m, transpile.Options{
		Package: "x", OutputImportPath: "example.com/x",
	})
	restoreZero()
	if err != nil {
		t.Fatalf("Translate zero-threshold: %v", err)
	}
	if _, ok := resZero.Files["base/base.go"]; !ok {
		t.Errorf("threshold=0 should trigger multi-package layout but base/base.go missing")
	}
}

// realAddWasm is a minimal module exporting add:(i32,i32)->i32 = a+b.
func realAddWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
		0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
	}
}

// TestTranspileEndToEnd drives the full public pipeline — Parse then
// Translate, which runs codegen AND the gcasm backend — writes the whole
// bundle to a temp module, and builds+runs it on the host. On amd64/arm64
// the gcasm-emitted asm supplies the function bodies (the pure bodies are
// dormant), so a successful `go run` exercises the real shipped path end
// to end: codegen.Translate, gcasm.Build (capture + transform + emit),
// the purego build-tag weaving, and the assembled output itself.
func TestTranspileEndToEnd(t *testing.T) {
	m, err := transpile.Parse(bytes.NewReader(realAddWasm()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
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
	writeFile("go.mod", []byte("module gentest\n\ngo 1.25.0\n"))
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

	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Add(7, 35))
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
