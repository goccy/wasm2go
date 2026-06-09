package transpile_test

import (
	"bytes"
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
