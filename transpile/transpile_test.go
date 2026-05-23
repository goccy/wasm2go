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
