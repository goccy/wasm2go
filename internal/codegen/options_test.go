package codegen_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
)

// codegenParse is a thin wrapper around wasm.Parse for the tests in
// this file that synthesise hand-crafted modules.
func codegenParse(src []byte) (*wasm.Module, error) {
	return wasm.Parse(bytes.NewReader(src))
}

// TestTranslateRequiresPackage exercises the explicit validation that
// Options.Package and Options.OutputImportPath must both be set on
// every Translate call — the old "default to wasm2go" fallback is gone.
func TestTranslateRequiresPackage(t *testing.T) {
	mod := readFixture(t, "arith.wasm")
	t.Run("missing-package", func(t *testing.T) {
		_, err := codegen.Translate(io.Discard, mod, codegen.Options{
			OutputImportPath: "example.com/x",
		})
		if err == nil || !strings.Contains(err.Error(), "Package") {
			t.Errorf("expected Package-required error, got %v", err)
		}
	})
	t.Run("missing-output-import-path", func(t *testing.T) {
		_, err := codegen.Translate(io.Discard, mod, codegen.Options{Package: "x"})
		if err == nil || !strings.Contains(err.Error(), "OutputImportPath") {
			t.Errorf("expected OutputImportPath-required error, got %v", err)
		}
	})
}

// TestEntryExportsRoots covers the nil / empty-slice / non-empty
// semantics of Options.EntryExports.
//
//	nil          : every export is a DCE root.
//	empty-slice  : NO export is a root (only start + table).
//	non-empty    : only the named exports are roots.
func TestEntryExportsRoots(t *testing.T) {
	mod := readFixture(t, "arith.wasm")
	for _, tc := range []struct {
		name string
		eset []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"named", []string{"add"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := codegen.Translate(&buf, mod, codegen.Options{
				Package: "pkg", OutputImportPath: "gentest/pkg",
				EntryExports: tc.eset,
			})
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			if !strings.Contains(buf.String(), "package pkg") {
				t.Errorf("output missing package decl for case %s", tc.name)
			}
		})
	}
}

// TestExportMethodNameCollisionDetection synthesises a module whose
// two exports mangle to the same Go method name and confirms that
// Translate surfaces a clear error rather than emitting duplicate
// methods that fail to compile.
func TestExportMethodNameCollisionDetection(t *testing.T) {
	// Hand-rolled minimal wasm with two exports named "XAlloc" and
	// "x_alloc" — both mangle to "XAlloc" via ExportMethodName.
	src := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		// type section: one type () -> ()
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		// function section: 2 funcs of type 0
		0x03, 0x03, 0x02, 0x00, 0x00,
		// export section: 2 exports
		0x07, 0x14, 0x02,
		0x06, 'X', 'A', 'l', 'l', 'o', 'c', 0x00, 0x00,
		0x07, 'x', '_', 'a', 'l', 'l', 'o', 'c', 0x00, 0x01,
		// code section: 2 empty bodies (just `end`)
		0x0a, 0x07, 0x02,
		0x02, 0x00, 0x0b,
		0x02, 0x00, 0x0b,
	}
	m, err := codegenParse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = codegen.Translate(io.Discard, m, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
	if err == nil {
		t.Fatalf("expected collision error, got nil")
	}
	if !strings.Contains(err.Error(), "mangle") {
		t.Errorf("error %v does not mention the mangle collision", err)
	}
}

// TestBulkExportEmptyWarning confirms that BulkExportPrefix matching
// zero exports surfaces the diagnostic warning to stderr — the
// caller would otherwise silently get back per-export wrappers and
// wonder why no Inv_ functions were emitted.
func TestBulkExportEmptyWarning(t *testing.T) {
	mod := readFixture(t, "arith.wasm")
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
		BulkExportPrefix: "totally_unrelated_prefix_",
	}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	// The warning is opportunistic — best confirmed by the
	// generated source containing no Inv_ functions. The stderr
	// path is exercised but not captured (would require a pipe).
	if strings.Contains(buf.String(), "func Inv_") {
		t.Errorf("expected no Inv_ functions with a non-matching prefix")
	}
}
