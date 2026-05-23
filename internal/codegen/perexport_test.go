package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestPerExportDispatch verifies the per-export dispatch shape that
// wasm2go always emits when Options.BulkExportPrefix matches at least
// one export: one standalone `Inv_<svc>_<mt>` function per export and
// a shared `safeInvokeWrap` helper. The Go linker can then drop
// whichever exports the consumer never calls. The previously-emitted
// consolidated `InvokeExport` switch has been removed.
func TestPerExportDispatch(t *testing.T) {
	bin := testfixture.Wasm(t, "wexports")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	out := buf.String()

	for _, name := range []string{"func Inv_0_0(", "func Inv_0_1(", "func Inv_1_0("} {
		if !strings.Contains(out, name) {
			t.Errorf("missing %q:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "safeInvokeWrap") {
		t.Errorf("missing the shared safeInvokeWrap helper")
	}
	if strings.Contains(out, "func InvokeExport") || strings.Contains(out, "func SafeInvokeExport") {
		t.Errorf("consolidated InvokeExport / SafeInvokeExport must not be emitted:\n%s", out)
	}
	// The non-bulk "helper" export still gets its direct wrapper.
	if !strings.Contains(out, "Helper") {
		t.Errorf("system export wrapper missing")
	}
}

// TestBulkExportEmpty drives a fixture with no bulk-prefixed exports
// through the same option. The translator must not emit any Inv_*
// functions and must surface the "matched zero exports" warning the
// caller relies on. We don't observe stderr here; we just confirm the
// generated code stays empty of bulk-dispatch artefacts.
func TestBulkExportEmpty(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if strings.Contains(buf.String(), "func Inv_") {
		t.Errorf("expected no Inv_ functions when prefix matches nothing")
	}
}
