package codegen

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestDetectRuntimeTables drives the init-loop detector over the
// fixture's two store loops: one covering a full f16-table range
// (verifies) and one covering half of it (must not).
func TestDetectRuntimeTables(t *testing.T) {
	bin := testfixture.Wasm(t, "f16_init_loop.wat")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tr := &translator{mod: mod}
	tr.detectRuntimeTables()
	if len(tr.runtimeTables) == 0 {
		t.Fatal("no init-loop store regions detected")
	}
	if !tr.runtimeInitCovered(4096) {
		t.Fatalf("full-range init loop not covering base 4096: %+v", tr.runtimeTables)
	}
	if tr.runtimeInitCovered(4100) {
		t.Fatal("misaligned base must not verify (range ends short)")
	}
	if tr.runtimeInitCovered(266240) {
		t.Fatalf("half-range init loop must not verify: %+v", tr.runtimeTables)
	}
	// The detection feeds f16TableOK without any assertion.
	if !tr.f16TableOK(4096) {
		t.Fatal("f16TableOK rejected an init-covered base")
	}
	if tr.f16TableOK(266240) {
		t.Fatal("f16TableOK accepted a half-covered base")
	}
}
