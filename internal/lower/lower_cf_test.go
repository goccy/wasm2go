package lower

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestLowerSwitch3 covers the switch3 export — a br_table dispatcher.
// br_table lowers to a chain of equality-If blocks, so the lowering
// should succeed and produce a CFG dominated by goto-based emission.
func TestLowerSwitch3(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "switch3" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Skip("switch3 not exported")
	}
	if _, err := LowerFunction(mod, idx, "switch3"); err != nil {
		t.Fatalf("lower switch3: %v", err)
	}
}
