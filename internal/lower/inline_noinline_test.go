package lower

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// A dbg_-exported function is pinned out-of-line so the gcasm
// retarget lands on a live body, even when it is small enough to
// inline; an ordinary small leaf is still inlinable.
func TestExportedRetargetAnchorNotInlined(t *testing.T) {
	body := []byte{0x0b} // just `end`: a tiny leaf body
	mod := &wasm.Module{
		Functions: []wasm.Function{{Body: body}, {Body: body}},
		Exports: []wasm.Export{
			{Name: "dbg_gemm_q8_0_4x4", Kind: wasm.ExportFunc, Index: 0},
			{Name: "dbg_gemv_q8_0_4x4", Kind: wasm.ExportFunc, Index: 1},
		},
	}
	a := analyzeModuleForInline(mod)
	if !a.fns[0].noInline {
		t.Error("dbg_-exported function must be pinned noInline")
	}
	if a.fns[1].noInline {
		t.Error("gemv (nrows=1 decode kernel) must stay inlinable")
	}
}
