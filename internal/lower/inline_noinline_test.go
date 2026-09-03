package lower

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// An export registered through SetNoInlineExports is pinned out of
// line so a assembly override lands on a live body, even when it is small
// enough to inline; an ordinary small exported leaf is still inlinable.
func TestPinnedExportNotInlined(t *testing.T) {
	body := []byte{0x0b} // just `end`: a tiny leaf body
	mod := &wasm.Module{
		Functions: []wasm.Function{{Body: body}, {Body: body}},
		Exports: []wasm.Export{
			{Name: "my_kernel", Kind: wasm.ExportFunc, Index: 0},
			{Name: "plain", Kind: wasm.ExportFunc, Index: 1},
		},
	}
	SetNoInlineExports(mod, []string{"my_kernel"})
	a := analyzeModuleForInline(mod)
	if !a.fns[0].noInline {
		t.Error("pinned export must be noInline")
	}
	if a.fns[1].noInline {
		t.Error("unpinned export must stay inlinable")
	}
}
