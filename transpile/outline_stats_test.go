package transpile_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// TestOutlineStatsCollector runs the loop-boundary metrics collector
// (WASM2GO_OUTLINE_STATS) together with outlining requested at the
// smallest threshold over a function large enough to clear the
// collector's size floor. The fixture's single loop is nearly the
// whole function, so the share gate keeps it in place — the point
// here is that the collector and the candidate walk both run and the
// translate still succeeds.
func TestOutlineStatsCollector(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_outline_stats.wasm")
	t.Setenv("WASM2GO_OUTLINE_STATS", "1")
	t.Setenv("WASM2GO_OUTLINE", "2")
	t.Setenv("WASM2GO_OUTLINE_DEBUG", "1")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "outlinestats/pkg"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !strings.Contains(buf.String(), "func (m *Module) Bigsum(") {
		t.Fatalf("exported function missing from output")
	}
}
