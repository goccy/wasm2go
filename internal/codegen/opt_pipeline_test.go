package codegen

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/ssa/pass"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// runOptPipeline lowers one wasm export and runs the optimization
// pipeline, returning the live SSA instruction count before and after.
func runOptPipeline(t *testing.T, mod *wasm.Module, export string) (before, after int) {
	t.Helper()
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == export {
			idx = e.Index
		}
	}
	if idx == ^uint32(0) {
		t.Fatalf("export %q not found", export)
	}
	fn, err := lower.LowerFunction(mod, idx, export, nil)
	if err != nil {
		t.Fatalf("lower %s: %v", export, err)
	}
	before = ssa.CountValues(fn)
	for i := 0; i < 8; i++ {
		ch := false
		if pass.ConstProp(fn) {
			ch = true
		}
		if pass.Simplify(fn) {
			ch = true
		}
		if pass.CSE(fn) {
			ch = true
		}
		if pass.DCE(fn) {
			ch = true
		}
		if !ch {
			break
		}
	}
	ssa.Compact(fn)
	if err := ssa.Verify(fn); err != nil {
		t.Fatalf("verify %s after opt: %v", export, err)
	}
	after = ssa.CountValues(fn)
	return before, after
}

// TestSSAOptFolds proves the optimization pipeline reduces the SSA
// instruction count on minimal, hand-chosen examples with known-good
// expected counts:
//
//   - fold_arith: 2 + 3*4 — every operand constant; ConstProp + DCE
//     collapse it to a single constant.
//   - fold_cse:   (n+1)*(n+1) — the (n+1) subexpression is built
//     twice; CSE merges it.
//   - fold_dead:  a dead `n*n` product alongside the live `n+1`;
//     DCE drops the product and its dead local-init.
func TestSSAOptFolds(t *testing.T) {
	bin := testfixture.Wasm(t, "ssa_cf")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		export        string
		wantBefore    int
		wantAfterMax  int // optimised count must be <= this
		wantReduction bool
	}{
		{"fold_arith", 7, 2, true},
		{"fold_cse", 7, 5, true},
		{"fold_dead", 6, 4, true},
	}
	for _, c := range cases {
		before, after := runOptPipeline(t, mod, c.export)
		t.Logf("%-12s instructions: %d -> %d", c.export, before, after)
		if before != c.wantBefore {
			t.Errorf("%s: before=%d, want %d", c.export, before, c.wantBefore)
		}
		if after > c.wantAfterMax {
			t.Errorf("%s: after=%d, want <= %d", c.export, after, c.wantAfterMax)
		}
		if c.wantReduction && after >= before {
			t.Errorf("%s: optimization did not reduce instruction count (%d -> %d)", c.export, before, after)
		}
	}
}
