package pass

// Structural test: the unroll matcher must fire on the loop shape the
// REAL lowering produces (the e2e fixture only proves semantics; this
// pins that unrolling actually happens and survives the verifier).

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

func TestUnrollSimdLoopsOnLoweredFixture(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd_loop.wasm")
	m, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	unrolled := 0
	for _, e := range m.Exports {
		if e.Kind != wasm.ExportFunc {
			continue
		}
		f, err := lower.LowerFunction(m, e.Index, e.Name, nil)
		if err != nil {
			t.Fatalf("lower %s: %v", e.Name, err)
		}
		if err := ssa.Verify(f); err != nil {
			t.Fatalf("verify %s pre: %v", e.Name, err)
		}
		if UnrollSimdLoops(f, 4) {
			unrolled++
			if err := ssa.Verify(f); err != nil {
				t.Fatalf("verify %s post-unroll: %v", e.Name, err)
			}
		} else if e.Name == "loopsum" || e.Name == "dot2" || e.Name == "quantnarrow" || e.Name == "scaledot" || e.Name == "axpy" || e.Name == "strideaxpy" || e.Name == "gathersum" {
			t.Errorf("%s: matcher did not fire; function:\n%s", e.Name, ssa.FuncString(f))
		}
	}
	// loopsum, dot2, quantnarrow, scaledot, axpy, strideaxpy and
	// gathersum all contain the countdown SIMD loop (a variable
	// stride unrolls fine — the bump repeats per copy). The int64-
	// counter variants (loopsum64, axpy64) stay un-unrolled: the
	// unroller only recognizes 32-bit countdowns.
	if unrolled != 7 {
		t.Fatalf("unrolled %d functions, want 7 (loopsum, dot2, quantnarrow, scaledot, axpy, strideaxpy, gathersum)", unrolled)
	}
}
