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
	// Every function with a countdown SIMD loop must unroll in WIDE
	// mode — a variable stride unrolls fine (the bump repeats per
	// copy), and wide additionally admits the i64-countdown variants
	// (loopsum64, axpy64, gemm4's outer loop): the shape memory64
	// modules produce, where LP64 promotes the induction variable.
	mustFire := map[string]bool{
		"loopsum": true, "dot2": true, "quantnarrow": true,
		"scaledot": true, "axpy": true, "strideaxpy": true,
		"gathersum": true, "loopsum64": true, "axpy64": true,
		"gemm4": true,
	}
	// Narrow mode (wasm32) must keep the exact historical set: the
	// i64-counter loops stay untouched there — admitting them was
	// measured to cost ~40% prompt throughput on the llama.cpp module
	// (their bodies do not window-fuse on wasm32).
	narrowFire := map[string]bool{
		"loopsum": true, "dot2": true, "quantnarrow": true,
		"scaledot": true, "axpy": true, "strideaxpy": true,
		"gathersum": true,
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
		narrow, err := lower.LowerFunction(m, e.Index, e.Name, nil)
		if err != nil {
			t.Fatalf("lower %s: %v", e.Name, err)
		}
		if UnrollSimdLoops(narrow, 4, false) != narrowFire[e.Name] {
			t.Errorf("%s: narrow matcher fired=%v, want %v", e.Name, !narrowFire[e.Name], narrowFire[e.Name])
		}
		if UnrollSimdLoops(f, 4, true) {
			unrolled++
			if !mustFire[e.Name] {
				t.Errorf("%s: matcher fired unexpectedly", e.Name)
			}
			if err := ssa.Verify(f); err != nil {
				t.Fatalf("verify %s post-unroll: %v", e.Name, err)
			}
		} else if mustFire[e.Name] {
			t.Errorf("%s: matcher did not fire; function:\n%s", e.Name, ssa.FuncString(f))
		}
	}
	if unrolled != len(mustFire) {
		t.Fatalf("unrolled %d functions, want %d", unrolled, len(mustFire))
	}
}
