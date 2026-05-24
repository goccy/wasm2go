package codegen

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestComputeReachableFuncs checks whole-function reachability on the
// deadfunc.wasm fixture:
//
//	used   — exported            → reachable (root)
//	helper — called by `used`    → reachable (transitive)
//	tabled — only in the table   → reachable (call_indirect root)
//	dead   — none of the above   → NOT reachable, droppable
func TestComputeReachableFuncs(t *testing.T) {
	bin := testfixture.Wasm(t, "deadfunc")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := computeReachableFuncs(mod, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Resolve each name to its local (defined) index via the exports +
	// the known module layout. deadfunc.wat defines functions in
	// source order: used=0, helper=1, tabled=2, dead=3 (no imports).
	if mod.NumImportedFuncs != 0 {
		t.Fatalf("fixture expected 0 imported funcs, got %d", mod.NumImportedFuncs)
	}
	const (
		used   = 0
		helper = 1
		tabled = 2
		dead   = 3
	)
	for _, tc := range []struct {
		name  string
		local uint32
		want  bool
	}{
		{"used", used, true},
		{"helper", helper, true},
		{"tabled", tabled, true},
		{"dead", dead, false},
	} {
		if got := reachable[tc.local]; got != tc.want {
			t.Errorf("%s (local %d): reachable=%v, want %v", tc.name, tc.local, got, tc.want)
		}
	}
	if len(reachable) != 3 {
		t.Errorf("expected 3 reachable functions, got %d", len(reachable))
	}

	// With `used` named as the sole entry export, the result is the
	// same here (tabled stays live via the table, helper via the call).
	narrowed, err := computeReachableFuncs(mod, map[string]bool{"used": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed[dead] {
		t.Errorf("dead function reachable under narrowed entry set")
	}
}
