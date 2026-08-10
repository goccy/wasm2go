package transpile_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// storeTree reports whether any fused tree contains a store sink, and
// whether that tree is a memory64 (Addr64) one.
func storeTrees(t *testing.T, fixture string) (found, addr64 bool) {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	res, err := transpile.Translate(io.Discard, m, transpile.Options{Package: "pkg", OutputImportPath: "sf/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	for _, tree := range res.FusedSimd {
		for _, n := range tree.Nodes {
			if simdfuse.IsStore(n.Op) {
				found = true
				if tree.Addr64 {
					addr64 = true
				}
			}
		}
	}
	return found, addr64
}

// The elementwise store-sink shape (store of mul(load, load)) must
// window-fuse on BOTH pointer widths: ggml's conversion and scale
// loops are exactly this shape, and leaving the memory64 twin
// unfused runs every store as a marshalled pair call.
func TestStoreSinkFusesBothWidths(t *testing.T) {
	if found, _ := storeTrees(t, "cg_simd_store32.wasm"); !found {
		t.Error("wasm32: no fused tree contains a store sink")
	}
	found, addr64 := storeTrees(t, "cg_mem64_simd_store.wasm")
	if !found {
		t.Error("memory64: no fused tree contains a store sink")
	}
	if found && !addr64 {
		t.Error("memory64: store tree not marked Addr64")
	}
}

// The variable-stride conversion-loop shape (load + load32_splat +
// mul + add + store per iteration, pointer bumps by a runtime stride)
// must fuse its loads INTO the window on both widths — this is the
// skeleton of ggml's row-scale loops.
func TestConvLoopFusesBothWidths(t *testing.T) {
	check := func(fixture string, wantAddr64 bool) {
		t.Helper()
		found, addr64 := storeTrees(t, fixture)
		if !found {
			t.Errorf("%s: no fused tree contains the store sink", fixture)
		}
		if found && addr64 != wantAddr64 {
			t.Errorf("%s: Addr64 = %v, want %v", fixture, addr64, wantAddr64)
		}
	}
	check("cg_simd_conv32.wasm", false)
	check("cg_mem64_simd_conv.wasm", true)
}
