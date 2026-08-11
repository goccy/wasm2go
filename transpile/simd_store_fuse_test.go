package transpile_test

import (
	"bytes"
	"io"
	"strings"
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

// Variable+variable addresses (base+stride with no constant side)
// must CHASE into scalar-node address chains and keep the whole
// load/splat/mul/store body inside one region on both widths. A mem
// node with an ArgNode address is the structural witness.
func TestAddrSumChasesBothWidths(t *testing.T) {
	check := func(fixture string, wantAddr64 bool) {
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
		var store, nodeAddr bool
		for _, tree := range res.FusedSimd {
			if tree.Addr64 != wantAddr64 {
				continue
			}
			for _, n := range tree.Nodes {
				mem := simdfuse.IsStore(n.Op) || strings.HasPrefix(n.Op, "v128_load")
				if simdfuse.IsStore(n.Op) {
					store = true
				}
				if mem && len(n.Args) > 0 && n.Args[0].Kind == simdfuse.ArgNode {
					nodeAddr = true
				}
			}
		}
		if !store {
			t.Errorf("%s: no fused store sink", fixture)
		}
		if !nodeAddr {
			t.Errorf("%s: no mem node carries a chased (ArgNode) address", fixture)
		}
	}
	check("cg_simd_addrsum32.wasm", false)
	check("cg_mem64_simd_addrsum.wasm", true)
}

// The countdown conversion loop must UPGRADE to a fused loop (one
// splice owning the whole loop) on both widths: the head-tested
// `c == 0` break with a unit decrement is one of the emitter's own
// shapes, and the memory64 call sites wrap their scalar arguments in
// int64() — neither may block the upgrade.
func TestConvLoopUpgradesBothWidths(t *testing.T) {
	for _, fx := range []string{"cg_simd_conv32.wasm", "cg_mem64_simd_conv.wasm"} {
		bin := testfixture.Wasm(t, fx)
		m, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatal(err)
		}
		res, err := transpile.Translate(io.Discard, m, transpile.Options{Package: "pkg", OutputImportPath: "sf/pkg", FuseLoops: true, FuseLoopUnroll: 4})
		if err != nil {
			t.Fatalf("translate %s: %v", fx, err)
		}
		if len(res.FusedLoops) == 0 {
			t.Errorf("%s: countdown conversion loop did not upgrade to a fused loop", fx)
		}
	}
}
