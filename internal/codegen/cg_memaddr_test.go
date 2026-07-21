package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestMemAddrFoldRuntime drives cg_memaddr — accesses whose base is
// `runtime index + large constant addend` (positive and negative).
// The FoldMemAddend pass moves the addend into the access's static
// offset (routed through _consts); this asserts the rewritten
// address arithmetic still matches wazero exactly, including the
// mod-2^32 wrap the negative addend relies on.
func TestMemAddrFoldRuntime(t *testing.T) {
	i32 := wasm.ValI32
	runExportMatrix(t, "cg_memaddr.wasm", []call{
		// write_far(1000, 42) stores 42 at 1000+100000+8 = 101008.
		{export: "write_far", args: []uint64{1000, 42}, argTypes: []wasm.ValType{i32, i32}, resType: 0},
		{export: "read_far", args: []uint64{1000}, argTypes: []wasm.ValType{i32}, resType: i32},
		// read_neg(166540) loads (166540-65536)+4 = 101008 — the cell
		// write_far populated — through the wrapped-uint32 offset.
		{export: "read_neg", args: []uint64{166540}, argTypes: []wasm.ValType{i32}, resType: i32},
	})
}

// TestMemAddrFoldEmitShape pins the generated-source shape the fold
// exists to produce: no access site may carry the large addend as an
// inline int32 literal (the arm64 literal-pool hazard — gc folds it
// into an addressing immediate); the totals must instead be read from
// the _consts table.
func TestMemAddrFoldEmitShape(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_memaddr")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "memaddrmod", OutputImportPath: "gentest/memaddrmod"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var sb strings.Builder
	sb.Write(buf.Bytes())
	for _, data := range res.AuxFiles {
		sb.Write(data)
	}
	for _, data := range res.Files {
		sb.Write(data)
	}
	src := sb.String()

	if !strings.Contains(src, "_consts[") {
		t.Fatalf("no _consts table access in output — large addends were not routed through the table")
	}
	// The addends must be gone from expression position: after the fold
	// the Add32 is dead and the totals (100008, 4294901764, ...) live
	// only as _consts table data. A surviving `int32(100000)` /
	// `int32(-65536)` means an access site kept the addend in its base
	// sum, reintroducing the out-of-range addressing immediate.
	for _, lit := range []string{"int32(100000)", "int32(-65536)"} {
		if strings.Contains(src, lit) {
			t.Errorf("addend survives in expression position as %s — access site bypassed the _consts guard", lit)
		}
	}
}
