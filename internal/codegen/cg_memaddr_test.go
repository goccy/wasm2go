package codegen_test

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// TestMemAddrLargeAddendRuntime drives cg_memaddr — accesses whose base
// is `runtime index + large constant addend` (positive and negative) —
// and asserts the address arithmetic matches wazero exactly, including
// the mod-2^32 wrap of the negative addend's i32 add. Run for arm64, it
// also shows that gc assembles the accesses (the fixture's doc says why
// that once failed).
func TestMemAddrLargeAddendRuntime(t *testing.T) {
	i32 := wasm.ValI32
	runExportMatrix(t, "cg_memaddr.wasm", []call{
		// write_far(1000, 42) stores 42 at 1000+100000+8 = 101008.
		{export: "write_far", args: []uint64{1000, 42}, argTypes: []wasm.ValType{i32, i32}, resType: 0},
		{export: "read_far", args: []uint64{1000}, argTypes: []wasm.ValType{i32}, resType: i32},
		// read_neg(166540) loads (166540-65536)+4 = 101008 — the cell
		// write_far populated — through the wrapped i32 add.
		{export: "read_neg", args: []uint64{166540}, argTypes: []wasm.ValType{i32}, resType: i32},
	})
}
