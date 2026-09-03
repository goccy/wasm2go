package gcasm

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// The expected sizes are the "-N" values the gc toolchain assigned to
// real bundle TEXT directives for these signatures ($128-16, $16-20,
// $304-24, $16-36, $448-56), so the trampolines' frames match what the
// Go declarations promise.
func TestABI0ArgBytes(t *testing.T) {
	i32, i64, f32 := wasm.ValI32, wasm.ValI64, wasm.ValF32
	cases := []struct {
		name    string
		params  []wasm.ValType
		results []wasm.ValType
		want    int
	}{
		{"(m, i64)", []wasm.ValType{i64}, nil, 16},
		{"(m, f32) f32: result section pointer-aligned", []wasm.ValType{f32}, []wasm.ValType{f32}, 20},
		{"(m, i64) i64", []wasm.ValType{i64}, []wasm.ValType{i64}, 24},
		{"(m, 7 x i32): no result, no tail rounding", []wasm.ValType{i32, i32, i32, i32, i32, i32, i32}, nil, 36},
		{"(m, i64, i32, i32, i64, i64, i64) i64", []wasm.ValType{i64, i32, i32, i64, i64, i64}, []wasm.ValType{i64}, 56},
		{"(m, i32) i64: i64 result aligns past the i32", []wasm.ValType{i32}, []wasm.ValType{i64}, 24},
		{"(m, i32, i64): i64 param aligns to 8", []wasm.ValType{i32, i64}, nil, 24},
	}
	for _, c := range cases {
		if got := abi0ArgBytes(wasm.FuncType{Params: c.params, Results: c.results}); got != c.want {
			t.Errorf("%s: abi0ArgBytes = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCrossChunkPullConflicts(t *testing.T) {
	pulled := map[string]bool{"m/p0.Fn1": true, "m/p2.Fn9": true, "m/base.Helper": true}
	spelled := map[string]bool{"m/p2.Fn9": true, "m/p0.Fn1": true, "m/p1.Fn3": true}
	got := crossChunkPullConflicts(pulled, spelled)
	if len(got) != 2 || got[0] != "m/p0.Fn1" || got[1] != "m/p2.Fn9" {
		t.Fatalf("conflicts = %v, want [m/p0.Fn1 m/p2.Fn9]", got)
	}
	if got := crossChunkPullConflicts(map[string]bool{"m/base.Helper": true}, spelled); len(got) != 0 {
		t.Fatalf("disjoint sets reported %v", got)
	}
}
