package asmgen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

func TestHelperNameUtils(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"add", "Add"},
		{"Add", "Add"},
		{"f32_min", "F32_min"},
	}
	for _, c := range cases {
		if got := capitalizeHelperName(c.in); got != c.want {
			t.Errorf("capitalizeHelperName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	exp := []struct{ in, want string }{
		{"", "_"},
		{"add", "Add"},
		{"Add", "Add"},
		{"_x", "X_x"},
		{"1abc", "X1abc"},
	}
	for _, c := range exp {
		if got := capitalizeExported(c.in); got != c.want {
			t.Errorf("capitalizeExported(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	types := []struct {
		in   ssa.Type
		want string
	}{
		{ssa.TypeI32, "int32"},
		{ssa.TypeI64, "int64"},
		{ssa.TypeF32, "float32"},
		{ssa.TypeF64, "float64"},
		{ssa.TypeV128, "<?>"},
	}
	for _, c := range types {
		if got := helperTypeName(c.in); got != c.want {
			t.Errorf("helperTypeName(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := packedSlotWords(ssa.TypeV128); got != 2 {
		t.Errorf("packedSlotWords(v128) = %d, want 2", got)
	}
	if got := packedSlotWords(ssa.TypeI64); got != 1 {
		t.Errorf("packedSlotWords(i64) = %d, want 1", got)
	}
}

// TestBuildWrappers smoke-checks the whole-module wrapper generator on
// a real fixture module in both naming conventions.
func TestBuildWrappers(t *testing.T) {
	// Wrappers are demand-driven: only modules whose SSA uses
	// call_indirect or the bulk-memory ops get any;
	// cg_indirect exercises the call_indirect trigger family.
	for _, fixture := range []string{"cg_indirect"} {
		bin := testfixture.Wasm(t, fixture)
		mod, err := wasm.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatalf("parse %s: %v", fixture, err)
		}
		single := BuildWrappers(mod, false)
		multi := BuildWrappers(mod, true)
		for _, s := range []string{single, multi} {
			if !strings.Contains(s, "func") {
				t.Fatalf("%s: wrapper output has no funcs:\n%.400s", fixture, s)
			}
		}
	}
}
