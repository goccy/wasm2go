package wasm_test

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// FuncImport and FuncTypeOf count the function imports only: a tag, memory or
// global import between them takes no function index.
func TestFuncImportSkipsImportsOfOtherKinds(t *testing.T) {
	m := &wasm.Module{
		Types: []wasm.FuncType{
			{Params: []wasm.ValType{wasm.ValI32}},
			{Params: []wasm.ValType{wasm.ValI64, wasm.ValI32}},
		},
		Imports: []wasm.Import{
			{Module: "env", Name: "g", Kind: wasm.ImportGlobal},
			{Module: "env", Name: "__cpp_exception", Kind: wasm.ImportTag},
			{Module: "m", Name: "first", Kind: wasm.ImportFunc, TypeIdx: 1},
			{Module: "env", Name: "memory", Kind: wasm.ImportMemory},
			{Module: "m", Name: "second", Kind: wasm.ImportFunc, TypeIdx: 0},
		},
		NumImportedFuncs: 2,
	}
	for idx, want := range []string{"first", "second"} {
		imp, ok := m.FuncImport(uint32(idx))
		if !ok || imp.Name != want {
			t.Errorf("FuncImport(%d) = %q, %v; want %q", idx, imp.Name, ok, want)
		}
	}
	if _, ok := m.FuncImport(2); ok {
		t.Error("FuncImport(2) of a module with two function imports reported one")
	}
	if got := m.FuncTypeOf(0); len(got.Params) != 2 {
		t.Errorf("FuncTypeOf(0) = %v, want first's type", got)
	}
	if got := m.FuncTypeOf(1); len(got.Params) != 1 {
		t.Errorf("FuncTypeOf(1) = %v, want second's type", got)
	}
}
