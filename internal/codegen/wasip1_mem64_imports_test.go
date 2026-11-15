package codegen_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestWasip1Mem64ImportsCompile translates a memory64 module that imports
// every wasi_snapshot_preview1 name WasiStubs binds, each with its wasm64
// signature, and builds the result: every import binds to the *64 method
// of its name, and the native WasiStubs has each of them with the
// signature the wasm type gives (NewWithWASI takes it as the interface the
// imports make). The fixture must name every import WasiStubs has a
// binding for, so that a memory64 module importing any of them compiles.
func TestWasip1Mem64ImportsCompile(t *testing.T) {
	bin := testfixture.Wasm(t, "wasip1_mem64_imports.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	src := buf.String()
	imported := map[string]bool{}
	for _, imp := range mod.Imports {
		if imp.Kind != wasm.ImportFunc {
			continue
		}
		imported[imp.Name] = true
		method := strings.ToUpper(imp.Name[:1]) + imp.Name[1:] + "64("
		if !strings.Contains(src, method) {
			t.Errorf("import %s does not bind to %s)", imp.Name, method)
		}
	}
	// The bindings of WasiStubs are the methods that take the Module first
	// and have a *64 twin; an import binds to its name capitalized (and
	// with 64 on a memory64 module), so the twin's name, lowercased in its
	// first letter, is the import's.
	stubs := reflect.TypeOf((*codegen.WasiStubs)(nil))
	module := reflect.TypeOf((*codegen.Module)(nil))
	takesModule := func(m reflect.Method) bool { return m.Type.NumIn() > 1 && m.Type.In(1) == module }
	bindings := 0
	for i := 0; i < stubs.NumMethod(); i++ {
		wide := stubs.Method(i)
		name, ok := strings.CutSuffix(wide.Name, "64")
		if !ok || !takesModule(wide) {
			continue
		}
		if narrow, ok := stubs.MethodByName(name); !ok || !takesModule(narrow) {
			continue
		}
		bindings++
		if imp := strings.ToLower(name[:1]) + name[1:]; !imported[imp] {
			t.Errorf("the fixture does not import %s, which WasiStubs binds (%s)", imp, wide.Name)
		}
	}
	if bindings < len(imported) {
		t.Errorf("WasiStubs has %d bindings with a *64 twin, fewer than the %d imports of the fixture", bindings, len(imported))
	}

	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	m := pkg.NewWithWASI(pkg.DefaultWASI())
	fmt.Println(m != nil)
}
`
	if got := runGoSnippetNoRace(t, src, main, res.Sidecars, filesWithAux(res)); strings.TrimSpace(got) != "true" {
		t.Fatalf("output = %q, want true", got)
	}
}
