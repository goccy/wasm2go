package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestWasip1Mem64ImportsCompile translates a memory64 module that imports
// every wasi_snapshot_preview1 name the Perl interpreter uses, each with its
// wasm64 signature, and builds the result: every import binds to the *64
// method of its name, and the native WasiStubs has each of them with the
// signature the wasm type gives (NewWithWASI takes it as the interface the
// imports make).
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
	imported := 0
	for _, imp := range mod.Imports {
		if imp.Kind != wasm.ImportFunc {
			continue
		}
		imported++
		method := strings.ToUpper(imp.Name[:1]) + imp.Name[1:] + "64("
		if !strings.Contains(src, method) {
			t.Errorf("import %s does not bind to %s)", imp.Name, method)
		}
	}
	if imported < 100 {
		t.Fatalf("the fixture imports %d functions, want every one the interpreter uses", imported)
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
