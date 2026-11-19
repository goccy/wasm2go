package codegen_test

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// A call of a function import binds to that import even when imports of
// other kinds come before it: a call names its callee by function index,
// which counts the function imports only. Before, the callee was looked up
// among all the imports by that index, so with a tag first (env's
// __cpp_exception, as wasi-sdk's libc++ imports it) every call went to the
// import before its own — a call to the tag, fd_close with clock_time_get's
// arguments — and the translation did not build.
func TestCallsOfFunctionImportsAfterATagImport(t *testing.T) {
	mod := readFixture(t, "cg_tag_import_first.wasm")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

type env struct{}

func main() {
	m := pkg.New(env{})
	fmt.Printf("closebad=%d clock=%d\n", m.Closebad(), m.Clock())
}
`
	auxFiles := map[string][]byte{}
	for k, v := range res.AuxFiles {
		auxFiles[k] = v
	}
	for k, v := range res.Files {
		auxFiles[k] = v
	}
	out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars}, auxFiles)
	if want := "closebad=8 clock=0\n"; out != want {
		t.Errorf("output %q, want %q", out, want)
	}
}
