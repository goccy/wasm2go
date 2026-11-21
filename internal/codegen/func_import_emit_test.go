package codegen_test

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// A call of a function import binds to that import when a global import and
// a tag import come before it: a call names its callee by function index,
// which counts the function imports only.
func TestCallsOfFunctionImportsAfterImportsOfOtherKinds(t *testing.T) {
	mod := readFixture(t, "cg_func_imports_last.wasm")
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

// An imported function that is exported (under a plain and under a
// bulk-dispatch name), sits in an element segment or is the start function
// reaches the host method, in the single- and the multi-package output.
func TestReferencesOfFunctionImports(t *testing.T) {
	const want = "1 101 102 12884901892 <nil>\n"
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", BulkExportPrefix: "w_"}
	t.Run("single", func(t *testing.T) {
		mod := readFixture(t, "cg_func_import_refs.wasm")
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		main := `package main

import (
	"fmt"
	"gentest/pkg"
)

type env struct{ inits *int }

func (e env) Add(m *pkg.Module, x int32) int32     { return x + 100 }
func (e env) Init(m *pkg.Module)                   { *e.inits++ }
func (e env) Pack(m *pkg.Module, a, b int32) int64 { return int64(a)<<32 | int64(b) }

func main() {
	inits := 0
	m := pkg.New(env{&inits})
	packed, err := pkg.Inv_1_2(m, 3, 4)
	fmt.Println(inits, m.Add(1), m.ViaTable(2), packed, err)
}
`
		if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
	t.Run("multi", func(t *testing.T) {
		restore := codegen.SetMultiPackageThreshold(0)
		defer restore()
		mod := readFixture(t, "cg_func_import_refs.wasm")
		res, err := codegen.Translate(nil, mod, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		if _, ok := res.Files["base/base.go"]; !ok {
			t.Fatalf("output is not multi-package: %v", res.Files)
		}
		main := `package main

import (
	"fmt"
	"gentest/pkg"
	"gentest/pkg/base"
)

type env struct{ inits *int }

func (e env) Add(m *base.Module, x int32) int32     { return x + 100 }
func (e env) Init(m *base.Module)                   { *e.inits++ }
func (e env) Pack(m *base.Module, a, b int32) int64 { return int64(a)<<32 | int64(b) }

func main() {
	inits := 0
	m := pkg.New(env{&inits})
	packed, err := pkg.Inv_1_2(m, 3, 4)
	fmt.Println(inits, pkg.Add(m, 1), pkg.ViaTable(m, 2), packed, err)
}
`
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}
