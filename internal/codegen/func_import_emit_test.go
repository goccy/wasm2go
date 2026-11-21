package codegen_test

import (
	"bytes"
	"fmt"
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
// Every constructor sets the element slot; New and NewWithMemory run the
// start function once, NewFromSnapshot does not run it.
func TestReferencesOfFunctionImports(t *testing.T) {
	const want = "1 101 102 12884901892 <nil>\n2 103\n2 104\n"
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
	w := pkg.NewWithMemory(env{&inits}, make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes)
	fmt.Println(inits, w.ViaTable(3))
	s := pkg.NewFromSnapshot(env{&inits}, make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes, nil)
	fmt.Println(inits, s.ViaTable(4))
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
	w := pkg.NewWithMemory(env{&inits}, make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes)
	fmt.Println(inits, pkg.ViaTable(w, 3))
	s := pkg.NewFromSnapshot(env{&inits}, make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes, nil)
	fmt.Println(inits, pkg.ViaTable(s, 4))
}
`
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}

// The wasi-threads thread-spawn import, served by the threadSpawn helper
// rather than by the host, can be exported and placed in an element
// segment without being called: the export and the slot spawn through the
// helper, in the single- and the multi-package output.
func TestThreadSpawnImportExportedAndInATable(t *testing.T) {
	const want = "true true 2\n"
	const mainSrc = `package main

import (
	"fmt"
	"time"

	"gentest/pkg"
)

func main() {
	m := pkg.New()
	direct, viaTable := %[1]s > 0, %[2]s > 0
	deadline := time.Now().Add(10 * time.Second)
	for %[3]s < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	fmt.Println(direct, viaTable, %[3]s)
}
`
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	t.Run("single", func(t *testing.T) {
		mod := readFixture(t, "cg_thread_spawn_refs.wasm")
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		main := fmt.Sprintf(mainSrc, "m.Spawn(64)", "m.SpawnViaTable(64)", "m.Count()")
		if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
	t.Run("multi", func(t *testing.T) {
		restore := codegen.SetMultiPackageThreshold(0)
		defer restore()
		mod := readFixture(t, "cg_thread_spawn_refs.wasm")
		res, err := codegen.Translate(nil, mod, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		if _, ok := res.Files["base/base.go"]; !ok {
			t.Fatalf("output is not multi-package: %v", res.Files)
		}
		main := fmt.Sprintf(mainSrc, "pkg.Spawn(m, 64)", "pkg.SpawnViaTable(m, 64)", "pkg.Count(m)")
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}
