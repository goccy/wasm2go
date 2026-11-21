package codegen_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// forkAux is a file of the package that holds the Module: RunFork copies the
// memory and globals of m into a memory with room for one more page, builds
// the child instance from the copy through the forkModule field and runs it
// through the forkChild field. Its verbs are the package, then the layout's
// names of memSize, memory, forkModule, saveGlobals and forkChild.
const forkAux = `package %[1]s

func RunFork(m *Module, w *WasiStubs) (*Module, int32) {
	size := m.%[2]s.Load()
	memory := make([]byte, size+65536)
	copy(memory, m.%[3]s[:size])
	child := m.%[4]s(m, w, memory, size, %[5]s(m))
	return child, child.%[6]s(child)
}

func HasFork(m *Module) bool { return m.%[6]s != nil && m.%[4]s != nil }
`

// forkMain forks an instance of cg_wasi_fork_child.wat. Its verbs are the
// path of the runtime's package below gentest/pkg and the export calls
// m.Set(3), m.Cell(), m.G(), c.Cell(), c.G() and c.Grow() as the layout
// writes them.
const forkMain = `package main

import (
	"fmt"

	gen "gentest/pkg"
	rt "gentest/pkg%[1]s"
)

type env struct{}

func (env) Base(*rt.Module) int32 { return 4 }

func main() {
	m := gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{Args: []string{"p"}}), env{})
	%[2]s
	c, status := rt.RunFork(m, rt.NewWASI(rt.WASIConfig{Args: []string{"c", "d"}}))
	fmt.Println(status, %[3]s, %[4]s, %[5]s, %[6]s, %[7]s, %[7]s, rt.HasFork(c))
}
`

// A module with the fork child export carries what a fork runs: the child
// instance is built from a copy of the parent's memory and globals, with the
// wasi import it is given and the parent's other imports, and runs the
// export, in the single- and the multi-package output. The export is a DCE
// root even when EntryExports does not name it. The child's memory grows as
// far as the memory it is given is long.
func TestForkChildExport(t *testing.T) {
	// argc 2, cell 3, g 6 and base 4 in the child; the child's changes stay
	// in the child; one page to grow into.
	const want = "4632 3 6 -1 9 1 -1 true\n"
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	entry := opts
	entry.EntryExports = []string{"set", "cell", "g", "grow"}
	for name, opts := range map[string]codegen.Options{"single": opts, "entry exports": entry} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			res, err := codegen.Translate(&buf, readFixture(t, "cg_wasi_fork_child.wasm"), opts)
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			aux := map[string][]byte{"fork_aux.go": fmt.Appendf(nil, forkAux, "pkg", "memSize", "memory", "forkModule", "saveGlobals", "forkChild")}
			for k, v := range res.AuxFiles {
				aux[k] = v
			}
			main := fmt.Sprintf(forkMain, "", "m.Set(3)", "m.Cell()", "m.G()", "c.Cell()", "c.G()", "c.Grow()")
			if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, aux); out != want {
				t.Errorf("output %q, want %q", out, want)
			}
		})
	}
	t.Run("multi", func(t *testing.T) {
		restore := codegen.SetMultiPackageThreshold(0)
		defer restore()
		res, err := codegen.Translate(nil, readFixture(t, "cg_wasi_fork_child.wasm"), opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		if _, ok := res.Files["base/base.go"]; !ok {
			t.Fatalf("output is not multi-package: %v", res.Files)
		}
		aux := map[string][]byte{"base/fork_aux.go": fmt.Appendf(nil, forkAux, "base", "MemSize", "Memory", "ForkModule", "SaveGlobals", "ForkChild")}
		for k, v := range res.AuxFiles {
			aux[k] = v
		}
		main := fmt.Sprintf(forkMain, "/base", "gen.Set(m, 3)", "gen.Cell(m)", "gen.G(m)", "gen.Cell(c)", "gen.G(c)", "gen.Grow(c)")
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, aux); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}

// With EntryExports naming no export, the fork child export stays, and an
// export of its name that is no fork child goes.
func TestForkChildExportIsADCERoot(t *testing.T) {
	method := "(m *Module) " + codegen.ExportMethodName("__wasip1_posix_extension_fork_child") + "("
	for fixture, kept := range map[string]bool{"cg_wasi_fork_child.wasm": true, "cg_wasi_fork_child_type.wasm": false} {
		var buf bytes.Buffer
		if _, err := codegen.Translate(&buf, readFixture(t, fixture), codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", EntryExports: []string{}}); err != nil {
			t.Fatalf("translate %s: %v", fixture, err)
		}
		if got := strings.Contains(buf.String(), method); got != kept {
			t.Errorf("%s: export kept %v, want %v", fixture, got, kept)
		}
	}
}

// An export of the fork child's name that is not of type () -> i32 is no
// fork child: the Module carries nothing a fork runs.
func TestForkChildExportOfAnotherType(t *testing.T) {
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, readFixture(t, "cg_wasi_fork_child_type.wasm"), codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	aux := map[string][]byte{"fork_aux.go": fmt.Appendf(nil, forkAux, "pkg", "memSize", "memory", "forkModule", "saveGlobals", "forkChild")}
	for k, v := range res.AuxFiles {
		aux[k] = v
	}
	main := `package main

import (
	"fmt"

	"gentest/pkg"
)

func main() {
	fmt.Println(pkg.HasFork(pkg.NewWithWASI(pkg.NewWASI(pkg.WASIConfig{}))))
}
`
	if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, aux); out != "false\n" {
		t.Errorf("output %q, want %q", out, "false\n")
	}
}
