package codegen_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// forkAux is a file of the package that holds the Module: RunFork copies the
// memory of m, builds the child instance from the copy through the
// forkModule field and runs it through the forkChild field. DataEnd is the
// dataEnd of m. Its verbs are the package, then the layout's names of
// memSize, memory, forkModule, forkChild and dataEnd.
const forkAux = `package %[1]s

func RunFork(m *Module, w *WasiStubs) (*Module, int32) {
	size := m.%[2]s.Load()
	memory := make([]byte, size)
	copy(memory, m.%[3]s[:size])
	child := m.%[4]s(m, w, memory, size)
	return child, child.%[5]s(child)
}

func HasFork(m *Module) bool { return m.%[5]s != nil && m.%[4]s != nil }

func DataEnd(m *Module) uint32 { return m.%[6]s }
`

// forkRefAux is a file of the package that holds the Module of
// cg_wasi_fork_child.wat: Ref and SetRef are its reference-typed global $r,
// which the guest's code cannot set. Its verbs are the package and the
// layout's name of $r.
const forkRefAux = `package %[1]s

func Ref(m *Module) any { return m.%[2]s }

func SetRef(m *Module, v any) { m.%[2]s = v }
`

// forkMain forks an instance of cg_wasi_fork_child.wat. Its verbs are the
// path of the runtime's package below gentest/pkg and the export calls
// m.Set(3), m.Init1(), m.Drop(), m.Cell(), m.G(), c.Cell(), c.G(), c.Grow()
// and c.Init0() as the layout writes them.
const forkMain = `package main

import (
	"fmt"

	gen "gentest/pkg"
	rt "gentest/pkg%[1]s"
)

type env struct{}

func (env) Base(*rt.Module) int32 { return 4 }

func trapped(f func()) (trap bool) {
	defer func() { trap = recover() != nil }()
	f()
	return false
}

func main() {
	m := gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{Args: []string{"p"}}), env{})
	%[2]s
	%[3]s
	%[4]s
	rt.SetRef(m, "r")
	c, status := rt.RunFork(m, rt.NewWASI(rt.WASIConfig{Args: []string{"c", "d"}}))
	fmt.Println(status, %[5]s, %[6]s, %[7]s, %[8]s, %[9]s, %[9]s, %[9]s, trapped(func() { %[10]s }), rt.DataEnd(c), rt.Ref(c), rt.HasFork(c))
}
`

// A module with the fork child export carries what a fork runs: the child
// instance is built from a copy of the parent's memory, with the parent's
// globals (a reference-typed one too), memory ceiling, dropped data segments
// and data end, the wasi import it is given and the parent's other imports,
// and runs the export, in the single- and the multi-package output. The
// export is a DCE root even when EntryExports does not name it.
func TestForkChildExport(t *testing.T) {
	// argc 2, cell 3, g 6 and base 4 in the child; the child's changes stay
	// in the child; the child grows to the parent's maximum of 3 pages, its
	// segment 0 is dropped, its data ends where the parent's does and its
	// $r is the parent's.
	const want = "4632 3 6 -1 9 1 2 -1 true 40004 r true\n"
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	entry := opts
	entry.EntryExports = []string{"set", "cell", "g", "grow", "drop", "init0", "init1"}
	for name, opts := range map[string]codegen.Options{"single": opts, "entry exports": entry} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			res, err := codegen.Translate(&buf, readFixture(t, "cg_wasi_fork_child.wasm"), opts)
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			aux := map[string][]byte{
				"fork_aux.go":     fmt.Appendf(nil, forkAux, "pkg", "memSize", "memory", "forkModule", "forkChild", "dataEnd"),
				"fork_ref_aux.go": fmt.Appendf(nil, forkRefAux, "pkg", "g1"),
			}
			for k, v := range res.AuxFiles {
				aux[k] = v
			}
			main := fmt.Sprintf(forkMain, "", "m.Set(3)", "m.Init1()", "m.Drop()", "m.Cell()", "m.G()", "c.Cell()", "c.G()", "c.Grow()", "c.Init0()")
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
		aux := map[string][]byte{
			"base/fork_aux.go":     fmt.Appendf(nil, forkAux, "base", "MemSize", "Memory", "ForkModule", "ForkChild", "DataEnd"),
			"base/fork_ref_aux.go": fmt.Appendf(nil, forkRefAux, "base", "G1"),
		}
		for k, v := range res.AuxFiles {
			aux[k] = v
		}
		main := fmt.Sprintf(forkMain, "/base", "gen.Set(m, 3)", "gen.Init1(m)", "gen.Drop(m)", "gen.Cell(m)", "gen.G(m)", "gen.Cell(c)", "gen.G(c)", "gen.Grow(c)", "gen.Init0(c)")
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
	aux := map[string][]byte{"fork_aux.go": fmt.Appendf(nil, forkAux, "pkg", "memSize", "memory", "forkModule", "forkChild", "dataEnd")}
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

// procForkMain runs cg_wasi_proc_fork.wat's run with CopyForker and with no
// Forker. Its verbs are the path of the runtime's package below gentest/pkg
// and the calls of run on fork and on none as the layout writes them.
const procForkMain = `package main

import (
	"fmt"

	gen "gentest/pkg"
	rt "gentest/pkg%[1]s"
)

func main() {
	fork := gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{Fork: rt.CopyForker}))
	none := gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{}))
	fmt.Println(%[2]s, %[3]s)
}
`

// A guest's proc_fork runs its fork child export in a copy of the instance,
// which the guest waits for, in the single- and the multi-package output;
// without a Forker it fails with ENOSYS.
func TestProcForkOfAGuest(t *testing.T) {
	// The child's exit status 7 + 10*3, and -ENOSYS.
	const want = "9472 -52\n"
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	t.Run("single", func(t *testing.T) {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, readFixture(t, "cg_wasi_proc_fork.wasm"), opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		main := fmt.Sprintf(procForkMain, "", "fork.Run()", "none.Run()")
		if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
	t.Run("multi", func(t *testing.T) {
		restore := codegen.SetMultiPackageThreshold(0)
		defer restore()
		res, err := codegen.Translate(nil, readFixture(t, "cg_wasi_proc_fork.wasm"), opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		main := fmt.Sprintf(procForkMain, "/base", "gen.Run(fork)", "gen.Run(none)")
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}
