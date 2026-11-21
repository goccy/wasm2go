package transpile_test

import (
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// Calls of function imports bind to their own imports when a global import
// and a tag import come first, in the pure Go output and in the asm one
// alike: a call names its callee by function index, which counts the
// function imports only.
func TestCallsAfterImportsOfOtherKindsBindToTheirImports(t *testing.T) {
	for _, c := range []struct {
		name string
		opts transpile.Options
	}{
		{name: "pure", opts: transpile.Options{PureOnly: true}},
		{name: "asm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := buildMem64Main(t, "cg_func_imports_last.wasm", `package main

import (
	"fmt"

	"m64test/pkg"
)

type env struct{}

func main() {
	m := pkg.New(env{})
	fmt.Println(m.Closebad(), m.Clock())
}
`, c.opts)
			if got := runMem64(t, dir); got != "8 0" {
				t.Fatalf("closebad and clock = %q, want %q", got, "8 0")
			}
		})
	}
}

// An imported function that is exported, sits in an element segment or is
// the start function reaches the host method: the export calls it, the
// table slot holds a function that calls it, and the constructor calls it
// as the start function. In the single- and the multi-package output, pure
// and asm alike.
func TestReferencesOfFunctionImportsReachTheHost(t *testing.T) {
	const single = `package main

import (
	"fmt"

	"m64test/pkg"
)

type env struct{ inits *int }

func (e env) Add(m *pkg.Module, x int32) int32     { return x + 100 }
func (e env) Init(m *pkg.Module)                   { *e.inits++ }
func (e env) Pack(m *pkg.Module, a, b int32) int64 { return int64(a)<<32 | int64(b) }

func main() {
	inits := 0
	m := pkg.New(env{&inits})
	fmt.Println(inits, m.Add(1), m.ViaTable(2))
}
`
	const multi = `package main

import (
	"fmt"

	"m64test/pkg"
	"m64test/pkg/base"
)

type env struct{ inits *int }

func (e env) Add(m *base.Module, x int32) int32     { return x + 100 }
func (e env) Init(m *base.Module)                   { *e.inits++ }
func (e env) Pack(m *base.Module, a, b int32) int64 { return int64(a)<<32 | int64(b) }

func main() {
	inits := 0
	m := pkg.New(env{&inits})
	fmt.Println(inits, pkg.Add(m, 1), pkg.ViaTable(m, 2))
}
`
	for _, c := range []struct {
		name  string
		multi bool
		opts  transpile.Options
	}{
		{name: "single/pure", opts: transpile.Options{PureOnly: true}},
		{name: "single/asm"},
		{name: "multi/pure", multi: true, opts: transpile.Options{PureOnly: true}},
		{name: "multi/asm", multi: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			mainSrc := single
			if c.multi {
				restore := transpile.SetMultiPackageThreshold(0)
				defer restore()
				mainSrc = multi
			}
			dir := buildMem64Main(t, "cg_func_import_refs.wasm", mainSrc, c.opts)
			if got := runMem64(t, dir); got != "1 101 102" {
				t.Fatalf("start calls, export and call_indirect = %q, want %q", got, "1 101 102")
			}
		})
	}
}
