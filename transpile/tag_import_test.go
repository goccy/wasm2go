package transpile_test

import (
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// Calls of function imports bind to their own imports when a tag import
// comes first, in the pure Go output and in the asm one alike: a call names
// its callee by function index, which counts the function imports only.
func TestCallsAfterATagImportBindToTheirImports(t *testing.T) {
	for _, c := range []struct {
		name string
		opts transpile.Options
	}{
		{name: "pure", opts: transpile.Options{PureOnly: true}},
		{name: "asm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := buildMem64Main(t, "cg_tag_import_first.wasm", `package main

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
