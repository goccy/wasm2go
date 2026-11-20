package codegen_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// The constructors that take the caller's memory (NewWithMemory,
// NewFromSnapshot) are handed an allocation and the size the guest sees.
// The guest's memory is the first memSize bytes of the allocation: a
// memSize as long as the allocation is taken, and one longer than the
// allocation is refused.
func TestNewWithMemoryBoundsAtMemorySize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		addr    string // the Go type of the guest's addresses
	}{
		{name: "wasm32", fixture: "cg_callermem_bounds", addr: "int32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := testfixture.Wasm(t, tc.fixture)
			parsed, err := wasm.Parse(bytes.NewReader(bin))
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			res, err := codegen.Translate(&buf, parsed, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
			if err != nil {
				t.Fatal(err)
			}
			main := fmt.Sprintf(callerMemBoundsMain, tc.addr)
			out := runGoSnippetWithAux(t, buf.String(), main,
				[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
			for _, want := range []string{
				"random_get below the end: 0",
				"random_get at the end: 21",
				"snapshot random_get below the end: 0",
				"snapshot random_get at the end: 21",
				"oversized: wasm2go: memory size exceeds the memory handed in",
				"oversized snapshot: wasm2go: memory size exceeds the memory handed in",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in output:\n%s", want, out)
				}
			}
		})
	}
}

// callerMemBoundsMain drives a cg_callermem_bounds module; %s is the Go
// type of its addresses.
const callerMemBoundsMain = `package main

import (
	"fmt"

	"gentest/pkg"
)

type addr = %s

const page = 1 << 16

// trapped runs f and returns what it panicked with, or "".
func trapped(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func main() {
	m := pkg.NewWithMemory(pkg.DefaultWASI(), make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes)
	end := addr(pkg.InitialMemoryBytes)
	fmt.Println("random_get below the end:", m.Random(end-1, 1))
	fmt.Println("random_get at the end:", m.Random(end, 1))

	s := pkg.NewFromSnapshot(pkg.DefaultWASI(), make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes, nil)
	fmt.Println("snapshot random_get below the end:", s.Random(end-1, 1))
	fmt.Println("snapshot random_get at the end:", s.Random(end, 1))

	fmt.Println("oversized:", trapped(func() {
		pkg.NewWithMemory(pkg.DefaultWASI(), make([]byte, page), pkg.InitialMemoryBytes)
	}))
	fmt.Println("oversized snapshot:", trapped(func() {
		pkg.NewFromSnapshot(pkg.DefaultWASI(), make([]byte, page), pkg.InitialMemoryBytes, nil)
	}))
}
`
