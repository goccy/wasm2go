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

// A shared memory's backing array spans its declared maximum from the
// start; the guest's memory is its first memory.size bytes. The WASI host
// bounds guest addresses by memory.size, not by the array: a buffer at
// memory.size gets EFAULT, and a C string whose NUL lies at memory.size,
// past the guest's memory, is refused (proc_spawn's path: EINVAL) rather
// than read on into the array. After memory.grow the same addresses are
// the guest's: random_get fills the buffer, and the path reaches the exec
// hook (which denies it, so no process starts).
func TestSharedMemoryWasiBoundsAtMemorySize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		addr    string // the Go type of the guest's addresses
	}{
		{name: "wasm32", fixture: "cg_wasi_shared_bounds", addr: "int32"},
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
			main := fmt.Sprintf(sharedWasiBoundsMain, tc.addr)
			out := runGoSnippetWithAux(t, buf.String(), main,
				[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
			for _, want := range []string{
				"memory spans the declared maximum: true",
				"random_get below the end: 0",
				"random_get at the end: 21",
				"random_get across the end: 21",
				"proc_spawn of a path unterminated within the memory: -28 exec hook saw: []",
				"grows from 1",
				"random_get at the old end: 0",
				"proc_spawn of the path: -2 exec hook saw: [path]",
				"random_get at the new end: 21",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in output:\n%s", want, out)
				}
			}
		})
	}
}

// sharedWasiBoundsMain drives a cg_wasi_shared_bounds module; %s is the Go
// type of its addresses.
const sharedWasiBoundsMain = `package main

import (
	"fmt"

	"gentest/pkg"
)

type addr = %s

const page = 1 << 16

func main() {
	w := pkg.DefaultWASI()
	var seen []string
	w.SetExecHook(func(path string, argv []string) bool {
		seen = append(seen, path)
		return false
	})
	m := pkg.NewWithWASI(w)
	end := addr(pkg.InitialMemoryBytes)
	fmt.Println("memory spans the declared maximum:", len(m.Memory()) == 4*page)

	fmt.Println("random_get below the end:", m.Random(end-1, 1))
	fmt.Println("random_get at the end:", m.Random(end, 1))
	fmt.Println("random_get across the end:", m.Random(end-1, 2))

	// "path" ends at memory.size; the array holds a zero right after it.
	for i, c := range "path" {
		m.Store(end-4+addr(i), int32(c))
	}
	fmt.Println("proc_spawn of a path unterminated within the memory:", m.Spawn(end-4), "exec hook saw:", seen)

	fmt.Println("grows from", m.Grow(1))
	fmt.Println("random_get at the old end:", m.Random(end, page))
	m.Store(end, 0)
	fmt.Println("proc_spawn of the path:", m.Spawn(end-4), "exec hook saw:", seen)
	fmt.Println("random_get at the new end:", m.Random(end+page, 1))
}
`
