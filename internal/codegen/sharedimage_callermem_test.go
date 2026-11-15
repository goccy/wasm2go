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
// NewFromSnapshot) are handed an allocation as long as the memory may grow
// to, and the size the guest sees. The guest's memory is the first memSize
// bytes of the allocation: before any memory.grow, a read just below
// memSize works and one at memSize traps, a WASI call refuses a buffer at
// memSize with EFAULT, and the host's view of the memory (Memory) is
// memSize long. memory.grow makes the following pages accessible in place
// — the memory does not move — up to the end of the allocation and no
// further. A memSize longer than the allocation is refused. The memory is
// a Go allocation here: where linear memory is a reservation
// (memreserve_on.go) the constructors copy what it holds into a
// reservation of the instance's own, as long as the allocation; elsewhere
// they take it in place.
func TestNewWithMemoryBoundsAtMemorySize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		addr    string // the Go type of the guest's addresses
	}{
		{name: "wasm32", fixture: "cg_callermem_bounds", addr: "int32"},
		{name: "memory64", fixture: "cg_callermem_bounds_mem64", addr: "int64"},
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
				"memory is memory.size long: true holds what was handed in: true within the allocation or copied: true",
				"load below the end: 76",
				"load at the end traps: wasm: memory.copy out of bounds",
				"random_get below the end: 0",
				"random_get at the end: 21",
				"random_get across the end: 21",
				"grows from 2",
				"load in the new page: 78",
				"random_get in the new page: 0",
				"grown memory is memory.size long: true in place: true",
				"load past the grown end traps: wasm: memory.copy out of bounds",
				"grows to the end of the allocation from 3 and no further: -1",
				"snapshot memory is memory.size long: true within the allocation or copied: true",
				"snapshot random_get at the end: 21",
				"oversized: wasm2go: memory size exceeds the memory handed in",
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
	"unsafe"

	"gentest/pkg"
)

type addr = %s

const page = 1 << 16

// allocation is the memory handed to the constructors: four times what the
// guest starts with.
const allocation = 4 * pkg.InitialMemoryBytes

// inAllocationOrCopied reports whether the instance's memory is the
// allocation handed in, spanning all of it, or lies elsewhere.
func inAllocationOrCopied(memory, allocated []byte) bool {
	if unsafe.SliceData(memory) == unsafe.SliceData(allocated) {
		return cap(memory) == len(allocated)
	}
	return true
}

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
	mem := make([]byte, allocation)
	mem[pkg.InitialMemoryBytes-2] = 'H'
	m := pkg.NewWithMemory(pkg.DefaultWASI(), mem, pkg.InitialMemoryBytes)
	end := addr(pkg.InitialMemoryBytes)
	fmt.Println("memory is memory.size long:", len(m.Memory()) == pkg.InitialMemoryBytes,
		"holds what was handed in:", m.Load(end-2) == 'H',
		"within the allocation or copied:", inAllocationOrCopied(m.Memory(), mem))

	m.Store(end-1, 'L')
	fmt.Println("load below the end:", m.Load(end-1))
	fmt.Println("load at the end traps:", trapped(func() { m.Load(end) }))
	fmt.Println("random_get below the end:", m.Random(end-1, 1))
	fmt.Println("random_get at the end:", m.Random(end, 1))
	fmt.Println("random_get across the end:", m.Random(end-1, 2))

	base := unsafe.SliceData(m.Memory())
	fmt.Println("grows from", m.Grow(1))
	m.Store(end, 'N')
	fmt.Println("load in the new page:", m.Load(end))
	fmt.Println("random_get in the new page:", m.Random(end, page))
	fmt.Println("grown memory is memory.size long:", len(m.Memory()) == int(end)+page,
		"in place:", unsafe.SliceData(m.Memory()) == base)
	fmt.Println("load past the grown end traps:", trapped(func() { m.Load(end + page) }))
	fmt.Println("grows to the end of the allocation from", m.Grow(addr((allocation-int(end))/page-1)),
		"and no further:", m.Grow(1))

	smem := make([]byte, allocation)
	s := pkg.NewFromSnapshot(pkg.DefaultWASI(), smem, pkg.InitialMemoryBytes, nil)
	fmt.Println("snapshot memory is memory.size long:", len(s.Memory()) == pkg.InitialMemoryBytes,
		"within the allocation or copied:", inAllocationOrCopied(s.Memory(), smem))
	fmt.Println("snapshot random_get at the end:", s.Random(end, 1))

	fmt.Println("oversized:", trapped(func() {
		pkg.NewWithMemory(pkg.DefaultWASI(), make([]byte, page), pkg.InitialMemoryBytes)
	}))
}
`
