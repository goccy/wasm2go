package transpile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestMemoryOfADroppedInstanceIsReleased pins that the reservation an
// instance's memory is, where the instance owns it, goes once nothing
// refers to the instance: memory New allocates, and memory handed to
// NewWithMemory that wasm2go did not map (copied into a reservation of the
// instance's own). The process's address space is no Go heap — dropping
// instances does not make the collector run, and the reservation of a
// wasm32 memory is 8 GiB of it — so a reservation kept after its instance
// is a leak of address space and of every page the instance wrote, until
// the process can map no more. After the instances are dropped and the
// collector has run, no byte of their memories can be read. Reservation
// builds only: a Go allocation stays readable while the heap keeps its
// pages. Both a wasm32 and a memory64 module.
func TestMemoryOfADroppedInstanceIsReleased(t *testing.T) {
	if !testReserved {
		t.Skip("memory is a Go allocation in this build")
	}
	for _, fixture := range []string{"cg_sharedimage.wat", "cg_sharedimage_mem64.wat"} {
		t.Run(strings.TrimSuffix(fixture, ".wat"), func(t *testing.T) {
			t.Parallel()
			got := runMem64(t, buildMem64Main(t, fixture, memReleaseMain, transpile.Options{}))
			diffLines(t, got, strings.TrimSpace(memReleaseWant))
		})
	}
}

// memReleaseMain drives cg_sharedimage or cg_sharedimage_mem64.
const memReleaseMain = `package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"

	"m64test/pkg"
)

const instances = 32

var sink byte

// readable reports whether the byte at p can be read: a fault there
// (panic-on-fault) says it cannot.
func readable(p unsafe.Pointer) (ok bool) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	sink = *(*byte)(p)
	return true
}

// mapped counts the memories, given by where they start, that can still be
// read once the collector has had its chance at the dropped instances
// (finalizers run on a goroutine of their own, after the collection that
// finds their objects unreachable).
func mapped(bases []uintptr) int {
	n := len(bases)
	for try := 0; try < 200 && n > 0; try++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
		n = 0
		for _, b := range bases {
			if readable(unsafe.Pointer(b)) {
				n++
			}
		}
	}
	return n
}

// base is where an instance's memory starts, as an address that keeps
// nothing alive.
func base(m *pkg.Module) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(m.Memory())))
}

func main() {
	var bases []uintptr
	for i := 0; i < instances; i++ {
		m := pkg.New()
		if !readable(unsafe.Pointer(base(m))) {
			panic("a live instance's memory cannot be read")
		}
		bases = append(bases, base(m))
	}
	fmt.Println("memories of New still mapped:", mapped(bases))

	bases = bases[:0]
	for i := 0; i < instances; i++ {
		m := pkg.NewWithMemory(make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes)
		bases = append(bases, base(m))
	}
	fmt.Println("memories copied from the Go heap still mapped:", mapped(bases))
}
`

var memReleaseWant = fmt.Sprintf("memories of New still mapped: %d\nmemories copied from the Go heap still mapped: %d", 0, 0)
