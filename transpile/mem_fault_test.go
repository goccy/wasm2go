package transpile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestMemoryFaultsTrap pins the traps of accesses past memory.size that,
// where linear memory is a reservation, fault on its inaccessible pages
// instead of failing a comparison: after memory.grow (the grown pages
// work, the next one traps), in a fork of the instance (ForkMemory and
// NewFromSnapshot: the child's memory ends where the parent's did, grows
// on its own, and the parent's stays as it was), and on goroutines that
// fault concurrently, each in its own instance. The goroutine's
// panic-on-fault setting is restored once guest code returns. A memory64
// memory with no ceiling grows past its 8 GiB reservation by moving to a
// larger one, contents and bounds intact (reservation builds only: a Go
// allocation of 8 GiB is no test fixture). With
// GOFLAGS=-tags=wasm2go_boundschecks, the same program runs the
// comparison form. Both backends, wasm32 and memory64.
func TestMemoryFaultsTrap(t *testing.T) {
	for _, mod := range []struct {
		name, fixture, addr string
	}{
		{name: "wasm32", fixture: "cg_mem32_bounds.wat", addr: "int32"},
		{name: "memory64", fixture: "cg_mem64_fault.wat", addr: "int64"},
	} {
		for _, tc := range []struct {
			name string
			opts transpile.Options
		}{
			{name: "asm"},
			{name: "pure", opts: transpile.Options{PureOnly: true}},
		} {
			t.Run(mod.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				main := fmt.Sprintf(memFaultMain, mod.addr, mod.name == "memory64" && testReserved)
				got := runMem64(t, buildMem64Main(t, mod.fixture, main, tc.opts))
				want := memFaultWant
				if mod.name == "memory64" && testReserved {
					want += memFaultMoveWant
				}
				diffLines(t, got, strings.TrimSpace(want))
			})
		}
	}
}

// memFaultMain drives cg_mem32_bounds or cg_mem64_fault; %s is the Go
// type of the guest's addresses, %v whether to grow a memory64 memory
// past its reservation.
const memFaultMain = `package main

import (
	"fmt"
	"runtime/debug"
	"sync"

	"m64test/pkg"
)

type addr = %s

const page = 65536

const moveTest = %v

const oob = "wasm: memory access out of bounds"

// trap runs f and returns what it panicked with, or "".
func trap(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func main() {
	m := pkg.New()
	end := addr(m.Size()) * page
	m.Store64(end-8, 7)
	fmt.Println("load64 end-8:", m.Load64(end-8))
	fmt.Println("load8 end:", trap(func() { m.Load8(end) }))
	fmt.Println("grows by 3 from", m.Grow(3))
	end = addr(m.Size()) * page
	fmt.Println("load8 at the old end:", m.Load8(end-3*page))
	fmt.Println("load8 new end-1:", m.Load8(end-1))
	fmt.Println("load8 new end:", trap(func() { m.Load8(end) }))
	fmt.Println("panic on fault left set:", debug.SetPanicOnFault(false))

	m.Store64(64, 42)
	f, err := pkg.ForkMemory(m, nil, 1<<20)
	if err != nil {
		panic(err)
	}
	c := pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals)
	fmt.Println("child load64 64:", c.Load64(64))
	fmt.Println("child load8 end-1:", c.Load8(end-1))
	fmt.Println("child load8 end:", trap(func() { c.Load8(end) }))
	fmt.Println("child grows by 1 from", c.Grow(1))
	fmt.Println("child load8 end:", c.Load8(end))
	fmt.Println("child load8 end+page:", trap(func() { c.Load8(end + page) }))
	fmt.Println("parent load8 end:", trap(func() { m.Load8(end) }))

	// Every goroutine faults in its own instance, half of its loads past
	// memory.size.
	var wg sync.WaitGroup
	results := make([]string, 8)
	for g := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst := pkg.New()
			e := addr(inst.Size()) * page
			loads, traps := 0, 0
			for i := 0; i < 2000; i++ {
				switch trap(func() { inst.Load8(e - 8 + addr(i%%16)) }) {
				case "":
					loads++
				case oob:
					traps++
				}
			}
			results[g] = fmt.Sprint(loads, "/", traps)
		}()
	}
	wg.Wait()
	fmt.Println("concurrent loads/traps:", results)

	if moveTest {
		n := pkg.New()
		n.Store64(64, 99)
		fmt.Println("grows past 8 GiB from", n.Grow(1<<17))
		e := addr(n.Size()) * page
		fmt.Println("keeps its contents:", n.Load64(64))
		n.Store64(e-8, 5)
		fmt.Println("load64 at the end:", n.Load64(e-8))
		fmt.Println("load8 past the end:", trap(func() { n.Load8(e) }))
	}
}
`

// memFaultWant is what memFaultMain prints for either module.
var memFaultWant = "load64 end-8: 7\n" +
	"load8 end: " + strings.TrimPrefix(oob, "trap ") + "\n" +
	"grows by 3 from 1\n" +
	"load8 at the old end: 0\n" +
	"load8 new end-1: 0\n" +
	"load8 new end: " + strings.TrimPrefix(oob, "trap ") + "\n" +
	"panic on fault left set: false\n" +
	"child load64 64: 42\n" +
	"child load8 end-1: 0\n" +
	"child load8 end: " + strings.TrimPrefix(oob, "trap ") + "\n" +
	"child grows by 1 from 4\n" +
	"child load8 end: 0\n" +
	"child load8 end+page: " + strings.TrimPrefix(oob, "trap ") + "\n" +
	"parent load8 end: " + strings.TrimPrefix(oob, "trap ") + "\n" +
	"concurrent loads/traps: [1000/1000 1000/1000 1000/1000 1000/1000 1000/1000 1000/1000 1000/1000 1000/1000]\n"

// memFaultMoveWant follows memFaultWant where the memory64 memory grows
// past its reservation.
var memFaultMoveWant = "grows past 8 GiB from 1\n" +
	"keeps its contents: 99\n" +
	"load64 at the end: 5\n" +
	"load8 past the end: " + strings.TrimPrefix(oob, "trap ") + "\n"
