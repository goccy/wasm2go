package helpers

import (
	"encoding/binary"
	"sync"
	"testing"
	"unsafe"
)

// TestAccessMemoryConcurrentGrow drives memoryGrow and accessMemory
// from two goroutines. Run under -race this pins the synchronisation
// contract: the out-of-band writer never observes a torn slice header
// and never writes into an abandoned backing array — accessMemory
// holds the same lock memoryGrow takes for the header rewrite and the
// relocating copy, so a write that lands is either already in the
// live array or is carried into the next one by the relocation copy.
func TestAccessMemoryConcurrentGrow(t *testing.T) {
	const flagAddr = 64 // low static-region word, always < initial len
	m := newTestModule(make([]byte, 1<<16, 1<<17))
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Grow one page at a time: the capacity doubling makes this
		// alternate between reslice-only and relocating grows, so both
		// header-mutation paths run against the concurrent writer.
		for i := 0; i < 200; i++ {
			if memoryGrow(m, 1) < 0 {
				t.Errorf("memoryGrow failed at step %d", i)
				return
			}
		}
	}()

	for i := uint32(1); i <= 1000; i++ {
		accessMemory(m, func(mem []byte) {
			binary.LittleEndian.PutUint32(mem[flagAddr:], i)
		})
	}
	wg.Wait()

	// After both sides quiesce, the LAST write must be visible in the
	// final backing array — relocations must have carried it forward.
	var got uint32
	accessMemory(m, func(mem []byte) {
		got = binary.LittleEndian.Uint32(mem[flagAddr:])
	})
	if got != 1000 {
		t.Fatalf("final flag = %d, want 1000 (write lost across a relocation)", got)
	}
	if wantPages := int32((1<<16)/65536 + 200); memorySize(m) != wantPages {
		t.Fatalf("memorySize = %d, want %d", memorySize(m), wantPages)
	}
}

// TestMemoryFillPaths pins both memoryFill fast paths: the constant-
// zero range fill (compiler memclr form) and the copy-doubling
// non-zero fill, across sizes that exercise the doubling loop's
// partial final chunk, plus byte-exact content and neighbour
// preservation.
func TestMemoryFillPaths(t *testing.T) {
	for _, n := range []int32{1, 2, 3, 7, 8, 9, 1000, 4096, 65537} {
		for _, val := range []int32{0, 0xA5} {
			m := newTestModule(make([]byte, 70000))
			for i := range m.memory {
				m.memory[i] = 0xEE
			}
			memoryFill(m, 16, val, n)
			if m.memory[15] != 0xEE || m.memory[16+int(n)] != 0xEE {
				t.Fatalf("n=%d val=%#x: neighbours clobbered", n, val)
			}
			want := byte(val)
			for i := int32(0); i < n; i++ {
				if m.memory[16+i] != want {
					t.Fatalf("n=%d val=%#x: byte %d = %#x, want %#x", n, val, i, m.memory[16+i], want)
				}
			}
		}
	}
	// Out-of-bounds still panics.
	m := newTestModule(make([]byte, 64))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected OOB panic")
			}
		}()
		memoryFill(m, 60, 1, 8)
	}()
}
