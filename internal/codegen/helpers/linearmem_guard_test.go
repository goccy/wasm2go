//go:build (linux || darwin) && !386 && !arm && !mips && !mipsle

package helpers

import (
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

const page = 65536

// readSink keeps faultAt's load from being optimized away.
var readSink byte

// faultAt reads m's linear-memory base + off with faults turned into panics
// and returns what memoryAccessTrap made of the recovered value (nil when the
// read succeeded).
func faultAt(m *Module, off uint64) (got any) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			got = memoryAccessTrap(m, r)
		}
	}()
	readSink = *(*byte)(unsafe.Add(m.M, uintptr(off)))
	return nil
}

func newReservedModule(t *testing.T, minBytes uint64) *Module {
	t.Helper()
	m := &Module{memMu: &sync.Mutex{}, memSize: &atomic.Uint64{}, threads: &threadPool{}}
	m.memory = initLinearMemory(m, minBytes, minBytes*2)
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	m.memSize.Store(minBytes)
	m.maxMem = 1 << 32
	return m
}

func TestNewLinearMemoryIsGuarded(t *testing.T) {
	m := newReservedModule(t, page)
	if got, want := uint64(len(m.memReserve)), linearMemoryReserve; got != want {
		t.Fatalf("reservation is %d bytes, want %d", got, want)
	}
	if len(m.memory) != page || cap(m.memory) != page {
		t.Fatalf("memory len/cap = %d/%d, want %d/%d", len(m.memory), cap(m.memory), page, page)
	}
	m.memory[page-1] = 1
	if got := faultAt(m, page-1); got != nil {
		t.Fatalf("in-bounds read faulted: %v", got)
	}
	for _, off := range []uint64{page, 1 << 32, linearMemoryReserve - 1} {
		if got := faultAt(m, off); got != "wasm: out of bounds memory access" {
			t.Fatalf("read at %#x: got %v, want the out-of-bounds trap", off, got)
		}
	}
}

func TestMemoryGrowReservedInPlace(t *testing.T) {
	m := newReservedModule(t, page)
	base := m.M
	if prev := memoryGrow(m, 2); prev != 1 {
		t.Fatalf("memoryGrow returned %d, want 1", prev)
	}
	if m.M != base {
		t.Fatal("growing a reserved memory moved it")
	}
	if len(m.memory) != 3*page || cap(m.memory) != 3*page {
		t.Fatalf("memory len/cap = %d/%d, want %d", len(m.memory), cap(m.memory), 3*page)
	}
	if m.memory[3*page-1] != 0 {
		t.Fatal("a freshly grown page is not zero")
	}
	m.memory[3*page-1] = 1
	if got := faultAt(m, 3*page); got != "wasm: out of bounds memory access" {
		t.Fatalf("read past the grown size: got %v, want the out-of-bounds trap", got)
	}
	m.maxMem = 3 * page
	if prev := memoryGrow(m, 1); prev != -1 {
		t.Fatalf("growing past maxMem returned %d, want -1", prev)
	}
}

func TestMemoryAccessTrapPassesOtherValues(t *testing.T) {
	m := newReservedModule(t, page)
	if got := memoryAccessTrap(m, "wasm: unreachable"); got != "wasm: unreachable" {
		t.Fatalf("a non-fault value changed: %v", got)
	}
	// A fault outside the reservation is the host's own bug: it must not be
	// reported as a guest trap.
	foreign := hostFault(uintptr(m.M) - 1)
	defer func() {
		if r := recover(); r != foreign {
			t.Fatalf("recovered %v, want the foreign fault re-raised", r)
		}
	}()
	memoryAccessTrap(m, foreign)
	t.Fatal("memoryAccessTrap returned for a fault outside the reservation")
}

type hostFault uintptr

func (f hostFault) Addr() uintptr { return uintptr(f) }

func TestMapLinearMemoryIsGuarded(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(2 * page); err != nil {
		t.Fatal(err)
	}
	mem, err := mapLinearMemory(int(f.Fd()), 2*page, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	if len(mem) != 2*page || cap(mem) != 2*page {
		t.Fatalf("mapping len/cap = %d/%d, want %d", len(mem), cap(mem), 2*page)
	}
	mem[2*page-1] = 1
	m := &Module{memory: mem, M: unsafe.Pointer(unsafe.SliceData(mem))}
	if got := faultAt(m, 2*page); got != "wasm: out of bounds memory access" {
		t.Fatalf("read past the mapping: got %v, want the out-of-bounds trap", got)
	}
	// Releasing through a shortened slice still returns the whole
	// reservation; a second release finds nothing mapped there.
	if err := releaseReservation(mem[:page]); err != nil {
		t.Fatalf("releasing the mapping: %v", err)
	}
	if err := releaseReservation(mem); err == nil {
		t.Fatal("the reservation was still mapped after release")
	}

	if _, err := mapLinearMemory(int(f.Fd()), int(linearMemoryReserve)+1, syscall.MAP_PRIVATE); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("mapping more than the reservation: err = %v, want the size error", err)
	}
}

func TestMapLinearMemoryErrors(t *testing.T) {
	if _, err := mapLinearMemory(-1, page, syscall.MAP_PRIVATE); err == nil {
		t.Fatal("mapping an invalid descriptor succeeded")
	}
	if _, err := mapLinearMemory(-1, 0, syscall.MAP_PRIVATE); err == nil {
		t.Fatal("mapping an empty memory succeeded")
	}
	// A shared mapping of a read-only descriptor reserves fine but cannot be
	// made writable: the commit fails and the reservation is released.
	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(page); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := mapLinearMemory(int(ro.Fd()), page, syscall.MAP_SHARED); err == nil {
		t.Fatal("a writable shared mapping of a read-only file succeeded")
	}
}

func TestEmptyLinearMemory(t *testing.T) {
	m := newReservedModule(t, 0)
	if len(m.memory) != 0 {
		t.Fatalf("memory len = %d, want 0", len(m.memory))
	}
	if got := faultAt(m, 0); got != "wasm: out of bounds memory access" {
		t.Fatalf("read of an empty memory: got %v, want the out-of-bounds trap", got)
	}
	if prev := memoryGrow(m, 1); prev != 0 {
		t.Fatalf("memoryGrow returned %d, want 0", prev)
	}
	m.memory[0] = 1
}

// A caller-supplied memory that outgrows its capacity moves into a guarded
// reservation instead of a heap array, and grows in place from then on.
func TestMemoryGrowRelocatesIntoReservation(t *testing.T) {
	m := newTestModule(make([]byte, page))
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	m.memory[page-1] = 7
	if prev := memoryGrow(m, 1); prev != 1 {
		t.Fatalf("memoryGrow returned %d, want 1", prev)
	}
	if m.memReserve == nil {
		t.Fatal("the relocated memory has no reservation")
	}
	if m.memory[page-1] != 7 {
		t.Fatal("relocation lost the old contents")
	}
	if got := faultAt(m, 2*page); got != "wasm: out of bounds memory access" {
		t.Fatalf("read past the relocated memory: got %v, want the out-of-bounds trap", got)
	}
	base := m.M
	if prev := memoryGrow(m, 1); prev != 2 || m.M != base {
		t.Fatalf("second grow: prev=%d moved=%v, want 2 in place", prev, m.M != base)
	}
}

// A shared memory's ceiling past the wasm32 address space is cut to it.
func TestNewLinearMemoryClampsToAddressSpace(t *testing.T) {
	mem, reserve, err := newLinearMemory(16<<30, 16<<30)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLinearMemory(reserve)
	if len(mem) != 1<<32 {
		t.Fatalf("memory len = %d, want %d", len(mem), uint64(1)<<32)
	}
}

func TestReleaseLinearMemory(t *testing.T) {
	_, reserve, err := newLinearMemory(page, page)
	if err != nil {
		t.Fatal(err)
	}
	releaseLinearMemory(reserve)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("releasing an already released reservation did not panic")
		}
	}()
	releaseLinearMemory(reserve)
}
