package helpers

import (
	"encoding/binary"
	"sync"
	"testing"
	"unsafe"
)

// Coverage for the memory-access, passive-segment, atomic, and thread helpers
// that codegen emits into generated output via //go:embed. They are selected by
// name at generation time, so nothing in this package references them directly;
// without a test they are both unlinted (staticcheck U1000) and, worse,
// unguarded against regression. These tests exercise each one against a
// hand-built Module, exactly as generated New() sets one up.

// newMemModuleM builds a Module whose M (the unsafe base pointer the
// mem-access and atomic helpers dereference) points at its memory, the way
// generated New() initialises it. newTestModule alone leaves M nil, which
// these helpers dereference through, so tests that touch memory must use this.
func newMemModuleM(size int) *Module {
	m := newTestModule(make([]byte, size))
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	return m
}

func TestMemoryInitAndDataDrop(t *testing.T) {
	m := newMemModuleM(64)
	m.dataSegs = [][]byte{[]byte("hello world")}

	// Copy "hello" (src 0, len 5) to offset 4.
	memoryInit(m, 0, 4, 0, 5)
	if got := string(m.memory[4:9]); got != "hello" {
		t.Errorf("memoryInit copied %q, want %q", got, "hello")
	}
	// dataEnd tracks the end of the installed segment (dst 4 + n 5).
	if m.dataEnd != 9 {
		t.Errorf("dataEnd = %d, want 9 (dst+n)", m.dataEnd)
	}
	// n == 0 is a no-op and must not touch memory or dataEnd.
	memoryInit(m, 0, 60, 0, 0)
	if m.dataEnd != 9 {
		t.Errorf("dataEnd moved on a zero-length init: %d", m.dataEnd)
	}
	// Re-initialising with identical bytes is the compare-then-write path: it
	// must leave the memory correct (and, though we cannot observe the skipped
	// write directly, must not corrupt it).
	memoryInit(m, 0, 4, 0, 5)
	if got := string(m.memory[4:9]); got != "hello" {
		t.Errorf("second memoryInit corrupted memory: %q", got)
	}

	// Out of bounds on the source and on the destination both trap.
	mustPanic(t, "wasm: memory.init out of bounds", func() { memoryInit(m, 0, 0, 0, 100) })
	mustPanic(t, "wasm: memory.init out of bounds", func() { memoryInit(m, 0, 60, 0, 10) })

	// After data.drop the segment is nil; naming it in memory.init traps.
	dataDrop(m, 0)
	if m.dataSegs[0] != nil {
		t.Error("dataDrop did not nil the segment")
	}
	mustPanic(t, "wasm: memory.init out of bounds", func() { memoryInit(m, 0, 0, 0, 1) })
}

func TestAtomicMemoryOps(t *testing.T) {
	m := newMemModuleM(64)

	// store / load, 32 and 64 bit.
	atomicStore32(m, 0, 0, 0x11223344)
	if got := atomicLoad32(m, 0, 0); got != 0x11223344 {
		t.Errorf("atomicLoad32 = %#x, want 0x11223344", got)
	}
	atomicStore64(m, 8, 0, 0x1122334455667788)
	if got := atomicLoad64(m, 8, 0); got != 0x1122334455667788 {
		t.Errorf("atomicLoad64 = %#x", got)
	}

	// RMW helpers return the OLD value and leave the new one behind.
	atomicStore32(m, 0, 0, 100)
	if old := atomicRmwAdd32(m, 0, 0, 5); old != 100 {
		t.Errorf("atomicRmwAdd32 old = %d, want 100", old)
	}
	if got := atomicLoad32(m, 0, 0); got != 105 {
		t.Errorf("after add: %d, want 105", got)
	}
	if old := atomicRmwSub32(m, 0, 0, 5); old != 105 {
		t.Errorf("atomicRmwSub32 old = %d, want 105", old)
	}
	atomicStore32(m, 0, 0, 0xF0)
	if old := atomicRmwAnd32(m, 0, 0, 0x3C); old != 0xF0 || atomicLoad32(m, 0, 0) != 0x30 {
		t.Errorf("atomicRmwAnd32: old %#x new %#x, want 0xF0 / 0x30", old, atomicLoad32(m, 0, 0))
	}
	atomicStore32(m, 0, 0, 0xF0)
	if old := atomicRmwOr32(m, 0, 0, 0x0F); old != 0xF0 || atomicLoad32(m, 0, 0) != 0xFF {
		t.Errorf("atomicRmwOr32: old %#x new %#x, want 0xF0 / 0xFF", old, atomicLoad32(m, 0, 0))
	}
	atomicStore32(m, 0, 0, 0xFF)
	if old := atomicRmwXor32(m, 0, 0, 0x0F); old != 0xFF || atomicLoad32(m, 0, 0) != 0xF0 {
		t.Errorf("atomicRmwXor32: old %#x new %#x, want 0xFF / 0xF0", old, atomicLoad32(m, 0, 0))
	}

	// The generic op-taking RMW forms (atomicRmw32 / atomicRmw64).
	atomicStore32(m, 0, 0, 7)
	if old := atomicRmw32(m, 0, 0, func(o uint32) uint32 { return o * 3 }); old != 7 || atomicLoad32(m, 0, 0) != 21 {
		t.Errorf("atomicRmw32: old %d new %d, want 7 / 21", old, atomicLoad32(m, 0, 0))
	}
	atomicStore64(m, 8, 0, 4)
	if old := atomicRmw64(m, 8, 0, func(o uint64) uint64 { return o + 100 }); old != 4 || atomicLoad64(m, 8, 0) != 104 {
		t.Errorf("atomicRmw64: old %d new %d, want 4 / 104", old, atomicLoad64(m, 8, 0))
	}

	// Sub-word atomics: store and zero-extended load, 8- and 16-bit lanes.
	atomicStore32_8(m, 16, 0, 0xAB)
	if got := atomicLoad32_8u(m, 16, 0); got != 0xAB {
		t.Errorf("atomicLoad32_8u = %#x, want 0xAB", got)
	}
	atomicStore32_16(m, 16, 0, 0xBEEF)
	if got := atomicLoad32_16u(m, 16, 0); got != 0xBEEF {
		t.Errorf("atomicLoad32_16u = %#x, want 0xBEEF", got)
	}
	atomicStore64_8(m, 24, 0, 0xCD)
	if got := atomicLoad64_8u(m, 24, 0); got != 0xCD {
		t.Errorf("atomicLoad64_8u = %#x, want 0xCD", got)
	}
	atomicStore64_16(m, 24, 0, 0xFACE)
	if got := atomicLoad64_16u(m, 24, 0); got != 0xFACE {
		t.Errorf("atomicLoad64_16u = %#x, want 0xFACE", got)
	}
	atomicStore64_32(m, 24, 0, 0x0BADF00D)
	if got := atomicLoad64_32u(m, 24, 0); got != 0x0BADF00D {
		t.Errorf("atomicLoad64_32u = %#x, want 0x0BADF00D", got)
	}

	// atomicEA's bounds and alignment checks (reached through the ops above).
	mustPanic(t, "wasm: unaligned atomic access", func() { atomicLoad32(m, 1, 0) })
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicLoad32(m, 60, 8) })
}

func TestThreadSpawnRunsThreadStart(t *testing.T) {
	m := newMemModuleM(64)

	var mu sync.Mutex
	var gotTID, gotArg int32
	m.threadStart = func(child *Module, tid, arg int32) {
		mu.Lock()
		gotTID, gotArg = tid, arg
		mu.Unlock()
		// The agent runs on a struct COPY that shares the memory: a write here
		// must be visible through the parent Module.
		binary.LittleEndian.PutUint32(child.memory[0:4], uint32(arg*2))
	}

	tid := threadSpawn(m, 21)
	if tid != 1 {
		t.Errorf("first threadSpawn tid = %d, want 1", tid)
	}
	ThreadsWait(m)

	mu.Lock()
	defer mu.Unlock()
	if gotTID != 1 || gotArg != 21 {
		t.Errorf("threadStart saw tid=%d arg=%d, want 1/21", gotTID, gotArg)
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[0:4])); got != 42 {
		t.Errorf("agent's write not visible through shared memory: %d, want 42", got)
	}

	// A module that exports no wasi_thread_start returns -1.
	if got := threadSpawn(newMemModuleM(8), 0); got != -1 {
		t.Errorf("threadSpawn with no threadStart = %d, want -1", got)
	}
}

func TestWasmTrapHelpersPanic(t *testing.T) {
	mustPanic(t, "wasm: memory.init out of bounds", wasm_trap_meminit_oob)
	mustPanic(t, "wasm: atomic access out of bounds", wasm_trap_atomic_oob)
	mustPanic(t, "wasm: unaligned atomic access", wasm_trap_atomic_unaligned)
	mustPanic(t, "wasm: blocking atomic wait with no other agents (wasi-threads not enabled)",
		wasm_trap_atomic_wait_forever)
}
