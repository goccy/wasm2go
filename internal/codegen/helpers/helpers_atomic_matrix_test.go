package helpers

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// The atomic RMW matrix and the wait/notify parking lot. These helpers are
// emitted into generated output for the threads proposal's full set of
// read-modify-write, compare-exchange, and wait/notify operations across widths
// (8/16/32/64) and lane sizes. Codegen selects them by name, so only a test
// links them — and gives them regression coverage.

// seedLane writes val into the low `bits`-wide lane at offset 0 of a cleared
// word, and readLane reads it back. Both go straight through the memory slice
// (little-endian), an independent path from the atomic helpers under test.
func seedLane(m *Module, bits int, val int64) {
	binary.LittleEndian.PutUint64(m.memory[0:8], 0)
	switch bits {
	case 8:
		m.memory[0] = byte(val)
	case 16:
		binary.LittleEndian.PutUint16(m.memory[0:2], uint16(val))
	case 32:
		binary.LittleEndian.PutUint32(m.memory[0:4], uint32(val))
	case 64:
		binary.LittleEndian.PutUint64(m.memory[0:8], uint64(val))
	}
}

func readLane(m *Module, bits int) int64 {
	switch bits {
	case 8:
		return int64(m.memory[0])
	case 16:
		return int64(binary.LittleEndian.Uint16(m.memory[0:2]))
	case 32:
		return int64(binary.LittleEndian.Uint32(m.memory[0:4]))
	default:
		return int64(binary.LittleEndian.Uint64(m.memory[0:8]))
	}
}

// TestAtomicRmw32Matrix covers the int32-valued RMW helpers (full 32-bit lane
// plus the 8- and 16-bit sub-word forms). Each returns the OLD lane value and
// leaves op(old, v) behind.
func TestAtomicRmw32Matrix(t *testing.T) {
	cases := []struct {
		name          string
		fn            func(m *Module, a, o, v int32) int32
		bits          int
		old, v, newLo int64
	}{
		{"Xchg32", atomicRmwXchg32, 32, 100, 7, 7},
		{"Add32_8u", atomicRmwAdd32_8u, 8, 100, 5, 105},
		{"Sub32_8u", atomicRmwSub32_8u, 8, 100, 5, 95},
		{"And32_8u", atomicRmwAnd32_8u, 8, 0xF0, 0x3C, 0x30},
		{"Or32_8u", atomicRmwOr32_8u, 8, 0xF0, 0x0F, 0xFF},
		{"Xor32_8u", atomicRmwXor32_8u, 8, 0xFF, 0x0F, 0xF0},
		{"Xchg32_8u", atomicRmwXchg32_8u, 8, 100, 7, 7},
		{"Add32_16u", atomicRmwAdd32_16u, 16, 1000, 5, 1005},
		{"Sub32_16u", atomicRmwSub32_16u, 16, 1000, 5, 995},
		{"And32_16u", atomicRmwAnd32_16u, 16, 0xFF00, 0x3C00, 0x3C00},
		{"Or32_16u", atomicRmwOr32_16u, 16, 0xF000, 0x0F00, 0xFF00},
		{"Xor32_16u", atomicRmwXor32_16u, 16, 0xFF00, 0x0F00, 0xF000},
		{"Xchg32_16u", atomicRmwXchg32_16u, 16, 1000, 7, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Run both the uncontended (nextTID==0 → plain read-modify-write
			// fast path) and contended (nextTID>0 → real atomic CAS path)
			// branches; both must return the same old value and leave the
			// same result behind.
			for _, contended := range []bool{false, true} {
				m := newMemModuleM(64)
				if contended {
					m.threads.nextTID.Store(1)
				}
				seedLane(m, tc.bits, tc.old)
				if old := int64(tc.fn(m, 0, 0, int32(tc.v))); old != tc.old {
					t.Errorf("%s[contended=%v] old = %d, want %d", tc.name, contended, old, tc.old)
				}
				if got := readLane(m, tc.bits); got != tc.newLo {
					t.Errorf("%s[contended=%v] new = %d, want %d", tc.name, contended, got, tc.newLo)
				}
			}
		})
	}
}

// TestAtomicRmw64Matrix covers the int64-valued RMW helpers (full 64-bit lane
// plus the 8/16/32-bit sub-word forms).
func TestAtomicRmw64Matrix(t *testing.T) {
	cases := []struct {
		name          string
		fn            func(m *Module, a, o int32, v int64) int64
		bits          int
		old, v, newLo int64
	}{
		{"Add64", atomicRmwAdd64, 64, 100, 5, 105},
		{"Sub64", atomicRmwSub64, 64, 100, 5, 95},
		{"And64", atomicRmwAnd64, 64, 0xF0, 0x3C, 0x30},
		{"Or64", atomicRmwOr64, 64, 0xF0, 0x0F, 0xFF},
		{"Xor64", atomicRmwXor64, 64, 0xFF, 0x0F, 0xF0},
		{"Xchg64", atomicRmwXchg64, 64, 100, 7, 7},
		{"Add64_8u", atomicRmwAdd64_8u, 8, 100, 5, 105},
		{"Xchg64_8u", atomicRmwXchg64_8u, 8, 100, 7, 7},
		{"And64_8u", atomicRmwAnd64_8u, 8, 0xF0, 0x3C, 0x30},
		{"Or64_8u", atomicRmwOr64_8u, 8, 0xF0, 0x0F, 0xFF},
		{"Sub64_8u", atomicRmwSub64_8u, 8, 100, 5, 95},
		{"Xor64_8u", atomicRmwXor64_8u, 8, 0xFF, 0x0F, 0xF0},
		{"Add64_16u", atomicRmwAdd64_16u, 16, 1000, 5, 1005},
		{"Xchg64_16u", atomicRmwXchg64_16u, 16, 1000, 7, 7},
		{"And64_16u", atomicRmwAnd64_16u, 16, 0xFF00, 0x3C00, 0x3C00},
		{"Or64_16u", atomicRmwOr64_16u, 16, 0xF000, 0x0F00, 0xFF00},
		{"Sub64_16u", atomicRmwSub64_16u, 16, 1000, 5, 995},
		{"Xor64_16u", atomicRmwXor64_16u, 16, 0xFF00, 0x0F00, 0xF000},
		{"Add64_32u", atomicRmwAdd64_32u, 32, 100000, 5, 100005},
		{"Xchg64_32u", atomicRmwXchg64_32u, 32, 100000, 7, 7},
		{"And64_32u", atomicRmwAnd64_32u, 32, 0xFF0000, 0x3C0000, 0x3C0000},
		{"Or64_32u", atomicRmwOr64_32u, 32, 0xF00000, 0x0F0000, 0xFF0000},
		{"Sub64_32u", atomicRmwSub64_32u, 32, 100000, 5, 99995},
		{"Xor64_32u", atomicRmwXor64_32u, 32, 0xFF0000, 0x0F0000, 0xF00000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, contended := range []bool{false, true} {
				m := newMemModuleM(64)
				if contended {
					m.threads.nextTID.Store(1)
				}
				seedLane(m, tc.bits, tc.old)
				if old := tc.fn(m, 0, 0, tc.v); old != tc.old {
					t.Errorf("%s[contended=%v] old = %d, want %d", tc.name, contended, old, tc.old)
				}
				if got := readLane(m, tc.bits); got != tc.newLo {
					t.Errorf("%s[contended=%v] new = %d, want %d", tc.name, contended, got, tc.newLo)
				}
			}
		})
	}
}

// TestAtomicCmpxchgMatrix covers compare-exchange across widths: on a match the
// lane takes the replacement and the old value is returned; on a mismatch the
// lane is left alone and the (unequal) current value is returned.
func TestAtomicCmpxchgMatrix(t *testing.T) {
	t.Run("32", func(t *testing.T) {
		cases := []struct {
			name string
			fn   func(m *Module, a, o, expected, replacement int32) int32
			bits int
		}{
			{"Cmpxchg32", atomicRmwCmpxchg32, 32},
			{"Cmpxchg32_8u", atomicRmwCmpxchg32_8u, 8},
			{"Cmpxchg32_16u", atomicRmwCmpxchg32_16u, 16},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				for _, contended := range []bool{false, true} {
					m := newMemModuleM(64)
					if contended {
						m.threads.nextTID.Store(1)
					}
					seedLane(m, tc.bits, 42)
					if old := tc.fn(m, 0, 0, 42, 99); old != 42 || readLane(m, tc.bits) != 99 {
						t.Errorf("%s[contended=%v] match: old %d new %d, want 42/99", tc.name, contended, old, readLane(m, tc.bits))
					}
					seedLane(m, tc.bits, 42)
					if old := tc.fn(m, 0, 0, 7, 99); old != 42 || readLane(m, tc.bits) != 42 {
						t.Errorf("%s[contended=%v] mismatch: old %d new %d, want 42/42", tc.name, contended, old, readLane(m, tc.bits))
					}
				}
			})
		}
	})
	t.Run("64", func(t *testing.T) {
		cases := []struct {
			name string
			fn   func(m *Module, a, o int32, expected, replacement int64) int64
			bits int
		}{
			{"Cmpxchg64", atomicRmwCmpxchg64, 64},
			{"Cmpxchg64_8u", atomicRmwCmpxchg64_8u, 8},
			{"Cmpxchg64_16u", atomicRmwCmpxchg64_16u, 16},
			{"Cmpxchg64_32u", atomicRmwCmpxchg64_32u, 32},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				for _, contended := range []bool{false, true} {
					m := newMemModuleM(64)
					if contended {
						m.threads.nextTID.Store(1)
					}
					seedLane(m, tc.bits, 42)
					if old := tc.fn(m, 0, 0, 42, 99); old != 42 || readLane(m, tc.bits) != 99 {
						t.Errorf("%s[contended=%v] match: old %d new %d, want 42/99", tc.name, contended, old, readLane(m, tc.bits))
					}
					seedLane(m, tc.bits, 42)
					if old := tc.fn(m, 0, 0, 7, 99); old != 42 || readLane(m, tc.bits) != 42 {
						t.Errorf("%s[contended=%v] mismatch: old %d new %d, want 42/42", tc.name, contended, old, readLane(m, tc.bits))
					}
				}
			})
		}
	})
}

// TestAtomicFence exercises the fence helper (an empty locked critical section
// as a memory barrier); it must return 0 and touch nothing.
func TestAtomicFence(t *testing.T) {
	m := newMemModuleM(8)
	if got := atomicFence(m); got != 0 {
		t.Errorf("atomicFence = %d, want 0", got)
	}
}

// TestAtomicWaitNotEqualAndTimeout covers the non-blocking exits of
// memory.atomic.wait: 1 when the value already differs, 2 on timeout, and 1 on
// a non-shared memory (parking there is a validation error upstream).
func TestAtomicWaitNotEqualAndTimeout(t *testing.T) {
	m := newMemModuleM(64)
	m.memShared = true
	atomicStore32(m, 0, 0, 0)

	if got := atomicWait32(m, 0, 0, 999, -1); got != 1 {
		t.Errorf("wait32 with wrong expected = %d, want 1 (not-equal)", got)
	}
	if got := atomicWait32(m, 0, 0, 0, 0); got != 2 {
		t.Errorf("wait32 that times out = %d, want 2", got)
	}
	atomicStore64(m, 8, 0, 0)
	if got := atomicWait64(m, 8, 0, 0, 0); got != 2 {
		t.Errorf("wait64 that times out = %d, want 2", got)
	}

	ns := newMemModuleM(64) // not shared
	if got := atomicWait32(ns, 0, 0, 0, -1); got != 1 {
		t.Errorf("wait on non-shared memory = %d, want 1", got)
	}
}

// TestAtomicWaitNotify parks a waiter and wakes it, exercising the parking lot
// (parked/parkMu), threadPool.wake, atomicNotify and the woken (0) exit of
// atomicWait. nextTID is bumped so the infinite-wait deadlock guard sees that
// another agent exists to notify it.
func TestAtomicWaitNotify(t *testing.T) {
	m := newMemModuleM(64)
	m.memShared = true
	m.threads.nextTID.Store(1) // pretend a sibling agent exists
	atomicStore32(m, 0, 0, 0)

	done := make(chan int32, 1)
	go func() { done <- atomicWait32(m, 0, 0, 0, -1) }() // parks: value matches, forever

	// Wait until the waiter is actually parked before notifying.
	for {
		m.threads.parkMu.Lock()
		parked := len(m.threads.parked) > 0
		m.threads.parkMu.Unlock()
		if parked {
			break
		}
		runtime.Gosched()
	}

	if woke := atomicNotify(m, 0, 0, 1); woke != 1 {
		t.Errorf("atomicNotify woke %d, want 1", woke)
	}
	if got := <-done; got != 0 {
		t.Errorf("parked wait returned %d, want 0 (woken)", got)
	}
	// Notifying an address with nobody parked wakes zero.
	if woke := atomicNotify(m, 0, 0, 1); woke != 0 {
		t.Errorf("atomicNotify with no waiters woke %d, want 0", woke)
	}
}
