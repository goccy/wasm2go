package helpers

// Coverage for the memory64 atomic helper family (_m64) and its
// effective-address core atomicEA64. Codegen selects these by name for
// memory64 modules, so nothing in-package references them statically;
// the tests both guard their semantics against the wasm32 twins' and give
// the 64-bit address-computation paths direct coverage — including the
// beyond-4GiB addresses no wasm32 helper can form.

import (
	"math"
	"sync/atomic"
	"testing"
)

func TestAtomicEA64(t *testing.T) {
	// Only memSize is consulted by atomicEA64, so a module with a fake
	// size beyond 4 GiB exercises the wide-address path without having
	// to allocate that much memory.
	m := &Module{memSize: &atomic.Uint64{}}
	m.memSize.Store(5 << 30) // 5 GiB

	// An address beyond 4 GiB is accepted when in bounds.
	if got := atomicEA64(m, 1<<32, 16, 8); got != (1<<32)+16 {
		t.Errorf("atomicEA64(4GiB+16) = %d, want %d", got, (1<<32)+16)
	}
	// addr + offset in u64, both halves contributing beyond 32 bits.
	if got := atomicEA64(m, 3<<30, 1<<30, 4); got != 4<<30 {
		t.Errorf("atomicEA64(3GiB+1GiB) = %d, want %d", got, uint64(4<<30))
	}
	// The last in-bounds word.
	if got := atomicEA64(m, (5<<30)-4, 0, 4); got != (5<<30)-4 {
		t.Errorf("atomicEA64(end-4) = %d", got)
	}
	// One past the end traps.
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicEA64(m, (5<<30)-3, 0, 4) })
	// Negative address / negative offset trap as out of bounds.
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicEA64(m, -8, 0, 4) })
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicEA64(m, 0, -8, 4) })
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicEA64(m, -4, 8, 4) })
	// addr+offset wrapping u64 traps rather than aliasing a low address.
	mustPanic(t, "wasm: atomic access out of bounds", func() {
		atomicEA64(m, math.MaxInt64, math.MaxInt64, 4)
	})
	// ea+size wrapping u64 traps (ea itself did not wrap).
	mustPanic(t, "wasm: atomic access out of bounds", func() {
		atomicEA64(m, 0, -1, 8)
	})
	// Misalignment traps AFTER the bounds check, like atomicEA.
	mustPanic(t, "wasm: unaligned atomic access", func() { atomicEA64(m, (1<<32)+2, 0, 4) })
	mustPanic(t, "wasm: unaligned atomic access", func() { atomicEA64(m, 1, 0, 2) })
}

// TestAtomicM64FullWidth drives the full-width _m64 load/store/RMW helpers
// against the semantics their wasm32 twins are already tested for.
func TestAtomicM64FullWidth(t *testing.T) {
	m := newMemModuleM(64)

	atomicStore32_m64(m, 0, 0, 0x11223344)
	if got := atomicLoad32_m64(m, 0, 0); got != 0x11223344 {
		t.Errorf("atomicLoad32_m64 = %#x", got)
	}
	atomicStore64_m64(m, 8, 0, 0x1122334455667788)
	if got := atomicLoad64_m64(m, 8, 0); got != 0x1122334455667788 {
		t.Errorf("atomicLoad64_m64 = %#x", got)
	}
	// addr/offset split across the two i64 operands.
	if got := atomicLoad64_m64(m, 4, 4); got != 0x1122334455667788 {
		t.Errorf("atomicLoad64_m64 split addr/offset = %#x", got)
	}

	atomicStore32_m64(m, 0, 0, 100)
	if old := atomicRmwAdd32_m64(m, 0, 0, 5); old != 100 || atomicLoad32_m64(m, 0, 0) != 105 {
		t.Errorf("atomicRmwAdd32_m64: old %d new %d", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwSub32_m64(m, 0, 0, 6); old != 105 || atomicLoad32_m64(m, 0, 0) != 99 {
		t.Errorf("atomicRmwSub32_m64: old %d new %d", old, atomicLoad32_m64(m, 0, 0))
	}
	atomicStore32_m64(m, 0, 0, 0xF0)
	if old := atomicRmwAnd32_m64(m, 0, 0, 0x3C); old != 0xF0 || atomicLoad32_m64(m, 0, 0) != 0x30 {
		t.Errorf("atomicRmwAnd32_m64: old %#x new %#x", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwOr32_m64(m, 0, 0, 0x0F); old != 0x30 || atomicLoad32_m64(m, 0, 0) != 0x3F {
		t.Errorf("atomicRmwOr32_m64: old %#x new %#x", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwXor32_m64(m, 0, 0, 0xFF); old != 0x3F || atomicLoad32_m64(m, 0, 0) != 0xC0 {
		t.Errorf("atomicRmwXor32_m64: old %#x new %#x", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwXchg32_m64(m, 0, 0, 7); old != 0xC0 || atomicLoad32_m64(m, 0, 0) != 7 {
		t.Errorf("atomicRmwXchg32_m64: old %#x new %d", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwCmpxchg32_m64(m, 0, 0, 7, 9); old != 7 || atomicLoad32_m64(m, 0, 0) != 9 {
		t.Errorf("atomicRmwCmpxchg32_m64 hit: old %d new %d", old, atomicLoad32_m64(m, 0, 0))
	}
	if old := atomicRmwCmpxchg32_m64(m, 0, 0, 7, 11); old != 9 || atomicLoad32_m64(m, 0, 0) != 9 {
		t.Errorf("atomicRmwCmpxchg32_m64 miss: old %d new %d", old, atomicLoad32_m64(m, 0, 0))
	}

	atomicStore64_m64(m, 8, 0, 4_000_000_000)
	if old := atomicRmwAdd64_m64(m, 8, 0, 4_000_000_000); old != 4_000_000_000 || atomicLoad64_m64(m, 8, 0) != 8_000_000_000 {
		t.Errorf("atomicRmwAdd64_m64: old %d new %d", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwSub64_m64(m, 8, 0, 1); old != 8_000_000_000 || atomicLoad64_m64(m, 8, 0) != 7_999_999_999 {
		t.Errorf("atomicRmwSub64_m64: old %d new %d", old, atomicLoad64_m64(m, 8, 0))
	}
	atomicStore64_m64(m, 8, 0, 0xF0)
	if old := atomicRmwAnd64_m64(m, 8, 0, 0x3C); old != 0xF0 || atomicLoad64_m64(m, 8, 0) != 0x30 {
		t.Errorf("atomicRmwAnd64_m64: old %#x new %#x", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwOr64_m64(m, 8, 0, 0x0F); old != 0x30 || atomicLoad64_m64(m, 8, 0) != 0x3F {
		t.Errorf("atomicRmwOr64_m64: old %#x new %#x", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwXor64_m64(m, 8, 0, 0xFF); old != 0x3F || atomicLoad64_m64(m, 8, 0) != 0xC0 {
		t.Errorf("atomicRmwXor64_m64: old %#x new %#x", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwXchg64_m64(m, 8, 0, 7); old != 0xC0 || atomicLoad64_m64(m, 8, 0) != 7 {
		t.Errorf("atomicRmwXchg64_m64: old %#x new %d", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwCmpxchg64_m64(m, 8, 0, 7, 9); old != 7 || atomicLoad64_m64(m, 8, 0) != 9 {
		t.Errorf("atomicRmwCmpxchg64_m64 hit: old %d new %d", old, atomicLoad64_m64(m, 8, 0))
	}
	if old := atomicRmwCmpxchg64_m64(m, 8, 0, 7, 11); old != 9 || atomicLoad64_m64(m, 8, 0) != 9 {
		t.Errorf("atomicRmwCmpxchg64_m64 miss: old %d new %d", old, atomicLoad64_m64(m, 8, 0))
	}

	// Out-of-bounds and misaligned addresses trap through atomicEA64.
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicLoad32_m64(m, 64, 0) })
	mustPanic(t, "wasm: atomic access out of bounds", func() { atomicStore64_m64(m, -8, 0, 1) })
	mustPanic(t, "wasm: unaligned atomic access", func() { atomicRmwAdd32_m64(m, 2, 0, 1) })
}

// TestAtomicM64Subword drives the sub-word lane forms (8/16-bit lanes of
// the i32 family, 8/16/32-bit lanes of the i64 family).
func TestAtomicM64Subword(t *testing.T) {
	m := newMemModuleM(64)

	atomicStore32_8_m64(m, 1, 0, 0xAB)
	if got := atomicLoad32_8u_m64(m, 1, 0); got != 0xAB {
		t.Errorf("atomicLoad32_8u_m64 = %#x", got)
	}
	atomicStore32_16_m64(m, 2, 0, 0x1234)
	if got := atomicLoad32_16u_m64(m, 2, 0); got != 0x1234 {
		t.Errorf("atomicLoad32_16u_m64 = %#x", got)
	}
	atomicStore64_8_m64(m, 8, 0, 0xCD)
	if got := atomicLoad64_8u_m64(m, 8, 0); got != 0xCD {
		t.Errorf("atomicLoad64_8u_m64 = %#x", got)
	}
	atomicStore64_16_m64(m, 10, 0, 0x5678)
	if got := atomicLoad64_16u_m64(m, 10, 0); got != 0x5678 {
		t.Errorf("atomicLoad64_16u_m64 = %#x", got)
	}
	atomicStore64_32_m64(m, 12, 0, 0x1_9999_0001) // truncates to the 32-bit lane
	if got := atomicLoad64_32u_m64(m, 12, 0); got != 0x9999_0001 {
		t.Errorf("atomicLoad64_32u_m64 = %#x (zero-extended lane)", got)
	}

	// i32-family RMW lanes: old value returned zero-extended, op applied.
	atomicStore32_8_m64(m, 1, 0, 250)
	if old := atomicRmwAdd32_8u_m64(m, 1, 0, 10); old != 250 || atomicLoad32_8u_m64(m, 1, 0) != 4 {
		t.Errorf("atomicRmwAdd32_8u_m64: old %d new %d (mod 256)", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwSub32_8u_m64(m, 1, 0, 5); old != 4 || atomicLoad32_8u_m64(m, 1, 0) != 255 {
		t.Errorf("atomicRmwSub32_8u_m64: old %d new %d", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwAnd32_8u_m64(m, 1, 0, 0x0F); old != 255 || atomicLoad32_8u_m64(m, 1, 0) != 0x0F {
		t.Errorf("atomicRmwAnd32_8u_m64: old %d new %d", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwOr32_8u_m64(m, 1, 0, 0xA0); old != 0x0F || atomicLoad32_8u_m64(m, 1, 0) != 0xAF {
		t.Errorf("atomicRmwOr32_8u_m64: old %#x new %#x", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwXor32_8u_m64(m, 1, 0, 0xFF); old != 0xAF || atomicLoad32_8u_m64(m, 1, 0) != 0x50 {
		t.Errorf("atomicRmwXor32_8u_m64: old %#x new %#x", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwXchg32_8u_m64(m, 1, 0, 0x7E); old != 0x50 || atomicLoad32_8u_m64(m, 1, 0) != 0x7E {
		t.Errorf("atomicRmwXchg32_8u_m64: old %#x new %#x", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwCmpxchg32_8u_m64(m, 1, 0, 0x7E, 0x11); old != 0x7E || atomicLoad32_8u_m64(m, 1, 0) != 0x11 {
		t.Errorf("atomicRmwCmpxchg32_8u_m64 hit: old %#x new %#x", old, atomicLoad32_8u_m64(m, 1, 0))
	}
	if old := atomicRmwCmpxchg32_8u_m64(m, 1, 0, 0x7E, 0x22); old != 0x11 || atomicLoad32_8u_m64(m, 1, 0) != 0x11 {
		t.Errorf("atomicRmwCmpxchg32_8u_m64 miss: old %#x new %#x", old, atomicLoad32_8u_m64(m, 1, 0))
	}

	atomicStore32_16_m64(m, 2, 0, 0xFFF0)
	if old := atomicRmwAdd32_16u_m64(m, 2, 0, 0x20); old != 0xFFF0 || atomicLoad32_16u_m64(m, 2, 0) != 0x10 {
		t.Errorf("atomicRmwAdd32_16u_m64: old %#x new %#x (mod 2^16)", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwSub32_16u_m64(m, 2, 0, 0x11); old != 0x10 || atomicLoad32_16u_m64(m, 2, 0) != 0xFFFF {
		t.Errorf("atomicRmwSub32_16u_m64: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwAnd32_16u_m64(m, 2, 0, 0x0F0F); old != 0xFFFF || atomicLoad32_16u_m64(m, 2, 0) != 0x0F0F {
		t.Errorf("atomicRmwAnd32_16u_m64: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwOr32_16u_m64(m, 2, 0, 0xA000); old != 0x0F0F || atomicLoad32_16u_m64(m, 2, 0) != 0xAF0F {
		t.Errorf("atomicRmwOr32_16u_m64: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwXor32_16u_m64(m, 2, 0, 0xFFFF); old != 0xAF0F || atomicLoad32_16u_m64(m, 2, 0) != 0x50F0 {
		t.Errorf("atomicRmwXor32_16u_m64: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwXchg32_16u_m64(m, 2, 0, 0x1357); old != 0x50F0 || atomicLoad32_16u_m64(m, 2, 0) != 0x1357 {
		t.Errorf("atomicRmwXchg32_16u_m64: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwCmpxchg32_16u_m64(m, 2, 0, 0x1357, 0x2468); old != 0x1357 || atomicLoad32_16u_m64(m, 2, 0) != 0x2468 {
		t.Errorf("atomicRmwCmpxchg32_16u_m64 hit: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}
	if old := atomicRmwCmpxchg32_16u_m64(m, 2, 0, 0x1357, 0x9); old != 0x2468 || atomicLoad32_16u_m64(m, 2, 0) != 0x2468 {
		t.Errorf("atomicRmwCmpxchg32_16u_m64 miss: old %#x new %#x", old, atomicLoad32_16u_m64(m, 2, 0))
	}

	// i64-family lanes: results are zero-extended into the i64.
	atomicStore64_8_m64(m, 8, 0, 250)
	if old := atomicRmwAdd64_8u_m64(m, 8, 0, 10); old != 250 || atomicLoad64_8u_m64(m, 8, 0) != 4 {
		t.Errorf("atomicRmwAdd64_8u_m64: old %d new %d", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwSub64_8u_m64(m, 8, 0, 5); old != 4 || atomicLoad64_8u_m64(m, 8, 0) != 255 {
		t.Errorf("atomicRmwSub64_8u_m64: old %d new %d", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwAnd64_8u_m64(m, 8, 0, 0x0F); old != 255 || atomicLoad64_8u_m64(m, 8, 0) != 0x0F {
		t.Errorf("atomicRmwAnd64_8u_m64: old %d new %d", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwOr64_8u_m64(m, 8, 0, 0xA0); old != 0x0F || atomicLoad64_8u_m64(m, 8, 0) != 0xAF {
		t.Errorf("atomicRmwOr64_8u_m64: old %#x new %#x", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwXor64_8u_m64(m, 8, 0, 0xFF); old != 0xAF || atomicLoad64_8u_m64(m, 8, 0) != 0x50 {
		t.Errorf("atomicRmwXor64_8u_m64: old %#x new %#x", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwXchg64_8u_m64(m, 8, 0, 0x7E); old != 0x50 || atomicLoad64_8u_m64(m, 8, 0) != 0x7E {
		t.Errorf("atomicRmwXchg64_8u_m64: old %#x new %#x", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwCmpxchg64_8u_m64(m, 8, 0, 0x7E, 0x11); old != 0x7E || atomicLoad64_8u_m64(m, 8, 0) != 0x11 {
		t.Errorf("atomicRmwCmpxchg64_8u_m64 hit: old %#x new %#x", old, atomicLoad64_8u_m64(m, 8, 0))
	}
	if old := atomicRmwCmpxchg64_8u_m64(m, 8, 0, 0x7E, 0x22); old != 0x11 || atomicLoad64_8u_m64(m, 8, 0) != 0x11 {
		t.Errorf("atomicRmwCmpxchg64_8u_m64 miss: old %#x new %#x", old, atomicLoad64_8u_m64(m, 8, 0))
	}

	atomicStore64_16_m64(m, 10, 0, 0xFFF0)
	if old := atomicRmwAdd64_16u_m64(m, 10, 0, 0x20); old != 0xFFF0 || atomicLoad64_16u_m64(m, 10, 0) != 0x10 {
		t.Errorf("atomicRmwAdd64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwSub64_16u_m64(m, 10, 0, 0x11); old != 0x10 || atomicLoad64_16u_m64(m, 10, 0) != 0xFFFF {
		t.Errorf("atomicRmwSub64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwAnd64_16u_m64(m, 10, 0, 0x0F0F); old != 0xFFFF || atomicLoad64_16u_m64(m, 10, 0) != 0x0F0F {
		t.Errorf("atomicRmwAnd64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwOr64_16u_m64(m, 10, 0, 0xA000); old != 0x0F0F || atomicLoad64_16u_m64(m, 10, 0) != 0xAF0F {
		t.Errorf("atomicRmwOr64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwXor64_16u_m64(m, 10, 0, 0xFFFF); old != 0xAF0F || atomicLoad64_16u_m64(m, 10, 0) != 0x50F0 {
		t.Errorf("atomicRmwXor64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwXchg64_16u_m64(m, 10, 0, 0x1357); old != 0x50F0 || atomicLoad64_16u_m64(m, 10, 0) != 0x1357 {
		t.Errorf("atomicRmwXchg64_16u_m64: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwCmpxchg64_16u_m64(m, 10, 0, 0x1357, 0x2468); old != 0x1357 || atomicLoad64_16u_m64(m, 10, 0) != 0x2468 {
		t.Errorf("atomicRmwCmpxchg64_16u_m64 hit: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}
	if old := atomicRmwCmpxchg64_16u_m64(m, 10, 0, 0x1357, 0x9); old != 0x2468 || atomicLoad64_16u_m64(m, 10, 0) != 0x2468 {
		t.Errorf("atomicRmwCmpxchg64_16u_m64 miss: old %#x new %#x", old, atomicLoad64_16u_m64(m, 10, 0))
	}

	// 32-bit lanes of the i64 family, incl. the wraparound the lane math
	// must confine to 32 bits.
	atomicStore64_32_m64(m, 12, 0, 0xFFFF_FFF0)
	if old := atomicRmwAdd64_32u_m64(m, 12, 0, 0x20); old != 0xFFFF_FFF0 || atomicLoad64_32u_m64(m, 12, 0) != 0x10 {
		t.Errorf("atomicRmwAdd64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwSub64_32u_m64(m, 12, 0, 0x11); old != 0x10 || atomicLoad64_32u_m64(m, 12, 0) != 0xFFFF_FFFF {
		t.Errorf("atomicRmwSub64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwAnd64_32u_m64(m, 12, 0, 0x0F0F_0F0F); old != 0xFFFF_FFFF || atomicLoad64_32u_m64(m, 12, 0) != 0x0F0F_0F0F {
		t.Errorf("atomicRmwAnd64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwOr64_32u_m64(m, 12, 0, 0xA000_0000); old != 0x0F0F_0F0F || atomicLoad64_32u_m64(m, 12, 0) != 0xAF0F_0F0F {
		t.Errorf("atomicRmwOr64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwXor64_32u_m64(m, 12, 0, 0xFFFF_FFFF); old != 0xAF0F_0F0F || atomicLoad64_32u_m64(m, 12, 0) != 0x50F0_F0F0 {
		t.Errorf("atomicRmwXor64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwXchg64_32u_m64(m, 12, 0, 0x1357_9BDF); old != 0x50F0_F0F0 || atomicLoad64_32u_m64(m, 12, 0) != 0x1357_9BDF {
		t.Errorf("atomicRmwXchg64_32u_m64: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwCmpxchg64_32u_m64(m, 12, 0, 0x1357_9BDF, 0x2468_ACE0); old != 0x1357_9BDF || atomicLoad64_32u_m64(m, 12, 0) != 0x2468_ACE0 {
		t.Errorf("atomicRmwCmpxchg64_32u_m64 hit: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
	if old := atomicRmwCmpxchg64_32u_m64(m, 12, 0, 0x1357_9BDF, 0x9); old != 0x2468_ACE0 || atomicLoad64_32u_m64(m, 12, 0) != 0x2468_ACE0 {
		t.Errorf("atomicRmwCmpxchg64_32u_m64 miss: old %#x new %#x", old, atomicLoad64_32u_m64(m, 12, 0))
	}
}

func TestAtomicM64WaitNotify(t *testing.T) {
	m := newMemModuleM(64)
	m.memShared = true

	// notify with no waiters wakes nobody.
	if got := atomicNotify_m64(m, 16, 0, -1); got != 0 {
		t.Errorf("atomicNotify_m64 with no waiters = %d, want 0", got)
	}
	// wait with a mismatched expected value returns 1 (not-equal).
	atomicStore32_m64(m, 16, 0, 5)
	if got := atomicWait32_m64(m, 16, 0, 4, 0); got != 1 {
		t.Errorf("atomicWait32_m64 not-equal = %d, want 1", got)
	}
	atomicStore64_m64(m, 24, 0, 5)
	if got := atomicWait64_m64(m, 24, 0, 4, 0); got != 1 {
		t.Errorf("atomicWait64_m64 not-equal = %d, want 1", got)
	}
	// wait on the current value with a zero timeout returns 2 (timed out).
	if got := atomicWait32_m64(m, 16, 0, 5, 0); got != 2 {
		t.Errorf("atomicWait32_m64 timeout = %d, want 2", got)
	}
	if got := atomicWait64_m64(m, 24, 0, 5, 0); got != 2 {
		t.Errorf("atomicWait64_m64 timeout = %d, want 2", got)
	}
}

func TestThreadSpawnM64(t *testing.T) {
	m := newMemModuleM(64)

	done := make(chan struct{})
	var gotTID int32
	var gotArg int64
	m.threadStart64 = func(child *Module, tid int32, arg int64) {
		gotTID, gotArg = tid, arg
		close(done)
	}
	tid := threadSpawn_m64(m, 5<<32) // an arg only an i64 can carry
	if tid != 1 {
		t.Errorf("threadSpawn_m64 tid = %d, want 1", tid)
	}
	<-done
	ThreadsWait(m)
	if gotTID != 1 || gotArg != 5<<32 {
		t.Errorf("threadStart64 saw tid=%d arg=%d, want 1 / %d", gotTID, gotArg, int64(5<<32))
	}

	// A module that exports no wasi_thread_start returns -1.
	if got := threadSpawn_m64(newMemModuleM(8), 0); got != -1 {
		t.Errorf("threadSpawn_m64 with no threadStart64 = %d, want -1", got)
	}
}

// TestMemoryGrow64Shared: growing a shared memory64 must never reslice or
// relocate the backing array — growth is a lone memSize store, and a grow
// past the reserved ceiling fails with -1.
func TestMemoryGrow64Shared(t *testing.T) {
	m := newMemModuleM(3 * 65536) // ceiling: 3 pages reserved up front
	m.memShared = true
	m.memSize.Store(65536) // guest currently sees 1 page

	base := &m.memory[0]
	if got := memoryGrow64(m, 1); got != 1 {
		t.Errorf("memoryGrow64(+1) = %d, want previous page count 1", got)
	}
	if m.memSize.Load() != 2*65536 {
		t.Errorf("memSize after grow = %d, want 2 pages", m.memSize.Load())
	}
	if len(m.memory) != 3*65536 || &m.memory[0] != base {
		t.Error("shared grow resliced or relocated the backing array")
	}
	// Growing past the reserved ceiling fails without touching anything.
	if got := memoryGrow64(m, 2); got != -1 {
		t.Errorf("memoryGrow64 past ceiling = %d, want -1", got)
	}
	if m.memSize.Load() != 2*65536 || &m.memory[0] != base {
		t.Error("failed grow mutated the module")
	}
	// A further in-ceiling grow still works.
	if got := memoryGrow64(m, 1); got != 2 {
		t.Errorf("memoryGrow64(+1) = %d, want 2", got)
	}
}
