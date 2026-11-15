package helpers

// Unit tests for the scalar-chain fallback helpers (the pure bodies
// of the fused-region scalar vocabulary): loads off m.M at the address
// plus the static offset, bounded by memory.size (this package builds
// as memory that is no reservation, see reserve_stub.go), and mod-2^32
// arithmetic, composed the way a quantized kernel's scale lookup uses
// them.

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync/atomic"
	"testing"
	"unsafe"
)

func newScalarTestModule(t *testing.T) *Module {
	t.Helper()
	m := &Module{}
	m.memory = make([]byte, 65536)
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	m.memSize = &atomic.Uint64{}
	m.memSize.Store(uint64(len(m.memory)))
	return m
}

// scalarTrap runs f and returns what it panicked with, or "".
func scalarTrap(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func TestSimdScalarHelpers(t *testing.T) {
	m := newScalarTestModule(t)
	binary.LittleEndian.PutUint16(m.memory[34:], 7)
	binary.LittleEndian.PutUint32(m.memory[768+7*4:], math.Float32bits(0.25))

	if got := simd_scalar_i32_load16_u(m, 34, 0); got != 7 {
		t.Errorf("load16_u = %d, want 7", got)
	}
	if got := simd_scalar_i32_load16_u(m, 30, 4); got != 7 {
		t.Errorf("load16_u with offset 4 = %d, want 7", got)
	}
	if got := simd_scalar_i32_shl(7, 2); got != 28 {
		t.Errorf("shl = %d, want 28", got)
	}
	if got := simd_scalar_i32_shl(1, 33); got != 2 {
		t.Errorf("shl count must wrap mod 32: got %d, want 2", got)
	}
	if got := simd_scalar_i32_add(28, 768); got != 796 {
		t.Errorf("add = %d, want 796", got)
	}
	if got := simd_scalar_i32_add(0x7fffffff, 1); got != -0x80000000 {
		t.Errorf("add must wrap mod 2^32: got %d", got)
	}
	if got := simd_scalar_f32_load(m, 796, 0); got != 0.25 {
		t.Errorf("f32_load = %v, want 0.25", got)
	}
	if got := simd_scalar_f32_load(m, 28, 768); got != 0.25 {
		t.Errorf("f32_load with offset 768 = %v, want 0.25", got)
	}
	const oob = "wasm: memory access out of bounds"
	for _, tc := range []struct {
		name string
		f    func()
	}{
		{name: "load16_u at the end", f: func() { simd_scalar_i32_load16_u(m, 65535, 0) }},
		{name: "f32_load at the end", f: func() { simd_scalar_f32_load(m, 65532, 1) }},
		// The address plus the offset passes 4 GiB: no wrap to 12.
		{name: "f32_load past 4 GiB", f: func() { simd_scalar_f32_load(m, -4, 16) }},
		{name: "load16_u past 4 GiB", f: func() { simd_scalar_i32_load16_u(m, 16, -8) }},
	} {
		if got := scalarTrap(tc.f); got != oob {
			t.Errorf("%s: got %q, want the trap", tc.name, got)
		}
	}
	if got := simd_scalar_f32_mul(0.25, 8); got != 2 {
		t.Errorf("f32_mul = %v, want 2", got)
	}

	// The composed chain, exactly as a fused region's fallback runs it.
	idx := simd_scalar_i32_load16_u(m, 34, 0)
	addr := simd_scalar_i32_add(simd_scalar_i32_shl(idx, 2), 768)
	scale := simd_scalar_f32_load(m, addr, 0)
	if got := simd_scalar_f32_mul(scale, 4); got != 1 {
		t.Errorf("composed scale chain = %v, want 1", got)
	}
}
