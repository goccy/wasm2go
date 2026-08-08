package helpers

// Unit tests for the scalar-chain fallback helpers (the pure bodies
// of the fused-region scalar vocabulary): unchecked loads off m.M and
// mod-2^32 arithmetic, composed the way a quantized kernel's scale
// lookup uses them.

import (
	"encoding/binary"
	"math"
	"testing"
	"unsafe"
)

func newScalarTestModule(t *testing.T) *Module {
	t.Helper()
	m := &Module{}
	m.memory = make([]byte, 65536)
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	return m
}

func TestSimdScalarHelpers(t *testing.T) {
	m := newScalarTestModule(t)
	binary.LittleEndian.PutUint16(m.memory[34:], 7)
	binary.LittleEndian.PutUint32(m.memory[768+7*4:], math.Float32bits(0.25))

	if got := simd_scalar_i32_load16_u(m, 34); got != 7 {
		t.Errorf("load16_u = %d, want 7", got)
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
	if got := simd_scalar_f32_load(m, 796); got != 0.25 {
		t.Errorf("f32_load = %v, want 0.25", got)
	}
	if got := simd_scalar_f32_mul(0.25, 8); got != 2 {
		t.Errorf("f32_mul = %v, want 2", got)
	}

	// The composed chain, exactly as a fused region's fallback runs it.
	idx := simd_scalar_i32_load16_u(m, 34)
	addr := simd_scalar_i32_add(simd_scalar_i32_shl(idx, 2), 768)
	scale := simd_scalar_f32_load(m, addr)
	if got := simd_scalar_f32_mul(scale, 4); got != 1 {
		t.Errorf("composed scale chain = %v, want 1", got)
	}
}
