package helpers

// Exhaustive smoke coverage for the memory64 helper family: every
// simd_m64_* / simd_p_m64_* helper is executed once over a live
// module with in-bounds arguments. The mem-op semantics are already
// specified by the wasm32 twins' behavioral tests (the m64 bodies
// differ only in address width); this drives the 64-bit
// address-computation paths, which nothing in-package referenced
// statically before.

import (
	"testing"
)

func anyOf(vs ...any) any { return vs }

func call(f func() any) any { return f() }

func TestM64HelperSmoke(t *testing.T) {
	m := memTestModule(t, 4096)
	v := [2]uint64{0x1122334455667788, 0x99aabbccddeeff00}
	_ = v
	_ = call(func() any { return anyOf(simd_m64_scalar_i32_load16_u(m, 40)) })
	_ = call(func() any { return anyOf(simd_m64_scalar_f32_load(m, 40)) })
	_ = call(func() any { return anyOf(simd_m64_scalar_i32_shl(8, 8)) })
	_ = call(func() any { return anyOf(simd_m64_scalar_i32_add(8, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load_rng(m, 40, 8, 8, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load_nc(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_store(m, 40, 8, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_f16x4_cvt_store(m, 40, 8, v)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_f16x4_cvt_store(m, 40, 8, 0 /*v0*/, 7)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load32_zero(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load64_zero(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load8_splat(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load16_splat(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load32_splat(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load64_splat(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_widen(m, 40, 8, 8, true)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load8x8_s(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load8x8_u(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load16x4_s(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load16x4_u(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load32x2_s(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load32x2_u(m, 40, 8)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load8_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load16_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load32_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_load64_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_store8_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_store16_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_store32_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_m64_v128_store64_lane(m, 40, 8, 1, v)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_store(m, 40, 8, 0 /*v0*/, 7)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_store8_lane(m, 40, 8, 1, 0 /*v0*/, 7)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_store16_lane(m, 40, 8, 1, 0 /*v0*/, 7)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_store32_lane(m, 40, 8, 1, 0 /*v0*/, 7)) })
	_ = call(func() any { return anyOf(simd_p_m64_v128_store64_lane(m, 40, 8, 1, 0 /*v0*/, 7)) })
}
