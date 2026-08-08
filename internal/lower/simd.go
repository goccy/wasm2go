package lower

import (
	"strings"

	"fmt"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// SIMD (0xfd-prefixed) lowering. Every v128 value is a ssa.TypeV128 (emitted
// as [2]uint64); the ops themselves lower to helper calls — pure lane /
// arithmetic ops to OpSimdCall (helper(args...)), memory ops to OpSimdMemCall
// (helper(m, addr, offset, ...)), mirroring the 0xfe atomics lowering. Lane
// immediates become trailing i32 constant arguments.

// fdSimdSpec describes one pure SIMD op: the helper name, the operand types
// popped from the stack (bottom-to-top), and the result type.
type fdSimdSpec struct {
	helper string
	args   []ssa.Type
	res    ssa.Type
}

const (
	simdV = ssa.TypeV128
	sdI32 = ssa.TypeI32
	sdI64 = ssa.TypeI64
	sdF32 = ssa.TypeF32
	sdF64 = ssa.TypeF64
)

// fdSimd maps 0xfd sub-opcodes of the plain (non-memory, non-immediate)
// SIMD ops to their lowering. Memory ops (0x00–0x0b, 0x54–0x5d), v128.const
// (0x0c), i8x16.shuffle (0x0d) and the lane ops (0x15–0x22) are handled
// directly in handleFDOp because they carry immediates.
var fdSimd = map[uint32]fdSimdSpec{
	0x0e: {"simd_i8x16_swizzle", []ssa.Type{simdV, simdV}, simdV},

	0x0f: {"simd_i8x16_splat", []ssa.Type{sdI32}, simdV},
	0x10: {"simd_i16x8_splat", []ssa.Type{sdI32}, simdV},
	0x11: {"simd_i32x4_splat", []ssa.Type{sdI32}, simdV},
	0x12: {"simd_i64x2_splat", []ssa.Type{sdI64}, simdV},
	0x13: {"simd_f32x4_splat", []ssa.Type{sdF32}, simdV},
	0x14: {"simd_f64x2_splat", []ssa.Type{sdF64}, simdV},

	0x4d: {"simd_v128_not", []ssa.Type{simdV}, simdV},
	0x4e: {"simd_v128_and", []ssa.Type{simdV, simdV}, simdV},
	0x4f: {"simd_v128_andnot", []ssa.Type{simdV, simdV}, simdV},
	0x50: {"simd_v128_or", []ssa.Type{simdV, simdV}, simdV},
	0x51: {"simd_v128_xor", []ssa.Type{simdV, simdV}, simdV},
	0x52: {"simd_v128_bitselect", []ssa.Type{simdV, simdV, simdV}, simdV},
	0x53: {"simd_v128_any_true", []ssa.Type{simdV}, sdI32},

	0x5e: {"simd_f32x4_demote_f64x2_zero", []ssa.Type{simdV}, simdV},
	0x5f: {"simd_f64x2_promote_low_f32x4", []ssa.Type{simdV}, simdV},

	0x60: {"simd_i8x16_abs", []ssa.Type{simdV}, simdV},
	0x61: {"simd_i8x16_neg", []ssa.Type{simdV}, simdV},
	0x62: {"simd_i8x16_popcnt", []ssa.Type{simdV}, simdV},
	0x63: {"simd_i8x16_all_true", []ssa.Type{simdV}, sdI32},
	0x64: {"simd_i8x16_bitmask", []ssa.Type{simdV}, sdI32},
	0x65: {"simd_i8x16_narrow_i16x8_s", []ssa.Type{simdV, simdV}, simdV},
	0x66: {"simd_i8x16_narrow_i16x8_u", []ssa.Type{simdV, simdV}, simdV},
	0x67: {"simd_f32x4_ceil", []ssa.Type{simdV}, simdV},
	0x68: {"simd_f32x4_floor", []ssa.Type{simdV}, simdV},
	0x69: {"simd_f32x4_trunc", []ssa.Type{simdV}, simdV},
	0x6a: {"simd_f32x4_nearest", []ssa.Type{simdV}, simdV},
	0x6b: {"simd_i8x16_shl", []ssa.Type{simdV, sdI32}, simdV},
	0x6c: {"simd_i8x16_shr_s", []ssa.Type{simdV, sdI32}, simdV},
	0x6d: {"simd_i8x16_shr_u", []ssa.Type{simdV, sdI32}, simdV},
	0x6e: {"simd_i8x16_add", []ssa.Type{simdV, simdV}, simdV},
	0x6f: {"simd_i8x16_add_sat_s", []ssa.Type{simdV, simdV}, simdV},
	0x70: {"simd_i8x16_add_sat_u", []ssa.Type{simdV, simdV}, simdV},
	0x71: {"simd_i8x16_sub", []ssa.Type{simdV, simdV}, simdV},
	0x72: {"simd_i8x16_sub_sat_s", []ssa.Type{simdV, simdV}, simdV},
	0x73: {"simd_i8x16_sub_sat_u", []ssa.Type{simdV, simdV}, simdV},
	0x74: {"simd_f64x2_ceil", []ssa.Type{simdV}, simdV},
	0x75: {"simd_f64x2_floor", []ssa.Type{simdV}, simdV},
	0x76: {"simd_i8x16_min_s", []ssa.Type{simdV, simdV}, simdV},
	0x77: {"simd_i8x16_min_u", []ssa.Type{simdV, simdV}, simdV},
	0x78: {"simd_i8x16_max_s", []ssa.Type{simdV, simdV}, simdV},
	0x79: {"simd_i8x16_max_u", []ssa.Type{simdV, simdV}, simdV},
	0x7a: {"simd_f64x2_trunc", []ssa.Type{simdV}, simdV},
	0x7b: {"simd_i8x16_avgr_u", []ssa.Type{simdV, simdV}, simdV},

	0x7c: {"simd_i16x8_extadd_pairwise_i8x16_s", []ssa.Type{simdV}, simdV},
	0x7d: {"simd_i16x8_extadd_pairwise_i8x16_u", []ssa.Type{simdV}, simdV},
	0x7e: {"simd_i32x4_extadd_pairwise_i16x8_s", []ssa.Type{simdV}, simdV},
	0x7f: {"simd_i32x4_extadd_pairwise_i16x8_u", []ssa.Type{simdV}, simdV},

	0x80: {"simd_i16x8_abs", []ssa.Type{simdV}, simdV},
	0x81: {"simd_i16x8_neg", []ssa.Type{simdV}, simdV},
	0x82: {"simd_i16x8_q15mulr_sat_s", []ssa.Type{simdV, simdV}, simdV},
	0x83: {"simd_i16x8_all_true", []ssa.Type{simdV}, sdI32},
	0x84: {"simd_i16x8_bitmask", []ssa.Type{simdV}, sdI32},
	0x85: {"simd_i16x8_narrow_i32x4_s", []ssa.Type{simdV, simdV}, simdV},
	0x86: {"simd_i16x8_narrow_i32x4_u", []ssa.Type{simdV, simdV}, simdV},
	0x87: {"simd_i16x8_extend_low_i8x16_s", []ssa.Type{simdV}, simdV},
	0x88: {"simd_i16x8_extend_high_i8x16_s", []ssa.Type{simdV}, simdV},
	0x89: {"simd_i16x8_extend_low_i8x16_u", []ssa.Type{simdV}, simdV},
	0x8a: {"simd_i16x8_extend_high_i8x16_u", []ssa.Type{simdV}, simdV},
	0x8b: {"simd_i16x8_shl", []ssa.Type{simdV, sdI32}, simdV},
	0x8c: {"simd_i16x8_shr_s", []ssa.Type{simdV, sdI32}, simdV},
	0x8d: {"simd_i16x8_shr_u", []ssa.Type{simdV, sdI32}, simdV},
	0x8e: {"simd_i16x8_add", []ssa.Type{simdV, simdV}, simdV},
	0x8f: {"simd_i16x8_add_sat_s", []ssa.Type{simdV, simdV}, simdV},
	0x90: {"simd_i16x8_add_sat_u", []ssa.Type{simdV, simdV}, simdV},
	0x91: {"simd_i16x8_sub", []ssa.Type{simdV, simdV}, simdV},
	0x92: {"simd_i16x8_sub_sat_s", []ssa.Type{simdV, simdV}, simdV},
	0x93: {"simd_i16x8_sub_sat_u", []ssa.Type{simdV, simdV}, simdV},
	0x94: {"simd_f64x2_nearest", []ssa.Type{simdV}, simdV},
	0x95: {"simd_i16x8_mul", []ssa.Type{simdV, simdV}, simdV},
	0x96: {"simd_i16x8_min_s", []ssa.Type{simdV, simdV}, simdV},
	0x97: {"simd_i16x8_min_u", []ssa.Type{simdV, simdV}, simdV},
	0x98: {"simd_i16x8_max_s", []ssa.Type{simdV, simdV}, simdV},
	0x99: {"simd_i16x8_max_u", []ssa.Type{simdV, simdV}, simdV},
	0x9b: {"simd_i16x8_avgr_u", []ssa.Type{simdV, simdV}, simdV},
	0x9c: {"simd_i16x8_extmul_low_i8x16_s", []ssa.Type{simdV, simdV}, simdV},
	0x9d: {"simd_i16x8_extmul_high_i8x16_s", []ssa.Type{simdV, simdV}, simdV},
	0x9e: {"simd_i16x8_extmul_low_i8x16_u", []ssa.Type{simdV, simdV}, simdV},
	0x9f: {"simd_i16x8_extmul_high_i8x16_u", []ssa.Type{simdV, simdV}, simdV},

	0xa0: {"simd_i32x4_abs", []ssa.Type{simdV}, simdV},
	0xa1: {"simd_i32x4_neg", []ssa.Type{simdV}, simdV},
	0xa3: {"simd_i32x4_all_true", []ssa.Type{simdV}, sdI32},
	0xa4: {"simd_i32x4_bitmask", []ssa.Type{simdV}, sdI32},
	0xa7: {"simd_i32x4_extend_low_i16x8_s", []ssa.Type{simdV}, simdV},
	0xa8: {"simd_i32x4_extend_high_i16x8_s", []ssa.Type{simdV}, simdV},
	0xa9: {"simd_i32x4_extend_low_i16x8_u", []ssa.Type{simdV}, simdV},
	0xaa: {"simd_i32x4_extend_high_i16x8_u", []ssa.Type{simdV}, simdV},
	0xab: {"simd_i32x4_shl", []ssa.Type{simdV, sdI32}, simdV},
	0xac: {"simd_i32x4_shr_s", []ssa.Type{simdV, sdI32}, simdV},
	0xad: {"simd_i32x4_shr_u", []ssa.Type{simdV, sdI32}, simdV},
	0xae: {"simd_i32x4_add", []ssa.Type{simdV, simdV}, simdV},
	0xb1: {"simd_i32x4_sub", []ssa.Type{simdV, simdV}, simdV},
	0xb5: {"simd_i32x4_mul", []ssa.Type{simdV, simdV}, simdV},
	0xb6: {"simd_i32x4_min_s", []ssa.Type{simdV, simdV}, simdV},
	0xb7: {"simd_i32x4_min_u", []ssa.Type{simdV, simdV}, simdV},
	0xb8: {"simd_i32x4_max_s", []ssa.Type{simdV, simdV}, simdV},
	0xb9: {"simd_i32x4_max_u", []ssa.Type{simdV, simdV}, simdV},
	0xba: {"simd_i32x4_dot_i16x8_s", []ssa.Type{simdV, simdV}, simdV},
	0xbc: {"simd_i32x4_extmul_low_i16x8_s", []ssa.Type{simdV, simdV}, simdV},
	0xbd: {"simd_i32x4_extmul_high_i16x8_s", []ssa.Type{simdV, simdV}, simdV},
	0xbe: {"simd_i32x4_extmul_low_i16x8_u", []ssa.Type{simdV, simdV}, simdV},
	0xbf: {"simd_i32x4_extmul_high_i16x8_u", []ssa.Type{simdV, simdV}, simdV},

	0xc0: {"simd_i64x2_abs", []ssa.Type{simdV}, simdV},
	0xc1: {"simd_i64x2_neg", []ssa.Type{simdV}, simdV},
	0xc3: {"simd_i64x2_all_true", []ssa.Type{simdV}, sdI32},
	0xc4: {"simd_i64x2_bitmask", []ssa.Type{simdV}, sdI32},
	0xc7: {"simd_i64x2_extend_low_i32x4_s", []ssa.Type{simdV}, simdV},
	0xc8: {"simd_i64x2_extend_high_i32x4_s", []ssa.Type{simdV}, simdV},
	0xc9: {"simd_i64x2_extend_low_i32x4_u", []ssa.Type{simdV}, simdV},
	0xca: {"simd_i64x2_extend_high_i32x4_u", []ssa.Type{simdV}, simdV},
	0xcb: {"simd_i64x2_shl", []ssa.Type{simdV, sdI32}, simdV},
	0xcc: {"simd_i64x2_shr_s", []ssa.Type{simdV, sdI32}, simdV},
	0xcd: {"simd_i64x2_shr_u", []ssa.Type{simdV, sdI32}, simdV},
	0xce: {"simd_i64x2_add", []ssa.Type{simdV, simdV}, simdV},
	0xd1: {"simd_i64x2_sub", []ssa.Type{simdV, simdV}, simdV},
	0xd5: {"simd_i64x2_mul", []ssa.Type{simdV, simdV}, simdV},
	0xd6: {"simd_i64x2_eq", []ssa.Type{simdV, simdV}, simdV},
	0xd7: {"simd_i64x2_ne", []ssa.Type{simdV, simdV}, simdV},
	0xd8: {"simd_i64x2_lt_s", []ssa.Type{simdV, simdV}, simdV},
	0xd9: {"simd_i64x2_gt_s", []ssa.Type{simdV, simdV}, simdV},
	0xda: {"simd_i64x2_le_s", []ssa.Type{simdV, simdV}, simdV},
	0xdb: {"simd_i64x2_ge_s", []ssa.Type{simdV, simdV}, simdV},
	0xdc: {"simd_i64x2_extmul_low_i32x4_s", []ssa.Type{simdV, simdV}, simdV},
	0xdd: {"simd_i64x2_extmul_high_i32x4_s", []ssa.Type{simdV, simdV}, simdV},
	0xde: {"simd_i64x2_extmul_low_i32x4_u", []ssa.Type{simdV, simdV}, simdV},
	0xdf: {"simd_i64x2_extmul_high_i32x4_u", []ssa.Type{simdV, simdV}, simdV},

	0xe0: {"simd_f32x4_abs", []ssa.Type{simdV}, simdV},
	0xe1: {"simd_f32x4_neg", []ssa.Type{simdV}, simdV},
	0xe3: {"simd_f32x4_sqrt", []ssa.Type{simdV}, simdV},
	0xe4: {"simd_f32x4_add", []ssa.Type{simdV, simdV}, simdV},
	0xe5: {"simd_f32x4_sub", []ssa.Type{simdV, simdV}, simdV},
	0xe6: {"simd_f32x4_mul", []ssa.Type{simdV, simdV}, simdV},
	0xe7: {"simd_f32x4_div", []ssa.Type{simdV, simdV}, simdV},
	0xe8: {"simd_f32x4_min", []ssa.Type{simdV, simdV}, simdV},
	0xe9: {"simd_f32x4_max", []ssa.Type{simdV, simdV}, simdV},
	0xea: {"simd_f32x4_pmin", []ssa.Type{simdV, simdV}, simdV},
	0xeb: {"simd_f32x4_pmax", []ssa.Type{simdV, simdV}, simdV},

	0xec: {"simd_f64x2_abs", []ssa.Type{simdV}, simdV},
	0xed: {"simd_f64x2_neg", []ssa.Type{simdV}, simdV},
	0xef: {"simd_f64x2_sqrt", []ssa.Type{simdV}, simdV},
	0xf0: {"simd_f64x2_add", []ssa.Type{simdV, simdV}, simdV},
	0xf1: {"simd_f64x2_sub", []ssa.Type{simdV, simdV}, simdV},
	0xf2: {"simd_f64x2_mul", []ssa.Type{simdV, simdV}, simdV},
	0xf3: {"simd_f64x2_div", []ssa.Type{simdV, simdV}, simdV},
	0xf4: {"simd_f64x2_min", []ssa.Type{simdV, simdV}, simdV},
	0xf5: {"simd_f64x2_max", []ssa.Type{simdV, simdV}, simdV},
	0xf6: {"simd_f64x2_pmin", []ssa.Type{simdV, simdV}, simdV},
	0xf7: {"simd_f64x2_pmax", []ssa.Type{simdV, simdV}, simdV},

	0xf8: {"simd_i32x4_trunc_sat_f32x4_s", []ssa.Type{simdV}, simdV},
	0xf9: {"simd_i32x4_trunc_sat_f32x4_u", []ssa.Type{simdV}, simdV},
	0xfa: {"simd_f32x4_convert_i32x4_s", []ssa.Type{simdV}, simdV},
	0xfb: {"simd_f32x4_convert_i32x4_u", []ssa.Type{simdV}, simdV},
	0xfc: {"simd_i32x4_trunc_sat_f64x2_s_zero", []ssa.Type{simdV}, simdV},
	0xfd: {"simd_i32x4_trunc_sat_f64x2_u_zero", []ssa.Type{simdV}, simdV},
	0xfe: {"simd_f64x2_convert_low_i32x4_s", []ssa.Type{simdV}, simdV},
	0xff: {"simd_f64x2_convert_low_i32x4_u", []ssa.Type{simdV}, simdV},
}

func init() {
	// The int comparison families share a fixed clause order:
	// eq, ne, lt_s, lt_u, gt_s, gt_u, le_s, le_u, ge_s, ge_u
	// at i8x16 base 0x23 and i16x8 base 0x2d and i32x4 base 0x37.
	// The float families order eq, ne, lt, gt, le, ge at f32x4 base 0x41
	// and f64x2 base 0x47. (i64x2 comparisons are irregular; they are
	// listed explicitly above.)
	intCmps := []string{"eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u"}
	for i, op := range intCmps {
		fdSimd[0x23+uint32(i)] = fdSimdSpec{"simd_i8x16_" + op, []ssa.Type{simdV, simdV}, simdV}
		fdSimd[0x2d+uint32(i)] = fdSimdSpec{"simd_i16x8_" + op, []ssa.Type{simdV, simdV}, simdV}
		fdSimd[0x37+uint32(i)] = fdSimdSpec{"simd_i32x4_" + op, []ssa.Type{simdV, simdV}, simdV}
	}
	fltCmps := []string{"eq", "ne", "lt", "gt", "le", "ge"}
	for i, op := range fltCmps {
		fdSimd[0x41+uint32(i)] = fdSimdSpec{"simd_f32x4_" + op, []ssa.Type{simdV, simdV}, simdV}
		fdSimd[0x47+uint32(i)] = fdSimdSpec{"simd_f64x2_" + op, []ssa.Type{simdV, simdV}, simdV}
	}
}

// fdSimdMem maps the memory sub-opcodes to their module-aware helpers.
// hasValue marks stores (an extra v128 operand under the address ... actually
// on top of it) and the lane ops (which also carry a lane immediate).
type fdSimdMemSpec struct {
	helper string
	// store: pops a v128 value operand (pushed after the address).
	store bool
	// lane: the op carries a trailing lane-index immediate byte.
	lane bool
	// res is TypeV128 for loads, TypeInvalid for stores.
	res ssa.Type
}

var fdSimdMem = map[uint32]fdSimdMemSpec{
	0x00: {helper: "simd_v128_load", res: simdV},
	0x01: {helper: "simd_v128_load8x8_s", res: simdV},
	0x02: {helper: "simd_v128_load8x8_u", res: simdV},
	0x03: {helper: "simd_v128_load16x4_s", res: simdV},
	0x04: {helper: "simd_v128_load16x4_u", res: simdV},
	0x05: {helper: "simd_v128_load32x2_s", res: simdV},
	0x06: {helper: "simd_v128_load32x2_u", res: simdV},
	0x07: {helper: "simd_v128_load8_splat", res: simdV},
	0x08: {helper: "simd_v128_load16_splat", res: simdV},
	0x09: {helper: "simd_v128_load32_splat", res: simdV},
	0x0a: {helper: "simd_v128_load64_splat", res: simdV},
	0x0b: {helper: "simd_v128_store", store: true},

	0x54: {helper: "simd_v128_load8_lane", lane: true, store: true, res: simdV},
	0x55: {helper: "simd_v128_load16_lane", lane: true, store: true, res: simdV},
	0x56: {helper: "simd_v128_load32_lane", lane: true, store: true, res: simdV},
	0x57: {helper: "simd_v128_load64_lane", lane: true, store: true, res: simdV},
	0x58: {helper: "simd_v128_store8_lane", lane: true, store: true},
	0x59: {helper: "simd_v128_store16_lane", lane: true, store: true},
	0x5a: {helper: "simd_v128_store32_lane", lane: true, store: true},
	0x5b: {helper: "simd_v128_store64_lane", lane: true, store: true},

	0x5c: {helper: "simd_v128_load32_zero", res: simdV},
	0x5d: {helper: "simd_v128_load64_zero", res: simdV},
}

// fdSimdLane maps the extract/replace lane sub-opcodes: helper, whether a
// scalar replacement operand is popped, and the result type.
type fdSimdLaneSpec struct {
	helper string
	scalar ssa.Type // replacement operand type (TypeInvalid for extracts)
	res    ssa.Type
}

var fdSimdLane = map[uint32]fdSimdLaneSpec{
	0x15: {"simd_i8x16_extract_lane_s", ssa.TypeInvalid, sdI32},
	0x16: {"simd_i8x16_extract_lane_u", ssa.TypeInvalid, sdI32},
	0x17: {"simd_i8x16_replace_lane", sdI32, simdV},
	0x18: {"simd_i16x8_extract_lane_s", ssa.TypeInvalid, sdI32},
	0x19: {"simd_i16x8_extract_lane_u", ssa.TypeInvalid, sdI32},
	0x1a: {"simd_i16x8_replace_lane", sdI32, simdV},
	0x1b: {"simd_i32x4_extract_lane", ssa.TypeInvalid, sdI32},
	0x1c: {"simd_i32x4_replace_lane", sdI32, simdV},
	0x1d: {"simd_i64x2_extract_lane", ssa.TypeInvalid, sdI64},
	0x1e: {"simd_i64x2_replace_lane", sdI64, simdV},
	0x1f: {"simd_f32x4_extract_lane", ssa.TypeInvalid, sdF32},
	0x20: {"simd_f32x4_replace_lane", sdF32, simdV},
	0x21: {"simd_f64x2_extract_lane", ssa.TypeInvalid, sdF64},
	0x22: {"simd_f64x2_replace_lane", sdF64, simdV},
}

// handleFDOp dispatches the wasm 0xfd SIMD opcodes.
func (ls *lowerState) handleFDOp(r *wasm.InstrReader) error {
	sub, err := r.ReadU32()
	if err != nil {
		return err
	}

	// Memory ops: memarg (+ optional lane byte).
	if spec, ok := fdSimdMem[sub]; ok {
		if _, err := r.ReadU32(); err != nil { // align (validated upstream)
			return err
		}
		offset, err := r.ReadU64()
		if err != nil {
			return err
		}
		lane := int64(-1)
		if spec.lane {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			lane = int64(b)
		}
		var vec *ssa.Value
		if spec.store {
			if vec, err = ls.pop(); err != nil {
				return err
			}
		}
		addr, err := ls.pop()
		if err != nil {
			return err
		}
		helper := spec.helper
		var offVal *ssa.Value
		if ls.mem64 {
			// memory64: i64 address and offset; the m64 helper family
			// takes uint64 operands and is never rewritten to the
			// pair/splice forms (those assume 32-bit addressing).
			helper = "simd_m64" + strings.TrimPrefix(spec.helper, "simd")
			offVal = ls.b.Const64(int64(offset))
		} else {
			offVal = ls.b.Const32(int32(offset))
		}
		args := []*ssa.Value{addr, offVal}
		if spec.lane {
			args = append(args, ls.b.Const32(int32(lane)))
		}
		if vec != nil {
			args = append(args, vec)
		}
		res := spec.res
		if res == ssa.TypeInvalid {
			res = ssa.TypeI32 // dummy; stores push nothing
		}
		val := ls.b.NewValueAux(ssa.OpSimdMemCall, res, helper, args...)
		if spec.res != ssa.TypeInvalid {
			ls.push(val)
		}
		return nil
	}

	switch sub {
	case 0x0c: // v128.const: 16 immediate bytes, little-endian lanes
		var lo, hi uint64
		for i := 0; i < 8; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			lo |= uint64(b) << (8 * uint(i))
		}
		for i := 0; i < 8; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			hi |= uint64(b) << (8 * uint(i))
		}
		ls.push(ls.b.NewValueAux(ssa.OpSimdConst, ssa.TypeV128, [2]uint64{lo, hi}))
		return nil

	case 0x0d: // i8x16.shuffle: 16 immediate lane indices
		var lo, hi uint64
		for i := 0; i < 8; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			lo |= uint64(b) << (8 * uint(i))
		}
		for i := 0; i < 8; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			hi |= uint64(b) << (8 * uint(i))
		}
		bv, err := ls.pop()
		if err != nil {
			return err
		}
		av, err := ls.pop()
		if err != nil {
			return err
		}
		pat := ls.b.NewValueAux(ssa.OpSimdConst, ssa.TypeV128, [2]uint64{lo, hi})
		ls.push(ls.b.NewValueAux(ssa.OpSimdCall, ssa.TypeV128, "simd_i8x16_shuffle", av, bv, pat))
		return nil
	}

	// Lane extract/replace: one lane-index immediate byte.
	if spec, ok := fdSimdLane[sub]; ok {
		laneB, err := r.ReadByte()
		if err != nil {
			return err
		}
		var repl *ssa.Value
		if spec.scalar != ssa.TypeInvalid {
			if repl, err = ls.pop(); err != nil {
				return err
			}
		}
		vec, err := ls.pop()
		if err != nil {
			return err
		}
		args := []*ssa.Value{vec, ls.b.Const32(int32(laneB))}
		if repl != nil {
			args = append(args, repl)
		}
		ls.push(ls.b.NewValueAux(ssa.OpSimdCall, spec.res, spec.helper, args...))
		return nil
	}

	// Plain lane / arithmetic ops.
	spec, ok := fdSimd[sub]
	if !ok {
		return fmt.Errorf("%w: 0xfd sub-opcode 0x%02x not implemented", ErrSSAUnsupported, sub)
	}
	args := make([]*ssa.Value, len(spec.args))
	for i := len(spec.args) - 1; i >= 0; i-- {
		val, err := ls.pop()
		if err != nil {
			return err
		}
		args[i] = val
	}
	ls.push(ls.b.NewValueAux(ssa.OpSimdCall, spec.res, spec.helper, args...))
	return nil
}
