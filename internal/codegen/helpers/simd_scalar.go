// The scalar reference implementations of the pure SIMD lane ops. On arm64 (and amd64 with GOAMD64>=v2) the simd_* entry
// points are assembly (simd_asm_*.s); everywhere else simd_fallback.go
// aliases them onto these _scalar bodies. The differential tests compare the
// two, so behavior changes must land here AND in the generated assembly
// (tools/gen-simd-asm regenerates the .s files from this contract).

//go:build (!arm64 && !amd64.v2) || simdmatrix

package helpers

import (
	"math"
	"math/bits"
)

var _ = bits.OnesCount8

func simdToU8(v [2]uint64) (r [16]uint8) {
	for i := range r {
		r[i] = uint8(v[i>>3] >> (8 * uint(i&7)))
	}
	return
}

func simdFromU8(r [16]uint8) (v [2]uint64) {
	for i, b := range r {
		v[i>>3] |= uint64(b) << (8 * uint(i&7))
	}
	return
}

func simdToU16(v [2]uint64) (r [8]uint16) {
	for i := range r {
		r[i] = uint16(v[i>>2] >> (16 * uint(i&3)))
	}
	return
}

func simdFromU16(r [8]uint16) (v [2]uint64) {
	for i, x := range r {
		v[i>>2] |= uint64(x) << (16 * uint(i&3))
	}
	return
}

func simdToU32(v [2]uint64) (r [4]uint32) {
	for i := range r {
		r[i] = uint32(v[i>>1] >> (32 * uint(i&1)))
	}
	return
}

func simdFromU32(r [4]uint32) (v [2]uint64) {
	for i, x := range r {
		v[i>>1] |= uint64(x) << (32 * uint(i&1))
	}
	return
}

func simdToF32(v [2]uint64) (r [4]float32) {
	u := simdToU32(v)
	for i := range r {
		r[i] = math.Float32frombits(u[i])
	}
	return
}

func simdFromF32(r [4]float32) [2]uint64 {
	var u [4]uint32
	for i := range r {
		u[i] = math.Float32bits(r[i])
	}
	return simdFromU32(u)
}

func simdToF64(v [2]uint64) [2]float64 {
	return [2]float64{math.Float64frombits(v[0]), math.Float64frombits(v[1])}
}

func simdFromF64(r [2]float64) [2]uint64 {
	return [2]uint64{math.Float64bits(r[0]), math.Float64bits(r[1])}
}

func simdBoolLane64(b bool) uint64 {
	if b {
		return ^uint64(0)
	}
	return 0
}

// Saturation clamps.

func simdSatI8(x int32) int8 {
	if x > 127 {
		return 127
	}
	if x < -128 {
		return -128
	}
	return int8(x)
}

func simdSatU8(x int32) uint8 {
	if x > 255 {
		return 255
	}
	if x < 0 {
		return 0
	}
	return uint8(x)
}

func simdSatI16(x int32) int16 {
	if x > 32767 {
		return 32767
	}
	if x < -32768 {
		return -32768
	}
	return int16(x)
}

func simdSatU16(x int32) uint16 {
	if x > 65535 {
		return 65535
	}
	if x < 0 {
		return 0
	}
	return uint16(x)
}

// Wasm float min/max (NaN-propagating, -0 < +0) and pmin/pmax
// (pseudo-min/max: plain b<a / a<b selects).

// simdPropNaN64 / simdPropNaN32 mirror the ARM FPProcessNaNs priority the
// asm bodies inherit from FMIN/FMAX: a signaling NaN in the first operand
// wins, then a signaling second, then a quiet first, then a quiet second —
// always quieted. Wasm permits any arithmetic NaN here; matching the
// hardware exactly keeps the asm-vs-scalar differential bit-exact.
func simdPropNaN64(a, b float64) (float64, bool) {
	const quiet = uint64(1) << 51
	ab, bb := math.Float64bits(a), math.Float64bits(b)
	aNaN := a != a
	bNaN := b != b
	if !aNaN && !bNaN {
		return 0, false
	}
	aSig := aNaN && ab&quiet == 0
	bSig := bNaN && bb&quiet == 0
	switch {
	case aSig:
		return math.Float64frombits(ab | quiet), true
	case bSig:
		return math.Float64frombits(bb | quiet), true
	case aNaN:
		return a, true
	default:
		return b, true
	}
}

func simdPropNaN32(a, b float32) (float32, bool) {
	const quiet = uint32(1) << 22
	ab, bb := math.Float32bits(a), math.Float32bits(b)
	aNaN := a != a
	bNaN := b != b
	if !aNaN && !bNaN {
		return 0, false
	}
	aSig := aNaN && ab&quiet == 0
	bSig := bNaN && bb&quiet == 0
	switch {
	case aSig:
		return math.Float32frombits(ab | quiet), true
	case bSig:
		return math.Float32frombits(bb | quiet), true
	case aNaN:
		return a, true
	default:
		return b, true
	}
}

func simdFMin64(a, b float64) float64 {
	if n, ok := simdPropNaN64(a, b); ok {
		return n
	}
	if a == b { // ±0: min is -0 if either is -0
		if math.Signbit(a) {
			return a
		}
		return b
	}
	if a < b {
		return a
	}
	return b
}

func simdFMax64(a, b float64) float64 {
	if n, ok := simdPropNaN64(a, b); ok {
		return n
	}
	if a == b { // ±0: max is +0 if either is +0
		if math.Signbit(a) {
			return b
		}
		return a
	}
	if a > b {
		return a
	}
	return b
}

func simdFMin32(a, b float32) float32 {
	if n, ok := simdPropNaN32(a, b); ok {
		return n
	}
	if a == b {
		if math.Signbit(float64(a)) {
			return a
		}
		return b
	}
	if a < b {
		return a
	}
	return b
}

func simdFMax32(a, b float32) float32 {
	if n, ok := simdPropNaN32(a, b); ok {
		return n
	}
	if a == b {
		if math.Signbit(float64(a)) {
			return b
		}
		return a
	}
	if a > b {
		return a
	}
	return b
}

func simd_i8x16_shuffle_scalar(a, b, pat [2]uint64) [2]uint64 {
	ab := simdToU8(a)
	bb := simdToU8(b)
	pb := simdToU8(pat)
	var out [16]uint8
	for i, idx := range pb {
		// Real modules only carry validated patterns (< 32); indexing like
		// TBL — anything else selects zero — keeps this total for the
		// asm-vs-scalar differential, which feeds arbitrary vectors.
		switch {
		case idx < 16:
			out[i] = ab[idx]
		case idx < 32:
			out[i] = bb[idx-16]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_swizzle_scalar(a, s [2]uint64) [2]uint64 {
	ab := simdToU8(a)
	sb := simdToU8(s)
	var out [16]uint8
	for i, idx := range sb {
		if idx < 16 {
			out[i] = ab[idx]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_splat_scalar(x int32) [2]uint64 {
	var out [16]uint8
	for i := range out {
		out[i] = uint8(x)
	}
	return simdFromU8(out)
}

func simd_i16x8_splat_scalar(x int32) [2]uint64 {
	var out [8]uint16
	for i := range out {
		out[i] = uint16(x)
	}
	return simdFromU16(out)
}

func simd_i32x4_splat_scalar(x int32) [2]uint64 {
	var out [4]uint32
	for i := range out {
		out[i] = uint32(x)
	}
	return simdFromU32(out)
}

func simd_i64x2_splat_scalar(x int64) [2]uint64 {
	return [2]uint64{uint64(x), uint64(x)}
}

func simd_f32x4_splat_scalar(x float32) [2]uint64 {
	return simdFromF32([4]float32{x, x, x, x})
}

func simd_f64x2_splat_scalar(x float64) [2]uint64 {
	return simdFromF64([2]float64{x, x})
}

func simd_i8x16_extract_lane_s_scalar(v [2]uint64, lane int32) int32 {
	return int32(int8(simdToU8(v)[lane]))
}

func simd_i8x16_extract_lane_u_scalar(v [2]uint64, lane int32) int32 {
	return int32(simdToU8(v)[lane])
}

func simd_i8x16_replace_lane_scalar(v [2]uint64, lane int32, x int32) [2]uint64 {
	b := simdToU8(v)
	b[lane] = uint8(x)
	return simdFromU8(b)
}

func simd_i16x8_extract_lane_s_scalar(v [2]uint64, lane int32) int32 {
	return int32(int16(simdToU16(v)[lane]))
}

func simd_i16x8_extract_lane_u_scalar(v [2]uint64, lane int32) int32 {
	return int32(simdToU16(v)[lane])
}

func simd_i16x8_replace_lane_scalar(v [2]uint64, lane int32, x int32) [2]uint64 {
	b := simdToU16(v)
	b[lane] = uint16(x)
	return simdFromU16(b)
}

func simd_i32x4_extract_lane_scalar(v [2]uint64, lane int32) int32 {
	return int32(simdToU32(v)[lane])
}

func simd_i32x4_replace_lane_scalar(v [2]uint64, lane int32, x int32) [2]uint64 {
	b := simdToU32(v)
	b[lane] = uint32(x)
	return simdFromU32(b)
}

func simd_i64x2_extract_lane_scalar(v [2]uint64, lane int32) int64 {
	return int64(v[lane])
}

func simd_i64x2_replace_lane_scalar(v [2]uint64, lane int32, x int64) [2]uint64 {
	v[lane] = uint64(x)
	return v
}

func simd_f32x4_extract_lane_scalar(v [2]uint64, lane int32) float32 {
	return simdToF32(v)[lane]
}

func simd_f32x4_replace_lane_scalar(v [2]uint64, lane int32, x float32) [2]uint64 {
	b := simdToF32(v)
	b[lane] = x
	return simdFromF32(b)
}

func simd_f64x2_extract_lane_scalar(v [2]uint64, lane int32) float64 {
	return simdToF64(v)[lane]
}

func simd_f64x2_replace_lane_scalar(v [2]uint64, lane int32, x float64) [2]uint64 {
	v[lane] = math.Float64bits(x)
	return v
}

func simd_v128_not_scalar(a [2]uint64) [2]uint64 { return [2]uint64{^a[0], ^a[1]} }

func simd_v128_and_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] & b[0], a[1] & b[1]} }

func simd_v128_andnot_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] &^ b[0], a[1] &^ b[1]} }

func simd_v128_or_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] | b[0], a[1] | b[1]} }

func simd_v128_xor_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] ^ b[0], a[1] ^ b[1]} }

func simd_v128_bitselect_scalar(a, b, c [2]uint64) [2]uint64 {
	return [2]uint64{a[0]&c[0] | b[0]&^c[0], a[1]&c[1] | b[1]&^c[1]}
}

// simd_f16x4_cvt_bits_scalar packs the float16 conversions of the
// four f32 lanes into one little-endian u64 (16 bits per lane).
// Round-to-nearest-even, NaN forced to sign|0x7E00 — exactly the
// software fp32->fp16 idiom this op replaces (and what arm64 FCVTN
// plus the NaN blend computes). The body inlines the proven
// f32_to_f16_bits algorithm so this file stays self-contained.
func simd_f16x4_cvt_bits_scalar(a [2]uint64) int64 {
	var out uint64
	for i := 0; i < 4; i++ {
		w := uint32(a[i/2] >> (32 * uint(i) % 64))
		shl1w := w + w
		sign := w & 0x80000000
		var h uint32
		if shl1w > 0xFF000000 { // NaN
			h = (sign >> 16) | 0x7E00
		} else {
			bias := shl1w & 0xFF000000
			if bias < 0x71000000 {
				bias = 0x71000000
			}
			f := math.Float32frombits(w&0x7FFFFFFF) * 0x1p+112 * 0x1p-110
			f += math.Float32frombits((bias >> 1) + 0x07800000)
			fbits := math.Float32bits(f)
			h = (sign >> 16) | (fbits>>13)&0x7C00 + fbits&0xFFF
		}
		out |= uint64(uint16(h)) << (16 * uint(i))
	}
	return int64(out)
}

func simd_v128_any_true_scalar(a [2]uint64) int32 {
	if a[0]|a[1] != 0 {
		return 1
	}
	return 0
}

func simd_i8x16_eq_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x == y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_ne_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x != y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_lt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if int8(x) < int8(y) {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_lt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x < y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_gt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if int8(x) > int8(y) {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_gt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x > y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_le_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if int8(x) <= int8(y) {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_le_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x <= y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_ge_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if int8(x) >= int8(y) {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_ge_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		x, y := av[i], bv[i]
		if x >= y {
			out[i] = uint8(^uint8(0))
		}
	}
	return simdFromU8(out)
}

func simd_i16x8_eq_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x == y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_ne_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x != y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_lt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if int16(x) < int16(y) {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_lt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x < y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_gt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if int16(x) > int16(y) {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_gt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x > y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_le_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if int16(x) <= int16(y) {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_le_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x <= y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_ge_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if int16(x) >= int16(y) {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_ge_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		x, y := av[i], bv[i]
		if x >= y {
			out[i] = uint16(^uint16(0))
		}
	}
	return simdFromU16(out)
}

func simd_i32x4_eq_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x == y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_ne_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x != y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_lt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if int32(x) < int32(y) {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_lt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x < y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_gt_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if int32(x) > int32(y) {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_gt_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x > y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_le_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if int32(x) <= int32(y) {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_le_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x <= y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_ge_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if int32(x) >= int32(y) {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_ge_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x >= y {
			out[i] = uint32(^uint32(0))
		}
	}
	return simdFromU32(out)
}

func simd_i64x2_eq_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(a[i] == b[i])
	}
	return out
}

func simd_i64x2_ne_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(a[i] != b[i])
	}
	return out
}

func simd_i64x2_lt_s_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(int64(a[i]) < int64(b[i]))
	}
	return out
}

func simd_i64x2_gt_s_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(int64(a[i]) > int64(b[i]))
	}
	return out
}

func simd_i64x2_le_s_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(int64(a[i]) <= int64(b[i]))
	}
	return out
}

func simd_i64x2_ge_s_scalar(a, b [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		out[i] = simdBoolLane64(int64(a[i]) >= int64(b[i]))
	}
	return out
}

func simd_f32x4_eq_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x == y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f32x4_ne_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x != y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f32x4_lt_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x < y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f32x4_gt_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x > y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f32x4_le_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x <= y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f32x4_ge_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]uint32
	for i := range out {
		x, y := av[i], bv[i]
		if x >= y {
			out[i] = ^uint32(0)
		}
	}
	return simdFromU32(out)
}

func simd_f64x2_eq_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x == y)
	}
	return out
}

func simd_f64x2_ne_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x != y)
	}
	return out
}

func simd_f64x2_lt_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x < y)
	}
	return out
}

func simd_f64x2_gt_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x > y)
	}
	return out
}

func simd_f64x2_le_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x <= y)
	}
	return out
}

func simd_f64x2_ge_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]uint64
	for i := range out {
		x, y := av[i], bv[i]
		out[i] = simdBoolLane64(x >= y)
	}
	return out
}

func simd_i8x16_add_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = av[i] + bv[i]
	}
	return simdFromU8(out)
}

func simd_i8x16_sub_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = av[i] - bv[i]
	}
	return simdFromU8(out)
}

func simd_i8x16_min_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		if int8(av[i]) < int8(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_min_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		if av[i] < bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_max_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		if int8(av[i]) > int8(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_max_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		if av[i] > bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU8(out)
}

func simd_i8x16_abs_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [16]uint8
	for i := range out {
		x := int8(av[i])
		if x < 0 {
			x = -x
		}
		out[i] = uint8(x)
	}
	return simdFromU8(out)
}

func simd_i8x16_neg_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [16]uint8
	for i := range out {
		out[i] = -av[i]
	}
	return simdFromU8(out)
}

func simd_i8x16_all_true_scalar(a [2]uint64) int32 {
	av := simdToU8(a)
	for i := range av {
		if av[i] == 0 {
			return 0
		}
	}
	return 1
}

func simd_i8x16_bitmask_scalar(a [2]uint64) int32 {
	av := simdToU8(a)
	r := int32(0)
	for i := range av {
		if int8(av[i]) < 0 {
			r |= 1 << uint(i)
		}
	}
	return r
}

func simd_i8x16_shl_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU8(a)
	sh := uint(s) % 8
	var out [16]uint8
	for i := range out {
		out[i] = av[i] << sh
	}
	return simdFromU8(out)
}

func simd_i8x16_shr_s_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU8(a)
	sh := uint(s) % 8
	var out [16]uint8
	for i := range out {
		out[i] = uint8(int8(av[i]) >> sh)
	}
	return simdFromU8(out)
}

func simd_i8x16_shr_u_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU8(a)
	sh := uint(s) % 8
	var out [16]uint8
	for i := range out {
		out[i] = av[i] >> sh
	}
	return simdFromU8(out)
}

func simd_i16x8_add_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = av[i] + bv[i]
	}
	return simdFromU16(out)
}

func simd_i16x8_sub_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = av[i] - bv[i]
	}
	return simdFromU16(out)
}

func simd_i16x8_mul_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = av[i] * bv[i]
	}
	return simdFromU16(out)
}

func simd_i16x8_min_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		if int16(av[i]) < int16(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_min_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		if av[i] < bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_max_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		if int16(av[i]) > int16(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_max_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		if av[i] > bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU16(out)
}

func simd_i16x8_abs_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [8]uint16
	for i := range out {
		x := int16(av[i])
		if x < 0 {
			x = -x
		}
		out[i] = uint16(x)
	}
	return simdFromU16(out)
}

func simd_i16x8_neg_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [8]uint16
	for i := range out {
		out[i] = -av[i]
	}
	return simdFromU16(out)
}

func simd_i16x8_all_true_scalar(a [2]uint64) int32 {
	av := simdToU16(a)
	for i := range av {
		if av[i] == 0 {
			return 0
		}
	}
	return 1
}

func simd_i16x8_bitmask_scalar(a [2]uint64) int32 {
	av := simdToU16(a)
	r := int32(0)
	for i := range av {
		if int16(av[i]) < 0 {
			r |= 1 << uint(i)
		}
	}
	return r
}

func simd_i16x8_shl_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU16(a)
	sh := uint(s) % 16
	var out [8]uint16
	for i := range out {
		out[i] = av[i] << sh
	}
	return simdFromU16(out)
}

func simd_i16x8_shr_s_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU16(a)
	sh := uint(s) % 16
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int16(av[i]) >> sh)
	}
	return simdFromU16(out)
}

func simd_i16x8_shr_u_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU16(a)
	sh := uint(s) % 16
	var out [8]uint16
	for i := range out {
		out[i] = av[i] >> sh
	}
	return simdFromU16(out)
}

func simd_i32x4_add_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		out[i] = av[i] + bv[i]
	}
	return simdFromU32(out)
}

func simd_i32x4_sub_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		out[i] = av[i] - bv[i]
	}
	return simdFromU32(out)
}

func simd_i32x4_mul_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		out[i] = av[i] * bv[i]
	}
	return simdFromU32(out)
}

func simd_i32x4_min_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		if int32(av[i]) < int32(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_min_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		if av[i] < bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_max_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		if int32(av[i]) > int32(bv[i]) {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_max_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [4]uint32
	for i := range out {
		if av[i] > bv[i] {
			out[i] = av[i]
		} else {
			out[i] = bv[i]
		}
	}
	return simdFromU32(out)
}

func simd_i32x4_abs_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [4]uint32
	for i := range out {
		x := int32(av[i])
		if x < 0 {
			x = -x
		}
		out[i] = uint32(x)
	}
	return simdFromU32(out)
}

func simd_i32x4_neg_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [4]uint32
	for i := range out {
		out[i] = -av[i]
	}
	return simdFromU32(out)
}

func simd_i32x4_all_true_scalar(a [2]uint64) int32 {
	av := simdToU32(a)
	for i := range av {
		if av[i] == 0 {
			return 0
		}
	}
	return 1
}

func simd_i32x4_bitmask_scalar(a [2]uint64) int32 {
	av := simdToU32(a)
	r := int32(0)
	for i := range av {
		if int32(av[i]) < 0 {
			r |= 1 << uint(i)
		}
	}
	return r
}

func simd_i32x4_shl_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU32(a)
	sh := uint(s) % 32
	var out [4]uint32
	for i := range out {
		out[i] = av[i] << sh
	}
	return simdFromU32(out)
}

func simd_i32x4_shr_s_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU32(a)
	sh := uint(s) % 32
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(av[i]) >> sh)
	}
	return simdFromU32(out)
}

func simd_i32x4_shr_u_scalar(a [2]uint64, s int32) [2]uint64 {
	av := simdToU32(a)
	sh := uint(s) % 32
	var out [4]uint32
	for i := range out {
		out[i] = av[i] >> sh
	}
	return simdFromU32(out)
}

func simd_i8x16_add_sat_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = uint8(simdSatI8(int32(int8(av[i])) + int32(int8(bv[i]))))
	}
	return simdFromU8(out)
}

func simd_i8x16_add_sat_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = simdSatU8(int32(av[i]) + int32(bv[i]))
	}
	return simdFromU8(out)
}

func simd_i8x16_sub_sat_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = uint8(simdSatI8(int32(int8(av[i])) - int32(int8(bv[i]))))
	}
	return simdFromU8(out)
}

func simd_i8x16_sub_sat_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = simdSatU8(int32(av[i]) - int32(bv[i]))
	}
	return simdFromU8(out)
}

func simd_i8x16_avgr_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [16]uint8
	for i := range out {
		out[i] = uint8((uint32(av[i]) + uint32(bv[i]) + 1) / 2)
	}
	return simdFromU8(out)
}

func simd_i16x8_add_sat_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(simdSatI16(int32(int16(av[i])) + int32(int16(bv[i]))))
	}
	return simdFromU16(out)
}

func simd_i16x8_add_sat_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = simdSatU16(int32(av[i]) + int32(bv[i]))
	}
	return simdFromU16(out)
}

func simd_i16x8_sub_sat_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(simdSatI16(int32(int16(av[i])) - int32(int16(bv[i]))))
	}
	return simdFromU16(out)
}

func simd_i16x8_sub_sat_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = simdSatU16(int32(av[i]) - int32(bv[i]))
	}
	return simdFromU16(out)
}

func simd_i16x8_avgr_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16((uint32(av[i]) + uint32(bv[i]) + 1) / 2)
	}
	return simdFromU16(out)
}

func simd_i8x16_popcnt_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [16]uint8
	for i := range out {
		out[i] = uint8(bits.OnesCount8(av[i]))
	}
	return simdFromU8(out)
}

func simd_i64x2_add_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] + b[0], a[1] + b[1]} }

func simd_i64x2_sub_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] - b[0], a[1] - b[1]} }

func simd_i64x2_mul_scalar(a, b [2]uint64) [2]uint64 { return [2]uint64{a[0] * b[0], a[1] * b[1]} }

func simd_i64x2_abs_scalar(a [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := range out {
		x := int64(a[i])
		if x < 0 {
			x = -x
		}
		out[i] = uint64(x)
	}
	return out
}

func simd_i64x2_neg_scalar(a [2]uint64) [2]uint64 { return [2]uint64{-a[0], -a[1]} }

func simd_i64x2_all_true_scalar(a [2]uint64) int32 {
	if a[0] != 0 && a[1] != 0 {
		return 1
	}
	return 0
}

func simd_i64x2_bitmask_scalar(a [2]uint64) int32 {
	r := int32(0)
	if int64(a[0]) < 0 {
		r |= 1
	}
	if int64(a[1]) < 0 {
		r |= 2
	}
	return r
}

func simd_i64x2_shl_scalar(a [2]uint64, s int32) [2]uint64 {
	sh := uint(s) % 64
	return [2]uint64{a[0] << sh, a[1] << sh}
}

func simd_i64x2_shr_s_scalar(a [2]uint64, s int32) [2]uint64 {
	sh := uint(s) % 64
	return [2]uint64{uint64(int64(a[0]) >> sh), uint64(int64(a[1]) >> sh)}
}

func simd_i64x2_shr_u_scalar(a [2]uint64, s int32) [2]uint64 {
	sh := uint(s) % 64
	return [2]uint64{a[0] >> sh, a[1] >> sh}
}

func simd_i16x8_q15mulr_sat_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [8]uint16
	for i := range out {
		p := (int32(int16(av[i]))*int32(int16(bv[i])) + 0x4000) >> 15
		out[i] = uint16(simdSatI16(p))
	}
	return simdFromU16(out)
}

func simd_i8x16_narrow_i16x8_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [16]uint8
	for i := 0; i < 8; i++ {
		out[i] = uint8(simdSatI8(int32(int16(av[i]))))
		out[i+8] = uint8(simdSatI8(int32(int16(bv[i]))))
	}
	return simdFromU8(out)
}

func simd_i8x16_narrow_i16x8_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [16]uint8
	for i := 0; i < 8; i++ {
		out[i] = simdSatU8(int32(int16(av[i])))
		out[i+8] = simdSatU8(int32(int16(bv[i])))
	}
	return simdFromU8(out)
}

func simd_i16x8_narrow_i32x4_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [8]uint16
	for i := 0; i < 4; i++ {
		out[i] = uint16(simdSatI16From32(int32(av[i])))
		out[i+4] = uint16(simdSatI16From32(int32(bv[i])))
	}
	return simdFromU16(out)
}

func simd_i16x8_narrow_i32x4_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [8]uint16
	for i := 0; i < 4; i++ {
		out[i] = simdSatU16From32(int32(av[i]))
		out[i+4] = simdSatU16From32(int32(bv[i]))
	}
	return simdFromU16(out)
}

func simdSatI16From32(x int32) int16 {
	if x > 32767 {
		return 32767
	}
	if x < -32768 {
		return -32768
	}
	return int16(x)
}

func simdSatU16From32(x int32) uint16 {
	if x > 65535 {
		return 65535
	}
	if x < 0 {
		return 0
	}
	return uint16(x)
}

func simd_i16x8_extend_low_i8x16_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int16(int8(av[i])))
	}
	return simdFromU16(out)
}

func simd_i16x8_extend_low_i8x16_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(av[i])
	}
	return simdFromU16(out)
}

func simd_i16x8_extend_high_i8x16_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int16(int8(av[i+8])))
	}
	return simdFromU16(out)
}

func simd_i16x8_extend_high_i8x16_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(av[i+8])
	}
	return simdFromU16(out)
}

func simd_i32x4_extend_low_i16x8_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(int16(av[i])))
	}
	return simdFromU32(out)
}

func simd_i32x4_extend_low_i16x8_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(av[i])
	}
	return simdFromU32(out)
}

func simd_i32x4_extend_high_i16x8_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(int16(av[i+4])))
	}
	return simdFromU32(out)
}

func simd_i32x4_extend_high_i16x8_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(av[i+4])
	}
	return simdFromU32(out)
}

func simd_i64x2_extend_low_i32x4_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(int64(int32(av[i])))
	}
	return out
}

func simd_i64x2_extend_low_i32x4_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(av[i])
	}
	return out
}

func simd_i64x2_extend_high_i32x4_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(int64(int32(av[i+2])))
	}
	return out
}

func simd_i64x2_extend_high_i32x4_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(av[i+2])
	}
	return out
}

func simd_i16x8_extadd_pairwise_i8x16_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int16(int8(av[2*i])) + int16(int8(av[2*i+1])))
	}
	return simdFromU16(out)
}

func simd_i16x8_extadd_pairwise_i8x16_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU8(a)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(av[2*i]) + uint16(av[2*i+1])
	}
	return simdFromU16(out)
}

func simd_i32x4_extadd_pairwise_i16x8_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(int16(av[2*i])) + int32(int16(av[2*i+1])))
	}
	return simdFromU32(out)
}

func simd_i32x4_extadd_pairwise_i16x8_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU16(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(av[2*i]) + uint32(av[2*i+1])
	}
	return simdFromU32(out)
}

func simd_i16x8_extmul_low_i8x16_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int32(int8(av[i+0])) * int32(int8(bv[i+0])))
	}
	return simdFromU16(out)
}

func simd_i16x8_extmul_low_i8x16_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(uint32(av[i+0]) * uint32(bv[i+0]))
	}
	return simdFromU16(out)
}

func simd_i16x8_extmul_high_i8x16_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(int32(int8(av[i+8])) * int32(int8(bv[i+8])))
	}
	return simdFromU16(out)
}

func simd_i16x8_extmul_high_i8x16_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU8(a), simdToU8(b)
	var out [8]uint16
	for i := range out {
		out[i] = uint16(uint32(av[i+8]) * uint32(bv[i+8]))
	}
	return simdFromU16(out)
}

func simd_i32x4_extmul_low_i16x8_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(int16(av[i+0])) * int32(int16(bv[i+0])))
	}
	return simdFromU32(out)
}

func simd_i32x4_extmul_low_i16x8_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(uint32(av[i+0]) * uint32(bv[i+0]))
	}
	return simdFromU32(out)
}

func simd_i32x4_extmul_high_i16x8_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(int32(int16(av[i+4])) * int32(int16(bv[i+4])))
	}
	return simdFromU32(out)
}

func simd_i32x4_extmul_high_i16x8_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(uint32(av[i+4]) * uint32(bv[i+4]))
	}
	return simdFromU32(out)
}

func simd_i64x2_extmul_low_i32x4_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(int64(int32(av[i+0])) * int64(int32(bv[i+0])))
	}
	return out
}

func simd_i64x2_extmul_low_i32x4_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(av[i+0]) * uint64(bv[i+0])
	}
	return out
}

func simd_i64x2_extmul_high_i32x4_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(int64(int32(av[i+2])) * int64(int32(bv[i+2])))
	}
	return out
}

func simd_i64x2_extmul_high_i32x4_u_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU32(a), simdToU32(b)
	var out [2]uint64
	for i := range out {
		out[i] = uint64(av[i+2]) * uint64(bv[i+2])
	}
	return out
}

func simd_i32x4_dot_i16x8_s_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToU16(a), simdToU16(b)
	var out [4]uint32
	for i := range out {
		p0 := int32(int16(av[2*i])) * int32(int16(bv[2*i]))
		p1 := int32(int16(av[2*i+1])) * int32(int16(bv[2*i+1]))
		out[i] = uint32(p0 + p1)
	}
	return simdFromU32(out)
}

func simd_f32x4_add_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = av[i] + bv[i]
	}
	return simdFromF32(out)
}

func simd_f32x4_sub_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = av[i] - bv[i]
	}
	return simdFromF32(out)
}

func simd_f32x4_mul_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = av[i] * bv[i]
	}
	return simdFromF32(out)
}

func simd_f32x4_div_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = av[i] / bv[i]
	}
	return simdFromF32(out)
}

func simd_f32x4_min_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = simdFMin32(av[i], bv[i])
	}
	return simdFromF32(out)
}

func simd_f32x4_max_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		out[i] = simdFMax32(av[i], bv[i])
	}
	return simdFromF32(out)
}

func simd_f32x4_pmin_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		if bv[i] < av[i] {
			out[i] = bv[i]
		} else {
			out[i] = av[i]
		}
	}
	return simdFromF32(out)
}

func simd_f32x4_pmax_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF32(a), simdToF32(b)
	var out [4]float32
	for i := range out {
		if av[i] < bv[i] {
			out[i] = bv[i]
		} else {
			out[i] = av[i]
		}
	}
	return simdFromF32(out)
}

func simd_f32x4_abs_scalar(a [2]uint64) [2]uint64 {
	u := simdToU32(a)
	for i := range u {
		u[i] &^= 1 << 31
	}
	return simdFromU32(u)
}

func simd_f32x4_neg_scalar(a [2]uint64) [2]uint64 {
	u := simdToU32(a)
	for i := range u {
		u[i] ^= 1 << 31
	}
	return simdFromU32(u)
}

func simd_f32x4_sqrt_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(math.Sqrt(float64(av[i])))
	}
	return simdFromF32(out)
}

func simd_f32x4_ceil_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(math.Ceil(float64(av[i])))
	}
	return simdFromF32(out)
}

func simd_f32x4_floor_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(math.Floor(float64(av[i])))
	}
	return simdFromF32(out)
}

func simd_f32x4_trunc_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(math.Trunc(float64(av[i])))
	}
	return simdFromF32(out)
}

func simd_f32x4_nearest_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(math.RoundToEven(float64(av[i])))
	}
	return simdFromF32(out)
}

func simd_f64x2_add_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{av[0] + bv[0], av[1] + bv[1]})
}

func simd_f64x2_sub_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{av[0] - bv[0], av[1] - bv[1]})
}

func simd_f64x2_mul_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{av[0] * bv[0], av[1] * bv[1]})
}

func simd_f64x2_div_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{av[0] / bv[0], av[1] / bv[1]})
}

func simd_f64x2_min_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{simdFMin64(av[0], bv[0]), simdFMin64(av[1], bv[1])})
}

func simd_f64x2_max_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	return simdFromF64([2]float64{simdFMax64(av[0], bv[0]), simdFMax64(av[1], bv[1])})
}

func simd_f64x2_pmin_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]float64
	for i := range out {
		if bv[i] < av[i] {
			out[i] = bv[i]
		} else {
			out[i] = av[i]
		}
	}
	return simdFromF64(out)
}

func simd_f64x2_pmax_scalar(a, b [2]uint64) [2]uint64 {
	av, bv := simdToF64(a), simdToF64(b)
	var out [2]float64
	for i := range out {
		if av[i] < bv[i] {
			out[i] = bv[i]
		} else {
			out[i] = av[i]
		}
	}
	return simdFromF64(out)
}

func simd_f64x2_abs_scalar(a [2]uint64) [2]uint64 {
	return [2]uint64{a[0] &^ (1 << 63), a[1] &^ (1 << 63)}
}

func simd_f64x2_neg_scalar(a [2]uint64) [2]uint64 {
	return [2]uint64{a[0] ^ (1 << 63), a[1] ^ (1 << 63)}
}

func simd_f64x2_sqrt_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	return simdFromF64([2]float64{math.Sqrt(av[0]), math.Sqrt(av[1])})
}

func simd_f64x2_ceil_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	return simdFromF64([2]float64{math.Ceil(av[0]), math.Ceil(av[1])})
}

func simd_f64x2_floor_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	return simdFromF64([2]float64{math.Floor(av[0]), math.Floor(av[1])})
}

func simd_f64x2_trunc_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	return simdFromF64([2]float64{math.Trunc(av[0]), math.Trunc(av[1])})
}

func simd_f64x2_nearest_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	return simdFromF64([2]float64{math.RoundToEven(av[0]), math.RoundToEven(av[1])})
}

func simd_i32x4_trunc_sat_f32x4_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]uint32
	for i := range out {
		out[i] = uint32(simdTruncSatI32(float64(av[i])))
	}
	return simdFromU32(out)
}

func simd_i32x4_trunc_sat_f32x4_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	var out [4]uint32
	for i := range out {
		out[i] = simdTruncSatU32(float64(av[i]))
	}
	return simdFromU32(out)
}

func simd_i32x4_trunc_sat_f64x2_s_zero_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	var out [4]uint32
	out[0] = uint32(simdTruncSatI32(av[0]))
	out[1] = uint32(simdTruncSatI32(av[1]))
	return simdFromU32(out)
}

func simd_i32x4_trunc_sat_f64x2_u_zero_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	var out [4]uint32
	out[0] = simdTruncSatU32(av[0])
	out[1] = simdTruncSatU32(av[1])
	return simdFromU32(out)
}

func simdTruncSatI32(x float64) int32 {
	if x != x {
		return 0
	}
	x = math.Trunc(x)
	if x >= 2147483647 {
		return 2147483647
	}
	if x <= -2147483648 {
		return -2147483648
	}
	return int32(x)
}

func simdTruncSatU32(x float64) uint32 {
	if x != x {
		return 0
	}
	x = math.Trunc(x)
	if x >= 4294967295 {
		return 4294967295
	}
	if x <= 0 {
		return 0
	}
	return uint32(x)
}

func simd_f32x4_convert_i32x4_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(int32(av[i]))
	}
	return simdFromF32(out)
}

func simd_f32x4_convert_i32x4_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	var out [4]float32
	for i := range out {
		out[i] = float32(av[i])
	}
	return simdFromF32(out)
}

func simd_f64x2_convert_low_i32x4_s_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	return simdFromF64([2]float64{float64(int32(av[0])), float64(int32(av[1]))})
}

func simd_f64x2_convert_low_i32x4_u_scalar(a [2]uint64) [2]uint64 {
	av := simdToU32(a)
	return simdFromF64([2]float64{float64(av[0]), float64(av[1])})
}

func simd_f32x4_demote_f64x2_zero_scalar(a [2]uint64) [2]uint64 {
	av := simdToF64(a)
	var out [4]float32
	out[0] = float32(av[0])
	out[1] = float32(av[1])
	return simdFromF32(out)
}

func simd_f64x2_promote_low_f32x4_scalar(a [2]uint64) [2]uint64 {
	av := simdToF32(a)
	return simdFromF64([2]float64{float64(av[0]), float64(av[1])})
}
