package helpers

import (
	"math"
	"testing"
)

// The lane conversion must be the IEEE binary16->binary32 map for
// every bit pattern (the transpiler substitutes it for verified
// table lookups, and the native splices use FCVTL / the SSE trick).
func TestSimdF16x4Cvt(t *testing.T) {
	for i := 0; i < 65536; i += 4 {
		var v [2]uint64
		for k := 0; k < 4; k++ {
			v[k/2] |= uint64(uint16(i+k)) << (32 * uint(k) % 64)
		}
		out := simd_f16x4_cvt(v)
		for k := 0; k < 4; k++ {
			h := uint16(i + k)
			got := uint32(out[k/2] >> (32 * uint(k) % 64))
			want := refF16(h)
			if got != want {
				t.Fatalf("f16 %#04x: got %#08x want %#08x", h, got, want)
			}
		}
	}
}

// refF16 computes the conversion through float64 for finite values
// (exact: binary16 embeds in binary32 embeds in binary64) and by the
// IEEE payload rule for inf/NaN.
func refF16(h uint16) uint32 {
	exp := (h >> 10) & 0x1F
	sign := uint32(h>>15) << 31
	if exp == 0x1F {
		return sign | 0xFF<<23 | uint32(h&0x3FF)<<13
	}
	s := float64(1)
	if h>>15 == 1 {
		s = -1
	}
	var val float64
	if exp == 0 {
		val = s * float64(h&0x3FF) * math.Pow(2, -24)
	} else {
		val = s * (1 + float64(h&0x3FF)/1024) * math.Pow(2, float64(int(exp)-15))
	}
	return math.Float32bits(float32(val))
}
