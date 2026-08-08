package helpers

import (
	"math"
	"testing"
)

// TestF32ToF16Bits pins the conversion against known IEEE binary16
// encodings, including round-to-nearest-even ties, denormals,
// overflow to infinity and the sign|0x7E00 NaN convention. Every
// non-NaN case must also match hardware FCVT (the asm backend
// replaces this helper with the native instruction).
func TestF32ToF16Bits(t *testing.T) {
	cases := []struct {
		in   float32
		want int32
	}{
		{0, 0x0000},
		{float32(math.Copysign(0, -1)), 0x8000},
		{1, 0x3C00},
		{-2.5, 0xC100},
		{65504, 0x7BFF},  // max finite half
		{65520, 0x7C00},  // rounds to +inf
		{-65520, 0xFC00}, // rounds to -inf
		{float32(math.Inf(1)), 0x7C00},
		{float32(math.Inf(-1)), 0xFC00},
		{float32(math.NaN()), 0x7E00},
		{5.9604645e-08, 0x0001}, // smallest denormal half
		{6.097555e-05, 0x03FF},  // largest denormal half
		{6.104e-05, 0x0400},     // smallest normal half
		{0.099975586, 0x2E66},   // 0.1 truncated to a half boundary
		{1.0009766, 0x3C01},     // one ulp above 1
		{1.0004883, 0x3C00},     // tie: rounds to even (down)
		{1.0014648, 0x3C02},     // tie: rounds to even (up)
	}
	for _, c := range cases {
		if got := f32_to_f16_bits(c.in); got != c.want {
			t.Errorf("f32_to_f16_bits(%v) = %#04x, want %#04x", c.in, got, c.want)
		}
	}
	if got := f32_to_f16_bits(float32(math.Float32frombits(0xFFC00001))); got != int32(0xFE00) {
		t.Errorf("negative NaN = %#04x, want 0xFE00", got)
	}
}
