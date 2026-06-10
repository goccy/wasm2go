package helpers

import (
	"math"
	"testing"
)

// TestFloat64Comparators covers the f64 boolean producers
// (f64_eq/ne/lt/gt/le/ge). Each helper has the same `if cond { 1 }
// else { 0 }` shape — we hit both arms once per helper. The
// reference comparison is a direct Go `==`, `!=`, etc. on the same
// operands so the assertion stays implementation-independent: if
// the helper agrees with the language operator, it's correct.
func TestFloat64Comparators(t *testing.T) {
	cases := []struct {
		x, y float64
	}{
		{1.0, 2.0}, {2.0, 1.0}, {1.0, 1.0}, {0.0, math.Copysign(0, -1)},
	}
	check := func(name string, h func(a, b float64) int32, ref func(a, b float64) bool) {
		for _, c := range cases {
			want := int32(0)
			if ref(c.x, c.y) {
				want = 1
			}
			if got := h(c.x, c.y); got != want {
				t.Errorf("%s(%v, %v) = %d, want %d", name, c.x, c.y, got, want)
			}
		}
	}
	check("f64_eq", f64_eq, func(a, b float64) bool { return a == b })
	check("f64_ne", f64_ne, func(a, b float64) bool { return a != b })
	check("f64_lt", f64_lt, func(a, b float64) bool { return a < b })
	check("f64_gt", f64_gt, func(a, b float64) bool { return a > b })
	check("f64_le", f64_le, func(a, b float64) bool { return a <= b })
	check("f64_ge", f64_ge, func(a, b float64) bool { return a >= b })
}

// TestFloat64PromoteNaN exercises the NaN-preserving path of
// f64_promote_f32. The non-NaN path is covered by the cg_numerics
// fixture's runtime tests; this fills in the NaN branch.
func TestFloat64PromoteNaN(t *testing.T) {
	nan := float32(math.NaN())
	got := f64_promote_f32(nan)
	if !math.IsNaN(got) {
		t.Errorf("f64_promote_f32(NaN) = %v, want NaN", got)
	}
	// Finite values must round-trip exactly: the helper's wide path
	// is for NaN only; the normal path is the language `float64(x)`.
	if got := f64_promote_f32(2.5); got != 2.5 {
		t.Errorf("f64_promote_f32(2.5) = %v, want 2.5", got)
	}
}

// TestWasmTrapHelpers — the three panic-only helpers the asm emit
// branches to on a div/rem/trunc trap path. Each one must panic
// with the exact spec-mandated message so the assertion path in
// TestTrapOpsArePreservedThroughDCE keeps matching what the
// integer / float trunc helpers raise from the pure-Go side.
func TestWasmTrapHelpers(t *testing.T) {
	mustPanic(t, "wasm: integer divide by zero", wasm_trap_div_zero)
	mustPanic(t, "wasm: integer overflow", wasm_trap_int_overflow)
	mustPanic(t, "wasm: invalid conversion to integer", wasm_trap_invalid_conv)
}

// mustPanic calls f and asserts it panics with a message containing want.
func mustPanic(t *testing.T, want string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic %q but did not panic", want)
			return
		}
		got, ok := r.(string)
		if !ok {
			t.Errorf("panic value is not a string: %v", r)
			return
		}
		if got != want {
			t.Errorf("panic message: got %q, want %q", got, want)
		}
	}()
	f()
}

// ---- Opaque identity helpers ------------------------------------------------

func TestIdentityHelpers(t *testing.T) {
	if got := i32(42); got != 42 {
		t.Errorf("i32(42) = %d", got)
	}
	if got := i32(-1); got != -1 {
		t.Errorf("i32(-1) = %d", got)
	}
	if got := i64(math.MaxInt64); got != math.MaxInt64 {
		t.Errorf("i64 = %d", got)
	}
	if got := ui32(-1); got != math.MaxUint32 {
		t.Errorf("ui32(-1) = %d", got)
	}
	if got := ui64(-1); got != math.MaxUint64 {
		t.Errorf("ui64(-1) = %d", got)
	}
	if got := f32(1.5); got != 1.5 {
		t.Errorf("f32 = %v", got)
	}
	if got := f64(3.14); got != 3.14 {
		t.Errorf("f64 = %v", got)
	}
	if got := f32(float32(math.NaN())); !math.IsNaN(float64(got)) {
		t.Errorf("f32(NaN) should be NaN")
	}
}

// ---- Integer division -------------------------------------------------------

func TestI32DivS(t *testing.T) {
	cases := []struct {
		x, y int32
		want int32
	}{
		{10, 3, 3},
		{-10, 3, -3},
		{10, -3, -3},
		{-10, -3, 3},
		{math.MinInt32 + 1, -1, math.MaxInt32},
	}
	for _, c := range cases {
		if got := i32_div_s(c.x, c.y); got != c.want {
			t.Errorf("i32_div_s(%d, %d) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
	mustPanic(t, "wasm: integer overflow", func() { i32_div_s(math.MinInt32, -1) })
	mustPanic(t, "wasm: integer divide by zero", func() { i32_div_s(1, 0) })
}

func TestI64DivS(t *testing.T) {
	cases := []struct {
		x, y int64
		want int64
	}{
		{10, 3, 3},
		{-10, -5, 2},
		{math.MinInt64 + 1, -1, math.MaxInt64},
	}
	for _, c := range cases {
		if got := i64_div_s(c.x, c.y); got != c.want {
			t.Errorf("i64_div_s(%d, %d) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
	mustPanic(t, "wasm: integer overflow", func() { i64_div_s(math.MinInt64, -1) })
	mustPanic(t, "wasm: integer divide by zero", func() { i64_div_s(5, 0) })
}

func TestI32DivU(t *testing.T) {
	if got := i32_div_u(10, 3); got != 3 {
		t.Errorf("i32_div_u(10,3) = %d", got)
	}
	if got := i32_div_u(math.MaxUint32, 2); got != math.MaxUint32/2 {
		t.Errorf("i32_div_u MaxUint32/2 = %d", got)
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i32_div_u(1, 0) })
}

func TestI64DivU(t *testing.T) {
	if got := i64_div_u(100, 7); got != 14 {
		t.Errorf("i64_div_u(100,7) = %d", got)
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i64_div_u(1, 0) })
}

// ---- Integer remainder ------------------------------------------------------

func TestI32RemS(t *testing.T) {
	cases := []struct {
		x, y int32
		want int32
	}{
		{10, 3, 1},
		{-10, 3, -1},
		{math.MinInt32, -1, 0}, // wasm spec: does NOT trap
		{7, -3, 1},
	}
	for _, c := range cases {
		if got := i32_rem_s(c.x, c.y); got != c.want {
			t.Errorf("i32_rem_s(%d, %d) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i32_rem_s(1, 0) })
}

func TestI64RemS(t *testing.T) {
	cases := []struct {
		x, y int64
		want int64
	}{
		{10, 3, 1},
		{-10, 3, -1},
		{math.MinInt64, -1, 0}, // spec: does not trap
	}
	for _, c := range cases {
		if got := i64_rem_s(c.x, c.y); got != c.want {
			t.Errorf("i64_rem_s(%d, %d) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i64_rem_s(5, 0) })
}

func TestI32RemU(t *testing.T) {
	if got := i32_rem_u(10, 3); got != 1 {
		t.Errorf("i32_rem_u(10,3) = %d", got)
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i32_rem_u(1, 0) })
}

func TestI64RemU(t *testing.T) {
	if got := i64_rem_u(11, 4); got != 3 {
		t.Errorf("i64_rem_u(11,4) = %d", got)
	}
	mustPanic(t, "wasm: integer divide by zero", func() { i64_rem_u(1, 0) })
}

// ---- Stack helpers ----------------------------------------------------------

func TestSubg(t *testing.T) {
	var v int32 = 100
	got := subg(&v, 16)
	if got != 84 || v != 84 {
		t.Errorf("subg: got=%d v=%d, want 84", got, v)
	}
}

func TestSubg64(t *testing.T) {
	var v int64 = 1000
	got := subg64(&v, 32)
	if got != 968 || v != 968 {
		t.Errorf("subg64: got=%d v=%d, want 968", got, v)
	}
}

// ---- Shifts -----------------------------------------------------------------

func TestShifts32(t *testing.T) {
	// shl: 1 << 4 = 16
	if got := i32_shl(1, 4); got != 16 {
		t.Errorf("i32_shl(1,4) = %d", got)
	}
	// shift count masked to 31
	if got := i32_shl(1, 32); got != 1 {
		t.Errorf("i32_shl(1,32) = %d, want 1 (masked)", got)
	}
	// shr_s: arithmetic right shift
	if got := i32_shr_s(-8, 1); got != -4 {
		t.Errorf("i32_shr_s(-8,1) = %d", got)
	}
	// shr_u: logical right shift
	if got := i32_shr_u(-1, 1); got != int32(math.MaxUint32>>1) {
		t.Errorf("i32_shr_u(-1,1) = %d", got)
	}
}

func TestRotate32(t *testing.T) {
	// rotl by 1: 0x80000000 << 1 wraps to 1
	got := i32_rotl(int32(-2147483648), 1)
	if got != 1 {
		t.Errorf("i32_rotl(MinInt32,1) = %d, want 1", got)
	}
	// rotr by 1: 1 >> 1 wraps to 0x80000000
	got = i32_rotr(1, 1)
	if got != int32(-2147483648) {
		t.Errorf("i32_rotr(1,1) = %d", got)
	}
}

func TestShifts64(t *testing.T) {
	if got := i64_shl(1, 4); got != 16 {
		t.Errorf("i64_shl(1,4) = %d", got)
	}
	if got := i64_shl(1, 64); got != 1 {
		t.Errorf("i64_shl(1,64) = %d, want 1 (masked to 63)", got)
	}
	if got := i64_shr_s(-8, 1); got != -4 {
		t.Errorf("i64_shr_s(-8,1) = %d", got)
	}
	if got := i64_shr_u(-1, 1); got != int64(math.MaxUint64>>1) {
		t.Errorf("i64_shr_u(-1,1) = %d", got)
	}
}

func TestRotate64(t *testing.T) {
	got := i64_rotl(int64(math.MinInt64), 1)
	if got != 1 {
		t.Errorf("i64_rotl(MinInt64,1) = %d, want 1", got)
	}
	got = i64_rotr(1, 1)
	if got != math.MinInt64 {
		t.Errorf("i64_rotr(1,1) = %d", got)
	}
}

// ---- Float min/max ----------------------------------------------------------

func TestF32MinMax(t *testing.T) {
	nan := float32(math.NaN())

	// NaN propagation
	if got := f32_min(nan, 1.0); !math.IsNaN(float64(got)) {
		t.Errorf("f32_min(NaN,1) not NaN")
	}
	if got := f32_min(1.0, nan); !math.IsNaN(float64(got)) {
		t.Errorf("f32_min(1,NaN) not NaN")
	}
	if got := f32_max(nan, 1.0); !math.IsNaN(float64(got)) {
		t.Errorf("f32_max(NaN,1) not NaN")
	}
	if got := f32_max(1.0, nan); !math.IsNaN(float64(got)) {
		t.Errorf("f32_max(1,NaN) not NaN")
	}

	// Normal ordering
	if got := f32_min(2.0, 3.0); got != 2.0 {
		t.Errorf("f32_min(2,3) = %v", got)
	}
	if got := f32_min(3.0, 2.0); got != 2.0 {
		t.Errorf("f32_min(3,2) = %v", got)
	}
	if got := f32_max(2.0, 3.0); got != 3.0 {
		t.Errorf("f32_max(2,3) = %v", got)
	}
	if got := f32_max(3.0, 2.0); got != 3.0 {
		t.Errorf("f32_max(3,2) = %v", got)
	}

	// -0 vs +0: min prefers -0, max prefers +0
	negZero := float32(math.Copysign(0, -1))
	posZero := float32(0)
	if got := f32_min(posZero, negZero); !math.Signbit(float64(got)) {
		t.Errorf("f32_min(+0,-0) should be -0, got %v signbit=%v", got, math.Signbit(float64(got)))
	}
	if got := f32_min(negZero, posZero); !math.Signbit(float64(got)) {
		t.Errorf("f32_min(-0,+0) should be -0")
	}
	if got := f32_max(negZero, posZero); math.Signbit(float64(got)) {
		t.Errorf("f32_max(-0,+0) should be +0")
	}
	if got := f32_max(posZero, negZero); math.Signbit(float64(got)) {
		t.Errorf("f32_max(+0,-0) should be +0")
	}
}

func TestF64MinMax(t *testing.T) {
	nan := math.NaN()

	if got := f64_min(nan, 1.0); !math.IsNaN(got) {
		t.Errorf("f64_min(NaN,1) not NaN")
	}
	if got := f64_min(1.0, nan); !math.IsNaN(got) {
		t.Errorf("f64_min(1,NaN) not NaN")
	}
	if got := f64_max(nan, 1.0); !math.IsNaN(got) {
		t.Errorf("f64_max(NaN,1) not NaN")
	}
	if got := f64_max(1.0, nan); !math.IsNaN(got) {
		t.Errorf("f64_max(1,NaN) not NaN")
	}

	if got := f64_min(2.0, 3.0); got != 2.0 {
		t.Errorf("f64_min(2,3) = %v", got)
	}
	if got := f64_min(3.0, 2.0); got != 2.0 {
		t.Errorf("f64_min(3,2) = %v", got)
	}
	if got := f64_max(2.0, 3.0); got != 3.0 {
		t.Errorf("f64_max(2,3) = %v", got)
	}
	if got := f64_max(3.0, 2.0); got != 3.0 {
		t.Errorf("f64_max(3,2) = %v", got)
	}

	negZero := math.Copysign(0, -1)
	posZero := 0.0
	if got := f64_min(posZero, negZero); !math.Signbit(got) {
		t.Errorf("f64_min(+0,-0) should be -0")
	}
	if got := f64_min(negZero, posZero); !math.Signbit(got) {
		t.Errorf("f64_min(-0,+0) should be -0")
	}
	if got := f64_max(negZero, posZero); math.Signbit(got) {
		t.Errorf("f64_max(-0,+0) should be +0")
	}
	if got := f64_max(posZero, negZero); math.Signbit(got) {
		t.Errorf("f64_max(+0,-0) should be +0")
	}
}

// ---- Float abs/neg/copysign -------------------------------------------------

func TestF32AbsNegCopysign(t *testing.T) {
	if got := f32_abs(-3.5); got != 3.5 {
		t.Errorf("f32_abs(-3.5) = %v", got)
	}
	if got := f32_abs(3.5); got != 3.5 {
		t.Errorf("f32_abs(3.5) = %v", got)
	}
	// abs of NaN should still be NaN with cleared sign bit
	nan := float32(math.NaN())
	if got := f32_abs(nan); !math.IsNaN(float64(got)) {
		t.Errorf("f32_abs(NaN) not NaN")
	}

	if got := f32_neg(3.5); got != -3.5 {
		t.Errorf("f32_neg(3.5) = %v", got)
	}
	if got := f32_neg(-3.5); got != 3.5 {
		t.Errorf("f32_neg(-3.5) = %v", got)
	}

	if got := f32_copysign(3.5, -1.0); got != -3.5 {
		t.Errorf("f32_copysign(3.5,-1) = %v", got)
	}
	if got := f32_copysign(-3.5, 1.0); got != 3.5 {
		t.Errorf("f32_copysign(-3.5,1) = %v", got)
	}
}

func TestF64AbsNegCopysign(t *testing.T) {
	if got := f64_abs(-3.5); got != 3.5 {
		t.Errorf("f64_abs(-3.5) = %v", got)
	}
	if got := f64_abs(3.5); got != 3.5 {
		t.Errorf("f64_abs(3.5) = %v", got)
	}
	if got := f64_neg(3.5); got != -3.5 {
		t.Errorf("f64_neg(3.5) = %v", got)
	}
	if got := f64_neg(-3.5); got != 3.5 {
		t.Errorf("f64_neg(-3.5) = %v", got)
	}
	if got := f64_copysign(3.5, -1.0); got != -3.5 {
		t.Errorf("f64_copysign(3.5,-1) = %v", got)
	}
}

// ---- Float rounding ---------------------------------------------------------

func TestNearest(t *testing.T) {
	cases32 := []struct {
		in   float32
		want float32
	}{
		{0.5, 0},  // round to even
		{1.5, 2},  // round to even
		{2.5, 2},  // round to even
		{-0.5, 0}, // round to even
		{1.4, 1},
		{1.6, 2},
		{-1.5, -2}, // round to even
	}
	for _, c := range cases32 {
		if got := f32_nearest(c.in); got != c.want {
			t.Errorf("f32_nearest(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	cases64 := []struct {
		in   float64
		want float64
	}{
		{0.5, 0},
		{1.5, 2},
		{2.5, 2},
		{-1.5, -2},
	}
	for _, c := range cases64 {
		if got := f64_nearest(c.in); got != c.want {
			t.Errorf("f64_nearest(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ---- Float-to-int trapping --------------------------------------------------

func TestI32TruncF32S(t *testing.T) {
	if got := i32_trunc_f32_s(1.9); got != 1 {
		t.Errorf("i32_trunc_f32_s(1.9) = %d", got)
	}
	if got := i32_trunc_f32_s(-1.9); got != -1 {
		t.Errorf("i32_trunc_f32_s(-1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i32_trunc_f32_s(float32(math.NaN())) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f32_s(float32(math.Inf(1))) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f32_s(float32(math.Inf(-1))) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f32_s(2.15e9) })
}

func TestI32TruncF32U(t *testing.T) {
	if got := i32_trunc_f32_u(1.9); got != 1 {
		t.Errorf("i32_trunc_f32_u(1.9) = %d", got)
	}
	if got := i32_trunc_f32_u(0.0); got != 0 {
		t.Errorf("i32_trunc_f32_u(0) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i32_trunc_f32_u(float32(math.NaN())) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f32_u(float32(math.Inf(1))) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f32_u(-1.0) })
}

func TestI32TruncF64S(t *testing.T) {
	if got := i32_trunc_f64_s(1.9); got != 1 {
		t.Errorf("i32_trunc_f64_s(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i32_trunc_f64_s(math.NaN()) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f64_s(math.Inf(1)) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f64_s(2.2e9) })
	// Wasm-spec boundary: every f64 whose truncation lies in
	// [-2^31, 2^31) succeeds. f64s slightly below -2^31 (down to
	// -2^31 - 1.0 + ε) truncate to -2^31 and must succeed; the
	// strict lower bound is at -2147483649.0.
	if got := i32_trunc_f64_s(-2147483648.5); got != -2147483648 {
		t.Errorf("i32_trunc_f64_s(-2147483648.5) = %d, want -2147483648", got)
	}
	if got := i32_trunc_f64_s(-2147483648.9999); got != -2147483648 {
		t.Errorf("i32_trunc_f64_s(-2147483648.9999) = %d, want -2147483648", got)
	}
	if got := i32_trunc_f64_s(-2147483648.0); got != -2147483648 {
		t.Errorf("i32_trunc_f64_s(-2147483648.0) = %d, want -2147483648", got)
	}
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f64_s(-2147483649.0) })
}

func TestI32TruncF64U(t *testing.T) {
	if got := i32_trunc_f64_u(1.9); got != 1 {
		t.Errorf("i32_trunc_f64_u(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i32_trunc_f64_u(math.NaN()) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f64_u(math.Inf(1)) })
	mustPanic(t, "wasm: integer overflow", func() { i32_trunc_f64_u(-1.0) })
}

func TestI64TruncF32S(t *testing.T) {
	if got := i64_trunc_f32_s(1.9); got != 1 {
		t.Errorf("i64_trunc_f32_s(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i64_trunc_f32_s(float32(math.NaN())) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f32_s(float32(math.Inf(1))) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f32_s(float32(math.Inf(-1))) })
}

func TestI64TruncF32U(t *testing.T) {
	if got := i64_trunc_f32_u(1.9); got != 1 {
		t.Errorf("i64_trunc_f32_u(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i64_trunc_f32_u(float32(math.NaN())) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f32_u(float32(math.Inf(1))) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f32_u(-1.0) })
}

func TestI64TruncF64S(t *testing.T) {
	if got := i64_trunc_f64_s(1.9); got != 1 {
		t.Errorf("i64_trunc_f64_s(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i64_trunc_f64_s(math.NaN()) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f64_s(math.Inf(1)) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f64_s(math.Inf(-1)) })
}

func TestI64TruncF64U(t *testing.T) {
	if got := i64_trunc_f64_u(1.9); got != 1 {
		t.Errorf("i64_trunc_f64_u(1.9) = %d", got)
	}
	mustPanic(t, "wasm: invalid conversion to integer", func() { i64_trunc_f64_u(math.NaN()) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f64_u(math.Inf(1)) })
	mustPanic(t, "wasm: integer overflow", func() { i64_trunc_f64_u(-1.0) })
}

// ---- Float-to-int saturating -----------------------------------------------

func TestI32TruncSatF32S(t *testing.T) {
	if got := i32_trunc_sat_f32_s(float32(math.NaN())); got != 0 {
		t.Errorf("sat_f32_s(NaN) = %d", got)
	}
	if got := i32_trunc_sat_f32_s(float32(math.Inf(-1))); got != math.MinInt32 {
		t.Errorf("sat_f32_s(-Inf) = %d", got)
	}
	if got := i32_trunc_sat_f32_s(float32(math.Inf(1))); got != math.MaxInt32 {
		t.Errorf("sat_f32_s(+Inf) = %d", got)
	}
	if got := i32_trunc_sat_f32_s(1.9); got != 1 {
		t.Errorf("sat_f32_s(1.9) = %d", got)
	}
	// -2.2e9 < MinInt32 (-2147483648) so should saturate to MinInt32
	if got := i32_trunc_sat_f32_s(-2.2e9); got != math.MinInt32 {
		t.Errorf("sat_f32_s(-2.2e9) = %d", got)
	}
	if got := i32_trunc_sat_f32_s(2.2e9); got != math.MaxInt32 {
		t.Errorf("sat_f32_s(2.2e9) = %d", got)
	}
}

func TestI32TruncSatF32U(t *testing.T) {
	if got := i32_trunc_sat_f32_u(float32(math.NaN())); got != 0 {
		t.Errorf("sat_f32_u(NaN) = %d", got)
	}
	if got := i32_trunc_sat_f32_u(-1.0); got != 0 {
		t.Errorf("sat_f32_u(-1) = %d", got)
	}
	if got := i32_trunc_sat_f32_u(float32(math.Inf(1))); got != -1 {
		t.Errorf("sat_f32_u(+Inf) = %d", got)
	}
	if got := i32_trunc_sat_f32_u(1.9); got != 1 {
		t.Errorf("sat_f32_u(1.9) = %d", got)
	}
	if got := i32_trunc_sat_f32_u(5e9); got != -1 {
		t.Errorf("sat_f32_u(5e9) = %d", got)
	}
}

func TestI32TruncSatF64S(t *testing.T) {
	if got := i32_trunc_sat_f64_s(math.NaN()); got != 0 {
		t.Errorf("sat_f64_s(NaN) = %d", got)
	}
	if got := i32_trunc_sat_f64_s(math.Inf(-1)); got != math.MinInt32 {
		t.Errorf("sat_f64_s(-Inf) = %d", got)
	}
	if got := i32_trunc_sat_f64_s(math.Inf(1)); got != math.MaxInt32 {
		t.Errorf("sat_f64_s(+Inf) = %d", got)
	}
	if got := i32_trunc_sat_f64_s(1.9); got != 1 {
		t.Errorf("sat_f64_s(1.9) = %d", got)
	}
	if got := i32_trunc_sat_f64_s(-2.2e9); got != math.MinInt32 {
		t.Errorf("sat_f64_s(-2.2e9) = %d", got)
	}
	if got := i32_trunc_sat_f64_s(2.2e9); got != math.MaxInt32 {
		t.Errorf("sat_f64_s(2.2e9) = %d", got)
	}
}

func TestI32TruncSatF64U(t *testing.T) {
	if got := i32_trunc_sat_f64_u(math.NaN()); got != 0 {
		t.Errorf("sat_f64_u(NaN) = %d", got)
	}
	if got := i32_trunc_sat_f64_u(-1.0); got != 0 {
		t.Errorf("sat_f64_u(-1) = %d", got)
	}
	if got := i32_trunc_sat_f64_u(math.Inf(1)); got != -1 {
		t.Errorf("sat_f64_u(+Inf) = %d", got)
	}
	if got := i32_trunc_sat_f64_u(1.9); got != 1 {
		t.Errorf("sat_f64_u(1.9) = %d", got)
	}
	if got := i32_trunc_sat_f64_u(5e9); got != -1 {
		t.Errorf("sat_f64_u(5e9) = %d", got)
	}
}

func TestI64TruncSatF32S(t *testing.T) {
	if got := i64_trunc_sat_f32_s(float32(math.NaN())); got != 0 {
		t.Errorf("i64_sat_f32_s(NaN) = %d", got)
	}
	if got := i64_trunc_sat_f32_s(float32(math.Inf(-1))); got != math.MinInt64 {
		t.Errorf("i64_sat_f32_s(-Inf) = %d", got)
	}
	if got := i64_trunc_sat_f32_s(float32(math.Inf(1))); got != math.MaxInt64 {
		t.Errorf("i64_sat_f32_s(+Inf) = %d", got)
	}
	if got := i64_trunc_sat_f32_s(1.9); got != 1 {
		t.Errorf("i64_sat_f32_s(1.9) = %d", got)
	}
	// value exceeding int64 range
	if got := i64_trunc_sat_f32_s(1e19); got != math.MaxInt64 {
		t.Errorf("i64_sat_f32_s(1e19) = %d", got)
	}
}

func TestI64TruncSatF32U(t *testing.T) {
	if got := i64_trunc_sat_f32_u(float32(math.NaN())); got != 0 {
		t.Errorf("i64_sat_f32_u(NaN) = %d", got)
	}
	if got := i64_trunc_sat_f32_u(-1.0); got != 0 {
		t.Errorf("i64_sat_f32_u(-1) = %d", got)
	}
	if got := i64_trunc_sat_f32_u(float32(math.Inf(1))); got != -1 {
		t.Errorf("i64_sat_f32_u(+Inf) = %d", got)
	}
	if got := i64_trunc_sat_f32_u(1.9); got != 1 {
		t.Errorf("i64_sat_f32_u(1.9) = %d", got)
	}
	// exceeds uint64 max
	if got := i64_trunc_sat_f32_u(2e19); got != -1 {
		t.Errorf("i64_sat_f32_u(2e19) = %d", got)
	}
}

func TestI64TruncSatF64S(t *testing.T) {
	if got := i64_trunc_sat_f64_s(math.NaN()); got != 0 {
		t.Errorf("i64_sat_f64_s(NaN) = %d", got)
	}
	if got := i64_trunc_sat_f64_s(math.Inf(-1)); got != math.MinInt64 {
		t.Errorf("i64_sat_f64_s(-Inf) = %d", got)
	}
	if got := i64_trunc_sat_f64_s(math.Inf(1)); got != math.MaxInt64 {
		t.Errorf("i64_sat_f64_s(+Inf) = %d", got)
	}
	if got := i64_trunc_sat_f64_s(1.9); got != 1 {
		t.Errorf("i64_sat_f64_s(1.9) = %d", got)
	}
	if got := i64_trunc_sat_f64_s(1e19); got != math.MaxInt64 {
		t.Errorf("i64_sat_f64_s(1e19) = %d", got)
	}
	if got := i64_trunc_sat_f64_s(-1e19); got != math.MinInt64 {
		t.Errorf("i64_sat_f64_s(-1e19) = %d", got)
	}
}

func TestI64TruncSatF64U(t *testing.T) {
	if got := i64_trunc_sat_f64_u(math.NaN()); got != 0 {
		t.Errorf("i64_sat_f64_u(NaN) = %d", got)
	}
	if got := i64_trunc_sat_f64_u(-1.0); got != 0 {
		t.Errorf("i64_sat_f64_u(-1) = %d", got)
	}
	if got := i64_trunc_sat_f64_u(math.Inf(1)); got != -1 {
		t.Errorf("i64_sat_f64_u(+Inf) = %d", got)
	}
	if got := i64_trunc_sat_f64_u(1.9); got != 1 {
		t.Errorf("i64_sat_f64_u(1.9) = %d", got)
	}
	if got := i64_trunc_sat_f64_u(2e19); got != -1 {
		t.Errorf("i64_sat_f64_u(2e19) = %d", got)
	}
}

// ---- Raw memory load/store helpers -----------------------------------------

func TestLoadStore(t *testing.T) {
	buf := make([]byte, 16)

	store8(buf[0:], 0xAB)
	if got := load8(buf[0:]); got != 0xAB {
		t.Errorf("load8 = %#x", got)
	}

	store16(buf[0:], 0x1234)
	if got := load16(buf[0:]); got != 0x1234 {
		t.Errorf("load16 = %#x", got)
	}

	store32(buf[0:], 0xDEADBEEF)
	if got := load32(buf[0:]); got != 0xDEADBEEF {
		t.Errorf("load32 = %#x", got)
	}

	store64(buf[0:], 0x0102030405060708)
	if got := load64(buf[0:]); got != 0x0102030405060708 {
		t.Errorf("load64 = %#x", got)
	}
}

// ---- Module-aware memory helpers -------------------------------------------

func newMemModule(size int) *Module {
	return &Module{memory: make([]byte, size)}
}

func TestMLoad8(t *testing.T) {
	m := newMemModule(16)
	m.memory[5] = 0xFF // sign-extends to -1
	if got := mload8s(m, 5, 0); got != -1 {
		t.Errorf("mload8s = %d", got)
	}
	if got := mload8u(m, 5, 0); got != 255 {
		t.Errorf("mload8u = %d", got)
	}
	// with offset
	m.memory[7] = 0x80
	// int8(0x80) = -128; sign-extended to int32 = -128
	if got := mload8s(m, 5, 2); got != -128 {
		t.Errorf("mload8s offset = %d", got)
	}
	if got := mload8u(m, 5, 2); got != 128 {
		t.Errorf("mload8u offset = %d", got)
	}
}

func TestMLoad16(t *testing.T) {
	m := newMemModule(16)
	// store 0x8001 little-endian at offset 4
	m.memory[4] = 0x01
	m.memory[5] = 0x80
	// 0x8001 as int16 = -32767 (signed), as uint16 = 32769
	if got := mload16s(m, 4, 0); got != -32767 {
		t.Errorf("mload16s = %d, want -32767", got)
	}
	if got := mload16u(m, 4, 0); got != 32769 {
		t.Errorf("mload16u = %d, want 32769", got)
	}
}

func TestMLoad32(t *testing.T) {
	m := newMemModule(16)
	m.memory[0] = 0x01
	m.memory[1] = 0x02
	m.memory[2] = 0x03
	m.memory[3] = 0x04
	if got := mload32(m, 0, 0); got != 0x04030201 {
		t.Errorf("mload32 = %#x", got)
	}
}

func TestMLoad64(t *testing.T) {
	m := newMemModule(16)
	for i := 0; i < 8; i++ {
		m.memory[i] = byte(i + 1)
	}
	if got := mload64(m, 0, 0); got != 0x0807060504030201 {
		t.Errorf("mload64 = %#x", got)
	}
}

func TestMLoad64Variants(t *testing.T) {
	m := newMemModule(16)
	m.memory[0] = 0xFF
	m.memory[1] = 0x80
	m.memory[2] = 0x01
	m.memory[3] = 0x80

	// 8-bit variants
	if got := mload64_8s(m, 0, 0); got != -1 {
		t.Errorf("mload64_8s = %d", got)
	}
	if got := mload64_8u(m, 0, 0); got != 255 {
		t.Errorf("mload64_8u = %d", got)
	}

	// 16-bit variants at offset 0: bytes[0x01,0x80] little-endian = 0x8001 wait...
	// m.memory[0]=0xFF, m.memory[1]=0x80 => 0x80FF little-endian
	// int16(0x80FF) = -32513, uint16(0x80FF) = 33023
	if got := mload64_16s(m, 0, 0); got != -32513 {
		t.Errorf("mload64_16s = %d, want -32513", got)
	}
	if got := mload64_16u(m, 0, 0); got != 33023 {
		t.Errorf("mload64_16u = %d, want 33023", got)
	}

	// 32-bit variants at offset 0: read 4 bytes [0xFF, 0x80, 0x01, 0x80]
	got32s := mload64_32s(m, 0, 0)
	// Just check it is sign-extended consistently with mload32
	if got32s != int64(int32(mload32(m, 0, 0))) {
		t.Errorf("mload64_32s sign extension mismatch: %d", got32s)
	}
	got32u := mload64_32u(m, 0, 0)
	if got32u != int64(uint32(mload32(m, 0, 0))) {
		t.Errorf("mload64_32u zero extension mismatch")
	}
}

func TestMLoadStoreFloat(t *testing.T) {
	m := newMemModule(16)

	mstoreF32(m, 0, 0, 3.14)
	if got := mloadF32(m, 0, 0); got != 3.14 {
		t.Errorf("mloadF32 = %v", got)
	}

	mstoreF64(m, 0, 0, 2.71828)
	if got := mloadF64(m, 0, 0); got != 2.71828 {
		t.Errorf("mloadF64 = %v", got)
	}
}

func TestMStore(t *testing.T) {
	m := newMemModule(16)

	mstore8(m, 0, 0, 0xAB)
	if m.memory[0] != 0xAB {
		t.Errorf("mstore8 byte = %#x", m.memory[0])
	}

	mstore8_64(m, 1, 0, 0xCD)
	if m.memory[1] != 0xCD {
		t.Errorf("mstore8_64 byte = %#x", m.memory[1])
	}

	mstore16(m, 0, 0, 0x1234)
	if got := load16(m.memory[0:]); got != 0x1234 {
		t.Errorf("mstore16 = %#x", got)
	}

	mstore16_64(m, 0, 0, 0x5678)
	if got := load16(m.memory[0:]); got != 0x5678 {
		t.Errorf("mstore16_64 = %#x", got)
	}

	mstore32(m, 0, 0, 0x12345678)
	if got := load32(m.memory[0:]); got != 0x12345678 {
		t.Errorf("mstore32 = %#x", got)
	}

	mstore32_64(m, 0, 0, 0xDEADBEEF)
	if got := load32(m.memory[0:]); got != 0xDEADBEEF {
		t.Errorf("mstore32_64 = %#x", got)
	}

	mstore64(m, 0, 0, 0x0102030405060708)
	if got := load64(m.memory[0:]); got != 0x0102030405060708 {
		t.Errorf("mstore64 = %#x", got)
	}
}

func TestMCopy(t *testing.T) {
	m := newMemModule(32)
	mstore32(m, 0, 0, int32(-559038737)) // 0xDEADBEEF reinterpreted as int32
	mcopy32(m, 0, 0, 16, 0)
	if got := mload32(m, 16, 0); got != int32(-559038737) {
		t.Errorf("mcopy32 = %#x", got)
	}

	mstore64(m, 0, 0, 0x0102030405060708)
	mcopy64(m, 0, 0, 16, 0)
	if got := mload64(m, 16, 0); got != 0x0102030405060708 {
		t.Errorf("mcopy64 = %#x", got)
	}
}

// ---- b32 --------------------------------------------------------------------

func TestB32(t *testing.T) {
	if got := b32(true); got != 1 {
		t.Errorf("b32(true) = %d", got)
	}
	if got := b32(false); got != 0 {
		t.Errorf("b32(false) = %d", got)
	}
}

// ---- memoryGrow with maxMem limit and reslice path -------------------------

func TestMemoryGrowMaxMem(t *testing.T) {
	// maxMem that allows geometric realloc capped at maxMem
	m := &Module{memory: make([]byte, 65536), maxMem: 4 * 65536}
	// grow 2 pages — cap doubles to 2*65536 but that's below maxMem
	if got := memoryGrow(m, 2); got != 1 {
		t.Errorf("grow 2 pages: prev=%d want 1", got)
	}
	if len(m.memory) != 3*65536 {
		t.Errorf("len=%d want %d", len(m.memory), 3*65536)
	}
	// grow past maxMem
	if got := memoryGrow(m, 5); got != -1 {
		t.Errorf("grow past maxMem: %d want -1", got)
	}
}

func TestMemoryGrowBeyond4GiB(t *testing.T) {
	// Simulate being at 4 GiB boundary — want>1<<32 triggers -1.
	// We can't actually allocate 4 GiB in a test; instead verify
	// the computation path via a module whose logical size would overflow.
	m := &Module{memory: make([]byte, 65536)}
	// n pages such that want > 1<<32: e.g. (1<<32/65536)+1 = 65537 pages
	if got := memoryGrow(m, 65537); got != -1 {
		t.Errorf("grow 65537 pages: %d want -1", got)
	}
}

func TestMemoryGrowSpareCapacity(t *testing.T) {
	// Pre-allocate backing array larger than initial len so the first grow
	// takes the reslice (spare capacity) path.
	mem := make([]byte, 65536, 4*65536)
	m := &Module{memory: mem}
	prev := memoryGrow(m, 1)
	if prev != 1 {
		t.Errorf("prev pages = %d, want 1", prev)
	}
	if len(m.memory) != 2*65536 {
		t.Errorf("len = %d, want %d", len(m.memory), 2*65536)
	}
	if cap(m.memory) != 4*65536 {
		t.Errorf("cap changed: %d, want %d", cap(m.memory), 4*65536)
	}
}
