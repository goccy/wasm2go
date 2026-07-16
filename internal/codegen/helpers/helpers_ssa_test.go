package helpers

import (
	"math"
	"testing"
)

// TestMemorySize / TestMemoryGrow are covered indirectly by integration
// tests; here we just probe the signatures so they're reachable to
// staticcheck's `unused` linter and exercise the most basic shape.
func TestMemorySize(t *testing.T) {
	m := newTestModule(make([]byte, 65536))
	if got := memorySize(m); got != 1 {
		t.Errorf("memorySize=%d want 1", got)
	}
}

// TestUnsignedDivRemSignedAdapters covers the i*_div/rem_u_s wrappers
// the SSA emitter uses: signed-input / signed-output wrappers around
// the existing uint-arg helpers.
func TestUnsignedDivRemSignedAdapters(t *testing.T) {
	if got := i32_div_u_s(10, 3); got != 3 {
		t.Errorf("i32_div_u_s(10,3)=%d want 3", got)
	}
	// -1 as int32 = MaxUint32 as uint32.
	if got := i32_div_u_s(-1, 2); got != int32(math.MaxUint32/2) {
		t.Errorf("i32_div_u_s(-1,2)=%d want %d", got, int32(math.MaxUint32/2))
	}
	if got := i32_rem_u_s(10, 3); got != 1 {
		t.Errorf("i32_rem_u_s(10,3)=%d want 1", got)
	}
	if got := i64_div_u_s(100, 7); got != 14 {
		t.Errorf("i64_div_u_s(100,7)=%d", got)
	}
	if got := i64_rem_u_s(100, 7); got != 2 {
		t.Errorf("i64_rem_u_s(100,7)=%d", got)
	}
}

// TestFloatBinaryAdapters covers the f32/f64 arithmetic adapters used
// by the SSA emitter's uniform helper-call path.
func TestFloatBinaryAdapters(t *testing.T) {
	if got := f32_add(1, 2); got != 3 {
		t.Errorf("f32_add=%v", got)
	}
	if got := f32_sub(3, 1); got != 2 {
		t.Errorf("f32_sub=%v", got)
	}
	if got := f32_mul(2, 3); got != 6 {
		t.Errorf("f32_mul=%v", got)
	}
	if got := f32_div(6, 2); got != 3 {
		t.Errorf("f32_div=%v", got)
	}
	if got := f64_add(1, 2); got != 3 {
		t.Errorf("f64_add=%v", got)
	}
	if got := f64_sub(3, 1); got != 2 {
		t.Errorf("f64_sub=%v", got)
	}
	if got := f64_mul(2, 3); got != 6 {
		t.Errorf("f64_mul=%v", got)
	}
	if got := f64_div(6, 2); got != 3 {
		t.Errorf("f64_div=%v", got)
	}
}

func TestIntUnary(t *testing.T) {
	if got := i32_eqz(0); got != 1 {
		t.Errorf("i32_eqz(0)=%d", got)
	}
	if got := i32_eqz(7); got != 0 {
		t.Errorf("i32_eqz(7)=%d", got)
	}
	if got := i64_eqz(0); got != 1 {
		t.Errorf("i64_eqz(0)=%d", got)
	}
	if got := i64_eqz(7); got != 0 {
		t.Errorf("i64_eqz(7)=%d", got)
	}
	if got := i32_clz(0); got != 32 {
		t.Errorf("i32_clz(0)=%d", got)
	}
	if got := i32_clz(1); got != 31 {
		t.Errorf("i32_clz(1)=%d", got)
	}
	if got := i32_ctz(8); got != 3 {
		t.Errorf("i32_ctz(8)=%d", got)
	}
	if got := i32_popcnt(7); got != 3 {
		t.Errorf("i32_popcnt(7)=%d", got)
	}
	if got := i64_clz(0); got != 64 {
		t.Errorf("i64_clz(0)=%d", got)
	}
	if got := i64_ctz(8); got != 3 {
		t.Errorf("i64_ctz(8)=%d", got)
	}
	if got := i64_popcnt(7); got != 3 {
		t.Errorf("i64_popcnt(7)=%d", got)
	}
}

func TestFloatUnaryAdapters(t *testing.T) {
	if got := f32_ceil(1.2); got != 2 {
		t.Errorf("f32_ceil=%v", got)
	}
	if got := f64_ceil(1.2); got != 2 {
		t.Errorf("f64_ceil=%v", got)
	}
	if got := f32_floor(1.8); got != 1 {
		t.Errorf("f32_floor=%v", got)
	}
	if got := f64_floor(1.8); got != 1 {
		t.Errorf("f64_floor=%v", got)
	}
	if got := f32_trunc(1.8); got != 1 {
		t.Errorf("f32_trunc=%v", got)
	}
	if got := f64_trunc(-1.8); got != -1 {
		t.Errorf("f64_trunc=%v", got)
	}
	if got := f32_sqrt(4); got != 2 {
		t.Errorf("f32_sqrt=%v", got)
	}
	if got := f64_sqrt(9); got != 3 {
		t.Errorf("f64_sqrt=%v", got)
	}
}

func TestFloatCompares(t *testing.T) {
	cases := []struct {
		name string
		got  int32
		want int32
	}{
		{"f32_eq=", f32_eq(1, 1), 1},
		{"f32_ne=", f32_ne(1, 1), 0},
		{"f32_lt", f32_lt(1, 2), 1},
		{"f32_gt", f32_gt(2, 1), 1},
		{"f32_le", f32_le(1, 1), 1},
		{"f32_ge", f32_ge(1, 1), 1},
		{"f64_eq", f64_eq(1, 1), 1},
		{"f64_ne", f64_ne(1, 1), 0},
		{"f64_lt", f64_lt(1, 2), 1},
		{"f64_gt", f64_gt(2, 1), 1},
		{"f64_le", f64_le(1, 1), 1},
		{"f64_ge", f64_ge(1, 1), 1},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d want %d", c.name, c.got, c.want)
		}
	}
	// NaN comparisons all return 0 except f*_ne.
	nan32 := float32(math.NaN())
	if got := f32_eq(nan32, nan32); got != 0 {
		t.Errorf("f32_eq(NaN,NaN)=%d want 0", got)
	}
	if got := f32_ne(nan32, nan32); got != 1 {
		t.Errorf("f32_ne(NaN,NaN)=%d want 1", got)
	}
}

func TestConversions(t *testing.T) {
	if got := i32_wrap_i64(0x1_0000_0001); got != 1 {
		t.Errorf("i32_wrap_i64=%d", got)
	}
	if got := i64_extend_i32_s(-1); got != -1 {
		t.Errorf("i64_extend_i32_s=%d", got)
	}
	if got := i64_extend_i32_u(-1); got != int64(math.MaxUint32) {
		t.Errorf("i64_extend_i32_u=%d", got)
	}
	if got := f32_demote_f64(1.5); got != 1.5 {
		t.Errorf("f32_demote_f64=%v", got)
	}
	if got := f64_promote_f32(1.5); got != 1.5 {
		t.Errorf("f64_promote_f32=%v", got)
	}
	if got := f32_convert_i32_s(-3); got != -3 {
		t.Errorf("f32_convert_i32_s=%v", got)
	}
	if got := f32_convert_i32_u(-1); got != float32(math.MaxUint32) {
		t.Errorf("f32_convert_i32_u=%v", got)
	}
	if got := f32_convert_i64_s(-3); got != -3 {
		t.Errorf("f32_convert_i64_s=%v", got)
	}
	if got := f32_convert_i64_u(-1); got != float32(math.MaxUint64) {
		t.Errorf("f32_convert_i64_u=%v", got)
	}
	if got := f64_convert_i32_s(-3); got != -3 {
		t.Errorf("f64_convert_i32_s=%v", got)
	}
	if got := f64_convert_i32_u(-1); got != float64(math.MaxUint32) {
		t.Errorf("f64_convert_i32_u=%v", got)
	}
	if got := f64_convert_i64_s(-3); got != -3 {
		t.Errorf("f64_convert_i64_s=%v", got)
	}
	if got := f64_convert_i64_u(-1); got != float64(math.MaxUint64) {
		t.Errorf("f64_convert_i64_u=%v", got)
	}
}

func TestReinterpret(t *testing.T) {
	if got := i32_reinterpret_f32(1.5); got != int32(math.Float32bits(1.5)) {
		t.Errorf("i32_reinterpret_f32=%x", got)
	}
	if got := f32_reinterpret_i32(int32(math.Float32bits(1.5))); got != 1.5 {
		t.Errorf("f32_reinterpret_i32=%v", got)
	}
	if got := i64_reinterpret_f64(1.5); got != int64(math.Float64bits(1.5)) {
		t.Errorf("i64_reinterpret_f64=%x", got)
	}
	if got := f64_reinterpret_i64(int64(math.Float64bits(1.5))); got != 1.5 {
		t.Errorf("f64_reinterpret_i64=%v", got)
	}
}

func TestSignExtend(t *testing.T) {
	if got := i32_extend8_s(0xff); got != -1 {
		t.Errorf("i32_extend8_s(0xff)=%d", got)
	}
	if got := i32_extend16_s(0xffff); got != -1 {
		t.Errorf("i32_extend16_s(0xffff)=%d", got)
	}
	if got := i64_extend8_s(0xff); got != -1 {
		t.Errorf("i64_extend8_s(0xff)=%d", got)
	}
	if got := i64_extend16_s(0xffff); got != -1 {
		t.Errorf("i64_extend16_s(0xffff)=%d", got)
	}
	if got := i64_extend32_s(0xffffffff); got != -1 {
		t.Errorf("i64_extend32_s(0xffffffff)=%d", got)
	}
}

func TestMemoryCopyFill(t *testing.T) {
	m := newTestModule(make([]byte, 65536))
	memoryFill(m, 10, 0x42, 4)
	if got := m.memory[10:14]; got[0] != 0x42 || got[3] != 0x42 {
		t.Errorf("memoryFill: %v", got)
	}
	memoryCopy(m, 20, 10, 4)
	if got := m.memory[20:24]; got[0] != 0x42 || got[3] != 0x42 {
		t.Errorf("memoryCopy: %v", got)
	}
	// zero-length is a no-op
	memoryFill(m, 0, 0, 0)
	memoryCopy(m, 0, 0, 0)
	// out-of-bounds traps
	defer func() {
		if r := recover(); r == nil {
			t.Error("memoryFill out-of-bounds should panic")
		}
	}()
	memoryFill(m, int32(len(m.memory)-1), 0, 10)
}

func TestMemoryGrowEmpty(t *testing.T) {
	m := newTestModule(make([]byte, 0))
	if got := memoryGrow(m, 0); got != 0 {
		t.Errorf("memoryGrow(0) on empty=%d", got)
	}
	if got := memoryGrow(m, 1); got != 0 {
		t.Errorf("memoryGrow(+1)=%d", got)
	}
	if len(m.memory) != 65536 {
		t.Errorf("memory size after grow=%d", len(m.memory))
	}
	if got := memoryGrow(m, -1); got != -1 {
		t.Errorf("memoryGrow(-1) should fail")
	}
}
