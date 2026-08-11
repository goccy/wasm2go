package helpers

// Behavioral tests for the replace-lane family (asm front doors,
// their pure _scalar twins, and the pair forms), the f16 convert-
// store, the memory64 bulk-memory helpers, and the trap/exception
// entry points — none of which had in-package callers before.

import (
	"strings"
	"testing"
)

func TestReplaceLaneFamily(t *testing.T) {
	v := [2]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908}
	if got := simd_i8x16_replace_lane(v, 3, 0x7f); got[0]&0xff000000 != 0x7f000000 {
		t.Fatalf("i8x16 lane3 = %x", got)
	}
	if got := simd_i16x8_replace_lane(v, 1, 0x1234); (got[0]>>16)&0xffff != 0x1234 {
		t.Fatalf("i16x8 lane1 = %x", got)
	}
	if got := simd_i32x4_replace_lane(v, 2, 0x55aa55aa); uint32(got[1]) != 0x55aa55aa {
		t.Fatalf("i32x4 lane2 = %x", got)
	}
	if got := simd_i64x2_replace_lane(v, 1, 0x1122334455667788); got[1] != 0x1122334455667788 {
		t.Fatalf("i64x2 lane1 = %x", got)
	}
	if got := simd_f32x4_replace_lane(v, 0, 1.0); uint32(got[0]) != 0x3f800000 {
		t.Fatalf("f32x4 lane0 = %x", got)
	}
	if got := simd_f64x2_replace_lane(v, 0, 1.0); got[0] != 0x3ff0000000000000 {
		t.Fatalf("f64x2 lane0 = %x", got)
	}
	// Pair forms delegate to the same lane semantics.
	lo, hi := simd_p_i32x4_replace_lane(v[0], v[1], 0, -1)
	if uint32(lo) != 0xffffffff {
		t.Fatalf("p_i32x4 lane0 = %x %x", lo, hi)
	}
	lo, hi = simd_p_i8x16_replace_lane(v[0], v[1], 15, 0x7f)
	if hi>>56 != 0x7f {
		t.Fatalf("p_i8x16 lane15 = %x %x", lo, hi)
	}
	lo, hi = simd_p_i16x8_replace_lane(v[0], v[1], 0, 0x7fff)
	if lo&0xffff != 0x7fff {
		t.Fatalf("p_i16x8 lane0 = %x %x", lo, hi)
	}
	lo, hi = simd_p_i64x2_replace_lane(v[0], v[1], 0, 42)
	if lo != 42 {
		t.Fatalf("p_i64x2 lane0 = %x %x", lo, hi)
	}
	lo, _ = simd_p_f32x4_replace_lane(v[0], v[1], 0, 1.0)
	if uint32(lo) != 0x3f800000 {
		t.Fatalf("p_f32x4 lane0 = %x", lo)
	}
	lo, _ = simd_p_f64x2_replace_lane(v[0], v[1], 0, 1.0)
	if lo != 0x3ff0000000000000 {
		t.Fatalf("p_f64x2 lane0 = %x", lo)
	}
}

func TestF16CvtStore(t *testing.T) {
	m := memTestModule(t, 4096)
	// Four f32 lanes 1.0 -> f16 0x3c00 each, packed into 8 bytes.
	one := uint64(0x3f800000)
	v := [2]uint64{one | one<<32, one | one<<32}
	if rc := simd_v128_f16x4_cvt_store(m, 64, 0, v); rc != 0 {
		t.Fatalf("cvt_store rc=%d", rc)
	}
	for i := 0; i < 4; i++ {
		got := uint16(m.memory[64+2*i]) | uint16(m.memory[64+2*i+1])<<8
		if got != 0x3c00 {
			t.Fatalf("f16 lane %d = %#x, want 0x3c00", i, got)
		}
	}
	if rc := simd_p_v128_f16x4_cvt_store(m, 96, 0, v[0], v[1]); rc != 0 {
		t.Fatalf("pair cvt_store rc=%d", rc)
	}
	if rc := simd_m64_v128_f16x4_cvt_store(m, 128, 0, v); rc != 0 {
		t.Fatalf("m64 cvt_store rc=%d", rc)
	}
	if rc := simd_p_m64_v128_f16x4_cvt_store(m, 160, 0, v[0], v[1]); rc != 0 {
		t.Fatalf("m64 pair cvt_store rc=%d", rc)
	}
	// f16x4_cvt widens four packed f16 lanes (low 64 bits) to f32x4:
	// 0x3c00 (f16 1.0) in each lane -> 0x3f800000 per f32 lane.
	// Input rides in load16x4_u form: one f16 in the LOW half of each
	// 32-bit lane.
	h16 := uint64(0x00003c00_00003c00)
	lo, hi := simd_p_f16x4_cvt(h16, h16)
	if lo != 0x3f8000003f800000 || hi != 0x3f8000003f800000 {
		t.Fatalf("p_f16x4_cvt = %#x %#x", lo, hi)
	}
}

func TestMemory64Ops(t *testing.T) {
	m := memTestModule(t, 1<<17)
	if cap := mem64HardCap(); cap != 1<<48 {
		t.Fatalf("hard cap = %#x", cap)
	}
	if got := memorySize64(m); got != (1<<17)>>16 {
		t.Fatalf("size64 = %d", got)
	}
	memoryFill64(m, 100, 0xAB, 8)
	for i := 100; i < 108; i++ {
		if m.memory[i] != 0xAB {
			t.Fatalf("fill64 byte %d = %#x", i, m.memory[i])
		}
	}
	memoryCopy64(m, 200, 100, 8)
	if m.memory[207] != 0xAB {
		t.Fatalf("copy64 missed")
	}
	if ea := simdEA64(m, 40, 8, 16); ea != 48 {
		t.Fatalf("simdEA64 = %d", ea)
	}
}

func TestTrapAndExceptionEntryPoints(t *testing.T) {
	trap := func(name string, f func(), want string) {
		t.Helper()
		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("%s: expected panic", name)
			}
			if msg, ok := r.(string); ok && !strings.Contains(msg, want) {
				t.Fatalf("%s: panic %q, want substring %q", name, msg, want)
			}
		}()
		f()
	}
	trap("unreachable", wasm_trap_unreachable, "unreachable")
	trap("memcopy", wasm_trap_memcopy_oob, "out of bounds")
	// throw/catch round-trip.
	func() {
		defer func() {
			exc := wasm_catch(recover())
			if exc == nil || exc.Tag != 3 || len(exc.Vals) != 2 || exc.Vals[1] != 9 {
				t.Fatalf("catch = %+v", exc)
			}
		}()
		wasm_throw(3, 7, 9)
	}()
	// Foreign panic values must re-panic, not be swallowed.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("wasm_catch swallowed a foreign panic value")
			}
		}()
		wasm_catch("not an exception")
	}()
	if wasm_catch(nil) != nil {
		t.Fatalf("wasm_catch(nil) must be nil")
	}
}
