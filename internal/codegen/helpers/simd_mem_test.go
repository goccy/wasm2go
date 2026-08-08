package helpers

// Behavioral tests for the SIMD memory helpers and their pair-form
// wrappers. In generated output these are called by name (extracted
// into the bundle, or spliced away entirely by the gcasm backend), so
// nothing in this package references them statically — these tests are
// both their in-package callers and their semantic specification:
// little-endian lane layout over the [2]uint64 carrier, u32+u32
// effective addresses evaluated in 64 bits, and a trap (panic) for any
// access past memSize.

import (
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// memTestModule builds a Module over n bytes of linear memory filled
// with a deterministic byte pattern.
func memTestModule(t *testing.T, n int) *Module {
	t.Helper()
	m := &Module{
		memory:  make([]byte, n),
		memMu:   &sync.Mutex{},
		memSize: &atomic.Uint64{},
	}
	for i := range m.memory {
		m.memory[i] = byte(i*7 + 3)
	}
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	m.memSize.Store(uint64(n))
	return m
}

// wantV128 reads 16 bytes at ea from the module's memory as the
// little-endian [2]uint64 carrier.
func wantV128(m *Module, ea int) [2]uint64 {
	return [2]uint64{
		binary.LittleEndian.Uint64(m.memory[ea:]),
		binary.LittleEndian.Uint64(m.memory[ea+8:]),
	}
}

// mustTrap runs f and requires the SIMD out-of-bounds panic.
func mustTrap(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("%s: expected an out-of-bounds trap", name)
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "out of bounds") {
			t.Fatalf("%s: trapped with %v, want the v128 out-of-bounds message", name, r)
		}
	}()
	f()
}

func TestSimdV128LoadStore(t *testing.T) {
	m := memTestModule(t, 4096)
	got := simd_v128_load(m, 100, 28)
	if want := wantV128(m, 128); got != want {
		t.Fatalf("load = %x, want %x", got, want)
	}
	v := [2]uint64{0x1122334455667788, 0x99aabbccddeeff00}
	if rc := simd_v128_store(m, 256, 0, v); rc != 0 {
		t.Fatalf("store rc = %d", rc)
	}
	if got := wantV128(m, 256); got != v {
		t.Fatalf("store roundtrip = %x, want %x", got, v)
	}
	// The effective address is a 64-bit sum of two u32 values: a
	// negative addr must wrap to a huge u32, not go negative.
	mustTrap(t, "load u32 wrap", func() { simd_v128_load(m, -16, 0) })
	mustTrap(t, "load end", func() { simd_v128_load(m, 4096-15, 0) })
	mustTrap(t, "store end", func() { simd_v128_store(m, 4081, 0, v) })
	if got := simd_v128_load(m, 4096-16, 0); got != wantV128(m, 4080) {
		t.Fatalf("last in-bounds load = %x", got)
	}
}

func TestSimdV128LoadRngAndNc(t *testing.T) {
	m := memTestModule(t, 4096)
	// The rng form checks [addr+rlo, addr+rlo+span) and loads at
	// addr+offset; the nc form checks nothing (sound only behind a
	// covering rng — the tests keep every nc access inside one).
	if got, want := simd_v128_load_rng(m, 64, 16, 0, 64), wantV128(m, 80); got != want {
		t.Fatalf("load_rng = %x, want %x", got, want)
	}
	if got, want := simd_v128_load_nc(m, 64, 48), wantV128(m, 112); got != want {
		t.Fatalf("load_nc = %x, want %x", got, want)
	}
	// A negative rlo rebases the window below addr.
	if got, want := simd_v128_load_rng(m, 128, 0, -64, 80), wantV128(m, 128); got != want {
		t.Fatalf("load_rng negative rlo = %x, want %x", got, want)
	}
	mustTrap(t, "rng window end", func() { simd_v128_load_rng(m, 4000, 0, 0, 128) })
	// A wrapped member's unwrapped window has a negative start.
	mustTrap(t, "rng negative start", func() { simd_v128_load_rng(m, 8, 0, -32, 64) })
}

func TestSimdExtendingLoads(t *testing.T) {
	m := memTestModule(t, 256)
	base := 32
	bytes := m.memory[base : base+8]
	cases := []struct {
		name string
		got  [2]uint64
		want func() [2]uint64
	}{
		{"8x8_s", simd_v128_load8x8_s(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 8; i++ {
				out[i/4] |= uint64(uint16(int16(int8(bytes[i])))) << (16 * uint(i) % 64)
			}
			return out
		}},
		{"8x8_u", simd_v128_load8x8_u(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 8; i++ {
				out[i/4] |= uint64(bytes[i]) << (16 * uint(i) % 64)
			}
			return out
		}},
		{"16x4_s", simd_v128_load16x4_s(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 4; i++ {
				x := binary.LittleEndian.Uint16(bytes[2*i:])
				out[i/2] |= uint64(uint32(int32(int16(x)))) << (32 * uint(i) % 64)
			}
			return out
		}},
		{"16x4_u", simd_v128_load16x4_u(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 4; i++ {
				out[i/2] |= uint64(binary.LittleEndian.Uint16(bytes[2*i:])) << (32 * uint(i) % 64)
			}
			return out
		}},
		{"32x2_s", simd_v128_load32x2_s(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 2; i++ {
				x := binary.LittleEndian.Uint32(bytes[4*i:])
				out[i] = uint64(int64(int32(x)))
			}
			return out
		}},
		{"32x2_u", simd_v128_load32x2_u(m, int32(base), 0), func() [2]uint64 {
			var out [2]uint64
			for i := 0; i < 2; i++ {
				out[i] = uint64(binary.LittleEndian.Uint32(bytes[4*i:]))
			}
			return out
		}},
	}
	for _, c := range cases {
		if want := c.want(); c.got != want {
			t.Errorf("load%s = %x, want %x", c.name, c.got, want)
		}
	}
}

func TestSimdSplatAndZeroLoads(t *testing.T) {
	m := memTestModule(t, 256)
	base := 40
	b8 := uint64(m.memory[base])
	b16 := uint64(binary.LittleEndian.Uint16(m.memory[base:]))
	b32 := uint64(binary.LittleEndian.Uint32(m.memory[base:]))
	b64 := binary.LittleEndian.Uint64(m.memory[base:])
	splat8 := b8 * 0x0101010101010101
	splat16 := b16 * 0x0001000100010001
	splat32 := b32<<32 | b32
	if got := simd_v128_load8_splat(m, int32(base), 0); got != [2]uint64{splat8, splat8} {
		t.Errorf("load8_splat = %x", got)
	}
	if got := simd_v128_load16_splat(m, int32(base), 0); got != [2]uint64{splat16, splat16} {
		t.Errorf("load16_splat = %x", got)
	}
	if got := simd_v128_load32_splat(m, int32(base), 0); got != [2]uint64{splat32, splat32} {
		t.Errorf("load32_splat = %x", got)
	}
	if got := simd_v128_load64_splat(m, int32(base), 0); got != [2]uint64{b64, b64} {
		t.Errorf("load64_splat = %x", got)
	}
	if got := simd_v128_load32_zero(m, int32(base), 0); got != [2]uint64{b32, 0} {
		t.Errorf("load32_zero = %x", got)
	}
	if got := simd_v128_load64_zero(m, int32(base), 0); got != [2]uint64{b64, 0} {
		t.Errorf("load64_zero = %x", got)
	}
}

func TestSimdLaneLoadsAndStores(t *testing.T) {
	m := memTestModule(t, 256)
	v := [2]uint64{0x0f0e0d0c0b0a0908, 0x1716151413121110}
	base := 64

	got := simd_v128_load8_lane(m, int32(base), 0, 5, v)
	want := v
	want[0] = want[0]&^(uint64(0xff)<<40) | uint64(m.memory[base])<<40
	if got != want {
		t.Errorf("load8_lane = %x, want %x", got, want)
	}
	got = simd_v128_load16_lane(m, int32(base), 0, 6, v)
	want = v
	x16 := uint64(binary.LittleEndian.Uint16(m.memory[base:]))
	want[1] = want[1]&^(uint64(0xffff)<<32) | x16<<32
	if got != want {
		t.Errorf("load16_lane = %x, want %x", got, want)
	}
	got = simd_v128_load32_lane(m, int32(base), 0, 1, v)
	want = v
	x32 := uint64(binary.LittleEndian.Uint32(m.memory[base:]))
	want[0] = want[0]&^(uint64(0xffffffff)<<32) | x32<<32
	if got != want {
		t.Errorf("load32_lane = %x, want %x", got, want)
	}
	got = simd_v128_load64_lane(m, int32(base), 0, 1, v)
	want = v
	want[1] = binary.LittleEndian.Uint64(m.memory[base:])
	if got != want {
		t.Errorf("load64_lane = %x, want %x", got, want)
	}

	if rc := simd_v128_store8_lane(m, 128, 0, 3, v); rc != 0 || m.memory[128] != byte(v[0]>>24) {
		t.Errorf("store8_lane wrote %x", m.memory[128])
	}
	if rc := simd_v128_store16_lane(m, 130, 0, 5, v); rc != 0 ||
		binary.LittleEndian.Uint16(m.memory[130:]) != uint16(v[1]>>16) {
		t.Errorf("store16_lane wrote %x", m.memory[130:132])
	}
	if rc := simd_v128_store32_lane(m, 132, 0, 2, v); rc != 0 ||
		binary.LittleEndian.Uint32(m.memory[132:]) != uint32(v[1]) {
		t.Errorf("store32_lane wrote %x", m.memory[132:136])
	}
	if rc := simd_v128_store64_lane(m, 136, 0, 0, v); rc != 0 ||
		binary.LittleEndian.Uint64(m.memory[136:]) != v[0] {
		t.Errorf("store64_lane wrote %x", m.memory[136:144])
	}
	mustTrap(t, "lane load oob", func() { simd_v128_load8_lane(m, 256, 0, 0, v) })
}

// TestSimdPairMemWrappers pins every pair-form wrapper to its
// array-form helper: same module state, same arguments, halves equal.
func TestSimdPairMemWrappers(t *testing.T) {
	m := memTestModule(t, 512)
	v := [2]uint64{0xdeadbeefcafef00d, 0x0123456789abcdef}
	checkPair := func(name string, lo, hi uint64, want [2]uint64) {
		t.Helper()
		if lo != want[0] || hi != want[1] {
			t.Errorf("%s = (%x, %x), want %x", name, lo, hi, want)
		}
	}
	lo, hi := simd_p_v128_load(m, 32, 0)
	checkPair("p_load", lo, hi, simd_v128_load(m, 32, 0))
	lo, hi = simd_p_v128_load_rng(m, 32, 16, 0, 48)
	checkPair("p_load_rng", lo, hi, simd_v128_load_rng(m, 32, 16, 0, 48))
	lo, hi = simd_p_v128_load_nc(m, 32, 16)
	checkPair("p_load_nc", lo, hi, simd_v128_load_nc(m, 32, 16))
	lo, hi = simd_p_v128_load8x8_s(m, 32, 0)
	checkPair("p_load8x8_s", lo, hi, simd_v128_load8x8_s(m, 32, 0))
	lo, hi = simd_p_v128_load8x8_u(m, 32, 0)
	checkPair("p_load8x8_u", lo, hi, simd_v128_load8x8_u(m, 32, 0))
	lo, hi = simd_p_v128_load16x4_s(m, 32, 0)
	checkPair("p_load16x4_s", lo, hi, simd_v128_load16x4_s(m, 32, 0))
	lo, hi = simd_p_v128_load16x4_u(m, 32, 0)
	checkPair("p_load16x4_u", lo, hi, simd_v128_load16x4_u(m, 32, 0))
	lo, hi = simd_p_v128_load32x2_s(m, 32, 0)
	checkPair("p_load32x2_s", lo, hi, simd_v128_load32x2_s(m, 32, 0))
	lo, hi = simd_p_v128_load32x2_u(m, 32, 0)
	checkPair("p_load32x2_u", lo, hi, simd_v128_load32x2_u(m, 32, 0))
	lo, hi = simd_p_v128_load8_splat(m, 32, 0)
	checkPair("p_load8_splat", lo, hi, simd_v128_load8_splat(m, 32, 0))
	lo, hi = simd_p_v128_load16_splat(m, 32, 0)
	checkPair("p_load16_splat", lo, hi, simd_v128_load16_splat(m, 32, 0))
	lo, hi = simd_p_v128_load32_splat(m, 32, 0)
	checkPair("p_load32_splat", lo, hi, simd_v128_load32_splat(m, 32, 0))
	lo, hi = simd_p_v128_load64_splat(m, 32, 0)
	checkPair("p_load64_splat", lo, hi, simd_v128_load64_splat(m, 32, 0))
	lo, hi = simd_p_v128_load32_zero(m, 32, 0)
	checkPair("p_load32_zero", lo, hi, simd_v128_load32_zero(m, 32, 0))
	lo, hi = simd_p_v128_load64_zero(m, 32, 0)
	checkPair("p_load64_zero", lo, hi, simd_v128_load64_zero(m, 32, 0))
	lo, hi = simd_p_v128_load8_lane(m, 32, 0, 3, v[0], v[1])
	checkPair("p_load8_lane", lo, hi, simd_v128_load8_lane(m, 32, 0, 3, v))
	lo, hi = simd_p_v128_load16_lane(m, 32, 0, 3, v[0], v[1])
	checkPair("p_load16_lane", lo, hi, simd_v128_load16_lane(m, 32, 0, 3, v))
	lo, hi = simd_p_v128_load32_lane(m, 32, 0, 3, v[0], v[1])
	checkPair("p_load32_lane", lo, hi, simd_v128_load32_lane(m, 32, 0, 3, v))
	lo, hi = simd_p_v128_load64_lane(m, 32, 0, 1, v[0], v[1])
	checkPair("p_load64_lane", lo, hi, simd_v128_load64_lane(m, 32, 0, 1, v))

	if rc := simd_p_v128_store(m, 200, 0, v[0], v[1]); rc != 0 || wantV128(m, 200) != v {
		t.Errorf("p_store roundtrip = %x", wantV128(m, 200))
	}
	if rc := simd_p_v128_store8_lane(m, 220, 0, 1, v[0], v[1]); rc != 0 || m.memory[220] != byte(v[0]>>8) {
		t.Errorf("p_store8_lane wrote %x", m.memory[220])
	}
	if rc := simd_p_v128_store16_lane(m, 222, 0, 1, v[0], v[1]); rc != 0 ||
		binary.LittleEndian.Uint16(m.memory[222:]) != uint16(v[0]>>16) {
		t.Errorf("p_store16_lane wrote %x", m.memory[222:224])
	}
	if rc := simd_p_v128_store32_lane(m, 224, 0, 1, v[0], v[1]); rc != 0 ||
		binary.LittleEndian.Uint32(m.memory[224:]) != uint32(v[0]>>32) {
		t.Errorf("p_store32_lane wrote %x", m.memory[224:228])
	}
	if rc := simd_p_v128_store64_lane(m, 228, 0, 1, v[0], v[1]); rc != 0 ||
		binary.LittleEndian.Uint64(m.memory[228:]) != v[1] {
		t.Errorf("p_store64_lane wrote %x", m.memory[228:236])
	}
	if got := simd_p_pack(v[0], v[1]); got != v {
		t.Errorf("p_pack = %x", got)
	}
}

// TestGcasmMemProbe pins the probe's contract: it returns exactly the
// fields whose offsets the gcasm memory splices extract from its
// captured assembly.
func TestGcasmMemProbe(t *testing.T) {
	m := memTestModule(t, 64)
	p, sz := gcasmMemProbe(m)
	if p != m.M || sz != m.memSize {
		t.Fatal("gcasmMemProbe must return m.M and m.memSize, in that order")
	}
}
