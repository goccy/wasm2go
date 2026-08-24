package codegen

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

func TestF16BitsToF32Bits(t *testing.T) {
	cases := []struct {
		h    uint16
		want uint32
	}{
		{0x0000, 0x00000000}, // +0
		{0x8000, 0x80000000}, // -0
		{0x3C00, 0x3F800000}, // 1.0
		{0xBC00, 0xBF800000}, // -1.0
		{0x4000, 0x40000000}, // 2.0
		{0x3555, 0x3EAAA000}, // ~0.3333
		{0x7BFF, 0x477FE000}, // max normal 65504
		{0x0400, 0x38800000}, // min normal 2^-14
		{0x0001, 0x33800000}, // min subnormal 2^-24
		{0x03FF, 0x387FC000}, // max subnormal
		{0x7C00, 0x7F800000}, // +inf
		{0xFC00, 0xFF800000}, // -inf
		{0x7E00, 0x7FC00000}, // canonical qNaN
		{0x7E01, 0x7FC02000}, // qNaN payload rides along
		{0xFDFF, 0xFFBFE000}, // -sNaN, payload preserved
	}
	for _, c := range cases {
		if got := f16BitsToF32Bits(c.h); got != c.want {
			t.Errorf("f16 %#04x: got %#08x want %#08x", c.h, got, c.want)
		}
	}
	// Cross-check finite values against the float64 route: the binary16
	// value converts exactly to binary32, so going through float64 is
	// also exact for non-NaN inputs.
	for i := 0; i < 65536; i++ {
		h := uint16(i)
		exp := (h >> 10) & 0x1F
		if exp == 0x1F {
			continue // inf/NaN checked above
		}
		sign := float64(1)
		if h>>15 == 1 {
			sign = -1
		}
		var v float64
		if exp == 0 {
			v = sign * float64(h&0x3FF) * math.Pow(2, -24)
		} else {
			v = sign * (1 + float64(h&0x3FF)/1024) * math.Pow(2, float64(int(exp)-15))
		}
		if got := f16BitsToF32Bits(h); got != math.Float32bits(float32(v)) {
			t.Fatalf("f16 %#04x: got %#08x want %#08x", h, got, math.Float32bits(float32(v)))
		}
	}
}

// i32ConstExpr encodes an `i32.const v; end` const expression.
func i32ConstExpr(v int32) []byte {
	out := []byte{0x41}
	u := uint32(v)
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if (u == 0 && b&0x40 == 0) || (u == 0x1FFFFFF && b&0x40 != 0) {
			out = append(out, b)
			break
		}
		out = append(out, b|0x80)
	}
	return append(out, 0x0B)
}

func ieeeF16TableBytes() []byte {
	tab := make([]byte, 65536*4)
	for i := 0; i < 65536; i++ {
		binary.LittleEndian.PutUint32(tab[i*4:], f16BitsToF32Bits(uint16(i)))
	}
	return tab
}

func TestHasIEEEF16TableAt(t *testing.T) {
	const base = 4096
	tab := ieeeF16TableBytes()
	tr := &translator{mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Offset: i32ConstExpr(base), Bytes: tab},
	}}}
	if !tr.hasIEEEF16TableAt(base) {
		t.Fatal("exact IEEE table not accepted")
	}
	if tr.hasIEEEF16TableAt(base + 4) {
		t.Fatal("shifted base must not verify")
	}

	// One corrupted byte anywhere fails the comparison.
	bad := make([]byte, len(tab))
	copy(bad, tab)
	bad[100*4] ^= 1
	tr = &translator{mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Offset: i32ConstExpr(base), Bytes: bad},
	}}}
	if tr.hasIEEEF16TableAt(base) {
		t.Fatal("corrupted table accepted")
	}

	// Split across two segments: still verifies (the image assembles
	// from every active segment overlapping the range).
	half := len(tab) / 2
	tr = &translator{mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Offset: i32ConstExpr(base), Bytes: tab[:half]},
		{Offset: i32ConstExpr(base + int32(half)), Bytes: tab[half:]},
	}}}
	if !tr.hasIEEEF16TableAt(base) {
		t.Fatal("split IEEE table not accepted")
	}

	// Passive segments do not populate the initial image.
	tr = &translator{mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Passive: true, Bytes: tab},
	}}}
	if tr.hasIEEEF16TableAt(base) {
		t.Fatal("passive segment must not count")
	}

	// No coverage at all: reject without comparing.
	tr = &translator{mod: &wasm.Module{}}
	if tr.hasIEEEF16TableAt(base) {
		t.Fatal("empty module accepted")
	}
}

func TestF16TableOKCacheAndAssertion(t *testing.T) {
	const base = 8192
	tr := &translator{mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Offset: i32ConstExpr(base), Bytes: ieeeF16TableBytes()},
	}}}
	if !tr.f16TableOK(base) {
		t.Fatal("verified table rejected")
	}
	if !tr.f16TableOK(base) {
		t.Fatal("cached result flipped")
	}
	if tr.f16TableOK(base + 8) {
		t.Fatal("unverified base accepted")
	}

	// The opt-out switch turns verification off wholesale, even for a
	// statically present table.
	tr = &translator{opts: Options{DisableF16Table: true}, mod: &wasm.Module{Datas: []wasm.DataSegment{
		{Offset: i32ConstExpr(base), Bytes: ieeeF16TableBytes()},
	}}}
	if tr.f16TableOK(base) {
		t.Fatal("disabled verification still accepted a table")
	}
}

func TestUnverifiedF16GatherMsg(t *testing.T) {
	for _, tc := range []struct {
		disabled bool
		tables   map[uint32]bool
		warn     bool
	}{
		{false, nil, false},                            // no gather sites
		{false, map[uint32]bool{9013200: true}, false}, // everything verified
		{false, map[uint32]bool{4096: false}, true},    // unverified base: warn
		{true, map[uint32]bool{4096: false}, false},    // rewrites disabled: silent
		{false, map[uint32]bool{4096: false, 8192: true}, true},
	} {
		msg := unverifiedF16GatherMsg(tc.disabled, tc.tables)
		if got := msg != ""; got != tc.warn {
			t.Errorf("unverifiedF16GatherMsg(disabled=%v, %v): warn=%v, want %v (msg %q)", tc.disabled, tc.tables, got, tc.warn, msg)
		}
	}
	// The warning names the unverified bases.
	if msg := unverifiedF16GatherMsg(false, map[uint32]bool{4096: false}); !strings.Contains(msg, "4096") {
		t.Errorf("warning should list unverified bases: %q", msg)
	}
}
