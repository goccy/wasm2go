package codegen

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestDecoderLEB covers the LEB128 readers: unsigned u32/u64 (incl.
// overflow) and signed sN over a range of bit widths.
func TestDecoderLEB(t *testing.T) {
	// u32: 624485 = 0xe5 0x8e 0x26 in unsigned LEB128.
	r := &instrReader{src: []byte{0xe5, 0x8e, 0x26}}
	if v, err := r.readU32(); err != nil || v != 624485 {
		t.Errorf("readU32=%d,%v want 624485", v, err)
	}
	// u32 overflow: a value > 0xffffffff must error.
	rov := &instrReader{src: []byte{0x80, 0x80, 0x80, 0x80, 0x10}}
	if _, err := rov.readU32(); err == nil {
		t.Error("readU32 should reject a value over 2^32")
	}
	// u64 overflow: 10+ continuation bytes.
	rbad := &instrReader{src: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}}
	if _, err := rbad.readU64(); err == nil {
		t.Error("readU64 should reject an over-long encoding")
	}
	// readByte EOF.
	empty := &instrReader{src: nil}
	if _, err := empty.readByte(); err == nil {
		t.Error("readByte on empty input should error")
	}
	if !empty.eof() {
		t.Error("eof() should be true for empty input")
	}
	// signed: -123456 in signed LEB128 = 0xc0 0xbb 0x78.
	rs := &instrReader{src: []byte{0xc0, 0xbb, 0x78}}
	if v, err := rs.readS64(); err != nil || v != -123456 {
		t.Errorf("readS64=%d,%v want -123456", v, err)
	}
	// small positive signed value.
	rs2 := &instrReader{src: []byte{0x02}}
	if v, err := rs2.readS32(); err != nil || v != 2 {
		t.Errorf("readS32=%d,%v want 2", v, err)
	}
	// small negative signed value (-1 = 0x7f).
	rs3 := &instrReader{src: []byte{0x7f}}
	if v, err := rs3.readS64(); err != nil || v != -1 {
		t.Errorf("readS64(0x7f)=%d,%v want -1", v, err)
	}
}

// TestDecoderFloats covers the fixed-width f32/f64 readers, including the
// truncated-input error paths.
func TestDecoderFloats(t *testing.T) {
	var f32 [4]byte
	binary.LittleEndian.PutUint32(f32[:], math.Float32bits(3.5))
	r := &instrReader{src: f32[:]}
	if v, err := r.readF32(); err != nil || v != 3.5 {
		t.Errorf("readF32=%v,%v want 3.5", v, err)
	}
	var f64 [8]byte
	binary.LittleEndian.PutUint64(f64[:], math.Float64bits(2.71828))
	r2 := &instrReader{src: f64[:]}
	if v, err := r2.readF64(); err != nil || v != 2.71828 {
		t.Errorf("readF64=%v,%v want 2.71828", v, err)
	}
	if _, err := (&instrReader{src: []byte{0, 0}}).readF32(); err == nil {
		t.Error("readF32 on truncated input should error")
	}
	if _, err := (&instrReader{src: []byte{0, 0, 0, 0}}).readF64(); err == nil {
		t.Error("readF64 on truncated input should error")
	}
}

// TestDecoderMemArgAndVec covers readMemArg and readVecU32.
func TestDecoderMemArgAndVec(t *testing.T) {
	// memarg: align=2, offset=16.
	r := &instrReader{src: []byte{0x02, 0x10}}
	align, offset, err := r.readMemArg()
	if err != nil || align != 2 || offset != 16 {
		t.Errorf("readMemArg=(%d,%d,%v) want (2,16,nil)", align, offset, err)
	}
	// vec of u32: count=3, then 10,20,30.
	rv := &instrReader{src: []byte{0x03, 0x0a, 0x14, 0x1e}}
	vec, err := rv.readVecU32()
	if err != nil || len(vec) != 3 || vec[0] != 10 || vec[2] != 30 {
		t.Errorf("readVecU32=%v,%v want [10 20 30]", vec, err)
	}
}

// TestGoEscapedBytes covers the Go-string-literal escaper used to inline
// data segments.
func TestGoEscapedBytes(t *testing.T) {
	got := goEscapedBytes([]byte("ab\n\t\"\\\x00\xff"))
	want := `"ab\n\t\"\\\x00\xff"`
	if got != want {
		t.Errorf("goEscapedBytes=%q want %q", got, want)
	}
	if goEscapedBytes(nil) != `""` {
		t.Errorf("goEscapedBytes(nil)=%q want \"\"", goEscapedBytes(nil))
	}
}
