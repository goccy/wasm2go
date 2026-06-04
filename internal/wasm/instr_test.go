package wasm

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestInstrReaderLEB covers the LEB128 readers: unsigned u32/u64
// (incl. overflow) and signed sN over a range of bit widths.
func TestInstrReaderLEB(t *testing.T) {
	// u32: 624485 = 0xe5 0x8e 0x26 in unsigned LEB128.
	r := NewInstrReader([]byte{0xe5, 0x8e, 0x26})
	if v, err := r.ReadU32(); err != nil || v != 624485 {
		t.Errorf("ReadU32=%d,%v want 624485", v, err)
	}
	// u32 overflow: a value > 0xffffffff must error.
	rov := NewInstrReader([]byte{0x80, 0x80, 0x80, 0x80, 0x10})
	if _, err := rov.ReadU32(); err == nil {
		t.Error("ReadU32 should reject a value over 2^32")
	}
	// u64 overflow: 10+ continuation bytes.
	rbad := NewInstrReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01})
	if _, err := rbad.ReadU64(); err == nil {
		t.Error("ReadU64 should reject an over-long encoding")
	}
	// ReadByte EOF.
	empty := NewInstrReader(nil)
	if _, err := empty.ReadByte(); err == nil {
		t.Error("ReadByte on empty input should error")
	}
	if !empty.EOF() {
		t.Error("EOF() should be true for empty input")
	}
	// signed: -123456 in signed LEB128 = 0xc0 0xbb 0x78.
	rs := NewInstrReader([]byte{0xc0, 0xbb, 0x78})
	if v, err := rs.ReadS64(); err != nil || v != -123456 {
		t.Errorf("ReadS64=%d,%v want -123456", v, err)
	}
	// small positive signed value.
	rs2 := NewInstrReader([]byte{0x02})
	if v, err := rs2.ReadS32(); err != nil || v != 2 {
		t.Errorf("ReadS32=%d,%v want 2", v, err)
	}
	// small negative signed value (-1 = 0x7f).
	rs3 := NewInstrReader([]byte{0x7f})
	if v, err := rs3.ReadS64(); err != nil || v != -1 {
		t.Errorf("ReadS64(0x7f)=%d,%v want -1", v, err)
	}
}

// TestInstrReaderFloats covers the fixed-width f32/f64 readers,
// including the truncated-input error paths.
func TestInstrReaderFloats(t *testing.T) {
	var f32 [4]byte
	binary.LittleEndian.PutUint32(f32[:], math.Float32bits(3.5))
	r := NewInstrReader(f32[:])
	if v, err := r.ReadF32(); err != nil || v != 3.5 {
		t.Errorf("ReadF32=%v,%v want 3.5", v, err)
	}
	var f64 [8]byte
	binary.LittleEndian.PutUint64(f64[:], math.Float64bits(2.71828))
	r2 := NewInstrReader(f64[:])
	if v, err := r2.ReadF64(); err != nil || v != 2.71828 {
		t.Errorf("ReadF64=%v,%v want 2.71828", v, err)
	}
	if _, err := NewInstrReader([]byte{0, 0}).ReadF32(); err == nil {
		t.Error("ReadF32 on truncated input should error")
	}
	if _, err := NewInstrReader([]byte{0, 0, 0, 0}).ReadF64(); err == nil {
		t.Error("ReadF64 on truncated input should error")
	}
}

// TestInstrReaderMemArgAndVec covers ReadMemArg and ReadVecU32.
func TestInstrReaderMemArgAndVec(t *testing.T) {
	// memarg: align=2, offset=16.
	r := NewInstrReader([]byte{0x02, 0x10})
	align, offset, err := r.ReadMemArg()
	if err != nil || align != 2 || offset != 16 {
		t.Errorf("ReadMemArg=(%d,%d,%v) want (2,16,nil)", align, offset, err)
	}
	// vec of u32: count=3, then 10,20,30.
	rv := NewInstrReader([]byte{0x03, 0x0a, 0x14, 0x1e})
	vec, err := rv.ReadVecU32()
	if err != nil || len(vec) != 3 || vec[0] != 10 || vec[2] != 30 {
		t.Errorf("ReadVecU32=%v,%v want [10 20 30]", vec, err)
	}
}
