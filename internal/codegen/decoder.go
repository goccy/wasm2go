package codegen

import (
	"encoding/binary"
	"fmt"
	"math"
)

// instrReader is a stateful reader over a wasm function body.
type instrReader struct {
	src []byte
	pos int
}

func (r *instrReader) eof() bool { return r.pos >= len(r.src) }

func (r *instrReader) readByte() (byte, error) {
	if r.pos >= len(r.src) {
		return 0, fmt.Errorf("unexpected EOF in instruction stream")
	}
	b := r.src[r.pos]
	r.pos++
	return b, nil
}

func (r *instrReader) readU32() (uint32, error) {
	v, err := r.readU64()
	if err != nil {
		return 0, err
	}
	if v > 0xffffffff {
		return 0, fmt.Errorf("u32 overflow")
	}
	return uint32(v), nil
}

func (r *instrReader) readU64() (uint64, error) {
	var v uint64
	var s uint
	for i := 0; i < 10; i++ {
		b, err := r.readByte()
		if err != nil {
			return 0, err
		}
		v |= uint64(b&0x7f) << s
		if b&0x80 == 0 {
			return v, nil
		}
		s += 7
	}
	return 0, fmt.Errorf("u64 overflow")
}

func (r *instrReader) readS32() (int32, error) {
	v, err := r.readSN(32)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

func (r *instrReader) readS33() (int64, error) {
	return r.readSN(33)
}

func (r *instrReader) readS64() (int64, error) {
	return r.readSN(64)
}

func (r *instrReader) readSN(bits uint) (int64, error) {
	var v int64
	var s uint
	var b byte
	for {
		var err error
		b, err = r.readByte()
		if err != nil {
			return 0, err
		}
		v |= int64(b&0x7f) << s
		s += 7
		if b&0x80 == 0 {
			break
		}
		if s > bits+7 {
			return 0, fmt.Errorf("sN overflow")
		}
	}
	if s < 64 && (b&0x40) != 0 {
		v |= -1 << s
	}
	return v, nil
}

func (r *instrReader) readF32() (float32, error) {
	if r.pos+4 > len(r.src) {
		return 0, fmt.Errorf("unexpected EOF reading f32")
	}
	bits := binary.LittleEndian.Uint32(r.src[r.pos:])
	r.pos += 4
	return math.Float32frombits(bits), nil
}

func (r *instrReader) readF64() (float64, error) {
	if r.pos+8 > len(r.src) {
		return 0, fmt.Errorf("unexpected EOF reading f64")
	}
	bits := binary.LittleEndian.Uint64(r.src[r.pos:])
	r.pos += 8
	return math.Float64frombits(bits), nil
}

// readMemArg reads (align: u32, offset: u32). Both are unsigned LEB128.
func (r *instrReader) readMemArg() (align, offset uint32, err error) {
	align, err = r.readU32()
	if err != nil {
		return
	}
	offset, err = r.readU32()
	return
}

// readVecU32 reads a vec(u32).
func (r *instrReader) readVecU32() ([]uint32, error) {
	n, err := r.readU32()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := range out {
		v, err := r.readU32()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
