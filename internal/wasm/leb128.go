package wasm

import (
	"errors"
	"fmt"
	"io"
)

var (
	errLEB128Overflow  = errors.New("wasm: LEB128 integer overflow")
	errLEB128Truncated = errors.New("wasm: LEB128 integer truncated")
)

type byteReader interface {
	io.Reader
	io.ByteReader
}

func readU32(r io.ByteReader) (uint32, error) {
	v, err := readU64(r)
	if err != nil {
		return 0, err
	}
	if v > 0xffffffff {
		return 0, errLEB128Overflow
	}
	return uint32(v), nil
}

func readU64(r io.ByteReader) (uint64, error) {
	var result uint64
	var shift uint
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, errLEB128Truncated
			}
			return 0, err
		}
		if shift >= 64 {
			return 0, errLEB128Overflow
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			if i == 9 && b > 1 {
				return 0, errLEB128Overflow
			}
			return result, nil
		}
		shift += 7
	}
	return 0, errLEB128Overflow
}

func readS32(r io.ByteReader) (int32, error) {
	v, err := readS64Bits(r, 32)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

func readS64(r io.ByteReader) (int64, error) {
	return readS64Bits(r, 64)
}

// readS64Bits decodes a signed LEB128 of at most `bits` bits. The
// `bits` argument is the declared spec width (32 for an i32, 64 for
// an i64). Payload bits beyond bit (bits-1) must be a clean sign-
// extension of bit (bits-1) per "Integers: numerical formats" in the
// wasm binary spec; any other pattern is reported as overflow rather
// than silently truncated. The 10-byte iteration cap matches the
// maximum legal LEB128 length for a 64-bit value, so a malformed
// input can never loop us indefinitely.
//
// The bit-width validation must inspect the assembled `result` AFTER
// the current byte's 7-bit payload has been OR'd in, because the bit
// that determines the sign-extension (bit `bits-1`) may live inside
// the very byte we are about to validate. Checking before the OR
// rejects legitimate encodings such as `0xff 0xff 0xff 0xff 0x7f`
// (SLEB128 for -1 as i32) — bit 31 of the value is in this last byte.
func readS64Bits(r io.ByteReader, bits uint) (int64, error) {
	var result int64
	var shift uint
	var b byte
	for i := 0; i < 10; i++ {
		var err error
		b, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, errLEB128Truncated
			}
			return 0, err
		}
		// OR this byte's payload into the assembled result first so
		// the sign-extension check below sees the final value of bit
		// (bits-1).
		result |= int64(b&0x7f) << shift
		// Once we have at least one bit's worth of payload beyond bit
		// (bits-1) in this byte, every payload bit at-or-above bit
		// (bits-1) must equal the sign-extension of the assembled
		// value's high bit.
		if shift+7 > bits {
			// signByte = 0x00 for a non-negative value-so-far,
			// 0x7f for a negative one.
			signBit := (result >> (bits - 1)) & 1
			var signByte byte
			if signBit != 0 {
				signByte = 0x7f
			}
			// mask = bits in this byte's payload at-or-above bit
			// (bits-1) of the assembled value — those are the bits
			// that must equal the sign-extension of the value's
			// high bit. (Strictly: bit `bits-1` itself lies in this
			// byte at position `bits-1-shift` and lower-position
			// bits of the payload contribute to the value while
			// higher-position bits must be a clean sign extension.
			// The bit at position `bits-1-shift` belongs to the
			// value, so legalInThisByte is `bits-shift`.)
			legalInThisByte := uint(0)
			if shift < bits {
				legalInThisByte = bits - shift
			}
			mask := byte(0x7f) &^ byte((1<<legalInThisByte)-1)
			if b&mask != signByte&mask {
				return 0, errLEB128Overflow
			}
		}
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && (b&0x40) != 0 {
				result |= -1 << shift
			}
			return result, nil
		}
	}
	return 0, errLEB128Overflow
}

// readByteVecCap is the safety cap on raw byte-vector lengths read
// from a wasm input. Matches the parser-side maxSectionPayload —
// nothing in any single section payload can plausibly exceed it,
// but a malformed LEB128 could otherwise demand a multi-gigabyte
// allocation before io.ReadFull truncates.
const readByteVecCap = 1 << 28

func readByteVec(r byteReader) ([]byte, error) {
	n, err := readU32(r)
	if err != nil {
		return nil, err
	}
	if n > readByteVecCap {
		return nil, fmt.Errorf("wasm: byte vector length %d exceeds %d-byte safety cap", n, readByteVecCap)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readName(r byteReader) (string, error) {
	b, err := readByteVec(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
