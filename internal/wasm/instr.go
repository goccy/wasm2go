package wasm

import (
	"encoding/binary"
	"fmt"
	"math"
)

// InstrReader is a stateful reader over a wasm function body's
// instruction stream. It is the per-instruction counterpart of the
// module-level Parser; downstream stages (SSA lowering, the
// multi-package call-graph scanner) consume the byte stream through
// the same primitives.
type InstrReader struct {
	src []byte
	pos int
}

// NewInstrReader returns a reader positioned at the start of src.
func NewInstrReader(src []byte) *InstrReader { return &InstrReader{src: src} }

// Pos returns the current byte offset.
func (r *InstrReader) Pos() int { return r.pos }

// Src returns the underlying instruction bytes. Useful for callers
// that want to extract a sub-slice (e.g. for nested-block recursion).
func (r *InstrReader) Src() []byte { return r.src }

// EOF reports whether the reader has consumed the entire stream.
func (r *InstrReader) EOF() bool { return r.pos >= len(r.src) }

// ReadByte consumes and returns one byte.
func (r *InstrReader) ReadByte() (byte, error) {
	if r.pos >= len(r.src) {
		return 0, fmt.Errorf("unexpected EOF in instruction stream")
	}
	b := r.src[r.pos]
	r.pos++
	return b, nil
}

// ReadU32 consumes an unsigned LEB128 and rejects values that don't
// fit in 32 bits.
func (r *InstrReader) ReadU32() (uint32, error) {
	v, err := r.ReadU64()
	if err != nil {
		return 0, err
	}
	if v > 0xffffffff {
		return 0, fmt.Errorf("u32 overflow")
	}
	return uint32(v), nil
}

// ReadU64 consumes an unsigned LEB128 up to 64 bits.
func (r *InstrReader) ReadU64() (uint64, error) {
	var v uint64
	var s uint
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
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

// ReadS32 consumes a signed LEB128 and rejects values that don't fit
// in 32 bits.
func (r *InstrReader) ReadS32() (int32, error) {
	v, err := r.ReadSN(32)
	if err != nil {
		return 0, err
	}
	return int32(v), nil
}

// ReadS33 consumes a signed LEB128 with up to 33 significant bits —
// used by block-type immediates.
func (r *InstrReader) ReadS33() (int64, error) {
	return r.ReadSN(33)
}

// ReadS64 consumes a signed LEB128 with up to 64 significant bits.
func (r *InstrReader) ReadS64() (int64, error) {
	return r.ReadSN(64)
}

// ReadSN consumes a signed LEB128 with the given bit-width cap.
func (r *InstrReader) ReadSN(bits uint) (int64, error) {
	var v int64
	var s uint
	var b byte
	for {
		var err error
		b, err = r.ReadByte()
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

// ReadF32 consumes four little-endian bytes as a float32.
func (r *InstrReader) ReadF32() (float32, error) {
	if r.pos+4 > len(r.src) {
		return 0, fmt.Errorf("unexpected EOF reading f32")
	}
	bits := binary.LittleEndian.Uint32(r.src[r.pos:])
	r.pos += 4
	return math.Float32frombits(bits), nil
}

// ReadF64 consumes eight little-endian bytes as a float64.
func (r *InstrReader) ReadF64() (float64, error) {
	if r.pos+8 > len(r.src) {
		return 0, fmt.Errorf("unexpected EOF reading f64")
	}
	bits := binary.LittleEndian.Uint64(r.src[r.pos:])
	r.pos += 8
	return math.Float64frombits(bits), nil
}

// ReadMemArg reads (align: u32, offset: u32). Both are unsigned LEB128.
func (r *InstrReader) ReadMemArg() (align, offset uint32, err error) {
	align, err = r.ReadU32()
	if err != nil {
		return
	}
	offset, err = r.ReadU32()
	return
}

// ReadVecU32 reads a vec(u32).
func (r *InstrReader) ReadVecU32() ([]uint32, error) {
	n, err := r.ReadU32()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := range out {
		v, err := r.ReadU32()
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// SkipImmediates advances r past the immediate operands of opcode op
// without doing any semantic decoding. Mirrors the instruction shapes
// the SSA lowering pass handles; opcodes whose immediate shape isn't
// modeled here return an error so callers stay in sync with the
// instruction set wasm2go actually emits. Silent fall-through used to
// drop real call edges (e.g. when an unknown opcode was followed by a
// `call` opcode value that SkipImmediates then misread as raw bytes).
func (r *InstrReader) SkipImmediates(op byte) error {
	// 0xfc-prefixed extended ops.
	if op == OpPrefixFC {
		sub, err := r.ReadU32()
		if err != nil {
			return err
		}
		switch sub {
		case 0, 1, 2, 3, 4, 5, 6, 7:
			// saturating-trunc family: no immediates.
			return nil
		case 8: // memory.init: dataIdx + reserved 0x00
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			if _, err := r.ReadByte(); err != nil {
				return err
			}
			return nil
		case 9: // data.drop: dataIdx
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			return nil
		case 10: // memory.copy: two reserved 0x00 bytes
			if _, err := r.ReadByte(); err != nil {
				return err
			}
			if _, err := r.ReadByte(); err != nil {
				return err
			}
			return nil
		case 11: // memory.fill: one reserved 0x00 byte
			if _, err := r.ReadByte(); err != nil {
				return err
			}
			return nil
		case 12: // table.init: elemIdx + tableIdx
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			return nil
		case 13: // elem.drop: elemIdx
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			return nil
		case 14: // table.copy: src tableIdx + dst tableIdx
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			return nil
		case 15, 16, 17: // table.grow / table.size / table.fill: tableIdx
			if _, err := r.ReadU32(); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("unsupported 0xFC subop %d", sub)
	}
	switch op {
	case OpBr, OpBrIf, OpLocalGet, OpLocalSet, OpLocalTee,
		OpGlobalGet, OpGlobalSet, OpCall:
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		return nil
	case OpRefFunc:
		// ref.func names a function whose address is taken; the call-
		// graph caller (scanDirectCalls) must read the index itself so
		// it can extend the live-function set with the target. Here we
		// only need to advance past the immediate.
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		return nil
	case OpRefNull:
		// reftype byte.
		if _, err := r.ReadByte(); err != nil {
			return err
		}
		return nil
	case OpCallIndirect:
		// type idx + table idx
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		return nil
	case OpBrTable:
		labels, err := r.ReadVecU32()
		if err != nil {
			return err
		}
		_ = labels
		if _, err := r.ReadU32(); err != nil { // default
			return err
		}
		return nil
	case OpBlock, OpLoop, OpIf:
		// blocktype: s33
		if _, err := r.ReadS33(); err != nil {
			return err
		}
		return nil
	case OpElse, OpEnd, OpReturn, OpUnreachable, OpNop, OpDrop, OpSelect:
		return nil
	case OpSelectT:
		// vec(valtype) — n + n bytes
		n, err := r.ReadU32()
		if err != nil {
			return err
		}
		for i := uint32(0); i < n; i++ {
			if _, err := r.ReadByte(); err != nil {
				return err
			}
		}
		return nil
	case OpMemSize, OpMemGrow:
		if _, err := r.ReadByte(); err != nil {
			return err
		}
		return nil
	case OpI32Const:
		if _, err := r.ReadS32(); err != nil {
			return err
		}
		return nil
	case OpI64Const:
		if _, err := r.ReadS64(); err != nil {
			return err
		}
		return nil
	case OpF32Const:
		if _, err := r.ReadF32(); err != nil {
			return err
		}
		return nil
	case OpF64Const:
		if _, err := r.ReadF64(); err != nil {
			return err
		}
		return nil
	}
	// Memory ops: align (u32) + offset (u32). Range covers 0x28..0x40
	// (loads, stores, memory.size, memory.grow). The MemSize/MemGrow
	// cases above handle 0x3f/0x40 explicitly with the single reserved
	// byte; the switch returns before we reach here for those opcodes.
	if op >= 0x28 && op <= 0x3e {
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		if _, err := r.ReadU32(); err != nil {
			return err
		}
		return nil
	}
	// Numeric ops have no immediates (they all read from the stack).
	if op >= 0x45 && op <= 0xC4 {
		return nil
	}
	return fmt.Errorf("unknown opcode 0x%02x", op)
}
