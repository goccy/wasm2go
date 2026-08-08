package wasm

// WebAssembly MVP opcodes plus the 0xfc prefix.
// For the full list see https://webassembly.github.io/spec/core/binary/instructions.html
const (
	OpUnreachable byte = 0x00
	OpNop         byte = 0x01
	OpBlock       byte = 0x02
	OpLoop        byte = 0x03
	OpIf          byte = 0x04
	OpElse        byte = 0x05

	// Legacy exception-handling proposal (what clang/wasi-sdk emits for
	// setjmp/longjmp under `-mllvm -wasm-enable-sjlj`). try opens a handler
	// region with a blocktype; catch/catch_all begin handlers; throw raises a
	// tag; rethrow/delegate re-raise. These carry the setjmp/longjmp lowering.
	OpTry      byte = 0x06
	OpCatch    byte = 0x07
	OpThrow    byte = 0x08
	OpRethrow  byte = 0x09
	OpDelegate byte = 0x18
	OpCatchAll byte = 0x19

	OpEnd          byte = 0x0b
	OpBr           byte = 0x0c
	OpBrIf         byte = 0x0d
	OpBrTable      byte = 0x0e
	OpReturn       byte = 0x0f
	OpCall         byte = 0x10
	OpCallIndirect byte = 0x11

	OpDrop    byte = 0x1a
	OpSelect  byte = 0x1b
	OpSelectT byte = 0x1c

	OpLocalGet  byte = 0x20
	OpLocalSet  byte = 0x21
	OpLocalTee  byte = 0x22
	OpGlobalGet byte = 0x23
	OpGlobalSet byte = 0x24

	OpI32Load    byte = 0x28
	OpI64Load    byte = 0x29
	OpF32Load    byte = 0x2a
	OpF64Load    byte = 0x2b
	OpI32Load8S  byte = 0x2c
	OpI32Load8U  byte = 0x2d
	OpI32Load16S byte = 0x2e
	OpI32Load16U byte = 0x2f
	OpI64Load8S  byte = 0x30
	OpI64Load8U  byte = 0x31
	OpI64Load16S byte = 0x32
	OpI64Load16U byte = 0x33
	OpI64Load32S byte = 0x34
	OpI64Load32U byte = 0x35
	OpI32Store   byte = 0x36
	OpI64Store   byte = 0x37
	OpF32Store   byte = 0x38
	OpF64Store   byte = 0x39
	OpI32Store8  byte = 0x3a
	OpI32Store16 byte = 0x3b
	OpI64Store8  byte = 0x3c
	OpI64Store16 byte = 0x3d
	OpI64Store32 byte = 0x3e
	OpMemSize    byte = 0x3f
	OpMemGrow    byte = 0x40

	OpI32Const byte = 0x41
	OpI64Const byte = 0x42
	OpF32Const byte = 0x43
	OpF64Const byte = 0x44

	OpI32Eqz byte = 0x45
	OpI32Eq  byte = 0x46
	OpI32Ne  byte = 0x47
	OpI32LtS byte = 0x48
	OpI32LtU byte = 0x49
	OpI32GtS byte = 0x4a
	OpI32GtU byte = 0x4b
	OpI32LeS byte = 0x4c
	OpI32LeU byte = 0x4d
	OpI32GeS byte = 0x4e
	OpI32GeU byte = 0x4f
	OpI64Eqz byte = 0x50
	OpI64Eq  byte = 0x51
	OpI64Ne  byte = 0x52
	OpI64LtS byte = 0x53
	OpI64LtU byte = 0x54
	OpI64GtS byte = 0x55
	OpI64GtU byte = 0x56
	OpI64LeS byte = 0x57
	OpI64LeU byte = 0x58
	OpI64GeS byte = 0x59
	OpI64GeU byte = 0x5a
	OpF32Eq  byte = 0x5b
	OpF32Ne  byte = 0x5c
	OpF32Lt  byte = 0x5d
	OpF32Gt  byte = 0x5e
	OpF32Le  byte = 0x5f
	OpF32Ge  byte = 0x60
	OpF64Eq  byte = 0x61
	OpF64Ne  byte = 0x62
	OpF64Lt  byte = 0x63
	OpF64Gt  byte = 0x64
	OpF64Le  byte = 0x65
	OpF64Ge  byte = 0x66

	OpI32Clz    byte = 0x67
	OpI32Ctz    byte = 0x68
	OpI32Popcnt byte = 0x69
	OpI32Add    byte = 0x6a
	OpI32Sub    byte = 0x6b
	OpI32Mul    byte = 0x6c
	OpI32DivS   byte = 0x6d
	OpI32DivU   byte = 0x6e
	OpI32RemS   byte = 0x6f
	OpI32RemU   byte = 0x70
	OpI32And    byte = 0x71
	OpI32Or     byte = 0x72
	OpI32Xor    byte = 0x73
	OpI32Shl    byte = 0x74
	OpI32ShrS   byte = 0x75
	OpI32ShrU   byte = 0x76
	OpI32Rotl   byte = 0x77
	OpI32Rotr   byte = 0x78
	OpI64Clz    byte = 0x79
	OpI64Ctz    byte = 0x7a
	OpI64Popcnt byte = 0x7b
	OpI64Add    byte = 0x7c
	OpI64Sub    byte = 0x7d
	OpI64Mul    byte = 0x7e
	OpI64DivS   byte = 0x7f
	OpI64DivU   byte = 0x80
	OpI64RemS   byte = 0x81
	OpI64RemU   byte = 0x82
	OpI64And    byte = 0x83
	OpI64Or     byte = 0x84
	OpI64Xor    byte = 0x85
	OpI64Shl    byte = 0x86
	OpI64ShrS   byte = 0x87
	OpI64ShrU   byte = 0x88
	OpI64Rotl   byte = 0x89
	OpI64Rotr   byte = 0x8a

	OpF32Abs      byte = 0x8b
	OpF32Neg      byte = 0x8c
	OpF32Ceil     byte = 0x8d
	OpF32Floor    byte = 0x8e
	OpF32Trunc    byte = 0x8f
	OpF32Nearest  byte = 0x90
	OpF32Sqrt     byte = 0x91
	OpF32Add      byte = 0x92
	OpF32Sub      byte = 0x93
	OpF32Mul      byte = 0x94
	OpF32Div      byte = 0x95
	OpF32Min      byte = 0x96
	OpF32Max      byte = 0x97
	OpF32Copysign byte = 0x98
	OpF64Abs      byte = 0x99
	OpF64Neg      byte = 0x9a
	OpF64Ceil     byte = 0x9b
	OpF64Floor    byte = 0x9c
	OpF64Trunc    byte = 0x9d
	OpF64Nearest  byte = 0x9e
	OpF64Sqrt     byte = 0x9f
	OpF64Add      byte = 0xa0
	OpF64Sub      byte = 0xa1
	OpF64Mul      byte = 0xa2
	OpF64Div      byte = 0xa3
	OpF64Min      byte = 0xa4
	OpF64Max      byte = 0xa5
	OpF64Copysign byte = 0xa6

	OpI32WrapI64        byte = 0xa7
	OpI32TruncF32S      byte = 0xa8
	OpI32TruncF32U      byte = 0xa9
	OpI32TruncF64S      byte = 0xaa
	OpI32TruncF64U      byte = 0xab
	OpI64ExtendI32S     byte = 0xac
	OpI64ExtendI32U     byte = 0xad
	OpI64TruncF32S      byte = 0xae
	OpI64TruncF32U      byte = 0xaf
	OpI64TruncF64S      byte = 0xb0
	OpI64TruncF64U      byte = 0xb1
	OpF32ConvertI32S    byte = 0xb2
	OpF32ConvertI32U    byte = 0xb3
	OpF32ConvertI64S    byte = 0xb4
	OpF32ConvertI64U    byte = 0xb5
	OpF32DemoteF64      byte = 0xb6
	OpF64ConvertI32S    byte = 0xb7
	OpF64ConvertI32U    byte = 0xb8
	OpF64ConvertI64S    byte = 0xb9
	OpF64ConvertI64U    byte = 0xba
	OpF64PromoteF32     byte = 0xbb
	OpI32ReinterpretF32 byte = 0xbc
	OpI64ReinterpretF64 byte = 0xbd
	OpF32ReinterpretI32 byte = 0xbe
	OpF64ReinterpretI64 byte = 0xbf

	OpI32Extend8S  byte = 0xc0
	OpI32Extend16S byte = 0xc1
	OpI64Extend8S  byte = 0xc2
	OpI64Extend16S byte = 0xc3
	OpI64Extend32S byte = 0xc4

	// OpRefNull / OpRefFunc model reference-typed operands. wasm2go does not
	// implement reference types, but the multi-package call-graph scanner
	// recognises OpRefFunc as a function reference so it can record those
	// edges alongside direct OpCall edges.
	OpRefNull byte = 0xd0
	OpRefFunc byte = 0xd2

	OpPrefixFC byte = 0xfc // saturating-trunc, bulk-memory
	OpPrefixFD byte = 0xfd // SIMD proposal: v128 ops
	OpPrefixFE byte = 0xfe // threads proposal: atomics
)
