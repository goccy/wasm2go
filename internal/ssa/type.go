package ssa

// Type is the static type of a Value. Mirrors the wasm value types plus
// SSA-specific tokens for memory state and multi-result returns.
type Type uint8

const (
	TypeInvalid Type = iota
	TypeI32          // wasm i32
	TypeI64          // wasm i64
	TypeF32          // wasm f32
	TypeF64          // wasm f64
	TypeMem          // memory state token (threading load/store dependencies)
	TypeBool         // boolean (only result of comparison ops; lowers to i32 at emit time)
	TypeTuple        // multi-value return from a call; accessed via OpSelect{0,1,...}
)

// String renders the canonical short type name used in IR dumps.
func (t Type) String() string {
	switch t {
	case TypeInvalid:
		return "<invalid>"
	case TypeI32:
		return "i32"
	case TypeI64:
		return "i64"
	case TypeF32:
		return "f32"
	case TypeF64:
		return "f64"
	case TypeMem:
		return "mem"
	case TypeBool:
		return "bool"
	case TypeTuple:
		return "tuple"
	}
	return "<?>"
}

// IsInt reports whether t is an integer scalar (i32 or i64).
func (t Type) IsInt() bool { return t == TypeI32 || t == TypeI64 }

// IsFloat reports whether t is a floating-point scalar.
func (t Type) IsFloat() bool { return t == TypeF32 || t == TypeF64 }

// Bits returns the bit width of a scalar type, or 0 for non-scalars.
func (t Type) Bits() int {
	switch t {
	case TypeI32, TypeF32:
		return 32
	case TypeI64, TypeF64:
		return 64
	case TypeBool:
		return 1
	}
	return 0
}
