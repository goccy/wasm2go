// Package pass collects SSA optimization passes that run between
// lowering and emission.
//
// Each pass is a func(*ssa.Func) that mutates the function in place.
// Passes must preserve well-formedness (every Value belongs to its
// Block, every Block has correct preds/succs); they may delete values
// only by setting Op to OpInvalid so other passes can detect and skip
// them — a separate compaction step rewrites the Values slice at the
// end.
package pass

import "github.com/goccy/wasm2go/internal/ssa"

// ConstProp folds constant expressions and propagates them to users.
// Currently handles the integer binary ops produced by the narrow
// lowering: add/sub/mul/and/or/xor/shl/shr/eq/ne/lt/le on 32- and 64-bit
// integers. Floating-point constants are left alone because IEEE-754
// rounding makes precomputed answers diverge subtly from runtime ones.
//
// Returns true if any value was changed; callers can rerun until a
// fixpoint is reached.
func ConstProp(f *ssa.Func) bool {
	changed := false
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if foldValue(v) {
				changed = true
			}
		}
	}
	return changed
}

// foldValue rewrites v in place if both of its arguments are known
// integer constants. Returns true on change.
func foldValue(v *ssa.Value) bool {
	if len(v.Args) != 2 {
		return false
	}
	a, b := v.Args[0], v.Args[1]
	if a == nil || b == nil {
		return false
	}
	aConst, aOK := intConst(a)
	bConst, bOK := intConst(b)
	if !aOK || !bOK {
		return false
	}
	// Evaluate at the bit width of the result.
	is32 := v.Type == ssa.TypeI32 || (v.Type == ssa.TypeBool && argIs32(v))
	var folded int64
	var foldedAsBool bool
	var producedBool bool
	switch v.Op {
	case ssa.OpAdd32, ssa.OpAdd64:
		folded = aConst + bConst
	case ssa.OpSub32, ssa.OpSub64:
		folded = aConst - bConst
	case ssa.OpMul32, ssa.OpMul64:
		folded = aConst * bConst
	case ssa.OpAnd32, ssa.OpAnd64:
		folded = aConst & bConst
	case ssa.OpOr32, ssa.OpOr64:
		folded = aConst | bConst
	case ssa.OpXor32, ssa.OpXor64:
		folded = aConst ^ bConst
	// Shift counts are taken mod-N (N = bit width) per the wasm
	// spec — `i32.shl(5, 33)` is `5 << (33 & 31) == 10`, not
	// `5 << 33` (which Go evaluates as 0 for the wide-shift case).
	// The runtime helpers already mask correctly; the SSA fold must
	// match so the optimized constant matches the unoptimized
	// runtime value bit-for-bit. Mask before folding so we never
	// feed an out-of-range shift to Go's `<<` / `>>`.
	case ssa.OpShl32:
		folded = int64(int32(aConst) << (uint32(bConst) & 31))
	case ssa.OpShl64:
		folded = aConst << (uint64(bConst) & 63)
	case ssa.OpShrS32:
		folded = int64(int32(aConst) >> (uint32(bConst) & 31))
	case ssa.OpShrS64:
		folded = aConst >> (uint64(bConst) & 63)
	case ssa.OpShrU32:
		folded = int64(uint32(aConst) >> (uint32(bConst) & 31))
	case ssa.OpShrU64:
		folded = int64(uint64(aConst) >> (uint64(bConst) & 63))
	case ssa.OpEq32, ssa.OpEq64:
		foldedAsBool = aConst == bConst
		producedBool = true
	case ssa.OpNe32, ssa.OpNe64:
		foldedAsBool = aConst != bConst
		producedBool = true
	case ssa.OpLtS32, ssa.OpLtS64:
		foldedAsBool = aConst < bConst
		producedBool = true
	case ssa.OpLeS32, ssa.OpLeS64:
		foldedAsBool = aConst <= bConst
		producedBool = true
	case ssa.OpLtU32:
		foldedAsBool = uint32(aConst) < uint32(bConst)
		producedBool = true
	case ssa.OpLeU32:
		foldedAsBool = uint32(aConst) <= uint32(bConst)
		producedBool = true
	case ssa.OpLtU64:
		foldedAsBool = uint64(aConst) < uint64(bConst)
		producedBool = true
	case ssa.OpLeU64:
		foldedAsBool = uint64(aConst) <= uint64(bConst)
		producedBool = true
	default:
		return false
	}

	// Truncate folded into the result width for integer ops, or coerce
	// the bool into an i32 0/1 for compare ops (matching wasm semantics).
	if producedBool {
		var n int64
		if foldedAsBool {
			n = 1
		}
		v.Op = ssa.OpConst32
		v.Type = ssa.TypeBool
		v.Args = nil
		v.AuxInt = n
		v.Aux = nil
		return true
	}
	if is32 {
		folded = int64(int32(folded))
		v.Op = ssa.OpConst32
		v.Type = ssa.TypeI32
	} else {
		v.Op = ssa.OpConst64
		v.Type = ssa.TypeI64
	}
	v.Args = nil
	v.AuxInt = folded
	v.Aux = nil
	return true
}

// intConst pulls the integer constant value out of a Value, or returns
// false if v is not a constant.
func intConst(v *ssa.Value) (int64, bool) {
	switch v.Op {
	case ssa.OpConst32:
		return int64(int32(v.AuxInt)), true
	case ssa.OpConst64:
		return v.AuxInt, true
	}
	return 0, false
}

// argIs32 returns true when the value's first argument has 32-bit width
// — used to decide the width of an integer comparison's folded result.
func argIs32(v *ssa.Value) bool {
	if len(v.Args) == 0 {
		return false
	}
	return v.Args[0].Type == ssa.TypeI32
}
