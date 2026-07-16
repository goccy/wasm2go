package ssa

// Op identifies the kind of an SSA Value. The set here is deliberately
// kept smaller than the wasm opcode space — many semantically-similar
// wasm ops (e.g. i32.lt_s vs i32.lt_u) become a single SSA op + a flag
// in AuxInt, and the lowering pass picks the right Go output for each.
//
// Roughly grouped:
//
//   - OpInvalid, OpCopy, OpPhi: bookkeeping
//   - OpConst*, OpParam: source-of-value ops with no Args (or only Mem)
//   - Op{Add,Sub,Mul,...}{32,64,F32,F64}: scalar arithmetic
//   - OpLoad*, OpStore*: memory ops; each carries a Mem arg
//   - OpCallDirect, OpCallIndirect, OpCallImport: cross-function dispatch
//   - OpLocalGet/Set, OpGlobalGet/Set: pre-SSAification accessors; the
//     lowering pass eliminates OpLocal* via Braun et al.'s lookup. OpGlobal*
//     stay because globals are observable across function calls.
//
// Adding a new op: update both String() and the property accessors below.
type Op uint16

const (
	OpInvalid Op = iota

	// --- Bookkeeping ---
	OpCopy  // identity; v = arg[0]. Used by phi elimination.
	OpPhi   // phi(args[0]=pred0, args[1]=pred1, ...)
	OpParam // function parameter. AuxInt = parameter index.

	// --- Constants ---
	OpConst32  // AuxInt holds the i32 value (sign-extended)
	OpConst64  // AuxInt holds the i64 value
	OpConstF32 // Aux holds float32 (boxed). AuxInt = math.Float32bits.
	OpConstF64 // Aux holds float64 (boxed). AuxInt = math.Float64bits.

	// --- Integer arithmetic ---
	OpAdd32
	OpAdd64
	OpSub32
	OpSub64
	OpMul32
	OpMul64
	OpDivS32 // signed division (may trap on div-by-zero / overflow)
	OpDivS64
	OpDivU32
	OpDivU64
	OpRemS32
	OpRemS64
	OpRemU32
	OpRemU64
	OpAnd32
	OpAnd64
	OpOr32
	OpOr64
	OpXor32
	OpXor64
	OpShl32
	OpShl64
	OpShrS32
	OpShrS64
	OpShrU32
	OpShrU64

	// --- Integer comparisons (result type: TypeBool) ---
	OpEq32
	OpEq64
	OpNe32
	OpNe64
	OpLtS32
	OpLtS64
	OpLtU32
	OpLtU64
	OpLeS32
	OpLeS64
	OpLeU32
	OpLeU64

	// --- Float arithmetic ---
	OpAddF32
	OpAddF64
	OpSubF32
	OpSubF64
	OpMulF32
	OpMulF64
	OpDivF32
	OpDivF64

	// --- Conversions ---
	OpExtend32To64S
	OpExtend32To64U
	OpTrunc64To32

	// --- Memory ---
	// Layout for OpLoad*: args = [base i32, mem]. AuxInt = constant
	// offset added to base. Result is the loaded value.
	OpLoad8U
	OpLoad8S
	OpLoad16U
	OpLoad16S
	OpLoad32
	OpLoad32U // for i64.load32_u
	OpLoad32S
	OpLoad64
	OpLoadF32
	OpLoadF64
	// Layout for OpStore*: args = [base i32, value, mem]. AuxInt = offset.
	// Result type: Mem (a new memory state).
	OpStore8
	OpStore16
	OpStore32
	OpStore64
	OpStoreF32
	OpStoreF64

	// --- Globals ---
	OpGlobalGet // AuxInt = global index. Result is the global's type.
	OpGlobalSet // AuxInt = global index. args = [value]. Result type: Mem.

	// --- Local accessors (pre-SSAification) ---
	OpLocalGet // AuxInt = local index. Removed by SSA construction.
	OpLocalSet // AuxInt = local index. args = [value]. Removed by SSA construction.

	// --- Calls ---
	// OpCallDirect: Aux = callee name (string). args = [m, params..., mem].
	// Result type is the callee's result (TypeTuple if >1 result).
	OpCallDirect
	// OpCallIndirect: args = [m, table-index, params..., mem]. Aux = the
	// expected wasm type index for runtime check.
	OpCallIndirect
	// OpCallImport: Aux = (moduleName, methodName). args = [m, params..., mem].
	OpCallImport

	// --- Multi-result demultiplex ---
	// OpSelect projects element i of a tuple. AuxInt = i.
	OpSelect

	// --- Control auxiliary (rare) ---
	OpUnreachable

	// OpHelperCall delegates to a pre-existing pure helper from
	// internal/codegen/helpers/helpers.go. Aux is the helper's bare
	// name (string), Args are the helper's parameters in order, and
	// the value's Type is the helper's result type. Used by the
	// lowering pass to fan out wasm opcodes that have no first-class
	// SSA op (rotl, clz, abs, sqrt, conversions, ...) without
	// expanding the SSA Op enum for every wasm instruction.
	OpHelperCall

	// OpAtomicCall delegates to a MODULE-AWARE helper (emitted as
	// helper(m, args...)) implementing a threads-proposal atomic op:
	// loads/stores/RMWs/cmpxchg, memory.atomic.wait/notify, atomic.fence.
	// Aux is the helper name. Always side-effecting: atomics synchronize
	// with other agents, so they must never be DCE'd, CSE'd or reordered.
	OpAtomicCall

	// OpMemSize / OpMemGrow are the wasm linear-memory size queries.
	// OpMemSize takes (mem) and returns the current page count.
	// OpMemGrow takes (delta_pages, mem) and returns the previous page
	// count (or -1 on failure), with side-effect on the memory state.
	OpMemSize
	OpMemGrow

	// OpMemoryCopy / OpMemoryFill / OpMemoryInit / OpDataDrop are the
	// bulk-memory ops (wasm 0xfc prefix). OpMemoryCopy args =
	// [dst i32, src i32, n i32, mem]; OpMemoryFill args =
	// [dst i32, val i32, n i32, mem]; OpMemoryInit args =
	// [dst i32, src i32, n i32, mem] with AuxInt = data-segment index;
	// OpDataDrop args = [mem] with AuxInt = data-segment index.
	OpMemoryCopy
	OpMemoryFill
	OpMemoryInit
	OpDataDrop

	// OpCatchArg is the i-th operand of the exception caught by an
	// enclosing EH catch handler. AuxInt = operand index; the result type
	// is the operand's type. Emitted as a read of the recovered wasmExc's
	// i-th value. Impure (its value comes from the caught exception, not a
	// pure computation), so it must not be CSE'd or hoisted.
	OpCatchArg
)

// String renders the op name. Used by IR dumps and golden tests.
func (op Op) String() string {
	if int(op) >= len(opNames) {
		return "Op?"
	}
	return opNames[op]
}

// opNames is the source of truth for op-to-string. Update whenever ops
// are added/renamed.
var opNames = [...]string{
	OpInvalid: "OpInvalid",
	OpCopy:    "OpCopy",
	OpPhi:     "OpPhi",
	OpParam:   "OpParam",

	OpConst32:  "OpConst32",
	OpConst64:  "OpConst64",
	OpConstF32: "OpConstF32",
	OpConstF64: "OpConstF64",

	OpAdd32:  "OpAdd32",
	OpAdd64:  "OpAdd64",
	OpSub32:  "OpSub32",
	OpSub64:  "OpSub64",
	OpMul32:  "OpMul32",
	OpMul64:  "OpMul64",
	OpDivS32: "OpDivS32",
	OpDivS64: "OpDivS64",
	OpDivU32: "OpDivU32",
	OpDivU64: "OpDivU64",
	OpRemS32: "OpRemS32",
	OpRemS64: "OpRemS64",
	OpRemU32: "OpRemU32",
	OpRemU64: "OpRemU64",
	OpAnd32:  "OpAnd32",
	OpAnd64:  "OpAnd64",
	OpOr32:   "OpOr32",
	OpOr64:   "OpOr64",
	OpXor32:  "OpXor32",
	OpXor64:  "OpXor64",
	OpShl32:  "OpShl32",
	OpShl64:  "OpShl64",
	OpShrS32: "OpShrS32",
	OpShrS64: "OpShrS64",
	OpShrU32: "OpShrU32",
	OpShrU64: "OpShrU64",

	OpEq32:  "OpEq32",
	OpEq64:  "OpEq64",
	OpNe32:  "OpNe32",
	OpNe64:  "OpNe64",
	OpLtS32: "OpLtS32",
	OpLtS64: "OpLtS64",
	OpLtU32: "OpLtU32",
	OpLtU64: "OpLtU64",
	OpLeS32: "OpLeS32",
	OpLeS64: "OpLeS64",
	OpLeU32: "OpLeU32",
	OpLeU64: "OpLeU64",

	OpAddF32: "OpAddF32",
	OpAddF64: "OpAddF64",
	OpSubF32: "OpSubF32",
	OpSubF64: "OpSubF64",
	OpMulF32: "OpMulF32",
	OpMulF64: "OpMulF64",
	OpDivF32: "OpDivF32",
	OpDivF64: "OpDivF64",

	OpExtend32To64S: "OpExtend32To64S",
	OpExtend32To64U: "OpExtend32To64U",
	OpTrunc64To32:   "OpTrunc64To32",

	OpLoad8U:  "OpLoad8U",
	OpLoad8S:  "OpLoad8S",
	OpLoad16U: "OpLoad16U",
	OpLoad16S: "OpLoad16S",
	OpLoad32:  "OpLoad32",
	OpLoad32U: "OpLoad32U",
	OpLoad32S: "OpLoad32S",
	OpLoad64:  "OpLoad64",
	OpLoadF32: "OpLoadF32",
	OpLoadF64: "OpLoadF64",

	OpStore8:   "OpStore8",
	OpStore16:  "OpStore16",
	OpStore32:  "OpStore32",
	OpStore64:  "OpStore64",
	OpStoreF32: "OpStoreF32",
	OpStoreF64: "OpStoreF64",

	OpGlobalGet: "OpGlobalGet",
	OpGlobalSet: "OpGlobalSet",
	OpLocalGet:  "OpLocalGet",
	OpLocalSet:  "OpLocalSet",

	OpCallDirect:   "OpCallDirect",
	OpCallIndirect: "OpCallIndirect",
	OpCallImport:   "OpCallImport",

	OpSelect:      "OpSelect",
	OpUnreachable: "OpUnreachable",

	OpHelperCall: "OpHelperCall",
	OpAtomicCall: "OpAtomicCall",

	OpMemSize:    "OpMemSize",
	OpMemGrow:    "OpMemGrow",
	OpMemoryCopy: "OpMemoryCopy",
	OpMemoryFill: "OpMemoryFill",
	OpCatchArg:   "OpCatchArg",
	OpMemoryInit: "OpMemoryInit",
	OpDataDrop:   "OpDataDrop",
}

// IsConstant reports whether op produces a compile-time-known value.
// constprop uses this to fold expressions.
func (op Op) IsConstant() bool {
	switch op {
	case OpConst32, OpConst64, OpConstF32, OpConstF64:
		return true
	}
	return false
}

// IsCommutative reports whether the op's two args may be swapped without
// changing semantics. CSE relies on this to canonicalise hash keys.
func (op Op) IsCommutative() bool {
	switch op {
	case OpAdd32, OpAdd64, OpMul32, OpMul64,
		OpAnd32, OpAnd64, OpOr32, OpOr64, OpXor32, OpXor64,
		OpEq32, OpEq64, OpNe32, OpNe64,
		OpAddF32, OpAddF64, OpMulF32, OpMulF64:
		return true
	}
	return false
}

// UsesAuxInt reports whether the op's identity / behavior depends on its
// AuxInt field. Used by the IR dumper to decide whether to print [N]
// even when N happens to be zero (e.g. OpParam [0] is the first parameter
// and the [0] must be visible).
func (op Op) UsesAuxInt() bool {
	switch op {
	case OpConst32, OpConst64, OpConstF32, OpConstF64,
		OpParam,
		OpLoad8U, OpLoad8S, OpLoad16U, OpLoad16S, OpLoad32, OpLoad32U, OpLoad32S, OpLoad64, OpLoadF32, OpLoadF64,
		OpStore8, OpStore16, OpStore32, OpStore64, OpStoreF32, OpStoreF64,
		OpGlobalGet, OpGlobalSet,
		OpLocalGet, OpLocalSet,
		OpSelect,
		OpMemoryInit, OpDataDrop,
		OpCatchArg:
		return true
	}
	return false
}

// HasSideEffect reports whether the op cannot be DCE'd even with no users.
// True for stores, calls, traps, and any op that may trap at runtime.
//
// OpHelperCall is conservatively treated as side-effecting at the Op
// level because some helper bodies (i32_div_s, i32_trunc_f32_s, ...) trap
// on invalid inputs and must execute even when the result is unused. Use
// Value.HasSideEffect() at IR-walking sites that can consult the helper
// name in v.Aux and skip DCE/CSE only for known-pure helpers (clz,
// popcnt, sqrt, ...).
//
// The OpDivS*/OpDivU*/OpRemS*/OpRemU* family is intentionally absent: the
// current lowering routes integer division through OpHelperCall and never
// constructs those Op values. They remain in the Op enum so the public
// API is stable, but no live code depends on their side-effect status. If
// a future lowering adopts them, add the entries back here.
func (op Op) HasSideEffect() bool {
	switch op {
	case OpStore8, OpStore16, OpStore32, OpStore64, OpStoreF32, OpStoreF64,
		OpGlobalSet,
		OpLocalSet, // writes a mutable local var (EH mutable-locals mode)
		OpCallDirect, OpCallIndirect, OpCallImport,
		OpHelperCall, // may trap (div, rem, non-saturating trunc-to-int)
		OpAtomicCall, // synchronizes with other agents; never removable
		OpUnreachable,
		OpMemGrow, OpMemoryCopy, OpMemoryFill, OpMemoryInit, OpDataDrop:
		return true
	}
	return false
}

// HasSideEffect reports whether this specific value cannot be DCE'd /
// CSE'd. Identical to Op.HasSideEffect() for most ops; for OpHelperCall
// it consults the helper name in v.Aux so that known-pure helpers
// (clz, ctz, popcnt, rotl/rotr, abs, neg, ceil, floor, trunc, nearest,
// sqrt, copysign, min/max, eqz, comparisons, conversions including
// extends/reinterpret/wrap, saturating truncs, and float arithmetic)
// remain DCE- and CSE-eligible. Helpers that may trap (i32/i64 div_s/u,
// rem_s/u, non-saturating trunc_f32/f64_s/u) report true.
func (v *Value) HasSideEffect() bool {
	if v == nil {
		return false
	}
	if v.Op == OpAtomicCall {
		return true
	}
	if v.Op != OpHelperCall {
		return v.Op.HasSideEffect()
	}
	name, ok := v.Aux.(string)
	if !ok {
		// Missing/typed-wrong aux — be conservative.
		return true
	}
	return !pureHelperNames[name]
}

// pureHelperNames is the set of OpHelperCall targets that are known to
// be observationally pure: same inputs ⇒ same outputs, no trap, no
// memory or i/o effect. Helpers absent from this set (notably the
// integer-division and non-saturating-trunc-to-int families) may trap
// and must be preserved by DCE/CSE.
//
// Kept in sync with helperBinarySpec / helperUnarySpec in
// internal/codegen/lower.go and the helper bodies in
// internal/codegen/helpers/helpers.go.
var pureHelperNames = map[string]bool{
	// --- integer unary ---
	"i32_eqz":    true,
	"i64_eqz":    true,
	"i32_clz":    true,
	"i32_ctz":    true,
	"i32_popcnt": true,
	"i64_clz":    true,
	"i64_ctz":    true,
	"i64_popcnt": true,
	// --- integer binary (rotate) ---
	"i32_rotl": true,
	"i32_rotr": true,
	"i64_rotl": true,
	"i64_rotr": true,
	// --- float unary ---
	"f32_abs":     true,
	"f32_neg":     true,
	"f32_ceil":    true,
	"f32_floor":   true,
	"f32_trunc":   true,
	"f32_nearest": true,
	"f32_sqrt":    true,
	"f64_abs":     true,
	"f64_neg":     true,
	"f64_ceil":    true,
	"f64_floor":   true,
	"f64_trunc":   true,
	"f64_nearest": true,
	"f64_sqrt":    true,
	// --- float binary (arith / minmax / copysign / compare) ---
	"f32_add":      true,
	"f32_sub":      true,
	"f32_mul":      true,
	"f32_div":      true,
	"f32_min":      true,
	"f32_max":      true,
	"f32_copysign": true,
	"f64_add":      true,
	"f64_sub":      true,
	"f64_mul":      true,
	"f64_div":      true,
	"f64_min":      true,
	"f64_max":      true,
	"f64_copysign": true,
	"f32_eq":       true,
	"f32_ne":       true,
	"f32_lt":       true,
	"f32_gt":       true,
	"f32_le":       true,
	"f32_ge":       true,
	"f64_eq":       true,
	"f64_ne":       true,
	"f64_lt":       true,
	"f64_gt":       true,
	"f64_le":       true,
	"f64_ge":       true,
	// --- conversions (non-trapping) ---
	"i32_wrap_i64":        true,
	"i64_extend_i32_s":    true,
	"i64_extend_i32_u":    true,
	"f32_convert_i32_s":   true,
	"f32_convert_i32_u":   true,
	"f32_convert_i64_s":   true,
	"f32_convert_i64_u":   true,
	"f32_demote_f64":      true,
	"f64_convert_i32_s":   true,
	"f64_convert_i32_u":   true,
	"f64_convert_i64_s":   true,
	"f64_convert_i64_u":   true,
	"f64_promote_f32":     true,
	"i32_reinterpret_f32": true,
	"i64_reinterpret_f64": true,
	"f32_reinterpret_i32": true,
	"f64_reinterpret_i64": true,
	"i32_extend8_s":       true,
	"i32_extend16_s":      true,
	"i64_extend8_s":       true,
	"i64_extend16_s":      true,
	"i64_extend32_s":      true,
	"i32_trunc_sat_f32_s": true,
	"i32_trunc_sat_f32_u": true,
	"i32_trunc_sat_f64_s": true,
	"i32_trunc_sat_f64_u": true,
	"i64_trunc_sat_f32_s": true,
	"i64_trunc_sat_f32_u": true,
	"i64_trunc_sat_f64_s": true,
	"i64_trunc_sat_f64_u": true,
	// NOTE: trapping helpers intentionally omitted:
	//   i32_div_s, i32_div_u_s, i32_rem_s, i32_rem_u_s,
	//   i64_div_s, i64_div_u_s, i64_rem_s, i64_rem_u_s,
	//   i32_trunc_f32_s, i32_trunc_f32_u,
	//   i32_trunc_f64_s, i32_trunc_f64_u,
	//   i64_trunc_f32_s, i64_trunc_f32_u,
	//   i64_trunc_f64_s, i64_trunc_f64_u
}
