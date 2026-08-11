package asmgen

import "github.com/goccy/wasm2go/internal/ssa"

// helperSpec is the Go-side signature of a runtime helper from
// internal/codegen/helpers/helpers.go. The asm emitter consults this
// when lowering OpHelperCall — it needs to know each parameter's
// size/alignment to stage the args in the right ABI0 slots, and the
// return type to read the result back. Adding a new helper here is
// what unlocks lowering for the wasm op that routes to it.
type helperSpec struct {
	params []ssa.Type
	ret    ssa.Type // ssa.TypeInvalid when the helper has no return
}

// helperSigs is the registry. The names mirror the helper-function
// names in internal/codegen/helpers/helpers.go and the strings the
// lowering pass writes into OpHelperCall.Aux (see
// internal/lower/lower.go's helperBinarySpec / helperUnarySpec).
//
// The wasm_trap_* entries are zero-arg, no-result panicking helpers
// that the inline div/rem/trunc asm emits as `CALL ·name(SB)` on the
// trap branch — they NEVER return, but go vet / the linker want a
// signature in scope to resolve the symbol, and in multi-package mode
// every chunk needs a per-package trampoline so the asm's local CALL
// resolves through //go:linkname to base. Including them here gives
// both: the trampoline generator builds the per-chunk stub, and
// emitHelpers always pulls the helper body into base.
var helperSigs = map[string]helperSpec{
	// --- integer unary helpers ---
	"i32_eqz":    {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i64_eqz":    {[]ssa.Type{ssa.TypeI64}, ssa.TypeI32},
	"i32_clz":    {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i32_ctz":    {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i32_popcnt": {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i64_clz":    {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},
	"i64_ctz":    {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},
	"i64_popcnt": {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},

	// --- integer binary helpers ---
	"i32_rotl":    {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i32_rotr":    {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i64_rotl":    {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},
	"i64_rotr":    {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},
	"i32_div_s":   {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i32_div_u_s": {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i32_rem_s":   {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i32_rem_u_s": {[]ssa.Type{ssa.TypeI32, ssa.TypeI32}, ssa.TypeI32},
	"i64_div_s":   {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},
	"i64_div_u_s": {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},
	"i64_rem_s":   {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},
	"i64_rem_u_s": {[]ssa.Type{ssa.TypeI64, ssa.TypeI64}, ssa.TypeI64},

	// --- integer extensions / conversions (non-trapping) ---
	"i32_wrap_i64":     {[]ssa.Type{ssa.TypeI64}, ssa.TypeI32},
	"i64_extend_i32_s": {[]ssa.Type{ssa.TypeI32}, ssa.TypeI64},
	"i64_extend_i32_u": {[]ssa.Type{ssa.TypeI32}, ssa.TypeI64},
	"i32_extend8_s":    {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i32_extend16_s":   {[]ssa.Type{ssa.TypeI32}, ssa.TypeI32},
	"i64_extend8_s":    {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},
	"i64_extend16_s":   {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},
	"i64_extend32_s":   {[]ssa.Type{ssa.TypeI64}, ssa.TypeI64},

	// --- float arithmetic helpers ---
	"f32_add":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_sub":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_mul":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_div":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_min":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_max":      {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f32_copysign": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeF32},
	"f64_add":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_sub":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_mul":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_div":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_min":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_max":      {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},
	"f64_copysign": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeF64},

	// --- float unary helpers ---
	"f32_abs":     {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_neg":     {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_ceil":    {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_floor":   {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_trunc":   {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_nearest": {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f32_sqrt":    {[]ssa.Type{ssa.TypeF32}, ssa.TypeF32},
	"f64_abs":     {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_neg":     {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_ceil":    {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_floor":   {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_trunc":   {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_nearest": {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},
	"f64_sqrt":    {[]ssa.Type{ssa.TypeF64}, ssa.TypeF64},

	// --- float comparisons (return i32 0/1) ---
	"f32_eq": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f32_ne": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f32_lt": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f32_gt": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f32_le": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f32_ge": {[]ssa.Type{ssa.TypeF32, ssa.TypeF32}, ssa.TypeI32},
	"f64_eq": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},
	"f64_ne": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},
	"f64_lt": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},
	"f64_gt": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},
	"f64_le": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},
	"f64_ge": {[]ssa.Type{ssa.TypeF64, ssa.TypeF64}, ssa.TypeI32},

	// --- float ↔ int conversions (non-trapping) ---
	"f32_convert_i32_s": {[]ssa.Type{ssa.TypeI32}, ssa.TypeF32},
	"f32_convert_i32_u": {[]ssa.Type{ssa.TypeI32}, ssa.TypeF32},
	"f32_convert_i64_s": {[]ssa.Type{ssa.TypeI64}, ssa.TypeF32},
	"f32_convert_i64_u": {[]ssa.Type{ssa.TypeI64}, ssa.TypeF32},
	"f32_demote_f64":    {[]ssa.Type{ssa.TypeF64}, ssa.TypeF32},
	"f64_convert_i32_s": {[]ssa.Type{ssa.TypeI32}, ssa.TypeF64},
	"f64_convert_i32_u": {[]ssa.Type{ssa.TypeI32}, ssa.TypeF64},
	"f64_convert_i64_s": {[]ssa.Type{ssa.TypeI64}, ssa.TypeF64},
	"f64_convert_i64_u": {[]ssa.Type{ssa.TypeI64}, ssa.TypeF64},
	"f64_promote_f32":   {[]ssa.Type{ssa.TypeF32}, ssa.TypeF64},

	// --- bit reinterpret (no conversion, just type punning) ---
	"i32_reinterpret_f32": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI32},
	"i64_reinterpret_f64": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI64},
	"f32_reinterpret_i32": {[]ssa.Type{ssa.TypeI32}, ssa.TypeF32},
	"f64_reinterpret_i64": {[]ssa.Type{ssa.TypeI64}, ssa.TypeF64},

	// --- trapping float→int conversions ---
	"i32_trunc_f32_s": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI32},
	"i32_trunc_f32_u": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI32},
	"i32_trunc_f64_s": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI32},
	"i32_trunc_f64_u": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI32},
	"i64_trunc_f32_s": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI64},
	"i64_trunc_f32_u": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI64},
	"i64_trunc_f64_s": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI64},
	"i64_trunc_f64_u": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI64},

	// --- saturating float→int conversions ---
	"i32_trunc_sat_f32_s": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI32},
	"i32_trunc_sat_f32_u": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI32},
	"i32_trunc_sat_f64_s": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI32},
	"i32_trunc_sat_f64_u": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI32},
	"i64_trunc_sat_f32_s": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI64},
	"i64_trunc_sat_f32_u": {[]ssa.Type{ssa.TypeF32}, ssa.TypeI64},
	"i64_trunc_sat_f64_s": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI64},
	"i64_trunc_sat_f64_u": {[]ssa.Type{ssa.TypeF64}, ssa.TypeI64},

	// --- wasm trap helpers (zero-arg, no-result, panic) ---
	"wasm_trap_div_zero":     {nil, ssa.TypeInvalid},
	"wasm_trap_int_overflow": {nil, ssa.TypeInvalid},
	"wasm_trap_invalid_conv": {nil, ssa.TypeInvalid},
}

// helperAlwaysInline names the helpers BOTH per-arch emitters lower
// to one or two native instructions with no CALL: the sign/zero
// extends, the 32-bit float/int reinterprets, and f32_abs. planFunc
// exempts them from hasCall (they impose no callee frame and no
// ForbidCalls consequence); each arch's emit path must keep inline
// coverage for exactly this set.
func helperAlwaysInline(name string) bool {
	switch name {
	case "i64_extend_i32_s", "i64_extend_i32_u", "i64_extend32_s",
		"i32_wrap_i64",
		"i32_reinterpret_f32", "f32_reinterpret_i32",
		"f32_abs", "f32_neg", "f64_abs", "f64_neg",
		"f64_promote_f32", "f32_demote_f64",
		"f32_eq", "f32_ne", "f32_lt", "f32_le", "f32_gt", "f32_ge",
		"f64_eq", "f64_ne", "f64_lt", "f64_le", "f64_gt", "f64_ge",
		"f32_add", "f32_sub", "f32_mul", "f32_div",
		"f64_add", "f64_sub", "f64_mul", "f64_div",
		"f32_convert_i32_s", "f32_convert_i32_u", "f32_convert_i64_s",
		"f64_convert_i32_s", "f64_convert_i32_u", "f64_convert_i64_s":
		return true
	}
	return false
}

// divRemHelper names the integer divide/remainder family lowered
// inline (native divide + trap-branch CALLs) on both arches.
func divRemHelper(name string) bool {
	switch name {
	case "i32_div_s", "i32_div_u_s", "i32_rem_s", "i32_rem_u_s",
		"i64_div_s", "i64_div_u_s", "i64_rem_s", "i64_rem_u_s":
		return true
	}
	return false
}

func helperSig(name string) (helperSpec, bool) {
	s, ok := helperSigs[name]
	return s, ok
}

// helperABISize returns (size, alignment) for one helper parameter
// or result in Go's ABI0 amd64 frame.
func helperABISize(t ssa.Type) (size, align int) {
	switch t {
	case ssa.TypeI32, ssa.TypeF32:
		return 4, 4
	case ssa.TypeI64, ssa.TypeF64:
		return 8, 8
	}
	return 0, 1
}

// helperCallFrameSize returns the total bytes a helper call consumes
// at the bottom of the caller's frame: every param at its naturally-
// aligned offset, then a hop to the next 8-byte boundary, then the
// return value(s), then a final pad to 8 bytes for the platform's
// stack-alignment expectation.
//
// The args→results 8-byte boundary mirrors Go's ABI0 layout: a
// caller compiled by `go build` expects to find the result at the
// 8-aligned offset after the args, even when the last arg's
// natural alignment would allow a smaller offset. Skipping this
// produces a silent miscompile because the helper writes the result
// where ABI0 says it goes (one slot higher than our naive layout),
// and our `MOVL ret(SP), AX` then reads back the *argument* bytes
// the helper never overwrote (which often happen to be 1, hence the
// "every input returns 1" symptom we hit during initial bring-up).
func helperCallFrameSize(spec helperSpec) int {
	off := 0
	for _, p := range spec.params {
		sz, al := helperABISize(p)
		off = alignUp(off, al)
		off += sz
	}
	if spec.ret != ssa.TypeInvalid {
		off = alignUp(off, 8)
		sz, al := helperABISize(spec.ret)
		off = alignUp(off, al)
		off += sz
	}
	return alignUp(off, 8)
}

// helperRetOffset returns the byte offset within the helper-call
// frame where the first return value lives. Mirrors the layout in
// helperCallFrameSize so emitHelperCall reads the value back from
// the same slot the helper wrote it to.
func helperRetOffset(spec helperSpec) int {
	off := 0
	for _, p := range spec.params {
		sz, al := helperABISize(p)
		off = alignUp(off, al)
		off += sz
	}
	if spec.ret != ssa.TypeInvalid {
		off = alignUp(off, 8)
	}
	return off
}
