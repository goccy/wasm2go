// Package helpers contains the runtime helper functions injected into wasm2go's
// generated output. The codegen embeds this file via //go:embed and selects
// only the helpers actually used by the translated module. The codegen filters
// to *ast.FuncDecl entries by name; non-func decls (the Module placeholder
// below) never appear in generated output.
package helpers

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Module is a placeholder so the helpers package compiles standalone. Real
// generated output supplies its own Module struct with at least `memory []byte`,
// `maxMem uint64`, and `M unsafe.Pointer` fields. M caches
// unsafe.Pointer(unsafe.SliceData(memory)) so generated load/store sites can
// deref through m.M without re-fetching the slice header on every access.
type Module struct {
	memory []byte
	maxMem uint64
	M      unsafe.Pointer
	// memMu serialises mutations of the memory slice header (and any
	// relocation of its backing array) against out-of-band readers and
	// writers — see memoryGrow and accessMemory. Generated output
	// declares the same field at the END of its Module struct so the
	// memory/maxMem/M offsets the asm hardcodes stay put.
	//
	// memMu/memSize/threads are POINTERS because a wasi-threads agent runs
	// on a struct COPY of the Module: wasm's threads model shares the memory
	// but gives every agent its own GLOBALS (the stack pointer above all —
	// two agents sharing one SP global scribble over each other's stacks).
	// A struct copy duplicates the global fields; the pointered state stays
	// genuinely shared.
	memMu *sync.Mutex
	// memSize is the size the guest sees, in bytes — the single source of
	// truth for memory.size, growth and every bounds check. For a shared
	// memory the slice header stays fixed at the declared maximum and this
	// is the only thing growth moves.
	memSize *atomic.Uint64
	// memShared records that the memory was declared shared (threads).
	memShared bool
	// dataSegs holds passive data segments by original index (nil = active
	// or dropped); memory.init copies out of them, data.drop nils them.
	dataSegs [][]byte
	// dataEnd is the highest offset any memory.init has written to — the end
	// of the data segments, which is where BSS begins. Learned at run time
	// (see memoryInit) because the offsets are wasm constants the host never
	// sees otherwise. An embedding that shares an initialized memory image
	// needs it: the image may carry everything BELOW this line and must carry
	// zeros above it. Zero until the start section has run.
	dataEnd uint32
	// threadStart runs the guest's wasi_thread_start export. New() assigns it
	// when the wasm exports one. A field (not an interface assertion on the
	// Module) because multi-package output emits exports as FREE FUNCTIONS in
	// the main package — there is no method for an assertion to find, and
	// base cannot import the main package to call it directly. It takes the
	// Module explicitly so threadSpawn can hand the AGENT'S clone to it.
	threadStart func(m *Module, tid int32, arg int32)
	// threads tracks agents spawned through wasi_thread_spawn.
	threads *threadPool
}

// ----- Opaque identity helpers ---------------------------------------------
//
// Wrap suspect literals so Go's constant evaluator does not collapse them.
// Wasm requires `i32.div_s 1 0` to trap at runtime; Go's `1 / 0` is a compile
// error. Routing through these defeats compile-time folding.

func i32(x int32) int32 { return x }

func i64(x int64) int64 { return x }

// ui32 / ui64 reinterpret a signed integer as its unsigned bit
// equivalent at runtime. Used for the operands of wasm unsigned
// comparisons (i32.lt_u etc.) — emitting `uint32(int32(-N))` directly
// fails Go's compile-time constant rule because the negative typed
// constant isn't representable in uint32; routing through these
// function-call boundaries forces runtime conversion.
func ui32(x int32) uint32 { return uint32(x) }

func ui64(x int64) uint64 { return uint64(x) }

// b2i32 materialises a wasm comparison result — an i32 that is 0 or 1 — from
// the Go bool the comparison expression evaluates to.
//
// It exists as a named helper rather than an inline `func() int32 { ... }()`
// because the gcasm backend requires every direct call left in the compiled
// output to be either a package-local FnN or something the Go inliner removed.
// A func literal is normally inlined at its call site, but the inliner gives up
// once the ENCLOSING function grows past its budget — and a single wasm function
// can translate to tens of thousands of lines of Go, as an interpreter's
// bytecode dispatch loop does. The literal is then outlined into a real closure
// symbol (FnN.funcA.funcB), which reaches the assembler as a direct call gcasm
// cannot marshal. A named helper this small is always inlined, and if it ever
// were not, it would fail loudly at its own symbol rather than as a nested
// closure.
func b2i32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func f32(x float32) float32 { runtime.KeepAlive(&x); return x }

func f64(x float64) float64 { runtime.KeepAlive(&x); return x }

// ----- Wasm trap helpers (panic with the exact spec-mandated message) ----
//
// Used by the inline asm emit for div/rem/trunc-trap paths. The pure-Go
// path panics directly inside i32_div_s / i32_trunc_f32_s / etc.; the
// inline asm short-circuits to one of these helpers via `CALL ·name(SB)`
// so the resulting panic message matches what the pure-Go path produces.
// They never return — the runtime turns the panic into a fatal error.

//go:noinline
func wasm_trap_div_zero() { panic("wasm: integer divide by zero") }

//go:noinline
func wasm_trap_int_overflow() { panic("wasm: integer overflow") }

//go:noinline
func wasm_trap_invalid_conv() { panic("wasm: invalid conversion to integer") }

//go:noinline
func wasm_trap_unreachable() { panic("wasm: unreachable") }

//go:noinline
func wasm_trap_memfill_oob() { panic("wasm: memory.fill out of bounds") }

//go:noinline
func wasm_trap_memcopy_oob() { panic("wasm: memory.copy out of bounds") }

//go:noinline
func wasm_trap_meminit_oob() { panic("wasm: memory.init out of bounds") }

// ----- Exception handling (EH proposal / setjmp-longjmp) --------------------
//
// A wasm `throw` becomes a Go panic carrying a wasmExc; a try/catch landing pad
// recovers it. Operand values are bit-reinterpreted into uint64 slots (i32/f32
// occupy the low 32 bits) and narrowed back at the catch by the generated code.

type wasmExc struct {
	Tag  uint32
	Vals []uint64
}

// wasm_throw raises exception tag with the given operand slots. It never
// returns (it panics), so the generated code emits it as a block terminator.
func wasm_throw(tag uint32, vals ...uint64) { panic(&wasmExc{Tag: tag, Vals: vals}) }

// wasm_catch is called in a try landing pad's deferred recover: it returns the
// caught *wasmExc, nil if there was no panic, and re-panics anything that is
// not a wasmExc (a real Go panic must not be swallowed by a wasm catch).
func wasm_catch(r any) *wasmExc {
	if r == nil {
		return nil
	}
	if e, ok := r.(*wasmExc); ok {
		return e
	}
	panic(r)
}

// wasm_trap_unreachable is only called from generated function bodies
// (the SSA emitter's BlockUnreachable/OpUnreachable lowering), never
// from the other helpers in this file.
var _ = wasm_trap_unreachable

// The exception-handling helpers above are likewise emitted into generated
// code, not called from within this package; reference them so the unused
// analyzer stays quiet.
var (
	_ = wasmExc{}
	_ = wasm_throw
	_ = wasm_catch
)

// ----- Integer division with overflow / divide-by-zero traps --------------

func i32_div_s(x, y int32) int32 {
	if y == -1 && x == math.MinInt32 {
		wasm_trap_int_overflow()
	}
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x / y
}

func i64_div_s(x, y int64) int64 {
	if y == -1 && x == math.MinInt64 {
		wasm_trap_int_overflow()
	}
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x / y
}

func i32_div_u(x, y uint32) uint32 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x / y
}

func i64_div_u(x, y uint64) uint64 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x / y
}

func i32_rem_s(x, y int32) int32 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	if y == -1 {
		// Per spec, MIN_INT % -1 == 0 and does NOT trap.
		return 0
	}
	return x % y
}

func i64_rem_s(x, y int64) int64 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	if y == -1 {
		return 0
	}
	return x % y
}

func i32_rem_u(x, y uint32) uint32 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x % y
}

func i64_rem_u(x, y uint64) uint64 {
	if y == 0 {
		wasm_trap_div_zero()
	}
	return x % y
}

// ----- Stack-frame helpers -------------------------------------------------
//
// Compresses the C++/Emscripten stack-frame prologue
//     tN = m.gK - int32(N)
//     lL = tN
//     m.gK = tN
// into a single helper call so the per-function source size shrinks and the
// SSA backend has fewer statements per body.

func subg(p *int32, n int32) int32 { *p -= n; return *p }

func subg64(p *int64, n int64) int64 { *p -= n; return *p }

// ----- Shifts with mod-N count ---------------------------------------------

func i32_shl(x, y int32) int32 { return x << (uint32(y) & 31) }

func i32_shr_s(x, y int32) int32 { return x >> (uint32(y) & 31) }

func i32_shr_u(x, y int32) int32 { return int32(uint32(x) >> (uint32(y) & 31)) }

func i32_rotl(x, y int32) int32 { return int32(bits.RotateLeft32(uint32(x), int(y&31))) }

func i32_rotr(x, y int32) int32 { return int32(bits.RotateLeft32(uint32(x), -int(y&31))) }

func i64_shl(x, y int64) int64 { return x << (uint64(y) & 63) }

func i64_shr_s(x, y int64) int64 { return x >> (uint64(y) & 63) }

func i64_shr_u(x, y int64) int64 { return int64(uint64(x) >> (uint64(y) & 63)) }

func i64_rotl(x, y int64) int64 { return int64(bits.RotateLeft64(uint64(x), int(y&63))) }

func i64_rotr(x, y int64) int64 { return int64(bits.RotateLeft64(uint64(x), -int(y&63))) }

// ----- Float min/max (NaN-propagating) -------------------------------------

func f32_min(x, y float32) float32 {
	if x != x || y != y {
		return float32(math.NaN())
	}
	if x < y {
		return x
	}
	if y < x {
		return y
	}
	// -0 vs +0 — wasm prefers -0.
	if x == 0 {
		if math.Signbit(float64(x)) {
			return x
		}
		return y
	}
	return x
}

func f32_max(x, y float32) float32 {
	if x != x || y != y {
		return float32(math.NaN())
	}
	if x > y {
		return x
	}
	if y > x {
		return y
	}
	if x == 0 {
		if math.Signbit(float64(x)) {
			return y
		}
		return x
	}
	return x
}

func f64_min(x, y float64) float64 {
	if x != x || y != y {
		return math.NaN()
	}
	if x < y {
		return x
	}
	if y < x {
		return y
	}
	if x == 0 {
		if math.Signbit(x) {
			return x
		}
		return y
	}
	return x
}

func f64_max(x, y float64) float64 {
	if x != x || y != y {
		return math.NaN()
	}
	if x > y {
		return x
	}
	if y > x {
		return y
	}
	if x == 0 {
		if math.Signbit(x) {
			return y
		}
		return x
	}
	return x
}

// ----- Float abs/neg/copysign ---------------------------------------------

func f32_abs(x float32) float32 {
	return math.Float32frombits(math.Float32bits(x) &^ (1 << 31))
}

func f64_abs(x float64) float64 {
	return math.Float64frombits(math.Float64bits(x) &^ (1 << 63))
}

func f32_neg(x float32) float32 {
	return math.Float32frombits(math.Float32bits(x) ^ (1 << 31))
}

func f64_neg(x float64) float64 {
	return math.Float64frombits(math.Float64bits(x) ^ (1 << 63))
}

func f32_copysign(x, y float32) float32 {
	return float32(math.Copysign(float64(x), float64(y)))
}

func f64_copysign(x, y float64) float64 { return math.Copysign(x, y) }

// ----- Float rounding ------------------------------------------------------

func f32_nearest(x float32) float32 { return float32(math.RoundToEven(float64(x))) }

func f64_nearest(x float64) float64 { return math.RoundToEven(x) }

// ----- Float-to-int (trapping) --------------------------------------------

func i32_trunc_f32_s(x float32) int32 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	// Lower bound is `> -2147483904.0` (one ULP below -2^31 in f32),
	// not `>= -2^31`, because every f32 in (-2147483904, -2147483648]
	// rounds to -2^31 and is representable as int32. The wasm
	// reference interpreter uses these bounds; replicate.
	if !(x > -2147483904.0 && x < 2147483648.0) {
		wasm_trap_int_overflow()
	}
	return int32(x)
}

func i32_trunc_f32_u(x float32) int32 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	if !(x > -1.0 && x < 4294967296.0) {
		wasm_trap_int_overflow()
	}
	return int32(uint32(x))
}

func i32_trunc_f64_s(x float64) int32 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	// The wasm spec accepts every f64 whose truncation lies in
	// [-2^31, 2^31). With f64 precision, -2147483648.5 truncates to
	// -2^31 and is representable; the strict lower bound is one ULP
	// below -2^31 (-2147483649.0). The previous closed lower bound
	// rejected -2147483648.5 / -2147483648.9999 — both legal inputs.
	if !(x > -2147483649.0 && x < 2147483648.0) {
		wasm_trap_int_overflow()
	}
	return int32(x)
}

func i32_trunc_f64_u(x float64) int32 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	if !(x > -1.0 && x < 4294967296.0) {
		wasm_trap_int_overflow()
	}
	return int32(uint32(x))
}

func i64_trunc_f32_s(x float32) int64 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	// Lower bound is one f32 ULP below -2^63. The smallest f32
	// strictly greater than -2^64 is -9223373136366403584.0 — every
	// f32 above that and at most -2^63 rounds to -2^63, the
	// smallest int64. The wasm reference interpreter uses these
	// strict-inequality bounds; replicate.
	if !(float64(x) > -9223373136366403584.0 && float64(x) < 9223372036854775808.0) {
		wasm_trap_int_overflow()
	}
	return int64(x)
}

func i64_trunc_f32_u(x float32) int64 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	if !(x > -1.0 && float64(x) < 18446744073709551616.0) {
		wasm_trap_int_overflow()
	}
	return int64(uint64(x))
}

func i64_trunc_f64_s(x float64) int64 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	if !(x >= -9223372036854775808.0 && x < 9223372036854775808.0) {
		wasm_trap_int_overflow()
	}
	return int64(x)
}

func i64_trunc_f64_u(x float64) int64 {
	if x != x {
		wasm_trap_invalid_conv()
	}
	if !(x > -1.0 && x < 18446744073709551616.0) {
		wasm_trap_int_overflow()
	}
	return int64(uint64(x))
}

// ----- Float-to-int (saturating) ------------------------------------------

func i32_trunc_sat_f32_s(x float32) int32 {
	if x != x {
		return 0
	}
	if x <= -2147483648.0 {
		return math.MinInt32
	}
	if x >= 2147483648.0 {
		return math.MaxInt32
	}
	return int32(x)
}

func i32_trunc_sat_f32_u(x float32) int32 {
	if x != x || x <= 0 {
		return 0
	}
	if x >= 4294967296.0 {
		return -1 // = uint32 max
	}
	return int32(uint32(x))
}

func i32_trunc_sat_f64_s(x float64) int32 {
	if x != x {
		return 0
	}
	if x <= -2147483648.0 {
		return math.MinInt32
	}
	if x >= 2147483648.0 {
		return math.MaxInt32
	}
	return int32(x)
}

func i32_trunc_sat_f64_u(x float64) int32 {
	if x != x || x <= 0 {
		return 0
	}
	if x >= 4294967296.0 {
		return -1
	}
	return int32(uint32(x))
}

func i64_trunc_sat_f32_s(x float32) int64 {
	if x != x {
		return 0
	}
	if float64(x) <= -9223372036854775808.0 {
		return math.MinInt64
	}
	if float64(x) >= 9223372036854775808.0 {
		return math.MaxInt64
	}
	return int64(x)
}

func i64_trunc_sat_f32_u(x float32) int64 {
	if x != x || x <= 0 {
		return 0
	}
	if float64(x) >= 18446744073709551616.0 {
		return -1
	}
	return int64(uint64(x))
}

func i64_trunc_sat_f64_s(x float64) int64 {
	if x != x {
		return 0
	}
	if x <= -9223372036854775808.0 {
		return math.MinInt64
	}
	if x >= 9223372036854775808.0 {
		return math.MaxInt64
	}
	return int64(x)
}

func i64_trunc_sat_f64_u(x float64) int64 {
	if x != x || x <= 0 {
		return 0
	}
	if x >= 18446744073709551616.0 {
		return -1
	}
	return int64(uint64(x))
}

// ----- Memory load/store helpers ------------------------------------------

func load8(b []byte) uint8 { return b[0] }

func load16(b []byte) uint16 {
	_ = b[1]
	return binary.LittleEndian.Uint16(b)
}

func load32(b []byte) uint32 {
	_ = b[3]
	return binary.LittleEndian.Uint32(b)
}

func load64(b []byte) uint64 {
	_ = b[7]
	return binary.LittleEndian.Uint64(b)
}

func store8(b []byte, v uint8) { b[0] = v }

func store16(b []byte, v uint16) {
	_ = b[1]
	binary.LittleEndian.PutUint16(b, v)
}

func store32(b []byte, v uint32) {
	_ = b[3]
	binary.LittleEndian.PutUint32(b, v)
}

func store64(b []byte, v uint64) {
	_ = b[7]
	binary.LittleEndian.PutUint64(b, v)
}

// ----- Module-aware memory load/store helpers -----------------------------
//
// These compress the per-call-site preamble at every wasm load/store. The
// "old" load32/store32 helpers above take a sliced []byte, forcing the
// codegen to emit `m.memory[uint64(uint32(addr))+offset:]` (40+ chars) at
// every call site. The new helpers take (m *Module, addr int32, offset uint32)
// and absorb the slicing/casting internally, cutting ~15-20 chars per access.
// With ~700k memory accesses in a typical Emscripten build this compounds to
// >10 MB of source-size savings.

// All helpers below return / accept the wasm-natural type (int32, int64,
// float32, float64) so the codegen never needs an outer cast at the call site.
// Sign vs. zero extension is encoded in the helper name (s = sign, u = zero).

func mload8s(m *Module, addr int32, offset uint32) int32 {
	return int32(int8(m.memory[uint64(uint32(addr))+uint64(offset)]))
}

func mload8u(m *Module, addr int32, offset uint32) int32 {
	return int32(m.memory[uint64(uint32(addr))+uint64(offset)])
}

func mload16s(m *Module, addr int32, offset uint32) int32 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	return int32(int16(binary.LittleEndian.Uint16(m.memory[a:])))
}

func mload16u(m *Module, addr int32, offset uint32) int32 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	return int32(binary.LittleEndian.Uint16(m.memory[a:]))
}

func mload32(m *Module, addr int32, offset uint32) int32 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	return int32(binary.LittleEndian.Uint32(m.memory[a:]))
}

func mload64(m *Module, addr int32, offset uint32) int64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+7]
	return int64(binary.LittleEndian.Uint64(m.memory[a:]))
}

// 64-bit-result variants with sub-word sign/zero extension (i64.load*).
func mload64_8s(m *Module, addr int32, offset uint32) int64 {
	return int64(int8(m.memory[uint64(uint32(addr))+uint64(offset)]))
}

func mload64_8u(m *Module, addr int32, offset uint32) int64 {
	return int64(m.memory[uint64(uint32(addr))+uint64(offset)])
}

func mload64_16s(m *Module, addr int32, offset uint32) int64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	return int64(int16(binary.LittleEndian.Uint16(m.memory[a:])))
}

func mload64_16u(m *Module, addr int32, offset uint32) int64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	return int64(binary.LittleEndian.Uint16(m.memory[a:]))
}

func mload64_32s(m *Module, addr int32, offset uint32) int64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	return int64(int32(binary.LittleEndian.Uint32(m.memory[a:])))
}

func mload64_32u(m *Module, addr int32, offset uint32) int64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	return int64(binary.LittleEndian.Uint32(m.memory[a:]))
}

func mloadF32(m *Module, addr int32, offset uint32) float32 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	return math.Float32frombits(binary.LittleEndian.Uint32(m.memory[a:]))
}

func mloadF64(m *Module, addr int32, offset uint32) float64 {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+7]
	return math.Float64frombits(binary.LittleEndian.Uint64(m.memory[a:]))
}

func mstore8(m *Module, addr int32, offset uint32, v int32) {
	m.memory[uint64(uint32(addr))+uint64(offset)] = byte(v)
}

func mstore8_64(m *Module, addr int32, offset uint32, v int64) {
	m.memory[uint64(uint32(addr))+uint64(offset)] = byte(v)
}

func mstore16(m *Module, addr int32, offset uint32, v int32) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	binary.LittleEndian.PutUint16(m.memory[a:], uint16(v))
}

func mstore16_64(m *Module, addr int32, offset uint32, v int64) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+1]
	binary.LittleEndian.PutUint16(m.memory[a:], uint16(v))
}

func mstore32(m *Module, addr int32, offset uint32, v int32) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	binary.LittleEndian.PutUint32(m.memory[a:], uint32(v))
}

func mstore32_64(m *Module, addr int32, offset uint32, v int64) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	binary.LittleEndian.PutUint32(m.memory[a:], uint32(v))
}

func mstore64(m *Module, addr int32, offset uint32, v int64) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+7]
	binary.LittleEndian.PutUint64(m.memory[a:], uint64(v))
}

func mstoreF32(m *Module, addr int32, offset uint32, v float32) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+3]
	binary.LittleEndian.PutUint32(m.memory[a:], math.Float32bits(v))
}

func mstoreF64(m *Module, addr int32, offset uint32, v float64) {
	a := uint64(uint32(addr)) + uint64(offset)
	_ = m.memory[a+7]
	binary.LittleEndian.PutUint64(m.memory[a:], math.Float64bits(v))
}

// Memory-to-memory single-word copy. Detected at codegen time by collapsing
// the (load → temp → store) pattern that C++/Emscripten emits for struct
// field copies. Saves a temp variable AND a line per copy.
func mcopy32(m *Module, srcAddr int32, srcOff uint32, dstAddr int32, dstOff uint32) {
	a := uint64(uint32(srcAddr)) + uint64(srcOff)
	b := uint64(uint32(dstAddr)) + uint64(dstOff)
	_ = m.memory[a+3]
	_ = m.memory[b+3]
	binary.LittleEndian.PutUint32(m.memory[b:], binary.LittleEndian.Uint32(m.memory[a:]))
}

func mcopy64(m *Module, srcAddr int32, srcOff uint32, dstAddr int32, dstOff uint32) {
	a := uint64(uint32(srcAddr)) + uint64(srcOff)
	b := uint64(uint32(dstAddr)) + uint64(dstOff)
	_ = m.memory[a+7]
	_ = m.memory[b+7]
	binary.LittleEndian.PutUint64(m.memory[b:], binary.LittleEndian.Uint64(m.memory[a:]))
}

// b32 returns 1 if b is true, else 0. Used by every comparison op so the
// generated bodies stay flat (no per-comparison closure).
func b32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// memorySize returns the current size of m.memory in wasm pages (each
// page is 64 KiB).
func memorySize(m *Module) int32 {
	return int32(m.memSize.Load() >> 16)
}

// wasmMemHardCap is the implementation limit on linear-memory size:
// 65534 pages, two short of wasm32's architectural 65536. Growth past
// it fails with -1 like any resource limit (the JS API allows an
// engine to refuse any grow). Keeping memSize strictly below 2^32
// minus a 128 KiB margin is what makes the coalesced SIMD bounds check
// (simd_v128_load_rng) exact: a group whose unwrapped address range
// reaches past memSize can then never be a group whose members all
// individually landed in bounds via u32 wraparound.
//
// A function rather than a const because the helper extractor carries
// only function declarations into the output (it must stay in sync
// with codegen's wasmMemHardCapBytes).
func wasmMemHardCap() uint64 { return (1 << 32) - (1 << 17) }

// memoryGrow grows m.memory by n wasm pages (64 KiB each). Returns the
// previous page count, or -1 if the new size would exceed maxMem or
// wasmMemHardCap. n may be 0, which simply returns the current size.
//
// len(m.memory) must always equal the exact wasm memory size (memory.size
// and every bounds check depend on it), but the backing array is grown
// GEOMETRICALLY: a sequence of small memory.grow calls — which a C++ heap
// does constantly during start-up — would otherwise reallocate and recopy
// the whole linear memory on every page, i.e. O(n^2) total copying. Spare
// capacity makes the common grow a zero-copy reslice and amortizes the
// reallocations to O(n).
func memoryGrow(m *Module, n int32) int32 {
	// Serialise growers against each other and against out-of-band
	// accessMemory. Guest loads/stores never take this lock.
	m.memMu.Lock()
	defer m.memMu.Unlock()
	cur := m.memSize.Load()
	prev := int32(cur >> 16)
	if n == 0 {
		return prev
	}
	if n < 0 {
		return -1
	}
	want := cur + uint64(n)*65536
	if m.maxMem != 0 && want > m.maxMem {
		return -1
	}
	if want > wasmMemHardCap() {
		return -1
	}
	if m.memShared {
		// The backing array already spans the declared maximum (New
		// reserved it; untouched pages are not resident). Growth is a
		// single atomic store: no copy, no reslice, and above all no
		// relocation — other agents hold m.M and deref it concurrently.
		if want > uint64(len(m.memory)) {
			return -1
		}
		m.memSize.Store(want)
		return prev
	}
	if want <= uint64(cap(m.memory)) {
		// Spare capacity already covers the new size. The bytes in
		// [len, want) were zero-filled when the backing array was
		// allocated and are unreachable until now, so the freshly
		// exposed pages are correctly zero — no copy, no clear.
		m.memory = m.memory[:want]
		m.memSize.Store(want)
		return prev
	}
	// Reallocate with at least double the current capacity so the next
	// grows are free reslices.
	newCap := uint64(cap(m.memory)) * 2
	if newCap < want {
		newCap = want
	}
	if m.maxMem != 0 && newCap > m.maxMem {
		newCap = m.maxMem
	}
	if newCap > wasmMemHardCap() {
		newCap = wasmMemHardCap()
	}
	grown := make([]byte, want, newCap)
	copy(grown, m.memory)
	m.memory = grown
	m.memSize.Store(want)
	// Reallocate moved the backing array, so the cached m.M pointer
	// is now stale. Reslice grows (the early-return path above) leave
	// the data pointer untouched so don't need this refresh.
	m.M = unsafe.Pointer(unsafe.SliceData(m.memory))
	return prev
}

// accessMemory runs f with the module's current linear memory while
// holding the same lock memoryGrow takes to mutate the memory slice
// header or relocate its backing array. It is the ONE safe way to
// touch linear memory from OUTSIDE the module's execution goroutine —
// e.g. a watchdog goroutine raising CPython's eval-breaker bit while
// an evaluation is running. For the duration of f the memory can
// neither be resliced nor relocated, so f's writes land in the array
// the guest observes; a grow that raced in just before blocks until f
// returns and then copies f's writes forward with the rest of the
// contents. Determinism notes for callers:
//
//   - f MUST NOT call back into the module or into memoryGrow — that
//     would self-deadlock.
//   - f should be short: a running guest blocks inside memory.grow
//     until f returns (ordinary guest loads/stores do not block).
//   - Bytes the guest reads or writes concurrently with f (that is
//     the point of an eval-breaker-style flag) are exchanged with
//     plain single-word accesses; keep such shared words
//     word-aligned and word-sized.
func accessMemory(m *Module, f func(mem []byte)) {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	f(m.memory)
}

// ----- Integer unary helpers ----------------------------------------------

// ----- Signed-arg adapters for the unsigned int helpers -----------------
//
// The generated Go uses int32/int64 throughout; the unsigned div/rem
// helpers take uint32/uint64. These adapters do the cast at the call
// site so the SSA emitter doesn't have to special-case them.

func i32_div_u_s(x, y int32) int32 { return int32(i32_div_u(uint32(x), uint32(y))) }
func i32_rem_u_s(x, y int32) int32 { return int32(i32_rem_u(uint32(x), uint32(y))) }
func i64_div_u_s(x, y int64) int64 { return int64(i64_div_u(uint64(x), uint64(y))) }
func i64_rem_u_s(x, y int64) int64 { return int64(i64_rem_u(uint64(x), uint64(y))) }

// ----- Float arithmetic adapters ----------------------------------------
//
// Wrap raw Go float arithmetic so the helper-call-based lowering can
// route through a uniform call boundary. Note these are NOT used for
// optimisation — they exist purely so the SSA emitter has a single
// pattern for every float binary op (the Go inliner removes the call).

// The explicit same-type conversions are NOT redundant: they are
// rounding points. Once these helpers inline, gc is free to fuse a
// multiply feeding an add into a single FMA — legal Go, but wasm
// requires every operation individually rounded, and a fused result
// diverges from every wasm runtime (bitwise, and observably in greedy
// sampling). A float conversion forces the intermediate rounding and
// forbids the fusion (spec: Conversions, "rounds to the precision of
// the target type"; the same rule math.FMA documents).
func f32_add(x, y float32) float32 { return float32(x + y) }
func f32_sub(x, y float32) float32 { return float32(x - y) }
func f32_mul(x, y float32) float32 { return float32(x * y) }
func f32_div(x, y float32) float32 { return float32(x / y) }
func f64_add(x, y float64) float64 { return float64(x + y) }
func f64_sub(x, y float64) float64 { return float64(x - y) }
func f64_mul(x, y float64) float64 { return float64(x * y) }
func f64_div(x, y float64) float64 { return float64(x / y) }

func i32_eqz(x int32) int32 {
	if x == 0 {
		return 1
	}
	return 0
}

func i64_eqz(x int64) int32 {
	if x == 0 {
		return 1
	}
	return 0
}

func i32_clz(x int32) int32    { return int32(bits.LeadingZeros32(uint32(x))) }
func i32_ctz(x int32) int32    { return int32(bits.TrailingZeros32(uint32(x))) }
func i32_popcnt(x int32) int32 { return int32(bits.OnesCount32(uint32(x))) }

func i64_clz(x int64) int64    { return int64(bits.LeadingZeros64(uint64(x))) }
func i64_ctz(x int64) int64    { return int64(bits.TrailingZeros64(uint64(x))) }
func i64_popcnt(x int64) int64 { return int64(bits.OnesCount64(uint64(x))) }

// ----- Float unary helpers (the ones not already defined above) -----------

func f32_ceil(x float32) float32  { return float32(math.Ceil(float64(x))) }
func f64_ceil(x float64) float64  { return math.Ceil(x) }
func f32_floor(x float32) float32 { return float32(math.Floor(float64(x))) }
func f64_floor(x float64) float64 { return math.Floor(x) }
func f32_trunc(x float32) float32 { return float32(math.Trunc(float64(x))) }
func f64_trunc(x float64) float64 { return math.Trunc(x) }
func f32_sqrt(x float32) float32  { return float32(math.Sqrt(float64(x))) }
func f64_sqrt(x float64) float64  { return math.Sqrt(x) }

// ----- Float comparisons -------------------------------------------------
//
// wasm float comparisons return an i32 (1 or 0). NaN propagation matches
// Go's standard float comparisons (NaN compares false to anything).

func f32_eq(x, y float32) int32 {
	if x == y {
		return 1
	}
	return 0
}
func f32_ne(x, y float32) int32 {
	if x != y {
		return 1
	}
	return 0
}
func f32_lt(x, y float32) int32 {
	if x < y {
		return 1
	}
	return 0
}
func f32_gt(x, y float32) int32 {
	if x > y {
		return 1
	}
	return 0
}
func f32_le(x, y float32) int32 {
	if x <= y {
		return 1
	}
	return 0
}
func f32_ge(x, y float32) int32 {
	if x >= y {
		return 1
	}
	return 0
}

func f64_eq(x, y float64) int32 {
	if x == y {
		return 1
	}
	return 0
}
func f64_ne(x, y float64) int32 {
	if x != y {
		return 1
	}
	return 0
}
func f64_lt(x, y float64) int32 {
	if x < y {
		return 1
	}
	return 0
}
func f64_gt(x, y float64) int32 {
	if x > y {
		return 1
	}
	return 0
}
func f64_le(x, y float64) int32 {
	if x <= y {
		return 1
	}
	return 0
}
func f64_ge(x, y float64) int32 {
	if x >= y {
		return 1
	}
	return 0
}

// ----- Conversions -------------------------------------------------------

func i32_wrap_i64(x int64) int32       { return int32(x) }
func i64_extend_i32_s(x int32) int64   { return int64(x) }
func i64_extend_i32_u(x int32) int64   { return int64(uint32(x)) }
func f32_demote_f64(x float64) float32 { return float32(x) }
func f64_promote_f32(x float32) float64 {
	// Preserve quiet NaN bit pattern via Float bits round-trip on NaN.
	if math.IsNaN(float64(x)) {
		// Wasm requires NaN payload to be deterministic; Go float
		// arithmetic does not guarantee bit-exact preservation but
		// the standard cast is acceptable for our test surface.
		return float64(x)
	}
	return float64(x)
}

func f32_convert_i32_s(x int32) float32 { return float32(x) }
func f32_convert_i32_u(x int32) float32 { return float32(uint32(x)) }
func f32_convert_i64_s(x int64) float32 { return float32(x) }
func f32_convert_i64_u(x int64) float32 { return float32(uint64(x)) }
func f64_convert_i32_s(x int32) float64 { return float64(x) }
func f64_convert_i32_u(x int32) float64 { return float64(uint32(x)) }
func f64_convert_i64_s(x int64) float64 { return float64(x) }
func f64_convert_i64_u(x int64) float64 { return float64(uint64(x)) }

func i32_reinterpret_f32(x float32) int32 { return int32(math.Float32bits(x)) }
func i64_reinterpret_f64(x float64) int64 { return int64(math.Float64bits(x)) }
func f32_reinterpret_i32(x int32) float32 { return math.Float32frombits(uint32(x)) }
func f64_reinterpret_i64(x int64) float64 { return math.Float64frombits(uint64(x)) }

// f32_to_f16_bits converts a float32 to IEEE binary16 bits with
// round-to-nearest-even. It agrees with the hardware convert
// instruction (arm64 FCVT h,s) on every non-NaN input, denormals and
// infinity included; NaN maps to sign|0x7E00. Injected by the SSA
// pass that recognizes the software fp32→fp16 rounding idiom — at
// those sites the NaN case is handled by the surrounding branch, so
// only the non-NaN agreement is load-bearing. The asm backend
// splices this call into the native convert.
func f32_to_f16_bits(x float32) int32 {
	w := math.Float32bits(x)
	shl1w := w + w
	sign := w & 0x80000000
	if shl1w > 0xFF000000 { // NaN
		return int32((sign >> 16) | 0x7E00)
	}
	bias := shl1w & 0xFF000000
	if bias < 0x71000000 {
		bias = 0x71000000
	}
	f := math.Float32frombits(w&0x7FFFFFFF) * 0x1p+112 * 0x1p-110
	f += math.Float32frombits((bias >> 1) + 0x07800000)
	fbits := math.Float32bits(f)
	nonsign := (fbits>>13)&0x7C00 + fbits&0xFFF
	return int32((sign >> 16) | nonsign)
}

// ----- Sign-extension (wasm 1.0 extension) -------------------------------

func i32_extend8_s(x int32) int32  { return int32(int8(x)) }
func i32_extend16_s(x int32) int32 { return int32(int16(x)) }
func i64_extend8_s(x int64) int64  { return int64(int8(x)) }
func i64_extend16_s(x int64) int64 { return int64(int16(x)) }
func i64_extend32_s(x int64) int64 { return int64(int32(x)) }

// ----- Bulk-memory ops ---------------------------------------------------
//
// memoryFill / memoryCopy delegate to the standard library — Go's slice
// builtins are far faster than a byte loop and propagate the same
// out-of-bounds trap shape (via runtime panic) that the spec demands.

// memoryInit implements memory.init: copy n bytes from passive data segment
// seg at src into memory at dst. Out-of-bounds on either side traps, as does
// naming a dropped (or active) segment with n > 0. The bounds check consults
// memSize (not len(m.M)) so a shared memory's reserved-but-ungrown tail stays
// out of reach, mirroring memoryFill/memoryCopy.
//
//go:noinline
func memoryInit(m *Module, seg int, dst int32, src int32, n int32) {
	data := m.dataSegs[seg]
	if n == 0 {
		return
	}
	if data == nil ||
		uint64(uint32(src))+uint64(uint32(n)) > uint64(len(data)) ||
		uint64(uint32(dst))+uint64(uint32(n)) > m.memSize.Load() {
		wasm_trap_meminit_oob()
	}
	// Record where the data segments land. The END of that region is where BSS
	// begins, and an embedding sharing an initialized memory image has to know
	// it: the image may carry the data segments (identical everywhere) but must
	// NOT carry BSS (the start section's "already ran" flag and the C++ static
	// state — inheriting either is fatal). The offsets are only known here, at
	// the memory.init that installs them.
	if end := uint32(dst) + uint32(n); end > m.dataEnd {
		m.dataEnd = end
	}
	d := m.memory[uint32(dst) : uint32(dst)+uint32(n)]
	s := data[uint32(src) : uint32(src)+uint32(n)]
	// Write only what differs. An embedding may hand New a linear memory that
	// ALREADY holds this segment — a copy-on-write map of an image shared by
	// every instance (the data segments of a big engine run to tens of MB and
	// are identical everywhere). Copying identical bytes over it would fault a
	// private copy of every page and throw the sharing away; comparing only
	// reads, so the pages stay shared. When the memory is blank, as it is for
	// an ordinary instance, the compare fails immediately and this costs
	// nothing measurable against the copy that follows.
	if bytes.Equal(d, s) {
		return
	}
	copy(d, s)
}

// dataDrop implements data.drop: discard passive segment seg. A later
// memory.init naming it traps (nil view); double-drop is a no-op per spec.
// dataDrop stays out of line: inlined into a gcasm-transformed function, the
// pointer write (a nil store into dataSegs) would drag runtime.gcWriteBarrier
// into the asm body, which the transformer rejects.
//
//go:noinline
func dataDrop(m *Module, seg int) {
	m.dataSegs[seg] = nil
}

func memoryFill(m *Module, dst int32, val int32, n int32) {
	if n == 0 {
		return
	}
	end := uint64(uint32(dst)) + uint64(uint32(n))
	if end > m.memSize.Load() {
		wasm_trap_memfill_oob()
	}
	b := m.memory[uint32(dst):uint32(end)]
	v := byte(val)
	// The compiler's range-fill-to-memclr rewrite fires only for a
	// CONSTANT zero — `b[k] = v` with a variable v stays a plain byte
	// loop (~1 byte/cycle). Dispatch the overwhelmingly common zero
	// fill (calloc paths) onto the constant form explicitly, and run
	// the rare non-zero fill at memmove speed by seeding one byte and
	// doubling with copy() — O(log n) memmoves instead of n stores.
	if v == 0 {
		for k := range b {
			b[k] = 0
		}
		return
	}
	b[0] = v
	for filled := 1; filled < len(b); filled *= 2 {
		copy(b[filled:], b[:filled])
	}
}

func memoryCopy(m *Module, dst int32, src int32, n int32) {
	if n == 0 {
		return
	}
	srcEnd := uint64(uint32(src)) + uint64(uint32(n))
	dstEnd := uint64(uint32(dst)) + uint64(uint32(n))
	if size := m.memSize.Load(); srcEnd > size || dstEnd > size {
		wasm_trap_memcopy_oob()
	}
	copy(m.memory[uint32(dst):uint32(dstEnd)], m.memory[uint32(src):uint32(srcEnd)])
}

// ----- Threads-proposal atomics ---------------------------------------------
//
// Module-aware helpers behind OpAtomicCall (helper(m, addr, offset, ...)).
// Effective addresses are computed in uint64 so base+offset cannot wrap;
// misalignment traps, as the proposal requires (unlike plain loads/stores,
// which tolerate it). 8/16-bit RMWs emulate subword atomicity with a CAS
// loop on the containing aligned 32-bit word — little-endian hosts only,
// which is every architecture wasm2go targets.

//go:noinline
func wasm_trap_atomic_oob() { panic("wasm: atomic access out of bounds") }

//go:noinline
func wasm_trap_atomic_unaligned() { panic("wasm: unaligned atomic access") }

//go:noinline
func wasm_trap_atomic_wait_forever() {
	panic("wasm: blocking atomic wait with no other agents (wasi-threads not enabled)")
}

// atomicEA bounds- and alignment-checks an atomic access and returns the
// effective address.
// Atomic and thread helpers are all //go:noinline: several take func-literal
// operands (the subword CAS loops, the RMW families), and if the compiler
// inlines such a helper into a gcasm-transformed generated function the
// closure becomes a cross-package symbol ("pN.FnX.AtomicRmwOr32.func4") the
// asm bundler cannot represent. Out-of-line, the closure stays homed in base.
//
//go:noinline
func atomicEA(m *Module, addr int32, offset int32, size uint64) uint64 {
	ea := uint64(uint32(addr)) + uint64(uint32(offset))
	// memSize, not len(m.memory): a shared memory's slice spans the whole
	// declared maximum from the start, so only memSize says how much of it
	// the guest may touch — and reading it atomically is what keeps growth
	// race-free without a lock on this path.
	if ea+size > m.memSize.Load() {
		wasm_trap_atomic_oob()
	}
	if ea&(size-1) != 0 {
		wasm_trap_atomic_unaligned()
	}
	return ea
}

//go:noinline
func atomicPtr32(m *Module, addr int32, offset int32) *uint32 {
	ea := atomicEA(m, addr, offset, 4)
	// atomicEA already bounds-checked ea against memSize, so index off the
	// raw base pointer to skip Go's redundant slice bounds check — the same
	// deal the plain load/store path gets. m.M tracks m.memory's data
	// pointer (New sets it; a shared memory never relocates, and the
	// non-shared reallocate path refreshes it).
	return (*uint32)(unsafe.Add(m.M, uintptr(ea)))
}

//go:noinline
func atomicPtr64(m *Module, addr int32, offset int32) *uint64 {
	ea := atomicEA(m, addr, offset, 8)
	return (*uint64)(unsafe.Add(m.M, uintptr(ea)))
}

// atomicsContended reports whether more than the main agent can touch the
// memory — i.e. at least one wasi thread has been spawned. Until that happens
// the engine's own atomic ops (interrupt-flag reads, GC bookkeeping) have no
// peer to race, so store/RMW helpers take an ordinary read-modify-write
// instead of a LOCKed one. The 0->1 transition happens inside threadSpawn on
// the sole agent, and the `go` statement that starts the child publishes
// every prior non-atomic write to it, so the fast path is race-free.
func atomicsContended(m *Module) bool {
	return m.threads != nil && m.threads.nextTID.Load() != 0
}

// atomicSubword32 runs op on the byte lanes [shift, shift+bits) of the
// aligned 32-bit word containing ea, via a CAS loop; returns the OLD lane
// value zero-extended. Little-endian lane math.
//
//go:noinline
func atomicSubword32(m *Module, ea uint64, bits uint, op func(old uint32) uint32) uint32 {
	word := (*uint32)(unsafe.Add(m.M, uintptr(ea&^3)))
	shift := uint(ea&3) * 8
	mask := uint32(1)<<bits - 1
	if !atomicsContended(m) {
		cur := *word
		lane := (cur >> shift) & mask
		*word = (cur &^ (mask << shift)) | ((op(lane) & mask) << shift)
		return lane
	}
	for {
		cur := atomic.LoadUint32(word)
		lane := (cur >> shift) & mask
		next := (cur &^ (mask << shift)) | ((op(lane) & mask) << shift)
		if atomic.CompareAndSwapUint32(word, cur, next) {
			return lane
		}
	}
}

//go:noinline
func atomicLoad32(m *Module, addr int32, offset int32) int32 {
	return int32(atomic.LoadUint32(atomicPtr32(m, addr, offset)))
}

//go:noinline
func atomicLoad64(m *Module, addr int32, offset int32) int64 {
	return int64(atomic.LoadUint64(atomicPtr64(m, addr, offset)))
}

//go:noinline
func atomicLoad32_8u(m *Module, addr int32, offset int32) int32 {
	ea := atomicEA(m, addr, offset, 1)
	return int32(atomicSubword32(m, ea, 8, func(old uint32) uint32 { return old }))
}

//go:noinline
func atomicLoad32_16u(m *Module, addr int32, offset int32) int32 {
	ea := atomicEA(m, addr, offset, 2)
	return int32(atomicSubword32(m, ea, 16, func(old uint32) uint32 { return old }))
}

//go:noinline
func atomicLoad64_8u(m *Module, addr int32, offset int32) int64 {
	ea := atomicEA(m, addr, offset, 1)
	return int64(atomicSubword32(m, ea, 8, func(old uint32) uint32 { return old }))
}

//go:noinline
func atomicLoad64_16u(m *Module, addr int32, offset int32) int64 {
	ea := atomicEA(m, addr, offset, 2)
	return int64(atomicSubword32(m, ea, 16, func(old uint32) uint32 { return old }))
}

//go:noinline
func atomicLoad64_32u(m *Module, addr int32, offset int32) int64 {
	return int64(atomic.LoadUint32(atomicPtr32(m, addr, offset)))
}

//go:noinline
func atomicStore32(m *Module, addr int32, offset int32, v int32) int32 {
	p := atomicPtr32(m, addr, offset)
	if atomicsContended(m) {
		atomic.StoreUint32(p, uint32(v))
	} else {
		*p = uint32(v)
	}
	return 0
}

//go:noinline
func atomicStore64(m *Module, addr int32, offset int32, v int64) int32 {
	p := atomicPtr64(m, addr, offset)
	if atomicsContended(m) {
		atomic.StoreUint64(p, uint64(v))
	} else {
		*p = uint64(v)
	}
	return 0
}

//go:noinline
func atomicStore32_8(m *Module, addr int32, offset int32, v int32) int32 {
	ea := atomicEA(m, addr, offset, 1)
	atomicSubword32(m, ea, 8, func(uint32) uint32 { return uint32(v) })
	return 0
}

//go:noinline
func atomicStore32_16(m *Module, addr int32, offset int32, v int32) int32 {
	ea := atomicEA(m, addr, offset, 2)
	atomicSubword32(m, ea, 16, func(uint32) uint32 { return uint32(v) })
	return 0
}

//go:noinline
func atomicStore64_8(m *Module, addr int32, offset int32, v int64) int32 {
	ea := atomicEA(m, addr, offset, 1)
	atomicSubword32(m, ea, 8, func(uint32) uint32 { return uint32(v) })
	return 0
}

//go:noinline
func atomicStore64_16(m *Module, addr int32, offset int32, v int64) int32 {
	ea := atomicEA(m, addr, offset, 2)
	atomicSubword32(m, ea, 16, func(uint32) uint32 { return uint32(v) })
	return 0
}

//go:noinline
func atomicStore64_32(m *Module, addr int32, offset int32, v int64) int32 {
	p := atomicPtr32(m, addr, offset)
	if atomicsContended(m) {
		atomic.StoreUint32(p, uint32(v))
	} else {
		*p = uint32(v)
	}
	return 0
}

//go:noinline
func atomicRmw32(m *Module, addr int32, offset int32, op func(old uint32) uint32) int32 {
	p := atomicPtr32(m, addr, offset)
	if !atomicsContended(m) {
		cur := *p
		*p = op(cur)
		return int32(cur)
	}
	for {
		cur := atomic.LoadUint32(p)
		if atomic.CompareAndSwapUint32(p, cur, op(cur)) {
			return int32(cur)
		}
	}
}

//go:noinline
func atomicRmw64(m *Module, addr int32, offset int32, op func(old uint64) uint64) int64 {
	p := atomicPtr64(m, addr, offset)
	if !atomicsContended(m) {
		cur := *p
		*p = op(cur)
		return int64(cur)
	}
	for {
		cur := atomic.LoadUint64(p)
		if atomic.CompareAndSwapUint64(p, cur, op(cur)) {
			return int64(cur)
		}
	}
}

//go:noinline
func atomicRmwAdd32(m *Module, addr, offset, v int32) int32 {
	p := atomicPtr32(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = old + uint32(v)
		return int32(old)
	}
	return int32(atomic.AddUint32(p, uint32(v)) - uint32(v))
}

//go:noinline
func atomicRmwSub32(m *Module, addr, offset, v int32) int32 {
	p := atomicPtr32(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = old - uint32(v)
		return int32(old)
	}
	return int32(atomic.AddUint32(p, -uint32(v)) + uint32(v))
}

//go:noinline
func atomicRmwAnd32(m *Module, addr, offset, v int32) int32 {
	return atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o & uint32(v) })
}

//go:noinline
func atomicRmwOr32(m *Module, addr, offset, v int32) int32 {
	return atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o | uint32(v) })
}

//go:noinline
func atomicRmwXor32(m *Module, addr, offset, v int32) int32 {
	return atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o ^ uint32(v) })
}

//go:noinline
func atomicRmwXchg32(m *Module, addr, offset, v int32) int32 {
	p := atomicPtr32(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = uint32(v)
		return int32(old)
	}
	return int32(atomic.SwapUint32(p, uint32(v)))
}

//go:noinline
func atomicRmwCmpxchg32(m *Module, addr, offset, expected, replacement int32) int32 {
	p := atomicPtr32(m, addr, offset)
	if !atomicsContended(m) {
		cur := *p
		if cur == uint32(expected) {
			*p = uint32(replacement)
		}
		return int32(cur)
	}
	for {
		cur := atomic.LoadUint32(p)
		if cur != uint32(expected) {
			return int32(cur)
		}
		if atomic.CompareAndSwapUint32(p, cur, uint32(replacement)) {
			return int32(cur)
		}
	}
}

//go:noinline
func atomicRmwAdd64(m *Module, addr, offset int32, v int64) int64 {
	p := atomicPtr64(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = old + uint64(v)
		return int64(old)
	}
	return int64(atomic.AddUint64(p, uint64(v)) - uint64(v))
}

//go:noinline
func atomicRmwSub64(m *Module, addr, offset int32, v int64) int64 {
	p := atomicPtr64(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = old - uint64(v)
		return int64(old)
	}
	return int64(atomic.AddUint64(p, -uint64(v)) + uint64(v))
}

//go:noinline
func atomicRmwAnd64(m *Module, addr, offset int32, v int64) int64 {
	return atomicRmw64(m, addr, offset, func(o uint64) uint64 { return o & uint64(v) })
}

//go:noinline
func atomicRmwOr64(m *Module, addr, offset int32, v int64) int64 {
	return atomicRmw64(m, addr, offset, func(o uint64) uint64 { return o | uint64(v) })
}

//go:noinline
func atomicRmwXor64(m *Module, addr, offset int32, v int64) int64 {
	return atomicRmw64(m, addr, offset, func(o uint64) uint64 { return o ^ uint64(v) })
}

//go:noinline
func atomicRmwXchg64(m *Module, addr, offset int32, v int64) int64 {
	p := atomicPtr64(m, addr, offset)
	if !atomicsContended(m) {
		old := *p
		*p = uint64(v)
		return int64(old)
	}
	return int64(atomic.SwapUint64(p, uint64(v)))
}

//go:noinline
func atomicRmwCmpxchg64(m *Module, addr, offset int32, expected, replacement int64) int64 {
	p := atomicPtr64(m, addr, offset)
	if !atomicsContended(m) {
		cur := *p
		if cur == uint64(expected) {
			*p = uint64(replacement)
		}
		return int64(cur)
	}
	for {
		cur := atomic.LoadUint64(p)
		if cur != uint64(expected) {
			return int64(cur)
		}
		if atomic.CompareAndSwapUint64(p, cur, uint64(replacement)) {
			return int64(cur)
		}
	}
}

//go:noinline
func atomicRmwSubword(m *Module, addr, offset int32, size uint64, bits uint, op func(old uint32) uint32) uint32 {
	ea := atomicEA(m, addr, offset, size)
	return atomicSubword32(m, ea, bits, op)
}

//go:noinline
func atomicRmwAdd32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o + uint32(v) }))
}

//go:noinline
func atomicRmwAdd32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o + uint32(v) }))
}

//go:noinline
func atomicRmwSub32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o - uint32(v) }))
}

//go:noinline
func atomicRmwSub32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o - uint32(v) }))
}

//go:noinline
func atomicRmwAnd32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o & uint32(v) }))
}

//go:noinline
func atomicRmwAnd32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o & uint32(v) }))
}

//go:noinline
func atomicRmwOr32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o | uint32(v) }))
}

//go:noinline
func atomicRmwOr32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o | uint32(v) }))
}

//go:noinline
func atomicRmwXor32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o ^ uint32(v) }))
}

//go:noinline
func atomicRmwXor32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o ^ uint32(v) }))
}

//go:noinline
func atomicRmwXchg32_8u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 1, 8, func(uint32) uint32 { return uint32(v) }))
}

//go:noinline
func atomicRmwXchg32_16u(m *Module, addr, offset, v int32) int32 {
	return int32(atomicRmwSubword(m, addr, offset, 2, 16, func(uint32) uint32 { return uint32(v) }))
}

//go:noinline
func atomicCmpxchgSubword(m *Module, addr, offset int32, size uint64, bits uint, expected, replacement uint32) uint32 {
	ea := atomicEA(m, addr, offset, size)
	word := (*uint32)(unsafe.Pointer(&m.memory[ea&^3]))
	shift := uint(ea&3) * 8
	mask := uint32(1)<<bits - 1
	for {
		cur := atomic.LoadUint32(word)
		lane := (cur >> shift) & mask
		if lane != expected&mask {
			return lane
		}
		next := (cur &^ (mask << shift)) | ((replacement & mask) << shift)
		if atomic.CompareAndSwapUint32(word, cur, next) {
			return lane
		}
	}
}

//go:noinline
func atomicRmwCmpxchg32_8u(m *Module, addr, offset, expected, replacement int32) int32 {
	return int32(atomicCmpxchgSubword(m, addr, offset, 1, 8, uint32(expected), uint32(replacement)))
}

//go:noinline
func atomicRmwCmpxchg32_16u(m *Module, addr, offset, expected, replacement int32) int32 {
	return int32(atomicCmpxchgSubword(m, addr, offset, 2, 16, uint32(expected), uint32(replacement)))
}

//go:noinline
func atomicRmwAdd64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o + uint32(v) }))
}

//go:noinline
func atomicRmwAdd64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o + uint32(v) }))
}

//go:noinline
func atomicRmwAdd64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomic.AddUint32(atomicPtr32(m, addr, offset), uint32(v)) - uint32(v))
}

//go:noinline
func atomicRmwSub64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o - uint32(v) }))
}

//go:noinline
func atomicRmwSub64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o - uint32(v) }))
}

//go:noinline
func atomicRmwSub64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomic.AddUint32(atomicPtr32(m, addr, offset), -uint32(v)) + uint32(v))
}

//go:noinline
func atomicRmwAnd64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o & uint32(v) }))
}

//go:noinline
func atomicRmwAnd64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o & uint32(v) }))
}

//go:noinline
func atomicRmwAnd64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o & uint32(v) })) & 0xffffffff
}

//go:noinline
func atomicRmwOr64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o | uint32(v) }))
}

//go:noinline
func atomicRmwOr64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o | uint32(v) }))
}

//go:noinline
func atomicRmwOr64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o | uint32(v) })) & 0xffffffff
}

//go:noinline
func atomicRmwXor64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(o uint32) uint32 { return o ^ uint32(v) }))
}

//go:noinline
func atomicRmwXor64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(o uint32) uint32 { return o ^ uint32(v) }))
}

//go:noinline
func atomicRmwXor64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmw32(m, addr, offset, func(o uint32) uint32 { return o ^ uint32(v) })) & 0xffffffff
}

//go:noinline
func atomicRmwXchg64_8u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 1, 8, func(uint32) uint32 { return uint32(v) }))
}

//go:noinline
func atomicRmwXchg64_16u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomicRmwSubword(m, addr, offset, 2, 16, func(uint32) uint32 { return uint32(v) }))
}

//go:noinline
func atomicRmwXchg64_32u(m *Module, addr, offset int32, v int64) int64 {
	return int64(atomic.SwapUint32(atomicPtr32(m, addr, offset), uint32(v)))
}

//go:noinline
func atomicRmwCmpxchg64_8u(m *Module, addr, offset int32, expected, replacement int64) int64 {
	return int64(atomicCmpxchgSubword(m, addr, offset, 1, 8, uint32(expected), uint32(replacement)))
}

//go:noinline
func atomicRmwCmpxchg64_16u(m *Module, addr, offset int32, expected, replacement int64) int64 {
	return int64(atomicCmpxchgSubword(m, addr, offset, 2, 16, uint32(expected), uint32(replacement)))
}

//go:noinline
func atomicRmwCmpxchg64_32u(m *Module, addr, offset int32, expected, replacement int64) int64 {
	p := atomicPtr32(m, addr, offset)
	for {
		cur := atomic.LoadUint32(p)
		if cur != uint32(expected) {
			return int64(cur)
		}
		if atomic.CompareAndSwapUint32(p, cur, uint32(replacement)) {
			return int64(cur)
		}
	}
}

// atomicFence is a sequentially consistent full barrier. Locking any mutex
// provides one under the Go memory model, and memMu is always present.
//
//go:noinline
func atomicFence(m *Module) int32 {
	m.memMu.Lock()
	m.memMu.Unlock() //nolint:staticcheck // empty critical section IS the fence
	return 0
}

// atomicNotify wakes up to count agents waiting on the address and reports
// how many it woke (0 when none are parked, which is also the single-agent
// answer).
//
//go:noinline
func atomicNotify(m *Module, addr int32, offset int32, count int32) int32 {
	ea := atomicEA(m, addr, offset, 4)
	return m.threads.wake(ea, count)
}

// atomicWait32/64 implement memory.atomic.wait: compare-and-park. The compare
// happens under the parking-lot lock a notifier must also take, so a notify
// that lands between the compare and the park cannot be missed.
//
// Returns 0 = woken, 1 = not-equal, 2 = timed-out. A negative timeout means
// wait forever; with no other agent able to notify, that is a guaranteed
// deadlock, so it traps rather than hanging the process.
//
//go:noinline
func atomicWait32(m *Module, addr int32, offset int32, expected int32, timeout int64) int32 {
	ea := atomicEA(m, addr, offset, 4)
	p := (*uint32)(unsafe.Add(m.M, uintptr(ea)))
	return atomicWait(m, ea, timeout, func() bool {
		return int32(atomic.LoadUint32(p)) == expected
	})
}

//go:noinline
func atomicWait64(m *Module, addr int32, offset int32, expected int64, timeout int64) int32 {
	ea := atomicEA(m, addr, offset, 8)
	p := (*uint64)(unsafe.Add(m.M, uintptr(ea)))
	return atomicWait(m, ea, timeout, func() bool {
		return int64(atomic.LoadUint64(p)) == expected
	})
}

//go:noinline
func atomicWait(m *Module, ea uint64, timeout int64, stillEqual func() bool) int32 {
	if !m.memShared {
		// Waiting on a non-shared memory is a validation error upstream;
		// treat it as not-equal rather than parking forever.
		return 1
	}
	m.threads.parkMu.Lock()
	if !stillEqual() {
		m.threads.parkMu.Unlock()
		return 1
	}
	ch := make(chan struct{})
	if m.threads.parked == nil {
		m.threads.parked = make(map[uint64][]chan struct{})
	}
	m.threads.parked[ea] = append(m.threads.parked[ea], ch)
	m.threads.parkMu.Unlock()

	unpark := func() {
		m.threads.parkMu.Lock()
		defer m.threads.parkMu.Unlock()
		waiters := m.threads.parked[ea]
		for i, c := range waiters {
			if c == ch {
				m.threads.parked[ea] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		if len(m.threads.parked[ea]) == 0 {
			delete(m.threads.parked, ea)
		}
	}

	if timeout < 0 {
		if m.threads.nextTID.Load() == 0 {
			// Nobody else exists to notify us: an infinite wait here can
			// only deadlock. Trap loudly instead of hanging.
			unpark()
			wasm_trap_atomic_wait_forever()
		}
		<-ch
		return 0
	}
	// +1ms: a guest measures its own wait with millisecond-granularity clocks
	// (test262 asserts lapse >= timeout), so a timer that fires at exactly the
	// requested nanosecond can look EARLY once both ends truncate. Late by a
	// millisecond is spec-legal; early is not.
	timer := time.NewTimer(time.Duration(timeout) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-ch:
		return 0
	case <-timer.C:
		unpark()
		return 2
	}
}

// ----- wasi-threads ---------------------------------------------------------
//
// A wasm thread is a goroutine. wasi_thread_spawn hands the guest a TID and
// starts wasi_thread_start(tid, arg) — the entry wasi-libc exports — on a
// fresh goroutine; that entry sets up the thread's stack and TLS INSIDE
// linear memory (the guest allocated them before spawning), so the Go side
// owns nothing but the goroutine. Growth cannot relocate a shared memory
// (see memoryGrow), so every agent's cached m.M stays valid for its lifetime.
//
// threadPool stays deliberately small: a TID counter, a WaitGroup so a host
// can await quiescence, and the wait/notify parking lot — whose map is only
// allocated if an agent actually blocks.
type threadPool struct {
	nextTID atomic.Int32
	wg      sync.WaitGroup

	parkMu sync.Mutex
	parked map[uint64][]chan struct{}
}

// wake releases up to count waiters on ea and reports how many it woke.
func (p *threadPool) wake(ea uint64, count int32) int32 {
	p.parkMu.Lock()
	defer p.parkMu.Unlock()
	waiters := p.parked[ea]
	n := int32(len(waiters))
	if count >= 0 && count < n {
		n = count
	}
	for _, ch := range waiters[:n] {
		close(ch)
	}
	if int(n) == len(waiters) {
		delete(p.parked, ea)
	} else {
		p.parked[ea] = waiters[n:]
	}
	return n
}

// threadSpawn implements the wasi_thread_spawn import: run the guest's thread
// entry on a goroutine, return the new TID (negative means "cannot spawn").
//
//go:noinline
func threadSpawn(m *Module, arg int32) int32 {
	start := m.threadStart
	if start == nil {
		return -1 // module exports no wasi_thread_start: nothing to run
	}
	tid := m.threads.nextTID.Add(1)
	m.threads.wg.Add(1)
	// The agent runs on a struct COPY: same memory (the slice header is
	// immutable for a shared memory), same pointered shared state
	// (memSize/memMu/threads/host imports), but its OWN globals — the wasm
	// threads model in one assignment. wasi_thread_start's first act is to
	// point the clone's stack-pointer global at the stack pthread_create
	// malloc'ed inside the shared memory.
	child := new(Module)
	*child = *m
	go func() {
		defer m.threads.wg.Done()
		// A trap on any wasm thread traps the whole instance (wasi-threads
		// semantics): surface WHERE it happened, then let it take the
		// process down instead of silently unwinding the goroutine.
		defer func() {
			if r := recover(); r != nil {
				println("wasm2go: wasi thread", tid, "trapped:")
				switch v := r.(type) {
				case error:
					println("  ", v.Error())
				case string:
					println("  ", v)
				}
				panic(r)
			}
		}()
		start(child, tid, arg)
	}()
	return tid
}

// ThreadsWait blocks until every spawned agent has returned. Hosts call it
// before tearing an instance down; the guest never sees it.
//
//go:noinline
func ThreadsWait(m *Module) { m.threads.wg.Wait() }

// ----- SIMD (v128) helpers ------------------------------------------------
//
// A v128 value is a [2]uint64: word 0 holds lanes 0-7 with byte lane 0 in
// its least-significant byte, word 1 holds lanes 8-15 — wasm's little-endian
// lane order. These are scalar reference implementations of the SIMD
// proposal's semantics (saturation, NaN propagation, round-to-even, lane
// masking of shift counts); the per-lane loops are deliberately simple and
// branch-free where the spec allows. All entry points are //go:noinline so
// the captured-asm backend sees plain calls it can keep (or fall back on)
// instead of inlined bodies.

//go:noinline
func wasm_trap_simd_oob() { panic("wasm: v128 memory access out of bounds") }

// gcasmMemProbe anchors the Module field offsets the gcasm memory-op
// splices hardcode. The splices read m.M and m.memSize straight off the
// receiver in generated assembly, and the offsets of those fields
// depend on the module (the import-interface fields between them vary).
// Rather than re-deriving Go's struct layout, gcasm extracts the two
// offsets from THIS function's captured assembly — two loads off R0/AX,
// M first — so they always come from the same compile that produced the
// code being spliced. Never called at run time.
//
//go:noinline
func gcasmMemProbe(m *Module) (unsafe.Pointer, *atomic.Uint64) {
	return m.M, m.memSize
}

func simdEA(m *Module, addr int32, offset int32, size uint64) uint64 {
	// Same shape as atomicEA, minus the alignment trap: SIMD memory access
	// is alignment-hint-only, never trapping on misalignment.
	ea := uint64(uint32(addr)) + uint64(uint32(offset))
	if ea+size > m.memSize.Load() {
		wasm_trap_simd_oob()
	}
	return ea
}

// Lane converters. Each returns lanes in index order (lane 0 first).

// simd_v128_load_rng is the range-checked first load of a coalesced
// group (pass.CoalesceSimdBounds): one trap decision covers every
// access in [addr+rlo, addr+rlo+span), then it loads at its own
// addr+offset. The group's other loads use the unchecked _nc form
// below — which is only sound BECAUSE this ran first; nothing else may
// emit either form.
//
// rlo is SIGNED: the group minimum may lie below this load's own
// address when the group's loads appear out of address order, and when
// a member's u32 address arithmetic wrapped, addr+rlo can go negative
// — a negative start means some member sits just below 2^32 unwrapped,
// which the per-load checks would have trapped (memSize can never
// reach 2^32: memoryGrow stops at wasmMemHardCap), so trapping on
// start < 0 reproduces the original semantics exactly.
//
//go:noinline
func simd_v128_load_rng(m *Module, addr int32, offset int32, rlo int32, span int32) [2]uint64 {
	start := int64(uint64(uint32(addr))) + int64(rlo)
	if start < 0 || uint64(start)+uint64(uint32(span)) > m.memSize.Load() {
		wasm_trap_simd_oob()
	}
	ea := uint64(uint32(addr)) + uint64(uint32(offset))
	p := unsafe.Add(m.M, uintptr(ea))
	return [2]uint64{*(*uint64)(p), *(*uint64)(unsafe.Add(p, 8))}
}

// simd_v128_load_nc is simd_v128_load minus the bounds check; emitted
// only by the bounds-coalescing pass, always behind a covering
// simd_v128_load_rng.
//
//go:noinline
func simd_v128_load_nc(m *Module, addr int32, offset int32) [2]uint64 {
	ea := uint64(uint32(addr)) + uint64(uint32(offset))
	p := unsafe.Add(m.M, uintptr(ea))
	return [2]uint64{*(*uint64)(p), *(*uint64)(unsafe.Add(p, 8))}
}

//go:noinline
func simd_v128_load(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 16)
	p := unsafe.Add(m.M, uintptr(ea))
	return [2]uint64{*(*uint64)(p), *(*uint64)(unsafe.Add(p, 8))}
}

// The simd_scalar_* helpers are the pure fallback bodies of the
// scalar-chain vocabulary inside fused regions (see internal/simdfuse):
// the per-block scale computations ggml kernels run between vector
// statements. The loads are UNCHECKED on purpose — they replace the
// emitter's own unchecked scalar derefs (`*(*uint16)(unsafe.Add(mBase,
// uint32(a)))`), whose safety rests on the same memoryGrow hard cap.
// The arithmetic wraps mod 2^32 exactly like the wasm ops it lowers.

//go:noinline
func simd_scalar_i32_load16_u(m *Module, addr int32) int32 {
	return int32(*(*uint16)(unsafe.Add(m.M, uintptr(uint32(addr)))))
}

//go:noinline
func simd_scalar_f32_load(m *Module, addr int32) float32 {
	return *(*float32)(unsafe.Add(m.M, uintptr(uint32(addr))))
}

//go:noinline
func simd_scalar_i32_shl(v int32, s int32) int32 { return v << (uint(s) % 32) }

//go:noinline
func simd_scalar_i32_add(a int32, b int32) int32 { return a + b }

//go:noinline
func simd_scalar_f32_mul(a float32, b float32) float32 { return a * b }

//go:noinline
func simd_v128_f16x4_cvt_store(m *Module, addr int32, offset int32, v [2]uint64) int32 {
	// Convert four f32 lanes to f16 with the software idiom's exact
	// semantics (the bias/multiply rounding chain; NaN forced to
	// sign|0x7E00 — the same contract as simd_f16x4_cvt_bits, inlined
	// so this helper carries no cross-file symbol dependency) and
	// store the packed 8-byte word.
	ea := simdEA(m, addr, offset, 8)
	var out uint64
	for i := 0; i < 4; i++ {
		w := uint32(v[i/2] >> (32 * uint(i) % 64))
		shl1w := w + w
		sign := w & 0x80000000
		var h uint32
		if shl1w > 0xFF000000 { // NaN
			h = (sign >> 16) | 0x7E00
		} else {
			bias := shl1w & 0xFF000000
			if bias < 0x71000000 {
				bias = 0x71000000
			}
			f := math.Float32frombits(w&0x7FFFFFFF) * 0x1p+112 * 0x1p-110
			f += math.Float32frombits((bias >> 1) + 0x07800000)
			fbits := math.Float32bits(f)
			h = (sign >> 16) | (fbits>>13)&0x7C00 + fbits&0xFFF
		}
		out |= uint64(uint16(h)) << (16 * uint(i))
	}
	*(*uint64)(unsafe.Add(m.M, uintptr(ea))) = out
	return 0
}

//go:noinline
func simd_v128_store(m *Module, addr int32, offset int32, v [2]uint64) int32 {
	ea := simdEA(m, addr, offset, 16)
	p := unsafe.Add(m.M, uintptr(ea))
	*(*uint64)(p) = v[0]
	*(*uint64)(unsafe.Add(p, 8)) = v[1]
	return 0
}

//go:noinline
func simd_v128_load8x8_s(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 8; i++ {
		x := *(*uint8)(unsafe.Add(p, 1*i))
		out[i*16/64] |= uint64(uint16(int16(int8(x)))) << (16 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load8x8_u(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 8; i++ {
		x := *(*uint8)(unsafe.Add(p, 1*i))
		out[i*16/64] |= uint64(uint16(x)) << (16 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load16x4_s(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 4; i++ {
		x := *(*uint16)(unsafe.Add(p, 2*i))
		out[i*32/64] |= uint64(uint32(int32(int16(x)))) << (32 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load16x4_u(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 4; i++ {
		x := *(*uint16)(unsafe.Add(p, 2*i))
		out[i*32/64] |= uint64(uint32(x)) << (32 * uint(i) % 64)
	}
	return out
}

// f16BitsToF32Bits is the IEEE binary16 -> binary32 conversion,
// bit-exact including subnormals, infinities and NaN payloads.
func f16BitsToF32Bits(h uint16) uint32 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1F
	man := uint32(h) & 0x3FF
	switch exp {
	case 0:
		if man == 0 {
			return sign
		}
		e := uint32(113)
		for man&0x400 == 0 {
			man <<= 1
			e--
		}
		return sign | e<<23 | (man&0x3FF)<<13
	case 0x1F:
		return sign | 0xFF<<23 | man<<13
	}
	return sign | (exp+112)<<23 | man<<13
}

// simd_f16x4_cvt converts four f16 values (widened to the low 16 bits
// of each i32x4 lane, the v128_load16x4_u result shape) to f32 lanes.
// Emitted only after the transpiler verified the module's conversion
// table is the IEEE map, so this computed conversion is bit-identical
// to the table reads it replaces (and to XTN+FCVTL on arm64).
//
//go:noinline
func simd_f16x4_cvt(v [2]uint64) [2]uint64 {
	var out [2]uint64
	for i := 0; i < 4; i++ {
		bits := uint16(v[i/2] >> (32 * uint(i) % 64))
		out[i/2] |= uint64(f16BitsToF32Bits(bits)) << (32 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load32x2_s(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 2; i++ {
		x := *(*uint32)(unsafe.Add(p, 4*i))
		out[i*64/64] |= uint64(uint64(int64(int32(x)))) << (64 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load32x2_u(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	p := unsafe.Add(m.M, uintptr(ea))
	var out [2]uint64
	for i := 0; i < 2; i++ {
		x := *(*uint32)(unsafe.Add(p, 4*i))
		out[i*64/64] |= uint64(uint64(x)) << (64 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load8_splat(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 1)
	x := *(*uint8)(unsafe.Add(m.M, uintptr(ea)))
	var out [2]uint64
	for i := 0; i < 16; i++ {
		out[i*8/64] |= uint64(x) << (8 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load16_splat(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 2)
	x := *(*uint16)(unsafe.Add(m.M, uintptr(ea)))
	var out [2]uint64
	for i := 0; i < 8; i++ {
		out[i*16/64] |= uint64(x) << (16 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load32_splat(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 4)
	x := *(*uint32)(unsafe.Add(m.M, uintptr(ea)))
	var out [2]uint64
	for i := 0; i < 4; i++ {
		out[i*32/64] |= uint64(x) << (32 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load64_splat(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	x := *(*uint64)(unsafe.Add(m.M, uintptr(ea)))
	var out [2]uint64
	for i := 0; i < 2; i++ {
		out[i*64/64] |= uint64(x) << (64 * uint(i) % 64)
	}
	return out
}

//go:noinline
func simd_v128_load32_zero(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 4)
	return [2]uint64{uint64(*(*uint32)(unsafe.Add(m.M, uintptr(ea)))), 0}
}

//go:noinline
func simd_v128_load64_zero(m *Module, addr int32, offset int32) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	return [2]uint64{*(*uint64)(unsafe.Add(m.M, uintptr(ea))), 0}
}

//go:noinline
func simd_v128_load8_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) [2]uint64 {
	ea := simdEA(m, addr, offset, 1)
	x := *(*uint8)(unsafe.Add(m.M, uintptr(ea)))
	sh := 8 * uint(lane) % 64
	i := int(lane) * 8 / 64
	v[i] = v[i]&^(uint64(uint8(^uint8(0)))<<sh) | uint64(x)<<sh
	return v
}

//go:noinline
func simd_v128_load16_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) [2]uint64 {
	ea := simdEA(m, addr, offset, 2)
	x := *(*uint16)(unsafe.Add(m.M, uintptr(ea)))
	sh := 16 * uint(lane) % 64
	i := int(lane) * 16 / 64
	v[i] = v[i]&^(uint64(uint16(^uint16(0)))<<sh) | uint64(x)<<sh
	return v
}

//go:noinline
func simd_v128_load32_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) [2]uint64 {
	ea := simdEA(m, addr, offset, 4)
	x := *(*uint32)(unsafe.Add(m.M, uintptr(ea)))
	sh := 32 * uint(lane) % 64
	i := int(lane) * 32 / 64
	v[i] = v[i]&^(uint64(uint32(^uint32(0)))<<sh) | uint64(x)<<sh
	return v
}

//go:noinline
func simd_v128_load64_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) [2]uint64 {
	ea := simdEA(m, addr, offset, 8)
	x := *(*uint64)(unsafe.Add(m.M, uintptr(ea)))
	sh := 64 * uint(lane) % 64
	i := int(lane) * 64 / 64
	v[i] = v[i]&^(uint64(uint64(^uint64(0)))<<sh) | uint64(x)<<sh
	return v
}

//go:noinline
func simd_v128_store8_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) int32 {
	ea := simdEA(m, addr, offset, 1)
	x := uint8(v[int(lane)*8/64] >> (8 * uint(lane) % 64))
	*(*uint8)(unsafe.Add(m.M, uintptr(ea))) = x
	return 0
}

//go:noinline
func simd_v128_store16_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) int32 {
	ea := simdEA(m, addr, offset, 2)
	x := uint16(v[int(lane)*16/64] >> (16 * uint(lane) % 64))
	*(*uint16)(unsafe.Add(m.M, uintptr(ea))) = x
	return 0
}

//go:noinline
func simd_v128_store32_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) int32 {
	ea := simdEA(m, addr, offset, 4)
	x := uint32(v[int(lane)*32/64] >> (32 * uint(lane) % 64))
	*(*uint32)(unsafe.Add(m.M, uintptr(ea))) = x
	return 0
}

//go:noinline
func simd_v128_store64_lane(m *Module, addr int32, offset int32, lane int32, v [2]uint64) int32 {
	ea := simdEA(m, addr, offset, 8)
	x := uint64(v[int(lane)*64/64] >> (64 * uint(lane) % 64))
	*(*uint64)(unsafe.Add(m.M, uintptr(ea))) = x
	return 0
}

// Scalar-pair forms of the SIMD memory helpers, mirroring the pure
// ops' simd_p_* wrappers in simd_pair.go: the scalarized emitter
// carries v128 values as two uint64 locals, which stay in registers
// where a [2]uint64 array would be stack-assigned. The gcasm
// backend splices these calls away; elsewhere they inline.

func simd_p_pack(lo, hi uint64) [2]uint64 { return [2]uint64{lo, hi} }

//go:noinline
func simd_p_v128_load_rng(m *Module, addr int32, offset int32, rlo int32, span int32) (uint64, uint64) {
	r := simd_v128_load_rng(m, addr, offset, rlo, span)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load_nc(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load_nc(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load8x8_s(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load8x8_s(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load8x8_u(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load8x8_u(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load16x4_s(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load16x4_s(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load16x4_u(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load16x4_u(m, addr, offset)
	return r[0], r[1]
}

// Referenced only from generated bundle code; the blank use keeps
// the analyzer quiet.
var _ = simd_p_f16x4_cvt

// The packed f16 store conversion is referenced by generated code
// only; keep the template pair alive for the in-package linter.
var (
	_ = simd_v128_f16x4_cvt_store
	_ = simd_p_v128_f16x4_cvt_store
)

//go:noinline
func simd_p_f16x4_cvt(lo uint64, hi uint64) (uint64, uint64) {
	r := simd_f16x4_cvt([2]uint64{lo, hi})
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load32x2_s(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load32x2_s(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load32x2_u(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load32x2_u(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load8_splat(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load8_splat(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load16_splat(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load16_splat(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load32_splat(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load32_splat(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load64_splat(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load64_splat(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load32_zero(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load32_zero(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load64_zero(m *Module, addr int32, offset int32) (uint64, uint64) {
	r := simd_v128_load64_zero(m, addr, offset)
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load8_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) (uint64, uint64) {
	r := simd_v128_load8_lane(m, addr, offset, lane, [2]uint64{v0, v1})
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load16_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) (uint64, uint64) {
	r := simd_v128_load16_lane(m, addr, offset, lane, [2]uint64{v0, v1})
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load32_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) (uint64, uint64) {
	r := simd_v128_load32_lane(m, addr, offset, lane, [2]uint64{v0, v1})
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_load64_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) (uint64, uint64) {
	r := simd_v128_load64_lane(m, addr, offset, lane, [2]uint64{v0, v1})
	return r[0], r[1]
}

//go:noinline
func simd_p_v128_store(m *Module, addr int32, offset int32, v0, v1 uint64) int32 {
	return simd_v128_store(m, addr, offset, [2]uint64{v0, v1})
}

//go:noinline
func simd_p_v128_f16x4_cvt_store(m *Module, addr int32, offset int32, v0, v1 uint64) int32 {
	return simd_v128_f16x4_cvt_store(m, addr, offset, [2]uint64{v0, v1})
}

//go:noinline
func simd_p_v128_store8_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) int32 {
	return simd_v128_store8_lane(m, addr, offset, lane, [2]uint64{v0, v1})
}

//go:noinline
func simd_p_v128_store16_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) int32 {
	return simd_v128_store16_lane(m, addr, offset, lane, [2]uint64{v0, v1})
}

//go:noinline
func simd_p_v128_store32_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) int32 {
	return simd_v128_store32_lane(m, addr, offset, lane, [2]uint64{v0, v1})
}

//go:noinline
func simd_p_v128_store64_lane(m *Module, addr int32, offset int32, lane int32, v0, v1 uint64) int32 {
	return simd_v128_store64_lane(m, addr, offset, lane, [2]uint64{v0, v1})
}
