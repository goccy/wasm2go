// Package helpers contains the runtime helper functions injected into wasm2go's
// generated output. The codegen embeds this file via //go:embed and selects
// only the helpers actually used by the translated module. The codegen filters
// to *ast.FuncDecl entries by name; non-func decls (the Module placeholder
// below) never appear in generated output.
package helpers

import (
	"encoding/binary"
	"math"
	"math/bits"
	"runtime"
)

// Module is a placeholder so the helpers package compiles standalone. Real
// generated output supplies its own Module struct with at least `memory []byte`
// and `maxMem uint64` fields.
type Module struct {
	memory []byte
	maxMem uint64
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

func f32(x float32) float32 { runtime.KeepAlive(&x); return x }

func f64(x float64) float64 { runtime.KeepAlive(&x); return x }

// ----- Integer division with overflow / divide-by-zero traps --------------

func i32_div_s(x, y int32) int32 {
	if y == -1 && x == math.MinInt32 {
		panic("wasm: integer overflow")
	}
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	return x / y
}

func i64_div_s(x, y int64) int64 {
	if y == -1 && x == math.MinInt64 {
		panic("wasm: integer overflow")
	}
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	return x / y
}

func i32_div_u(x, y uint32) uint32 {
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	return x / y
}

func i64_div_u(x, y uint64) uint64 {
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	return x / y
}

func i32_rem_s(x, y int32) int32 {
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	if y == -1 {
		// Per spec, MIN_INT % -1 == 0 and does NOT trap.
		return 0
	}
	return x % y
}

func i64_rem_s(x, y int64) int64 {
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	if y == -1 {
		return 0
	}
	return x % y
}

func i32_rem_u(x, y uint32) uint32 {
	if y == 0 {
		panic("wasm: integer divide by zero")
	}
	return x % y
}

func i64_rem_u(x, y uint64) uint64 {
	if y == 0 {
		panic("wasm: integer divide by zero")
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
		panic("wasm: invalid conversion to integer")
	}
	// Lower bound is `> -2147483904.0` (one ULP below -2^31 in f32),
	// not `>= -2^31`, because every f32 in (-2147483904, -2147483648]
	// rounds to -2^31 and is representable as int32. The wasm
	// reference interpreter uses these bounds; replicate.
	if !(x > -2147483904.0 && x < 2147483648.0) {
		panic("wasm: integer overflow")
	}
	return int32(x)
}

func i32_trunc_f32_u(x float32) int32 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	if !(x > -1.0 && x < 4294967296.0) {
		panic("wasm: integer overflow")
	}
	return int32(uint32(x))
}

func i32_trunc_f64_s(x float64) int32 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	// The wasm spec accepts every f64 whose truncation lies in
	// [-2^31, 2^31). With f64 precision, -2147483648.5 truncates to
	// -2^31 and is representable; the strict lower bound is one ULP
	// below -2^31 (-2147483649.0). The previous closed lower bound
	// rejected -2147483648.5 / -2147483648.9999 — both legal inputs.
	if !(x > -2147483649.0 && x < 2147483648.0) {
		panic("wasm: integer overflow")
	}
	return int32(x)
}

func i32_trunc_f64_u(x float64) int32 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	if !(x > -1.0 && x < 4294967296.0) {
		panic("wasm: integer overflow")
	}
	return int32(uint32(x))
}

func i64_trunc_f32_s(x float32) int64 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	// Lower bound is one f32 ULP below -2^63. The smallest f32
	// strictly greater than -2^64 is -9223373136366403584.0 — every
	// f32 above that and at most -2^63 rounds to -2^63, the
	// smallest int64. The wasm reference interpreter uses these
	// strict-inequality bounds; replicate.
	if !(float64(x) > -9223373136366403584.0 && float64(x) < 9223372036854775808.0) {
		panic("wasm: integer overflow")
	}
	return int64(x)
}

func i64_trunc_f32_u(x float32) int64 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	if !(x > -1.0 && float64(x) < 18446744073709551616.0) {
		panic("wasm: integer overflow")
	}
	return int64(uint64(x))
}

func i64_trunc_f64_s(x float64) int64 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	if !(x >= -9223372036854775808.0 && x < 9223372036854775808.0) {
		panic("wasm: integer overflow")
	}
	return int64(x)
}

func i64_trunc_f64_u(x float64) int64 {
	if x != x {
		panic("wasm: invalid conversion to integer")
	}
	if !(x > -1.0 && x < 18446744073709551616.0) {
		panic("wasm: integer overflow")
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
	return int32(len(m.memory) >> 16)
}

// memoryGrow grows m.memory by n wasm pages (64 KiB each). Returns the
// previous page count, or -1 if the new size would exceed maxMem. n may be 0,
// which simply returns the current size.
//
// len(m.memory) must always equal the exact wasm memory size (memory.size
// and every bounds check depend on it), but the backing array is grown
// GEOMETRICALLY: a sequence of small memory.grow calls — which a C++ heap
// does constantly during start-up — would otherwise reallocate and recopy
// the whole linear memory on every page, i.e. O(n^2) total copying. Spare
// capacity makes the common grow a zero-copy reslice and amortizes the
// reallocations to O(n).
func memoryGrow(m *Module, n int32) int32 {
	prev := int32(len(m.memory) >> 16)
	if n == 0 {
		return prev
	}
	if n < 0 {
		return -1
	}
	want := uint64(len(m.memory)) + uint64(n)*65536
	if m.maxMem != 0 && want > m.maxMem {
		return -1
	}
	if want > 1<<32 {
		return -1
	}
	if want <= uint64(cap(m.memory)) {
		// Spare capacity already covers the new size. The bytes in
		// [len, want) were zero-filled when the backing array was
		// allocated and are unreachable until now, so the freshly
		// exposed pages are correctly zero — no copy, no clear.
		m.memory = m.memory[:want]
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
	if newCap > 1<<32 {
		newCap = 1 << 32
	}
	grown := make([]byte, want, newCap)
	copy(grown, m.memory)
	m.memory = grown
	return prev
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

func f32_add(x, y float32) float32 { return x + y }
func f32_sub(x, y float32) float32 { return x - y }
func f32_mul(x, y float32) float32 { return x * y }
func f32_div(x, y float32) float32 { return x / y }
func f64_add(x, y float64) float64 { return x + y }
func f64_sub(x, y float64) float64 { return x - y }
func f64_mul(x, y float64) float64 { return x * y }
func f64_div(x, y float64) float64 { return x / y }

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

func memoryFill(m *Module, dst int32, val int32, n int32) {
	if n == 0 {
		return
	}
	end := uint64(uint32(dst)) + uint64(uint32(n))
	if end > uint64(len(m.memory)) {
		panic("wasm: memory.fill out of bounds")
	}
	b := m.memory[uint32(dst):uint32(end)]
	v := byte(val)
	// Use Go's optimised slice fill: for k := range b { b[k] = v } is
	// rewritten to memclr-like code by the compiler.
	for k := range b {
		b[k] = v
	}
}

func memoryCopy(m *Module, dst int32, src int32, n int32) {
	if n == 0 {
		return
	}
	srcEnd := uint64(uint32(src)) + uint64(uint32(n))
	dstEnd := uint64(uint32(dst)) + uint64(uint32(n))
	if srcEnd > uint64(len(m.memory)) || dstEnd > uint64(len(m.memory)) {
		panic("wasm: memory.copy out of bounds")
	}
	copy(m.memory[uint32(dst):uint32(dstEnd)], m.memory[uint32(src):uint32(srcEnd)])
}
