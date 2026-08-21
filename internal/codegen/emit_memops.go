package codegen

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/goccy/wasm2go/internal/ssa"
)

// emit_memops.go renders wasm linear-memory load/store ops as an
// inline `unsafe.Pointer` expression instead of a per-access helper
// CALL.
//
// Background: the Go wasm linker rejects any function whose internal
// PC counter reaches 65536 with "function too big: %s exceeds 65536
// blocks" (cmd/internal/obj/wasm/wasmobj.go). On the wasm backend
// each emitted CALL increments PC, so a function with N memory
// accesses pays at least N PC if every access goes through a helper
// call. Helpers cannot be relied on to be inlined either: Go's mid-
// stack inliner declines to inline them inside very large callers
// (caller-size budget), so once a transpiled function gets big enough
// the helper-call form alone is enough to blow the PC cap.
//
// The inline form collapses an access to a single expression:
//
//	*(*T)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(m.Memory)), uintptr(uint32(base)+offset)))
//
// Every step is a Go compiler intrinsic — no CALL, no PC++. The
// shared slice header (m.Memory) is read fresh on every access so
// memory.grow reallocations between calls are picked up without any
// stale-pointer hazard.
//
// Bounds check
//
// The wasm spec traps on out-of-bounds memory access. We deliberately
// drop the runtime bounds check: by the time we reach Go-level
// codegen, the input wasm has already been validated and the source
// language has done its own bounds enforcement. An out-of-range
// address indicates a bug in the input wasm, not a normal trap path.
// With the check kept, even a per-function shared-panic-block form
// still leaves a non-trivial PC contribution per access; without it,
// access cost is zero.
//
// Entry points
//
// emitMemLoadExpr returns an ast.Expr suitable for both inline use
// and as the RHS of a hoisted `vN = ...` assignment (emit.ComputeHoist
// already force-hoists every OpLoad*, so loads always come out as
// assignments at their definition site).
//
// emitMemStoreStmt returns a single ast.Stmt — the RHS cast for
// narrowing stores (i32.store8 / i32.store16 / i64.store32 / ...)
// relies on emit.ComputeHoist having force-hoisted args[1] so the cast
// is a runtime conversion and Go's constant evaluator never sees
// the out-of-range literal.

// emitMemLoadExpr renders the read expression for an OpLoad* value.
//
//	full-width:        *(*T)(unsafe.Add(..., uintptr(uint32(base)+offset)))
//	with outer cast:   <outerCast>(*(*T)(unsafe.Add(...)))
//
// The outer cast handles wasm's sub-word sign- or zero-extension
// (i32.load8_u reads `uint8` and widens to `int32`, etc.).
func (em *ssaEmitter) emitMemLoadExpr(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	spec, ok := loadSpec(v)
	if !ok {
		return nil, fmt.Errorf("emitMemLoadExpr: not a load op: %v", v.Op)
	}
	baseExpr, err := emitExpr(v.Args[0])
	if err != nil {
		return nil, err
	}
	// Non-atomic loads are ordinary typed-pointer dereferences on every
	// module, shared or not. wasm gives non-atomic accesses hardware-like
	// coherence and the CPU keeps another agent's stores visible; only the
	// explicit atomic ops (lowered to OpAtomicCall helpers) need ordering.
	expr := em.unsafeDerefExpr(spec, baseExpr, uint64(v.AuxInt), v.Args[0])
	if spec.outerCast != "" {
		expr = &ast.CallExpr{Fun: newID(spec.outerCast), Args: []ast.Expr{expr}}
	}
	return expr, nil
}

// emitMemStoreStmt renders an OpStore* as one assignment statement:
//
//	*(*T)(unsafe.Add(...)) = val               // no cast (i32.store, i64.store, fN.store)
//	*(*T)(unsafe.Add(...)) = T(val)            // narrowing (i32.store8, i32.store16,
//	                                           //            i64.store32, i64.store16, i64.store8)
//
// Narrowing stores pick UNSIGNED elemTypes (uint8 / uint16 / uint32)
// to match the wasm spec's "store the low N bits" semantics, and
// rely on emit.ComputeHoist having force-hoisted args[1] so the cast
// operand is always a typed local variable. The constant-evaluator
// quirk `uint8(int32(255))` produces "constant 255 overflows int8" /
// "constant -1 overflows uint8" depending on choice of signedness;
// using a typed-variable operand sidesteps the check entirely.
func (em *ssaEmitter) emitMemStoreStmt(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Stmt, error) {
	spec, ok := storeSpec(v)
	if !ok {
		return nil, fmt.Errorf("emitMemStoreStmt: not a store op: %v", v.Op)
	}
	baseExpr, err := emitExpr(v.Args[0])
	if err != nil {
		return nil, err
	}
	valExpr, err := emitExpr(v.Args[1])
	if err != nil {
		return nil, err
	}
	dst := em.unsafeDerefExpr(spec, baseExpr, uint64(v.AuxInt), v.Args[0])
	rhs := valExpr
	if spec.elemType != spec.valSrcType {
		rhs = &ast.CallExpr{Fun: newID(spec.elemType), Args: []ast.Expr{valExpr}}
	}
	return &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{dst},
		Rhs: []ast.Expr{rhs},
	}, nil
}

// unsafeDerefExpr builds the typed-pointer dereference used as both
// the load source and the store destination:
//
//	*(*<elemType>)(unsafe.Add(m.M, <off>))
//
// m.M is the per-Module unsafe.Pointer cache populated by New() and
// kept current by memoryGrow's reallocate path. Reslice grows leave
// the underlying data pointer unchanged, so the cache stays valid
// across every memory.grow that fits in the existing capacity; only
// the rare reallocating grow refreshes m.M, and it does so atomically
// before returning to the caller. The result is one shared pointer
// every load/store can deref without any per-function prologue or
// per-call refresh statements.
//
// The <off> argument is passed to unsafe.Add directly — Add's signature
// is `Add(ptr Pointer, len IntegerType) Pointer` and the spec already
// performs the implicit uintptr conversion, so the caller does not need
// to wrap it. wasm i32 addresses are semantically unsigned 32-bit, so
// for runtime int32 SSA values we wrap in uint32(...) to prevent Go's
// sign-extension to uintptr on 64-bit hosts; positive untyped constants
// are passed bare.
//
// Registers "unsafe" with the translator so the generated file picks
// up the import.
func (em *ssaEmitter) unsafeDerefExpr(spec memOpSpec, baseExpr ast.Expr, offset uint64, baseVal *ssa.Value) ast.Expr {
	em.useImport("unsafe")
	added := &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Add")},
		Args: []ast.Expr{em.memBasePtrExpr(), em.memOffsetExpr(baseExpr, offset, baseVal)},
	}
	castFn := &ast.ParenExpr{X: &ast.StarExpr{X: newID(spec.elemType)}}
	cast := &ast.CallExpr{Fun: castFn, Args: []ast.Expr{added}}
	return &ast.StarExpr{X: cast}
}

// memBasePtrExpr returns the expression for the linear-memory base
// pointer at a load/store site. When the function hoisted the base
// (see emitFuncBody) this is the `mBase` LOCAL — which the Go
// compiler can keep in a register across unsafe stores, unlike the
// `m.M` FIELD it shadows, because a local whose address never
// escapes cannot be aliased by a store. Functions without memops
// (never reached here) and non-hoisted contexts fall back to the
// field read. See emitModuleStruct (where the M field is declared)
// and memoryGrow (where M is refreshed on reallocate) for the
// lifecycle.
func (em *ssaEmitter) memBasePtrExpr() ast.Expr {
	if em.memBaseHoisted {
		return newID(memBaseLocal)
	}
	return &ast.SelectorExpr{X: newID("m"), Sel: newID("M")}
}

// memOffsetExpr returns the integer offset passed to unsafe.Add. It
// elides redundant casts and routes large constant offsets through
// the package-level _consts table:
//
//   - A constant baseExpr emitted as int32(N) by emitConst is unwrapped:
//     small totals (< largeConstThreshold) become a bare untyped literal
//     `N+offset`; large totals are stored once in the file's _consts
//     table and emitted as `_consts[<idx>]`. The indirection forces a
//     runtime memory load, which the Go ARM64 backend resolves with
//     register-offset LDR — sidestepping the literal-pool reachability
//     failure that otherwise blows up very large transpiled functions.
//   - Values whose int32 representation has the high bit set keep the
//     uint32 wrap so the bit pattern survives Go's sign-extension to
//     uintptr (only applies on the inline literal path; table entries
//     already hold the full uintptr bit pattern).
//   - Runtime int32 baseExprs are wrapped in uint32(...) for the same
//     zero-extension guarantee.
func (em *ssaEmitter) memOffsetExpr(baseExpr ast.Expr, offset uint64, baseVal *ssa.Value) ast.Expr {
	if em.mem64 {
		return em.memOffsetExpr64(baseExpr, offset, baseVal)
	}
	n, ok := constInt32(baseExpr)
	if !ok {
		// The AST shape check misses a constant base that was HOISTED
		// into a local (usage ≥ 2 — e.g. an inlined callee whose
		// address parameter was a constant at the call site): baseExpr
		// is then just `vN`, but gc's own constant propagation sees
		// through the local and re-materialises the total as a huge
		// addressing-mode immediate, reproducing the exact literal-pool
		// failure the _consts table exists to prevent ("LDPSW ...:
		// constant is not in pool" on arm64). Detect constness on the
		// SSA value instead of the AST shape.
		if c := ssaConstBase(baseVal); c != nil {
			n = int32(c.AuxInt)
			ok = true
		}
	}
	if !ok {
		// baseExpr is not a compile-time int32 constant — fall back to
		// the runtime cast path with an explicit uint32 wrap so wasm's
		// unsigned-i32 address semantics survive Go's sign-extension
		// to uintptr.
		addr := ast.Expr(&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{baseExpr}})
		if offset != 0 {
			var off ast.Expr = uintLit(offset)
			// A large static offset added to a runtime index must NOT be
			// emitted as a bare immediate: the gc ARM64 backend fuses
			// adjacent f64 loads at a common base into an FLDPD (load-pair)
			// and bakes the offset into its immediate field, whose range
			// is tiny — a multi-MB offset then fails to assemble
			// ("constant is not in pool"). Routing the offset through the
			// _consts table forces a runtime memory load, so the backend
			// keeps the offset in a register (register-offset LDR) and no
			// out-of-range immediate is ever formed. uint32(...) preserves
			// the wasm unsigned-i32 wrap of the index+offset addition.
			if offset >= largeConstThreshold && em.t != nil {
				off = &ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{em.constsIndexExpr(offset)}}
			}
			addr = &ast.BinaryExpr{X: addr, Op: token.ADD, Y: off}
		}
		return addr
	}
	total := uint64(uint32(n)) + offset
	// Large positive offsets land in the table. Negative-int32
	// constants (high-bit-set unsigned addresses) ALWAYS go to the
	// table — they're always above the threshold once interpreted
	// as uint64, and the table entry stores the full pattern so we
	// don't need the uint32 wrap on the access site.
	if total >= largeConstThreshold && em.t != nil {
		return em.constsIndexExpr(total)
	}
	if n >= 0 {
		return uintLit(total)
	}
	return &ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{uintLit(total)}}
}

// memOffsetExpr64 is memOffsetExpr for a memory64 module: the address
// is a u64 and effective-address arithmetic is u64 (mod 2^64), so no
// 32-bit wrap is ever applied. Large constant totals still route
// through the _consts table for the same addressing-immediate reasons.
func (em *ssaEmitter) memOffsetExpr64(baseExpr ast.Expr, offset uint64, baseVal *ssa.Value) ast.Expr {
	if c := ssaConstBase64(baseVal); c != nil {
		total := uint64(c.AuxInt) + offset
		if total >= largeConstThreshold && em.t != nil {
			return em.constsIndexExpr(total)
		}
		return uintLit(total)
	}
	addr := ast.Expr(&ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{baseExpr}})
	if offset != 0 {
		var off ast.Expr = uintLit(offset)
		if offset >= largeConstThreshold && em.t != nil {
			off = &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{em.constsIndexExpr(offset)}}
		}
		addr = &ast.BinaryExpr{X: addr, Op: token.ADD, Y: off}
	}
	return addr
}

// ssaConstBase64 is ssaConstBase for i64 addresses.
func ssaConstBase64(v *ssa.Value) *ssa.Value {
	for v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 {
		v = v.Args[0]
	}
	if v != nil && v.Op == ssa.OpConst64 {
		return v
	}
	return nil
}

// ssaConstBase peels OpCopy chains and returns the OpConst32 value a
// memory-access base resolves to, or nil when the base is not a
// compile-time constant at the SSA level.
func ssaConstBase(v *ssa.Value) *ssa.Value {
	for v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 {
		v = v.Args[0]
	}
	if v != nil && v.Op == ssa.OpConst32 {
		return v
	}
	return nil
}

// constsIndexExpr returns `_consts[<idx>]` for the given constant
// value, registering it in the current file's table on first use.
func (em *ssaEmitter) constsIndexExpr(value uint64) ast.Expr {
	idx := em.t.useLargeConst(value)
	return &ast.IndexExpr{
		X:     newID("_consts"),
		Index: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(idx)},
	}
}

// constInt32 reports whether expr is a compile-time int32 constant
// in the form produced by goConstI32, i.e. `int32(N)` where N is a
// non-negative integer literal, and returns its value when it is.
//
// The (value, ok) shape is deliberate: "expression matches this
// pattern" is a binary classification, not a fallible operation, so
// the (value, ok) idiom (cf. `v, ok := m[k]`) is the right fit.
// Callers must inspect `ok` and route the !ok case explicitly.
//
// goConstI32 is the SSA emitter's only source of i32 constants used
// as memory addresses, so this is the only form the caller needs to
// recognise: every other expression returns (0, false) and the caller
// emits the runtime cast path.
//
// Negative-i32 constants are emitted as `int32(-N)` — an inner
// UnaryExpr around the BasicLit — and intentionally do not match
// here; they need the uint32 sign-extension wrap and so are handled
// by the runtime path.
//
// The `int32(N)` cast itself asserts at the Go-source level that N
// fits int32 (Go's compiler would reject the generated source
// otherwise). A literal that fails the int32 range parse therefore
// indicates an emitter bug, not a runtime input condition, and we
// panic rather than fall through silently.
func constInt32(expr ast.Expr) (int32, bool) {
	call, isCall := expr.(*ast.CallExpr)
	if !isCall {
		return 0, false
	}
	id, isIdent := call.Fun.(*ast.Ident)
	if !isIdent || id.Name != "int32" || len(call.Args) != 1 {
		return 0, false
	}
	lit, isLit := call.Args[0].(*ast.BasicLit)
	if !isLit || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.ParseInt(lit.Value, 0, 32)
	if err != nil {
		panic(fmt.Sprintf("constInt32: emitter produced int32(%s) but the literal does not fit int32: %v", lit.Value, err))
	}
	return int32(n), true
}

// memOpSpec describes one memory op's in-memory shape.
//
//   - elemType:   Go type used as the deref target.
//   - outerCast:  optional cast wrapping the load result (sub-word
//     sign/zero extension); empty when elemType already
//     matches the SSA result type.
//   - valSrcType: only used for stores — the Go type of the SSA value
//     being stored. When valSrcType != elemType the
//     emitter wraps `vN` in `elemType(vN)`.
type memOpSpec struct {
	elemType   string
	outerCast  string
	valSrcType string
}

// loadSpec returns the access spec for an OpLoad* value.
func loadSpec(v *ssa.Value) (memOpSpec, bool) {
	intCast := "int32"
	if v.Type == ssa.TypeI64 {
		intCast = "int64"
	}
	switch v.Op {
	case ssa.OpLoad8U:
		return memOpSpec{elemType: "uint8", outerCast: intCast}, true
	case ssa.OpLoad8S:
		return memOpSpec{elemType: "int8", outerCast: intCast}, true
	case ssa.OpLoad16U:
		return memOpSpec{elemType: "uint16", outerCast: intCast}, true
	case ssa.OpLoad16S:
		return memOpSpec{elemType: "int16", outerCast: intCast}, true
	case ssa.OpLoad32:
		// i32.load: full-width 32-bit load, no extension.
		return memOpSpec{elemType: "int32"}, true
	case ssa.OpLoad32U:
		// i64.load32_u: read uint32, zero-extend to int64.
		return memOpSpec{elemType: "uint32", outerCast: "int64"}, true
	case ssa.OpLoad32S:
		// i64.load32_s: read int32, sign-extend to int64.
		return memOpSpec{elemType: "int32", outerCast: "int64"}, true
	case ssa.OpLoad64:
		return memOpSpec{elemType: "int64"}, true
	case ssa.OpLoadF32:
		return memOpSpec{elemType: "float32"}, true
	case ssa.OpLoadF64:
		return memOpSpec{elemType: "float64"}, true
	}
	return memOpSpec{}, false
}

// storeSpec returns the access spec for an OpStore* value.
//
// Sub-word stores use UNSIGNED elemTypes (uint8 / uint16 / uint32) to
// match the wasm spec ("store the low N bits as the unsigned
// representation"); a signed elemType would semantically misrepresent
// the operation (i32.store8 of 255 must write 0xFF, not "out of int8
// range"). The cast in emitMemStoreStmt is a runtime conversion
// because args[1] is force-hoisted by emit.ComputeHoist.
//
// For non-narrowing stores (i32.store, i64.store, fN.store) elemType
// equals valSrcType and no cast is emitted.
func storeSpec(v *ssa.Value) (memOpSpec, bool) {
	if len(v.Args) < 2 || v.Args[1] == nil {
		return memOpSpec{}, false
	}
	valSrc := "int32"
	if v.Args[1].Type == ssa.TypeI64 {
		valSrc = "int64"
	}
	switch v.Op {
	case ssa.OpStore8:
		return memOpSpec{elemType: "uint8", valSrcType: valSrc}, true
	case ssa.OpStore16:
		return memOpSpec{elemType: "uint16", valSrcType: valSrc}, true
	case ssa.OpStore32:
		// i32.store: identity. i64.store32: low 32 bits as unsigned.
		if valSrc == "int64" {
			return memOpSpec{elemType: "uint32", valSrcType: "int64"}, true
		}
		return memOpSpec{elemType: "int32", valSrcType: "int32"}, true
	case ssa.OpStore64:
		return memOpSpec{elemType: "int64", valSrcType: "int64"}, true
	case ssa.OpStoreF32:
		return memOpSpec{elemType: "float32", valSrcType: "float32"}, true
	case ssa.OpStoreF64:
		return memOpSpec{elemType: "float64", valSrcType: "float64"}, true
	}
	return memOpSpec{}, false
}

// Inline atomics
//
// The four full-width aligned atomic accesses (i32/i64 atomic
// load/store) are emitted inline as sync/atomic intrinsics instead of
// the base.AtomicLoad*/AtomicStore* helper calls:
//
//	int32(atomic.LoadUint32((*uint32)(unsafe.Add(mBase, <off>))))
//	atomic.StoreUint32((*uint32)(unsafe.Add(mBase, <off>)), uint32(vN))
//
// The helper chain is three //go:noinline calls deep (AtomicLoad32 →
// AtomicPtr32 → AtomicEA — noinline so the closure-taking RMW helpers
// stay representable in the gcasm bundler, see helpers.go), which is
// what a wasm engine emits as ONE machine instruction. Interpreter-style
// guests hit an atomic load on every dispatch (interrupt-flag checks),
// so the call chain shows up as tens of percent of runtime.
// sync/atomic Load/Store are Go compiler intrinsics — a plain MOV /
// LDAR / STLR-class instruction, no CALL — and give exactly the
// seq-cst ordering the wasm threads proposal requires.
//
// Alignment and bounds checks are dropped, mirroring the plain
// load/store rationale at the top of this file: validated wasm from a
// C/C++/Rust toolchain only issues ABI-aligned atomics, so a
// misaligned or out-of-bounds atomic indicates a bug in the input, not
// a runtime condition. (A misaligned inline atomic fails loudly anyway:
// LDAR/STLR fault, and Go's race-free unaligned 64-bit atomics panic on
// 32-bit-aligned addresses.)
//
// Everything else — sub-word loads/stores (CAS-loop lane math), RMW
// families, cmpxchg, wait/notify, fence — keeps the helper form; those
// either take closures or are far off any hot path.

// atomicInlineSpec describes one inlineable atomic helper: the
// sync/atomic function stem, the unsigned element type, the load
// result cast, and where the value operand sits for stores.
type atomicInlineSpec struct {
	elemType string // uint32 / uint64: deref target and atomic operand type
	fn       string // sync/atomic function name
	loadCast string // int32 / int64 wrap on load results; "" for stores
	isStore  bool
}

// atomicInlineSpecs maps OpAtomicCall helper names (lower.go feAtomics)
// to their inline form. Only the four full-width aligned accesses
// appear here — in both address widths, since the op itself is
// identical and only the effective-address arithmetic differs (see
// memOffsetExpr / memOffsetExpr64); absence means "keep the helper
// call".
var atomicInlineSpecs = map[string]atomicInlineSpec{
	"atomicLoad32":      {elemType: "uint32", fn: "LoadUint32", loadCast: "int32"},
	"atomicLoad64":      {elemType: "uint64", fn: "LoadUint64", loadCast: "int64"},
	"atomicStore32":     {elemType: "uint32", fn: "StoreUint32", isStore: true},
	"atomicStore64":     {elemType: "uint64", fn: "StoreUint64", isStore: true},
	"atomicLoad32_m64":  {elemType: "uint32", fn: "LoadUint32", loadCast: "int32"},
	"atomicLoad64_m64":  {elemType: "uint64", fn: "LoadUint64", loadCast: "int64"},
	"atomicStore32_m64": {elemType: "uint32", fn: "StoreUint32", isStore: true},
	"atomicStore64_m64": {elemType: "uint64", fn: "StoreUint64", isStore: true},
}

// emitAtomicInline renders an OpAtomicCall as an inline sync/atomic
// expression when the helper has an entry in atomicInlineSpecs and the
// op's static offset operand is the OpConst32 the lowering built
// (anything else — e.g. a future pass rewriting the operand — falls
// back to the helper call). Loads return the value expression; stores
// return the atomic.Store call expression, which the side-effect
// statement path wraps in an ExprStmt.
func (em *ssaEmitter) emitAtomicInline(v *ssa.Value, name string, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Expr, bool, error) {
	spec, ok := atomicInlineSpecs[name]
	if !ok {
		return nil, false, nil
	}
	// The static offset is the OpConst32 (wasm32) or OpConst64 (memory64)
	// the lowering built; its width decides the truncation-free extraction.
	// memOffsetExpr itself dispatches on em.mem64 for the address math.
	var offU uint64
	if em.mem64 {
		off := ssaConstBase64(v.Args[1])
		if off == nil {
			return nil, false, nil
		}
		offU = uint64(off.AuxInt)
	} else {
		off := ssaConstBase(v.Args[1])
		if off == nil {
			return nil, false, nil
		}
		offU = uint64(uint32(off.AuxInt))
	}
	baseExpr, err := emitExpr(v.Args[0])
	if err != nil {
		return nil, false, err
	}
	em.useImport("unsafe")
	em.useImport("sync/atomic")
	added := &ast.CallExpr{
		Fun: &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Add")},
		Args: []ast.Expr{
			em.memBasePtrExpr(),
			em.memOffsetExpr(baseExpr, offU, v.Args[0]),
		},
	}
	ptr := &ast.CallExpr{
		Fun:  &ast.ParenExpr{X: &ast.StarExpr{X: newID(spec.elemType)}},
		Args: []ast.Expr{added},
	}
	atomicFn := &ast.SelectorExpr{X: newID("atomic"), Sel: newID(spec.fn)}
	if spec.isStore {
		valExpr, err := emitExpr(v.Args[2])
		if err != nil {
			return nil, false, err
		}
		return &ast.CallExpr{
			Fun:  atomicFn,
			Args: []ast.Expr{ptr, &ast.CallExpr{Fun: newID(spec.elemType), Args: []ast.Expr{valExpr}}},
		}, true, nil
	}
	loaded := &ast.CallExpr{Fun: atomicFn, Args: []ast.Expr{ptr}}
	return &ast.CallExpr{Fun: newID(spec.loadCast), Args: []ast.Expr{loaded}}, true, nil
}
