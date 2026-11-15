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
// The wasm spec traps on out-of-bounds memory access. A wasm32 access
// carries no runtime bounds check: its effective address is a u32 plus
// a u32 offset, which reaches at most 8 GiB past the memory's base.
// A memory64 access has no such limit — its 64-bit address added to
// the base can name any byte of the host process — so it is preceded
// by an exact check (memAccessGuard below): an access below
// memory.size works, one that reaches memory.size or past it traps.
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
// On wasm32 the alignment and bounds checks are dropped, mirroring the
// plain load/store rationale at the top of this file: validated wasm
// from a C/C++/Rust toolchain only issues ABI-aligned atomics, so a
// misaligned or out-of-bounds atomic indicates a bug in the input, not
// a runtime condition. (A misaligned inline atomic fails loudly anyway:
// LDAR/STLR fault, and Go's race-free unaligned 64-bit atomics panic on
// 32-bit-aligned addresses.) On memory64, memAccessGuard checks both in
// front of the access, with the traps the helper form raises.
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

// atomicInlineAccess reports whether the OpAtomicCall v, a call of the
// helper name, is emitted inline, and returns its spec and static offset.
// The static offset is the OpConst32 (wasm32) or OpConst64 (memory64)
// the lowering built; its width decides the truncation-free extraction.
// memOffsetExpr itself dispatches on em.mem64 for the address math.
func (em *ssaEmitter) atomicInlineAccess(v *ssa.Value, name string) (atomicInlineSpec, uint64, bool) {
	spec, ok := atomicInlineSpecs[name]
	if !ok || len(v.Args) < 2 {
		return atomicInlineSpec{}, 0, false
	}
	if em.mem64 {
		off := ssaConstBase64(v.Args[1])
		if off == nil {
			return atomicInlineSpec{}, 0, false
		}
		return spec, uint64(off.AuxInt), true
	}
	off := ssaConstBase(v.Args[1])
	if off == nil {
		return atomicInlineSpec{}, 0, false
	}
	return spec, uint64(uint32(off.AuxInt)), true
}

// emitAtomicInline renders an OpAtomicCall as an inline sync/atomic
// expression when the helper has an entry in atomicInlineSpecs and the
// op's static offset operand is the OpConst32 the lowering built
// (anything else — e.g. a future pass rewriting the operand — falls
// back to the helper call). Loads return the value expression; stores
// return the atomic.Store call expression, which the side-effect
// statement path wraps in an ExprStmt.
func (em *ssaEmitter) emitAtomicInline(v *ssa.Value, name string, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Expr, bool, error) {
	spec, offU, ok := em.atomicInlineAccess(v, name)
	if !ok {
		return nil, false, nil
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

// Memory64 bounds checks
//
// Every plain load and store of a memory64 memory, and every atomic
// access emitted inline, is preceded by a check of its whole byte range
// against memory.size (L below):
//
//	if uint64(base) > mLim-K {
//		goto trapMem
//	}
//	v7 = *(*int64)(unsafe.Add(mBase, uint64(base)+16))
//	...
//	trapMem:
//		wasm_trap_mem_oob()
//		for {
//		}
//
// K is the access's static offset plus its size, a compile-time
// constant, and the access is in bounds exactly when base + K <= L in
// unbounded arithmetic. Written as base > L-K, the comparison cannot
// wrap: L never drops below the memory's declared minimum (memory only
// grows, and the constructors refuse a smaller size), so for every K up
// to that minimum L-K is exact, and base takes its full u64 range — an
// address near 2^64, whose sum with the offset would wrap, fails it like
// any other. A K above the minimum adds the test L < K. A constant
// address needs no check when its range ends within the minimum, and
// compares L with its end otherwise; so does an address that is a phi of
// constants, through the largest of them. A K that overflows u64 names
// bytes no memory has: such an access traps unconditionally.
//
// A check is left out where one that always runs before it implies it,
// and a load's check covers the accesses right after it on the same
// address (memGuardCoverage): memory never shrinks, so an address proven
// in bounds stays in bounds for the rest of the function, calls and
// memory.grow included.
//
// L lives in mLim, a function-level local beside mBase: read from
// len(m.memory) (memory.size, for a memory that is not shared) where
// mBase is read, and refreshed where mBase is, after every value that
// can run memory.grow. A shared memory grows under other agents at any
// moment, so its checks read memSize afresh instead.
//
// The checks of a function share one trap block per trap kind, at the
// end of its body (trapStmt, memTrapTail). The trap helper never
// returns; the empty loop after it tells gc so, which keeps the cold
// path from saving and restoring what the accesses need (the shape the
// unreachable trap has too).

// memLimLocal is the name of the per-function copy of memory.size the
// bounds checks compare with. Like mBase, it cannot collide with
// generated value names.
const memLimLocal = "mLim"

// memGuarded reports whether the module's accesses are bounds-checked.
func (em *ssaEmitter) memGuarded() bool { return em.mem64 }

// memShared reports whether the module's memory is shared (threads).
func (em *ssaEmitter) memShared() bool { return em.t != nil && em.t.memoryIsShared() }

// memLimHoisted reports whether the function keeps memory.size in mLim.
func (em *ssaEmitter) memLimHoisted() bool {
	return em.memBaseHoisted && em.memGuarded() && !em.memShared()
}

// memSizeRead is `uint64(len(m.memory))`: memory.size of a memory that
// is not shared, which every constructor and memoryGrow keep equal to
// the slice's length.
func (em *ssaEmitter) memSizeRead() ast.Expr {
	return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{
		&ast.CallExpr{Fun: newID("len"), Args: []ast.Expr{em.fieldRef("memory")}},
	}}
}

// memLimitExpr is memory.size in bytes at a bounds check.
func (em *ssaEmitter) memLimitExpr() ast.Expr {
	if em.memLimHoisted() {
		return newID(memLimLocal)
	}
	if em.memShared() {
		return &ast.CallExpr{Fun: &ast.SelectorExpr{X: em.fieldRef("memSize"), Sel: newID("Load")}}
	}
	return em.memSizeRead()
}

// memMinBytes is the memory's declared minimum in bytes: memory.size is
// never below it.
func (em *ssaEmitter) memMinBytes() uint64 {
	if em.t == nil || len(em.t.mod.Memories) == 0 {
		return 0
	}
	return em.t.mod.Memories[0].Limits.Min * 65536
}

// memElemSize is the byte width of a load/store element type.
func memElemSize(elemType string) uint64 {
	switch elemType {
	case "uint8", "int8":
		return 1
	case "uint16", "int16":
		return 2
	case "uint32", "int32", "float32":
		return 4
	}
	return 8
}

// memConstExpr is a u64 constant operand of a bounds check: small ones
// inline, large ones through the _consts table for the addressing-
// immediate reasons memOffsetExpr routes them there.
func (em *ssaEmitter) memConstExpr(c uint64) ast.Expr {
	if c >= largeConstThreshold && em.t != nil {
		return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{em.constsIndexExpr(c)}}
	}
	return uintLit(c)
}

// memAccessShape classifies v as an access the emitter renders inline —
// a plain load or store, or an atomic emitted inline (any other atomic
// goes through a helper that checks it) — with its width and static
// offset.
func (em *ssaEmitter) memAccessShape(v *ssa.Value) (size, off uint64, atomic, ok bool) {
	if len(v.Args) == 0 {
		return 0, 0, false, false
	}
	if spec, sok := loadSpec(v); sok {
		return memElemSize(spec.elemType), uint64(v.AuxInt), false, true
	}
	if spec, sok := storeSpec(v); sok {
		return memElemSize(spec.elemType), uint64(v.AuxInt), false, true
	}
	if v.Op == ssa.OpAtomicCall {
		name, _ := v.Aux.(string)
		if spec, o, aok := em.atomicInlineAccess(v, name); aok {
			return memElemSize(spec.elemType), o, true, true
		}
	}
	return 0, 0, false, false
}

// memAccessGuard returns the statements that check v's byte range
// before v runs, or nil when v is no checked access or provably in
// bounds. See "Memory64 bounds checks" above.
func (em *ssaEmitter) memAccessGuard(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) ([]ast.Stmt, error) {
	if !em.memGuarded() {
		return nil, nil
	}
	size, off, atomic, ok := em.memAccessShape(v)
	if !ok {
		return nil, nil
	}
	trap := "wasm_trap_mem_oob"
	if atomic {
		trap = "wasm_trap_atomic_oob"
	}
	// k is the checked span past the address: offset plus size, or
	// what memGuardCoverage widened it to.
	k := off + size
	if plan, ok := em.memGuardPlan[v.ID]; ok {
		if plan == 0 {
			return nil, nil // implied by an earlier check
		}
		k = plan
	}
	minBytes := em.memMinBytes()
	if !atomic && k >= off {
		if hi, ok := memConstMax(v.Args[0], nil); ok {
			if end := hi + k; end >= hi && end <= minBytes {
				return nil, nil
			}
		}
	}
	var oob, misaligned ast.Expr
	if c := ssaConstBase64(v.Args[0]); c != nil {
		ea := uint64(c.AuxInt) + off
		end := ea + size
		switch {
		case ea < off || end < ea:
			oob = newID("true")
		case end > minBytes:
			oob = &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.LSS, Y: em.memConstExpr(end)}
		}
		if atomic && ea&(size-1) != 0 {
			misaligned = newID("true")
		}
	} else {
		baseExpr, err := emitExpr(v.Args[0])
		if err != nil {
			return nil, err
		}
		a := &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{baseExpr}}
		if k < off { // off+size overflowed
			oob = newID("true")
		} else {
			oob = &ast.BinaryExpr{
				X:  a,
				Op: token.GTR,
				Y:  &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.SUB, Y: em.memConstExpr(k)},
			}
			if k > minBytes {
				oob = &ast.BinaryExpr{
					X:  &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.LSS, Y: em.memConstExpr(k)},
					Op: token.LOR,
					Y:  oob,
				}
			}
		}
		if atomic {
			// A second rendering of the base: AST nodes are not shared.
			baseExpr, err := emitExpr(v.Args[0])
			if err != nil {
				return nil, err
			}
			ea := ast.Expr(&ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{baseExpr}})
			if off != 0 {
				ea = &ast.BinaryExpr{X: ea, Op: token.ADD, Y: em.memConstExpr(off)}
			}
			misaligned = &ast.BinaryExpr{
				X:  &ast.ParenExpr{X: &ast.BinaryExpr{X: ea, Op: token.AND, Y: uintLit(size - 1)}},
				Op: token.NEQ,
				Y:  uintLit(0),
			}
		}
	}
	var stmts []ast.Stmt
	if oob != nil {
		stmts = append(stmts, em.trapStmt(trap, oob))
	}
	if misaligned != nil {
		stmts = append(stmts, em.trapStmt("wasm_trap_atomic_unaligned", misaligned))
	}
	return stmts, nil
}

// memConstMax reports whether the i64 address v is a constant, or a phi
// (through copies and nested phis) all of whose incoming values are
// constants, and returns the largest of them as a u64. seen guards the
// phi cycles of loops; nil starts a fresh walk.
func memConstMax(v *ssa.Value, seen map[ssa.ValueID]bool) (uint64, bool) {
	for v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 {
		v = v.Args[0]
	}
	if v == nil {
		return 0, false
	}
	switch v.Op {
	case ssa.OpConst64:
		return uint64(v.AuxInt), true
	case ssa.OpPhi:
		if seen == nil {
			seen = map[ssa.ValueID]bool{}
		}
		if seen[v.ID] {
			// A cycle adds no value the other incoming edges lack.
			return 0, true
		}
		seen[v.ID] = true
		var hi uint64
		for _, a := range v.Args {
			c, ok := memConstMax(a, seen)
			if !ok {
				return 0, false
			}
			hi = max(hi, c)
		}
		return hi, true
	}
	return 0, false
}

// memGuardSpan describes the bytes a checked access with a run-time
// address touches as root+lo .. root+hi: root is the address value with
// a constant addend peeled off (lo, which the guest's i64.add put there),
// hi is lo plus the static offset and the access size. ok is false for
// anything that is no such access, or whose span does not fit.
func (em *ssaEmitter) memGuardSpan(v *ssa.Value) (root ssa.ValueID, lo, hi uint64, atomic, ok bool) {
	size, off, atomic, ok := em.memAccessShape(v)
	if !ok || off >= 1<<32 {
		return 0, 0, 0, false, false
	}
	base := v.Args[0]
	for base != nil && base.Op == ssa.OpCopy && len(base.Args) == 1 {
		base = base.Args[0]
	}
	if base == nil || ssaConstBase64(base) != nil {
		return 0, 0, 0, false, false
	}
	if base.Op == ssa.OpAdd64 && len(base.Args) == 2 {
		for i, a := range base.Args {
			if c := ssaConstBase64(a); c != nil && c.AuxInt >= 0 && c.AuxInt < 1<<32 {
				if x := base.Args[1-i]; ssaConstBase64(x) == nil {
					return x.ID, uint64(c.AuxInt), uint64(c.AuxInt) + off + size, atomic, true
				}
			}
		}
	}
	return base.ID, 0, off + size, atomic, true
}

// memGuardLookahead bounds how many values after a load memGuardCoverage
// looks at to widen the load's check.
const memGuardLookahead = 256

// memGuardCoverage plans the checks of f's memory64 accesses with a
// run-time address. It returns, per access, 0 when the access needs no
// check of its own, or the span its check covers past its address when
// that is wider than its own offset plus size; an access it does not
// list is checked as usual.
//
// An access needs no check when a check that runs before it on every
// path implies its own: one of an access in a dominating position (an
// earlier value of the same block, or any value of a dominating block)
// on the same root address. The covering check proved
// root+lo_u .. root+hi_u in bounds, in the notation of memGuardSpan;
// memory only grows, so that still holds at the covered access, calls
// and memory.grow included. A span lo_v..hi_v is then in bounds when
// lo_v ≥ lo_u and hi_v ≤ hi_u: either root+lo_u did not wrap and
// root+lo_v is root+lo_u moved up by lo_v-lo_u within the proven range,
// or it wrapped and root+lo_v wrapped the same way (lo_v ≥ lo_u) and lies
// within the same proven range. An access whose addend is below the
// covering one's is not covered: its address may not have wrapped where
// the covering one's did.
//
// A load's check is widened over the accesses that follow it in its
// block on the same root, with an addend at or above its own, up to the
// next value with a side effect (included when it is such an access, a
// store): their checks are then implied. Trapping at the load for a
// later access is not observable — nothing between them writes or
// calls, and every plain access traps with the same message — and when
// the widened check fails, the original program traps by the last of
// them: the access that reaches furthest is out of bounds, or (its
// address having wrapped where this one's did not) this one is.
//
// Atomic accesses cover others (their check traps every access that is
// out of bounds) but keep their own exact checks, which include
// alignment and trap with their own message. Functions with try regions
// keep every check.
func (em *ssaEmitter) memGuardCoverage(f *ssa.Func) map[ssa.ValueID]uint64 {
	if !em.memGuarded() || f.Entry == nil || len(f.TryRegions) > 0 {
		return nil
	}
	idom := ssa.Dominators(f)
	children := map[ssa.BlockID][]*ssa.Block{}
	for _, b := range f.Blocks {
		if d := idom[b.ID]; d != nil && b != f.Entry {
			children[d.ID] = append(children[d.ID], b)
		}
	}
	type span struct{ lo, hi uint64 }
	avail := map[ssa.ValueID][]span{}
	var plan map[ssa.ValueID]uint64
	set := func(id ssa.ValueID, k uint64) {
		if plan == nil {
			plan = map[ssa.ValueID]uint64{}
		}
		plan[id] = k
	}
	var walk func(b *ssa.Block)
	walk = func(b *ssa.Block) {
		var pushed []ssa.ValueID
		for i, v := range b.Values {
			root, lo, hi, atomic, ok := em.memGuardSpan(v)
			if !ok {
				continue
			}
			if !atomic {
				implied := false
				for _, s := range avail[root] {
					if lo >= s.lo && hi <= s.hi {
						implied = true
						break
					}
				}
				if implied {
					set(v.ID, 0)
					continue
				}
				own := hi
				// A store is a side effect itself: a trap moved in front
				// of it would undo its write. Only a load's check widens.
				// The look-ahead is bounded so that a long block of loads
				// costs linear time.
				rest := b.Values[i+1:]
				if len(rest) > memGuardLookahead {
					rest = rest[:memGuardLookahead]
				}
				for _, w := range rest {
					if v.HasSideEffect() {
						break
					}
					if wr, wlo, whi, watomic, wok := em.memGuardSpan(w); wok && !watomic && wr == root && wlo >= lo {
						hi = max(hi, whi)
					}
					if w.HasSideEffect() {
						break
					}
				}
				if hi != own {
					set(v.ID, hi-lo)
				}
			}
			avail[root] = append(avail[root], span{lo, hi})
			pushed = append(pushed, root)
		}
		for _, c := range children[b.ID] {
			walk(c)
		}
		for i := len(pushed) - 1; i >= 0; i-- {
			r := pushed[i]
			avail[r] = avail[r][:len(avail[r])-1]
		}
	}
	walk(f.Entry)
	return plan
}

// memTrapKinds are the traps of the bounds checks, each with the label
// of the function's one block that raises it, in the order those blocks
// close the function (memTrapTail).
var memTrapKinds = []struct{ helper, label string }{
	{"wasm_trap_mem_oob", "trapMem"},
	{"wasm_trap_atomic_oob", "trapAtomic"},
	{"wasm_trap_atomic_unaligned", "trapUnaligned"},
}

// trapStmt renders `if cond { goto <the trap's label> }`. Every check
// of a function shares one trap block per kind (memTrapTail) instead of
// carrying a call of its own: the cold path costs one branch per check,
// and gc lays the check out to fall through to the access (with a block
// per check, gc's branch heuristics take the call that never returns for
// the likely path and fall through into it).
func (em *ssaEmitter) trapStmt(trap string, cond ast.Expr) ast.Stmt {
	label := ""
	for _, k := range memTrapKinds {
		if k.helper == trap {
			label = k.label
		}
	}
	if em.memTrapsUsed == nil {
		em.memTrapsUsed = map[string]bool{}
	}
	em.memTrapsUsed[trap] = true
	return &ast.IfStmt{
		Cond: cond,
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.BranchStmt{Tok: token.GOTO, Label: newID(label)}}},
	}
}

// memTrapTail renders the trap blocks the function's checks branch to,
// appended at the end of its body:
//
//	trapMem:
//		wasm_trap_mem_oob()
//		for {
//		}
//
// At the top level of the body, each label is in scope of every check,
// however deeply nested; no variable is declared at the top level after
// the first check (the emitters declare their values at the head of the
// body), so no goto jumps into a declaration's scope.
func (em *ssaEmitter) memTrapTail() []ast.Stmt {
	var out []ast.Stmt
	for _, k := range memTrapKinds {
		if !em.memTrapsUsed[k.helper] {
			continue
		}
		out = append(out,
			&ast.LabeledStmt{Label: newID(k.label), Stmt: &ast.ExprStmt{X: &ast.CallExpr{Fun: em.helperRef(k.helper)}}},
			&ast.ForStmt{Body: &ast.BlockStmt{}})
	}
	return out
}
