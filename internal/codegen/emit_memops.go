package codegen

import (
	"fmt"
	"go/ast"
	"go/token"

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
// and as the RHS of a hoisted `vN = ...` assignment (computeHoist
// already force-hoists every OpLoad*, so loads always come out as
// assignments at their definition site).
//
// emitMemStoreStmt returns a single ast.Stmt — the RHS cast for
// narrowing stores (i32.store8 / i32.store16 / i64.store32 / ...)
// relies on computeHoist having force-hoisted args[1] so the cast
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
	expr := em.unsafeDerefExpr(spec, baseExpr, uint64(v.AuxInt))
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
// rely on computeHoist having force-hoisted args[1] so the cast
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
	dst := em.unsafeDerefExpr(spec, baseExpr, uint64(v.AuxInt))
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
//	*(*<elemType>)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(m.Memory)),
//	                          uintptr(uint32(base)[+offset])))
//
// Registers "unsafe" with the translator so the generated file picks
// up the import.
func (em *ssaEmitter) unsafeDerefExpr(spec memOpSpec, baseExpr ast.Expr, offset uint64) ast.Expr {
	em.useImport("unsafe")
	addr := ast.Expr(&ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{baseExpr}})
	if offset != 0 {
		addr = &ast.BinaryExpr{X: addr, Op: token.ADD, Y: uintLit(offset)}
	}
	addrUptr := &ast.CallExpr{Fun: newID("uintptr"), Args: []ast.Expr{addr}}
	sliceData := &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("SliceData")},
		Args: []ast.Expr{em.fieldRef("memory")},
	}
	asPtr := &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Pointer")},
		Args: []ast.Expr{sliceData},
	}
	added := &ast.CallExpr{
		Fun:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Add")},
		Args: []ast.Expr{asPtr, addrUptr},
	}
	castFn := &ast.ParenExpr{X: &ast.StarExpr{X: newID(spec.elemType)}}
	cast := &ast.CallExpr{Fun: castFn, Args: []ast.Expr{added}}
	return &ast.StarExpr{X: cast}
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
// because args[1] is force-hoisted by computeHoist.
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
