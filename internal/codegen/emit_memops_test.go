package codegen

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/ssa"
)

// formatExpr / formatStmt render an AST node through go/format so the
// tests can assert on the canonical Go source representation rather
// than chase ast.Node pointer chains.
func formatExpr(t *testing.T, e ast.Expr) string {
	t.Helper()
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, e); err != nil {
		t.Fatalf("format expr: %v", err)
	}
	return buf.String()
}

func formatStmt(t *testing.T, s ast.Stmt) string {
	t.Helper()
	fset := token.NewFileSet()
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, s); err != nil {
		t.Fatalf("format stmt: %v", err)
	}
	return buf.String()
}

// TestLoadSpec covers every wasm load shape and asserts elemType /
// outerCast pick.
func TestLoadSpec(t *testing.T) {
	// (op, type, elemType, outerCast) — the i64 variants of sub-word
	// loads pick the int64 outer cast while still reading the narrow
	// sub-word elem.
	type tc struct {
		op   ssa.Op
		typ  ssa.Type
		elem string
		cast string
	}
	cases := []tc{
		{ssa.OpLoad8U, ssa.TypeI32, "uint8", "int32"},
		{ssa.OpLoad8S, ssa.TypeI32, "int8", "int32"},
		{ssa.OpLoad8U, ssa.TypeI64, "uint8", "int64"},
		{ssa.OpLoad16U, ssa.TypeI32, "uint16", "int32"},
		{ssa.OpLoad16S, ssa.TypeI32, "int16", "int32"},
		{ssa.OpLoad32, ssa.TypeI32, "int32", ""},
		{ssa.OpLoad32U, ssa.TypeI64, "uint32", "int64"},
		{ssa.OpLoad32S, ssa.TypeI64, "int32", "int64"},
		{ssa.OpLoad64, ssa.TypeI64, "int64", ""},
		{ssa.OpLoadF32, ssa.TypeF32, "float32", ""},
		{ssa.OpLoadF64, ssa.TypeF64, "float64", ""},
	}
	for _, c := range cases {
		t.Run(c.op.String(), func(t *testing.T) {
			b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
			entry := b.NewBlock(ssa.BlockRet)
			b.SetEntry(entry)
			b.SetCurrent(entry)
			v := b.NewValueAuxInt(c.op, c.typ, 0, b.Const32(0))
			spec, ok := loadSpec(v)
			if !ok {
				t.Fatalf("loadSpec returned !ok for %v", c.op)
			}
			if spec.elemType != c.elem {
				t.Errorf("elemType = %q, want %q", spec.elemType, c.elem)
			}
			if spec.outerCast != c.cast {
				t.Errorf("outerCast = %q, want %q", spec.outerCast, c.cast)
			}
		})
	}
}

// TestStoreSpec covers every wasm store shape. Sub-word stores must
// pick UNSIGNED elemTypes (uint8/uint16/uint32) to honour the wasm
// "store low N bits unsigned" semantics; non-narrowing stores set
// valSrcType == elemType so the emitter skips the cast.
func TestStoreSpec(t *testing.T) {
	type tc struct {
		op     ssa.Op
		valTyp ssa.Type
		elem   string
		valSrc string
	}
	cases := []tc{
		{ssa.OpStore8, ssa.TypeI32, "uint8", "int32"},
		{ssa.OpStore8, ssa.TypeI64, "uint8", "int64"},
		{ssa.OpStore16, ssa.TypeI32, "uint16", "int32"},
		{ssa.OpStore16, ssa.TypeI64, "uint16", "int64"},
		{ssa.OpStore32, ssa.TypeI32, "int32", "int32"},  // i32.store: no cast
		{ssa.OpStore32, ssa.TypeI64, "uint32", "int64"}, // i64.store32: narrowing
		{ssa.OpStore64, ssa.TypeI64, "int64", "int64"},
		{ssa.OpStoreF32, ssa.TypeF32, "float32", "float32"},
		{ssa.OpStoreF64, ssa.TypeF64, "float64", "float64"},
	}
	for _, c := range cases {
		t.Run(c.op.String()+"/"+c.valTyp.String(), func(t *testing.T) {
			b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
			entry := b.NewBlock(ssa.BlockRet)
			b.SetEntry(entry)
			b.SetCurrent(entry)
			var val *ssa.Value
			switch c.valTyp {
			case ssa.TypeI32:
				val = b.Const32(0)
			case ssa.TypeI64:
				val = b.Const64(0)
			default:
				// Use a constant 0 of the right type via a CallDirect stub.
				// Simpler: just synthesise with NewValue and a placeholder.
				val = b.NewValueAuxInt(ssa.OpCallDirect, c.valTyp, 0)
			}
			v := b.NewValueAuxInt(c.op, ssa.TypeMem, 0, b.Const32(0), val)
			spec, ok := storeSpec(v)
			if !ok {
				t.Fatalf("storeSpec returned !ok for %v", c.op)
			}
			if spec.elemType != c.elem {
				t.Errorf("elemType = %q, want %q", spec.elemType, c.elem)
			}
			if spec.valSrcType != c.valSrc {
				t.Errorf("valSrcType = %q, want %q", spec.valSrcType, c.valSrc)
			}
		})
	}
}

// TestEmitMemLoadExpr_Load32 renders the OpLoad32 inline form and
// asserts it matches the documented one-liner shape. Catches any
// regression in unsafeDerefExpr's pointer-arithmetic chain.
func TestEmitMemLoadExpr_Load32(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	v := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 8, addr)

	em := newSSAEmitter(nil)
	emit := func(arg *ssa.Value) (ast.Expr, error) { return constArgExpr(arg), nil }
	expr, err := em.emitMemLoadExpr(v, emit)
	if err != nil {
		t.Fatalf("emitMemLoadExpr: %v", err)
	}
	got := formatExpr(t, expr)
	// New compact form: the unsafe.Pointer(unsafe.SliceData(m.memory))
	// chain is cached into the function-entry local `_m`, so the access
	// site references just `_m`. unsafe.Add accepts IntegerType so the
	// outer uintptr() wrap is gone; the int32 constant operand collapses
	// to a bare untyped literal (positive int32 constants are passed as
	// uint64 fitting into Go's untyped-constant rules).
	want := "*(*int32)(unsafe.Add(m.M, 8))"
	if got != want {
		t.Errorf("Load32 inline form:\n got:  %s\n want: %s", got, want)
	}
}

// TestEmitMemLoadExpr_Load8U checks the outer cast wraps the inner
// unsafe deref when sign/zero extension is needed.
func TestEmitMemLoadExpr_Load8U(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	v := b.NewValueAuxInt(ssa.OpLoad8U, ssa.TypeI32, 0, addr)

	em := newSSAEmitter(nil)
	emit := func(arg *ssa.Value) (ast.Expr, error) { return constArgExpr(arg), nil }
	expr, err := em.emitMemLoadExpr(v, emit)
	if err != nil {
		t.Fatalf("emitMemLoadExpr: %v", err)
	}
	got := formatExpr(t, expr)
	if !strings.HasPrefix(got, "int32(*(*uint8)") {
		t.Errorf("Load8U should be int32-cast over *(*uint8)(...); got: %s", got)
	}
	// New compact form: the unsafe.Pointer(unsafe.SliceData(m.memory))
	// chain is cached into the function-entry local `_m`, so the access
	// site only references it. Verify the cache var name shows up; the
	// SliceData lookup itself lives in the prologue emitted by
	// emitFuncBody, not in unsafeDerefExpr's output.
	if !strings.Contains(got, "unsafe.Add(m.M,") {
		t.Errorf("Load8U missing m.M cache reference; got: %s", got)
	}
}

// TestEmitMemStoreStmt_Store32 — non-narrowing store renders as a
// plain `*(*int32)(...) = val` one-liner; no cast around the RHS.
func TestEmitMemStoreStmt_Store32(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	val := b.Const32(7)
	v := b.NewValueAuxInt(ssa.OpStore32, ssa.TypeMem, 0, addr, val)

	em := newSSAEmitter(nil)
	emit := func(arg *ssa.Value) (ast.Expr, error) { return constArgExpr(arg), nil }
	stmt, err := em.emitMemStoreStmt(v, emit)
	if err != nil {
		t.Fatalf("emitMemStoreStmt: %v", err)
	}
	got := formatStmt(t, stmt)
	// New compact form: see TestEmitMemLoadExpr_Load32 for the
	// motivation. The destination references the cached _m base and
	// the offset is a bare untyped literal.
	want := "*(*int32)(unsafe.Add(m.M, 0)) = int32(7)"
	if got != want {
		t.Errorf("Store32 inline form:\n got:  %s\n want: %s", got, want)
	}
	// RHS must be the bare valExpr, NOT wrapped in `int32(int32(7))`.
	// (Non-narrowing stores skip the cast entirely — see emitMemStoreStmt.)
	if strings.Count(got, "= int32(int32(") > 0 {
		t.Errorf("Store32 must NOT wrap RHS in a no-op int32 cast; got: %s", got)
	}
}

// TestEmitMemStoreStmt_Store8 — narrowing store renders the uint8
// cast on the RHS (the value side is force-hoisted by emit.ComputeHoist
// so the emit form is a runtime conversion).
func TestEmitMemStoreStmt_Store8(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	val := b.Const32(255) // out of int8 range — must NOT be inlined into the cast
	v := b.NewValueAuxInt(ssa.OpStore8, ssa.TypeMem, 0, addr, val)

	em := newSSAEmitter(nil)
	// Simulate the post-hoist state by emitting val as the bare `vN`
	// identifier the real emitter would substitute.
	emit := func(arg *ssa.Value) (ast.Expr, error) {
		if arg == val {
			return newID("v9"), nil
		}
		return constArgExpr(arg), nil
	}
	stmt, err := em.emitMemStoreStmt(v, emit)
	if err != nil {
		t.Fatalf("emitMemStoreStmt: %v", err)
	}
	got := formatStmt(t, stmt)
	want := "*(*uint8)(unsafe.Add(m.M, 0)) = uint8(v9)"
	if got != want {
		t.Errorf("Store8 narrowing form:\n got:  %s\n want: %s", got, want)
	}
}

// TestComputeHoistForceHoistsNarrowingStoreValue: when args[1] of a
// narrowing store is a constant-producing op (OpConst32), emit.ComputeHoist
// must mark it for hoisting so emitMemStoreStmt's runtime cast lands
// on a variable instead of a literal.
func TestComputeHoistForceHoistsNarrowingStoreValue(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	// val has usage = 1 (only the store), so without force-hoist it
	// would be folded inline.
	val := b.Const32(255)
	b.NewValueAuxInt(ssa.OpStore8, ssa.TypeMem, 0, addr, val)
	f := b.Func()

	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)

	if !hoist[val.ID] {
		t.Errorf("ComputeHoist did not force-hoist OpStore8 value arg (usage=%d, hoist=%v)",
			usage[val.ID], hoist[val.ID])
	}
}

// TestComputeHoistSkipsNonNarrowingStore: when elemType == valSrcType
// the cast is absent, so we don't need the force-hoist either.
// (Without this guard we'd needlessly bloat hoisted-var declarations
// on every i32.store and i64.store.)
func TestComputeHoistSkipsNonNarrowingStore(t *testing.T) {
	b := ssa.NewFuncBuilder("t", ssa.FuncSig{})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(0)
	val := b.Const32(7)
	b.NewValueAuxInt(ssa.OpStore32, ssa.TypeMem, 0, addr, val)
	f := b.Func()

	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)

	if hoist[val.ID] {
		t.Errorf("ComputeHoist wrongly force-hoisted OpStore32 value arg (no narrowing cast needed)")
	}
}

// constArgExpr renders a constant arg for the test fixtures' emit
// closure. Matches what emitOp would return for OpConst32 / OpConst64.
func constArgExpr(v *ssa.Value) ast.Expr {
	switch v.Op {
	case ssa.OpConst32:
		return goConstI32(int32(v.AuxInt))
	case ssa.OpConst64:
		return goConstI64(v.AuxInt)
	}
	return newID("?")
}

// TestMemOffsetExpr_RuntimeBaseLargeOffset guards the fix for the gc
// ARM64 "FLDPD ... constant is not in pool" assembly failure. A large
// static offset added to a RUNTIME index must be routed through the
// _consts table (a runtime memory load) rather than emitted as a bare
// immediate: the ARM64 backend fuses adjacent f64 loads at a common base
// into a load-pair and bakes the offset into its tiny immediate field,
// so a multi-MB offset otherwise fails to assemble. Small offsets stay
// inline. (The constant-base path was already covered; this pins the
// runtime-base path that regressed arm64 for wasmify's simplelib bundle.)
func TestMemOffsetExpr_RuntimeBaseLargeOffset(t *testing.T) {
	em := newSSAEmitter(&translator{})

	large := formatExpr(t, em.memOffsetExpr(newID("v160"), 33571920, nil))
	if !strings.Contains(large, "_consts[") {
		t.Errorf("large runtime-base offset must route through _consts, got: %s", large)
	}
	if strings.Contains(large, "33571920") {
		t.Errorf("large offset must not appear as a bare immediate, got: %s", large)
	}

	small := formatExpr(t, em.memOffsetExpr(newID("v160"), 8, nil))
	if strings.Contains(small, "_consts") {
		t.Errorf("small runtime-base offset must stay inline, got: %s", small)
	}
	if !strings.Contains(small, "8") {
		t.Errorf("small offset should be an inline literal, got: %s", small)
	}
}
