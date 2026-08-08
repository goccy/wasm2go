// Package ssa — additional tests to raise statement coverage to ≥85%.
// Covers: Type methods, Op methods, FuncBuilder panics, Compact/CountValues,
// Verify invariants, PruneDeadBlocks, domtree functions, MemMetrics helpers,
// print edge cases, memclass helpers.
package ssa

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Type methods
// ---------------------------------------------------------------------------

func TestTypeString(t *testing.T) {
	cases := []struct {
		t    Type
		want string
	}{
		{TypeInvalid, "<invalid>"},
		{TypeI32, "i32"},
		{TypeI64, "i64"},
		{TypeF32, "f32"},
		{TypeF64, "f64"},
		{TypeMem, "mem"},
		{TypeBool, "bool"},
		{TypeTuple, "tuple"},
		{Type(255), "<?>"},
	}
	for _, c := range cases {
		if got := c.t.String(); got != c.want {
			t.Errorf("Type(%d).String() = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestTypeIsInt(t *testing.T) {
	if !TypeI32.IsInt() {
		t.Error("TypeI32.IsInt() = false")
	}
	if !TypeI64.IsInt() {
		t.Error("TypeI64.IsInt() = false")
	}
	if TypeF32.IsInt() {
		t.Error("TypeF32.IsInt() = true")
	}
	if TypeMem.IsInt() {
		t.Error("TypeMem.IsInt() = true")
	}
}

func TestTypeIsFloat(t *testing.T) {
	if !TypeF32.IsFloat() {
		t.Error("TypeF32.IsFloat() = false")
	}
	if !TypeF64.IsFloat() {
		t.Error("TypeF64.IsFloat() = false")
	}
	if TypeI32.IsFloat() {
		t.Error("TypeI32.IsFloat() = true")
	}
}

func TestTypeBits(t *testing.T) {
	cases := []struct {
		t    Type
		want int
	}{
		{TypeI32, 32},
		{TypeI64, 64},
		{TypeF32, 32},
		{TypeF64, 64},
		{TypeBool, 1},
		{TypeMem, 0},
		{TypeTuple, 0},
		{TypeInvalid, 0},
	}
	for _, c := range cases {
		if got := c.t.Bits(); got != c.want {
			t.Errorf("Type(%d).Bits() = %d, want %d", c.t, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Op methods
// ---------------------------------------------------------------------------

func TestOpString(t *testing.T) {
	cases := []struct {
		op   Op
		want string
	}{
		{OpInvalid, "OpInvalid"},
		{OpAdd32, "OpAdd32"},
		{OpUnreachable, "OpUnreachable"},
		{Op(9999), "Op?"}, // out of range
	}
	for _, c := range cases {
		if got := c.op.String(); got != c.want {
			t.Errorf("Op(%d).String() = %q, want %q", c.op, got, c.want)
		}
	}
}

func TestOpIsConstant(t *testing.T) {
	for _, op := range []Op{OpConst32, OpConst64, OpConstF32, OpConstF64} {
		if !op.IsConstant() {
			t.Errorf("%v.IsConstant() = false", op)
		}
	}
	if OpAdd32.IsConstant() {
		t.Error("OpAdd32.IsConstant() = true")
	}
}

func TestOpIsCommutative(t *testing.T) {
	commutative := []Op{
		OpAdd32, OpAdd64, OpMul32, OpMul64,
		OpAnd32, OpAnd64, OpOr32, OpOr64, OpXor32, OpXor64,
		OpEq32, OpEq64, OpNe32, OpNe64,
		OpAddF32, OpAddF64, OpMulF32, OpMulF64,
	}
	for _, op := range commutative {
		if !op.IsCommutative() {
			t.Errorf("%v.IsCommutative() = false", op)
		}
	}
	nonCommutative := []Op{OpSub32, OpDivS32, OpShl32, OpLtS32}
	for _, op := range nonCommutative {
		if op.IsCommutative() {
			t.Errorf("%v.IsCommutative() = true", op)
		}
	}
}

func TestOpHasSideEffect(t *testing.T) {
	sideEffect := []Op{
		OpStore8, OpStore16, OpStore32, OpStore64, OpStoreF32, OpStoreF64,
		OpGlobalSet,
		OpCallDirect, OpCallIndirect, OpCallImport,
		OpHelperCall,
		OpUnreachable,
		OpMemGrow, OpMemoryCopy, OpMemoryFill, OpMemoryInit, OpDataDrop,
	}
	for _, op := range sideEffect {
		if !op.HasSideEffect() {
			t.Errorf("%v.HasSideEffect() = false", op)
		}
	}
	pure := []Op{OpAdd32, OpMul64, OpConst32, OpPhi, OpLoad32}
	for _, op := range pure {
		if op.HasSideEffect() {
			t.Errorf("%v.HasSideEffect() = true", op)
		}
	}
}

// TestValueHasSideEffectHelper exercises the per-helper-name purity table
// reached via Value.HasSideEffect(): trapping helpers (div, rem, non-
// saturating trunc-to-int) must report true; pure helpers (clz, popcnt,
// sqrt, ...) must report false.
func TestValueHasSideEffectHelper(t *testing.T) {
	trapping := []string{
		"i32_div_s", "i32_div_u_s", "i32_rem_s", "i32_rem_u_s",
		"i64_div_s", "i64_div_u_s", "i64_rem_s", "i64_rem_u_s",
		"i32_trunc_f32_s", "i32_trunc_f32_u",
		"i32_trunc_f64_s", "i32_trunc_f64_u",
		"i64_trunc_f32_s", "i64_trunc_f32_u",
		"i64_trunc_f64_s", "i64_trunc_f64_u",
	}
	for _, name := range trapping {
		v := &Value{Op: OpHelperCall, Aux: name}
		if !v.HasSideEffect() {
			t.Errorf("trapping helper %q: Value.HasSideEffect() = false, want true", name)
		}
	}
	pure := []string{
		"i32_clz", "i32_popcnt", "i64_ctz",
		"i32_rotl", "i64_rotr",
		"f32_sqrt", "f64_abs", "f32_min", "f64_copysign",
		"f32_eq", "f64_lt",
		"i32_trunc_sat_f32_s", "i64_trunc_sat_f64_u",
		"i64_extend_i32_s", "i32_wrap_i64",
		"f32_demote_f64", "f64_promote_f32",
		"i32_reinterpret_f32", "f64_reinterpret_i64",
		"i32_extend8_s", "i64_extend32_s",
	}
	for _, name := range pure {
		v := &Value{Op: OpHelperCall, Aux: name}
		if v.HasSideEffect() {
			t.Errorf("pure helper %q: Value.HasSideEffect() = true, want false", name)
		}
	}
	// Missing Aux must be treated as side-effecting (conservative).
	v := &Value{Op: OpHelperCall}
	if !v.HasSideEffect() {
		t.Errorf("OpHelperCall without Aux: Value.HasSideEffect() = false, want true (conservative)")
	}
	// Non-helper ops must agree with Op.HasSideEffect().
	mismatchCases := []struct {
		op   Op
		want bool
	}{
		{OpAdd32, false},
		{OpStore32, true},
		{OpCallImport, true},
		{OpMemGrow, true},
	}
	for _, tc := range mismatchCases {
		got := (&Value{Op: tc.op}).HasSideEffect()
		if got != tc.want {
			t.Errorf("Value{Op:%v}.HasSideEffect() = %v, want %v", tc.op, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// FuncBuilder panics and uncovered paths
// ---------------------------------------------------------------------------

func TestFuncBuilderCurrent(t *testing.T) {
	b := NewFuncBuilder("f", FuncSig{})
	if b.Current() != nil {
		t.Error("Current() should be nil initially")
	}
	blk := b.NewBlock(BlockPlain)
	b.SetCurrent(blk)
	if b.Current() != blk {
		t.Error("Current() should return set block")
	}
}

func TestFuncBuilderConst64(t *testing.T) {
	b := NewFuncBuilder("f64", FuncSig{Results: []Type{TypeI64}})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const64(42)
	if c.Op != OpConst64 {
		t.Errorf("Const64 op = %v, want OpConst64", c.Op)
	}
	if c.AuxInt != 42 {
		t.Errorf("Const64 AuxInt = %d, want 42", c.AuxInt)
	}
}

func TestFuncBuilderLinkPlain(t *testing.T) {
	b := NewFuncBuilder("lp", FuncSig{})
	entry := b.NewBlock(BlockPlain)
	succ := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	b.LinkPlain(succ)
	if len(entry.Succs) != 1 || entry.Succs[0].Block != succ {
		t.Error("LinkPlain did not wire the edge")
	}
}

func TestFuncBuilderNewValuePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewValue with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic", FuncSig{})
	b.NewValue(OpConst32, TypeI32)
}

func TestFuncBuilderNewValueAuxIntPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewValueAuxInt with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic2", FuncSig{})
	b.NewValueAuxInt(OpConst32, TypeI32, 0)
}

func TestFuncBuilderNewValueAuxPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewValueAux with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic3", FuncSig{})
	b.NewValueAux(OpCallDirect, TypeI32, "fn")
}

func TestFuncBuilderLinkPlainPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("LinkPlain with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic4", FuncSig{})
	dummy := b.NewBlock(BlockRet)
	b.LinkPlain(dummy)
}

func TestFuncBuilderLinkIfPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("LinkIf with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic5", FuncSig{})
	thenB := b.NewBlock(BlockRet)
	elseB := b.NewBlock(BlockRet)
	b.LinkIf(nil, thenB, elseB)
}

func TestFuncBuilderFinishRetPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("FinishRet with no current block should panic")
		}
	}()
	b := NewFuncBuilder("panic6", FuncSig{})
	b.FinishRet()
}

// ---------------------------------------------------------------------------
// Value.String edge cases
// ---------------------------------------------------------------------------

func TestValueStringNil(t *testing.T) {
	var v *Value
	if got := v.String(); got != "<nil-value>" {
		t.Errorf("nil Value.String() = %q", got)
	}
}

func TestValueStringAux(t *testing.T) {
	b := NewFuncBuilder("auxtest", FuncSig{})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	v := b.NewValueAux(OpCallDirect, TypeI32, "myfunc")
	s := v.String()
	if !strings.Contains(s, "{myfunc}") {
		t.Errorf("Value.String missing aux: %s", s)
	}
}

func TestValueStringNilArg(t *testing.T) {
	b := NewFuncBuilder("nilarg", FuncSig{})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	// Build a phi with a nil arg to hit the nil-arg branch in String.
	c := b.Const32(1)
	v := b.f.newValue(OpPhi, TypeI32, []*Value{c, nil}, entry, 0, nil)
	s := v.String()
	if !strings.Contains(s, "<nil>") {
		t.Errorf("Value.String with nil arg missing <nil>: %s", s)
	}
}

// ---------------------------------------------------------------------------
// Compact and CountValues
// ---------------------------------------------------------------------------

func TestCompactAndCountValues(t *testing.T) {
	b := NewFuncBuilder("compact", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c1 := b.Const32(1)
	c2 := b.Const32(2)
	_ = b.NewValue(OpAdd32, TypeI32, c1, c2)
	b.FinishRet(c1)
	f := b.Func()

	before := CountValues(f)
	if before != 4 {
		t.Fatalf("before Compact: CountValues=%d, want 4", before)
	}

	// Mark one value dead.
	c2.Op = OpInvalid
	c2.Args = nil

	Compact(f)
	after := CountValues(f)
	if after != 3 {
		t.Errorf("after Compact: CountValues=%d, want 3", after)
	}
}

// ---------------------------------------------------------------------------
// FuncString — uncovered branches
// ---------------------------------------------------------------------------

func TestFuncStringNoResultOrMultiResult(t *testing.T) {
	// Zero results.
	sig0 := FuncSig{}
	b0 := NewFuncBuilder("noret", sig0)
	entry := b0.NewBlock(BlockRet)
	b0.SetEntry(entry)
	b0.SetCurrent(entry)
	b0.FinishRet()
	got0 := FuncString(b0.Func())
	if !strings.Contains(got0, "func noret()") {
		t.Errorf("no-result signature wrong: %s", got0)
	}

	// Two results (multi-result).
	sig2 := FuncSig{Results: []Type{TypeI32, TypeI64}}
	b2 := NewFuncBuilder("multi", sig2)
	entry2 := b2.NewBlock(BlockRet)
	b2.SetEntry(entry2)
	b2.SetCurrent(entry2)
	r0 := b2.Const32(1)
	r1 := b2.Const64(2)
	b2.FinishRet(r0, r1)
	got2 := FuncString(b2.Func())
	if !strings.Contains(got2, "(i32, i64)") {
		t.Errorf("multi-result signature wrong: %s", got2)
	}
}

func TestFuncStringUnreachableAndInvalid(t *testing.T) {
	// Unreachable block kind.
	sig := FuncSig{}
	b := NewFuncBuilder("unreachtest", sig)
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	unreachable := b.NewBlock(BlockUnreachable)
	b.SetCurrent(entry)
	b.LinkPlain(unreachable)
	b.SetCurrent(unreachable)
	got := FuncString(b.Func())
	if !strings.Contains(got, "Unreachable") {
		t.Errorf("Unreachable kind not printed: %s", got)
	}

	// Invalid block kind — set explicitly.
	b2 := NewFuncBuilder("invalidkind", sig)
	entry2 := b2.NewBlock(BlockInvalid)
	b2.SetEntry(entry2)
	got2 := FuncString(b2.Func())
	if !strings.Contains(got2, "<invalid block kind>") {
		t.Errorf("invalid block kind not printed: %s", got2)
	}
}

func TestFuncStringPlainNoSuccs(t *testing.T) {
	// Plain block with no successors (unusual but must not panic).
	sig := FuncSig{}
	b := NewFuncBuilder("plainnosuccs", sig)
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	got := FuncString(b.Func())
	if !strings.Contains(got, "Plain → <none>") {
		t.Errorf("Plain with no succs: %s", got)
	}
}

func TestFuncStringIfNoControl(t *testing.T) {
	// If block with no Control set and no succs — triggers nil-control path.
	sig := FuncSig{}
	b := NewFuncBuilder("ifnoctl", sig)
	entry := b.NewBlock(BlockIf)
	b.SetEntry(entry)
	got := FuncString(b.Func())
	if !strings.Contains(got, "If v0 →") {
		t.Errorf("If with nil control: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

func buildSimpleValid(t *testing.T) *Func {
	t.Helper()
	sig := FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}}
	b := NewFuncBuilder("valid", sig)
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p := b.Param(0, TypeI32)
	b.FinishRet(p)
	return b.Func()
}

func TestVerifyValid(t *testing.T) {
	f := buildSimpleValid(t)
	if err := Verify(f); err != nil {
		t.Errorf("Verify valid func: %v", err)
	}
}

func TestVerifyNoEntry(t *testing.T) {
	f := NewFunc("noentry", FuncSig{})
	f.NewBlock(BlockRet)
	if err := Verify(f); err == nil {
		t.Error("expected error for missing entry")
	}
}

func TestVerifyPlainWrongSuccCount(t *testing.T) {
	// Plain block with 0 successors.
	b := NewFuncBuilder("plain0", FuncSig{})
	entry := b.NewBlock(BlockPlain) // Plain but no succ added
	b.SetEntry(entry)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for Plain block with 0 succs")
	}
}

func TestVerifyIfWrongSuccCount(t *testing.T) {
	// If block with only 1 successor.
	b := NewFuncBuilder("if1", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockIf)
	thenB := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	cond := b.Const32(1)
	entry.Control = cond
	AddEdge(entry, thenB) // only 1 succ
	b.SetCurrent(thenB)
	b.FinishRet(cond)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for If block with 1 succ")
	}
}

func TestVerifyIfNilControl(t *testing.T) {
	// If block with nil Control.
	b := NewFuncBuilder("ifnilctl", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockIf)
	thenB := b.NewBlock(BlockRet)
	elseB := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	AddEdge(entry, thenB)
	AddEdge(entry, elseB)
	// Don't set entry.Control — leave nil.
	b.SetCurrent(thenB)
	b.FinishRet(c)
	b.SetCurrent(elseB)
	b.FinishRet(c)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for If block with nil Control")
	}
}

func TestVerifyRetHasSucc(t *testing.T) {
	// Ret block with a successor.
	b := NewFuncBuilder("retsucc", FuncSig{})
	entry := b.NewBlock(BlockRet)
	other := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	// Manually wire entry → other even though entry is Ret.
	AddEdge(entry, other)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for Ret block with succs")
	}
}

func TestVerifyInvalidKind(t *testing.T) {
	// Block with kind BlockInvalid.
	b := NewFuncBuilder("invalidkind", FuncSig{})
	entry := b.NewBlock(BlockInvalid)
	b.SetEntry(entry)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for BlockInvalid kind")
	}
}

func TestVerifyPhiArityMismatch(t *testing.T) {
	// A phi with 2 args but block has 1 pred.
	b := NewFuncBuilder("phiarity", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	merge := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c1 := b.Const32(1)
	c2 := b.Const32(2)
	AddEdge(entry, merge)
	b.SetCurrent(merge)
	// Manually create phi with 2 args, but merge only has 1 pred.
	phi := b.f.newValue(OpPhi, TypeI32, []*Value{c1, c2}, merge, 0, nil)
	merge.Values = append(merge.Values, phi)
	b.FinishRet(phi)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for phi arity mismatch")
	}
}

func TestVerifyPhiAfterNonPhi(t *testing.T) {
	// A phi that appears after a non-phi value.
	b := NewFuncBuilder("phiorder", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	merge := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c1 := b.Const32(1)
	AddEdge(entry, merge)
	b.SetCurrent(merge)
	// Emit a non-phi first, then a phi.
	nonPhi := b.f.newValue(OpConst32, TypeI32, nil, merge, 99, nil)
	merge.Values = append(merge.Values, nonPhi)
	phi := b.f.newValue(OpPhi, TypeI32, []*Value{c1}, merge, 0, nil)
	merge.Values = append(merge.Values, phi)
	b.FinishRet(nonPhi)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for phi after non-phi")
	}
}

func TestVerifyNilArgInValue(t *testing.T) {
	// A value with a nil arg.
	b := NewFuncBuilder("nilarg", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	// Manufacture a value with a nil argument.
	v := b.f.newValue(OpAdd32, TypeI32, []*Value{c, nil}, entry, 0, nil)
	entry.Values = append(entry.Values, v)
	b.FinishRet(c)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for nil arg")
	}
}

func TestVerifyValueInWrongBlock(t *testing.T) {
	// A value's Block pointer points to a different block.
	b := NewFuncBuilder("wrongblock", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	other := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	AddEdge(entry, other)
	b.SetCurrent(other)
	b.FinishRet(c)
	// Move c's Block pointer to other but keep it in entry.Values.
	c.Block = other
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for value in wrong block")
	}
}

func TestVerifyUnreachableBlock(t *testing.T) {
	// A block with no path from entry.
	b := NewFuncBuilder("unreachfail", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	dead := b.NewBlock(BlockRet) // never wired
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(42)
	b.FinishRet(c)
	b.SetCurrent(dead)
	d := b.Const32(0)
	b.FinishRet(d)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for unreachable block")
	}
}

func TestVerifyUseDominanceSameBlock(t *testing.T) {
	// Value uses another defined later in the same block — violation.
	b := NewFuncBuilder("latedep", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	// Manually build: v1 = Add(v2, v2), but place v2 after v1.
	f := b.Func()
	v2 := f.newValue(OpConst32, TypeI32, nil, entry, 7, nil)
	v1 := f.newValue(OpAdd32, TypeI32, []*Value{v2, v2}, entry, 0, nil)
	// v1 listed first, v2 listed second — v1 uses v2 before its definition.
	entry.Values = []*Value{v1, v2}
	retv := f.newValue(OpCopy, TypeI32, []*Value{v1}, entry, 0, nil)
	entry.Values = append(entry.Values, retv)
	f.Sig.Results = []Type{TypeI32}
	if err := Verify(f); err == nil {
		t.Error("expected error for use of value defined later in same block")
	}
}

func TestVerifyNilSuccEdge(t *testing.T) {
	// Build a Plain block with a manually set nil successor.
	b := NewFuncBuilder("nilsucc", FuncSig{})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	// Add a nil-block edge manually.
	entry.Succs = append(entry.Succs, Edge{Block: nil, Index: 0})
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for nil succ edge")
	}
}

func TestVerifyEdgeAsymmetric(t *testing.T) {
	// Succ edge index points to wrong block in pred list.
	b := NewFuncBuilder("asym", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	succ := b.NewBlock(BlockRet)
	other := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	AddEdge(entry, succ)
	// Point the succ edge's index to other instead.
	succ.Preds[0] = Edge{Block: other, Index: 0}
	b.SetCurrent(succ)
	b.FinishRet(c)
	b.SetCurrent(other)
	b.FinishRet(c)
	if err := Verify(b.Func()); err == nil {
		t.Error("expected error for asymmetric edge")
	}
}

// ---------------------------------------------------------------------------
// PruneDeadBlocks
// ---------------------------------------------------------------------------

func TestPruneDeadBlocks(t *testing.T) {
	b := NewFuncBuilder("prunetest", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	dead := b.NewBlock(BlockRet) // no preds, no succs
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	b.FinishRet(c)
	b.SetCurrent(dead)
	d := b.Const32(0)
	b.FinishRet(d)
	f := b.Func()

	if len(f.Blocks) != 2 {
		t.Fatalf("expected 2 blocks before prune, got %d", len(f.Blocks))
	}
	PruneDeadBlocks(f)
	if len(f.Blocks) != 1 {
		t.Errorf("expected 1 block after prune, got %d", len(f.Blocks))
	}
	if f.Blocks[0] != entry {
		t.Error("entry block removed by prune")
	}
}

// Under branch-based exception handling a catch handler is reached by a real
// CFG edge (the check-and-branch after a call that may raise), so it is an
// ordinary block: one with no edges at all belongs to a try whose protected
// body cannot raise, and pruning it — region metadata and all — is correct.
func TestPruneDeadBlocksUnreachableHandlerRemoved(t *testing.T) {
	b := NewFuncBuilder("prune_handler", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockRet)
	reached := b.NewBlock(BlockRet) // a handler the body really branches to
	unreached := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	b.FinishRet(b.Const32(1))
	b.SetCurrent(reached)
	b.FinishRet(b.Const32(42))
	b.SetCurrent(unreached)
	b.FinishRet(b.Const32(0))
	AddEdge(entry, reached)
	f := b.Func()
	f.TryRegions = []*TryRegion{{
		Entry: entry, Post: entry,
		Handlers: []TryHandler{{Block: reached}, {Block: unreached}},
	}}

	PruneDeadBlocks(f)

	kept := map[*Block]bool{}
	for _, blk := range f.Blocks {
		kept[blk] = true
	}
	if !kept[entry] {
		t.Error("entry block removed by prune")
	}
	if !kept[reached] {
		t.Error("handler with a real predecessor removed by prune")
	}
	if kept[unreached] {
		t.Error("edge-less handler survived prune")
	}
}

func TestPruneDeadBlocksEntryKept(t *testing.T) {
	// Entry block with no preds and no succs must not be pruned.
	b := NewFuncBuilder("prune_entry", FuncSig{})
	entry := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	b.FinishRet()
	f := b.Func()
	PruneDeadBlocks(f)
	if len(f.Blocks) != 1 {
		t.Errorf("entry should survive prune, got %d blocks", len(f.Blocks))
	}
}

// ---------------------------------------------------------------------------
// domtree.go: Dominators, PostDominators, BackEdges, LoopHeaders, IsReducible
// ---------------------------------------------------------------------------

func buildLinearChain() *Func {
	// entry → b1 → b2 (ret)
	b := NewFuncBuilder("linear", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b1 := b.NewBlock(BlockPlain)
	ret := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(0)
	AddEdge(entry, b1)
	b.SetCurrent(b1)
	AddEdge(b1, ret)
	b.SetCurrent(ret)
	b.FinishRet(c)
	return b.Func()
}

func buildLoopFunc() *Func {
	// entry → header ↺ header → exit
	b := NewFuncBuilder("loop", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	header := b.NewBlock(BlockIf)
	exit := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(0)
	AddEdge(entry, header)
	b.SetCurrent(header)
	cond := b.Const32(1)
	header.Control = cond
	AddEdge(header, header) // back-edge: Succs[0] = self (then)
	AddEdge(header, exit)   // Succs[1] = else (exit)
	b.SetCurrent(exit)
	b.FinishRet(c)
	return b.Func()
}

func TestDominators(t *testing.T) {
	f := buildLinearChain()
	idom := Dominators(f)
	if len(idom) == 0 {
		t.Fatal("Dominators returned empty map")
	}
	// Entry dominates itself.
	if idom[f.Entry.ID] != f.Entry {
		t.Errorf("Entry idom should be itself")
	}
}

func TestPostDominators(t *testing.T) {
	f := buildLinearChain()
	pdom := PostDominators(f)
	if pdom == nil {
		t.Fatal("PostDominators returned nil")
	}
}

func TestBackEdgesAndLoopHeaders(t *testing.T) {
	f := buildLoopFunc()
	edges := BackEdges(f)
	if len(edges) == 0 {
		t.Error("expected at least one back-edge in loop function")
	}
	hdrs := LoopHeaders(f)
	// The header block should be a loop header.
	found := false
	for _, b := range f.Blocks {
		if hdrs[b.ID] {
			found = true
			break
		}
	}
	if !found {
		t.Error("no loop header found")
	}
}

func TestIsReducible(t *testing.T) {
	f := buildLoopFunc()
	if !IsReducible(f) {
		t.Error("structured loop should be reducible")
	}
}

func TestIsReducibleLinear(t *testing.T) {
	f := buildLinearChain()
	if !IsReducible(f) {
		t.Error("linear chain should be reducible")
	}
}

func TestPostDominatorsWithUnreachable(t *testing.T) {
	// A function with a BlockUnreachable block.
	b := NewFuncBuilder("unreachpost", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	trap := b.NewBlock(BlockUnreachable)
	ret := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(0)
	AddEdge(entry, trap)
	// Also make entry reach ret via second edge doesn't apply to Plain —
	// let trap be the only path. So entry is also Plain → trap → exit.
	// We need a second entry for ret or use BlockIf.
	// Simplify: plain → trap, and trap has no succs.
	// Also add ret as an isolated block just to test.
	b.SetCurrent(trap)
	b.SetCurrent(ret)
	b.FinishRet(c)
	f := b.Func()
	pdom := PostDominators(f)
	_ = pdom // Just verifies it doesn't crash.
}

// ---------------------------------------------------------------------------
// MemMetrics additional coverage
// ---------------------------------------------------------------------------

func TestMemMetricsAddOpt(t *testing.T) {
	m := NewMemMetrics()
	m.AddOpt(100, 60)
	m.AddOpt(50, 40)
	if m.OptInsBefore != 150 {
		t.Errorf("OptInsBefore = %d, want 150", m.OptInsBefore)
	}
	if m.OptInsAfter != 100 {
		t.Errorf("OptInsAfter = %d, want 100", m.OptInsAfter)
	}
}

func TestMemMetricsOptReduction(t *testing.T) {
	m := NewMemMetrics()
	if m.OptReduction() != 0 {
		t.Error("OptReduction() with zero before should be 0")
	}
	m.AddOpt(100, 40)
	got := m.OptReduction()
	want := 0.6
	if got < want-0.001 || got > want+0.001 {
		t.Errorf("OptReduction() = %v, want %v", got, want)
	}
}

func TestMemMetricsSummary(t *testing.T) {
	m := NewMemMetrics()
	s := m.Summary()
	if !strings.Contains(s, "SSA-lowered functions") {
		t.Errorf("Summary missing expected text: %s", s)
	}
	// Summary with accesses.
	f := buildFrameFunc(false)
	mc := ClassifyMemory(f)
	m.Add(f, mc)
	m.AddOpt(10, 7)
	m.StructuredFuncs = 2
	m.GotoFuncs = 1
	s2 := m.Summary()
	if !strings.Contains(s2, "SSA instructions") {
		t.Errorf("Summary with opt missing SSA instructions line: %s", s2)
	}
	if !strings.Contains(s2, "emit form") {
		t.Errorf("Summary missing emit form line: %s", s2)
	}
}

func TestMemMetricsTopSlabFunctions(t *testing.T) {
	m := NewMemMetrics()
	f1 := buildFrameFunc(false)
	f1.Name = "f1"
	f2 := buildFrameFunc(true)
	f2.Name = "f2"
	m.Add(f1, ClassifyMemory(f1))
	m.Add(f2, ClassifyMemory(f2))

	top := m.TopSlabFunctions(1)
	if len(top) != 1 {
		t.Fatalf("TopSlabFunctions(1) returned %d, want 1", len(top))
	}

	top2 := m.TopSlabFunctions(10)
	if len(top2) != 2 {
		t.Fatalf("TopSlabFunctions(10) returned %d, want 2", len(top2))
	}
}

func TestMemMetricsRateZero(t *testing.T) {
	m := NewMemMetrics()
	if m.Rate() != 0 {
		t.Error("Rate() on empty metrics should be 0")
	}
}

// ---------------------------------------------------------------------------
// AliasClass.String
// ---------------------------------------------------------------------------

func TestAliasClassString(t *testing.T) {
	cases := []struct {
		c    AliasClass
		want string
	}{
		{AliasUnknown, "unknown"},
		{AliasSlab, "slab"},
		{AliasFrame, "frame"},
		{AliasRodata, "rodata"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("AliasClass(%d).String() = %q, want %q", c.c, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// memclass helpers: constFoldAddr, isFrameOffset, frameEscapes edge cases
// ---------------------------------------------------------------------------

func TestConstFoldAddrNil(t *testing.T) {
	if constFoldAddr(nil) != nil {
		t.Error("constFoldAddr(nil) should return nil")
	}
}

func TestConstFoldAddrAdd32(t *testing.T) {
	// Two const32 operands: should fold to their sum.
	a := &Value{Op: OpConst32, Type: TypeI32, AuxInt: 10}
	b := &Value{Op: OpConst32, Type: TypeI32, AuxInt: 20}
	add := &Value{Op: OpAdd32, Type: TypeI32, Args: []*Value{a, b}}
	result := constFoldAddr(add)
	if result == nil || result.Op != OpConst32 || result.AuxInt != 30 {
		t.Errorf("constFoldAddr Add32 fold: got %v", result)
	}
}

func TestConstFoldAddrCopy(t *testing.T) {
	inner := &Value{Op: OpConst32, Type: TypeI32, AuxInt: 5}
	copy := &Value{Op: OpCopy, Type: TypeI32, Args: []*Value{inner}}
	result := constFoldAddr(copy)
	if result == nil || result.Op != OpConst32 {
		t.Errorf("constFoldAddr(copy) should unwrap to inner const, got %v", result)
	}
}

func TestIsFrameOffsetSub32NonConst(t *testing.T) {
	// fp - dynamicValue (not const) should NOT be frame-derived.
	fp := &Value{ID: 1, Op: OpSub32}
	dyn := &Value{ID: 2, Op: OpAdd32} // not a const
	sub := &Value{Op: OpSub32, Args: []*Value{fp, dyn}}
	fd := map[ValueID]bool{fp.ID: true}
	if isFrameOffset(sub, fd) {
		t.Error("sub with non-const should not be frame offset")
	}
}

func TestIsFrameOffsetAdd32BothConst(t *testing.T) {
	// Two non-frame-derived constants: Add32 of them is not a frame offset.
	c1 := &Value{ID: 10, Op: OpConst32, AuxInt: 4}
	c2 := &Value{ID: 11, Op: OpConst32, AuxInt: 8}
	add := &Value{Op: OpAdd32, Args: []*Value{c1, c2}}
	fd := map[ValueID]bool{}
	if isFrameOffset(add, fd) {
		t.Error("add of two unrelated consts should not be a frame offset")
	}
}

func TestFrameEscapesOpaqueMath(t *testing.T) {
	// Build a function where the frame pointer is used in non-constant
	// arithmetic (e.g. fp - dynamic), triggering the escape reason
	// "frame pointer used in non-constant arithmetic".
	b := NewFuncBuilder("opaque", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, TypeI32)
	g0 := b.NewValueAuxInt(OpGlobalGet, TypeI32, 0)
	n := b.Const32(16)
	fp := b.NewValue(OpSub32, TypeI32, g0, n) // frame pointer
	b.NewValueAuxInt(OpGlobalSet, TypeMem, 0, fp)
	// fp - p0: p0 is not a constant, so result is not frame-derived.
	opaqueAdd := b.NewValue(OpSub32, TypeI32, fp, p0)
	_ = opaqueAdd
	b.FinishRet(fp)
	f := b.Func()

	mc := ClassifyMemory(f)
	if !mc.FrameEscapes {
		t.Errorf("frame should escape due to opaque arithmetic, reason: %s", mc.EscapeReason)
	}
}

func TestFrameEscapesPointerStoredToMem(t *testing.T) {
	// Frame pointer stored as the *value* of a store (Args[1]).
	b := NewFuncBuilder("fpstore", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, TypeI32)
	g0 := b.NewValueAuxInt(OpGlobalGet, TypeI32, 0)
	n := b.Const32(16)
	fp := b.NewValue(OpSub32, TypeI32, g0, n)
	b.NewValueAuxInt(OpGlobalSet, TypeMem, 0, fp)
	// Store fp as the value (not address) → escape.
	b.NewValueAuxInt(OpStore32, TypeMem, 0, p0, fp)
	b.FinishRet(fp)
	f := b.Func()

	mc := ClassifyMemory(f)
	if !mc.FrameEscapes {
		t.Errorf("frame should escape when fp is stored as value, reason: %s", mc.EscapeReason)
	}
	if mc.EscapeReason != "frame pointer stored to memory" {
		t.Errorf("unexpected escape reason: %s", mc.EscapeReason)
	}
}

func TestClassifyMemoryRodata(t *testing.T) {
	// A load from a compile-time constant address — should be AliasRodata.
	b := NewFuncBuilder("rodata", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	addr := b.Const32(1024) // constant address
	mem := b.NewValueAuxInt(OpLoad32, TypeI32, 0, addr)
	_ = mem
	b.FinishRet(addr)
	f := b.Func()

	mc := ClassifyMemory(f)
	found := false
	for _, c := range mc.Class {
		if c == AliasRodata {
			found = true
		}
	}
	if !found {
		t.Error("expected AliasRodata for load from const address")
	}
}

func TestClassifyMemoryDynamicAddrSlab(t *testing.T) {
	// A load from a dynamic (non-const) address — should be AliasSlab.
	b := NewFuncBuilder("slab", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, TypeI32)
	mem := b.NewValueAuxInt(OpLoad32, TypeI32, 0, p0)
	_ = mem
	b.FinishRet(p0)
	f := b.Func()

	mc := ClassifyMemory(f)
	found := false
	for _, c := range mc.Class {
		if c == AliasSlab {
			found = true
		}
	}
	if !found {
		t.Error("expected AliasSlab for load from param address")
	}
}

// ---------------------------------------------------------------------------
// Verify use-dominance: cross-block dominance violation
// ---------------------------------------------------------------------------

func TestVerifyUseDominanceCrossBlock(t *testing.T) {
	// entry (If) → b1, b2. b1 defines v, b2 tries to use v without
	// b1 dominating b2. This is a use-dominance violation.
	b := NewFuncBuilder("domviol", FuncSig{Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockIf)
	b1 := b.NewBlock(BlockRet)
	b2 := b.NewBlock(BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	entry.Control = c
	AddEdge(entry, b1)
	AddEdge(entry, b2)
	b.SetCurrent(b1)
	local := b.Const32(99) // defined only in b1
	b.FinishRet(local)
	b.SetCurrent(b2)
	// Directly put a use of local in b2.
	v := b.f.newValue(OpCopy, TypeI32, []*Value{local}, b2, 0, nil)
	b2.Values = append([]*Value{v}, b2.Values...)
	b.FinishRet(v)
	f := b.Func()

	if err := Verify(f); err == nil {
		t.Error("expected use-dominance error for cross-block use without domination")
	}
}
