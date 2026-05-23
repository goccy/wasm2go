// Package pass — additional tests to raise statement coverage to ≥85%.
// Covers: uncovered foldValue ops, intConst OpConst64, argIs32 no-args,
// CSE ineligible values and nil-arg cseKey, Simplify edge cases,
// trivialPhiArg nil-arg, BranchFold no-change path, removeEdge no-match paths.
package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// ---------------------------------------------------------------------------
// ConstProp: cover all remaining foldValue op branches
// ---------------------------------------------------------------------------

func buildConstFunc(op ssa.Op, typ ssa.Type, a, b int64) (*ssa.Func, *ssa.Value) {
	var paramTyp ssa.Type
	switch typ {
	case ssa.TypeI64:
		paramTyp = ssa.TypeI64
	default:
		paramTyp = ssa.TypeI32
	}
	sig := ssa.FuncSig{Results: []ssa.Type{paramTyp}}
	bl := ssa.NewFuncBuilder("cptest", sig)
	entry := bl.NewBlock(ssa.BlockRet)
	bl.SetEntry(entry)
	bl.SetCurrent(entry)
	var va, vb *ssa.Value
	if paramTyp == ssa.TypeI64 {
		va = bl.NewValueAuxInt(ssa.OpConst64, ssa.TypeI64, a)
		vb = bl.NewValueAuxInt(ssa.OpConst64, ssa.TypeI64, b)
	} else {
		va = bl.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, a)
		vb = bl.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, b)
	}
	v := bl.NewValue(op, typ, va, vb)
	bl.FinishRet(v)
	return bl.Func(), v
}

func assertFoldedInt(t *testing.T, op ssa.Op, typ ssa.Type, a, b, want int64) {
	t.Helper()
	f, v := buildConstFunc(op, typ, a, b)
	if !ConstProp(f) {
		t.Errorf("%v: ConstProp returned false", op)
		return
	}
	if v.AuxInt != want {
		t.Errorf("%v: folded AuxInt = %d, want %d", op, v.AuxInt, want)
	}
}

func assertFoldedBool(t *testing.T, op ssa.Op, typ ssa.Type, a, b int64, want bool) {
	t.Helper()
	f, v := buildConstFunc(op, typ, a, b)
	if !ConstProp(f) {
		t.Errorf("%v: ConstProp returned false", op)
		return
	}
	var wantInt int64
	if want {
		wantInt = 1
	}
	if v.AuxInt != wantInt {
		t.Errorf("%v(%d,%d): folded AuxInt = %d, want %d", op, a, b, v.AuxInt, wantInt)
	}
}

func TestConstPropSub32(t *testing.T) { assertFoldedInt(t, ssa.OpSub32, ssa.TypeI32, 10, 3, 7) }
func TestConstPropSub64(t *testing.T) { assertFoldedInt(t, ssa.OpSub64, ssa.TypeI64, 20, 5, 15) }
func TestConstPropMul32(t *testing.T) { assertFoldedInt(t, ssa.OpMul32, ssa.TypeI32, 3, 4, 12) }
func TestConstPropMul64(t *testing.T) { assertFoldedInt(t, ssa.OpMul64, ssa.TypeI64, 5, 6, 30) }
func TestConstPropAnd32(t *testing.T) {
	assertFoldedInt(t, ssa.OpAnd32, ssa.TypeI32, 0b1100, 0b1010, 0b1000)
}
func TestConstPropAnd64(t *testing.T) { assertFoldedInt(t, ssa.OpAnd64, ssa.TypeI64, 0xFF, 0x0F, 0x0F) }
func TestConstPropOr32(t *testing.T) {
	assertFoldedInt(t, ssa.OpOr32, ssa.TypeI32, 0b1100, 0b0011, 0b1111)
}
func TestConstPropOr64(t *testing.T) { assertFoldedInt(t, ssa.OpOr64, ssa.TypeI64, 1, 2, 3) }
func TestConstPropXor32(t *testing.T) {
	assertFoldedInt(t, ssa.OpXor32, ssa.TypeI32, 0b1111, 0b0101, 0b1010)
}
func TestConstPropXor64(t *testing.T)  { assertFoldedInt(t, ssa.OpXor64, ssa.TypeI64, 0xF0, 0xFF, 0x0F) }
func TestConstPropShl32(t *testing.T)  { assertFoldedInt(t, ssa.OpShl32, ssa.TypeI32, 1, 3, 8) }
func TestConstPropShl64(t *testing.T)  { assertFoldedInt(t, ssa.OpShl64, ssa.TypeI64, 1, 4, 16) }
func TestConstPropShrS32(t *testing.T) { assertFoldedInt(t, ssa.OpShrS32, ssa.TypeI32, -8, 1, -4) }
func TestConstPropShrS64(t *testing.T) { assertFoldedInt(t, ssa.OpShrS64, ssa.TypeI64, -16, 1, -8) }
func TestConstPropShrU32(t *testing.T) { assertFoldedInt(t, ssa.OpShrU32, ssa.TypeI32, 8, 1, 4) }
func TestConstPropShrU64(t *testing.T) { assertFoldedInt(t, ssa.OpShrU64, ssa.TypeI64, 16, 1, 8) }

func TestConstPropAdd64(t *testing.T) { assertFoldedInt(t, ssa.OpAdd64, ssa.TypeI64, 100, 200, 300) }

func TestConstPropEq32True(t *testing.T)  { assertFoldedBool(t, ssa.OpEq32, ssa.TypeBool, 5, 5, true) }
func TestConstPropEq32False(t *testing.T) { assertFoldedBool(t, ssa.OpEq32, ssa.TypeBool, 5, 6, false) }
func TestConstPropEq64(t *testing.T)      { assertFoldedBool(t, ssa.OpEq64, ssa.TypeBool, 7, 7, true) }
func TestConstPropNe32(t *testing.T)      { assertFoldedBool(t, ssa.OpNe32, ssa.TypeBool, 1, 2, true) }
func TestConstPropNe64(t *testing.T)      { assertFoldedBool(t, ssa.OpNe64, ssa.TypeBool, 3, 3, false) }
func TestConstPropLtS64(t *testing.T)     { assertFoldedBool(t, ssa.OpLtS64, ssa.TypeBool, -1, 1, true) }
func TestConstPropLeS32(t *testing.T)     { assertFoldedBool(t, ssa.OpLeS32, ssa.TypeBool, 5, 5, true) }
func TestConstPropLeS64(t *testing.T)     { assertFoldedBool(t, ssa.OpLeS64, ssa.TypeBool, 10, 5, false) }
func TestConstPropLtU32(t *testing.T)     { assertFoldedBool(t, ssa.OpLtU32, ssa.TypeBool, 1, 2, true) }
func TestConstPropLeU32(t *testing.T)     { assertFoldedBool(t, ssa.OpLeU32, ssa.TypeBool, 2, 2, true) }
func TestConstPropLtU64(t *testing.T)     { assertFoldedBool(t, ssa.OpLtU64, ssa.TypeBool, 3, 5, true) }
func TestConstPropLeU64(t *testing.T)     { assertFoldedBool(t, ssa.OpLeU64, ssa.TypeBool, 5, 5, true) }

// OpLtS32 with i32 inputs — exercises the argIs32(v) path for bool result width.
func TestConstPropLtS32With32BitArgs(t *testing.T) {
	assertFoldedBool(t, ssa.OpLtS32, ssa.TypeBool, 3, 7, true)
}

// intConst with OpConst64 input.
func TestConstPropWithConst64Inputs(t *testing.T) {
	sig := ssa.FuncSig{Results: []ssa.Type{ssa.TypeI64}}
	b := ssa.NewFuncBuilder("c64fold", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Const64(10)
	y := b.Const64(20)
	sum := b.NewValue(ssa.OpAdd64, ssa.TypeI64, x, y)
	b.FinishRet(sum)
	f := b.Func()
	if !ConstProp(f) {
		t.Fatal("ConstProp did not fold Const64 + Const64")
	}
	if sum.AuxInt != 30 {
		t.Errorf("folded value = %d, want 30", sum.AuxInt)
	}
}

// argIs32 with zero args — exercises the false path.
func TestArgIs32ZeroArgs(t *testing.T) {
	v := &ssa.Value{Op: ssa.OpConst32, Args: nil}
	if argIs32(v) {
		t.Error("argIs32 with zero args should return false")
	}
}

// ---------------------------------------------------------------------------
// ConstProp: foldValue with 1-arg or nil-arg values (no-op paths)
// ---------------------------------------------------------------------------

func TestConstPropOneArgValue(t *testing.T) {
	sig := ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("onearg", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	// OpCopy has one arg — foldValue returns false.
	cp := b.NewValue(ssa.OpCopy, ssa.TypeI32, c)
	b.FinishRet(cp)
	f := b.Func()
	// ConstProp should not fold a 1-arg value.
	if ConstProp(f) {
		t.Error("ConstProp should not fold 1-arg OpCopy")
	}
}

// ---------------------------------------------------------------------------
// CSE: cover ineligible values (loads, params, phi, side-effecting),
//     and nil-arg commutative key, no-change path, control rewrite
// ---------------------------------------------------------------------------

func TestCSEIneligibleLoad(t *testing.T) {
	// Two identical loads must NOT be CSE'd.
	b := ssa.NewFuncBuilder("cseload", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	ld1 := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, p0)
	ld2 := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, p0)
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, ld1, ld2)
	b.FinishRet(v)
	f := b.Func()

	if CSE(f) {
		t.Error("CSE should not merge loads")
	}
	if ld1.Op == ssa.OpInvalid || ld2.Op == ssa.OpInvalid {
		t.Error("CSE wrongly merged loads")
	}
}

func TestCSEIneligibleGlobalGet(t *testing.T) {
	// Two identical OpGlobalGet must NOT be CSE'd.
	b := ssa.NewFuncBuilder("cseglobget", ssa.FuncSig{
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	g1 := b.NewValueAuxInt(ssa.OpGlobalGet, ssa.TypeI32, 0)
	g2 := b.NewValueAuxInt(ssa.OpGlobalGet, ssa.TypeI32, 0)
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, g1, g2)
	b.FinishRet(v)
	f := b.Func()

	if CSE(f) {
		t.Error("CSE should not merge global loads")
	}
}

func TestCSEIneligiblePhi(t *testing.T) {
	// Phis must not be merged by CSE.
	b := ssa.NewFuncBuilder("csephi", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	merge := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	ssa.AddEdge(entry, merge)
	b.SetCurrent(merge)
	phi1 := b.NewValue(ssa.OpPhi, ssa.TypeI32, p0)
	phi2 := b.NewValue(ssa.OpPhi, ssa.TypeI32, p0)
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, phi1, phi2)
	b.FinishRet(v)
	f := b.Func()

	CSE(f)
	if phi1.Op == ssa.OpInvalid || phi2.Op == ssa.OpInvalid {
		t.Error("CSE wrongly merged phis")
	}
}

func TestCSENoChange(t *testing.T) {
	// CSE with nothing to merge returns false.
	b := ssa.NewFuncBuilder("csenoop", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	b.FinishRet(p0)
	f := b.Func()
	if CSE(f) {
		t.Error("CSE on unique values should return false")
	}
}

func TestCSECommutativeCanonicalisation(t *testing.T) {
	// a+b and b+a should be merged by CSE's commutative canonicalisation.
	b := ssa.NewFuncBuilder("csecomm", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32, ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	p1 := b.Param(1, ssa.TypeI32)
	ab := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p0, p1) // a+b
	ba := b.NewValue(ssa.OpAdd32, ssa.TypeI32, p1, p0) // b+a
	v := b.NewValue(ssa.OpAdd32, ssa.TypeI32, ab, ba)
	b.FinishRet(v)
	f := b.Func()

	if !CSE(f) {
		t.Error("CSE should merge a+b and b+a")
	}
	if ab.Op != ssa.OpInvalid && ba.Op != ssa.OpInvalid {
		// one of them should be merged away
		if ab.Op != ssa.OpInvalid && ba.Op != ssa.OpInvalid {
			t.Error("CSE: neither a+b nor b+a was merged")
		}
	}
}

func TestCSEControlRewrite(t *testing.T) {
	// CSE must also rewrite a block's Control value when the duplicate
	// is the condition of an If block.
	b := ssa.NewFuncBuilder("csectl", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockRet)
	elseB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	// Two identical comparisons — the first one is the real condition.
	cond1 := b.NewValue(ssa.OpEq32, ssa.TypeBool, p0, p0)
	cond2 := b.NewValue(ssa.OpEq32, ssa.TypeBool, p0, p0) // duplicate
	entry.Control = cond2
	ssa.AddEdge(entry, thenB)
	ssa.AddEdge(entry, elseB)
	c := b.Const32(1)
	b.SetCurrent(thenB)
	b.FinishRet(c)
	b.SetCurrent(elseB)
	b.FinishRet(c)
	f := b.Func()

	CSE(f)
	// After CSE cond2 should be merged away and Control rewritten to cond1.
	if entry.Control != cond1 {
		t.Errorf("CSE did not rewrite Control: got v%d want v%d", entry.Control.ID, cond1.ID)
	}
}

// ---------------------------------------------------------------------------
// Simplify: edge cases
// ---------------------------------------------------------------------------

func TestSimplifyNoChange(t *testing.T) {
	// A function with no copies and no trivial phis — Simplify returns false.
	b := ssa.NewFuncBuilder("simpnoop", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	b.FinishRet(p0)
	f := b.Func()
	if Simplify(f) {
		t.Error("Simplify on a pure param-return should return false")
	}
}

func TestSimplifyRetMarkerPreserved(t *testing.T) {
	// The Ret-tail OpCopy marker must NOT be dissolved by Simplify.
	b := ssa.NewFuncBuilder("simpret", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	b.FinishRet(p0)
	f := b.Func()

	// The last value in entry is the Ret marker (OpCopy wrapping p0).
	retMarker := entry.Values[len(entry.Values)-1]
	if retMarker.Op != ssa.OpCopy {
		t.Fatalf("expected OpCopy as ret marker, got %v", retMarker.Op)
	}
	Simplify(f)
	if retMarker.Op != ssa.OpCopy {
		t.Errorf("Simplify dissolved the Ret marker: op=%v", retMarker.Op)
	}
}

func TestSimplifyControlRewrite(t *testing.T) {
	// Simplify must rewrite a block's Control value through copies.
	b := ssa.NewFuncBuilder("simpctl", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockRet)
	elseB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	// A copy of p0 used as the If condition.
	cp := b.NewValue(ssa.OpCopy, ssa.TypeI32, p0)
	entry.Control = cp
	ssa.AddEdge(entry, thenB)
	ssa.AddEdge(entry, elseB)
	c := b.Const32(0)
	b.SetCurrent(thenB)
	b.FinishRet(c)
	b.SetCurrent(elseB)
	b.FinishRet(c)
	f := b.Func()

	if !Simplify(f) {
		t.Error("Simplify should propagate copy through Control")
	}
	if entry.Control != p0 {
		t.Errorf("Control not rewritten: got v%d want v%d (p0)", entry.Control.ID, p0.ID)
	}
}

// ---------------------------------------------------------------------------
// trivialPhiArg: nil args
// ---------------------------------------------------------------------------

func TestTrivialPhiArgAllNil(t *testing.T) {
	// A phi with all nil args returns nil (treated as non-trivial).
	v := &ssa.Value{Op: ssa.OpPhi, Args: []*ssa.Value{nil, nil}}
	if got := trivialPhiArg(v); got != nil {
		t.Errorf("trivialPhiArg all-nil: got v%d, want nil", got.ID)
	}
}

func TestTrivialPhiArgNonPhi(t *testing.T) {
	// Non-phi values return nil.
	v := &ssa.Value{Op: ssa.OpAdd32}
	if got := trivialPhiArg(v); got != nil {
		t.Errorf("trivialPhiArg non-phi: want nil, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// BranchFold: no-change path
// ---------------------------------------------------------------------------

func TestBranchFoldNoChange(t *testing.T) {
	// A function with no If blocks (only a Ret) — BranchFold returns false.
	b := ssa.NewFuncBuilder("bfnoop", ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}})
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	c := b.Const32(1)
	b.FinishRet(c)
	f := b.Func()
	if BranchFold(f) {
		t.Error("BranchFold on a non-If function should return false")
	}
}

func TestBranchFoldNonConstCondition(t *testing.T) {
	// If block whose condition is a Param (not a constant) — no fold.
	b := ssa.NewFuncBuilder("bfparam", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockRet)
	elseB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	entry.Control = p0
	ssa.AddEdge(entry, thenB)
	ssa.AddEdge(entry, elseB)
	c := b.Const32(0)
	b.SetCurrent(thenB)
	b.FinishRet(c)
	b.SetCurrent(elseB)
	b.FinishRet(c)
	f := b.Func()
	if BranchFold(f) {
		t.Error("BranchFold with param condition should return false")
	}
}

// ---------------------------------------------------------------------------
// removeEdge: early return when src not in dst's preds
// ---------------------------------------------------------------------------

func TestRemoveEdgeNotFound(t *testing.T) {
	// Call removeEdge when src is not actually a predecessor of dst —
	// should not panic and leave edges intact.
	b := ssa.NewFuncBuilder("rmedge", ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}})
	src := b.NewBlock(ssa.BlockPlain)
	dst := b.NewBlock(ssa.BlockRet)
	b.SetEntry(src)
	b.SetCurrent(src)
	c := b.Const32(1)
	b.FinishRet(c)
	b.SetCurrent(dst)
	b.FinishRet(c)
	// Don't wire src→dst; just call removeEdge — should be a no-op.
	removeEdge(src, dst)
	if len(dst.Preds) != 0 {
		t.Error("removeEdge on unwired blocks modified preds")
	}
}

// ---------------------------------------------------------------------------
// DCE: control value on non-Ret blocks
// ---------------------------------------------------------------------------

func TestDCEControlKept(t *testing.T) {
	// A Control value that is the only reference to a computation must be
	// kept alive by DCE (roots include block Control values).
	b := ssa.NewFuncBuilder("dcectl", ssa.FuncSig{
		Params:  []ssa.Type{ssa.TypeI32},
		Results: []ssa.Type{ssa.TypeI32},
	})
	entry := b.NewBlock(ssa.BlockIf)
	thenB := b.NewBlock(ssa.BlockRet)
	elseB := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	p0 := b.Param(0, ssa.TypeI32)
	cond := b.NewValue(ssa.OpEq32, ssa.TypeBool, p0, p0)
	entry.Control = cond
	ssa.AddEdge(entry, thenB)
	ssa.AddEdge(entry, elseB)
	c := b.Const32(0)
	b.SetCurrent(thenB)
	b.FinishRet(c)
	b.SetCurrent(elseB)
	b.FinishRet(c)
	f := b.Func()

	DCE(f)
	if cond.Op != ssa.OpEq32 {
		t.Errorf("DCE killed a Control value: op=%v", cond.Op)
	}
}

// ---------------------------------------------------------------------------
// cseKey nil-arg path
// ---------------------------------------------------------------------------

func TestCSEKeyWithNilArg(t *testing.T) {
	// A value with a nil arg in a non-commutative op still produces a key
	// (no panic).
	v := &ssa.Value{
		ID:   1,
		Op:   ssa.OpSub32,
		Type: ssa.TypeI32,
		Args: []*ssa.Value{nil, nil},
	}
	resolve := func(x *ssa.Value) *ssa.Value { return x }
	key := cseKey(v, resolve)
	if key == "" {
		t.Error("cseKey with nil args returned empty string")
	}
}
