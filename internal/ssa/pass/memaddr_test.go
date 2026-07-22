package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// foldThreshold mirrors codegen's largeConstThreshold (4096); the pass
// takes it as a parameter so the tests pin the production value here.
const foldThreshold = 4096

// TestFoldMemAddendLargePositive folds a multi-MB constant addend of a
// load base into the AuxInt offset — the arm64 literal-pool regression
// shape ("LDPSW 27325896(R2): constant is not in pool"): the constant
// must reach the emitter as AuxInt so the _consts-table guard routes it.
func TestFoldMemAddendLargePositive(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, b.Const32(27325896))
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 8)
	b.FinishRet(l)
	f := b.Func()

	if !FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend returned false; expected the 27325896 addend to fold")
	}
	if l.Args[0] != x {
		t.Errorf("load base = v%d (%v), want the runtime param v%d", l.Args[0].ID, l.Args[0].Op, x.ID)
	}
	if want := int64(27325896 + 8); l.AuxInt != want {
		t.Errorf("load AuxInt = %d, want %d", l.AuxInt, want)
	}
	if FoldMemAddend(f, foldThreshold) {
		t.Errorf("FoldMemAddend should be idempotent once folded")
	}
}

// TestFoldMemAddendStore covers the store path (base is Args[0], the
// value operand must stay untouched), with the constant as the FIRST
// add operand to exercise the commuted match.
func TestFoldMemAddendStore(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	val := b.Param(1, ssa.TypeI32)
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, b.Const32(1<<20), x)
	st := store(b, ssa.OpStore32, base, 4, val)
	b.FinishRet()
	f := b.Func()

	if !FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend returned false; expected the 1<<20 addend to fold")
	}
	if st.Args[0] != x {
		t.Errorf("store base = v%d (%v), want the runtime param v%d", st.Args[0].ID, st.Args[0].Op, x.ID)
	}
	if st.Args[1] != val {
		t.Errorf("store value operand changed: v%d, want v%d", st.Args[1].ID, val.ID)
	}
	if want := int64(1<<20 + 4); st.AuxInt != want {
		t.Errorf("store AuxInt = %d, want %d", st.AuxInt, want)
	}
}

// TestFoldMemAddendNegative folds a large-magnitude NEGATIVE addend:
// it sign-extends into the same out-of-range addressing immediate, and
// the folded AuxInt must hold the uint32 bit pattern of the addend so
// the emitter's uint32 wrap reproduces wasm's mod-2^32 address.
func TestFoldMemAddendNegative(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, b.Const32(-8192))
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 16)
	b.FinishRet(l)
	f := b.Func()

	if !FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend returned false; expected the -8192 addend to fold")
	}
	if l.Args[0] != x {
		t.Errorf("load base = v%d (%v), want the runtime param v%d", l.Args[0].ID, l.Args[0].Op, x.ID)
	}
	if want := int64(16) + (1<<32 - 8192); l.AuxInt != want {
		t.Errorf("load AuxInt = %d, want %d (uint32 bit pattern of -8192, plus 16)", l.AuxInt, want)
	}
}

// TestFoldMemAddendKeepsSmall leaves sub-threshold addends in the base
// sum, where they fold into an in-range addressing immediate — a table
// detour would pessimise the common small-offset access.
func TestFoldMemAddendKeepsSmall(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    int32
		off  int64
	}{
		{"small positive", 512, 8},
		{"small negative", -16, 8},
		{"just under threshold with offset", 4000, 64}, // 4064 < 4096
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
			b := ssa.NewFuncBuilder("f", sig)
			entry := b.NewBlock(ssa.BlockRet)
			b.SetEntry(entry)
			b.SetCurrent(entry)
			x := b.Param(0, ssa.TypeI32)
			base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, b.Const32(tc.c))
			l := load(b, ssa.OpLoad32, ssa.TypeI32, base, tc.off)
			b.FinishRet(l)
			f := b.Func()

			if FoldMemAddend(f, foldThreshold) {
				t.Fatalf("FoldMemAddend folded a sub-threshold addend %d", tc.c)
			}
			if l.Args[0] != base || l.AuxInt != tc.off {
				t.Errorf("access rewritten: base v%d AuxInt %d, want base v%d AuxInt %d",
					l.Args[0].ID, l.AuxInt, base.ID, tc.off)
			}
		})
	}
}

// TestFoldMemAddendPositiveTotalCrossesThreshold: a positive addend
// below the threshold on its own still folds when addend+AuxInt
// crosses it — the emitter's immediate is formed from the TOTAL.
func TestFoldMemAddendPositiveTotalCrossesThreshold(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, b.Const32(4000))
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 200) // 4200 >= 4096
	b.FinishRet(l)
	f := b.Func()

	if !FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend returned false; total 4200 crosses the threshold")
	}
	if l.Args[0] != x || l.AuxInt != 4200 {
		t.Errorf("got base v%d AuxInt %d, want base v%d AuxInt 4200", l.Args[0].ID, l.AuxInt, x.ID)
	}
}

// TestFoldMemAddendSkipsConstConst: a two-constant add is ConstProp's
// job (it folds the add itself, with i32 wraparound); the pass must
// not touch it.
func TestFoldMemAddendSkipsConstConst(t *testing.T) {
	sig := ssa.FuncSig{Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, b.Const32(1<<20), b.Const32(1<<21))
	l := load(b, ssa.OpLoad32, ssa.TypeI32, base, 0)
	b.FinishRet(l)
	f := b.Func()

	if FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend must skip a const+const base (ConstProp's job)")
	}
	if l.Args[0] != base {
		t.Errorf("access base rewritten to v%d, want untouched v%d", l.Args[0].ID, base.ID)
	}
}

// TestFoldMemAddendPeelsCopies: OpCopy chains around the base, the add
// operands, or both must not hide the shape (Simplify usually
// dissolves them first, but the fixpoint order doesn't guarantee it).
func TestFoldMemAddendPeelsCopies(t *testing.T) {
	sig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("f", sig)
	entry := b.NewBlock(ssa.BlockRet)
	b.SetEntry(entry)
	b.SetCurrent(entry)
	x := b.Param(0, ssa.TypeI32)
	cconst := b.NewValue(ssa.OpCopy, ssa.TypeI32, b.Const32(1<<22))
	base := b.NewValue(ssa.OpAdd32, ssa.TypeI32, x, cconst)
	cbase := b.NewValue(ssa.OpCopy, ssa.TypeI32, base)
	l := load(b, ssa.OpLoad32, ssa.TypeI32, cbase, 0)
	b.FinishRet(l)
	f := b.Func()

	if !FoldMemAddend(f, foldThreshold) {
		t.Fatalf("FoldMemAddend returned false; copies must be peeled")
	}
	if l.Args[0] != x {
		t.Errorf("load base = v%d (%v), want the runtime param v%d", l.Args[0].ID, l.Args[0].Op, x.ID)
	}
	if want := int64(1 << 22); l.AuxInt != want {
		t.Errorf("load AuxInt = %d, want %d", l.AuxInt, want)
	}
}
