package pass

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// buildDiamond returns entry→If{armA, armB}→join→ret with the given
// statements materialized: cond in the If block, and optionally a phi
// or arm values.
func buildDiamond(t *testing.T, withPhi, armValue, triangle bool) (*ssa.Func, *ssa.Block) {
	t.Helper()
	b := ssa.NewFuncBuilder("Fn3", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: nil})
	f := b.Func()
	bIf := b.NewBlock(ssa.BlockIf)
	b.SetEntry(bIf)
	armA := b.NewBlock(ssa.BlockPlain)
	var armB *ssa.Block
	if !triangle {
		armB = b.NewBlock(ssa.BlockPlain)
	}
	join := b.NewBlock(ssa.BlockRet)

	b.SetCurrent(bIf)
	p := b.NewValueAuxInt(ssa.OpParam, ssa.TypeI32, 0)
	zero := b.NewValueAuxInt(ssa.OpConst32, ssa.TypeI32, 0)
	cond := b.NewValue(ssa.OpLtU32, ssa.TypeBool, p, zero)
	bIf.Control = cond

	var av *ssa.Value
	if armValue {
		b.SetCurrent(armA)
		av = b.NewValue(ssa.OpAdd32, ssa.TypeI32, p, zero)
		_ = av
	}
	if withPhi {
		b.SetCurrent(join)
		b.NewValue(ssa.OpPhi, ssa.TypeI32, p, zero)
	}

	ssa.AddEdge(bIf, armA)
	ssa.AddEdge(armA, join)
	if triangle {
		ssa.AddEdge(bIf, join)
	} else {
		ssa.AddEdge(bIf, armB)
		ssa.AddEdge(armB, join)
	}
	return f, bIf
}

func TestFoldEmptyDiamondFull(t *testing.T) {
	f, bIf := buildDiamond(t, false, false, false)
	if !FoldEmptyDiamonds(f) {
		t.Fatal("empty diamond not folded")
	}
	if bIf.Kind != ssa.BlockPlain || len(bIf.Succs) != 1 {
		t.Fatalf("if block not linearized: kind=%v succs=%d", bIf.Kind, len(bIf.Succs))
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFoldEmptyDiamondTriangle(t *testing.T) {
	f, bIf := buildDiamond(t, false, false, true)
	if !FoldEmptyDiamonds(f) {
		t.Fatal("triangle not folded")
	}
	if bIf.Kind != ssa.BlockPlain || len(bIf.Succs) != 1 {
		t.Fatalf("if block not linearized")
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFoldEmptyDiamondKeepsPhi(t *testing.T) {
	f, _ := buildDiamond(t, true, false, false)
	if FoldEmptyDiamonds(f) {
		t.Fatal("diamond with a live phi must not fold")
	}
}

func TestFoldEmptyDiamondKeepsArmValues(t *testing.T) {
	f, _ := buildDiamond(t, false, true, false)
	if FoldEmptyDiamonds(f) {
		t.Fatal("diamond with arm computation must not fold")
	}
}
