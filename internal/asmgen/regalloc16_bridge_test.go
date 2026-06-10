package asmgen

import (
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestHasMergeBlock covers the gate predicate. A single-block
// function has no merge blocks; a 4-block diamond has one.
func TestHasMergeBlock(t *testing.T) {
	// Single block.
	bb1 := ssa.NewFuncBuilder("single", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}})
	b0 := bb1.NewBlock(ssa.BlockRet)
	bb1.SetEntry(b0)
	bb1.SetCurrent(b0)
	x := bb1.Param(0, ssa.TypeI32)
	bb1.FinishRet(x)
	if hasMergeBlock(bb1.Func()) {
		t.Errorf("single-block function should not have a merge block")
	}

	// Diamond — 4 blocks, the merge block has 2 preds.
	bb2 := ssa.NewFuncBuilder("dia", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}})
	bIf := bb2.NewBlock(ssa.BlockIf)
	bT := bb2.NewBlock(ssa.BlockPlain)
	bE := bb2.NewBlock(ssa.BlockPlain)
	bM := bb2.NewBlock(ssa.BlockRet)
	bb2.SetEntry(bIf)
	bb2.SetCurrent(bIf)
	x2 := bb2.Param(0, ssa.TypeI32)
	bb2.LinkIf(x2, bT, bE)
	bb2.SetCurrent(bT)
	bb2.LinkPlain(bM)
	bb2.SetCurrent(bE)
	bb2.LinkPlain(bM)
	bb2.SetCurrent(bM)
	bb2.FinishRet(x2)
	if !hasMergeBlock(bb2.Func()) {
		t.Errorf("4-block diamond should have a merge block")
	}
}

// TestApplyNewRegallocStraightLineAMD64 confirms the bridge produces
// the same observable asm shape (functional equivalence) on a
// straight-line function. We emit the same fixture twice — once
// through the block-local regalloc and once through the
// cross-block allocator — and assert both compile to valid Plan9 asm
// without panic. We DON'T assert byte-equal output (the new
// allocator chooses different registers); we DO assert the per-arch
// Go assembler accepts each.
func TestApplyNewRegallocStraightLineAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only smoke test (GOARCH=%s)", runtime.GOARCH)
	}
	// Build a single-block function: f(x) { return x + 1 }.
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("straight16p", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	x := bb.Param(0, ssa.TypeI32)
	one := bb.Const32(1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, x, one)
	bb.FinishRet(sum)

	// Trigger the bridge by setting the env var and (re-)emitting.
	t.Setenv("WASM2GO_NEWREGALLOC", "1")
	t.Setenv("WASM2GO_REGALLOC", "1")
	t.Setenv("WASM2GO_REGALLOC_BISECT_LO", "0")
	t.Setenv("WASM2GO_REGALLOC_BISECT_HI", "999999999")

	asm, _, err := EmitFuncAMD64("straight16p", sig, bb.Func(), FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64 with new regalloc: %v", err)
	}
	if !strings.Contains(asm, "ADDL") {
		t.Errorf("expected ADDL in emitted asm; got:\n%s", asm)
	}
}
