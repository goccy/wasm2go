package asmgen

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// buildBrTableFunc constructs f(sel i32) i32 with an n-way arity-0
// BlockBrTable: case k returns k*10, default returns -1.
func buildBrTableFunc(t *testing.T, n int) (*ssa.Func, wasm.FuncType) {
	t.Helper()
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("bt", fsig)
	dispatch := bb.NewBlock(ssa.BlockBrTable)
	bb.SetEntry(dispatch)
	bb.SetCurrent(dispatch)
	sel := bb.Param(0, ssa.TypeI32)
	dispatch.Control = sel
	for k := 0; k < n; k++ {
		target := bb.NewBlock(ssa.BlockRet)
		bb.SetCurrent(target)
		bb.FinishRet(bb.Const32(int32(k * 10)))
		ssa.AddEdge(dispatch, target)
		dispatch.TableCases = append(dispatch.TableCases, []int32{int32(k)})
	}
	dflt := bb.NewBlock(ssa.BlockRet)
	bb.SetCurrent(dflt)
	bb.FinishRet(bb.Const32(-1))
	ssa.AddEdge(dispatch, dflt)
	dispatch.TableCases = append(dispatch.TableCases, nil)
	dispatch.TableDefault = len(dispatch.Succs) - 1
	if err := ssa.Verify(bb.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	return bb.Func(), sig
}

// TestBrTableBinarySearchTreeAMD64 pins the dispatch shape: for a
// 64-way table the tree must stay logarithmic — every root-to-leaf
// path is ≤ ~log2(n) inner compares + a ≤4-entry leaf run — instead
// of the old 64-long equality chain. We assert the structural
// signals: BT_ split labels exist, and the JE count equals the case
// count while split compares (JLT) stay ≈ n/4 (each split's JLT is
// one per inner node ≈ n/4 for leaf size 4).
func TestBrTableBinarySearchTreeAMD64(t *testing.T) {
	f, sig := buildBrTableFunc(t, 64)
	asm, _, err := EmitFuncAMD64("bt", sig, f, FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64: %v", err)
	}
	if !strings.Contains(asm, "BT_") {
		t.Fatalf("no binary-search split labels — dispatch degenerated to a linear chain:\n%s", asm)
	}
	je := strings.Count(asm, "\tJE ")
	jlt := strings.Count(asm, "\tJLT ")
	if je != 64 {
		t.Fatalf("JE count = %d, want 64 (one per case)", je)
	}
	// 64 cases with ≤4-entry leaves ⇒ ~2^4 leaves ⇒ ~15 inner nodes.
	// Anything close to 64 would mean the tree collapsed to a chain.
	if jlt < 8 || jlt > 24 {
		t.Fatalf("JLT (split) count = %d, want ~15 (log-shaped tree)", jlt)
	}
	if !strings.Contains(asm, "\tMOVL l0+8(FP), AX") && !strings.Contains(asm, ", AX\n\tCMPL AX, $") {
		t.Fatalf("selector not staged in AX before the tree:\n%s", asm)
	}
}

// TestBrTableTreeARM64Shape mirrors the amd64 pin for the arm64
// emitter (BEQ per case, BLT splits).
func TestBrTableTreeARM64Shape(t *testing.T) {
	f, sig := buildBrTableFunc(t, 64)
	asm, _, err := EmitFuncARM64("bt", sig, f, FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncARM64: %v", err)
	}
	if !strings.Contains(asm, "BT_") {
		t.Fatalf("no binary-search split labels:\n%s", asm)
	}
	beq := strings.Count(asm, "\tBEQ ")
	blt := strings.Count(asm, "\tBLT ")
	if beq != 64 {
		t.Fatalf("BEQ count = %d, want 64", beq)
	}
	if blt < 8 || blt > 24 {
		t.Fatalf("BLT (split) count = %d, want ~15", blt)
	}
}

// TestBrTable64Runtime executes the emitted amd64 binary-search tree
// for a 64-way dispatcher, probing selectors that walk distinct
// root-to-leaf paths (splits, leaf runs, both extremes) plus the
// out-of-range default. The payload-carrying `pick` export pins the
// arity>0 If-chain fallback at runtime in the same build.
func TestBrTable64Runtime(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64 driver test (GOARCH=%s)", runtime.GOARCH)
	}
	var cases []driverCase
	for _, sel := range []int{0, 1, 2, 7, 15, 16, 31, 32, 33, 47, 48, 62, 63} {
		cases = append(cases, driverCase{"switch64", []string{fmt.Sprintf("%d", sel)}, fmt.Sprintf("%d", sel*10+7)})
	}
	cases = append(cases,
		driverCase{"switch64", []string{"64"}, "-1"},
		driverCase{"switch64", []string{"1000000"}, "-1"},
		driverCase{"pick", []string{"0"}, "1111"},
		driverCase{"pick", []string{"1"}, "111"},
		driverCase{"pick", []string{"9"}, "1111"},
	)
	buildAndRunDriver(t, "cg_brtable64", []string{"switch64", "pick"}, driverPlaceholder, cases)
}
