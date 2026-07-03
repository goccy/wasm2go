package asmgen

import (
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

func countReloads(s string) int { return strings.Count(s, "\tMOVQ 32(R11), BX") }

// TestMemBaseFlowDedup_JoinBothPredsValid: both branch arms load m.M
// and neither calls; the reload after the join is redundant on every
// path and must be dropped, while each arm's own (first) load stays.
func TestMemBaseFlowDedup_JoinBothPredsValid(t *testing.T) {
	in := strings.Join([]string{
		"\tMOVL l0+8(FP), AX",
		"\tTESTL AX, AX",
		"\tJE L2",
		"L1:",
		"\tMOVQ 32(R11), BX",
		"\tMOVL (BX)(SI*1), AX",
		"\tJMP L3",
		"L2:",
		"\tMOVQ 32(R11), BX",
		"\tMOVL 4(BX)(SI*1), AX",
		"L3:",
		"\tMOVQ 32(R11), BX", // redundant: valid on both preds
		"\tMOVL 8(BX)(SI*1), AX",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if n := countReloads(got); n != 2 {
		t.Fatalf("want 2 reloads after dedup, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "L3:\n\tMOVL 8(BX)(SI*1), AX") {
		t.Fatalf("join-block reload not the one dropped:\n%s", got)
	}
}

// TestMemBaseFlowDedup_CallOnOnePathKeepsReload: one arm CALLs after
// its load, so the join reload is NOT redundant and must survive.
func TestMemBaseFlowDedup_CallOnOnePathKeepsReload(t *testing.T) {
	in := strings.Join([]string{
		"\tJE L2",
		"L1:",
		"\tMOVQ 32(R11), BX",
		"\tCALL ·Fn1(SB)",
		"\tJMP L3",
		"L2:",
		"\tMOVQ 32(R11), BX",
		"L3:",
		"\tMOVQ 32(R11), BX",
		"\tMOVL (BX)(SI*1), AX",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if n := countReloads(got); n != 3 {
		t.Fatalf("want all 3 reloads kept, got %d:\n%s", n, got)
	}
}

// TestMemBaseFlowDedup_LoopHeader: a call-free loop re-loads m.M
// every iteration; with the pre-loop load available the in-loop
// reload must be dropped (optimistic fixpoint across the back edge).
func TestMemBaseFlowDedup_LoopHeader(t *testing.T) {
	in := strings.Join([]string{
		"\tMOVQ 32(R11), BX",
		"\tMOVL (BX)(SI*1), AX",
		"L1:",
		"\tMOVQ 32(R11), BX", // redundant: preheader valid, body call-free
		"\tMOVL 4(BX)(SI*1), AX",
		"\tADDL $1, CX",
		"\tCMPL CX, DX",
		"\tJNE L1",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if n := countReloads(got); n != 1 {
		t.Fatalf("want 1 reload (preheader only), got %d:\n%s", n, got)
	}
}

// TestMemBaseFlowDedup_LoopWithCallKeepsReload: the loop body calls,
// so the back edge invalidates the fact and the header reload stays.
func TestMemBaseFlowDedup_LoopWithCallKeepsReload(t *testing.T) {
	in := strings.Join([]string{
		"\tMOVQ 32(R11), BX",
		"L1:",
		"\tMOVQ 32(R11), BX",
		"\tMOVL (BX)(SI*1), AX",
		"\tCALL ·Fn1(SB)",
		"\tMOVQ m+0(FP), R11",
		"\tJNE L1",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if n := countReloads(got); n != 2 {
		t.Fatalf("want both reloads kept, got %d:\n%s", n, got)
	}
}

// TestMemBaseFlowDedup_BXClobberKills: a plain write to BX between
// the load and the next reload keeps the reload alive.
func TestMemBaseFlowDedup_BXClobberKills(t *testing.T) {
	in := strings.Join([]string{
		"\tMOVQ 32(R11), BX",
		"\tMOVQ AX, BX", // clobber
		"\tMOVQ 32(R11), BX",
		"\tMOVL (BX)(SI*1), AX",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if n := countReloads(got); n != 2 {
		t.Fatalf("want both reloads kept, got %d:\n%s", n, got)
	}
}

// TestMemBaseFlowDedup_TwoLineFPFormPair: the no-mcache two-line form
// participates as a unit — dropped together when redundant.
func TestMemBaseFlowDedup_TwoLineFPFormPair(t *testing.T) {
	in := strings.Join([]string{
		"\tMOVQ m+0(FP), BX",
		"\tMOVQ 32(BX), BX",
		"\tMOVL (BX)(SI*1), AX",
		"\tMOVQ m+0(FP), BX", // redundant pair
		"\tMOVQ 32(BX), BX",
		"\tMOVL 4(BX)(SI*1), AX",
		"\tRET",
	}, "\n")
	got := memBaseFlowDedup(in)
	if strings.Count(got, "MOVQ m+0(FP), BX") != 1 || strings.Count(got, "MOVQ 32(BX), BX") != 1 {
		t.Fatalf("redundant FP pair not dropped exactly once:\n%s", got)
	}
}

// TestDirectIndexAndFlowDedupEndToEnd pins the two memop-addressing
// properties on real emitted output (not synthetic text):
//
//  1. direct-index: a load whose base value has a GP register home
//     addresses memory as `disp(BX)(<home>*1)` with no `MOVL <reg>,
//     SI` staging hop;
//  2. flow dedup: dependent loads in one function share a single
//     `MOVQ 32(R11), BX` m.M read.
func TestDirectIndexAndFlowDedupEndToEnd(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("dix", fsig)
	b0 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)
	bb.SetCurrent(b0)
	base := bb.Param(0, ssa.TypeI32)
	v1 := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, base)
	v2 := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 8, v1)
	v3 := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 4, v1)
	sum := bb.NewValue(ssa.OpAdd32, ssa.TypeI32, v2, v3)
	bb.FinishRet(sum)
	if err := ssa.Verify(bb.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	asm, _, err := EmitFuncAMD64("dix", sig, bb.Func(), FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64: %v", err)
	}
	// v1 has two load users reading offsets 8 and 4 off it. With a GP
	// home the addressing must be direct-index; a `MOVL <home>, SI`
	// staging hop for either user means the fast path regressed.
	if !strings.Contains(asm, "8(BX)(") || !strings.Contains(asm, "4(BX)(") {
		t.Errorf("expected direct-index `8(BX)(<reg>*1)` / `4(BX)(<reg>*1)` addressing:\n%s", asm)
	}
	if n := countReloads(asm); n != 1 {
		t.Errorf("want exactly 1 m.M reload for 3 dependent loads, got %d:\n%s", n, asm)
	}
}

// TestFlowDedupAcrossDiamondEndToEnd pins the cross-label case the
// straight-line dedupMemMReload cannot handle: both diamond arms
// load m.M and neither calls, so the merge block's load must be
// deleted by memBaseFlowDedup.
func TestFlowDedupAcrossDiamondEndToEnd(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	bb := ssa.NewFuncBuilder("diamond", fsig)
	b0 := bb.NewBlock(ssa.BlockIf)
	b1 := bb.NewBlock(ssa.BlockPlain)
	b2 := bb.NewBlock(ssa.BlockPlain)
	b3 := bb.NewBlock(ssa.BlockRet)
	bb.SetEntry(b0)

	bb.SetCurrent(b0)
	p := bb.Param(0, ssa.TypeI32)
	zero := bb.Const32(0)
	cond := bb.NewValue(ssa.OpNe32, ssa.TypeBool, p, zero)
	bb.LinkIf(cond, b1, b2)

	bb.SetCurrent(b1)
	t1 := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 16, p)
	ssa.AddEdge(b1, b3)

	bb.SetCurrent(b2)
	t2 := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 32, p)
	ssa.AddEdge(b2, b3)

	bb.SetCurrent(b3)
	merged := bb.NewValue(ssa.OpPhi, ssa.TypeI32, t1, t2)
	final := bb.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, merged)
	bb.FinishRet(final)

	if err := ssa.Verify(bb.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	asm, _, err := EmitFuncAMD64("diamond", sig, bb.Func(), FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64: %v", err)
	}
	// One reload per arm; the merge block's reload must be gone.
	if n := countReloads(asm); n > 2 {
		t.Errorf("want at most 2 m.M reloads (one per arm, none at the merge), got %d:\n%s", n, asm)
	}
}
