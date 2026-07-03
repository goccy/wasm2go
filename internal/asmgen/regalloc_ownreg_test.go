package asmgen

import (
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// buildTwoCarryLoop constructs the minimal Fn58-shaped loop the
// own-register mode targets: two loop-carry phis where one (accPhi)
// satisfies the SHARED coalesce conditions (its back-edge carry is
// its sole user) and the other (posPhi) is read by several ops per
// iteration, which the shared mode must decline:
//
//	block 0 (Plain):  start = param0, limit = param1; jmp b1
//	block 1 (BlockIf):
//	  posPhi = phi(start, posNext)
//	  accPhi = phi(start, accNext)
//	  posNext = OpAdd32(posPhi, 1)
//	  accNext = OpAdd32(accPhi, posPhi)   // 2nd read of posPhi
//	  cond    = OpLtS32(posNext, limit)
//	  if cond -> b3 (continue) else -> b2 (exit)
//	block 3 (Plain):  jmp b1               // back edge
//	block 2 (BlockRet): return accNext
func buildTwoCarryLoop(t *testing.T) (f *ssa.Func, sig wasm.FuncType, blocks [4]*ssa.Block, phis [2]*ssa.Value, carries [2]*ssa.Value) {
	t.Helper()
	sig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("twocarry", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	b.SetCurrent(b1)
	posPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	accPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	one := b.Const32(1)
	posNext := b.NewValue(ssa.OpAdd32, ssa.TypeI32, posPhi, one)
	posPhi.Args[1] = posNext
	accNext := b.NewValue(ssa.OpAdd32, ssa.TypeI32, accPhi, posPhi)
	accPhi.Args[1] = accNext
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, posNext, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	b.SetCurrent(b2)
	b.FinishRet(accNext)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	return b.Func(), sig, [4]*ssa.Block{b0, b1, b2, b3}, [2]*ssa.Value{posPhi, accPhi}, [2]*ssa.Value{posNext, accNext}
}

// TestRegallocOwnRegisterPhi pins the own-register coalesce mode: a
// multi-user loop-carry phi (declined by the shared mode) still gets
// a reserved register of its own, with the register reserved across
// the loop body, while the shared-eligible sibling keeps the original
// shared coalesce.
func TestRegallocOwnRegisterPhi(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	f, sig, blocks, phis, carries := buildTwoCarryLoop(t)
	b1, b2, b3 := blocks[1], blocks[2], blocks[3]
	posPhi, accPhi := phis[0], phis[1]
	posNext, accNext := carries[0], carries[1]

	plan, err := planFunc(f, FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	computeRegHomes(f, plan)

	// accPhi: SHARED mode — same register as its sole-user carry.
	accReg := plan.regHome[accPhi.ID]
	if accReg == "" {
		t.Fatalf("accPhi (v%d) has no regHome; expected the shared coalesce to fire", accPhi.ID)
	}
	if got := plan.regHome[accNext.ID]; got != accReg {
		t.Errorf("shared coalesce: accNext regHome=%q, want the phi's register %q", got, accReg)
	}
	if got := plan.coalescedPhi[accPhi.ID]; got != accReg {
		t.Errorf("plan.coalescedPhi[accPhi]=%q, want %q", got, accReg)
	}

	// posPhi: OWN-REGISTER mode — a register of its own, distinct
	// from the shared pair's, with the carry (posNext) left alone.
	posReg := plan.regHome[posPhi.ID]
	if posReg == "" {
		t.Fatalf("posPhi (v%d) has no regHome; expected the own-register mode to fire "+
			"for the multi-user loop carry (users: posNext, accNext)", posPhi.ID)
	}
	if posReg == accReg {
		t.Errorf("posPhi and accPhi must not share a register; both got %q", posReg)
	}
	if got := plan.coalescedPhi[posPhi.ID]; got != posReg {
		t.Errorf("plan.coalescedPhi[posPhi]=%q, want %q (edge copies must target the register)", got, posReg)
	}
	if got := plan.regHome[posNext.ID]; got != "" && got == posReg {
		t.Errorf("own-register mode must NOT alias the carry into the phi's register; posNext got %q", got)
	}

	// Both registers reserved across the loop body {b1, b3}.
	for _, blk := range []*ssa.Block{b1, b3} {
		for _, reg := range []string{posReg, accReg} {
			if !plan.reservedRegs[blk.ID][reg] {
				t.Errorf("register %q not reserved in loop-body block %d", reg, blk.ID)
			}
		}
	}
	// accNext is read by the BlockRet AFTER the loop — the shared
	// register must stay reserved on that exit block so a block-local
	// allocation there cannot clobber the carry before the return
	// reads it.
	if !plan.reservedRegs[b2.ID][accReg] {
		t.Errorf("shared register %q not reserved in exit block %d where the carry is still live", accReg, b2.ID)
	}
}

// TestRegallocOwnRegisterPhiEmit checks the emitted asm for the
// two-carry loop: the own-register phi's back-edge copy is a single
// MOV into its reserved register, and in-loop reads of the phi come
// out of the register (no slot round-trip for the phi).
func TestRegallocOwnRegisterPhiEmit(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	f, sig, _, _, _ := buildTwoCarryLoop(t)
	asm, _, err := EmitFuncAMD64("twocarry", sig, f, FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64: %v", err)
	}
	// The own-register phi must be read from a coalesce-pool register
	// somewhere in the body (the accNext = accPhi + posPhi add reads
	// it as a register operand).
	sawPoolRegRead := false
	for _, reg := range coalesceReservedPool {
		if strings.Contains(asm, reg+",") || strings.Contains(asm, reg+"\n") {
			sawPoolRegRead = true
			break
		}
	}
	if !sawPoolRegRead {
		t.Errorf("expected at least one coalesce-pool register operand in the emitted asm:\n%s", asm)
	}
	// The back edge must write one of the pool registers via a plain
	// MOVL (the own-register phi's edge copy). We detect `MOVL <src>,
	// R12/R13/R15` with a non-register, non-immediate source — i.e. a
	// slot or FP read staged straight into the reserved register.
	sawRegTargetCopy := false
	for _, line := range strings.Split(asm, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "MOVL ") {
			continue
		}
		for _, reg := range coalesceReservedPool {
			if strings.HasSuffix(trimmed, ", "+reg) {
				sawRegTargetCopy = true
			}
		}
	}
	if !sawRegTargetCopy {
		t.Errorf("expected a MOVL edge copy targeting a coalesce-pool register:\n%s", asm)
	}
}

// TestRegallocOwnRegisterSiblingHazard pins the parallel-copy hazard
// guard: when one header phi reads another (a shift-register pair),
// NEITHER side may take the own-register mode — register-destination
// edge copies bypass the staged-phi temp machinery, so an emit-order
// dependent read of the sibling would observe the new value.
func TestRegallocOwnRegisterSiblingHazard(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("shiftpair", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	// prev/cur shift-register: cur's old value becomes prev each
	// iteration (prevPhi's back-edge arg IS curPhi), so the pair has
	// a genuine parallel-copy ordering dependency on the back edge.
	// Both phis are multi-user (the adds below read each phi twice)
	// so the shared mode declines them and only the own-register mode
	// could fire — the hazard guard must keep it from doing so.
	b.SetCurrent(b1)
	prevPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	curPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	prevPhi.Args[1] = curPhi
	sum := b.NewValue(ssa.OpAdd32, ssa.TypeI32, prevPhi, curPhi)
	sum2 := b.NewValue(ssa.OpAdd32, ssa.TypeI32, sum, prevPhi)
	curNext := b.NewValue(ssa.OpAdd32, ssa.TypeI32, sum2, curPhi)
	curPhi.Args[1] = curNext
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, curNext, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	b.SetCurrent(b2)
	b.FinishRet(curNext)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	plan, err := planFunc(b.Func(), FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	computeRegHomes(b.Func(), plan)

	// prevPhi reads curPhi (its back-edge arg) → read-side hazard.
	// curPhi is read by prevPhi → write-side hazard. Both must stay
	// slot-resident.
	if reg := plan.regHome[prevPhi.ID]; reg != "" {
		t.Errorf("prevPhi (v%d) got register %q; the sibling-phi hazard guard must decline it "+
			"(its back-edge arg is curPhi, a phi of the same header)", prevPhi.ID, reg)
	}
	if reg := plan.regHome[curPhi.ID]; reg != "" {
		t.Errorf("curPhi (v%d) got register %q; the sibling-phi hazard guard must decline it "+
			"(prevPhi of the same header reads it on the back edge)", curPhi.ID, reg)
	}
}

// TestRegallocOwnRegisterLiveAcrossCall pins the exit-path safety
// check: a multi-user loop-carry phi that is still live across a CALL
// after the loop must stay slot-resident (R12/R13/R15 are caller-save
// and the callee would clobber the carry).
func TestRegallocOwnRegisterLiveAcrossCall(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("liveacross", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	b.SetCurrent(b1)
	posPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	one := b.Const32(1)
	posNext := b.NewValue(ssa.OpAdd32, ssa.TypeI32, posPhi, one)
	posPhi.Args[1] = posNext
	// Second in-loop read of posPhi so the shared mode declines and
	// the own-register mode is the one under test.
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, posPhi, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	// Exit block: a memory.size CALL (opEmitsCall) fires BEFORE the
	// phi's final read, so the phi is live across it.
	b.SetCurrent(b2)
	memSize := b.NewValue(ssa.OpMemSize, ssa.TypeI32)
	after := b.NewValue(ssa.OpAdd32, ssa.TypeI32, posPhi, memSize)
	b.FinishRet(after)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	plan, err := planFunc(b.Func(), FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	computeRegHomes(b.Func(), plan)

	if reg := plan.regHome[posPhi.ID]; reg != "" {
		t.Errorf("posPhi (v%d) got register %q; it is live across the OpMemSize CALL in the "+
			"exit block and must stay slot-resident", posPhi.ID, reg)
	}
}

// TestRegallocCoalesceAcrossInlineHelper pins the helperCallIsInline
// subtraction in the coalesce pass's call-free check: a loop whose
// only opEmitsCall value is an inline-emitted helper (i64.extend_i32_u
// — the exact shape of the varint-decode loops pprof flagged) must
// still coalesce its loop-carry phi. Before the subtraction the
// OpHelperCall marked the block call-unsafe and every coalesce in the
// loop was declined.
func TestRegallocCoalesceAcrossInlineHelper(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI64}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI64}}
	b := ssa.NewFuncBuilder("inlinehelperloop", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	b.SetCurrent(b1)
	posPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	one := b.Const32(1)
	posNext := b.NewValue(ssa.OpAdd32, ssa.TypeI32, posPhi, one)
	posPhi.Args[1] = posNext
	// The inline helper in the loop body — must NOT be a CALL barrier.
	ext := b.NewValueAux(ssa.OpHelperCall, ssa.TypeI64, "i64_extend_i32_u", posNext)
	_ = ext
	// Keep posPhi multi-user so the own-register mode is the mode
	// under test (shared would also be blocked by the same bug).
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, posPhi, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	b.SetCurrent(b2)
	b.FinishRet(ext)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	plan, err := planFunc(b.Func(), FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	plan.helperInlineFn = archAMD64{}.HelperIsInline
	computeRegHomes(b.Func(), plan)

	if reg := plan.regHome[posPhi.ID]; reg == "" {
		t.Errorf("posPhi (v%d) has no regHome; the inline helper (i64_extend_i32_u) in the loop "+
			"body must not count as a CALL barrier", posPhi.ID)
	}
}

// TestRegallocSharedCoalesceLagPattern is the regression for the
// Fn39800 hash-probe miscompile: a loop-carry phi whose SINGLE user
// is NOT the back-edge carry (here: an exit-block read) must not be
// shared-coalesced. Sharing the register makes the exit read observe
// the carry value computed in the FINAL iteration instead of the phi
// value, which in the integration corpus corrupted a hash probe index
// and took down the guest allocator.
func TestRegallocSharedCoalesceLagPattern(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("lagpattern", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	// lagPhi's back-edge arg (next) does NOT read lagPhi; lagPhi's one
	// and only user is the return in the exit block. This is the exact
	// shape the sole-user==carry check must decline.
	b.SetCurrent(b1)
	lagPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	one := b.Const32(1)
	next := b.NewValue(ssa.OpAdd32, ssa.TypeI32, limit, one)
	lagPhi.Args[1] = next
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, next, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	b.SetCurrent(b2)
	b.FinishRet(lagPhi)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	plan, err := planFunc(b.Func(), FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	computeRegHomes(b.Func(), plan)

	pReg, vReg := plan.regHome[lagPhi.ID], plan.regHome[next.ID]
	if pReg != "" && pReg == vReg {
		t.Errorf("lag-pattern phi (v%d) and its non-reading carry (v%d) were shared-coalesced "+
			"into %q; the exit read of the phi would observe the final carry value", lagPhi.ID, next.ID, pReg)
	}
}

// TestRegallocSharedCoalesceArgPositionHazard pins the emit-shape
// guard: emitBinALU writes the shared home register in its FIRST
// instruction (MOV src0, home), so a carry of the shape
// `V = x - P` (phi as the SECOND operand, x != P) must not share a
// register with P — the subtract would read the home after the MOV
// already clobbered it, computing x - x instead of x - P.
func TestRegallocSharedCoalesceArgPositionHazard(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32, ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("argpos", fsig)

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b3 := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	limit := b.Param(1, ssa.TypeI32)
	b.LinkPlain(b1)

	b.SetCurrent(b1)
	pPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	// V = limit - P: P sits at args[1] with args[0] != P.
	pNext := b.NewValue(ssa.OpSub32, ssa.TypeI32, limit, pPhi)
	pPhi.Args[1] = pNext
	cond := b.NewValue(ssa.OpLtS32, ssa.TypeBool, pNext, limit)
	b.LinkIf(cond, b3, b2)

	b.SetCurrent(b3)
	b.LinkPlain(b1)

	b.SetCurrent(b2)
	b.FinishRet(pNext)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	plan, err := planFunc(b.Func(), FuncOptions{ModulePkgRef: "*Module"}, sig, 0, false)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	plan.supportsCoalesce = true
	computeRegHomes(b.Func(), plan)

	pReg, vReg := plan.regHome[pPhi.ID], plan.regHome[pNext.ID]
	if pReg != "" && pReg == vReg {
		t.Errorf("arg-position hazard: phi (v%d) shared %q with V = limit - phi (v%d); "+
			"emitBinALU32 would compute limit - limit", pPhi.ID, pReg, pNext.ID)
	}
}

// TestRegallocOwnRegisterPhiARM64Pool runs the two-carry fixture with
// the arm64 arch hooks (register pools, eligibility filter, coalesce
// pool) and checks both coalesce modes assign registers from arm64's
// R13/R14/R15 pool. The allocation pass is arch-independent; this
// pins the arm64 plumbing (plan.coalescePool + RegHomeEligibleOp).
func TestRegallocOwnRegisterPhiARM64Pool(t *testing.T) {
	f, sig, blocks, phis, carries := buildTwoCarryLoop(t)
	b1, b3 := blocks[1], blocks[3]
	posPhi, accPhi := phis[0], phis[1]
	accNext := carries[1]

	plan, err := planFunc(f, FuncOptions{ModulePkgRef: "*Module"}, sig, archARM64{}.CallArgBias(), true)
	if err != nil {
		t.Fatalf("planFunc: %v", err)
	}
	a := archARM64{}
	plan.gpRegPool = a.GPRegPool()
	plan.sseRegPool = a.SSERegPool()
	plan.regHomeEligibleOpFn = a.RegHomeEligibleOp
	plan.supportsCoalesce = a.SupportsLoopCarryCoalesce()
	plan.coalescePool = a.CoalesceRegPool()
	plan.helperInlineFn = a.HelperIsInline
	computeRegHomes(f, plan)

	inPool := func(reg string) bool {
		for _, r := range a.CoalesceRegPool() {
			if r == reg {
				return true
			}
		}
		return false
	}
	accReg := plan.regHome[accPhi.ID]
	if accReg == "" || !inPool(accReg) {
		t.Fatalf("accPhi shared coalesce on arm64: regHome=%q, want a register from %v", accReg, a.CoalesceRegPool())
	}
	if got := plan.regHome[accNext.ID]; got != accReg {
		t.Errorf("shared coalesce: accNext regHome=%q, want %q", got, accReg)
	}
	posReg := plan.regHome[posPhi.ID]
	if posReg == "" || !inPool(posReg) {
		t.Fatalf("posPhi own-register on arm64: regHome=%q, want a register from %v", posReg, a.CoalesceRegPool())
	}
	if posReg == accReg {
		t.Errorf("posPhi and accPhi must not share a register; both got %q", posReg)
	}
	for _, blk := range []int{int(b1.ID), int(b3.ID)} {
		for _, reg := range []string{posReg, accReg} {
			if !plan.reservedRegs[ssa.BlockID(blk)][reg] {
				t.Errorf("register %q not reserved in loop-body block %d", reg, blk)
			}
		}
	}
}

// TestRegallocOwnRegisterPhiEmitARM64 checks the emitted arm64 asm
// for the two-carry loop: edge copies target the coalesce-pool
// registers (R13/R14/R15) and the emit completes without error with
// the coalesce active.
func TestRegallocOwnRegisterPhiEmitARM64(t *testing.T) {
	f, sig, _, _, _ := buildTwoCarryLoop(t)
	asm, _, err := EmitFuncARM64("twocarry", sig, f, FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncARM64: %v", err)
	}
	saw := false
	for _, line := range strings.Split(asm, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "MOVW ") {
			continue
		}
		for _, reg := range (archARM64{}).CoalesceRegPool() {
			if strings.HasSuffix(trimmed, ", "+reg) {
				saw = true
			}
		}
	}
	if !saw {
		t.Errorf("expected a MOVW edge copy targeting an arm64 coalesce-pool register:\n%s", asm)
	}
}
