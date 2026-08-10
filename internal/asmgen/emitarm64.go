package asmgen

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// archARM64 implements the arch interface for the arm64 target. The
// per-op lowerings mirror archAMD64's but emit plan9 arm64 syntax —
// MOVW/MOVD/FMOVS/FMOVD, three-operand ALU with the destination
// last (ADDW R1, R0, R2 ≡ R2 = R0 + R1), CSET <cond>, R for
// comparison-to-bool, and B/CBNZ for branches.
type archARM64 struct{}

func (archARM64) EmitValue(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	return emitValueARM64(b, v, plan, frame)
}

func (archARM64) EmitJmp(b *strings.Builder, label, fallthroughLabel string) {
	if fallthroughLabel != "" && fallthroughLabel == label {
		return
	}
	fmt.Fprintf(b, "\tJMP %s\n", label)
}

func (archARM64) EmitBrTable(b *strings.Builder, sel *ssa.Value, cases [][]int32, labels []string, defaultLabel string, plan *funcPlan, frame argFrame) {
	// Selector once into R0 (the branch emitters' scratch); CMPW
	// clobbers only flags across the chain.
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(sel, plan, frame))
	for i, vals := range cases {
		for _, v := range vals {
			fmt.Fprintf(b, "\tCMPW $%d, R0\n", v)
			fmt.Fprintf(b, "\tBEQ %s\n", labels[i])
		}
	}
	fmt.Fprintf(b, "\tJMP %s\n", defaultLabel)
}

func (archARM64) EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel, fallthroughLabel string, plan *funcPlan, frame argFrame) {
	// Branch-fused eqz: the helper CALL was skipped during value
	// emission. The BlockIf's "result != 0" check inverts to a
	// direct "value-was-zero" branch on the original arg. For
	// arm64 this is a particularly large win — the helper path
	// goes through a real BL into base.I32Eqz / base.I64Eqz with
	// full Go ABI plumbing, while the fused path is a single CBZ.
	if plan.branchFused[cond.ID] {
		switch plan.branchFusedKind[cond.ID] {
		case "i32_eqz":
			fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(cond.Args[0], plan, frame))
			emitCondBranchARM64(b, "CBZW R0", "CBNZW R0", thenLabel, elseLabel, fallthroughLabel)
			return
		case "i64_eqz":
			fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(cond.Args[0], plan, frame))
			emitCondBranchARM64(b, "CBZ R0", "CBNZ R0", thenLabel, elseLabel, fallthroughLabel)
			return
		case "i32_eq", "i32_ne", "i32_lt_s", "i32_lt_u", "i32_le_s", "i32_le_u":
			emitFusedCmpBranchARM64(b, cond, plan, frame, false, thenLabel, elseLabel, fallthroughLabel)
			return
		case "i64_eq", "i64_ne", "i64_lt_s", "i64_lt_u", "i64_le_s", "i64_le_u":
			emitFusedCmpBranchARM64(b, cond, plan, frame, true, thenLabel, elseLabel, fallthroughLabel)
			return
		case "i32_bittest_eq", "i32_bittest_ne", "i64_bittest_eq", "i64_bittest_ne":
			emitFusedBitTestBranchARM64(b, cond, plan, frame, thenLabel, elseLabel, fallthroughLabel)
			return
		}
	}
	// Load condition into R0 and branch if non-zero. CBNZW
	// compares the low 32 bits, which matches our slot width for
	// TypeBool/TypeI32. plan9 arm64 spells it CBNZW.
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(cond, plan, frame))
	emitCondBranchARM64(b, "CBNZW R0", "CBZW R0", thenLabel, elseLabel, fallthroughLabel)
}

// emitCondBranchARM64 is the arm64 counterpart of emitCondBranchAMD64:
// it emits a conditional + (optional) unconditional jump pair while
// honouring the fall-through hint. `branchOp` is the mnemonic + operand
// prefix that branches to thenLabel; `branchOpInv` branches to elseLabel
// on the OPPOSITE condition. Both strings end just before the label —
// the implementation appends ` <label>`. arm64 inversions follow the
// usual table (BEQ ↔ BNE, BLT ↔ BGE, BLE ↔ BGT, BLO ↔ BHS, BLS ↔ BHI,
// CBZ ↔ CBNZ).
func emitCondBranchARM64(b *strings.Builder, branchOp, branchOpInv, thenLabel, elseLabel, fallthroughLabel string) {
	if fallthroughLabel != "" && fallthroughLabel == elseLabel {
		fmt.Fprintf(b, "\t%s, %s\n", branchOp, thenLabel)
		return
	}
	if fallthroughLabel != "" && fallthroughLabel == thenLabel {
		fmt.Fprintf(b, "\t%s, %s\n", branchOpInv, elseLabel)
		return
	}
	fmt.Fprintf(b, "\t%s, %s\n", branchOp, thenLabel)
	fmt.Fprintf(b, "\tJMP %s\n", elseLabel)
}

// SupportsRegHome — arm64 opts in for block-local regalloc,
// loop-carry coalesce, frame compaction, and cross-block stackalloc
// in a follow-up that teaches every per-op emit to honour
// plan.regHome on the write side (operandSrc32/64ARM64 already
// honours it on the read side). For now keep it false so the
// emit-side contract isn't broken, but expose GPRegPool / SSERegPool
// already so the regalloc machinery sees the arm64 register set and
// the gate flip becomes a one-line change.
func (archARM64) SupportsRegHome() bool { return true }

// RegHomeEligibleOp — arm64 honours regHome on the set of ops
// where both the consumer-side reader (operandSrc{32,64}ARM64 /
// operandSrcFloat) and the producer-side write path have been
// taught to talk through a register. Each entry here corresponds
// to an emit function with a `if home := plan.regHome[v.ID]; ...`
// short-circuit.
func (archARM64) RegHomeEligibleOp(op ssa.Op) bool {
	switch op {
	// emitBin32ARM64 / emitBin64ARM64 cover binary arith + bit ops.
	case ssa.OpAdd32, ssa.OpSub32, ssa.OpMul32,
		ssa.OpAnd32, ssa.OpOr32, ssa.OpXor32,
		ssa.OpAdd64, ssa.OpSub64, ssa.OpMul64,
		ssa.OpAnd64, ssa.OpOr64, ssa.OpXor64:
		return true
	// emitShift32ARM64 / emitShift64ARM64 cover the wasm shifts.
	case ssa.OpShl32, ssa.OpShrS32, ssa.OpShrU32,
		ssa.OpShl64, ssa.OpShrS64, ssa.OpShrU64:
		return true
	// emitCmp32ARM64 / emitCmp64ARM64 cover the comparison
	// boolean producers.
	case ssa.OpEq32, ssa.OpNe32,
		ssa.OpLtS32, ssa.OpLtU32, ssa.OpLeS32, ssa.OpLeU32,
		ssa.OpEq64, ssa.OpNe64,
		ssa.OpLtS64, ssa.OpLtU64, ssa.OpLeS64, ssa.OpLeU64:
		return true
	// emitLoadARM64 covers every wasm load. The destination
	// register form lands the result directly in `home`.
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64:
		return true
	// emitCallDirectARM64 / emitHelperCallARM64: the call result
	// (read from the return slot in the callee's stack frame) is
	// loaded straight into `home` when set. The regalloc filters
	// out values whose lifetime crosses a CALL, so the call's own
	// result is the only "lives past the call" case the regalloc
	// has to model — and it lives in a register from this point
	// forward.
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpHelperCall,
		ssa.OpMemSize, ssa.OpMemGrow:
		return true
	}
	return false
}

// GPRegPool — arm64's block-local regalloc set. Excludes:
//   - R0/R1: emit scratch (binary ops, helpers, control)
//   - R2/R3: emit scratch (load/store address computation)
//   - R4    : mCacheReg (the m-pointer cache register)
//   - R26   : Go runtime `g` pointer
//   - R27/R28: arm64 reserved
//   - R29/R30: FP / LR
//
// Available: R5..R15 (caller-save, refreshed after each CALL) and
// the callee-save block R19..R25. We start with the caller-save
// half because it matches amd64's "all caller-save" pool shape and
// the existing post-CALL refresh path already covers them; the
// callee-save half can be added once a save/restore prologue/
// epilogue is in place.
func (archARM64) GPRegPool() []string {
	return []string{"R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
}

// SSERegPool — arm64 float side. F0/F1 are emit scratch; F2..F7
// available (caller-save, refreshed after each CALL).
func (archARM64) SSERegPool() []string {
	return []string{"F2", "F3", "F4", "F5", "F6", "F7"}
}

// EmitMCachePrime stages the function-wide `m` pointer into the
// arm64 cache register. Issued by the prologue and after every
// real CALL (Go ABI0 caller-save).
func (archARM64) EmitMCachePrime(b *strings.Builder, reg string) {
	fmt.Fprintf(b, "\tMOVD m+0(FP), %s\n", reg)
}

// MCacheReg is "R4" on arm64. Choice criteria: not used as a
// scratch by emitBin32ARM64 (R0/R1), emitLoadARM64 / emitStoreARM64
// (R0/R2/R3), emitCmpARM64 (R0/R1), emitShiftARM64 (R0/R1), or any
// float emit (F0/F1). Not a Go-reserved register (R26 = g, R27/R28
// reserved, R29/R30 = FP/LR). Caller-save in the arm64 PCS so we
// must refresh it after every CALL — emitBlock takes care of that
// via the existing opEmitsCall hook.
func (archARM64) MCacheReg() string { return "R4" }

// CallArgBias is 8 on arm64. The Go arm64 BL instruction does NOT
// push the return PC — it leaves LR in R30 and the callee's
// prologue stores LR on the stack with `MOVD.W R30, -autosize(SP)`.
// The first 8 bytes at the caller's SP+0 are reserved for that
// saved-LR slot. The Go assembler's FP-offset resolver bakes the
// same +8 into `m+0(FP)`-style references (for frame=$F the
// resolved offset is SP+autosize+8), so caller and callee only
// agree on the address when the caller also adds +8 to every
// outgoing-arg / incoming-result SP store.
//
// asmgen.planFunc bumps the local-slot floor by this bias so the
// SP+0..SP+(bias-1) area stays reserved and the SP+bias.. region
// holds the outgoing-arg block; emitCallDirectARM64 and
// emitHelperCallARM64 add the bias to every paramOffsets[i] /
// resultOffsets[i] / helperRetOffset they emit.
func (archARM64) CallArgBias() int { return 8 }

func (archARM64) SkipValue(v *ssa.Value) bool {
	// arm64's operandSrc32/64ARM64 helpers never inline Const — the
	// MOVW $imm forms reject most 32-bit literals — so the per-value
	// materialise is the only path that gets the constant into its
	// slot. Never skip emission here for constants.
	//
	// Same reasoning as the amd64 side — every
	// operandSrc{32,64,Float}ARM64 inlines OpParam as `lN+off(FP)`,
	// never via the slot. The producer would write
	// `MOVW lN+off(FP), R0; MOVW R0, dst(RSP)` and the consumer
	// would immediately read FP-relative again; skipping the
	// producer removes a dead store. Slot reuse may hand the slot
	// to a later value; that's the first live writer.
	if v.Op == ssa.OpParam {
		return true
	}
	return false
}

func (archARM64) EmitUnreachable(b *strings.Builder) {
	// Match amd64's nil-deref strategy so the Go runtime turns
	// this into a recoverable panic ("runtime error: invalid
	// memory address or nil pointer dereference") instead of
	// the unrecoverable SIGILL/BRK that UNDEF produces.
	fmt.Fprintf(b, "\tMOVD ZR, R0\n")
	fmt.Fprintf(b, "\tMOVW (R0), R0\n")
}

func (archARM64) EmitReturn(b *strings.Builder, blk *ssa.Block, sig wasm.FuncType, plan *funcPlan, frame argFrame) error {
	k := len(sig.Results)
	if k > len(blk.Values) {
		return fmt.Errorf("ret block has %d values but signature declares %d results", len(blk.Values), k)
	}
	rets := blk.Values[len(blk.Values)-k:]
	for i, rv := range rets {
		off := frame.resultOffsets[i]
		retName := "ret"
		if k > 1 {
			retName = fmt.Sprintf("ret%d", i)
		}
		switch sig.Results[i] {
		case wasm.ValI32:
			fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(rv, plan, frame))
			fmt.Fprintf(b, "\tMOVW R0, %s+%d(FP)\n", retName, off)
		case wasm.ValI64:
			fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(rv, plan, frame))
			fmt.Fprintf(b, "\tMOVD R0, %s+%d(FP)\n", retName, off)
		case wasm.ValF32:
			fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(rv, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVS F0, %s+%d(FP)\n", retName, off)
		case wasm.ValF64:
			fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(rv, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVD F0, %s+%d(FP)\n", retName, off)
		default:
			return fmt.Errorf("result type %v not supported", sig.Results[i])
		}
	}
	fmt.Fprintf(b, "\tRET\n")
	return nil
}

func (a archARM64) EmitPhiCopyValue(b *strings.Builder, src *ssa.Value, dstOff int, t ssa.Type, plan *funcPlan, frame argFrame) error {
	var srcOp string
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		srcOp = operandSrc32ARM64(src, plan, frame)
	case ssa.TypeI64:
		srcOp = operandSrc64ARM64(src, plan, frame)
	case ssa.TypeF32, ssa.TypeF64:
		srcOp = operandSrcFloat(src, plan, frame, "RSP")
	case ssa.TypeV128:
		lo, hi := v128Parts(src, plan, frame, "RSP")
		if lo == fmt.Sprintf("%d(RSP)", dstOff) {
			return nil // self-copy
		}
		fmt.Fprintf(b, "\tMOVD %s, R0\n", lo)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dstOff)
		fmt.Fprintf(b, "\tMOVD %s, R0\n", hi)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dstOff+8)
		return nil
	default:
		return fmt.Errorf("phi type %v not supported", t)
	}
	return a.emitPhiCopyARM64(b, srcOp, dstOff, t)
}

func (a archARM64) EmitPhiCopySlot(b *strings.Builder, srcOff, dstOff int, t ssa.Type) error {
	if t == ssa.TypeV128 {
		if srcOff == dstOff {
			return nil
		}
		fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", srcOff)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dstOff)
		fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", srcOff+8)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dstOff+8)
		return nil
	}
	return a.emitPhiCopyARM64(b, fmt.Sprintf("%d(RSP)", srcOff), dstOff, t)
}

// EmitPhiCopyValueToReg is the arm64 stub for the loop-carry coalesce
// path. arm64 reports SupportsRegHome() == false, so the regalloc
// never assigns a regHome to ANY value on arm64 — which means
// plan.coalescedPhi is also empty by construction. Reaching this
// method on arm64 would be an internal-consistency failure, hence
// the error.
func (archARM64) EmitPhiCopyValueToReg(b *strings.Builder, src *ssa.Value, dstReg string, t ssa.Type, plan *funcPlan, frame argFrame) error {
	// Same shape as archAMD64: read the source operand and MOV it
	// straight into the coalesced register. arm64's `MOVW src, Rn`
	// zero-extends the low 32 bits into Rn, and `MOVD src, Rn`
	// moves the full 64-bit value.
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVW %s, %s\n", operandSrc32ARM64(src, plan, frame), dstReg)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVD %s, %s\n", operandSrc64ARM64(src, plan, frame), dstReg)
	default:
		return fmt.Errorf("phi-copy-to-reg type %v not supported (loop-carry coalesce is GP only)", t)
	}
	return nil
}

func (archARM64) emitPhiCopyARM64(b *strings.Builder, srcOperand string, dstOff int, t ssa.Type) error {
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVW %s, R0\n", srcOperand)
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dstOff)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVD %s, R0\n", srcOperand)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dstOff)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", srcOperand)
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dstOff)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", srcOperand)
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dstOff)
	default:
		return fmt.Errorf("phi type %v not supported", t)
	}
	return nil
}

func emitValueARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	switch v.Op {
	case ssa.OpCopy:
		return emitCopyARM64(b, v, plan, frame)

	case ssa.OpConst32:
		fmt.Fprintf(b, "\tMOVD $%d, R0\n", int32(v.AuxInt))
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpConst64:
		fmt.Fprintf(b, "\tMOVD $%d, R0\n", v.AuxInt)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpConstF32:
		// OpConstF32 carries the f32 bit pattern in AuxInt (set by
		// lower as `int64(math.Float32bits(v))`). Reinterpret-store
		// the low 32 bits into the destination slot — MOVW into a
		// float slot is fine because the slot is just bytes (the
		// downstream float ops reload via FMOVS, which interprets
		// those 4 bytes as the IEEE-754 single).
		fmt.Fprintf(b, "\tMOVD $%d, R0\n", int32(uint32(v.AuxInt)))
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpConstF64:
		// OpConstF64's AuxInt is the f64 bit pattern. Same
		// reinterpret-store as ConstF32, just 8 bytes.
		fmt.Fprintf(b, "\tMOVD $%d, R0\n", v.AuxInt)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil

	// OpParam is skipped via SkipValue at the emit-loop entry — its
	// consumers read `lN+off(FP)` directly through operandSrc32ARM64
	// / operandSrc64ARM64 / operandSrcFloat. No case here.

	// --- Integer binary (32-bit) ---
	case ssa.OpAdd32:
		return emitBin32ARM64(b, v, plan, frame, "ADDW")
	case ssa.OpSub32:
		return emitBin32ARM64(b, v, plan, frame, "SUBW")
	case ssa.OpMul32:
		return emitBin32ARM64(b, v, plan, frame, "MULW")
	case ssa.OpAnd32:
		return emitBin32ARM64(b, v, plan, frame, "ANDW")
	case ssa.OpOr32:
		return emitBin32ARM64(b, v, plan, frame, "ORRW")
	case ssa.OpXor32:
		return emitBin32ARM64(b, v, plan, frame, "EORW")

	// --- Integer binary (64-bit) ---
	case ssa.OpAdd64:
		return emitBin64ARM64(b, v, plan, frame, "ADD")
	case ssa.OpSub64:
		return emitBin64ARM64(b, v, plan, frame, "SUB")
	case ssa.OpMul64:
		return emitBin64ARM64(b, v, plan, frame, "MUL")
	case ssa.OpAnd64:
		return emitBin64ARM64(b, v, plan, frame, "AND")
	case ssa.OpOr64:
		return emitBin64ARM64(b, v, plan, frame, "ORR")
	case ssa.OpXor64:
		return emitBin64ARM64(b, v, plan, frame, "EOR")

	// --- Shifts (arm64 LSL/LSR/ASR mask the count to 5/6 bits which
	// matches wasm's mod-N rule). ---
	case ssa.OpShl32:
		return emitShift32ARM64(b, v, plan, frame, "LSLW")
	case ssa.OpShrU32:
		return emitShift32ARM64(b, v, plan, frame, "LSRW")
	case ssa.OpShrS32:
		return emitShift32ARM64(b, v, plan, frame, "ASRW")
	case ssa.OpShl64:
		return emitShift64ARM64(b, v, plan, frame, "LSL")
	case ssa.OpShrU64:
		return emitShift64ARM64(b, v, plan, frame, "LSR")
	case ssa.OpShrS64:
		return emitShift64ARM64(b, v, plan, frame, "ASR")

	// --- Comparisons (32-bit). CMPW src, dst sets flags as
	// dst - src, then CSET <cond>, dst materialises the 0/1
	// result. The condition codes match the signed/unsigned
	// semantics we need. ---
	case ssa.OpEq32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "EQ")
	case ssa.OpNe32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "NE")
	case ssa.OpLtS32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "LT")
	case ssa.OpLeS32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "LE")
	case ssa.OpLtU32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "LO")
	case ssa.OpLeU32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32ARM64(b, v, plan, frame, "LS")
	case ssa.OpEq64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "EQ")
	case ssa.OpNe64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "NE")
	case ssa.OpLtS64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "LT")
	case ssa.OpLeS64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "LE")
	case ssa.OpLtU64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "LO")
	case ssa.OpLeU64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64ARM64(b, v, plan, frame, "LS")

	// --- Integer extensions / truncation ---
	case ssa.OpExtend32To64S:
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSXTW R0, R0\n")
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpExtend32To64U:
		fmt.Fprintf(b, "\tMOVWU %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpTrunc64To32:
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", plan.offsets[v.ID])
		return nil

	// --- Memory loads / stores ---
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64:
		return emitLoadARM64(b, v, plan, frame)
	case ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpStoreF32, ssa.OpStoreF64:
		return emitStoreARM64(b, v, plan, frame)

	// --- Helper calls and direct calls (same plumbing — both go
	// through plan.directs / plan.helperRefs and BL the resolved
	// asm symbol). ---
	case ssa.OpHelperCall:
		// Branch-fused eqz: the BlockIf emitter performs the test
		// directly on the eqz argument, so the helper CALL, the
		// ABI bridge, and the slot store all disappear. The slot
		// stays allocated (harmless), and the call is skipped
		// here. See planFunc Pass 4 for the fusion detection.
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitHelperCallARM64(b, v, plan, frame)
	case ssa.OpGlobalGet:
		if _, ok := plan.globalInline[v.ID]; ok {
			return emitGlobalGetInlineARM64(b, v, plan, frame)
		}
		return emitCallDirectARM64(b, v, plan, frame)
	case ssa.OpGlobalSet:
		if _, ok := plan.globalInline[v.ID]; ok {
			return emitGlobalSetInlineARM64(b, v, plan, frame)
		}
		return emitCallDirectARM64(b, v, plan, frame)
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpMemSize, ssa.OpMemGrow,
		ssa.OpMemoryCopy, ssa.OpMemoryFill:
		return emitCallDirectARM64(b, v, plan, frame)

	// --- SIMD: v128 constants and helper CALLs ---
	case ssa.OpSimdConst:
		return emitSimdConstARM64(b, v, plan)
	case ssa.OpSimdCall, ssa.OpSimdMemCall:
		return emitSimdCallARM64(b, v, plan, frame)
	}
	return fmt.Errorf("op %v not supported by the arm64 emitter", v.Op)
}

func emitCopyARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) != 1 || v.Args[0] == nil {
		return fmt.Errorf("OpCopy expects one non-nil arg")
	}
	dst := plan.offsets[v.ID]
	switch v.Type {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
	default:
		return fmt.Errorf("OpCopy type %v not supported", v.Type)
	}
	return nil
}

func emitBin32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	// If the result has a register home, compute the op directly
	// into that register and skip the slot store.
	// arm64 three-operand ALU (`OP Rm, Rn, Rd`) lets us pick the
	// destination register independently of either source, so we
	// stage args into R0/R1 (scratch) and write the op result to
	// the home register in one instruction.
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\t%s R1, R0, %s\n", mnemonic, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitBin64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\t%s R1, R0, %s\n", mnemonic, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	return nil
}

func emitShift32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\t%s R1, R0, %s\n", mnemonic, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitShift64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\t%s R1, R0, %s\n", mnemonic, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	return nil
}

// emitFusedBitTestBranchARM64 lowers a fused
// `(base & 1<<bit) <eq/ne> 0` test to TBZ / TBNZ — the arm64
// counterparts of amd64's BTL+JCC pair. TBNZ branches when the
// specified bit is non-zero; TBZ branches when it is zero. The
// fall-through hint flips the choice the same way it does for
// the other cond shapes.
func emitFusedBitTestBranchARM64(b *strings.Builder, cond *ssa.Value, plan *funcPlan, frame argFrame, thenLabel, elseLabel, fallthroughLabel string) {
	info, ok := plan.branchFusedBit[cond.ID]
	if !ok {
		emitFusedCmpBranchARM64(b, cond, plan, frame, false, thenLabel, elseLabel, fallthroughLabel)
		return
	}
	kind := plan.branchFusedKind[cond.ID]
	is64 := kind == "i64_bittest_eq" || kind == "i64_bittest_ne"
	wantEq := kind == "i32_bittest_eq" || kind == "i64_bittest_eq"
	var src string
	if is64 {
		src = operandSrc64ARM64(info.base, plan, frame)
		fmt.Fprintf(b, "\tMOVD %s, R0\n", src)
	} else {
		src = operandSrc32ARM64(info.base, plan, frame)
		fmt.Fprintf(b, "\tMOVW %s, R0\n", src)
	}
	// TBNZ / TBZ take the form `<op> R0, $<bit>, label`. To match
	// the existing arm64 branch helpers we use emitBcondBranchARM64
	// — its formatting wraps `<bcond> <label>`, so we encode the
	// bit number into the mnemonic prefix.
	tbn := fmt.Sprintf("TBNZ $%d, R0,", info.bit)
	tbz := fmt.Sprintf("TBZ $%d, R0,", info.bit)
	if wantEq {
		// `(x & 1<<k) == 0` is "bit is zero" → TBZ takes the branch.
		emitBcondBranchARM64(b, tbz, tbn, thenLabel, elseLabel, fallthroughLabel)
	} else {
		emitBcondBranchARM64(b, tbn, tbz, thenLabel, elseLabel, fallthroughLabel)
	}
}

// emitFusedCmpBranchARM64 lowers a branch-fused integer comparison
// into a CMP + B<cond>. Mirrors emitCmp{32,64}ARM64's CMPW-second-
// minus-first ordering (CMPW R1, R0 computes R0 - R1) so the
// condition codes line up 1-for-1 with the original CSET <cond>.
// Maps: eq→BEQ, ne→BNE, lt_s→BLT, le_s→BLE, lt_u→BLO, le_u→BLS.
func emitFusedCmpBranchARM64(b *strings.Builder, cond *ssa.Value, plan *funcPlan, frame argFrame, is64 bool, thenLabel, elseLabel, fallthroughLabel string) {
	if is64 {
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(cond.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(cond.Args[1], plan, frame))
		fmt.Fprintf(b, "\tCMP R1, R0\n")
	} else {
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(cond.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(cond.Args[1], plan, frame))
		fmt.Fprintf(b, "\tCMPW R1, R0\n")
	}
	var bcond, bcondInv string
	switch plan.branchFusedKind[cond.ID] {
	case "i32_eq", "i64_eq":
		bcond, bcondInv = "BEQ", "BNE"
	case "i32_ne", "i64_ne":
		bcond, bcondInv = "BNE", "BEQ"
	case "i32_lt_s", "i64_lt_s":
		bcond, bcondInv = "BLT", "BGE"
	case "i32_lt_u", "i64_lt_u":
		bcond, bcondInv = "BLO", "BHS"
	case "i32_le_s", "i64_le_s":
		bcond, bcondInv = "BLE", "BGT"
	case "i32_le_u", "i64_le_u":
		bcond, bcondInv = "BLS", "BHI"
	}
	// emitCondBranchARM64 expects the branch op without the trailing
	// label-separator comma; the BEQ-class mnemonics use a single
	// operand (the label), so we pass the bare mnemonic and pre-form
	// the resulting "<op>, <label>" line. Use a small adapter here so
	// the same helper handles both the CB[N]Z and B<cond> shapes.
	emitBcondBranchARM64(b, bcond, bcondInv, thenLabel, elseLabel, fallthroughLabel)
}

// emitBcondBranchARM64 mirrors emitCondBranchARM64 but emits the
// `B<cond> <label>` shape used by the fused-compare path (no register
// operand prefix). The two helpers are kept separate to keep each
// caller's mnemonic explicit at the call site.
func emitBcondBranchARM64(b *strings.Builder, bcond, bcondInv, thenLabel, elseLabel, fallthroughLabel string) {
	if fallthroughLabel != "" && fallthroughLabel == elseLabel {
		fmt.Fprintf(b, "\t%s %s\n", bcond, thenLabel)
		return
	}
	if fallthroughLabel != "" && fallthroughLabel == thenLabel {
		fmt.Fprintf(b, "\t%s %s\n", bcondInv, elseLabel)
		return
	}
	fmt.Fprintf(b, "\t%s %s\n", bcond, thenLabel)
	fmt.Fprintf(b, "\tJMP %s\n", elseLabel)
}

func emitCmp32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, cond string) error {
	// CMPW second-operand-minus-first matches plan9 amd64's
	// CMP-after-rewrite convention; CSET sets R = 1 if the
	// requested condition is true after the compare.
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\tCMPW R1, R0\n")
		fmt.Fprintf(b, "\tCSET %s, %s\n", cond, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\tCMPW R1, R0\n")
	fmt.Fprintf(b, "\tCSET %s, R0\n", cond)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitCmp64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, cond string) error {
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
		fmt.Fprintf(b, "\tCMP R1, R0\n")
		fmt.Fprintf(b, "\tCSET %s, %s\n", cond, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\tCMP R1, R0\n")
	fmt.Fprintf(b, "\tCSET %s, R0\n", cond)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

// emitMemAddrARM64 emits the effective-address computation shared by
// emitLoadARM64 and emitStoreARM64. R2 must hold m.M on entry; on
// return R2 holds the full access address. The two memory widths
// share this one mechanism and differ only in the effective-address
// rule, mirroring the pure-Go emitter:
//
//   - wasm32: address = uint32(base + off) — computed in 32-bit so a
//     negative int32 base wraps the way wasm semantics require (the
//     pure-Go path is `uint32(base + int32(off))`). MOVWU / ADDW
//     zero-extend the low 32 bits into R3.
//   - memory64: address = base + off in full 64-bit, no wrap (the
//     pure-Go path is `uint64(base) + offset`). The Go assembler
//     materialises out-of-range ADD immediates via REGTMP, so the
//     shape stays a single ADD regardless of offset size.
func emitMemAddrARM64(b *strings.Builder, baseArg *ssa.Value, aux int64, plan *funcPlan, frame argFrame) {
	if plan.mem64 {
		fmt.Fprintf(b, "\tMOVD %s, R3\n", operandSrc64ARM64(baseArg, plan, frame))
		if aux != 0 {
			fmt.Fprintf(b, "\tADD $%d, R3, R3\n", aux)
		}
		fmt.Fprintf(b, "\tADD R3, R2, R2\n")
		return
	}
	off := int32(aux)
	fmt.Fprintf(b, "\tMOVWU %s, R3\n", operandSrc32ARM64(baseArg, plan, frame))
	if off != 0 {
		fmt.Fprintf(b, "\tADDW $%d, R3, R3\n", off)
	}
	fmt.Fprintf(b, "\tADD R3, R2, R2\n")
}

func emitLoadARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) < 1 || v.Args[0] == nil {
		return fmt.Errorf("OpLoad needs at least a base arg")
	}
	dst := plan.offsets[v.ID]
	// Compute effective address into R2:
	//   R2 = *(m + moduleMOffset) + uint32(base) + uint32(off)
	if plan.mCacheReg != "" {
		// m is in mCacheReg, skip the `MOVD m+0(FP), R2`
		// and read m.M directly off the cached pointer.
		fmt.Fprintf(b, "\tMOVD %d(%s), R2\n", moduleMOffset, plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R2\n")
		fmt.Fprintf(b, "\tMOVD %d(R2), R2\n", moduleMOffset)
	}
	emitMemAddrARM64(b, v.Args[0], v.AuxInt, plan, frame)
	is64 := v.Type == ssa.TypeI64
	// Load directly into the destination register when the value
	// has a regHome. Saves the final `MOVx R0, dst(RSP)` slot
	// store.
	home := plan.regHome[v.ID]
	// Load goes into either `home` (when set) or `R0` (scratch).
	loadReg := "R0"
	if home != "" {
		loadReg = home
	}
	switch v.Op {
	case ssa.OpLoad8U:
		fmt.Fprintf(b, "\tMOVBU (R2), %s\n", loadReg)
		if home == "" {
			if is64 {
				fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			} else {
				fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
			}
		}
	case ssa.OpLoad8S:
		fmt.Fprintf(b, "\tMOVB (R2), %s\n", loadReg)
		if home == "" {
			if is64 {
				fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			} else {
				fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
			}
		}
	case ssa.OpLoad16U:
		fmt.Fprintf(b, "\tMOVHU (R2), %s\n", loadReg)
		if home == "" {
			if is64 {
				fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			} else {
				fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
			}
		}
	case ssa.OpLoad16S:
		fmt.Fprintf(b, "\tMOVH (R2), %s\n", loadReg)
		if home == "" {
			if is64 {
				fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			} else {
				fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
			}
		}
	case ssa.OpLoad32:
		fmt.Fprintf(b, "\tMOVW (R2), %s\n", loadReg)
		if home == "" {
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad32U:
		// i64.load32_u: read u32 → zero-extend to i64.
		fmt.Fprintf(b, "\tMOVWU (R2), %s\n", loadReg)
		if home == "" {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad32S:
		// Sign-extend in place. SXTW writes the full 64-bit
		// result so the destination register holds the i64
		// the consumer expects.
		fmt.Fprintf(b, "\tMOVW (R2), %s\n", loadReg)
		fmt.Fprintf(b, "\tSXTW %s, %s\n", loadReg, loadReg)
		if home == "" {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad64:
		fmt.Fprintf(b, "\tMOVD (R2), %s\n", loadReg)
		if home == "" {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoadF32:
		// Float load. operandSrcFloat already returns regHome for
		// the float pool (F2..F7), so we mirror the same pattern.
		fLoadReg := "F0"
		if home != "" {
			fLoadReg = home
		}
		fmt.Fprintf(b, "\tFMOVS (R2), %s\n", fLoadReg)
		if home == "" {
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
		}
	case ssa.OpLoadF64:
		fLoadReg := "F0"
		if home != "" {
			fLoadReg = home
		}
		fmt.Fprintf(b, "\tFMOVD (R2), %s\n", fLoadReg)
		if home == "" {
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
		}
	default:
		return fmt.Errorf("OpLoad variant %v not supported", v.Op)
	}
	return nil
}

func emitStoreARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) < 2 || v.Args[0] == nil || v.Args[1] == nil {
		return fmt.Errorf("OpStore needs base and value args")
	}
	if plan.mCacheReg != "" {
		// m is in mCacheReg, dereference directly to m.M.
		fmt.Fprintf(b, "\tMOVD %d(%s), R2\n", moduleMOffset, plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R2\n")
		fmt.Fprintf(b, "\tMOVD %d(R2), R2\n", moduleMOffset)
	}
	emitMemAddrARM64(b, v.Args[0], v.AuxInt, plan, frame)
	valIs64 := v.Args[1].Type == ssa.TypeI64
	val32 := operandSrc32ARM64(v.Args[1], plan, frame)
	val64 := operandSrc64ARM64(v.Args[1], plan, frame)
	valFlt := operandSrcFloat(v.Args[1], plan, frame, "RSP")
	switch v.Op {
	case ssa.OpStore8:
		if valIs64 {
			fmt.Fprintf(b, "\tMOVD %s, R0\n", val64)
		} else {
			fmt.Fprintf(b, "\tMOVW %s, R0\n", val32)
		}
		fmt.Fprintf(b, "\tMOVB R0, (R2)\n")
	case ssa.OpStore16:
		if valIs64 {
			fmt.Fprintf(b, "\tMOVD %s, R0\n", val64)
		} else {
			fmt.Fprintf(b, "\tMOVW %s, R0\n", val32)
		}
		fmt.Fprintf(b, "\tMOVH R0, (R2)\n")
	case ssa.OpStore32:
		if valIs64 {
			fmt.Fprintf(b, "\tMOVD %s, R0\n", val64)
		} else {
			fmt.Fprintf(b, "\tMOVW %s, R0\n", val32)
		}
		fmt.Fprintf(b, "\tMOVW R0, (R2)\n")
	case ssa.OpStore64:
		fmt.Fprintf(b, "\tMOVD %s, R0\n", val64)
		fmt.Fprintf(b, "\tMOVD R0, (R2)\n")
	case ssa.OpStoreF32:
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", valFlt)
		fmt.Fprintf(b, "\tFMOVS F0, (R2)\n")
	case ssa.OpStoreF64:
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", valFlt)
		fmt.Fprintf(b, "\tFMOVD F0, (R2)\n")
	default:
		return fmt.Errorf("OpStore variant %v not supported", v.Op)
	}
	return nil
}

// emitSimdConstARM64 materializes an OpSimdConst's [2]uint64 lane
// payload into the value's 16-byte slot. The Go arm64 assembler
// materializes arbitrary MOVD immediates via its literal machinery.
func emitSimdConstARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan) error {
	c, err := simdConstAux(v)
	if err != nil {
		return err
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD $%d, R0\n", int64(c[0]))
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	fmt.Fprintf(b, "\tMOVD $%d, R0\n", int64(c[1]))
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst+8)
	return nil
}

// emitSimdCallARM64 is the arm64 twin of emitSimdCallAMD64: ABI0 CALL
// of the simd_* helper with the arm64 +8 callee-frame bias (see
// emitCallDirectARM64), v128 args/results as two 8-byte halves.
func emitSimdCallARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	sp, err := simdCallSpecOf(v, plan)
	if err != nil {
		return err
	}
	const bias = 8 // archARM64.CallArgBias()
	if done, err := trySpliceSimdCall(b, v, &sp, plan, frame, "RSP", bias); err != nil || done {
		return err
	}
	// See the amd64 twin: the CALL fallback only resolves in
	// single-package output.
	if plan.helperPfx != "" {
		return fmt.Errorf("%s: SIMD helper CALL cannot resolve cross-package", sp.name)
	}
	if sp.withM {
		if plan.mCacheReg != "" {
			fmt.Fprintf(b, "\tMOVD %s, %d(RSP)\n", plan.mCacheReg, bias+0)
		} else {
			fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", bias+0)
		}
	}
	for i, arg := range v.Args {
		off := bias + sp.argOffs[i]
		switch sp.args[i] {
		case ssa.TypeI32:
			fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", off)
		case ssa.TypeI64:
			fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", off)
		case ssa.TypeF32:
			fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", off)
		case ssa.TypeF64:
			fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", off)
		case ssa.TypeV128:
			lo, hi := v128Parts(arg, plan, frame, "RSP")
			fmt.Fprintf(b, "\tMOVD %s, R0\n", lo)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", off)
			fmt.Fprintf(b, "\tMOVD %s, R0\n", hi)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", off+8)
		default:
			return fmt.Errorf("%s arg %d type %v not supported", sp.name, i, sp.args[i])
		}
	}
	fmt.Fprintf(b, "\tCALL %s\n", goCallSymbol(plan.helperPfx, sp.name))
	plan.emittedCall = true
	if sp.ret != ssa.TypeInvalid && !plan.unusedResult[v.ID] {
		dst := plan.offsets[v.ID]
		retOff := bias + sp.retOff
		switch sp.ret {
		case ssa.TypeI32:
			fmt.Fprintf(b, "\tMOVW %d(RSP), R0\n", retOff)
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		case ssa.TypeI64:
			fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		case ssa.TypeF32:
			fmt.Fprintf(b, "\tFMOVS %d(RSP), F0\n", retOff)
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
		case ssa.TypeF64:
			fmt.Fprintf(b, "\tFMOVD %d(RSP), F0\n", retOff)
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
		case ssa.TypeV128:
			fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff+8)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst+8)
		default:
			return fmt.Errorf("%s ret type %v not supported", sp.name, sp.ret)
		}
	}
	return nil
}

// emitInlineHelperARM64 lowers the helperAlwaysInline set natively —
// no CALL, no ABI bridge. Results honor plan.regHome (OpHelperCall is
// regHome-eligible on arm64) or land in the value's slot.
func emitInlineHelperARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, name string) (bool, error) {
	dst := plan.offsets[v.ID]
	home := plan.regHome[v.ID]
	// storeGP writes the result in R0 to its destination.
	storeGP := func(mn string) {
		if home != "" {
			fmt.Fprintf(b, "\t%s R0, %s\n", mn, home)
		} else {
			fmt.Fprintf(b, "\t%s R0, %d(RSP)\n", mn, dst)
		}
	}
	storeF := func() {
		if home != "" {
			fmt.Fprintf(b, "\tFMOVS F0, %s\n", home)
		} else {
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
		}
	}
	storeF64 := func() {
		if home != "" {
			fmt.Fprintf(b, "\tFMOVD F0, %s\n", home)
		} else {
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
		}
	}
	switch name {
	case "i64_extend_i32_s":
		// MOVW sign-extends the low 32 bits into the full register.
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		storeGP("MOVD")
		return true, nil
	case "i64_extend_i32_u":
		fmt.Fprintf(b, "\tMOVWU %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		storeGP("MOVD")
		return true, nil
	case "i64_extend32_s":
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSXTW R0, R0\n")
		storeGP("MOVD")
		return true, nil
	case "i32_reinterpret_f32":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFMOVS F0, R0\n")
		storeGP("MOVW")
		return true, nil
	case "f32_reinterpret_i32":
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tFMOVS R0, F0\n")
		storeF()
		return true, nil
	case "f32_abs":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFABSS F0, F0\n")
		storeF()
		return true, nil
	case "f32_neg":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFNEGS F0, F0\n")
		storeF()
		return true, nil
	case "f64_abs":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFABSD F0, F0\n")
		storeF64()
		return true, nil
	case "f64_neg":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFNEGD F0, F0\n")
		storeF64()
		return true, nil
	case "i32_wrap_i64":
		// Low 32 bits; MOVWU zero-extends whether the source is a
		// slot or a register home.
		fmt.Fprintf(b, "\tMOVWU %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		storeGP("MOVW")
		return true, nil
	case "f64_promote_f32":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFCVTSD F0, F0\n")
		storeF64()
		return true, nil
	case "f32_demote_f64":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFCVTDS F0, F0\n")
		storeF()
		return true, nil
	case "f32_add", "f32_sub", "f32_mul", "f32_div",
		"f64_add", "f64_sub", "f64_mul", "f64_div":
		wide := strings.HasPrefix(name, "f64")
		fmov := "FMOVS"
		mn := map[string]string{"add": "FADDS", "sub": "FSUBS", "mul": "FMULS", "div": "FDIVS"}[name[4:]]
		if wide {
			fmov = "FMOVD"
			mn = map[string]string{"add": "FADDD", "sub": "FSUBD", "mul": "FMULD", "div": "FDIVD"}[name[4:]]
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", fmov, operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\t%s %s, F1\n", fmov, operandSrcFloat(v.Args[1], plan, frame, "RSP"))
		fmt.Fprintf(b, "\t%s F1, F0, F0\n", mn)
		if wide {
			storeF64()
		} else {
			storeF()
		}
		return true, nil
	case "f32_convert_i32_s":
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSCVTFWS R0, F0\n")
		storeF()
		return true, nil
	case "f32_convert_i32_u":
		fmt.Fprintf(b, "\tMOVWU %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tUCVTFWS R0, F0\n")
		storeF()
		return true, nil
	case "f32_convert_i64_s":
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSCVTFS R0, F0\n")
		storeF()
		return true, nil
	case "f64_convert_i32_s":
		fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSCVTFWD R0, F0\n")
		storeF64()
		return true, nil
	case "f64_convert_i32_u":
		fmt.Fprintf(b, "\tMOVWU %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tUCVTFWD R0, F0\n")
		storeF64()
		return true, nil
	case "f64_convert_i64_s":
		fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
		fmt.Fprintf(b, "\tSCVTFD R0, F0\n")
		storeF64()
		return true, nil
	case "i32_div_s", "i32_div_u_s", "i32_rem_s", "i32_rem_u_s",
		"i64_div_s", "i64_div_u_s", "i64_rem_s", "i64_rem_u_s":
		if !plan.divRemInline {
			// Trap helpers unresolved in this package; the inline
			// form would not link. Keep the marshalled CALL path.
			return false, nil
		}
		return true, emitInlineDivRemARM64(b, v, plan, frame, name)
	case "f32_eq", "f32_ne", "f32_lt", "f32_le", "f32_gt", "f32_ge",
		"f64_eq", "f64_ne", "f64_lt", "f64_le", "f64_gt", "f64_ge":
		// IEEE compare, wasm semantics: unordered (NaN) yields 0 for
		// every predicate except ne, which yields 1. The condition
		// codes below are all unordered-false (NE is unordered-true),
		// matching gc's own float-compare lowering.
		wide := strings.HasPrefix(name, "f64")
		fmov, fcmp := "FMOVS", "FCMPS"
		if wide {
			fmov, fcmp = "FMOVD", "FCMPD"
		}
		cond := map[string]string{
			"eq": "EQ", "ne": "NE", "lt": "MI", "le": "LS", "gt": "GT", "ge": "GE",
		}[name[4:]]
		fmt.Fprintf(b, "\t%s %s, F0\n", fmov, operandSrcFloat(v.Args[0], plan, frame, "RSP"))
		fmt.Fprintf(b, "\t%s %s, F1\n", fmov, operandSrcFloat(v.Args[1], plan, frame, "RSP"))
		fmt.Fprintf(b, "\t%s F1, F0\n", fcmp)
		fmt.Fprintf(b, "\tCSET %s, R0\n", cond)
		storeGP("MOVW")
		return true, nil
	}
	return false, nil
}

// emitInlineDivRemARM64 lowers the integer divide/remainder family:
// SDIV/UDIV (which never fault on arm64 — traps are explicit
// branches), MSUB for remainders. wasm semantics:
//
//   - every op traps on a zero divisor;
//   - div_s(INT_MIN, -1) traps as integer overflow (SDIV would
//     silently wrap to INT_MIN);
//   - rem_s(INT_MIN, -1) is 0, NO trap — SDIV wraps q to INT_MIN and
//     MSUB computes x - q*y = 0 with the same wrap, so no check is
//     needed.
//
// The trap CALL targets come from the plan (resolved to forward
// wrappers in multi-package chunks); the trap helpers panic, so
// control never returns from those labels.
func emitInlineDivRemARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, name string) error {
	dst := plan.offsets[v.ID]
	home := plan.regHome[v.ID]
	wide := strings.HasPrefix(name, "i64")
	signed := !strings.Contains(name, "_u")
	isRem := strings.Contains(name, "rem")
	mov, cbz, div, st := "MOVW", "CBZW", "UDIVW", "MOVW"
	if signed {
		div = "SDIVW"
	}
	if wide {
		mov, cbz, st = "MOVD", "CBZ", "MOVD"
		div = "UDIV"
		if signed {
			div = "SDIV"
		}
	}
	// Unsigned operands still load with the plain MOV: the divide
	// consumes exactly the register width either way.
	fmt.Fprintf(b, "\t%s %s, R0\n", mov, operandSrcXARM64(v.Args[0], plan, frame, wide))
	fmt.Fprintf(b, "\t%s %s, R1\n", mov, operandSrcXARM64(v.Args[1], plan, frame, wide))
	zeroLbl := fmt.Sprintf("DIVREM_ZERO_%d", v.ID)
	doneLbl := fmt.Sprintf("DIVREM_DONE_%d", v.ID)
	fmt.Fprintf(b, "\t%s R1, %s\n", cbz, zeroLbl)
	if signed && !isRem {
		// div_s overflow check: y == -1 && x == INT_MIN.
		ovfLbl := fmt.Sprintf("DIVREM_OVF_%d", v.ID)
		goLbl := fmt.Sprintf("DIVREM_GO_%d", v.ID)
		if wide {
			fmt.Fprintf(b, "\tCMP $-1, R1\n")
			fmt.Fprintf(b, "\tBNE %s\n", goLbl)
			fmt.Fprintf(b, "\tMOVD $-9223372036854775808, R2\n")
			fmt.Fprintf(b, "\tCMP R2, R0\n")
		} else {
			fmt.Fprintf(b, "\tCMPW $-1, R1\n")
			fmt.Fprintf(b, "\tBNE %s\n", goLbl)
			fmt.Fprintf(b, "\tMOVD $-2147483648, R2\n")
			fmt.Fprintf(b, "\tCMPW R2, R0\n")
		}
		fmt.Fprintf(b, "\tBEQ %s\n", ovfLbl)
		fmt.Fprintf(b, "%s:\n", goLbl)
		fmt.Fprintf(b, "\t%s R1, R0, R0\n", div)
		if home != "" {
			fmt.Fprintf(b, "\t%s R0, %s\n", st, home)
		} else {
			fmt.Fprintf(b, "\t%s R0, %d(RSP)\n", st, dst)
		}
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", ovfLbl)
		fmt.Fprintf(b, "\tCALL %s(SB)\n", plan.trapIntOvf)
	} else if isRem {
		// q = x / y; r = x - q*y (MSUB).
		fmt.Fprintf(b, "\t%s R1, R0, R2\n", div)
		if wide {
			fmt.Fprintf(b, "\tMSUB R1, R0, R2, R0\n")
		} else {
			fmt.Fprintf(b, "\tMSUBW R1, R0, R2, R0\n")
		}
		if home != "" {
			fmt.Fprintf(b, "\t%s R0, %s\n", st, home)
		} else {
			fmt.Fprintf(b, "\t%s R0, %d(RSP)\n", st, dst)
		}
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
	} else {
		fmt.Fprintf(b, "\t%s R1, R0, R0\n", div)
		if home != "" {
			fmt.Fprintf(b, "\t%s R0, %s\n", st, home)
		} else {
			fmt.Fprintf(b, "\t%s R0, %d(RSP)\n", st, dst)
		}
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
	}
	fmt.Fprintf(b, "%s:\n", zeroLbl)
	fmt.Fprintf(b, "\tCALL %s(SB)\n", plan.trapDivZero)
	fmt.Fprintf(b, "%s:\n", doneLbl)
	return nil
}

// operandSrcXARM64 picks the 32- or 64-bit operand renderer.
func operandSrcXARM64(v *ssa.Value, plan *funcPlan, frame argFrame, wide bool) string {
	if wide {
		return operandSrc64ARM64(v, plan, frame)
	}
	return operandSrc32ARM64(v, plan, frame)
}

func emitHelperCallARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	name := plan.helperRefs[v.ID]
	if done, err := emitInlineHelperARM64(b, v, plan, frame, name); done || err != nil {
		return err
	}
	if helperAlwaysInline(name) {
		// planFunc exempted this call from the callee-frame budget on
		// the strength of the inline lowering above; reaching the
		// CALL path would clobber a frame that was never reserved.
		return fmt.Errorf("helper %q: inline lowering missing", name)
	}
	spec, ok := helperSig(name)
	if !ok {
		return fmt.Errorf("unknown helper %q", name)
	}
	if len(v.Args) != len(spec.params) {
		return fmt.Errorf("helper %q wants %d args, got %d", name, len(spec.params), len(v.Args))
	}
	// Same +8 bias as emitCallDirectARM64 — see CallArgBias() comment.
	const bias = 8 // archARM64.CallArgBias()
	off := 0
	for i, arg := range v.Args {
		size, align := helperABISize(spec.params[i])
		off = alignUp(off, align)
		switch spec.params[i] {
		case ssa.TypeI32:
			fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", bias+off)
		case ssa.TypeI64:
			fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", bias+off)
		case ssa.TypeF32:
			fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", bias+off)
		case ssa.TypeF64:
			fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", bias+off)
		default:
			return fmt.Errorf("helper %q arg %d type %v not supported", name, i, spec.params[i])
		}
		off += size
	}
	retOff := bias + helperRetOffset(spec)
	symbol := goCallSymbol(plan.helperPfx, name)
	fmt.Fprintf(b, "\tCALL %s\n", symbol)
	plan.emittedCall = true
	// Drop the result load+store pair when nothing reads it (same
	// rationale as the amd64 helpers).
	if spec.ret != ssa.TypeInvalid && !plan.unusedResult[v.ID] {
		dst := plan.offsets[v.ID]
		// Load directly into regHome when present.
		home := plan.regHome[v.ID]
		switch spec.ret {
		case ssa.TypeI32:
			if home != "" {
				fmt.Fprintf(b, "\tMOVW %d(RSP), %s\n", retOff, home)
			} else {
				fmt.Fprintf(b, "\tMOVW %d(RSP), R0\n", retOff)
				fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
			}
		case ssa.TypeI64:
			if home != "" {
				fmt.Fprintf(b, "\tMOVD %d(RSP), %s\n", retOff, home)
			} else {
				fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff)
				fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
			}
		case ssa.TypeF32:
			if home != "" {
				fmt.Fprintf(b, "\tFMOVS %d(RSP), %s\n", retOff, home)
			} else {
				fmt.Fprintf(b, "\tFMOVS %d(RSP), F0\n", retOff)
				fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
			}
		case ssa.TypeF64:
			if home != "" {
				fmt.Fprintf(b, "\tFMOVD %d(RSP), %s\n", retOff, home)
			} else {
				fmt.Fprintf(b, "\tFMOVD %d(RSP), F0\n", retOff)
				fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
			}
		default:
			return fmt.Errorf("helper %q ret type %v not supported", name, spec.ret)
		}
	}
	return nil
}

// emitGlobalGetInlineARM64 lowers an OpGlobalGet directly to a MOV
// against the Module struct, skipping the loadGlobal_<idx> CALL.
// See the amd64 counterpart's comment for motivation.
func emitGlobalGetInlineARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	_ = frame
	info, ok := plan.globalInline[v.ID]
	if !ok {
		return fmt.Errorf("OpGlobalGet v%d: no globalInline entry", v.ID)
	}
	dst := plan.offsets[v.ID]
	// Use mCacheReg as the m pointer when available; fall back to
	// the one-shot `MOVD m+0(FP), R0` for legacy.
	mReg := "R0"
	if plan.mCacheReg != "" {
		mReg = plan.mCacheReg
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
	}
	switch info.vtype {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVW %d(%s), R1\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVW R1, %d(RSP)\n", dst)
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVD %d(%s), R1\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVD R1, %d(RSP)\n", dst)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tFMOVS %d(%s), F0\n", info.offset, mReg)
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tFMOVD %d(%s), F0\n", info.offset, mReg)
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
	default:
		return fmt.Errorf("OpGlobalGet v%d: global type %v unsupported by inline emitter", v.ID, info.vtype)
	}
	return nil
}

// emitGlobalSetInlineARM64 is the OpGlobalSet counterpart of
// emitGlobalGetInlineARM64.
func emitGlobalSetInlineARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	info, ok := plan.globalInline[v.ID]
	if !ok {
		return fmt.Errorf("OpGlobalSet v%d: no globalInline entry", v.ID)
	}
	if len(v.Args) != 1 || v.Args[0] == nil {
		return fmt.Errorf("OpGlobalSet v%d: expected 1 arg, got %d", v.ID, len(v.Args))
	}
	src := v.Args[0]
	// m caching, same shape as emitGlobalGetInlineARM64.
	mReg := "R0"
	if plan.mCacheReg != "" {
		mReg = plan.mCacheReg
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
	}
	switch info.vtype {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(src, plan, frame))
		fmt.Fprintf(b, "\tMOVW R1, %d(%s)\n", info.offset, mReg)
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(src, plan, frame))
		fmt.Fprintf(b, "\tMOVD R1, %d(%s)\n", info.offset, mReg)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(src, plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFMOVS F0, %d(%s)\n", info.offset, mReg)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(src, plan, frame, "RSP"))
		fmt.Fprintf(b, "\tFMOVD F0, %d(%s)\n", info.offset, mReg)
	default:
		return fmt.Errorf("OpGlobalSet v%d: global type %v unsupported by inline emitter", v.ID, info.vtype)
	}
	return nil
}

func emitCallDirectARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	d, ok := plan.directs[v.ID]
	if !ok {
		return fmt.Errorf("%v v%d: no plan entry", v.Op, v.ID)
	}
	if len(v.Args) != len(d.sig.Params) {
		return fmt.Errorf("%v v%d: signature has %d params, IR has %d args", v.Op, v.ID, len(d.sig.Params), len(v.Args))
	}
	// Forward the caller's m at FP+0 to the callee's frame.
	// The callee will read m+0(FP), which the Go arm64 assembler
	// resolves to SP_callee_after_prologue + autosize + 8 == caller_SP
	// + 8. So we store m at caller_SP+8 (== archARM64.CallArgBias()).
	const bias = 8 // archARM64.CallArgBias()
	if plan.mCacheReg != "" {
		// Stage from the cache register.
		fmt.Fprintf(b, "\tMOVD %s, %d(RSP)\n", plan.mCacheReg, bias+0)
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", bias+0)
	}
	for i, arg := range v.Args {
		argOff := bias + d.frame.paramOffsets[i]
		switch d.sig.Params[i] {
		case wasm.ValI32:
			fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", argOff)
		case wasm.ValI64:
			fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(arg, plan, frame))
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", argOff)
		case wasm.ValF32:
			fmt.Fprintf(b, "\tFMOVS %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", argOff)
		case wasm.ValF64:
			fmt.Fprintf(b, "\tFMOVD %s, F0\n", operandSrcFloat(arg, plan, frame, "RSP"))
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", argOff)
		default:
			return fmt.Errorf("%v v%d: param %d type %v unsupported", v.Op, v.ID, i, d.sig.Params[i])
		}
	}
	fmt.Fprintf(b, "\tCALL %s\n", d.symbol)
	plan.emittedCall = true

	if len(d.sig.Results) == 0 {
		return nil
	}
	if len(d.sig.Results) > 1 {
		return fmt.Errorf("%v v%d: multi-result returns not supported", v.Op, v.ID)
	}
	// Same as amd64 — drop the result load+store when no
	// downstream consumer reads it. The CALL itself stays.
	if plan.unusedResult[v.ID] {
		return nil
	}
	dst := plan.offsets[v.ID]
	retOff := bias + d.frame.resultOffsets[0]
	// Load the call result directly into the result's regHome
	// when present. CALL clobbers R0..R15 in the arm64 ABI
	// but the emitBlock loop already refreshes mCacheReg after the
	// CALL via opEmitsCall; the per-value regHome is OK to write
	// AFTER the refresh because the regHome lifetime starts at
	// THIS value's def (the CALL site) and the regalloc filtered
	// out anything that crossed the CALL.
	home := plan.regHome[v.ID]
	switch d.sig.Results[0] {
	case wasm.ValI32:
		if home != "" {
			fmt.Fprintf(b, "\tMOVW %d(RSP), %s\n", retOff, home)
		} else {
			fmt.Fprintf(b, "\tMOVW %d(RSP), R0\n", retOff)
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case wasm.ValI64:
		if home != "" {
			fmt.Fprintf(b, "\tMOVD %d(RSP), %s\n", retOff, home)
		} else {
			fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff)
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		}
	case wasm.ValF32:
		if home != "" {
			fmt.Fprintf(b, "\tFMOVS %d(RSP), %s\n", retOff, home)
		} else {
			fmt.Fprintf(b, "\tFMOVS %d(RSP), F0\n", retOff)
			fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
		}
	case wasm.ValF64:
		if home != "" {
			fmt.Fprintf(b, "\tFMOVD %d(RSP), %s\n", retOff, home)
		} else {
			fmt.Fprintf(b, "\tFMOVD %d(RSP), F0\n", retOff)
			fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
		}
	default:
		return fmt.Errorf("%v v%d: result type %v unsupported", v.Op, v.ID, d.sig.Results[0])
	}
	return nil
}
