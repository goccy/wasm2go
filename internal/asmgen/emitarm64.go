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

// SupportsRegHome — arm64 opts in for BLOCK-LOCAL regalloc: its
// operandSrc32/64ARM64 honour plan.regHome on the read side and the
// per-op emits that RegHomeEligibleOp accepts honour it on the write
// side. Block-local regalloc keeps every value within one block, so a
// carry is reloaded from its slot each iteration — always correct.
func (archARM64) SupportsRegHome() bool { return true }

// SupportsLoopCarryCoalesce — arm64 opts into the cross-block
// loop-carry coalesce pass. The SHARED mode is safe because the
// candidate filter only accepts carries whose producer op passes
// archARM64.RegHomeEligibleOp — exactly the ops whose write side
// honours plan.regHome — and the OWN-REGISTER mode never requires a
// producer write at all (the edge copies go through
// EmitPhiCopyValueToReg). Reservation bookkeeping (loop body +
// out-of-body live region) is arch-independent.
func (archARM64) SupportsLoopCarryCoalesce() bool { return true }

// CoalesceRegPool — the unallocated tail of arm64's block-local pool
// (R5..R15). R13/R14/R15 are not used as scratches by any arm64
// per-op emit (R0-R3 / F0-F1 only), are not the m-cache (R4), and are
// not Go-reserved (R18 platform, R27 assembler temp, R28 g, R29/R30
// FP/LR).
func (archARM64) CoalesceRegPool() []string {
	return []string{"R13", "R14", "R15"}
}

// HelperIsInline — arm64 emits the helpers in inlineHelperNamesARM64
// without a returning CALL (see emitInlineHelperARM64); everything
// else stages args and CALLs the Go-side helper.
func (archARM64) HelperIsInline(name string) bool {
	return inlineHelperNamesARM64[name]
}

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
	default:
		return fmt.Errorf("phi type %v not supported", t)
	}
	return a.emitPhiCopyARM64(b, srcOp, dstOff, t)
}

func (a archARM64) EmitPhiCopySlot(b *strings.Builder, srcOff, dstOff int, t ssa.Type) error {
	return a.emitPhiCopyARM64(b, fmt.Sprintf("%d(RSP)", srcOff), dstOff, t)
}

// EmitPhiCopyValueToReg is the arm64 edge copy for the loop-carry
// coalesce path: every edge of an own-register phi and the forward
// (entry) edge of a shared coalesce route through here.
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

func emitLoadARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) < 1 || v.Args[0] == nil {
		return fmt.Errorf("OpLoad needs at least a base arg")
	}
	off := int32(v.AuxInt)
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
	// Compute base+off in 32-bit so a negative int32 base wraps
	// the way wasm semantics require — the pure-Go path uses
	// `uint32(base + int32(off))`. ADDW writes the low 32 bits and
	// zero-extends to 64, leaving R3 holding the correct u32.
	fmt.Fprintf(b, "\tMOVWU %s, R3\n", operandSrc32ARM64(v.Args[0], plan, frame))
	if off != 0 {
		fmt.Fprintf(b, "\tADDW $%d, R3, R3\n", off)
	}
	fmt.Fprintf(b, "\tADD R3, R2, R2\n")
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
	off := int32(v.AuxInt)
	if plan.mCacheReg != "" {
		// m is in mCacheReg, dereference directly to m.M.
		fmt.Fprintf(b, "\tMOVD %d(%s), R2\n", moduleMOffset, plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVD m+0(FP), R2\n")
		fmt.Fprintf(b, "\tMOVD %d(R2), R2\n", moduleMOffset)
	}
	// Same u32 wrap-around story as emitLoadARM64.
	fmt.Fprintf(b, "\tMOVWU %s, R3\n", operandSrc32ARM64(v.Args[0], plan, frame))
	if off != 0 {
		fmt.Fprintf(b, "\tADDW $%d, R3, R3\n", off)
	}
	fmt.Fprintf(b, "\tADD R3, R2, R2\n")
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

func emitHelperCallARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	name := plan.helperRefs[v.ID]
	spec, ok := helperSig(name)
	if !ok {
		return fmt.Errorf("unknown helper %q", name)
	}
	if len(v.Args) != len(spec.params) {
		return fmt.Errorf("helper %q wants %d args, got %d", name, len(spec.params), len(v.Args))
	}
	// Prefer inline asm — same policy as amd64's emitHelperCall. The
	// helpers arm64 does not natively implement fall through to the
	// staged CALL below.
	if done, err := emitInlineHelperARM64(b, v, plan, frame, name); err != nil {
		return err
	} else if done {
		return nil
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

// inlineHelperNamesARM64 is the set of helper names
// emitInlineHelperARM64 handles WITHOUT a returning CALL. It must
// stay in sync with that function's switch —
// TestInlineHelperPredicateMatchesEmitARM64 pins the correspondence
// by dry-running the emitter for every registered helper name.
//
// Names in this set are transparent to the CALL-barrier analyses
// (block-local regalloc, loop-carry coalesce, m-cache refresh): their
// emit clobbers only the fixed scratches (R0-R3 / F0-F1), never a
// pool or reserved register. The inline div/rem bodies contain
// conditional `CALL ·wasm_trap_*(SB)` branches, but those helpers
// panic and never return — execution never rejoins the function with
// clobbered registers, so they are not a barrier.
//
// Differences from the amd64 set: popcnt stays a CALL (no scalar
// arm64 popcount instruction), while ALL FOUR trunc_sat unsigned
// variants join the inline set (FCVTZU saturates natively; amd64
// only inlines the signed pair).
var inlineHelperNamesARM64 = map[string]bool{
	"i32_eqz": true, "i64_eqz": true,
	"i32_clz": true, "i32_ctz": true, "i64_clz": true, "i64_ctz": true,
	"i32_rotl": true, "i32_rotr": true, "i64_rotl": true, "i64_rotr": true,
	"i32_div_s": true, "i32_div_u_s": true,
	"i32_rem_s": true, "i32_rem_u_s": true,
	"i64_div_s": true, "i64_div_u_s": true,
	"i64_rem_s": true, "i64_rem_u_s": true,
	"i32_wrap_i64": true, "i64_extend_i32_s": true, "i64_extend_i32_u": true,
	"i32_extend8_s": true, "i32_extend16_s": true,
	"i64_extend8_s": true, "i64_extend16_s": true, "i64_extend32_s": true,
	"i32_reinterpret_f32": true, "f32_reinterpret_i32": true,
	"i64_reinterpret_f64": true, "f64_reinterpret_i64": true,
	"f32_add": true, "f32_sub": true, "f32_mul": true, "f32_div": true,
	"f64_add": true, "f64_sub": true, "f64_mul": true, "f64_div": true,
	"f32_sqrt": true, "f64_sqrt": true,
	"f32_abs": true, "f64_abs": true, "f32_neg": true, "f64_neg": true,
	"f32_eq": true, "f32_ne": true, "f32_lt": true, "f32_le": true, "f32_gt": true, "f32_ge": true,
	"f64_eq": true, "f64_ne": true, "f64_lt": true, "f64_le": true, "f64_gt": true, "f64_ge": true,
	"f32_ceil": true, "f32_floor": true, "f32_trunc": true, "f32_nearest": true,
	"f64_ceil": true, "f64_floor": true, "f64_trunc": true, "f64_nearest": true,
	"f32_min": true, "f32_max": true, "f64_min": true, "f64_max": true,
	"f32_copysign": true, "f64_copysign": true,
	"f32_demote_f64": true, "f64_promote_f32": true,
	"f32_convert_i32_s": true, "f32_convert_i64_s": true,
	"f64_convert_i32_s": true, "f64_convert_i64_s": true,
	"f32_convert_i32_u": true, "f32_convert_i64_u": true,
	"f64_convert_i32_u": true, "f64_convert_i64_u": true,
	"i32_trunc_sat_f32_s": true, "i32_trunc_sat_f32_u": true,
	"i32_trunc_sat_f64_s": true, "i32_trunc_sat_f64_u": true,
	"i64_trunc_sat_f32_s": true, "i64_trunc_sat_f32_u": true,
	"i64_trunc_sat_f64_s": true, "i64_trunc_sat_f64_u": true,
}

// isFloatRegARM64 reports whether s names an arm64 FP register (the
// SSERegPool entries F2..F7 plus the F0/F1 scratches).
func isFloatRegARM64(s string) bool {
	return len(s) >= 2 && s[0] == 'F' && s[1] >= '0' && s[1] <= '9'
}

// emitInlineHelperARM64 emits the inline arm64 body for a known
// helper — no CALL to a Go-side helper function. Returns true when
// the helper was handled inline; emitHelperCallARM64 falls back to
// the staged CALL otherwise.
//
// Scratch discipline: bodies read operands via
// operandSrc{32,64}ARM64 / operandSrcFloat into R0/R1/R2/R3 and
// F0/F1 only, and write the result to plan.regHome[v.ID] when the
// regalloc assigned one (OpHelperCall is regHome-eligible on arm64)
// or to the value's slot otherwise. Pool registers (R5..R15,
// F2..F7) are never used as intermediates, so the CALL-barrier
// subtraction in the regalloc/coalesce analyses stays sound. The
// result register is only written AFTER every operand has been
// read — an operand may itself live in the home register's pool
// neighbourhood, but never in the result's own home (the linear
// scan keeps an operand's register live through its last use).
//
// Instruction-selection notes (all verified by native execution on
// darwin/arm64 before this landed):
//   - SDIVW/UDIVW Rm, Rn, Rd computes Rd = Rn / Rm; MSUBW Rm, Rn,
//     Ra, Rd computes Rd = Rn − Ra×Rm — together they form wasm's
//     div/rem. arm64 division does NOT fault: div-by-zero returns 0
//     and INT_MIN/−1 wraps, so the wasm traps are explicit compare+
//     branch to the never-returning wasm_trap_* helpers (amd64 gets
//     the same traps from the hardware #DE).
//   - RORW/ROR $imm|Rm rotates right; rotl is ROR of the negated
//     count (NEGW/NEG), which the hardware masks mod width.
//   - FCMPS/FCMPD Fm, Fn sets flags from Fn ? Fm with unordered
//     mapping such that CSET MI/LS/GT/GE/EQ are exactly wasm's
//     lt/le/gt/ge/eq (false on NaN) and NE is wasm ne (true on NaN).
//   - FCVTZS/FCVTZU saturate to the destination range and map NaN
//     to 0 — precisely wasm's trunc_sat semantics, one instruction.
//   - FMIN/FMAX propagate NaN and order ±0 the way wasm requires.
//   - CLZ handles a zero input (returns the width) with no branch,
//     so clz/ctz have no labels at all (ctz = CLZ ∘ RBIT).
func emitInlineHelperARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, name string) (bool, error) {
	dst := plan.offsets[v.ID]
	home := plan.regHome[v.ID]
	// Integer result target: the value's home register when it has
	// one, else the R0 scratch followed by a slot store.
	iTgt, iStore := "R0", true
	if home != "" && !isFloatRegARM64(home) {
		iTgt, iStore = home, false
	}
	fTgt, fStore := "F0", true
	if home != "" && isFloatRegARM64(home) {
		fTgt, fStore = home, false
	}
	storeI32 := func() {
		if iStore {
			fmt.Fprintf(b, "\tMOVW %s, %d(RSP)\n", iTgt, dst)
		}
	}
	storeI64 := func() {
		if iStore {
			fmt.Fprintf(b, "\tMOVD %s, %d(RSP)\n", iTgt, dst)
		}
	}
	storeF32 := func() {
		if fStore {
			fmt.Fprintf(b, "\tFMOVS %s, %d(RSP)\n", fTgt, dst)
		}
	}
	storeF64 := func() {
		if fStore {
			fmt.Fprintf(b, "\tFMOVD %s, %d(RSP)\n", fTgt, dst)
		}
	}
	src32 := func(i int) string { return operandSrc32ARM64(v.Args[i], plan, frame) }
	src64 := func(i int) string { return operandSrc64ARM64(v.Args[i], plan, frame) }
	srcF := func(i int) string { return operandSrcFloat(v.Args[i], plan, frame, "RSP") }

	// floatBin/floatUn/floatCmp factor the fully regular float
	// families; the switch below routes each name with its mnemonic.
	floatBin := func(mnem string, is64 bool) (bool, error) {
		mov := "FMOVS"
		if is64 {
			mov = "FMOVD"
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", mov, srcF(0))
		fmt.Fprintf(b, "\t%s %s, F1\n", mov, srcF(1))
		fmt.Fprintf(b, "\t%s F1, F0\n", mnem) // F0 = F0 <op> F1
		if fTgt != "F0" {
			fmt.Fprintf(b, "\t%s F0, %s\n", mov, fTgt)
		}
		if is64 {
			storeF64()
		} else {
			storeF32()
		}
		return true, nil
	}
	floatBin3 := func(mnem string, is64 bool) (bool, error) {
		// FMIN/FMAX use the 3-operand form so the result can land in
		// the home register directly.
		mov := "FMOVS"
		if is64 {
			mov = "FMOVD"
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", mov, srcF(0))
		fmt.Fprintf(b, "\t%s %s, F1\n", mov, srcF(1))
		fmt.Fprintf(b, "\t%s F1, F0, %s\n", mnem, fTgt) // fTgt = min/max(F0, F1)
		if is64 {
			storeF64()
		} else {
			storeF32()
		}
		return true, nil
	}
	floatUn := func(mnem string, is64 bool) (bool, error) {
		mov := "FMOVS"
		if is64 {
			mov = "FMOVD"
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", mov, srcF(0))
		fmt.Fprintf(b, "\t%s F0, %s\n", mnem, fTgt)
		if is64 {
			storeF64()
		} else {
			storeF32()
		}
		return true, nil
	}
	floatCmp := func(cond string, is64 bool) (bool, error) {
		mov, cmp := "FMOVS", "FCMPS"
		if is64 {
			mov, cmp = "FMOVD", "FCMPD"
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", mov, srcF(0))
		fmt.Fprintf(b, "\t%s %s, F1\n", mov, srcF(1))
		fmt.Fprintf(b, "\t%s F1, F0\n", cmp) // flags from F0 ? F1
		fmt.Fprintf(b, "\tCSET %s, %s\n", cond, iTgt)
		storeI32()
		return true, nil
	}
	convert := func(cvt string, srcIs64 bool, dstIs64 bool) (bool, error) {
		if srcIs64 {
			fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		} else {
			fmt.Fprintf(b, "\tMOVWU %s, R1\n", src32(0))
		}
		fmt.Fprintf(b, "\t%s R1, %s\n", cvt, fTgt)
		if dstIs64 {
			storeF64()
		} else {
			storeF32()
		}
		return true, nil
	}
	truncSat := func(cvt string, srcIs64 bool, dstIs64 bool) (bool, error) {
		mov := "FMOVS"
		if srcIs64 {
			mov = "FMOVD"
		}
		fmt.Fprintf(b, "\t%s %s, F0\n", mov, srcF(0))
		fmt.Fprintf(b, "\t%s F0, %s\n", cvt, iTgt)
		if dstIs64 {
			storeI64()
		} else {
			storeI32()
		}
		return true, nil
	}
	// divRem emits the shared div/rem skeleton: explicit div-by-zero
	// trap, optional signed-overflow trap (div_s only — rem_s of
	// INT_MIN/−1 is 0 by MSUB wraparound, which is what wasm wants),
	// then SDIV/UDIV (+ MSUB for rem).
	divRem := func(is64, signed, rem bool) (bool, error) {
		movLoad := "MOVWU"
		if signed {
			movLoad = "MOVW"
		}
		cmp, div, msub, minConst := "CMPW", "UDIVW", "MSUBW", ""
		if signed {
			div = "SDIVW"
			minConst = "$-2147483648"
		}
		if is64 {
			cmp, div, msub = "CMP", "UDIV", "MSUB"
			if signed {
				div = "SDIV"
				minConst = "$-9223372036854775808"
			}
			movLoad = "MOVD"
		}
		var s0, s1 string
		if is64 {
			s0, s1 = src64(0), src64(1)
		} else {
			s0, s1 = src32(0), src32(1)
		}
		zeroLbl := fmt.Sprintf("DIVZ_%d", v.ID)
		doneLbl := fmt.Sprintf("DIVD_%d", v.ID)
		okLbl := fmt.Sprintf("DIVOK_%d", v.ID)
		fmt.Fprintf(b, "\t%s %s, R1\n", movLoad, s0)
		fmt.Fprintf(b, "\t%s %s, R2\n", movLoad, s1)
		fmt.Fprintf(b, "\t%s $0, R2\n", cmp)
		fmt.Fprintf(b, "\tBEQ %s\n", zeroLbl)
		if signed && !rem {
			// wasm div_s traps on INT_MIN / −1; arm64 SDIV wraps
			// silently, so the trap is explicit.
			fmt.Fprintf(b, "\t%s $-1, R2\n", cmp)
			fmt.Fprintf(b, "\tBNE %s\n", okLbl)
			fmt.Fprintf(b, "\tMOVD %s, R3\n", minConst)
			fmt.Fprintf(b, "\t%s R3, R1\n", cmp)
			fmt.Fprintf(b, "\tBNE %s\n", okLbl)
			fmt.Fprintf(b, "\tCALL %s\n", goCallSymbol(plan.helperPfx, "wasm_trap_int_overflow"))
			fmt.Fprintf(b, "%s:\n", okLbl)
		}
		if rem {
			fmt.Fprintf(b, "\t%s R2, R1, R3\n", div)
			fmt.Fprintf(b, "\t%s R2, R1, R3, %s\n", msub, iTgt) // iTgt = R1 − R3×R2
		} else {
			fmt.Fprintf(b, "\t%s R2, R1, %s\n", div, iTgt)
		}
		if is64 {
			storeI64()
		} else {
			storeI32()
		}
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL %s\n", goCallSymbol(plan.helperPfx, "wasm_trap_div_zero"))
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	}
	rotate := func(is64, left bool) (bool, error) {
		width := 32
		movLoad, ror, neg := "MOVWU", "RORW", "NEGW"
		if is64 {
			width = 64
			movLoad, ror, neg = "MOVD", "ROR", "NEG"
		}
		var s0 string
		var imm int64
		var immOK bool
		if is64 {
			s0 = src64(0)
			imm, immOK = inlineableI64(v.Args[1])
		} else {
			s0 = src32(0)
			var imm32 int32
			imm32, immOK = inlineableI32(v.Args[1])
			imm = int64(imm32)
		}
		fmt.Fprintf(b, "\t%s %s, R1\n", movLoad, s0)
		if immOK {
			n := uint64(imm) & uint64(width-1)
			if left {
				n = uint64(width) - n
				n &= uint64(width - 1)
			}
			fmt.Fprintf(b, "\t%s $%d, R1, %s\n", ror, n, iTgt)
		} else {
			var s1 string
			if is64 {
				s1 = src64(1)
			} else {
				s1 = src32(1)
			}
			fmt.Fprintf(b, "\t%s %s, R2\n", movLoad, s1)
			if left {
				// rotl(x, n) == rotr(x, −n); the hardware masks the
				// count mod width, which also makes n == 0 exact.
				fmt.Fprintf(b, "\t%s R2, R2\n", neg)
			}
			fmt.Fprintf(b, "\t%s R2, R1, %s\n", ror, iTgt)
		}
		if is64 {
			storeI64()
		} else {
			storeI32()
		}
		return true, nil
	}

	switch name {
	// --- integer predicates / bit scans ---
	case "i32_eqz":
		fmt.Fprintf(b, "\tMOVWU %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tCMPW $0, R1\n")
		fmt.Fprintf(b, "\tCSET EQ, %s\n", iTgt)
		storeI32()
		return true, nil
	case "i64_eqz":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tCMP $0, R1\n")
		fmt.Fprintf(b, "\tCSET EQ, %s\n", iTgt)
		storeI32()
		return true, nil
	case "i32_clz":
		fmt.Fprintf(b, "\tMOVWU %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tCLZW R1, %s\n", iTgt)
		storeI32()
		return true, nil
	case "i32_ctz":
		fmt.Fprintf(b, "\tMOVWU %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tRBITW R1, R1\n")
		fmt.Fprintf(b, "\tCLZW R1, %s\n", iTgt)
		storeI32()
		return true, nil
	case "i64_clz":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tCLZ R1, %s\n", iTgt)
		storeI64()
		return true, nil
	case "i64_ctz":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tRBIT R1, R1\n")
		fmt.Fprintf(b, "\tCLZ R1, %s\n", iTgt)
		storeI64()
		return true, nil

	// --- rotates ---
	case "i32_rotl":
		return rotate(false, true)
	case "i32_rotr":
		return rotate(false, false)
	case "i64_rotl":
		return rotate(true, true)
	case "i64_rotr":
		return rotate(true, false)

	// --- division / remainder ---
	case "i32_div_s":
		return divRem(false, true, false)
	case "i32_div_u_s":
		return divRem(false, false, false)
	case "i32_rem_s":
		return divRem(false, true, true)
	case "i32_rem_u_s":
		return divRem(false, false, true)
	case "i64_div_s":
		return divRem(true, true, false)
	case "i64_div_u_s":
		return divRem(true, false, false)
	case "i64_rem_s":
		return divRem(true, true, true)
	case "i64_rem_u_s":
		return divRem(true, false, true)

	// --- width changes ---
	case "i32_wrap_i64":
		fmt.Fprintf(b, "\tMOVWU %s, %s\n", src64(0), iTgt)
		storeI32()
		return true, nil
	case "i64_extend_i32_s":
		fmt.Fprintf(b, "\tMOVW %s, %s\n", src32(0), iTgt)
		storeI64()
		return true, nil
	case "i64_extend_i32_u":
		fmt.Fprintf(b, "\tMOVWU %s, %s\n", src32(0), iTgt)
		storeI64()
		return true, nil
	case "i32_extend8_s":
		fmt.Fprintf(b, "\tMOVB %s, %s\n", src32(0), iTgt)
		storeI32()
		return true, nil
	case "i32_extend16_s":
		fmt.Fprintf(b, "\tMOVH %s, %s\n", src32(0), iTgt)
		storeI32()
		return true, nil
	case "i64_extend8_s":
		fmt.Fprintf(b, "\tMOVB %s, %s\n", src64(0), iTgt)
		storeI64()
		return true, nil
	case "i64_extend16_s":
		fmt.Fprintf(b, "\tMOVH %s, %s\n", src64(0), iTgt)
		storeI64()
		return true, nil
	case "i64_extend32_s":
		fmt.Fprintf(b, "\tMOVW %s, %s\n", src64(0), iTgt)
		storeI64()
		return true, nil

	// --- reinterpret ---
	case "i32_reinterpret_f32":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFMOVS F0, %s\n", iTgt)
		storeI32()
		return true, nil
	case "f32_reinterpret_i32":
		fmt.Fprintf(b, "\tMOVWU %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tFMOVS R1, %s\n", fTgt)
		storeF32()
		return true, nil
	case "i64_reinterpret_f64":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFMOVD F0, %s\n", iTgt)
		storeI64()
		return true, nil
	case "f64_reinterpret_i64":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tFMOVD R1, %s\n", fTgt)
		storeF64()
		return true, nil

	// --- float arithmetic ---
	case "f32_add":
		return floatBin("FADDS", false)
	case "f32_sub":
		return floatBin("FSUBS", false)
	case "f32_mul":
		return floatBin("FMULS", false)
	case "f32_div":
		return floatBin("FDIVS", false)
	case "f64_add":
		return floatBin("FADDD", true)
	case "f64_sub":
		return floatBin("FSUBD", true)
	case "f64_mul":
		return floatBin("FMULD", true)
	case "f64_div":
		return floatBin("FDIVD", true)
	case "f32_sqrt":
		return floatUn("FSQRTS", false)
	case "f64_sqrt":
		return floatUn("FSQRTD", true)
	case "f32_abs":
		return floatUn("FABSS", false)
	case "f64_abs":
		return floatUn("FABSD", true)
	case "f32_neg":
		return floatUn("FNEGS", false)
	case "f64_neg":
		return floatUn("FNEGD", true)
	case "f32_min":
		return floatBin3("FMINS", false)
	case "f32_max":
		return floatBin3("FMAXS", false)
	case "f64_min":
		return floatBin3("FMIND", true)
	case "f64_max":
		return floatBin3("FMAXD", true)

	// --- float compares (flags false on NaN except NE) ---
	case "f32_eq":
		return floatCmp("EQ", false)
	case "f32_ne":
		return floatCmp("NE", false)
	case "f32_lt":
		return floatCmp("MI", false)
	case "f32_le":
		return floatCmp("LS", false)
	case "f32_gt":
		return floatCmp("GT", false)
	case "f32_ge":
		return floatCmp("GE", false)
	case "f64_eq":
		return floatCmp("EQ", true)
	case "f64_ne":
		return floatCmp("NE", true)
	case "f64_lt":
		return floatCmp("MI", true)
	case "f64_le":
		return floatCmp("LS", true)
	case "f64_gt":
		return floatCmp("GT", true)
	case "f64_ge":
		return floatCmp("GE", true)

	// --- float rounding ---
	case "f32_ceil":
		return floatUn("FRINTPS", false)
	case "f32_floor":
		return floatUn("FRINTMS", false)
	case "f32_trunc":
		return floatUn("FRINTZS", false)
	case "f32_nearest":
		return floatUn("FRINTNS", false)
	case "f64_ceil":
		return floatUn("FRINTPD", true)
	case "f64_floor":
		return floatUn("FRINTMD", true)
	case "f64_trunc":
		return floatUn("FRINTZD", true)
	case "f64_nearest":
		return floatUn("FRINTND", true)

	// --- copysign (bit surgery through the GP side) ---
	case "f32_copysign":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFMOVS %s, F1\n", srcF(1))
		fmt.Fprintf(b, "\tFMOVS F0, R1\n")
		fmt.Fprintf(b, "\tFMOVS F1, R2\n")
		fmt.Fprintf(b, "\tBICW $2147483648, R1, R1\n")
		fmt.Fprintf(b, "\tANDW $2147483648, R2, R2\n")
		fmt.Fprintf(b, "\tORRW R2, R1, R1\n")
		fmt.Fprintf(b, "\tFMOVS R1, %s\n", fTgt)
		storeF32()
		return true, nil
	case "f64_copysign":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFMOVD %s, F1\n", srcF(1))
		fmt.Fprintf(b, "\tFMOVD F0, R1\n")
		fmt.Fprintf(b, "\tFMOVD F1, R2\n")
		fmt.Fprintf(b, "\tBIC $-9223372036854775808, R1, R1\n")
		fmt.Fprintf(b, "\tAND $-9223372036854775808, R2, R2\n")
		fmt.Fprintf(b, "\tORR R2, R1, R1\n")
		fmt.Fprintf(b, "\tFMOVD R1, %s\n", fTgt)
		storeF64()
		return true, nil

	// --- float width conversions ---
	case "f32_demote_f64":
		fmt.Fprintf(b, "\tFMOVD %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFCVTDS F0, %s\n", fTgt)
		storeF32()
		return true, nil
	case "f64_promote_f32":
		fmt.Fprintf(b, "\tFMOVS %s, F0\n", srcF(0))
		fmt.Fprintf(b, "\tFCVTSD F0, %s\n", fTgt)
		storeF64()
		return true, nil

	// --- int → float conversions (arm64 has native unsigned forms) ---
	case "f32_convert_i32_s":
		fmt.Fprintf(b, "\tMOVW %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tSCVTFWS R1, %s\n", fTgt)
		storeF32()
		return true, nil
	case "f64_convert_i32_s":
		fmt.Fprintf(b, "\tMOVW %s, R1\n", src32(0))
		fmt.Fprintf(b, "\tSCVTFWD R1, %s\n", fTgt)
		storeF64()
		return true, nil
	case "f32_convert_i64_s":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tSCVTFS R1, %s\n", fTgt)
		storeF32()
		return true, nil
	case "f64_convert_i64_s":
		fmt.Fprintf(b, "\tMOVD %s, R1\n", src64(0))
		fmt.Fprintf(b, "\tSCVTFD R1, %s\n", fTgt)
		storeF64()
		return true, nil
	case "f32_convert_i32_u":
		return convert("UCVTFWS", false, false)
	case "f64_convert_i32_u":
		return convert("UCVTFWD", false, true)
	case "f32_convert_i64_u":
		return convert("UCVTFS", true, false)
	case "f64_convert_i64_u":
		return convert("UCVTFD", true, true)

	// --- saturating float → int (single native instruction) ---
	case "i32_trunc_sat_f32_s":
		return truncSat("FCVTZSSW", false, false)
	case "i32_trunc_sat_f64_s":
		return truncSat("FCVTZSDW", true, false)
	case "i64_trunc_sat_f32_s":
		return truncSat("FCVTZSS", false, true)
	case "i64_trunc_sat_f64_s":
		return truncSat("FCVTZSD", true, true)
	case "i32_trunc_sat_f32_u":
		return truncSat("FCVTZUSW", false, false)
	case "i32_trunc_sat_f64_u":
		return truncSat("FCVTZUDW", true, false)
	case "i64_trunc_sat_f32_u":
		return truncSat("FCVTZUS", false, true)
	case "i64_trunc_sat_f64_u":
		return truncSat("FCVTZUD", true, true)
	}
	return false, nil
}
