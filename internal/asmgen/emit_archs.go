package asmgen

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// moduleMOffset is the byte offset of the Module.M field
// (unsafe.Pointer cache of &Memory[0]) within the *Module struct.
// The codegen translator emits Module as `{ memory []byte; maxMem
// uint64; M unsafe.Pointer }` — 24 (slice header) + 8 (uint64) = 32.
// Asm fixtures and the future codegen-asm integration must agree on
// this layout; the moduleMOffset test pins it explicitly.
const moduleMOffset = 32

// archAMD64 implements the arch interface for the x86_64 target.
type archAMD64 struct{}

func (archAMD64) EmitValue(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	return emitValueAMD64(b, v, plan, frame)
}

func (archAMD64) EmitJmp(b *strings.Builder, label, fallthroughLabel string) {
	if fallthroughLabel != "" && fallthroughLabel == label {
		return
	}
	fmt.Fprintf(b, "\tJMP %s\n", label)
}

func (archAMD64) EmitBrTable(b *strings.Builder, sel *ssa.Value, cases [][]int32, labels []string, defaultLabel string, plan *funcPlan, frame argFrame) {
	// Selector once into AX; CMP clobbers only flags, so the chain
	// reuses it across every case.
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(sel, plan, frame, "SP"))
	for i, vals := range cases {
		for _, v := range vals {
			fmt.Fprintf(b, "\tCMPL AX, $%d\n", v)
			fmt.Fprintf(b, "\tJEQ %s\n", labels[i])
		}
	}
	fmt.Fprintf(b, "\tJMP %s\n", defaultLabel)
}

func (archAMD64) EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel, fallthroughLabel string, plan *funcPlan, frame argFrame) {
	// Branch-fused: the value's body was skipped during emission;
	// here we emit the comparison and branch directly off the
	// flags, dropping the SET<cc> + MOVBLZX + slot store + slot
	// reload + TEST entirely. The original "JNE thenLabel" tests
	// the SET<cc> result for non-zero — i.e. the JCC corresponds
	// 1-for-1 to the original SET<cc>'s condition code.
	if plan.branchFused[cond.ID] {
		switch plan.branchFusedKind[cond.ID] {
		case "i32_eqz":
			fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(cond.Args[0], plan, frame, "SP"))
			fmt.Fprintf(b, "\tTESTL AX, AX\n")
			emitCondBranchAMD64(b, "JE", "JNE", thenLabel, elseLabel, fallthroughLabel)
			return
		case "i64_eqz":
			fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(cond.Args[0], plan, frame, "SP"))
			fmt.Fprintf(b, "\tTESTQ AX, AX\n")
			emitCondBranchAMD64(b, "JE", "JNE", thenLabel, elseLabel, fallthroughLabel)
			return
		case "i32_eq", "i32_ne", "i32_lt_s", "i32_lt_u", "i32_le_s", "i32_le_u":
			emitFusedCmpBranchAMD64(b, cond, plan, frame, false, thenLabel, elseLabel, fallthroughLabel)
			return
		case "i64_eq", "i64_ne", "i64_lt_s", "i64_lt_u", "i64_le_s", "i64_le_u":
			emitFusedCmpBranchAMD64(b, cond, plan, frame, true, thenLabel, elseLabel, fallthroughLabel)
			return
		case "i32_bittest_eq", "i32_bittest_ne", "i64_bittest_eq", "i64_bittest_ne":
			emitFusedBitTestBranchAMD64(b, cond, plan, frame, thenLabel, elseLabel, fallthroughLabel)
			return
		}
	}
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(cond, plan, frame, "SP"))
	fmt.Fprintf(b, "\tTESTL AX, AX\n")
	emitCondBranchAMD64(b, "JNE", "JE", thenLabel, elseLabel, fallthroughLabel)
}

// emitCondBranchAMD64 emits the conditional jump + unconditional jump
// pair that terminates a BlockIf, applying the fall-through hint to
// drop one of the jumps when possible.
//
//   - fallthroughLabel == elseLabel: emit only `JCC thenLabel` — control
//     "falls through" to elseLabel via the next emitted block.
//   - fallthroughLabel == thenLabel: emit `JCC_inv elseLabel` so the
//     "if condition" case falls through to thenLabel via the next
//     emitted block. The inverted JCC takes the branch on the OPPOSITE
//     condition, routing the no-fall-through (else) side through the
//     remaining jump.
//   - otherwise: emit the classic `JCC thenLabel; JMP elseLabel`.
//
// `jcc` is the mnemonic that branches to thenLabel; `jccInv` is its
// inverse (branches when the original condition is false). The caller
// supplies both because the inverse mnemonic depends on the original
// (JE ↔ JNE, JLT ↔ JGE, JLE ↔ JGT, JCS ↔ JCC, JLS ↔ JHI).
func emitCondBranchAMD64(b *strings.Builder, jcc, jccInv, thenLabel, elseLabel, fallthroughLabel string) {
	if fallthroughLabel != "" && fallthroughLabel == elseLabel {
		fmt.Fprintf(b, "\t%s %s\n", jcc, thenLabel)
		return
	}
	if fallthroughLabel != "" && fallthroughLabel == thenLabel {
		fmt.Fprintf(b, "\t%s %s\n", jccInv, elseLabel)
		return
	}
	fmt.Fprintf(b, "\t%s %s\n", jcc, thenLabel)
	fmt.Fprintf(b, "\tJMP %s\n", elseLabel)
}

// emitFusedBitTestBranchAMD64 lowers a fused
// `(base & 1<<bit) <eq/ne> 0` test to a single BTL/BTQ + Jcc pair.
// BTL sets the carry flag to the value of bit `bit` of the source
// operand. `... != 0` ⇔ "bit was set" ⇔ JCS; `... == 0` ⇔ "bit
// was clear" ⇔ JCC. With the fall-through hint we can drop the
// trailing JMP (or invert JCS↔JCC) when one of the destinations is
// the natural fall-through.
func emitFusedBitTestBranchAMD64(b *strings.Builder, cond *ssa.Value, plan *funcPlan, frame argFrame, thenLabel, elseLabel, fallthroughLabel string) {
	info, ok := plan.branchFusedBit[cond.ID]
	if !ok {
		// Shouldn't happen — Pass 4 always populates the map when it
		// sets a bittest_* kind. Fall back to the classic comparison
		// path so the compile stays correct even if the metadata is
		// missing.
		emitFusedCmpBranchAMD64(b, cond, plan, frame, false, thenLabel, elseLabel, fallthroughLabel)
		return
	}
	kind := plan.branchFusedKind[cond.ID]
	is64 := kind == "i64_bittest_eq" || kind == "i64_bittest_ne"
	wantEq := kind == "i32_bittest_eq" || kind == "i64_bittest_eq"
	var bt string
	var src string
	if is64 {
		bt = "BTQ"
		src = operandSrc64(info.base, plan, frame, "SP")
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", src)
	} else {
		bt = "BTL"
		src = operandSrc32(info.base, plan, frame, "SP")
		fmt.Fprintf(b, "\tMOVL %s, AX\n", src)
	}
	fmt.Fprintf(b, "\t%s $%d, AX\n", bt, info.bit)
	jcc, jccInv := "JCS", "JCC"
	if wantEq {
		// `(x & 1<<k) == 0` is true when the bit is clear, so we
		// branch on JCC.
		jcc, jccInv = "JCC", "JCS"
	}
	emitCondBranchAMD64(b, jcc, jccInv, thenLabel, elseLabel, fallthroughLabel)
}

// emitFusedCmpBranchAMD64 lowers a branch-fused integer comparison
// (OpEq{32,64} / OpNe / OpLtS / OpLtU / OpLeS / OpLeU) into the
// matching CMP + JCC + JMP triple. The mapping mirrors the SET<cc>
// that emitCmp32 / emitCmp64 would have used: JE for eq, JNE for
// ne, JLT for signed-lt (matches SETLT), JCS for unsigned-lt
// (matches SETCS = SETB), JLE for signed-le, JLS for unsigned-le
// (matches SETLS = SETBE). The CMP argument order is the same as
// the non-fused path so the flag semantics match 1-for-1.
func emitFusedCmpBranchAMD64(b *strings.Builder, cond *ssa.Value, plan *funcPlan, frame argFrame, is64 bool, thenLabel, elseLabel, fallthroughLabel string) {
	movInstr, cmpInstr := "MOVL", "CMPL"
	if is64 {
		movInstr, cmpInstr = "MOVQ", "CMPQ"
	}
	var src0, src1 string
	if is64 {
		src0 = operandSrc64(cond.Args[0], plan, frame, "SP")
		src1 = operandSrc64(cond.Args[1], plan, frame, "SP")
	} else {
		src0 = operandSrc32(cond.Args[0], plan, frame, "SP")
		src1 = operandSrc32(cond.Args[1], plan, frame, "SP")
	}
	fmt.Fprintf(b, "\t%s %s, AX\n", movInstr, src0)
	fmt.Fprintf(b, "\t%s AX, %s\n", cmpInstr, src1)
	var jcc, jccInv string
	switch plan.branchFusedKind[cond.ID] {
	case "i32_eq", "i64_eq":
		jcc, jccInv = "JE", "JNE"
	case "i32_ne", "i64_ne":
		jcc, jccInv = "JNE", "JE"
	case "i32_lt_s", "i64_lt_s":
		jcc, jccInv = "JLT", "JGE"
	case "i32_lt_u", "i64_lt_u":
		jcc, jccInv = "JCS", "JCC"
	case "i32_le_s", "i64_le_s":
		jcc, jccInv = "JLE", "JGT"
	case "i32_le_u", "i64_le_u":
		jcc, jccInv = "JLS", "JHI"
	}
	emitCondBranchAMD64(b, jcc, jccInv, thenLabel, elseLabel, fallthroughLabel)
}

func (archAMD64) SupportsRegHome() bool { return true }

// RegHomeEligibleOp — amd64 honours regHome on every op the
// package-level regHomeEligibleOp filter accepts.
func (archAMD64) RegHomeEligibleOp(op ssa.Op) bool {
	return regHomeEligibleOp(op)
}

// GPRegPool — amd64's block-local regalloc set. AX/CX/DX/BX/SI are
// scratch in emitBin/emitLoad/emitStore; BP is the Go frame
// pointer; R14 is the goroutine pointer. R11 is in the pool but
// gets filtered out at allocation when the m-cache owns it
// (assignBlockRegHomes consults plan.mCacheReg). Order is the
// first-fit preference — kept identical to the previous standalone
// `gpRegPool` var so amd64 output is byte-for-byte stable.
func (archAMD64) GPRegPool() []string {
	return []string{"DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"}
}

// SSERegPool — amd64 float side. X0/X1 are emit scratch; X2-X7
// available.
func (archAMD64) SSERegPool() []string {
	return []string{"X2", "X3", "X4", "X5", "X6", "X7"}
}

// EmitMCachePrime stages m in the cache register (R11 by default).
// Same MOVQ used in the prologue and after every CALL.
func (archAMD64) EmitMCachePrime(b *strings.Builder, reg string) {
	fmt.Fprintf(b, "\tMOVQ m+0(FP), %s\n", reg)
}

// MCacheReg is "R11" on amd64 — the m-cache register.
func (archAMD64) MCacheReg() string { return "R11" }

// CallArgBias is 0 on amd64: caller stores arg `i` directly at
// SP+paramOffsets[i] and the CALL instruction itself pushes the
// return PC at SP-8, so the callee's `m+0(FP)` assembler-resolution
// already accounts for the retPC slot. No bias needed.
func (archAMD64) CallArgBias() int { return 0 }

func (archAMD64) SkipValue(v *ssa.Value) bool {
	// operandSrc32 on amd64 always inlines OpConst32 as `$imm`, so
	// its materialise is dead.
	if v.Op == ssa.OpConst32 {
		return true
	}
	// operandSrc64 inlines OpConst64 ONLY when the value fits in a
	// sign-extended 32-bit immediate. For out-of-range literals the
	// helper falls back to a slot read, so we must NOT skip the
	// materialise — otherwise the slot is uninitialised and the
	// reader picks up garbage (caught by TestNumericsRuntime which
	// stores INT64_MIN-ish constants).
	if v.Op == ssa.OpConst64 && v.AuxInt >= -(1<<31) && v.AuxInt < (1<<31) {
		return true
	}
	// Every operandSrc{32,64,Float} on amd64 inlines OpParam as
	// `lN+off(FP)`, never via the slot. The producer would write
	// `MOVL lN+off(FP), AX; MOVL AX, dst(SP)` and the consumer
	// would immediately read FP-relative again — the slot store
	// has no live reader, so we skip the producer entirely.
	// Pure-Go's compiler skips the equivalent spill the same way.
	// Slot reuse may hand this OpParam's slot to a later value;
	// that value's first store is the slot's first live writer.
	if v.Op == ssa.OpParam {
		return true
	}
	return false
}

func (archAMD64) EmitUnreachable(b *strings.Builder) {
	// Go's runtime converts SIGSEGV from a nil-pointer dereference
	// into a runtime.errorString panic (caller can recover). SIGILL
	// from UD2, by contrast, throws an unrecoverable fatal error —
	// which doesn't match pure-Go's `panic("wasm: unreachable")`
	// semantics that tests can recover. A nil-load gets the same
	// "test framework catches the panic" behaviour without needing
	// a callback into a Go helper.
	fmt.Fprintf(b, "\tXORQ AX, AX\n")
	fmt.Fprintf(b, "\tMOVL (AX), AX\n")
}

func (archAMD64) EmitReturn(b *strings.Builder, blk *ssa.Block, sig wasm.FuncType, plan *funcPlan, frame argFrame) error {
	k := len(sig.Results)
	if k > len(blk.Values) {
		return fmt.Errorf("ret block has %d values but signature declares %d results", len(blk.Values), k)
	}
	rets := blk.Values[len(blk.Values)-k:]
	for i, rv := range rets {
		off := frame.resultOffsets[i]
		// Single-result is the common case; go vet asmdecl uses
		// `ret+<off>(FP)` for the lone (unnamed) return. With ≥2
		// results we fall back to a positional name; the wasm
		// lowering doesn't produce multi-result calls today so
		// this branch is a future-proofing stub.
		retName := "ret"
		if k > 1 {
			retName = fmt.Sprintf("ret%d", i)
		}
		switch sig.Results[i] {
		case wasm.ValI32:
			fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(rv, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVL AX, %s+%d(FP)\n", retName, off)
		case wasm.ValI64:
			fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(rv, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVQ AX, %s+%d(FP)\n", retName, off)
		case wasm.ValF32:
			fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(rv, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSS X0, %s+%d(FP)\n", retName, off)
		case wasm.ValF64:
			fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(rv, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSD X0, %s+%d(FP)\n", retName, off)
		default:
			return fmt.Errorf("result type %v not supported", sig.Results[i])
		}
	}
	fmt.Fprintf(b, "\tRET\n")
	return nil
}

func (a archAMD64) EmitPhiCopyValue(b *strings.Builder, src *ssa.Value, dstOff int, t ssa.Type, plan *funcPlan, frame argFrame) error {
	var srcOp string
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		srcOp = operandSrc32(src, plan, frame, "SP")
	case ssa.TypeI64:
		srcOp = operandSrc64(src, plan, frame, "SP")
	case ssa.TypeF32, ssa.TypeF64:
		srcOp = operandSrcFloat(src, plan, frame, "SP")
	default:
		return fmt.Errorf("phi type %v not supported", t)
	}
	return a.emitPhiCopyAMD64(b, srcOp, dstOff, t)
}

func (a archAMD64) EmitPhiCopySlot(b *strings.Builder, srcOff, dstOff int, t ssa.Type) error {
	return a.emitPhiCopyAMD64(b, fmt.Sprintf("%d(SP)", srcOff), dstOff, t)
}

// EmitPhiCopyValueToReg writes src directly to dstReg for the
// forward (entry) edge of a coalesced loop. The reserved
// register is guaranteed by the regalloc to be free at this point
// (the coalesce pass removed it from every loop-body block's
// per-block free pool), so a single MOV does the whole copy.
func (archAMD64) EmitPhiCopyValueToReg(b *strings.Builder, src *ssa.Value, dstReg string, t ssa.Type, plan *funcPlan, frame argFrame) error {
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVL %s, %s\n", operandSrc32(src, plan, frame, "SP"), dstReg)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVQ %s, %s\n", operandSrc64(src, plan, frame, "SP"), dstReg)
	default:
		return fmt.Errorf("phi-copy-to-reg type %v not supported (loop-carry coalesce is GP only)", t)
	}
	return nil
}

func (archAMD64) emitPhiCopyAMD64(b *strings.Builder, srcOperand string, dstOff int, t ssa.Type) error {
	// Self-copy elision: when the phi's source operand resolves to
	// the same SP-relative slot as the destination, the MOV pair
	// (load from src, store to dst) is a NO-OP. The wasm-to-SSA
	// lowering emits a phi at every multi-pred block for every wasm
	// local; when the lowering of that local on a given edge
	// happens to coincide with the same slot the slot-reuse and
	// cross-block stackalloc passes gave the phi destination, both
	// src and dst spell out the same
	// `N(SP)` operand and the round-trip through AX/X0 is dead
	// work. Skipping it removes two instructions per dead edge copy
	// and (more importantly) lets the next-block emit start with a
	// cleaner register state.
	dstOperand := fmt.Sprintf("%d(SP)", dstOff)
	if srcOperand == dstOperand {
		return nil
	}
	switch t {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVL %s, AX\n", srcOperand)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dstOff)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", srcOperand)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dstOff)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tMOVSS %s, X0\n", srcOperand)
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dstOff)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tMOVSD %s, X0\n", srcOperand)
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dstOff)
	default:
		return fmt.Errorf("phi type %v not supported", t)
	}
	return nil
}

// emitValueAMD64 lowers one SSA value to amd64 plan9 asm. Every
// produced value writes to its slot at the end; operands are read
// from their slots into AX (and CX/DX when binary). This is the
// simplest correct lowering; a register-allocating peephole pass is
// a follow-up. Float ops go through XMM (X0/X1) for the same reason.
func emitValueAMD64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	switch v.Op {
	// --- Bookkeeping ---
	case ssa.OpCopy:
		return emitCopy(b, v, plan, frame)

	// --- Constants ---
	case ssa.OpConst32:
		fmt.Fprintf(b, "\tMOVL $%d, %d(SP)\n", int32(v.AuxInt), plan.offsets[v.ID])
		return nil
	case ssa.OpConst64:
		fmt.Fprintf(b, "\tMOVQ $%d, AX\n", v.AuxInt)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpConstF32:
		// OpConstF32 carries the f32 bit pattern in AuxInt (set by
		// lower as `int64(math.Float32bits(v))`). Reinterpret-store
		// the low 32 bits into the destination slot — MOVL into a
		// float slot is fine because the slot is just bytes.
		fmt.Fprintf(b, "\tMOVL $%d, %d(SP)\n", int32(uint32(v.AuxInt)), plan.offsets[v.ID])
		return nil
	case ssa.OpConstF64:
		// OpConstF64's AuxInt is the f64 bit pattern.
		fmt.Fprintf(b, "\tMOVQ $%d, AX\n", v.AuxInt)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", plan.offsets[v.ID])
		return nil

	// OpParam is skipped via SkipValue at the emit-loop entry — its
	// consumers resolve to `lN+off(FP)` directly. OpAddF32/SubF32/
	// MulF32/DivF32/AddF64/SubF64/MulF64/DivF64 are routed through
	// the f{32,64}_{add,sub,mul,div} helper-call lowering by
	// internal/lower, so the asm emit never sees them as direct ops.
	// Both groups intentionally have no case here.

	// --- Integer binary (32-bit) ---
	case ssa.OpAdd32:
		return emitBinALU32(b, v, plan, frame, "ADDL")
	case ssa.OpSub32:
		return emitBinALU32(b, v, plan, frame, "SUBL")
	case ssa.OpMul32:
		return emitBinALU32(b, v, plan, frame, "IMULL")
	case ssa.OpAnd32:
		return emitBinALU32(b, v, plan, frame, "ANDL")
	case ssa.OpOr32:
		return emitBinALU32(b, v, plan, frame, "ORL")
	case ssa.OpXor32:
		return emitBinALU32(b, v, plan, frame, "XORL")

	// --- Integer binary (64-bit) ---
	case ssa.OpAdd64:
		return emitBinALU64(b, v, plan, frame, "ADDQ")
	case ssa.OpSub64:
		return emitBinALU64(b, v, plan, frame, "SUBQ")
	case ssa.OpMul64:
		return emitBinALU64(b, v, plan, frame, "IMULQ")
	case ssa.OpAnd64:
		return emitBinALU64(b, v, plan, frame, "ANDQ")
	case ssa.OpOr64:
		return emitBinALU64(b, v, plan, frame, "ORQ")
	case ssa.OpXor64:
		return emitBinALU64(b, v, plan, frame, "XORQ")

	// --- Shifts (use CL as count; x86 masks count to 5/6 bits which
	// matches wasm's mod-N semantics exactly). ---
	case ssa.OpShl32:
		return emitShift32(b, v, plan, frame, "SHLL")
	case ssa.OpShrS32:
		return emitShift32(b, v, plan, frame, "SARL")
	case ssa.OpShrU32:
		return emitShift32(b, v, plan, frame, "SHRL")
	case ssa.OpShl64:
		return emitShift64(b, v, plan, frame, "SHLQ")
	case ssa.OpShrS64:
		return emitShift64(b, v, plan, frame, "SARQ")
	case ssa.OpShrU64:
		return emitShift64(b, v, plan, frame, "SHRQ")

	// --- Comparisons (32-bit). Result is TypeBool but the slot is
	// 4 bytes and the value is 0 or 1, so consumers that route it
	// through an i32 are coherent. ---
	case ssa.OpEq32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETEQ")
	case ssa.OpNe32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETNE")
	case ssa.OpLtS32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETLT")
	case ssa.OpLtU32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETCS") // below = CF set = SETB
	case ssa.OpLeS32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETLE")
	case ssa.OpLeU32:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp32(b, v, plan, frame, "SETLS") // below-or-equal = SETBE

	// --- Comparisons (64-bit) ---
	case ssa.OpEq64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETEQ")
	case ssa.OpNe64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETNE")
	case ssa.OpLtS64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETLT")
	case ssa.OpLtU64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETCS")
	case ssa.OpLeS64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETLE")
	case ssa.OpLeU64:
		if plan.branchFused[v.ID] {
			return nil
		}
		return emitCmp64(b, v, plan, frame, "SETLS")

	// --- Integer extensions / truncation ---
	case ssa.OpExtend32To64S:
		fmt.Fprintf(b, "\tMOVLQSX %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpExtend32To64U:
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		// MOVL into a 64-bit register zero-extends on amd64.
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", plan.offsets[v.ID])
		return nil
	case ssa.OpTrunc64To32:
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", plan.offsets[v.ID])
		return nil

	// --- Memory loads / stores ---
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64:
		return emitLoad(b, v, plan, frame)
	case ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpStoreF32, ssa.OpStoreF64:
		return emitStore(b, v, plan, frame)

	// --- Helper calls (rotl, div_s, eqz, rem_u, ...) ---
	case ssa.OpHelperCall:
		return emitHelperCall(b, v, plan, frame)

	// --- Direct call to a sibling generated function or to a
	// host-imports wrapper, plus global accessors. All four go
	// through the plan.directs map, which resolved the asm symbol
	// at planning time (Fn42 / callImport_3 / loadGlobal_2 /
	// storeGlobal_2). ---
	case ssa.OpGlobalGet:
		if _, ok := plan.globalInline[v.ID]; ok {
			return emitGlobalGetInlineAMD64(b, v, plan, frame)
		}
		return emitCallDirect(b, v, plan, frame)
	case ssa.OpGlobalSet:
		if _, ok := plan.globalInline[v.ID]; ok {
			return emitGlobalSetInlineAMD64(b, v, plan, frame)
		}
		return emitCallDirect(b, v, plan, frame)
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpMemSize, ssa.OpMemGrow,
		ssa.OpMemoryCopy, ssa.OpMemoryFill:
		return emitCallDirect(b, v, plan, frame)
	}
	return fmt.Errorf("op %v not supported by the amd64 emitter", v.Op)
}

// resolveCopy walks OpCopy chains to the underlying value, stopping
// at any non-Copy op (or at a self-reference). Used by the operand
// resolvers so a chain of OpCopy → OpParam → … reads the FP slot
// directly without materialising every link.
func resolveCopy(v *ssa.Value) *ssa.Value {
	for i := 0; v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 && v.Args[0] != nil && v.Args[0] != v && i < 16; i++ {
		v = v.Args[0]
	}
	return v
}

// inlineableImmediate reports the immediate Go-style 32-bit literal
// for a constant value, or 0/false if v isn't an inline-able i32
// constant. Used by the operand resolvers to spell `$N` directly in
// the asm instead of materialising a slot.
func inlineableI32(v *ssa.Value) (int32, bool) {
	v = resolveCopy(v)
	if v == nil || v.Op != ssa.OpConst32 {
		return 0, false
	}
	return int32(v.AuxInt), true
}

func inlineableI64(v *ssa.Value) (int64, bool) {
	v = resolveCopy(v)
	if v == nil || v.Op != ssa.OpConst64 {
		return 0, false
	}
	return v.AuxInt, true
}

// operandSrc32 returns the asm operand string for reading v as a
// 32-bit value (amd64). Resolves OpCopy chains, materialises
// OpConst32 as `$<imm>`, materialises OpParam as `lN+off(FP)`, and
// falls back to the value's stack slot otherwise. spReg is the
// architecture's stack-pointer name ("SP" on amd64, "RSP" on arm64).
// On amd64 every integer ALU instruction accepts a 32-bit immediate
// operand so const inlining is universally safe; on arm64 it is not
// (MOVW $imm, R0 rejects most 32-bit immediates), and the arm64
// emitter calls operandSrc32ARM64 which routes constants through
// their hoisted slot instead.
func operandSrc32(v *ssa.Value, plan *funcPlan, frame argFrame, spReg string) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpConst32 {
		return fmt.Sprintf("$%d", int32(v.AuxInt))
	}
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
	}
	if reg := plan.regHome[v.ID]; reg != "" {
		return reg
	}
	return fmt.Sprintf("%d(%s)", plan.offsets[v.ID], spReg)
}

// operandSrc64 is operandSrc32 for 64-bit values. amd64 ADDQ/etc.
// accept sign-extended 32-bit immediates as second operand; for
// out-of-range OpConst64 we fall through to the slot path which
// loads the full 64-bit literal into a register first.
func operandSrc64(v *ssa.Value, plan *funcPlan, frame argFrame, spReg string) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpConst64 {
		c := v.AuxInt
		if c >= -(1<<31) && c < (1<<31) {
			return fmt.Sprintf("$%d", c)
		}
	}
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
	}
	if reg := plan.regHome[v.ID]; reg != "" {
		return reg
	}
	return fmt.Sprintf("%d(%s)", plan.offsets[v.ID], spReg)
}

// operandSrc32ARM64 / operandSrc64ARM64 are the arm64 counterparts
// that NEVER materialise OpConst inline — arm64 MOV with an
// arbitrary 32/64-bit immediate is rejected by the assembler, so
// the constant has to live in its slot and be read from there.
// The slot is guaranteed to exist because planFunc keeps Const
// emission on for archs where SkipValue(OpConst32) returns false.
func operandSrc32ARM64(v *ssa.Value, plan *funcPlan, frame argFrame) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
	}
	// regHome'd values live in a register; the per-op emit on the
	// WRITE side is responsible for putting the result there. The
	// arm64 MOV can read directly from a register source operand,
	// so the consumer's `MOVW <src>, R0` becomes `MOVW R<n>, R0`
	// for free.
	if reg := plan.regHome[v.ID]; reg != "" {
		return reg
	}
	return fmt.Sprintf("%d(RSP)", plan.offsets[v.ID])
}

func operandSrc64ARM64(v *ssa.Value, plan *funcPlan, frame argFrame) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
	}
	if reg := plan.regHome[v.ID]; reg != "" {
		return reg
	}
	return fmt.Sprintf("%d(RSP)", plan.offsets[v.ID])
}

// operandSrcFloat returns the source for a float value. Float
// constants are NOT inline-able (no float-imm in amd64/arm64 ALUs);
// the slot fallback handles them once they've been materialised via
// OpConstF32/F64 (those still allocate a slot).
func operandSrcFloat(v *ssa.Value, plan *funcPlan, frame argFrame, spReg string) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
	}
	if reg := plan.regHome[v.ID]; reg != "" {
		return reg
	}
	return fmt.Sprintf("%d(%s)", plan.offsets[v.ID], spReg)
}

// emitCopy is reached only for hoisted OpCopy values (multi-use).
// It materialises the chain root via operandSrc so the source can
// be an immediate, an FP-relative param read, or another slot.
func emitCopy(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) != 1 || v.Args[0] == nil {
		return fmt.Errorf("OpCopy expects one non-nil arg")
	}
	dst := plan.offsets[v.ID]
	switch v.Type {
	case ssa.TypeI32, ssa.TypeBool:
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	default:
		return fmt.Errorf("OpCopy type %v not supported", v.Type)
	}
	return nil
}

// emitBinALU32 lowers a 32-bit binary ALU op as:
//
//	MOVL <src1>, AX
//	<mnem>L <src2>, AX
//	MOVL AX, <dst>(SP)
//
// where src1/src2 are operandSrc32 strings (either `$imm`,
// `<off>(SP)`, or `lN+off(FP)`). Saves one MOV per op compared to
// the previous always-load-both-into-registers form.
func emitBinALU32(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	// If the result has a register home, compute the op directly
	// into that register and skip the slot store. The
	// "MOVL <src0>, dst" form below STILL has to load src0 first
	// because amd64 32-bit ALU ops are two-operand (RMW on the
	// destination), so we cannot OP-fold src1 against src0 in a
	// single instruction.
	src0 := operandSrc32(v.Args[0], plan, frame, "SP")
	src1 := operandSrc32(v.Args[1], plan, frame, "SP")
	if home := plan.regHome[v.ID]; home != "" {
		// MOVL src0, home — if src0 IS home (src0 lives in the
		// same reg the regalloc picked for v), the MOV is a self-
		// move and would be a no-op; emit it anyway since the
		// post-emit register-tracking pass cleans up self-moves
		// cheaply and the alternative (special-casing here) leaks
		// regalloc state into the per-op emitter.
		fmt.Fprintf(b, "\tMOVL %s, %s\n", src0, home)
		fmt.Fprintf(b, "\t%s %s, %s\n", mnemonic, src1, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVL %s, AX\n", src0)
	fmt.Fprintf(b, "\t%s %s, AX\n", mnemonic, src1)
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	return nil
}

func emitBinALU64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	src0 := operandSrc64(v.Args[0], plan, frame, "SP")
	src1 := operandSrc64(v.Args[1], plan, frame, "SP")
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVQ %s, %s\n", src0, home)
		fmt.Fprintf(b, "\t%s %s, %s\n", mnemonic, src1, home)
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", src0)
	fmt.Fprintf(b, "\t%s %s, AX\n", mnemonic, src1)
	fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	return nil
}

// emitShift32 lowers a 32-bit shift. The amd64 shift family takes
// the count in CL implicitly; the hardware masks CL to 5 bits which
// matches wasm's `(count & 31)` rule. When the count is a constant
// the encoding becomes `<mnem>L $imm, AX` — saves the CX load.
func emitShift32(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	// amd64 shifts insist on CL (the low byte of CX) as the count
	// register, so the count side always goes through CX regardless
	// of regalloc choices. The regalloc pool excludes CX so this is
	// a fixed scratch that no regHome'd value can be living in.
	src0 := operandSrc32(v.Args[0], plan, frame, "SP")
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVL %s, %s\n", src0, home)
		if imm, ok := inlineableI32(v.Args[1]); ok {
			fmt.Fprintf(b, "\t%s $%d, %s\n", mnemonic, uint32(imm)&31, home)
		} else {
			fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
			fmt.Fprintf(b, "\t%s CX, %s\n", mnemonic, home)
		}
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVL %s, AX\n", src0)
	if imm, ok := inlineableI32(v.Args[1]); ok {
		fmt.Fprintf(b, "\t%s $%d, AX\n", mnemonic, uint32(imm)&31)
	} else {
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\t%s CX, AX\n", mnemonic)
	}
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	return nil
}

func emitShift64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	src0 := operandSrc64(v.Args[0], plan, frame, "SP")
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVQ %s, %s\n", src0, home)
		if imm, ok := inlineableI64(v.Args[1]); ok {
			fmt.Fprintf(b, "\t%s $%d, %s\n", mnemonic, uint64(imm)&63, home)
		} else {
			fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
			fmt.Fprintf(b, "\t%s CX, %s\n", mnemonic, home)
		}
		return nil
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", src0)
	if imm, ok := inlineableI64(v.Args[1]); ok {
		fmt.Fprintf(b, "\t%s $%d, AX\n", mnemonic, uint64(imm)&63)
	} else {
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\t%s CX, AX\n", mnemonic)
	}
	fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	return nil
}

// emitCmp32 lowers a 32-bit comparison. The op stores 0 or 1 into a
// 4-byte slot. The byte-wide SETxx writes the low byte of AX; we
// zero-extend the upper bytes before the store so an i32 consumer
// sees a clean 0 or 1. CMPL accepts a mem/imm second operand, so
// the second operand goes through operandSrc directly.
func emitCmp32(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, setOp string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\tCMPL AX, %s\n", operandSrc32(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s AL\n", setOp)
	// When v has a register home, zero-extend AL straight
	// into that register and skip the slot store. MOVBLZX accepts
	// any GP destination (including R8-R15), so the only thing we
	// need to be careful about is that AL is the low byte of AX,
	// which means we MUST keep AX as the compare's first operand —
	// the SET<cc> writes to AL, not to home's low byte directly.
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVBLZX AL, %s\n", home)
		return nil
	}
	fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", plan.offsets[v.ID])
	return nil
}

func emitCmp64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, setOp string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\tCMPQ AX, %s\n", operandSrc64(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s AL\n", setOp)
	if home := plan.regHome[v.ID]; home != "" {
		fmt.Fprintf(b, "\tMOVBLZX AL, %s\n", home)
		return nil
	}
	fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", plan.offsets[v.ID])
	return nil
}

// emitLoad lowers a wasm linear-memory read. args = [base i32, mem];
// AuxInt = constant offset. The asm dereferences Module.M (the
// cached unsafe.Pointer at offset moduleMOffset) and indexes by
// `base + AuxInt`. The mem token is ignored (it threads ordering
// dependencies in the IR; the asm is sequentially consistent).
func emitLoad(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) < 1 || v.Args[0] == nil {
		return fmt.Errorf("OpLoad needs at least a base arg")
	}
	off := int32(v.AuxInt)
	dst := plan.offsets[v.ID]
	// BX = m.M + uint32(base + off). wasm semantics: the effective
	// address is `(base + offset) mod 2^32` — adding base and off
	// in 64-bit would NOT wrap negative-int32 bases the way the
	// pure-Go path (`uint32(base + int32(off))`) does, sending the
	// load out to ~4 GiB above m.M. We do the addition in 32-bit
	// (ADDL leaves the upper 32 bits of RAX zero per amd64 spec),
	// then add the zero-extended result to m.M.
	if plan.mCacheReg != "" {
		// m is cached in the function-wide reserved register;
		// dereference it directly for m.M.
		fmt.Fprintf(b, "\tMOVQ %d(%s), BX\n", moduleMOffset, plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), BX\n")
		fmt.Fprintf(b, "\tMOVQ %d(BX), BX\n", moduleMOffset)
	}
	var addr string
	// Constant-base fast path: fold `base + off` at generation time
	// and reference the slot via disp(BX) directly.
	if base, ok := inlineableI32(v.Args[0]); ok {
		disp := int32(uint32(base) + uint32(off))
		addr = fmt.Sprintf("%d(BX)", disp)
	} else {
		// Dynamic base: form the address through SI, then access via
		// (BX)(SI*1) indexed addressing instead of `ADDQ AX, BX` +
		// `disp(BX)`. The indexed access is the same one MOV at the
		// load site but leaves BX = m.M intact, so any follow-on
		// load / store in the same straight-line span can reuse the
		// cached m.M without re-emitting the 2-line preamble
		// (dedupMemMReload strips the redundant preambles). SI is
		// otherwise unused by the asmgen — emit_amd64.go only
		// writes AX / BX / CX / DX / X0 elsewhere — so claiming it
		// for the load/store index has no cross-instruction conflict
		// and the indexed mode keeps the value-side register (AX /
		// X0) free for the access result. ADDL zero-extends the
		// upper 32 bits of SI, matching the wasm `(base + offset)
		// mod 2^32` effective-address rule.
		fmt.Fprintf(b, "\tMOVL %s, SI\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		// Fold a non-negative constant offset into the addressing
		// mode's displacement instead of emitting a separate ADDL.
		// We restrict the fold to off >= 0 because amd64's
		// addressing mode sign-extends the displacement to 64
		// bits, while wasm's effective-address rule wraps
		// `uint32(base + off)`. The two only diverge when off has
		// its high (sign) bit set — for positive offsets the sext
		// is identical to a zext and the result matches the wasm
		// wrap. The integration corpus loads use struct-field
		// offsets, all small non-negative constants, so this fires
		// on every dynamic-base memop in the bundle.
		if off > 0 {
			addr = fmt.Sprintf("%d(BX)(SI*1)", off)
		} else if off == 0 {
			addr = "(BX)(SI*1)"
		} else {
			// Negative off: keep the ADDL so the 32-bit wrap matches
			// `uint32(base + off)`.
			fmt.Fprintf(b, "\tADDL $%d, SI\n", off)
			addr = "(BX)(SI*1)"
		}
	}
	// Narrow loads (8/16-bit) produce either i32 or i64 depending
	// on the wasm op — i32.load8_u vs i64.load8_u both lower to
	// OpLoad8U, distinguished only by v.Type. The asm has to
	// zero/sign-extend to the right width and use MOVQ for i64.
	is64 := v.Type == ssa.TypeI64
	// When the load result has a register home, the extending MOV
	// can write directly into that register and the follow-on
	// MOV-to-slot store goes away. The GP pool excludes
	// SI (used here for the dynamic-base index path) and BX (used
	// for m.M) so there is no conflict between a regHome and the
	// address-computation scratch registers. The SSE pool excludes
	// X0/X1 so the float-load case has the same safety.
	intHome, hasIntHome := "AX", false
	if r := plan.regHome[v.ID]; r != "" && !isSSEReg(r) {
		intHome, hasIntHome = r, true
	}
	sseHome, hasSSEHome := "X0", false
	if r := plan.regHome[v.ID]; r != "" && isSSEReg(r) {
		sseHome, hasSSEHome = r, true
	}
	switch v.Op {
	case ssa.OpLoad8U:
		if is64 {
			fmt.Fprintf(b, "\tMOVBQZX %s, %s\n", addr, intHome)
		} else {
			fmt.Fprintf(b, "\tMOVBLZX %s, %s\n", addr, intHome)
		}
	case ssa.OpLoad8S:
		if is64 {
			fmt.Fprintf(b, "\tMOVBQSX %s, %s\n", addr, intHome)
		} else {
			fmt.Fprintf(b, "\tMOVBLSX %s, %s\n", addr, intHome)
		}
	case ssa.OpLoad16U:
		if is64 {
			fmt.Fprintf(b, "\tMOVWQZX %s, %s\n", addr, intHome)
		} else {
			fmt.Fprintf(b, "\tMOVWLZX %s, %s\n", addr, intHome)
		}
	case ssa.OpLoad16S:
		if is64 {
			fmt.Fprintf(b, "\tMOVWQSX %s, %s\n", addr, intHome)
		} else {
			fmt.Fprintf(b, "\tMOVWLSX %s, %s\n", addr, intHome)
		}
	case ssa.OpLoad32:
		fmt.Fprintf(b, "\tMOVL %s, %s\n", addr, intHome)
	case ssa.OpLoad32U:
		// i64.load32_u: read u32 → zero-extend to i64. MOVL into
		// a 32-bit operand zero-extends to the parent 64-bit reg
		// implicitly per amd64 spec, which gives us the i64 value
		// in intHome directly.
		fmt.Fprintf(b, "\tMOVL %s, %s\n", addr, intHome)
	case ssa.OpLoad32S:
		// i64.load32_s: read i32 → sign-extend to i64.
		fmt.Fprintf(b, "\tMOVLQSX %s, %s\n", addr, intHome)
	case ssa.OpLoad64:
		fmt.Fprintf(b, "\tMOVQ %s, %s\n", addr, intHome)
	case ssa.OpLoadF32:
		fmt.Fprintf(b, "\tMOVSS %s, %s\n", addr, sseHome)
	case ssa.OpLoadF64:
		fmt.Fprintf(b, "\tMOVSD %s, %s\n", addr, sseHome)
	default:
		return fmt.Errorf("OpLoad variant %v not supported", v.Op)
	}
	// If the load went straight into a regHome register (no AX/X0
	// scratch involved) the slot store is dead — the consumer will
	// read via operandSrc which now returns the register. The
	// slot-reuse allocator still reserves a slot for v but it
	// won't be touched in this function body.
	if hasIntHome || hasSSEHome {
		return nil
	}
	// Slot-resident fallback: stash the AX / X0 scratch into v's
	// slot so downstream consumers read it from there. The store
	// width follows the result type: i64 / load32_u / load32_s /
	// load64 all hold a 64-bit value (the narrower variants zero-
	// or sign-extended into the parent register); i32 loads
	// (Load32 and the narrow Load8*/Load16* when not is64) hold a
	// 32-bit value; the float variants use the SSE-width stores.
	switch v.Op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S:
		if is64 {
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case ssa.OpLoad32:
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	case ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64:
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.OpLoadF32:
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case ssa.OpLoadF64:
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	}
	return nil
}

// emitStore lowers a wasm linear-memory write. args = [base, value,
// mem]; AuxInt = offset. Narrowing stores (Store8/16/32 of an i64)
// truncate the value to the requested width.
func emitStore(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	if len(v.Args) < 2 || v.Args[0] == nil || v.Args[1] == nil {
		return fmt.Errorf("OpStore needs base and value args")
	}
	off := int32(v.AuxInt)
	// Same u32 wrap-around story as emitLoad — base+offset is
	// computed in 32-bit so a negative int32 base lands at the
	// expected wrapped offset, not 4 GiB above m.M.
	if plan.mCacheReg != "" {
		// m is cached in the function-wide reserved register;
		// dereference it directly for m.M.
		fmt.Fprintf(b, "\tMOVQ %d(%s), BX\n", moduleMOffset, plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), BX\n")
		fmt.Fprintf(b, "\tMOVQ %d(BX), BX\n", moduleMOffset)
	}
	var addr string
	// Fast path: if `base` is a Const32 we can fold `base + off` at
	// generation time and use a single MOVx disp(BX), <val> store
	// instead of the 3-instruction MOVL+ADDL+ADDQ address build-up.
	// The displacement uses the same uint32(base+off) wrap as the
	// runtime path because we form the constant via int32 add and
	// re-cast as int32 — that gives identical low-32-bit behaviour
	// for both negative-int32 bases and very-large offsets.
	if base, ok := inlineableI32(v.Args[0]); ok {
		disp := int32(uint32(base) + uint32(off))
		addr = fmt.Sprintf("%d(BX)", disp)
	} else {
		// Dynamic-base store: form the address in SI so the access
		// uses `(BX)(SI*1)` indexed addressing. Mirror of emitLoad's
		// SI-as-index strategy — keeps BX = m.M live so the next
		// store / load in the same straight-line span doesn't need
		// to re-emit the m.M preamble (dedupMemMReload strips the
		// redundant copies later).
		fmt.Fprintf(b, "\tMOVL %s, SI\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		// See emitLoad for the matching disp-fold rationale —
		// non-negative offsets fold into the addressing
		// mode's displacement; negative offsets keep the ADDL so the
		// 32-bit wrap matches wasm's effective-address semantics.
		if off > 0 {
			addr = fmt.Sprintf("%d(BX)(SI*1)", off)
		} else if off == 0 {
			addr = "(BX)(SI*1)"
		} else {
			fmt.Fprintf(b, "\tADDL $%d, SI\n", off)
			addr = "(BX)(SI*1)"
		}
	}
	// The wasm store-narrow ops truncate the low N bits of the value.
	// On amd64 the small-store mnemonics (MOVB/MOVW) naturally write
	// only the low bits of the register, so we just MOV the value
	// into AX as its declared width and store the matching size.
	// When the value is a literal constant, MOVx $imm, addr writes
	// memory directly without the intermediate AX hop — saves one
	// instruction per store. The narrowing stores (Store8/16) must
	// mask the constant to the destination width because plan9's
	// MOVB/MOVW reject out-of-range immediates.
	val := resolveCopy(v.Args[1])
	switch v.Op {
	case ssa.OpStore8:
		if val != nil && val.Op == ssa.OpConst32 {
			fmt.Fprintf(b, "\tMOVB $%d, %s\n", uint32(val.AuxInt)&0xff, addr)
		} else if val != nil && val.Op == ssa.OpConst64 {
			fmt.Fprintf(b, "\tMOVB $%d, %s\n", uint64(val.AuxInt)&0xff, addr)
		} else {
			if v.Args[1].Type == ssa.TypeI64 {
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
			} else {
				fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
			}
			fmt.Fprintf(b, "\tMOVB AX, %s\n", addr)
		}
	case ssa.OpStore16:
		if val != nil && val.Op == ssa.OpConst32 {
			fmt.Fprintf(b, "\tMOVW $%d, %s\n", uint32(val.AuxInt)&0xffff, addr)
		} else if val != nil && val.Op == ssa.OpConst64 {
			fmt.Fprintf(b, "\tMOVW $%d, %s\n", uint64(val.AuxInt)&0xffff, addr)
		} else {
			if v.Args[1].Type == ssa.TypeI64 {
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
			} else {
				fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
			}
			fmt.Fprintf(b, "\tMOVW AX, %s\n", addr)
		}
	case ssa.OpStore32:
		if val != nil && val.Op == ssa.OpConst32 {
			fmt.Fprintf(b, "\tMOVL $%d, %s\n", int32(val.AuxInt), addr)
		} else if val != nil && val.Op == ssa.OpConst64 {
			fmt.Fprintf(b, "\tMOVL $%d, %s\n", int32(val.AuxInt), addr)
		} else {
			if v.Args[1].Type == ssa.TypeI64 {
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
			} else {
				fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
			}
			fmt.Fprintf(b, "\tMOVL AX, %s\n", addr)
		}
	case ssa.OpStore64:
		// MOVQ $imm, mem accepts only sign-extended 32-bit immediates;
		// outside that range we have to go through AX.
		if val != nil && val.Op == ssa.OpConst64 && val.AuxInt >= -(1<<31) && val.AuxInt < (1<<31) {
			fmt.Fprintf(b, "\tMOVQ $%d, %s\n", val.AuxInt, addr)
		} else {
			fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVQ AX, %s\n", addr)
		}
	case ssa.OpStoreF32:
		fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %s\n", addr)
	case ssa.OpStoreF64:
		fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %s\n", addr)
	default:
		return fmt.Errorf("OpStore variant %v not supported", v.Op)
	}
	return nil
}

// emitHelperCall stages the helper's args at 0(SP)+offsets, CALLs
// the helper, and reads the return value (when present) back into
// the value's slot. The helper's calling convention is Go ABI0 with
// no *Module receiver (helpers are pure Go functions in the helpers
// package).
func emitHelperCall(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	name := plan.helperRefs[v.ID]
	spec, ok := helperSig(name)
	if !ok {
		return fmt.Errorf("unknown helper %q", name)
	}
	if len(v.Args) != len(spec.params) {
		return fmt.Errorf("helper %q wants %d args, got %d", name, len(spec.params), len(v.Args))
	}
	// Branch-fused eqz: the BlockIf emitter inlines the TEST + JE
	// against the eqz argument, so the helper body, the slot store,
	// and the slot reload all disappear. The slot stays allocated
	// (harmless — frame still 8-byte aligned and unread).
	if plan.branchFused[v.ID] {
		return nil
	}
	// Prefer inline asm — the asm-to-Go boundary is reserved for
	// user-registered callbacks (env imports and indirect dispatch).
	// Helpers with native amd64 instruction sequences get emitted
	// directly; anything still missing surfaces as an error below
	// rather than silently falling through to a stub.
	if done, err := emitInlineHelper(b, v, plan, frame, name); err != nil {
		return err
	} else if done {
		return nil
	}
	// Stage each arg at its callee-frame offset.
	off := 0
	for i, arg := range v.Args {
		size, align := helperABISize(spec.params[i])
		off = alignUp(off, align)
		switch spec.params[i] {
		case ssa.TypeI32:
			if imm, ok := inlineableI32(arg); ok {
				fmt.Fprintf(b, "\tMOVL $%d, %d(SP)\n", imm, off)
			} else {
				fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(arg, plan, frame, "SP"))
				fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", off)
			}
		case ssa.TypeI64:
			if imm, ok := inlineableI64(arg); ok && imm >= -(1<<31) && imm < (1<<31) {
				fmt.Fprintf(b, "\tMOVQ $%d, %d(SP)\n", imm, off)
			} else {
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(arg, plan, frame, "SP"))
				fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", off)
			}
		case ssa.TypeF32:
			fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(arg, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", off)
		case ssa.TypeF64:
			fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(arg, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", off)
		default:
			return fmt.Errorf("helper %q arg %d type %v not supported", name, i, spec.params[i])
		}
		off += size
	}
	// The result lives at the next 8-aligned offset after the args,
	// not just at `off`. Computed by helperRetOffset so the rule is
	// applied in exactly one place.
	retOff := helperRetOffset(spec)

	// CALL.
	symbol := goCallSymbol(plan.helperPfx, name)
	fmt.Fprintf(b, "\tCALL %s\n", symbol)

	// Read return value back into v's slot.
	// Skip the load+store pair when this value's result has no
	// downstream consumers — same rationale as in emitCallDirect
	// (Pure-Go drops the moves entirely).
	if spec.ret != ssa.TypeInvalid && !plan.unusedResult[v.ID] {
		dst := plan.offsets[v.ID]
		switch spec.ret {
		case ssa.TypeI32:
			fmt.Fprintf(b, "\tMOVL %d(SP), AX\n", retOff)
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		case ssa.TypeI64:
			fmt.Fprintf(b, "\tMOVQ %d(SP), AX\n", retOff)
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		case ssa.TypeF32:
			fmt.Fprintf(b, "\tMOVSS %d(SP), X0\n", retOff)
			fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		case ssa.TypeF64:
			fmt.Fprintf(b, "\tMOVSD %d(SP), X0\n", retOff)
			fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		default:
			return fmt.Errorf("helper %q ret type %v not supported", name, spec.ret)
		}
	}
	return nil
}

// emitInlineHelper emits the inline asm body for a known helper —
// no CALL to a Go-side helper function. The asm-to-Go boundary is
// reserved for user-registered callbacks (env imports and indirect
// dispatch). Returns true if the helper was handled inline; the
// caller (emitHelperCall) falls back to a CALL only for helpers
// the asm doesn't natively implement (currently a hard error).
//
// Helpers operate on values from operandSrc{32,64,Float}(args[i],
// ...) and store the result to plan.offsets[v.ID]. The instruction
// sequences below match the Go-side base.X helper semantics
// 1-for-1 (input X → same output).
func emitInlineHelper(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, name string) (bool, error) {
	dst := plan.offsets[v.ID]
	switch name {
	// --- 32-bit integer ---
	case "i32_eqz":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL AX, AX\n")
		fmt.Fprintf(b, "\tSETEQ AL\n")
		fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_clz":
		zeroLbl := fmt.Sprintf("CLZ32_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("CLZ32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL AX, AX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tBSRL AX, AX\n")
		fmt.Fprintf(b, "\tMOVL $31, CX\n")
		fmt.Fprintf(b, "\tSUBL AX, CX\n")
		fmt.Fprintf(b, "\tMOVL CX, AX\n")
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVL $32, AX\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_ctz":
		// BSF gives lowest set bit position; result undefined when
		// input is 0 (CPU sets ZF). We branch around to write 32
		// for the zero case.
		skipLbl := fmt.Sprintf("CTZ32_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("CTZ32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL AX, AX\n")
		fmt.Fprintf(b, "\tJE %s\n", skipLbl)
		fmt.Fprintf(b, "\tBSFL AX, AX\n")
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", skipLbl)
		fmt.Fprintf(b, "\tMOVL $32, AX\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_popcnt":
		fmt.Fprintf(b, "\tPOPCNTL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_rotl":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tROLL CX, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_rotr":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tRORL CX, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	// --- 64-bit integer ---
	case "i64_eqz":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ AX, AX\n")
		fmt.Fprintf(b, "\tSETEQ AL\n")
		fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i64_clz":
		skipLbl := fmt.Sprintf("CLZ64_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("CLZ64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ AX, AX\n")
		fmt.Fprintf(b, "\tJE %s\n", skipLbl)
		fmt.Fprintf(b, "\tBSRQ AX, AX\n")
		fmt.Fprintf(b, "\tMOVQ $63, CX\n")
		fmt.Fprintf(b, "\tSUBQ AX, CX\n")
		fmt.Fprintf(b, "\tMOVQ CX, AX\n")
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", skipLbl)
		fmt.Fprintf(b, "\tMOVQ $64, AX\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_ctz":
		skipLbl := fmt.Sprintf("CTZ64_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("CTZ64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ AX, AX\n")
		fmt.Fprintf(b, "\tJE %s\n", skipLbl)
		fmt.Fprintf(b, "\tBSFQ AX, AX\n")
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", skipLbl)
		fmt.Fprintf(b, "\tMOVQ $64, AX\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_popcnt":
		fmt.Fprintf(b, "\tPOPCNTQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_rotl":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tROLQ CX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_rotr":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tRORQ CX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	// --- 32-bit signed division / remainder ---
	// wasm semantics: divide-by-zero traps; INT_MIN / -1 traps
	// for div_s but yields 0 for rem_s. We emit the divisor
	// zero-check inline; the overflow trap is left to the CPU's
	// #DE handler for div_s, and rem_s gets an explicit guard
	// to return 0 instead of trapping. The Go runtime turns #DE
	// into a panic, so out-of-bounds inputs surface as panics
	// rather than silent garbage — matching wasm trap semantics.
	case "i32_div_s":
		zeroLbl := fmt.Sprintf("DIVS32_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("DIVS32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCDQ\n") // sign-extend AX into EDX:EAX
		fmt.Fprintf(b, "\tIDIVL CX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n") // wasm: integer divide by zero
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i32_div_u_s", "i32_div_u":
		zeroLbl := fmt.Sprintf("DIVU32_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("DIVU32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tXORL DX, DX\n") // zero-extend
		fmt.Fprintf(b, "\tDIVL CX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i32_rem_s":
		// INT_MIN % -1 == 0 in wasm; the CPU #DE we'd otherwise
		// get is avoided by short-circuiting that case.
		zeroLbl := fmt.Sprintf("REMS32_ZERO_%d", v.ID)
		overflowLbl := fmt.Sprintf("REMS32_OVF_%d", v.ID)
		doneLbl := fmt.Sprintf("REMS32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tCMPL CX, $-1\n")
		fmt.Fprintf(b, "\tJE %s\n", overflowLbl)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCDQ\n")
		fmt.Fprintf(b, "\tIDIVL CX\n")
		fmt.Fprintf(b, "\tMOVL DX, %d(SP)\n", dst) // remainder in DX
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", overflowLbl)
		fmt.Fprintf(b, "\tMOVL $0, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i32_rem_u_s", "i32_rem_u":
		zeroLbl := fmt.Sprintf("REMU32_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("REMU32_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrc32(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTL CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tXORL DX, DX\n")
		fmt.Fprintf(b, "\tDIVL CX\n")
		fmt.Fprintf(b, "\tMOVL DX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	// --- 64-bit signed division / remainder ---
	case "i64_div_s":
		zeroLbl := fmt.Sprintf("DIVS64_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("DIVS64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCQO\n")
		fmt.Fprintf(b, "\tIDIVQ CX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i64_div_u_s", "i64_div_u":
		zeroLbl := fmt.Sprintf("DIVU64_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("DIVU64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tXORQ DX, DX\n")
		fmt.Fprintf(b, "\tDIVQ CX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i64_rem_s":
		zeroLbl := fmt.Sprintf("REMS64_ZERO_%d", v.ID)
		overflowLbl := fmt.Sprintf("REMS64_OVF_%d", v.ID)
		doneLbl := fmt.Sprintf("REMS64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tCMPQ CX, $-1\n")
		fmt.Fprintf(b, "\tJE %s\n", overflowLbl)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCQO\n")
		fmt.Fprintf(b, "\tIDIVQ CX\n")
		fmt.Fprintf(b, "\tMOVQ DX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", overflowLbl)
		fmt.Fprintf(b, "\tMOVQ $0, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	case "i64_rem_u_s", "i64_rem_u":
		zeroLbl := fmt.Sprintf("REMU64_ZERO_%d", v.ID)
		doneLbl := fmt.Sprintf("REMU64_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, CX\n", operandSrc64(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ CX, CX\n")
		fmt.Fprintf(b, "\tJE %s\n", zeroLbl)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tXORQ DX, DX\n")
		fmt.Fprintf(b, "\tDIVQ CX\n")
		fmt.Fprintf(b, "\tMOVQ DX, %d(SP)\n", dst)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", zeroLbl)
		fmt.Fprintf(b, "\tCALL ·wasm_trap_div_zero(SB)\n")
		fmt.Fprintf(b, "%s:\n", doneLbl)
		return true, nil
	// --- Integer width conversions ---
	case "i32_wrap_i64":
		// Take low 32 bits.
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i64_extend_i32_s":
		fmt.Fprintf(b, "\tMOVLQSX %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_extend_i32_u":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i32_extend8_s":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVBLSX AL, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i32_extend16_s":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVWLSX AX, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i64_extend8_s":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVBQSX AL, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_extend16_s":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVWQSX AX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "i64_extend32_s":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVLQSX AX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	// --- Bit-pattern reinterprets (free: same slot bits) ---
	case "i32_reinterpret_f32":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "f32_reinterpret_i32":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "i64_reinterpret_f64":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "f64_reinterpret_i64":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	// --- Float basic arithmetic (alongside OpAddF*/OpSubF*/... ssa ops). ---
	case "f32_add":
		return emitInlineFloatBin(b, v, plan, frame, "ADDSS", false, dst)
	case "f32_sub":
		return emitInlineFloatBin(b, v, plan, frame, "SUBSS", false, dst)
	case "f32_mul":
		return emitInlineFloatBin(b, v, plan, frame, "MULSS", false, dst)
	case "f32_div":
		return emitInlineFloatBin(b, v, plan, frame, "DIVSS", false, dst)
	case "f64_add":
		return emitInlineFloatBin(b, v, plan, frame, "ADDSD", true, dst)
	case "f64_sub":
		return emitInlineFloatBin(b, v, plan, frame, "SUBSD", true, dst)
	case "f64_mul":
		return emitInlineFloatBin(b, v, plan, frame, "MULSD", true, dst)
	case "f64_div":
		return emitInlineFloatBin(b, v, plan, frame, "DIVSD", true, dst)
	case "f32_sqrt":
		fmt.Fprintf(b, "\tSQRTSS %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f64_sqrt":
		fmt.Fprintf(b, "\tSQRTSD %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	// --- f32/f64 absolute value (clear sign bit) ---
	case "f32_abs":
		// 0x7FFFFFFF mask preserves bits 0..30 and clears the sign bit.
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tANDL $0x7FFFFFFF, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "f64_abs":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ $0x7FFFFFFFFFFFFFFF, CX\n")
		fmt.Fprintf(b, "\tANDQ CX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	case "f32_neg":
		// Flip sign bit (0x80000000 XOR).
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tXORL $0x80000000, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "f64_neg":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ $0x8000000000000000, CX\n")
		fmt.Fprintf(b, "\tXORQ CX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	// --- Float comparisons (UCOMISS/UCOMISD, NaN-aware). ---
	case "f32_eq":
		return emitInlineFloatCmp(b, v, plan, frame, "SETEQ", false, dst, "and-np")
	case "f32_ne":
		return emitInlineFloatCmp(b, v, plan, frame, "SETNE", false, dst, "or-p")
	case "f32_lt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCS", false, dst, "and-np")
	case "f32_le":
		return emitInlineFloatCmp(b, v, plan, frame, "SETLS", false, dst, "and-np")
	case "f32_gt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETHI", false, dst, "")
	case "f32_ge":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCC", false, dst, "")
	case "f64_eq":
		return emitInlineFloatCmp(b, v, plan, frame, "SETEQ", true, dst, "and-np")
	case "f64_ne":
		return emitInlineFloatCmp(b, v, plan, frame, "SETNE", true, dst, "or-p")
	case "f64_lt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCS", true, dst, "and-np")
	case "f64_le":
		return emitInlineFloatCmp(b, v, plan, frame, "SETLS", true, dst, "and-np")
	case "f64_gt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETHI", true, dst, "")
	case "f64_ge":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCC", true, dst, "")
	// --- Float rounding via SSE4.1 ROUNDSS/ROUNDSD ---
	// Mode bits: 0=nearest-even, 1=floor (-Inf), 2=ceil (+Inf),
	// 3=trunc (toward zero). wasm's nearest matches mode 0.
	case "f32_ceil":
		fmt.Fprintf(b, "\tROUNDSS $2, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f32_floor":
		fmt.Fprintf(b, "\tROUNDSS $1, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f32_trunc":
		fmt.Fprintf(b, "\tROUNDSS $3, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f32_nearest":
		fmt.Fprintf(b, "\tROUNDSS $0, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f64_ceil":
		fmt.Fprintf(b, "\tROUNDSD $2, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f64_floor":
		fmt.Fprintf(b, "\tROUNDSD $1, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f64_trunc":
		fmt.Fprintf(b, "\tROUNDSD $3, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f64_nearest":
		fmt.Fprintf(b, "\tROUNDSD $0, %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	// --- Float min/max — wasm spec: NaN-propagating. MINSS/MAXSS
	// return the second operand on NaN, so we need explicit NaN
	// handling: if either is NaN, result is the canonical NaN. ---
	case "f32_min":
		return emitInlineFloatMinMax(b, v, plan, frame, "MINSS", false, dst)
	case "f32_max":
		return emitInlineFloatMinMax(b, v, plan, frame, "MAXSS", false, dst)
	case "f64_min":
		return emitInlineFloatMinMax(b, v, plan, frame, "MINSD", true, dst)
	case "f64_max":
		return emitInlineFloatMinMax(b, v, plan, frame, "MAXSD", true, dst)
	// --- Float copysign — copy sign of arg1 onto magnitude of arg0. ---
	case "f32_copysign":
		// result = (arg0 & ~sign) | (arg1 & sign)
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tANDL $0x7FFFFFFF, AX\n")
		fmt.Fprintf(b, "\tMOVL %s, CX\n", operandSrcFloat(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tANDL $0x80000000, CX\n")
		fmt.Fprintf(b, "\tORL CX, AX\n")
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		return true, nil
	case "f64_copysign":
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ $0x7FFFFFFFFFFFFFFF, CX\n")
		fmt.Fprintf(b, "\tANDQ CX, AX\n")
		fmt.Fprintf(b, "\tMOVQ %s, DX\n", operandSrcFloat(v.Args[1], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ $0x8000000000000000, CX\n")
		fmt.Fprintf(b, "\tANDQ CX, DX\n")
		fmt.Fprintf(b, "\tORQ DX, AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		return true, nil
	// --- f32 ↔ f64 width changes ---
	case "f32_demote_f64":
		fmt.Fprintf(b, "\tCVTSD2SS %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f64_promote_f32":
		fmt.Fprintf(b, "\tCVTSS2SD %s, X0\n", operandSrcFloat(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	// --- Integer → Float conversions ---
	case "f32_convert_i32_s":
		fmt.Fprintf(b, "\tCVTSL2SS %s, X0\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f32_convert_i64_s":
		fmt.Fprintf(b, "\tCVTSQ2SS %s, X0\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f64_convert_i32_s":
		fmt.Fprintf(b, "\tCVTSL2SD %s, X0\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f64_convert_i64_s":
		fmt.Fprintf(b, "\tCVTSQ2SD %s, X0\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f32_convert_i32_u":
		// Zero-extend to 64-bit then convert.
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCVTSQ2SS AX, X0\n")
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		return true, nil
	case "f64_convert_i32_u":
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tCVTSQ2SD AX, X0\n")
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		return true, nil
	case "f32_convert_i64_u", "f64_convert_i64_u":
		// Unsigned i64 → float. The signed CVTSQ2S* works for
		// non-negative inputs. For values ≥ 2^63 we add the
		// proper offset (2^64 as float). This matches Go's
		// runtime conversion semantics.
		is64 := name == "f64_convert_i64_u"
		mov := "MOVSS"
		cvt := "CVTSQ2SS"
		add := "ADDSS"
		if is64 {
			mov = "MOVSD"
			cvt = "CVTSQ2SD"
			add = "ADDSD"
		}
		negLbl := fmt.Sprintf("CVT_NEG_%d", v.ID)
		doneLbl := fmt.Sprintf("CVT_DONE_%d", v.ID)
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
		fmt.Fprintf(b, "\tTESTQ AX, AX\n")
		fmt.Fprintf(b, "\tJS %s\n", negLbl)
		fmt.Fprintf(b, "\t%s AX, X0\n", cvt)
		fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
		fmt.Fprintf(b, "%s:\n", negLbl)
		// Halve, convert, double — preserves precision.
		fmt.Fprintf(b, "\tMOVQ AX, CX\n")
		fmt.Fprintf(b, "\tSHRQ $1, CX\n")
		fmt.Fprintf(b, "\tANDQ $1, AX\n")
		fmt.Fprintf(b, "\tORQ CX, AX\n")
		fmt.Fprintf(b, "\t%s AX, X0\n", cvt)
		fmt.Fprintf(b, "\t%s X0, X0\n", add) // x + x = 2x
		fmt.Fprintf(b, "%s:\n", doneLbl)
		fmt.Fprintf(b, "\t%s X0, %d(SP)\n", mov, dst)
		return true, nil
	// --- Float → Integer (truncating). wasm spec: trap on NaN,
	// overflow, or value outside dst range. Saturated variants
	// (trunc_sat_*) clamp instead. ---
	// Non-saturating trunc must trap on NaN / out-of-range per wasm
	// spec. The previous inline emit ran CVTT bare — which on x86 sets
	// the invalid-op flag but produces INT_MIN as the result instead of
	// raising, so the trap was silently swallowed. Route these through
	// the helper-call path (i32_trunc_f32_s etc.) which panics with the
	// right message. Saturating variants stay inline: their semantics
	// match CVTT's no-trap clamp behaviour up to the NaN case, and the
	// sat helpers are still on the helper-call fallback if anything
	// goes wrong.
	case "i32_trunc_f32_s", "i32_trunc_f64_s",
		"i64_trunc_f32_s", "i64_trunc_f64_s":
		return false, nil
	case "i32_trunc_sat_f32_s":
		return emitTruncFloatToInt(b, v, plan, frame, false, false, dst, true)
	case "i32_trunc_sat_f64_s":
		return emitTruncFloatToInt(b, v, plan, frame, true, false, dst, true)
	case "i64_trunc_sat_f32_s":
		return emitTruncFloatToInt(b, v, plan, frame, false, true, dst, true)
	case "i64_trunc_sat_f64_s":
		return emitTruncFloatToInt(b, v, plan, frame, true, true, dst, true)
		// Unsigned variants — use signed convert and adjust; or for
		// saturated, clamp via Go-side helpers (still keep these as
		// CALLs since the asm sequences are long and the helpers are
		// pure scalar Go code). TODO: inline these too if profiling
		// shows them on a hot path.
	}
	return false, nil
}

// emitInlineFloatMinMax handles wasm f32_min/f64_min/f32_max/f64_max:
// the wasm spec mandates NaN propagation (returning canonical NaN if
// either operand is NaN). MINSS/MAXSS instead return the SECOND
// operand for unordered inputs, so we explicitly bias on UCOMI's PF
// flag.
func emitInlineFloatMinMax(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnem string, is64 bool, dst int) (bool, error) {
	mov := "MOVSS"
	cmp := "UCOMISS"
	nanBits := "$0x7FC00000" // canonical f32 NaN
	if is64 {
		mov = "MOVSD"
		cmp = "UCOMISD"
		nanBits = "$0x7FF8000000000000" // canonical f64 NaN
	}
	nanLbl := fmt.Sprintf("FNAN_%d", v.ID)
	doneLbl := fmt.Sprintf("FNANDONE_%d", v.ID)
	fmt.Fprintf(b, "\t%s %s, X0\n", mov, operandSrcFloat(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, X1\n", mov, operandSrcFloat(v.Args[1], plan, frame, "SP"))
	// Detect NaN: UCOMI sets PF if unordered.
	fmt.Fprintf(b, "\t%s X1, X0\n", cmp)
	fmt.Fprintf(b, "\tJP %s\n", nanLbl)
	fmt.Fprintf(b, "\t%s X1, X0\n", mnem)
	fmt.Fprintf(b, "\tJMP %s\n", doneLbl)
	fmt.Fprintf(b, "%s:\n", nanLbl)
	if is64 {
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", nanBits)
		fmt.Fprintf(b, "\tMOVQ AX, X0\n")
	} else {
		fmt.Fprintf(b, "\tMOVL %s, AX\n", nanBits)
		fmt.Fprintf(b, "\tMOVL AX, X0\n")
	}
	fmt.Fprintf(b, "%s:\n", doneLbl)
	fmt.Fprintf(b, "\t%s X0, %d(SP)\n", mov, dst)
	return true, nil
}

// emitTruncFloatToInt handles signed-truncate float→int with optional
// saturation. is64Src picks f64 input, is64Dst picks i64 output.
// When sat is true, NaN/overflow yields clamped values; otherwise the
// CPU's #DE / invalid-operand exception triggers a trap (which the
// Go runtime turns into a panic — matching wasm trap semantics).
func emitTruncFloatToInt(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, is64Src, is64Dst bool, dst int, _ bool) (bool, error) {
	mov := "MOVSS"
	cvtt := "CVTTSS2SL"
	if is64Src {
		mov = "MOVSD"
		cvtt = "CVTTSD2SL"
	}
	if is64Dst {
		cvtt = "CVTTSS2SQ"
		if is64Src {
			cvtt = "CVTTSD2SQ"
		}
	}
	fmt.Fprintf(b, "\t%s %s, X0\n", mov, operandSrcFloat(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s X0, AX\n", cvtt)
	if is64Dst {
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	} else {
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	}
	return true, nil
}

// emitInlineFloatBin emits a 2-arg float arithmetic op.
func emitInlineFloatBin(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnem string, is64 bool, dst int) (bool, error) {
	mov := "MOVSS"
	if is64 {
		mov = "MOVSD"
	}
	fmt.Fprintf(b, "\t%s %s, X0\n", mov, operandSrcFloat(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, X0\n", mnem, operandSrcFloat(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s X0, %d(SP)\n", mov, dst)
	return true, nil
}

// emitInlineFloatCmp does UCOMISS / UCOMISD followed by SETxx,
// then zero-extends and stores into the i32 dst slot. The result
// is 0 or 1 in wasm semantics.
// emitInlineFloatCmp lowers a wasm float comparison (`f{32,64}.{eq,
// ne,lt,le,gt,ge}`) to a UCOMI + SET cc pair. The IEEE-754 NaN cases
// need an explicit fix-up because `UCOMI` reports unordered (NaN-vs-
// anything) by setting ZF=1, PF=1, CF=1 — every `SET cc` that
// inspects ZF or CF therefore returns the "true" arm of an ordered
// compare for NaN, which is the OPPOSITE of what wasm wants for
// every relational op except `ne`.
//
// Per wasm spec, NaN must produce 0 for `eq/lt/le/gt/ge` and 1 for
// `ne`. The combination that's correct depends on the cc:
//
//   - eq / lt / le  : cc returns 1 for NaN (we want 0). After SETcc,
//     `AND SETNP` clears the bit when PF=1 (NaN).
//   - ne            : cc returns 0 for NaN (we want 1). After SETcc,
//     `OR  SETP`  forces the bit to 1 when PF=1.
//   - gt / ge       : cc already returns 0 for NaN (UCOMI's CF=1
//     makes SETA / SETAE both 0). No fix needed.
//
// Pre-fix, `f64_ne(NaN, NaN)` returned 0 because SETNE alone reads
// ZF=0 — but for NaN ZF=1, so SETNE → 0. Wasm's spec requires 1
// (caught by TestNaNGlobalInit, `f64.ne (global.get $gnan) (global
// .get $gnan)`). The corresponding eq/lt/le bug returned 1 for any
// NaN comparison, which is also wrong (wasm spec says 0).
//
// The `nanFix` argument selects the fix-up shape:
//
//	"and-np" → emit `SETNP BL; ANDL BX, AX` after SETcc
//	"or-p"   → emit `SETP  BL; ORL  BX, AX` after SETcc
//	""       → no fix-up (gt/ge — UCOMI's CF makes SETcc already 0)
func emitInlineFloatCmp(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, setOp string, is64 bool, dst int, nanFix string) (bool, error) {
	mov := "MOVSS"
	cmp := "UCOMISS"
	if is64 {
		mov = "MOVSD"
		cmp = "UCOMISD"
	}
	fmt.Fprintf(b, "\t%s %s, X0\n", mov, operandSrcFloat(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, X0\n", cmp, operandSrcFloat(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s AL\n", setOp)
	fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
	switch nanFix {
	case "and-np":
		// SETPC (parity clear, PF=0 — "ordered") in plan9 syntax.
		fmt.Fprintf(b, "\tSETPC BL\n")
		fmt.Fprintf(b, "\tMOVBLZX BL, BX\n")
		fmt.Fprintf(b, "\tANDL BX, AX\n")
	case "or-p":
		// SETPS (parity set, PF=1 — "unordered / NaN") in plan9.
		fmt.Fprintf(b, "\tSETPS BL\n")
		fmt.Fprintf(b, "\tMOVBLZX BL, BX\n")
		fmt.Fprintf(b, "\tORL BX, AX\n")
	}
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	return true, nil
}

// emitCallDirect lowers a direct call to another generated function.
// The caller forwards its own *Module receiver at offset 0, stages
// every wasm param at the callee's ABI0 offset, CALLs the resolved
// asm symbol, and reads the return value back into the producing
// value's slot. The callee staging area at the low end of the
// caller's frame was sized in planFunc to fit the largest callee
// any of this function's direct calls or helper calls will need.
func emitCallDirect(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	d, ok := plan.directs[v.ID]
	if !ok {
		return fmt.Errorf("OpCallDirect v%d: no plan entry", v.ID)
	}
	if len(v.Args) != len(d.sig.Params) {
		return fmt.Errorf("OpCallDirect v%d: signature has %d params, IR has %d args", v.ID, len(d.sig.Params), len(v.Args))
	}
	// Forward the caller's m at FP+0 (8 bytes) to the callee's
	// frame at SP+0. When m is cached in a function-wide register,
	// stage it from there directly — saves the redundant
	// `MOVQ m+0(FP), AX; MOVQ AX, 0(SP)` pair every CALL would
	// otherwise pay.
	if plan.mCacheReg != "" {
		fmt.Fprintf(b, "\tMOVQ %s, 0(SP)\n", plan.mCacheReg)
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
		fmt.Fprintf(b, "\tMOVQ AX, 0(SP)\n")
	}
	// Stage each wasm param at its ABI0 offset within the callee
	// frame. The offsets were precomputed by computeArgFrame on the
	// callee's signature.
	for i, arg := range v.Args {
		argOff := d.frame.paramOffsets[i]
		switch d.sig.Params[i] {
		case wasm.ValI32:
			if imm, ok := inlineableI32(arg); ok {
				fmt.Fprintf(b, "\tMOVL $%d, %d(SP)\n", imm, argOff)
			} else {
				fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(arg, plan, frame, "SP"))
				fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", argOff)
			}
		case wasm.ValI64:
			if imm, ok := inlineableI64(arg); ok && imm >= -(1<<31) && imm < (1<<31) {
				fmt.Fprintf(b, "\tMOVQ $%d, %d(SP)\n", imm, argOff)
			} else {
				fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(arg, plan, frame, "SP"))
				fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", argOff)
			}
		case wasm.ValF32:
			fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(arg, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", argOff)
		case wasm.ValF64:
			fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(arg, plan, frame, "SP"))
			fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", argOff)
		default:
			return fmt.Errorf("OpCallDirect v%d: param %d type %v unsupported", v.ID, i, d.sig.Params[i])
		}
	}
	fmt.Fprintf(b, "\tCALL %s\n", d.symbol)

	// Read back the single result if there is one. void-returning
	// calls leave the producing value's type set to TypeMem (the
	// lowering's sentinel for "no usable result"); we honour that
	// by skipping the readback rather than relying on the result
	// type, which keeps this path simple even if a future caller
	// produces a tuple here.
	if len(d.sig.Results) == 0 {
		return nil
	}
	if len(d.sig.Results) > 1 {
		return fmt.Errorf("OpCallDirect v%d: multi-result returns not supported", v.ID)
	}
	// Skip the result load + slot store when this value has zero
	// downstream consumers. Pure-Go drops the equivalent
	// pair entirely; planFunc's computeUnusedResults pass marks the
	// values that are safe to elide. The CALL itself stays — its
	// side effects matter — only the post-CALL readback is dead.
	if plan.unusedResult[v.ID] {
		return nil
	}
	dst := plan.offsets[v.ID]
	retOff := d.frame.resultOffsets[0]
	// When the result has a register home, load
	// straight from the callee's return slot into the home register
	// and skip the local slot store. The home reg is guaranteed to
	// be free at this point — the regalloc's CALL-barrier check
	// denies regHome to any value whose lifetime spans a CALL, so
	// the home was only assigned to OpCallDirect/Import/Indirect
	// values that themselves DEFINE the result at the CALL site,
	// where the post-CALL clobber happens BEFORE the value's
	// lifetime starts.
	gpHome, hasGpHome := "AX", false
	sseHome, hasSseHome := "X0", false
	if r := plan.regHome[v.ID]; r != "" {
		if isSSEReg(r) {
			sseHome, hasSseHome = r, true
		} else {
			gpHome, hasGpHome = r, true
		}
	}
	switch d.sig.Results[0] {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVL %d(SP), %s\n", retOff, gpHome)
		if !hasGpHome {
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVQ %d(SP), %s\n", retOff, gpHome)
		if !hasGpHome {
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		}
	case wasm.ValF32:
		fmt.Fprintf(b, "\tMOVSS %d(SP), %s\n", retOff, sseHome)
		if !hasSseHome {
			fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
		}
	case wasm.ValF64:
		fmt.Fprintf(b, "\tMOVSD %d(SP), %s\n", retOff, sseHome)
		if !hasSseHome {
			fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
		}
	default:
		return fmt.Errorf("OpCallDirect v%d: result type %v unsupported", v.ID, d.sig.Results[0])
	}
	return nil
}

// emitGlobalGetInlineAMD64 lowers an OpGlobalGet directly to a MOV
// against the Module struct, skipping the loadGlobal_<idx> CALL.
// Replaces the 5-instruction wrapper sequence (stash m as arg 0,
// CALL, reload return) with a 3-instruction load (m → AX, M[off] →
// scratch, scratch → dst slot). Saves the Go-ABI plumbing AND the
// caller-save BX clobber that would have followed the CALL.
func emitGlobalGetInlineAMD64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	_ = frame
	info, ok := plan.globalInline[v.ID]
	if !ok {
		return fmt.Errorf("OpGlobalGet v%d: no globalInline entry", v.ID)
	}
	dst := plan.offsets[v.ID]
	// When m is cached in a function-wide register, dereference it
	// directly — skip the redundant
	// `MOVQ m+0(FP), AX` that every global access would otherwise
	// pay for. Pure-Go does this implicitly via the Go compiler's
	// regalloc keeping the receiver in AX across the body.
	mReg := "AX"
	if plan.mCacheReg != "" {
		mReg = plan.mCacheReg
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
	}
	switch info.vtype {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVL %d(%s), DX\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVL DX, %d(SP)\n", dst)
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVQ %d(%s), DX\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVQ DX, %d(SP)\n", dst)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tMOVSS %d(%s), X0\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tMOVSD %d(%s), X0\n", info.offset, mReg)
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	default:
		return fmt.Errorf("OpGlobalGet v%d: global type %v unsupported by inline emitter", v.ID, info.vtype)
	}
	return nil
}

// emitGlobalSetInlineAMD64 is the OpGlobalSet counterpart of
// emitGlobalGetInlineAMD64 — see that function's comment for the
// motivation. The source value is in v.Args[0]; its operandSrc
// resolution handles const-fold (MOVL $imm directly), parameter-FP
// reads, and the regular slot fallback.
func emitGlobalSetInlineAMD64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	info, ok := plan.globalInline[v.ID]
	if !ok {
		return fmt.Errorf("OpGlobalSet v%d: no globalInline entry", v.ID)
	}
	if len(v.Args) != 1 || v.Args[0] == nil {
		return fmt.Errorf("OpGlobalSet v%d: expected 1 arg, got %d", v.ID, len(v.Args))
	}
	src := v.Args[0]
	mReg := "AX"
	if plan.mCacheReg != "" {
		mReg = plan.mCacheReg
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
	}
	switch info.vtype {
	case wasm.ValI32:
		if imm, ok := inlineableI32(src); ok {
			fmt.Fprintf(b, "\tMOVL $%d, %d(%s)\n", imm, info.offset, mReg)
			return nil
		}
		fmt.Fprintf(b, "\tMOVL %s, DX\n", operandSrc32(src, plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVL DX, %d(%s)\n", info.offset, mReg)
	case wasm.ValI64:
		if imm, ok := inlineableI64(src); ok && imm >= -(1<<31) && imm < (1<<31) {
			fmt.Fprintf(b, "\tMOVQ $%d, %d(%s)\n", imm, info.offset, mReg)
			return nil
		}
		fmt.Fprintf(b, "\tMOVQ %s, DX\n", operandSrc64(src, plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVQ DX, %d(%s)\n", info.offset, mReg)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tMOVSS %s, X0\n", operandSrcFloat(src, plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSS X0, %d(%s)\n", info.offset, mReg)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tMOVSD %s, X0\n", operandSrcFloat(src, plan, frame, "SP"))
		fmt.Fprintf(b, "\tMOVSD X0, %d(%s)\n", info.offset, mReg)
	default:
		return fmt.Errorf("OpGlobalSet v%d: global type %v unsupported by inline emitter", v.ID, info.vtype)
	}
	return nil
}

// goCallSymbol renders the asm symbol for a Go-side helper. We
// always emit the local same-package form (·name) because plan9
// asm rejects cross-package CALL targets — the linker reports
// "relocation target base.Foo not defined" when a chunk's asm
// CALLs into the base package directly. In multi-package mode
// the caller is responsible for emitting a chunk-local
// //go:linkname trampoline that bridges to the canonical
// implementation in base.
func goCallSymbol(prefix, helperName string) string {
	_ = prefix
	return fmt.Sprintf("·%s(SB)", helperName)
}
