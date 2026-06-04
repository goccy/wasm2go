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

func (archARM64) EmitJmp(b *strings.Builder, label string) {
	fmt.Fprintf(b, "\tJMP %s\n", label)
}

func (archARM64) EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel string, plan *funcPlan, frame argFrame) {
	// Load condition into R0 and branch if non-zero. CBNZW
	// compares the low 32 bits, which matches our slot width for
	// TypeBool/TypeI32. plan9 arm64 spells it CBNZW.
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(cond, plan, frame))
	fmt.Fprintf(b, "\tCBNZW R0, %s\n", thenLabel)
	fmt.Fprintf(b, "\tJMP %s\n", elseLabel)
}

func (archARM64) EmitMemMRefresh(b *strings.Builder, plan *funcPlan) {
	if plan.memMSlot < 0 {
		return
	}
	fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
	fmt.Fprintf(b, "\tMOVD %d(R0), R0\n", moduleMOffset)
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", plan.memMSlot)
}

func (archARM64) SkipValue(v *ssa.Value) bool {
	// arm64's operandSrc32/64ARM64 helpers never inline Const — the
	// MOVW $imm forms reject most 32-bit literals — so the per-value
	// materialise is the only path that gets the constant into its
	// slot. Never skip emission here.
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

	case ssa.OpParam:
		return emitParamARM64(b, v, frame, plan)

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
		return emitCmp32ARM64(b, v, plan, frame, "EQ")
	case ssa.OpNe32:
		return emitCmp32ARM64(b, v, plan, frame, "NE")
	case ssa.OpLtS32:
		return emitCmp32ARM64(b, v, plan, frame, "LT")
	case ssa.OpLeS32:
		return emitCmp32ARM64(b, v, plan, frame, "LE")
	case ssa.OpLtU32:
		return emitCmp32ARM64(b, v, plan, frame, "LO")
	case ssa.OpLeU32:
		return emitCmp32ARM64(b, v, plan, frame, "LS")
	case ssa.OpEq64:
		return emitCmp64ARM64(b, v, plan, frame, "EQ")
	case ssa.OpNe64:
		return emitCmp64ARM64(b, v, plan, frame, "NE")
	case ssa.OpLtS64:
		return emitCmp64ARM64(b, v, plan, frame, "LT")
	case ssa.OpLeS64:
		return emitCmp64ARM64(b, v, plan, frame, "LE")
	case ssa.OpLtU64:
		return emitCmp64ARM64(b, v, plan, frame, "LO")
	case ssa.OpLeU64:
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
		return emitHelperCallARM64(b, v, plan, frame)
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpGlobalGet, ssa.OpGlobalSet,
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

func emitParamARM64(b *strings.Builder, v *ssa.Value, frame argFrame, plan *funcPlan) error {
	idx := int(v.AuxInt)
	if idx < 0 || idx >= len(frame.paramOffsets) {
		return fmt.Errorf("OpParam index %d out of range", idx)
	}
	off := frame.paramOffsets[idx]
	dst := plan.offsets[v.ID]
	switch v.Type {
	case ssa.TypeI32:
		fmt.Fprintf(b, "\tMOVW l%d+%d(FP), R0\n", idx, off)
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVD l%d+%d(FP), R0\n", idx, off)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tFMOVS l%d+%d(FP), F0\n", idx, off)
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tFMOVD l%d+%d(FP), F0\n", idx, off)
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
	default:
		return fmt.Errorf("OpParam type %v not supported", v.Type)
	}
	return nil
}

func emitBin32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitBin64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	return nil
}

func emitShift32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitShift64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVD %s, R0\n", operandSrc64ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVD %s, R1\n", operandSrc64ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\t%s R1, R0, R0\n", mnemonic)
	fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	return nil
}

func emitCmp32ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, cond string) error {
	dst := plan.offsets[v.ID]
	// CMPW second-operand-minus-first matches plan9 amd64's
	// CMP-after-rewrite convention; CSET sets R0 = 1 if the
	// requested condition is true after the compare.
	fmt.Fprintf(b, "\tMOVW %s, R0\n", operandSrc32ARM64(v.Args[0], plan, frame))
	fmt.Fprintf(b, "\tMOVW %s, R1\n", operandSrc32ARM64(v.Args[1], plan, frame))
	fmt.Fprintf(b, "\tCMPW R1, R0\n")
	fmt.Fprintf(b, "\tCSET %s, R0\n", cond)
	fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	return nil
}

func emitCmp64ARM64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, cond string) error {
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
	if plan.memMSlot >= 0 {
		fmt.Fprintf(b, "\tMOVD %d(RSP), R2\n", plan.memMSlot)
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
	switch v.Op {
	case ssa.OpLoad8U:
		fmt.Fprintf(b, "\tMOVBU (R2), R0\n")
		if is64 {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad8S:
		fmt.Fprintf(b, "\tMOVB (R2), R0\n")
		if is64 {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad16U:
		fmt.Fprintf(b, "\tMOVHU (R2), R0\n")
		if is64 {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad16S:
		fmt.Fprintf(b, "\tMOVH (R2), R0\n")
		if is64 {
			fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
		}
	case ssa.OpLoad32:
		fmt.Fprintf(b, "\tMOVW (R2), R0\n")
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	case ssa.OpLoad32U:
		// i64.load32_u: read u32 → zero-extend to i64.
		fmt.Fprintf(b, "\tMOVWU (R2), R0\n")
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case ssa.OpLoad32S:
		fmt.Fprintf(b, "\tMOVW (R2), R0\n")
		fmt.Fprintf(b, "\tSXTW R0, R0\n")
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case ssa.OpLoad64:
		fmt.Fprintf(b, "\tMOVD (R2), R0\n")
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case ssa.OpLoadF32:
		fmt.Fprintf(b, "\tFMOVS (R2), F0\n")
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
	case ssa.OpLoadF64:
		fmt.Fprintf(b, "\tFMOVD (R2), F0\n")
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
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
	if plan.memMSlot >= 0 {
		fmt.Fprintf(b, "\tMOVD %d(RSP), R2\n", plan.memMSlot)
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
	off := 0
	for i, arg := range v.Args {
		size, align := helperABISize(spec.params[i])
		off = alignUp(off, align)
		switch spec.params[i] {
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
		default:
			return fmt.Errorf("helper %q arg %d type %v not supported", name, i, spec.params[i])
		}
		off += size
	}
	retOff := helperRetOffset(spec)
	symbol := goCallSymbol(plan.helperPfx, name)
	fmt.Fprintf(b, "\tCALL %s\n", symbol)
	if spec.ret != ssa.TypeInvalid {
		dst := plan.offsets[v.ID]
		switch spec.ret {
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
		default:
			return fmt.Errorf("helper %q ret type %v not supported", name, spec.ret)
		}
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
	// Forward the caller's m at FP+0 to the callee's frame at SP+0.
	fmt.Fprintf(b, "\tMOVD m+0(FP), R0\n")
	fmt.Fprintf(b, "\tMOVD R0, 0(RSP)\n")
	for i, arg := range v.Args {
		argOff := d.frame.paramOffsets[i]
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
	dst := plan.offsets[v.ID]
	retOff := d.frame.resultOffsets[0]
	switch d.sig.Results[0] {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVW %d(RSP), R0\n", retOff)
		fmt.Fprintf(b, "\tMOVW R0, %d(RSP)\n", dst)
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVD %d(RSP), R0\n", retOff)
		fmt.Fprintf(b, "\tMOVD R0, %d(RSP)\n", dst)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tFMOVS %d(RSP), F0\n", retOff)
		fmt.Fprintf(b, "\tFMOVS F0, %d(RSP)\n", dst)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tFMOVD %d(RSP), F0\n", retOff)
		fmt.Fprintf(b, "\tFMOVD F0, %d(RSP)\n", dst)
	default:
		return fmt.Errorf("%v v%d: result type %v unsupported", v.Op, v.ID, d.sig.Results[0])
	}
	return nil
}
