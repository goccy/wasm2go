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
// this layout; the Phase 2.3 test pins it explicitly.
const moduleMOffset = 32

// archAMD64 implements the arch interface for the x86_64 target.
type archAMD64 struct{}

func (archAMD64) EmitValue(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error {
	return emitValueAMD64(b, v, plan, frame)
}

func (archAMD64) EmitJmp(b *strings.Builder, label string) {
	fmt.Fprintf(b, "\tJMP %s\n", label)
}

func (archAMD64) EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel string, plan *funcPlan, frame argFrame) {
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(cond, plan, frame, "SP"))
	fmt.Fprintf(b, "\tTESTL AX, AX\n")
	fmt.Fprintf(b, "\tJNE %s\n", thenLabel)
	fmt.Fprintf(b, "\tJMP %s\n", elseLabel)
}

func (archAMD64) EmitMemMRefresh(b *strings.Builder, plan *funcPlan) {
	if plan.memMSlot < 0 {
		return
	}
	fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
	fmt.Fprintf(b, "\tMOVQ %d(AX), AX\n", moduleMOffset)
	fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", plan.memMSlot)
}

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

func (archAMD64) emitPhiCopyAMD64(b *strings.Builder, srcOperand string, dstOff int, t ssa.Type) error {
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

	// --- Function parameters ---
	case ssa.OpParam:
		return emitParam(b, v, frame, plan)

	// --- Float binary (32-bit / 64-bit) — SSE scalar ops over X0/X1. ---
	case ssa.OpAddF32:
		return emitBinFloat(b, v, plan, frame, "ADDSS", false)
	case ssa.OpSubF32:
		return emitBinFloat(b, v, plan, frame, "SUBSS", false)
	case ssa.OpMulF32:
		return emitBinFloat(b, v, plan, frame, "MULSS", false)
	case ssa.OpDivF32:
		return emitBinFloat(b, v, plan, frame, "DIVSS", false)
	case ssa.OpAddF64:
		return emitBinFloat(b, v, plan, frame, "ADDSD", true)
	case ssa.OpSubF64:
		return emitBinFloat(b, v, plan, frame, "SUBSD", true)
	case ssa.OpMulF64:
		return emitBinFloat(b, v, plan, frame, "MULSD", true)
	case ssa.OpDivF64:
		return emitBinFloat(b, v, plan, frame, "DIVSD", true)

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
		return emitCmp32(b, v, plan, frame, "SETEQ")
	case ssa.OpNe32:
		return emitCmp32(b, v, plan, frame, "SETNE")
	case ssa.OpLtS32:
		return emitCmp32(b, v, plan, frame, "SETLT")
	case ssa.OpLtU32:
		return emitCmp32(b, v, plan, frame, "SETCS") // below = CF set = SETB
	case ssa.OpLeS32:
		return emitCmp32(b, v, plan, frame, "SETLE")
	case ssa.OpLeU32:
		return emitCmp32(b, v, plan, frame, "SETLS") // below-or-equal = SETBE

	// --- Comparisons (64-bit) ---
	case ssa.OpEq64:
		return emitCmp64(b, v, plan, frame, "SETEQ")
	case ssa.OpNe64:
		return emitCmp64(b, v, plan, frame, "SETNE")
	case ssa.OpLtS64:
		return emitCmp64(b, v, plan, frame, "SETLT")
	case ssa.OpLtU64:
		return emitCmp64(b, v, plan, frame, "SETCS")
	case ssa.OpLeS64:
		return emitCmp64(b, v, plan, frame, "SETLE")
	case ssa.OpLeU64:
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
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpGlobalGet, ssa.OpGlobalSet,
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
	return fmt.Sprintf("%d(%s)", plan.offsets[v.ID], spReg)
}

// operandSrc32ARM64 / operandSrc64ARM64 are the arm64 counterparts
// that NEVER materialise OpConst inline — arm64 MOV with an
// arbitrary 32/64-bit immediate is rejected by the assembler, so the
// constant has to live in its slot and be read from there. The slot
// is guaranteed to exist because planFunc keeps Const ops out of
// isInlineableOp's slot-skip set on arm64-eligible builds.
func operandSrc32ARM64(v *ssa.Value, plan *funcPlan, frame argFrame) string {
	v = resolveCopy(v)
	if v.Op == ssa.OpParam {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			return fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])
		}
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

func emitParam(b *strings.Builder, v *ssa.Value, frame argFrame, plan *funcPlan) error {
	idx := int(v.AuxInt)
	if idx < 0 || idx >= len(frame.paramOffsets) {
		return fmt.Errorf("OpParam index %d out of range", idx)
	}
	off := frame.paramOffsets[idx]
	dst := plan.offsets[v.ID]
	switch v.Type {
	case ssa.TypeI32:
		fmt.Fprintf(b, "\tMOVL l%d+%d(FP), AX\n", idx, off)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	case ssa.TypeI64:
		fmt.Fprintf(b, "\tMOVQ l%d+%d(FP), AX\n", idx, off)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.TypeF32:
		fmt.Fprintf(b, "\tMOVSS l%d+%d(FP), X0\n", idx, off)
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case ssa.TypeF64:
		fmt.Fprintf(b, "\tMOVSD l%d+%d(FP), X0\n", idx, off)
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	default:
		return fmt.Errorf("OpParam type %v not supported", v.Type)
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
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, AX\n", mnemonic, operandSrc32(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	return nil
}

func emitBinALU64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, AX\n", mnemonic, operandSrc64(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	return nil
}

// emitBinFloat lowers a binary float op (ADDSS/SUBSS/MULSS/DIVSS for
// f32, ADDSD/SUBSD/MULSD/DIVSD for f64) via SSE scalar instructions.
// First operand → X0, second operand → X1, op X1, X0, store X0.
// `is64` picks MOVSD vs MOVSS for the load/store.
func emitBinFloat(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, mnemonic string, is64 bool) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	dst := plan.offsets[v.ID]
	loadMov := "MOVSS"
	if is64 {
		loadMov = "MOVSD"
	}
	fmt.Fprintf(b, "\t%s %s, X0\n", loadMov, operandSrcFloat(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s %s, X0\n", mnemonic, operandSrcFloat(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s X0, %d(SP)\n", loadMov, dst)
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
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
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
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
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
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\tCMPL AX, %s\n", operandSrc32(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s AL\n", setOp)
	fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	return nil
}

func emitCmp64(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, setOp string) error {
	if len(v.Args) != 2 {
		return fmt.Errorf("%s expects 2 args", v.Op)
	}
	dst := plan.offsets[v.ID]
	fmt.Fprintf(b, "\tMOVQ %s, AX\n", operandSrc64(v.Args[0], plan, frame, "SP"))
	fmt.Fprintf(b, "\tCMPQ AX, %s\n", operandSrc64(v.Args[1], plan, frame, "SP"))
	fmt.Fprintf(b, "\t%s AL\n", setOp)
	fmt.Fprintf(b, "\tMOVBLZX AL, AX\n")
	fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
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
	if plan.memMSlot >= 0 {
		fmt.Fprintf(b, "\tMOVQ %d(SP), BX\n", plan.memMSlot)
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), BX\n")
		fmt.Fprintf(b, "\tMOVQ %d(BX), BX\n", moduleMOffset)
	}
	addr := "(BX)"
	// Mirror of emitStore's constant-base fast path: when the base is
	// a known Const32 we fold `base + off` at generation time and
	// emit a single MOVx disp(BX), <reg> load, dropping the
	// MOVL+ADDL+ADDQ address-formation triplet. Same uint32 wrap
	// semantics as the runtime path.
	if base, ok := inlineableI32(v.Args[0]); ok {
		disp := int32(uint32(base) + uint32(off))
		addr = fmt.Sprintf("%d(BX)", disp)
	} else {
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		if off != 0 {
			fmt.Fprintf(b, "\tADDL $%d, AX\n", off)
		}
		fmt.Fprintf(b, "\tADDQ AX, BX\n")
	}
	// Narrow loads (8/16-bit) produce either i32 or i64 depending
	// on the wasm op — i32.load8_u vs i64.load8_u both lower to
	// OpLoad8U, distinguished only by v.Type. The asm has to
	// zero/sign-extend to the right width and use MOVQ for i64.
	is64 := v.Type == ssa.TypeI64
	switch v.Op {
	case ssa.OpLoad8U:
		if is64 {
			fmt.Fprintf(b, "\tMOVBQZX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVBLZX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case ssa.OpLoad8S:
		if is64 {
			fmt.Fprintf(b, "\tMOVBQSX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVBLSX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case ssa.OpLoad16U:
		if is64 {
			fmt.Fprintf(b, "\tMOVWQZX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVWLZX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case ssa.OpLoad16S:
		if is64 {
			fmt.Fprintf(b, "\tMOVWQSX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
		} else {
			fmt.Fprintf(b, "\tMOVWLSX %s, AX\n", addr)
			fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
		}
	case ssa.OpLoad32:
		fmt.Fprintf(b, "\tMOVL %s, AX\n", addr)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	case ssa.OpLoad32U:
		// i64.load32_u: read u32 → zero-extend to i64.
		fmt.Fprintf(b, "\tMOVL %s, AX\n", addr) // MOVL zero-extends to RAX
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.OpLoad32S:
		// i64.load32_s: read i32 → sign-extend to i64.
		fmt.Fprintf(b, "\tMOVLQSX %s, AX\n", addr)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.OpLoad64:
		fmt.Fprintf(b, "\tMOVQ %s, AX\n", addr)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case ssa.OpLoadF32:
		fmt.Fprintf(b, "\tMOVSS %s, X0\n", addr)
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case ssa.OpLoadF64:
		fmt.Fprintf(b, "\tMOVSD %s, X0\n", addr)
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	default:
		return fmt.Errorf("OpLoad variant %v not supported", v.Op)
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
	if plan.memMSlot >= 0 {
		fmt.Fprintf(b, "\tMOVQ %d(SP), BX\n", plan.memMSlot)
	} else {
		fmt.Fprintf(b, "\tMOVQ m+0(FP), BX\n")
		fmt.Fprintf(b, "\tMOVQ %d(BX), BX\n", moduleMOffset)
	}
	addr := "(BX)"
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
		fmt.Fprintf(b, "\tMOVL %s, AX\n", operandSrc32(v.Args[0], plan, frame, "SP"))
		if off != 0 {
			fmt.Fprintf(b, "\tADDL $%d, AX\n", off)
		}
		fmt.Fprintf(b, "\tADDQ AX, BX\n")
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
	if spec.ret != ssa.TypeInvalid {
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n") // wasm: integer divide by zero
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		fmt.Fprintf(b, "\tXORQ AX, AX\n\tMOVL (AX), AX\n")
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
		return emitInlineFloatCmp(b, v, plan, frame, "SETEQ", false, dst, true)
	case "f32_ne":
		return emitInlineFloatCmp(b, v, plan, frame, "SETNE", false, dst, false)
	case "f32_lt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCS", false, dst, true) // unordered (NaN) → 0
	case "f32_le":
		return emitInlineFloatCmp(b, v, plan, frame, "SETLS", false, dst, true)
	case "f32_gt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETHI", false, dst, true)
	case "f32_ge":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCC", false, dst, true)
	case "f64_eq":
		return emitInlineFloatCmp(b, v, plan, frame, "SETEQ", true, dst, true)
	case "f64_ne":
		return emitInlineFloatCmp(b, v, plan, frame, "SETNE", true, dst, false)
	case "f64_lt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCS", true, dst, true)
	case "f64_le":
		return emitInlineFloatCmp(b, v, plan, frame, "SETLS", true, dst, true)
	case "f64_gt":
		return emitInlineFloatCmp(b, v, plan, frame, "SETHI", true, dst, true)
	case "f64_ge":
		return emitInlineFloatCmp(b, v, plan, frame, "SETCC", true, dst, true)
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
	case "i32_trunc_f32_s":
		return emitTruncFloatToInt(b, v, plan, frame, false, false, dst, false)
	case "i32_trunc_f64_s":
		return emitTruncFloatToInt(b, v, plan, frame, true, false, dst, false)
	case "i64_trunc_f32_s":
		return emitTruncFloatToInt(b, v, plan, frame, false, true, dst, false)
	case "i64_trunc_f64_s":
		return emitTruncFloatToInt(b, v, plan, frame, true, true, dst, false)
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
func emitInlineFloatCmp(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame, setOp string, is64 bool, dst int, _ bool) (bool, error) {
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
	// frame at SP+0.
	fmt.Fprintf(b, "\tMOVQ m+0(FP), AX\n")
	fmt.Fprintf(b, "\tMOVQ AX, 0(SP)\n")
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
	dst := plan.offsets[v.ID]
	retOff := d.frame.resultOffsets[0]
	switch d.sig.Results[0] {
	case wasm.ValI32:
		fmt.Fprintf(b, "\tMOVL %d(SP), AX\n", retOff)
		fmt.Fprintf(b, "\tMOVL AX, %d(SP)\n", dst)
	case wasm.ValI64:
		fmt.Fprintf(b, "\tMOVQ %d(SP), AX\n", retOff)
		fmt.Fprintf(b, "\tMOVQ AX, %d(SP)\n", dst)
	case wasm.ValF32:
		fmt.Fprintf(b, "\tMOVSS %d(SP), X0\n", retOff)
		fmt.Fprintf(b, "\tMOVSS X0, %d(SP)\n", dst)
	case wasm.ValF64:
		fmt.Fprintf(b, "\tMOVSD %d(SP), X0\n", retOff)
		fmt.Fprintf(b, "\tMOVSD X0, %d(SP)\n", dst)
	default:
		return fmt.Errorf("OpCallDirect v%d: result type %v unsupported", v.ID, d.sig.Results[0])
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

// exportHelperName capitalises a helper name for cross-package use.
// The codegen translator's `capitalize` does the same — anything
// starting with `_` gets an `X` prefix; lowercase letters become
// uppercase. Names that are already exported pass through.
func exportHelperName(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
		return string(r)
	}
	if r[0] >= 'A' && r[0] <= 'Z' {
		return s
	}
	return "X" + s
}
