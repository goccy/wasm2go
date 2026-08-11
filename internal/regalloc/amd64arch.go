package regalloc

import "github.com/goccy/wasm2go/internal/ssa"

// archAMD64 is the ArchInfo implementation for Plan9 amd64 asm. The
// register-name table mirrors what the asmgen emitter already uses;
// numbering is dense from 0 so register masks stay tight (12 GP +
// 14 SSE = 26 bits used out of 64).
//
// Registers reserved out of the allocator pool:
//   - SP   : stack pointer, never touched
//   - BP   : Plan9-style indirect FP — Go runtime relies on it for
//     traceback in some configurations
//   - R11  : m-cache register (function-wide *Module)
//   - R14  : Go runtime's `g` pointer
//   - R15  : Go runtime's static base (when -dynlink); we conservatively
//     reserve it even for the static case to avoid divergence
//     from Pure-Go's reservation set
type archAMD64 struct{}

// ArchAMD64 is the singleton archAMD64 — share it across allocator
// runs; ArchInfo has no per-run state.
var ArchAMD64 ArchInfo = archAMD64{}

// amd64 register layout. Order matches Go's regalloc.go convention:
// GP first (with the call-arg regs ordered AX/BX/CX/DX/DI/SI/R8/R9
// for ABIInternal compatibility, even though our caller still uses
// ABI0), then non-call-arg GP (R10, R11, R12, R13), then SSE in X0..
// X13 order. The fixed numerical order means a string ↔ index lookup
// is just a switch.
//
// Indices below MUST stay stable — emit code references them by name
// at the boundary, but the allocator manipulates masks built from
// these indices. Changing the order forces every per-arch mask
// constant in this file to be recomputed.
const (
	amd64AX  register = iota // 0
	amd64BX                  // 1
	amd64CX                  // 2
	amd64DX                  // 3
	amd64DI                  // 4
	amd64SI                  // 5
	amd64R8                  // 6
	amd64R9                  // 7
	amd64R10                 // 8
	amd64R11                 // 9 — RESERVED (m-cache)
	amd64R12                 // 10
	amd64R13                 // 11
	amd64R14                 // 12 — RESERVED (Go's g)
	amd64R15                 // 13 — RESERVED (Go's static base)
	amd64SP                  // 14 — RESERVED (stack pointer)
	amd64BP                  // 15 — RESERVED (frame pointer)
	amd64X0                  // 16
	amd64X1                  // 17
	amd64X2                  // 18
	amd64X3                  // 19
	amd64X4                  // 20
	amd64X5                  // 21
	amd64X6                  // 22
	amd64X7                  // 23
	amd64X8                  // 24
	amd64X9                  // 25
	amd64X10                 // 26
	amd64X11                 // 27
	amd64X12                 // 28
	amd64X13                 // 29
	amd64NumRegs
)

// Pre-computed register masks for amd64. Building them at package init
// keeps the per-call ArchInfo methods constant-time.
var (
	// amd64GPMask covers every GP register, reserved or not.
	amd64GPMask regMask = 1<<amd64AX | 1<<amd64BX | 1<<amd64CX | 1<<amd64DX |
		1<<amd64DI | 1<<amd64SI |
		1<<amd64R8 | 1<<amd64R9 | 1<<amd64R10 | 1<<amd64R11 |
		1<<amd64R12 | 1<<amd64R13 | 1<<amd64R14 | 1<<amd64R15 |
		1<<amd64SP | 1<<amd64BP

	// amd64SSEMask covers every SSE register X0..X13.
	amd64SSEMask regMask = 1<<amd64X0 | 1<<amd64X1 | 1<<amd64X2 | 1<<amd64X3 |
		1<<amd64X4 | 1<<amd64X5 | 1<<amd64X6 | 1<<amd64X7 |
		1<<amd64X8 | 1<<amd64X9 | 1<<amd64X10 | 1<<amd64X11 |
		1<<amd64X12 | 1<<amd64X13

	// amd64ReservedMask is the union of registers the allocator may
	// not touch. R11 is the m-cache (set by emitFunc), R14 is
	// Go's g, R15 is the static base, SP and BP are obvious.
	amd64ReservedMask regMask = 1<<amd64R11 | 1<<amd64R14 | 1<<amd64R15 |
		1<<amd64SP | 1<<amd64BP

	// amd64AllocGP is the allocatable GP set: AX, BX, CX, DX, DI, SI,
	// R8, R9, R10, R12, R13 (11 registers).
	amd64AllocGP regMask = amd64GPMask &^ amd64ReservedMask

	// amd64AllocSSE is the allocatable SSE set: X0..X13 (14 registers).
	// We reserve none of them for the asm-generated functions — there
	// is no equivalent of "Go's g" in the SSE bank.
	amd64AllocSSE regMask = amd64SSEMask

	// amd64Allocatable is the union of allocatable GP and SSE — what
	// ArchInfo.Allocatable() returns. The m-cache reservation
	// is reflected via amd64ReservedMask above; the allocator never
	// sees R11 as a candidate.
	amd64Allocatable regMask = amd64AllocGP | amd64AllocSSE

	// amd64CallClobbersGP names the GP regs a CALL trashes. Under Go's
	// ABI0 every GP is caller-save, so this is amd64AllocGP itself
	// (we don't need to clobber the reserved ones — they're never in
	// the allocator's hands to begin with).
	amd64CallClobbersGP regMask = amd64AllocGP

	// amd64CallClobbersSSE is similarly the full allocatable SSE set —
	// every X register is caller-save.
	amd64CallClobbersSSE regMask = amd64AllocSSE
)

// amd64Names is the index → asm-mnemonic table. Used by RegName at
// emit boundaries and in error / log messages.
var amd64Names = [...]string{
	amd64AX: "AX", amd64BX: "BX", amd64CX: "CX", amd64DX: "DX",
	amd64DI: "DI", amd64SI: "SI",
	amd64R8: "R8", amd64R9: "R9", amd64R10: "R10", amd64R11: "R11",
	amd64R12: "R12", amd64R13: "R13", amd64R14: "R14", amd64R15: "R15",
	amd64SP: "SP", amd64BP: "BP",
	amd64X0: "X0", amd64X1: "X1", amd64X2: "X2", amd64X3: "X3",
	amd64X4: "X4", amd64X5: "X5", amd64X6: "X6", amd64X7: "X7",
	amd64X8: "X8", amd64X9: "X9", amd64X10: "X10", amd64X11: "X11",
	amd64X12: "X12", amd64X13: "X13",
}

func (archAMD64) Name() string             { return "amd64" }
func (archAMD64) NumRegs() register        { return amd64NumRegs }
func (archAMD64) GPRegMask() regMask       { return amd64GPMask }
func (archAMD64) SSERegMask() regMask      { return amd64SSEMask }
func (archAMD64) Allocatable() regMask     { return amd64Allocatable }
func (archAMD64) CallClobbersGP() regMask  { return amd64CallClobbersGP }
func (archAMD64) CallClobbersSSE() regMask { return amd64CallClobbersSSE }
func (archAMD64) MaxCallArgs() int         { return 0 }
func (archAMD64) NeedsTemp(ssa.Op) bool    { return false }

func (archAMD64) RegName(r register) string {
	if int(r) >= len(amd64Names) {
		return "?"
	}
	return amd64Names[r]
}

// RegIndex looks up a register by mnemonic. The expected hot path is
// the small per-function emit boundary; using a switch keeps it
// allocation-free without a map.
func (archAMD64) RegIndex(name string) register {
	switch name {
	case "AX":
		return amd64AX
	case "BX":
		return amd64BX
	case "CX":
		return amd64CX
	case "DX":
		return amd64DX
	case "DI":
		return amd64DI
	case "SI":
		return amd64SI
	case "R8":
		return amd64R8
	case "R9":
		return amd64R9
	case "R10":
		return amd64R10
	case "R11":
		return amd64R11
	case "R12":
		return amd64R12
	case "R13":
		return amd64R13
	case "R14":
		return amd64R14
	case "R15":
		return amd64R15
	case "SP":
		return amd64SP
	case "BP":
		return amd64BP
	case "X0":
		return amd64X0
	case "X1":
		return amd64X1
	case "X2":
		return amd64X2
	case "X3":
		return amd64X3
	case "X4":
		return amd64X4
	case "X5":
		return amd64X5
	case "X6":
		return amd64X6
	case "X7":
		return amd64X7
	case "X8":
		return amd64X8
	case "X9":
		return amd64X9
	case "X10":
		return amd64X10
	case "X11":
		return amd64X11
	case "X12":
		return amd64X12
	case "X13":
		return amd64X13
	}
	return noRegister
}

// ClassFor maps SSA types to their amd64 register class. Memory tokens
// and void / flags get ClassFlags so the allocator skips them. The
// fall-through covers any future TypeXyz the lowering might add — we
// default to GP rather than crashing.
func (archAMD64) ClassFor(t ssa.Type) regClass {
	switch t {
	case ssa.TypeF32, ssa.TypeF64:
		return ClassSSE
	case ssa.TypeMem, ssa.TypeInvalid:
		return ClassFlags
	}
	return ClassGP
}

// RegSpec returns the per-op input/output/clobber requirements. For
// the wide majority of ops (arithmetic, comparisons, loads, stores)
// the spec is "any GP for inputs, any GP for output". CALLs widen to
// full GP+SSE clobber. A handful of ops (IDIV, SHL by CL) have
// register-specific constraints — we model those explicitly so the
// allocator picks the right register up front instead of paying a
// reg-to-reg move at emit time.
func (a archAMD64) RegSpec(v *ssa.Value) regInfo {
	switch v.Op {
	// CALL family — all caller-save regs get clobbered.
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpHelperCall,
		ssa.OpMemGrow, ssa.OpMemSize, ssa.OpMemoryCopy, ssa.OpMemoryFill,
		ssa.OpGlobalGet, ssa.OpGlobalSet:
		return regInfo{
			// Inputs / outputs are sized by asmgen's CallArgs frame —
			// they're not register-resident at the CALL boundary in our
			// ABI0 model. Mark them empty here; the allocator's CALL
			// handling does the clobber sweep and the asmgen emitter
			// stages args through the stack frame.
			Clobbers: amd64CallClobbersGP | amd64CallClobbersSSE,
		}
	// IDIV i32 / i64 — quotient ends up in AX, remainder in DX. We
	// model both as "AX-fixed output + DX-clobbered" so the allocator
	// keeps DX free for the divisor and the result-receiver picks AX
	// up front.
	case ssa.OpDivS32, ssa.OpDivU32, ssa.OpDivS64, ssa.OpDivU64:
		return regInfo{
			Inputs:   []regParam{{Idx: 0, Regs: 1 << amd64AX}, {Idx: 1, Regs: amd64AllocGP &^ (1<<amd64AX | 1<<amd64DX)}},
			Outputs:  []regParam{{Idx: 0, Regs: 1 << amd64AX}},
			Clobbers: 1 << amd64DX,
		}
	case ssa.OpRemS32, ssa.OpRemU32, ssa.OpRemS64, ssa.OpRemU64:
		return regInfo{
			Inputs:   []regParam{{Idx: 0, Regs: 1 << amd64AX}, {Idx: 1, Regs: amd64AllocGP &^ (1<<amd64AX | 1<<amd64DX)}},
			Outputs:  []regParam{{Idx: 0, Regs: 1 << amd64DX}},
			Clobbers: 1 << amd64AX,
		}
	// SHL / SHR by variable count — the shift amount must be in CL.
	// We pin the second arg to CX and let the allocator route around it.
	case ssa.OpShl32, ssa.OpShl64,
		ssa.OpShrS32, ssa.OpShrS64, ssa.OpShrU32, ssa.OpShrU64:
		return regInfo{
			Inputs:  []regParam{{Idx: 0, Regs: amd64AllocGP}, {Idx: 1, Regs: 1 << amd64CX}},
			Outputs: []regParam{{Idx: 0, Regs: amd64AllocGP}},
		}
	// Float arithmetic lives in SSE and accepts any X-register.
	case ssa.OpAddF32, ssa.OpAddF64, ssa.OpSubF32, ssa.OpSubF64,
		ssa.OpMulF32, ssa.OpMulF64, ssa.OpDivF32, ssa.OpDivF64:
		return regInfo{
			Inputs:  []regParam{{Idx: 0, Regs: amd64AllocSSE}, {Idx: 1, Regs: amd64AllocSSE}},
			Outputs: []regParam{{Idx: 0, Regs: amd64AllocSSE}},
		}
	}
	// Float comparisons, float↔int conversions, rotates, and reinterpret
	// don't have dedicated SSA ops in our wasm-lowering — they route
	// through OpHelperCall("f32_eq" / "f32_to_i32_s" / ...). The CALL
	// branch above already captured those via the clobber-all-callers
	// path; we don't need a dedicated case here. Fall through to the
	// generic default for non-call ops.
	// Default: GP-class input, GP-class output. Covers Add / Sub / Mul
	// / And / Or / Xor / Eq / Ne / Lt* / Le* / Extend / Truncate /
	// Const / Param / Copy / Load* / Store*. The allocator chooses
	// freely within amd64AllocGP for each position.
	out := regInfo{}
	for i := range v.Args {
		if v.Args[i] == nil {
			continue
		}
		if a.ClassFor(v.Args[i].Type) == ClassSSE {
			out.Inputs = append(out.Inputs, regParam{Idx: i, Regs: amd64AllocSSE})
		} else if a.ClassFor(v.Args[i].Type) == ClassGP {
			out.Inputs = append(out.Inputs, regParam{Idx: i, Regs: amd64AllocGP})
		}
	}
	switch a.ClassFor(v.Type) {
	case ClassGP:
		out.Outputs = []regParam{{Idx: 0, Regs: amd64AllocGP}}
	case ClassSSE:
		out.Outputs = []regParam{{Idx: 0, Regs: amd64AllocSSE}}
	}
	return out
}

// IsResultInArg0 reports whether the op's output must alias its first
// arg. On amd64 every plan9-syntax 2-operand arithmetic instruction is
// `OP src, dst` where dst is both an input and the output — `ADDL src,
// dst` does `dst += src`. The allocator needs to know so it can either
// pick the same register for arg0 and the output, or insert a leading
// MOV from arg0 to the output register when arg0 is live past the op.
func (archAMD64) IsResultInArg0(op ssa.Op) bool {
	switch op {
	case ssa.OpAdd32, ssa.OpAdd64, ssa.OpSub32, ssa.OpSub64,
		ssa.OpMul32, ssa.OpMul64,
		ssa.OpAnd32, ssa.OpAnd64, ssa.OpOr32, ssa.OpOr64, ssa.OpXor32, ssa.OpXor64,
		ssa.OpShl32, ssa.OpShl64,
		ssa.OpShrS32, ssa.OpShrS64, ssa.OpShrU32, ssa.OpShrU64,
		ssa.OpAddF32, ssa.OpAddF64, ssa.OpSubF32, ssa.OpSubF64,
		ssa.OpMulF32, ssa.OpMulF64, ssa.OpDivF32, ssa.OpDivF64:
		return true
	}
	return false
}

// IsRematerializeable identifies ops the allocator may reissue at
// every use site instead of spilling. OpConst32 and OpConst64 with a
// fits-in-i32 immediate qualify on amd64 (the emit lowers them as
// `MOVL $imm, dst` or `MOVQ $imm, dst`); OpConst32 always does.
// Larger OpConst64 values would still need a constant-pool load,
// which is one instruction more expensive than reloading from a stack
// slot, so we decline.
func (archAMD64) IsRematerializeable(v *ssa.Value) bool {
	switch v.Op {
	case ssa.OpConst32:
		return true
	case ssa.OpConst64:
		return v.AuxInt >= -(1<<31) && v.AuxInt < (1<<31)
	}
	return false
}

// FixedRegForFixedOp returns the hard-wired register for SP/SB-class
// ops. wasm2go's lowering doesn't currently emit OpSP / OpSB synthetic
// values (we read SP indirectly via slot offsets in the emit
// boundary), so this returns noRegister for everything — left in place
// so a future OpSP/OpSB introduction stays a one-line addition rather
// than a refactor of the allocator's special-case path.
func (archAMD64) FixedRegForFixedOp(v *ssa.Value) register {
	return noRegister
}
