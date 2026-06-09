package regalloc

import "github.com/goccy/wasm2go/internal/ssa"

// archARM64 is the ArchInfo implementation for Plan9 arm64 asm. Go's
// arm64 register file has 65 entries (R0..R31, F0..F31, with R31
// double-encoded as SP/ZR) — more than a single uint64 regMask can
// hold. The allocator only needs to mask ALLOCATABLE registers, so we
// pack those at the low indices (0..57) and put reserved ones at the
// tail (58..); masks therefore never overflow uint64.
//
// Reserved set (mirroring Go's _gen/ARM64Ops.go):
//   - R18 : Apple platform register
//   - R27 : REGTMP (assembler scratch)
//   - R28 : Go's goroutine pointer (`g`)
//   - R29 : frame pointer
//   - R30 : link register / return address (REGLINK)
//   - SP  : stack pointer (encoded as R31 in some forms)
//   - ZR  : zero register (encoded as R31 in others)
//
// Allocatable: R0..R17 (18) + R19..R26 (8) + F0..F31 (32) = 58
// registers, fitting in the regMask uint64 with 6 bits to spare.
type archARM64 struct{}

// ArchARM64 is the singleton archARM64.
var ArchARM64 ArchInfo = archARM64{}

// arm64 indices. The split is:
//   - 0..17  : R0..R17  (18 allocatable GP)
//   - 18..25 : R19..R26 (8 allocatable GP, skipping the reserved R18)
//   - 26..57 : F0..F31  (32 allocatable SSE)
//   - 58..64 : reserved (R18, R27, R28=g, R29=FP, R30=LR, SP, ZR)
//
// Reserved indices >= 58 are NEVER folded into a regMask — they exist
// only so RegName / RegIndex can round-trip the asm names.
const (
	arm64R0 register = iota
	arm64R1
	arm64R2
	arm64R3
	arm64R4
	arm64R5
	arm64R6
	arm64R7
	arm64R8
	arm64R9
	arm64R10
	arm64R11
	arm64R12
	arm64R13
	arm64R14
	arm64R15
	arm64R16
	arm64R17 // last of the dense R0..R17 block; index 17
	arm64R19 // index 18 — note we SKIP R18, which lives at the reserved tail
	arm64R20
	arm64R21
	arm64R22
	arm64R23
	arm64R24
	arm64R25
	arm64R26 // index 25 — last allocatable GP
	arm64F0  // index 26
	arm64F1
	arm64F2
	arm64F3
	arm64F4
	arm64F5
	arm64F6
	arm64F7
	arm64F8
	arm64F9
	arm64F10
	arm64F11
	arm64F12
	arm64F13
	arm64F14
	arm64F15
	arm64F16
	arm64F17
	arm64F18
	arm64F19
	arm64F20
	arm64F21
	arm64F22
	arm64F23
	arm64F24
	arm64F25
	arm64F26
	arm64F27
	arm64F28
	arm64F29
	arm64F30
	arm64F31 // index 57 — last allocatable SSE
	// Reserved tail. Indices 58..64 fit in uint8 but we never shift
	// them into a regMask, so a uint64 holding bits 0..57 is enough
	// for every allocator operation.
	arm64R18 // 58 — Apple platform register
	arm64R27 // 59 — REGTMP
	arm64R28 // 60 — g
	arm64R29 // 61 — frame pointer
	arm64R30 // 62 — link register
	arm64SP  // 63 — stack pointer
	arm64ZR  // 64 — zero register
	arm64NumRegs
)

// Pre-computed register masks. All allocator-visible masks span bits
// 0..arm64F31 (57) and stay well under uint64's 64-bit limit. Reserved
// registers (R18 and onward) are NEVER masked — their indices appear
// only in the RegName / RegIndex round-trip table.
var (
	// arm64GPMask is the union of allocatable GP indices 0..25.
	arm64GPMask = func() regMask {
		var m regMask
		for r := arm64R0; r <= arm64R26; r++ {
			m |= 1 << r
		}
		return m
	}()

	// arm64SSEMask is the union of allocatable SSE indices 26..57.
	arm64SSEMask = func() regMask {
		var m regMask
		for r := arm64F0; r <= arm64F31; r++ {
			m |= 1 << r
		}
		return m
	}()

	// arm64Allocatable is the union of GP + SSE allocatable sets.
	// Reserved registers (R18, R27..R30, SP, ZR) are entirely outside
	// these masks — they live at higher numerical indices and are
	// never shifted into a regMask. Treating them as "not in any
	// mask" is equivalent to subtracting them from the allocatable
	// set, with the bonus that the masks stay uint64.
	arm64Allocatable regMask = arm64GPMask | arm64SSEMask

	// arm64CallClobbersGP — every allocatable GP is caller-save.
	arm64CallClobbersGP regMask = arm64GPMask

	// arm64CallClobbersSSE — every allocatable F-register is
	// caller-save.
	arm64CallClobbersSSE regMask = arm64SSEMask
)

// arm64Names is the index → mnemonic table. Allocatable indices map to
// the dense names; reserved indices map to their Plan9 names ("RSP",
// "ZR", and the plain "R18" / "R27"... for the GP reserves).
var arm64Names = func() [arm64NumRegs]string {
	var t [arm64NumRegs]string
	// Dense R0..R17 block.
	for i := 0; i < 18; i++ {
		t[arm64R0+register(i)] = "R" + itoaSmall(i)
	}
	// R19..R26 block — table index = 18 + i, register number = 19 + i.
	for i := 0; i < 8; i++ {
		t[arm64R19+register(i)] = "R" + itoaSmall(i+19)
	}
	// F0..F31.
	for i := 0; i < 32; i++ {
		t[arm64F0+register(i)] = "F" + itoaSmall(i)
	}
	// Reserved tail.
	t[arm64R18] = "R18"
	t[arm64R27] = "R27"
	t[arm64R28] = "R28"
	t[arm64R29] = "R29"
	t[arm64R30] = "R30"
	t[arm64SP] = "RSP"
	t[arm64ZR] = "ZR"
	return t
}()

// itoaSmall is a tiny strconv.Itoa for register numbering. Avoids
// pulling strconv into a package init context where the allocator
// only ever calls it during table construction.
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func (archARM64) Name() string             { return "arm64" }
func (archARM64) NumRegs() register        { return arm64NumRegs }
func (archARM64) GPRegMask() regMask       { return arm64GPMask }
func (archARM64) SSERegMask() regMask      { return arm64SSEMask }
func (archARM64) Allocatable() regMask     { return arm64Allocatable }
func (archARM64) CallClobbersGP() regMask  { return arm64CallClobbersGP }
func (archARM64) CallClobbersSSE() regMask { return arm64CallClobbersSSE }
func (archARM64) MaxCallArgs() int         { return 0 }
func (archARM64) NeedsTemp(ssa.Op) bool    { return false }

func (archARM64) RegName(r register) string {
	if int(r) >= len(arm64Names) {
		return "?"
	}
	return arm64Names[r]
}

// RegIndex looks up the index for an arm64 register name by walking
// the names table. The hot path is the emit boundary; the table walk
// is amortized.
func (archARM64) RegIndex(name string) register {
	for i, n := range arm64Names {
		if n == name {
			return register(i)
		}
	}
	return noRegister
}

func (archARM64) ClassFor(t ssa.Type) regClass {
	switch t {
	case ssa.TypeF32, ssa.TypeF64:
		return ClassSSE
	case ssa.TypeMem, ssa.TypeInvalid:
		return ClassFlags
	}
	return ClassGP
}

// RegSpec mirrors archAMD64.RegSpec but with arm64 conventions: no
// fixed-register IDIV equivalent, no CL pinning for shifts, full GP +
// FP clobber on CALL.
func (a archARM64) RegSpec(v *ssa.Value) regInfo {
	switch v.Op {
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpHelperCall,
		ssa.OpMemGrow, ssa.OpMemSize, ssa.OpMemoryCopy, ssa.OpMemoryFill,
		ssa.OpGlobalGet, ssa.OpGlobalSet:
		return regInfo{
			Clobbers: arm64CallClobbersGP | arm64CallClobbersSSE,
		}
	case ssa.OpAddF32, ssa.OpAddF64, ssa.OpSubF32, ssa.OpSubF64,
		ssa.OpMulF32, ssa.OpMulF64, ssa.OpDivF32, ssa.OpDivF64:
		return regInfo{
			Inputs:  []regParam{{Idx: 0, Regs: arm64SSEMask}, {Idx: 1, Regs: arm64SSEMask}},
			Outputs: []regParam{{Idx: 0, Regs: arm64SSEMask}},
		}
	}
	out := regInfo{}
	for i := range v.Args {
		if v.Args[i] == nil {
			continue
		}
		if a.ClassFor(v.Args[i].Type) == ClassSSE {
			out.Inputs = append(out.Inputs, regParam{Idx: i, Regs: arm64SSEMask})
		} else if a.ClassFor(v.Args[i].Type) == ClassGP {
			out.Inputs = append(out.Inputs, regParam{Idx: i, Regs: arm64GPMask})
		}
	}
	switch a.ClassFor(v.Type) {
	case ClassGP:
		out.Outputs = []regParam{{Idx: 0, Regs: arm64GPMask}}
	case ClassSSE:
		out.Outputs = []regParam{{Idx: 0, Regs: arm64SSEMask}}
	}
	return out
}

// IsResultInArg0 returns false on arm64 — every arm64 arithmetic
// instruction is a 3-operand form (`ADD Rd, Rn, Rm`), so the
// destination is independent of the inputs. The allocator never needs
// to insert a leading copy to alias arg0 with the output.
func (archARM64) IsResultInArg0(op ssa.Op) bool { return false }

// IsRematerializeable matches amd64's policy: constants are cheap to
// reissue at every use.
func (archARM64) IsRematerializeable(v *ssa.Value) bool {
	switch v.Op {
	case ssa.OpConst32, ssa.OpConst64:
		return true
	}
	return false
}

func (archARM64) FixedRegForFixedOp(v *ssa.Value) register {
	return noRegister
}
