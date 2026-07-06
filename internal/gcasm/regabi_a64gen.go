package gcasm

// arm64 ABIInternal register sequences (go/src/cmd/compile/abi-internal.md).
// Integer args: R0–R15. Float args: F0–F15. Results: R0 / F0. R27 is the
// linker temp (also gc's jump-table target register); R16/R17 are the
// morestack/stack-check temps; R28 is g, R29 the frame pointer, R30 the
// link register, RSP the stack pointer.
var arm64IntArgRegs = []string{
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
	"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
}
var arm64FloatArgRegs = []string{
	"F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
	"F8", "F9", "F10", "F11", "F12", "F13", "F14", "F15",
}

// assignARM64 maps a signature to ABIInternal registers, mirroring gc's
// integer/float sequences. Params beyond the register file are
// stack-assigned (Reg == "", SeqOf set); functions whose own signature
// stack-assigns are kept as pure fallbacks by the pipeline.
func assignARM64(params []ArgKind, hasResult bool, result ArgKind) (args []RegAssignment, res *RegAssignment) {
	intN, fltN := 0, 0
	stackOff := 0
	seqOff := 0
	align := func(n, a int) int { return (n + a - 1) &^ (a - 1) }
	for _, k := range params {
		var ra RegAssignment
		ra.Kind = k
		sz, al := 8, 8
		if k == ArgI32 || k == ArgU32 || k == ArgF32 {
			sz, al = 4, 4
		}
		isFloat := k == ArgF32 || k == ArgF64
		switch {
		case isFloat && fltN < len(arm64FloatArgRegs):
			ra.Reg = arm64FloatArgRegs[fltN]
			fltN++
		case !isFloat && intN < len(arm64IntArgRegs):
			ra.Reg = arm64IntArgRegs[intN]
			intN++
		default:
			seqOff = align(seqOff, al)
			ra.SeqOf = seqOff
			seqOff += sz
		}
		stackOff = align(stackOff, al)
		ra.StackOf = stackOff
		stackOff += sz
		args = append(args, ra)
	}
	if hasResult {
		r := RegAssignment{Kind: result}
		stackOff = align(stackOff, 8)
		r.StackOf = stackOff
		if result == ArgF32 || result == ArgF64 {
			r.Reg = "F0"
		} else {
			r.Reg = "R0"
		}
		res = &r
	}
	return args, res
}

// loadForARM64 returns the mnemonic for a memory→register move that
// EXTENDS narrow integers to the full 64-bit register per ABIInternal
// (MOVW sign-extends int32, MOVWU zero-extends uint32).
func loadForARM64(k ArgKind) string {
	switch k {
	case ArgPtr, ArgI64:
		return "MOVD"
	case ArgI32:
		return "MOVW"
	case ArgU32:
		return "MOVWU"
	case ArgF32:
		return "FMOVS"
	case ArgF64:
		return "FMOVD"
	}
	return "MOVD"
}

// storeForARM64 returns the mnemonic for a register→memory move (width
// only — stores never extend).
func storeForARM64(k ArgKind) string {
	switch k {
	case ArgPtr, ArgI64:
		return "MOVD"
	case ArgI32, ArgU32:
		return "MOVW"
	case ArgF32:
		return "FMOVS"
	case ArgF64:
		return "FMOVD"
	}
	return "MOVD"
}
