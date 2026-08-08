// Package gcasm implements the gc-capture asm backend: the pure-Go
// output is compiled by the Go compiler at BUNDLE GENERATION time,
// the `-S` listing is captured, and a mechanical, deterministic
// transform turns it into shippable Plan9 .s files. Consumers get
// gc-quality function bodies at assembler-only build cost.
//
// Determinism contract (the generator must be idempotent): for a
// fixed toolchain and fixed input source, the emitted .s is
// byte-identical across runs. Everything the transform iterates is
// sorted, labels derive from instruction offsets, and no paths,
// timestamps, or map-order artifacts reach the output.
package gcasm

// ArgKind is the width/class of one ABI value.
type ArgKind int

const (
	ArgPtr ArgKind = iota // pointer-sized integer register (e.g. *Module)
	ArgI32                // SIGNED 32-bit (sign-extended in registers)
	ArgU32                // UNSIGNED 32-bit (zero-extended in registers)
	ArgI64
	ArgF32
	ArgF64
	// ArgV128 is a [2]uint64 (a wasm v128 value). ABIInternal never
	// register-assigns arrays, so v128 params and results are always
	// stack-assigned on both sides — the call marshal copies 16 bytes.
	ArgV128
)

// amd64 ABIInternal register sequences (go/src/cmd/compile/abi-internal.md).
var amd64IntArgRegs = []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}
var amd64FloatArgRegs = []string{"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
	"X8", "X9", "X10", "X11", "X12", "X13", "X14"}

// RegAssignment describes where one value lives under ABIInternal
// and where its ABI0 stack slot sits.
type RegAssignment struct {
	Kind    ArgKind
	Reg     string // ABIInternal register; "" when stack-assigned
	StackOf int    // ABI0 FP-relative offset (args) or SP-relative (outgoing)
	// SeqOf is the ABIInternal stack-argument sequence offset, valid
	// only when Reg == "". At an ABIInternal call site the caller
	// writes such a value to SeqOf(SP); the callee reads it above its
	// frame. The transform's call marshal copies it from there into
	// the ABI0 slot.
	SeqOf int
}

// AssignABIInternal maps a signature's params (and the single
// optional result) to ABIInternal registers, mirroring gc's
// assignment for the integer/float sequences. Params beyond the
// register file are stack-assigned (Reg == "", SeqOf set) — callers
// marshal those from the captured outgoing sequence; functions whose
// OWN signature stack-assigns are not transformed (pure fallback),
// which Transform enforces by rejecting Reg=="" among opts.Params.
func AssignABIInternal(params []ArgKind, hasResult bool, result ArgKind) (args []RegAssignment, res *RegAssignment, err error) {
	intN, fltN := 0, 0
	stackOff := 0
	seqOff := 0
	align := func(n, a int) int { return (n + a - 1) &^ (a - 1) }
	for _, k := range params {
		var ra RegAssignment
		ra.Kind = k
		sz, al := 8, 8
		switch k {
		case ArgI32, ArgU32, ArgF32:
			sz, al = 4, 4
		case ArgV128:
			sz = 16
		}
		isFloat := k == ArgF32 || k == ArgF64
		switch {
		case k == ArgV128:
			// Never register-assigned; always the stack sequence.
			seqOff = align(seqOff, al)
			ra.SeqOf = seqOff
			seqOff += sz
		case isFloat && fltN < len(amd64FloatArgRegs):
			ra.Reg = amd64FloatArgRegs[fltN]
			fltN++
		case !isFloat && intN < len(amd64IntArgRegs):
			ra.Reg = amd64IntArgRegs[intN]
			intN++
		default:
			// ABIInternal stack sequence (natural alignment, starts
			// at the caller's 0(SP) at call time).
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
		// ABI0 places the results area at the next POINTER-aligned
		// offset after the arguments, regardless of the result's own
		// alignment (go vet asmdecl enforces this: `(int32) int32`
		// is $...-12 with the result at +8, not +4).
		r := RegAssignment{Kind: result}
		stackOff = align(stackOff, 8)
		r.StackOf = stackOff
		switch result {
		case ArgV128:
			// Stack result on both sides: the ABIInternal caller reads
			// it from its outgoing sequence right after the stack args.
			r.SeqOf = align(seqOff, 8)
		case ArgF32, ArgF64:
			r.Reg = "X0"
		default:
			r.Reg = "AX"
		}
		res = &r
	}
	return args, res, nil
}

// StoreFor returns the Plan9 mnemonic for a register→memory move of
// a value class (width only — stores never extend).
func StoreFor(k ArgKind) string {
	switch k {
	case ArgPtr, ArgI64:
		return "MOVQ"
	case ArgI32, ArgU32:
		return "MOVL"
	case ArgF32:
		return "MOVSS"
	case ArgF64:
		return "MOVSD"
	}
	return "MOVQ"
}

// LoadFor returns the Plan9 mnemonic for a memory→register move of a
// value class. ABIInternal requires narrow integers to be EXTENDED to
// the full register — sign-extended for int32, zero-extended for
// uint32 — and captured code downstream of an argument or call result
// relies on that (64-bit compares, indexing with negative i32).
func LoadFor(k ArgKind) string {
	switch k {
	case ArgPtr, ArgI64:
		return "MOVQ"
	case ArgI32:
		return "MOVLQSX"
	case ArgU32:
		return "MOVL" // MOVL zero-extends to 64 bits
	case ArgF32:
		return "MOVSS"
	case ArgF64:
		return "MOVSD"
	}
	return "MOVQ"
}
