package regalloc

import "github.com/goccy/wasm2go/internal/ssa"

// ArchInfo abstracts the per-architecture register pool, calling
// convention, and per-op register requirements. The allocator works
// with `register` indices (uint8) and `regMask` bitsets; ArchInfo is
// the bridge between those numeric abstractions and the concrete asm
// names ("AX", "R0", "X3", ...).
//
// One ArchInfo implementation is supplied per target arch (ArchAMD64,
// ArchARM64). The same Allocator binary can in principle be retargeted
// at runtime by swapping ArchInfo; in practice we pick one per asmgen
// session and never switch mid-walk.
type ArchInfo interface {
	// Name reports a short arch identifier ("amd64", "arm64") for log
	// messages and error wrapping. Not used by the allocator's logic.
	Name() string

	// NumRegs reports the total register count for this arch. Indices
	// 0..NumRegs()-1 are valid `register` values; NumRegs() must be
	// strictly less than 64 (regMask is uint64). Includes reserved
	// registers — Allocatable() is the subset the allocator may pick.
	NumRegs() register

	// RegName returns the asm mnemonic ("AX", "R12", "X3", "F0") for a
	// register index. Used by the emitter and by tests; never on the
	// hot path of allocation.
	RegName(r register) string

	// RegIndex looks up the index for a register name. Returns
	// noRegister when the name isn't known to this arch. Used to bridge
	// the existing asmgen plan (which keys on names) to the new index-
	// based allocator state. Case-sensitive.
	RegIndex(name string) register

	// GPRegMask is the union of all general-purpose integer registers
	// for this arch, including reserved ones. Class membership uses
	// this mask; Allocatable() prunes the reserved set.
	GPRegMask() regMask

	// SSERegMask is the union of all floating-point / SIMD registers
	// for this arch. Distinct from GPRegMask so the type-class check
	// in computeLive / allocReg picks the correct pool.
	SSERegMask() regMask

	// Allocatable returns the registers the allocator is permitted to
	// pick from. This excludes SP, the goroutine pointer (R14 amd64 /
	// R28 arm64), any function-cache register reserved by the
	// m-cache (R11 = m on amd64), and any other arch-specific
	// lockouts. The
	// allocator subtracts further per-instruction pins via nospill.
	Allocatable() regMask

	// CallClobbersGP returns the mask of GP registers that a CALL
	// trashes. Go's ABI0 (which our generated functions follow) marks
	// every GP as caller-save, so this is GPRegMask() minus reserved
	// registers (g, frame ptr, static base). CALL handling sets these
	// regs free in the allocator state at every CALL site.
	CallClobbersGP() regMask

	// CallClobbersSSE returns the matching mask for the SSE / FP
	// registers. ABI0 treats all of them as caller-save, so this is
	// just SSERegMask() in practice.
	CallClobbersSSE() regMask

	// ClassFor maps an SSA value type to its register class. Memory /
	// void / flag types report ClassFlags (the allocator skips them);
	// float types report ClassSSE; everything else (i32, i64, bool,
	// pointer) reports ClassGP.
	ClassFor(t ssa.Type) regClass

	// RegSpec returns the per-op register-info for an SSA value. The
	// returned regInfo names the input / output / clobber constraints
	// that op imposes — most ALU ops have free choice (full GP mask on
	// both sides), CALL has rigid ABI args + a full clobber mask, MUL
	// pins the AX/DX outputs, and so on.
	//
	// The result is cached per-arch and is safe to share across
	// allocator runs; the allocator does NOT mutate the returned
	// regInfo.
	RegSpec(v *ssa.Value) regInfo

	// IsResultInArg0 reports whether the op's output must alias its
	// first arg's register (the two-address-instruction case — most
	// amd64 arithmetic, "ADDL src, dst" where dst is both input 0 and
	// the result). When true, the allocator emits a leading reg-to-reg
	// copy if arg0 is still live past the op.
	IsResultInArg0(op ssa.Op) bool

	// NeedsTemp reports whether the op needs a scratch register
	// distinct from its inputs and outputs. Used for ops whose lowering
	// performs an internal computation it can't fold into the
	// destination — none in our current opset, included for parity
	// with Go's allocator so future lowerings can opt in.
	NeedsTemp(op ssa.Op) bool

	// IsRematerializeable reports whether the op can be re-issued at
	// each use site cheaply (no side effects, no slot read, the result
	// is a pure function of constants and SP/SB). OpConst32 and
	// OpConst64 with a small immediate qualify on amd64; OpParam never
	// qualifies (FP-relative read, not a constant).
	IsRematerializeable(v *ssa.Value) bool

	// FixedRegForFixedOp reports the hard-wired register for ops whose
	// output position has exactly one acceptable register. Returns
	// noRegister when the op is not fixed (the common case).
	// Examples: OpSP → SP, OpSB → SB. Never used for ALU ops.
	FixedRegForFixedOp(v *ssa.Value) register

	// MaxCallArgs reports the largest CallArgs frame size that the
	// allocator should reserve. Currently unused (asmgen computes the
	// callee-area separately); included for parity with Go and to
	// document the convention.
	MaxCallArgs() int
}
