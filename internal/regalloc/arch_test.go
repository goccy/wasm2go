package regalloc

import (
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestRegMaskBasics covers the regMask uint64 wrapper's basic
// invariants: setting / clearing single bits, counting set bits, the
// "empty" mask test. We rely on these everywhere so the test doubles
// as documentation of the contract.
func TestRegMaskBasics(t *testing.T) {
	var m regMask
	if m != 0 {
		t.Fatalf("zero-value regMask should be 0, got %#x", m)
	}
	m |= 1 << amd64AX
	if m&(1<<amd64AX) == 0 {
		t.Errorf("expected bit for amd64AX (%d) to be set", amd64AX)
	}
	if m&(1<<amd64BX) != 0 {
		t.Errorf("did not expect bit for amd64BX (%d) to be set", amd64BX)
	}
	m |= 1 << amd64R12
	if popcount(m) != 2 {
		t.Errorf("expected 2 bits set, got %d (mask %#x)", popcount(m), m)
	}
	m &^= 1 << amd64AX
	if popcount(m) != 1 || m&(1<<amd64R12) == 0 {
		t.Errorf("after clearing AX expected only R12, got mask %#x", m)
	}
}

// popcount counts the set bits in a regMask — sanity check helper.
// Not on a hot path; the allocator uses bits.OnesCount64 directly.
func popcount(m regMask) int {
	n := 0
	for m != 0 {
		m &= m - 1
		n++
	}
	return n
}

// TestArchAMD64RegisterTable exercises the bidirectional name/index
// mapping. Every register the allocator can pick MUST round-trip — if
// we corrupt the table emit-time conversions will route a value to the
// wrong asm-level register and the bug is silent until runtime.
func TestArchAMD64RegisterTable(t *testing.T) {
	a := ArchAMD64
	if a.Name() != "amd64" {
		t.Fatalf("Name() = %q, want amd64", a.Name())
	}
	// Every name → index → name must round-trip.
	names := []string{
		"AX", "BX", "CX", "DX", "DI", "SI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
		"SP", "BP",
		"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
		"X8", "X9", "X10", "X11", "X12", "X13",
	}
	for _, n := range names {
		idx := a.RegIndex(n)
		if idx == noRegister {
			t.Errorf("RegIndex(%q) returned noRegister", n)
			continue
		}
		if got := a.RegName(idx); got != n {
			t.Errorf("RegIndex(%q) = %d, RegName(%d) = %q (want %q)", n, idx, idx, got, n)
		}
	}
	// Unknown names → noRegister, not a random low index.
	for _, bad := range []string{"", "AAX", "R99", "X14", "G", "ax", "ah"} {
		if got := a.RegIndex(bad); got != noRegister {
			t.Errorf("RegIndex(%q) = %d, want noRegister", bad, got)
		}
	}
}

// TestArchAMD64ReservedSet locks in the reserved register set. R11 is
// the m-cache; R14 is Go's g; R15 is the static base; SP and BP
// are platform-reserved. None must appear in Allocatable(); all must
// be present in GPRegMask().
func TestArchAMD64ReservedSet(t *testing.T) {
	a := ArchAMD64
	alloc := a.Allocatable()
	gp := a.GPRegMask()
	mustReserved := []register{amd64R11, amd64R14, amd64R15, amd64SP, amd64BP}
	for _, r := range mustReserved {
		bit := regMask(1) << r
		if alloc&bit != 0 {
			t.Errorf("expected %s to be RESERVED (not in Allocatable), but it's allocatable", a.RegName(r))
		}
		if gp&bit == 0 {
			t.Errorf("expected %s to still appear in GPRegMask (reserved != absent)", a.RegName(r))
		}
	}
	// Sanity: allocatable GP count should be 11.
	allocGP := alloc & gp
	if got := popcount(allocGP); got != 11 {
		t.Errorf("expected 11 allocatable GP regs, got %d", got)
	}
	// Sanity: allocatable SSE count should be 14 (X0..X13).
	allocSSE := alloc & a.SSERegMask()
	if got := popcount(allocSSE); got != 14 {
		t.Errorf("expected 14 allocatable SSE regs, got %d", got)
	}
}

// TestArchAMD64ClassFor maps each SSA type to its class and asserts
// the allocator-relevant ones (GP / SSE). Memory / Invalid land in
// ClassFlags so the allocator skips them.
func TestArchAMD64ClassFor(t *testing.T) {
	a := ArchAMD64
	tests := []struct {
		typ  ssa.Type
		want regClass
	}{
		{ssa.TypeI32, ClassGP},
		{ssa.TypeI64, ClassGP},
		{ssa.TypeBool, ClassGP},
		{ssa.TypeF32, ClassSSE},
		{ssa.TypeF64, ClassSSE},
		{ssa.TypeMem, ClassFlags},
		{ssa.TypeInvalid, ClassFlags},
	}
	for _, tt := range tests {
		if got := a.ClassFor(tt.typ); got != tt.want {
			t.Errorf("ClassFor(%v) = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

// TestArchAMD64CallClobbers locks in the CALL clobber set. Under Go's
// ABI0 every allocatable register is caller-save, so CallClobbersGP
// must equal the allocatable GP set, and CallClobbersSSE must equal
// the allocatable SSE set.
func TestArchAMD64CallClobbers(t *testing.T) {
	a := ArchAMD64
	allocGP := a.Allocatable() & a.GPRegMask()
	if got := a.CallClobbersGP(); got != allocGP {
		t.Errorf("CallClobbersGP = %#x, want %#x (allocatable GP)", got, allocGP)
	}
	allocSSE := a.Allocatable() & a.SSERegMask()
	if got := a.CallClobbersSSE(); got != allocSSE {
		t.Errorf("CallClobbersSSE = %#x, want %#x (allocatable SSE)", got, allocSSE)
	}
}

// TestArchAMD64IsResultInArg0 spot-checks the two-address marker. Add
// is YES (ADDL src, dst is dst += src); Load is NO (loads don't have
// the resultInArg0 constraint); Const is NO (constants have no inputs).
func TestArchAMD64IsResultInArg0(t *testing.T) {
	a := ArchAMD64
	yes := []ssa.Op{ssa.OpAdd32, ssa.OpAdd64, ssa.OpSub32, ssa.OpMul64, ssa.OpAnd32, ssa.OpOr64, ssa.OpXor32, ssa.OpShl32, ssa.OpAddF64}
	no := []ssa.Op{ssa.OpLoad32, ssa.OpStore32, ssa.OpConst32, ssa.OpEq32, ssa.OpCallDirect, ssa.OpParam, ssa.OpPhi}
	for _, op := range yes {
		if !a.IsResultInArg0(op) {
			t.Errorf("%v: IsResultInArg0 = false, want true", op)
		}
	}
	for _, op := range no {
		if a.IsResultInArg0(op) {
			t.Errorf("%v: IsResultInArg0 = true, want false", op)
		}
	}
}

// TestArchARM64RegisterTable exercises the bidirectional name/index
// mapping for arm64. R0..R30, RSP, ZR, F0..F31 must all round-trip.
func TestArchARM64RegisterTable(t *testing.T) {
	a := ArchARM64
	if a.Name() != "arm64" {
		t.Fatalf("Name() = %q, want arm64", a.Name())
	}
	// R0..R30
	for i := 0; i <= 30; i++ {
		n := "R" + itoaSmall(i)
		idx := a.RegIndex(n)
		if idx == noRegister {
			t.Errorf("RegIndex(%q) returned noRegister", n)
			continue
		}
		if got := a.RegName(idx); got != n {
			t.Errorf("RegIndex(%q) = %d, RegName(%d) = %q", n, idx, idx, got)
		}
	}
	// SP and ZR are special — they sit at index 31/32 but have unique
	// names ("RSP" / "ZR") in Plan9.
	for _, n := range []string{"RSP", "ZR"} {
		idx := a.RegIndex(n)
		if idx == noRegister {
			t.Errorf("RegIndex(%q) returned noRegister", n)
			continue
		}
		if got := a.RegName(idx); got != n {
			t.Errorf("RegName roundtrip for %q failed: got %q", n, got)
		}
	}
	// F0..F31
	for i := 0; i <= 31; i++ {
		n := "F" + itoaSmall(i)
		idx := a.RegIndex(n)
		if idx == noRegister {
			t.Errorf("RegIndex(%q) returned noRegister", n)
			continue
		}
		if got := a.RegName(idx); got != n {
			t.Errorf("RegIndex(%q) = %d, RegName(%d) = %q", n, idx, idx, got)
		}
	}
}

// TestArchARM64ReservedSet locks in arm64's reserved registers: R18
// (platform), R27 (REGTMP), R28 (g), R29 (FP), R30 (LR), SP, ZR. None
// may appear in Allocatable.
func TestArchARM64ReservedSet(t *testing.T) {
	a := ArchARM64
	alloc := a.Allocatable()
	for _, r := range []register{arm64R18, arm64R27, arm64R28, arm64R29, arm64R30, arm64SP, arm64ZR} {
		if alloc&(1<<r) != 0 {
			t.Errorf("expected %s to be RESERVED, but it's in Allocatable()", a.RegName(r))
		}
	}
	// Allocatable GP count: 26 — R0..R17 (18 entries) + R19..R26 (8
	// entries) = 26. R18 / R27..R31 are reserved.
	allocGP := alloc & a.GPRegMask()
	if got := popcount(allocGP); got != 26 {
		t.Errorf("expected 26 allocatable GP regs on arm64, got %d", got)
	}
	allocSSE := alloc & a.SSERegMask()
	if got := popcount(allocSSE); got != 32 {
		t.Errorf("expected 32 allocatable SSE regs on arm64, got %d", got)
	}
}

// TestArchARM64IsResultInArg0 confirms arm64 reports false for every
// op — arm64's 3-operand encoding (ADD Rd, Rn, Rm) never requires
// destination/source aliasing.
func TestArchARM64IsResultInArg0(t *testing.T) {
	a := ArchARM64
	for _, op := range []ssa.Op{ssa.OpAdd32, ssa.OpAdd64, ssa.OpSub32, ssa.OpMul64, ssa.OpAnd32, ssa.OpOr64, ssa.OpShl32, ssa.OpAddF64} {
		if a.IsResultInArg0(op) {
			t.Errorf("%v: arm64 IsResultInArg0 = true, want false (arm64 is 3-operand)", op)
		}
	}
}

// TestRegInfoCallClobbersAllAllocatable confirms that on both arches
// a CALL's RegSpec returns the full caller-save clobber set. This is
// the property the main allocator depends on when it calls
// `s.freeRegs(spec.Clobbers)` at every CALL site.
func TestRegInfoCallClobbersAllAllocatable(t *testing.T) {
	for _, a := range []ArchInfo{ArchAMD64, ArchARM64} {
		// Build a fake CALL value with no real callee — only the Op
		// matters for RegSpec.
		v := &ssa.Value{Op: ssa.OpCallDirect, Type: ssa.TypeMem}
		spec := a.RegSpec(v)
		wantClob := a.CallClobbersGP() | a.CallClobbersSSE()
		if spec.Clobbers != wantClob {
			t.Errorf("%s: RegSpec(OpCallDirect).Clobbers = %#x, want %#x", a.Name(), spec.Clobbers, wantClob)
		}
	}
}

// TestRegInfoArithDefault checks that a vanilla arithmetic op gets
// the "any GP, any GP" treatment on both arches. The allocator relies
// on this for the bulk of values.
func TestRegInfoArithDefault(t *testing.T) {
	for _, a := range []ArchInfo{ArchAMD64, ArchARM64} {
		// Synthesize an Add with two i32 args.
		arg0 := &ssa.Value{ID: 1, Op: ssa.OpParam, Type: ssa.TypeI32}
		arg1 := &ssa.Value{ID: 2, Op: ssa.OpParam, Type: ssa.TypeI32}
		v := &ssa.Value{ID: 3, Op: ssa.OpAdd32, Type: ssa.TypeI32, Args: []*ssa.Value{arg0, arg1}}
		spec := a.RegSpec(v)
		if len(spec.Inputs) != 2 {
			t.Errorf("%s: OpAdd32 expected 2 input specs, got %d", a.Name(), len(spec.Inputs))
		}
		if len(spec.Outputs) != 1 {
			t.Errorf("%s: OpAdd32 expected 1 output spec, got %d", a.Name(), len(spec.Outputs))
		}
		if spec.Clobbers != 0 {
			t.Errorf("%s: OpAdd32 should not have Clobbers, got %#x", a.Name(), spec.Clobbers)
		}
		// Both input masks should be subsets of allocatable GP.
		want := a.Allocatable() & a.GPRegMask()
		for _, p := range spec.Inputs {
			if p.Regs&^want != 0 {
				t.Errorf("%s: OpAdd32 input %d allows non-allocatable regs %#x", a.Name(), p.Idx, p.Regs&^want)
			}
		}
	}
}

// TestArchInfoConstantAccessors covers the small accessor methods on
// the ArchInfo implementations that aren't already exercised by the
// regalloc walk tests: MaxCallArgs, NeedsTemp, FixedRegForFixedOp.
// We assert on the publicly observable contract (zero / false / no-
// fixed-reg by default for both archs) without inspecting internal
// fields, so the test survives any future change to how the data is
// stored.
func TestArchInfoConstantAccessors(t *testing.T) {
	for _, a := range []ArchInfo{ArchAMD64, ArchARM64} {
		if got := a.MaxCallArgs(); got != 0 {
			t.Errorf("%s MaxCallArgs()=%d, want 0 (regalloc doesn't reserve call-arg regs)", a.Name(), got)
		}
		// NeedsTemp returns false for every op that doesn't need a
		// scratch register. Probe with a handful of representative ops
		// — we don't enumerate the whole opcode space, just confirm
		// the typical "no temp needed" answers are stable.
		probe := []ssa.Op{
			ssa.OpAdd32, ssa.OpSub32, ssa.OpAnd32,
			ssa.OpLoad32, ssa.OpStore32,
			ssa.OpCallDirect,
		}
		for _, op := range probe {
			if a.NeedsTemp(op) {
				t.Errorf("%s NeedsTemp(%v)=true, want false for typical ALU/memop", a.Name(), op)
			}
		}
		// FixedRegForFixedOp reports noRegister for ops that don't
		// pin their result to a specific register. We construct a
		// throwaway *ssa.Value per probe op so the call signature is
		// satisfied without depending on any internal representation.
		for _, op := range probe {
			v := &ssa.Value{Op: op}
			if r := a.FixedRegForFixedOp(v); r != noRegister {
				t.Errorf("%s FixedRegForFixedOp(%v)=%v, want noRegister", a.Name(), op, r)
			}
		}
	}
}

// TestRegInfoShiftPinsCX is amd64-only — arm64 has no CL-pin
// equivalent. SHL must pin its second arg (the shift count) to CX so
// the allocator routes around it.
func TestRegInfoShiftPinsCXAMD64(t *testing.T) {
	a := ArchAMD64
	arg0 := &ssa.Value{ID: 1, Op: ssa.OpParam, Type: ssa.TypeI32}
	arg1 := &ssa.Value{ID: 2, Op: ssa.OpParam, Type: ssa.TypeI32}
	v := &ssa.Value{ID: 3, Op: ssa.OpShl32, Type: ssa.TypeI32, Args: []*ssa.Value{arg0, arg1}}
	spec := a.RegSpec(v)
	if len(spec.Inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(spec.Inputs))
	}
	if spec.Inputs[1].Regs != 1<<amd64CX {
		t.Errorf("expected shift count (arg1) pinned to CX (%#x), got %#x", regMask(1)<<amd64CX, spec.Inputs[1].Regs)
	}
}
