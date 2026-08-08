package gcasm

// Unit tests for the fused-region splice synthesizers. The e2e
// transpile suite executes fused regions for real; these tests pin the
// synthesis contracts directly on hand-built descriptor trees: operand
// routing (chain through v0/X0, pool parking, pair builds), the load
// forms with immediate windows, float-argument homes, the multi-root
// epilogue, and the hard errors for malformed descriptors.

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

var fuseTestOffs = &ModuleOffsets{M: 32, MemSize: 128}

// fastTestOffs is fuseTestOffs with fast-math splice synthesis on.
var fastTestOffs = &ModuleOffsets{M: 32, MemSize: 128, Cfg: Config{FastMath: true}}

// fuseChainTree is add(extend_low(load(s0)), p0): one load, one chain,
// one pair input.
func fuseChainTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:       "simd_p_fx0",
		NumScalars: 1,
		NumPairs:   1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 0},
				{Kind: simdfuse.ArgConst, Const: 16},
			}},
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
			}},
			{Op: "i16x8_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 1},
				{Kind: simdfuse.ArgPairIn, Index: 0},
			}},
		},
	}
}

func TestA64SpliceFusedChain(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := a64SpliceFused(&b, fuseChainTree(), nil, fuseTestOffs, false)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"MOVD R0, R23",      // m saved
		"MOVWU R1, R25",     // load addr from the first scalar arg
		"ADD $16, R25, R25", // constant offset folded as an immediate
		"BLO " + a64SimdMemTrapLabel,
		"ldr q0, [x20, x25]", // load lands in v0
		"sshll v0.8h, v0.8b", // extend consumes the chained v0
		"FMOVD R2, F1",       // pair input builds into operand 1
		"VMOV R3, V1.D[1]",
		"add v0.8h, v0.8h, v1.8h",
		"FMOVD F0, R0", // single-root epilogue
		"VMOV V0.D[1], R1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	// The chain must not have parked: no pool copies for a straight line.
	if strings.Contains(body, "(fuse)") {
		t.Errorf("straight chain should not use pool copies:\n%s", body)
	}
}

func TestX64SpliceFusedChain(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := x64SpliceFused(&b, fuseChainTree(), nil, fuseTestOffs, 0)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"MOVQ AX, R13",  // m saved
		"MOVL BX, R12",  // load addr
		"ADDQ $16, R12", // constant offset immediate
		"JCS " + x64SimdMemTrapLabel,
		"MOVOU (R12), X0", // load lands in X0
		"PMOVSXBW X0, X0", // extend consumes the chain
		"MOVQ CX, X1",     // pair input builds into operand 1
		"PINSRQ $1, DI, X1",
		"PADDW X1, X0",
		"PEXTRQ $1, X0, BX", // single-root epilogue
		"MOVQ X0, AX",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

// fuseMultiRootTree shares one rng load between two extend roots and
// splats a float scale as a third root.
func fuseMultiRootTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:       "simd_p_fx1",
		NumScalars: 1,
		NumFloats:  1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load_rng", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 0},
				{Kind: simdfuse.ArgConst, Const: 0},
				{Kind: simdfuse.ArgConst, Const: -16},
				{Kind: simdfuse.ArgConst, Const: 48},
			}},
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
			}},
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
			}},
			{Op: "f32x4_splat", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgFloat, Index: 0},
			}},
		},
		Roots: []int{1, 2, 3},
	}
}

func TestA64SpliceFusedMultiRoot(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := a64SpliceFused(&b, fuseMultiRootTree(), nil, fuseTestOffs, false)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"mov v15.16b, v0.16b", // float argument saved to its home
		"MOVD $-16, R26",      // signed rlo immediate
		"TBNZ $63, R26",       // negative-start trap
		"dup v0.4s, v15.s[0]", // splat broadcasts from the home
		"FMOVD F0, R4",        // third root: results R4/R5
		"VMOV V0.D[1], R5",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	// The shared load has two consumers: it must park, and each extend
	// must copy it back into v0.
	if !strings.Contains(body, "(fuse)") {
		t.Errorf("multi-consumer load should park in the pool:\n%s", body)
	}
	// Epilogue covers all three roots: R0..R5.
	for _, want := range []string{"FMOVD F", "R0\n", "R2\n", "R4\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("epilogue missing %q:\n%s", want, body)
		}
	}
}

func TestX64SpliceFusedMultiRoot(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := x64SpliceFused(&b, fuseMultiRootTree(), nil, fuseTestOffs, 0)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"MOVOU X0, X14",  // float arguments packed into X14 lanes
		"ADDQ $-16, R12", // signed rlo immediate
		"JS " + x64SimdMemTrapLabel,
		"PSHUFD $0, X14, X0", // splat broadcasts lane 0 of the pack
		"MOVQ X0, SI",        // third root lands in result 4 (SI)
		"PEXTRQ $1, X0, R8",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

// fuseFloatPackTree carries several float arguments so the amd64
// splicer must pack them into one register and broadcast per lane.
func fuseFloatPackTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:      "simd_p_fx2",
		NumFloats: 3,
		Nodes: []simdfuse.Node{
			{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgFloat, Index: 0}}},
			{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgFloat, Index: 1}}},
			{Op: "f32x4_mul", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
				{Kind: simdfuse.ArgNode, Index: 1},
			}},
			{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgFloat, Index: 2}}},
			{Op: "f32x4_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 2},
				{Kind: simdfuse.ArgNode, Index: 3},
			}},
		},
		Roots: []int{4},
	}
}

func TestX64SpliceFusedFloatPack(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, fuseFloatPackTree(), nil, fuseTestOffs, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	for _, want := range []string{
		"MOVOU X0, X14",         // lane 0
		"INSERTPS $16, X1, X14", // lane 1
		"INSERTPS $32, X2, X14", // lane 2
		"PSHUFD $0, X14, X",     // broadcast lane 0
		"PSHUFD $85, X14, X",    // broadcast lane 1
		"PSHUFD $170, X14, X",   // broadcast lane 2
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	// X14 is reserved for the packed floats: no node result may park
	// there while floats are live.
	if strings.Contains(body, ", X14\n") && strings.Count(body, ", X14\n") > 3 {
		t.Errorf("unexpected extra writes to X14:\n%s", body)
	}
}

func TestA64SpliceFusedFloatPack(t *testing.T) {
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, fuseFloatPackTree(), nil, fuseTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	for _, want := range []string{
		", v15.s[0]", // splat of float 0 from its home
		", v14.s[0]",
		", v13.s[0]",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

// fuseScalarChainTree models a quantized kernel's scale lookup: two
// u16 loads feed shifted table lookups whose f32 product is splatted
// and multiplied into a loaded block — the shape the scalar-chase
// vocabulary internalizes.
func fuseScalarChainTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:       "simd_p_fx3",
		NumScalars: 3, // block base, second base, table base
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "scalar_i32_load16_u", Args: []simdfuse.Arg{{Kind: simdfuse.ArgSum, Index: 0, Const: 34}}},
			{Op: "scalar_i32_shl", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0}, {Kind: simdfuse.ArgConst, Const: 2},
			}},
			{Op: "scalar_i32_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 1}, {Kind: simdfuse.ArgScalar, Index: 2},
			}},
			{Op: "scalar_f32_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 2}}},
			{Op: "scalar_i32_load16_u", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 1}}},
			{Op: "scalar_i32_shl", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 4}, {Kind: simdfuse.ArgConst, Const: 2},
			}},
			{Op: "scalar_i32_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 5}, {Kind: simdfuse.ArgScalar, Index: 2},
			}},
			{Op: "scalar_f32_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 6}}},
			{Op: "scalar_f32_mul", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 3}, {Kind: simdfuse.ArgNode, Index: 7},
			}},
			{Op: "v128_load_rng", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgSum, Index: 0, Const: 2},
				{Kind: simdfuse.ArgConst, Const: 0},
				{Kind: simdfuse.ArgConst, Const: 0},
				{Kind: simdfuse.ArgConst, Const: 34},
			}},
			{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 8}}},
			{Op: "f32x4_mul", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 10},
				{Kind: simdfuse.ArgNode, Index: 9},
			}},
		},
	}
}

func TestA64SpliceFusedScalarChain(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := a64SpliceFused(&b, fuseScalarChainTree(), nil, fuseTestOffs, false)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"ADDW $34, R1, R",   // u16 address: ArgSum folded into one W-add
		"MOVHU (R20)(R",     // unchecked u16 load off the hoisted base
		"LSLW $2, R",        // shift chain in place
		"ADDW R3, R",        // table base joins as a scalar argument
		"FMOVS (R20)(R",     // unchecked f32 load
		"FMULS F",           // product in scalar scratch
		", v1.s[0]",         // splat broadcasts straight from chain scratch
		"ADDW $2, R1, R25",  // vector load address folded the same way
		"ADD $34, R25, R27", // rng end as one immediate add
		", [x20, x25]",      // register-offset vector load
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	// rlo=0 with a u32 address cannot go negative: no sign trap.
	if strings.Contains(body, "TBNZ") {
		t.Errorf("unexpected sign trap for rlo=0:\n%s", body)
	}
}

func TestX64SpliceFusedScalarChain(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := x64SpliceFused(&b, fuseScalarChainTree(), nil, fuseTestOffs, 0)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{
		"MOVWLZX (AX)(",    // unchecked u16 load
		"SHLL $2, ",        // shift chain
		"MOVSS (AX)(",      // unchecked f32 load
		"MULSS X",          // product
		"PSHUFD $0, X1, X", // splat broadcasts straight from chain scratch
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

func TestSpliceFusedErrors(t *testing.T) {
	memTree := fuseChainTree()
	var b strings.Builder
	if _, _, err := a64SpliceFused(&b, memTree, nil, nil, false); err == nil {
		t.Error("a64: memory tree without Module offsets must fail")
	}
	if _, _, err := x64SpliceFused(&b, memTree, nil, nil, 0); err == nil {
		t.Error("x64: memory tree without Module offsets must fail")
	}
	unknown := &simdfuse.Tree{
		Name:  "simd_p_fxbad",
		Nodes: []simdfuse.Node{{Op: "no_such_op"}},
	}
	if _, _, err := a64SpliceFused(&b, unknown, nil, fuseTestOffs, false); err == nil {
		t.Error("a64: unknown op must fail")
	}
	if _, _, err := x64SpliceFused(&b, unknown, nil, fuseTestOffs, 0); err == nil {
		t.Error("x64: unknown op must fail")
	}
}

// A signature whose pair block reaches past R16 must degrade to the
// capacity error (helper call kept): R17 is the loop splicers'
// LUT-hoist scratch and R18 is the platform register the assembler
// rejects outright. R16 itself is allowed — long-standing bundles
// carry proven 17-slot signatures.
func TestA64SpliceFusedPairPastR15(t *testing.T) {
	add := func(a, b simdfuse.Arg) simdfuse.Node {
		return simdfuse.Node{Op: "i16x8_add", Args: []simdfuse.Arg{a, b}}
	}
	node := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	pair := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	// 8 scalars + pair index 3 puts the pair's high half in R16 —
	// past the R0..R15 ABIInternal argument registers: gc would pass
	// that argument on the stack, so the splice must refuse.
	tree := &simdfuse.Tree{
		Name:       "simd_p_fxcap",
		NumScalars: 8,
		NumPairs:   4,
		Nodes: []simdfuse.Node{
			add(pair(0), pair(1)),
			add(node(0), pair(2)),
			add(node(1), pair(3)),
		},
	}
	var b strings.Builder
	_, _, err := a64SpliceFused(&b, tree, nil, fuseTestOffs, false)
	if err == nil || !strings.Contains(err.Error(), "pair argument past R15") {
		t.Fatalf("want pair-past-R15 capacity error, got %v", err)
	}
	// The full 16-slot shape (high half exactly R15) must splice.
	tree.NumScalars = 7
	b.Reset()
	if _, _, err := a64SpliceFused(&b, tree, nil, fuseTestOffs, false); err != nil {
		t.Fatalf("16-slot signature must splice, got %v", err)
	}
}

// The fused load16x4_u widen must be the 4h -> 4s USHLL (0x2f10a400
// base): the 8b -> 8h form (0x2f08a400) silently misplaces every high
// byte, which corrupted the K-quant and f16-gather kernels.
func TestA64SpliceFusedLoad16x4Widen(t *testing.T) {
	scalar := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: i} }
	konst := func(c int32) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c} }
	tree := &simdfuse.Tree{
		Name:       "simd_p_fxld16x4",
		NumScalars: 1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load16x4_u", Args: []simdfuse.Arg{scalar(0), konst(0)}},
		},
	}
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, tree, nil, fuseTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if !strings.Contains(body, "$0x2f10a400") {
		t.Errorf("missing 4h->4s ushll (0x2f10a400) in body:\n%s", body)
	}
	if strings.Contains(body, "$0x2f08a400") {
		t.Errorf("8b->8h ushll (0x2f08a400) must not appear:\n%s", body)
	}
}

// The dispatch stub must keep the caller's frame (NOSPLIT, $0 with
// the body's argument area) and tail-jump so arguments stay in place.
func TestA64DispatchStub(t *testing.T) {
	got := a64DispatchStub("Fn9", "Fn9dotprod", "Fn9generic", "gcasmCPUDotProd", "40")
	for _, want := range []string{
		"TEXT ·Fn9(SB), NOSPLIT, $0-40",
		"MOVBU ·gcasmCPUDotProd(SB), R27",
		"CBZ R27, 2(PC)",
		"JMP ·Fn9dotprod(SB)",
		"JMP ·Fn9generic(SB)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in stub:\n%s", want, got)
		}
	}
	if strings.Count(got, "\n") != 5 {
		t.Errorf("stub must be exactly the header plus four instructions:\n%s", got)
	}
}
