package gcasm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// blockDotTree builds one 16-byte signed 8-bit dot:
//
//	add( dot(extend_low a, extend_low b), dot(extend_high a, extend_high b) )
//
// over two loaded byte vectors — the shape x64Dot8Rewrite collapses.
func blockDotTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:       "simd_p_fxdot",
		NumScalars: 1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 0}}},      // 0: a
			{Op: "v128_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 16}}},     // 1: b
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 0}}},                              // 2
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 1}}},                              // 3
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 2}, {Kind: simdfuse.ArgNode, Index: 3}}}, // 4: dot_low
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 0}}},                             // 5
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 1}}},                             // 6
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 5}, {Kind: simdfuse.ArgNode, Index: 6}}}, // 7: dot_high
			{Op: "i32x4_add", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 4}, {Kind: simdfuse.ArgNode, Index: 7}}},         // 8: result
		},
		Roots: []int{8},
	}
}

func TestX64Dot8RewriteCollapsesBlockDot(t *testing.T) {
	out, used := x64Dot8Rewrite(blockDotTree(), false)
	if !used {
		t.Fatal("x64Dot8Rewrite did not fire on the block-dot shape")
	}
	if got := out.Nodes[8].Op; got != x64OpBlockDot {
		t.Fatalf("add node not rewritten: op=%q, want %q", got, x64OpBlockDot)
	}
	// The block dot must read the two byte sources directly.
	args := out.Nodes[8].Args
	if len(args) != 2 || args[0].Index != 0 || args[1].Index != 1 {
		t.Fatalf("block-dot args = %+v, want sources 0 and 1", args)
	}
	// The two dots and four extends are absorbed.
	for _, i := range []int{2, 3, 4, 5, 6, 7} {
		if out.Nodes[i].Op != a64OpElided {
			t.Errorf("node %d = %q, want elided", i, out.Nodes[i].Op)
		}
	}
}

func TestX64Dot8RewritePortableSuppresses(t *testing.T) {
	out, used := x64Dot8Rewrite(blockDotTree(), true)
	if used {
		t.Fatal("portable mode must not rewrite")
	}
	if out.Nodes[8].Op != "i32x4_add" {
		t.Fatalf("portable tree mutated: op=%q", out.Nodes[8].Op)
	}
}

func TestX64Dot8RewriteKeepsSharedExtend(t *testing.T) {
	// If an extend feeds something else too (not single-use), the chunk
	// is not eligible and the tree is left literal.
	tr := blockDotTree()
	tr.Nodes = append(tr.Nodes, simdfuse.Node{Op: "i32x4_add", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 4}, {Kind: simdfuse.ArgNode, Index: 8}}})
	tr.Roots = []int{9}
	out, used := x64Dot8Rewrite(tr, false)
	if used {
		t.Fatal("must not rewrite when a dot has a second consumer")
	}
	if out.Nodes[8].Op != "i32x4_add" {
		t.Fatal("tree mutated despite ineligibility")
	}
}

// spineDotTree mirrors the real q8 kernel helper shape (two chunks,
// K=2): chunk A's halves are direct add siblings, while chunk B's high
// and low dots join the accumulator spine separately —
//
//	n6  = add(dot(extlow P0, extlow P1), dot(exthigh P0, exthigh P1))
//	n10 = add(n6, dot(exthigh P2, exthigh P3))
//	n14 = add(n10, dot(extlow P2, extlow P3))
//
// Both chunks must collapse to block dots.
func spineDotTree() *simdfuse.Tree {
	pin := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	return &simdfuse.Tree{
		Name:     "simd_p_fxspine",
		NumPairs: 4,
		Nodes: []simdfuse.Node{
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(0)}},  // 0
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(1)}},  // 1
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(0), nd(1)}},   // 2: lowA
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(0)}}, // 3
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(1)}}, // 4
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(3), nd(4)}},   // 5: highA
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(2), nd(5)}},           // 6: chunk A
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(2)}}, // 7
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(3)}}, // 8
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(7), nd(8)}},   // 9: highB
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(6), nd(9)}},           // 10: spine
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(2)}},  // 11
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(3)}},  // 12
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(11), nd(12)}}, // 13: lowB
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(10), nd(13)}},         // 14: spine top
		},
		Roots: []int{14},
	}
}

func TestX64Dot8RewriteCollapsesSpineChain(t *testing.T) {
	out, used := x64Dot8Rewrite(spineDotTree(), false)
	if !used {
		t.Fatal("spine chain not rewritten")
	}
	// Chunk A's block dot lives in its low-dot slot (2); chunk B's in
	// the lower of its two dot slots (9). The top add chains them.
	if out.Nodes[2].Op != x64OpBlockDot || out.Nodes[9].Op != x64OpBlockDot {
		t.Fatalf("block dots not at 2 and 9: n2=%q n9=%q", out.Nodes[2].Op, out.Nodes[9].Op)
	}
	if got := out.Nodes[9].Args; got[0].Index != 2 || got[1].Index != 3 {
		t.Fatalf("chunk B block dot reads %+v, want pair sources 2,3", got)
	}
	top := out.Nodes[14]
	if top.Op != "i32x4_add" || top.Args[0].Index != 2 || top.Args[1].Index != 9 {
		t.Fatalf("top add = %+v, want add(2, 9)", top)
	}
	for _, i := range []int{0, 1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13} {
		if out.Nodes[i].Op != a64OpElided {
			t.Errorf("node %d = %q, want elided", i, out.Nodes[i].Op)
		}
	}
}

func TestX64SpineChainEmitsTwoBlockDots(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, spineDotTree(), &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	if got := strings.Count(asm, "VPMADDWD"); got != 2 {
		t.Errorf("VPMADDWD count = %d, want 2 (one per chunk):\n%s", got, asm)
	}
	if strings.Count(asm, "PMADDWL") != 0 {
		t.Errorf("literal SSE dot remains:\n%s", asm)
	}
	if strings.Count(asm, "VZEROUPPER") != 2 {
		t.Errorf("want one VZEROUPPER per block dot (Intel dirty-upper false deps):\n%s", asm)
	}
}

// accSpineTree mirrors the fused-LOOP kernel shape: the loop-carried
// accumulator (a pair input) sits at the bottom of the add spine, so
// every add on the spine carries it —
//
//	n2  = dot(extlow P1, extlow P2)
//	n3  = add(ACC, n2)          <- ACC = ArgPairIn 0
//	n6  = dot(exthigh P1, exthigh P2)
//	n7  = add(n3, n6)           <- root (the carried value)
//
// The chunk must still collapse: the ACC rides the rebuilt chain.
func accSpineTree() *simdfuse.Tree {
	pin := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	return &simdfuse.Tree{
		Name:     "simd_p_fxacc",
		NumPairs: 3,
		Nodes: []simdfuse.Node{
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(1)}},  // 0
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(2)}},  // 1
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(0), nd(1)}},   // 2: low
			{Op: "i32x4_add", Args: []simdfuse.Arg{pin(0), nd(2)}},          // 3: ACC + low
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(1)}}, // 4
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(2)}}, // 5
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(4), nd(5)}},   // 6: high
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(3), nd(6)}},           // 7: root
		},
		Roots: []int{7},
	}
}

func TestX64Dot8RewriteCarriesAccumulator(t *testing.T) {
	out, used := x64Dot8Rewrite(accSpineTree(), false)
	if !used {
		t.Fatal("acc-spine chunk not rewritten")
	}
	// The block dot lands in the lower dot slot (2); the surviving add
	// (t=7) folds ACC (pair-in 0) with it; everything else is elided.
	if out.Nodes[2].Op != x64OpBlockDot {
		t.Fatalf("n2 = %q, want block dot", out.Nodes[2].Op)
	}
	top := out.Nodes[7]
	if top.Op != "i32x4_add" {
		t.Fatalf("top = %q, want add", top.Op)
	}
	// One arg is the ACC pair-in, the other the block dot.
	var hasAcc, hasDot bool
	for _, a := range top.Args {
		if a.Kind == simdfuse.ArgPairIn && a.Index == 0 {
			hasAcc = true
		}
		if a.Kind == simdfuse.ArgNode && a.Index == 2 {
			hasDot = true
		}
	}
	if !hasAcc || !hasDot {
		t.Fatalf("top args = %+v, want ACC pair-in 0 and node 2", top.Args)
	}
	for _, i := range []int{0, 1, 3, 4, 5, 6} {
		if out.Nodes[i].Op != a64OpElided {
			t.Errorf("node %d = %q, want elided", i, out.Nodes[i].Op)
		}
	}
}

func TestX64BlockDotEmitsAVX2(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, blockDotTree(), &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	for _, want := range []string{"VPMOVSXBW", "VPMADDWD Y3, Y2, Y2", "VEXTRACTI128 $1, Y2, X3", "VPADDD", "// avx2 dot", "VZEROUPPER"} {
		if !strings.Contains(asm, want) {
			t.Errorf("emitted asm missing %q:\n%s", want, asm)
		}
	}
}

// blockDotPairTree is the block dot over two PAIR-IN byte sources — the
// staging-order hazard case: X2 is Y2's own low half, so both sources
// must be staged before either extend runs.
func blockDotPairTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:     "simd_p_fxdotp",
		NumPairs: 2,
		Nodes: []simdfuse.Node{
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 0}}},
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 1}}},
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 0}, {Kind: simdfuse.ArgNode, Index: 1}}},
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 0}}},
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 1}}},
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 3}, {Kind: simdfuse.ArgNode, Index: 4}}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 2}, {Kind: simdfuse.ArgNode, Index: 5}}},
		},
		Roots: []int{6},
	}
}

func TestX64BlockDotStagesBothSourcesFirst(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, blockDotPairTree(), &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	// The two sources must land in DISTINCT staging registers (X2 and
	// X3), and both stagings must precede the first extend: X2 is Y2's
	// low half, so staging after the first VPMOVSXBW corrupts it.
	firstExt := strings.Index(asm, "VPMOVSXBW")
	if firstExt < 0 {
		t.Fatalf("no extend emitted:\n%s", asm)
	}
	pre := asm[:firstExt]
	if !strings.Contains(pre, "X2") || !strings.Contains(pre, "X3") {
		t.Errorf("both sources must be staged (X2 and X3) before the first extend:\n%s", asm)
	}
	if strings.Contains(asm[firstExt:], "PINSRQ") {
		t.Errorf("staging PINSRQ after the first extend corrupts Y2's low half:\n%s", asm)
	}
}

func TestX64BlockDotPortableIsLiteral(t *testing.T) {
	var b strings.Builder
	if _, _, err := x64SpliceFused(&b, blockDotTree(), &ConstPool{}, fuseTestOffs, true, 0); err != nil {
		t.Fatalf("splice: %v", err)
	}
	asm := b.String()
	if strings.Contains(asm, "VPMADDWD") || strings.Contains(asm, "VZEROUPPER") {
		t.Errorf("portable body used AVX2:\n%s", asm)
	}
	if !strings.Contains(asm, "PMADDWL") {
		t.Errorf("portable body missing the literal SSE dot:\n%s", asm)
	}
}

// TestX64LoopHoistsMemBase: a fused loop with several member loads
// pins m.M and the memSize value once in the prologue and never
// reloads them per access inside the loop body.
func TestX64LoopHoistsMemBase(t *testing.T) {
	pin := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	tr := &simdfuse.Tree{
		Name:       "simd_p_fxlhoist",
		NumScalars: 1,
		NeedsMem:   true,
		NumPairs:   1,
		Nodes: []simdfuse.Node{
			{Op: "v128_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 0}}},
			{Op: "v128_load", Args: []simdfuse.Arg{{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 16}}},
			{Op: "i16x8_add", Args: []simdfuse.Arg{nd(0), nd(1)}},
			{Op: "i16x8_add", Args: []simdfuse.Arg{nd(2), pin(0)}},
		},
		Roots: []int{3},
	}
	loop := &simdfuse.Loop{
		Tree:          tr,
		CarriedPairs:  [][2]int{{0, 3}},
		Bumps:         []simdfuse.LoopBump{{Scalar: 0, Delta: 32, DeltaScalar: -1}},
		CounterScalar: 0,
		Dec:           1,
	}
	var b strings.Builder
	spliced, _, err := x64SpliceLoop(&b, loop, &ConstPool{}, fuseTestOffs, "7", false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	loopStart := strings.Index(asm, "gcasmfxl7:")
	if loopStart < 0 {
		t.Fatalf("no loop label:\n%s", asm)
	}
	pre, body := asm[:loopStart], asm[loopStart:]
	// The prologue pins both values...
	if !strings.Contains(pre, fmt.Sprintf("MOVQ %d(R13),", fuseTestOffs.M)) {
		t.Errorf("prologue does not hoist m.M:\n%s", asm)
	}
	if !strings.Contains(pre, fmt.Sprintf("MOVQ %d(R13),", fuseTestOffs.MemSize)) {
		t.Errorf("prologue does not hoist memSize:\n%s", asm)
	}
	// ...and the loop body never touches the Module struct again.
	if strings.Contains(body, "(R13)") {
		t.Errorf("loop body reloads Module fields:\n%s", asm)
	}
}

// TestX64LoopHoistsRangeChecks: a memory64 pretest loop's strided
// window loads check once at the loop head and become single indexed
// loads inside the body.
func TestX64LoopHoistsRangeChecks(t *testing.T) {
	tr := &simdfuse.Tree{
		Name:       "simd_p_fxlrng",
		NumScalars: 1,
		NeedsMem:   true,
		NumPairs:   1,
		Addr64:     true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load_rng", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 0},
				{Kind: simdfuse.ArgConst, Const: 2},
				{Kind: simdfuse.ArgConst, Const: 0},
				{Kind: simdfuse.ArgConst, Const: 134},
			}},
			{Op: "i16x8_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
				{Kind: simdfuse.ArgPairIn, Index: 0},
			}},
		},
		Roots: []int{1},
	}
	loop := &simdfuse.Loop{
		Tree:          tr,
		CarriedPairs:  [][2]int{{0, 1}},
		Bumps:         []simdfuse.LoopBump{{Scalar: 0, Delta: 34, DeltaScalar: -1}},
		CounterScalar: 0,
		Dec:           4,
		PreTest:       true,
	}
	var b strings.Builder
	spliced, needsTrap, err := x64SpliceLoop(&b, loop, &ConstPool{}, fuseTestOffs, "9", false, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	if !needsTrap {
		t.Error("hoisted check must still request the trap label")
	}
	asm := b.String()
	loopStart := strings.Index(asm, "gcasmfxl9:")
	if loopStart < 0 {
		t.Fatalf("no loop label:\n%s", asm)
	}
	pre, body := asm[:loopStart], asm[loopStart:]
	// The prologue computes iters-1, scales by the stride, and checks
	// once (guarded against the zero-iteration entry).
	for _, want := range []string{"SHRQ $2, R12", "JZ gcasmfxh9_0", "IMUL3Q $34, R12, R12", "gcasmfxh9_0:"} {
		if !strings.Contains(pre, want) {
			t.Errorf("prologue missing %q:\n%s", want, pre)
		}
	}
	// Inside the loop: no span dance, a single folded indexed load.
	if strings.Contains(body, "$134") {
		t.Errorf("loop body still carries the window span:\n%s", body)
	}
	if !strings.Contains(body, "MOVOU 2(") {
		t.Errorf("loop body lost the folded indexed load:\n%s", body)
	}
}
