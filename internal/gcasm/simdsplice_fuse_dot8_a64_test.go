package gcasm

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// fuseDot8Tree is the ggml integer-dot shape: two byte loads, both
// halves sign-extended, dotted per half and summed.
func fuseDot8Tree(extraRoot bool) *simdfuse.Tree {
	load := func(scalar int) simdfuse.Node {
		return simdfuse.Node{Op: "v128_load_rng", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgScalar, Index: scalar},
			{Kind: simdfuse.ArgConst, Const: 0},
			{Kind: simdfuse.ArgConst, Const: 0},
			{Kind: simdfuse.ArgConst, Const: 16},
		}}
	}
	t := &simdfuse.Tree{
		Name:       "simd_p_fxd8",
		NumScalars: 2,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			load(0),
			load(1),
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 0}}},
			{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 1}}},
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 2}, {Kind: simdfuse.ArgNode, Index: 3}}},
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 0}}},
			{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 1}}},
			{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 5}, {Kind: simdfuse.ArgNode, Index: 6}}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 4}, {Kind: simdfuse.ArgNode, Index: 7}}},
		},
		Roots: []int{8},
	}
	if extraRoot {
		// An extend that is also a region result must survive the
		// rewrite, which then leaves the whole shape alone.
		t.Roots = []int{2, 8}
	}
	return t
}

func TestA64Dot8Rewrite(t *testing.T) {
	// The portable twin keeps the smull/sadalp form (no SDOT upgrade),
	// which is the shape this test pins.
	tree := fuseDot8Tree(false)
	rt := a64Dot8Rewrite(tree, true, false)
	if rt == tree {
		t.Fatal("eligible tree not rewritten")
	}
	if got := rt.Nodes[4].Op; got != a64OpDot8Low {
		t.Errorf("node 4: got %q, want %q", got, a64OpDot8Low)
	}
	// The add-tree flattening turns the second dot into products-only
	// and the summing add into a sadalp accumulation.
	if got := rt.Nodes[7].Op; got != a64OpDot8MulHigh {
		t.Errorf("node 7: got %q, want %q", got, a64OpDot8MulHigh)
	}
	if got := rt.Nodes[8].Op; got != a64OpDot8Acc {
		t.Errorf("node 8: got %q, want %q", got, a64OpDot8Acc)
	}
	if args := rt.Nodes[8].Args; len(args) != 2 || args[0].Index != 4 || args[1].Index != 7 {
		t.Errorf("node 8 args: %+v, want the dot and its products", rt.Nodes[8].Args)
	}
	for _, n := range []int{2, 3, 5, 6} {
		if got := rt.Nodes[n].Op; got != a64OpElided {
			t.Errorf("node %d: got %q, want elided", n, got)
		}
	}
	for _, n := range []int{4, 7} {
		args := rt.Nodes[n].Args
		if len(args) != 2 || args[0].Index != 0 || args[1].Index != 1 ||
			args[0].Kind != simdfuse.ArgNode || args[1].Kind != simdfuse.ArgNode {
			t.Errorf("node %d args: %+v, want the byte loads", n, args)
		}
	}
	// The original tree must be untouched (the amd64 splicer and the
	// Go fallback body keep the literal shape).
	if tree.Nodes[2].Op != "i16x8_extend_low_i8x16_s" {
		t.Error("rewrite mutated the shared tree")
	}
	if same := a64Dot8Rewrite(fuseDot8Tree(true), false, false); same != nil && same.Nodes[2].Op != "i16x8_extend_low_i8x16_s" {
		t.Error("root extend rewritten away")
	}
}

// The (low, high) pair over the same byte loads collapses further
// into one full 16-byte SDOT at the chain tail.
func TestA64SdotRewrite(t *testing.T) {
	tree := fuseDot8Tree(false)
	rt := a64Dot8Rewrite(tree, false, false)
	if rt == tree {
		t.Fatal("eligible tree not rewritten")
	}
	for _, n := range []int{2, 3, 4, 5, 6, 7} {
		if got := rt.Nodes[n].Op; got != a64OpElided {
			t.Errorf("node %d: got %q, want elided", n, got)
		}
	}
	if got := rt.Nodes[8].Op; got != a64OpSdot16 {
		t.Errorf("node 8: got %q, want %q", got, a64OpSdot16)
	}
	if args := rt.Nodes[8].Args; len(args) != 2 || args[0].Index != 0 || args[1].Index != 1 ||
		args[0].Kind != simdfuse.ArgNode || args[1].Kind != simdfuse.ArgNode {
		t.Errorf("node 8 args: %+v, want the byte loads", rt.Nodes[8].Args)
	}
	if a64TreeHasSdot(fuseDot8Tree(false), false, false) != true {
		t.Error("a64TreeHasSdot disagrees with the rewrite")
	}
	if a64TreeHasSdot(fuseDot8Tree(true), false, false) {
		t.Error("a64TreeHasSdot true for the unrewritable root-extend shape")
	}
}

// fuseDot8ChainTree extends the shape to two 16-byte chunks summed
// into one accumulator: dot(low0)+dot(high0)+dot(high1)+dot(low1),
// the ggml per-block order.
func fuseDot8ChainTree() *simdfuse.Tree {
	load := func(scalar int, off int32) simdfuse.Node {
		return simdfuse.Node{Op: "v128_load_rng", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgScalar, Index: scalar},
			{Kind: simdfuse.ArgConst, Const: off},
			{Kind: simdfuse.ArgConst, Const: 0},
			{Kind: simdfuse.ArgConst, Const: 16},
		}}
	}
	ext := func(op string, n int) simdfuse.Node {
		return simdfuse.Node{Op: op, Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: n}}}
	}
	dot := func(a, b int) simdfuse.Node {
		return simdfuse.Node{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: a}, {Kind: simdfuse.ArgNode, Index: b}}}
	}
	add := func(a, b int) simdfuse.Node {
		return simdfuse.Node{Op: "i32x4_add", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: a}, {Kind: simdfuse.ArgNode, Index: b}}}
	}
	return &simdfuse.Tree{
		Name:       "simd_p_fxd8c",
		NumScalars: 2,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			load(0, 0),                           // 0
			load(1, 0),                           // 1
			ext("i16x8_extend_low_i8x16_s", 0),   // 2
			ext("i16x8_extend_low_i8x16_s", 1),   // 3
			dot(2, 3),                            // 4
			ext("i16x8_extend_high_i8x16_s", 0),  // 5
			ext("i16x8_extend_high_i8x16_s", 1),  // 6
			dot(5, 6),                            // 7
			add(4, 7),                            // 8
			load(0, 16),                          // 9
			load(1, 16),                          // 10
			ext("i16x8_extend_high_i8x16_s", 9),  // 11
			ext("i16x8_extend_high_i8x16_s", 10), // 12
			dot(11, 12),                          // 13
			add(8, 13),                           // 14
			ext("i16x8_extend_low_i8x16_s", 9),   // 15
			ext("i16x8_extend_low_i8x16_s", 10),  // 16
			dot(15, 16),                          // 17
			add(14, 17),                          // 18
		},
		Roots: []int{18},
	}
}

func TestA64SdotRewriteChain(t *testing.T) {
	tree := fuseDot8ChainTree()
	rt := a64Dot8Rewrite(tree, false, false)
	if rt == tree {
		t.Fatal("eligible tree not rewritten")
	}
	// Pair (low0, high0) lands as the fresh dot on the first add, pair
	// (high1, low1) accumulates on the chain tail; everything between
	// is elided.
	if got := rt.Nodes[8].Op; got != a64OpSdot16 {
		t.Errorf("node 8: got %q, want %q", got, a64OpSdot16)
	}
	if args := rt.Nodes[8].Args; len(args) != 2 || args[0].Index != 0 || args[1].Index != 1 {
		t.Errorf("node 8 args: %+v, want the first byte loads", rt.Nodes[8].Args)
	}
	if got := rt.Nodes[18].Op; got != a64OpSdotAcc {
		t.Errorf("node 18: got %q, want %q", got, a64OpSdotAcc)
	}
	if args := rt.Nodes[18].Args; len(args) != 3 || args[0].Index != 8 ||
		args[1].Index != 9 || args[2].Index != 10 {
		t.Errorf("node 18 args: %+v, want acc 8 and the second byte loads", rt.Nodes[18].Args)
	}
	for _, n := range []int{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17} {
		if got := rt.Nodes[n].Op; got != a64OpElided {
			t.Errorf("node %d: got %q, want elided", n, got)
		}
	}
}

func TestA64SpliceFusedDot8(t *testing.T) {
	// The portable twin keeps the smull/sadalp form (no SDOT upgrade).
	var b strings.Builder
	spliced, needsTrap, err := a64SpliceFused(&b, fuseDot8Tree(false), nil, fuseTestOffs, true)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	for _, want := range []string{"// smull v", "// smull2 v", "// saddlp v", "// sadalp v"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	if strings.Contains(body, "sshll") {
		t.Errorf("extend survived the 8-bit dot selection:\n%s", body)
	}
}

func TestA64SpliceFusedSdot(t *testing.T) {
	var b strings.Builder
	spliced, needsTrap, err := a64SpliceFused(&b, fuseDot8ChainTree(), nil, fuseTestOffs, false)
	if err != nil || !spliced || !needsTrap {
		t.Fatalf("spliced=%v trap=%v err=%v", spliced, needsTrap, err)
	}
	body := b.String()
	// The permutation constant, its two TBLs per dot, the zeroed
	// accumulator and both SDOTs must all be present; no smull-form
	// instruction may survive.
	for _, want := range []string{
		"MOVD $0x0b0a030209080100, R22",
		"MOVD $0x0f0e07060d0c0504, R22",
		"// tbl v", "// movi v", "// sdot v",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
	if got := strings.Count(body, "// sdot v"); got != 2 {
		t.Errorf("want 2 sdot, got %d:\n%s", got, body)
	}
	if got := strings.Count(body, "// movi v"); got != 1 {
		t.Errorf("want 1 movi, got %d:\n%s", got, body)
	}
	if got := strings.Count(body, "// tbl v"); got != 4 {
		t.Errorf("want 4 tbl, got %d:\n%s", got, body)
	}
	for _, bad := range []string{"smull", "saddlp", "sadalp", "sshll"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s survived the SDOT selection:\n%s", bad, body)
		}
	}
}

func TestA64SpliceFusedDot8RootExtend(t *testing.T) {
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, fuseDot8Tree(true), nil, fuseTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	if body := b.String(); !strings.Contains(body, "sshll") {
		t.Errorf("literal lowering expected when an extend is a root:\n%s", body)
	}
}

// Fast-math mode: SDOT feeds on raw byte sources (no TBL) and the
// mul-by-lane + add pair fuses into FMLA.
func TestA64SpliceFusedFastMath(t *testing.T) {
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, fuseDot8ChainTree(), nil, fastTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if strings.Contains(body, "// tbl v") {
		t.Errorf("TBL emitted in fast mode:\n%s", body)
	}
	if got := strings.Count(body, "// sdot v"); got != 2 {
		t.Errorf("want 2 sdot, got %d:\n%s", got, body)
	}
}

func TestA64FmlaRewriteFast(t *testing.T) {
	// mul_lane feeding an add: splat(f) * v + acc
	tree := &simdfuse.Tree{
		Name:      "simd_p_fxfma",
		NumFloats: 1,
		NumPairs:  2,
		Nodes: []simdfuse.Node{
			{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgFloat, Index: 0}}},
			{Op: "f32x4_mul", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
				{Kind: simdfuse.ArgPairIn, Index: 0}}},
			{Op: "f32x4_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgPairIn, Index: 1},
				{Kind: simdfuse.ArgNode, Index: 1}}},
		},
		Roots: []int{2},
	}
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, tree, nil, fastTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	// The fast accumulate is SCOPED to dot-kernel trees; a tree with
	// no 8-bit dot keeps its IEEE mul + add.
	body := b.String()
	if strings.Contains(body, "// fmla v") {
		t.Errorf("fmla leaked outside dot trees:\n%s", body)
	}
}

// A dot tree with the scale tail: the mul-by-lane + add pair fuses
// into FMLA under fast math.
func TestA64FmlaRewriteDotTree(t *testing.T) {
	base := fuseDot8ChainTree()
	n := len(base.Nodes)
	base.NumFloats = 1
	base.NumPairs = 1
	base.Nodes = append(base.Nodes,
		simdfuse.Node{Op: "f32x4_convert_i32x4_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: n - 1}}}, // n
		simdfuse.Node{Op: "f32x4_splat", Args: []simdfuse.Arg{{Kind: simdfuse.ArgFloat, Index: 0}}},              // n+1
		simdfuse.Node{Op: "f32x4_mul", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: n}, {Kind: simdfuse.ArgNode, Index: n + 1}}}, // n+2
		simdfuse.Node{Op: "f32x4_add", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgPairIn, Index: 0}, {Kind: simdfuse.ArgNode, Index: n + 2}}}, // n+3
	)
	base.Roots = []int{n + 3}
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, base, nil, fastTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if !strings.Contains(body, "// fmla v") {
		t.Errorf("no fmla in fast dot tree:\n%s", body)
	}
	if strings.Contains(body, "// fadd v") {
		t.Errorf("unfused fadd survived:\n%s", body)
	}
}
