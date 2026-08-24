package gcasm

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// crossChainTree builds the interleaved-kernel per-block shape with
// two source pairs: a low sadalp chain over both, a high chain over
// the same sources, and the even/odd dword-select combine. Pairs
// 0..3 are the byte sources (b0, a0, b1, a1); pairs 4/5 carry the
// shuffle patterns as call-site constants.
func crossChainTree(evenPat, oddPat [2]uint64, highB1 simdfuse.Arg) *simdfuse.Tree {
	pin := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	nodes := []simdfuse.Node{
		{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(0)}},     // 0
		{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(1)}},     // 1
		{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(0), nd(1)}},      // 2
		{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(2)}},     // 3
		{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{pin(3)}},     // 4
		{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(3), nd(4)}},      // 5
		{Op: "i32x4_add", Args: []simdfuse.Arg{nd(2), nd(5)}},              // 6: low tail
		{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(0)}},    // 7
		{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(1)}},    // 8
		{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(7), nd(8)}},      // 9
		{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{highB1}},    // 10
		{Op: "i16x8_extend_high_i8x16_s", Args: []simdfuse.Arg{pin(3)}},    // 11
		{Op: "i32x4_dot_i16x8_s", Args: []simdfuse.Arg{nd(10), nd(11)}},    // 12
		{Op: "i32x4_add", Args: []simdfuse.Arg{nd(9), nd(12)}},             // 13: high tail
		{Op: "i8x16_shuffle", Args: []simdfuse.Arg{nd(6), nd(13), pin(4)}}, // 14
		{Op: "i8x16_shuffle", Args: []simdfuse.Arg{nd(6), nd(13), pin(5)}}, // 15
		{Op: "i32x4_add", Args: []simdfuse.Arg{nd(14), nd(15)}},            // 16: combine
	}
	return &simdfuse.Tree{
		Name: "simd_p_fxtest", NumPairs: 6, Nodes: nodes, Roots: []int{16},
		ConstPairs: map[int][2]uint64{4: evenPat, 5: oddPat},
	}
}

func countOps(nodes []simdfuse.Node) map[string]int {
	out := map[string]int{}
	for _, n := range nodes {
		out[n.Op]++
	}
	return out
}

func TestA64CrossSdotRewrite(t *testing.T) {
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	rt := a64Dot8Rewrite(tree, false, false)
	ops := countOps(rt.Nodes)
	if ops[a64OpSdotRaw] != 1 || ops[a64OpSdotRawAcc] != 1 {
		t.Fatalf("raw sdot chain not built: %v", ops)
	}
	if ops["i8x16_shuffle"] != 0 || ops["i32x4_add"] != 0 ||
		ops[a64OpSdot16] != 0 || ops[a64OpSdotAcc] != 0 {
		t.Fatalf("combine not fully absorbed: %v", ops)
	}
	// The final accumulation must sit on the combine's slot (16), so
	// consumers and the root are untouched.
	if rt.Nodes[16].Op != a64OpSdotRawAcc {
		t.Fatalf("final accumulation not at the combine slot: %s", rt.Nodes[16].Op)
	}
	// Chain: node16 accumulates the head's slot with the second pair.
	head := rt.Nodes[16].Args[0]
	if head.Kind != simdfuse.ArgNode || rt.Nodes[head.Index].Op != a64OpSdotRaw {
		t.Fatalf("chain head malformed: %+v", rt.Nodes[16].Args)
	}
	hArgs := rt.Nodes[head.Index].Args
	if hArgs[0] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 0}) ||
		hArgs[1] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 1}) {
		t.Fatalf("head sources wrong: %+v", hArgs)
	}
	tArgs := rt.Nodes[16].Args
	if tArgs[1] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2}) ||
		tArgs[2] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 3}) {
		t.Fatalf("tail sources wrong: %+v", tArgs)
	}
}

// Four or more pairs split across two alternating raw-sdot chains
// joined by one add, breaking the serial accumulation latency.
func TestA64CrossSdotRewriteDualChains(t *testing.T) {
	pin := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: i} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	cst := func(c uint32) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: int32(c)} }
	pat := func(p [2]uint64) []simdfuse.Arg {
		return []simdfuse.Arg{
			cst(uint32(p[0])), cst(uint32(p[0] >> 32)), cst(uint32(p[1])), cst(uint32(p[1] >> 32)),
		}
	}
	nodes := []simdfuse.Node{
		{Op: a64OpDot8Low, Args: []simdfuse.Arg{pin(0), pin(1)}},                                     // 0
		{Op: a64OpDot8MulLow, Args: []simdfuse.Arg{pin(2), pin(3)}},                                  // 1
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(0), nd(1)}},                                       // 2
		{Op: a64OpDot8MulLow, Args: []simdfuse.Arg{pin(4), pin(5)}},                                  // 3
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(2), nd(3)}},                                       // 4
		{Op: a64OpDot8MulLow, Args: []simdfuse.Arg{pin(6), pin(7)}},                                  // 5
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(4), nd(5)}},                                       // 6: dl
		{Op: a64OpDot8High, Args: []simdfuse.Arg{pin(0), pin(1)}},                                    // 7
		{Op: a64OpDot8MulHigh, Args: []simdfuse.Arg{pin(2), pin(3)}},                                 // 8
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(7), nd(8)}},                                       // 9
		{Op: a64OpDot8MulHigh, Args: []simdfuse.Arg{pin(4), pin(5)}},                                 // 10
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(9), nd(10)}},                                      // 11
		{Op: a64OpDot8MulHigh, Args: []simdfuse.Arg{pin(6), pin(7)}},                                 // 12
		{Op: a64OpDot8Acc, Args: []simdfuse.Arg{nd(11), nd(12)}},                                     // 13: dh
		{Op: "i8x16_shuffle_const", Args: append([]simdfuse.Arg{nd(6), nd(13)}, pat(a64EvenSel)...)}, // 14
		{Op: "i8x16_shuffle_const", Args: append([]simdfuse.Arg{nd(6), nd(13)}, pat(a64OddSel)...)},  // 15
		{Op: "i32x4_add", Args: []simdfuse.Arg{nd(14), nd(15)}},                                      // 16
	}
	isRoot := make([]bool, len(nodes))
	isRoot[16] = true
	a64CrossSdotRewrite(nodes, isRoot, nil)
	ops := countOps(nodes)
	if ops[a64OpSdotRaw] != 2 || ops[a64OpSdotRawAcc] != 2 {
		t.Fatalf("dual chains not built: %v", ops)
	}
	if nodes[16].Op != "i32x4_add" {
		t.Fatalf("join not at the combine slot: %s", nodes[16].Op)
	}
	a, b := nodes[16].Args[0], nodes[16].Args[1]
	if a.Kind != simdfuse.ArgNode || b.Kind != simdfuse.ArgNode ||
		nodes[a.Index].Op != a64OpSdotRawAcc || nodes[b.Index].Op != a64OpSdotRawAcc {
		t.Fatalf("join arms malformed: %+v / %+v", nodes[a.Index], nodes[b.Index])
	}
	// The two arms cover disjoint alternating source pairs.
	headOf := func(i int) simdfuse.Node { return nodes[nodes[i].Args[0].Index] }
	if headOf(a.Index).Op != a64OpSdotRaw || headOf(b.Index).Op != a64OpSdotRaw {
		t.Fatalf("chain heads not raw sdot")
	}
}

func TestA64CrossSdotRewriteRejectsWrongPattern(t *testing.T) {
	// A non-even/odd control constant must leave the combine intact.
	tree := crossChainTree([2]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908},
		a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	rt := a64Dot8Rewrite(tree, false, false)
	ops := countOps(rt.Nodes)
	if ops[a64OpSdotRaw] != 0 || ops[a64OpSdotRawAcc] != 0 {
		t.Fatalf("rewrite fired on wrong pattern: %v", ops)
	}
	if ops["i8x16_shuffle"] != 2 {
		t.Fatalf("shuffles disturbed: %v", ops)
	}
}

func TestA64CrossSdotRewriteRejectsUnpairedSources(t *testing.T) {
	// High chain's second leaf reads a DIFFERENT byte source: the
	// chains are not pairwise-identical and must stay literal.
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 1})
	rt := a64Dot8Rewrite(tree, false, false)
	ops := countOps(rt.Nodes)
	if ops[a64OpSdotRaw] != 0 || ops[a64OpSdotRawAcc] != 0 {
		t.Fatalf("rewrite fired on unpaired chains: %v", ops)
	}
}

// The raw ops must splice without a TBL permutation or the SDOT index
// constant, and still zero-seed the head accumulator.
func TestA64SpliceRawSdotEmission(t *testing.T) {
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	var b strings.Builder
	spliced, _, err := a64SpliceFused(&b, tree, &ConstPool{}, fuseTestOffs, false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if c := strings.Count(body, "// sdot"); c != 2 {
		t.Fatalf("want 2 sdot, got %d:\n%s", c, body)
	}
	if strings.Contains(body, "tbl") {
		t.Fatalf("raw sdot must not permute:\n%s", body)
	}
	if !strings.Contains(body, "movi") {
		t.Fatalf("head accumulator not zero-seeded:\n%s", body)
	}
}
