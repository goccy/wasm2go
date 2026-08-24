package codegen

import (
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// rightDeepChain builds the emitter's reduction shape: leaves d0..d7
// (nodes 0-7, standing in for dot results) and a right-deep add tree
// whose OUTERMOST node consumes the earliest leaf:
//
//	n12 = add(d0, n11); n11 = add(d1, n10); ... n8 = add(d6, d7)
//
// in post-order array form (interior nodes 8..12 ascending =
// innermost..outermost).
func rightDeepChain(op string) *fusedTreeBuilder {
	fb := &fusedTreeBuilder{}
	for i := 0; i < 8; i++ {
		fb.nodes = append(fb.nodes, simdfuse.Node{Op: "i16x8_extend_low_i8x16_s", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: i}}})
	}
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: op, Args: []simdfuse.Arg{
		{Kind: simdfuse.ArgNode, Index: 6}, {Kind: simdfuse.ArgNode, Index: 7}}})
	for k := 5; k >= 0; k-- {
		fb.nodes = append(fb.nodes, simdfuse.Node{Op: op, Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: k}, {Kind: simdfuse.ArgNode, Index: len(fb.nodes) - 1}}})
	}
	return fb
}

func TestReassociateChainsLeftFolds(t *testing.T) {
	fb := rightDeepChain("i32x4_add")
	root := len(fb.nodes) - 1
	fb.reassociateChains([]int{root})

	// Post-order stays valid: every ArgNode indexes an earlier node.
	for i, nd := range fb.nodes {
		for _, a := range nd.Args {
			if a.Kind == simdfuse.ArgNode && a.Index >= i {
				t.Fatalf("node %d references later node %d", i, a.Index)
			}
		}
	}
	// The chain is now a left fold: the first interior slot (node 8)
	// combines two leaves, and every later slot chains the previous
	// one with exactly one leaf.
	if a := fb.nodes[8].Args; a[0].Kind != simdfuse.ArgNode || a[1].Kind != simdfuse.ArgNode ||
		fb.nodes[a[0].Index].Op == "i32x4_add" || fb.nodes[a[1].Index].Op == "i32x4_add" {
		t.Fatalf("first fold slot not a two-leaf combine: %+v", fb.nodes[8].Args)
	}
	leafSeen := map[int]bool{fb.nodes[8].Args[0].Index: true, fb.nodes[8].Args[1].Index: true}
	for i := 9; i <= root; i++ {
		a := fb.nodes[i].Args
		if a[0].Kind != simdfuse.ArgNode || a[0].Index != i-1 {
			t.Fatalf("slot %d does not chain the previous partial: %+v", i, a)
		}
		if a[1].Kind != simdfuse.ArgNode || fb.nodes[a[1].Index].Op == "i32x4_add" {
			t.Fatalf("slot %d second arg not a leaf: %+v", i, a)
		}
		leafSeen[a[1].Index] = true
	}
	if len(leafSeen) != 8 {
		t.Fatalf("fold consumes %d distinct leaves, want 8", len(leafSeen))
	}
}

func TestReassociateChainsSkipsNonAssociative(t *testing.T) {
	for _, op := range []string{"f32x4_add", "i8x16_add_sat_s"} {
		fb := rightDeepChain(op)
		want := make([][]simdfuse.Arg, len(fb.nodes))
		for i, nd := range fb.nodes {
			want[i] = append([]simdfuse.Arg{}, nd.Args...)
		}
		fb.reassociateChains([]int{len(fb.nodes) - 1})
		for i, nd := range fb.nodes {
			for j, a := range nd.Args {
				if a != want[i][j] {
					t.Fatalf("%s: node %d arg %d rewritten", op, i, j)
				}
			}
		}
	}
}

func TestReassociateChainsRespectsSharedInterior(t *testing.T) {
	fb := rightDeepChain("i32x4_add")
	root := len(fb.nodes) - 1
	// A second consumer of an interior partial makes its value
	// observable: the bigger chain must keep that node as a LEAF (its
	// value intact), never absorb it as rewrite fodder. The node may
	// still head its own sub-fold, so compare the leaf multisets its
	// value sums over, not its literal arguments.
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: "i32x4_neg", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: 10}}})
	leavesOf := func(n int) map[int]int {
		out := map[int]int{}
		var rec func(i int)
		rec = func(i int) {
			if fb.nodes[i].Op != "i32x4_add" {
				out[-1-i]++ // non-add node leaf, keyed by node index
				return
			}
			for _, a := range fb.nodes[i].Args {
				if a.Kind == simdfuse.ArgNode {
					rec(a.Index)
				} else {
					out[a.Index]++ // pair leaf, keyed by pair index
				}
			}
		}
		rec(n)
		return out
	}
	wantShared := leavesOf(10)
	wantRoot := leavesOf(root)
	fb.reassociateChains([]int{root, len(fb.nodes) - 1})
	gotShared := leavesOf(10)
	gotRoot := leavesOf(root)
	for k, v := range wantShared {
		if gotShared[k] != v {
			t.Fatalf("shared node value changed: leaves %v -> %v", wantShared, gotShared)
		}
	}
	if len(gotShared) != len(wantShared) {
		t.Fatalf("shared node value changed: leaves %v -> %v", wantShared, gotShared)
	}
	for k, v := range wantRoot {
		if gotRoot[k] != v {
			t.Fatalf("root value changed: leaves %v -> %v", wantRoot, gotRoot)
		}
	}
}
