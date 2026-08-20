package gcasm

import (
	"github.com/goccy/wasm2go/internal/simdfuse"
)

// AVX2 8-bit dot selection (amd64).
//
// The quantized integer kernels compute, per 16-byte chunk, the two
// half dots
//
//	dot(extend_low_i8x16_s(a),  extend_low_i8x16_s(b))
//	dot(extend_high_i8x16_s(a), extend_high_i8x16_s(b))
//
// and sum them into an i32x4 accumulator chain. The SSE baseline
// lowers each half literally (~9 xmm ops per chunk). AVX2 does the
// whole chunk in one 256-bit pass: VPMOVSXBW sign-extends all 16
// bytes of a (and of b) into a ymm of 16 i16 lanes, VPMADDWD
// multiplies and pair-adds them into 8 i32 lanes — lanes 0..3 are
// exactly the low-half dot, lanes 4..7 the high-half — and
// VEXTRACTI128 + VPADDD fold the high 128 onto the low 128. int8*int8
// fits i16 and the pair sums fit i32, so no lane saturates; i32
// addition is associative, so re-grouping the chain's adds is
// bit-identical to the literal lowering. Five ops replace nine.
//
// The two halves of a chunk are NOT always direct siblings under one
// add: the unrolled kernels emit left-leaning chains where a chunk's
// low and high dots join the accumulator spine separately
// (add(add(prev, dot_high_B), dot_low_B)). So, like the arm64
// a64Dot8FlattenAdds, the rewrite walks each maximal i32x4_add tree
// whose leaves are all eligible half dots, pairs the leaves by their
// byte-source pair (one low + one high over the same (a, b)), and
// rebuilds the chain over the paired block dots plus any unpaired
// half dots left literal.
//
// The rewrite runs on a local copy of the tree at splice time; every
// absorbed node becomes a no-op placeholder (a64OpElided) so node
// indices stay stable for roots and loop-carried bookkeeping.
// portable (the baseline-ISA twin body) suppresses it, so a non-AVX2
// host runs the literal SSE path.
const (
	// x64OpBlockDot(a, b): the full 16-byte signed 8-bit dot of two
	// byte vectors — four i32 lanes, each the sum of its four byte
	// products (the value of dot_low + dot_high for the chunk).
	x64OpBlockDot = "i32x4_blockdot8_avx2"
)

// x64Dot8Src reports whether a byte source can feed the synthetic
// block dot directly: a member's register-resident result or a pair
// input (mirrors a64Dot8Src).
func x64Dot8Src(a simdfuse.Arg) bool {
	return a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn
}

// x64HalfDot describes one eligible half dot: an i32x4_dot_i16x8_s
// whose operands are both extend_low (high=false) or both extend_high
// (high=true) of register-readable byte sources.
type x64HalfDot struct {
	dot        int // the dot node
	e0, e1     int // the two extend nodes it consumes
	srcA, srcB simdfuse.Arg
	high       bool
}

// x64ClassifyHalfDot classifies node k, requiring the extends to exist
// solely for this dot (single use, not a region result).
func x64ClassifyHalfDot(nodes []simdfuse.Node, uses []int, isRoot []bool, k int) (x64HalfDot, bool) {
	n := &nodes[k]
	if n.Op != "i32x4_dot_i16x8_s" || len(n.Args) != 2 {
		return x64HalfDot{}, false
	}
	a0, a1 := n.Args[0], n.Args[1]
	if a0.Kind != simdfuse.ArgNode || a1.Kind != simdfuse.ArgNode || a0.Index == a1.Index {
		return x64HalfDot{}, false
	}
	e0, e1 := &nodes[a0.Index], &nodes[a1.Index]
	var high bool
	switch {
	case e0.Op == "i16x8_extend_low_i8x16_s" && e1.Op == "i16x8_extend_low_i8x16_s":
		high = false
	case e0.Op == "i16x8_extend_high_i8x16_s" && e1.Op == "i16x8_extend_high_i8x16_s":
		high = true
	default:
		return x64HalfDot{}, false
	}
	if uses[a0.Index] != 1 || uses[a1.Index] != 1 || isRoot[a0.Index] || isRoot[a1.Index] {
		return x64HalfDot{}, false
	}
	if len(e0.Args) != 1 || len(e1.Args) != 1 || !x64Dot8Src(e0.Args[0]) || !x64Dot8Src(e1.Args[0]) {
		return x64HalfDot{}, false
	}
	return x64HalfDot{dot: k, e0: a0.Index, e1: a1.Index, srcA: e0.Args[0], srcB: e1.Args[0], high: high}, true
}

// x64SrcKey is a comparable byte-source pair identity.
type x64SrcKey struct {
	ka, kb simdfuse.ArgKind
	ia, ib int
}

func x64KeyOf(h x64HalfDot) x64SrcKey {
	return x64SrcKey{ka: h.srcA.Kind, ia: h.srcA.Index, kb: h.srcB.Kind, ib: h.srcB.Index}
}

// x64Dot8Rewrite returns the tree with chunk half-dot pairs collapsed
// into synthetic AVX2 block dots, and reports whether it rewrote
// anything (the caller emits one VZEROUPPER when it did). The tree is
// returned unchanged when nothing matches or portable suppresses the
// upgrade.
func x64Dot8Rewrite(tree *simdfuse.Tree, portable bool) (*simdfuse.Tree, bool) {
	if portable {
		return tree, false
	}
	uses := make([]int, len(tree.Nodes))
	for _, n := range tree.Nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	isRoot := make([]bool, len(tree.Nodes))
	for _, r := range tree.RootList() {
		isRoot[r] = true
	}
	nodes := append([]simdfuse.Node(nil), tree.Nodes...)
	consumed := make([]bool, len(nodes))
	rewrote := false
	// Walk tops in DESCENDING index so each maximal add tree is claimed
	// from its outermost add (mirrors a64Dot8FlattenAdds).
	for t := len(nodes) - 1; t >= 0; t-- {
		if consumed[t] || !isAddAny(nodes, t) {
			continue
		}
		var leaves []x64HalfDot
		var adds []int
		// The chain may carry AT MOST ONE non-dot value — the running
		// accumulator (a loop-carried pair input, or any prior node) the
		// kernels fold each chunk into. It rides the rebuilt chain like
		// any other leaf; i32 adds are associative, so its position is
		// free.
		var extra []simdfuse.Arg
		ok := true
		var walk func(a simdfuse.Arg)
		walk = func(a simdfuse.Arg) {
			if !ok {
				return
			}
			if a.Kind == simdfuse.ArgNode {
				i := a.Index
				if isAddAny(nodes, i) && i != t && uses[i] == 1 && !isRoot[i] && !consumed[i] {
					adds = append(adds, i)
					walk(nodes[i].Args[0])
					walk(nodes[i].Args[1])
					return
				}
				if h, hok := x64ClassifyHalfDot(nodes, uses, isRoot, i); hok && uses[i] == 1 && !isRoot[i] {
					leaves = append(leaves, h)
					return
				}
			}
			// Non-dot leaf (accumulator or anything else): one allowed.
			if len(extra) == 0 {
				extra = append(extra, a)
				return
			}
			ok = false
		}
		adds = append(adds, t)
		walk(nodes[t].Args[0])
		walk(nodes[t].Args[1])
		if !ok || len(leaves) < 2 || len(adds) != len(leaves)+len(extra)-1 {
			continue
		}
		// Pair one low with one high per byte-source pair.
		lows := map[x64SrcKey][]int{} // leaf index in leaves
		highs := map[x64SrcKey][]int{}
		for li, h := range leaves {
			if h.high {
				highs[x64KeyOf(h)] = append(highs[x64KeyOf(h)], li)
			} else {
				lows[x64KeyOf(h)] = append(lows[x64KeyOf(h)], li)
			}
		}
		type pair struct{ low, high x64HalfDot }
		var pairs []pair
		paired := make([]bool, len(leaves))
		for k, ls := range lows {
			hs := highs[k]
			for len(ls) > 0 && len(hs) > 0 {
				pairs = append(pairs, pair{low: leaves[ls[0]], high: leaves[hs[0]]})
				paired[ls[0]], paired[hs[0]] = true, true
				ls, hs = ls[1:], hs[1:]
			}
		}
		if len(pairs) == 0 {
			continue
		}
		// The rebuilt chain's values: each pair's block dot lives in the
		// lower-indexed dot slot (its byte sources index below both
		// dots); unpaired half dots stay literal; the extra leaf (the
		// accumulator) rides along as-is.
		var newLeaves []simdfuse.Arg
		for _, p := range pairs {
			bd := p.low.dot
			if p.high.dot < bd {
				bd = p.high.dot
			}
			newLeaves = append(newLeaves, simdfuse.Arg{Kind: simdfuse.ArgNode, Index: bd})
		}
		for li, h := range leaves {
			if !paired[li] {
				newLeaves = append(newLeaves, simdfuse.Arg{Kind: simdfuse.ArgNode, Index: h.dot})
			}
		}
		newLeaves = append(newLeaves, extra...)
		// Order by node index (non-node leaves first: they have no
		// position constraint).
		sortArgsByIndex(newLeaves)
		sortInts(adds)
		// availableAt reports whether arg a may be referenced from a
		// chain node at index slot (post-order: node args index below).
		availableAt := func(a simdfuse.Arg, slot int) bool {
			return a.Kind != simdfuse.ArgNode || a.Index < slot
		}
		if len(newLeaves) == 1 {
			// Single pair, nothing else: the block dot must live at t
			// itself (its consumers reference t); its byte sources index
			// below every dot, so post-order holds.
			p := pairs[0]
			nodes[t] = simdfuse.Node{Op: x64OpBlockDot, Args: []simdfuse.Arg{p.low.srcA, p.low.srcB}}
			x64ElidePair(nodes, p.low, p.high, -1)
			for _, a := range adds {
				if a != t {
					nodes[a] = simdfuse.Node{Op: a64OpElided}
				}
				consumed[a] = true
			}
			rewrote = true
			continue
		}
		// Rebuild into the LARGEST len(newLeaves)-1 add slots (ending at
		// t); verify post-order before mutating.
		used := adds[len(adds)-(len(newLeaves)-1):]
		valid := true
		prev := newLeaves[0]
		for j, slot := range used {
			if !availableAt(prev, slot) || !availableAt(newLeaves[j+1], slot) {
				valid = false
				break
			}
			prev = simdfuse.Arg{Kind: simdfuse.ArgNode, Index: slot}
		}
		if !valid {
			continue
		}
		// Mutate: block dots, elisions, then the rebuilt chain.
		for _, p := range pairs {
			bd := p.low.dot
			if p.high.dot < bd {
				bd = p.high.dot
			}
			nodes[bd] = simdfuse.Node{Op: x64OpBlockDot, Args: []simdfuse.Arg{p.low.srcA, p.low.srcB}}
			x64ElidePair(nodes, p.low, p.high, bd)
		}
		usedSet := map[int]bool{}
		for _, u := range used {
			usedSet[u] = true
		}
		prev = newLeaves[0]
		for j, slot := range used {
			nodes[slot] = simdfuse.Node{Op: "i32x4_add", Args: []simdfuse.Arg{prev, newLeaves[j+1]}}
			prev = simdfuse.Arg{Kind: simdfuse.ArgNode, Index: slot}
		}
		for _, a := range adds {
			if !usedSet[a] {
				nodes[a] = simdfuse.Node{Op: a64OpElided}
			}
			consumed[a] = true
		}
		rewrote = true
	}
	if !rewrote {
		return tree, false
	}
	out := *tree
	out.Nodes = nodes
	return &out, true
}

// isAddAny reports whether node i is a two-operand i32x4_add of any
// argument kinds (the chain walk itself dispatches per kind).
func isAddAny(nodes []simdfuse.Node, i int) bool {
	n := &nodes[i]
	return n.Op == "i32x4_add" && len(n.Args) == 2
}

// x64ElidePair blanks a matched pair's absorbed nodes: the four
// extends and whichever dot slot is not keep (the block dot's home).
func x64ElidePair(nodes []simdfuse.Node, low, high x64HalfDot, keep int) {
	if low.dot != keep {
		nodes[low.dot] = simdfuse.Node{Op: a64OpElided}
	}
	if high.dot != keep {
		nodes[high.dot] = simdfuse.Node{Op: a64OpElided}
	}
	for _, e := range []int{low.e0, low.e1, high.e0, high.e1} {
		nodes[e] = simdfuse.Node{Op: a64OpElided}
	}
}

// sortArgsByIndex orders args ascending by node index, with non-node
// args (no position constraint) first.
func sortArgsByIndex(s []simdfuse.Arg) {
	key := func(a simdfuse.Arg) int {
		if a.Kind != simdfuse.ArgNode {
			return -1
		}
		return a.Index
	}
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && key(s[j]) < key(s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
