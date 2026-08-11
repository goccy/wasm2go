package gcasm

import (
	"github.com/goccy/wasm2go/internal/simdfuse"
)

// 8-bit dot selection.
//
// Quantized integer kernels compute i32x4_dot_i16x8_s over sign-extended
// byte vectors:
//
//	dot(i16x8_extend_low_i8x16_s(a),  i16x8_extend_low_i8x16_s(b))
//	dot(i16x8_extend_high_i8x16_s(a), i16x8_extend_high_i8x16_s(b))
//
// Lowered literally that is four sshll + smull + smull2 + addp per
// half — twelve vector instructions per 16-byte chunk. The same value
// is computable in two: smull (smull2 for the high half) multiplies
// the int8 lanes directly into exact int16 products (|a*b| <= 16384
// always fits), and saddlp widens adjacent pairs into the int32 sums
// the dot produces. Every intermediate is exact integer arithmetic,
// so the result is bit-identical to the literal lowering.
//
// The rewrite happens on a local copy of the tree at splice time:
// eligible dot nodes become synthetic ops (a64OpDot8Low/High) reading
// the byte sources directly, and the extend nodes they absorbed are
// replaced by no-op placeholders so node indices stay stable for
// roots and loop-carried bookkeeping. The Go fallback body and the
// amd64 splicer keep the original shape.
const (
	a64OpDot8Low  = "i32x4_dot8_low_s"
	a64OpDot8High = "i32x4_dot8_high_s"
	// Products-only variants: the smull without the saddlp. Their
	// value is the int16 product vector, consumable ONLY by the
	// accumulate op below (the add-tree flattening pairs them up).
	a64OpDot8MulLow  = "i32x4_dot8mul_low_s"
	a64OpDot8MulHigh = "i32x4_dot8mul_high_s"
	// sadalp: arg0's int32 accumulator + pairwise sums of arg1's
	// int16 products.
	a64OpDot8Acc = "i32x4_dot8_sadalp"
	// SDOT selection: a (low, high) dot pair over the SAME byte
	// sources is one full 16-byte dot. SDOT sums groups of four
	// CONSECUTIVE bytes per lane while the saddlp form sums bytes
	// {2j, 2j+1, 2j+8, 2j+9} into lane j, so both operands are first
	// permuted by TBL with [0,1,8,9, 2,3,10,11, 4,5,12,13, 6,7,14,15]:
	// every lane then receives exactly the original byte products, and
	// integer addition is associative, so lane values stay
	// bit-identical to the literal lowering. Requires FEAT_DotProd
	// (ARMv8.2 optional, mandatory from ARMv8.4 — same baseline the
	// f16 FCVT peephole already assumes).
	a64OpSdot16 = "i32x4_sdot16" // movi #0 + tbl + tbl + sdot
	// arg0's int32 accumulator + the full 16-byte dot of arg1, arg2.
	a64OpSdotAcc = "i32x4_sdot16_acc" // tbl + tbl + sdot (accumulating)
	// FMUL by element: multiplies a vector by lane 0 of a scalar
	// source register, absorbing a single-use f32x4_splat. IEEE
	// multiply per lane, identical to dup + vector fmul.
	a64OpMulLane = "f32x4_mul_lane0"
	// FMLA by element (fast-math only): acc += vec * scalar.s[0] with
	// a single rounding — what the native kernels use. Fuses a
	// single-use a64OpMulLane into its consuming f32x4_add.
	a64OpFmlaLane = "f32x4_fmla_lane0"
	a64OpElided   = "fused_elided"
)

// a64Dot8Src reports whether an extend input can feed the synthetic
// dot directly: a member's register-resident result or a pair input.
func a64Dot8Src(a simdfuse.Arg) bool {
	return a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn
}

// a64Dot8Rewrite returns the tree with eligible dot/extend triples
// collapsed into synthetic 8-bit dot ops, or the tree itself when
// nothing matches (or the rewrite is disabled). portable suppresses
// the SDOT upgrade (baseline-ISA twin bodies).
func a64Dot8Rewrite(tree *simdfuse.Tree, portable, fastMath bool) *simdfuse.Tree {
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
	rewrote := false
	for i := range nodes {
		n := &nodes[i]
		if n.Op != "i32x4_dot_i16x8_s" || len(n.Args) != 2 {
			continue
		}
		a0, a1 := n.Args[0], n.Args[1]
		if a0.Kind != simdfuse.ArgNode || a1.Kind != simdfuse.ArgNode || a0.Index == a1.Index {
			continue
		}
		e0, e1 := &nodes[a0.Index], &nodes[a1.Index]
		var newOp string
		switch {
		case e0.Op == "i16x8_extend_low_i8x16_s" && e1.Op == "i16x8_extend_low_i8x16_s":
			newOp = a64OpDot8Low
		case e0.Op == "i16x8_extend_high_i8x16_s" && e1.Op == "i16x8_extend_high_i8x16_s":
			newOp = a64OpDot8High
		default:
			continue
		}
		// The extends must exist solely for this dot: single consumer,
		// not a region result, and byte sources the emitter can read
		// from a register.
		if uses[a0.Index] != 1 || uses[a1.Index] != 1 || isRoot[a0.Index] || isRoot[a1.Index] {
			continue
		}
		if len(e0.Args) != 1 || len(e1.Args) != 1 || !a64Dot8Src(e0.Args[0]) || !a64Dot8Src(e1.Args[0]) {
			continue
		}
		n.Op = newOp
		n.Args = []simdfuse.Arg{e0.Args[0], e1.Args[0]}
		nodes[a0.Index] = simdfuse.Node{Op: a64OpElided}
		nodes[a1.Index] = simdfuse.Node{Op: a64OpElided}
		rewrote = true
	}
	mulRewrote := a64MulLaneRewrite(nodes, uses, isRoot)
	if !rewrote && !mulRewrote {
		return tree
	}
	if rewrote {
		a64Dot8FlattenAdds(nodes, isRoot)
		if !portable {
			a64SdotRewrite(nodes)
		}
	}
	if rewrote && fastMath {
		// Scope the fast-math accumulate to the dot kernels (trees the
		// 8-bit dot rewrite touched): the measured win lives there, and
		// blanket application churned other trees' pools for a loss.
		a64FmlaRewrite(nodes, uses, isRoot)
	}
	rt := *tree
	rt.Nodes = nodes
	return &rt
}

// a64FmlaRewrite (fast-math only) fuses a single-use mul-by-lane into
// its consuming f32x4_add: add(acc, mul_lane0(x, s)) becomes
// fmla_lane0(acc, x, s) — one rounding instead of two, exactly the
// native kernels' accumulate.
func a64FmlaRewrite(nodes []simdfuse.Node, uses []int, isRoot []bool) bool {
	rewrote := false
	for i := range nodes {
		n := &nodes[i]
		if n.Op != "f32x4_add" || len(n.Args) != 2 {
			continue
		}
		for k := 0; k < 2; k++ {
			ma := n.Args[k]
			if ma.Kind != simdfuse.ArgNode {
				continue
			}
			m := &nodes[ma.Index]
			if m.Op != a64OpMulLane || len(m.Args) != 2 ||
				uses[ma.Index] != 1 || isRoot[ma.Index] {
				continue
			}
			acc := n.Args[1-k]
			if acc.Kind != simdfuse.ArgNode && acc.Kind != simdfuse.ArgPairIn {
				continue
			}
			n.Op = a64OpFmlaLane
			n.Args = []simdfuse.Arg{acc, m.Args[0], m.Args[1]}
			nodes[ma.Index] = simdfuse.Node{Op: a64OpElided}
			rewrote = true
			break
		}
	}
	return rewrote
}

// a64TreeHasSdot reports whether splicing tree will emit SDOT ops
// (used by loop callers to hoist the TBL index constant). The dot
// rewrite is deterministic and idempotent, so probing a rewritten
// copy always agrees with the splice-time rewrite.
func a64TreeHasSdot(tree *simdfuse.Tree, portable, fastMath bool) bool {
	for _, n := range a64Dot8Rewrite(tree, portable, fastMath).Nodes {
		if n.Op == a64OpSdot16 || n.Op == a64OpSdotAcc {
			return true
		}
	}
	return false
}

// a64SdotRewrite upgrades the flattened sadalp chains to SDOT: each
// (low, high) product pair over the same byte sources becomes one
// full 16-byte dot (see a64OpSdot16). Chains whose leaves do not
// pair up cleanly keep the sadalp form.
func a64SdotRewrite(nodes []simdfuse.Node) {
	// Collect maximal chains: head is a Dot8Low/High, links are the
	// Acc nodes threaded through arg0.
	prevOf := make(map[int]int) // acc node -> arg0 (previous link)
	leafOf := make(map[int]int) // acc node -> arg1 (product leaf)
	isLink := func(i int) bool { _, ok := prevOf[i]; return ok }
	for i, n := range nodes {
		if n.Op == a64OpDot8Acc {
			prevOf[i] = n.Args[0].Index
			leafOf[i] = n.Args[1].Index
		}
	}
	// An acc that is arg0 of another acc is chain-internal; chain
	// tails are accs no other acc consumes.
	internal := make(map[int]bool)
	for i := range prevOf {
		if isLink(prevOf[i]) {
			internal[prevOf[i]] = true
		}
	}
	for tail := range prevOf {
		if internal[tail] {
			continue
		}
		// Walk back to the head, gathering links in chain order.
		var links []int
		at := tail
		for isLink(at) {
			links = append(links, at)
			at = prevOf[at]
		}
		head := at
		if nodes[head].Op != a64OpDot8Low && nodes[head].Op != a64OpDot8High {
			continue
		}
		for l, r := 0, len(links)-1; l < r; l, r = l+1, r-1 {
			links[l], links[r] = links[r], links[l]
		}
		// Leaves in chain order: the head, then each link's product.
		leaves := append([]int{head}, make([]int, 0, len(links))...)
		for _, a := range links {
			leaves = append(leaves, leafOf[a])
		}
		if len(leaves)%2 != 0 {
			continue
		}
		// Pair up adjacent leaves: one low + one high over identical
		// byte sources.
		type pair struct{ a, b simdfuse.Arg }
		var pairs []pair
		ok := true
		for j := 0; j+1 < len(leaves); j += 2 {
			l0, l1 := &nodes[leaves[j]], &nodes[leaves[j+1]]
			low0 := l0.Op == a64OpDot8Low || l0.Op == a64OpDot8MulLow
			low1 := l1.Op == a64OpDot8Low || l1.Op == a64OpDot8MulLow
			if low0 == low1 || len(l0.Args) != 2 || len(l1.Args) != 2 ||
				l0.Args[0] != l1.Args[0] || l0.Args[1] != l1.Args[1] {
				ok = false
				break
			}
			pairs = append(pairs, pair{l0.Args[0], l0.Args[1]})
		}
		if !ok {
			continue
		}
		// Rebuild: pair 0 lands on links[0] as a fresh dot, pair k on
		// links[2k] as an accumulation; every other chain node is
		// elided. Argument indices only ever move backward (head and
		// leaves precede their links), so post-order is preserved.
		nodes[head] = simdfuse.Node{Op: a64OpElided}
		for _, a := range links {
			nodes[leafOf[a]] = simdfuse.Node{Op: a64OpElided}
			nodes[a] = simdfuse.Node{Op: a64OpElided}
		}
		prev := links[0]
		nodes[prev] = simdfuse.Node{Op: a64OpSdot16, Args: []simdfuse.Arg{pairs[0].a, pairs[0].b}}
		for k := 1; k < len(pairs); k++ {
			at := links[2*k]
			nodes[at] = simdfuse.Node{Op: a64OpSdotAcc, Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: prev}, pairs[k].a, pairs[k].b,
			}}
			prev = at
		}
		if prev != tail {
			// The chain's consumer reads the tail index; the last
			// accumulation must land there. len(links) == 2*len(pairs)-1,
			// so links[2k] for the final k IS the tail.
			panic("sdot rewrite: chain tail mismatch")
		}
	}
}

// a64MulLaneRewrite absorbs single-use f32x4_splat feeders of
// f32x4_mul into the multiply itself (FMUL by element reads lane 0
// of the scalar source register directly).
func a64MulLaneRewrite(nodes []simdfuse.Node, uses []int, isRoot []bool) bool {
	rewrote := false
	for i := range nodes {
		n := &nodes[i]
		if n.Op != "f32x4_mul" || len(n.Args) != 2 {
			continue
		}
		for k := 0; k < 2; k++ {
			sa := n.Args[k]
			if sa.Kind != simdfuse.ArgNode {
				continue
			}
			sp := &nodes[sa.Index]
			if sp.Op != "f32x4_splat" || len(sp.Args) != 1 ||
				uses[sa.Index] != 1 || isRoot[sa.Index] {
				continue
			}
			// Float homes are stable for the whole region; a computed
			// (chain-scratch) source is only safe because the producer
			// sinks single-consumer splats next to their multiply, so
			// the scratch stays live just across the elided splat.
			src := sp.Args[0]
			srcOK := src.Kind == simdfuse.ArgFloat ||
				(src.Kind == simdfuse.ArgNode && nodes[src.Index].Class() == simdfuse.ClassF32)
			other := n.Args[1-k]
			if !srcOK || !a64Dot8Src(other) {
				continue
			}
			n.Op = a64OpMulLane
			n.Args = []simdfuse.Arg{other, src}
			nodes[sa.Index] = simdfuse.Node{Op: a64OpElided}
			rewrote = true
			break
		}
	}
	return rewrote
}

// a64Dot8FlattenAdds folds i32x4_add trees whose leaves are all
// synthetic 8-bit dots into a pairwise-accumulate chain: the first
// leaf keeps its saddlp, every other leaf becomes products-only, and
// the add nodes become sadalp accumulations. Integer adds are exact
// and associative, so the reassociation is bit-identical.
func a64Dot8FlattenAdds(nodes []simdfuse.Node, isRoot []bool) {
	uses := make([]int, len(nodes))
	for _, n := range nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	isDot := func(i int) bool {
		return nodes[i].Op == a64OpDot8Low || nodes[i].Op == a64OpDot8High
	}
	innerAdd := func(i int) bool {
		n := &nodes[i]
		return n.Op == "i32x4_add" && len(n.Args) == 2 &&
			n.Args[0].Kind == simdfuse.ArgNode && n.Args[1].Kind == simdfuse.ArgNode &&
			uses[i] == 1 && !isRoot[i]
	}
	consumed := make([]bool, len(nodes))
	// Walk tops in DESCENDING index so each maximal tree is claimed
	// from its outermost add.
	for t := len(nodes) - 1; t >= 0; t-- {
		n := &nodes[t]
		if consumed[t] || n.Op != "i32x4_add" || len(n.Args) != 2 ||
			n.Args[0].Kind != simdfuse.ArgNode || n.Args[1].Kind != simdfuse.ArgNode {
			continue
		}
		var leaves, adds []int
		ok := true
		var walk func(i int)
		walk = func(i int) {
			if !ok {
				return
			}
			switch {
			case innerAdd(i) && !consumed[i]:
				adds = append(adds, i)
				walk(nodes[i].Args[0].Index)
				walk(nodes[i].Args[1].Index)
			case isDot(i) && uses[i] == 1 && !isRoot[i]:
				leaves = append(leaves, i)
			default:
				ok = false
			}
		}
		adds = append(adds, t)
		walk(n.Args[0].Index)
		walk(n.Args[1].Index)
		if !ok || len(leaves) < 2 || len(adds) != len(leaves)-1 {
			continue
		}
		sortInts(leaves)
		sortInts(adds)
		// Post-order guarantees leaf j precedes the j-th add; keep the
		// guarantee as a hard bail so a malformed tree stays literal.
		valid := true
		for j := 1; j < len(leaves); j++ {
			if leaves[j] > adds[j-1] {
				valid = false
			}
		}
		if !valid {
			continue
		}
		for j := 1; j < len(leaves); j++ {
			l := &nodes[leaves[j]]
			if l.Op == a64OpDot8Low {
				l.Op = a64OpDot8MulLow
			} else {
				l.Op = a64OpDot8MulHigh
			}
		}
		prev := leaves[0]
		for j, a := range adds {
			nodes[a] = simdfuse.Node{Op: a64OpDot8Acc, Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: prev},
				{Kind: simdfuse.ArgNode, Index: leaves[j+1]},
			}}
			consumed[a] = true
			prev = a
		}
	}
}

func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// a64TreeFmlaCount reports how many fused multiply-adds splicing tree
// will emit (fast math only; zero otherwise). Deterministic like
// a64TreeHasSdot.
func a64TreeFmlaCount(tree *simdfuse.Tree, portable, fastMath bool) int {
	n := 0
	for _, nd := range a64Dot8Rewrite(tree, portable, fastMath).Nodes {
		if nd.Op == a64OpFmlaLane {
			n++
		}
	}
	return n
}
