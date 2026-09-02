package gcasm

import (
	"sort"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// Cross-chain raw dot selection (amd64).
//
// Interleaved-layout kernels (ggml's q8_0x4 repack gemv/gemm) keep
// TWO i32x4_add chains per block — one over all the extend_low half
// dots, one over all the extend_high half dots of the same byte-source
// pairs — and combine them with the even/odd dword-select shuffles:
//
//	add(shuffle(dl, dh, even), shuffle(dl, dh, odd))
//
// Per output lane that is the product sum of one FOUR-CONSECUTIVE-BYTE
// group, summed over the chains' common leaf sequence (see the arm64
// twin a64CrossSdotRewrite for the lane algebra). The x64Dot8Rewrite
// (low, high)-pairing never fires on this shape: a chunk's low and
// high dots live in different chains.
//
// The rewrite replaces both chains, both shuffles and the combine with
// a chain of synthetic raw block dots. The AVX2 emission computes each
// 16-byte leaf in the 8-lane madd domain and collapses to the 4-byte
// grouping in-register:
//
//	VPMOVSXBW  a, Y2         ; 16 x i16
//	VPMOVSXBW  b, Y3
//	VPMADDWD   Y3, Y2, Y2    ; 8 x i32 two-byte pair sums p0..p7
//	VPHADDD    Y2, Y2, Y2    ; [p01, p23, ., . | p45, p67, ., .]
//	VEXTRACTI128 $1, Y2, X3
//	VPUNPCKLQDQ  X3, X2, dst ; [p01, p23, p45, p67]
//
// i16 products of i8 lanes cannot overflow and VPMADDWD accumulates
// into i32, so every step is exact for ALL inputs (unlike the
// VPSIGNB/VPMADDUBSW route native kernels use, which wraps on -128);
// i32 wraparound addition is associative and commutative, so
// regrouping the chains' adds per leaf is bit-identical. Like the
// block dot this is a feature-body-only upgrade: portable twins keep
// the literal SSE lowering.
const (
	// x64OpRawDot(a, b): the 16-byte signed 8-bit dot with SDOT's
	// natural grouping — lane j sums the products of bytes 4j..4j+3.
	// Self-contained (collapses in-place); used for single-leaf
	// chains and as the fallback when the wide form is unavailable.
	x64OpRawDot = "i32x4_rawdot8_avx2"
	// x64OpRawDotAcc(acc, a, b): acc + the raw dot, acc and result in
	// the collapsed 4-lane domain. acc is always a rebuilt chain node
	// (ArgNode), never a pair input.
	x64OpRawDotAcc = "i32x4_rawdot8_acc_avx2"
	// Wide-chain forms: the accumulation stays in the 8-lane VPMADDWD
	// pair domain across one full ymm — 4 ops per leaf, only the two
	// unavoidable VPMOVSXBW lane crossings — and collapses ONCE per
	// chain (the Zen 3 lesson: per-leaf ymm collapses lose to their
	// own lane-crossing shuffles). The ymm upper half of the running
	// value must survive between links, so these are selected only
	// for fully-VEX trees, where the region defers VZEROUPPER to its
	// exit and every other write is VEX (upper-zeroing only for its
	// own destination).
	x64OpRawDotWide    = "i32x8_rawdotwide8_avx2"     // (a, b)
	x64OpRawDotWideAcc = "i32x8_rawdotwide8_acc_avx2" // (acc, a, b)
	// x64OpRawDotFold(v): collapse the 8-lane pair-domain value to
	// the four-consecutive-byte grouping.
	x64OpRawDotFold = "i32x4_rawdotfold_avx2"
)

// x64CrossDotRewrite matches the cross-chain combine shape on the RAW
// node forms (adds over dot(extend, extend) leaves — nothing here has
// been touched by the pairing walk, which skips all-low/all-high
// chains) and rebuilds it as a raw-dot chain. wide selects the
// pair-domain chain forms (see the op comments); the caller falls
// back to the self-contained per-leaf form for trees whose emission
// is not fully VEX. Mutates nodes in place; reports whether anything
// was rewritten.
func x64CrossDotRewrite(nodes []simdfuse.Node, isRoot []bool, constPairs map[int][2]uint64, wide bool) bool {
	uses := make([]int, len(nodes))
	for _, n := range nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	// rawChainOf collects the half-dot leaves of the add spine rooted
	// at tail, all of the required lowness, in deterministic in-order
	// walk order, plus every absorbed node (adds, dots, extends).
	// Interior values must be unobservable (single use, not a root).
	rawChainOf := func(tail int, low bool) (leaves []x64HalfDot, all []int, ok bool) {
		ok = true
		var walk func(a simdfuse.Arg, isTail bool)
		walk = func(a simdfuse.Arg, isTail bool) {
			if !ok {
				return
			}
			if a.Kind != simdfuse.ArgNode {
				ok = false
				return
			}
			i := a.Index
			if !isTail && (uses[i] != 1 || isRoot[i]) {
				ok = false
				return
			}
			if isAddAny(nodes, i) {
				if nodes[i].Args[0].Kind != simdfuse.ArgNode || nodes[i].Args[1].Kind != simdfuse.ArgNode {
					ok = false
					return
				}
				all = append(all, i)
				walk(nodes[i].Args[0], false)
				walk(nodes[i].Args[1], false)
				return
			}
			h, hok := x64ClassifyHalfDot(nodes, uses, isRoot, i)
			if !hok || h.high == low {
				ok = false
				return
			}
			leaves = append(leaves, h)
			all = append(all, i, h.e0, h.e1)
		}
		walk(simdfuse.Arg{Kind: simdfuse.ArgNode, Index: tail}, true)
		if !ok || len(leaves) == 0 {
			return nil, nil, false
		}
		return leaves, all, true
	}
	rewrote := false
	for c := len(nodes) - 1; c >= 0; c-- {
		n := &nodes[c]
		if n.Op != "i32x4_add" || len(n.Args) != 2 ||
			n.Args[0].Kind != simdfuse.ArgNode || n.Args[1].Kind != simdfuse.ArgNode {
			continue
		}
		e, o := n.Args[0].Index, n.Args[1].Index
		ex, ey, eEven, eok := crossSelKind(nodes, constPairs, e)
		ox, oy, oEven, ook := crossSelKind(nodes, constPairs, o)
		if !eok || !ook || eEven == oEven || ex != ox || ey != oy {
			continue
		}
		if uses[e] != 1 || uses[o] != 1 || isRoot[e] || isRoot[o] {
			continue
		}
		// Both shuffles read (dl, dh); each chain tail is consumed by
		// exactly the two shuffles.
		dl, dh := ex, ey
		if uses[dl] != 2 || uses[dh] != 2 || isRoot[dl] || isRoot[dh] {
			continue
		}
		lowLeaves, lowAll, lok := rawChainOf(dl, true)
		highLeaves, highAll, hok := rawChainOf(dh, false)
		if !lok || !hok || len(lowLeaves) != len(highLeaves) {
			continue
		}
		paired := true
		for j := range lowLeaves {
			if lowLeaves[j].srcA != highLeaves[j].srcA || lowLeaves[j].srcB != highLeaves[j].srcB {
				paired = false
				break
			}
		}
		if !paired {
			continue
		}
		// Rebuild: a raw-dot chain over the common sources. Chain
		// nodes land on the low chain's dot slots (ascending — each
		// already follows its own byte sources in post-order); the
		// final accumulation lands on the combine node so its
		// consumers read the same index. The accumulation link is one
		// VPADDD (1 cycle), so a single chain suffices — the a64
		// twin's dual-chain latency split has nothing to win here.
		k := len(lowLeaves)
		// Chain nodes land on the low dots' slots in ascending index
		// order, each carrying its own slot's sources (their indices
		// precede the dot, so post-order holds at every link). The
		// pairing above was positional; the chain's summation order is
		// free (associative), so re-sorting the (slot, sources)
		// triples together is exact.
		rl := append([]x64HalfDot(nil), lowLeaves...)
		sort.Slice(rl, func(i, j int) bool { return rl[i].dot < rl[j].dot })
		srcArgs := make([][2]simdfuse.Arg, k)
		slots := make([]int, k)
		for j, h := range rl {
			srcArgs[j] = [2]simdfuse.Arg{h.srcA, h.srcB}
			slots[j] = h.dot
		}
		for _, i := range lowAll {
			nodes[i] = simdfuse.Node{Op: a64OpElided}
		}
		for _, i := range highAll {
			nodes[i] = simdfuse.Node{Op: a64OpElided}
		}
		nodes[e] = simdfuse.Node{Op: a64OpElided}
		nodes[o] = simdfuse.Node{Op: a64OpElided}
		switch {
		case k == 1:
			nodes[c] = simdfuse.Node{Op: x64OpRawDot, Args: []simdfuse.Arg{srcArgs[0][0], srcArgs[0][1]}}
		case wide:
			// Pair-domain chain: the last leaf's accumulation lands on
			// the highest slot and the fold on the combine node, so
			// consumers keep reading c.
			prev := slots[0]
			nodes[prev] = simdfuse.Node{Op: x64OpRawDotWide, Args: []simdfuse.Arg{srcArgs[0][0], srcArgs[0][1]}}
			for j := 1; j < k; j++ {
				nodes[slots[j]] = simdfuse.Node{Op: x64OpRawDotWideAcc, Args: []simdfuse.Arg{
					{Kind: simdfuse.ArgNode, Index: prev}, srcArgs[j][0], srcArgs[j][1],
				}}
				prev = slots[j]
			}
			nodes[c] = simdfuse.Node{Op: x64OpRawDotFold, Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: prev},
			}}
		default:
			prev := slots[0]
			nodes[prev] = simdfuse.Node{Op: x64OpRawDot, Args: []simdfuse.Arg{srcArgs[0][0], srcArgs[0][1]}}
			for j := 1; j < k-1; j++ {
				nodes[slots[j]] = simdfuse.Node{Op: x64OpRawDotAcc, Args: []simdfuse.Arg{
					{Kind: simdfuse.ArgNode, Index: prev}, srcArgs[j][0], srcArgs[j][1],
				}}
				prev = slots[j]
			}
			nodes[c] = simdfuse.Node{Op: x64OpRawDotAcc, Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: prev}, srcArgs[k-1][0], srcArgs[k-1][1],
			}}
		}
		for _, i := range append(append([]int{}, lowAll...), highAll...) {
			uses[i] = 0
		}
		rewrote = true
	}
	return rewrote
}
