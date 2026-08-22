package codegen

// f16 gather normalization inside fused windows.
//
// The guest converts f16 values through ggml's f32 lookup table one
// lane at a time: four scalar load16_u reads feed shifted indices
// into a v128_load32_zero + 3x v128_load32_lane chain over the
// table. The SSA-level RecognizeF16Gather pass cannot claim the
// shape whenever the shift amount rides a local (constant only
// through definition chasing) — exactly the form the window fusion's
// chase machinery resolves. So the normalization runs HERE, on the
// built tree: chase each lane's index expression down to a
// scalar_i32_load16_u at consecutive addresses, verify the table is
// the IEEE conversion, and rewrite the chain into
// f16x4_cvt(v128_load16x4_u(base)) — which the splicers emit as one
// D-register load plus FCVTL. Proven by direct measurement (hand
// patch first, per the asm-first rule) before being wired here.

import (
	"github.com/goccy/wasm2go/internal/simdfuse"
)

// fuseF16Gather normalizes every recognizable lane-gather group in
// the built tree and returns the (possibly remapped) roots. Any
// mismatch leaves that group untouched; the rewrite is fully
// transactional per group via the chase snapshot.
func (fb *fusedTreeBuilder) fuseF16Gather(roots []int) []int {
	if fb.sc == nil || fb.sc.em == nil || fb.sc.em.t == nil {
		return roots
	}
	tableOK := fb.sc.em.t.f16TableOK
	changed := false
	// Uses of each node by other nodes (chain-interior nodes must be
	// exclusively chain-consumed).
	uses := func() []int {
		u := make([]int, len(fb.nodes))
		for _, n := range fb.nodes {
			for _, a := range n.Args {
				if a.Kind == simdfuse.ArgNode {
					u[a.Index]++
				}
			}
		}
		return u
	}

	for tailIdx := range fb.nodes {
		if fb.nodes[tailIdx].Op != "v128_load32_lane" {
			continue
		}
		fn := ""
		if fb.sc != nil && fb.sc.em != nil && fb.sc.em.curFn != nil {
			fn = fb.sc.em.curFn.Name
		}
		_ = fn
		u := uses()
		chain, ok := fb.f16GatherChain(tailIdx, u)
		if !ok {
			fuseDebugf("f16gather: node %d (%s args=%d) no chain", tailIdx, fb.nodes[tailIdx].Op, len(fb.nodes[tailIdx].Args))
			continue
		}
		snap := fb.snapshotChase()
		fb.wideChase = true
		fb.chaseTrace = true
		fb.capRelax = true
		if fb.rewriteF16GatherGroup(tailIdx, chain, tableOK) {
			fuseDebugf("f16gather: node %d REWRITTEN", tailIdx)
			changed = true
		} else {
			fuseDebugf("f16gather: node %d chain ok but group rejected (fn=%s)", tailIdx, fn)
			fb.restoreChase(snap)
		}
		fb.wideChase = false
		fb.chaseTrace = false
		fb.capRelax = false
	}
	if !changed {
		return roots
	}
	return fb.compactDeadNodes(roots)
}

// f16GatherChain follows a lane-3 tail down to its load32_zero,
// returning the four node indices in lane order 0..3. Interior nodes
// must be single-use (the chain itself).
func (fb *fusedTreeBuilder) f16GatherChain(tailIdx int, uses []int) ([4]int, bool) {
	var chain [4]int
	n := &fb.nodes[tailIdx]
	if len(n.Args) != 4 || n.Args[2].Kind != simdfuse.ArgConst || n.Args[2].Const != 3 ||
		n.Args[3].Kind != simdfuse.ArgNode {
		return chain, false
	}
	chain[3] = tailIdx
	cur := n.Args[3].Index
	for lane := int32(2); lane >= 1; lane-- {
		c := &fb.nodes[cur]
		if c.Op != "v128_load32_lane" || len(c.Args) != 4 ||
			c.Args[2].Kind != simdfuse.ArgConst || c.Args[2].Const != lane ||
			c.Args[3].Kind != simdfuse.ArgNode || uses[cur] != 1 {
			return chain, false
		}
		chain[lane] = cur
		cur = c.Args[3].Index
	}
	z := &fb.nodes[cur]
	if z.Op != "v128_load32_zero" || len(z.Args) != 2 || uses[cur] != 1 {
		return chain, false
	}
	chain[0] = cur
	return chain, true
}

// f16LaneIndex chases one lane's address argument down to a
// scalar_i32_load16_u node, returning the load's address argument and
// the total table addend accumulated along the way.
func (fb *fusedTreeBuilder) f16LaneIndex(a simdfuse.Arg) (base simdfuse.Arg, addend int64, ok bool) {
	switch a.Kind {
	case simdfuse.ArgScalar:
		narg, cok := fb.chaseI32(fb.scalars[a.Index])
		if !cok {
			fuseDebugf("f16gather: chase fail on scalar %d: %s (interDef=%v)", a.Index, exprDebugString(fb.scalars[a.Index]), fb.interDef != nil)
			return base, 0, false
		}
		a = narg
	case simdfuse.ArgSum:
		narg, cok := fb.chaseI32(fb.scalars[a.Index])
		if !cok {
			fuseDebugf("f16gather: chase fail on SUM scalar %d: %s", a.Index, exprDebugString(fb.scalars[a.Index]))
			return base, 0, false
		}
		addend += int64(a.Const)
		a = narg
	case simdfuse.ArgConst:
		fuseDebugf("f16gather: addr is const")
		return base, 0, false
	}
	if a.Kind != simdfuse.ArgNode {
		fuseDebugf("f16gather: post-chase kind %d", a.Kind)
		return base, 0, false
	}
	n := &fb.nodes[a.Index]
	if n.Op == "scalar_i32_add" && len(n.Args) == 2 {
		x, c := n.Args[0], n.Args[1]
		if x.Kind == simdfuse.ArgConst {
			x, c = c, x
		}
		if c.Kind != simdfuse.ArgConst || x.Kind != simdfuse.ArgNode {
			fuseDebugf("f16gather: add arms kinds %d/%d", x.Kind, c.Kind)
			return base, 0, false
		}
		addend += int64(c.Const)
		n = &fb.nodes[x.Index]
	}
	if n.Op != "scalar_i32_shl" || len(n.Args) != 2 ||
		n.Args[1].Kind != simdfuse.ArgConst || n.Args[1].Const != 2 ||
		n.Args[0].Kind != simdfuse.ArgNode {
		fuseDebugf("f16gather: not shl2 (op=%s args=%d a1kind=%d a1c=%d a0kind=%d)", n.Op, len(n.Args), n.Args[1].Kind, n.Args[1].Const, n.Args[0].Kind)
		return base, 0, false
	}
	ld := &fb.nodes[n.Args[0].Index]
	if ld.Op != "scalar_i32_load16_u" || len(ld.Args) != 1 {
		fuseDebugf("f16gather: shl src not load16 (op=%s)", ld.Op)
		return base, 0, false
	}
	// Any address form is acceptable here — the group verifier proves
	// lane adjacency structurally (argOffsetBy), and the fused mem
	// emitters take chain-computed ArgNode addresses.
	return ld.Args[0], addend, true
}

// rewriteF16GatherGroup verifies one chain group end to end and
// rewrites it in place. False leaves the tree unchanged (the caller
// restores the chase snapshot).
func (fb *fusedTreeBuilder) rewriteF16GatherGroup(tailIdx int, chain [4]int, tableOK func(uint32) bool) bool {
	var bases [4]simdfuse.Arg
	var totals [4]int64
	for k := 0; k < 4; k++ {
		n := &fb.nodes[chain[k]]
		if n.Args[1].Kind != simdfuse.ArgConst {
			fuseDebugf("f16gather: lane %d memarg not const (kind=%d)", k, n.Args[1].Kind)
			return false
		}
		b, addend, ok := fb.f16LaneIndex(n.Args[0])
		if !ok {
			fuseDebugf("f16gather: lane %d index unchaseable (addr kind=%d)", k, n.Args[0].Kind)
			return false
		}
		bases[k] = b
		totals[k] = addend + int64(n.Args[1].Const)
	}
	for k := 1; k < 4; k++ {
		if totals[k] != totals[0] {
			fuseDebugf("f16gather: lane %d table addend %d != %d", k, totals[k], totals[0])
			return false
		}
	}
	if totals[0] <= 0 || totals[0] > 1<<31-1 || !tableOK(uint32(totals[0])) {
		fuseDebugf("f16gather: table %d not verified", totals[0])
		return false
	}
	// The four f16 sources must be one base value at +0,+2,+4,+6 in
	// lane order: proven structurally, with the lane delta carried by
	// exactly one constant along otherwise-identical chase trees.
	for k := 1; k < 4; k++ {
		if !fb.argOffsetBy(bases[0], bases[k], int32(2*k)) {
			fuseDebugf("f16gather: lane %d not base+%d", k, 2*k)
			return false
		}
	}
	// Capacity: the rewrite adds two nodes (the chain nodes die in
	// compaction afterwards).
	if len(fb.nodes)+2 > fusedMaxNodes {
		return false
	}
	// The rewrite removes the original per-lane call sites, so the
	// synthetic fallback body's helpers must be registered here.
	fb.sc.em.useHelper("simd_f16x4_cvt")
	if fb.addr64 {
		fb.sc.em.useHelper("simd_m64_v128_load16x4_u")
	} else {
		fb.sc.em.useHelper("simd_v128_load16x4_u")
	}
	ldArgs := []simdfuse.Arg{bases[0], {Kind: simdfuse.ArgConst, Const: 0}}
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: "v128_load16x4_u", Args: ldArgs})
	fb.nodeVals = append(fb.nodeVals, nil)
	nl := len(fb.nodes) - 1
	fb.nodes[tailIdx] = simdfuse.Node{Op: "f16x4_cvt", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: nl}}}
	return true
}

// argOffsetBy reports that b evaluates to a + delta, structurally:
// matching scalar/sum indices with the constant difference, or equal
// node trees in which exactly one constant arm carries the whole
// delta. Two separate loads of one address compare equal — the same
// no-concurrent-writer contract the chase already relies on.
func (fb *fusedTreeBuilder) argOffsetBy(a, b simdfuse.Arg, delta int32) bool {
	switch {
	case a.Kind == simdfuse.ArgScalar && b.Kind == simdfuse.ArgScalar:
		return a.Index == b.Index && delta == 0
	case a.Kind == simdfuse.ArgScalar && b.Kind == simdfuse.ArgSum:
		return a.Index == b.Index && b.Const == delta
	case a.Kind == simdfuse.ArgSum && b.Kind == simdfuse.ArgScalar:
		return a.Index == b.Index && -a.Const == delta
	case a.Kind == simdfuse.ArgSum && b.Kind == simdfuse.ArgSum:
		return a.Index == b.Index && b.Const-a.Const == delta
	case a.Kind == simdfuse.ArgConst && b.Kind == simdfuse.ArgConst:
		return b.Const-a.Const == delta
	case a.Kind == simdfuse.ArgNode && b.Kind == simdfuse.ArgNode:
		na, nb := &fb.nodes[a.Index], &fb.nodes[b.Index]
		if na.Op != nb.Op || len(na.Args) != len(nb.Args) {
			return false
		}
		if len(na.Args) == 0 {
			return delta == 0
		}
		for carry := range na.Args {
			ok := true
			for i := range na.Args {
				d := int32(0)
				if i == carry {
					d = delta
				}
				if !fb.argOffsetBy(na.Args[i], nb.Args[i], d) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	case b.Kind == simdfuse.ArgNode:
		nb := &fb.nodes[b.Index]
		if nb.Op == "scalar_i32_add" && len(nb.Args) == 2 {
			x, c := nb.Args[0], nb.Args[1]
			if x.Kind == simdfuse.ArgConst {
				x, c = c, x
			}
			if c.Kind == simdfuse.ArgConst {
				return c.Const == delta && fb.argOffsetBy(a, x, 0)
			}
		}
		return false
	case a.Kind == simdfuse.ArgNode:
		na := &fb.nodes[a.Index]
		if na.Op == "scalar_i32_add" && len(na.Args) == 2 {
			x, c := na.Args[0], na.Args[1]
			if x.Kind == simdfuse.ArgConst {
				x, c = c, x
			}
			if c.Kind == simdfuse.ArgConst {
				return -c.Const == delta && fb.argOffsetBy(x, b, 0)
			}
		}
		return false
	}
	return false
}

// compactDeadNodes drops nodes no live node reaches (stores and roots
// are live; everything else must be referenced), remaps every
// ArgNode index and the roots, and compacts the scalar parameter
// arrays the dropped nodes exclusively used.
func (fb *fusedTreeBuilder) compactDeadNodes(roots []int) []int {
	n := len(fb.nodes)
	live := make([]bool, n)
	var mark func(i int)
	mark = func(i int) {
		if live[i] {
			return
		}
		live[i] = true
		for _, a := range fb.nodes[i].Args {
			if a.Kind == simdfuse.ArgNode {
				mark(a.Index)
			}
		}
	}
	for _, r := range roots {
		mark(r)
	}
	for i, nd := range fb.nodes {
		if simdfuse.IsStore(nd.Op) {
			mark(i)
		}
	}
	remap := make([]int, n)
	var newNodes []simdfuse.Node
	newNodeVals := fb.nodeVals[:0:0]
	for i := 0; i < n; i++ {
		if !live[i] {
			remap[i] = -1
			continue
		}
		remap[i] = len(newNodes)
		newNodes = append(newNodes, fb.nodes[i])
		newNodeVals = append(newNodeVals, fb.nodeVals[i])
	}
	for i := range newNodes {
		for ai := range newNodes[i].Args {
			if newNodes[i].Args[ai].Kind == simdfuse.ArgNode {
				newNodes[i].Args[ai].Index = remap[newNodes[i].Args[ai].Index]
			}
		}
	}
	fb.nodes = newNodes
	fb.nodeVals = newNodeVals
	newRoots := make([]int, len(roots))
	for i, r := range roots {
		newRoots[i] = remap[r]
	}

	// Scalar parameter compaction: keep only indices some live node
	// still references.
	usedScalar := map[int]bool{}
	for _, nd := range fb.nodes {
		for _, a := range nd.Args {
			if a.Kind == simdfuse.ArgScalar || a.Kind == simdfuse.ArgSum {
				usedScalar[a.Index] = true
			}
		}
	}
	sremap := make([]int, len(fb.scalars))
	newScalars := fb.scalars[:0:0]
	newOwner := fb.scalarOwner[:0:0]
	newSrc := fb.scalarSrc[:0:0]
	for i := range fb.scalars {
		if !usedScalar[i] {
			sremap[i] = -1
			continue
		}
		sremap[i] = len(newScalars)
		newScalars = append(newScalars, fb.scalars[i])
		newOwner = append(newOwner, fb.scalarOwner[i])
		newSrc = append(newSrc, fb.scalarSrc[i])
	}
	for i := range fb.nodes {
		for ai := range fb.nodes[i].Args {
			a := &fb.nodes[i].Args[ai]
			if a.Kind == simdfuse.ArgScalar || a.Kind == simdfuse.ArgSum {
				a.Index = sremap[a.Index]
			}
		}
	}
	fb.scalars = newScalars
	fb.scalarOwner = newOwner
	fb.scalarSrc = newSrc
	// The dedup maps hold stale indices now; the rewrite runs after
	// every walk, so nothing consults them again.
	fb.scalarDedup = nil
	return newRoots
}
