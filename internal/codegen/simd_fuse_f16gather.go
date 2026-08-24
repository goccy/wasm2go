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
	"fmt"
	"go/ast"
	"go/token"

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
			continue
		}
		snap := fb.snapshotChase()
		fb.wideChase = true
		fb.capRelax = true
		if fb.rewriteF16GatherGroup(tailIdx, chain, tableOK) {
			changed = true
		} else {
			fb.restoreChase(snap)
		}
		fb.wideChase = false
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
			return base, 0, false
		}
		a = narg
	case simdfuse.ArgSum:
		narg, cok := fb.chaseI32(fb.scalars[a.Index])
		if !cok {
			return base, 0, false
		}
		addend += int64(a.Const)
		a = narg
	case simdfuse.ArgConst:
		return base, 0, false
	}
	if a.Kind != simdfuse.ArgNode {
		return base, 0, false
	}
	n := &fb.nodes[a.Index]
	if n.Op == "scalar_i32_add" && len(n.Args) == 2 {
		x, c := n.Args[0], n.Args[1]
		if x.Kind == simdfuse.ArgConst {
			x, c = c, x
		}
		if c.Kind != simdfuse.ArgConst || x.Kind != simdfuse.ArgNode {
			return base, 0, false
		}
		addend += int64(c.Const)
		n = &fb.nodes[x.Index]
	}
	if n.Op != "scalar_i32_shl" || len(n.Args) != 2 ||
		n.Args[1].Kind != simdfuse.ArgConst || n.Args[1].Const != 2 ||
		n.Args[0].Kind != simdfuse.ArgNode {
		return base, 0, false
	}
	ld := &fb.nodes[n.Args[0].Index]
	if ld.Op != "scalar_i32_load16_u" || len(ld.Args) != 1 {
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
	ldBase, total, ok := fb.f16LaneGather(chain)
	if !ok {
		ldBase, total, ok = fb.f16WordGather(chain)
	}
	if !ok {
		return false
	}
	if total <= 0 || total > 1<<31-1 || !tableOK(uint32(total)) {
		return false
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
	ldArgs := []simdfuse.Arg{ldBase, {Kind: simdfuse.ArgConst, Const: 0}}
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: "v128_load16x4_u", Args: ldArgs})
	fb.nodeVals = append(fb.nodeVals, nil)
	nl := len(fb.nodes) - 1
	fb.nodes[tailIdx] = simdfuse.Node{Op: "f16x4_cvt", Args: []simdfuse.Arg{{Kind: simdfuse.ArgNode, Index: nl}}}
	return true
}

// f16LaneGather proves the four-scalar-loads gather form: each lane's
// index chases to a scalar_i32_load16_u, the four loads sit at one
// base +0,+2,+4,+6 in lane order, and every lane accumulates the same
// table addend. Returns the base address argument for the collapsed
// 8-byte load and the shared table addend.
func (fb *fusedTreeBuilder) f16LaneGather(chain [4]int) (simdfuse.Arg, int64, bool) {
	var bases [4]simdfuse.Arg
	var totals [4]int64
	for k := 0; k < 4; k++ {
		n := &fb.nodes[chain[k]]
		if n.Args[1].Kind != simdfuse.ArgConst {
			return simdfuse.Arg{}, 0, false
		}
		b, addend, ok := fb.f16LaneIndex(n.Args[0])
		if !ok {
			return simdfuse.Arg{}, 0, false
		}
		bases[k] = b
		totals[k] = addend + int64(n.Args[1].Const)
	}
	for k := 1; k < 4; k++ {
		if totals[k] != totals[0] {
			return simdfuse.Arg{}, 0, false
		}
	}
	// The four f16 sources must be one base value at +0,+2,+4,+6 in
	// lane order: proven structurally, with the lane delta carried by
	// exactly one constant along otherwise-identical chase trees.
	for k := 1; k < 4; k++ {
		if !fb.argOffsetBy(bases[0], bases[k], int32(2*k)) {
			// Diagnosis: report which deltas DO hold to reveal the
			// lane-order variant.
			pat := ""
			for j := 1; j < 4; j++ {
				for _, d := range []int32{-6, -4, -2, 0, 2, 4, 6} {
					if fb.argOffsetBy(bases[0], bases[j], d) {
						pat += fmt.Sprintf(" l%d=%+d", j, d)
						break
					}
				}
			}
			return simdfuse.Arg{}, 0, false
		}
	}
	return bases[0], totals[0], true
}

// f16WordGather proves the word-unpack gather form the guest emits
// when it loads four f16 values as one 64-bit word and unpacks the
// table indices by shift and mask:
//
//	lane 0: ( w        & 0xffff ) << 2
//	lane k: ( w >>u (16k-2) & 0x3fffc ) + table      (k = 1..3)
//
// The mask 0x3fffc after the pre-scaled shift selects exactly
// half-word k times 4, so each lane's index equals the classic
// per-load form; signedness of the shift is irrelevant because the
// mask discards every bit above 17. The collapsed v128_load16x4_u
// reads the same eight bytes the word load does.
func (fb *fusedTreeBuilder) f16WordGather(chain [4]int) (simdfuse.Arg, int64, bool) {
	wName := ""
	var totals [4]int64
	for k := 0; k < 4; k++ {
		n := &fb.nodes[chain[k]]
		if n.Args[1].Kind != simdfuse.ArgConst {
			return simdfuse.Arg{}, 0, false
		}
		a := n.Args[0]
		add := int64(n.Args[1].Const)
		var e ast.Expr
		switch a.Kind {
		case simdfuse.ArgScalar:
			e = fb.scalars[a.Index]
		case simdfuse.ArgSum:
			e = fb.scalars[a.Index]
			add += int64(a.Const)
		default:
			return simdfuse.Arg{}, 0, false
		}
		name, tadd, ok := fb.f16WordLane(e, k)
		if !ok {
			return simdfuse.Arg{}, 0, false
		}
		if k == 0 {
			wName = name
		} else if name != wName {
			return simdfuse.Arg{}, 0, false
		}
		totals[k] = add + tadd
	}
	for k := 1; k < 4; k++ {
		if totals[k] != totals[0] {
			return simdfuse.Arg{}, 0, false
		}
	}
	// Resolve the shared word ident to its 64-bit linear-memory load
	// and chase that load's address as the gather base.
	if fb.sc == nil || fb.sc.defBind == nil {
		return simdfuse.Arg{}, 0, false
	}
	def, isDef := fb.sc.defBind[wName]
	if !isDef || len(def.Rhs) != 1 {
		return simdfuse.Arg{}, 0, false
	}
	star, ok := def.Rhs[0].(*ast.StarExpr)
	if !ok {
		return simdfuse.Arg{}, 0, false
	}
	// The uint64 address wrapper on the 64-bit load carries no
	// memory64 information (every 8-byte deref widens its offset), so
	// addr64 is deliberately not derived from it here.
	addr, _, mok := matchMemDeref(star, "int64")
	if !mok {
		return simdfuse.Arg{}, 0, false
	}
	aarg, aok := fb.chaseAddr(addr)
	if !aok {
		return simdfuse.Arg{}, 0, false
	}
	return aarg, totals[0], true
}

// f16WordLane matches one lane of the word-unpack form, returning the
// word local's name and the table addend folded into the expression.
func (fb *fusedTreeBuilder) f16WordLane(e ast.Expr, lane int) (wName string, tadd int64, ok bool) {
	e = stripIntConv(e)
	if lane == 0 {
		// (w & mask16) << 2
		shl, sok := e.(*ast.BinaryExpr)
		if !sok || shl.Op != token.SHL {
			return "", 0, false
		}
		if s, cok := matchShiftConst(shl.Y, fb); !cok || s != 2 {
			return "", 0, false
		}
		and, aok := stripIntConv(shl.X).(*ast.BinaryExpr)
		if !aok || and.Op != token.AND {
			return "", 0, false
		}
		w, m := and.X, and.Y
		if _, isID := wordOperandIdent(w); !isID {
			w, m = m, w
		}
		name, isID := wordOperandIdent(w)
		if !isID {
			return "", 0, false
		}
		mc, mok := fb.chaseI32(m)
		if !mok || mc.Kind != simdfuse.ArgConst || uint32(mc.Const)&0xffff != 0xffff {
			return "", 0, false
		}
		return name, 0, true
	}
	// ((w >> (16*lane-2)) & 0x3fffc) + table
	addE, aok := e.(*ast.BinaryExpr)
	if !aok || addE.Op != token.ADD {
		return "", 0, false
	}
	andSide, constSide := addE.X, addE.Y
	if _, isAnd := stripIntConv(andSide).(*ast.BinaryExpr); !isAnd {
		andSide, constSide = constSide, andSide
	}
	tc, tok := fb.chaseI32(constSide)
	if !tok || tc.Kind != simdfuse.ArgConst {
		return "", 0, false
	}
	and, andok := stripIntConv(andSide).(*ast.BinaryExpr)
	if !andok || and.Op != token.AND {
		return "", 0, false
	}
	shrSide, maskSide := and.X, and.Y
	if _, isShr := stripIntConv(shrSide).(*ast.BinaryExpr); !isShr {
		shrSide, maskSide = maskSide, shrSide
	}
	mc, mok := fb.chaseI32(maskSide)
	if !mok || mc.Kind != simdfuse.ArgConst || mc.Const != 0x3fffc {
		return "", 0, false
	}
	shr, shrok := stripIntConv(shrSide).(*ast.BinaryExpr)
	if !shrok || shr.Op != token.SHR {
		return "", 0, false
	}
	if s, cok := matchShiftConst(shr.Y, fb); !cok || s != int32(16*lane-2) {
		return "", 0, false
	}
	name, isID := wordOperandIdent(shr.X)
	if !isID {
		return "", 0, false
	}
	return name, int64(tc.Const), true
}

// stripIntConv unwraps integer-width conversion calls around an
// expression (identities for the chase, which runs at pointer width).
func stripIntConv(e ast.Expr) ast.Expr {
	for {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return e
		}
		id, ok := c.Fun.(*ast.Ident)
		if !ok {
			return e
		}
		switch id.Name {
		case "int32", "uint32", "int64", "uint64", "uint":
			e = c.Args[0]
		default:
			return e
		}
	}
}

// wordOperandIdent unwraps conversions and the unsigned-view helper
// (base.Ui64) around the packed-word operand and returns its ident.
func wordOperandIdent(e ast.Expr) (string, bool) {
	e = stripIntConv(e)
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 && helperName(c.Fun) == "Ui64" {
		e = stripIntConv(c.Args[0])
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
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
		if na.Op == nb.Op && len(na.Args) == len(nb.Args) {
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
		}
		// Fall back to const-add peeling: one side may carry the lane
		// delta as an explicit `base + const` node the other side lacks
		// (lane 0 is the bare base). Each peel removes one add node, so
		// the recursion terminates.
		if x, c, ok := fb.addConstArm(nb); ok && fb.argOffsetBy(a, x, delta-c) {
			return true
		}
		if x, c, ok := fb.addConstArm(na); ok && fb.argOffsetBy(x, b, delta+c) {
			return true
		}
		return false
	case b.Kind == simdfuse.ArgNode:
		if x, c, ok := fb.addConstArm(&fb.nodes[b.Index]); ok {
			return fb.argOffsetBy(a, x, delta-c)
		}
		return false
	case a.Kind == simdfuse.ArgNode:
		if x, c, ok := fb.addConstArm(&fb.nodes[a.Index]); ok {
			return fb.argOffsetBy(x, b, delta+c)
		}
		return false
	}
	return false
}

// addConstArm decomposes a `scalar_i32_add(x, const)` node into its
// non-const arm and the constant.
func (fb *fusedTreeBuilder) addConstArm(n *simdfuse.Node) (x simdfuse.Arg, c int32, ok bool) {
	if n.Op != "scalar_i32_add" || len(n.Args) != 2 {
		return x, 0, false
	}
	x, ca := n.Args[0], n.Args[1]
	if x.Kind == simdfuse.ArgConst {
		x, ca = ca, x
	}
	if ca.Kind != simdfuse.ArgConst || x.Kind == simdfuse.ArgConst {
		return x, 0, false
	}
	return x, ca.Const, true
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
