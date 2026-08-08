package ssa

// domtree.go exposes the control-flow analyses the structured-emit
// stage needs: dominators, post-dominators, back-edge / loop-header
// detection, and a reducibility check. All operate on the block CFG
// and are independent of value-level IR.

// Dominators returns the immediate-dominator map for f's CFG, computed
// by the Cooper-Harvey-Kennedy iterative algorithm. idom[Entry] is the
// Entry block itself; every other reachable block maps to its unique
// immediate dominator.
func Dominators(f *Func) map[BlockID]*Block {
	idom, _ := iterativeDom(f.Entry, cfgSuccs, f.Blocks)
	return idom
}

// cfgSuccs is the plain successor list. Branch-based exception handling
// reaches handlers through real edges, so no virtual edges are needed.
func cfgSuccs(b *Block) []*Block {
	out := make([]*Block, 0, len(b.Succs))
	for _, e := range b.Succs {
		out = append(out, e.Block)
	}
	return out
}

// PostDominators returns the immediate-post-dominator map: idom of the
// reverse CFG rooted at a virtual exit that all Ret / Unreachable
// blocks flow into. A block whose post-dominator is the virtual exit
// maps to nil — it has no real post-dominator inside the function.
func PostDominators(f *Func) map[BlockID]*Block {
	// Virtual exit: a synthetic block all function-exit blocks point
	// to. Build a reverse-edge adjacency where the exit is the root.
	exits := []*Block{}
	for _, b := range f.Blocks {
		if b.Kind == BlockRet || b.Kind == BlockUnreachable || len(b.Succs) == 0 {
			exits = append(exits, b)
		}
	}
	virtual := &Block{ID: -1}
	// preds of a block in the reverse graph = succs in the forward
	// graph; the virtual exit's "succs" (reverse) are the exit blocks.
	revSuccs := func(b *Block) []*Block {
		if b == virtual {
			return exits
		}
		out := make([]*Block, 0, len(b.Preds))
		for _, e := range b.Preds {
			out = append(out, e.Block)
		}
		return out
	}
	all := append([]*Block{virtual}, f.Blocks...)
	idom, _ := iterativeDom(virtual, revSuccs, all)
	// Translate: drop the virtual root; a block whose post-dominator
	// is the virtual exit becomes nil.
	out := make(map[BlockID]*Block, len(f.Blocks))
	for _, b := range f.Blocks {
		d := idom[b.ID]
		if d == nil || d == virtual {
			out[b.ID] = nil
			continue
		}
		out[b.ID] = d
	}
	return out
}

// iterativeDom runs Cooper-Harvey-Kennedy over a CFG defined by `root`
// and a successor function. `all` is every node (used only to size
// maps). Returns the immediate-dominator map and the reverse-postorder
// numbering.
func iterativeDom(root *Block, succs func(*Block) []*Block, all []*Block) (map[BlockID]*Block, map[BlockID]int) {
	// Reverse-postorder via iterative DFS.
	seen := map[BlockID]bool{}
	var post []*Block
	type frame struct {
		b  *Block
		ss []*Block
		i  int
	}
	stack := []frame{{root, succs(root), 0}}
	seen[root.ID] = true
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.i < len(top.ss) {
			s := top.ss[top.i]
			top.i++
			if s != nil && !seen[s.ID] {
				seen[s.ID] = true
				stack = append(stack, frame{s, succs(s), 0})
			}
			continue
		}
		post = append(post, top.b)
		stack = stack[:len(stack)-1]
	}
	rpo := make([]*Block, len(post))
	for i, b := range post {
		rpo[len(post)-1-i] = b
	}
	rpoNum := make(map[BlockID]int, len(rpo))
	for i, b := range rpo {
		rpoNum[b.ID] = i
	}
	// Reverse-edge lookup for the predecessor scan.
	preds := map[BlockID][]*Block{}
	for _, b := range rpo {
		for _, s := range succs(b) {
			if s != nil {
				preds[s.ID] = append(preds[s.ID], b)
			}
		}
	}

	idom := map[BlockID]*Block{root.ID: root}
	intersect := func(a, b *Block) *Block {
		for a != b {
			for rpoNum[a.ID] > rpoNum[b.ID] {
				a = idom[a.ID]
			}
			for rpoNum[b.ID] > rpoNum[a.ID] {
				b = idom[b.ID]
			}
		}
		return a
	}
	for changed := true; changed; {
		changed = false
		for _, b := range rpo {
			if b == root {
				continue
			}
			var nd *Block
			for _, p := range preds[b.ID] {
				if idom[p.ID] == nil {
					continue
				}
				if nd == nil {
					nd = p
				} else {
					nd = intersect(p, nd)
				}
			}
			if nd != nil && idom[b.ID] != nd {
				idom[b.ID] = nd
				changed = true
			}
		}
	}
	return idom, rpoNum
}

// BackEdges returns the CFG back-edges: an edge src→dst where dst
// dominates src. In a reducible CFG every cycle has exactly one such
// edge and dst is that loop's header.
func BackEdges(f *Func) [][2]*Block {
	idom := Dominators(f)
	dominates := func(a, b *Block) bool {
		for x := b; x != nil; x = idom[x.ID] {
			if x == a {
				return true
			}
			if idom[x.ID] == x {
				break
			}
		}
		return false
	}
	var edges [][2]*Block
	for _, b := range f.Blocks {
		for _, e := range b.Succs {
			if dominates(e.Block, b) {
				edges = append(edges, [2]*Block{b, e.Block})
			}
		}
	}
	return edges
}

// LoopHeaders returns the set of blocks that are the target of at
// least one back-edge.
func LoopHeaders(f *Func) map[BlockID]bool {
	hdrs := map[BlockID]bool{}
	for _, e := range BackEdges(f) {
		hdrs[e[1].ID] = true
	}
	return hdrs
}

// IsReducible reports whether f's CFG is reducible — every retreating
// edge (an edge to an ancestor in the DFS tree) is a back-edge (target
// dominates source). Structured-control wasm always lowers to a
// reducible CFG; an irreducible result would signal a lowering bug.
func IsReducible(f *Func) bool {
	idom := Dominators(f)
	dominates := func(a, b *Block) bool {
		for x := b; x != nil; x = idom[x.ID] {
			if x == a {
				return true
			}
			if idom[x.ID] == x {
				break
			}
		}
		return false
	}
	// DFS; classify edges. A retreating edge whose target does not
	// dominate its source means irreducibility.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[BlockID]int{}
	reducible := true
	var dfs func(b *Block)
	dfs = func(b *Block) {
		color[b.ID] = gray
		for _, e := range b.Succs {
			s := e.Block
			switch color[s.ID] {
			case white:
				dfs(s)
			case gray:
				// retreating edge — must be a back-edge
				if !dominates(s, b) {
					reducible = false
				}
			}
		}
		color[b.ID] = black
	}
	if f.Entry != nil {
		dfs(f.Entry)
	}
	return reducible
}
