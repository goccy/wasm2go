package codegen

// SIMD chain fusion, codegen side (see internal/simdfuse for the
// shared descriptor and the architecture note).
//
// The scalarizer's per-call rewriting still round-trips every value
// between the vector file and GPR pairs, and gc spills the pairs
// between ops. Fusing a whole nested tree of SIMD calls into ONE
// synthetic helper removes the intermediates from Go entirely: the
// gcasm backend splices the fused call with every internal edge kept
// in vector registers, and the pure fallback runs the synthetic
// helper's ordinary Go body.
//
// This file owns shape detection (tryFuse), shape interning on the
// translator, and emission of the synthetic helpers' Go bodies.

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// Fused-signature caps. The whole signature must ride integer
// registers on BOTH ABIs; amd64's nine (AX,BX,CX,DI,SI,R8,R9,R10,R11)
// is the binding one — its fused loads make do with two scratch
// registers (R12 plus AX, which frees once m is saved) so all nine
// stay available for arguments. A whole q8_0 dot-kernel iteration
// (four load addresses, the accumulator pair, and the scale-splat
// pair) fits exactly.
const (
	fusedMaxIntRegs = 9
	fusedMaxFloats  = 4
	fusedMaxNodes   = 320
	fusedMaxShapes  = 1024
	// fusedMaxRoots bounds a multi-root window: 2 result registers per
	// root, and both ABIs return the first 8+ results in registers.
	fusedMaxRoots = 4
	// fusedPoolBudget is the amd64 vector budget outside the X0..X3
	// body scratch (X4..X14; X15 is the ABI zero register). All float
	// arguments are packed into the lanes of ONE register at the top
	// of the budget (fusedMaxFloats = one v128's four float32 lanes),
	// so the walk's peak-live bound is fusedPoolBudget minus one when
	// the window carries any float. arm64 is roomier (homes v12..v15,
	// pool v16..v30) and never binds.
	fusedPoolBudget = 11
	// fusedMaxIntSlots bounds the TOTAL integer argument slots of a
	// fused signature (register + stack), INCLUDING m. arm64
	// ABIInternal passes integer arguments in R0..R15 only — sixteen
	// slots — so this cap is a hard architectural bound there; a
	// seventeenth argument would be passed on the stack by gc while
	// the splice reads a register, yielding silent garbage. amd64
	// reads slots past its nine registers from the ABIInternal stack
	// sequence. Scalars (addresses the body indexes with, loop
	// counters, stride deltas) must stay register-resident on both
	// arches — only PAIR arguments may overflow.
	fusedMaxIntSlots = 16
)

// fusedMemOps are the memory ops fusion accepts, mapped to their
// scalar arity after the leading m (addr, offset[, rlo, span]). These
// are this package's own op vocabulary (the emitter and the bounds
// pass produce exactly these names), not foreign strings.
var fusedMemOps = map[string]int{
	"simd_v128_load":         2,
	"simd_v128_load_nc":      2,
	"simd_v128_load_rng":     4,
	"simd_v128_load32_zero":  2,
	"simd_v128_load32_splat": 2,
	"simd_v128_load16x4_u":   2,
	// load32_lane additionally consumes a v128 operand (the vector the
	// lane inserts into); the walk accounts for it via the mark.
	"simd_v128_load32_lane": 3,
}

// fusedStoreOps are the store SINKS fusion accepts: scalar arity
// (addr, offset) before the v128 value. Stores join windows as
// statements; the scheduler keeps every memory op in original order,
// so store-load and store-store ordering is preserved outright.
var fusedStoreOps = map[string]int{
	"simd_v128_store": 2,
	// f32x4 -> packed f16 store (idiom semantics); addr + offset
	// scalars plus the v128 value operand, like simd_v128_store.
	"simd_v128_f16x4_cvt_store": 2,
}

// isMemHelperOp reports whether a normalized node op is one of the
// vector memory ops (loads; stores are classified by IsStore).
func isMemHelperOp(op string) bool {
	_, ok := fusedMemOps["simd_"+op]
	return ok
}

// fuseLookupName strips the memory64 marker so the width-independent
// fusion vocabulary (fusedMemOps, fusedStoreOps, the per-op arity and
// name comparisons) applies to both helper families; the reported flag
// makes the builder mark the tree Addr64.
func fuseLookupName(name string) (string, bool) {
	if rest, ok := strings.CutPrefix(name, "simd_m64_"); ok {
		return "simd_" + rest, true
	}
	return name, false
}

// fusableOp reports whether a marked call can be a fused-tree member:
// the accepted memory loads, or a pure op in the generated
// simdFusePureOps contract — ops whose BOTH-arch pair bodies stay
// inside the vector file (no GPR beyond the scalar staging register)
// and whose scalars are int32. The generator computes that set with
// the same classification the fused splicers apply, so codegen and
// gcasm can never disagree.
func fusableOp(m simdCallMark) bool {
	name, _ := fuseLookupName(m.name)
	if _, ok := fusedMemOps[name]; ok {
		return true
	}
	if _, ok := fusedStoreOps[name]; ok {
		return true
	}
	if !m.resV128 {
		return false
	}
	if m.name == "simd_f16x4_cvt" {
		// Synthesized by the f16 gather rewrite; both splicers emit a
		// dedicated inline conversion (no pair-table body).
		return true
	}
	if m.name == "simd_f32x4_splat" {
		// Special-cased: its float scalar rides a FLOAT argument
		// register and the splicers emit a dedicated broadcast from
		// the saved argument (the table body would expect the value
		// pre-staged in v0/X0).
		return true
	}
	return simdFusePureOps[strings.TrimPrefix(m.name, "simd_")]
}

// fusedShapeState lives on the translator: every distinct fused tree
// shape (ops, wiring, constants) becomes one synthetic helper shared
// by all its call sites.
type fusedShapeState struct {
	byKey map[string]*simdfuse.Tree
	order []*simdfuse.Tree
}

// fusedLoopState interns fused-loop descriptors; every distinct
// (tree, carry/bump/counter shape) becomes one synthetic loop helper.
type fusedLoopState struct {
	byKey map[string]*simdfuse.Loop
	order []*simdfuse.Loop
	names []string
}

// FusedLoops returns the interned loops keyed by helper name.
func (t *translator) FusedLoops() map[string]*simdfuse.Loop {
	if t.fusedLoops == nil || len(t.fusedLoops.order) == 0 {
		return nil
	}
	out := make(map[string]*simdfuse.Loop, len(t.fusedLoops.order))
	for i, l := range t.fusedLoops.order {
		out[t.fusedLoops.names[i]] = l
	}
	return out
}

func (t *translator) internFusedLoop(l *simdfuse.Loop) (string, bool) {
	if t.fusedLoops == nil {
		t.fusedLoops = &fusedLoopState{byKey: map[string]*simdfuse.Loop{}}
	}
	key := fmt.Sprintf("%s|D%d|P%v|C%d|B%v|N%d|X%v|T%v|W%v", l.Tree.Name, l.Dec, l.CarriedPairs, l.CounterScalar, l.Bumps, l.NumDeltas, l.ExitScalars, l.PreTest, l.CounterWide)
	if _, ok := t.fusedLoops.byKey[key]; ok {
		for i, k := range t.fusedLoops.names {
			_ = i
			_ = k
		}
		// Find the name for the existing entry.
		for i := range t.fusedLoops.order {
			if t.fusedLoops.order[i] == t.fusedLoops.byKey[key] {
				return t.fusedLoops.names[i], true
			}
		}
	}
	if len(t.fusedLoops.order) >= fusedMaxShapes {
		return "", false
	}
	name := fmt.Sprintf("simd_p_fxl%d", len(t.fusedLoops.order))
	t.fusedLoops.byKey[key] = l
	t.fusedLoops.order = append(t.fusedLoops.order, l)
	t.fusedLoops.names = append(t.fusedLoops.names, name)
	return name, true
}

// FusedTrees returns the interned shapes keyed by helper name, for the
// transpiler to hand to the gcasm backend.
func (t *translator) FusedTrees() map[string]*simdfuse.Tree {
	if t.fusedShapes == nil || len(t.fusedShapes.byKey) == 0 {
		return nil
	}
	out := make(map[string]*simdfuse.Tree, len(t.fusedShapes.order))
	for _, tree := range t.fusedShapes.order {
		out[tree.Name] = tree
	}
	return out
}

func (t *translator) internFusedTree(key string, tree *simdfuse.Tree) (*simdfuse.Tree, bool) {
	// Hard architectural bound, re-checked here because every tree
	// passes through the intern point: pair registers are based past
	// the FINAL scalar count, and both walk paths can admit scalars
	// after a pair (each admission individually under its cap), so a
	// late-growing tree can push the pair block upward. Arguments are
	// confined to R0..R15 — the arm64 ABIInternal integer-argument
	// registers; gc passes a seventeenth argument on the stack, which
	// the register-only arm64 splice cannot see. Fused loops re-check
	// with their extra counter and delta slots at upgrade time.
	if 1+tree.NumScalars+2*tree.NumPairs > fusedMaxIntSlots {
		return nil, false
	}
	if t.fusedShapes == nil {
		t.fusedShapes = &fusedShapeState{byKey: map[string]*simdfuse.Tree{}}
	}
	if got, ok := t.fusedShapes.byKey[key]; ok {
		return got, true
	}
	if len(t.fusedShapes.order) >= fusedMaxShapes {
		return nil, false
	}
	tree.Name = fmt.Sprintf("simd_p_fx%d", len(t.fusedShapes.order))
	t.fusedShapes.byKey[key] = tree
	t.fusedShapes.order = append(t.fusedShapes.order, tree)
	return tree, true
}

// fusedTreeBuilder accumulates one call tree during tryFuse. The walk
// is a PURE analysis: it mutates nothing and emits nothing, recording
// the AST expressions that become scalar and pair parameters so the
// caller can materialize them only once the fuse is known to succeed
// (rewriteExpr/pairExprs are destructive — running them on a tree that
// then fails to fuse would strand their hoisted preludes).
type fusedTreeBuilder struct {
	sc      *simdScalarizer
	nodes   []simdfuse.Node
	scalars []ast.Expr // scalar parameter source expressions, in order
	floats  []ast.Expr // float32 parameter source expressions, in order
	pairs   []ast.Expr // pair parameter source expressions, in order
	key     strings.Builder
	// varNode maps window-internal variable names to the node index
	// holding their value, so a multi-root window's later statements
	// consume earlier results as internal edges instead of pair
	// parameters. Nil outside window fusion.
	varNode  map[string]int
	varEdges int // ArgNode edges resolved through varNode
	// varNodeHits counts per-name varNode resolutions: together with
	// the function-wide semantic use count it proves a window variable
	// internal (all uses consumed by the region).
	varNodeHits map[string]int
	// scalarDedup shares one scalar parameter among identical
	// identifier arguments; pairDedup does the same for v128 pair
	// inputs (kernels pass the same block to several trees).
	scalarDedup map[string]int
	pairDedup   map[string]int
	// candReads collects, per window candidate, every identifier its
	// parameter expressions read (dedup hits included) — the exact
	// input for the intervener interference check.
	candReads []map[string]bool
	// readsCandVar poisons the trial: a parameter expression read an
	// earlier candidate's variable outside varNode resolution (see
	// noteRead).
	readsCandVar bool
	// interDef maps window-intervener names to their defining
	// statements for scalar chasing (window fusion only, nil
	// otherwise); chaseUses/chaseCache/chaseReads track what the
	// chases consumed so the window can prove the interveners
	// droppable at commit (see simd_fuse_scalar.go).
	interDef   map[string]*ast.AssignStmt
	chaseUses  map[string]int
	chaseCache map[string]int
	chaseReads map[string]bool
	// addr64 marks the tree-in-progress as a memory64 one (some member
	// is a simd_m64_* memory op); see simdfuse.Tree.Addr64.
	addr64 bool
	// chaseVisiting guards the definition-chasing recursion against
	// self-referential definitions (a loop-carried `v = v + 4` in the
	// goto-form emission): a name already on the chase path is not
	// chaseable, it stays an intervener. Purely re-entrancy state — no
	// snapshot needed, entries are removed on unwind.
	chaseVisiting map[string]bool
	// failWhy records the walk's first refusal (diagnosis only).
	failWhy string
	// owner attributes each scalar/pair parameter to the window
	// candidate whose walk added it (positional interference checks);
	// single-tree fusion leaves them at the zero candidate.
	scalarOwner []int
	pairOwner   []int
	curCand     int
}

// intRegsUsed is the fused signature's integer-register footprint.
func (fb *fusedTreeBuilder) intRegsUsed() int {
	return 1 + len(fb.scalars) + 2*len(fb.pairs)
}

// floatPoolCost is how many pool registers the window's float
// arguments cost on the binding (amd64) splicer: all floats share one
// packed register, so any float count reserves exactly one.
func floatPoolCost(nFloats int) int {
	if nFloats == 0 {
		return 0
	}
	return 1
}

// scheduleNodes reorders the region's nodes to minimize
// simultaneously-live values: statement order piles every unrolled
// load up front (peak live = the load count), but inside a region only
// DATA dependences and the load ORDER matter — loads keep their
// original relative order (an unchecked load must stay behind the
// range check that covers it, and load-to-load trap order is
// preserved outright), while pure ops slot in right after their
// operands so values die quickly. Greedy: always prefer a ready pure
// op that consumes at least one dying value; otherwise advance to the
// next load; otherwise take any ready pure op. Node indices, roots
// and the shape key are remapped afterwards.
func (fb *fusedTreeBuilder) scheduleNodes(roots []int) []int {
	n := len(fb.nodes)
	deps := make([][]int, n)
	remaining := make([]int, n) // unmet dependency count
	consumers := make([]int, n) // total consumers (for dying-value test)
	for i, nd := range fb.nodes {
		for _, a := range nd.Args {
			if a.Kind == simdfuse.ArgNode {
				deps[i] = append(deps[i], a.Index)
				remaining[i]++
				consumers[a.Index]++
			}
		}
	}
	isLoad := make([]bool, n)
	var loadOrder []int
	for i, nd := range fb.nodes {
		_, ld := fusedMemOps["simd_"+nd.Op]
		if ld || simdfuse.IsStore(nd.Op) {
			// Loads AND stores share one ordered queue: preserving the
			// full memory-op sequence keeps trap order and store-load
			// aliasing exactly as the program wrote them.
			isLoad[i] = true
			loadOrder = append(loadOrder, i)
		}
	}
	emittedDeps := make([]int, n)
	copy(emittedDeps, remaining)
	scheduled := make([]int, 0, n)
	done := make([]bool, n)
	// Scalar-chain nodes are not scheduled by the greedy walk: they are
	// spliced back in right before their unique vector consumer below,
	// where they evaluate in low scratch registers without touching the
	// pool. Mark them done so their consumers become ready.
	nScalar := 0
	for i, nd := range fb.nodes {
		if nd.Class() != simdfuse.ClassV128 {
			done[i] = true
			nScalar++
			for j := range fb.nodes {
				for _, d := range deps[j] {
					if d == i {
						emittedDeps[j]--
					}
				}
			}
		}
	}
	left := make([]int, n)
	copy(left, consumers)
	nextLoad := 0
	ready := func(i int) bool {
		if done[i] {
			return false
		}
		if emittedDeps[i] != 0 {
			return false
		}
		if isLoad[i] {
			// Loads only in their original relative order.
			return nextLoad < len(loadOrder) && loadOrder[nextLoad] == i
		}
		return true
	}
	emit := func(i int) {
		scheduled = append(scheduled, i)
		done[i] = true
		if isLoad[i] {
			nextLoad++
		}
		for j, nd := range fb.nodes {
			_ = nd
			for _, d := range deps[j] {
				if d == i {
					emittedDeps[j]--
				}
			}
		}
		for _, d := range deps[i] {
			left[d]--
		}
	}
	last := -1
	for len(scheduled) < n-nScalar {
		pick := -1
		// Preference 0: a ready pure op consuming the LAST emitted
		// value as its first v128 operand — it will CHAIN through
		// v0/X0 and park nothing at all.
		if pick == -1 && last >= 0 && left[last] > 0 {
			for i := 0; i < n; i++ {
				if !ready(i) || isLoad[i] {
					continue
				}
				for _, a := range fb.nodes[i].Args {
					if a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn {
						if a.Kind == simdfuse.ArgNode && a.Index == last {
							pick = i
						}
						break
					}
				}
				if pick != -1 {
					break
				}
			}
		}
		// Preference 1: a ready pure op consuming a dying value (frees
		// a register immediately).
		if pick == -1 {
			for i := 0; i < n; i++ {
				if !ready(i) || isLoad[i] {
					continue
				}
				for _, d := range deps[i] {
					if left[d] == 1 {
						pick = i
						break
					}
				}
				if pick != -1 {
					break
				}
			}
		}
		// Preference 2: any ready pure op — running computation between
		// loads caps live growth even when nothing dies yet (a value
		// consumed twice, as every dual-extended block load is, only
		// dies at its second use).
		if pick == -1 {
			for i := 0; i < n; i++ {
				if ready(i) && !isLoad[i] {
					pick = i
					break
				}
			}
		}
		// Preference 3: the next load.
		if pick == -1 && nextLoad < len(loadOrder) && ready(loadOrder[nextLoad]) {
			pick = loadOrder[nextLoad]
		}
		if pick == -1 {
			return roots // cycle cannot happen; bail to original order
		}
		emit(pick)
		last = pick
	}
	// Sink single-consumer splats to just before their consumer:
	// splats are pure, so the move is always safe, and it keeps the
	// splat's scalar feed chain (glued in below) adjacent to the real
	// use. Backends that absorb the splat into the consuming multiply
	// then hold the scalar source live only across that gap.
	{
		vecUses := make([]int, n)
		lastUse := make([]int, n)
		for pos, vi := range scheduled {
			for _, a := range fb.nodes[vi].Args {
				if a.Kind == simdfuse.ArgNode && fb.nodes[a.Index].Class() == simdfuse.ClassV128 {
					vecUses[a.Index]++
					lastUse[a.Index] = pos
				}
			}
		}
		rootUse := map[int]bool{}
		for _, r := range roots {
			rootUse[r] = true
		}
		for pos := len(scheduled) - 1; pos >= 0; pos-- {
			vi := scheduled[pos]
			if fb.nodes[vi].Op != "f32x4_splat" || vecUses[vi] != 1 || rootUse[vi] {
				continue
			}
			at := lastUse[vi]
			if at <= pos+1 {
				continue // already adjacent
			}
			copy(scheduled[pos:], scheduled[pos+1:at])
			scheduled[at-1] = vi
			for p, v := range scheduled {
				for _, a := range fb.nodes[v].Args {
					if a.Kind == simdfuse.ArgNode && fb.nodes[a.Index].Class() == simdfuse.ClassV128 {
						lastUse[a.Index] = p
					}
				}
			}
		}
	}
	// Splice scalar chains back in: every scalar node run is glued
	// immediately before the FIRST scheduled vector node that consumes
	// any of its values (chains are trees; original index order within
	// the tree is already topological).
	if nScalar > 0 {
		feeds := make([][]int, n) // vector node -> scalar nodes to emit before it (orig idx)
		placed := make([]bool, n)
		var place func(si, consumer int)
		place = func(si, consumer int) {
			if placed[si] {
				return
			}
			placed[si] = true
			for _, a := range fb.nodes[si].Args {
				if a.Kind == simdfuse.ArgNode && fb.nodes[a.Index].Class() != simdfuse.ClassV128 {
					place(a.Index, consumer)
				}
			}
			feeds[consumer] = append(feeds[consumer], si)
		}
		for _, vi := range scheduled {
			for _, a := range fb.nodes[vi].Args {
				if a.Kind == simdfuse.ArgNode && fb.nodes[a.Index].Class() != simdfuse.ClassV128 {
					place(a.Index, vi)
				}
			}
		}
		withScalars := make([]int, 0, n)
		for _, vi := range scheduled {
			withScalars = append(withScalars, feeds[vi]...)
			withScalars = append(withScalars, vi)
		}
		scheduled = withScalars
	}
	// Remap: old index → new index.
	remap := make([]int, n)
	for newIdx, oldIdx := range scheduled {
		remap[oldIdx] = newIdx
	}
	newNodes := make([]simdfuse.Node, n)
	for newIdx, oldIdx := range scheduled {
		nd := fb.nodes[oldIdx]
		args := make([]simdfuse.Arg, len(nd.Args))
		copy(args, nd.Args)
		for ai := range args {
			if args[ai].Kind == simdfuse.ArgNode {
				args[ai].Index = remap[args[ai].Index]
			}
		}
		newNodes[newIdx] = simdfuse.Node{Op: nd.Op, Args: args}
	}
	fb.nodes = newNodes
	newRoots := make([]int, len(roots))
	for i, r := range roots {
		newRoots[i] = remap[r]
	}
	// Rebuild the shape key from the scheduled form so interning stays
	// canonical. The key must be TOTAL over everything the synthetic
	// helper's body and splice depend on — nodes, wiring, signature
	// widths AND the root set. (Omitting the roots once collided two
	// different trees onto one helper name, which computed garbage for
	// one of its call sites.)
	fb.key.Reset()
	for _, nd := range fb.nodes {
		for _, a := range nd.Args {
			switch a.Kind {
			case simdfuse.ArgNode:
				fmt.Fprintf(&fb.key, "n%d,", a.Index)
			case simdfuse.ArgPairIn:
				fmt.Fprintf(&fb.key, "p%d,", a.Index)
			case simdfuse.ArgScalar:
				fmt.Fprintf(&fb.key, "s%d,", a.Index)
			case simdfuse.ArgFloat:
				fmt.Fprintf(&fb.key, "f%d,", a.Index)
			case simdfuse.ArgSum:
				fmt.Fprintf(&fb.key, "m%d+%d,", a.Index, a.Const)
			default:
				fmt.Fprintf(&fb.key, "c%d,", a.Const)
			}
		}
		fmt.Fprintf(&fb.key, "%s;", nd.Op)
	}
	fmt.Fprintf(&fb.key, "|S%dF%dP%d|R", len(fb.scalars), len(fb.floats), len(fb.pairs))
	for _, r := range newRoots {
		fmt.Fprintf(&fb.key, "%d,", r)
	}
	return newRoots
}

// peakLive simulates the splice synthesizers' value placement over the
// node list and reports the maximum number of simultaneously parked
// values (chained values ride v0/X0 and are excluded, mirroring the
// synthesizers' willChain rule). roots gain an extra epilogue use.
func (fb *fusedTreeBuilder) peakLive(roots []int) int {
	uses := make([]int, len(fb.nodes))
	for _, n := range fb.nodes {
		for _, a := range n.Args {
			if a.Kind == simdfuse.ArgNode {
				uses[a.Index]++
			}
		}
	}
	rootSet := map[int]bool{}
	for _, r := range roots {
		uses[r]++
		rootSet[r] = true
	}
	hasStore := false
	for _, n := range fb.nodes {
		if simdfuse.IsStore(n.Op) {
			hasStore = true
		}
	}
	if len(roots) == 0 && len(fb.nodes) > 0 && !hasStore {
		uses[len(fb.nodes)-1]++ // implicit single root
		rootSet[len(fb.nodes)-1] = true
	}
	chainsNext := func(i int) bool {
		next := i + 1
		for next < len(fb.nodes) && fb.nodes[next].Class() != simdfuse.ClassV128 {
			next++ // scalar chains preserve v0 (they avoid F0/X0 scratch)
		}
		if next >= len(fb.nodes) {
			return false
		}
		for _, a := range fb.nodes[next].Args {
			if a.Kind == simdfuse.ArgNode || a.Kind == simdfuse.ArgPairIn {
				return a.Kind == simdfuse.ArgNode && a.Index == i
			}
		}
		return false
	}
	live, peak := 0, 0
	parked := make([]bool, len(fb.nodes))
	for i, n := range fb.nodes {
		for _, a := range n.Args {
			if a.Kind != simdfuse.ArgNode {
				continue
			}
			uses[a.Index]--
			if uses[a.Index] == 0 && parked[a.Index] {
				live--
			}
		}
		if n.Class() != simdfuse.ClassV128 || simdfuse.IsStore(n.Op) {
			// Scalar-chain nodes ride GPR/float scratch and homes, and
			// stores produce nothing: neither touches the parking pool.
			continue
		}
		willChain := i == len(fb.nodes)-1 || (uses[i] == 1 && chainsNext(i))
		if !willChain {
			parked[i] = true
			live++
			if live > peak {
				peak = live
			}
		}
	}
	return peak
}

// noteRead records every identifier of a parameter expression against
// the current candidate. A parameter expression that references an
// EARLIER candidate's variable poisons the window: parameters evaluate
// before the fused call, but that variable's value is produced BY the
// call — only direct v128 arguments resolve through varNode as
// internal edges, so a nested reference (an extract_lane inside a
// scalar expression, say) would read the stale pre-window value.
func (fb *fusedTreeBuilder) noteRead(e ast.Expr) {
	for len(fb.candReads) <= fb.curCand {
		fb.candReads = append(fb.candReads, map[string]bool{})
	}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name != "_" {
			fb.candReads[fb.curCand][id.Name] = true
			if _, isCand := fb.varNode[id.Name]; isCand {
				fb.readsCandVar = true
			}
		}
		return true
	})
}

// walk adds call's tree to the builder in post-order and returns the
// node index, or false if any part is unfusable or over the caps.
func (fb *fusedTreeBuilder) walk(call *ast.CallExpr) (int, bool) {
	m := fb.sc.em.simdCalls[call]
	if !fusableOp(m) || len(fb.nodes) >= fusedMaxNodes {
		if fb.failWhy == "" {
			if len(fb.nodes) >= fusedMaxNodes {
				fb.failWhy = "node cap"
			} else {
				fb.failWhy = "unfusable op " + m.name
			}
		}
		return 0, false
	}
	lookupName, m64 := fuseLookupName(m.name)
	memScalars, isMem := fusedMemOps[lookupName]
	isStore := false
	if !isMem {
		if sc, ok := fusedStoreOps[lookupName]; ok {
			memScalars, isMem, isStore = sc, true, true
		}
	}
	if m64 {
		fb.addr64 = true
		fb.key.WriteString("m64;")
	}
	args := call.Args
	if isMem {
		// Drop the leading `m`; the fused call passes its own.
		want := 1 + memScalars
		if isStore || lookupName == "simd_v128_load32_lane" {
			want++ // the stored / lane-inserted v128 value
		}
		if len(args) != want {
			return 0, false
		}
		args = args[1:]
		// The rng window (rlo, span) must be constants: the splicers
		// bake them as immediates, which is also what keeps the load's
		// scratch-register budget at two on amd64. The bounds pass
		// always emits constant windows — Const32 on wasm32, Const64
		// (spelled int64(...)) on memory64 — so the resolvability
		// check matches the module's width.
		resolvable := fb.constResolvable
		if m64 {
			resolvable = func(e ast.Expr) bool {
				_, ok := fb.addrConstValue(e)
				return ok
			}
		}
		if lookupName == "simd_v128_load32_lane" && !resolvable(args[2]) {
			if fb.failWhy == "" {
				fb.failWhy = "non-const lane"
			}
			return 0, false
		}
		if lookupName == "simd_v128_load_rng" {
			if !resolvable(args[2]) || !resolvable(args[3]) {
				if fb.failWhy == "" {
					fb.failWhy = "non-const rng window"
				}
				return 0, false
			}
		}
	}
	var nodeArgs []simdfuse.Arg
	isFloatSplat := lookupName == "simd_f32x4_splat"
	for i, a := range args {
		argIdx := i
		if isMem {
			argIdx = i + 1 // marks include the m slot
		}
		if isFloatSplat {
			// The single argument is a float32 expression. A chaseable
			// scale chain joins the region as scalar nodes; anything
			// else rides as a float parameter.
			if narg, ok := fb.chaseSplatFloat(a); ok {
				nodeArgs = append(nodeArgs, narg)
				fmt.Fprintf(&fb.key, "n%d,", narg.Index)
				continue
			}
			if len(fb.floats) >= fusedMaxFloats {
				if fb.failWhy == "" {
					fb.failWhy = "float cap"
				}
				return 0, false
			}
			nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgFloat, Index: len(fb.floats)})
			fmt.Fprintf(&fb.key, "f%d,", len(fb.floats))
			fb.floats = append(fb.floats, a)
			fb.noteRead(a)
			continue
		}
		isV128 := argIdx < len(m.args) && m.args[argIdx]
		if lookupName == "simd_v128_load32_lane" {
			// The mark's positions come from the SSA args (addr, value);
			// the emitted call interleaves literal memarg/lane operands,
			// so classify by helper position: only the trailing value is
			// a v128.
			isV128 = i == 3
		}
		if isV128 {
			// v128 operand: a nested fusable call joins the tree, a
			// window-internal variable resolves to its producing node;
			// any other source becomes a pair input.
			if sub, ok := a.(*ast.CallExpr); ok {
				if sm, marked := fb.sc.em.simdCalls[sub]; marked && fusableOp(sm) {
					idx, ok := fb.walk(sub)
					if !ok {
						return 0, false
					}
					nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx})
					fmt.Fprintf(&fb.key, "n%d,", idx)
					continue
				}
			}
			if id, ok := a.(*ast.Ident); ok && fb.varNode != nil {
				if idx, ok := fb.varNode[id.Name]; ok {
					fb.varEdges++
					fb.varNodeHits[id.Name]++
					nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx})
					fmt.Fprintf(&fb.key, "n%d,", idx)
					continue
				}
			}
			if id, ok := a.(*ast.Ident); ok {
				if idx, ok := fb.pairDedup[id.Name]; ok {
					nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: idx})
					fmt.Fprintf(&fb.key, "p%d,", idx)
					fb.noteRead(a)
					continue
				}
			}
			if fb.intRegsUsed()+2 > fusedMaxIntSlots {
				if fb.failWhy == "" {
					fb.failWhy = fmt.Sprintf("int cap (pair #%d: %s; prior=%s)", len(fb.pairs), exprDebugString(a), fb.pairDebug())
				}
				return 0, false
			}
			nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: len(fb.pairs)})
			fmt.Fprintf(&fb.key, "p%d,", len(fb.pairs))
			if id, ok := a.(*ast.Ident); ok {
				if fb.pairDedup == nil {
					fb.pairDedup = map[string]int{}
				}
				fb.pairDedup[id.Name] = len(fb.pairs)
			}
			fb.pairs = append(fb.pairs, a)
			fb.pairOwner = append(fb.pairOwner, fb.curCand)
			fb.noteRead(a)
			continue
		}
		// Scalar operand: constants ride the descriptor as immediates
		// (no ABI slot) — including single-assignment constant LOCALS,
		// which the emitter's constant CSE creates for shared memarg
		// offsets; identical scalar identifiers share one parameter.
		//
		// A memory64 member's ADDRESS (arg 0) never folds to a bare
		// ArgConst: Arg.Const is 32-bit, so a fully-constant 64-bit
		// pointer would truncate. The base+const ArgSum fold below IS
		// open to it — the base stays a full-width runtime scalar and
		// the constant is a small reassociated memarg delta — and the
		// small memarg offset / coalesced window (rlo/span) at args ≥ 1
		// fold as bounded constants via the int64-aware matcher, since
		// m64 spells them int64(...).
		foldOK := !m64 || !isMem || i != 0
		if m64 && isMem && i >= 1 {
			if c, ok := fb.addrConstValue(a); ok {
				nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c})
				fmt.Fprintf(&fb.key, "c%d,", c)
				continue
			}
		}
		if c, ok := intConstValue(a); ok && foldOK {
			nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c})
			fmt.Fprintf(&fb.key, "c%d,", c)
			continue
		}
		if id, ok := a.(*ast.Ident); ok {
			if c, ok := fb.sc.constBind[id.Name]; ok && foldOK {
				nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c})
				fmt.Fprintf(&fb.key, "c%d,", c)
				continue
			}
			if idx, ok := fb.scalarDedup[id.Name]; ok {
				nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: idx})
				fmt.Fprintf(&fb.key, "s%d,", idx)
				fb.noteRead(a)
				continue
			}
		}
		// base+const address sums: one deduplicated base scalar plus a
		// descriptor constant (ArgSum), truncated to u32 like Add32.
		// LOAD ADDRESSES ONLY: the splicers materialize the sum in the
		// address path; pure-op scalar staging would drop the constant.
		// A shared address LOCAL (`v103 = v65 + 18`, hoisted by the
		// const-add reassociation) resolves through its window
		// definition to the same form, under the chase's consumption
		// bookkeeping so a fully-internalized definition drops out.
		// The ArgSum fold applies at BOTH widths: on memory64 the base
		// rides a full-width scalar register and the emitters
		// materialize base+const with a full i64 add, so nothing
		// truncates; only the constant matcher differs (m64 spells the
		// reassociated deltas int64(...)).
		addrConstOf := fb.constValueOf
		if m64 {
			addrConstOf = fb.addrConstValue
		}
		aAddr := a
		var addrDefName string
		if id, ok := a.(*ast.Ident); ok && isMem && i == 0 && fb.interDef != nil {
			if def, dok := fb.interDef[id.Name]; dok {
				if bin, bok := def.Rhs[0].(*ast.BinaryExpr); bok && bin.Op == token.ADD {
					aAddr = bin
					addrDefName = id.Name
				}
			}
		}
		if bin, ok := aAddr.(*ast.BinaryExpr); ok && bin.Op == token.ADD && isMem && i == 0 {
			base, cExpr := bin.X, bin.Y
			c, cok := addrConstOf(cExpr)
			if !cok {
				base, cExpr = bin.Y, bin.X
				c, cok = addrConstOf(cExpr)
			}
			if cok {
				if baseID, ok := base.(*ast.Ident); ok && !fb.sc.pairs[baseID.Name] && !fb.sc.arrays[baseID.Name] {
					idx, iok := fb.scalarDedup[baseID.Name]
					if !iok {
						if 1+len(fb.scalars)+1 > fusedMaxIntRegs {
							if fb.failWhy == "" {
								fb.failWhy = "int cap (sum base)"
							}
							return 0, false
						}
						idx = len(fb.scalars)
						if fb.scalarDedup == nil {
							fb.scalarDedup = map[string]int{}
						}
						fb.scalarDedup[baseID.Name] = idx
						fb.scalars = append(fb.scalars, base)
						fb.scalarOwner = append(fb.scalarOwner, fb.curCand)
					}
					nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgSum, Index: idx, Const: c})
					fmt.Fprintf(&fb.key, "m%d+%d,", idx, c)
					fb.noteRead(base)
					if addrDefName != "" {
						if fb.chaseUses == nil {
							fb.chaseUses = map[string]int{}
						}
						fb.chaseUses[addrDefName]++
						// The base is read at CALL time through the
						// definition; the positional interference check
						// cannot see that, so use the chase's
						// position-insensitive write guard.
						fb.noteChaseRead(base)
					}
					continue
				}
			}
		}
		if 1+len(fb.scalars)+1 > fusedMaxIntRegs {
			if fb.failWhy == "" {
				fb.failWhy = "int cap (scalar)"
			}
			return 0, false
		}
		nodeArgs = append(nodeArgs, simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: len(fb.scalars)})
		fmt.Fprintf(&fb.key, "s%d,", len(fb.scalars))
		if id, ok := a.(*ast.Ident); ok {
			if fb.scalarDedup == nil {
				fb.scalarDedup = map[string]int{}
			}
			fb.scalarDedup[id.Name] = len(fb.scalars)
		}
		fb.scalars = append(fb.scalars, a)
		fb.scalarOwner = append(fb.scalarOwner, fb.curCand)
		fb.noteRead(a)
	}
	op := strings.TrimPrefix(lookupName, "simd_")
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: op, Args: nodeArgs})
	fmt.Fprintf(&fb.key, "%s;", op)
	return len(fb.nodes) - 1, true
}

// exprDebugString renders an expression compactly for diagnostics.
func exprDebugString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok {
			return id.Name + "(...)"
		}
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name + "(...)"
		}
		return "call(...)"
	case *ast.BinaryExpr:
		return exprDebugString(x.X) + x.Op.String() + exprDebugString(x.Y)
	case *ast.CompositeLit:
		return "{...}"
	case *ast.IndexExpr:
		return exprDebugString(x.X) + "[i]"
	}
	return fmt.Sprintf("%T", e)
}

// pairDebug lists the pair parameters collected so far.
func (fb *fusedTreeBuilder) pairDebug() string {
	out := ""
	for i, p := range fb.pairs {
		if i > 0 {
			out += ","
		}
		out += exprDebugString(p)
	}
	return out
}

// fuseDebugEnabled gates the window-trial diagnostics: with
// WASM2GO_FUSE_DEBUG set, every failed fusion trial of at least four
// candidates prints its width and first refusal to stderr. This is
// the histogram workflow that localized both the K=4 unlock and the
// memory64 window-starvation regressions.
var fuseDebugEnabled = os.Getenv("WASM2GO_FUSE_DEBUG") != ""

func fuseDebugf(format string, args ...interface{}) {
	if fuseDebugEnabled {
		fmt.Fprintf(os.Stderr, "wasm2go: fuse-debug: "+format+"\n", args...)
	}
}

// constResolvable reports whether e will become an ArgConst: a
// literal, or a bound constant local.
func (fb *fusedTreeBuilder) constResolvable(e ast.Expr) bool {
	_, ok := fb.constValueOf(e)
	return ok
}

// addrConstValue resolves an address-offset constant. Unlike
// constValueOf it also accepts int64/uint64-wrapped literals (a
// memory64 offset like `int64(2)`), which the address arithmetic
// materializes at pointer width — but only when the value fits int32,
// the width of an ArgSum/ArgConst descriptor field. A larger offset
// falls back to a full scalar node.
func (fb *fusedTreeBuilder) addrConstValue(e ast.Expr) (int32, bool) {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
		if id, ok := c.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "int64", "uint64", "int32", "uint32":
				return fb.addrConstValue(c.Args[0])
			}
		}
	}
	return fb.constValueOf(e)
}

// constValueOf resolves a literal or a bound constant local.
func (fb *fusedTreeBuilder) constValueOf(e ast.Expr) (int32, bool) {
	if c, ok := intConstValue(e); ok {
		return c, true
	}
	if id, ok := e.(*ast.Ident); ok {
		c, ok := fb.sc.constBind[id.Name]
		return c, ok
	}
	return 0, false
}

// intConstValue matches an int32-representable constant expression:
// the emitter's Const32 shape `int32(<lit>)` (goConstI32), a bare
// literal, or either negated (intLitSigned). 64-bit conversions are
// deliberately NOT accepted here — the window classifier must not
// swallow int64 constants as int32 arguments; only the fused-loop
// COUNTER analysis unwraps them (see loopConstValue).
func intConstValue(e ast.Expr) (int32, bool) {
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
		if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "int32" || id.Name == "uint32") {
			e = c.Args[0]
		}
	}
	neg := false
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		neg = true
		e = u.X
	}
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, false
	}
	v, err := strconv.ParseInt(bl.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	if v < -(1<<31) || v >= 1<<31 {
		return 0, false
	}
	return int32(v), true
}

// tryFuse attempts to claim call's whole nested tree as one fused
// region. On success it returns the rewritten fused call (result in
// pair form, like rewriteCall's output).
func (sc *simdScalarizer) tryFuse(call *ast.CallExpr, prelude *[]ast.Stmt) (*ast.CallExpr, bool) {
	m := sc.em.simdCalls[call]
	if !m.resV128 || !fusableOp(m) {
		return nil, false
	}
	fb := &fusedTreeBuilder{sc: sc}
	if _, ok := fb.walk(call); !ok || len(fb.nodes) < 2 {
		return nil, false
	}
	if fb.peakLive(nil) > fusedPoolBudget-floatPoolCost(len(fb.floats)) {
		return nil, false
	}
	fmt.Fprintf(&fb.key, "|S%dF%dP%d|", len(fb.scalars), len(fb.floats), len(fb.pairs))
	needsMem := false
	for _, n := range fb.nodes {
		if _, ok := fusedMemOps["simd_"+n.Op]; ok {
			needsMem = true
		}
	}
	tree, ok := sc.em.t.internFusedTree(fb.key.String(), &simdfuse.Tree{
		NumScalars: len(fb.scalars),
		NumFloats:  len(fb.floats),
		NumPairs:   len(fb.pairs),
		NeedsMem:   needsMem,
		Addr64:     fb.addr64,
		Nodes:      fb.nodes,
	})
	if !ok {
		return nil, false
	}
	sc.em.useHelper(tree.Name)
	if needsMem {
		// The synthetic body calls the memory helpers; the splice needs
		// the Module offsets probe like any mem splice.
		if fb.addr64 {
			sc.em.useHelper("simd_m64_v128_load")
		} else {
			sc.em.useHelper("simd_v128_load")
		}
	}
	// Materialize the parameter expressions only now that the fuse is
	// committed: rewriteExpr/pairExprs mutate the AST and emit hoists.
	// Evaluation order of the fused call's arguments matches the walk
	// order, which is the original nested evaluation order.
	fusedArgs := []ast.Expr{newID("m")}
	for _, s := range fb.scalars {
		e := sc.rewriteExpr(s, prelude)
		if fb.addr64 {
			// Addr64 signatures take int64 scalars; non-address
			// scalars (int32-typed in the source) widen losslessly.
			e = &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{e}}
		}
		fusedArgs = append(fusedArgs, e)
	}
	for _, f := range fb.floats {
		fusedArgs = append(fusedArgs, sc.rewriteExpr(f, prelude))
	}
	for _, p := range fb.pairs {
		lo, hi := sc.pairExprs(p, prelude)
		fusedArgs = append(fusedArgs, lo, hi)
	}
	return &ast.CallExpr{Fun: sc.em.helperRef(tree.Name), Args: fusedArgs}, true
}

// tryFuseWindow fuses a run of consecutive pair assignments
// `v = <fusable call tree>` starting at list[start] into ONE
// multi-root fused call, `v1, v1__h, v2, v2__h, ... = fx(...)`.
// EVERY window statement's variable is a root: values consumed only
// inside the window come back as results the compiler then sees are
// dead — gc's own DCE does the cleanup, and no liveness analysis can
// go wrong here. Longer windows are tried first; a window commits
// only when at least one cross-statement edge exists (otherwise the
// per-statement fusion is just as good and creates fewer shapes).
func (sc *simdScalarizer) tryFuseWindow(list []ast.Stmt, start int, prelude *[]ast.Stmt) (ast.Stmt, int, bool) {
	return sc.tryFuseWindowEx(list, start, prelude, false)
}

// tryFuseWindowEx is tryFuseWindow with loop-mode extras: leading
// interveners (statements before the first candidate) may join the
// window, which the loop upgrade needs because an iteration's scale
// chains precede its first load.
func (sc *simdScalarizer) tryFuseWindowEx(list []ast.Stmt, start int, prelude *[]ast.Stmt, allowLeading bool) (ast.Stmt, int, bool) {
	// allowLeading is set only by the loop fuser: the whole-body trial
	// may treat clone-duplicated values as internal (see cloneInternal
	// below) because the loop context guarantees each duplicate reads
	// its own same-iteration definition.
	loopMode := allowLeading
	// Collect the candidate run. ggml kernels interleave the fusable
	// statements with pure scalar work (scale loads, float math), so a
	// bounded number of provably safe statements may sit BETWEEN
	// candidates: they are emitted before the fused call, which moves
	// the window's loads after them — invisible when the intervener
	// writes nothing the window reads, reads nothing the window
	// writes, and stores nothing to memory (fuseSafeIntervener).
	type cand struct {
		lhs   *ast.Ident
		call  *ast.CallExpr // nil for an alias candidate
		alias *ast.Ident    // `lhs = alias`: carries a window value onward
		store *ast.CallExpr // a store-sink statement (no lhs)
		span  int           // statements consumed through this candidate
		inter []ast.Stmt    // interveners since the previous candidate
	}
	const maxInterveners = 224
	const maxWindowStmts = 320
	var cands []cand
	var pendingInter []ast.Stmt
	nInter := 0
	for i := start; i < len(list) && len(cands) < maxWindowStmts; i++ {
		if es, ok := list[i].(*ast.ExprStmt); ok {
			if call, cok := es.X.(*ast.CallExpr); cok {
				if m, marked := sc.em.simdCalls[call]; marked {
					// Strip the memory64 marker: a simd_m64_v128_store
					// statement is the same store sink as its wasm32
					// twin (missing this kept every memory64 store out
					// of window fusion, unfusing whole conversion loops).
					storeName, _ := fuseLookupName(m.name)
					if _, sok := fusedStoreOps[storeName]; sok {
						cands = append(cands, cand{store: call, span: i - start + 1, inter: pendingInter})
						pendingInter = nil
						continue
					}
				}
			}
		}
		if as, ok := list[i].(*ast.AssignStmt); ok && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if lhs, ok := as.Lhs[0].(*ast.Ident); ok && sc.pairs[lhs.Name] {
				if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
					if m, marked := sc.em.simdCalls[call]; marked && m.resV128 && fusableOp(m) {
						cands = append(cands, cand{lhs: lhs, call: call, span: i - start + 1, inter: pendingInter})
						pendingInter = nil
						continue
					}
				}
				if rhs, ok := as.Rhs[0].(*ast.Ident); ok && sc.pairs[rhs.Name] && len(cands) > 0 {
					// Accumulator carries (`accNext = accPrev`) thread a
					// window value under a new name — an alias, not a
					// computation.
					cands = append(cands, cand{lhs: lhs, alias: rhs, span: i - start + 1, inter: pendingInter})
					pendingInter = nil
					continue
				}
			}
		}
		if (len(cands) == 0 && !allowLeading) || nInter >= maxInterveners {
			break
		}
		st := list[i]
		if !sc.fuseSafeIntervener(st) {
			break
		}
		pendingInter = append(pendingInter, st)
		nInter++
	}
	// Try the longest window first; the walk is a pure analysis, so a
	// failed length just retries shorter on a fresh builder.
	for w := len(cands); w >= 2; w-- {
		fb := &fusedTreeBuilder{
			sc: sc, varNode: map[string]int{}, varNodeHits: map[string]int{},
			interDef: map[string]*ast.AssignStmt{},
		}
		var nodeOf []int
		var inter []ast.Stmt
		interSlot := map[ast.Stmt]int{} // intervener → candidate index it precedes
		ok := true
		for ci, c := range cands[:w] {
			for _, st := range c.inter {
				interSlot[st] = ci
				inter = append(inter, st)
				// Single-assignment scalar definitions are chaseable:
				// scale chains resolve through them (simd_fuse_scalar.go).
				if as, aok := st.(*ast.AssignStmt); aok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					if lhs, lok := as.Lhs[0].(*ast.Ident); lok && !sc.pairs[lhs.Name] {
						fb.interDef[lhs.Name] = as
					}
				}
			}
			fb.curCand = ci
			if c.store != nil {
				idx, wok := fb.walk(c.store)
				if !wok {
					ok = false
					break
				}
				nodeOf = append(nodeOf, idx)
				continue
			}
			if c.alias != nil {
				idx, aok := fb.varNode[c.alias.Name]
				if !aok {
					ok = false // aliases a value from outside the window
					break
				}
				fb.varEdges++
				fb.varNodeHits[c.alias.Name]++
				fb.varNode[c.lhs.Name] = idx
				nodeOf = append(nodeOf, idx)
				continue
			}
			idx, wok := fb.walk(c.call)
			if !wok {
				ok = false
				break
			}
			fb.varNode[c.lhs.Name] = idx
			nodeOf = append(nodeOf, idx)
		}
		// The authoritative slot bound lives at the intern point (see
		// internFusedTree); reject early here only for the diagnosis
		// message.
		if ok && fb.intRegsUsed() > fusedMaxIntSlots {
			ok = false
			if fb.failWhy == "" {
				fb.failWhy = fmt.Sprintf("int cap (final: %d slots)", fb.intRegsUsed())
			}
		}
		if !ok || fb.varEdges == 0 || fb.readsCandVar {
			if w >= 4 && !ok {
				fuseDebugf("w=%d walk fail: %s", w, fb.failWhy)
			}
			continue
		}
		// A window variable is INTERNAL when the region consumes every
		// semantic use it has (its write plus its in-window reads):
		// internal variables need no root slot and no assignment —
		// their declarations' blank uses keep them legal. Everything
		// else is a root. A reassigned variable (two candidates, one
		// name) must stay a root at its LAST candidate only.
		lastCand := map[string]int{}
		for ci, c := range cands[:w] {
			if c.store != nil {
				continue
			}
			lastCand[c.lhs.Name] = ci
		}
		hasStore := false
		for _, c := range cands[:w] {
			if c.store != nil {
				hasStore = true
			}
		}
		var roots []int
		var rootVars []string
		rootsOverCap := false
		for ci, c := range cands[:w] {
			if c.store != nil {
				continue
			}
			name := c.lhs.Name
			if lastCand[name] != ci {
				continue // superseded by a later reassignment
			}
			cloneInternal := loopMode &&
				fb.varNodeHits[name] > 0 && sc.readCount[name] == sc.carryLoopReads[name]
			if _, pairArg := fb.pairDedup[name]; sc.identCount[name] == 1+fb.varNodeHits[name] ||
				(cloneInternal && !pairArg) {
				// Internal: fully consumed by this window — either
				// every semantic use sits here, or (loop-mode
				// clone-tolerant form) every read function-wide lives
				// inside a for body that redefines the name before
				// reading it, i.e. the emitter's duplicated copies of
				// this very loop, each satisfied by its own
				// same-iteration definition.
				continue
			}
			if len(roots) == fusedMaxRoots {
				rootsOverCap = true
				roots = nil
				break
			}
			roots = append(roots, nodeOf[ci])
			rootVars = append(rootVars, name)
		}
		if rootsOverCap || (len(roots) == 0 && !hasStore) {
			if w >= 4 {
				fuseDebugf("w=%d roots=%d overCap=%v", w, len(roots), rootsOverCap)
			}
			continue // over the root cap, or a window with no live output
		}
		roots = fb.scheduleNodes(roots)
		if pl := fb.peakLive(roots); pl > fusedPoolBudget-floatPoolCost(len(fb.floats)) {
			if w >= 4 {
				fuseDebugf("w=%d peakLive=%d budget=%d floats=%d roots=%d", w, pl, fusedPoolBudget-floatPoolCost(len(fb.floats)), len(fb.floats), len(roots))
			}
			continue // would exhaust the splice synthesizers' vector pool
		}
		if hasStore {
			// In-region scalar memory reads (chased scale chains) run in
			// the region preamble, BEFORE every in-region store — but
			// their original position may have been after one. Keep the
			// two features apart until an ordering proof exists.
			scalarMem := false
			for _, n := range fb.nodes {
				if simdfuse.ScalarMemOp(n.Op) {
					scalarMem = true
				}
			}
			if scalarMem {
				continue
			}
			// An intervener with a memory READ that originally sat
			// after an in-window store would read stale data once moved
			// ahead of the fused call.
			firstStore := -1
			for ci, c := range cands[:w] {
				if c.store != nil {
					firstStore = ci
					break
				}
			}
			bad := false
			for _, st := range inter {
				if interSlot[st] > firstStore && interReadsMem(st) {
					bad = true
					break
				}
			}
			if bad {
				continue
			}
		}
		// A chased intervener DROPS out of the emitted window only when
		// every semantic use was internalized (a partially-consumed
		// definition — say an address that also feeds a vector load's
		// scalar argument — stays, and the region recomputes the pure
		// value redundantly). Independent of dropping, no remaining
		// intervener may REWRITE a name the chains read: the chains
		// evaluate at the fused call, after every remaining intervener.
		consumedInter := map[ast.Stmt]bool{}
		for name, uses := range fb.chaseUses {
			if sc.identCount[name] == uses+1 {
				consumedInter[fb.interDef[name]] = true
			}
		}
		chaseOK := true
		if len(fb.chaseReads) > 0 {
			for _, st := range inter {
				if consumedInter[st] {
					continue
				}
				as := st.(*ast.AssignStmt)
				if lhs, lok := as.Lhs[0].(*ast.Ident); lok && fb.chaseReads[lhs.Name] {
					chaseOK = false
					break
				}
			}
		}
		if !chaseOK {
			continue
		}
		if len(consumedInter) > 0 {
			kept := make([]ast.Stmt, 0, len(inter))
			for _, st := range inter {
				if !consumedInter[st] {
					kept = append(kept, st)
				}
			}
			inter = kept
		}
		// Positional interference: an intervener moves ahead of the
		// whole window, so it may not touch what candidates BEFORE its
		// original position produced or consumed. Every candidate's
		// variable counts here (internal ones are still written in the
		// original order the interveners observed).
		if len(inter) > 0 {
			var candNames []string
			for _, c := range cands[:w] {
				if c.store != nil {
					candNames = append(candNames, "")
					continue
				}
				candNames = append(candNames, c.lhs.Name)
			}
			if !fuseInterferenceFree(inter, interSlot, fb, candNames) {
				continue
			}
		}
		needsMem := false
		for _, n := range fb.nodes {
			if _, isMem := fusedMemOps["simd_"+n.Op]; isMem || simdfuse.ScalarMemOp(n.Op) || simdfuse.IsStore(n.Op) {
				needsMem = true
			}
		}
		tree, iok := sc.em.t.internFusedTree(fb.key.String(), &simdfuse.Tree{
			NumScalars: len(fb.scalars),
			NumFloats:  len(fb.floats),
			NumPairs:   len(fb.pairs),
			NeedsMem:   needsMem,
			Addr64:     fb.addr64,
			Nodes:      fb.nodes,
			Roots:      roots,
			NoResult:   len(roots) == 0,
		})
		if !iok {
			continue
		}
		sc.em.useHelper(tree.Name)
		if needsMem {
			if fb.addr64 {
				sc.em.useHelper("simd_m64_v128_load")
			} else {
				sc.em.useHelper("simd_v128_load")
			}
		}
		for _, n := range fb.nodes {
			if n.Class() != simdfuse.ClassV128 || simdfuse.IsStore(n.Op) {
				helper := "simd_" + n.Op
				if fb.addr64 && (isMemHelperOp(n.Op) || simdfuse.IsStore(n.Op)) {
					helper = "simd_m64_" + n.Op
				}
				sc.em.useHelper(helper)
			}
		}
		// Interveners run FIRST: later candidates' parameter
		// expressions may read what they define (the interference
		// check guarantees no EARLIER candidate does), so every
		// intervener must have executed before the arguments evaluate.
		for _, st := range inter {
			if rst := sc.rewriteStmt(st, prelude); rst != nil {
				*prelude = append(*prelude, rst)
			}
		}
		fusedArgs := []ast.Expr{newID("m")}
		for _, sa := range fb.scalars {
			e := sc.rewriteExpr(sa, prelude)
			if fb.addr64 {
				// Addr64 signatures take int64 scalars; non-address
				// scalars (int32-typed in the source) widen losslessly.
				e = &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{e}}
			}
			fusedArgs = append(fusedArgs, e)
		}
		for _, fa := range fb.floats {
			fusedArgs = append(fusedArgs, sc.rewriteExpr(fa, prelude))
		}
		for _, pa := range fb.pairs {
			lo, hi := sc.pairExprs(pa, prelude)
			fusedArgs = append(fusedArgs, lo, hi)
		}
		fusedCall := &ast.CallExpr{Fun: sc.em.helperRef(tree.Name), Args: fusedArgs}
		if len(rootVars) == 0 {
			return &ast.ExprStmt{X: fusedCall}, cands[w-1].span, true
		}
		var lhs []ast.Expr
		for _, name := range rootVars {
			lhs = append(lhs, newID(name), newID(pairName(name)))
		}
		return &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: lhs,
			Rhs: []ast.Expr{fusedCall},
		}, cands[w-1].span, true
	}
	return nil, 0, false
}

// fuseSafeIntervener reports whether st may move ahead of a fused
// window: a single-target assignment whose RHS performs no memory
// WRITE and calls nothing but marked scalar-result SIMD helpers
// (extract_lane and friends — pure). Inline memory READS are allowed:
// they are side-effect-free, and reordering one OOB trap against
// another leaves the same trap. The statement's write/read names
// accumulate for the interference check.
func (sc *simdScalarizer) fuseSafeIntervener(st ast.Stmt) bool {
	as, ok := st.(*ast.AssignStmt)
	if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	if _, ok := as.Lhs[0].(*ast.Ident); !ok {
		return false // memory store (`*(*T)(...) = v`) or other: keep order
	}
	safe := true
	ast.Inspect(as.Rhs[0], func(n ast.Node) bool {
		if x, isCall := n.(*ast.CallExpr); isCall {
			if m, marked := sc.em.simdCalls[x]; marked {
				if m.mem {
					// Loads could only reorder traps, but stores move a
					// WRITE across the window's loads — keep both ordered.
					safe = false
					return false
				}
				return true // pure SIMD helper, any result kind
			}
			if id, isConv := x.Fun.(*ast.Ident); isConv && len(x.Args) == 1 && conversionName(id.Name) {
				return true
			}
			if paren, isParen := x.Fun.(*ast.ParenExpr); isParen {
				if _, isStar := paren.X.(*ast.StarExpr); isStar {
					// A pointer-type conversion `(*T)(...)` — the shape
					// of the emitter's inline memory reads. Pure.
					return true
				}
			}
			if sel, isSel := x.Fun.(*ast.SelectorExpr); isSel {
				if pkg, isPkg := sel.X.(*ast.Ident); isPkg && pkg.Name == "unsafe" {
					// unsafe.Add / unsafe.Pointer: address arithmetic
					// for the emitter's INLINE MEMORY READS, which may
					// move ahead of the window — reads are effect-free
					// and reordering one out-of-bounds trap against
					// another leaves the same trap. Stores never get
					// here (their statement shape is rejected above).
					return true
				}
			}
			// Unmarked calls may have arbitrary effects.
			safe = false
			return false
		}
		return true
	})
	return safe
}

// conversionName matches the emitter's builtin numeric conversions.
func conversionName(name string) bool {
	switch name {
	case "int32", "uint32", "int64", "uint64", "int8", "uint8", "int16", "uint16", "float32", "float64", "int", "uint", "uintptr":
		return true
	}
	return false
}

// fuseInterferenceFree checks the mover's contract positionally. An
// intervener originally sat before candidate k; emitted ahead of the
// fused call it still runs before candidates k, k+1, ... — only its
// order against candidates 0..k-1 changes. So it must not:
//
//   - write a name candidates BEFORE k read (their parameters would
//     see the new value; originally they read the old one),
//   - write a root variable of a candidate BEFORE k (the fused
//     assignment would overwrite it; originally the intervener's
//     write was final),
//   - read a root variable of a candidate BEFORE k (it would see the
//     pre-window value; originally it saw the root's).
//
// Candidates at or after k need no checks: their relative order with
// the intervener is preserved.
func fuseInterferenceFree(inter []ast.Stmt, interSlot map[ast.Stmt]int, fb *fusedTreeBuilder, rootNames []string) bool {
	candReads := fb.candReads
	for len(candReads) < len(rootNames) {
		candReads = append(candReads, map[string]bool{})
	}
	for _, st := range inter {
		k := interSlot[st]
		as := st.(*ast.AssignStmt)
		w := as.Lhs[0].(*ast.Ident).Name
		reads := map[string]bool{}
		ast.Inspect(as.Rhs[0], func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				reads[id.Name] = true
			}
			return true
		})
		for ci := 0; ci < k; ci++ {
			if candReads[ci][w] || rootNames[ci] == w || reads[rootNames[ci]] {
				return false
			}
		}
	}
	return true
}

// fusedHelperDecls builds the synthetic helpers' Go declarations: the
// naive chain of the member helpers in array form. This body is what
// the pure fallback executes and what the capture compile type-checks
// and compiles; the gcasm transform replaces the CALL SITES with the
// synthesized fused body, so this function's own code only runs on the
// pure tree.
func (t *translator) fusedHelperDecls() []ast.Decl {
	if t.fusedShapes == nil {
		return nil
	}
	var out []ast.Decl
	for _, tree := range t.fusedShapes.order {
		out = append(out, fusedHelperDecl(tree, t.multiPackage))
	}
	if t.fusedLoops != nil {
		for i, l := range t.fusedLoops.order {
			out = append(out, fusedLoopDecl(t.fusedLoops.names[i], l, t.multiPackage))
		}
	}
	return out
}

func fusedHelperDecl(tree *simdfuse.Tree, multiPackage bool) *ast.FuncDecl {
	// Memory64 trees carry every scalar at pointer width; the register
	// assignment is identical (one integer register either way).
	scalarType := "int32"
	if tree.Addr64 {
		scalarType = "int64"
	}
	params := []*ast.Field{{Names: []*ast.Ident{newID("m")}, Type: &ast.StarExpr{X: newID("Module")}}}
	for i := 0; i < tree.NumScalars; i++ {
		params = append(params, &ast.Field{Names: []*ast.Ident{newID(fmt.Sprintf("s%d", i))}, Type: newID(scalarType)})
	}
	for i := 0; i < tree.NumFloats; i++ {
		params = append(params, &ast.Field{Names: []*ast.Ident{newID(fmt.Sprintf("f%d", i))}, Type: newID("float32")})
	}
	for i := 0; i < tree.NumPairs; i++ {
		params = append(params, &ast.Field{
			Names: []*ast.Ident{newID(fmt.Sprintf("p%d", i)), newID(fmt.Sprintf("p%dh", i))},
			Type:  newID("uint64"),
		})
	}
	var body []ast.Stmt
	// narrow re-types an int64 scalar for an int32-consuming (pure)
	// node on an Addr64 tree: only memory members consume the widened
	// scalars raw (their m64 helpers take int64 address/offset).
	argExpr := func(a simdfuse.Arg, narrow bool) ast.Expr {
		switch a.Kind {
		case simdfuse.ArgNode:
			return newID(fmt.Sprintf("n%d", a.Index))
		case simdfuse.ArgPairIn:
			return &ast.CompositeLit{
				Type: &ast.ArrayType{Len: intLit(2), Elt: newID("uint64")},
				Elts: []ast.Expr{newID(fmt.Sprintf("p%d", a.Index)), newID(fmt.Sprintf("p%dh", a.Index))},
			}
		case simdfuse.ArgScalar:
			if narrow {
				return &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{newID(fmt.Sprintf("s%d", a.Index))}}
			}
			return newID(fmt.Sprintf("s%d", a.Index))
		case simdfuse.ArgFloat:
			return newID(fmt.Sprintf("f%d", a.Index))
		case simdfuse.ArgSum:
			// int32 addition wraps mod 2^32, exactly Add32. (Addr64
			// trees never carry ArgSum — the builder keeps their
			// memory scalars opaque.)
			var sum ast.Expr = &ast.BinaryExpr{
				X:  newID(fmt.Sprintf("s%d", a.Index)),
				Op: token.ADD,
				Y:  intLitSigned(int64(a.Const)),
			}
			if narrow {
				sum = &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{sum}}
			}
			return sum
		default: // ArgConst
			return intLitSigned(int64(a.Const))
		}
	}
	for i, n := range tree.Nodes {
		helper := "simd_" + n.Op
		var callArgs []ast.Expr
		_, isMem := fusedMemOps[helper]
		isScalar := n.Class() != simdfuse.ClassV128
		// On a memory64 tree the address-carrying members switch to
		// their int64 m64 twins: the vector loads/stores, and the
		// scalar-chain address ops (the scale/LUT computations —
		// everything but the value-only f32_mul).
		addrM64 := tree.Addr64 && (isMem || simdfuse.IsStore(n.Op) ||
			(strings.HasPrefix(n.Op, "scalar_") && n.Op != "scalar_f32_mul"))
		if addrM64 {
			helper = "simd_m64_" + n.Op
		}
		if isMem || simdfuse.ScalarMemOp(n.Op) || simdfuse.IsStore(n.Op) {
			// Memory helpers (vector and scalar) live in the embedded
			// helper set; the multi-package export rename covers them
			// because their names are in helperNames.
			callArgs = append(callArgs, newID("m"))
		} else if multiPackage && !isScalar {
			// The pure v128 ops live in the whole-file SIMD set,
			// outside helperNames — reference their exported form
			// directly. Scalar arithmetic helpers are embedded like the
			// memory ops.
			helper = capitalize(helper)
		}
		// A widened scalar reaches a narrowing int32 consumer only when
		// the node is a pure op that stayed 32-bit; the m64 scalar/
		// memory members take the int64 scalars raw.
		narrow := tree.Addr64 && !isMem && !simdfuse.IsStore(n.Op) && !addrM64
		for _, a := range n.Args {
			callArgs = append(callArgs, argExpr(a, narrow))
		}
		lhs := ast.Expr(newID(fmt.Sprintf("n%d", i)))
		tok := token.DEFINE
		if simdfuse.IsStore(n.Op) {
			// Sinks produce nothing worth naming (the helper returns a
			// dummy int32).
			lhs, tok = newID("_"), token.ASSIGN
		}
		body = append(body, &ast.AssignStmt{
			Tok: tok,
			Lhs: []ast.Expr{lhs},
			Rhs: []ast.Expr{&ast.CallExpr{Fun: newID(helper), Args: callArgs}},
		})
	}
	// Window statements can reassign a variable, mapping two roots to
	// one node; every root still returns its (then-identical) value.
	var rets []ast.Expr
	var results []*ast.Field
	for _, r := range tree.RootList() {
		root := fmt.Sprintf("n%d", r)
		rets = append(rets,
			&ast.IndexExpr{X: newID(root), Index: intLit(0)},
			&ast.IndexExpr{X: newID(root), Index: intLit(1)})
		results = append(results,
			&ast.Field{Type: newID("uint64")}, &ast.Field{Type: newID("uint64")})
	}
	body = append(body, &ast.ReturnStmt{Results: rets})
	return &ast.FuncDecl{
		Doc:  &ast.CommentGroup{List: []*ast.Comment{{Text: "//go:noinline"}}},
		Name: newID(tree.Name),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: params},
			Results: &ast.FieldList{List: results},
		},
		Body: &ast.BlockStmt{List: body},
	}
}
