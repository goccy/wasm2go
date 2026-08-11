package ssa

import (
	"fmt"
	"sort"
)

// Loop outlining.
//
// gc's register allocator and the structured emitter both degrade on
// giant translated functions: allocation quality collapses into spill
// storms, and CFGs past the duplication budget fall to goto form where
// loop fusion never fires. Outlining moves a whole natural loop into
// its own function — the parent shrinks and the extracted body becomes
// a small, structurable unit — without changing any observable
// behaviour: the loop's boundary values become plain parameters and
// results, and traps keep propagating as panics.
//
// A loop is eligible when its call boundary is trivially representable:
//
//   - exactly one entry edge (a unique preheader → header edge),
//   - exactly one exit TARGET block, with every phi in it agreeing on
//     one value across all exiting edges (so the collapsed edge keeps
//     the phi well-formed),
//   - at most one value defined inside and used outside (the single
//     call result the downstream call marshalling supports), of scalar
//     type,
//   - no v128 values crossing the boundary in either direction (they
//     ride as uint64 pairs and would need multi-results),
//   - the enclosing function has no EH state (try regions / mutable
//     locals).
//
// Constants living outside the loop are cloned into the extracted
// body instead of being passed, which keeps parameter lists to the
// values that actually vary.

// OutlinedFunc pairs an extracted function with its boundary shape.
// Packed marks a boundary too wide for the register ABI: the caller
// passes one pointer to a uint64 slot array instead of individual
// scalar arguments (emission-level concern; the SSA signature keeps
// the logical parameter list either way).
type OutlinedFunc struct {
	Fn     *Func
	Packed bool
}

// outlinePackedMax bounds a packed boundary: beyond this the loop is
// carrying so much context that extraction stops being attractive.
// Must match the module scratch array length in the emitter.
const outlinePackedMax = 128

// outlinePackAmortRatio is the minimum body-values-per-boundary-slot
// ratio for a PACKED extraction on a memory64 module: the caller
// writes every slot into the scratch array and the outlined function
// reads them all back on every call, and with i64 locals doubling the
// callers' register pressure the round trip stops paying for wide
// boundaries. Measured on the llama.cpp module: gating these packs
// gains ~17% memory64 prompt throughput (the ~130-slot conversion
// loop), while the SAME gate on wasm32 LOSES ~25% — its outlined
// conversion loop compiles better extracted than inline — so the
// ratio applies only when wide.
const outlinePackAmortRatio = 24

// outlineV128MinBody is the minimum body size for a v128-boundary loop.
const outlineV128MinBody = 600

// outlineMaxShare rejects a body covering most of the function (the
// giant driver loop): outlining it would just move the problem, and
// it would take every nested loop with it into a function that is
// never re-scanned. Measured on the llama module: extracting drained
// drivers (rejecting them only while a nested eligible loop remained)
// was a consistent ~0.6% tg regression, so the hard cap stays.
const outlineMaxShare = 0.8

// OutlineLoops extracts eligible loops of at least minValues values
// from f. name generates the extracted function's name from the loop
// header's block ID (the caller owns naming policy). The parent is
// modified in place and re-verified; extracted functions are returned
// ready for their own lowering pipeline.
func OutlineLoops(f *Func, name func(header BlockID) string, minValues int, wide bool) ([]OutlinedFunc, error) {
	if f.MutableLocals || len(f.TryRegions) > 0 {
		return nil, nil
	}
	total := 0
	for _, b := range f.Blocks {
		total += len(b.Values)
	}
	if total < minValues {
		return nil, nil
	}
	var out []OutlinedFunc
	taken := map[BlockID]bool{} // blocks already extracted (stale IDs guarded by re-detection)
	// Re-detect after each extraction: the surgery invalidates block
	// sets, and one extraction can make an enclosing loop eligible.
	for {
		cand := findOutlineCandidate(f, minValues, taken, wide)
		if cand == nil {
			break
		}
		g, err := extractLoop(f, cand, name(cand.header.ID))
		if err != nil {
			return nil, fmt.Errorf("outline %s L%d: %w", f.Name, cand.header.ID, err)
		}
		// Foreign-edge sweep before Verify: a leftover reference to a
		// moved block would send Verify's dominator fixpoint into a
		// cycle instead of an error.
		for _, fn := range []*Func{f, g} {
			own := map[*Block]bool{}
			for _, b := range fn.Blocks {
				own[b] = true
			}
			for _, b := range fn.Blocks {
				for _, e := range b.Preds {
					if !own[e.Block] {
						return nil, fmt.Errorf("outline %s: %s block L%d (kind %d) pred references foreign block L%d (kind %d); cand header L%d exit L%d", f.Name, fn.Name, b.ID, b.Kind, e.Block.ID, e.Block.Kind, cand.header.ID, cand.exit.ID)
					}
				}
				for _, e := range b.Succs {
					if !own[e.Block] {
						return nil, fmt.Errorf("outline %s: %s block L%d succ references foreign block", f.Name, fn.Name, b.ID)
					}
				}
			}
		}
		if err := Verify(f); err != nil {
			return nil, fmt.Errorf("outline %s L%d: parent: %w", f.Name, cand.header.ID, err)
		}
		if err := Verify(g); err != nil {
			return nil, fmt.Errorf("outline %s L%d: extracted: %w", f.Name, cand.header.ID, err)
		}
		out = append(out, OutlinedFunc{Fn: g, Packed: cand.packed})
	}
	return out, nil
}

type outlineCand struct {
	header  *Block
	body    map[BlockID]bool
	nBody   int // values in body
	liveIns []*Value
	liveOut *Value
	// exit is the single exit target, or nil when exit2 is set: a
	// TWO-exit loop returns an encoded int64 — exit index in the
	// high word, the (optional, i32) live-out in the low — and the
	// parent dispatches on the index.
	exit   *Block
	exit2  [2]*Block
	prei   int // index of the preheader edge in header.Preds
	packed bool
}

// findOutlineCandidate returns the largest eligible loop of f, or nil.
func findOutlineCandidate(f *Func, minValues int, taken map[BlockID]bool, wide bool) *outlineCand {
	idom := Dominators(f)
	dominates := func(a, b *Block) bool {
		for b != nil {
			if b == a {
				return true
			}
			p := idom[b.ID]
			if p == b {
				return false
			}
			b = p
		}
		return false
	}
	total := 0
	for _, b := range f.Blocks {
		total += len(b.Values)
	}
	bodies := map[BlockID]map[BlockID]bool{}
	headers := map[BlockID]*Block{}
	for _, b := range f.Blocks {
		for _, s := range b.Succs {
			h := s.Block
			if !dominates(h, b) {
				continue
			}
			body := bodies[h.ID]
			if body == nil {
				body = map[BlockID]bool{h.ID: true}
				bodies[h.ID] = body
				headers[h.ID] = h
			}
			stack := []*Block{b}
			for len(stack) > 0 {
				x := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if body[x.ID] {
					continue
				}
				body[x.ID] = true
				for _, p := range x.Preds {
					stack = append(stack, p.Block)
				}
			}
		}
	}
	blockOf := map[BlockID]*Block{}
	for _, b := range f.Blocks {
		blockOf[b.ID] = b
	}
	var best *outlineCand
	for hid, body := range bodies {
		if taken[hid] {
			continue
		}
		n := 0
		for id := range body {
			n += len(blockOf[id].Values)
		}
		if n < minValues {
			continue
		}
		if float64(n) > outlineMaxShare*float64(total) {
			continue
		}
		c := checkOutlineCand(f, headers[hid], body, minValues, dominates, wide)
		if c == nil {
			continue
		}
		// Ties break on header ID: bodies is a map, and a map-order
		// winner makes the whole extraction sequence — block
		// renumbering, emission order, helper interning — differ from
		// run to run on identical input.
		if best == nil || c.nBody > best.nBody ||
			(c.nBody == best.nBody && c.header.ID < best.header.ID) {
			best = c
		}
	}
	if best != nil {
		taken[best.header.ID] = true
	}
	return best
}

// checkOutlineCand tests eligibility and computes the boundary. Size
// and share policy live in findOutlineCandidate; this checks only the
// boundary shape.
func checkOutlineCand(f *Func, h *Block, body map[BlockID]bool, minValues int, dominates func(a, b *Block) bool, wide bool) *outlineCand {
	c := &outlineCand{header: h, body: body}
	reject := func(format string, args ...any) *outlineCand {
		return nil
	}
	blockOf := map[BlockID]*Block{}
	for _, b := range f.Blocks {
		blockOf[b.ID] = b
	}
	for id := range body {
		if blockOf[id] == nil {
			return nil // stale candidate from a previous extraction
		}
		c.nBody += len(blockOf[id].Values)
	}
	if c.nBody < minValues {
		return reject("size gate: %d values (min %d)", c.nBody, minValues)
	}
	// Single entry edge, and no side entrance into the body: an
	// outside pred of a non-header body block (an irreducible region)
	// would keep referencing the moved blocks after extraction.
	c.prei = -1
	for i, p := range h.Preds {
		if body[p.Block.ID] {
			continue
		}
		if c.prei != -1 {
			return reject("multiple entry edges into header (preds L%d and L%d)", h.Preds[c.prei].Block.ID, p.Block.ID)
		}
		c.prei = i
	}
	if c.prei == -1 {
		return reject("no entry edge from outside the body")
	}
	for id := range body {
		if id == h.ID {
			continue
		}
		for _, p := range blockOf[id].Preds {
			if !body[p.Block.ID] {
				return reject("side entrance: outside block L%d preds body block L%d", p.Block.ID, id)
			}
		}
	}
	// Defs inside; ops that cannot be moved.
	defsIn := map[ValueID]*Value{}
	for id := range body {
		for _, v := range blockOf[id].Values {
			defsIn[v.ID] = v
			switch v.Op {
			case OpLocalGet, OpLocalSet:
				return reject("mutable-local op %s inside body (block L%d)", v.Op, id)
			}
		}
		switch blockOf[id].Kind {
		case BlockThrow:
			return reject("throw block L%d inside body", id)
		}
	}
	// Live-ins: invariant pure chains are recomputed inside the body,
	// so only their FRONTIER (loads, phis, params — values whose
	// results depend on when they run) rides as parameters.
	liveInSet := map[ValueID]*Value{}
	rematMemo := map[ValueID]bool{}
	var canRemat func(v *Value) bool
	canRemat = func(v *Value) bool {
		if r, ok := rematMemo[v.ID]; ok {
			return r
		}
		rematMemo[v.ID] = false // cycle guard (phis are excluded anyway)
		ok := outlineRemat(v)
		for _, a := range v.Args {
			if !ok {
				break
			}
			if defsIn[a.ID] != nil {
				ok = false // inside-defined feeder: not an invariant chain
				break
			}
			if !canRemat(a) && !outlineScalarType(a.Type) {
				ok = false
				break
			}
		}
		rematMemo[v.ID] = ok
		return ok
	}
	var noteIn func(a *Value) bool
	noteIn = func(a *Value) bool {
		if defsIn[a.ID] != nil {
			return true
		}
		if canRemat(a) {
			for _, aa := range a.Args {
				if !noteIn(aa) {
					return false
				}
			}
			return true
		}
		if !outlineScalarType(a.Type) && a.Type != TypeV128 {
			return false
		}
		liveInSet[a.ID] = a
		return true
	}
	for id := range body {
		for _, v := range blockOf[id].Values {
			for _, a := range v.Args {
				if !noteIn(a) {
					return reject("non-scalar live-in: v%d (op %s, type %s) feeding v%d (op %s) in block L%d", a.ID, a.Op, a.Type, v.ID, v.Op, id)
				}
			}
		}
		if ctl := blockOf[id].Control; ctl != nil && !noteIn(ctl) {
			return reject("non-scalar live-in as control: v%d (op %s, type %s) of block L%d", ctl.ID, ctl.Op, ctl.Type, id)
		}
	}
	ints, floats, vecs := 0, 0, 0
	for _, v := range liveInSet {
		c.liveIns = append(c.liveIns, v)
		switch v.Type {
		case TypeF32, TypeF64:
			floats++
		case TypeV128:
			vecs++
		default:
			ints++
		}
	}
	if vecs > 0 && c.nBody < outlineV128MinBody {
		return reject("v128 boundary needs %d+ values to amortize (have %d)", outlineV128MinBody, c.nBody)
	}
	if ints > outlineIntArgBudget || floats > outlineFloatArgBudget || vecs > 0 {
		slots := ints + floats + 2*vecs
		if slots > outlinePackedMax {
			return reject("packed cap: %d int + %d float + %d v128 live-ins > %d slots", ints, floats, vecs, outlinePackedMax)
		}
		if wide && c.nBody < slots*outlinePackAmortRatio {
			return reject("packed boundary unamortized: %d slots against %d body values (need %dx)", slots, c.nBody, outlinePackAmortRatio)
		}
		c.packed = true
	}
	sort.Slice(c.liveIns, func(i, j int) bool { return c.liveIns[i].ID < c.liveIns[j].ID })
	// Live-outs and the single exit target.
	liveOutSet := map[ValueID]*Value{}
	var exits []*Block
	for _, b := range f.Blocks {
		if body[b.ID] {
			for _, s := range b.Succs {
				if body[s.Block.ID] {
					continue
				}
				seen := false
				for _, e := range exits {
					if e == s.Block {
						seen = true
					}
				}
				if !seen {
					exits = append(exits, s.Block)
				}
			}
			continue
		}
		for _, v := range b.Values {
			for _, a := range v.Args {
				if defsIn[a.ID] != nil {
					liveOutSet[a.ID] = a
				}
			}
		}
		if ctl := b.Control; ctl != nil && defsIn[ctl.ID] != nil {
			liveOutSet[ctl.ID] = ctl
		}
	}
	if len(exits) == 0 || len(exits) > 2 || len(liveOutSet) > 1 {
		var outs []ValueID
		for id := range liveOutSet {
			outs = append(outs, id)
		}
		sortValueIDs(outs)
		return reject("boundary shape: %d exit targets, %d live-outs %v", len(exits), len(liveOutSet), outs)
	}
	for _, v := range liveOutSet {
		c.liveOut = v
	}
	if len(exits) == 1 {
		if c.liveOut != nil && !outlineScalarType(c.liveOut.Type) {
			return reject("live-out v%d has non-scalar type %s", c.liveOut.ID, c.liveOut.Type)
		}
		c.exit = exits[0]
	} else {
		// Two-exit form: the encoded return carries an i32 live-out
		// in the low word, so wider types stay ineligible. Sort by
		// block ID for a deterministic index assignment.
		if c.liveOut != nil && c.liveOut.Type != TypeI32 {
			return reject("two-exit live-out v%d has type %s (only i32 rides the encoded return)", c.liveOut.ID, c.liveOut.Type)
		}
		if exits[0].ID > exits[1].ID {
			exits[0], exits[1] = exits[1], exits[0]
		}
		// Both return paths encode the live-out, so its definition
		// must dominate every exiting block of either target.
		if c.liveOut != nil {
			for _, b := range f.Blocks {
				if !body[b.ID] {
					continue
				}
				for _, sc := range b.Succs {
					if !body[sc.Block.ID] && !dominates(c.liveOut.Block, b) {
						return reject("two-exit live-out v%d (block L%d) does not dominate exiting block L%d", c.liveOut.ID, c.liveOut.Block.ID, b.ID)
					}
				}
			}
		}
		c.exit2 = [2]*Block{exits[0], exits[1]}
	}
	// Every phi in each exit target must agree on ONE value across
	// its exiting edges — the collapsed call edge keeps a single arg.
	phiTargets := exits
	for _, exit := range phiTargets {
		for _, v := range exit.Values {
			if v.Op != OpPhi {
				continue
			}
			var common *Value
			for i, p := range exit.Preds {
				if !body[p.Block.ID] {
					continue
				}
				if i >= len(v.Args) {
					return reject("exit L%d phi v%d has fewer args than preds", exit.ID, v.ID)
				}
				if common == nil {
					common = v.Args[i]
				} else if common != v.Args[i] {
					return reject("exit L%d phi v%d disagrees across exiting edges (v%d vs v%d)", exit.ID, v.ID, common.ID, v.Args[i].ID)
				}
			}
		}
	}
	// The header's phis must take scalars on the entry edge (checked
	// above via liveIns) — nothing extra here.
	return c
}

func sortValueIDs(ids []ValueID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
}

func outlineScalarType(t Type) bool {
	switch t {
	case TypeI32, TypeI64, TypeF32, TypeF64:
		return true
	}
	return false
}

// isOutlineConst reports values cheap and safe to clone into the
// extracted body instead of passing as parameters.
func isOutlineConst(v *Value) bool {
	switch v.Op {
	case OpConst32, OpConst64, OpConstF32, OpConstF64:
		return true
	}
	return false
}

// outlineRemat reports whether a value may be recomputed inside the
// extracted body: pure scalar computation whose value cannot depend on
// WHEN it runs. Memory and global reads are excluded — re-executing
// them at the call site could observe stores that happened after the
// original — as are phis, params and anything v128-typed (v128 never
// crosses the boundary). Bool values (comparisons) are also excluded,
// which keeps loops with outside-defined bool feeders ineligible:
// admitting them was measured as a ~1% tg regression on the llama
// module — the bigger loops it unlocks absorb inner loops that are
// worth more as separate extractions.
func outlineRemat(v *Value) bool {
	if v.HasSideEffect() {
		return false
	}
	if !outlineScalarType(v.Type) && !isOutlineConst(v) {
		return false
	}
	switch v.Op {
	case OpPhi, OpParam, OpGlobalGet, OpSelect, OpSimdCall, OpSimdMemCall,
		OpLoad8U, OpLoad8S, OpLoad16U, OpLoad16S, OpLoad32, OpLoad32U,
		OpLoad32S, OpLoad64, OpLoadF32, OpLoadF64,
		OpLocalGet, OpLocalSet, OpMemGrow:
		return false
	}
	return true
}

// outlineArgRegBudget is the cross-arch minimum of Go's ABIInternal
// argument registers, minus the module pointer: amd64 assigns 9
// integer registers (arm64 has 16) and 15 float registers. Boundaries
// beyond this would marshal through the stack — a shape the asm
// call-site marshalling does not support, and pure-Go fallbacks are
// forbidden on the asm GOARCHs.
const (
	outlineIntArgBudget   = 8
	outlineFloatArgBudget = 15
)

// extractLoop performs the surgery described in the package comment.
func extractLoop(f *Func, c *outlineCand, gname string) (*Func, error) {
	body := c.body
	twoExit := c.exit == nil
	// Pointer-identity membership: block IDs are reassigned when the
	// body is adopted into the new function, so every membership test
	// after that point must NOT go through IDs.
	inBody := map[*Block]bool{}
	for _, b := range f.Blocks {
		if body[b.ID] {
			inBody[b] = true
		}
	}
	h := c.header
	var results []Type
	if twoExit {
		// Encoded return: exit index in the high word, the optional
		// i32 live-out in the low.
		results = []Type{TypeI64}
	} else if c.liveOut != nil {
		results = []Type{c.liveOut.Type}
	}
	params := make([]Type, len(c.liveIns))
	for i, v := range c.liveIns {
		params[i] = v.Type
	}
	g := NewFunc(gname, FuncSig{Params: params, Results: results})

	// Entry block with the parameter values, then a clone site for
	// outside constants.
	entry := g.NewBlock(BlockPlain)
	g.SetEntry(entry)
	paramOf := map[ValueID]*Value{}
	for i, v := range c.liveIns {
		p := g.newValue(OpParam, v.Type, nil, entry, int64(i), nil)
		entry.Values = append(entry.Values, p)
		paramOf[v.ID] = p
	}
	// Invariant chains recompute in the entry block: clones are
	// memoized and emitted in dependency order, with frontier values
	// reading their parameter.
	constOf := map[ValueID]*Value{}
	var cloneChain func(v *Value) *Value
	cloneChain = func(v *Value) *Value {
		if cl := constOf[v.ID]; cl != nil {
			return cl
		}
		if p := paramOf[v.ID]; p != nil {
			return p
		}
		var args []*Value
		for _, a := range v.Args {
			args = append(args, cloneChain(a))
		}
		cl := g.newValue(v.Op, v.Type, args, entry, v.AuxInt, v.Aux)
		entry.Values = append(entry.Values, cl)
		constOf[v.ID] = cl
		return cl
	}
	// Return block(s); the trailing copy is the returned value
	// (BlockRet convention: last values match FuncSig.Results). The
	// two-exit form gets one ret block per exit target, each
	// returning its encoded index.
	ret := g.NewBlock(BlockRet)
	var ret2 *Block
	if twoExit {
		ret2 = g.NewBlock(BlockRet)
	}

	// Adopt the body blocks in the parent's deterministic order.
	defsIn := map[ValueID]bool{}
	var moved []*Block
	keep := f.Blocks[:0]
	for _, b := range f.Blocks {
		if inBody[b] {
			moved = append(moved, b)
			for _, v := range b.Values {
				defsIn[v.ID] = true
			}
		} else {
			keep = append(keep, b)
		}
	}
	f.Blocks = keep
	remap := func(a *Value) *Value {
		if defsIn[a.ID] {
			return a
		}
		if p := paramOf[a.ID]; p != nil {
			return p
		}
		return cloneChain(a)
	}
	for _, b := range moved {
		b.f = g
		b.ID = g.nextBlockID
		g.nextBlockID++
		g.Blocks = append(g.Blocks, b)
		for _, v := range b.Values {
			for i, a := range v.Args {
				v.Args[i] = remap(a)
			}
		}
		if b.Control != nil {
			b.Control = remap(b.Control)
		}
	}
	// Entry wiring: the preheader edge position now belongs to g's
	// entry, so header phis keep their positional args.
	pre := h.Preds[c.prei]
	h.Preds[c.prei] = Edge{Block: entry, Index: 0}
	entry.Succs = []Edge{{Block: h, Index: c.prei}}
	// Exit wiring: every edge that left the loop now returns instead.
	retOf := func(target *Block) *Block {
		if twoExit && target == c.exit2[1] {
			return ret2
		}
		return ret
	}
	for _, b := range moved {
		for i, s := range b.Succs {
			if s.Block == c.exit || (twoExit && (s.Block == c.exit2[0] || s.Block == c.exit2[1])) {
				r := retOf(s.Block)
				b.Succs[i] = Edge{Block: r, Index: len(r.Preds)}
				r.Preds = append(r.Preds, Edge{Block: b, Index: i})
			}
		}
	}
	if twoExit {
		for idx, r := range []*Block{ret, ret2} {
			enc := g.newValue(OpConst64, TypeI64, nil, r, int64(idx)<<32, nil)
			r.Values = append(r.Values, enc)
			if c.liveOut != nil {
				ext := g.newValue(OpExtend32To64U, TypeI64, []*Value{c.liveOut}, r, 0, nil)
				or := g.newValue(OpOr64, TypeI64, []*Value{enc, ext}, r, 0, nil)
				r.Values = append(r.Values, ext, or)
				enc = or
			}
			cp := g.newValue(OpCopy, TypeI64, []*Value{enc}, r, 0, nil)
			r.Values = append(r.Values, cp)
		}
	} else if c.liveOut != nil {
		cp := g.newValue(OpCopy, c.liveOut.Type, []*Value{c.liveOut}, ret, 0, nil)
		ret.Values = append(ret.Values, cp)
	}
	// Adopt values into g's table with fresh IDs; clear them from the
	// parent's (Compact would strand pointers otherwise).
	for _, b := range moved {
		for _, v := range b.Values {
			f.Values[v.ID] = nil
			v.ID = ValueID(len(g.Values))
			g.Values = append(g.Values, v)
		}
	}
	compactParentValues(f)

	// Parent-side call replacement: preheader → call block → exit(s).
	kind := BlockPlain
	if twoExit {
		kind = BlockIf
	}
	callBlk := f.NewBlock(kind)
	resType := TypeMem // void-call sentinel, keeps statement order
	if twoExit {
		resType = TypeI64
	} else if c.liveOut != nil {
		resType = c.liveOut.Type
	}
	callArgs := append([]*Value(nil), c.liveIns...)
	call := f.newValue(OpCallDirect, resType, callArgs, callBlk, -1, gname)
	callBlk.Values = append(callBlk.Values, call)
	var outVal *Value // decoded live-out replacing outside uses
	if twoExit {
		c32 := f.newValue(OpConst64, TypeI64, nil, callBlk, 32, nil)
		shr := f.newValue(OpShrU64, TypeI64, []*Value{call, c32}, callBlk, 0, nil)
		idx := f.newValue(OpTrunc64To32, TypeI32, []*Value{shr}, callBlk, 0, nil)
		callBlk.Values = append(callBlk.Values, c32, shr, idx)
		callBlk.Control = idx
		if c.liveOut != nil {
			outVal = f.newValue(OpTrunc64To32, TypeI32, []*Value{call}, callBlk, 0, nil)
			callBlk.Values = append(callBlk.Values, outVal)
		}
	} else if c.liveOut != nil {
		outVal = call
	}
	// preheader edge → call block.
	pre.Block.Succs[pre.Index] = Edge{Block: callBlk, Index: 0}
	callBlk.Preds = []Edge{{Block: pre.Block, Index: pre.Index}}
	if twoExit {
		// BlockIf: control non-zero → Succs[0]. Index 1 encodes
		// exit2[1], so it takes the then-slot.
		for slot, exit := range []*Block{c.exit2[1], c.exit2[0]} {
			var keptIdx []int
			for i, p := range exit.Preds {
				if !inBody[p.Block] {
					keptIdx = append(keptIdx, i)
				}
			}
			newPreds := make([]Edge, 0, len(keptIdx)+1)
			for _, i := range keptIdx {
				p := exit.Preds[i]
				p.Block.Succs[p.Index] = Edge{Block: exit, Index: len(newPreds)}
				newPreds = append(newPreds, p)
			}
			callBlk.Succs = append(callBlk.Succs, Edge{Block: exit, Index: len(newPreds)})
			for _, v := range exit.Values {
				if v.Op != OpPhi {
					continue
				}
				var loopArg *Value
				newArgs := make([]*Value, 0, len(newPreds)+1)
				for _, i := range keptIdx {
					newArgs = append(newArgs, v.Args[i])
				}
				for i, p := range exit.Preds {
					if inBody[p.Block] {
						loopArg = v.Args[i]
						break
					}
				}
				if loopArg == c.liveOut && c.liveOut != nil {
					loopArg = outVal
				}
				if loopArg == nil {
					return nil, fmt.Errorf("exit phi v%d has no loop arg", v.ID)
				}
				newArgs = append(newArgs, loopArg)
				v.Args = newArgs
			}
			exit.Preds = append(newPreds, Edge{Block: callBlk, Index: slot})
		}
		// Remaining outside uses of the live-out become the decode.
		if c.liveOut != nil {
			for _, b := range f.Blocks {
				for _, v := range b.Values {
					if v == call || v == outVal {
						continue
					}
					for i, a := range v.Args {
						if a == c.liveOut {
							v.Args[i] = outVal
						}
					}
				}
				if b.Control == c.liveOut {
					b.Control = outVal
				}
			}
		}
		return g, nil
	}
	// exit preds: drop the loop edges, add the call block once.
	exit := c.exit
	var keptIdx []int
	for i, p := range exit.Preds {
		if !inBody[p.Block] {
			keptIdx = append(keptIdx, i)
		}
	}
	newPreds := make([]Edge, 0, len(keptIdx)+1)
	for _, i := range keptIdx {
		p := exit.Preds[i]
		p.Block.Succs[p.Index] = Edge{Block: exit, Index: len(newPreds)}
		newPreds = append(newPreds, p)
	}
	callBlk.Succs = []Edge{{Block: exit, Index: len(newPreds)}}
	newPreds = append(newPreds, Edge{Block: callBlk, Index: 0})
	// Phi args follow the pred rebuild; the collapsed loop edges agree
	// on one value (eligibility), which the call result replaces when
	// loop-defined.
	for _, v := range exit.Values {
		if v.Op != OpPhi {
			continue
		}
		var loopArg *Value
		newArgs := make([]*Value, 0, len(newPreds))
		for _, i := range keptIdx {
			newArgs = append(newArgs, v.Args[i])
		}
		for i, p := range exit.Preds {
			if inBody[p.Block] {
				loopArg = v.Args[i]
				break
			}
		}
		if loopArg == c.liveOut && c.liveOut != nil {
			loopArg = outVal
		}
		if loopArg == nil {
			return nil, fmt.Errorf("exit phi v%d has no loop arg", v.ID)
		}
		newArgs = append(newArgs, loopArg)
		v.Args = newArgs
	}
	exit.Preds = newPreds
	// Remaining outside uses of the live-out become the call result.
	if c.liveOut != nil {
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				if v == call {
					continue
				}
				for i, a := range v.Args {
					if a == c.liveOut {
						v.Args[i] = outVal
					}
				}
			}
			if b.Control == c.liveOut {
				b.Control = outVal
			}
		}
	}
	return g, nil
}

// compactParentValues rebuilds f.Values without the nil slots left by
// an extraction, renumbering IDs densely.
func compactParentValues(f *Func) {
	vals := []*Value{nil}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			v.ID = ValueID(len(vals))
			vals = append(vals, v)
		}
	}
	f.Values = vals
	f.nextValueID = ValueID(len(vals))
}
