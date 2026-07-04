package asmgen

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Cross-block coalescing for loop-carry phis.
//
// The block-local regalloc denies a regHome to any value
// whose lifetime crosses a block boundary — including loop-carry
// values, which is the single biggest miss against Pure-Go on
// hot inner loops. Pure-Go's regalloc gives the loop counter a
// register and keeps it there for the entire loop body; the
// equivalent in our emitter would assign the same register R to
// the phi destination at the loop header AND to its back-edge
// arg, then reserve R across every block in the loop body so no
// other block-local decision can steal it.
//
// What this file does:
//
//  1. Find natural loops via the existing ssa.BackEdges helper.
//     A back-edge is (X, H) where H dominates X; the loop body
//     for that edge is { B | H dominates B and B can reach X via
//     paths inside the loop body, plus H itself }.
//
//  2. For each loop, walk the header's phis. A phi P whose
//     Args[backIdx] = V — where backIdx corresponds to the back-
//     edge predecessor X, V is regHome-eligible, AND V is defined
//     in some block inside the loop body — is a coalesce
//     candidate.
//
//  3. Coalesce safely. The reserved register must remain valid
//     across every block in the loop body, so the loop body must
//     not contain a CALL barrier (Go ABI0's caller-save rule
//     would clobber the carry across a CALL). Phi destinations
//     are not regHome-eligible under the block-local regalloc,
//     but this coalesce pass grants them one for the coalesced
//     group.
//
//  4. Assign the coalesce. plan.regHome[P.ID] = plan.regHome[V.ID]
//     = R; plan.reservedRegs[B][R] = true for every B in the loop
//     body; plan.coalescedPhi[P.ID] = R so emitPhiCopyValue can
//     short-circuit the back-edge copy.
//
// Two coalesce modes exist, tried in this order per phi:
//
//   - SHARED mode (the original): P and its unique back-edge carry V
//     share one register. Requires V to be P's SOLE user function-wide
//     (V's write to the shared register destroys P) and V's producer
//     to honour regHome on the write side. The back-edge copy is
//     elided entirely.
//
//   - OWN-REGISTER mode: P gets a register of its own; V is left
//     wherever it lives (slot or block-local register). Every edge
//     copy into P becomes a single `MOV <src>, R` (emitted by
//     EmitPhiCopyValueToReg on entry AND back edges), and every
//     in-loop read of P comes out of R via operandSrc. This fires for
//     the multi-user carries the shared mode must decline — the
//     varint-decoder shape (pos/shift/acc phis each read by several
//     ops per iteration) that pprof flagged as the dominant asm-vs-
//     pure-Go gap on the window suite. The per-iteration win is the
//     removal of the store-to-load forwarding chain through the
//     phi's stack slot.
//
// Both modes require the loop body to be CALL-free (Go ABI0
// preserves none of R12/R13/R15 across a CALL) and the carry to not
// be live across a CALL on any loop-exit path. The reserved register
// is excluded from the per-block linear scan in every loop-body
// block AND every out-of-body block the phi (or shared carry) is
// still live in — an exit-path reader consumes the register long
// after the body, so a block-local value grabbing R12 there would
// clobber the carry before its last read.

// coalesceReservedPool is the dedicated register set the
// coalesce pass draws from when reserving a register across a
// loop body. It is disjoint from the per-block linear-scan pool
// (gpRegPool) so a per-block decision cannot accidentally steal
// a reserved loop carry. R14 (Go's G pointer) and BP (frame
// pointer) stay reserved by the ABI; R12/R13/R15 are the
// unallocated tail of gpRegPool we leverage here. When the
// coalesce pass picks R12 for a loop carry, the per-block scan
// inside the loop body removes
// R12 from its free list and stays correct.
var coalesceReservedPool = []string{
	"R12", "R13", "R15",
}

// runCoalescePass identifies loop-carry phis and reserves a
// dedicated register for each safe candidate. Must run BEFORE
// the per-block linear scan (assignBlockRegHomes) so the per-
// block scans see the reserved registers in plan.reservedRegs.
func runCoalescePass(f *ssa.Func, plan *funcPlan) {
	if len(f.Blocks) == 0 {
		return
	}
	backEdges := ssa.BackEdges(f)
	if len(backEdges) == 0 {
		return
	}

	// Per-block CALL detection. opEmitsCall over-approximates;
	// branchFused and globalInline subtract the false positives
	// where the emit was actually short-circuited (no real CALL
	// reached the asm).
	blockHasCall := make(map[ssa.BlockID]bool, len(f.Blocks))
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if !opEmitsCall(v.Op) {
				continue
			}
			if plan.branchFused[v.ID] {
				continue
			}
			if _, ok := plan.globalInline[v.ID]; ok {
				continue
			}
			// Inline-emitted helpers (extends, rotates, div/rem,
			// float arith) produce no returning CALL and never touch
			// a reserved register — without this subtraction a
			// single i64.extend in a varint-decode loop marks the
			// whole loop call-unsafe and blocks every coalesce in it.
			if helperCallIsInline(plan, v) {
				continue
			}
			blockHasCall[blk.ID] = true
			break
		}
	}

	// Index blocks for fast lookup, and identify which block each
	// SSA value is defined in (used to determine "V's def block").
	valueBlock := make(map[ssa.ValueID]ssa.BlockID, len(f.Blocks)*16)
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			valueBlock[v.ID] = blk.ID
		}
	}

	pool := plan.coalescePool
	if pool == nil {
		pool = coalesceReservedPool
	}
	freePool := append([]string{}, pool...)

	// Pre-compute P-is-used-only-by-V check inputs (function-wide,
	// independent of any one loop). For each candidate (P, V) we must
	// verify that V is the SOLE user of P in the entire function —
	// otherwise the coalesce would destroy P's value the moment V
	// writes to the shared register, and any later read of P (e.g.
	// another phi's back-edge arg, a second consumer in some other
	// block) would silently observe V's bytes instead.
	phiUsers := map[ssa.ValueID]int{}
	// soleUser[id] remembers the (last-seen) value that reads id; it is
	// THE user exactly when phiUsers[id] == 1. The shared coalesce must
	// verify that P's single user IS the back-edge carry V — a phi whose
	// one user is anything else (the "lag" pattern: prev = phi(init, cur)
	// with prev consumed by an exit read or an unrelated op) reads P
	// AFTER V has already overwritten the shared register within the
	// iteration, observing the new value instead of the phi.
	soleUser := map[ssa.ValueID]*ssa.Value{}
	phiUsedAsControl := map[ssa.ValueID]bool{}
	// useBlocks[id] is the set of blocks that reference value id (as an
	// arg or as a block control). Used to verify a coalesce candidate's
	// live range is confined to the loop body: a carry value used in a
	// block OUTSIDE the loop escapes it, and the exit path may cross a
	// CALL that clobbers the reserved (caller-save) register — Go ABI0
	// preserves none of R12/R13/R15. The loop-body callFree check only
	// proves the body is call-free, not the exit paths.
	useBlocks := map[ssa.ValueID]map[ssa.BlockID]bool{}
	noteUse := func(id ssa.ValueID, bid ssa.BlockID) {
		s := useBlocks[id]
		if s == nil {
			s = map[ssa.BlockID]bool{}
			useBlocks[id] = s
		}
		s[bid] = true
	}
	// phiArgOf[id] is the set of OpPhi values (by ID) that reference
	// value id in their args, EXCLUDING self-references (a phi whose
	// back-edge arg is the phi itself is a harmless no-op copy — the
	// emit-side regHome-equality check skips it). Used by the
	// own-register mode's parallel-copy hazard guard: edge copies for
	// one edge are emitted in phi order with no staging for register
	// destinations, so a phi P that is read by a SIBLING phi of the
	// same header (or that reads a sibling) must stay slot-resident —
	// the slot path is protected by the staged-phi machinery, the
	// register path is not.
	phiArgOf := map[ssa.ValueID]map[ssa.ValueID]bool{}
	for _, blk2 := range f.Blocks {
		for _, v2 := range blk2.Values {
			for _, a := range v2.Args {
				if a == nil {
					continue
				}
				if act := resolveCopy(a); act != nil {
					phiUsers[act.ID]++
					soleUser[act.ID] = v2
					noteUse(act.ID, blk2.ID)
					if v2.Op == ssa.OpPhi && act.ID != v2.ID {
						s := phiArgOf[act.ID]
						if s == nil {
							s = map[ssa.ValueID]bool{}
							phiArgOf[act.ID] = s
						}
						s[v2.ID] = true
					}
				}
			}
		}
		if blk2.Control != nil {
			if act := resolveCopy(blk2.Control); act != nil {
				phiUsedAsControl[act.ID] = true
				noteUse(act.ID, blk2.ID)
			}
		}
	}

	// Group back edges by header. A loop header can be the target of
	// MORE THAN ONE back edge (e.g. a loop body with several `continue`
	// sites all branching back to the test). Each back edge's
	// naturalLoopBody only covers the blocks on paths to THAT edge's
	// source; the real loop — and the live range of any loop-carry phi
	// at the header — is the UNION over all back edges to the header.
	// We must therefore reason about that union, not each edge in
	// isolation: a carry assigned a register is only safe if the WHOLE
	// loop is CALL-free, and the register must be reserved across the
	// whole loop. Processing edges independently (as an earlier version
	// did) could pick a call-free sub-body, pin the carry to a register
	// globally, and then have a sibling back edge route the same carry
	// through a CALL that clobbers it — corrupting the loop counter.
	hdrOrder := make([]ssa.BlockID, 0, len(backEdges))
	hdrByID := map[ssa.BlockID]*ssa.Block{}
	srcsByHdr := map[ssa.BlockID][]*ssa.Block{}
	for _, e := range backEdges {
		src, hdr := e[0], e[1]
		if _, seen := srcsByHdr[hdr.ID]; !seen {
			hdrOrder = append(hdrOrder, hdr.ID)
			hdrByID[hdr.ID] = hdr
		}
		srcsByHdr[hdr.ID] = append(srcsByHdr[hdr.ID], src)
	}

	// reserve marks reg as untouchable by the block-local linear scan
	// in every listed block.
	reserve := func(reg string, blocks map[ssa.BlockID]bool) {
		if plan.reservedRegs == nil {
			plan.reservedRegs = map[ssa.BlockID]map[string]bool{}
		}
		for bid := range blocks {
			m := plan.reservedRegs[bid]
			if m == nil {
				m = map[string]bool{}
				plan.reservedRegs[bid] = m
			}
			m[reg] = true
		}
	}

	// Own-register candidates are collected across every loop first
	// and assigned AFTER all shared coalesces, ranked by in-loop use
	// count: the shared mode saves strictly more per iteration (the
	// back-edge copy disappears entirely), so it keeps first claim on
	// the 3-register pool, and when the leftovers cannot cover every
	// own-register candidate the hottest phis win.
	type ownRegCand struct {
		phi  *ssa.Value
		body map[ssa.BlockID]bool
		// liveOutside is the out-of-body live-in region (exit blocks
		// that still read the phi after the loop). Pre-checked to be
		// CALL-free; the register must stay reserved there.
		liveOutside map[ssa.BlockID]bool
		uses        int
	}
	var ownCands []ownRegCand

	// Process each loop (one per header) as a unit.
	for _, hid := range hdrOrder {
		hdr := hdrByID[hid]
		srcs := srcsByHdr[hid]

		// Union loop body over every back edge into this header.
		body := map[ssa.BlockID]bool{}
		for _, src := range srcs {
			for bid := range naturalLoopBody(f, src, hdr) {
				body[bid] = true
			}
		}
		if len(body) == 0 {
			continue
		}
		// The ENTIRE loop must be CALL-free for the carry to survive
		// in a register across every path through the body. Go ABI0's
		// caller-save rule clobbers the carry across any CALL.
		callFree := true
		for bid := range body {
			if blockHasCall[bid] {
				callFree = false
				break
			}
		}
		if !callFree {
			continue
		}
		// Back-edge arg positions: indices in hdr.Preds whose pred is
		// one of this loop's back-edge sources.
		backIdxs := make([]int, 0, len(srcs))
		for i, p := range hdr.Preds {
			for _, src := range srcs {
				if p.Block == src {
					backIdxs = append(backIdxs, i)
					break
				}
			}
		}
		if len(backIdxs) == 0 {
			continue
		}

		// Sibling-phi index for the own-register parallel-copy hazard
		// guard: edge copies for one edge are emitted in phi order, and
		// register-destination copies bypass the staged-phi temp
		// machinery, so a register phi must not read — or be read by —
		// another phi of the same header.
		hdrPhiIDs := map[ssa.ValueID]bool{}
		for _, q := range hdr.Values {
			if q.Op == ssa.OpPhi {
				hdrPhiIDs[q.ID] = true
			}
		}

		// Walk hdr's phis. Try the SHARED coalesce first (see the file
		// header); a phi the shared mode must decline can still become
		// an OWN-REGISTER candidate.
		for _, phi := range hdr.Values {
			if phi.Op != ssa.OpPhi {
				continue
			}
			// Phi's destination must be a scalar of a kind GP
			// registers can hold. Floats use a different pool we
			// don't tap here yet.
			if !isCoalesceableType(phi.Type) {
				continue
			}
			// Avoid double-coalescing: if P already has a regHome
			// (set by an earlier loop iteration of this pass), skip.
			if plan.regHome[phi.ID] != "" {
				continue
			}
			if trySharedCoalesce(f, plan, phi, hdr, body, backIdxs, valueBlock, phiUsers, soleUser, phiUsedAsControl, useBlocks, blockHasCall, &freePool, reserve) {
				continue
			}

			// ---- OWN-REGISTER candidacy ----
			// The pool only ever shrinks; once drained no later
			// candidate can be assigned either.
			if len(freePool) == 0 {
				continue
			}
			// Parallel-copy hazard guard (both directions, see
			// hdrPhiIDs above). Self-references are exempt: the
			// emit-side regHome-equality check turns them into
			// emitted-nothing no-ops.
			hazard := false
			for uid := range phiArgOf[phi.ID] {
				if hdrPhiIDs[uid] {
					hazard = true
					break
				}
			}
			if !hazard {
				for _, a := range phi.Args {
					if a == nil {
						continue
					}
					act := resolveCopy(a)
					if act != nil && act.ID != phi.ID && act.Op == ssa.OpPhi && hdrPhiIDs[act.ID] {
						hazard = true
						break
					}
				}
			}
			if hazard {
				continue
			}
			// Exit-path safety: the phi must not be live across a
			// CALL outside the loop (the register is caller-save).
			liveP := outOfBodyLiveIn(f, phi, body, useBlocks)
			if liveHitsCall(liveP, blockHasCall) {
				continue
			}
			// Worth a reserved register only when the loop actually
			// re-reads the phi; a single in-loop read breaks even
			// (one saved slot load vs one entry-edge register MOV)
			// and is not worth burning a pool slot on.
			uses := countInLoopUses(f, phi, body)
			if uses < 2 {
				continue
			}
			ownCands = append(ownCands, ownRegCand{phi: phi, body: body, liveOutside: liveP, uses: uses})
		}
	}

	// Assign own-register candidates from whatever the shared mode
	// left in the pool, hottest first. Ties break on phi ID to keep
	// the emitted asm deterministic across runs.
	sort.SliceStable(ownCands, func(i, j int) bool {
		if ownCands[i].uses != ownCands[j].uses {
			return ownCands[i].uses > ownCands[j].uses
		}
		return ownCands[i].phi.ID < ownCands[j].phi.ID
	})
	for _, c := range ownCands {
		if len(freePool) == 0 {
			break
		}
		if plan.regHome[c.phi.ID] != "" {
			continue
		}
		reg := freePool[0]
		freePool = freePool[1:]
		if dbg := os.Getenv("WASM2GO_COALESCE_DEBUG"); dbg != "" && (dbg == "1" || dbg == f.Name) {
			bodyIDs := make([]int, 0, len(c.body))
			for bid := range c.body {
				bodyIDs = append(bodyIDs, int(bid))
			}
			sort.Ints(bodyIDs)
			fmt.Fprintf(os.Stderr, "[coalesce-own] fn=%s phi=v%d reg=%s uses=%d body=%v\n",
				f.Name, c.phi.ID, reg, c.uses, bodyIDs)
		}
		plan.regHome[c.phi.ID] = reg
		plan.coalescedPhi[c.phi.ID] = reg
		reserve(reg, c.body)
		reserve(reg, c.liveOutside)
		// Every predecessor of the phi's block runs an entry- or
		// back-edge copy INTO the reserved register at its tail
		// (EmitPhiCopyValueToReg). Blocks outside body/liveOutside —
		// a forward entry pred in particular — must also be reserved,
		// or an allocator handing the register to a value whose last
		// use is a phi-arg read at that same tail gets clobbered by
		// the adjacent edge copy (found by the Phase R global scan:
		// entry-pred tail did `MOVL src, R13` right between another
		// value's R13 def and its edge-copy read).
		predBlocks := map[ssa.BlockID]bool{}
		for _, pe := range c.phi.Block.Preds {
			predBlocks[pe.Block.ID] = true
		}
		reserve(reg, predBlocks)
	}
}

// trySharedCoalesce attempts the original shared-register coalesce
// for one phi: P and its unique back-edge carry V share a reserved
// register, eliding the back-edge copy entirely. Returns true when
// the coalesce was assigned. The conditions are unchanged from the
// original single-mode pass; see the comments inline.
func trySharedCoalesce(
	f *ssa.Func,
	plan *funcPlan,
	phi *ssa.Value,
	hdr *ssa.Block,
	body map[ssa.BlockID]bool,
	backIdxs []int,
	valueBlock map[ssa.ValueID]ssa.BlockID,
	phiUsers map[ssa.ValueID]int,
	soleUser map[ssa.ValueID]*ssa.Value,
	phiUsedAsControl map[ssa.ValueID]bool,
	useBlocks map[ssa.ValueID]map[ssa.BlockID]bool,
	blockHasCall map[ssa.BlockID]bool,
	freePool *[]string,
	reserve func(reg string, blocks map[ssa.BlockID]bool),
) bool {
	// All back-edge args must resolve to the same V — one loop carry
	// flowing back from every continue site. (When the back edges
	// carry different values a single shared register cannot hold
	// them; the own-register mode may still apply.)
	var actual *ssa.Value
	for _, bi := range backIdxs {
		if bi >= len(phi.Args) {
			return false
		}
		arg := phi.Args[bi]
		if arg == nil {
			return false
		}
		act := resolveCopy(arg)
		if act == nil {
			return false
		}
		if actual == nil {
			actual = act
		} else if act != actual {
			return false
		}
	}
	if actual == nil {
		return false
	}
	// V's producer must honour regHome on the write side.
	if !planRegHomeEligibleOp(plan, actual.Op) {
		return false
	}
	// V must be defined inside the loop body. (If V is defined
	// OUTSIDE the body — e.g., a constant from before the loop —
	// coalescing has no value beyond what the regular block-local
	// regalloc already provides.)
	vBlk, ok := valueBlock[actual.ID]
	if !ok || !body[vBlk] {
		return false
	}
	if plan.regHome[actual.ID] != "" {
		return false
	}
	// SAFETY: V's write to the shared register destroys P's value.
	// So P must have NO uses other than V itself, anywhere in the
	// function. If P appears as an arg in some OTHER value besides V,
	// or as a block control anywhere, the coalesce would silently
	// hand the new V bytes to that other reader. Deny.
	if phiUsers[phi.ID] != 1 || phiUsedAsControl[phi.ID] {
		return false
	}
	// The single user must BE V. A phi whose one user is anything
	// else — the "lag" pattern `prev = phi(init, cur)` where cur does
	// NOT read prev and the one reader is an exit copy or an
	// unrelated op — reads P at a point that may execute AFTER V's
	// write to the shared register within the same iteration, so the
	// reader would observe the new carry instead of the phi. (Fn39800
	// in the integration corpus has exactly this shape in its hash-
	// probe loop; sharing there corrupts the probe index and the
	// guest heap.) The own-register mode handles these safely — its
	// back-edge copy runs at the very end of the edge, after every
	// in-iteration read.
	if soleUser[phi.ID] != actual {
		return false
	}
	// The shared register also makes V's OWN emit read P through the
	// home register, and the read must precede the emit's first
	// write to the home. emitBinALU32/64 and emitShift32/64 write
	// the home in their FIRST instruction (`MOV <src0>, home`), so P
	// may only appear as src0 — a `V = x <op> P` shape with x != P
	// would read the home after `MOV x, home` clobbered it. (When
	// src0 is also P the leading MOV is a self-move and every later
	// read still sees P.) Cmp / Load / Call emits write the home
	// last, so any arg position is safe there.
	switch actual.Op {
	case ssa.OpAdd32, ssa.OpSub32, ssa.OpMul32,
		ssa.OpAnd32, ssa.OpOr32, ssa.OpXor32,
		ssa.OpAdd64, ssa.OpSub64, ssa.OpMul64,
		ssa.OpAnd64, ssa.OpOr64, ssa.OpXor64,
		ssa.OpShl32, ssa.OpShrS32, ssa.OpShrU32,
		ssa.OpShl64, ssa.OpShrS64, ssa.OpShrU64:
		if len(actual.Args) > 0 && resolveCopy(actual.Args[0]) != phi {
			for _, a := range actual.Args[1:] {
				if a != nil && resolveCopy(a) == phi {
					return false
				}
			}
		}
	}
	// SAFETY: the reserved register is one of R12/R13/R15, none of
	// which Go's ABI0 preserves across a CALL. The loop body is
	// proven call-free by the caller, so the carry is safe WHILE it
	// stays in the loop. But a carry that is also live OUT of the
	// loop travels an exit path we have not proven call-free. If any
	// CALL lies on that path with the carry still live across it,
	// the callee clobbers the register and the out-of-loop reader
	// sees garbage. Keep such a carry slot-resident. A carry that
	// escapes only onto call-free exit paths (e.g. returned
	// directly) is still safe — the check is for a CALL crossing,
	// not mere escape. Both P and V are checked; P's sole user is V
	// (verified above) so in practice only V can escape.
	liveP := outOfBodyLiveIn(f, phi, body, useBlocks)
	if liveHitsCall(liveP, blockHasCall) {
		return false
	}
	liveV := outOfBodyLiveIn(f, actual, body, useBlocks)
	if liveHitsCall(liveV, blockHasCall) {
		return false
	}
	// Pick a register; decline if the dedicated pool is drained
	// (nested loops with many carries — rare).
	if len(*freePool) == 0 {
		return false
	}
	reg := (*freePool)[0]
	*freePool = (*freePool)[1:]

	if dbg := os.Getenv("WASM2GO_COALESCE_DEBUG"); dbg != "" && (dbg == "1" || dbg == f.Name) {
		bodyIDs := make([]int, 0, len(body))
		for bid := range body {
			bodyIDs = append(bodyIDs, int(bid))
		}
		sort.Ints(bodyIDs)
		fmt.Fprintf(os.Stderr, "[coalesce] fn=%s hdr=b%d phi=v%d carry=v%d reg=%s body=%v\n",
			f.Name, hdr.ID, phi.ID, actual.ID, reg, bodyIDs)
	}
	plan.regHome[phi.ID] = reg
	plan.regHome[actual.ID] = reg
	plan.coalescedPhi[phi.ID] = reg
	reserve(reg, body)
	// Reserve the phi block's predecessors too — their tails run the
	// edge copies that write the register (see the own-register mode
	// for the clobber this prevents).
	hdrPreds := map[ssa.BlockID]bool{}
	for _, pe := range phi.Block.Preds {
		hdrPreds[pe.Block.ID] = true
	}
	reserve(reg, hdrPreds)
	// The register must survive on every out-of-body block the carry
	// (or the phi) is still live in: an exit-path reader consumes it
	// via operandSrc long after the loop, and a block-local value
	// grabbing the register there would clobber the carry before its
	// last read.
	reserve(reg, liveP)
	reserve(reg, liveV)
	return true
}

// countInLoopUses counts how many in-loop reads the phi has: args of
// non-phi values in body blocks plus block controls. Edge-copy reads
// by sibling phis are excluded (the hazard guard already declined
// those candidates) and self-loop args are no-op copies.
func countInLoopUses(f *ssa.Func, phi *ssa.Value, body map[ssa.BlockID]bool) int {
	n := 0
	for _, blk := range f.Blocks {
		if !body[blk.ID] {
			continue
		}
		for _, v2 := range blk.Values {
			if v2.Op == ssa.OpPhi {
				continue
			}
			for _, a := range v2.Args {
				if a == nil {
					continue
				}
				if resolveCopy(a) == phi {
					n++
				}
			}
		}
		if blk.Control != nil && resolveCopy(blk.Control) == phi {
			n++
		}
	}
	return n
}

// liveHitsCall reports whether any block in the live-in set contains
// a CALL — the caller-save reserved register would be clobbered with
// the value still live.
func liveHitsCall(liveIn map[ssa.BlockID]bool, blockHasCall map[ssa.BlockID]bool) bool {
	for bid := range liveIn {
		if blockHasCall[bid] {
			return true
		}
	}
	return false
}

// outOfBodyLiveIn computes the set of out-of-body blocks value v is
// live into (or used in). The loop body is call-free by construction,
// so a reserved caller-save register (R12/R13/R15) survives while the
// carry stays in the body; the returned region is where the carry is
// STILL live after leaving the loop — the caller must (a) verify no
// block in it contains a CALL (liveHitsCall) and (b) reserve the
// register there so a block-local allocation cannot clobber the carry
// before its last exit-path read.
//
// It runs a single-value backward liveness over the out-of-body region:
// in-body blocks are treated as absorbing (the carry's def lives there
// and the body is safe), so propagation flows from out-of-body uses up
// to — and stops at — the loop body.
//
// Phi-arg uses are attributed to the predecessor edge (the value is
// live-out of the predecessor, not live-through the phi's own block),
// so a carry handed to an out-of-loop phi via a call-free exit copy is
// correctly scoped.
//
// useBlocks (the function-wide arg/control use index) is used only as a
// fast reject: a value with no out-of-body uses has an empty region, so
// the dataflow is skipped entirely and nil is returned.
func outOfBodyLiveIn(
	f *ssa.Func,
	v *ssa.Value,
	body map[ssa.BlockID]bool,
	useBlocks map[ssa.ValueID]map[ssa.BlockID]bool,
) map[ssa.BlockID]bool {
	// Fast reject: no use outside the body at all.
	anyExternal := false
	for bid := range useBlocks[v.ID] {
		if !body[bid] {
			anyExternal = true
			break
		}
	}
	if !anyExternal {
		return nil
	}

	usedIn := map[ssa.BlockID]bool{}
	liveIn := map[ssa.BlockID]bool{}
	liveOut := map[ssa.BlockID]bool{}
	for _, blk := range f.Blocks {
		if body[blk.ID] {
			continue
		}
		for _, v2 := range blk.Values {
			if v2.Op == ssa.OpPhi {
				// A phi arg is consumed on the edge from the matching
				// predecessor, so it makes v live-out of that pred, not
				// live-through this phi's block.
				for k, a := range v2.Args {
					if a == nil {
						continue
					}
					if resolveCopy(a) == v && k < len(blk.Preds) {
						if pb := blk.Preds[k].Block; pb != nil {
							liveOut[pb.ID] = true
						}
					}
				}
				continue
			}
			for _, a := range v2.Args {
				if a == nil {
					continue
				}
				if resolveCopy(a) == v {
					usedIn[blk.ID] = true
				}
			}
		}
		if blk.Control != nil && resolveCopy(blk.Control) == v {
			usedIn[blk.ID] = true
		}
	}

	for changed := true; changed; {
		changed = false
		for _, blk := range f.Blocks {
			if body[blk.ID] {
				continue
			}
			lo := liveOut[blk.ID]
			for _, e := range blk.Succs {
				s := e.Block
				if s == nil || body[s.ID] {
					continue
				}
				if liveIn[s.ID] {
					lo = true
				}
			}
			li := usedIn[blk.ID] || lo
			if lo != liveOut[blk.ID] {
				liveOut[blk.ID] = lo
				changed = true
			}
			if li != liveIn[blk.ID] {
				liveIn[blk.ID] = li
				changed = true
			}
		}
	}

	// Collect the live region: every out-of-body block v is live into.
	// liveIn subsumes usedIn and liveOut by construction of the
	// fixpoint (liveIn = usedIn ∨ liveOut), including the pure
	// phi-arg-attribution blocks (liveOut set directly above).
	region := map[ssa.BlockID]bool{}
	for _, blk := range f.Blocks {
		if body[blk.ID] {
			continue
		}
		if liveIn[blk.ID] {
			region[blk.ID] = true
		}
	}
	return region
}

// naturalLoopBody returns the set of blocks (by ID) that form
// the natural loop with header hdr induced by the back-edge
// src → hdr. The body is hdr plus every block that can reach
// src via predecessor traversal without going through hdr,
// limited to blocks dominated by hdr (which is implicit in the
// reach-from-src view but we add a check anyway for safety).
func naturalLoopBody(f *ssa.Func, src, hdr *ssa.Block) map[ssa.BlockID]bool {
	body := map[ssa.BlockID]bool{hdr.ID: true}
	if src == hdr {
		// Single-block self-loop — body is just hdr.
		return body
	}
	body[src.ID] = true
	// BFS backwards from src, stopping at hdr.
	stack := []*ssa.Block{src}
	for len(stack) > 0 {
		b := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range b.Preds {
			p := e.Block
			if p == nil || body[p.ID] {
				continue
			}
			body[p.ID] = true
			if p != hdr {
				stack = append(stack, p)
			}
		}
	}
	return body
}

// isCoalesceableType reports whether t is a GP-register-sized
// scalar the coalesce pass is willing to assign a reserved GP
// register to. Floats go through the SSE pool — we don't
// coalesce them here yet, mostly because the bench impact would
// be tiny (most loop carries are integer counters and pointers).
func isCoalesceableType(t ssa.Type) bool {
	switch t {
	case ssa.TypeI32, ssa.TypeI64, ssa.TypeBool:
		return true
	}
	return false
}
