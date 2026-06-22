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
// This is intentionally conservative — single-phi natural loops
// with no CALL inside, only — to keep the failure mode bounded
// while we land it. Nested loops, multi-phi coalescing, and
// CALL-spanning carries are follow-ups.

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

	freePool := append([]string{}, coalesceReservedPool...)

	// Pre-compute P-is-used-only-by-V check inputs (function-wide,
	// independent of any one loop). For each candidate (P, V) we must
	// verify that V is the SOLE user of P in the entire function —
	// otherwise the coalesce would destroy P's value the moment V
	// writes to the shared register, and any later read of P (e.g.
	// another phi's back-edge arg, a second consumer in some other
	// block) would silently observe V's bytes instead.
	phiUsers := map[ssa.ValueID]int{}
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
	for _, blk2 := range f.Blocks {
		for _, v2 := range blk2.Values {
			for _, a := range v2.Args {
				if a == nil {
					continue
				}
				if act := resolveCopy(a); act != nil {
					phiUsers[act.ID]++
					noteUse(act.ID, blk2.ID)
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

		// Walk hdr's phis. A phi is a coalesce candidate when ALL of
		// its back-edge args resolve to the SAME value V — i.e. one
		// loop carry flowing back from every continue site. (When the
		// back edges carry different values we conservatively decline:
		// a single reserved register can hold only one of them, and
		// the emit-side short-circuit assumes the carry is already
		// resident.) V must be regHome-eligible and defined inside the
		// loop body. Each candidate gets its own register from freePool.
		for _, phi := range hdr.Values {
			if phi.Op != ssa.OpPhi {
				continue
			}
			// All back-edge args must resolve to the same V.
			var actual *ssa.Value
			sameV := true
			for _, bi := range backIdxs {
				if bi >= len(phi.Args) {
					sameV = false
					break
				}
				arg := phi.Args[bi]
				if arg == nil {
					sameV = false
					break
				}
				act := resolveCopy(arg)
				if act == nil {
					sameV = false
					break
				}
				if actual == nil {
					actual = act
				} else if act != actual {
					sameV = false
					break
				}
			}
			if !sameV || actual == nil {
				continue
			}
			if !planRegHomeEligibleOp(plan, actual.Op) {
				continue
			}
			// V must be defined inside the loop body. (If V is
			// defined OUTSIDE the body — e.g., a constant from
			// before the loop — coalescing has no value beyond
			// what the regular block-local regalloc already provides.)
			vBlk, ok := valueBlock[actual.ID]
			if !ok || !body[vBlk] {
				continue
			}
			// Phi's destination must be a scalar of a kind GP
			// registers can hold. Floats use a different pool we
			// don't tap here yet.
			if !isCoalesceableType(phi.Type) {
				continue
			}
			// Avoid double-coalescing: if either P or V already
			// has a regHome (set by an earlier loop iteration of
			// this pass), skip.
			if plan.regHome[phi.ID] != "" {
				continue
			}
			if plan.regHome[actual.ID] != "" {
				continue
			}
			// SAFETY: V's write to the shared register destroys
			// P's value. So P must have NO uses other than V
			// itself, anywhere in the function. (V is one of P's
			// users — phi.ID appears in V.Args, the OpSub32 /
			// OpAdd32 / etc. that reads the phi.) If P appears
			// as an arg in some OTHER value besides V, or as a
			// block control anywhere, the coalesce would silently
			// hand the new V bytes to that other reader. Deny.
			if phiUsers[phi.ID] != 1 || phiUsedAsControl[phi.ID] {
				continue
			}
			// SAFETY: the reserved register is one of R12/R13/R15,
			// none of which Go's ABI0 preserves across a CALL. The
			// loop body is proven call-free above, so the carry is
			// safe WHILE it stays in the loop. But a carry that is
			// also live OUT of the loop — used in a block not in
			// `body` — travels an exit path we have not proven
			// call-free. If any CALL lies on that path with the carry
			// still live across it (a very common shape: a scan-loop
			// counter consumed after the loop, past a helper call),
			// the callee clobbers the register and the out-of-loop
			// reader sees garbage; the corrupted value then feeds the
			// next iteration's address computation and the guest
			// segfaults. We must keep such a carry slot-resident
			// (decline the coalesce). A carry that escapes only onto
			// call-free exit paths (e.g. returned directly) is still
			// safe, so this checks for a CALL crossing, not mere
			// escape. Both P and V are checked; P's sole user is V
			// (verified above) so in practice only V can escape.
			if liveAcrossExternalCall(f, phi, body, blockHasCall, useBlocks) ||
				liveAcrossExternalCall(f, actual, body, blockHasCall, useBlocks) {
				continue
			}
			// Pick a register; bail if the dedicated pool is
			// drained (nested loops with many carries — rare).
			if len(freePool) == 0 {
				return
			}
			reg := freePool[0]
			freePool = freePool[1:]

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
			if plan.reservedRegs == nil {
				plan.reservedRegs = map[ssa.BlockID]map[string]bool{}
			}
			for bid := range body {
				m := plan.reservedRegs[bid]
				if m == nil {
					m = map[string]bool{}
					plan.reservedRegs[bid] = m
				}
				m[reg] = true
			}
		}
	}
}

// liveAcrossExternalCall reports whether value v is live across a CALL
// in some block OUTSIDE the loop body. The loop body is call-free by
// construction, so a reserved caller-save register (R12/R13/R15) only
// survives while the carry stays in the body; this is the check that a
// carry escaping onto an exit path does not have its register clobbered
// by an intervening call.
//
// It runs a single-value backward liveness over the out-of-body region:
// in-body blocks are treated as absorbing (the carry's def lives there
// and the body is safe), so propagation flows from out-of-body uses up
// to — and stops at — the loop body. A block outside the body that has
// a CALL and into which v is live on entry means v crosses that call.
//
// Phi-arg uses are attributed to the predecessor edge (the value is
// live-out of the predecessor, not live-through the phi's own block),
// so a carry handed to an out-of-loop phi via a call-free exit copy is
// correctly judged safe.
//
// useBlocks (the function-wide arg/control use index) is used only as a
// fast reject: a value with no out-of-body uses cannot be live across an
// out-of-body call, so the dataflow is skipped entirely.
func liveAcrossExternalCall(
	f *ssa.Func,
	v *ssa.Value,
	body map[ssa.BlockID]bool,
	blockHasCall map[ssa.BlockID]bool,
	useBlocks map[ssa.ValueID]map[ssa.BlockID]bool,
) bool {
	// Fast reject: no use outside the body at all.
	anyExternal := false
	for bid := range useBlocks[v.ID] {
		if !body[bid] {
			anyExternal = true
			break
		}
	}
	if !anyExternal {
		return false
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

	for _, blk := range f.Blocks {
		if body[blk.ID] {
			continue
		}
		if blockHasCall[blk.ID] && liveIn[blk.ID] {
			return true
		}
	}
	return false
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
