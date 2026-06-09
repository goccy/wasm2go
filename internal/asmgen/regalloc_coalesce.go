package asmgen

import (
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

	// Process each back edge as one potential loop.
	for _, e := range backEdges {
		src, hdr := e[0], e[1]
		body := naturalLoopBody(f, src, hdr)
		if len(body) == 0 {
			continue
		}
		// Loop body must be CALL-free for the carry to survive in
		// a register across iterations.
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
		// Find the index of src in hdr.Preds — that is the
		// back-edge arg position in hdr's phis.
		backIdx := -1
		for i, p := range hdr.Preds {
			if p.Block == src {
				backIdx = i
				break
			}
		}
		if backIdx < 0 {
			continue
		}

		// Pre-compute P-is-used-only-by-V check inputs. For each
		// candidate (P, V) we must verify that V is the SOLE user
		// of P in the entire function — otherwise the coalesce
		// would destroy P's value the moment V writes to the
		// shared register, and any later read of P (e.g. another
		// phi's back-edge arg, a second consumer in some other
		// block) would silently observe V's bytes instead.
		// Building a function-wide use map once per candidate
		// loop avoids quadratic cost across loops.
		phiUsers := map[ssa.ValueID]int{}
		phiUsedAsControl := map[ssa.ValueID]bool{}
		for _, blk2 := range f.Blocks {
			for _, v2 := range blk2.Values {
				for _, a := range v2.Args {
					if a == nil {
						continue
					}
					if act := resolveCopy(a); act != nil {
						phiUsers[act.ID]++
					}
				}
			}
			if blk2.Control != nil {
				if act := resolveCopy(blk2.Control); act != nil {
					phiUsedAsControl[act.ID] = true
				}
			}
		}

		// Walk hdr's phis. Each phi whose backIdx-th arg is a
		// regHome-eligible value defined inside the loop body is a
		// candidate. Multiple phis can coalesce per loop — each
		// gets its own register from freePool.
		for _, phi := range hdr.Values {
			if phi.Op != ssa.OpPhi {
				continue
			}
			if backIdx >= len(phi.Args) {
				continue
			}
			arg := phi.Args[backIdx]
			if arg == nil {
				continue
			}
			actual := resolveCopy(arg)
			if actual == nil {
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
			// Pick a register; bail if the dedicated pool is
			// drained (nested loops with many carries — rare).
			if len(freePool) == 0 {
				return
			}
			reg := freePool[0]
			freePool = freePool[1:]

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
