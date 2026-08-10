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

// spliceCoalescePool is the arm64 register set the SPLICE-MODE
// coalesce draws from. Inline SIMD splice bodies confine themselves
// to R0–R15 / R25–R27 plus the V registers (the documented splice
// contract), so R19–R24 survive every splice; R22–R24 are reserved
// for the hoisted module state (memSize pointer, m.M, m), leaving
// R19–R21 to carry loop scalars — the reload-traffic lever gc can
// never pull, since it must assume every call site clobbers
// everything.
//
// CAVEAT for the fused-window follow-up: the fused splices
// (simdsplice_fuse_a64) additionally claim R20–R23 as window-wide
// state; when asmgen learns to emit fused windows, this pool must
// shrink to the disjoint remainder.
var spliceCoalescePool = []string{
	"R19", "R20", "R21",
}

// coalesceBlockHasCall computes per-block CALL presence for the
// coalesce safety rule. opEmitsCall over-approximates; branchFused
// and globalInline subtract the false positives where the emit was
// actually short-circuited (no real CALL reached the asm). exempt,
// when non-nil, marks additional values whose CALL will be replaced
// by an inline splice — the caller is responsible for enforcing that
// replacement at emit time.
func coalesceBlockHasCall(f *ssa.Func, plan *funcPlan, exempt func(*ssa.Value) bool) map[ssa.BlockID]bool {
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
			if exempt != nil && exempt(v) {
				continue
			}
			blockHasCall[blk.ID] = true
			break
		}
	}
	return blockHasCall
}

// runCoalescePass identifies loop-carry phis and reserves a
// dedicated register for each safe candidate. Must run BEFORE
// the per-block linear scan (assignBlockRegHomes) so the per-
// block scans see the reserved registers in plan.reservedRegs.
func runCoalescePass(f *ssa.Func, plan *funcPlan) {
	runCoalesceWith(f, plan, coalesceReservedPool, coalesceBlockHasCall(f, plan, nil), nil, false,
		func(op ssa.Op) bool { return planRegHomeEligibleOp(plan, op) }, isCoalesceableType, false)
}

// spliceCoalesceVPool holds the v128 loop-carry homes: V25–V31 sit
// above both the splice bodies' registers (V0–V4, F16) and the
// spare-register cache (V17–V24), so an accumulator parked here
// survives every splice in the loop. Real CALLs clobber the whole
// vector file (Go's ABI is caller-save), which the coalesce safety
// rules already exclude from the loop body; the emitter additionally
// forces every SIMD site in the function to splice once a v128 phi
// is coalesced, so no fallback CALL can appear later and clobber a
// live home.
var spliceCoalesceVPool = []string{
	"V25", "V26", "V27", "V28", "V29", "V30", "V31",
}

// runSpliceCoalescePass is the splice-mode arm64 variant: SIMD
// helper calls inside a loop do NOT bar coalescing (their inline
// splice bodies leave the pool registers untouched), but every such
// value in a coalesced loop is recorded in plan.mustSplice — the
// emitter turns a splice-table miss there into a per-function
// fallback instead of a CALL that would clobber the carry.
func runSpliceCoalescePass(f *ssa.Func, plan *funcPlan) {
	exempt := func(v *ssa.Value) bool {
		return v.Op == ssa.OpSimdCall || v.Op == ssa.OpSimdMemCall
	}
	onCoalesced := func(body map[ssa.BlockID]bool) {
		for _, blk := range f.Blocks {
			if !body[blk.ID] {
				continue
			}
			for _, v := range blk.Values {
				if exempt(v) {
					if plan.mustSplice == nil {
						plan.mustSplice = map[ssa.ValueID]bool{}
					}
					plan.mustSplice[v.ID] = true
				}
			}
		}
	}
	runCoalesceWith(f, plan, spliceCoalescePool, coalesceBlockHasCall(f, plan, exempt), onCoalesced, true,
		func(op ssa.Op) bool { return planRegHomeEligibleOp(plan, op) }, isCoalesceableType, false)

	// v128 loop carries (accumulators). A home in the vector file is
	// only safe while nothing CALLs: the function must be free of
	// non-SIMD callees, and once any phi is coalesced EVERY SIMD site
	// in the function must splice (a fallback CALL would clobber the
	// home) — enforced by marking them all mustSplice.
	if !plan.hasNonSimdCall {
		coalescedV := false
		runCoalesceWith(f, plan, spliceCoalesceVPool, coalesceBlockHasCall(f, plan, exempt),
			func(map[ssa.BlockID]bool) { coalescedV = true }, true,
			func(op ssa.Op) bool { return op == ssa.OpSimdCall || op == ssa.OpSimdMemCall },
			func(t ssa.Type) bool { return t == ssa.TypeV128 }, true)
		if coalescedV {
			if plan.mustSplice == nil {
				plan.mustSplice = map[ssa.ValueID]bool{}
			}
			for _, blk := range f.Blocks {
				for _, v := range blk.Values {
					if exempt(v) {
						plan.mustSplice[v.ID] = true
					}
				}
			}
		}
	}
}

// runCoalesceWith is the shared mechanism behind the two entry
// points; pool and call-detection differ, the safety rules do not.
// onCoalesced fires once per loop that coalesced at least one phi.
// relaxedUses selects the finer use-safety analysis
// (coalesceUsesSafe) instead of the original single-use rule. The
// relaxed rule admits the canonical counter/pointer carries (read by
// the loop condition or an address user AND by the bump); it is
// currently enabled for the splice-mode pass only, pending an A/B of
// the default pass with it.
func runCoalesceWith(f *ssa.Func, plan *funcPlan, pool []string, blockHasCall map[ssa.BlockID]bool, onCoalesced func(body map[ssa.BlockID]bool), relaxedUses bool, opEligibleFn func(ssa.Op) bool, typeOK func(ssa.Type) bool, liveOutOK bool) {
	if len(f.Blocks) == 0 {
		return
	}
	backEdges := ssa.BackEdges(f)
	if len(backEdges) == 0 {
		return
	}

	// Index blocks for fast lookup, and identify which block each
	// SSA value is defined in (used to determine "V's def block").
	valueBlock := make(map[ssa.ValueID]ssa.BlockID, len(f.Blocks)*16)
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			valueBlock[v.ID] = blk.ID
		}
	}

	freePool := append([]string{}, pool...)

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
		coalescedInLoop := false
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
			if !opEligibleFn(actual.Op) {
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
			if !typeOK(phi.Type) {
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
			// P's value; no read of P may observe it. The original
			// rule demands P have NO user but V anywhere. The
			// relaxed rule (splice mode) instead proves every read
			// executes before V's write in each iteration — see
			// coalesceUsesSafe.
			if relaxedUses {
				if !coalesceUsesSafe(f, body, src, phi, actual, liveOutOK) {
					continue
				}
			} else if phiUsers[phi.ID] != 1 || phiUsedAsControl[phi.ID] {
				continue
			}
			// Pick a register; stop coalescing when the dedicated
			// pool is drained (nested loops with many carries —
			// rare). Break rather than return so the loops already
			// coalesced still get their onCoalesced bookkeeping.
			if len(freePool) == 0 {
				break
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
			coalescedInLoop = true
		}
		if coalescedInLoop && onCoalesced != nil {
			onCoalesced(body)
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

// coalesceUsesSafe reports whether every read of phi P is guaranteed
// to execute BEFORE the carry value V overwrites their shared
// register within each iteration. Sufficient conditions:
//
//   - V is defined in the latch block (the back-edge source). The
//     latch runs LAST in every iteration: all its successors are the
//     header (back edge) or exit blocks outside the body, so a use
//     in any other body block has already executed when V's write
//     happens.
//   - Reads of P in the latch itself sit at earlier value indices
//     than V.
//   - P has no reads outside the loop body (it would observe V's
//     final bytes rather than its own), no reads via another phi's
//     edge copy (those run at latch end, after V), and no use as
//     the latch's own control (evaluated at latch end).
//
// V's own read of P is the carry (`n-1` reads the register it then
// writes — a single instruction on the emit side) and is exempt.
func coalesceUsesSafe(f *ssa.Func, body map[ssa.BlockID]bool, latch *ssa.Block, phi, vDef *ssa.Value, liveOutOK bool) bool {
	vIdx := -1
	for i, v2 := range latch.Values {
		if v2 == vDef {
			vIdx = i
			break
		}
	}
	if vIdx < 0 {
		// V lives outside the latch; ordering of later-block reads
		// relative to V's write is not established. Deny.
		return false
	}
	for _, blk := range f.Blocks {
		inBody := body[blk.ID]
		for i, v2 := range blk.Values {
			reads := false
			for _, a := range v2.Args {
				if a != nil && resolveCopy(a) == phi {
					reads = true
					break
				}
			}
			if !reads || v2 == vDef {
				continue
			}
			if !inBody {
				// Live-out read. GPR homes die with the loop (the
				// pool recycles and later calls clobber); a V home
				// survives to function end — the pool is consumed
				// once, the function is call-free by gate, and no
				// splice touches the home range — so consumers may
				// keep reading it.
				if liveOutOK {
					continue
				}
				return false
			}
			if v2.Op == ssa.OpPhi {
				return false // edge-copy read at block end
			}
			if blk == latch && i >= vIdx {
				return false // reads after V's write
			}
		}
		if blk.Control != nil && resolveCopy(blk.Control) == phi {
			if !inBody || blk == latch {
				return false
			}
		}
	}
	return true
}
