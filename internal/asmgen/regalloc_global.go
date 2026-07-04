package asmgen

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Function-wide linear-scan register allocation ("Phase R").
//
// The block-local allocator (assignBlockRegHomes) can only home
// values whose def and every use sit inside one block; anything
// cross-block round-trips through its SP slot at every block
// boundary, which chains a store-forwarding hop (~4-6 cycles) into
// every consumer. The 2026-07-04 pure-vs-asm matrix (docs/
// pure-vs-asm-benchmarks.md) put the asm backend 1.6-6.1× behind
// pure-Go, and slot residency of multi-block values is the
// structural difference — the Go compiler holds exactly these
// values in registers.
//
// This pass assigns registers to MULTI-block live ranges under a
// deliberately simple v1 model:
//
//   - Spill-free: a value either lives in one register for its whole
//     life or stays in its slot for its whole life. No reload code
//     is ever emitted, so the emit contract is unchanged from what
//     block-local regalloc and the loop-carry coalesce already
//     exercise (producers write plan.regHome, consumers read it via
//     operandSrc*).
//   - Call barriers: Go's ABI0 preserves nothing across CALL, and we
//     emit no save/restore code, so any interval containing a
//     CALL-emitting position is ineligible. The barrier set mirrors
//     emitBlock's re-prime condition exactly (opEmitsCall minus
//     branch-fused, minus inlined helpers, minus inlined global
//     accesses).
//   - Composition: the coalesce pass runs FIRST (its reservations are
//     honored here); this pass runs SECOND and records its own
//     assignments in plan.reservedRegs for every block the interval
//     touches; the block-local scan runs LAST and fills leftover
//     block-local values with whatever registers remain free.
//
// WASM2GO_NO_GLOBAL_REGALLOC=1 disables the pass (bisect kill
// switch, same convention as WASM2GO_NO_COALESCE).

// globalInterval is one candidate's live range in linearized block
// order. Positions are (blockOrdinal << 20) | valueIndex, which
// keeps comparisons cheap and gives every block a disjoint span
// (blocks never hold 2^20 values; buildpkg splits functions long
// before that).
type globalInterval struct {
	v          *ssa.Value
	start, end int
	firstBlk   int // ordinal of first touched block
	lastBlk    int // ordinal of last touched block
	uses       int
	sse        bool
}

const gposShift = 20

func gpos(blkOrd, valIdx int) int { return blkOrd<<gposShift | valIdx }

// computeGlobalRegHomes runs the function-wide linear scan. Must run
// after the coalesce pass (reads its reservations) and before
// assignBlockRegHomes (which reads the reservations this writes).
func computeGlobalRegHomes(f *ssa.Func, plan *funcPlan) {
	if os.Getenv("WASM2GO_NO_GLOBAL_REGALLOC") != "" {
		return
	}
	if len(f.Blocks) < 2 {
		return // single-block functions are fully served block-locally
	}

	ord := make(map[ssa.BlockID]int, len(f.Blocks))
	for i, b := range f.Blocks {
		ord[b.ID] = i
	}

	// ---- liveness (backward fixpoint). Per block: gen = values used
	// before (re)definition; kill = values defined. Phi args count as
	// uses at the tail of the PREDECESSOR (edge copy emission point);
	// phi defs count as normal defs; block Control counts as a use.
	gen := make([]map[ssa.ValueID]bool, len(f.Blocks))
	kill := make([]map[ssa.ValueID]bool, len(f.Blocks))
	for i, b := range f.Blocks {
		g := map[ssa.ValueID]bool{}
		k := map[ssa.ValueID]bool{}
		for _, v := range b.Values {
			if v.Op != ssa.OpPhi { // phi args are pred-edge uses, not here
				for _, a := range v.Args {
					aa := resolveCopy(a)
					if aa != nil && !k[aa.ID] {
						g[aa.ID] = true
					}
				}
			}
			k[v.ID] = true
		}
		if b.Control != nil {
			if cc := resolveCopy(b.Control); cc != nil && !k[cc.ID] {
				g[cc.ID] = true
			}
		}
		gen[i], kill[i] = g, k
	}
	liveIn := make([]map[ssa.ValueID]bool, len(f.Blocks))
	liveOut := make([]map[ssa.ValueID]bool, len(f.Blocks))
	for i := range f.Blocks {
		liveIn[i] = map[ssa.ValueID]bool{}
		liveOut[i] = map[ssa.ValueID]bool{}
	}
	for changed := true; changed; {
		changed = false
		for i := len(f.Blocks) - 1; i >= 0; i-- {
			b := f.Blocks[i]
			out := liveOut[i]
			for _, se := range b.Succs {
				si := ord[se.Block.ID]
				for id := range liveIn[si] {
					if !out[id] {
						out[id] = true
						changed = true
					}
				}
				// Phi args flowing on the b→succ edge are live at
				// b's tail.
				for _, phi := range se.Block.Values {
					if phi.Op != ssa.OpPhi {
						continue
					}
					if se.Index < len(phi.Args) {
						if aa := resolveCopy(phi.Args[se.Index]); aa != nil && !out[aa.ID] {
							out[aa.ID] = true
							changed = true
						}
					}
				}
			}
			in := liveIn[i]
			for id := range gen[i] {
				if !in[id] {
					in[id] = true
					changed = true
				}
			}
			for id := range out {
				if !kill[i][id] && !in[id] {
					in[id] = true
					changed = true
				}
			}
		}
	}

	// ---- call-barrier positions, mirroring emitBlock's re-prime
	// condition (a position that clobbers every caller-save register).
	var callPos []int
	for i, b := range f.Blocks {
		for vi, v := range b.Values {
			if opEmitsCall(v.Op) && !plan.branchFused[v.ID] && !helperCallIsInline(plan, v) {
				if _, inline := plan.globalInline[v.ID]; !inline {
					callPos = append(callPos, gpos(i, vi))
				}
			}
		}
	}

	// ---- build intervals for cross-block values.
	defAt := map[ssa.ValueID]int{}
	defBlk := map[ssa.ValueID]int{}
	useCount := map[ssa.ValueID]int{}
	for i, b := range f.Blocks {
		for vi, v := range b.Values {
			defAt[v.ID] = gpos(i, vi)
			defBlk[v.ID] = i
			for _, a := range v.Args {
				if aa := resolveCopy(a); aa != nil {
					useCount[aa.ID]++
				}
			}
		}
		if b.Control != nil {
			if cc := resolveCopy(b.Control); cc != nil {
				useCount[cc.ID]++
			}
		}
	}

	var cands []*globalInterval
	for i, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == ssa.OpPhi || v.Op == ssa.OpParam || v.Op == ssa.OpCopy {
				continue
			}
			if plan.branchFused[v.ID] || plan.branchFusedSkip[v.ID] {
				continue
			}
			if plan.regHome[v.ID] != "" || plan.coalescedPhi[v.ID] != "" {
				continue // coalesce already placed it
			}
			if !planRegHomeEligibleOp(plan, v.Op) {
				continue
			}
			// Cross-block only: live-out of the defining block. Block-
			// local values stay with assignBlockRegHomes (it packs
			// them tighter than whole-interval reservation would).
			if !liveOut[i][v.ID] {
				continue
			}
			iv := &globalInterval{
				v: v, start: defAt[v.ID], end: defAt[v.ID],
				firstBlk: i, lastBlk: i,
				uses: useCount[v.ID],
				sse:  v.Type == ssa.TypeF32 || v.Type == ssa.TypeF64,
			}
			// Extend over every block where the value is live (in or
			// out), plus in-block last uses in its def block. This
			// over-approximates lifetime holes — safe, just wider.
			for j, b2 := range f.Blocks {
				if liveIn[j][v.ID] || liveOut[j][v.ID] || j == i {
					s, e := gpos(j, 0), gpos(j, len(b2.Values)+1)
					if j == i {
						s = defAt[v.ID]
					}
					if s < iv.start {
						iv.start = s
					}
					if e > iv.end {
						iv.end = e
					}
					if j < iv.firstBlk {
						iv.firstBlk = j
					}
					if j > iv.lastBlk {
						iv.lastBlk = j
					}
				}
			}
			cands = append(cands, iv)
		}
	}
	if len(cands) == 0 {
		return
	}
	if os.Getenv("WASM2GO_GLOBAL_REGALLOC_STATS") != "" {
		defer func() {
			assignedN := 0
			for _, iv := range cands {
				if plan.regHome[iv.v.ID] != "" {
					assignedN++
				}
			}
			fmt.Fprintf(os.Stderr, "globalra %s: blocks=%d cands=%d assigned=%d calls=%d\n",
				f.Name, len(f.Blocks), len(cands), assignedN, len(callPos))
		}()
	}

	if dbg := os.Getenv("WASM2GO_GLOBAL_REGALLOC_DEBUG_FN"); dbg != "" && dbg == f.Name {
		fmt.Fprintf(os.Stderr, "=== global regalloc debug %s: %d blocks, %d callPos, %d cands\n",
			f.Name, len(f.Blocks), len(callPos), len(cands))
		for _, cp := range callPos {
			bo := cp >> gposShift
			fmt.Fprintf(os.Stderr, "  callpos ord=%d (blockID=%d) idx=%d\n", bo, f.Blocks[bo].ID, cp&(1<<gposShift-1))
		}
		if vs := os.Getenv("WASM2GO_GLOBAL_REGALLOC_DEBUG_VAL"); vs != "" {
			var vid int
			fmt.Sscanf(vs, "%d", &vid)
			for j, b2 := range f.Blocks {
				if liveIn[j][ssa.ValueID(vid)] || liveOut[j][ssa.ValueID(vid)] {
					fmt.Fprintf(os.Stderr, "  v%d live ord=%d blockID=%d in=%v out=%v\n",
						vid, j, b2.ID, liveIn[j][ssa.ValueID(vid)], liveOut[j][ssa.ValueID(vid)])
				}
			}
			for _, b2 := range f.Blocks {
				for _, phi := range b2.Values {
					if phi.Op != ssa.OpPhi {
						continue
					}
					for ai, a := range phi.Args {
						if aa := resolveCopy(a); aa != nil && int(aa.ID) == vid {
							fmt.Fprintf(os.Stderr, "  v%d is phi v%d arg[%d] in blockID=%d (pred blockID=%d)\n",
								vid, phi.ID, ai, b2.ID, phi.Block.Preds[ai].Block.ID)
						}
					}
				}
			}
		}
		for _, iv := range cands {
			crossed := false
			for _, cp := range callPos {
				if cp > iv.start && cp <= iv.end {
					crossed = true
					break
				}
			}
			fmt.Fprintf(os.Stderr, "  v%d %v uses=%d blk[%d..%d] pos[%d..%d] crossed=%v\n",
				iv.v.ID, iv.v.Op, iv.uses, iv.firstBlk, iv.lastBlk, iv.start, iv.end, crossed)
		}
	}

	// ---- drop call-crossing intervals. The ONLY call position a
	// live range may contain is the value's own defining call (a
	// call RESULT is written after the callee returns). Comparing
	// against the interval START is NOT equivalent: a loop-carried
	// value's start extends to its header block's first position,
	// and a call sitting right there (e.g. a call_indirect opening
	// the loop header) is crossed by the carried value on every
	// back-edge trip — that exact shape produced the Fn71 DI clobber
	// (call at gpos(hdr,0) == iv.start, phi edge copy reading the
	// stale register after the CALL).
	eligible := cands[:0]
	for _, iv := range cands {
		def := defAt[iv.v.ID]
		crossed := false
		for _, cp := range callPos {
			if cp >= iv.start && cp <= iv.end && cp != def {
				crossed = true
				break
			}
		}
		if !crossed {
			eligible = append(eligible, iv)
		}
	}
	if len(eligible) == 0 {
		return
	}

	// ---- linear scan, densest-first. With a 7-register pool and no
	// second chances (no splitting), giving hot values first pick
	// beats strict start-order; ties resolve to the shorter interval.
	sort.Slice(eligible, func(a, b int) bool {
		if eligible[a].uses != eligible[b].uses {
			return eligible[a].uses > eligible[b].uses
		}
		la := eligible[a].end - eligible[a].start
		lb := eligible[b].end - eligible[b].start
		if la != lb {
			return la < lb
		}
		return eligible[a].v.ID < eligible[b].v.ID
	})

	// Same pool discipline as the block-local scan: the m-cache
	// register is function-wide reserved and must never be handed
	// out — assigning it silently clobbers `m`, and every later
	// memop's `MOVQ 32(R11), BX` reads garbage. (Found the hard way:
	// the first Phase R prototype allocated R11 and googlesqlite's
	// analyzer init crashed on a nil deref.)
	gpPool := make([]string, 0, len(planGPRegPool(plan)))
	for _, r := range planGPRegPool(plan) {
		if r != plan.mCacheReg {
			gpPool = append(gpPool, r)
		}
	}
	ssePool := planSSERegPool(plan)
	type taken struct{ start, end int }
	assigned := map[string][]taken{}
	overlaps := func(reg string, iv *globalInterval) bool {
		for _, t := range assigned[reg] {
			if iv.start < t.end && t.start < iv.end {
				return true
			}
		}
		return false
	}
	reservedInRange := func(reg string, iv *globalInterval) bool {
		for j := iv.firstBlk; j <= iv.lastBlk; j++ {
			if plan.reservedRegs[f.Blocks[j].ID][reg] {
				return true
			}
		}
		return false
	}
	reserve := func(reg string, iv *globalInterval) {
		if plan.reservedRegs == nil {
			plan.reservedRegs = map[ssa.BlockID]map[string]bool{}
		}
		for j := iv.firstBlk; j <= iv.lastBlk; j++ {
			bid := f.Blocks[j].ID
			m := plan.reservedRegs[bid]
			if m == nil {
				m = map[string]bool{}
				plan.reservedRegs[bid] = m
			}
			m[reg] = true
		}
	}
	for _, iv := range eligible {
		pool := gpPool
		if iv.sse {
			pool = ssePool
		}
		for _, reg := range pool {
			if overlaps(reg, iv) || reservedInRange(reg, iv) {
				continue
			}
			plan.regHome[iv.v.ID] = reg
			assigned[reg] = append(assigned[reg], taken{iv.start, iv.end})
			reserve(reg, iv)
			break
		}
	}
	if dbg := os.Getenv("WASM2GO_GLOBAL_REGALLOC_DEBUG_FN"); dbg != "" && dbg == f.Name {
		for _, iv := range eligible {
			if r := plan.regHome[iv.v.ID]; r != "" {
				fmt.Fprintf(os.Stderr, "  ASSIGNED v%d -> %s blk[%d..%d]\n", iv.v.ID, r, iv.firstBlk, iv.lastBlk)
			}
		}
	}
}
