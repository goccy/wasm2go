package asmgen

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Emit-time block-local register allocator.
//
// This pass produces plan.regHome — a map from SSA value ID to a
// physical register name — for short-lived values whose lifetime
// is entirely within one block and never crosses a CALL barrier.
// The downstream emit functions consult plan.regHome via
// operandSrc{32,64,Float} (read-side) and a dst-side helper
// (write-side) to skip the slot store / reload pair when the
// producer and every consumer of a value can talk through a
// register directly.
//
// Design notes:
//
//   - Block-local only. We do NOT coordinate register assignment
//     across blocks: any value used outside its def block stays
//     slot-resident. Cross-block reg coordination needs phi-edge
//     conventions and a join-point reconciliation step (Go's
//     ssa.regalloc has both). Block-local is the easy 80%.
//
//   - Linear scan. Within a block, values are processed in
//     emission order. Each value's "lifetime" is [defIdx,
//     lastUseIdx]. A register is freed at the instruction AFTER
//     its owner's last use. At a value's def, if it is eligible,
//     we pick the lowest-numbered free register from the pool.
//
//   - Pool. The register pool excludes anything the existing
//     emit code uses as a scratch register. AX/CX/DX/BX/SI are
//     used by emitBinALU32, emitShift32, emitLoad/emitStore,
//     etc. BP is the Go frame pointer; R14 is the goroutine
//     pointer. That leaves {DI, R8, R9, R10, R11, R12, R13,
//     R15} for GP int values. SSE values use {X1..X7} (X0 is
//     scratch).
//
//   - CALL barrier. Go's ABI0 treats almost every register as
//     caller-save, so any reg-resident value whose lifetime
//     crosses a CALL would be clobbered. We mark such values
//     ineligible. "CALL barrier" means an op that emits a real
//     CALL instruction — opEmitsCall(v.Op) minus the cases
//     where the emit was short-circuited (plan.branchFused and
//     plan.globalInline).
//
//   - Single-use vs multi-use. Both are fine: the regalloc just
//     needs all uses to be inside the def block and before the
//     last-use boundary. Multi-use values commonly appear (e.g.,
//     a base address used by both a load and a later store) and
//     they benefit just as much.

// gpRegPool / sseRegPool are kept as package-level fallbacks only
// for the small number of test fixtures that build a funcPlan by
// hand without going through emitFunc; emitFunc populates
// plan.gpRegPool / plan.sseRegPool from the arch's GPRegPool /
// SSERegPool, and assignBlockRegHomes reads from plan when set,
// falling back to these vars otherwise. The fallback set matches
// the previous amd64-only shape so existing callers behave
// identically.
var gpRegPool = []string{
	"DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15",
}

var sseRegPool = []string{
	"X2", "X3", "X4", "X5", "X6", "X7",
}

// planGPRegPool / planSSERegPool resolve the pool for one plan,
// preferring the arch-provided set when emitFunc plumbed it
// through (the normal path) and falling back to the package var
// for hand-built test plans.
func planGPRegPool(plan *funcPlan) []string {
	if plan.gpRegPool != nil {
		return plan.gpRegPool
	}
	return gpRegPool
}
func planSSERegPool(plan *funcPlan) []string {
	if plan.sseRegPool != nil {
		return plan.sseRegPool
	}
	return sseRegPool
}

// planRegHomeEligibleOp consults the plan's arch-provided
// eligibility filter, falling back to the package-level filter
// when the plan was built without an arch (test fixtures).
func planRegHomeEligibleOp(plan *funcPlan, op ssa.Op) bool {
	if plan.regHomeEligibleOpFn != nil {
		return plan.regHomeEligibleOpFn(op)
	}
	return regHomeEligibleOp(op)
}

// regHomeEligibleOp reports whether the regalloc considers v.Op as
// a candidate for register residency. The op's PRODUCER emit
// function must be able to write directly to a register operand
// when plan.regHome[v.ID] is set; ops whose producers still always
// store to a slot are excluded so the contract "result in regHome"
// is never violated.
//
// We start small: just the integer ALU ops, because their producer
// (emitBinALU32 / emitBinALU64) is straightforward to teach and
// their results are the densest part of typical hot blocks. Other
// ops can be added incrementally once their producers honor
// regHome.
func regHomeEligibleOp(op ssa.Op) bool {
	switch op {
	case ssa.OpAdd32, ssa.OpSub32, ssa.OpMul32,
		ssa.OpAnd32, ssa.OpOr32, ssa.OpXor32,
		ssa.OpAdd64, ssa.OpSub64, ssa.OpMul64,
		ssa.OpAnd64, ssa.OpOr64, ssa.OpXor64,
		ssa.OpShl32, ssa.OpShrS32, ssa.OpShrU32,
		ssa.OpShl64, ssa.OpShrS64, ssa.OpShrU64,
		ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64,
		ssa.OpEq32, ssa.OpNe32,
		ssa.OpLtS32, ssa.OpLtU32, ssa.OpLeS32, ssa.OpLeU32,
		ssa.OpEq64, ssa.OpNe64,
		ssa.OpLtS64, ssa.OpLtU64, ssa.OpLeS64, ssa.OpLeU64,
		ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpMemSize, ssa.OpMemGrow:
		return true
	}
	return false
}

// computeRegHomes walks f and fills the plan.regHome map. Must be
// called AFTER planFunc has populated plan.branchFused and
// plan.globalInline (so the CALL-barrier check sees only the ops
// that actually emit a CALL).
//
// Setting WASM2GO_REGALLOC_DEBUG in the environment activates an
// extra post-pass that re-derives each value's lifetime by an
// independent walk and prints a stderr warning if any pair of
// values whose lifetimes overlap inside one block got assigned
// the same register. Useful for shaking out lifetime-miscount
// bugs without spamming logs in the steady state.
//
// Setting WASM2GO_REGALLOC_DUMP=<funcName> dumps the regalloc
// decisions for the matching function to stderr.
//
// Setting WASM2GO_NO_COALESCE disables the cross-block loop-carry
// coalesce pass (every carry stays slot-resident). Setting
// WASM2GO_COALESCE_DEBUG=<funcName> (or =1 for all) logs each coalesce
// decision — header, phi, carry value, reserved register, loop body —
// to stderr.
func computeRegHomes(f *ssa.Func, plan *funcPlan) {
	// The cross-block loop-carry coalesce pass runs FIRST so the
	// per-block linear scan sees the reserved-register set in
	// plan.reservedRegs and treats those registers as "in use" for
	// the duration of every loop-body block. Without this ordering
	// a per-block scan could pick a coalesced register for a
	// transient block-local value, silently corrupting the loop
	// carry it was holding for.
	// The cross-block loop-carry coalesce pass runs only on arches with
	// a validated coalesce emit path (plan.supportsCoalesce, set from
	// arch.SupportsLoopCarryCoalesce()). It is STRICTLY stronger than
	// block-local regalloc: it keeps a carry in a reserved register
	// across the whole loop with no per-iteration slot reload, so every
	// per-op emit that can produce the carry must honour plan.regHome on
	// the write side. An arch that only partially honours regHome (e.g.
	// arm64 today) must NOT run this pass or the carry is silently
	// clobbered. WASM2GO_NO_COALESCE additionally disables it everywhere
	// — a fast kill-switch for confirming or ruling out the pass when a
	// codegen miscompile is suspected.
	if plan.supportsCoalesce && os.Getenv("WASM2GO_NO_COALESCE") == "" {
		runCoalescePass(f, plan)
	}
	for _, blk := range f.Blocks {
		assignBlockRegHomes(blk, f, plan)
	}
	if os.Getenv("WASM2GO_REGALLOC_DEBUG") != "" {
		verifyRegHomes(f, plan)
	}
	if dumpName := os.Getenv("WASM2GO_REGALLOC_DUMP"); dumpName != "" && dumpName == f.Name {
		dumpRegHomes(f, plan)
	}
}

// dumpRegHomes prints the function's per-block value list with
// each value's def block, its Op, the regHome reg (if any), and a
// brief use summary. Used to inspect regalloc decisions for a
// specific function during debugging.
func dumpRegHomes(f *ssa.Func, plan *funcPlan) {
	fmt.Fprintf(os.Stderr, "=== regalloc dump for %s ===\n", f.Name)
	for _, blk := range f.Blocks {
		fmt.Fprintf(os.Stderr, "block %d:\n", blk.ID)
		for i, v := range blk.Values {
			reg := plan.regHome[v.ID]
			args := ""
			for j, a := range v.Args {
				if j > 0 {
					args += ", "
				}
				if a == nil {
					args += "<nil>"
				} else {
					args += fmt.Sprintf("v%d", a.ID)
				}
			}
			fmt.Fprintf(os.Stderr, "  %d: v%d %v(%s) %v home=%q\n",
				i, v.ID, v.Op, args, v.Type, reg)
		}
		if blk.Control != nil {
			fmt.Fprintf(os.Stderr, "  control: v%d\n", blk.Control.ID)
		}
		fmt.Fprintf(os.Stderr, "  succs: ")
		for _, s := range blk.Succs {
			if s.Block != nil {
				fmt.Fprintf(os.Stderr, "b%d ", s.Block.ID)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
}

// verifyRegHomes is a debug-only sanity check that two values
// assigned the same register never have overlapping lifetimes
// within the same block. Triggered by WASM2GO_REGALLOC_DEBUG.
func verifyRegHomes(f *ssa.Func, plan *funcPlan) {
	for _, blk := range f.Blocks {
		idx := map[ssa.ValueID]int{}
		for i, v := range blk.Values {
			idx[v.ID] = i
		}
		lastUse := map[ssa.ValueID]int{}
		for i, v := range blk.Values {
			for _, a := range v.Args {
				if a == nil {
					continue
				}
				actual := resolveCopy(a)
				if actual == nil {
					continue
				}
				if _, ok := idx[actual.ID]; ok {
					if i > lastUse[actual.ID] {
						lastUse[actual.ID] = i
					}
				}
			}
		}
		if blk.Control != nil {
			if actual := resolveCopy(blk.Control); actual != nil {
				if _, ok := idx[actual.ID]; ok {
					lastUse[actual.ID] = len(blk.Values)
				}
			}
		}
		type span struct {
			id    ssa.ValueID
			start int
			end   int
		}
		byReg := map[string][]span{}
		for vid, reg := range plan.regHome {
			s, ok := idx[vid]
			if !ok {
				continue
			}
			e := lastUse[vid]
			if e < s {
				e = s
			}
			byReg[reg] = append(byReg[reg], span{vid, s, e})
		}
		for reg, spans := range byReg {
			for i := 0; i < len(spans); i++ {
				for j := i + 1; j < len(spans); j++ {
					a, b := spans[i], spans[j]
					if a.start <= b.end && b.start <= a.end {
						fmt.Fprintf(os.Stderr, "REGALLOC CONFLICT: block %d reg %s: v%d [%d,%d] vs v%d [%d,%d]\n",
							blk.ID, reg, a.id, a.start, a.end, b.id, b.start, b.end)
					}
				}
			}
		}
	}
}

// assignBlockRegHomes runs the linear-scan pass over a single
// block.
func assignBlockRegHomes(blk *ssa.Block, f *ssa.Func, plan *funcPlan) {
	// Step 1: per-value index within the block (def position).
	defIdx := make(map[ssa.ValueID]int, len(blk.Values))
	for i, v := range blk.Values {
		defIdx[v.ID] = i
	}

	// Step 2: lastUseIdx within the block. Initially -1 (unused
	// inside the block). Walking the block's own value list
	// captures intra-block uses; we treat the Control of THIS
	// block as a use at index len(blk.Values).
	lastUseIdx := make(map[ssa.ValueID]int, len(blk.Values))
	for i, v := range blk.Values {
		for _, a := range v.Args {
			if a == nil {
				continue
			}
			actual := resolveCopy(a)
			if actual == nil {
				continue
			}
			if di, ok := defIdx[actual.ID]; ok && di < i {
				if i > lastUseIdx[actual.ID] {
					lastUseIdx[actual.ID] = i
				}
			}
		}
	}
	if blk.Control != nil {
		actual := resolveCopy(blk.Control)
		if actual != nil {
			if _, ok := defIdx[actual.ID]; ok {
				lastUseIdx[actual.ID] = len(blk.Values)
			}
		}
	}

	// Step 2b: phi-arg uses on outgoing edges. A value used as a
	// phi argument is READ on the predecessor edge — i.e., at the
	// end of THIS block — not at the phi's own index inside the
	// successor. Phis live in the SUCCESSOR block, so walking
	// blk's own values would only catch the self-loop case (and
	// even there only when the phi sits later than the value in
	// linear order, which it usually doesn't). The right scan is:
	// for every successor of blk, look at every phi at the head
	// of that successor and mark each Args[i] that resolves to a
	// value defined in blk as live until len(blk.Values). The
	// cross-block check at Step 3 still disqualifies these values
	// from regalloc when the succ is a DIFFERENT block (the value
	// is observably cross-block), but the SELF-LOOP succ == blk
	// case keeps the value block-local — and without this fixup
	// the linear scan would reuse its register before the phi-
	// edge copy ran, silently corrupting the loop carry.
	for _, succ := range blk.Succs {
		if succ.Block == nil {
			continue
		}
		for _, phi := range succ.Block.Values {
			if phi.Op != ssa.OpPhi {
				continue
			}
			for _, a := range phi.Args {
				if a == nil {
					continue
				}
				actual := resolveCopy(a)
				if actual == nil {
					continue
				}
				if _, ok := defIdx[actual.ID]; ok {
					lastUseIdx[actual.ID] = len(blk.Values)
				}
			}
		}
	}

	// Step 3: cross-block check. Any value used by another block's
	// value (as an Arg) or by another block's Control is
	// disqualified. Phi destinations and phi-arg sources are also
	// disqualified (phis live across edges by construction).
	crossBlock := make(map[ssa.ValueID]bool, len(blk.Values))

	// Step 3a: loop-carry phi-arg detection. A value V defined in
	// blk that is referenced by ONE OF BLK'S OWN PHIS — phi.Args[i]
	// = V where pred[i] is some block X different from blk — means V
	// is read on the X → blk edge. For that to be a well-formed SSA
	// arg, V must be ALIVE at end of X, which only happens if a path
	// blk → ... → X carries V forward. In other words V is a loop
	// carry: it crosses block boundaries on its way back into blk.
	//
	// The main cross-block sweep below skips b2 == blk to avoid
	// double-counting in-block uses; that skip would also throw out
	// this case if we relied on it alone. Mark these loop-carry
	// values cross-block here so the linear scan denies them a
	// register — the actual implementation of "value carried across
	// many blocks in a register" needs proper join-point
	// reconciliation that this block-local allocator does not yet
	// do, and the safe answer is to keep them slot-resident.
	//
	// A naïve "just extend lastUseIdx to end of blk" doesn't work:
	// the phi-edge-copy that reads V actually lives at the END of
	// some block X (the back-edge predecessor), and the path from
	// V's def in blk to that read passes through intermediate
	// blocks (e.g. blk → b4 → b5 → blk). Those intermediate blocks
	// freely reuse V's register for their own regalloc'd values,
	// so by the time the phi-edge-copy emits, V's reg holds
	// something else. The block-local model has no way to coordinate
	// "reserve this reg across these blocks" — that needs the join-
	// point pass.
	for _, v := range blk.Values {
		if v.Op != ssa.OpPhi {
			continue
		}
		for _, a := range v.Args {
			if a == nil {
				continue
			}
			actual := resolveCopy(a)
			if actual == nil {
				continue
			}
			if _, ok := defIdx[actual.ID]; ok {
				crossBlock[actual.ID] = true
			}
		}
	}

	for _, b2 := range f.Blocks {
		if b2 == blk {
			continue
		}
		for _, v2 := range b2.Values {
			for _, a := range v2.Args {
				if a == nil {
					continue
				}
				actual := resolveCopy(a)
				if actual == nil {
					continue
				}
				if _, ok := defIdx[actual.ID]; ok {
					crossBlock[actual.ID] = true
				}
			}
		}
		if b2.Control != nil {
			actual := resolveCopy(b2.Control)
			if actual != nil {
				if _, ok := defIdx[actual.ID]; ok {
					crossBlock[actual.ID] = true
				}
			}
		}
	}

	// Step 4: CALL-barrier index list. For each value v in this
	// block, the value's lifetime [defIdx[v.ID]+1, lastUseIdx[v.ID]]
	// must not contain any op that actually emits a CALL — that
	// would clobber every caller-save register. opEmitsCall is the
	// over-approximation; branchFused and globalInline subtract the
	// false positives where the producer was short-circuited.
	hasCallAt := make([]bool, len(blk.Values))
	for i, v := range blk.Values {
		if !opEmitsCall(v.Op) {
			continue
		}
		if plan.branchFused[v.ID] {
			continue
		}
		if _, ok := plan.globalInline[v.ID]; ok {
			continue
		}
		// Inline-emitted helpers clobber only the fixed scratches
		// (AX/CX/DX/X0/X1), never a pool register — a lifetime that
		// crosses one is register-safe.
		if helperCallIsInline(plan, v) {
			continue
		}
		hasCallAt[i] = true
	}

	// Step 5: linear scan. Maintain per-register "free?" and per-
	// register "owner's lastUseIdx" so we know when to release.
	type activeEntry struct {
		owner   ssa.ValueID
		lastIdx int
	}
	gpActive := map[string]activeEntry{}
	sseActive := map[string]activeEntry{}
	// Subtract any registers the cross-block coalesce pass reserved
	// for a loop-carry value passing through this block. Those
	// registers are "in use" for the entire block — the per-block
	// linear scan must not touch them.
	// Also subtract mCacheReg — the function-wide cache of `m`
	// (FP+0). It is reserved across every block of the function so
	// emit code can dereference m without bouncing through the arg
	// slot.
	reserved := plan.reservedRegs[blk.ID]
	gpPool := planGPRegPool(plan)
	gpFree := make([]string, 0, len(gpPool))
	for _, r := range gpPool {
		if reserved[r] {
			continue
		}
		if r == plan.mCacheReg {
			continue
		}
		gpFree = append(gpFree, r)
	}
	ssePool := planSSERegPool(plan)
	sseFree := make([]string, 0, len(ssePool))
	for _, r := range ssePool {
		if reserved[r] {
			continue
		}
		sseFree = append(sseFree, r)
	}

	popFree := func(pool *[]string) string {
		if len(*pool) == 0 {
			return ""
		}
		r := (*pool)[0]
		*pool = (*pool)[1:]
		return r
	}
	pushFree := func(pool *[]string, r string) {
		*pool = append(*pool, r)
	}

	// expireFrom releases every register in active whose lifetime ended
	// before idx, returning it to free. The expired registers are collected
	// and sorted before they are pushed back: ranging a Go map yields a
	// random order, and since popFree hands out registers from the front of
	// the pool, a map-order push would make the next value's register choice
	// depend on map iteration — i.e. non-deterministic asm output across runs.
	// Sorting keeps the freed-register order stable so codegen is reproducible.
	expireFrom := func(active map[string]activeEntry, free *[]string, idx int) {
		var expired []string
		for r, e := range active {
			if e.lastIdx < idx {
				expired = append(expired, r)
			}
		}
		sort.Strings(expired)
		for _, r := range expired {
			delete(active, r)
			pushFree(free, r)
		}
	}
	expireAt := func(idx int) {
		expireFrom(gpActive, &gpFree, idx)
		expireFrom(sseActive, &sseFree, idx)
	}

	for i, v := range blk.Values {
		expireAt(i)

		// Skip ineligible values: they remain slot-resident.
		if crossBlock[v.ID] {
			continue
		}
		last := lastUseIdx[v.ID]
		if last <= i {
			// Never used inside this block (last stays at 0 from
			// the default, or equals defIdx for a value that is
			// only used by an emit-side side effect). Slot-resident.
			continue
		}
		if !planRegHomeEligibleOp(plan, v.Op) {
			continue
		}
		// Branch-fused values are short-circuited at emit time —
		// the BlockIf terminator reads their cond.Args directly and
		// the value's own emit is skipped. Giving them a regHome
		// would never produce a write to that register, but a
		// downstream consumer might still read it via operandSrc
		// and get whatever stale bytes the previous owner left
		// behind. branchFused values are guaranteed to have ONE use
		// (the BlockIf control) — see Pass 4 in planFunc — so the
		// slot they keep is never read either; skipping regHome
		// just keeps the contract clean.
		if plan.branchFused[v.ID] {
			continue
		}

		// CALL between (i, last]? If so, the lifetime crosses a
		// register-clobbering boundary; skip.
		hit := false
		for j := i + 1; j <= last && j < len(blk.Values); j++ {
			if hasCallAt[j] {
				hit = true
				break
			}
		}
		if hit {
			continue
		}

		// Choose pool by type.
		var pool *[]string
		var active map[string]activeEntry
		switch v.Type {
		case ssa.TypeI32, ssa.TypeI64, ssa.TypeBool:
			pool = &gpFree
			active = gpActive
		case ssa.TypeF32, ssa.TypeF64:
			pool = &sseFree
			active = sseActive
		default:
			continue
		}

		reg := popFree(pool)
		if reg == "" {
			// No free register; value falls back to its slot.
			continue
		}
		active[reg] = activeEntry{owner: v.ID, lastIdx: last}
		plan.regHome[v.ID] = reg
	}
}
