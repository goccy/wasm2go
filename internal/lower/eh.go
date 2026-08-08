package lower

import (
	"fmt"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Branch-based exception handling.
//
// A wasm exception is not a Go panic here. `throw` writes the tag and its
// operands into the module's exception state, sets a pending flag, and
// returns; every call that MAY raise one is followed by a check of that flag
// which branches either to an enclosing try's handler dispatch or to a
// propagating return. Handlers are therefore ordinary blocks with real CFG
// predecessors, and an EH function is ordinary straight-line code — which is
// what lets the asm backend transform it (a panic/recover lowering pins every
// such function to a compiled-Go fallback body, and the whole point of that
// backend is to keep generated Go small).
//
// The cost is a predictable branch on an almost-always-zero flag after calls
// the throw analysis cannot rule out; ThrowSet keeps that set small.

// excTarget describes where a raised exception goes from the current point:
// an enclosing try's dispatch block, or out of the function.
type excTarget struct {
	dispatch *ssa.Block // nil ⇒ propagate out of the function
	// stackBase is the operand-stack height the dispatch block runs at
	// (the try's entry height — an exception unwinds the operands the
	// protected body pushed).
	stackBase int
}

// currentExcTarget finds where an exception raised at the current point
// lands: the innermost enclosing try still executing its PROTECTED BODY. A
// frame whose handler is already running cannot catch again, so it is
// skipped — the exception belongs to whatever encloses that try.
func (ls *lowerState) currentExcTarget() excTarget {
	for i := len(ls.ctrl) - 1; i >= 0; i-- {
		f := ls.ctrl[i]
		if f.kind != ctrlTry || f.inHandler || f.tryRegion == nil {
			continue
		}
		if f.excDispatch == nil {
			continue
		}
		return excTarget{dispatch: f.excDispatch, stackBase: f.stackHeightAtEntry}
	}
	return excTarget{}
}

// propagateBlock returns the function's shared "an exception is propagating
// out of here" block: it returns zero values, leaving the flag set for the
// caller's check to observe. Created on first use.
func (ls *lowerState) propagateBlock() *ssa.Block {
	if ls.excPropagate != nil {
		return ls.excPropagate
	}
	blk := ls.b.NewBlock(ssa.BlockPlain)
	saved := ls.b.Current()
	ls.b.SetCurrent(blk)
	rets := make([]*ssa.Value, len(ls.ft.Results))
	for i, t := range ls.ft.Results {
		rets[i] = zeroValueOf(ls.b, toSSAType(t))
	}
	ls.b.FinishRet(rets...)
	ls.b.SetCurrent(saved)
	ls.excPropagate = blk
	return blk
}

// emitExcCheck splits the current block after a call that may raise: the
// pending flag selects the exception path (an enclosing handler dispatch, or
// a propagating return) over the normal continuation.
//
// The operand stack at the branch is whatever the call left; the exception
// edge carries no operands (they unwind), so only the locals are recorded
// for the dispatch block's phis.
func (ls *lowerState) emitExcCheck() {
	tgt := ls.currentExcTarget()
	var excBlk *ssa.Block
	if tgt.dispatch != nil {
		excBlk = tgt.dispatch
		ls.recordIncoming(excBlk, 0)
	} else {
		excBlk = ls.propagateBlock()
	}
	cont := ls.b.NewBlock(ssa.BlockPlain)
	ls.recordIncoming(cont, len(ls.stack))

	cur := ls.b.Current()
	pending := ls.b.NewValue(ssa.OpExcPending, ssa.TypeI32)
	cur.Kind = ssa.BlockIf
	cur.Control = pending
	ssa.AddEdge(cur, excBlk)
	ssa.AddEdge(cur, cont)

	ls.b.SetCurrent(cont)
	// The continuation inherits the pre-branch state verbatim; resolving
	// its single incoming edge keeps the phi bookkeeping uniform.
	base := 0 // the continuation consumes no operands; resolve from the full stack
	if err := ls.resolveIncoming(cont, len(ls.stack), base); err != nil {
		// resolveIncoming only fails on inconsistent bookkeeping, which
		// would be a lowering bug; surface it through the recover in
		// LowerFunction rather than silently continuing.
		panic(err)
	}
}

// mayThrowCall reports whether a direct call to funcIdx needs a post-call
// exception check.
func (ls *lowerState) mayThrowCall(funcIdx uint32) bool {
	return ls.throwSet.AnyThrows() && ls.throwSet.MayThrow(funcIdx)
}

// mayThrowIndirect reports whether a call_indirect of typeIdx needs one.
func (ls *lowerState) mayThrowIndirect(typeIdx uint32) bool {
	return ls.throwSet.AnyThrows() && ls.throwSet.IndirectMayThrow(typeIdx)
}

// handleTryBranch opens a `try` region under the branch-based model: the
// protected body falls through from the current block, and a dispatch block
// is pre-allocated for the check-and-branches inside it to target.
func (ls *lowerState) handleTryBranch(results int) {
	entryBlk := ls.b.NewBlock(ssa.BlockPlain)
	postBlk := ls.b.NewBlock(ssa.BlockPlain)
	dispatchBlk := ls.b.NewBlock(ssa.BlockPlain)

	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	ssa.AddEdge(cur, entryBlk)
	ls.b.SetCurrent(entryBlk)

	region := &ssa.TryRegion{Entry: entryBlk, Post: postBlk, Dispatch: dispatchBlk}
	ls.b.Func().TryRegions = append(ls.b.Func().TryRegions, region)

	ls.ctrl = append(ls.ctrl, &ctrlFrame{
		kind:               ctrlTry,
		target:             postBlk,
		fallthrough_:       postBlk,
		resultCount:        results,
		stackHeightAtEntry: len(ls.stack),
		tryRegion:          region,
		excDispatch:        dispatchBlk,
	})
}

// sealDeadExcBlocks terminates any block the EH lowering created that the
// control flow never reached: a dispatch for a body that cannot raise, or a
// clause chain whose tests are all dead. They carry no code, so marking them
// unreachable lets PruneDeadBlocks drop them before verification.
func sealDeadExcBlocks(region *ssa.TryRegion, extra ...*ssa.Block) {
	seal := func(b *ssa.Block) {
		if b == nil || b.Kind != ssa.BlockPlain || len(b.Succs) != 0 {
			return
		}
		b.Kind = ssa.BlockUnreachable
	}
	if region != nil {
		seal(region.Dispatch)
		for _, h := range region.Handlers {
			seal(h.Block)
		}
	}
	for _, b := range extra {
		seal(b)
	}
}

// gotoExcTarget seals the current block with an unconditional branch to
// where a just-raised exception goes: an enclosing try's dispatch, or a
// propagating return. Used by throw / rethrow / a dispatch's no-match edge.
func (ls *lowerState) gotoExcTarget() {
	tgt := ls.currentExcTarget()
	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	if tgt.dispatch != nil {
		ls.recordIncoming(tgt.dispatch, 0)
		ssa.AddEdge(cur, tgt.dispatch)
	} else {
		ssa.AddEdge(cur, ls.propagateBlock())
	}
	ls.unreachable = true
}

// raiseAndGo emits the state write for a raise and branches to its target.
// tag is the tag index as a value; vals are the operand slots in order.
func (ls *lowerState) raiseAndGo(tag *ssa.Value, vals ...*ssa.Value) {
	args := append([]*ssa.Value{tag}, vals...)
	ls.b.NewValue(ssa.OpExcRaise, ssa.TypeMem, args...)
	ls.gotoExcTarget()
}

// openDispatch switches lowering to a try's dispatch block, which runs when
// an exception reached this try. It clears the pending flag (the handler is
// no longer propagating) and reads the tag, which the clause chain compares
// against. Returns the tag value.
//
// Called once, when the first catch clause is seen (or at `delegate`, which
// forwards instead of dispatching).
func (ls *lowerState) openDispatch(f *ctrlFrame) (*ssa.Value, error) {
	d := f.excDispatch
	ls.b.SetCurrent(d)
	ls.unreachable = false
	if err := ls.resolveIncoming(d, 0, f.stackHeightAtEntry); err != nil {
		return nil, err
	}
	// The operand stack unwinds to the try's entry height.
	if f.stackHeightAtEntry > len(ls.stack) {
		return nil, fmt.Errorf("%w: dispatch stack underflow (entry %d, have %d)",
			ErrSSAUnsupported, f.stackHeightAtEntry, len(ls.stack))
	}
	ls.stack = ls.stack[:f.stackHeightAtEntry]

	// Snapshot tag and operand slots BEFORE any handler body runs: a
	// handler can call code that raises and overwrites the state, and a
	// `rethrow` naming this try must still reproduce the original. Unused
	// snapshots are pure loads and get DCE'd.
	f.excDispatchLocals = append([]*ssa.Value(nil), ls.locals...)
	tag := ls.b.NewValue(ssa.OpExcTag, ssa.TypeI32)
	f.excSavedTag = tag
	f.excSavedVals = make([]*ssa.Value, ls.excSlots)
	for i := range f.excSavedVals {
		f.excSavedVals[i] = ls.b.NewValueAuxInt(ssa.OpExcVal, ssa.TypeI64, int64(i))
	}
	ls.b.NewValue(ssa.OpExcClear, ssa.TypeMem)
	return tag, nil
}

// beginClause opens one catch / catch_all clause. The first clause enters
// the dispatch block (clearing the flag and snapshotting the state); each
// subsequent one continues the tag-compare chain from where the previous
// clause's test left off. Returns the handler's entry block, which becomes
// the current block.
func (ls *lowerState) beginClause(f *ctrlFrame, catchAll bool, tagIdx uint32) (*ssa.Block, error) {
	if f.excChain == nil {
		tag, err := ls.openDispatch(f)
		if err != nil {
			return nil, err
		}
		f.excChain = ls.b.Current()
		f.excTagVal = tag
		f.excDead = len(f.excDispatch.Preds) == 0
	} else {
		ls.b.SetCurrent(f.excChain)
		// A later clause continues from the dispatch's state, not from
		// wherever the previous clause's body ended.
		ls.locals = append([]*ssa.Value(nil), f.excDispatchLocals...)
	}
	ls.unreachable = f.excDead
	if f.stackHeightAtEntry <= len(ls.stack) {
		ls.stack = ls.stack[:f.stackHeightAtEntry]
	} else {
		ls.stack = ls.stack[:0]
	}

	if catchAll {
		// Terminal clause: whatever reached the chain runs here.
		f.excChain = nil
		f.excHasCatchAll = true
		return ls.b.Current(), nil
	}
	handler := ls.b.NewBlock(ssa.BlockPlain)
	next := ls.b.NewBlock(ssa.BlockPlain)
	cur := ls.b.Current()
	cmp := ls.b.NewValue(ssa.OpEq32, ssa.TypeBool, f.excTagVal, ls.b.Const32(int32(tagIdx)))
	cur.Kind = ssa.BlockIf
	cur.Control = cmp
	ssa.AddEdge(cur, handler)
	ssa.AddEdge(cur, next)
	f.excChain = next
	ls.b.SetCurrent(handler)
	return handler, nil
}

// closeChain finishes a try's clause chain at its `end`: if no catch_all
// swallowed everything, the fall-through of the last tag test re-arms the
// flag and forwards the exception outward.
func (ls *lowerState) closeChain(f *ctrlFrame) {
	if f.excChain == nil {
		return
	}
	// The chain's no-match edge is emitted OUT OF LINE: the caller is in
	// the middle of closing the last clause into post, so every piece of
	// lowering state has to be restored afterwards.
	saved := ls.b.Current()
	savedUnreachable := ls.unreachable
	savedStack := append([]*ssa.Value(nil), ls.stack...)
	savedLocals := append([]*ssa.Value(nil), ls.locals...)

	ls.b.SetCurrent(f.excChain)
	ls.unreachable = false
	ls.stack = ls.stack[:0]
	ls.locals = append([]*ssa.Value(nil), f.excDispatchLocals...)
	// The tag and operands are untouched — clearing the flag was the only
	// state change — so re-arming is enough to keep the exception intact.
	ls.b.NewValue(ssa.OpExcRearm, ssa.TypeMem)
	// The frame is popped by the caller before this runs, so
	// currentExcTarget already resolves to the ENCLOSING context.
	ls.gotoExcTarget()
	f.excChain = nil

	ls.b.SetCurrent(saved)
	ls.unreachable = savedUnreachable
	ls.stack = savedStack
	ls.locals = savedLocals
}
