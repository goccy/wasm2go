package codegen

import (
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// ssaDebug is true when WASM2GO_SSA_DEBUG is set in the environment.
// When on, LowerFunction prints the constructed IR to stderr — the
// primary tool for debugging multi-block lowering correctness.
var ssaDebug = os.Getenv("WASM2GO_SSA_DEBUG") != ""

// ssaMaxFunc, when set via WASM2GO_SSA_MAXFUNC, caps which function
// indices are eligible for SSA lowering: a function with funcIdx >=
// ssaMaxFunc returns ErrSSAUnsupported and Translate fails the build.
// This is the bisection knob for hunting behavioural lowering bugs —
// set it to the midpoint, rebuild, and see whether the failure
// persists. A value of -1 (the default / unset) means "no cap".
var ssaMaxFunc = parseEnvInt("WASM2GO_SSA_MAXFUNC", -1)

// ssaMinFunc is the lower bound counterpart of ssaMaxFunc. Together
// they restrict SSA lowering to funcIdx in [ssaMinFunc, ssaMaxFunc).
var ssaMinFunc = parseEnvInt("WASM2GO_SSA_MINFUNC", 0)

// parseEnvInt reads an integer env var, returning def when unset or
// unparseable.
func parseEnvInt(name string, def int) int {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return def
	}
	return v
}

// ssaFuncString re-exports ssa.FuncString without forcing test files
// to import the internal/ssa package.
func ssaFuncString(f interface{}) string {
	if ff, ok := f.(*ssa.Func); ok {
		return ssa.FuncString(ff)
	}
	return ""
}

// ErrSSAUnsupported is returned by LowerFunction (and the rest of the
// SSA pipeline) when a wasm function uses a feature the lowering /
// optimizer / emitter does not yet handle. Translate surfaces it as a
// hard build error; there is no longer a legacy direct-opcode fallback.
var ErrSSAUnsupported = errors.New("ssa lowering: unsupported wasm feature")

// LowerFunction decodes a single wasm function body and produces an
// ssa.Func.
//
// Anything not yet implemented returns ErrSSAUnsupported wrapped with
// the function index and the offending opcode; Translate fails the
// build with that message so the gap can be addressed in the SSA
// pipeline rather than worked around silently.
func LowerFunction(mod *wasm.Module, funcIdx uint32, name string) (resFn *ssa.Func, resErr error) {
	// Recover from lowering bugs and surface them as ErrSSAUnsupported
	// with a clear function reference. Without this, a single edge case
	// anywhere in the lowering would crash the whole codegen run.
	defer func() {
		if r := recover(); r != nil {
			resFn = nil
			resErr = fmt.Errorf("%w: lower panic in fn%d (%s): %v", ErrSSAUnsupported, funcIdx, name, r)
		}
	}()

	// Bisection gate (WASM2GO_SSA_MINFUNC / WASM2GO_SSA_MAXFUNC):
	// restrict SSA lowering to a funcIdx window so a behavioural bug
	// can be binary-searched. Outside the window we deliberately fail
	// — Translate aborts with the unsupported error, which is exactly
	// what the bisection caller is looking for.
	if int(funcIdx) < ssaMinFunc {
		return nil, fmt.Errorf("%w: fn%d below SSA bisection window", ErrSSAUnsupported, funcIdx)
	}
	if ssaMaxFunc >= 0 && int(funcIdx) >= ssaMaxFunc {
		return nil, fmt.Errorf("%w: fn%d above SSA bisection window", ErrSSAUnsupported, funcIdx)
	}
	localIdx := funcIdx - mod.NumImportedFuncs
	fn := mod.Functions[localIdx]
	ft := mod.Types[fn.TypeIdx]

	sig := ssa.FuncSig{
		Params:  toSSATypes(ft.Params),
		Results: toSSATypes(ft.Results),
	}
	b := ssa.NewFuncBuilder(name, sig)

	entry := b.NewBlock(ssa.BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)

	locals, localTypes, err := setupLocals(b, fn, ft)
	if err != nil {
		return nil, err
	}

	ls := &lowerState{
		b:          b,
		mod:        mod,
		ft:         ft,
		locals:     locals,
		localTypes: localTypes,
		incoming:   map[*ssa.Block][]incomingEdge{},
	}

	r := &instrReader{src: fn.Body}
	if err := skipLocalDecls(r); err != nil {
		return nil, err
	}

	if err := ls.lowerBody(r); err != nil {
		return nil, err
	}
	// Drop isolated (no-edge) blocks left behind by structured-control
	// lowering — e.g. the unused post block of a loop that never falls
	// through. Done before verification so they don't trip the
	// reachability / terminator checks.
	ssa.PruneDeadBlocks(b.Func())
	if ssaDebug {
		fmt.Fprintf(os.Stderr, "=== SSA IR for fn%d (%s) ===\n%s\n", funcIdx, name, ssa.FuncString(b.Func()))
	}
	// Structural verification: a malformed CFG (mismatched edges, bad
	// phi arity, unreachable block, ...) is a lowering bug. Surface it
	// as ErrSSAUnsupported so Translate aborts with a clear error
	// instead of emitting wrong Go. With WASM2GO_SSA_DEBUG set, the
	// offending IR is also dumped.
	if err := ssa.Verify(b.Func()); err != nil {
		if ssaDebug {
			fmt.Fprintf(os.Stderr, "=== VERIFY FAILED fn%d (%s): %v ===\n%s\n",
				funcIdx, name, err, ssa.FuncString(b.Func()))
		}
		return nil, fmt.Errorf("%w: verify fn%d: %v", ErrSSAUnsupported, funcIdx, err)
	}
	return b.Func(), nil
}

// lowerState carries the per-function bookkeeping needed during SSA
// construction.
type lowerState struct {
	b   *ssa.FuncBuilder
	mod *wasm.Module
	ft  wasm.FuncType

	// locals[i] = current SSA value of local index i (params + decls).
	// Mutated by local.set / local.tee and at block transitions.
	locals     []*ssa.Value
	localTypes []ssa.Type

	// stack is the wasm operand stack: a list of *ssa.Value most recent
	// at end.
	stack []*ssa.Value

	// ctrl is the wasm control stack. Top of stack is the innermost
	// frame.
	ctrl []*ctrlFrame

	// incoming records, per target block, the list of edges flowing in
	// (from explicit branches AND fall-through). Materialised into phis
	// when the target block is finalised.
	incoming map[*ssa.Block][]incomingEdge

	// unreachable is true after an unconditional br / return / trap
	// terminates the current block. Subsequent instructions are
	// skipped until end/else realigns the cursor with a reachable
	// successor block.
	unreachable bool
	// unreachableDepth counts block/loop/if frames opened *inside* a
	// dead (unreachable) region. Their matching `end`s are consumed
	// without touching the live control stack.
	unreachableDepth int
}

// ctrlFrame is one entry on the wasm control stack.
type ctrlFrame struct {
	kind ctrlKind
	// target: where `br N` whose depth resolves to this frame jumps.
	// For block / if: the post-block (continuation after end).
	// For loop: the header block (back-edge target).
	target *ssa.Block
	// fallthrough: where the END instruction transitions to when
	// reached via fall-through (i.e. the bottom of the structured
	// region). For block / if: the post-block. For loop: the post-
	// loop block.
	fallthrough_ *ssa.Block
	// elseBlk: for if frames, the else branch entry block.
	elseBlk *ssa.Block
	// haveElse: for if frames, true once `else` has been seen so the
	// matching `end` knows to use elseBlk's snapshot instead of the
	// then-side one.
	haveElse bool
	// resultCount: arity of values the block produces at fall-through
	// (result-arity, not param-arity).
	resultCount int
	// stackHeightAtEntry is the operand-stack height at the moment the
	// frame opened, AFTER popping any block-type parameters. End / br
	// truncate the stack back to this height + resultCount values.
	stackHeightAtEntry int
	// entryLocals is a snapshot of the per-local SSA values at the
	// moment the frame opened. The else-branch of an if/else must
	// start from this snapshot (not the then-branch's mutated state),
	// and an if-without-else's implicit else edge carries it verbatim.
	entryLocals []*ssa.Value
}

type ctrlKind uint8

const (
	ctrlBlock ctrlKind = iota + 1
	ctrlLoop
	ctrlIf
)

// incomingEdge captures the locals + result-stack snapshot of a
// predecessor at the moment it branches into a target block.
type incomingEdge struct {
	from   *ssa.Block
	locals []*ssa.Value
	stack  []*ssa.Value // size = target block's expected param/result arity
}

// lowerBody walks the wasm bytecode r and emits SSA into ls.b.
func (ls *lowerState) lowerBody(r *instrReader) error {
	// depth tracks the open structured-control nesting. The function
	// body itself is depth 0; the implicit function-level End terminates
	// at depth 0.
	for !r.eof() {
		op, err := r.readByte()
		if err != nil {
			return err
		}
		if ls.unreachable {
			// Skip ops in the dead region until the structured
			// boundary that re-establishes a reachable cursor. Nested
			// block/loop/if opened *within* the dead region must be
			// counted so their matching `end` is consumed here and
			// not mistaken for the end of an enclosing live frame
			// (which would pop the wrong ctrlFrame and corrupt the
			// control stack).
			switch op {
			case opBlock, opLoop, opIf:
				ls.unreachableDepth++
				if err := r.skipImmediates(op); err != nil {
					return fmt.Errorf("%w: skipping unreachable block-open 0x%02x: %v", ErrSSAUnsupported, op, err)
				}
			case opElse:
				if ls.unreachableDepth > 0 {
					// `else` of a dead-region if — stay dead.
					break
				}
				if err := ls.handleElse(); err != nil {
					return err
				}
			case opEnd:
				if ls.unreachableDepth > 0 {
					ls.unreachableDepth--
					break
				}
				done, err := ls.handleEnd()
				if err != nil {
					return err
				}
				if done {
					return nil
				}
			default:
				if err := r.skipImmediates(op); err != nil {
					return fmt.Errorf("%w: skipping unreachable opcode 0x%02x: %v", ErrSSAUnsupported, op, err)
				}
			}
			continue
		}
		// Function-level End must terminate the loop directly so the
		// done signal isn't swallowed by handleOp.
		if op == opEnd {
			done, err := ls.handleEnd()
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			continue
		}
		if err := ls.handleOp(op, r); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: function body ended without End", ErrSSAUnsupported)
}

func (ls *lowerState) handleOp(op byte, r *instrReader) error {
	switch {
	case op == opEnd:
		_, err := ls.handleEnd()
		return err
	case op == opElse:
		return ls.handleElse()
	case op == opIf:
		return ls.handleIf(r)
	case op == opBlock:
		return ls.handleBlock(r)
	case op == opLoop:
		return ls.handleLoop(r)
	case op == opBr:
		return ls.handleBr(r)
	case op == opBrIf:
		return ls.handleBrIf(r)
	case op == opBrTable:
		return ls.handleBrTable(r)
	case op == opReturn:
		return ls.handleReturn()
	case op == opLocalGet:
		idx, err := r.readU32()
		if err != nil {
			return err
		}
		if int(idx) >= len(ls.locals) {
			return fmt.Errorf("local.get out of range: %d", idx)
		}
		ls.push(ls.locals[idx])
		return nil
	case op == opLocalSet:
		idx, err := r.readU32()
		if err != nil {
			return err
		}
		if int(idx) >= len(ls.locals) {
			return fmt.Errorf("local.set out of range: %d", idx)
		}
		v, err := ls.pop()
		if err != nil {
			return err
		}
		ls.locals[idx] = v
		return nil
	case op == opLocalTee:
		idx, err := r.readU32()
		if err != nil {
			return err
		}
		if int(idx) >= len(ls.locals) {
			return fmt.Errorf("local.tee out of range: %d", idx)
		}
		if len(ls.stack) == 0 {
			return fmt.Errorf("local.tee on empty stack")
		}
		ls.locals[idx] = ls.stack[len(ls.stack)-1]
		return nil
	case op == opI32Const:
		v, err := r.readS32()
		if err != nil {
			return err
		}
		ls.push(ls.b.Const32(v))
		return nil
	case op == opI64Const:
		v, err := r.readS64()
		if err != nil {
			return err
		}
		ls.push(ls.b.Const64(v))
		return nil
	case op == opCall:
		return ls.handleCall(r)
	case op == opCallIndirect:
		return ls.handleCallIndirect(r)
	case op == opGlobalGet:
		idx, err := r.readU32()
		if err != nil {
			return err
		}
		t := ls.globalType(idx)
		if t == ssa.TypeInvalid {
			return fmt.Errorf("%w: global.get for unsupported global type %d", ErrSSAUnsupported, idx)
		}
		ls.push(ls.b.NewValueAuxInt(ssa.OpGlobalGet, t, int64(idx)))
		return nil
	case op == opGlobalSet:
		idx, err := r.readU32()
		if err != nil {
			return err
		}
		v, err := ls.pop()
		if err != nil {
			return err
		}
		ls.b.NewValueAuxInt(ssa.OpGlobalSet, ssa.TypeMem, int64(idx), v)
		return nil
	case isMemoryOp(op):
		return ls.handleMemoryOp(op, r)
	case op == opMemSize:
		// memory.size and memory.grow each carry a 1-byte memory index
		// immediate (must be 0 in MVP wasm).
		if _, err := r.readByte(); err != nil {
			return err
		}
		ls.push(ls.b.NewValue(ssa.OpMemSize, ssa.TypeI32))
		return nil
	case op == opMemGrow:
		if _, err := r.readByte(); err != nil {
			return err
		}
		delta, err := ls.pop()
		if err != nil {
			return err
		}
		ls.push(ls.b.NewValue(ssa.OpMemGrow, ssa.TypeI32, delta))
		return nil
	case op == opUnreachable:
		// `unreachable` is a hard trap. Seal the current block as
		// Unreachable; subsequent ops are dead until the next
		// structured boundary.
		cur := ls.b.Current()
		cur.Kind = ssa.BlockUnreachable
		ls.unreachable = true
		return nil
	case op == opNop:
		return nil
	case op == opDrop:
		_, err := ls.pop()
		return err
	case op == opSelect, op == opSelectT:
		return ls.handleSelect(op, r)
	case op == opF32Const:
		v, err := r.readF32()
		if err != nil {
			return err
		}
		ls.push(ls.b.NewValueAuxInt(ssa.OpConstF32, ssa.TypeF32, int64(math.Float32bits(v))))
		return nil
	case op == opF64Const:
		v, err := r.readF64()
		if err != nil {
			return err
		}
		ls.push(ls.b.NewValueAuxInt(ssa.OpConstF64, ssa.TypeF64, int64(math.Float64bits(v))))
		return nil
	case isSimpleBinary(op):
		rhs, err := ls.pop()
		if err != nil {
			return err
		}
		lhs, err := ls.pop()
		if err != nil {
			return err
		}
		ssaOp, ssaType := simpleBinaryOp(op)
		// gt / ge wasm ops compile to the same SSA op as lt / le with
		// swapped arguments. simpleBinaryOp signals this via the
		// inverted mapping; we swap here.
		if isGtGe(op) {
			lhs, rhs = rhs, lhs
		}
		ls.push(ls.b.NewValue(ssaOp, ssaType, lhs, rhs))
		return nil
	case isHelperBinary(op):
		rhs, err := ls.pop()
		if err != nil {
			return err
		}
		lhs, err := ls.pop()
		if err != nil {
			return err
		}
		spec := helperBinarySpec(op)
		ls.push(ls.b.NewValueAux(ssa.OpHelperCall, spec.resType, spec.helper, lhs, rhs))
		return nil
	case isHelperUnary(op):
		x, err := ls.pop()
		if err != nil {
			return err
		}
		spec := helperUnarySpec(op)
		ls.push(ls.b.NewValueAux(ssa.OpHelperCall, spec.resType, spec.helper, x))
		return nil
	case op == opPrefixFC:
		return ls.handleFCOp(r)
	}
	return fmt.Errorf("%w: opcode 0x%02x not implemented", ErrSSAUnsupported, op)
}

// handleSelect implements the select / select-typed opcodes. Both pop
// (then-val, else-val, cond) — typed select additionally carries a 1-vec
// of value types we currently ignore (the polymorphic check is left to
// validation upstream).
func (ls *lowerState) handleSelect(op byte, r *instrReader) error {
	if op == opSelectT {
		n, err := r.readU32()
		if err != nil {
			return err
		}
		for i := uint32(0); i < n; i++ {
			if _, err := r.readByte(); err != nil {
				return err
			}
		}
	}
	cond, err := ls.pop()
	if err != nil {
		return err
	}
	elseVal, err := ls.pop()
	if err != nil {
		return err
	}
	thenVal, err := ls.pop()
	if err != nil {
		return err
	}
	// Lower as: thenBlk if cond != 0 else elseBlk; phi at join. This
	// matches what an if/then/else with one result would produce, so the
	// existing emitter handles it without further changes.
	thenBlk := ls.b.NewBlock(ssa.BlockPlain)
	elseBlk := ls.b.NewBlock(ssa.BlockPlain)
	postBlk := ls.b.NewBlock(ssa.BlockPlain)
	cur := ls.b.Current()
	cur.Kind = ssa.BlockIf
	cur.Control = cond
	ssa.AddEdge(cur, thenBlk)
	ssa.AddEdge(cur, elseBlk)
	ssa.AddEdge(thenBlk, postBlk)
	ssa.AddEdge(elseBlk, postBlk)
	ls.b.SetCurrent(postBlk)
	phi := ls.b.NewValue(ssa.OpPhi, thenVal.Type, thenVal, elseVal)
	ls.push(phi)
	return nil
}

// handleFCOp dispatches the wasm 0xFC prefix opcodes: saturating-trunc
// conversions and bulk-memory ops.
func (ls *lowerState) handleFCOp(r *instrReader) error {
	sub, err := r.readU32()
	if err != nil {
		return err
	}
	switch sub {
	case 0, 1, 2, 3, 4, 5, 6, 7:
		// i32.trunc_sat_f32_s / _u, i32.trunc_sat_f64_s / _u,
		// i64.trunc_sat_f32_s / _u, i64.trunc_sat_f64_s / _u.
		specs := []helperUnary{
			{"i32_trunc_sat_f32_s", ssa.TypeI32},
			{"i32_trunc_sat_f32_u", ssa.TypeI32},
			{"i32_trunc_sat_f64_s", ssa.TypeI32},
			{"i32_trunc_sat_f64_u", ssa.TypeI32},
			{"i64_trunc_sat_f32_s", ssa.TypeI64},
			{"i64_trunc_sat_f32_u", ssa.TypeI64},
			{"i64_trunc_sat_f64_s", ssa.TypeI64},
			{"i64_trunc_sat_f64_u", ssa.TypeI64},
		}
		x, err := ls.pop()
		if err != nil {
			return err
		}
		s := specs[sub]
		ls.push(ls.b.NewValueAux(ssa.OpHelperCall, s.resType, s.helper, x))
		return nil
	case 8: // memory.init
		segIdx, err := r.readU32()
		if err != nil {
			return err
		}
		if _, err := r.readByte(); err != nil { // memory index (must be 0)
			return err
		}
		n, err := ls.pop()
		if err != nil {
			return err
		}
		src, err := ls.pop()
		if err != nil {
			return err
		}
		dst, err := ls.pop()
		if err != nil {
			return err
		}
		ls.b.NewValueAuxInt(ssa.OpMemoryInit, ssa.TypeMem, int64(segIdx), dst, src, n)
		return nil
	case 9: // data.drop
		segIdx, err := r.readU32()
		if err != nil {
			return err
		}
		ls.b.NewValueAuxInt(ssa.OpDataDrop, ssa.TypeMem, int64(segIdx))
		return nil
	case 10: // memory.copy
		if _, err := r.readByte(); err != nil { // dst mem index
			return err
		}
		if _, err := r.readByte(); err != nil { // src mem index
			return err
		}
		n, err := ls.pop()
		if err != nil {
			return err
		}
		src, err := ls.pop()
		if err != nil {
			return err
		}
		dst, err := ls.pop()
		if err != nil {
			return err
		}
		ls.b.NewValue(ssa.OpMemoryCopy, ssa.TypeMem, dst, src, n)
		return nil
	case 11: // memory.fill
		if _, err := r.readByte(); err != nil {
			return err
		}
		n, err := ls.pop()
		if err != nil {
			return err
		}
		val, err := ls.pop()
		if err != nil {
			return err
		}
		dst, err := ls.pop()
		if err != nil {
			return err
		}
		ls.b.NewValue(ssa.OpMemoryFill, ssa.TypeMem, dst, val, n)
		return nil
	}
	return fmt.Errorf("%w: prefix 0xfc sub-opcode %d not implemented", ErrSSAUnsupported, sub)
}

// handleBlock implements `block blocktype ... end`. The block opens a
// new scope whose `br 0` target is the post-block; the body runs in the
// same SSA basic block until something branches.
func (ls *lowerState) handleBlock(r *instrReader) error {
	bt, err := r.readS33()
	if err != nil {
		return err
	}
	results, err := decodeBlockResults(bt)
	if err != nil {
		return fmt.Errorf("%w: block blocktype %v: %v", ErrSSAUnsupported, bt, err)
	}
	postBlk := ls.b.NewBlock(ssa.BlockPlain)
	ls.ctrl = append(ls.ctrl, &ctrlFrame{
		kind:               ctrlBlock,
		target:             postBlk,
		fallthrough_:       postBlk,
		resultCount:        len(results),
		stackHeightAtEntry: len(ls.stack),
	})
	return nil
}

// handleLoop implements `loop blocktype ... end`. The loop header is a
// new SSA block reached both from the entry edge and from any
// back-branch (br targeting depth 0). To support back-edges with
// SSA-correct local values we install Braun-style "incomplete phis" at
// the header: one per local, initially carrying the entry-edge value;
// further args are appended as branches into the header land.
func (ls *lowerState) handleLoop(r *instrReader) error {
	bt, err := r.readS33()
	if err != nil {
		return err
	}
	results, err := decodeBlockResults(bt)
	if err != nil {
		return fmt.Errorf("%w: loop blocktype %v: %v", ErrSSAUnsupported, bt, err)
	}

	header := ls.b.NewBlock(ssa.BlockPlain)
	postBlk := ls.b.NewBlock(ssa.BlockPlain)

	// Wire current → header as the first edge in. Snapshot is the
	// pre-loop state.
	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	ssa.AddEdge(cur, header)

	// Move into header. Install one incomplete-phi value per local
	// (Args initially just the entry-edge value; appended as more
	// preds arrive). Stack values at this point belong to the
	// surrounding scope and stay as-is.
	ls.b.SetCurrent(header)
	headerPhis := make([]*ssa.Value, len(ls.locals))
	for i, v := range ls.locals {
		phi := ls.b.NewValue(ssa.OpPhi, ls.localTypes[i], v)
		headerPhis[i] = phi
	}
	ls.locals = headerPhis

	ls.ctrl = append(ls.ctrl, &ctrlFrame{
		kind:               ctrlLoop,
		target:             header,
		fallthrough_:       postBlk,
		resultCount:        len(results),
		stackHeightAtEntry: len(ls.stack),
	})
	return nil
}

// handleBr implements unconditional `br N`. The Nth-enclosing frame's
// target receives an edge; the current block is sealed Plain → target,
// and execution becomes unreachable until the next structured boundary.
func (ls *lowerState) handleBr(r *instrReader) error {
	depth, err := r.readU32()
	if err != nil {
		return err
	}
	if int(depth) >= len(ls.ctrl) {
		return fmt.Errorf("br %d: out of range (ctrl depth %d)", depth, len(ls.ctrl))
	}
	frame := ls.ctrl[len(ls.ctrl)-1-int(depth)]
	ls.recordIncoming(frame.target, frame.resultCount)
	// For loops, `br 0` is a back-edge into the header phi. Each
	// header local phi gets one more incoming arg = current value.
	if frame.kind == ctrlLoop {
		ls.appendLoopBackArgs(frame.target)
	}
	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	ssa.AddEdge(cur, frame.target)
	ls.unreachable = true
	return nil
}

// handleBrIf implements conditional `br_if N`. Behaves like br when
// cond != 0 else falls through. The current block becomes an If
// terminator: then-succ = frame.target, else-succ = a new continuation
// block. The current block tail is sealed; subsequent ops emit into the
// continuation.
func (ls *lowerState) handleBrIf(r *instrReader) error {
	depth, err := r.readU32()
	if err != nil {
		return err
	}
	if int(depth) >= len(ls.ctrl) {
		return fmt.Errorf("br_if %d: out of range (ctrl depth %d)", depth, len(ls.ctrl))
	}
	cond, err := ls.pop()
	if err != nil {
		return err
	}
	frame := ls.ctrl[len(ls.ctrl)-1-int(depth)]
	cont := ls.b.NewBlock(ssa.BlockPlain)

	// Snapshot for the taken edge.
	ls.recordIncoming(frame.target, frame.resultCount)
	if frame.kind == ctrlLoop {
		ls.appendLoopBackArgs(frame.target)
	}

	cur := ls.b.Current()
	cur.Kind = ssa.BlockIf
	cur.Control = cond
	ssa.AddEdge(cur, frame.target)
	ssa.AddEdge(cur, cont)

	ls.b.SetCurrent(cont)
	return nil
}

// handleBrTable implements `br_table cases* default`. The selector is
// the i32 on top of the operand stack: if 0 <= sel < len(cases), branch
// to cases[sel]; otherwise branch to default. All targets share the same
// result arity (validated by wasm), so the same top-K stack values are
// passed as the branch payload regardless of which target is taken.
//
// We do not introduce a new SSA block kind for switch dispatch; instead
// we lower the table to a chain of If blocks of the form
//
//	if sel == 0 { goto cases[0] } else if sel == 1 { goto cases[1] }
//	... else { goto default }
//
// which the goto-based SSA emitter handles natively. The downstream Go
// compiler is well-equipped to fold such cascades back into a jump
// table where profitable; the extra blocks are also cheap for the SSA
// optimization passes because the equality checks are pure.
func (ls *lowerState) handleBrTable(r *instrReader) error {
	cases, err := r.readVecU32()
	if err != nil {
		return err
	}
	defaultDepth, err := r.readU32()
	if err != nil {
		return err
	}
	sel, err := ls.pop()
	if err != nil {
		return err
	}

	// Validate every depth before we mutate any CFG state, so a bad
	// depth surfaces as a clean error instead of a half-constructed
	// chain of If blocks.
	maxDepth := int(defaultDepth)
	for _, d := range cases {
		if int(d) > maxDepth {
			maxDepth = int(d)
		}
	}
	if maxDepth >= len(ls.ctrl) {
		return fmt.Errorf("br_table: depth %d out of range (ctrl depth %d)", maxDepth, len(ls.ctrl))
	}

	// Validate that every target (cases + default) carries the same
	// result arity. The wasm spec requires this — without the check a
	// malformed input would silently miscompile by passing the wrong
	// stack-top values through one of the branches.
	defFrame := ls.ctrl[len(ls.ctrl)-1-int(defaultDepth)]
	wantArity := defFrame.resultCount
	for i, d := range cases {
		f := ls.ctrl[len(ls.ctrl)-1-int(d)]
		if f.resultCount != wantArity {
			return fmt.Errorf("%w: br_table target %d has arity %d, default has %d",
				ErrSSAUnsupported, i, f.resultCount, wantArity)
		}
	}

	// Emit one If block per case index. The fall-through path of each
	// If becomes the predecessor of the next comparison.
	for i, depth := range cases {
		frame := ls.ctrl[len(ls.ctrl)-1-int(depth)]
		cont := ls.b.NewBlock(ssa.BlockPlain)
		ls.recordIncoming(frame.target, frame.resultCount)
		if frame.kind == ctrlLoop {
			ls.appendLoopBackArgs(frame.target)
		}
		eq := ls.b.NewValue(ssa.OpEq32, ssa.TypeBool, sel, ls.b.Const32(int32(i)))
		cur := ls.b.Current()
		cur.Kind = ssa.BlockIf
		cur.Control = eq
		ssa.AddEdge(cur, frame.target)
		ssa.AddEdge(cur, cont)
		ls.b.SetCurrent(cont)
	}

	// Default branch — the final block is sealed as Plain → default.
	frame := ls.ctrl[len(ls.ctrl)-1-int(defaultDepth)]
	ls.recordIncoming(frame.target, frame.resultCount)
	if frame.kind == ctrlLoop {
		ls.appendLoopBackArgs(frame.target)
	}
	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	ssa.AddEdge(cur, frame.target)
	ls.unreachable = true
	return nil
}

// handleReturn implements explicit `return` — drains the operand stack
// of nResults values and routes them as the function result, then
// marks the cursor unreachable. The function-level End will see the
// previously-Ret block and not double-emit.
func (ls *lowerState) handleReturn() error {
	nRes := len(ls.ft.Results)
	if len(ls.stack) < nRes {
		return fmt.Errorf("return with %d stack values, expected %d", len(ls.stack), nRes)
	}
	rets := make([]*ssa.Value, nRes)
	for i := 0; i < nRes; i++ {
		rets[i] = ls.stack[len(ls.stack)-nRes+i]
	}
	cur := ls.b.Current()
	cur.Kind = ssa.BlockRet
	ls.b.FinishRet(rets...)
	ls.unreachable = true
	return nil
}

// isMemoryOp reports whether op is a wasm load/store the current
// lowering handles. SIMD (v128.load*) and atomic loads/stores are not
// in scope.
func isMemoryOp(op byte) bool {
	switch op {
	case opI32Load, opI64Load, opF32Load, opF64Load,
		opI32Load8S, opI32Load8U, opI32Load16S, opI32Load16U,
		opI64Load8S, opI64Load8U, opI64Load16S, opI64Load16U, opI64Load32S, opI64Load32U,
		opI32Store, opI64Store, opF32Store, opF64Store,
		opI32Store8, opI32Store16,
		opI64Store8, opI64Store16, opI64Store32:
		return true
	}
	return false
}

// memoryOpSpec describes a wasm memory op's SSA mapping.
type memoryOpSpec struct {
	ssaOp ssa.Op
	typ   ssa.Type // result type for loads, value type for stores
	store bool
}

func memoryOpKind(op byte) memoryOpSpec {
	switch op {
	case opI32Load:
		return memoryOpSpec{ssa.OpLoad32, ssa.TypeI32, false}
	case opI32Load8S:
		return memoryOpSpec{ssa.OpLoad8S, ssa.TypeI32, false}
	case opI32Load8U:
		return memoryOpSpec{ssa.OpLoad8U, ssa.TypeI32, false}
	case opI32Load16S:
		return memoryOpSpec{ssa.OpLoad16S, ssa.TypeI32, false}
	case opI32Load16U:
		return memoryOpSpec{ssa.OpLoad16U, ssa.TypeI32, false}
	case opI64Load:
		return memoryOpSpec{ssa.OpLoad64, ssa.TypeI64, false}
	case opI64Load8S:
		return memoryOpSpec{ssa.OpLoad8S, ssa.TypeI64, false}
	case opI64Load8U:
		return memoryOpSpec{ssa.OpLoad8U, ssa.TypeI64, false}
	case opI64Load16S:
		return memoryOpSpec{ssa.OpLoad16S, ssa.TypeI64, false}
	case opI64Load16U:
		return memoryOpSpec{ssa.OpLoad16U, ssa.TypeI64, false}
	case opI64Load32S:
		return memoryOpSpec{ssa.OpLoad32S, ssa.TypeI64, false}
	case opI64Load32U:
		return memoryOpSpec{ssa.OpLoad32U, ssa.TypeI64, false}
	case opF32Load:
		return memoryOpSpec{ssa.OpLoadF32, ssa.TypeF32, false}
	case opF64Load:
		return memoryOpSpec{ssa.OpLoadF64, ssa.TypeF64, false}
	case opI32Store:
		return memoryOpSpec{ssa.OpStore32, ssa.TypeI32, true}
	case opI32Store8:
		return memoryOpSpec{ssa.OpStore8, ssa.TypeI32, true}
	case opI32Store16:
		return memoryOpSpec{ssa.OpStore16, ssa.TypeI32, true}
	case opI64Store:
		return memoryOpSpec{ssa.OpStore64, ssa.TypeI64, true}
	case opI64Store8:
		return memoryOpSpec{ssa.OpStore8, ssa.TypeI64, true}
	case opI64Store16:
		return memoryOpSpec{ssa.OpStore16, ssa.TypeI64, true}
	case opI64Store32:
		return memoryOpSpec{ssa.OpStore32, ssa.TypeI64, true}
	case opF32Store:
		return memoryOpSpec{ssa.OpStoreF32, ssa.TypeF32, true}
	case opF64Store:
		return memoryOpSpec{ssa.OpStoreF64, ssa.TypeF64, true}
	}
	return memoryOpSpec{ssa.OpInvalid, ssa.TypeInvalid, false}
}

// handleMemoryOp decodes a wasm load/store and emits the corresponding
// SSA op. The memarg align is ignored (Go's helpers don't honor it),
// the offset is recorded as AuxInt.
func (ls *lowerState) handleMemoryOp(op byte, r *instrReader) error {
	_, offset, err := r.readMemArg()
	if err != nil {
		return err
	}
	spec := memoryOpKind(op)
	if spec.ssaOp == ssa.OpInvalid {
		return fmt.Errorf("%w: memoryOpKind for 0x%02x", ErrSSAUnsupported, op)
	}
	if spec.store {
		value, err := ls.pop()
		if err != nil {
			return err
		}
		base, err := ls.pop()
		if err != nil {
			return err
		}
		v := ls.b.NewValueAuxInt(spec.ssaOp, ssa.TypeMem, int64(offset), base, value)
		_ = v // stored as a side-effecting value; emit handles as statement
		return nil
	}
	base, err := ls.pop()
	if err != nil {
		return err
	}
	ls.push(ls.b.NewValueAuxInt(spec.ssaOp, spec.typ, int64(offset), base))
	return nil
}

// handleCall lowers `call <funcidx>`. The callee may be an imported
// function or a defined one; both lower to OpCallImport / OpCallDirect
// respectively, with the function index as AuxInt.
//
// Multi-result returns (≥2) are not supported yet; OpSelect projection
// from a tuple value would be the way to handle them.
func (ls *lowerState) handleCall(r *instrReader) error {
	funcIdx, err := r.readU32()
	if err != nil {
		return err
	}
	ft := ls.mod.FuncTypeOf(funcIdx)
	if len(ft.Results) > 1 {
		return fmt.Errorf("%w: multi-result call (%d results)", ErrSSAUnsupported, len(ft.Results))
	}
	// Pop args from stack in reverse order.
	if len(ls.stack) < len(ft.Params) {
		return fmt.Errorf("call fn%d: stack underflow (need %d, have %d)", funcIdx, len(ft.Params), len(ls.stack))
	}
	argStart := len(ls.stack) - len(ft.Params)
	args := append([]*ssa.Value(nil), ls.stack[argStart:]...)
	ls.stack = ls.stack[:argStart]

	isImport := funcIdx < ls.mod.NumImportedFuncs
	var op ssa.Op
	var resType ssa.Type
	if len(ft.Results) == 1 {
		resType = toSSAType(ft.Results[0])
		if resType == ssa.TypeInvalid {
			return fmt.Errorf("%w: call result type %v unsupported", ErrSSAUnsupported, ft.Results[0])
		}
	} else {
		resType = ssa.TypeMem // sentinel for void-returning call's value placeholder
	}
	if isImport {
		op = ssa.OpCallImport
	} else {
		op = ssa.OpCallDirect
	}
	v := ls.b.NewValueAuxInt(op, resType, int64(funcIdx), args...)
	if len(ft.Results) == 1 {
		ls.push(v)
	}
	return nil
}

// handleCallIndirect lowers `call_indirect <typeidx> <tableidx>`. The
// last stack value is the table index; the values below it are the
// call's parameters.
func (ls *lowerState) handleCallIndirect(r *instrReader) error {
	typeIdx, err := r.readU32()
	if err != nil {
		return err
	}
	tableIdx, err := r.readU32()
	if err != nil {
		return err
	}
	_ = tableIdx
	ft := ls.mod.Types[typeIdx]
	if len(ft.Results) > 1 {
		return fmt.Errorf("%w: multi-result call_indirect", ErrSSAUnsupported)
	}
	if len(ls.stack) < 1+len(ft.Params) {
		return fmt.Errorf("call_indirect: stack underflow")
	}
	tableArg, err := ls.pop()
	if err != nil {
		return err
	}
	argStart := len(ls.stack) - len(ft.Params)
	args := []*ssa.Value{tableArg}
	args = append(args, ls.stack[argStart:]...)
	ls.stack = ls.stack[:argStart]

	var resType ssa.Type
	if len(ft.Results) == 1 {
		resType = toSSAType(ft.Results[0])
	} else {
		resType = ssa.TypeMem
	}
	v := ls.b.NewValueAuxInt(ssa.OpCallIndirect, resType, int64(typeIdx), args...)
	if len(ft.Results) == 1 {
		ls.push(v)
	}
	return nil
}

// globalType returns the SSA type of global index idx, or TypeInvalid
// if the index is out of range or the type isn't lowerable.
func (ls *lowerState) globalType(idx uint32) ssa.Type {
	if int(idx) < int(ls.mod.NumImportedGlobals) {
		// Imported globals — type lookup via mod.Imports.
		var seen uint32
		for _, imp := range ls.mod.Imports {
			if imp.Kind != wasm.ImportGlobal {
				continue
			}
			if seen == idx {
				return toSSAType(imp.Global.Type)
			}
			seen++
		}
		return ssa.TypeInvalid
	}
	localIdx := idx - ls.mod.NumImportedGlobals
	if int(localIdx) >= len(ls.mod.Globals) {
		return ssa.TypeInvalid
	}
	return toSSAType(ls.mod.Globals[localIdx].Type.Type)
}

// appendLoopBackArgs extends each phi at the loop header with the
// current per-local value, recording the back-edge contribution.
func (ls *lowerState) appendLoopBackArgs(header *ssa.Block) {
	for i, v := range ls.locals {
		// Find the phi for local i at the header. We installed them
		// at handleLoop in the same order, so it's the i'th OpPhi
		// in header.Values.
		nFound := 0
		for _, candidate := range header.Values {
			if candidate.Op != ssa.OpPhi {
				continue
			}
			if nFound == i {
				candidate.Args = append(candidate.Args, v)
				break
			}
			nFound++
		}
	}
}

// handleIf implements `if blocktype ... [else ...] end`. Both branches
// inherit the locals + stack-below-cond snapshot at entry; the join at
// `end` reconciles via phi when a local or stack-result diverges.
func (ls *lowerState) handleIf(r *instrReader) error {
	// blocktype: s33; 0x40 (empty) or a value type encoded as a negative.
	bt, err := r.readS33()
	if err != nil {
		return err
	}
	results, err := decodeBlockResults(bt)
	if err != nil {
		return fmt.Errorf("%w: if blocktype %v: %v", ErrSSAUnsupported, bt, err)
	}
	cond, err := ls.pop()
	if err != nil {
		return err
	}

	thenBlk := ls.b.NewBlock(ssa.BlockPlain)
	elseBlk := ls.b.NewBlock(ssa.BlockPlain)
	postBlk := ls.b.NewBlock(ssa.BlockPlain)

	// Make the current block into an If node with two successors.
	cur := ls.b.Current()
	cur.Kind = ssa.BlockIf
	cur.Control = cond
	ssa.AddEdge(cur, thenBlk)
	ssa.AddEdge(cur, elseBlk)

	// Push frame. target == postBlk for br purposes. Snapshot the
	// locals so the else-branch (and implicit no-else fall-through)
	// starts from the if-entry state, not the then-branch's mutations.
	ls.ctrl = append(ls.ctrl, &ctrlFrame{
		kind:               ctrlIf,
		target:             postBlk,
		fallthrough_:       postBlk,
		elseBlk:            elseBlk,
		resultCount:        len(results),
		stackHeightAtEntry: len(ls.stack),
		entryLocals:        append([]*ssa.Value(nil), ls.locals...),
	})

	// Enter the then-block. Locals + stack stay the same.
	ls.b.SetCurrent(thenBlk)
	return nil
}

// handleElse closes the then-branch of the innermost if frame and
// switches the cursor to the else-branch entry block. Snapshots the
// current locals + (last resultCount) stack values for the post-block
// merge.
func (ls *lowerState) handleElse() error {
	if len(ls.ctrl) == 0 || ls.ctrl[len(ls.ctrl)-1].kind != ctrlIf {
		return fmt.Errorf("%w: else without matching if", ErrSSAUnsupported)
	}
	f := ls.ctrl[len(ls.ctrl)-1]
	if !ls.unreachable {
		ls.recordIncoming(f.target, f.resultCount)
		// Wire the then-side block as Plain → post so the CFG is
		// well-formed (recordIncoming only captures the data; the
		// edge belongs in the block graph).
		cur := ls.b.Current()
		cur.Kind = ssa.BlockPlain
		ssa.AddEdge(cur, f.target)
	}
	ls.stack = ls.stack[:f.stackHeightAtEntry]
	// The else-branch starts from the if-entry locals, NOT the
	// then-branch's mutated state.
	ls.locals = append([]*ssa.Value(nil), f.entryLocals...)
	f.haveElse = true
	ls.unreachable = false
	ls.b.SetCurrent(f.elseBlk)
	return nil
}

// handleEnd closes the innermost frame. When that frame is the function-
// level marker (ctrl empty), it finalises the function: collects the
// trailing operand stack as return values and marks the entry/last
// block as Ret. Returns done=true in that case.
func (ls *lowerState) handleEnd() (bool, error) {
	if len(ls.ctrl) == 0 {
		// Function-level end. Snapshot current results.
		nRes := len(ls.ft.Results)
		// If the cursor is already unreachable, the current block was
		// terminated by the op that set unreachable — an explicit
		// `return`, a `br`, or `unreachable`. That terminator already
		// finished the block (BlockRet / BlockUnreachable) with the
		// correct return values; re-finishing it here would append a
		// second set of return markers and clobber the real ones (the
		// emit pass reads the LAST nRes markers). So only finish the
		// implicit fall-through end.
		cur := ls.b.Current()
		if ls.unreachable {
			if cur.Kind == ssa.BlockInvalid {
				// Defensive: a dead trailing block that was never
				// terminated — make it well-formed with zero returns.
				rets := make([]*ssa.Value, nRes)
				for i, t := range ls.ft.Results {
					rets[i] = zeroValueOf(ls.b, toSSAType(t))
				}
				ls.b.FinishRet(rets...)
			}
			return true, nil
		}
		if len(ls.stack) < nRes {
			return false, fmt.Errorf("%w: function end with %d stack values, expected %d", ErrSSAUnsupported, len(ls.stack), nRes)
		}
		rets := make([]*ssa.Value, nRes)
		copy(rets, ls.stack[len(ls.stack)-nRes:])
		cur.Kind = ssa.BlockRet
		// FinishRet adds OpCopy markers for the emit pass to find.
		ls.b.FinishRet(rets...)
		return true, nil
	}
	// Pop frame.
	f := ls.ctrl[len(ls.ctrl)-1]
	ls.ctrl = ls.ctrl[:len(ls.ctrl)-1]

	switch f.kind {
	case ctrlIf:
		// Add the current-block snapshot as one more incoming edge to
		// post (this is the then-side end if no else, or the else-
		// side end if `else` was seen).
		if !ls.unreachable {
			ls.recordIncoming(f.target, f.resultCount)
		}
		// If no else was seen, the else-block is an immediate
		// fall-through with no extra values: it inherits the entry
		// snapshot and just bridges to post. Add an edge from elseBlk
		// to post mirroring the original locals + (whatever results
		// the fall-through carries from the entry stack).
		if !f.haveElse {
			// Build a "synthetic" entry-state edge: the else block
			// is empty and falls through to post. The locals & stack
			// at entry to the else are the same as at entry to the
			// if (which were snapshotted on the then-edge as
			// f.stackHeightAtEntry).
			//
			// To synthesise this, we momentarily switch current to
			// elseBlk and snapshot. The stack at this point has
			// resultCount values only if the if produces results
			// without an else, which is illegal per wasm spec (if
			// produces results, an else is required). So
			// resultCount must be 0 here.
			if f.resultCount != 0 {
				return false, fmt.Errorf("%w: if without else cannot have block results", ErrSSAUnsupported)
			}
			// The implicit else edge carries the if-ENTRY locals
			// (the if-cond was false, so nothing in the then-branch
			// ran). Snapshot from f.entryLocals, not ls.locals which
			// still holds the then-branch's mutations.
			savedLocals := ls.locals
			prev := ls.b.Current()
			ls.locals = append([]*ssa.Value(nil), f.entryLocals...)
			ls.b.SetCurrent(f.elseBlk)
			ls.recordIncoming(f.target, 0)
			ls.b.SetCurrent(prev)
			ls.locals = savedLocals
		}
		// Wire elseBlk → postBlk for the no-else case AND elseBlk's
		// natural fall-through to post when else IS present.
		if !f.haveElse {
			ssa.AddEdge(f.elseBlk, f.target)
		}
		// Make the previous current block (then-side end OR else-
		// side end) a Plain edge to post if reachable. (The incoming-
		// edge snapshot was already taken above, before the
		// no-else else-bridge synthesis.)
		if !ls.unreachable {
			cur := ls.b.Current()
			cur.Kind = ssa.BlockPlain
			ssa.AddEdge(cur, f.target)
		}
		// Switch to post only if anything actually flows in. If both
		// then- and else-side trapped or branched away (the post block
		// is unreachable), keep the cursor where it is and stay in the
		// unreachable region so we don't construct an orphan post that
		// emits dead code.
		if _, ok := ls.incoming[f.target]; ok {
			ls.b.SetCurrent(f.target)
			ls.unreachable = false
			if err := ls.resolveIncoming(f.target, f.resultCount, f.stackHeightAtEntry); err != nil {
				return false, err
			}
		}
	case ctrlBlock:
		// Fall-through edge from current block into the post block,
		// if reachable. The post block becomes the new current; if
		// it has no incoming edges (nothing ever branched here and
		// the body trapped), the function is just done with the
		// block scope; skip the transition.
		if !ls.unreachable {
			ls.recordIncoming(f.target, f.resultCount)
			cur := ls.b.Current()
			cur.Kind = ssa.BlockPlain
			ssa.AddEdge(cur, f.target)
		}
		if _, ok := ls.incoming[f.target]; ok {
			ls.b.SetCurrent(f.target)
			ls.unreachable = false
			if err := ls.resolveIncoming(f.target, f.resultCount, f.stackHeightAtEntry); err != nil {
				return false, err
			}
		}
	case ctrlLoop:
		// Fall-through past the loop goes to the post-loop block.
		// Loop header phis have been accumulating back-edge args
		// throughout the body; nothing more to do here. Seal them
		// implicitly: if a phi's args are all identical, we can
		// optimise by replacing with the value — but we leave that
		// for ConstProp / phielim.
		if !ls.unreachable {
			ls.recordIncoming(f.fallthrough_, f.resultCount)
			cur := ls.b.Current()
			cur.Kind = ssa.BlockPlain
			ssa.AddEdge(cur, f.fallthrough_)
		}
		if _, ok := ls.incoming[f.fallthrough_]; ok {
			ls.b.SetCurrent(f.fallthrough_)
			ls.unreachable = false
			if err := ls.resolveIncoming(f.fallthrough_, f.resultCount, f.stackHeightAtEntry); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

// recordIncoming snapshots the current locals + last `resultCount` stack
// values as an edge flowing into target.
func (ls *lowerState) recordIncoming(target *ssa.Block, resultCount int) {
	from := ls.b.Current()
	locSnap := append([]*ssa.Value(nil), ls.locals...)
	var stackSnap []*ssa.Value
	if resultCount > 0 {
		base := len(ls.stack) - resultCount
		if base < 0 {
			base = 0
		}
		stackSnap = append([]*ssa.Value(nil), ls.stack[base:]...)
	}
	ls.incoming[target] = append(ls.incoming[target], incomingEdge{
		from:   from,
		locals: locSnap,
		stack:  stackSnap,
	})
}

// resolveIncoming materialises phis at target's entry for each local
// (and stack-result slot) whose values differ across predecessors, then
// updates the active locals/stack to point at those phis. Single-pred
// blocks simply adopt the predecessor's state without phis.
//
// baseHeight is the operand-stack height of the structured-control
// region's ENTRY — the number of values that sit below the region's
// results. The post-region stack is reset to exactly
// baseHeight + resultCount values: baseHeight original base values plus
// the merged results. This explicit reset is essential because the
// current ls.stack may be a *stale* unreachable-branch stack (e.g. the
// then-branch of an if ended in `br`, leaving its own pushed values on
// ls.stack); trimming `len(ls.stack)-resultCount` would then preserve
// those leftovers and corrupt the base stack.
func (ls *lowerState) resolveIncoming(target *ssa.Block, resultCount, baseHeight int) error {
	edges := ls.incoming[target]
	delete(ls.incoming, target)
	if len(edges) == 0 {
		// Block is unreachable. Leave as-is; caller may set it to
		// Ret synthetically.
		return nil
	}
	if baseHeight < 0 || baseHeight > len(ls.stack) {
		return fmt.Errorf("resolveIncoming: baseHeight %d out of range (stack %d)", baseHeight, len(ls.stack))
	}
	if len(edges) == 1 {
		ls.locals = append([]*ssa.Value(nil), edges[0].locals...)
		// Reset to the region-entry base, then append the single
		// edge's result snapshot.
		ls.stack = append(ls.stack[:baseHeight:baseHeight], edges[0].stack...)
		return nil
	}

	// Multi-pred: emit phis. The current block must be the target.
	if ls.b.Current() != target {
		return fmt.Errorf("resolveIncoming: current block %d != target %d", ls.b.Current().ID, target.ID)
	}

	// CRITICAL: a phi's Args must be ordered to match target.Preds —
	// phi.Args[i] is the value flowing in along target.Preds[i]. The
	// incoming-edge list was built in branch-processing order, which
	// is NOT the same as the pred-edge insertion order. Re-order the
	// edges to follow target.Preds, matching by predecessor block.
	ordered := make([]incomingEdge, len(target.Preds))
	for i, pe := range target.Preds {
		found := false
		for _, e := range edges {
			if e.from == pe.Block {
				ordered[i] = e
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("resolveIncoming: no incoming edge recorded for pred b%d of b%d", pe.Block.ID, target.ID)
		}
	}
	edges = ordered

	// Locals.
	nLocals := len(edges[0].locals)
	mergedLocals := make([]*ssa.Value, nLocals)
	for i := 0; i < nLocals; i++ {
		args := make([]*ssa.Value, len(edges))
		allSame := true
		for j, e := range edges {
			args[j] = e.locals[i]
			if args[j] != args[0] {
				allSame = false
			}
		}
		if allSame {
			mergedLocals[i] = args[0]
			continue
		}
		phi := ls.b.NewValue(ssa.OpPhi, ls.localTypes[i], args...)
		mergedLocals[i] = phi
	}
	ls.locals = mergedLocals

	// Stack results.
	mergedStack := make([]*ssa.Value, resultCount)
	for i := 0; i < resultCount; i++ {
		args := make([]*ssa.Value, len(edges))
		allSame := true
		var t ssa.Type
		for j, e := range edges {
			args[j] = e.stack[i]
			t = e.stack[i].Type
			if args[j] != args[0] {
				allSame = false
			}
		}
		if allSame {
			mergedStack[i] = args[0]
			continue
		}
		phi := ls.b.NewValue(ssa.OpPhi, t, args...)
		mergedStack[i] = phi
	}
	// Reset to the region-entry base height (discarding any stale
	// unreachable-branch leftovers), then push the merged results.
	ls.stack = append(ls.stack[:baseHeight:baseHeight], mergedStack...)
	return nil
}

// decodeBlockResults parses a wasm block-type s33 byte. Returns the
// list of result types. Empty block (0x40) → no results. Single
// inline value type → one-element slice. Function-type-index encoding
// (positive s33) is rejected here; that's a future feature.
func decodeBlockResults(bt int64) ([]wasm.ValType, error) {
	if bt == -0x40 || bt == 0x40 {
		return nil, nil
	}
	switch bt {
	case -0x01: // i32 (encoded as 0x7f → s33 -1)
		return []wasm.ValType{wasm.ValI32}, nil
	case -0x02:
		return []wasm.ValType{wasm.ValI64}, nil
	case -0x03:
		return []wasm.ValType{wasm.ValF32}, nil
	case -0x04:
		return []wasm.ValType{wasm.ValF64}, nil
	}
	return nil, fmt.Errorf("blocktype %v not supported (function-type-index encoding)", bt)
}

// push / pop wrap the operand stack with error reporting.
func (ls *lowerState) push(v *ssa.Value) {
	ls.stack = append(ls.stack, v)
}
func (ls *lowerState) pop() (*ssa.Value, error) {
	if len(ls.stack) == 0 {
		return nil, fmt.Errorf("ssa lowering: pop on empty stack")
	}
	v := ls.stack[len(ls.stack)-1]
	ls.stack = ls.stack[:len(ls.stack)-1]
	return v, nil
}

// zeroValueOf emits a zero constant of the given type. Used when a
// path falls off the end unreachable but the wasm signature demands
// results.
func zeroValueOf(b *ssa.FuncBuilder, t ssa.Type) *ssa.Value {
	switch t {
	case ssa.TypeI32:
		return b.Const32(0)
	case ssa.TypeI64:
		return b.Const64(0)
	case ssa.TypeF32:
		return b.NewValueAuxInt(ssa.OpConstF32, ssa.TypeF32, 0)
	case ssa.TypeF64:
		return b.NewValueAuxInt(ssa.OpConstF64, ssa.TypeF64, 0)
	}
	return b.Const32(0)
}

// toSSATypes maps wasm value types to ssa.Type.
func toSSATypes(in []wasm.ValType) []ssa.Type {
	out := make([]ssa.Type, len(in))
	for i, t := range in {
		out[i] = toSSAType(t)
	}
	return out
}

func toSSAType(t wasm.ValType) ssa.Type {
	switch t {
	case wasm.ValI32:
		return ssa.TypeI32
	case wasm.ValI64:
		return ssa.TypeI64
	case wasm.ValF32:
		return ssa.TypeF32
	case wasm.ValF64:
		return ssa.TypeF64
	}
	return ssa.TypeInvalid
}

// setupLocals emits OpParam values for parameters and OpConst zeros for
// the function's declared locals. Returns the per-local current-value
// slice + per-local types (for phi typing later).
func setupLocals(b *ssa.FuncBuilder, fn wasm.Function, ft wasm.FuncType) ([]*ssa.Value, []ssa.Type, error) {
	var locals []*ssa.Value
	var types []ssa.Type
	for i, p := range ft.Params {
		t := toSSAType(p)
		if t == ssa.TypeInvalid {
			return nil, nil, fmt.Errorf("%w: parameter %d has unsupported type %v", ErrSSAUnsupported, i, p)
		}
		locals = append(locals, b.Param(i, t))
		types = append(types, t)
	}
	r := &instrReader{src: fn.Body}
	nDecls, err := r.readU32()
	if err != nil {
		return nil, nil, err
	}
	for i := uint32(0); i < nDecls; i++ {
		count, err := r.readU32()
		if err != nil {
			return nil, nil, err
		}
		t, err := r.readByte()
		if err != nil {
			return nil, nil, err
		}
		st := toSSAType(wasm.ValType(t))
		if st == ssa.TypeInvalid {
			return nil, nil, fmt.Errorf("%w: local block %d has unsupported type 0x%02x", ErrSSAUnsupported, i, t)
		}
		for j := uint32(0); j < count; j++ {
			var zero *ssa.Value
			switch st {
			case ssa.TypeI32:
				zero = b.Const32(0)
			case ssa.TypeI64:
				zero = b.Const64(0)
			case ssa.TypeF32:
				zero = b.NewValueAuxInt(ssa.OpConstF32, ssa.TypeF32, 0)
			case ssa.TypeF64:
				zero = b.NewValueAuxInt(ssa.OpConstF64, ssa.TypeF64, 0)
			default:
				return nil, nil, fmt.Errorf("%w: zero-init local of type %v", ErrSSAUnsupported, st)
			}
			locals = append(locals, zero)
			types = append(types, st)
		}
	}
	return locals, types, nil
}

func skipLocalDecls(r *instrReader) error {
	nDecls, err := r.readU32()
	if err != nil {
		return err
	}
	for i := uint32(0); i < nDecls; i++ {
		if _, err := r.readU32(); err != nil {
			return err
		}
		if _, err := r.readByte(); err != nil {
			return err
		}
	}
	return nil
}

// isGtGe reports whether the wasm op is a greater-than or
// greater-or-equal comparison (which lower to the corresponding lt/le
// SSA op with swapped arguments).
func isGtGe(op byte) bool {
	switch op {
	case opI32GtS, opI32GtU, opI32GeS, opI32GeU,
		opI64GtS, opI64GtU, opI64GeS, opI64GeU:
		return true
	}
	return false
}

// isSimpleBinary reports whether op is a stack-consuming binary op
// supported by the current lowering directly via simpleBinaryOp (no
// helper-call indirection).
func isSimpleBinary(op byte) bool {
	switch op {
	case opI32Add, opI32Sub, opI32Mul, opI32And, opI32Or, opI32Xor,
		opI32Shl, opI32ShrS, opI32ShrU,
		opI64Add, opI64Sub, opI64Mul, opI64And, opI64Or, opI64Xor,
		opI64Shl, opI64ShrS, opI64ShrU,
		opI32Eq, opI32Ne, opI32LtS, opI32LtU, opI32LeS, opI32LeU,
		opI32GtS, opI32GtU, opI32GeS, opI32GeU,
		opI64Eq, opI64Ne, opI64LtS, opI64LtU, opI64LeS, opI64LeU,
		opI64GtS, opI64GtU, opI64GeS, opI64GeU:
		return true
	}
	return false
}

// simpleBinaryOp maps a wasm opcode to (ssa.Op, result type).
func simpleBinaryOp(op byte) (ssa.Op, ssa.Type) {
	switch op {
	case opI32Add:
		return ssa.OpAdd32, ssa.TypeI32
	case opI32Sub:
		return ssa.OpSub32, ssa.TypeI32
	case opI32Mul:
		return ssa.OpMul32, ssa.TypeI32
	case opI32And:
		return ssa.OpAnd32, ssa.TypeI32
	case opI32Or:
		return ssa.OpOr32, ssa.TypeI32
	case opI32Xor:
		return ssa.OpXor32, ssa.TypeI32
	case opI32Shl:
		return ssa.OpShl32, ssa.TypeI32
	case opI32ShrS:
		return ssa.OpShrS32, ssa.TypeI32
	case opI32ShrU:
		return ssa.OpShrU32, ssa.TypeI32
	case opI64Add:
		return ssa.OpAdd64, ssa.TypeI64
	case opI64Sub:
		return ssa.OpSub64, ssa.TypeI64
	case opI64Mul:
		return ssa.OpMul64, ssa.TypeI64
	case opI64And:
		return ssa.OpAnd64, ssa.TypeI64
	case opI64Or:
		return ssa.OpOr64, ssa.TypeI64
	case opI64Xor:
		return ssa.OpXor64, ssa.TypeI64
	case opI64Shl:
		return ssa.OpShl64, ssa.TypeI64
	case opI64ShrS:
		return ssa.OpShrS64, ssa.TypeI64
	case opI64ShrU:
		return ssa.OpShrU64, ssa.TypeI64
	case opI32Eq:
		return ssa.OpEq32, ssa.TypeBool
	case opI32Ne:
		return ssa.OpNe32, ssa.TypeBool
	case opI32LtS:
		return ssa.OpLtS32, ssa.TypeBool
	case opI32LtU:
		return ssa.OpLtU32, ssa.TypeBool
	case opI32LeS:
		return ssa.OpLeS32, ssa.TypeBool
	case opI32LeU:
		return ssa.OpLeU32, ssa.TypeBool
	case opI32GtS:
		// gt is lt with swapped args; we'll wrap at emit time.
		return ssa.OpLtS32, ssa.TypeBool
	case opI32GtU:
		return ssa.OpLtU32, ssa.TypeBool
	case opI32GeS:
		return ssa.OpLeS32, ssa.TypeBool
	case opI32GeU:
		return ssa.OpLeU32, ssa.TypeBool
	case opI64Eq:
		return ssa.OpEq64, ssa.TypeBool
	case opI64Ne:
		return ssa.OpNe64, ssa.TypeBool
	case opI64LtS:
		return ssa.OpLtS64, ssa.TypeBool
	case opI64LtU:
		return ssa.OpLtU64, ssa.TypeBool
	case opI64LeS:
		return ssa.OpLeS64, ssa.TypeBool
	case opI64LeU:
		return ssa.OpLeU64, ssa.TypeBool
	case opI64GtS:
		return ssa.OpLtS64, ssa.TypeBool
	case opI64GtU:
		return ssa.OpLtU64, ssa.TypeBool
	case opI64GeS:
		return ssa.OpLeS64, ssa.TypeBool
	case opI64GeU:
		return ssa.OpLeU64, ssa.TypeBool
	}
	panic("simpleBinaryOp: not a binary op")
}

// helperBinary describes a wasm binary op that lowers to a 2-arg call
// to a pre-existing pure helper (rotation, min/max, copysign, float
// compares).
type helperBinary struct {
	helper  string
	resType ssa.Type
}

// helperUnary describes a wasm unary op that lowers to a 1-arg helper
// call (eqz, clz/ctz/popcnt, float unary, conversions, sign-extend).
type helperUnary struct {
	helper  string
	resType ssa.Type
}

func isHelperBinary(op byte) bool {
	switch op {
	case opI32Rotl, opI32Rotr, opI64Rotl, opI64Rotr,
		opI32DivS, opI32DivU, opI32RemS, opI32RemU,
		opI64DivS, opI64DivU, opI64RemS, opI64RemU,
		opF32Add, opF32Sub, opF32Mul, opF32Div,
		opF64Add, opF64Sub, opF64Mul, opF64Div,
		opF32Min, opF32Max, opF32Copysign,
		opF64Min, opF64Max, opF64Copysign,
		opF32Eq, opF32Ne, opF32Lt, opF32Gt, opF32Le, opF32Ge,
		opF64Eq, opF64Ne, opF64Lt, opF64Gt, opF64Le, opF64Ge:
		return true
	}
	return false
}

func helperBinarySpec(op byte) helperBinary {
	switch op {
	case opI32Rotl:
		return helperBinary{"i32_rotl", ssa.TypeI32}
	case opI32Rotr:
		return helperBinary{"i32_rotr", ssa.TypeI32}
	case opI64Rotl:
		return helperBinary{"i64_rotl", ssa.TypeI64}
	case opI64Rotr:
		return helperBinary{"i64_rotr", ssa.TypeI64}
	case opI32DivS:
		return helperBinary{"i32_div_s", ssa.TypeI32}
	case opI32DivU:
		return helperBinary{"i32_div_u_s", ssa.TypeI32}
	case opI32RemS:
		return helperBinary{"i32_rem_s", ssa.TypeI32}
	case opI32RemU:
		return helperBinary{"i32_rem_u_s", ssa.TypeI32}
	case opI64DivS:
		return helperBinary{"i64_div_s", ssa.TypeI64}
	case opI64DivU:
		return helperBinary{"i64_div_u_s", ssa.TypeI64}
	case opI64RemS:
		return helperBinary{"i64_rem_s", ssa.TypeI64}
	case opI64RemU:
		return helperBinary{"i64_rem_u_s", ssa.TypeI64}
	case opF32Add:
		return helperBinary{"f32_add", ssa.TypeF32}
	case opF32Sub:
		return helperBinary{"f32_sub", ssa.TypeF32}
	case opF32Mul:
		return helperBinary{"f32_mul", ssa.TypeF32}
	case opF32Div:
		return helperBinary{"f32_div", ssa.TypeF32}
	case opF64Add:
		return helperBinary{"f64_add", ssa.TypeF64}
	case opF64Sub:
		return helperBinary{"f64_sub", ssa.TypeF64}
	case opF64Mul:
		return helperBinary{"f64_mul", ssa.TypeF64}
	case opF64Div:
		return helperBinary{"f64_div", ssa.TypeF64}
	case opF32Min:
		return helperBinary{"f32_min", ssa.TypeF32}
	case opF32Max:
		return helperBinary{"f32_max", ssa.TypeF32}
	case opF32Copysign:
		return helperBinary{"f32_copysign", ssa.TypeF32}
	case opF64Min:
		return helperBinary{"f64_min", ssa.TypeF64}
	case opF64Max:
		return helperBinary{"f64_max", ssa.TypeF64}
	case opF64Copysign:
		return helperBinary{"f64_copysign", ssa.TypeF64}
	case opF32Eq:
		return helperBinary{"f32_eq", ssa.TypeI32}
	case opF32Ne:
		return helperBinary{"f32_ne", ssa.TypeI32}
	case opF32Lt:
		return helperBinary{"f32_lt", ssa.TypeI32}
	case opF32Gt:
		return helperBinary{"f32_gt", ssa.TypeI32}
	case opF32Le:
		return helperBinary{"f32_le", ssa.TypeI32}
	case opF32Ge:
		return helperBinary{"f32_ge", ssa.TypeI32}
	case opF64Eq:
		return helperBinary{"f64_eq", ssa.TypeI32}
	case opF64Ne:
		return helperBinary{"f64_ne", ssa.TypeI32}
	case opF64Lt:
		return helperBinary{"f64_lt", ssa.TypeI32}
	case opF64Gt:
		return helperBinary{"f64_gt", ssa.TypeI32}
	case opF64Le:
		return helperBinary{"f64_le", ssa.TypeI32}
	case opF64Ge:
		return helperBinary{"f64_ge", ssa.TypeI32}
	}
	panic(fmt.Sprintf("helperBinarySpec: unknown op 0x%02x", op))
}

func isHelperUnary(op byte) bool {
	switch op {
	case opI32Eqz, opI64Eqz,
		opI32Clz, opI32Ctz, opI32Popcnt,
		opI64Clz, opI64Ctz, opI64Popcnt,
		opF32Abs, opF32Neg, opF32Ceil, opF32Floor, opF32Trunc, opF32Nearest, opF32Sqrt,
		opF64Abs, opF64Neg, opF64Ceil, opF64Floor, opF64Trunc, opF64Nearest, opF64Sqrt,
		opI32WrapI64,
		opI32TruncF32S, opI32TruncF32U, opI32TruncF64S, opI32TruncF64U,
		opI64ExtendI32S, opI64ExtendI32U,
		opI64TruncF32S, opI64TruncF32U, opI64TruncF64S, opI64TruncF64U,
		opF32ConvertI32S, opF32ConvertI32U, opF32ConvertI64S, opF32ConvertI64U,
		opF32DemoteF64,
		opF64ConvertI32S, opF64ConvertI32U, opF64ConvertI64S, opF64ConvertI64U,
		opF64PromoteF32,
		opI32ReinterpretF32, opI64ReinterpretF64, opF32ReinterpretI32, opF64ReinterpretI64,
		opI32Extend8S, opI32Extend16S,
		opI64Extend8S, opI64Extend16S, opI64Extend32S:
		return true
	}
	return false
}

func helperUnarySpec(op byte) helperUnary {
	switch op {
	case opI32Eqz:
		return helperUnary{"i32_eqz", ssa.TypeI32}
	case opI64Eqz:
		return helperUnary{"i64_eqz", ssa.TypeI32}
	case opI32Clz:
		return helperUnary{"i32_clz", ssa.TypeI32}
	case opI32Ctz:
		return helperUnary{"i32_ctz", ssa.TypeI32}
	case opI32Popcnt:
		return helperUnary{"i32_popcnt", ssa.TypeI32}
	case opI64Clz:
		return helperUnary{"i64_clz", ssa.TypeI64}
	case opI64Ctz:
		return helperUnary{"i64_ctz", ssa.TypeI64}
	case opI64Popcnt:
		return helperUnary{"i64_popcnt", ssa.TypeI64}
	case opF32Abs:
		return helperUnary{"f32_abs", ssa.TypeF32}
	case opF32Neg:
		return helperUnary{"f32_neg", ssa.TypeF32}
	case opF32Ceil:
		return helperUnary{"f32_ceil", ssa.TypeF32}
	case opF32Floor:
		return helperUnary{"f32_floor", ssa.TypeF32}
	case opF32Trunc:
		return helperUnary{"f32_trunc", ssa.TypeF32}
	case opF32Nearest:
		return helperUnary{"f32_nearest", ssa.TypeF32}
	case opF32Sqrt:
		return helperUnary{"f32_sqrt", ssa.TypeF32}
	case opF64Abs:
		return helperUnary{"f64_abs", ssa.TypeF64}
	case opF64Neg:
		return helperUnary{"f64_neg", ssa.TypeF64}
	case opF64Ceil:
		return helperUnary{"f64_ceil", ssa.TypeF64}
	case opF64Floor:
		return helperUnary{"f64_floor", ssa.TypeF64}
	case opF64Trunc:
		return helperUnary{"f64_trunc", ssa.TypeF64}
	case opF64Nearest:
		return helperUnary{"f64_nearest", ssa.TypeF64}
	case opF64Sqrt:
		return helperUnary{"f64_sqrt", ssa.TypeF64}
	case opI32WrapI64:
		return helperUnary{"i32_wrap_i64", ssa.TypeI32}
	case opI32TruncF32S:
		return helperUnary{"i32_trunc_f32_s", ssa.TypeI32}
	case opI32TruncF32U:
		return helperUnary{"i32_trunc_f32_u", ssa.TypeI32}
	case opI32TruncF64S:
		return helperUnary{"i32_trunc_f64_s", ssa.TypeI32}
	case opI32TruncF64U:
		return helperUnary{"i32_trunc_f64_u", ssa.TypeI32}
	case opI64ExtendI32S:
		return helperUnary{"i64_extend_i32_s", ssa.TypeI64}
	case opI64ExtendI32U:
		return helperUnary{"i64_extend_i32_u", ssa.TypeI64}
	case opI64TruncF32S:
		return helperUnary{"i64_trunc_f32_s", ssa.TypeI64}
	case opI64TruncF32U:
		return helperUnary{"i64_trunc_f32_u", ssa.TypeI64}
	case opI64TruncF64S:
		return helperUnary{"i64_trunc_f64_s", ssa.TypeI64}
	case opI64TruncF64U:
		return helperUnary{"i64_trunc_f64_u", ssa.TypeI64}
	case opF32ConvertI32S:
		return helperUnary{"f32_convert_i32_s", ssa.TypeF32}
	case opF32ConvertI32U:
		return helperUnary{"f32_convert_i32_u", ssa.TypeF32}
	case opF32ConvertI64S:
		return helperUnary{"f32_convert_i64_s", ssa.TypeF32}
	case opF32ConvertI64U:
		return helperUnary{"f32_convert_i64_u", ssa.TypeF32}
	case opF32DemoteF64:
		return helperUnary{"f32_demote_f64", ssa.TypeF32}
	case opF64ConvertI32S:
		return helperUnary{"f64_convert_i32_s", ssa.TypeF64}
	case opF64ConvertI32U:
		return helperUnary{"f64_convert_i32_u", ssa.TypeF64}
	case opF64ConvertI64S:
		return helperUnary{"f64_convert_i64_s", ssa.TypeF64}
	case opF64ConvertI64U:
		return helperUnary{"f64_convert_i64_u", ssa.TypeF64}
	case opF64PromoteF32:
		return helperUnary{"f64_promote_f32", ssa.TypeF64}
	case opI32ReinterpretF32:
		return helperUnary{"i32_reinterpret_f32", ssa.TypeI32}
	case opI64ReinterpretF64:
		return helperUnary{"i64_reinterpret_f64", ssa.TypeI64}
	case opF32ReinterpretI32:
		return helperUnary{"f32_reinterpret_i32", ssa.TypeF32}
	case opF64ReinterpretI64:
		return helperUnary{"f64_reinterpret_i64", ssa.TypeF64}
	case opI32Extend8S:
		return helperUnary{"i32_extend8_s", ssa.TypeI32}
	case opI32Extend16S:
		return helperUnary{"i32_extend16_s", ssa.TypeI32}
	case opI64Extend8S:
		return helperUnary{"i64_extend8_s", ssa.TypeI64}
	case opI64Extend16S:
		return helperUnary{"i64_extend16_s", ssa.TypeI64}
	case opI64Extend32S:
		return helperUnary{"i64_extend32_s", ssa.TypeI64}
	}
	panic(fmt.Sprintf("helperUnarySpec: unknown op 0x%02x", op))
}
