package lower

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// This file implements the wasm-level function inliner: small leaf
// callees are spliced into their callers during lowering instead of
// emitting an OpCallDirect.
//
// Why wasm2go needs its own inliner when gc already has one: in the
// multi-package layout, cross-chunk calls go through //go:linkname
// forwarders, which are OPAQUE to gc's inliner — a 35-line leaf in p7
// called from the interpreter loop in p0 can never be inlined by gc,
// no matter how small. And on the gcasm backend every surviving call
// additionally pays the ABI0 marshalling the capture transform
// inserts (measured: 1.38× on the SpiderMonkey cpubench) plus, for
// cross-chunk sites, a gcasmFwd trampoline. Inlining at the wasm
// level deletes the call BEFORE chunking, so the marshalling and the
// trampoline disappear with it, on both backends.
//
// Mechanism: the callee body is lowered inline as if it were a
// `block <callee-results> ... end` — a ctrlBlock frame whose post
// block is the join. Callee params become the popped argument values;
// non-param locals are fresh zero constants; `return` inside the
// callee lowers as `br` to the inline frame (identical semantics:
// wasm return IS a branch to the function-body block). The existing
// block/br/phi machinery handles multi-path joins, early returns,
// traps and loops inside the callee with no new CFG code.
//
// v1 policy (deliberately conservative):
//   - leaf callees only (no call / call_indirect in the body): bounds
//     code growth structurally and makes recursion impossible;
//   - no try (EH) in the callee, and the CALLER must not be in
//     mutable-locals mode (its local indices would collide);
//   - ≤1 result (same limit as handleCall);
//   - size caps, all env-tunable for experiments (see below).

// inline policy knobs. Defaults chosen from the SpiderMonkey cpubench
// hot set (Fn1466: ~60 B × 36 sites; Fn2120: ~1 KiB × 16 sites).
var (
	// WASM2GO_INLINE=off disables the inliner entirely.
	inlineOff = os.Getenv("WASM2GO_INLINE") == "off"
	// Max callee body size in wasm bytes.
	inlineMaxBody = envInt("WASM2GO_INLINE_MAXBODY", 4096)
	// Max bodyBytes × staticCallSites product: bounds the total code
	// growth any single callee can cause module-wide.
	inlineMaxProduct = envInt("WASM2GO_INLINE_MAXPRODUCT", 49152)
	// Max total wasm bytes inlined into one caller.
	inlineCallerBudget = envInt("WASM2GO_INLINE_CALLER_BUDGET", 65536)
	// Bisection gate (mirrors WASM2GO_SSA_MINFUNC/MAXFUNC): inlining
	// only happens in CALLERS whose absolute funcIdx is in
	// [MINFN, MAXFN). MAXFN < 0 means no upper bound. Diagnostic only.
	inlineMinFn = envInt("WASM2GO_INLINE_MINFN", 0)
	inlineMaxFn = envInt("WASM2GO_INLINE_MAXFN", -1)
	// WASM2GO_INLINE_ONLY_CALLEES: comma-separated absolute callee
	// funcIdx allowlist — when non-empty only these callees inline.
	// Diagnostic only (callee-level bisection).
	inlineOnlyCallees = envIdxSet("WASM2GO_INLINE_ONLY_CALLEES")
)

func envIdxSet(name string) map[uint32]bool {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	out := map[uint32]bool{}
	for _, part := range strings.Split(v, ",") {
		// ParseUint with bitSize 32 both rejects negatives and bounds
		// the value to uint32, so the conversion below cannot truncate.
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wasm2go: invalid %s entry %q: %v\n", name, part, err)
			continue
		}
		out[uint32(n)] = true
	}
	return out
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm2go: invalid %s=%q (using default %d): %v\n", name, v, def, err)
		return def
	}
	return n
}

// fnInlineInfo is the per-defined-function summary the inline decision
// consults. Keyed by ABSOLUTE function index (imports first).
type fnInlineInfo struct {
	bodyBytes int
	leaf      bool // no call / call_indirect anywhere in the body
	hasTry    bool
	sites     int // static `call <idx>` sites referencing this function
}

type inlineAnalysis struct {
	fns map[uint32]*fnInlineInfo
}

// inlineAnalysisCache maps *wasm.Module → *inlineAnalysis. LowerFunction
// is called once per function of the same module; the scan runs once.
var inlineAnalysisCache sync.Map

// analyzeModuleForInline scans every defined function body once,
// recording size, leafness, try-presence and per-callee static call
// site counts.
func analyzeModuleForInline(mod *wasm.Module) *inlineAnalysis {
	if a, ok := inlineAnalysisCache.Load(mod); ok {
		return a.(*inlineAnalysis)
	}
	a := &inlineAnalysis{fns: make(map[uint32]*fnInlineInfo, len(mod.Functions))}
	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		a.fns[idx] = &fnInlineInfo{bodyBytes: len(mod.Functions[i].Body), leaf: true}
	}
	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		info := a.fns[idx]
		if err := scanBodyForInline(mod.Functions[i].Body, a, info); err != nil {
			// Unparseable body: mark it never-inlinable. The regular
			// lowering will surface the real error with full context.
			info.leaf = false
		}
	}
	actual, _ := inlineAnalysisCache.LoadOrStore(mod, a)
	return actual.(*inlineAnalysis)
}

// scanBodyForInline walks one function body, filling info (leafness,
// try-presence) and bumping the static-call-site counters of every
// direct callee it references.
func scanBodyForInline(body []byte, a *inlineAnalysis, info *fnInlineInfo) error {
	r := wasm.NewInstrReader(body)
	if err := skipLocalDecls(r); err != nil {
		return err
	}
	for !r.EOF() {
		op, err := r.ReadByte()
		if err != nil {
			return err
		}
		switch op {
		case wasm.OpCall:
			info.leaf = false
			callee, err := r.ReadU32()
			if err != nil {
				return err
			}
			if ci, ok := a.fns[callee]; ok {
				ci.sites++
			}
		case wasm.OpCallIndirect:
			info.leaf = false
			if err := r.SkipImmediates(op); err != nil {
				return err
			}
		case wasm.OpTry:
			info.hasTry = true
			if err := r.SkipImmediates(op); err != nil {
				return err
			}
		default:
			if err := r.SkipImmediates(op); err != nil {
				return err
			}
		}
	}
	return nil
}

// shouldInline reports whether the direct call to funcIdx should be
// inlined at this call site.
func (ls *lowerState) shouldInline(funcIdx uint32, ft wasm.FuncType) bool {
	if inlineOff {
		return false
	}
	if int(ls.callerIdx) < inlineMinFn || (inlineMaxFn >= 0 && int(ls.callerIdx) >= inlineMaxFn) {
		return false
	}
	if inlineOnlyCallees != nil && !inlineOnlyCallees[funcIdx] {
		return false
	}
	// The caller's mutable-locals mode keeps locals as indexed Go vars;
	// splicing a callee would collide local indices.
	if ls.mutableLocals {
		return false
	}
	if funcIdx < ls.mod.NumImportedFuncs {
		return false // imports have no body
	}
	if len(ft.Results) > 1 {
		return false
	}
	if ls.inlineInfo == nil {
		return false
	}
	info, ok := ls.inlineInfo.fns[funcIdx]
	if !ok || !info.leaf || info.hasTry {
		return false
	}
	if info.bodyBytes > inlineMaxBody {
		return false
	}
	if info.bodyBytes*info.sites > inlineMaxProduct {
		return false
	}
	if ls.inlinedBytes+info.bodyBytes > inlineCallerBudget {
		return false
	}
	return true
}

// inlineFrame tracks one in-progress inline expansion. `return` inside
// the spliced body branches to ctrl[ctrlIdx].target instead of sealing
// a BlockRet.
type inlineFrame struct {
	ctrlIdx         int
	savedFt         wasm.FuncType
	savedLocals     []*ssa.Value
	savedLocalTypes []ssa.Type
}

// lowerInlineCall splices the body of funcIdx at the current cursor.
// Preconditions: shouldInline returned true (leaf, no-EH, size-capped
// callee; non-mutable-locals caller).
func (ls *lowerState) lowerInlineCall(funcIdx uint32, ft wasm.FuncType) error {
	if len(ls.stack) < len(ft.Params) {
		return fmt.Errorf("inline call fn%d: stack underflow (need %d, have %d)", funcIdx, len(ft.Params), len(ls.stack))
	}
	argStart := len(ls.stack) - len(ft.Params)
	args := append([]*ssa.Value(nil), ls.stack[argStart:]...)
	ls.stack = ls.stack[:argStart]

	fn := ls.mod.Functions[funcIdx-ls.mod.NumImportedFuncs]

	// Callee locals: params = the argument values, non-param locals =
	// fresh zero constants (wasm zero-initialises declared locals).
	locals := append([]*ssa.Value(nil), args...)
	types := make([]ssa.Type, 0, len(ft.Params))
	for i, p := range ft.Params {
		t := toSSAType(p)
		if t == ssa.TypeInvalid {
			return fmt.Errorf("%w: inline fn%d: param %d type %v", ErrSSAUnsupported, funcIdx, i, p)
		}
		types = append(types, t)
	}
	r := wasm.NewInstrReader(fn.Body)
	nDecls, err := r.ReadU32()
	if err != nil {
		return err
	}
	for i := uint32(0); i < nDecls; i++ {
		count, err := r.ReadU32()
		if err != nil {
			return err
		}
		tb, err := r.ReadByte()
		if err != nil {
			return err
		}
		st := toSSAType(wasm.ValType(tb))
		if st == ssa.TypeInvalid {
			return fmt.Errorf("%w: inline fn%d: local type 0x%02x", ErrSSAUnsupported, funcIdx, tb)
		}
		for j := uint32(0); j < count; j++ {
			locals = append(locals, zeroValueOf(ls.b, st))
			types = append(types, st)
		}
	}

	// Open the inline frame: semantically `block <callee-results>`.
	postBlk := ls.b.NewBlock(ssa.BlockPlain)
	ls.ctrl = append(ls.ctrl, &ctrlFrame{
		kind:               ctrlBlock,
		target:             postBlk,
		fallthrough_:       postBlk,
		resultCount:        len(ft.Results),
		stackHeightAtEntry: len(ls.stack),
	})
	ls.inlineFrames = append(ls.inlineFrames, inlineFrame{
		ctrlIdx:         len(ls.ctrl) - 1,
		savedFt:         ls.ft,
		savedLocals:     ls.locals,
		savedLocalTypes: ls.localTypes,
	})
	baseCtrl := len(ls.ctrl) - 1 // inline body finished once ctrl pops back to this depth

	ls.ft = ft
	ls.locals = locals
	ls.localTypes = types
	ls.inlinedBytes += len(fn.Body)

	if err := ls.lowerBodyUntil(r, baseCtrl); err != nil {
		return fmt.Errorf("inline fn%d: %w", funcIdx, err)
	}

	// Restore the caller's view. The operand stack already holds the
	// callee's result (pushed by the inline frame's end join) — or the
	// cursor is unreachable if the callee provably never returns.
	inf := ls.inlineFrames[len(ls.inlineFrames)-1]
	ls.inlineFrames = ls.inlineFrames[:len(ls.inlineFrames)-1]
	ls.ft = inf.savedFt
	ls.locals = inf.savedLocals
	ls.localTypes = inf.savedLocalTypes
	if len(ls.ctrl) != baseCtrl {
		return fmt.Errorf("%w: inline fn%d: control stack imbalance (%d != %d)", ErrSSAUnsupported, funcIdx, len(ls.ctrl), baseCtrl)
	}
	return nil
}

// returnAsInlineBr lowers `return` inside an inline body: a branch to
// the innermost inline frame's post block, carrying the callee's
// results — exactly the semantics of `br` to the function-body block.
func (ls *lowerState) returnAsInlineBr() error {
	inf := ls.inlineFrames[len(ls.inlineFrames)-1]
	frame := ls.ctrl[inf.ctrlIdx]
	nRes := frame.resultCount
	if len(ls.stack) < nRes {
		return fmt.Errorf("inline return with %d stack values, expected %d", len(ls.stack), nRes)
	}
	ls.recordIncoming(frame.target, nRes)
	cur := ls.b.Current()
	cur.Kind = ssa.BlockPlain
	ssa.AddEdge(cur, frame.target)
	ls.unreachable = true
	return nil
}
