package lower

import (
	"fmt"
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

// inline policy caps. Chosen from the SpiderMonkey cpubench hot set
// (Fn1466: ~60 B x 36 sites; Fn2120: ~1 KiB x 16 sites).
const (
	// Max callee body size in wasm bytes.
	inlineMaxBody = 4096
	// Max bodyBytes x staticCallSites product: bounds the total code
	// growth any single callee can cause module-wide.
	inlineMaxProduct = 131072
	// Max total wasm bytes inlined into one caller.
	inlineCallerBudget = 65536
	// Non-leaf callees qualify only when SMALL (the expf/erf class of
	// math kernels with cold error-path calls) — opening this wider
	// inflates module-wide code growth and compile time out of
	// proportion.
	inlineNonLeafMaxBody = 512
)

// fnInlineInfo is the per-defined-function summary the inline decision
// consults. Keyed by ABSOLUTE function index (imports first).
type fnInlineInfo struct {
	bodyBytes int
	leaf      bool // no call / call_indirect anywhere in the body
	hasTry    bool
	// noInline pins the function out-of-line regardless of size: it
	// is an export whose body the downstream asm bundle replaces (a
	// kernel override). Inlining it into every caller would leave the
	// exported body dead and the replacement landing on unreachable
	// code.
	noInline bool
	sites    int // static `call <idx>` sites referencing this function
	// innerCalls lists the direct callees inside the body (dedup'd);
	// hasIndirect marks a call_indirect. A non-leaf body may still
	// inline when every inner call is direct and non-throwing: the
	// inner calls stay ordinary calls inside the inline frame, which
	// keeps recursion impossible and code growth capped, and the
	// non-throwing requirement keeps the post-call exception check
	// (whose edge would need the CALLER's locals) out of the frame.
	innerCalls  []uint32
	hasIndirect bool
}

type inlineAnalysis struct {
	fns map[uint32]*fnInlineInfo
}

// inlineAnalysisCache maps *wasm.Module → *inlineAnalysis. LowerFunction
// is called once per function of the same module; the scan runs once.
var inlineAnalysisCache sync.Map

// noInlineExports maps *wasm.Module → map[string]bool of export names
// pinned out of line (see fnInlineInfo.noInline). SetNoInlineExports
// registers them; it must run before the module's first LowerFunction,
// since the inline analysis is computed once and cached.
var noInlineExports sync.Map

// SetNoInlineExports pins the named exports of mod out of line for
// inlining decisions. Call it before lowering any function of mod.
func SetNoInlineExports(mod *wasm.Module, names []string) {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	noInlineExports.Store(mod, set)
	inlineAnalysisCache.Delete(mod)
}

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
	// Pinned exports: the asm bundle replaces their bodies (kernel
	// overrides), so every call must reach the exported body itself.
	if pinned, ok := noInlineExports.Load(mod); ok {
		for _, e := range mod.Exports {
			if e.Kind == wasm.ExportFunc && pinned.(map[string]bool)[e.Name] {
				if info, ok := a.fns[e.Index]; ok {
					info.noInline = true
				}
			}
		}
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
			seen := false
			for _, c := range info.innerCalls {
				if c == callee {
					seen = true
					break
				}
			}
			if !seen {
				info.innerCalls = append(info.innerCalls, callee)
			}
		case wasm.OpCallIndirect:
			info.leaf = false
			info.hasIndirect = true
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
	// Depth 1 only: a call inside an inline frame stays a call. This
	// is what makes non-leaf inlining terminate — without it, two
	// small functions calling each other expand forever.
	if len(ls.inlineFrames) > 0 {
		return false
	}
	if funcIdx < ls.mod.NumImportedFuncs {
		return false // imports have no body
	}
	// A callee that can leave an exception pending needs a post-call check
	// whose exception edge carries the CALLER's locals; inside an inline
	// frame the local set is the callee's, so the edge would be malformed.
	// Refusing such callees also keeps the check-and-branch out of spliced
	// bodies entirely.
	if ls.mayThrowCall(funcIdx) {
		return false
	}
	if len(ft.Results) > 1 {
		return false
	}
	if ls.inlineInfo == nil {
		return false
	}
	info, ok := ls.inlineInfo.fns[funcIdx]
	if !ok || info.hasTry || info.noInline {
		return false
	}
	// A non-leaf body may inline when every inner call is direct,
	// defined, and non-throwing: the inner calls stay ordinary calls
	// inside the inline frame (no recursion, growth still capped by
	// the body-size products), and no post-call exception check is
	// needed inside the frame.
	if !info.leaf {
		// Bound the relaxation tightly: only SMALL non-leaf bodies
		// (the expf/erf class of math kernels with cold error-path
		// calls) qualify — opening it wider inflates module-wide
		// code growth and compile time out of proportion.
		if info.bodyBytes > inlineNonLeafMaxBody {
			return false
		}
		if info.hasIndirect {
			return false
		}
		for _, c := range info.innerCalls {
			if c < ls.mod.NumImportedFuncs || ls.mayThrowCall(c) {
				return false
			}
		}
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
