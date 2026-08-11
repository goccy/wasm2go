// Package asmgen lowers an ssa.Func to plan9 assembly so the generated
// body can be compiled by the Go toolchain without ever appearing as
// Go source on the host's GOARCH. The companion Go file produced
// alongside the .s contains only the function declaration — go/types
// reads it in microseconds and golangci-lint's SSA-based analyses
// have no body to walk. On a GOARCH the asm emitter doesn't target,
// the project falls back to the original Go-source emitter at
// build-tag dispatch time.
//
// This first cut targets amd64 and supports the opcode set needed by
// the project's arith / control-flow / memory-op fixtures: integer
// binary/shift/compare ops at i32 and i64, helper calls (rotl, div_s,
// rem, eqz, etc.), single- and multi-block CFGs with Plain / If /
// Ret / Unreachable terminators, OpPhi via predecessor-edge copies,
// and linear-memory loads/stores via Module.M.
package asmgen

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// FuncOptionsFromDriver builds FuncOptions whose Module and naming
// callbacks delegate to the given emit.Driver. modulePkgRef is the
// Go-side spelling of the host's *Module parameter type, picked by
// the caller to match its packaging ("*Module" same-package,
// "*base.Module" multi-package). HelperPrefix is taken from
// MultiPackage: "" same-package, "base" multi-package outside base
// itself (where the helpers live alongside).
//
// The Driver returns Go-side qualified names (e.g. "base.Fn42").
// asmgen translates those into plan9 asm symbols ("base·Fn42(SB)")
// inside goAsmSymbol — callers don't need to construct .vs·.
// themselves.
func FuncOptionsFromDriver(d emit.Driver, modulePkgRef string) FuncOptions {
	prefix := ""
	if d.MultiPackage() {
		prefix = "base"
	}
	return FuncOptions{
		ModulePkgRef: modulePkgRef,
		HelperPrefix: prefix,
		Module:       d.Module(),
		FuncSymbol: func(idx uint32) string {
			return d.FuncRefName(idx)
		},
	}
}

// FuncOptions bundles the per-function emit knobs that have a
// chance of changing per-host (single-package vs multi-package,
// same-vs-cross chunk callees, etc).
type FuncOptions struct {
	// ModulePkgRef is the qualified Go expression for the host's
	// `*Module` parameter type — "*Module" for single-package
	// output, "*base.Module" for the multi-package + linkname-split
	// layout. The asm body never dereferences the type; the
	// qualifier is purely a decl-side detail.
	ModulePkgRef string
	// HelperPrefix is the asm-symbol prefix for helper CALLs. Empty
	// string means the helper lives in the same package
	// (CALL ·foo(SB)); "base" means cross-package
	// (CALL base·Foo(SB)).
	HelperPrefix string
	// Module is the parsed wasm module the function belongs to.
	// Used to look up callee signatures during OpCallDirect
	// emission. Required when the function contains direct calls.
	Module *wasm.Module
	// FuncSymbol returns the asm symbol for a direct-call target by
	// wasm function index. The returned string is the bare name
	// (without ·); the emitter wraps it in the appropriate package-
	// qualifier form. nil means "use Fn<idx>" — the default name
	// produced by the codegen translator's multi-package mode.
	FuncSymbol func(funcIdx uint32) string
	// GlobalOffsets is the byte offset of each WASM global within
	// the generated Module struct, indexed by the WASM global index
	// (imported globals at the low indices keep a -1 sentinel — the
	// Module struct doesn't carry them, so OpGlobalGet/Set for those
	// indices still routes through the loadGlobal_N / storeGlobal_N
	// CALL path). When non-nil, OpGlobalGet/OpGlobalSet on
	// module-defined globals lower to an inline MOV against the
	// `*Module` parameter — skipping the wrapper CALL and the
	// caller-side BX clobber that comes with it. ComputeGlobalOffsets
	// produces a slice with the layout this field expects.
	GlobalOffsets []int
	// Splicer, when non-nil, supplies inline bodies for SIMD helper
	// call sites (OpSimdCall / OpSimdMemCall) in place of the
	// marshalled CALL. Functions containing SIMD calls then emit in
	// slot-only mode (no register homes, no m-cache, no loop-carry
	// coalesce) because splice bodies clobber registers freely.
	Splicer SimdSplicer
	// CalleeSymbol, when non-nil, resolves a direct-call target to a
	// locally CALLable bare asm symbol (no ·/(SB) decoration; possibly
	// a host-emitted forward wrapper). Calls resolved this way are
	// exempt from ForbidCalls — the host guarantees the symbol links
	// in the package the body lands in. ok=false falls back to the
	// FuncSymbol spelling and the ForbidCalls consequence.
	CalleeSymbol func(funcIdx uint32) (string, bool)
	// MemHelperSymbol likewise resolves the memory-op helper family
	// (memorySize / memoryGrow / memoryCopy / memoryFill and their 64
	// variants) to a locally CALLable bare symbol.
	MemHelperSymbol func(name string) (string, bool)
	// PackedParams, when non-nil, marks the packed outlined-boundary
	// form: the Go-side signature carries only the module pointer and
	// the parameter VALUES ride the Module's outline-pack scratch
	// (one uint64 word per scalar, two per v128), in the order given
	// here. The emitter loads them into the params' frame slots in a
	// prologue, and parameter reads resolve to those slots instead of
	// FP offsets. The sig passed to EmitFunc* must then be
	// results-only.
	PackedParams []ssa.Type
	// ForbidCalls makes emission fail for any function that would
	// CALL another symbol (helpers, direct/indirect/import callees,
	// memory ops, global wrappers). Hosts that embed asmgen bodies
	// into a bundle whose callee symbols asmgen cannot resolve (e.g.
	// the gcasm bundle's per-chunk wrapper scheme) set this so such
	// functions fall back to the host's own backend instead of
	// emitting asm that fails to link.
	ForbidCalls bool
}

// arch abstracts the per-architecture pieces of asm emission so the
// block-iteration, phi-edge-copy, and frame-layout logic can be
// shared across amd64 and arm64. The interface methods all write
// into the caller's strings.Builder.
//
// The branch / phi / return methods take *ssa.Value (not a pre-
// resolved operand string) so each arch can resolve operands
// against its own SP-pseudo-register convention — amd64 plan9
// uses `(SP)` for stack-slot reads, arm64 uses `(RSP)` — and inline
// OpConst* / OpParam / OpCopy producers that don't have a slot.
type arch interface {
	// EmitValue lowers one SSA value to per-arch asm.
	EmitValue(b *strings.Builder, v *ssa.Value, plan *funcPlan, frame argFrame) error
	// EmitJmp emits an unconditional branch to the named label. When
	// `fallthroughLabel` matches `label`, the branch is a no-op (the
	// next block emitted is the target) so nothing is emitted. An
	// empty `fallthroughLabel` disables the optimisation.
	EmitJmp(b *strings.Builder, label, fallthroughLabel string)
	// EmitIfBranch tests cond for non-zero, branches to thenLabel
	// when set, else jumps to elseLabel. When `fallthroughLabel`
	// names one of the two destinations the implementation may skip
	// the JMP to that side (using JCC inversion when the
	// fall-through is the then side) so that control "falls through"
	// to the matching block. An empty `fallthroughLabel` disables
	// the optimisation; arches that ignore the hint produce the
	// classic `JCC thenLabel; JMP elseLabel` pair.
	EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel, fallthroughLabel string, plan *funcPlan, frame argFrame)
	// EmitReturn moves the function's K return values into their
	// FP-relative result locations, then RET.
	EmitReturn(b *strings.Builder, blk *ssa.Block, sig wasm.FuncType, plan *funcPlan, frame argFrame) error
	// EmitUnreachable emits a deliberate trap (UD2 / UNDEF).
	EmitUnreachable(b *strings.Builder)
	// EmitPackedPrologue loads a packed boundary's parameter values
	// from the Module's outline-pack scratch into their frame slots.
	EmitPackedPrologue(b *strings.Builder, f *ssa.Func, plan *funcPlan) error
	// EmitBrTable emits a BlockBrTable dispatch: materialize the i32
	// selector once, compare it against each case list's values
	// branching to that successor's label, and fall to defaultLabel.
	// Correct for any table; emitted as a linear compare chain (the
	// hot asmgen targets carry no br_table, so simplicity wins).
	EmitBrTable(b *strings.Builder, sel *ssa.Value, cases [][]int32, labels []string, defaultLabel string, plan *funcPlan, frame argFrame)
	// EmitPhiCopyValue copies an SSA value into a phi destination
	// slot. Used on each predecessor's outgoing edge.
	EmitPhiCopyValue(b *strings.Builder, src *ssa.Value, dstOff int, t ssa.Type, plan *funcPlan, frame argFrame) error
	// EmitPhiCopySlot copies a staging slot into the real phi slot
	// during the second phase of a staged parallel copy.
	EmitPhiCopySlot(b *strings.Builder, srcOff, dstOff int, t ssa.Type) error
	// EmitPhiCopyValueToReg copies an SSA value into a register that
	// the loop-carry coalesce pass reserved. Called instead of
	// EmitPhiCopyValue on the forward (entry) edge of a coalesced
	// loop, so the loop body sees the right initial value in the
	// reserved register. arm64 returns an error — the coalesce pass
	// only fires behind SupportsRegHome().
	EmitPhiCopyValueToReg(b *strings.Builder, src *ssa.Value, dstReg string, t ssa.Type, plan *funcPlan, frame argFrame) error
	// SkipValue reports whether the arch's operandSrc helpers handle
	// v inline at every consumer, so the materialise instruction in
	// EmitValue would write a slot nobody reads. amd64 returns true
	// for OpConst32/64 (every ALU instruction accepts a 32-bit imm);
	// arm64 returns false (no compact form to spell a 32-bit
	// immediate operand, so the slot must hold the constant).
	SkipValue(v *ssa.Value) bool
	// SupportsRegHome reports whether the arch's operandSrc helpers
	// and per-op emit functions honour the block-local regalloc's
	// plan.regHome. amd64 opted in; arm64 has not yet, so its
	// operandSrcFloat would emit
	// amd64-only X<n> register names that arm64's assembler rejects.
	SupportsRegHome() bool
	// RegHomeEligibleOp narrows the regalloc eligibility list per
	// arch. The default for amd64 is "every op whose producer can
	// write directly to a register" — that's the existing
	// regHomeEligibleOp set. arm64 starts narrower because only
	// some of its per-op emits honour plan.regHome on the write
	// side; the rest still need a slot. Returning false here makes
	// the regalloc skip the value so its slot store survives.
	RegHomeEligibleOp(op ssa.Op) bool
	// GPRegPool returns the GP register pool the block-local regalloc
	// hands out to int / pointer SSA values. The order matters only
	// for determinism — first-fit during linear scan. Each entry
	// must NOT collide with any scratch register the arch's per-op
	// emits use, with MCacheReg() (the function-wide m-pointer
	// cache), or with anything Go's runtime reserves (g, FP, LR).
	// Returning nil disables block-local regalloc for the arch.
	GPRegPool() []string
	// SSERegPool is the float-register counterpart of GPRegPool.
	// Returning nil disables float-side block-local regalloc for the arch.
	SSERegPool() []string
	// EmitMCachePrime stages the function-wide `m` pointer into the
	// arch's mCacheReg. Called from the prologue and again after every
	// real CALL (Go's ABI0 treats every register as caller-save, so
	// the cache is invalidated at every call boundary). Receives the
	// already-arch-resolved register name — the asmgen layer knows
	// which register the arch uses for the cache.
	//
	// archAMD64 emits `MOVQ m+0(FP), <reg>`; archARM64 emits the
	// arm64 `MOVD m+0(FP), <reg>` equivalent.
	EmitMCachePrime(b *strings.Builder, reg string)
	// MCacheReg returns the name of the GP register that stages the
	// function-wide `m` pointer. Returns "" when the arch has not
	// yet enabled the optimisation. amd64 returns "R11";
	// arm64 returns "R4" (caller-save, refreshed after every CALL,
	// not clobbered by any per-op scratch — emitBin uses R0/R1,
	// emitLoad/Store uses R0/R2/R3, callee-save start at R19).
	MCacheReg() string
	// CallArgBias is the SP-relative offset where the OUTGOING call
	// argument area begins in the CALLER's frame. On amd64 the caller
	// stores arg `i` at SP+paramOffsets[i]; on arm64 the first 8 bytes
	// at SP+0 are reserved for the callee's saved-LR slot, so the
	// caller must store arg `i` at SP+8+paramOffsets[i] and read the
	// result at SP+8+resultOffsets[i]. The Go arm64 assembler bakes
	// the same +8 into its FP-relative offset resolution (`m+0(FP)`
	// for a frame=$F function resolves to SP+autosize+8), so caller
	// and callee agree on the address only when both sides include
	// the +8.
	//
	// Returns 0 on amd64, 8 on arm64. The asmgen frame planner adds
	// the bias to maxCallee so the local-slot region starts above
	// the bias-shifted call-arg region.
	CallArgBias() int
}

// EmitFuncAMD64 produces the amd64 plan9 asm body and the matching
// Go-side declaration for one SSA function.
//
// name is the bare identifier used both in the Go decl and as the
// asm symbol. sig is the wasm function signature. f is the lowered
// SSA function. opts carries the host-dependent knobs (Module
// reference type, helper prefix, sibling-function name lookup).
func EmitFuncAMD64(name string, sig wasm.FuncType, f *ssa.Func, opts FuncOptions) (asm, goDecl string, err error) {
	return emitFunc(name, sig, f, opts, archAMD64{})
}

// EmitFuncARM64 is the arm64 counterpart of EmitFuncAMD64. It
// produces plan9 arm64 asm and a matching Go decl for the same SSA
// function. The two emitters share the block-iteration scaffolding
// (frame plan, phi staging, control-flow walk); only the per-op
// lowering differs by arch.
func EmitFuncARM64(name string, sig wasm.FuncType, f *ssa.Func, opts FuncOptions) (asm, goDecl string, err error) {
	return emitFunc(name, sig, f, opts, archARM64{})
}

// parseTrailingInt returns the trailing decimal integer in s, if any —
// "Fn42" → (42, true), "Fn" → (0, false), "abc" → (0, false). Used by
// the BISECT_LO/HI env-var path to map function names back to their
// wasm function index.
func parseTrailingInt(s string) (int, bool) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s[i:])
	if err != nil {
		return 0, false
	}
	return n, true
}

func emitFunc(name string, sig wasm.FuncType, f *ssa.Func, opts FuncOptions, a arch) (asm, goDecl string, err error) {
	frame, err := computeArgFrame(sig)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", name, err)
	}

	// constsNeedSlot: archs whose per-op emit re-reads OpConst operands
	// from the slot need Const uses tracked. Probe with a synthetic
	// OpConst32 value — every arch's SkipValue returns the same answer
	// for OpConst32 regardless of which specific value is passed.
	var probe ssa.Value
	probe.Op = ssa.OpConst32
	constsNeedSlot := !a.SkipValue(&probe)
	plan, err := planFunc(f, opts, sig, a.CallArgBias(), constsNeedSlot)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", name, err)
	}
	if opts.ForbidCalls && plan.hasNonSimdCall {
		return "", "", fmt.Errorf("%s: function calls out (%s) and ForbidCalls is set", name, strings.Join(plan.callDescs, "; "))
	}
	plan.gpRegPool = a.GPRegPool()
	plan.sseRegPool = a.SSERegPool()
	plan.regHomeEligibleOpFn = a.RegHomeEligibleOp

	// m-pointer caching: stage `m` into a function-wide register
	// so every memop / global access / call-site arg-staging that
	// would have done `MOV m+0(FP), Rtmp` reads from the cache
	// register directly. Both archs implement this now — the
	// MOV mnemonic, register name, and per-op read shape are all
	// arch-specific (amd64 stages into R11 via MOVQ, arm64 stages
	// into R4 via MOVD).
	plan.splicer = opts.Splicer
	plan.spliceMode = opts.Splicer != nil && plan.hasSimdCall
	if plan.spliceMode {
		// Splice bodies clobber the default m-cache register and the
		// block-local pools freely (they were written for gc call
		// sites, where everything is dead), so the default m-cache is
		// off. With a hoisting splicer, m and the module state the
		// splices consume ride the splice-safe registers instead:
		// R24 = m (the m-cache mechanism with a safe register),
		// R23/R22 = the splicer's hoist prologue.
		plan.mCacheCandidate = false
		if _, isARM64 := a.(archARM64); isARM64 && plan.hasMem {
			// The hoist prologue reads m off R24, so the two prime
			// together; memory-less functions need neither (their
			// splices have no memory preambles).
			if hoist := opts.Splicer.HoistPrologue(); hoist != "" {
				plan.spliceHoist = hoist
				plan.mCacheReg = "R24"
			}
		}
	}
	if plan.mCacheCandidate {
		plan.mCacheReg = a.MCacheReg()
	}

	// Hand the function to the block-local regalloc only on archs
	// whose operandSrc / per-op emit code knows how to honour
	// plan.regHome. SupportsRegHome gates this — archAMD64 returns
	// true; archARM64 returns false until its emit side learns the
	// same trick.
	//
	// Frame compaction: once we know which values went to a
	// register, walk the original slot map and reclaim every slot
	// whose only owner is a regHome'd value. The remaining live
	// slots get re-packed densely starting at calleeArea, shrinking
	// plan.frameSize from "one slot per SSA value with a type" to
	// "one slot per actually-spilled value". On the hot integration
	// corpus functions this collapses a 3.7 KB frame to the
	// neighbourhood of what Pure-Go produces (~100 bytes).
	//
	// WASM2GO_REGALLOC_BISECT_LO / _HI restrict regalloc to functions
	// whose numeric suffix lies in the inclusive range [LO, HI].
	// Function names are "Fn42" / "fn42" / similar — the trailing
	// integer is the wasm function index, which is sequential and
	// stable across regeneration runs. When neither is set, regalloc
	// runs for every function. When one or both are set:
	//   - parse a trailing decimal integer from f.Name; if none, the
	//     function is excluded;
	//   - LO defaults to 0, HI defaults to math.MaxInt;
	//   - regalloc runs iff LO <= index <= HI.
	// This gives a clean log2(N) bisection over the function-index
	// space — pin a failing range, halve it, repeat.
	// Splice-mode arm64: no block-local regalloc (splices clobber
	// its pool), but loop carries CAN live in the splice-safe
	// registers — see runSpliceCoalescePass.
	if plan.spliceMode {
		if _, isARM64 := a.(archARM64); isARM64 {
			runSpliceCoalescePass(f, plan)
		}
	}
	if a.SupportsRegHome() && !plan.spliceMode {
		runRegalloc := true
		loStr, hiStr := os.Getenv("WASM2GO_REGALLOC_BISECT_LO"), os.Getenv("WASM2GO_REGALLOC_BISECT_HI")
		if loStr != "" || hiStr != "" {
			runRegalloc = false
			idx, ok := parseTrailingInt(f.Name)
			if ok {
				lo := 0
				hi := math.MaxInt
				if loStr != "" {
					if v, err := strconv.Atoi(loStr); err == nil {
						lo = v
					}
				}
				if hiStr != "" {
					if v, err := strconv.Atoi(hiStr); err == nil {
						hi = v
					}
				}
				if idx >= lo && idx <= hi {
					runRegalloc = true
				}
			}
		}
		if runRegalloc {
			// Always-on: route through the cross-block Belady
			// allocator's bridge. For functions outside the safe
			// shape (isSafeForNewRegalloc returns false) the bridge
			// falls back to computeRegHomes internally, so the call
			// is correct for every function — the safety gate lives
			// in applyNewRegalloc, not here.
			//
			// The cross-block allocator's stackalloc subsumes
			// compactFrame: applyNewRegalloc runs the
			// interference-aware slot allocator inline and rewrites
			// plan.offsets / plan.frameSize itself. Running
			// compactFrame after would re-shuffle the offsets via
			// its own (simpler) re-packing, which can mis-handle
			// shared slots — compactFrame dedupes by offset without
			// an interference test, so it would treat each
			// shared-slot occupant as a fresh pool entry and grow
			// the frame again. The bridge skips compactFrame when
			// its stackalloc fired; for functions where it didn't
			// (no shrinkage opportunity), compactFrame still runs.
			didStackalloc := applyNewRegalloc(f, plan, a)
			if !didStackalloc {
				compactFrame(f, plan)
			}
		}
	}

	var b strings.Builder
	// Per-function header comment dropped — the corresponding Go
	// decl in decls_<arch>.go documents the signature and the asm
	// reader can find it from the TEXT line. Across ~40k generated
	// functions × 2 archs this comment alone added ~6MB to the
	// bundle for no semantic value.
	flag := "NOSPLIT"
	if plan.hasCall {
		// Functions that CALL a non-NOSPLIT Go helper can't be
		// NOSPLIT themselves — the runtime's stack-growth check has
		// to run on the way in.
		flag = "0"
	} else if plan.frameSize > 700 {
		// NOSPLIT frames are capped at ~792 bytes (the runtime's
		// stack-overflow trip-wire). Any function whose own frame
		// alone is close to that limit must keep the prologue's
		// growth check so the runtime can extend the stack when
		// needed. A 700-byte cutoff leaves a safety margin for the
		// caller's frame.
		flag = "0"
	}
	fmt.Fprintf(&b, "TEXT ·%s(SB), %s, $%d-%d\n", name, flag, plan.frameSize, frame.argSize)
	// NO_LOCAL_POINTERS is the runtime's "this frame's locals hold
	// no pointers" marker, required for non-NOSPLIT functions so
	// the stack scanner can walk them across a CALL. NOSPLIT
	// functions never trigger stack copy and don't need the
	// marker — emitting it there is just dead bytes.
	if flag != "NOSPLIT" {
		fmt.Fprintf(&b, "\tNO_LOCAL_POINTERS\n")
	}
	// Prime the m-cache register. Subsequent emits that
	// would have read `m+0(FP)` instead read mCacheReg directly,
	// saving one memory load per memop / global access / direct-
	// call arg-staging site. Every CALL invalidates the cache
	// (Go ABI0 = all caller-save) so the emitBlock loop reissues
	// this same MOV after each opEmitsCall site.
	if plan.mCacheReg != "" {
		a.EmitMCachePrime(&b, plan.mCacheReg)
	}
	if plan.spliceHoist != "" {
		b.WriteString(plan.spliceHoist)
	}

	// Packed boundary: load the parameter values from the Module's
	// outline-pack scratch into their frame slots before any block
	// runs.
	if plan.packed {
		if len(sig.Params) != 0 {
			return "", "", fmt.Errorf("%s: packed emission requires a results-only signature", name)
		}
		if err := a.EmitPackedPrologue(&b, f, plan); err != nil {
			return "", "", fmt.Errorf("%s: packed prologue: %w", name, err)
		}
	}

	// Per-block fall-through label. `f.Blocks[i+1]`'s label
	// is the natural next destination after `f.Blocks[i]` finishes —
	// emitBlock hands this to the arch's EmitJmp / EmitIfBranch so a
	// terminal JMP / JCC-pair that names the fall-through label can
	// drop the jump. For the last block there is no fall-through, so
	// the hint stays empty and the arch emits the classic shape.
	for i, blk := range f.Blocks {
		fallthroughLabel := ""
		if i+1 < len(f.Blocks) {
			fallthroughLabel = labelFor(f.Blocks[i+1])
		}
		if err := emitBlock(&b, blk, f, plan, sig, frame, a, fallthroughLabel); err != nil {
			return "", "", fmt.Errorf("%s: block %d: %w", name, blk.ID, err)
		}
	}

	// Shared out-of-bounds stub for spliced SIMD memory ops: their
	// bodies branch to the splicer's trap label; the stub is appended
	// once after the last block (control never returns from it).
	if plan.wantsTrapStub && opts.Splicer != nil {
		b.WriteString(opts.Splicer.TrapStub())
	}

	goDecl = fmt.Sprintf("//go:noescape\nfunc %s%s\n", name, goSignature(sig, opts.ModulePkgRef))
	// Pipeline order:
	//   dedupMemMReload     — collapses adjacent `m+0(FP)→reg; reg.M→reg`
	//                         pairs that the per-op emitter naively re-
	//                         emits at every memop and global access.
	//   peepholeOpt         — line-local reductions (skip-reload, LEAQ
	//                         fold, imm-store fold, fallthrough-JMP
	//                         drop, adjacent slot forward).
	//   regTrackPass        — non-adjacent register tracking. Walks the
	//                         post-peephole asm with a per-register
	//                         model of which slot's value is currently
	//                         cached, and rewrites later slot reads to
	//                         take their source from the still-live
	//                         register instead of round-tripping to
	//                         memory. Safe to run last because it never
	//                         introduces patterns that the earlier
	//                         passes would have matched.
	// Pipeline:
	//   dedupMemMReload  — collapse the `m+0(FP) -> R11 -> m.M`
	//                      pair into a single load when m is the
	//                      same across uses.
	//   peepholeOpt      — line-local reductions (skip-reload,
	//                      LEAQ fold, imm-store fold, fallthrough-
	//                      JMP drop, adjacent slot forward,
	//                      adjacent dead-store).
	//   regTrackPass     — multi-line register-mirror tracking,
	//                      including the D-2 slot-immediate
	//                      forwarding that lets a later
	//                      `MOV{L,Q} slot, reg` be rewritten to
	//                      `MOV{L,Q} $imm, reg` when the slot
	//                      was last written by an immediate of
	//                      matching width.
	//   peepholeOpt      — run again: regTrackPass's $imm-load
	//                      rewrites unlock a fresh round of
	//                      peepholeImmStore folds (the
	//                      `MOV $imm, reg; MOV reg, slot(SP)`
	//                      pair collapses to a single
	//                      `MOV $imm, slot(SP)` and the imm-
	//                      loaded register is no longer needed).
	//   eliminateDeadStoresMultiLine — drop SP-slot writes that
	//                      the next same-width write to the
	//                      same slot silently overwrites, with no
	//                      intervening read. D-1.
	emitted := dedupMemMReload(b.String())
	emitted = peepholeOpt(emitted)
	emitted = regTrackPass(emitted)
	emitted = peepholeOpt(emitted)
	emitted = eliminateDeadStoresMultiLine(emitted)
	return emitted, goDecl, nil
}

// eliminateDeadStoresMultiLine drops stores to stack slots that are
// silently overwritten by a later store to the SAME slot within the
// same basic block, with no intervening read of that slot.
//
// Extends peepholeDeadStore (which only catches adjacent same-slot
// stores) to the case where some non-conflicting work — typically an
// AX-staging load for the next arg of a phi-edge copy, or an unrelated
// stash through a different slot — sits between the two writes. The
// SSA phi-edge lowering routinely produces this shape when two phi
// destinations end up in the same slot via cross-block stackalloc but
// the per-edge `MOVL src, AX; MOVL AX, dst` copies are issued back-
// to-back: the load for the second copy clobbers AX between the two
// store lines, so the older peephole's strict-adjacency match misses
// the dead store.
//
// Scope: one basic block. A label, JMP, conditional branch, CALL or
// RET flushes the pending-write map — anything that ends a basic
// block destroys the linear assumption. Inside a block, an SP-slot
// read (slot used as a source operand of any instruction) clears the
// pending entry for that slot; non-SP operands are ignored, since
// stack slots cannot alias them.
//
// Conservative: a multi-write store (e.g. MOVQ <hi>:<lo>, slot, which
// the emitter does not produce) would defeat this; the per-line
// parser would simply not recognise it and fall through to the "read
// of all referenced SP slots" branch, leaving pending state intact in
// the best case.
func eliminateDeadStoresMultiLine(asm string) string {
	lines := strings.Split(asm, "\n")
	pending := map[string]int{}         // slot -> line index of pending dead-candidate write
	pendingInstr := map[string]string{} // slot -> MOVL / MOVQ / MOVSS / MOVSD that wrote it
	dead := map[int]bool{}

	flush := func() {
		for k := range pending {
			delete(pending, k)
			delete(pendingInstr, k)
		}
	}

	for i, line := range lines {
		trim := strings.TrimLeft(line, " \t")
		// Block boundaries — anything that can be jumped to or that
		// ends linear control flow flushes the tracking.
		if isLabelLine(trim) {
			flush()
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "TEXT ") ||
			strings.HasPrefix(trim, "#") || trim == "NO_LOCAL_POINTERS" {
			continue
		}
		if strings.HasPrefix(trim, "JMP ") || strings.HasPrefix(trim, "CALL ") || trim == "RET" {
			flush()
			continue
		}
		if isControlFlowBranch(trim) {
			flush()
			continue
		}

		// Recognise SP-slot writes: MOV{L,Q,SS,SD} <src>, <slot>(SP).
		instr, src, dst, ok := parseMOV(line)
		if ok && isMemSPOperand(dst) {
			switch instr {
			case "MOVL", "MOVQ", "MOVSS", "MOVSD":
				// src side may reference an SP slot — clear its
				// pending entry first (a read invalidates the
				// dead-candidate).
				if isMemSPOperand(src) {
					delete(pending, src)
					delete(pendingInstr, src)
				}
				// If we already had a pending write to dst of the
				// same width, that previous store is dead — nothing
				// between then and now read it.
				if prevIdx, has := pending[dst]; has && pendingInstr[dst] == instr {
					dead[prevIdx] = true
				}
				pending[dst] = i
				pendingInstr[dst] = instr
				continue
			}
		}

		// Anything else: every SP-slot reference in this line counts
		// as a read of that slot.
		for _, s := range extractSPSlots(line) {
			delete(pending, s)
			delete(pendingInstr, s)
		}
	}

	if len(dead) == 0 {
		return asm
	}
	var b strings.Builder
	b.Grow(len(asm))
	first := true
	for i, line := range lines {
		if dead[i] {
			continue
		}
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(line)
	}
	return b.String()
}

// isLabelLine reports whether the (left-trimmed) line is a label of
// the `L<n>:` shape that the per-block emit writes.
func isLabelLine(trim string) bool {
	if !strings.HasSuffix(trim, ":") {
		return false
	}
	if len(trim) < 3 || trim[0] != 'L' {
		return false
	}
	for i := 1; i < len(trim)-1; i++ {
		if trim[i] < '0' || trim[i] > '9' {
			return false
		}
	}
	return true
}

// isControlFlowBranch reports whether trim is a conditional jump
// (amd64: J<cc>) or the arm64 equivalent (B<cc>, BL, CBZ/CBNZ). These
// terminate the current straight-line region for the purpose of the
// dead-store tracker.
func isControlFlowBranch(trim string) bool {
	if len(trim) < 2 {
		return false
	}
	switch trim[0] {
	case 'J':
		// J<letter>... family (JE, JNE, JLE, JGE, JA, JB, ...).
		return trim[1] >= 'A' && trim[1] <= 'Z'
	case 'B':
		// arm64 B<cc> and CBZ/CBNZ — see isBranchInstr above for the
		// full mnemonic list; here we treat any leading-B mnemonic as
		// a branch.
		return trim[1] >= 'A' && trim[1] <= 'Z'
	}
	return false
}

// extractSPSlots scans line for every `<digits>(SP)` operand and
// returns the literal slot string ("<digits>(SP)") for each match.
// Used by the dead-store tracker as a coarse "this line reads N
// stack slots" probe — every match is treated as a potential read of
// that slot, so the tracker stays correct even for instructions the
// MOV parser does not recognise (ADD / SUB / CMP / SHL / TEST / ...).
func extractSPSlots(line string) []string {
	var result []string
	i := 0
	for i < len(line) {
		if line[i] >= '0' && line[i] <= '9' {
			j := i
			for j < len(line) && line[j] >= '0' && line[j] <= '9' {
				j++
			}
			if j+4 <= len(line) && line[j:j+4] == "(SP)" {
				result = append(result, line[i:j+4])
				i = j + 4
				continue
			}
			i = j
			continue
		}
		i++
	}
	return result
}

// dedupMemMReload drops redundant `MOVQ m+0(FP), BX; MOVQ 32(BX), BX`
// (amd64) and `MOVD m+0(FP), R0; MOVD 32(R0), R0` (arm64) pairs when
// the target register still holds m.M from a previous load. The
// per-value emitter has no shared state, so every load / store
// emits its own preamble — but between two const-base loads or
// stores in the same straight-line span the second preamble is
// dead code (the first preamble's BX / R0 is still live, the
// `MOVx imm, disp(BX)` store form does not write BX, and no
// other generated instruction between them touches BX as a
// destination).
//
// Reset conditions for the "register holds m.M" bit:
//
//   - Label declaration (control-flow merge — predecessors may
//     not have visited the preamble, so the register's value at
//     the label is undefined).
//   - CALL (clobbers all caller-save registers including BX / R0).
//   - JMP / Jcc / B<cond> (control flow leaves; the next block
//     enters via a label that will reset on its own, but resetting
//     on the branch keeps the analysis straight even if a later
//     pass interleaves fall-through code).
//   - Any instruction whose destination operand is exactly the
//     target register (bare BX / R0 — `MOVQ src, BX`, `LEAQ ..., BX`,
//     `ADDQ src, BX`, `MOVD src, R0`, etc.). CMP / TEST do not
//     write either operand and are excluded.
//
// The pass is a separate post-step from peepholeOpt because it
// needs multi-line state — peepholeOpt only looks at adjacent
// pairs. Output passes through peepholeOpt afterward so any
// store/reload pairs created in the dedup wake stay covered.
func dedupMemMReload(asm string) string {
	if asm == "" {
		return asm
	}
	lines := strings.Split(asm, "\n")
	out := make([]string, 0, len(lines))
	bxValid := false
	r0Valid := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// amd64 m.M load pair?
		if i+1 < len(lines) &&
			strings.TrimRight(line, " \t") == "\tMOVQ m+0(FP), BX" &&
			strings.TrimRight(lines[i+1], " \t") == "\tMOVQ 32(BX), BX" {
			if bxValid {
				i++ // skip both
				continue
			}
			out = append(out, line, lines[i+1])
			i++
			bxValid = true
			continue
		}
		// amd64 m.M load via the R11 m-cache?
		// Pattern: `MOVQ 32(R11), BX` (single line). R11 holds the m
		// pointer for the whole function (m-pointer caching), and
		// `+32` is the m.M field offset. Dedup the same way as the
		// two-line `m+0(FP) -> BX -> 32(BX)` pair above: if BX is
		// already known to hold m.M from a previous load and nothing
		// between the loads has clobbered BX or moved control, the
		// reload is dead.
		if strings.TrimRight(line, " \t") == "\tMOVQ 32(R11), BX" {
			if bxValid {
				continue
			}
			out = append(out, line)
			bxValid = true
			continue
		}
		// arm64 m.M load pair?
		if i+1 < len(lines) &&
			strings.TrimRight(line, " \t") == "\tMOVD m+0(FP), R0" &&
			strings.TrimRight(lines[i+1], " \t") == "\tMOVD 32(R0), R0" {
			if r0Valid {
				i++
				continue
			}
			out = append(out, line, lines[i+1])
			i++
			r0Valid = true
			continue
		}
		// arm64 m.M load via the R26 m-cache?
		// Pattern: `MOVD 32(R26), R0`. Same logic as amd64's
		// `MOVQ 32(R11), BX`. The arm64 m-cache reservation places m
		// in R26.
		if strings.TrimRight(line, " \t") == "\tMOVD 32(R26), R0" {
			if r0Valid {
				continue
			}
			out = append(out, line)
			r0Valid = true
			continue
		}
		// State transitions for the current line.
		switch {
		case isAsmLabel(line):
			bxValid = false
			r0Valid = false
		case isAsmCall(line):
			bxValid = false
			r0Valid = false
		case isAsmUnconditionalOrCondBranch(line):
			bxValid = false
			r0Valid = false
		default:
			if writesRegister(line, "BX") {
				bxValid = false
			}
			if writesRegister(line, "R0") {
				r0Valid = false
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// isAsmLabel reports whether line is a plan9-asm label declaration
// (e.g. `L42:`). The generated bodies never use indented labels.
func isAsmLabel(line string) bool {
	if line == "" || line[0] == '\t' || line[0] == ' ' {
		return false
	}
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return false
	}
	for i := 0; i < colon; i++ {
		c := line[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') &&
			(c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// isAsmCall reports whether line is a `CALL ...` instruction.
func isAsmCall(line string) bool {
	s := strings.TrimLeft(line, " \t")
	return strings.HasPrefix(s, "CALL ")
}

// isAsmUnconditionalOrCondBranch reports whether line is a
// control-flow transfer (JMP / Jcc on amd64, JMP / B<cond> on arm64,
// CB[N]Z[W] on arm64). RET is not handled here — it never has a
// successor in the same function body to confuse the state.
func isAsmUnconditionalOrCondBranch(line string) bool {
	s := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(s, "JMP ") || strings.HasPrefix(s, "JMP\t") {
		return true
	}
	// amd64 conditional jumps: JE, JNE, JLT, JLE, JGT, JGE, JCS, JCC,
	// JLS, JHI, JS, JP, JNP, etc. All start with "J" and are followed
	// by a short condition code then whitespace.
	if len(s) > 1 && s[0] == 'J' && (s[1] >= 'A' && s[1] <= 'Z') {
		// Skip JMP (already handled). Anything else starting "J<X>..."
		// where the rest looks like a JCC mnemonic is a conditional
		// branch.
		sp := strings.IndexAny(s, " \t")
		if sp > 0 && sp <= 5 {
			return true
		}
	}
	// arm64 conditional branches: BEQ, BNE, BLT, BLE, BLO, BLS, etc.
	// Also CBZ, CBNZ, CBZW, CBNZW.
	if strings.HasPrefix(s, "B") && len(s) > 2 {
		sp := strings.IndexAny(s, " \t")
		// Avoid matching unrelated opcodes that start with B
		// (BSF/BSR on amd64). amd64's BSF/BSR have a destination
		// operand; we want to clobber tracking for the operand
		// elsewhere — so we still return false here and let
		// writesRegister catch the BX-destination case. The arm64
		// B<cond> instructions never have BX/R0 as the operand
		// (they branch to labels), so the only confusion is the
		// false-negative on JMP-style — which is fine because
		// writesRegister handles BSF/BSR's clobber.
		if sp > 0 && sp <= 5 {
			switch s[:sp] {
			case "BEQ", "BNE", "BLT", "BLE", "BGT", "BGE",
				"BLO", "BLS", "BHI", "BHS", "BCC", "BCS",
				"BMI", "BPL", "BVC", "BVS",
				"BL", "B":
				return true
			}
			if strings.HasPrefix(s[:sp], "CBZ") || strings.HasPrefix(s[:sp], "CBNZ") {
				return true
			}
		}
	}
	return false
}

// writesRegister reports whether line writes the named register as
// its destination operand. Bare-register destination is detected;
// memory operands of the form `<disp>(REG)` reference but do not
// write REG (so e.g. `MOVQ 32(BX), AX` does not clobber BX). Comparison
// and test instructions (CMP / TEST family) read both operands and
// are explicitly excluded.
func writesRegister(line, reg string) bool {
	s := strings.TrimLeft(line, " \t")
	sp := strings.IndexAny(s, " \t")
	if sp < 0 {
		return false
	}
	op := s[:sp]
	switch op {
	case "CMPB", "CMPW", "CMPL", "CMPQ",
		"TESTB", "TESTW", "TESTL", "TESTQ",
		"CMP", "CMN", "CMNW",
		"TST", "TSTW":
		return false
	}
	// arm64 single-source compare-and-branch: CBZ / CBNZ / CBZW /
	// CBNZW — read R0 but don't write.
	if strings.HasPrefix(op, "CBZ") || strings.HasPrefix(op, "CBNZ") {
		return false
	}
	// Strip trailing comment.
	rest := s[sp:]
	if i := strings.Index(rest, "//"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimRight(rest, " \t")
	if rest == "" {
		return false
	}
	// Last operand is the dst for the two-operand forms emit_*.go
	// produces (MOVQ src, dst), and for single-operand RMW forms
	// (NEG / NOT / INC / DEC / POP) the single operand is dst. The
	// reads-only single-operand forms (PUSH / DIV / IDIV / MUL /
	// IMUL / SETxx / JMP / Jcc / JCC etc.) we either don't emit at
	// all or are caught by the CMP/TEST/CB[N]Z list above.
	parts := strings.Split(rest, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	return last == reg
}

// peepholeOpt runs a tiny set of arch-agnostic line-level reductions
// over an emitted asm body. It is line-local — never reorders, never
// looks past a label, a CALL, or any instruction other than the one
// it is matching — so it can't change observable behaviour. The
// reductions remove patterns the emitter produces by construction
// (every SSA value emits a `MOV reg, slot(SP)` store followed at the
// next consumer by a `MOV slot(SP), reg` reload, even when the value
// is still live in the register); removing them shrinks the bundle's
// machine code without changing semantics.
//
// Patterns reduced:
//
//  1. Adjacent self-cancelling store/reload pairs, e.g.
//     MOVL AX, 92(SP)
//     MOVL 92(SP), AX            ← redundant; value is in AX already
//     Variants: MOVQ, MOVL with any GP register, MOVSS / MOVSD with
//     SSE registers. The store stays; the reload is dropped.
//
//  2. amd64 `MOVL $imm, AX; ADDQ AX, BX` collapses to
//     LEAQ imm(BX), BX
//     when imm is a non-negative literal. Negative literals would
//     differ in the upper 32 bits (the MOVL form zero-extends imm to
//     RAX; LEAQ sign-extends the displacement) so we leave those
//     alone.
func peepholeOpt(asm string) string {
	if asm == "" {
		return asm
	}
	lines := strings.Split(asm, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if n := len(out); n > 0 {
			prev := out[n-1]
			if peepholeSkipReload(prev, line) {
				// Drop `line` — value still live in the register.
				continue
			}
			if rewritten, ok := peepholeSlotForward(prev, line); ok {
				// Replace the slot reload with a register-to-register
				// move so the next consumer reads from the producing
				// register directly instead of round-tripping through
				// memory.
				out = append(out, rewritten)
				continue
			}
			if combined, ok := peepholeLEAQ(prev, line); ok {
				out[n-1] = combined
				continue
			}
			if combined, ok := peepholeLEALReg(prev, line); ok {
				out[n-1] = combined
				continue
			}
			if combined, ok := peepholeImmStore(prev, line); ok {
				out[n-1] = combined
				continue
			}
			if peepholeDeadStore(prev, line) {
				// Replace `prev` (the dead store) with the new
				// store on `line`. Nothing between the two
				// reads the slot, so prev's contribution is
				// invisible.
				out[n-1] = line
				continue
			}
			if peepholeFallthroughJmp(prev, line) {
				// Drop the unconditional jump in `prev`; the label
				// on `line` is its target and immediately follows.
				out[n-1] = line
				continue
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// peepholeSkipReload reports whether `cur` is a load that exactly
// undoes the store in `prev`. Matches:
//
//	prev: \tMOV{L,Q} <REG>, <off>(SP)
//	cur:  \tMOV{L,Q} <off>(SP), <REG>
//
// and the SSE float pair (MOVSS / MOVSD with X<n>). The store side
// is left in place — only the reload is dropped — so the value is
// still observable in memory for any non-adjacent consumer that may
// follow later in the same function. Anything between the two lines
// (a label declaration, another instruction, a CALL) breaks the
// adjacency and the peephole declines to fire.
func peepholeSkipReload(prev, cur string) bool {
	pInstr, pSrc, pDst, ok := parseMOV(prev)
	if !ok {
		return false
	}
	cInstr, cSrc, cDst, ok := parseMOV(cur)
	if !ok || pInstr != cInstr {
		return false
	}
	// Store form: src is a register, dst is a memory operand.
	// Reload form: src is the same memory operand, dst is the same register.
	return isRegOperand(pSrc) && isMemSPOperand(pDst) && pSrc == cDst && pDst == cSrc
}

// peepholeSlotForward rewrites a `MOV<W> <REG1>, <slot>(SP); MOV<W>
// <slot>(SP), <REG2>` pair where REG1 != REG2 into the same store
// followed by a register-to-register move:
//
//	MOV<W> REG1, slot(SP)
//	MOV<W> REG1, REG2     ← rewritten reload, reads from REG1 not memory
//
// The store is kept intact because the slot's value may still be
// read non-adjacently later in the function (linear-scan slot reuse
// only retires a slot at its last consumer, so a later block can
// still read it). Removing only the memory round-trip on the
// adjacent reload is observable as a reg-to-reg move with no
// semantic change.
//
// Same-register case (REG1 == REG2) is left to peepholeSkipReload
// which drops the redundant reload entirely.
func peepholeSlotForward(prev, cur string) (string, bool) {
	pInstr, pSrc, pDst, ok := parseMOV(prev)
	if !ok {
		return "", false
	}
	cInstr, cSrc, cDst, ok := parseMOV(cur)
	if !ok || pInstr != cInstr {
		return "", false
	}
	// prev must be a register store; cur must be a load from the
	// same slot into a different register of the same family.
	if !isRegOperand(pSrc) || !isMemSPOperand(pDst) {
		return "", false
	}
	if !isRegOperand(cDst) || !isMemSPOperand(cSrc) {
		return "", false
	}
	if pDst != cSrc {
		return "", false
	}
	if pSrc == cDst {
		// Identical-register reload — peepholeSkipReload will drop
		// `cur` entirely; emitting a reg-to-reg copy from REG1 to
		// REG1 would be a useless instruction.
		return "", false
	}
	// SSE vs general-purpose register families must not mix; the
	// MOVL / MOVQ widths only apply to GP regs, MOVSS / MOVSD to
	// SSE. parseMOV's instr already pins the family so this is
	// just a safety belt for any future width additions.
	if isSSEReg(pSrc) != isSSEReg(cDst) {
		return "", false
	}
	return fmt.Sprintf("\t%s %s, %s", pInstr, pSrc, cDst), true
}

// isSSEReg reports whether s is a plan9 SSE register name.
func isSSEReg(s string) bool {
	switch s {
	case "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7":
		return true
	}
	return false
}

// peepholeImmStore folds a `MOV{L,Q} $<imm>, AX; MOV{L,Q} AX, <slot>(SP)`
// sequence into a single `MOV{L,Q} $<imm>, <slot>(SP)` instruction.
// Plan 9 amd64 supports MOV imm → memory directly for the L width
// for any 32-bit immediate, and for the Q width only when the
// immediate fits the sign-extended-int32 range (−2^31 .. 2^31−1) —
// outside that range the assembler rejects the direct form with
// "invalid instruction" and the value has to be staged through a
// register first. The peephole gates the Q form accordingly so we
// never produce something the assembler rejects.
//
// On amd64 this halves the cost of the "store a const to a slot"
// idiom that the SSA emitter produces in bulk — every zero-init of
// an unused-but-allocated SSA slot, every constant assignment in
// generated code, every immediate-base address computation that did
// not get folded by the LEAQ peephole. Reports the combined line and
// true if the pattern matched, otherwise returns false.
func peepholeImmStore(prev, cur string) (string, bool) {
	// prev shape: \tMOV{L,Q} $<imm>, <reg>
	// cur  shape: \tMOV{L,Q} <reg>, <off>(SP)
	pInstr, pSrc, pDst, ok := parseMOV(prev)
	if !ok || (pInstr != "MOVL" && pInstr != "MOVQ") {
		return "", false
	}
	if !strings.HasPrefix(pSrc, "$") {
		return "", false
	}
	if !isRegOperand(pDst) {
		return "", false
	}
	cInstr, cSrc, cDst, ok := parseMOV(cur)
	if !ok || cInstr != pInstr {
		return "", false
	}
	if cSrc != pDst || !isMemSPOperand(cDst) {
		return "", false
	}
	if pInstr == "MOVQ" {
		// MOVQ $imm, mem only accepts immediates in
		// sign-extended-int32 range; anything bigger must be
		// staged through a register.
		raw := strings.TrimPrefix(pSrc, "$")
		raw = strings.TrimPrefix(raw, "-") // allow leading "-"
		// Accept only pure decimal digits; reject "0x...", hex, etc.
		// The emitter only produces decimal literals here.
		if raw == "" {
			return "", false
		}
		for i := 0; i < len(raw); i++ {
			if raw[i] < '0' || raw[i] > '9' {
				return "", false
			}
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(pSrc, "$"), 10, 64)
		if err != nil {
			return "", false
		}
		if v < math.MinInt32 || v > math.MaxInt32 {
			return "", false
		}
	}
	return fmt.Sprintf("\t%s %s, %s", pInstr, pSrc, cDst), true
}

// peepholeDeadStore reports whether `prev` is a store to a stack
// slot that `cur` (an adjacent store to the SAME slot of the same
// width) immediately overwrites. The first store is dead because
// nothing between the two lines can observe its bytes — the slot
// is written, then re-written, with no read in between.
//
// Matches the shapes:
//
//	prev: \tMOV{L,Q,SS,SD} <src1>, <off>(SP)
//	cur:  \tMOV{L,Q,SS,SD} <src2>, <off>(SP)
//
// The sources may differ — only the destination slot and the
// instruction width matter for dead-store detection. The
// wasm-to-SSA layer's per-edge phi copies regularly emit
// back-to-back writes to the same slot when cross-block stackalloc
// shares the slot between multiple phis whose lifetimes don't
// overlap; the last write is the one any downstream consumer
// reads, and every earlier write to that slot in the same edge is
// silently overwritten.
func peepholeDeadStore(prev, cur string) bool {
	pInstr, _, pDst, ok := parseMOV(prev)
	if !ok {
		return false
	}
	cInstr, _, cDst, ok := parseMOV(cur)
	if !ok || pInstr != cInstr {
		return false
	}
	if !isMemSPOperand(pDst) || pDst != cDst {
		return false
	}
	switch pInstr {
	case "MOVL", "MOVQ", "MOVSS", "MOVSD":
		return true
	}
	return false
}

// peepholeFallthroughJmp reports whether `prev` is an unconditional
// jump to a label that is declared on the very next line. Both arch
// emitters use the same `\tJMP L<n>` / `\tB L<n>` shape and place the
// target label on its own line as `L<n>:`. When the two are
// adjacent, the jump is a fall-through and can be dropped: the
// branch on `prev` becomes the label line in `cur`. The label is
// kept (something else may still target it).
func peepholeFallthroughJmp(prev, cur string) bool {
	var target string
	switch {
	case strings.HasPrefix(prev, "\tJMP L"):
		target = prev[len("\tJMP "):]
	case strings.HasPrefix(prev, "\tB L"):
		target = prev[len("\tB "):]
	default:
		return false
	}
	if target == "" {
		return false
	}
	for i := 1; i < len(target); i++ {
		if target[i] < '0' || target[i] > '9' {
			return false
		}
	}
	return cur == target+":"
}

// peepholeLEAQ folds a `MOVL $<imm>, AX; ADDQ AX, BX` pair into a
// single `LEAQ <imm>(BX), BX`. Returns the combined line and true if
// the pattern matched. Only fires when the immediate is a non-
// negative decimal literal — for negatives, MOVL zero-extends through
// RAX while LEAQ would sign-extend the displacement, so the two
// forms diverge and we leave them alone.
func peepholeLEAQ(prev, cur string) (string, bool) {
	// We accept ANY GP register pair as long as MOV's dst register
	// matches ADD's src register, but in practice the emitter only
	// uses AX as the scratch so we keep the matcher narrow.
	const (
		movPrefix = "\tMOVL $"
		movSuffix = ", AX"
		addLine   = "\tADDQ AX, BX"
	)
	if !strings.HasPrefix(prev, movPrefix) || !strings.HasSuffix(prev, movSuffix) {
		return "", false
	}
	if cur != addLine {
		return "", false
	}
	imm := prev[len(movPrefix) : len(prev)-len(movSuffix)]
	if imm == "" || imm[0] == '-' {
		return "", false
	}
	// Reject anything that isn't a plain decimal literal.
	for i := 0; i < len(imm); i++ {
		if imm[i] < '0' || imm[i] > '9' {
			return "", false
		}
	}
	return fmt.Sprintf("\tLEAQ %s(BX), BX", imm), true
}

// peepholeLEALReg folds a `MOV<W> <REG_SRC>, <REG_DST>; <ADD|SUB><W>
// $<imm>, <REG_DST>` pair into a single `LEA<W> <signed_imm>(<REG_SRC>),
// <REG_DST>` instruction. The pair fires every time the emitter
// computes "value + constant" via the canonical regalloc emit path
// (MOVL src0, home; ADDL src1, home where src1 is a const), saving
// roughly half of every "base + offset" address build sequence in
// the wasm load/store path. LEA also has the side-benefit of NOT
// setting flags — the wasm semantics never read flags out of an
// integer add, so eliminating the flag write is a free latency
// improvement on modern OoO cores.
//
// Only the REG-SRC form is matched: LEAL's memory operand must use
// a register base, so a MOV from a slot or an FP-relative param
// can't be folded directly here. (A MOV-from-slot can be combined
// AFTER the regtrack pass forwards the slot read to a reg-to-reg
// move, but that interleaving is left to a future pass.)
func peepholeLEALReg(prev, cur string) (string, bool) {
	pInstr, pSrc, pDst, ok := parseMOV(prev)
	if !ok {
		return "", false
	}
	if pInstr != "MOVL" && pInstr != "MOVQ" {
		return "", false
	}
	if !isRegOperand(pSrc) || !isRegOperand(pDst) {
		return "", false
	}
	// cur shape: `\t(ADDL|SUBL|ADDQ|SUBQ) $<imm>, <reg>`
	s := strings.TrimLeft(cur, " \t")
	var op string
	var widthW int // L = 32-bit, Q = 64-bit
	switch {
	case strings.HasPrefix(s, "ADDL $"):
		op = "ADDL"
		widthW = 32
	case strings.HasPrefix(s, "SUBL $"):
		op = "SUBL"
		widthW = 32
	case strings.HasPrefix(s, "ADDQ $"):
		op = "ADDQ"
		widthW = 64
	case strings.HasPrefix(s, "SUBQ $"):
		op = "SUBQ"
		widthW = 64
	default:
		return "", false
	}
	// Match widths: a 32-bit MOV can only fold with a 32-bit add, etc.
	if (widthW == 32) != (pInstr == "MOVL") {
		return "", false
	}
	rest := s[len(op)+len(" $"):]
	comma := strings.Index(rest, ", ")
	if comma < 0 {
		return "", false
	}
	imm := rest[:comma]
	addDst := strings.TrimRight(rest[comma+2:], " \t")
	if addDst != pDst {
		return "", false
	}
	// Imm must parse as a signed decimal literal. LEA's displacement
	// is sign-extended to address width, so we keep the sign verbatim
	// and flip it for SUB.
	if imm == "" {
		return "", false
	}
	signedImm := imm
	if op == "SUBL" || op == "SUBQ" {
		if signedImm[0] == '-' {
			signedImm = signedImm[1:]
		} else {
			signedImm = "-" + signedImm
		}
	}
	// Validate the (possibly-negated) immediate is a clean decimal.
	check := signedImm
	if check[0] == '-' {
		check = check[1:]
	}
	if check == "" {
		return "", false
	}
	for i := 0; i < len(check); i++ {
		if check[i] < '0' || check[i] > '9' {
			return "", false
		}
	}
	leaOp := "LEAL"
	if widthW == 64 {
		leaOp = "LEAQ"
	}
	return fmt.Sprintf("\t%s %s(%s), %s", leaOp, signedImm, pSrc, pDst), true
}

// parseMOV decomposes a "\tMOV<suffix> <src>, <dst>" line. Returns
// the bare opcode (e.g. "MOVL"), the source operand, the destination
// operand, and whether the line matched the shape. Anything that
// isn't an indented MOV with exactly one ", " separating two
// operands is rejected, which is sufficient to keep peephole
// matching to the emitter's canonical output.
func parseMOV(line string) (instr, src, dst string, ok bool) {
	if len(line) < 5 || line[0] != '\t' {
		return "", "", "", false
	}
	body := line[1:]
	// Match the four MOV opcodes the emitter produces.
	var prefix string
	switch {
	case strings.HasPrefix(body, "MOVL "):
		prefix = "MOVL"
	case strings.HasPrefix(body, "MOVQ "):
		prefix = "MOVQ"
	case strings.HasPrefix(body, "MOVSS "):
		prefix = "MOVSS"
	case strings.HasPrefix(body, "MOVSD "):
		prefix = "MOVSD"
	default:
		return "", "", "", false
	}
	rest := body[len(prefix)+1:]
	i := strings.Index(rest, ", ")
	if i < 0 {
		return "", "", "", false
	}
	return prefix, rest[:i], rest[i+2:], true
}

func isRegOperand(s string) bool {
	switch s {
	case "AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	case "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7":
		return true
	}
	return false
}

func isMemSPOperand(s string) bool {
	// "<digits>(SP)" — exactly the stack-slot syntax the emitter
	// produces for every SSA-value store. Negative offsets are
	// rejected; the frame planner never emits them.
	if !strings.HasSuffix(s, "(SP)") {
		return false
	}
	core := s[:len(s)-len("(SP)")]
	if core == "" {
		return false
	}
	for i := 0; i < len(core); i++ {
		if core[i] < '0' || core[i] > '9' {
			return false
		}
	}
	return true
}

// bitTestInfo carries the operand and bit position for
// a `(base & 1<<bit) <eq/ne> 0` test that was lowered to a single
// BTL/BTQ instruction by the BlockIf-control fusion. EmitIfBranch
// reads it back from plan.branchFusedBit at the matching cond ID.
type bitTestInfo struct {
	base *ssa.Value
	bit  int
}

// isZeroConst reports whether v is an OpConst{32,64} (resolving
// through OpCopy) whose value is exactly 0. Used by the bit-test
// fusion to recognise `... <eq/ne> 0` shapes.
func isZeroConst(v *ssa.Value) bool {
	v = resolveCopy(v)
	if v == nil {
		return false
	}
	switch v.Op {
	case ssa.OpConst32, ssa.OpConst64:
		return v.AuxInt == 0
	}
	return false
}

// powerOfTwoBit reports whether v is an OpConst{32,64} whose value
// is exactly 1<<bit for some 0 <= bit < W (W = 32 or 64 depending on
// the `is64` flag). Returns the bit position when so. Negative
// constants and zero return false.
func powerOfTwoBit(v *ssa.Value, is64 bool) (int, bool) {
	v = resolveCopy(v)
	if v == nil {
		return 0, false
	}
	switch v.Op {
	case ssa.OpConst32:
		if !is64 {
			x := uint32(v.AuxInt)
			if x == 0 || x&(x-1) != 0 {
				return 0, false
			}
			for i := 0; i < 32; i++ {
				if x>>i == 1 {
					return i, true
				}
			}
		}
	case ssa.OpConst64:
		if is64 {
			x := uint64(v.AuxInt)
			if x == 0 || x&(x-1) != 0 {
				return 0, false
			}
			for i := 0; i < 64; i++ {
				if x>>i == 1 {
					return i, true
				}
			}
		}
	}
	return 0, false
}

// passthroughTarget walks an empty BlockPlain chain and
// returns the first block in the chain that is NOT a pure pass-through.
// A pass-through is a BlockPlain with no emittable values (only Phis
// or inlineable values, which produce no asm), exactly one successor,
// and no phi edge-copies to run on its outgoing edge. Branching to
// such a block is observationally identical to branching to its
// successor, so this lets the caller name the chain's effective
// destination in JMP / JCC instructions. The intermediate block stays
// in the asm as an (now-dead) label.
//
// wasm-to-SSA emits a 4-block "diamond" for `if x { foo }` (no else
// clause) — `b_test`, `b_then` (the body), `b_else` (empty, jumps
// straight to merge), `b_merge` — and the lone JMP coming out of the
// BlockIf would unconditionally route through the empty `b_else`.
// Resolving `b_else` → `b_merge` here turns that into a direct branch
// to `b_merge`, which combined with the fall-through hint lets the
// arch invert the JCC and drop the JMP entirely.
//
// A small hop limit (8) catches degenerate cases (cyclic empty chains
// shouldn't exist in well-formed SSA but we guard anyway).
func passthroughTarget(blk *ssa.Block, plan *funcPlan) *ssa.Block {
	cur := blk
	for hop := 0; hop < 8; hop++ {
		if cur == nil || cur.Kind != ssa.BlockPlain || len(cur.Succs) != 1 {
			break
		}
		if !blockIsPassthrough(cur, plan) {
			break
		}
		next := cur.Succs[0].Block
		if next == cur {
			break
		}
		// Don't redirect across an edge that needs phi edge-copies —
		// those copies live in the pass-through block's emit (called
		// from its BlockPlain terminator) and would be lost if the
		// branch skipped the block.
		if plan.hasPhi[next.ID] {
			break
		}
		cur = next
	}
	return cur
}

// blockIsPassthrough reports whether `blk` has no emittable values —
// every value is either a Phi (slot placeholder, no body emitted), an
// inlineable Op (operandSrc resolves it at consumer sites), or — when
// regHome decided it could stay in a register — a value whose arch
// emitter chose to skip. Frame compaction has already reclaimed regHome'd
// slots, so a Phi-only block that started life as an "empty else"
// in the source emits nothing here.
func blockIsPassthrough(blk *ssa.Block, plan *funcPlan) bool {
	if plan.hasPhi[blk.ID] {
		// Block has phis to emit on its incoming edges; even if its
		// body is otherwise empty we'd lose those edge-copies by
		// skipping it. Conservatively keep the block as a real target.
		return false
	}
	for _, v := range blk.Values {
		if v.Op == ssa.OpPhi {
			continue
		}
		return false
	}
	return true
}

// emitBlock emits one block: its label, its values, the phi
// edge-copies to each successor, and the terminator. The arch
// argument supplies the per-architecture asm strings.
//
// `fallthroughLabel` (when non-empty) names the label of the block
// that emits immediately after this one — the natural fall-through
// destination. emitBlock passes it down to EmitJmp / EmitIfBranch so a
// terminal jump to that label can be omitted (or a JCC inverted to put
// the fall-through side on the no-jump path). It also drives the
// passthrough-redirection logic for empty BlockPlain successors.
func emitBlock(b *strings.Builder, blk *ssa.Block, f *ssa.Func, plan *funcPlan, sig wasm.FuncType, frame argFrame, a arch, fallthroughLabel string) error {
	fmt.Fprintf(b, "%s:\n", labelFor(blk))

	for _, v := range blk.Values {
		if v.Op == ssa.OpPhi {
			// Phi nodes are just slot placeholders; the copies are
			// emitted on the predecessor edges.
			continue
		}
		// Arch-specific skip: amd64's operandSrc inlines OpConst as
		// `$imm` at every consumer, so the materialise to the slot
		// is dead. arm64 cannot encode arbitrary 32-bit immediates
		// in the MOV form used most call sites, so it still needs
		// the materialise — its SkipValue returns false for Const.
		if a.SkipValue(v) {
			continue
		}
		// branchFusedSkip holds the SUPPORT values that the
		// BlockIf control fusion absorbs (e.g. the OpAnd32 feeding an
		// OpNe32 in the `v & K != 0` bit-test pattern). The cond
		// itself is also in branchFused so its own emit short-
		// circuits; this map covers the "produces a flag the cond
		// reads, no slot store needed" case for the support op.
		if plan.branchFusedSkip[v.ID] {
			continue
		}
		if err := a.EmitValue(b, v, plan, frame); err != nil {
			return fmt.Errorf("v%d (%s): %w", v.ID, v.Op, err)
		}
		// A callee can have triggered memory.grow which moves the
		// memory backing array and refreshes m.M on the Module —
		// so any CALL invalidates the cached m.M slot. Refresh
		// here unless this function never touches memory.
		//
		// Every real CALL clobbers mCacheReg (caller-save).
		// Re-prime it so the next memop / global access / arg
		// staging keeps using the cached register. Skip the refresh
		// for ops whose emit produced no CALL: globalInline lowers
		// OpGlobalGet/Set to a plain MOV against the Module struct,
		// and branchFused values' helper emit is short-circuited at
		// the source site (the BlockIf terminator inlines the
		// compare). Without these guards every inlined access would
		// cost the refresh pair it was supposed to save.
		// plan.emittedCall is set by exactly the emit paths that
		// produced a real CALL (marshalled helpers, direct/indirect/
		// import callees, memory-op helpers, unspliced SIMD calls).
		// Inline lowerings — spliced SIMD, branch-fused compares,
		// inlined globals and helpers, the div/rem family (whose trap
		// CALLs never return) — leave it unset, so the refresh cost
		// lands only where a callee could actually have clobbered
		// the cached state.
		if plan.emittedCall {
			plan.emittedCall = false
			if plan.mCacheReg != "" {
				a.EmitMCachePrime(b, plan.mCacheReg)
			}
			if plan.spliceHoist != "" {
				b.WriteString(plan.spliceHoist)
			}
		}
	}

	switch blk.Kind {
	case ssa.BlockPlain:
		if len(blk.Succs) != 1 {
			return fmt.Errorf("BlockPlain expects 1 successor, got %d", len(blk.Succs))
		}
		// Phi edge-copies for the (single) outgoing edge — must run
		// BEFORE the jump so the successor sees the right phi values.
		succ := blk.Succs[0]
		if err := emitPhiEdgeCopies(b, blk, succ.Block, succ.Index, plan, frame, a); err != nil {
			return err
		}
		// Redirect through empty pass-through blocks. The
		// emit path will still emit the (now-dead) intermediate label,
		// but no JMP references it after redirection. If the resolved
		// label IS the fall-through, EmitJmp drops the jump entirely.
		succLabel := labelFor(passthroughTarget(succ.Block, plan))
		a.EmitJmp(b, succLabel, fallthroughLabel)
	case ssa.BlockIf:
		if len(blk.Succs) != 2 || blk.Control == nil {
			return fmt.Errorf("BlockIf needs 2 successors and a Control value")
		}
		thenSucc := blk.Succs[0]
		elseSucc := blk.Succs[1]
		// Passthrough redirection. When the immediate
		// successor is a no-value BlockPlain that just jumps to its
		// own successor (and there is no phi work on its outgoing
		// edge), we can branch straight to the chain's effective
		// target — the intermediate block stays in the asm as a
		// dead label, but the branch instruction names the real
		// destination. This collapses the empty-`else` pattern that
		// wasm-to-SSA emits for `if x { foo }` (no else clause).
		thenLabel := labelFor(passthroughTarget(thenSucc.Block, plan))
		elseLabel := labelFor(passthroughTarget(elseSucc.Block, plan))
		// CRITICAL: phi edge-copies must be per-branch, not block-end.
		// A BlockIf has two outgoing edges; the phi values destined for
		// each successor differ (per the phi.Args[predIdx] selection).
		// Emitting both edges' copies unconditionally at block end
		// would overwrite each other AND clobber the current block's
		// own phi-targets (e.g. a self-loop where the loop header
		// phi reads v62, and one edge has phi.next = v_loaded; emitting
		// the back-edge copy before testing the loop condition mutates
		// v62 even when the fall-through is taken). Pure-Go emits this
		// correctly by placing phi assigns INSIDE the if/else branches.
		// We mirror that by intercepting the branch and emitting the
		// edge copies on the side that's actually taken.
		thenHasPhi := plan.hasPhi[thenSucc.Block.ID]
		elseHasPhi := plan.hasPhi[elseSucc.Block.ID]
		if !thenHasPhi && !elseHasPhi {
			// No phis to copy on either edge — direct branch is fine.
			// Pass the fall-through hint so the arch can drop the
			// JMP / invert the JCC when the natural-next-block is
			// the same as one of the branch targets.
			a.EmitIfBranch(b, blk.Control, thenLabel, elseLabel, fallthroughLabel, plan, frame)
			break
		}
		// Insert intermediate labels for the branches that need phi
		// copies. The condition test branches to the intermediate,
		// which copies phis then jumps to the real successor.
		// Pass an empty fall-through hint to the arch — the PHI_<id>
		// intermediates emit immediately after the conditional, so
		// neither side is a natural fall-through and we want the
		// classic `JCC then; JMP else` shape.
		thenJmp := thenLabel
		elseJmp := elseLabel
		var thenInter, elseInter string
		if thenHasPhi {
			thenInter = fmt.Sprintf("PHI_%d_then", blk.ID)
			thenJmp = thenInter
		}
		if elseHasPhi {
			elseInter = fmt.Sprintf("PHI_%d_else", blk.ID)
			elseJmp = elseInter
		}
		a.EmitIfBranch(b, blk.Control, thenJmp, elseJmp, "", plan, frame)
		if elseHasPhi {
			fmt.Fprintf(b, "%s:\n", elseInter)
			if err := emitPhiEdgeCopies(b, blk, elseSucc.Block, elseSucc.Index, plan, frame, a); err != nil {
				return err
			}
			a.EmitJmp(b, elseLabel, "")
		}
		if thenHasPhi {
			fmt.Fprintf(b, "%s:\n", thenInter)
			if err := emitPhiEdgeCopies(b, blk, thenSucc.Block, thenSucc.Index, plan, frame, a); err != nil {
				return err
			}
			a.EmitJmp(b, thenLabel, "")
		}
	case ssa.BlockRet:
		if err := a.EmitReturn(b, blk, sig, plan, frame); err != nil {
			return err
		}
	case ssa.BlockUnreachable:
		a.EmitUnreachable(b)
	case ssa.BlockBrTable:
		if blk.Control == nil || len(blk.Succs) == 0 {
			return fmt.Errorf("BlockBrTable needs a selector and successors")
		}
		// Per-edge phi copies would need one intermediate label per
		// successor; no interpreter-dispatch shape produces them, so
		// reject and let the per-function fallback keep the gc body.
		for _, s := range blk.Succs {
			if plan.hasPhi[s.Block.ID] {
				return fmt.Errorf("BlockBrTable successor L%d carries phis", s.Block.ID)
			}
		}
		labels := make([]string, len(blk.Succs))
		for i, s := range blk.Succs {
			labels[i] = labelFor(passthroughTarget(s.Block, plan))
		}
		if blk.TableDefault < 0 || blk.TableDefault >= len(labels) {
			return fmt.Errorf("BlockBrTable default %d out of range", blk.TableDefault)
		}
		a.EmitBrTable(b, blk.Control, blk.TableCases, labels, labels[blk.TableDefault], plan, frame)
	default:
		return fmt.Errorf("unsupported block kind %v", blk.Kind)
	}
	return nil
}

// emitPhiEdgeCopies emits MOV instructions that copy each phi's
// pred-side operand to the phi's slot. When the staged-phi analysis
// marked the successor's phis as needing temps, edge copies go via
// per-phi scratch slots to break parallel-assignment cycles (back-
// edge swap hazard). The MOV itself is per-arch (delegated to
// arch.EmitPhiCopy).
func emitPhiEdgeCopies(b *strings.Builder, pred, succ *ssa.Block, predIdx int, plan *funcPlan, frame argFrame, a arch) error {
	if !plan.hasPhi[succ.ID] {
		return nil
	}
	staged := plan.staged[succ.ID]
	// Pass 1: write each phi's incoming value to either the phi's
	// real slot (no staging needed) or to its staging slot.
	//
	// Loop-carry coalesce short-circuit: when the phi destination has
	// a regHome (set only by the loop-carry coalesce pass —
	// block-local regalloc never sets a regHome on a phi) AND the src
	// value resolves to the same
	// register, the value is already in the register from the
	// producer's emit and the next iteration's reads pick it up
	// via operandSrc. Emit nothing in that case. This is the actual
	// "loop carry lives in a register across iterations" payoff.
	for _, phi := range plan.phisOf[succ.ID] {
		if predIdx >= len(phi.Args) {
			return fmt.Errorf("phi v%d in block %d has no arg for pred index %d", phi.ID, succ.ID, predIdx)
		}
		src := phi.Args[predIdx]
		if src == nil {
			return fmt.Errorf("phi v%d arg %d is nil", phi.ID, predIdx)
		}
		if reg := plan.coalescedPhi[phi.ID]; reg != "" {
			actual := resolveCopy(src)
			if actual != nil && plan.regHome[actual.ID] == reg {
				// Coalesced loop carry — src already lives in the
				// phi's reserved register. No copy needed.
				continue
			}
			// Forward (non-back-edge) entry into the loop. Copy the
			// source into the phi's reserved register so the loop
			// body sees the right initial value. Delegated to the
			// arch — only amd64 implements coalescing today; arm64
			// never sees plan.coalescedPhi populated because the
			// coalesce pass runs behind arch.SupportsRegHome.
			if err := a.EmitPhiCopyValueToReg(b, src, reg, phi.Type, plan, frame); err != nil {
				return err
			}
			continue
		}
		var dstOff int
		if staged {
			dstOff = plan.phiTemp[phi.ID]
		} else {
			dstOff = plan.offsets[phi.ID]
		}
		if err := a.EmitPhiCopyValue(b, src, dstOff, phi.Type, plan, frame); err != nil {
			return err
		}
	}
	// Pass 2: when staged, copy each temp into its phi's real slot.
	// Coalesced phis skip this — their Pass 1 wrote
	// directly to the reserved register OR was a no-op, neither of
	// which produced a staging-slot value to copy out of. Touching
	// the temp slot here would read uninitialised bytes and clobber
	// the phi's real slot for any downstream consumer that still
	// goes through it.
	if staged {
		for _, phi := range plan.phisOf[succ.ID] {
			if plan.coalescedPhi[phi.ID] != "" {
				continue
			}
			if err := a.EmitPhiCopySlot(b, plan.phiTemp[phi.ID], plan.offsets[phi.ID], phi.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

func labelFor(b *ssa.Block) string { return fmt.Sprintf("L%d", b.ID) }

// opEmitsCall reports whether emitting v results in a runtime
// CALL instruction (helper, direct, indirect, import, global
// accessor, memory builtin). Used to schedule m.M cache
// refreshes — any callee may have invoked memory.grow.
func opEmitsCall(op ssa.Op) bool {
	switch op {
	case ssa.OpHelperCall,
		ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
		ssa.OpGlobalGet, ssa.OpGlobalSet,
		ssa.OpMemSize, ssa.OpMemGrow,
		ssa.OpMemoryCopy, ssa.OpMemoryFill,
		// SIMD helper calls are real CALLs unless a splicer inlines
		// them; consumers that model call clobbers (m-cache
		// re-prime, loop-carry coalesce) must treat them as such.
		// The splice-mode coalesce pass exempts them explicitly and
		// enforces the splice at emit time (plan.mustSplice).
		ssa.OpSimdCall, ssa.OpSimdMemCall:
		return true
	}
	return false
}

// resolveSlotArg walks OpCopy chains and returns the underlying
// value if (a) the chain terminates and (b) the terminal value is
// one whose slot a downstream operandSrc{32,64,Float} would read
// — i.e. not an OpConst{32,64,F32,F64} or an OpParam (those have
// no consumer-visible slot read; constants inline as $imm and
// parameters resolve to FP+offset). Returns nil otherwise so
// callers can skip the use cleanly.
//
// Mirrors emit_amd64.go's resolveCopy / operandSrc resolution so
// the Pass 2 lifetime analysis agrees with what the emitter will
// actually access. Without this, an OpCopy-aliased use was being
// charged to the OpCopy's index instead of the underlying
// value's real reader, causing the linear-scan slot reuse to
// reclaim the underlying's slot before its last reader ran.
// arm64ReuseUnsafe reports whether v.Op should be excluded from
// slot reuse on archs where arch.SkipValue(OpConst32) is
// false (currently arm64 only). The bisect proceeds by starting
// with EVERY op marked unsafe and re-enabling op classes one
// group at a time, running a real-module spec suite after each.
// Each entry in the unsafe set is therefore a "haven't checked
// yet" / "verified to break" marker — once resolveSlotArg learns
// the corresponding use site, the entry here can be removed.
//
// The amd64 path doesn't consult this — its operandSrc inlines
// OpConst32 as $imm, OpParam as FP-relative, and OpCopy walks
// through, so the existing exclude list in Pass 2 is already
// complete for amd64.
func arm64ReuseUnsafe(op ssa.Op) bool {
	// Bisect bucket A — arithmetic / cmp / shift / bit ops.
	// Currently every op except Const32 is in this bucket; the
	// bisect log will halve this list once a failing test set is
	// in hand.
	switch op {
	case ssa.OpConst32:
		return false // verified by recursive_init.wasm fix
	// Verified safe by bisect against a real-module spec suite:
	// enabling these ops for arm64 slot reuse keeps every
	// downstream test green. Each op's emit shape on arm64
	// matches what the lifetime analyzer can model (the consumer
	// reads the operand slot at the same SSA index that
	// resolveSlotArg records).
	// i32 ops (size 4) — the only width Pass 6 currently reuses
	// (the `if size >= 8` gate excludes i64/f64 slots). Every op
	// here has had its arm64 emit shape audited and runs the
	// spec suite clean.
	case ssa.OpAdd32, ssa.OpSub32, ssa.OpMul32,
		ssa.OpAnd32, ssa.OpOr32, ssa.OpXor32,
		ssa.OpShl32, ssa.OpShrU32, ssa.OpShrS32,
		ssa.OpEq32, ssa.OpNe32,
		ssa.OpLtS32, ssa.OpLeS32, ssa.OpLtU32, ssa.OpLeU32,
		ssa.OpEq64, ssa.OpNe64,
		ssa.OpLtS64, ssa.OpLeS64, ssa.OpLtU64, ssa.OpLeU64,
		ssa.OpTrunc64To32, ssa.OpCopy:
		return false
		// Arithmetic (Add/Sub/Mul) on arm64 stayed UNSAFE through
		// the initial slot-reuse rollout because enabling slot reuse
		// for any of them triggered a "wasm trap: interface
		// conversion: nil func" in the deep call_indirect chain
		// (p9.Fn15018 -> p9.Fn37659). After the block-local regalloc was
		// extended to cover these ops on arm64, the *typical*
		// arithmetic value lives in a register and never gets a
		// slot, so the failing reuse path almost never fires. The
		// underlying lifetime-tracking miss in Pass 6 still exists
		// for the cross-block / cross-call arith result case, so
		// keeping these in the unsafe set is a correctness choice:
		// the regalloc has dropped them down to the cases that
		// ALWAYS need a slot anyway, and reuse there is the part
		// that breaks. The slot-allocation delta is small enough
		// (block-local regalloc picks up the bulk of them) that the
		// correctness margin is the better trade.
	}
	return true
}

func resolveSlotArg(v *ssa.Value, constsNeedSlot bool) *ssa.Value {
	for i := 0; v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 && v.Args[0] != nil && v.Args[0] != v && i < 16; i++ {
		v = v.Args[0]
	}
	if v == nil {
		return nil
	}
	switch v.Op {
	case ssa.OpConst32, ssa.OpConst64, ssa.OpConstF32, ssa.OpConstF64:
		// amd64 inlines these as `$imm`, so the slot has no consumer
		// and there is nothing to lifetime-track — return nil.
		//
		// arm64's per-op emit (operandSrc32ARM64 etc.) re-reads the
		// const FROM its slot at every consumer, so the slot stays
		// live until the constant's last user. If we return nil here
		// the Pass 6 reuse allocator sees zero uses, releases the
		// slot the instant it is written, and a later block-local
		// def grabs that slot from the free pool — overwriting the
		// constant before the original constant's reader executes.
		// recursive_init.wasm's `i32.add (load 128) (const 1)` makes
		// this concrete: Const(128)'s slot was reused for Const(1),
		// so the increment computed counter+128 instead of counter+1
		// and `run` returned 128 instead of 6.
		if constsNeedSlot {
			return v
		}
		return nil
	case ssa.OpParam:
		// operandSrc reads from FP+offset, never from a slot.
		return nil
	}
	return v
}

// directCall captures the per-OpCallDirect / per-OpCallImport info
// computed during planFunc: the callee's wasm signature (for ABI0
// frame layout), the argument-frame layout, and the asm symbol the
// emitter should CALL. For import calls the symbol points at a Go-
// side wrapper (`·callImport_<funcIdx>(SB)`) that performs the
// interface dispatch; the wrapper is registered for the caller to
// emit as Go source alongside the asm.
type directCall struct {
	sig    wasm.FuncType
	frame  argFrame
	symbol string // already wrapped — `·name(SB)` or `pkg·Name(SB)`
}

// funcPlan is the per-function layout state computed before code
// emission. It captures stack-slot offsets, the per-block phi list,
// the staging-temp map, the hoist set (values that need a slot vs
// values inlined at the use site), and the chosen NOSPLIT / non-
// NOSPLIT flag.
type funcPlan struct {
	// gpRegPool / sseRegPool are the arch's block-local regalloc
	// register pools. emitFunc seeds them from arch.GPRegPool() /
	// arch.SSERegPool() so the regalloc machinery picks
	// arch-appropriate names without threading arch everywhere.
	gpRegPool  []string
	sseRegPool []string
	// regHomeEligibleOp narrows the set of ops the regalloc gives
	// a register home to. emitFunc seeds it from
	// arch.RegHomeEligibleOp so the arm64 emit path can opt in
	// op-by-op as each per-op emit learns to honour plan.regHome
	// on the write side.
	regHomeEligibleOpFn func(ssa.Op) bool
	offsets             map[ssa.ValueID]int
	hoist               map[ssa.ValueID]bool
	phiTemp             map[ssa.ValueID]int
	phisOf              map[ssa.BlockID][]*ssa.Value
	hasPhi              map[ssa.BlockID]bool
	staged              map[ssa.BlockID]bool
	hasCall             bool
	// hasSimdCall / spliceMode / wantsTrapStub drive SIMD splicing:
	// hasSimdCall marks OpSimdCall / OpSimdMemCall presence,
	// spliceMode is set when a Splicer is available for them (slot-
	// only emission), and wantsTrapStub records that some splice
	// branched to the OOB trap label so the stub must be appended
	// once at body end. splicer is the FuncOptions.Splicer handle
	// for the per-op emitters.
	hasSimdCall   bool
	spliceMode    bool
	wantsTrapStub bool
	splicer       SimdSplicer
	// packed / packedParams mirror FuncOptions.PackedParams: the
	// packed outlined-boundary form whose parameter values live in
	// frame slots filled by the pack prologue rather than FP offsets.
	packed       bool
	packedParams []ssa.Type
	// trapDivZero / trapIntOvf are the CALL targets of the inline
	// div/rem trap branches ("·wasm_trap_div_zero" style, resolved to
	// forward wrappers in multi-package chunks). divRemInline gates
	// the inline lowering: false when a resolver was available but
	// could not resolve the trap helpers — emitting the default
	// spelling there would fail to link.
	trapDivZero  string
	trapIntOvf   string
	divRemInline bool
	// spliceHoist is the splicer's module-state staging text (m.M /
	// memSize pointer into splice-safe registers), emitted at entry
	// and re-issued after every value that actually emitted a CALL.
	// emittedCall is the per-value flag those emitters set.
	spliceHoist string
	emittedCall bool
	// mustSplice marks SIMD call values inside register-coalesced
	// loops: their inline splice is load-bearing (a fallback CALL
	// would clobber the carry registers), so a splice-table miss
	// there fails the function to the host's fallback instead.
	mustSplice map[ssa.ValueID]bool
	// hasNonSimdCall narrows hasCall to non-SIMD callees (scalar
	// helpers, direct/indirect/import calls, memory ops, global
	// wrappers) — the set FuncOptions.ForbidCalls rejects. SIMD
	// helper symbols ship with every SIMD-using bundle, so their
	// CALLs stay allowed under ForbidCalls.
	hasNonSimdCall bool
	// callDescs names the distinct non-SIMD callees planFunc saw
	// (capped), for the ForbidCalls diagnostic — listing all blockers
	// lets one transpile show the full widening work list.
	callDescs  []string
	frameSize  int
	calleeArea int // bytes reserved at low SP for callee-arg staging
	helperPfx  string
	helperRefs map[ssa.ValueID]string
	directs    map[ssa.ValueID]*directCall
	// hasMem records whether the function performs at least one
	// load / store / mem-size / mem-grow op. Drives the
	// `mCacheCandidate` decision — only memory-touching functions
	// need m staged into mCacheReg.
	hasMem bool
	// mem64 reports whether the module's linear memory uses 64-bit
	// addressing. Memory accesses then take i64 bases with no
	// mod-2^32 wrap, and the mem-size / mem-grow / copy / fill ops
	// route to the 64-bit helper family.
	mem64 bool
	// branchFused holds value IDs for OpHelperCall("i32_eqz" /
	// "i64_eqz") whose single use is a BlockIf control. The eqz
	// helper body and slot store are skipped; the BlockIf emits a
	// TEST + JE directly on the eqz argument (inverted polarity)
	// instead of the 5-instruction TEST + SETEQ + MOVBLZX + store
	// + reload + TEST + JNE / JMP pair. branchFusedKind[v.ID] is
	// the helper name ("i32_eqz" / "i64_eqz") so the BlockIf
	// emitter can pick the right operand width.
	branchFused     map[ssa.ValueID]bool
	branchFusedKind map[ssa.ValueID]string
	// branchFusedSkip marks SUPPORT values that the
	// BlockIf control absorbs. For the `v & K != 0` → BTL pattern
	// it holds the OpAnd32's ID: the cond is OpNe32 (already in
	// branchFused), and the BTL instruction reads the original
	// `v` directly without needing the AND's slot store. emitBlock
	// skips emission for any value in this map.
	branchFusedSkip map[ssa.ValueID]bool
	// branchFusedBit records, per BlockIf cond value, the base
	// operand that BTL/BTQ should test and which bit to examine.
	// Populated only for the `(x & 1<<bit) <eq/ne> 0` pattern
	// detected in Pass 4; nil otherwise.
	branchFusedBit map[ssa.ValueID]bitTestInfo
	// globalInline holds OpGlobalGet/OpGlobalSet values that should
	// be lowered to an inline MOV against the Module struct instead
	// of a CALL to the loadGlobal_N / storeGlobal_N wrapper. The map
	// entry carries the byte offset of the global field within
	// Module and the wasm value type (so the emitter picks the
	// right MOV width). Only set when FuncOptions.GlobalOffsets is
	// populated AND the global is module-defined (imported globals
	// keep the CALL path because they live behind the host iface).
	globalInline map[ssa.ValueID]globalInlineInfo
	// regHome holds the block-local register assignment
	// for SSA values whose entire lifetime fits inside one block and
	// does not cross a CALL boundary. When a value has an entry
	// here, operandSrc{32,64,Float} resolves it to the register
	// name instead of its stack slot, and the producer's emit
	// function writes the result directly to that register rather
	// than storing to the slot. computeRegHomes populates this in
	// planFunc's last pass; the slot still gets allocated (the
	// reuse pool keeps it cheap) so the existing peephole / regtrack
	// passes stay simple and the conservative fallback "produce to
	// slot" path remains correct for any producer that hasn't yet
	// been taught to honour regHome.
	regHome map[ssa.ValueID]string
	// reservedRegs records, per block, the set of GP
	// registers that the cross-block coalescing pre-pass has
	// reserved for a loop-carry value passing through this block.
	// Per-block linear scan must subtract these from the free pool
	// so a transient value in this block does not steal a reg that
	// is "really" still holding a coalesced loop carry. When the
	// pre-pass declines a coalesce (loop body contains a CALL, no
	// regHome-eligible carry, etc.), this stays nil and the per-
	// block scan runs unchanged.
	reservedRegs map[ssa.BlockID]map[string]bool
	// coalescedPhi records loop-carry phi destinations
	// that have been merged with their back-edge args into a
	// shared register. When emitPhiCopyValue sees a phi-edge-copy
	// whose phi destination AND src value resolve to the same
	// register, it emits nothing — the value is already in the
	// register from the producer's emit, and the next iteration's
	// reads pick it up via operandSrc → regHome. The map value is
	// the shared register name (same as plan.regHome[phi.ID] and
	// plan.regHome[v.ID] for any coalesced arg).
	coalescedPhi map[ssa.ValueID]string
	// mCacheReg is the GP register the per-function
	// prologue loads `m` (the *Module argument at FP+0) into so
	// subsequent emits can dereference it without re-reading FP
	// every time. Empty if the optimization is off for this
	// function — typically because the function has no memops, no
	// inlined-global accesses, no direct CALLs (nothing to amortise
	// the per-CALL refresh against). When non-empty, every emit
	// that previously wrote `MOVQ m+0(FP), <scratch>` writes
	// `MOVQ <mCacheReg>, <scratch>` instead, the per-CALL emit
	// path inserts a `MOVQ m+0(FP), <mCacheReg>` refresh (Go ABI0
	// classes every GP register as caller-save, so the cache is
	// invalidated by every CALL), and the per-block linear scan in
	// assignBlockRegHomes excludes mCacheReg from its free pool.
	mCacheReg string
	// mCacheCandidate is the planFunc-level "this function would
	// benefit from caching m" hint. emitFunc consults it together
	// with arch.SupportsRegHome to decide whether to actually
	// populate mCacheReg.
	mCacheCandidate bool
	// unusedResult marks SSA values whose result is
	// never consumed — no other value's Args refer to them (after
	// resolving OpCopy chains), no block.Control reads them, and
	// they are not among the function's BlockRet outputs. The emit
	// path uses it to skip the post-CALL `MOVL retOff(SP), AX;
	// MOVL AX, dstOff(SP)` pair for OpCallDirect / OpCallImport /
	// OpCallIndirect / OpHelperCall sites — Pure-Go's compiler
	// drops these entirely, and on functions like Fn31214 (where
	// most helper calls' return values are discarded) this is a
	// pure two-instructions-per-call win.
	unusedResult map[ssa.ValueID]bool
}

// globalInlineInfo describes one inlined global access: where it
// sits in Module (byte offset) and what type to read/write (so the
// emitter picks MOVL/MOVQ/MOVSS/MOVSD).
type globalInlineInfo struct {
	offset int
	vtype  wasm.ValType
}

// planFunc walks f and builds the layout plan. The walk happens once
// up-front so emitValueAMD64 can stay a simple op-by-op switch with
// O(1) lookups.
//
// callArgBias is the SP-offset where the outgoing-call argument
// block starts (0 on amd64, 8 on arm64 — see arch.CallArgBias).
//
// constsNeedSlot reflects whether the arch's per-op emit reads
// OpConst* operands from their slot (true on arm64 — operandSrc32ARM64
// returns `slot(RSP)` for every Const) or inlines them as immediates
// (false on amd64 — operandSrc32 returns `$imm`). When true, the
// Pass 2 lifetime analysis MUST track Const uses; otherwise the
// linear-scan slot-reuse releases each Const's slot before its
// real reader runs, producing a stale-data read at the consumer.
// resolveSlotArg honours the flag at use-tracking time so the same
// allocator code path works for both archs.
// noteNonSimdCall records a non-SIMD callee for the ForbidCalls
// diagnostic and sets the flag.
func (p *funcPlan) noteNonSimdCall(v *ssa.Value) {
	p.hasNonSimdCall = true
	aux, _ := v.Aux.(string)
	if aux == "" {
		aux = fmt.Sprintf("#%d", v.AuxInt)
	}
	desc := fmt.Sprintf("%v %s", v.Op, aux)
	for _, d := range p.callDescs {
		if d == desc {
			return
		}
	}
	if len(p.callDescs) < 8 {
		p.callDescs = append(p.callDescs, desc)
	}
}

func planFunc(f *ssa.Func, opts FuncOptions, sig wasm.FuncType, callArgBias int, constsNeedSlot bool) (*funcPlan, error) {
	p := &funcPlan{
		offsets:         map[ssa.ValueID]int{},
		phiTemp:         map[ssa.ValueID]int{},
		phisOf:          map[ssa.BlockID][]*ssa.Value{},
		hasPhi:          map[ssa.BlockID]bool{},
		staged:          map[ssa.BlockID]bool{},
		helperPfx:       opts.HelperPrefix,
		helperRefs:      map[ssa.ValueID]string{},
		directs:         map[ssa.ValueID]*directCall{},
		branchFused:     map[ssa.ValueID]bool{},
		branchFusedKind: map[ssa.ValueID]string{},
		branchFusedSkip: map[ssa.ValueID]bool{},
		globalInline:    map[ssa.ValueID]globalInlineInfo{},
		regHome:         map[ssa.ValueID]string{},
		coalescedPhi:    map[ssa.ValueID]string{},
		unusedResult:    map[ssa.ValueID]bool{},
	}
	p.mem64 = opts.Module != nil && opts.Module.Memory64()
	p.trapDivZero, p.trapIntOvf = "·wasm_trap_div_zero", "·wasm_trap_int_overflow"
	p.divRemInline = true
	p.packed = opts.PackedParams != nil
	p.packedParams = opts.PackedParams

	// Pass 1: scan calls (helper + direct), compute the max
	// callee-arg/ret frame, resolve each direct call's symbol,
	// and detect whether the function touches wasm memory at all
	// (so the m.M cache slot can be elided in pure-arithmetic
	// leaves).
	maxCallee := 0
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			switch v.Op {
			case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
				ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
				ssa.OpLoadF32, ssa.OpLoadF64,
				ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
				ssa.OpStoreF32, ssa.OpStoreF64,
				// SIMD memory helpers take m; staging it per call
				// benefits from the m-cache exactly like inline memops.
				ssa.OpSimdMemCall:
				p.hasMem = true
			}
			switch v.Op {
			case ssa.OpHelperCall:
				name, ok := v.Aux.(string)
				if !ok {
					return nil, fmt.Errorf("OpHelperCall v%d has non-string Aux", v.ID)
				}
				p.helperRefs[v.ID] = name
				if helperAlwaysInline(name) {
					// Both arches emit these as one or two native
					// instructions — no CALL, no callee frame, and
					// no ForbidCalls consequence.
					break
				}
				if divRemHelper(name) {
					// Inline div/rem: native divide plus trap-branch
					// CALLs (zero-arg, no callee frame). With a
					// resolver, the trap symbols must resolve for the
					// inline form to link; unresolved (or resolver-
					// less) hosts keep the current behavior.
					p.hasCall = true
					if opts.MemHelperSymbol != nil {
						z, ok1 := opts.MemHelperSymbol("wasm_trap_div_zero")
						ovf, ok2 := opts.MemHelperSymbol("wasm_trap_int_overflow")
						if ok1 && ok2 {
							p.trapDivZero, p.trapIntOvf = "·"+z, "·"+ovf
							break
						}
						p.divRemInline = false
					}
					p.noteNonSimdCall(v)
					spec, ok := helperSig(name)
					if !ok {
						return nil, fmt.Errorf("OpHelperCall v%d: unknown helper %q", v.ID, name)
					}
					if sz := helperCallFrameSize(spec); sz > maxCallee {
						maxCallee = sz
					}
					break
				}
				p.hasCall = true
				p.noteNonSimdCall(v)
				spec, ok := helperSig(name)
				if !ok {
					return nil, fmt.Errorf("OpHelperCall v%d: unknown helper %q", v.ID, name)
				}
				if sz := helperCallFrameSize(spec); sz > maxCallee {
					maxCallee = sz
				}
			case ssa.OpCallDirect:
				p.hasCall = true
				if opts.Module == nil {
					return nil, fmt.Errorf("OpCallDirect v%d: FuncOptions.Module is required", v.ID)
				}
				if v.AuxInt < 0 {
					// Synthetic call to an extracted sibling (the
					// outline pass names the callee in Aux and has no
					// wasm index). The packed call-site protocol
					// (staging the boundary through the module's
					// outline pack) is not emitted here yet — count
					// it as an unresolvable callee so ForbidCalls
					// falls the function back to the host's backend.
					p.noteNonSimdCall(v)
					break
				}
				calleeIdx := uint32(v.AuxInt)
				csig := opts.Module.FuncTypeOf(calleeIdx)
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("OpCallDirect v%d: callee %d frame: %w", v.ID, calleeIdx, err)
				}
				var bareName string
				resolved := false
				if opts.CalleeSymbol != nil {
					bareName, resolved = opts.CalleeSymbol(calleeIdx)
				}
				if !resolved {
					// Unresolved callees count against ForbidCalls.
					p.noteNonSimdCall(v)
					if opts.FuncSymbol != nil {
						bareName = opts.FuncSymbol(calleeIdx)
					} else {
						bareName = fmt.Sprintf("Fn%d", calleeIdx)
					}
				}
				p.directs[v.ID] = &directCall{
					sig:    csig,
					frame:  cframe,
					symbol: goAsmSymbol(bareName),
				}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			case ssa.OpCallImport:
				p.hasCall = true
				p.noteNonSimdCall(v)
				if opts.Module == nil {
					return nil, fmt.Errorf("OpCallImport v%d: FuncOptions.Module is required", v.ID)
				}
				calleeIdx := uint32(v.AuxInt)
				csig := opts.Module.FuncTypeOf(calleeIdx)
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("OpCallImport v%d: callee %d frame: %w", v.ID, calleeIdx, err)
				}
				// The asm CALLs a Go-side wrapper named
				// `callImport_<funcIdx>` (in the same package). The
				// host is responsible for emitting the wrapper as
				// Go source; the asm side just needs the symbol.
				// We use the same name regardless of which wasm
				// import-module the function belongs to so the
				// wrapper-emit loop on the host side can be driven
				// from a single `mod.Imports[]` walk rather than
				// per-call introspection.
				p.directs[v.ID] = &directCall{
					sig:    csig,
					frame:  cframe,
					symbol: wrapperSymbol(opts.HelperPrefix, fmt.Sprintf("callImport_%d", calleeIdx)),
				}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			case ssa.OpCallIndirect:
				p.hasCall = true
				p.noteNonSimdCall(v)
				if opts.Module == nil {
					return nil, fmt.Errorf("OpCallIndirect v%d: FuncOptions.Module is required", v.ID)
				}
				typeIdx := uint32(v.AuxInt)
				if typeIdx >= uint32(len(opts.Module.Types)) {
					return nil, fmt.Errorf("OpCallIndirect v%d: type idx %d out of range", v.ID, typeIdx)
				}
				ft := opts.Module.Types[typeIdx]
				// Wrapper signature prepends i32 for the table-index
				// argument. The wrapper does `t0[idx].(funcType)(m,
				// params...)` so it absorbs the type-assertion and
				// the function-pointer call in one Go expression.
				csig := wasm.FuncType{
					Params:  append([]wasm.ValType{wasm.ValI32}, ft.Params...),
					Results: ft.Results,
				}
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("OpCallIndirect v%d: frame: %w", v.ID, err)
				}
				p.directs[v.ID] = &directCall{
					sig:    csig,
					frame:  cframe,
					symbol: wrapperSymbol(opts.HelperPrefix, fmt.Sprintf("callIndirect_type%d", typeIdx)),
				}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			case ssa.OpSimdCall, ssa.OpSimdMemCall:
				// SIMD helper CALL: signature derived from the SSA
				// value itself (see simdCallSpecOf); only the callee
				// frame size matters at planning time.
				p.hasCall = true // NOT hasNonSimdCall: allowed under ForbidCalls
				p.hasSimdCall = true
				sp, err := simdCallSpecOf(v, p)
				if err != nil {
					return nil, err
				}
				if sp.frame > maxCallee {
					maxCallee = sp.frame
				}
			case ssa.OpMemoryCopy, ssa.OpMemoryFill, ssa.OpMemSize, ssa.OpMemGrow:
				// Route to the codegen-emitted helpers
				// (memorySize / memoryGrow / memoryCopy /
				// memoryFill). The codegen translator copies these
				// from internal/codegen/helpers/helpers.go into the
				// generated package; the asm side just CALLs them
				// rather than re-implementing the slice grow / copy
				// logic. In multi-package mode the helpers live in
				// base/ and are capitalized for cross-package use.
				p.hasCall = true
				var csig wasm.FuncType
				helperName := ""
				switch v.Op {
				case ssa.OpMemSize:
					csig = wasm.FuncType{Results: []wasm.ValType{wasm.ValI32}}
					helperName = "memorySize"
				case ssa.OpMemGrow:
					csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
					helperName = "memoryGrow"
				case ssa.OpMemoryCopy:
					csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32, wasm.ValI32}}
					helperName = "memoryCopy"
				case ssa.OpMemoryFill:
					csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI32, wasm.ValI32, wasm.ValI32}}
					helperName = "memoryFill"
				}
				if p.mem64 {
					// Memory64 modules route to the 64-bit helper family
					// (i64 page counts / addresses / lengths). Sig shapes
					// mirror internal/codegen/helpers: memorySize64() i64,
					// memoryGrow64(i64) i64, memoryFill64(i64, i32, i64),
					// memoryCopy64(i64, i64, i64).
					helperName += "64"
					switch v.Op {
					case ssa.OpMemSize:
						csig = wasm.FuncType{Results: []wasm.ValType{wasm.ValI64}}
					case ssa.OpMemGrow:
						csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI64}, Results: []wasm.ValType{wasm.ValI64}}
					case ssa.OpMemoryCopy:
						csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI64, wasm.ValI64, wasm.ValI64}}
					case ssa.OpMemoryFill:
						csig = wasm.FuncType{Params: []wasm.ValType{wasm.ValI64, wasm.ValI32, wasm.ValI64}}
					}
				}
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("%v v%d: frame: %w", v.Op, v.ID, err)
				}
				// OpMem* lowerings always CALL the same-package
				// helper symbol — `·memorySize(SB)` etc. In
				// multi-package mode the caller is responsible for
				// emitting a chunk-local trampoline that uses
				// //go:linkname to bridge to the canonical
				// implementation living in base. Plan9 asm cannot
				// CALL across packages on user code, so the indirect
				// hop is mandatory.
				sym := ""
				if opts.MemHelperSymbol != nil {
					if bare, ok := opts.MemHelperSymbol(helperName); ok {
						sym = fmt.Sprintf("·%s(SB)", bare)
					}
				}
				if sym == "" {
					// Unresolved helpers count against ForbidCalls.
					p.noteNonSimdCall(v)
					sym = fmt.Sprintf("·%s(SB)", helperName)
				}
				p.directs[v.ID] = &directCall{sig: csig, frame: cframe, symbol: sym}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			case ssa.OpGlobalGet, ssa.OpGlobalSet:
				if opts.Module == nil {
					return nil, fmt.Errorf("%v v%d: FuncOptions.Module is required", v.Op, v.ID)
				}
				gidx := int(v.AuxInt)
				gtype, err := globalValType(opts.Module, uint32(v.AuxInt))
				if err != nil {
					return nil, fmt.Errorf("%v v%d: %w", v.Op, v.ID, err)
				}
				// When the host supplied GlobalOffsets and
				// this is a module-defined global (offset >= 0),
				// lower the access to a direct MOV against the
				// Module struct — no wrapper CALL, no hasCall bump.
				// Imported globals (offset == -1) keep the CALL path
				// below because they live behind the host iface.
				if opts.GlobalOffsets != nil && gidx >= 0 && gidx < len(opts.GlobalOffsets) && opts.GlobalOffsets[gidx] >= 0 {
					p.globalInline[v.ID] = globalInlineInfo{
						offset: opts.GlobalOffsets[gidx],
						vtype:  gtype,
					}
					break
				}
				p.hasCall = true
				p.noteNonSimdCall(v)
				var csig wasm.FuncType
				var sym string
				if v.Op == ssa.OpGlobalGet {
					csig = wasm.FuncType{Results: []wasm.ValType{gtype}}
					sym = wrapperSymbol(opts.HelperPrefix, fmt.Sprintf("loadGlobal_%d", v.AuxInt))
				} else {
					csig = wasm.FuncType{Params: []wasm.ValType{gtype}}
					sym = wrapperSymbol(opts.HelperPrefix, fmt.Sprintf("storeGlobal_%d", v.AuxInt))
				}
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("%v v%d: frame: %w", v.Op, v.ID, err)
				}
				p.directs[v.ID] = &directCall{sig: csig, frame: cframe, symbol: sym}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			}
		}
	}
	// arm64's Go ABI reserves the first 8 bytes at caller SP+0 for the
	// callee's saved-LR slot, so the outgoing call-arg area spans
	// SP+bias..SP+bias+maxCallee on arm64 and SP+0..SP+maxCallee on
	// amd64. Pad calleeArea by the bias so the local-slot allocator's
	// floor sits above the call-arg region for both archs without the
	// arch-specific arms needing to remember the offset twice.
	maxCallee += callArgBias
	p.calleeArea = maxCallee

	// Pass 2: assign slot to every value. emit.ComputeHoist is
	// captured for the per-op emitter to use as a tie-breaker
	// (e.g., short-circuiting redundant materialisations) but the
	// slot map covers every storable scalar so any consumer can
	// safely read plan.offsets[v.ID]. operandSrc{32,64,Float} is
	// what shortens the binary-op MOV pair into one MOV + memory/
	// immediate operand — that win lands without touching slot
	// allocation.
	//
	// Slot REUSE: a value whose entire lifetime is inside its
	// def block can share its slot with a later value defined
	// after its last use (in the same block or any subsequent
	// block — the def block's execution is over by the time the
	// next block starts, so the slot's contents are dead). The
	// allocator maintains a free pool keyed by (size, align) and
	// pops from it before falling back to the high-water mark.
	// Cross-block values — anything used outside its def block,
	// including phi sources — keep dedicated, non-reusable slots
	// since their lifetimes can overlap arbitrarily with each
	// other under branching control flow. This is the main lever
	// against the per-value slot growth that pushed Fn18113 in
	// the googlesql bundle to a 680 KB frame; with reuse, only
	// the cross-block residual + the per-block peak survive.
	off := maxCallee
	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)
	p.hoist = hoist

	// 2a. Identify cross-block values. A value is cross-block iff
	// any use is in a different block than its def, OR it is the
	// Control of a different block.
	//
	// Use sites are computed by walking OpCopy chains all the way
	// to the underlying value: operandSrc{32,64,Float} resolves
	// `OpCopy → X` at every consumer and reads from X's slot
	// directly, so a use of an OpCopy through resolveCopy is a
	// REAL use of the underlying X — not of the intermediate
	// OpCopy. Without this resolution the cross-block / last-use
	// analyses miss the actual reader and the linear-scan slot
	// reuse can mark X's slot dead while X is still being read
	// through an OpCopy alias from another block (or later in the
	// same block past the OpCopy itself). That bug — observed as
	// a hang during downstream module initialisation in a real
	// wasm bundle — is what gates the rest of the algorithm.
	defBlock := make(map[ssa.ValueID]ssa.BlockID, 0)
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			defBlock[v.ID] = blk.ID
		}
	}
	crossBlock := make(map[ssa.ValueID]bool, 0)
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			for _, arg := range v.Args {
				r := resolveSlotArg(arg, constsNeedSlot)
				if r == nil {
					continue
				}
				if db, ok := defBlock[r.ID]; ok && db != blk.ID {
					crossBlock[r.ID] = true
				}
			}
		}
		if blk.Control != nil {
			r := resolveSlotArg(blk.Control, constsNeedSlot)
			if r != nil {
				if db, ok := defBlock[r.ID]; ok && db != blk.ID {
					crossBlock[r.ID] = true
				}
			}
		}
	}

	// 2b. Walk blocks; for each block, compute lastUseInBlock for
	// the block-local values, then allocate slots in linear order
	// with free-pool reuse.
	type slotKey struct {
		size, align int
	}
	pool := map[slotKey][]int{}
	type activeSlot struct {
		vid       ssa.ValueID
		expiresAt int // last block-internal index where the slot is still live
		key       slotKey
		offset    int
	}
	for _, blk := range f.Blocks {
		// Compute lastUseInBlock for block-local values. Args are
		// resolved through OpCopy chains so the underlying value
		// (the one whose slot operandSrc actually reads) gets its
		// last-use index extended to the real consumer's index,
		// not the index of an intermediate OpCopy.
		blkLen := len(blk.Values)
		lastUseInBlock := map[ssa.ValueID]int{}
		recordUse := func(arg *ssa.Value, atIdx int) {
			r := resolveSlotArg(arg, constsNeedSlot)
			if r == nil {
				return
			}
			if crossBlock[r.ID] {
				return
			}
			if defBlock[r.ID] != blk.ID {
				return
			}
			if atIdx > lastUseInBlock[r.ID] {
				lastUseInBlock[r.ID] = atIdx
			}
		}
		for i, v := range blk.Values {
			if v.Op == ssa.OpPhi {
				// Phi args are read by the PREDECESSOR block's
				// edge-copy emission (in emitPhiEdgeCopies, called
				// from the predecessor's terminator). For args
				// from other blocks the crossBlock pass already
				// pins a dedicated slot — but the missed case is
				// the SELF-LOOP back-edge: `phi.Args[predIdx]`
				// can reference a value defined LATER in THIS
				// block, and that value's "use via edge-copy"
				// happens at this block's terminator, not at the
				// phi's value-index. The default
				// `recordUse(arg, i)` would charge the use to
				// the phi's index, which is < the arg's def
				// index — so my reuse allocator sees
				// lastUseInBlock < def_idx, decides the value is
				// unused, and reclaims its slot the instant it's
				// written. The edge-copy at the terminator then
				// reads stale data. Record self-loop phi args at
				// blkLen so the slot stays live through the
				// whole block.
				for _, arg := range v.Args {
					r := resolveSlotArg(arg, constsNeedSlot)
					if r == nil {
						continue
					}
					if crossBlock[r.ID] {
						continue
					}
					if defBlock[r.ID] != blk.ID {
						continue
					}
					if blkLen > lastUseInBlock[r.ID] {
						lastUseInBlock[r.ID] = blkLen
					}
				}
				continue
			}
			for _, arg := range v.Args {
				recordUse(arg, i)
			}
		}
		// blk.Control is consumed by the terminator that follows
		// every value in this block — its lifetime extends to
		// blkLen (sentinel for "after the last value").
		if blk.Control != nil {
			r := resolveSlotArg(blk.Control, constsNeedSlot)
			if r != nil && !crossBlock[r.ID] && defBlock[r.ID] == blk.ID {
				if blkLen > lastUseInBlock[r.ID] {
					lastUseInBlock[r.ID] = blkLen
				}
			}
		}
		// BlockRet: archAMD64.EmitReturn / archARM64.EmitReturn
		// take the LAST k values of blk.Values (where k =
		// len(sig.Results)) as the return values to move into the
		// FP-relative result locations. Those values are "used"
		// at the terminator — exactly the same shape as
		// blk.Control above — so extend their lastUseInBlock to
		// blkLen. Without this, a return value that has no
		// in-block consumers gets released back to the pool the
		// moment it is defined; a later block's local picks up
		// the slot, and EmitReturn reads garbage.
		if blk.Kind == ssa.BlockRet {
			k := len(sig.Results)
			if k > 0 && k <= blkLen {
				for j := blkLen - k; j < blkLen; j++ {
					rv := blk.Values[j]
					r := resolveSlotArg(rv, constsNeedSlot)
					if r == nil || crossBlock[r.ID] || defBlock[r.ID] != blk.ID {
						continue
					}
					if blkLen > lastUseInBlock[r.ID] {
						lastUseInBlock[r.ID] = blkLen
					}
				}
			}
		}

		var active []activeSlot
		for i, v := range blk.Values {
			size, align := slotSize(v.Type)
			if size == 0 {
				continue
			}
			// Release any block-local slot whose lifetime ended
			// strictly before this index.
			if len(active) > 0 {
				keep := active[:0]
				for _, e := range active {
					if e.expiresAt < i {
						pool[e.key] = append(pool[e.key], e.offset)
					} else {
						keep = append(keep, e)
					}
				}
				active = keep
			}
			key := slotKey{size: size, align: align}
			// Slot reuse covers only op classes whose
			// lifetime my use-def walk can compute precisely.
			// The bisect against the full downstream test
			// suite localised three sources of missed use sites:
			//
			//   - OpPhi:  predecessor edge-copies write the slot
			//             at terminator time, which the
			//             "lastUseInBlock counts v.Args in own
			//             block" model misses for the destination
			//             phi itself.
			//   - OpHelperCall result: the helper return may be
			//             consumed through OpCopy chains that
			//             cross block boundaries in ways
			//             resolveSlotArg's single-block walk does
			//             not catch.
			//   - OpLoad* / OpStore*: wasm-memory operations
			//             surface addresses whose consumers (the
			//             arithmetic feeding the next load /
			//             store) are sometimes in different
			//             blocks, again past the same-block
			//             analysis. Bisect bullet: enabling
			//             OpLoad reuse alone triggers SIGSEGV in
			//             a catalog-init helper
			//             (Fn18584 → bad m.M index); enabling
			//             OpStore alone hangs an inner scan in
			//             p8.Fn39813 (loop variable shares a
			//             slot with the byte-test temp).
			//   - 8-byte slots (i64 / f64): the NUMERIC /
			//             BIGNUMERIC arithmetic in TestQuery
			//             produces wrong digits when i64-typed
			//             ops participate in reuse. The same
			//             same-block lifetime model that handles
			//             i32 correctly mis-tracks an i64 value
			//             somewhere in the multi-word add /
			//             mul / shr chain, but the specific
			//             miss site is not yet isolated. Pinning
			//             size >= 8 slots to dedicated offsets
			//             dodges the corruption without giving up
			//             the i32 reuse, which is where the bulk
			//             of the frame-size win sits anyway.
			//   - OpCall* / OpGlobal* / OpMem*: same kind of
			//             cross-block-via-helper aliasing as
			//             OpHelperCall.
			//
			// What remains eligible: pure-arithmetic and bit ops
			// at i32 width (Add / Sub / Mul / Div / And / Or /
			// Xor / Shl / Shr / Eq / Ne / Lt / Le / Extend32To32
			// / TruncTo32 / Const32). The self-loop phi back-edge
			// arg fix below (recording phi.Args[i] uses at blkLen
			// for args defined in this same block) is required
			// for even this subset to be correct — without it
			// the loop-carried scalar in a self-loop dies the
			// instant it is written.
			// Slot reuse — eligibility per op class.
			// The list below excludes op classes whose downstream
			// uses the lifetime model can't track precisely. amd64
			// reaches this with most i32 arithmetic enabled. arm64
			// adds extra exclusions in `arm64ReuseUnsafe` because
			// its per-op emit reads operands from slots in cases
			// where amd64 inlines them (no large-imm ALU on arm64).
			opEligible := true
			switch v.Op {
			// OpParam: FP-resident normally (slot unread), but the
			// packed prologue writes the slot and every read uses it;
			// reuse would clobber the parameter. Dedicated always.
			case ssa.OpParam:
				opEligible = false
			case ssa.OpPhi, ssa.OpHelperCall,
				ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
				ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
				ssa.OpLoadF32, ssa.OpLoadF64,
				ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
				ssa.OpStoreF32, ssa.OpStoreF64,
				ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
				ssa.OpGlobalGet, ssa.OpGlobalSet,
				ssa.OpMemSize, ssa.OpMemGrow,
				ssa.OpMemoryCopy, ssa.OpMemoryFill:
				opEligible = false
			}
			if size >= 8 {
				opEligible = false
			}
			if constsNeedSlot && arm64ReuseUnsafe(v.Op) {
				opEligible = false
			}
			if crossBlock[v.ID] || !opEligible {
				off = alignUp(off, align)
				p.offsets[v.ID] = off
				off += size
				continue
			}
			// Block-local: try the pool first.
			if free := pool[key]; len(free) > 0 {
				n := len(free) - 1
				p.offsets[v.ID] = free[n]
				pool[key] = free[:n]
			} else {
				off = alignUp(off, align)
				p.offsets[v.ID] = off
				off += size
			}
			expires := lastUseInBlock[v.ID]
			if expires < i {
				// Unused value (no consumers); slot is dead the
				// moment it is written. Releasing now keeps the
				// pool tight without the active list churn.
				pool[key] = append(pool[key], p.offsets[v.ID])
				continue
			}
			active = append(active, activeSlot{
				vid:       v.ID,
				expiresAt: expires,
				key:       key,
				offset:    p.offsets[v.ID],
			})
		}
		// End of block: every still-active block-local value's
		// lifetime is over (it cannot be referenced outside its
		// def block by construction).
		for _, e := range active {
			pool[e.key] = append(pool[e.key], e.offset)
		}
	}

	// Pass 3: phi index + staged-phi analysis.
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if v.Op == ssa.OpPhi {
				p.phisOf[blk.ID] = append(p.phisOf[blk.ID], v)
				p.hasPhi[blk.ID] = true
			}
		}
	}
	staged := emit.ComputeStagedPhis(f, hoist)
	for _, blk := range f.Blocks {
		for _, phi := range p.phisOf[blk.ID] {
			if !staged[phi.ID] {
				continue
			}
			p.staged[blk.ID] = true
			size, align := slotSize(phi.Type)
			if size == 0 {
				continue
			}
			off = alignUp(off, align)
			p.phiTemp[phi.ID] = off
			off += size
		}
	}

	// Pass 4: branch-fusion. When a value is consumed solely as a
	// BlockIf control, the SET<cc> + MOVBLZX + slot store + slot
	// reload + TEST + JCC chain (5–6 instructions) collapses to a
	// single direct conditional branch — the comparison's flags
	// are still live at the branch point, so we can JCC straight
	// off them. Candidate ops:
	//
	//   OpHelperCall("i32_eqz" / "i64_eqz") — TEST → JE
	//   OpEq{32,64}, OpNe{32,64}            — CMP → JE / JNE
	//   OpLtS / OpLeS / OpLtU / OpLeU       — CMP → JLT / JLE / JCS / JLS
	//
	// branchFusedKind[v.ID] is a stable identifier per fused
	// flavour — eqz helpers reuse the helper name as-is; for the
	// SSA comparison ops we use a parallel "i{32,64}_<rel>" naming
	// so each arch's EmitIfBranch can translate one map to its
	// native mnemonics. Detection runs once here so the emitters
	// stay simple lookups.
	for _, blk := range f.Blocks {
		if blk.Kind != ssa.BlockIf || blk.Control == nil {
			continue
		}
		cond := blk.Control
		if usage[cond.ID] != 1 {
			continue
		}
		var kind string
		switch cond.Op {
		case ssa.OpHelperCall:
			name, _ := cond.Aux.(string)
			if name == "i32_eqz" || name == "i64_eqz" {
				kind = name
			}
		case ssa.OpEq32:
			kind = "i32_eq"
		case ssa.OpNe32:
			kind = "i32_ne"
		case ssa.OpLtS32:
			kind = "i32_lt_s"
		case ssa.OpLtU32:
			kind = "i32_lt_u"
		case ssa.OpLeS32:
			kind = "i32_le_s"
		case ssa.OpLeU32:
			kind = "i32_le_u"
		case ssa.OpEq64:
			kind = "i64_eq"
		case ssa.OpNe64:
			kind = "i64_ne"
		case ssa.OpLtS64:
			kind = "i64_lt_s"
		case ssa.OpLtU64:
			kind = "i64_lt_u"
		case ssa.OpLeS64:
			kind = "i64_le_s"
		case ssa.OpLeU64:
			kind = "i64_le_u"
		}
		// Single-bit BTL/BTQ fusion. Two shapes match:
		//
		//  (a) cond is OpEq/OpNe against zero, other arg is
		//      OpAnd<W>(x, const_pow2) — explicit `(x & K) <op> 0`.
		//  (b) cond is OpAnd<W>(x, const_pow2) directly, and the
		//      BlockIf treats the value as a boolean ("non-zero").
		//      This is the wasm-lowering shape for `if x & K {...}`:
		//      no explicit OpNe/OpEq, the And's result IS the cond.
		//
		// Both collapse to
		//
		//   BTL $k, x ; JCC <label>   ; "bit is clear"
		//   BTL $k, x ; JCS <label>   ; "bit is set"
		//
		// (and the matching BTQ / TBZ-style mnemonic on arm64).
		// Dropping the AND's emit AND replacing the comparison's
		// SET<cc>+TEST+JCC+JMP with the two-op BTL sequence saves
		// ~4–6 instructions per occurrence.
		if kind == "" {
			// Shape (b) — fall through to the bit-test detection
			// below. We do NOT set branchFused here because we may
			// reject the bit-test pattern and need the default
			// BlockIf emit (which reads the cond's slot) to fire.
		} else {
			p.branchFused[cond.ID] = true
			p.branchFusedKind[cond.ID] = kind
		}
		var andVal *ssa.Value
		var is64 bool
		var wantEq bool
		switch kind {
		case "i32_eq", "i32_ne", "i64_eq", "i64_ne":
			if len(cond.Args) != 2 {
				continue
			}
			andArg, zeroArg := cond.Args[0], cond.Args[1]
			if !isZeroConst(zeroArg) {
				if isZeroConst(andArg) {
					andArg, zeroArg = cond.Args[1], cond.Args[0]
				} else {
					continue
				}
			}
			_ = zeroArg
			andVal = resolveCopy(andArg)
			is64 = kind == "i64_eq" || kind == "i64_ne"
			wantEq = kind == "i32_eq" || kind == "i64_eq"
		case "":
			// Direct shape (b): the cond IS the And. usage[cond] == 1
			// is already guaranteed by the outer check.
			switch cond.Op {
			case ssa.OpAnd32:
				andVal = cond
				is64 = false
				wantEq = false
			case ssa.OpAnd64:
				andVal = cond
				is64 = true
				wantEq = false
			default:
				continue
			}
		default:
			continue
		}
		if andVal == nil {
			continue
		}
		if (is64 && andVal.Op != ssa.OpAnd64) || (!is64 && andVal.Op != ssa.OpAnd32) {
			continue
		}
		// For shape (a) the And's only user is the cond; for shape
		// (b) the And IS the cond, and `usage[cond.ID] == 1` was
		// already enforced. Both cases require the same check.
		if usage[andVal.ID] != 1 {
			continue
		}
		if len(andVal.Args) != 2 {
			continue
		}
		base, mask := andVal.Args[0], andVal.Args[1]
		bit, ok := powerOfTwoBit(mask, is64)
		if !ok {
			base, mask = andVal.Args[1], andVal.Args[0]
			bit, ok = powerOfTwoBit(mask, is64)
			if !ok {
				continue
			}
		}
		newKind := "i32_bittest_ne"
		if is64 {
			newKind = "i64_bittest_ne"
		}
		if wantEq {
			newKind = "i32_bittest_eq"
			if is64 {
				newKind = "i64_bittest_eq"
			}
		}
		// Shape (a): cond.ID already in branchFused; rewrite kind
		// and add the And to branchFusedSkip. Shape (b): cond IS
		// the And; add both branchFused entries and the bit info.
		p.branchFused[cond.ID] = true
		p.branchFusedKind[cond.ID] = newKind
		if cond != andVal {
			p.branchFusedSkip[andVal.ID] = true
		}
		// Note: for shape (b) we don't set branchFusedSkip on the
		// And because cond == andVal and emit already short-circuits
		// when branchFused[cond.ID] is true at the helper-call /
		// comparison emit site... but OpAnd32's emit DOESN'T check
		// branchFused. We need the branchFusedSkip entry on cond
		// in shape (b) so emitBlock's loop skips it.
		p.branchFusedSkip[cond.ID] = true
		if p.branchFusedBit == nil {
			p.branchFusedBit = map[ssa.ValueID]bitTestInfo{}
		}
		p.branchFusedBit[cond.ID] = bitTestInfo{base: base, bit: bit}
	}

	// Pad to 8-byte alignment so the callee-side prologue's SP is
	// aligned to the platform's stack-alignment expectation.
	off = alignUp(off, 8)
	p.frameSize = off

	// Decide whether to keep `m` in a register across the
	// function lifetime. Pure-Go does this by virtue of the Go
	// compiler's regalloc — every `m.G0` / `m.M` / `m.someField`
	// access dereferences AX (or whichever GPR holds the receiver)
	// in a single instruction. The asm bundle previously read
	// `m+0(FP)` from the arg slot at every memop / global access /
	// direct-call arg-staging site, costing one redundant memory
	// load per use. Caching `m` in a function-wide reserved
	// register (R11) collapses that to a register move and a single
	// post-CALL refresh.
	//
	// Eligibility: the function must touch `m` enough times to
	// amortise the prologue load + per-CALL refresh. Concretely we
	// require either a memop (always needs m to deref m.M) or at
	// least one direct-call site (the staged m at SP+0 is the most
	// common use). Helper-only / pure-arithmetic leaves stay unset
	// — for them the optimisation is dead weight.
	wantsMCache := p.hasMem
	if !wantsMCache {
		for _, blk := range f.Blocks {
			for _, v := range blk.Values {
				switch v.Op {
				case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect,
					ssa.OpGlobalGet, ssa.OpGlobalSet,
					ssa.OpMemSize, ssa.OpMemGrow,
					ssa.OpMemoryCopy, ssa.OpMemoryFill:
					wantsMCache = true
				}
				if wantsMCache {
					break
				}
			}
			if wantsMCache {
				break
			}
		}
	}
	// Record the candidacy on the plan; emitFunc decides whether to
	// actually populate mCacheReg per-arch (only amd64 currently
	// implements the use side — arm64 emit code still reads
	// `m+0(FP)` everywhere, and a non-empty mCacheReg would have
	// the prologue emit `MOVQ ..., R11` which arm64 rejects).
	p.mCacheCandidate = wantsMCache

	// computeRegHomes is intentionally deferred to emitFunc — the
	// arch instance is the gate for block-local regalloc, and only
	// archAMD64.SupportsRegHome currently returns true. Running it
	// here unconditionally would assign amd64-named registers
	// (X2..X7 etc.) that the arm64 operandSrcFloat helper would
	// then emit verbatim into arm64 asm, which the assembler
	// rejects.

	// Detect SSA values whose result has zero downstream
	// consumers. The asm emitter currently follows every CALL with a
	// `MOVL retOff(SP), AX; MOVL AX, dstOff(SP)` pair to land the
	// return value in the producing value's slot — but on call sites
	// like `if v != 0 { _ = Fn31236(m, v) }` the slot is never read
	// and both moves are dead. Pure-Go's compiler drops them entirely.
	//
	// "Used" here means: at least one other value's Args (after
	// OpCopy resolution), at least one block.Control, or one of the
	// BlockRet output positions references this value. Anything else
	// can have its return-value store elided. We currently only
	// honour the flag for OpCall{Direct,Import,Indirect} and
	// OpHelperCall — the OpGlobalGet / OpMemSize / OpMemGrow emit
	// paths might use it later but their result load is wrapped in
	// other state that's not worth touching for the same pass.
	computeUnusedResults(f, p, sig)

	return p, nil
}

// computeUnusedResults populates plan.unusedResult — CALL-class
// values whose result has zero LIVE downstream consumers.
//
// A naive "any other value references me" check is wrong for the
// wasm-to-SSA shape: every wasm `local.set N` after a `call` becomes
// an OpCopy of the CALL result into local N's wire, which keeps the
// CALL "used" even when local N itself is never read. To handle that
// we run a proper liveness pass:
//
//  1. Seed `live` with sinks — side-effecting ops (CALLs are seeds
//     here so they STAY in the asm even if their result is unused;
//     OpStore* / OpGlobalSet / OpMem*; etc.), block.Control values,
//     and the BlockRet output positions.
//  2. Propagate backward through Args (resolving OpCopy chains so the
//     producer is what becomes live, not the alias). A value is live
//     iff at least one live consumer chains back to it.
//  3. For each CALL V, ask "does any LIVE value other than V reference
//     V?". If not, V's result has no real consumer — Pure-Go drops
//     the readback and so do we. Note V itself is always live (it's
//     a side-effecting seed); what we test is whether V's RESULT
//     reaches a real use.
//
// Non-CALL ops are deliberately left alone — their result store is
// already covered by slot-reuse and frame-compaction passes and the
// emit-time savings are smaller than the cost of widening the rule
// to every emitter site.
func computeUnusedResults(f *ssa.Func, p *funcPlan, sig wasm.FuncType) {
	resolveCopy := func(v *ssa.Value) *ssa.Value {
		for hop := 0; v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 && hop < 16; hop++ {
			if v.Args[0] == v {
				break
			}
			v = v.Args[0]
		}
		return v
	}
	// Build a value-by-ID index so the backward walk can find a value
	// by its producer ID without re-scanning the function each step.
	byID := map[ssa.ValueID]*ssa.Value{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			byID[v.ID] = v
		}
	}
	live := map[ssa.ValueID]bool{}
	var worklist []ssa.ValueID
	mark := func(id ssa.ValueID) {
		if !live[id] {
			live[id] = true
			worklist = append(worklist, id)
		}
	}
	// Step 1: seed sinks.
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if isSideEffectingOp(v.Op) {
				mark(v.ID)
			}
		}
		if blk.Control != nil {
			if r := resolveCopy(blk.Control); r != nil {
				mark(r.ID)
			}
		}
	}
	k := len(sig.Results)
	for _, blk := range f.Blocks {
		if blk.Kind != ssa.BlockRet {
			continue
		}
		n := len(blk.Values)
		if k == 0 || k > n {
			continue
		}
		for j := n - k; j < n; j++ {
			if r := resolveCopy(blk.Values[j]); r != nil {
				mark(r.ID)
			}
		}
	}
	// Step 2: backward propagate.
	for len(worklist) > 0 {
		id := worklist[0]
		worklist = worklist[1:]
		v := byID[id]
		if v == nil {
			continue
		}
		for _, arg := range v.Args {
			if arg == nil {
				continue
			}
			if r := resolveCopy(arg); r != nil {
				mark(r.ID)
			}
		}
	}
	// Step 3: a CALL value's result is unused iff no LIVE value
	// (other than the CALL itself, which is live as a sink)
	// references it through its Args / Control / BlockRet outputs.
	// We compute hasLiveConsumer by re-walking the live set and
	// noting every Arg they touch.
	hasLiveConsumer := map[ssa.ValueID]bool{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			if !live[v.ID] {
				continue
			}
			for _, arg := range v.Args {
				if arg == nil {
					continue
				}
				if r := resolveCopy(arg); r != nil && r.ID != v.ID {
					hasLiveConsumer[r.ID] = true
				}
			}
		}
		if blk.Control != nil {
			if r := resolveCopy(blk.Control); r != nil {
				hasLiveConsumer[r.ID] = true
			}
		}
	}
	for _, blk := range f.Blocks {
		if blk.Kind != ssa.BlockRet {
			continue
		}
		n := len(blk.Values)
		if k == 0 || k > n {
			continue
		}
		for j := n - k; j < n; j++ {
			if r := resolveCopy(blk.Values[j]); r != nil {
				hasLiveConsumer[r.ID] = true
			}
		}
	}
	calls, dead := 0, 0
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			switch v.Op {
			case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpHelperCall:
			default:
				continue
			}
			calls++
			if hasLiveConsumer[v.ID] {
				continue
			}
			p.unusedResult[v.ID] = true
			dead++
		}
	}
	_ = calls
	_ = dead
}

// isSideEffectingOp reports whether an SSA op has externally visible
// side effects that pin it in the program even when its result has no
// downstream consumer. Used by computeUnusedResults as the seed set
// for liveness — these ops are "always live" and propagate liveness
// to their args, so a chain of OpCopy aliases that terminates only at
// a dead local.set still leaves the producer CALL marked live.
func isSideEffectingOp(op ssa.Op) bool {
	switch op {
	case ssa.OpCallDirect, ssa.OpCallImport, ssa.OpCallIndirect, ssa.OpHelperCall,
		ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpStoreF32, ssa.OpStoreF64,
		ssa.OpGlobalSet,
		ssa.OpMemoryCopy, ssa.OpMemoryFill, ssa.OpMemGrow:
		return true
	}
	return false
}

// capitalizeHelperName matches codegen's helper-name capitalisation
// for multi-package emission: lowercase first letter becomes
// uppercase; names already exported pass through. Used to spell the
// asm CALL target for codegen-emitted helpers like
// `base·MemorySize(SB)`.
func capitalizeHelperName(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
		return string(r)
	}
	return s
}

// wrapperSymbol renders the asm CALL target for one of the
// asmgen-emitted dispatch wrappers (callImport_N, callIndirect_typeN,
// loadGlobal_N, storeGlobal_N). Every chunk now carries its own copy
// of these wrappers (see BuildPackageOptions.SkipWrappers), so the
// CALL is always a same-package `·name(SB)` reference. Plan9 asm
// can't CALL a function in another Go package directly — the
// linker rejects the relocation — and the wrappers are tiny
// enough that per-chunk duplication is cheaper than the alternative.
func wrapperSymbol(helperPfx, name string) string {
	_ = helperPfx
	return fmt.Sprintf("·%s(SB)", name)
}

// goAsmSymbol renders a plan9 asm symbol from a Go-side qualified
// name. "Fn42" (same-package) becomes "·Fn42(SB)"; "base.Fn42"
// (single-name cross-package) becomes "base·Fn42(SB)";
// "github.com/foo/bar.Fn42" (full import path) becomes
// "github·com∕foo∕bar·Fn42(SB)".
//
// The remapping is forced by two pieces of the plan 9 asm lexer:
//
//   - src/cmd/asm/internal/lex/tokenizer.go: isIdentRune accepts
//     only unicode.IsLetter, digits (after position 0), '_',
//     U+00B7 ("·"), and U+2215 ("∕") as identifier runes. The
//     ASCII "/" is reserved as the division operator and ASCII
//     "." is reserved for offset / displacement syntax, so they
//     cannot appear directly in a symbol-reference token.
//
//   - src/cmd/asm/internal/lex/lex.go: lex.Make post-processes
//     every identifier token by `strings.ReplaceAll`-ing "·" back
//     to "." and "∕" back to "/", so the symbol name the linker
//     finally sees is the canonical Go form
//     (e.g. "github.com/foo/bar.Fn42"). The Unicode runes are
//     purely a source-level escape, not a separate name space.
//
// Together those two passes give the lexer exactly one way to
// embed a "/" or "." inside a symbol operand — the U+00B7 /
// U+2215 substitution we apply here. Any other punctuation that
// Go module paths permit ("-", "+", "~", ...) has no plan 9
// counterpart, which is why the asm-CALL optimization in
// asm_bundle.go is gated behind isPlan9AsmSafe and falls back to
// the per-chunk Go-body wrapper for hyphenated host paths
// (see asm_bundle.go's comment on buildAsmFilesMultiChunk).
//
// The split between package and symbol uses the LAST dot, which
// is the only dot that can legitimately separate path from symbol
// — any earlier dots are part of a path component such as
// "github.com".
func goAsmSymbol(qualified string) string {
	if i := strings.LastIndexByte(qualified, '.'); i >= 0 {
		pkg := qualified[:i]
		pkg = strings.ReplaceAll(pkg, "/", "∕")
		pkg = strings.ReplaceAll(pkg, ".", "·")
		return fmt.Sprintf("%s·%s(SB)", pkg, qualified[i+1:])
	}
	return fmt.Sprintf("·%s(SB)", qualified)
}

// ComputeGlobalOffsets returns the byte offsets of each WASM global
// field within the Module struct. The slice is indexed by the WASM
// global index (mod.NumImportedGlobals + i for the i-th defined
// global). Imported globals receive a -1 sentinel because the Module
// struct never carries them — they live behind the host iface and
// keep the CALL path.
//
// The layout mirrors codegen.translator.emitModuleStruct exactly:
// Memory []byte (24) + MaxMem uint64 (8) + M unsafe.Pointer (8) when
// the module has memories, then 24 bytes per Table ([]any slice
// header), then each defined global in the order it appears in
// mod.Globals, aligned to its Go type's natural alignment.
func ComputeGlobalOffsets(mod *wasm.Module) []int {
	off := 0
	if len(mod.Memories) > 0 {
		off += 24 // Memory []byte slice header (data, len, cap on amd64/arm64)
		off += 8  // MaxMem uint64
		off += 8  // M unsafe.Pointer
	}
	off += 24 * len(mod.Tables) // T_i []any per table
	n := int(mod.NumImportedGlobals) + len(mod.Globals)
	offs := make([]int, n)
	for i := 0; i < int(mod.NumImportedGlobals); i++ {
		offs[i] = -1
	}
	for i, g := range mod.Globals {
		a, s := goTypeSizeAlign(g.Type.Type)
		off = (off + a - 1) &^ (a - 1)
		offs[int(mod.NumImportedGlobals)+i] = off
		off += s
	}
	return offs
}

// goTypeSizeAlign returns the Go-side (align, size) of the
// generated Module field for a WASM value type.
func goTypeSizeAlign(t wasm.ValType) (align, size int) {
	switch t {
	case wasm.ValI32, wasm.ValF32:
		return 4, 4
	case wasm.ValI64, wasm.ValF64:
		return 8, 8
	}
	return 8, 8
}

// globalValType returns the wasm value type of the global at the
// given module-level global index, accounting for imported globals.
// The lookup matches FuncTypeOf's pattern: walk imports counting
// ImportGlobal entries, then fall through to the defined-globals
// slice for indices beyond the imported range.
func globalValType(mod *wasm.Module, idx uint32) (wasm.ValType, error) {
	if idx < mod.NumImportedGlobals {
		var i uint32
		for _, imp := range mod.Imports {
			if imp.Kind != wasm.ImportGlobal {
				continue
			}
			if i == idx {
				return imp.Global.Type, nil
			}
			i++
		}
		return 0, fmt.Errorf("imported global %d not found", idx)
	}
	local := idx - mod.NumImportedGlobals
	if local >= uint32(len(mod.Globals)) {
		return 0, fmt.Errorf("global %d out of range (have %d)", idx, len(mod.Globals))
	}
	return mod.Globals[local].Type.Type, nil
}

// slotSize returns (size, alignment) for an SSA value type, or
// (0, 1) for non-storable kinds (Mem state token, Tuple, Invalid).
func slotSize(t ssa.Type) (int, int) {
	switch t {
	case ssa.TypeI32, ssa.TypeF32, ssa.TypeBool:
		return 4, 4
	case ssa.TypeI64, ssa.TypeF64:
		return 8, 8
	case ssa.TypeV128:
		// [2]uint64 pair; 8-byte alignment matches the Go-side value.
		return 16, 8
	}
	return 0, 1
}
