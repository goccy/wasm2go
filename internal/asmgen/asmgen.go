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
	// EmitJmp emits an unconditional branch to the named label.
	EmitJmp(b *strings.Builder, label string)
	// EmitIfBranch tests cond for non-zero, branches to thenLabel
	// when set, else jumps to elseLabel.
	EmitIfBranch(b *strings.Builder, cond *ssa.Value, thenLabel, elseLabel string, plan *funcPlan, frame argFrame)
	// EmitReturn moves the function's K return values into their
	// FP-relative result locations, then RET.
	EmitReturn(b *strings.Builder, blk *ssa.Block, sig wasm.FuncType, plan *funcPlan, frame argFrame) error
	// EmitUnreachable emits a deliberate trap (UD2 / UNDEF).
	EmitUnreachable(b *strings.Builder)
	// EmitPhiCopyValue copies an SSA value into a phi destination
	// slot. Used on each predecessor's outgoing edge.
	EmitPhiCopyValue(b *strings.Builder, src *ssa.Value, dstOff int, t ssa.Type, plan *funcPlan, frame argFrame) error
	// EmitPhiCopySlot copies a staging slot into the real phi slot
	// during the second phase of a staged parallel copy.
	EmitPhiCopySlot(b *strings.Builder, srcOff, dstOff int, t ssa.Type) error
	// SkipValue reports whether the arch's operandSrc helpers handle
	// v inline at every consumer, so the materialise instruction in
	// EmitValue would write a slot nobody reads. amd64 returns true
	// for OpConst32/64 (every ALU instruction accepts a 32-bit imm);
	// arm64 returns false (no compact form to spell a 32-bit
	// immediate operand, so the slot must hold the constant).
	SkipValue(v *ssa.Value) bool
	// EmitMemMRefresh stores `*(m + moduleMOffset)` into the cached
	// m.M frame slot. Called once at the function prologue and
	// again after every CALL so the cache survives a callee that
	// triggered memory.grow.
	EmitMemMRefresh(b *strings.Builder, plan *funcPlan)
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

func emitFunc(name string, sig wasm.FuncType, f *ssa.Func, opts FuncOptions, a arch) (asm, goDecl string, err error) {
	frame, err := computeArgFrame(sig)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", name, err)
	}

	plan, err := planFunc(f, opts)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", name, err)
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
	// Prime the cached m.M slot for functions that touch wasm
	// memory. The emitter then drops the per-access two-MOVQ
	// preamble to a single load from this slot.
	if plan.memMSlot >= 0 {
		a.EmitMemMRefresh(&b, plan)
	}

	for _, blk := range f.Blocks {
		if err := emitBlock(&b, blk, f, plan, sig, frame, a); err != nil {
			return "", "", fmt.Errorf("%s: block %d: %w", name, blk.ID, err)
		}
	}

	goDecl = fmt.Sprintf("//go:noescape\nfunc %s%s\n", name, goSignature(sig, opts.ModulePkgRef))
	return peepholeOpt(b.String()), goDecl, nil
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
//        MOVL AX, 92(SP)
//        MOVL 92(SP), AX            ← redundant; value is in AX already
//     Variants: MOVQ, MOVL with any GP register, MOVSS / MOVSD with
//     SSE registers. The store stays; the reload is dropped.
//
//  2. amd64 `MOVL $imm, AX; ADDQ AX, BX` collapses to
//        LEAQ imm(BX), BX
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
			if combined, ok := peepholeLEAQ(prev, line); ok {
				out[n-1] = combined
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

// emitBlock emits one block: its label, its values, the phi
// edge-copies to each successor, and the terminator. The arch
// argument supplies the per-architecture asm strings.
func emitBlock(b *strings.Builder, blk *ssa.Block, f *ssa.Func, plan *funcPlan, sig wasm.FuncType, frame argFrame, a arch) error {
	fmt.Fprintf(b, "%s:\n", labelFor(blk))

	for _, v := range blk.Values {
		if v.Op == ssa.OpPhi {
			// Phi nodes are just slot placeholders; the copies are
			// emitted on the predecessor edges.
			continue
		}
		// OpParam/OpCopy values are inlined by operandSrc helpers on
		// every arch, so the materialise instruction would be dead
		// code. Skip emission and (in planFunc) slot allocation.
		if isInlineableOp(v.Op) {
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
		if err := a.EmitValue(b, v, plan, frame); err != nil {
			return fmt.Errorf("v%d (%s): %w", v.ID, v.Op, err)
		}
		// A callee can have triggered memory.grow which moves the
		// memory backing array and refreshes m.M on the Module —
		// so any CALL invalidates the cached m.M slot. Refresh
		// here unless this function never touches memory.
		if plan.memMSlot >= 0 && opEmitsCall(v.Op) {
			a.EmitMemMRefresh(b, plan)
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
		a.EmitJmp(b, labelFor(succ.Block))
	case ssa.BlockIf:
		if len(blk.Succs) != 2 || blk.Control == nil {
			return fmt.Errorf("BlockIf needs 2 successors and a Control value")
		}
		thenSucc := blk.Succs[0]
		elseSucc := blk.Succs[1]
		thenLabel := labelFor(thenSucc.Block)
		elseLabel := labelFor(elseSucc.Block)
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
			a.EmitIfBranch(b, blk.Control, thenLabel, elseLabel, plan, frame)
			break
		}
		// Insert intermediate labels for the branches that need phi
		// copies. The condition test branches to the intermediate,
		// which copies phis then jumps to the real successor.
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
		a.EmitIfBranch(b, blk.Control, thenJmp, elseJmp, plan, frame)
		if elseHasPhi {
			fmt.Fprintf(b, "%s:\n", elseInter)
			if err := emitPhiEdgeCopies(b, blk, elseSucc.Block, elseSucc.Index, plan, frame, a); err != nil {
				return err
			}
			a.EmitJmp(b, elseLabel)
		}
		if thenHasPhi {
			fmt.Fprintf(b, "%s:\n", thenInter)
			if err := emitPhiEdgeCopies(b, blk, thenSucc.Block, thenSucc.Index, plan, frame, a); err != nil {
				return err
			}
			a.EmitJmp(b, thenLabel)
		}
	case ssa.BlockRet:
		if err := a.EmitReturn(b, blk, sig, plan, frame); err != nil {
			return err
		}
	case ssa.BlockUnreachable:
		a.EmitUnreachable(b)
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
	// Phase 1: write each phi's incoming value to either the phi's
	// real slot (no staging needed) or to its staging slot.
	for _, phi := range plan.phisOf[succ.ID] {
		if predIdx >= len(phi.Args) {
			return fmt.Errorf("phi v%d in block %d has no arg for pred index %d", phi.ID, succ.ID, predIdx)
		}
		src := phi.Args[predIdx]
		if src == nil {
			return fmt.Errorf("phi v%d arg %d is nil", phi.ID, predIdx)
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
	// Phase 2: when staged, copy each temp into its phi's real slot.
	if staged {
		for _, phi := range plan.phisOf[succ.ID] {
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
		ssa.OpMemoryCopy, ssa.OpMemoryFill:
		return true
	}
	return false
}

// isInlineableOp temporarily returns false everywhere — bisecting
// the googlesqlite-wasm2go runtime SIGSEGV. With every value
// pinned to a real slot and emitted explicitly, the emitter
// matches the original slow-but-correct layout; if the crash
// persists, the optimisation tier is not the cause.
func isInlineableOp(op ssa.Op) bool {
	_ = op
	return false
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
	offsets    map[ssa.ValueID]int
	hoist      map[ssa.ValueID]bool
	phiTemp    map[ssa.ValueID]int
	phisOf     map[ssa.BlockID][]*ssa.Value
	hasPhi     map[ssa.BlockID]bool
	staged     map[ssa.BlockID]bool
	hasCall    bool
	frameSize  int
	calleeArea int // bytes reserved at low SP for callee-arg staging
	helperPfx  string
	helperRefs map[ssa.ValueID]string
	directs    map[ssa.ValueID]*directCall
	// memMSlot is the frame offset of an 8-byte stash for the
	// cached m.M pointer. Populated at function prologue and
	// refreshed after every CALL (in case the callee triggered
	// memory.grow which moves the memory backing array). -1 when
	// the function performs no memory accesses, so the slot can
	// be elided entirely.
	memMSlot int
	hasMem   bool
}

// planFunc walks f and builds the layout plan. The walk happens once
// up-front so emitValueAMD64 can stay a simple op-by-op switch with
// O(1) lookups.
func planFunc(f *ssa.Func, opts FuncOptions) (*funcPlan, error) {
	p := &funcPlan{
		offsets:    map[ssa.ValueID]int{},
		phiTemp:    map[ssa.ValueID]int{},
		phisOf:     map[ssa.BlockID][]*ssa.Value{},
		hasPhi:     map[ssa.BlockID]bool{},
		staged:     map[ssa.BlockID]bool{},
		helperPfx:  opts.HelperPrefix,
		helperRefs: map[ssa.ValueID]string{},
		directs:    map[ssa.ValueID]*directCall{},
	}

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
				ssa.OpStoreF32, ssa.OpStoreF64:
				p.hasMem = true
			}
			switch v.Op {
			case ssa.OpHelperCall:
				p.hasCall = true
				name, ok := v.Aux.(string)
				if !ok {
					return nil, fmt.Errorf("OpHelperCall v%d has non-string Aux", v.ID)
				}
				p.helperRefs[v.ID] = name
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
				calleeIdx := uint32(v.AuxInt)
				csig := opts.Module.FuncTypeOf(calleeIdx)
				cframe, err := computeArgFrame(csig)
				if err != nil {
					return nil, fmt.Errorf("OpCallDirect v%d: callee %d frame: %w", v.ID, calleeIdx, err)
				}
				var bareName string
				if opts.FuncSymbol != nil {
					bareName = opts.FuncSymbol(calleeIdx)
				} else {
					bareName = fmt.Sprintf("Fn%d", calleeIdx)
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
				sym := fmt.Sprintf("·%s(SB)", helperName)
				p.directs[v.ID] = &directCall{sig: csig, frame: cframe, symbol: sym}
				if cframe.argSize > maxCallee {
					maxCallee = cframe.argSize
				}
			case ssa.OpGlobalGet, ssa.OpGlobalSet:
				p.hasCall = true
				if opts.Module == nil {
					return nil, fmt.Errorf("%v v%d: FuncOptions.Module is required", v.Op, v.ID)
				}
				gtype, err := globalValType(opts.Module, uint32(v.AuxInt))
				if err != nil {
					return nil, fmt.Errorf("%v v%d: %w", v.Op, v.ID, err)
				}
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
	p.calleeArea = maxCallee

	// Pass 2: assign slot to every value. emit.ComputeHoist is
	// captured for the per-op emitter to use as a tie-breaker
	// (e.g., short-circuiting redundant materialisations) but the
	// slot map covers every storable scalar so any consumer can
	// safely read plan.offsets[v.ID]. operandSrc{32,64,Float} is
	// what shortens the binary-op MOV pair into one MOV + memory/
	// immediate operand — that win lands without touching slot
	// allocation.
	off := maxCallee
	usage := emit.ComputeValueUsage(f)
	hoist := emit.ComputeHoist(f, usage)
	p.hoist = hoist
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			size, align := slotSize(v.Type)
			if size == 0 {
				continue
			}
			// Skip slot allocation for ops that operandSrc inlines
			// at every consumer (Const/Param/Copy). Hoist[v.ID] for
			// these would have allocated a slot whose materialise-
			// write nobody reads. Removing it is the main asm-size
			// win — every multi-use OpConst32 stops emitting one
			// dead MOV.
			if isInlineableOp(v.Op) {
				continue
			}
			off = alignUp(off, align)
			p.offsets[v.ID] = off
			off += size
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

	// m.M cache was tried (one MOVQ saved per load/store) but
	// the conservative per-CALL refresh — required so memory.grow
	// inside a callee doesn't leave a stale pointer in the slot —
	// added 3 lines per CALL, overshooting the 1-line/access win
	// in practice. Disabled until a cheaper invalidation signal
	// (e.g. a per-function "transitively calls memory.grow" flag)
	// lets the refresh be skipped on the common path.
	p.memMSlot = -1
	_ = p.hasMem

	// Pad to 8-byte alignment so the callee-side prologue's SP is
	// aligned to the platform's stack-alignment expectation.
	off = alignUp(off, 8)
	p.frameSize = off
	return p, nil
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
// (cross-package, multi-package + linkname-split layout) becomes
// "base·Fn42(SB)". Plan9 syntax uses "·" between package and symbol
// where Go source uses ".".
func goAsmSymbol(qualified string) string {
	if i := strings.IndexByte(qualified, '.'); i >= 0 {
		return fmt.Sprintf("%s·%s(SB)", qualified[:i], qualified[i+1:])
	}
	return fmt.Sprintf("·%s(SB)", qualified)
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
	}
	return 0, 1
}
