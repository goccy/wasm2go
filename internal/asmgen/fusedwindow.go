package asmgen

// Fused-window planning for direct-asm bodies.
//
// The codegen fusion pass claims whole trees of SIMD ops and, in the
// pure output, replaces them with one synthetic helper call whose
// splice keeps every internal edge in vector registers. The retained
// SSA still carries the raw per-op stream; FuncOptions.Windows names
// each claimed region (members, roots, parameter sources) so this
// pass can emit the SAME fused body the gc path gets — one bounds
// check per window, no per-op slot round-trips — instead of per-op
// splices.
//
// Validation is strict and every failure is a quiet per-op fallback,
// never an error: the per-op path is correct, just slower.

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
	"github.com/goccy/wasm2go/internal/ssa"
)

// fusedWinDebug gates plan-time reject diagnostics (stderr), for
// coverage work on real modules where a silent per-op fallback and a
// fused window are indistinguishable in the output values.
var fusedWinDebug = os.Getenv("WASM2GO_FUSEDWIN_DEBUG") != ""

// plannedFusedWindow is one validated window, resolved to emission
// terms: operands in fused-signature order and the roots' value IDs
// (their slots come from plan.offsets at emit time).
type plannedFusedWindow struct {
	win     *FusedWindow
	scalars []FusedOperand
	floats  []FusedOperand
	pairs   []FusedOperand
	roots   []ssa.ValueID
}

// planFusedWindows validates each descriptor against the plan's slot
// map and records the emission index. Called after Pass 2 (slots
// assigned) so operand resolution can use plan.offsets.
func (p *funcPlan) planFusedWindows(f *ssa.Func, windows []FusedWindow, frame argFrame) {
	if len(windows) == 0 {
		return
	}
	// Value ID -> defining block and in-block position, for the
	// membership and ordering checks.
	blockOf := map[ssa.ValueID]ssa.BlockID{}
	posOf := map[ssa.ValueID]int{}
	blockValues := map[ssa.BlockID][]*ssa.Value{}
	consumers := map[ssa.ValueID]int{}
	for _, blk := range f.Blocks {
		blockValues[blk.ID] = blk.Values
		for i, v := range blk.Values {
			blockOf[v.ID] = blk.ID
			posOf[v.ID] = i
			for _, a := range v.Args {
				if a != nil {
					consumers[a.ID]++
				}
			}
		}
		if blk.Control != nil {
			consumers[blk.Control.ID]++
		}
	}
	for i := range windows {
		w := &windows[i]
		pw, last, ok := p.resolveFusedWindow(w, blockOf, posOf, blockValues, consumers, frame)
		if !ok && fusedWinDebug {
			fmt.Fprintf(os.Stderr, "wasm2go: fused window %s in %s: plan reject: %s\n", w.Tree.Name, f.Name, p.fusedRejectWhy)
		}
		if ok {
			if p.fusedAt == nil {
				p.fusedAt = map[ssa.ValueID]*plannedFusedWindow{}
				p.fusedMember = map[ssa.ValueID]bool{}
			}
			p.fusedAt[last] = pw
			for _, m := range w.Members {
				p.fusedMember[m.ID] = true
			}
		}
	}
}

// resolveFusedWindow checks one descriptor and resolves its operands.
// The returned value ID is the window's LAST member: the whole body
// emits there, so every input value defined between the members has
// already been materialized; earlier members emit nothing.
func (p *funcPlan) resolveFusedWindow(w *FusedWindow, blockOf map[ssa.ValueID]ssa.BlockID, posOf map[ssa.ValueID]int, blockValues map[ssa.BlockID][]*ssa.Value, consumers map[ssa.ValueID]int, frame argFrame) (*plannedFusedWindow, ssa.ValueID, bool) {
	p.fusedRejectWhy = ""
	reject := func(why string) (*plannedFusedWindow, ssa.ValueID, bool) {
		p.fusedRejectWhy = why
		return nil, 0, false
	}
	if w.Tree == nil || len(w.Members) == 0 {
		return reject("empty descriptor")
	}
	// Every member must live in one block, and no member may already
	// belong to another planned window (identical trees repeat; the
	// first claim wins and later duplicates must not double-plan).
	blk, ok := blockOf[w.Members[0].ID]
	if !ok {
		return reject("first member not in the SSA")
	}
	isRoot := map[ssa.ValueID]bool{}
	for _, r := range w.Roots {
		if r == nil {
			return reject("nil root")
		}
		isRoot[r.ID] = true
	}
	memberSet := map[ssa.ValueID]bool{}
	first, last := -1, -1
	var lastID ssa.ValueID
	for _, m := range w.Members {
		if m == nil || blockOf[m.ID] != blk || p.fusedMember[m.ID] {
			return reject("member outside the block or already claimed")
		}
		memberSet[m.ID] = true
		pos := posOf[m.ID]
		if first < 0 || pos < first {
			first = pos
		}
		if pos > last {
			last = pos
			lastID = m.ID
		}
	}
	// Values interleaved between the members must be safe to ORDER
	// BEFORE the whole window (emission defers the window to its last
	// member): pure scalar glue always is, and plain scalar LOADS are
	// when the window writes no memory — the codegen fusion proved
	// exactly this hoist when it claimed the region past them. Any
	// store, call, SIMD op, or read of a root rejects the window.
	windowStores := false
	for _, n := range w.Tree.Nodes {
		if simdfuse.IsStore(n.Op) {
			windowStores = true
		}
	}
	for _, v := range blockValues[blk][first : last+1] {
		if memberSet[v.ID] {
			continue
		}
		switch v.Op {
		case ssa.OpSimdCall, ssa.OpSimdMemCall:
			return reject(fmt.Sprintf("interleaved SIMD op %v", v.Op))
		case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
			ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
			ssa.OpLoadF32, ssa.OpLoadF64:
			if windowStores {
				return reject(fmt.Sprintf("interleaved load %v across a storing window", v.Op))
			}
			continue
		}
		if isSideEffectingOp(v.Op) || opEmitsCall(v.Op) {
			return reject(fmt.Sprintf("interleaved effectful op %v", v.Op))
		}
		for _, a := range v.Args {
			if a != nil && isRoot[a.ID] {
				return reject("interleaved read of a root")
			}
		}
	}
	// Non-root members must be consumed ONLY inside the window: the
	// fused body never materializes them, so an outside reader (a
	// pass moved something since fusion claimed the region) would
	// read a stale slot. Count in-window argument references and
	// compare against the total consumer count.
	inWindow := map[ssa.ValueID]int{}
	for _, m := range w.Members {
		for _, a := range m.Args {
			if a != nil && memberSet[a.ID] {
				inWindow[a.ID]++
			}
		}
	}
	for _, m := range w.Members {
		if isRoot[m.ID] {
			continue
		}
		if consumers[m.ID] != inWindow[m.ID] {
			return reject(fmt.Sprintf("non-root member v%d consumed outside the window", m.ID))
		}
	}
	pw := &plannedFusedWindow{win: w}
	resolve := func(srcs []FusedParamSrc, pair bool) ([]FusedOperand, bool) {
		out := make([]FusedOperand, 0, len(srcs))
		for _, s := range srcs {
			if s.IsConst {
				out = append(out, FusedOperand{IsConst: true, Const: s.Const})
				continue
			}
			if s.Val == nil || s.ArgIdx < 0 || s.ArgIdx >= len(s.Val.Args) || s.Val.Args[s.ArgIdx] == nil {
				return nil, false
			}
			arg := resolveSlotValue(s.Val.Args[s.ArgIdx])
			wide := pair || w.Tree.Addr64
			if arg.Op == ssa.OpParam && !p.packed {
				// Unpacked parameters are FP-resident: their RSP slots
				// exist but are never written. Read the argument frame,
				// exactly like the per-op operand resolvers. v128
				// parameters never reach a pair source (fusion pairs
				// come from SIMD producers), so a pair here rejects.
				idx := int(arg.AuxInt)
				if pair || idx < 0 || idx >= len(frame.paramOffsets) {
					return nil, false
				}
				out = append(out, FusedOperand{Wide: wide, FPRef: fmt.Sprintf("l%d+%d(FP)", idx, frame.paramOffsets[idx])})
				continue
			}
			// Everything else must have a materialized slot the
			// staging can read.
			off, ok := p.offsets[arg.ID]
			if !ok {
				return nil, false
			}
			out = append(out, FusedOperand{SlotOff: off, Wide: wide})
		}
		return out, true
	}
	var ok2 bool
	if pw.scalars, ok2 = resolve(w.ScalarSrc, false); !ok2 {
		return reject("unresolvable scalar operand")
	}
	if pw.floats, ok2 = resolve(w.FloatSrc, false); !ok2 {
		return reject("unresolvable float operand")
	}
	if pw.pairs, ok2 = resolve(w.PairSrc, true); !ok2 {
		return reject("unresolvable pair operand")
	}
	for _, r := range w.Roots {
		if _, ok := p.offsets[r.ID]; !ok {
			return reject("root without a slot")
		}
		pw.roots = append(pw.roots, r.ID)
	}
	return pw, lastID, true
}

// emitFusedWindowARM64 emits one validated window's whole body at its
// last member. A splicer decline here is a hard per-function error:
// earlier members already emitted nothing, so there is no correct
// per-op recovery mid-body — the bundle falls back to the listing
// transform for the whole function.
func emitFusedWindowARM64(b *strings.Builder, v *ssa.Value, pw *plannedFusedWindow, plan *funcPlan) error {
	fs, ok := plan.splicer.(FusedSplicer)
	if !ok {
		return fmt.Errorf("v%d: fused window %s planned without a FusedSplicer", v.ID, pw.win.Tree.Name)
	}
	rootSlots := make([][2]int, len(pw.roots))
	for i, id := range pw.roots {
		off := plan.offsets[id]
		rootSlots[i] = [2]int{off, off + 8}
	}
	const bias = 8 // archARM64.CallArgBias()
	spliced, wantsTrap := fs.SpliceFused(b, pw.win.Tree, pw.scalars, pw.floats, pw.pairs, rootSlots, bias)
	if !spliced {
		return fmt.Errorf("v%d: fused window %s declined by the splicer", v.ID, pw.win.Tree.Name)
	}
	if wantsTrap {
		plan.wantsTrapStub = true
	}
	return nil
}

// resolveSlotValue walks OpCopy chains to the value whose slot the
// operand resolvers would read.
func resolveSlotValue(v *ssa.Value) *ssa.Value {
	for i := 0; v.Op == ssa.OpCopy && len(v.Args) == 1 && v.Args[0] != nil && v.Args[0] != v && i < 16; i++ {
		v = v.Args[0]
	}
	return v
}
