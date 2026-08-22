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
	"github.com/goccy/wasm2go/internal/ssa"
)

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
func (p *funcPlan) planFusedWindows(f *ssa.Func, windows []FusedWindow) {
	if len(windows) == 0 {
		return
	}
	// Value ID -> defining block, for the same-block membership check.
	blockOf := map[ssa.ValueID]ssa.BlockID{}
	consumers := map[ssa.ValueID]int{}
	for _, blk := range f.Blocks {
		for _, v := range blk.Values {
			blockOf[v.ID] = blk.ID
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
		if pw, ok := p.resolveFusedWindow(w, blockOf, consumers); ok {
			if p.fusedAt == nil {
				p.fusedAt = map[ssa.ValueID]*plannedFusedWindow{}
				p.fusedMember = map[ssa.ValueID]bool{}
			}
			p.fusedAt[w.Members[0].ID] = pw
			for _, m := range w.Members {
				p.fusedMember[m.ID] = true
			}
		}
	}
}

// resolveFusedWindow checks one descriptor and resolves its operands.
func (p *funcPlan) resolveFusedWindow(w *FusedWindow, blockOf map[ssa.ValueID]ssa.BlockID, consumers map[ssa.ValueID]int) (*plannedFusedWindow, bool) {
	if w.Tree == nil || len(w.Members) == 0 {
		return nil, false
	}
	// Every member must live in one block, and no member may already
	// belong to another planned window (identical trees repeat; the
	// first claim wins and later duplicates must not double-plan).
	blk, ok := blockOf[w.Members[0].ID]
	if !ok {
		return nil, false
	}
	isRoot := map[ssa.ValueID]bool{}
	for _, r := range w.Roots {
		if r == nil {
			return nil, false
		}
		isRoot[r.ID] = true
	}
	memberSet := map[ssa.ValueID]bool{}
	for _, m := range w.Members {
		if m == nil || blockOf[m.ID] != blk || p.fusedMember[m.ID] {
			return nil, false
		}
		memberSet[m.ID] = true
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
			return nil, false
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
			arg := s.Val.Args[s.ArgIdx]
			// The operand must have a materialized slot the staging
			// can read. Constants and params resolve through the
			// per-arch operand machinery at emit time instead; keep
			// the strict subset slot-only for now.
			off, ok := p.offsets[resolveSlotValue(arg).ID]
			if !ok {
				return nil, false
			}
			wide := pair || w.Tree.Addr64
			out = append(out, FusedOperand{SlotOff: off, Wide: wide})
		}
		return out, true
	}
	var ok2 bool
	if pw.scalars, ok2 = resolve(w.ScalarSrc, false); !ok2 {
		return nil, false
	}
	if pw.floats, ok2 = resolve(w.FloatSrc, false); !ok2 {
		return nil, false
	}
	if pw.pairs, ok2 = resolve(w.PairSrc, true); !ok2 {
		return nil, false
	}
	for _, r := range w.Roots {
		if _, ok := p.offsets[r.ID]; !ok {
			return nil, false
		}
		pw.roots = append(pw.roots, r.ID)
	}
	return pw, true
}

// resolveSlotValue walks OpCopy chains to the value whose slot the
// operand resolvers would read.
func resolveSlotValue(v *ssa.Value) *ssa.Value {
	for i := 0; v.Op == ssa.OpCopy && len(v.Args) == 1 && v.Args[0] != nil && v.Args[0] != v && i < 16; i++ {
		v = v.Args[0]
	}
	return v
}
