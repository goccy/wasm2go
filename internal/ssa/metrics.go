package ssa

import (
	"encoding/json"
	"fmt"
	"sort"
)

// MemMetrics accumulates memory-access classification counts across an
// entire module. It is the data behind the memory-promotion observability
// requirement: report, in `promoted / total` (y/x) form, how much of
// the linear-memory traffic the transpiler proved function-local.
type MemMetrics struct {
	// Counts over every memory access in every SSA-lowered function.
	Total  int
	Frame  int
	Rodata int
	Slab   int

	// SSAFunctions is the number of functions analysed (those that
	// fully lowered to SSA). Functions that fell back to the legacy
	// path are not counted — their memory traffic is not observable
	// through this analysis.
	SSAFunctions   int
	FuncsWithFrame int // functions with a detected stack frame
	FuncsFrameKept int // ... whose frame did not escape (promotable)

	// PerFunc keeps a one-line record per analysed function for the
	// sidecar report. Keyed insertion order is preserved via the
	// parallel funcOrder slice.
	PerFunc   map[string]FuncMemRecord
	funcOrder []string

	// OptInsBefore / OptInsAfter are the total SSA instruction (value)
	// counts across all optimised functions, summed before and after
	// the optimization pipeline. The difference quantifies how much
	// folding the passes achieved.
	OptInsBefore int
	OptInsAfter  int

	// StructuredFuncs / GotoFuncs count how the SSA-emitted functions
	// were rendered: structured (if/else + for) vs the goto/label
	// fallback.
	StructuredFuncs int
	GotoFuncs       int
}

// FuncMemRecord is the per-function memory summary.
type FuncMemRecord struct {
	Name         string `json:"fn"`
	Total        int    `json:"total"`
	Frame        int    `json:"frame"`
	Rodata       int    `json:"rodata"`
	Slab         int    `json:"slab"`
	FrameSize    int64  `json:"frame_size"`
	FrameEscaped bool   `json:"frame_escaped"`
	EscapeReason string `json:"escape_reason,omitempty"`
}

// NewMemMetrics returns an empty accumulator.
func NewMemMetrics() *MemMetrics {
	return &MemMetrics{PerFunc: map[string]FuncMemRecord{}}
}

// Add folds one function's classification into the running totals.
func (m *MemMetrics) Add(f *Func, mc *MemClass) {
	m.SSAFunctions++
	rec := FuncMemRecord{Name: f.Name}
	for _, c := range mc.Class {
		rec.Total++
		switch c {
		case AliasFrame:
			rec.Frame++
		case AliasRodata:
			rec.Rodata++
		default:
			rec.Slab++
		}
	}
	if mc.FramePtr != nil {
		m.FuncsWithFrame++
		rec.FrameSize = mc.FrameSize
		rec.FrameEscaped = mc.FrameEscapes
		rec.EscapeReason = mc.EscapeReason
		if !mc.FrameEscapes {
			m.FuncsFrameKept++
		}
	}
	m.Total += rec.Total
	m.Frame += rec.Frame
	m.Rodata += rec.Rodata
	m.Slab += rec.Slab

	if _, seen := m.PerFunc[f.Name]; !seen {
		m.funcOrder = append(m.funcOrder, f.Name)
	}
	m.PerFunc[f.Name] = rec
}

// AddOpt folds one function's pre/post optimization instruction counts
// into the running totals.
func (m *MemMetrics) AddOpt(before, after int) {
	m.OptInsBefore += before
	m.OptInsAfter += after
}

// OptReduction returns the fraction of SSA instructions the
// optimization pipeline eliminated, in [0,1].
func (m *MemMetrics) OptReduction() float64 {
	if m.OptInsBefore == 0 {
		return 0
	}
	return float64(m.OptInsBefore-m.OptInsAfter) / float64(m.OptInsBefore)
}

// Promoted is y in the y/x ratio: accesses proven function-local.
func (m *MemMetrics) Promoted() int { return m.Frame + m.Rodata }

// Rate returns the promotion ratio in [0,1]; 0 when there are no
// accesses at all.
func (m *MemMetrics) Rate() float64 {
	if m.Total == 0 {
		return 0
	}
	return float64(m.Promoted()) / float64(m.Total)
}

// Summary renders the human-readable stderr report.
func (m *MemMetrics) Summary() string {
	pct := func(n int) string {
		if m.Total == 0 {
			return "  0.0%"
		}
		return fmt.Sprintf("%5.1f%%", 100*float64(n)/float64(m.Total))
	}
	s := "wasm2go: SSA optimization + memory promotion summary\n"
	if m.OptInsBefore > 0 {
		s += fmt.Sprintf("  SSA instructions:        %8d -> %d  (-%.1f%% folded)\n",
			m.OptInsBefore, m.OptInsAfter, 100*m.OptReduction())
	}
	if tot := m.StructuredFuncs + m.GotoFuncs; tot > 0 {
		s += fmt.Sprintf("  emit form:               %8d structured / %d goto  (%.1f%% structured)\n",
			m.StructuredFuncs, m.GotoFuncs, 100*float64(m.StructuredFuncs)/float64(tot))
	}
	s += fmt.Sprintf("  SSA-lowered functions:   %8d\n", m.SSAFunctions)
	s += fmt.Sprintf("  functions with a frame:  %8d  (%d non-escaping)\n", m.FuncsWithFrame, m.FuncsFrameKept)
	s += fmt.Sprintf("  total memory accesses:   %8d\n", m.Total)
	s += fmt.Sprintf("  promoted (y/x):          %8d / %d  (%s)\n", m.Promoted(), m.Total, pct(m.Promoted()))
	s += fmt.Sprintf("    frame:                 %8d  (%s)\n", m.Frame, pct(m.Frame))
	s += fmt.Sprintf("    rodata:                %8d  (%s)\n", m.Rodata, pct(m.Rodata))
	s += fmt.Sprintf("  slab (not promoted):     %8d  (%s)\n", m.Slab, pct(m.Slab))
	return s
}

// FuncRecords returns the per-function records in analysis order.
func (m *MemMetrics) FuncRecords() []FuncMemRecord {
	out := make([]FuncMemRecord, 0, len(m.funcOrder))
	for _, name := range m.funcOrder {
		out = append(out, m.PerFunc[name])
	}
	return out
}

// TopSlabFunctions returns up to n function records with the most
// un-promoted (slab) accesses — the highest-value targets for
// improving the promotion rate.
func (m *MemMetrics) TopSlabFunctions(n int) []FuncMemRecord {
	recs := m.FuncRecords()
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Slab > recs[j].Slab })
	if len(recs) > n {
		recs = recs[:n]
	}
	return recs
}

// JSON renders the full metrics — module totals plus every
// per-function record — as an indented JSON document for the
// `-promotion-report` sidecar.
func (m *MemMetrics) JSON() ([]byte, error) {
	type doc struct {
		SSAFunctions   int             `json:"ssa_functions"`
		FuncsWithFrame int             `json:"funcs_with_frame"`
		FuncsFrameKept int             `json:"funcs_frame_non_escaping"`
		Total          int             `json:"total_accesses"`
		Promoted       int             `json:"promoted"`
		Frame          int             `json:"frame"`
		Rodata         int             `json:"rodata"`
		Slab           int             `json:"slab"`
		Rate           float64         `json:"promotion_rate"`
		Functions      []FuncMemRecord `json:"functions"`
	}
	d := doc{
		SSAFunctions:   m.SSAFunctions,
		FuncsWithFrame: m.FuncsWithFrame,
		FuncsFrameKept: m.FuncsFrameKept,
		Total:          m.Total,
		Promoted:       m.Promoted(),
		Frame:          m.Frame,
		Rodata:         m.Rodata,
		Slab:           m.Slab,
		Rate:           m.Rate(),
		Functions:      m.FuncRecords(),
	}
	return json.MarshalIndent(d, "", "  ")
}
