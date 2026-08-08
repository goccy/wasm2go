package codegen

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Loop-outlining feasibility metrics.
//
// Outlining a natural loop into its own Go function needs the loop's
// boundary to fit a call: every value live into the loop becomes a
// parameter and every value live out becomes a result. This collector
// measures those boundaries for the largest functions so the outlining
// design can be sized against real kernels instead of guesses. Enabled
// by WASM2GO_OUTLINE_STATS=1; reporting happens per function during
// lowering, on stderr next to the memory-promotion metrics.

// outlineStatsEnabled gates the collector.
func outlineStatsEnabled() bool {
	return os.Getenv("WASM2GO_OUTLINE_STATS") != ""
}

// outlineStatsMinValues: only functions at least this big are worth
// splitting, and only their loops are reported.
const outlineStatsMinValues = 600

type outlineLoopStat struct {
	header   ssa.BlockID
	blocks   int
	values   int
	liveIn   int
	liveOut  int
	exits    int
	nestedIn bool // body of another reported loop
}

// reportOutlineStats prints the per-loop boundary sizes of f when the
// collector is enabled and f is large enough to be a split candidate.
func reportOutlineStats(f *ssa.Func) {
	if !outlineStatsEnabled() {
		return
	}
	nValues := 0
	for _, b := range f.Blocks {
		nValues += len(b.Values)
	}
	if nValues < outlineStatsMinValues {
		return
	}
	idom := ssa.Dominators(f)
	dominates := func(a, b *ssa.Block) bool {
		for b != nil {
			if b == a {
				return true
			}
			p := idom[b.ID]
			if p == b {
				return false // reached the root (its idom is itself)
			}
			b = p
		}
		return false
	}
	// Natural loops from back edges; merge bodies sharing a header.
	loops := map[ssa.BlockID]map[ssa.BlockID]bool{}
	headers := map[ssa.BlockID]*ssa.Block{}
	for _, b := range f.Blocks {
		for _, s := range b.Succs {
			h := s.Block
			if !dominates(h, b) {
				continue
			}
			body := loops[h.ID]
			if body == nil {
				body = map[ssa.BlockID]bool{h.ID: true}
				loops[h.ID] = body
				headers[h.ID] = h
			}
			// Walk predecessors from the latch until the header.
			stack := []*ssa.Block{b}
			for len(stack) > 0 {
				x := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if body[x.ID] {
					continue
				}
				body[x.ID] = true
				for _, p := range x.Preds {
					stack = append(stack, p.Block)
				}
			}
		}
	}
	if len(loops) == 0 {
		return
	}
	blockOf := map[ssa.BlockID]*ssa.Block{}
	for _, b := range f.Blocks {
		blockOf[b.ID] = b
	}
	var stats []outlineLoopStat
	for h, body := range loops {
		st := outlineLoopStat{header: h, blocks: len(body)}
		defsIn := map[ssa.ValueID]bool{}
		for id := range body {
			for _, v := range blockOf[id].Values {
				defsIn[v.ID] = true
				st.values++
			}
		}
		liveIn := map[ssa.ValueID]bool{}
		for id := range body {
			for _, v := range blockOf[id].Values {
				for _, a := range v.Args {
					if !defsIn[a.ID] {
						liveIn[a.ID] = true
					}
				}
			}
			if c := blockOf[id].Control; c != nil && !defsIn[c.ID] {
				liveIn[c.ID] = true
			}
		}
		liveOut := map[ssa.ValueID]bool{}
		exits := map[ssa.BlockID]bool{}
		for _, b := range f.Blocks {
			if body[b.ID] {
				for _, s := range b.Succs {
					if !body[s.Block.ID] {
						exits[s.Block.ID] = true
					}
				}
				continue
			}
			for _, v := range b.Values {
				for _, a := range v.Args {
					if defsIn[a.ID] {
						liveOut[a.ID] = true
					}
				}
			}
			if c := b.Control; c != nil && defsIn[c.ID] {
				liveOut[c.ID] = true
			}
		}
		st.liveIn, st.liveOut, st.exits = len(liveIn), len(liveOut), len(exits)
		stats = append(stats, st)
	}
	// Mark nesting so outermost candidates stand out.
	for i := range stats {
		for j := range stats {
			if i != j && loops[stats[j].header][stats[i].header] && stats[j].blocks > stats[i].blocks {
				stats[i].nestedIn = true
				break
			}
		}
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].values > stats[j].values })
	fmt.Fprintf(os.Stderr, "outline candidates %s (%d values, %d loops):\n", f.Name, nValues, len(loops))
	for i, st := range stats {
		if i == 400 {
			fmt.Fprintf(os.Stderr, "    ... %d more\n", len(stats)-i)
			break
		}
		nest := ""
		if st.nestedIn {
			nest = " nested"
		}
		fmt.Fprintf(os.Stderr, "    L%-5d blocks=%-4d values=%-6d liveIn=%-3d liveOut=%-3d exits=%d%s\n",
			st.header, st.blocks, st.values, st.liveIn, st.liveOut, st.exits, nest)
	}
}
