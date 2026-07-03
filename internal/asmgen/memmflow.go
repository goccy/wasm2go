package asmgen

import "strings"

// memMFlowConfig names, per architecture, the emitted-text patterns
// whose redundancy memBaseFlowDedup eliminates: the reload of m.M
// into the memop base register, and that register itself (the
// dataflow fact tracked is "<reg> == m.M").
type memMFlowConfig struct {
	genCache string // m-cache form: one-line m.M read
	genFP1   string // no-cache form, line 1: m pointer from the frame
	genFP2   string // no-cache form, line 2: m.M off the m pointer
	reg      string // the register the fact is about
	regByte  string // partial-register alias whose write kills reg ("" if none)
}

var memMFlowConfigs = []memMFlowConfig{
	{
		// amd64: BX carries m.M; R11 is the function-wide m cache.
		genCache: "\tMOVQ 32(R11), BX",
		genFP1:   "\tMOVQ m+0(FP), BX",
		genFP2:   "\tMOVQ 32(BX), BX",
		reg:      "BX",
		regByte:  "BL",
	},
	{
		// arm64: R2 carries m.M; R4 is the m cache. Only meaningful
		// once memops address memory as (R2)(R3) — the historical
		// `ADD R3, R2, R2` form killed the fact inside every memop.
		genCache: "\tMOVD 32(R4), R2",
		genFP1:   "\tMOVD m+0(FP), R2",
		genFP2:   "\tMOVD 32(R2), R2",
		reg:      "R2",
	},
}

// memBaseFlowDedup removes m.M reloads (per-arch patterns in
// memMFlowConfigs) that are redundant on EVERY control-flow path — a
// dataflow generalisation of dedupMemMReload, which can only track
// validity through straight-line spans and must give up at labels.
//
// The property computed is the classic "available expression": the
// base register holds m.M on entry to a block iff it holds it on
// exit of ALL predecessors. m.M itself can only change inside a CALL
// (memory.grow is a call), and CALLs clobber every caller-save
// register anyway, so the kill set is simply {CALL, any write of the
// base register}. The pass only DELETES existing reload lines — it
// never inserts code — so unlike a prologue-loaded function-wide
// cache it cannot regress functions whose shape doesn't profit
// (Phase F-1's failure mode, re-measured and reproduced as a
// consistent window-suite loss before this pass replaced that
// design).
//
// Solved as a forward must-analysis with optimistic initialisation
// (everything valid except the function entry), AND-meet over
// predecessors, iterated to fixpoint — the standard formulation, and
// the optimism is what lets loop headers keep validity across
// call-free loop bodies.
func memBaseFlowDedup(asm string) string {
	for _, cfg := range memMFlowConfigs {
		if strings.Contains(asm, cfg.genCache) || strings.Contains(asm, cfg.genFP1) {
			asm = memBaseFlowDedupFor(asm, cfg)
		}
	}
	return asm
}

func memBaseFlowDedupFor(asm string, cfg memMFlowConfig) string {
	lines := strings.Split(asm, "\n")

	// ---- 1. Partition into blocks. A leader is line 0, every label,
	// and every line following a branch. Record label positions.
	isBranch := func(s string) bool { return isAsmUnconditionalOrCondBranch(s) }
	labelOf := func(s string) (string, bool) {
		if !isAsmLabel(s) {
			return "", false
		}
		t := strings.TrimSpace(s)
		return strings.TrimSuffix(t, ":"), true
	}
	leader := make([]bool, len(lines))
	if len(lines) > 0 {
		leader[0] = true
	}
	labelLine := map[string]int{}
	for i, ln := range lines {
		if name, ok := labelOf(ln); ok {
			leader[i] = true
			labelLine[name] = i
		}
		if isBranch(ln) || strings.TrimSpace(ln) == "RET" {
			if i+1 < len(lines) {
				leader[i+1] = true
			}
		}
	}
	type block struct {
		start, end int // [start, end) line range
		succs      []int
	}
	var blocks []block
	blockAt := make([]int, len(lines))
	for i := 0; i < len(lines); i++ {
		if leader[i] {
			blocks = append(blocks, block{start: i})
			if len(blocks) > 1 {
				blocks[len(blocks)-2].end = i
			}
		}
		if len(blocks) > 0 {
			blockAt[i] = len(blocks) - 1
		}
	}
	if len(blocks) == 0 {
		return asm
	}
	blocks[len(blocks)-1].end = len(lines)

	// ---- 2. Successor edges: explicit branch targets plus
	// fall-through (unless the block's last line is an unconditional
	// JMP / B or RET).
	branchTarget := func(s string) (string, bool) {
		t := strings.TrimSpace(s)
		sp := strings.IndexAny(t, " \t")
		if sp < 0 {
			return "", false
		}
		return strings.TrimSpace(t[sp:]), true
	}
	isUncond := func(t string) bool {
		return strings.HasPrefix(t, "JMP ") || strings.HasPrefix(t, "JMP\t") ||
			strings.HasPrefix(t, "B ") || strings.HasPrefix(t, "B\t")
	}
	for bi := range blocks {
		blk := &blocks[bi]
		fallThrough := true
		for i := blk.start; i < blk.end; i++ {
			t := strings.TrimSpace(lines[i])
			if t == "RET" {
				fallThrough = false
				continue
			}
			if !isBranch(lines[i]) {
				continue
			}
			if tgt, ok := branchTarget(lines[i]); ok {
				if pos, ok := labelLine[tgt]; ok {
					blk.succs = append(blk.succs, blockAt[pos])
				}
			}
			if isUncond(t) {
				fallThrough = false
			}
		}
		if fallThrough && bi+1 < len(blocks) {
			blk.succs = append(blk.succs, bi+1)
		}
	}
	preds := make([][]int, len(blocks))
	for bi, blk := range blocks {
		for _, s := range blk.succs {
			preds[s] = append(preds[s], bi)
		}
	}

	// ---- 3. Per-line transfer over the "<reg> == m.M" fact.
	step := func(valid bool, i int) bool {
		ln := strings.TrimRight(lines[i], " \t")
		switch {
		case ln == cfg.genCache:
			return true
		case ln == cfg.genFP1:
			// Only the completed two-line pair re-establishes the
			// fact; the first line alone leaves the register = m.
			if i+1 < len(lines) && strings.TrimRight(lines[i+1], " \t") == cfg.genFP2 {
				return valid // decided when the pair's 2nd line runs
			}
			return false
		case ln == cfg.genFP2 && i > 0 && strings.TrimRight(lines[i-1], " \t") == cfg.genFP1:
			return true
		case isAsmCall(lines[i]):
			return false
		default:
			// A partial-register write (BL on amd64) clobbers the low
			// byte; treat it as a full kill (nothing emits BL today,
			// but stay safe).
			if writesRegister(lines[i], cfg.reg) ||
				(cfg.regByte != "" && writesRegister(lines[i], cfg.regByte)) {
				return false
			}
			return valid
		}
	}
	transferBlock := func(in bool, bi int) bool {
		v := in
		for i := blocks[bi].start; i < blocks[bi].end; i++ {
			v = step(v, i)
		}
		return v
	}

	// ---- 4. Fixpoint (optimistic init; entry pessimistic).
	in := make([]bool, len(blocks))
	out := make([]bool, len(blocks))
	for i := range out {
		in[i], out[i] = true, true
	}
	in[0] = false
	out[0] = transferBlock(false, 0)
	for changed := true; changed; {
		changed = false
		for bi := range blocks {
			ni := true
			if bi == 0 {
				ni = false
			} else if len(preds[bi]) == 0 {
				// Unreachable via edges we model — be conservative.
				ni = false
			} else {
				for _, p := range preds[bi] {
					ni = ni && out[p]
				}
			}
			no := transferBlock(ni, bi)
			if ni != in[bi] || no != out[bi] {
				in[bi], out[bi] = ni, no
				changed = true
			}
		}
	}

	// ---- 5. Rewrite: drop reload lines whose fact is already valid.
	dropped := map[int]bool{}
	for bi := range blocks {
		v := in[bi]
		for i := blocks[bi].start; i < blocks[bi].end; i++ {
			ln := strings.TrimRight(lines[i], " \t")
			if v && ln == cfg.genCache {
				dropped[i] = true
			}
			if v && ln == cfg.genFP1 && i+1 < blocks[bi].end &&
				strings.TrimRight(lines[i+1], " \t") == cfg.genFP2 {
				dropped[i] = true
				dropped[i+1] = true
			}
			v = step(v, i)
		}
	}
	if len(dropped) == 0 {
		return asm
	}
	outLines := make([]string, 0, len(lines))
	for i, ln := range lines {
		if dropped[i] {
			continue
		}
		outLines = append(outLines, ln)
	}
	return strings.Join(outLines, "\n")
}
