package gcasm

import (
	"fmt"
	"strings"
)

// a64StripPrologueEpilogue removes the captured arm64 stack-check,
// frame setup, frame teardown and morestack tail so the assembler
// regenerates them from the declared frame size. Handles gc's three
// shapes: LEAF (no frame), small-frame (MOVD.W R30 / MOVD R29), and
// large-frame (SUB/STP pair).
func a64StripPrologueEpilogue(insns []Insn) ([]Insn, error) {
	drop := map[int]bool{}
	i := 0
	splitTarget := -1

	// Stack check. The exact instruction sequence varies with frame
	// size (small: CMP RSP; large: SUB/SUBS into R17 with an optional
	// materialised constant and a wraparound BLO guard), so rather than
	// enumerate every variant, drop the whole check region — from
	// `MOVD 16(g),R16` up to (not including) the frame setup — and take
	// splitTarget as the FARTHEST branch target seen (the morestack
	// tail sits at the very end of the function).
	if i < len(insns) && strings.HasPrefix(insns[i].Text, "MOVD\t16(g),") {
		drop[i] = true
		i++
		for i < len(insns) {
			t := insns[i].Text
			// Stop at the frame setup (small: MOVD.W R30 / large: SUB
			// ...,RSP,R20) or any real body instruction.
			if strings.HasPrefix(t, "MOVD.W\tR30,") ||
				(strings.HasPrefix(t, "SUB\t") && strings.HasSuffix(t, ", RSP, R20")) {
				break
			}
			// Within the check: comparisons, the RSP-frame computation
			// (into R17), the frame-constant materialisation, and the
			// guard branches. Branches record their target.
			// Check temps are R17 (RSP-frame) and R27 (materialised
			// frame constant); R20 belongs to the frame setup and must
			// NOT be swept here.
			isCheck := strings.HasPrefix(t, "CMP") ||
				(strings.HasSuffix(t, ", R17") && (strings.HasPrefix(t, "SUB") || strings.HasPrefix(t, "MOVD"))) ||
				(strings.HasPrefix(t, "MOVD\t$") && strings.HasSuffix(t, ", R27"))
			if m := a64BranchRe.FindStringSubmatch(t); m != nil {
				var tt int
				if _, err := fmt.Sscanf(m[3], "%d", &tt); err == nil && tt > splitTarget {
					splitTarget = tt
				}
				drop[i] = true
				i++
				continue
			}
			if !isCheck {
				break
			}
			drop[i] = true
			i++
		}
	}

	// Frame setup. Small: MOVD.W R30,-N(RSP) / MOVD R29,-8(RSP) / SUB $8,RSP,R29.
	// Large: SUB $N,RSP,R20 / STP (R29,R30),-8(R20) / MOVD R20,RSP / SUB $8,RSP,R29.
	if i < len(insns) && strings.HasPrefix(insns[i].Text, "MOVD.W\tR30,") {
		drop[i] = true
		i++
		if i < len(insns) && strings.HasPrefix(insns[i].Text, "MOVD\tR29,") {
			drop[i] = true
			i++
		}
		if i < len(insns) && strings.HasPrefix(insns[i].Text, "SUB\t$8, RSP, R29") {
			drop[i] = true
		}
	} else if i < len(insns) && strings.HasPrefix(insns[i].Text, "SUB\t$") && strings.HasSuffix(insns[i].Text, ", RSP, R20") {
		drop[i] = true
		i++
		if i < len(insns) && strings.HasPrefix(insns[i].Text, "STP\t(R29, R30),") {
			drop[i] = true
			i++
		}
		if i < len(insns) && insns[i].Text == "MOVD\tR20, RSP" {
			drop[i] = true
			i++
		}
		if i < len(insns) && strings.HasPrefix(insns[i].Text, "SUB\t$8, RSP, R29") {
			drop[i] = true
		}
	}

	// Frame teardown before each RET. Small: MOVD -8(RSP),R29 / MOVD.P
	// N(RSP),R30. Large: LDP -8(RSP),(R29,R30) / ADD $N,RSP — or, when
	// N doesn't fit an add immediate, MOVD $N,R27 / ADD R27,RSP,RSP.
	for k, in := range insns {
		if !strings.HasPrefix(in.Text, "RET") {
			continue
		}
		for back := k - 1; back >= 0 && back >= k-4; back-- {
			t := insns[back].Text
			// SP restore: `ADD $N, RSP` (imm) or `ADD R27, RSP` (reg,
			// for frame sizes needing a materialised constant).
			isSPrestore := strings.HasPrefix(t, "ADD\t") && strings.HasSuffix(t, ", RSP")
			isFrameConst := strings.HasPrefix(t, "MOVD\t$") && strings.HasSuffix(t, ", R27")
			if strings.HasPrefix(t, "MOVD\t-8(RSP), R29") ||
				(strings.HasPrefix(t, "MOVD.P\t") && strings.HasSuffix(t, "(RSP), R30")) ||
				strings.HasPrefix(t, "LDP\t-8(RSP), (R29, R30)") ||
				isSPrestore || isFrameConst {
				drop[back] = true
				continue
			}
			break
		}
	}

	// Morestack tail: from the split target to the end.
	if splitTarget >= 0 {
		on := false
		for k, in := range insns {
			if in.Off == splitTarget {
				on = true
			}
			if on {
				drop[k] = true
			}
		}
	}

	var out []Insn
	for k, in := range insns {
		if !drop[k] {
			out = append(out, in)
		}
	}
	return out, nil
}

// a64FindJumpTables detects gc arm64 jump-table dispatch triples
// (`MOVD $tab(SB),Rb; MOVD (Rb)(Ri<<3),Rt; JMP (Rt)`) and resolves the
// table's R_ADDR relocs to run-compressed target lists.
func a64FindJumpTables(fnName string, insns []Insn, datas map[string]*DataSym) (map[int]*jtSite, error) {
	sites := map[int]*jtSite{}
	for i, in := range insns {
		lm := a64JtLeaqRe.FindStringSubmatch(in.Text)
		if lm == nil {
			continue
		}
		// Next non-NOP: the indexed load.
		j := i + 1
		for j < len(insns) && insns[j].Text == "NOP" {
			j++
		}
		if j >= len(insns) {
			return nil, fmt.Errorf("jump-table load %q at end of body", in.Text)
		}
		dm := a64JtLdrRe.FindStringSubmatch(insns[j].Text)
		if dm == nil || dm[1] != lm[2] {
			return nil, fmt.Errorf("jump-table %q not followed by indexed load (got %q)", in.Text, insns[j].Text)
		}
		idxReg := dm[2]
		tReg := dm[3]
		k := j + 1
		for k < len(insns) && insns[k].Text == "NOP" {
			k++
		}
		jm := a64JtJmpRe.FindStringSubmatch(insns[k].Text)
		if jm == nil || jm[1] != tReg {
			return nil, fmt.Errorf("jump-table load %q not followed by indirect JMP (got %q)", insns[j].Text, insns[k].Text)
		}
		tab, ok := datas[lm[1]]
		if !ok {
			return nil, fmt.Errorf("jump table %s not captured", lm[1])
		}
		if len(tab.Relocs) == 0 || len(tab.Relocs)*8 != tab.Size {
			return nil, fmt.Errorf("jump table %s: %d relocs for size %d", lm[1], len(tab.Relocs), tab.Size)
		}
		site := &jtSite{idx: i, jmpIdx: k, idxReg: idxReg}
		for ri, r := range tab.Relocs {
			if r.Off != ri*8 {
				return nil, fmt.Errorf("jump table %s: reloc %d at offset %d", lm[1], ri, r.Off)
			}
			if r.Sym != fnName {
				return nil, fmt.Errorf("jump table %s: reloc targets %s, not %s", lm[1], r.Sym, fnName)
			}
			if n := len(site.runs); n > 0 && site.runs[n-1].target == r.Addend {
				continue
			}
			site.runs = append(site.runs, jtRun{start: ri, target: r.Addend})
		}
		// NZCV liveness across the dispatch — the arm64 port of the
		// amd64 findJumpTables replay logic. gc's captured dispatch
		// (MOVD $tab / indexed MOVD / indirect JMP) PRESERVES NZCV,
		// and gc exploits that by letting a dispatch target consume
		// flags set before the dispatch (typically the bounds-check
		// `CMPW $max, Ri` ahead of the table jump). The compare tree
		// a64EmitJumpTree emits (CMPW/BHS) CLOBBERS NZCV, so the
		// pre-dispatch flag state must be RESTORED at every tree leaf.
		// Detection of which targets consume flags is unsound (a
		// target can reach a flag read across an unconditional JMP or
		// an unrecorded offset — the exact false-negative hole that
		// produced the amd64 wild-pointer SIGSEGV, and, unported, the
		// arm64 go-python SIGSEGV in Fn3705's dispatch), so: if a
		// CLEAN, replayable flag-setter sits immediately before the
		// dispatch, ALWAYS replay it at the leaves. Replaying a
		// compare nothing reads is harmless — it writes only flags.
		//
		// Clean means: a pure register/immediate CMP/CMN/TST (no
		// memory operand — leaves get no frame-shift rewrite) whose
		// operands exclude the table-base and target registers, which
		// the captured dispatch clobbers between the compare and the
		// leaf (the tree itself only READS the selector register).
		replay, replayClean := "", false
		for k2 := i - 1; k2 >= 0 && i-k2 <= 8; k2-- {
			t := insns[k2].Text
			if a64WritesFlags(t) {
				if (strings.HasPrefix(t, "CMP") || strings.HasPrefix(t, "CMN") || strings.HasPrefix(t, "TST")) &&
					!strings.Contains(t, "(") &&
					!a64MentionsReg(t, lm[2]) && !a64MentionsReg(t, tReg) {
					replay, replayClean = t, true
				}
				break
			}
			// An unconditional JMP breaks linear fall-through: the
			// flag state at the dispatch then depends on the jump-in
			// path, not on this scan's instructions.
			if strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") || strings.HasPrefix(t, "JMP") {
				break
			}
		}
		if replayClean {
			site.replay = replay
		} else {
			// No cleanly-replayable flag-setter. Fall back to pure
			// unless we can prove NO target consumes flags
			// (conservative: any unverifiable target counts as
			// consuming).
			offIndex := map[int]int{}
			for k2, in2 := range insns {
				offIndex[in2.Off] = k2
			}
			consumes := false
			for _, r := range site.runs {
				k2, ok := offIndex[r.target]
				if !ok {
					consumes = true
					break
				}
				for ; k2 < len(insns); k2++ {
					t := insns[k2].Text
					if a64ReadsFlags(t) {
						consumes = true
						break
					}
					if a64WritesFlags(t) || strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") || strings.HasPrefix(t, "JMP") {
						break
					}
				}
				if consumes {
					break
				}
			}
			if consumes {
				return nil, fmt.Errorf("%w: jump table at +%d: flags consumed by targets but no replayable flag-setter found", errUnsupportedJumpTable, in.Off)
			}
		}
		sites[i] = site
	}
	owned := map[int]bool{}
	for _, s := range sites {
		owned[s.jmpIdx] = true
	}
	for i, in := range insns {
		if a64JtJmpRe.MatchString(in.Text) && !owned[i] {
			return nil, fmt.Errorf("unmatched indirect JMP %q at +%d", in.Text, in.Off)
		}
	}
	return sites, nil
}

// a64EmitJumpTree emits a binary search tree over the site's runs
// dispatching to pcN labels (O(log n)). The selector is bounds-checked
// by the captured code (CMP/BHI to default) before the table jump.
func a64EmitJumpTree(b *strings.Builder, site *jtSite, leaqOff int) {
	labelID := 0
	var rec func(lo, hi int)
	rec = func(lo, hi int) {
		if lo == hi {
			// Restore the dispatch-entry NZCV state clobbered by the
			// tree's compares (see the replay scan in
			// a64FindJumpTables); the tree writes nothing but flags,
			// so the compare's operands are unchanged.
			if site.replay != "" {
				fmt.Fprintf(b, "\t%s\n", site.replay)
			}
			fmt.Fprintf(b, "\tJMP pc%d\n", site.runs[lo].target)
			return
		}
		mid := (lo + hi + 1) / 2
		labelID++
		lbl := fmt.Sprintf("jt%d_%d", leaqOff, labelID)
		// CMPW imm, reg then BHS (unsigned >=) to the high half.
		fmt.Fprintf(b, "\tCMPW $%d, %s\n", site.runs[mid].start, site.idxReg)
		fmt.Fprintf(b, "\tBHS %s\n", lbl)
		rec(lo, mid-1)
		fmt.Fprintf(b, "%s:\n", lbl)
		rec(mid, hi)
	}
	rec(0, len(site.runs)-1)
}

// a64WritesFlags reports whether an arm64 instruction writes NZCV:
// compares (CMP/CMN/TST, conditional CCMP/CCMN, float FCMP) and the
// flag-setting S-suffixed arithmetic forms. CBZ/CBNZ/TBZ/TBNZ test a
// register directly and do NOT touch NZCV.
func a64WritesFlags(txt string) bool {
	mn := txt
	if i := strings.IndexByte(mn, '\t'); i >= 0 {
		mn = mn[:i]
	}
	for _, p := range []string{"CMP", "CMN", "TST", "CCMP", "CCMN", "FCMP",
		"ADDS", "SUBS", "ANDS", "BICS", "ADCS", "SBCS", "NEGS", "NGCS"} {
		if strings.HasPrefix(mn, p) {
			return true
		}
	}
	return false
}

// a64ReadsFlags reports whether an arm64 instruction reads NZCV:
// conditional branches, conditional selects/sets, conditional
// compares, and the carry-consuming arithmetic family.
func a64ReadsFlags(txt string) bool {
	mn := txt
	if i := strings.IndexByte(mn, '\t'); i >= 0 {
		mn = mn[:i]
	}
	switch mn {
	case "BEQ", "BNE", "BHS", "BCS", "BLO", "BCC", "BMI", "BPL",
		"BVS", "BVC", "BHI", "BLS", "BGE", "BLT", "BGT", "BLE":
		return true
	}
	for _, p := range []string{"CSEL", "CSET", "CSETM", "CSINC", "CSINV", "CSNEG",
		"CINC", "CINV", "CNEG", "CCMP", "CCMN", "FCSEL", "ADC", "SBC", "NGC"} {
		if strings.HasPrefix(mn, p) {
			return true
		}
	}
	return false
}

// a64MentionsReg reports whether the instruction text references reg
// as a whole token (R1 must not match R16).
func a64MentionsReg(txt, reg string) bool {
	for i := 0; ; {
		j := strings.Index(txt[i:], reg)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(reg)
		beforeOK := j == 0 || !isAlnumByte(txt[j-1])
		afterOK := end >= len(txt) || !isAlnumByte(txt[end])
		if beforeOK && afterOK {
			return true
		}
		i = end
	}
}

func isAlnumByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}
