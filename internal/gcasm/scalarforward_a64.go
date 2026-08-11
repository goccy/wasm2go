package gcasm

// Store-to-load forwarding over SCALAR (8-byte) stack slots, arm64,
// for direct-asm bodies.
//
// The slot-only emission spells every scalar intermediate as a
// store/reload pair through its frame slot — address chains read as
// `MOVD a(RSP), R0; MOVD b(RSP), R1; ADD R1, R0, R0; MOVD R0,
// c(RSP); MOVD c(RSP), R0; ...`. Within a straight-line span the
// reload is redundant: the value is still in the register that
// stored it. This pass tracks MOVD-width register→slot bindings and
// rewrites such reloads into register moves (or drops them outright
// when source and destination coincide).
//
// Conservative whitelist in the style of the sibling passes:
//
//   - labels and CALL/RET reset everything (conditional branches
//     fall through with state intact — the taken path lands on a
//     label, which resets);
//   - WORD-encoded splice bodies clobber R0–R15/R25–R27 per the
//     splice contract: bindings to those registers die;
//   - a store through a pointer register may alias any slot and
//     resets the slot side;
//   - narrower MOV stores invalidate the slot they touch without
//     creating a binding (only full-width MOVD⇄MOVD forwards);
//   - any other line drops the bindings of every register it names
//     in destination position and of every slot it writes.
//
// Only MOVD forms participate; a MOVW/MOVWU reload of a slot bound
// by an MOVD store is left untouched (the reload's implicit
// truncation/extension must keep happening in memory form).

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	sfStoreRe    = regexp.MustCompile(`^MOVD (R\d+), (\d+)\(RSP\)$`)
	sfLoadRe     = regexp.MustCompile(`^MOVD (\d+)\(RSP\), (R\d+)$`)
	sfAnyStoreRe = regexp.MustCompile(`, (\d+)\(RSP\)$`)
	sfPtrStoreRe = regexp.MustCompile(`, \(R\d+\)$`)
	sfLabelRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:$`)
	sfLastRegRe  = regexp.MustCompile(`, (R\d+)$`)
)

// sfSpliceClobbered reports whether reg dies at a WORD splice body
// (the contract set R0–R15 / R25–R27).
func sfSpliceClobbered(reg string) bool {
	n, err := strconv.Atoi(strings.TrimPrefix(reg, "R"))
	if err != nil {
		return true
	}
	return n <= 15 || (n >= 25 && n <= 27)
}

func a64ScalarSlotForward(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))

	regSlot := map[string]int{} // reg → slot whose value it holds
	slotReg := map[int]string{} // slot → canonical register copy

	reset := func() {
		regSlot = map[string]int{}
		slotReg = map[int]string{}
	}
	dropReg := func(r string) {
		if off, ok := regSlot[r]; ok {
			if slotReg[off] == r {
				delete(slotReg, off)
			}
			delete(regSlot, r)
		}
	}
	dropSlotRange := func(off, size int) {
		for so, r := range slotReg {
			if so < off+size && off < so+8 {
				delete(slotReg, so)
				if regSlot[r] == so {
					delete(regSlot, r)
				}
			}
		}
	}

	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case sfLabelRe.MatchString(t):
			reset()
			out = append(out, l)
			continue
		case strings.HasPrefix(t, "CALL") || t == "RET" || strings.HasPrefix(t, "RET "):
			reset()
			out = append(out, l)
			continue
		case strings.HasPrefix(t, "WORD $"):
			for r := range regSlot {
				if sfSpliceClobbered(r) {
					dropReg(r)
				}
			}
			out = append(out, l)
			continue
		}

		if m := sfStoreRe.FindStringSubmatch(t); m != nil {
			reg := m[1]
			off, err := strconv.Atoi(m[2])
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			dropSlotRange(off, 8)
			dropReg(reg)
			regSlot[reg] = off
			slotReg[off] = reg
			out = append(out, l)
			continue
		}
		if m := sfLoadRe.FindStringSubmatch(t); m != nil {
			off, err := strconv.Atoi(m[1])
			dst := m[2]
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			if src, ok := slotReg[off]; ok {
				if src == dst {
					// Value already there; the load is dead.
					continue
				}
				out = append(out, fmt.Sprintf("	MOVD %s, %s // fwd %d(RSP)", src, dst, off))
				dropReg(dst)
				regSlot[dst] = off
				continue
			}
			dropReg(dst)
			regSlot[dst] = off
			slotReg[off] = dst
			out = append(out, l)
			continue
		}
		if sfPtrStoreRe.MatchString(t) {
			// May alias any slot.
			slotReg = map[int]string{}
			regSlot = map[string]int{}
			out = append(out, l)
			continue
		}
		if m := sfAnyStoreRe.FindStringSubmatch(t); m != nil {
			off, err := strconv.Atoi(m[1])
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			size := 8
			if strings.HasPrefix(t, "FMOVQ") {
				size = 16
			}
			dropSlotRange(off, size)
			out = append(out, l)
			continue
		}
		// Any other instruction: its destination (last register
		// operand, plan9 `OP src.., dst`) loses its binding.
		if m := sfLastRegRe.FindStringSubmatch(t); m != nil {
			dropReg(m[1])
		}
		out = append(out, l)
		continue
	}
	return strings.Join(out, "\n")
}
