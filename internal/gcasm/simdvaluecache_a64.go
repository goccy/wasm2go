package gcasm

// Spare-register value caching over v128 stack slots, arm64.
//
// The direct-asm per-op splice protocol reads every v128 argument
// from its frame slot and writes every result back — and every splice
// body computes through V0, so a value never survives in a register
// past the next op. Store-to-load forwarding alone cannot help: by
// the time a slot is reloaded, V0 holds something else.
//
// This pass parks each splice result in a SPARE vector register
// (V17–V31 — strictly above everything any splice body touches; see
// a64SpliceWordClobberList and the F16 lane copies) right after its
// "// simd out" store, and rewrites later reloads of that slot into
// single-cycle register moves. The store itself always remains: later
// blocks (and spilled paths) may read the slot.
//
// Invalidation is conservative, mirroring a64ForwardSimdSlots:
// labels and CALL/RET reset everything (conditional branches fall
// through with state intact — the taken path lands on a label);
// a store to N(RSP) drops cached slots overlapping its width; any
// store through a pointer register (`... , (Rn)`) may alias the frame
// and drops the whole cache. WORD-encoded splice bodies touch only
// V0–V4, below the spare pool.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	svcOutRe      = regexp.MustCompile(`^FMOVQ F0, (\d+)\(RSP\) // simd out$`)
	svcLoadRe     = regexp.MustCompile(`^FMOVQ (\d+)\(RSP\), F(\d+)$`)
	svcFmovqStRe  = regexp.MustCompile(`^FMOVQ F(\d+), (\d+)\(RSP\)`)
	svcRspStoreRe = regexp.MustCompile(`, (\d+)\(RSP\)$`)
	svcPtrStoreRe = regexp.MustCompile(`, \(R\d+\)$`)
	svcLabelRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:$`)
)

const svcSpareLo, svcSpareHi = 17, 31

// a64SpliceValueCache rewrites one TEXT's worth of direct-asm body.
func a64SpliceValueCache(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines)+16)

	slotSpare := map[int]int{} // slot offset → spare V holding its value
	spareSlot := map[int]int{} // inverse
	next := svcSpareLo

	reset := func() {
		slotSpare = map[int]int{}
		spareSlot = map[int]int{}
		next = svcSpareLo
	}
	dropSlot := func(off, size int) {
		for so, sp := range slotSpare {
			if so < off+size && off < so+16 {
				delete(slotSpare, so)
				delete(spareSlot, sp)
			}
		}
	}

	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case svcLabelRe.MatchString(t):
			reset()
			out = append(out, l)
			continue
		case strings.HasPrefix(t, "CALL") || t == "RET" || strings.HasPrefix(t, "RET "):
			reset()
			out = append(out, l)
			continue
		}

		if m := svcOutRe.FindStringSubmatch(t); m != nil {
			off, err := strconv.Atoi(m[1])
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			dropSlot(off, 16)
			// Park the result. Round-robin allocation; evicting a
			// spare only forgets a cached copy, never a value's home.
			sp := next
			next++
			if next > svcSpareHi {
				next = svcSpareLo
			}
			if old, ok := spareSlot[sp]; ok {
				delete(slotSpare, old)
			}
			slotSpare[off] = sp
			spareSlot[sp] = off
			out = append(out, l)
			out = append(out, fmt.Sprintf("	VORR V0.B16, V0.B16, V%d.B16 // cached", sp))
			continue
		}
		if m := svcLoadRe.FindStringSubmatch(t); m != nil {
			off, err1 := strconv.Atoi(m[1])
			dst, err2 := strconv.Atoi(m[2])
			if err1 != nil || err2 != nil {
				reset()
				out = append(out, l)
				continue
			}
			if sp, ok := slotSpare[off]; ok && dst <= 3 {
				out = append(out, fmt.Sprintf("	VORR V%d.B16, V%d.B16, V%d.B16 // fwd %d(RSP)", sp, sp, dst, off))
				continue
			}
			out = append(out, l)
			continue
		}
		if m := svcFmovqStRe.FindStringSubmatch(t); m != nil {
			off, err := strconv.Atoi(m[2])
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			dropSlot(off, 16)
			out = append(out, l)
			continue
		}
		if svcPtrStoreRe.MatchString(t) {
			// Store through a pointer register may alias any slot.
			reset()
			out = append(out, l)
			continue
		}
		if m := svcRspStoreRe.FindStringSubmatch(t); m != nil && !strings.HasPrefix(t, "FMOVQ") {
			// Non-FMOVQ stores write at most 8 bytes.
			off, err := strconv.Atoi(m[1])
			if err != nil {
				reset()
				out = append(out, l)
				continue
			}
			dropSlot(off, 8)
			out = append(out, l)
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
