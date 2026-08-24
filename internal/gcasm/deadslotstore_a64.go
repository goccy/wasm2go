package gcasm

// Function-scoped dead-store elimination over v128 result slots,
// arm64, for direct-asm bodies.
//
// After store-to-load forwarding and spare-register caching rewrite
// the reloads, many "// simd out" stores lose their last reader: a
// single-use v128 intermediate is produced, parked in a spare
// register, consumed from there — and the 16-byte store to its frame
// slot serves nobody. This pass counts every read of each RSP offset
// across the WHOLE body and drops "// simd out" stores (and their
// trailing "// cached" park when it becomes the value's only
// remaining mention) whose slot is never read.
//
// Conservative bail-outs: any RSP-relative addressing this pass does
// not fully understand keeps everything. Specifically, reads counted
// are `off(RSP)` operands anywhere and `ADD $off, RSP, Rn` slot-
// address escapes (the lane splices build pointers this way); a
// non-constant or unparseable RSP mention aborts the pass for the
// whole body. Offsets are counted with 16-byte overlap so an 8-byte
// read of either half keeps the store.

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	dssOutRe = regexp.MustCompile(`^FMOVQ F0, (\d+)\(RSP\) // simd out$`)
	// fmovqF0StoreRe is dssOutRe after comment stripping.
	fmovqF0StoreRe = regexp.MustCompile(`^FMOVQ F0, (\d+)\(RSP\)$`)
	dssRspOpRe     = regexp.MustCompile(`(\d+)\(RSP\)`)
	dssRspAddrRe   = regexp.MustCompile(`^ADD \$(\d+), RSP, R\d+$`)
	dssRspAnyRe    = regexp.MustCompile(`\(RSP\)|, RSP,|RSP\b`)
)

func a64DeadSimdOutStores(body string) string {
	return a64DeadSimdOutStoresSegmented(body, body)
}

// a64DeadSimdOutStoresSegmented is the fused-window form: reads are
// counted over `whole` (the complete function body, so a store whose
// only reader sits inside a fused window stays), while stores are
// dropped only within `body` (one outside-window segment).
func a64DeadSimdOutStoresSegmented(body, whole string) string {
	lines := strings.Split(body, "\n")

	// Pass 1: count reads per offset (16-byte overlap granularity)
	// across the WHOLE function.
	reads := map[int]int{}
	note := func(off int) { reads[off]++ }
	for _, l := range strings.Split(whole, "\n") {
		t := strings.TrimSpace(l)
		// Comments are not memory operands: a spare-forwarded reload
		// carries its origin slot in a comment only, and pinning the
		// store on that would keep every single-use intermediate
		// alive. The spare park (kept unconditionally below) is what
		// serves those consumers.
		if c := strings.Index(t, " // "); c >= 0 {
			t = t[:c]
		}
		if m := fmovqF0StoreRe.FindStringSubmatch(t); m != nil {
			// The store itself is not a read.
			continue
		}
		if m := dssRspAddrRe.FindStringSubmatch(t); m != nil {
			// Slot address escapes into a register; the pointee may
			// be read at any width later. Count both halves.
			off, err := strconv.Atoi(m[1])
			if err != nil {
				return body
			}
			note(off)
			note(off + 8)
			continue
		}
		if strings.Contains(t, "RSP") {
			ms := dssRspOpRe.FindAllStringSubmatch(t, -1)
			rest := dssRspOpRe.ReplaceAllString(t, "")
			if dssRspAnyRe.MatchString(rest) {
				// An RSP mention this pass does not model (bare RSP
				// arithmetic, unparseable form): keep everything.
				return body
			}
			for _, m := range ms {
				off, err := strconv.Atoi(m[1])
				if err != nil {
					return body
				}
				// Reads and writes both count: a narrower store into
				// the slot does not kill the wider value's other
				// half, so the original store must stay.
				note(off)
			}
		}
	}

	// Pass 2: drop stores whose 16 bytes nobody reads, plus a
	// directly trailing spare park (its value then has no consumer
	// the cache could serve — reloads of this slot cannot exist).
	isRead := func(off int) bool {
		for ro := range reads {
			if ro < off+16 && off < ro+8 {
				return true
			}
		}
		return false
	}
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if m := dssOutRe.FindStringSubmatch(t); m != nil {
			off, err := strconv.Atoi(m[1])
			if err == nil && !isRead(off) {
				// The spare park that may follow always stays: it is
				// what serves the consumers whose reloads were
				// rewritten to register moves.
				continue
			}
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n")
}
