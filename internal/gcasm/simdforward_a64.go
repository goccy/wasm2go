package gcasm

// Store-to-load forwarding over v128 stack slots, arm64.
//
// After splicing, a v128 op is one NEON instruction — but the VALUES
// still travel through the stack, because gc compiled them as [2]uint64
// locals: the result is stored to the outgoing-result slot, copied to a
// local via an LDP/STP pair, copied back to an outgoing-arg slot for
// the next op, and reloaded. One op, one instruction of work, around
// ten instructions of freight.
//
// This pass runs over one transformed body and tracks, within a basic
// block, which 16-byte stack slots and which V registers hold the same
// value. Three rewrites fall out:
//
//   - an FMOVQ reload of a value already sitting in the SAME V register
//     is dropped;
//   - a reload of a value sitting in a DIFFERENT V register becomes a
//     register move (one ORR);
//   - an LDP/STP pair that copies a slot whose value is already known
//     is dropped when the pass can PROVE the loaded GPRs are dead —
//     both are redefined before any use in the remainder of the block.
//
// Tracking is strictly conservative. The recognized instruction set is
// a whitelist; anything else invalidates whatever state it could
// possibly touch — an unknown mention of an F/V register clears the
// register cache, an unknown (RSP) operand clears the slot map, a
// label, branch target or call clears everything. When the pass cannot
// tell, it forwards nothing and the body runs exactly as emitted.
//
// The pass never deletes a STORE: a slot may be read by a later block,
// and blocks are analysed independently.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	fwdFmovqStoreRe = regexp.MustCompile(`^\s*FMOVQ F(\d+), (\d+)\(RSP\)(?: //.*)?$`)
	fwdFmovqLoadRe  = regexp.MustCompile(`^\s*FMOVQ (\d+)\(RSP\), F(\d+)(?: //.*)?$`)
	fwdLdpRe        = regexp.MustCompile(`^\s*LDP\s+(\d+)\(RSP\), \((R\d+), (R\d+)\)$`)
	fwdLdpSymRe     = regexp.MustCompile(`^\s*LDP\s+(·[A-Za-z0-9_]+)\(SB\), \((R\d+), (R\d+)\)$`)
	fwdStpRe        = regexp.MustCompile(`^\s*STP\s+\((R\d+), (R\d+)\), (\d+)\(RSP\)$`)
	fwdLabelRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:$`)
	fwdBranchRe     = regexp.MustCompile(`^\s*(B[A-Z]*|JMP|CBZ\w*|CBNZ\w*|TBZ|TBNZ|CALL|RET)\b`)
	fwdRegTokenRe   = regexp.MustCompile(`\b(F\d+|V\d+|R\d+)\b`)
	fwdRspWriteRe   = regexp.MustCompile(`\(RSP\)$`)
	fwdRspOffRe     = regexp.MustCompile(`(\d+)\(RSP\)$`)
	// A store through a register (`MOVD R24, (R26)`) may alias any stack
	// slot — the lane splices build RSP-relative addresses in GPRs.
	fwdIndirectRe = regexp.MustCompile(`\((R\d+)\)(\((R\d+)[^)]*\))?$`)
)

// fwdState is the per-block equivalence state. constIDs persists across
// blocks: a rodata symbol always denotes the same 16 bytes.
type fwdState struct {
	nextID   int
	slotVal  map[int]int    // RSP offset of a 16-byte slot → value id
	fregVal  map[int]int    // V register number → value id
	pairLo   map[string]int // GPR holding the LOW half of a value
	pairHi   map[string]int // GPR holding the HIGH half
	constIDs map[string]int // rodata symbol → value id
}

func newFwdState() *fwdState {
	return &fwdState{
		slotVal:  map[int]int{},
		fregVal:  map[int]int{},
		pairLo:   map[string]int{},
		pairHi:   map[string]int{},
		constIDs: map[string]int{},
	}
}

// constOf returns the stable value id of a rodata symbol.
func (s *fwdState) constOf(sym string) int {
	if v, ok := s.constIDs[sym]; ok {
		return v
	}
	v := s.fresh()
	s.constIDs[sym] = v
	return v
}

func (s *fwdState) reset() {
	s.slotVal = map[int]int{}
	s.fregVal = map[int]int{}
	s.pairLo = map[string]int{}
	s.pairHi = map[string]int{}
}

func (s *fwdState) fresh() int {
	s.nextID++
	return s.nextID
}

// slotOf returns the value in a slot, minting one if unknown.
func (s *fwdState) slotOf(off int) int {
	if v, ok := s.slotVal[off]; ok {
		return v
	}
	v := s.fresh()
	s.slotVal[off] = v
	return v
}

// clobberSlots drops every tracked slot overlapping [off, off+n).
func (s *fwdState) clobberSlots(off, n int) {
	for so := range s.slotVal {
		if off < so+16 && so < off+n {
			delete(s.slotVal, so)
		}
	}
}

// clobberGPR forgets a GPR's pair binding.
func (s *fwdState) clobberGPR(r string) {
	delete(s.pairLo, r)
	delete(s.pairHi, r)
}

// clobberFreg forgets one V register.
func (s *fwdState) clobberFreg(n int) {
	delete(s.fregVal, n)
}

// a64SpliceWordClobbers reports the V registers a spliced WORD line can
// write. The splice tables only ever use v0–v3 plus the replace-lane
// copy in F16; go: lines use R3/R4 (handled by the GPR scan). Being
// generous here costs nothing but a missed forward.
// v4 appears in the f16 conversion body ("movi v4"); omitting it
// let a forwarded value parked in F4 survive across that splice on
// paper while being clobbered in fact.
var a64SpliceWordClobberList = []int{0, 1, 2, 3, 4, 16}

// gprsDeadAfter proves that every register in regs is redefined before
// any use in the rest of the basic block. Only definitely-recognized
// definition forms count; a branch, label, call, or any ambiguous
// mention ends the proof as failure. Used before deleting an LDP/STP
// copy pair, whose registers would otherwise still carry the value.
func gprsDeadAfter(lines []string, start int, regs ...string) bool {
	alive := map[string]bool{}
	for _, r := range regs {
		alive[r] = true
	}
	for i := start; i < len(lines) && len(alive) > 0; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if fwdLabelRe.MatchString(t) || fwdBranchRe.MatchString(t) {
			return false
		}
		if m := fwdLdpRe.FindStringSubmatch(t); m != nil {
			delete(alive, m[2])
			delete(alive, m[3])
			continue
		}
		if m := fwdLdpSymRe.FindStringSubmatch(t); m != nil {
			delete(alive, m[2])
			delete(alive, m[3])
			continue
		}
		toks := fwdRegTokenRe.FindAllString(t, -1)
		for ti, tok := range toks {
			if !alive[tok] {
				continue
			}
			// A pure definition mentions the register exactly once, as
			// the final operand of a load/move whose source is not the
			// register itself.
			mentions := 0
			for _, o := range toks {
				if o == tok {
					mentions++
				}
			}
			if mentions == 1 && ti == len(toks)-1 && strings.HasSuffix(t, tok) &&
				(strings.HasPrefix(t, "MOVD") || strings.HasPrefix(t, "MOVW") ||
					strings.HasPrefix(t, "MOVH") || strings.HasPrefix(t, "MOVB")) {
				delete(alive, tok)
			} else {
				return false
			}
		}
	}
	return len(alive) == 0
}

// a64ForwardSimdSlots rewrites body (one TEXT's worth of lines, as
// produced by TransformARM64) with slot/register forwarding applied.
func a64ForwardSimdSlots(body string) string {
	lines := strings.Split(body, "\n")
	st := newFwdState()
	out := make([]string, 0, len(lines))

	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case t == "" || strings.HasPrefix(t, "TEXT ") || strings.HasPrefix(t, "NO_LOCAL_POINTERS") ||
			strings.HasPrefix(t, "GLOBL ") || strings.HasPrefix(t, "DATA "):
			out = append(out, l)
			continue
		case fwdLabelRe.MatchString(t):
			st.reset()
			out = append(out, l)
			continue
		case fwdBranchRe.MatchString(t):
			// Conditional branches fall through with state intact —
			// the taken path lands on a label, which resets. CALL and
			// RET end the block's usefulness outright.
			if strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") {
				st.reset()
			}
			out = append(out, l)
			continue
		}

		if m := fwdFmovqStoreRe.FindStringSubmatch(t); m != nil {
			freg, ferr := strconv.Atoi(m[1])
			off, oerr := strconv.Atoi(m[2])
			if ferr != nil || oerr != nil {
				// \d+ captures cannot fail to parse short of overflow;
				// treat an overflowing offset as an unknown instruction.
				st.reset()
				out = append(out, l)
				continue
			}
			v, ok := st.fregVal[freg]
			if !ok {
				v = st.fresh()
				st.fregVal[freg] = v
			}
			st.clobberSlots(off, 16)
			st.slotVal[off] = v
			out = append(out, l)
			continue
		}
		if m := fwdFmovqLoadRe.FindStringSubmatch(t); m != nil {
			off, oerr := strconv.Atoi(m[1])
			freg, ferr := strconv.Atoi(m[2])
			if ferr != nil || oerr != nil {
				st.reset()
				out = append(out, l)
				continue
			}
			v := st.slotOf(off)
			if cur, ok := st.fregVal[freg]; ok && cur == v {
				continue // already there: drop the reload
			}
			if srcReg, ok := fwdFindFreg(st, v, freg); ok {
				// mov v<freg>.16b, v<src>.16b (ORR): value is in
				// another V register.
				enc := 0x4EA01C00 | uint32(srcReg)<<16 | uint32(srcReg)<<5 | uint32(freg)
				out = append(out, fmt.Sprintf("\tWORD $0x%08x // mov v%d.16b, v%d.16b (fwd)", enc, freg, srcReg))
				st.fregVal[freg] = v
				continue
			}
			st.fregVal[freg] = v
			out = append(out, l)
			continue
		}
		if m := fwdLdpRe.FindStringSubmatch(t); m != nil {
			off, oerr := strconv.Atoi(m[1])
			if oerr != nil {
				st.reset()
				out = append(out, l)
				continue
			}
			ra, rb := m[2], m[3]
			// A 16-byte-slot copy begins. If the following instruction
			// is the matching STP, treat the pair as one slot→slot copy.
			if i+1 < len(lines) {
				if sm := fwdStpRe.FindStringSubmatch(strings.TrimSpace(lines[i+1])); sm != nil && sm[1] == ra && sm[2] == rb {
					dst, derr := strconv.Atoi(sm[3])
					if derr != nil {
						st.reset()
						out = append(out, l)
						continue
					}
					v := st.slotOf(off)
					st.clobberSlots(dst, 16)
					st.slotVal[dst] = v
					st.clobberGPR(ra)
					st.clobberGPR(rb)
					// When the value already sits in a V register and
					// the pair registers are provably dead afterwards,
					// the whole GPR bounce collapses into one vector
					// store (the destination slot must still be
					// written: later blocks may read it).
					if srcReg, ok := fwdFindFreg(st, v, -1); ok && gprsDeadAfter(lines, i+2, ra, rb) {
						out = append(out, fmt.Sprintf("	FMOVQ F%d, %d(RSP) // fwd copy", srcReg, dst))
						i++
						continue
					}
					st.pairLo[ra] = v
					st.pairHi[rb] = v
					out = append(out, l, lines[i+1])
					i++
					continue
				}
			}
			st.clobberGPR(ra)
			st.clobberGPR(rb)
			st.pairLo[ra] = st.slotOf(off)
			st.pairHi[rb] = st.slotOf(off)
			out = append(out, l)
			continue
		}
		if m := fwdLdpSymRe.FindStringSubmatch(t); m != nil {
			// A rodata (v128 const) load: the pair now holds a value
			// identified by the symbol, stable across the function.
			v := st.constOf(m[1])
			st.clobberGPR(m[2])
			st.clobberGPR(m[3])
			st.pairLo[m[2]] = v
			st.pairHi[m[3]] = v
			out = append(out, l)
			continue
		}
		if m := fwdStpRe.FindStringSubmatch(t); m != nil {
			ra, rb := m[1], m[2]
			off, oerr := strconv.Atoi(m[3])
			if oerr != nil {
				st.reset()
				out = append(out, l)
				continue
			}
			st.clobberSlots(off, 16)
			if lo, ok := st.pairLo[ra]; ok {
				if hi, ok2 := st.pairHi[rb]; ok2 && lo == hi {
					st.slotVal[off] = lo
				}
			}
			out = append(out, l)
			continue
		}
		if strings.HasPrefix(t, "WORD $") {
			// A spliced op body writes v0–v3 (and the lane copies use
			// F16). After the op, V0 holds the op's RESULT — give it a
			// fresh id so the store that follows records it and later
			// reloads forward from the register.
			for _, n := range a64SpliceWordClobberList {
				st.clobberFreg(n)
			}
			st.fregVal[0] = st.fresh()
			out = append(out, l)
			continue
		}

		// Generic instruction: invalidate what it could touch.
		if fwdRspWriteRe.MatchString(t) {
			// Store to a stack slot (last operand is N(RSP)).
			if mm := fwdRspOffRe.FindStringSubmatch(t); mm != nil {
				off, oerr := strconv.Atoi(mm[1])
				if oerr != nil {
					st.reset()
					out = append(out, l)
					continue
				}
				// Non-FMOVQ/STP stores write at most 8 bytes.
				st.clobberSlots(off, 8)
			} else {
				st.slotVal = map[int]int{}
			}
		} else if fwdIndirectRe.MatchString(t) {
			// The last operand is a register-indirect memory form, so
			// this is a STORE through a register, which may target any
			// stack slot — the lane splices address RSP through a GPR.
			// (Loads never match: their destination register is last.)
			st.slotVal = map[int]int{}
		}
		for _, tok := range fwdRegTokenRe.FindAllString(t, -1) {
			switch tok[0] {
			case 'F', 'V':
				if n, err := strconv.Atoi(tok[1:]); err == nil {
					st.clobberFreg(n)
				}
			case 'R':
				st.clobberGPR(tok)
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// a64DeadArgStores deletes splice result stores (marked `// simd out`)
// that are never read again in their basic block. Those stores target
// gc's outgoing ABIInternal result slots — communication scratch that
// gc rewrites per call site and never carries across a block — so a
// store whose block ends, or whose slot is completely overwritten,
// without an intervening read served no one. Splicing plus forwarding
// removes the READS of these slots; this removes the writes.
//
// Reads through computed addresses are handled conservatively: an
// `ADD $n, RSP, R` materializing an address into the slot's range, or
// any bare `MOVD RSP, R`, marks the slot readable.
func a64DeadArgStores(body string) string {
	lines := strings.Split(body, "\n")
	kill := map[int]bool{}
	for i, l := range lines {
		if !strings.HasSuffix(l, "// simd out") {
			continue
		}
		m := fwdFmovqStoreRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		off, oerr := strconv.Atoi(m[2])
		if oerr != nil {
			continue
		}
		if a64ArgStoreDead(lines, i+1, off) {
			kill[i] = true
		}
	}
	if len(kill) == 0 {
		return body
	}
	out := make([]string, 0, len(lines))
	for i, l := range lines {
		if !kill[i] {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

var fwdRspAnyRe = regexp.MustCompile(`(\d+)\(RSP\)`)
var fwdAddRspRe = regexp.MustCompile(`^ADD \$(\d+), RSP, R\d+$`)

// a64ArgStoreDead scans forward from start for a read of the 16-byte
// slot at off. It reports true when the block ends or the slot is
// completely overwritten first.
func a64ArgStoreDead(lines []string, start, off int) bool {
	for i := start; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if fwdLabelRe.MatchString(t) || fwdBranchRe.MatchString(t) {
			return true // dead: the area does not survive the block
		}
		if strings.Contains(t, "MOVD RSP") {
			return false
		}
		if m := fwdAddRspRe.FindStringSubmatch(t); m != nil {
			n, nerr := strconv.Atoi(m[1])
			if nerr != nil {
				return false // unparseable offset: assume the address escapes
			}
			if n < off+16 && off < n+16 {
				return false // address of the slot escapes into a register
			}
			continue
		}
		// Complete overwrite kills the store; any other overlapping
		// mention is (conservatively) a read.
		if sm := fwdFmovqStoreRe.FindStringSubmatch(t); sm != nil {
			so, serr := strconv.Atoi(sm[2])
			if serr != nil {
				return false // unparseable offset: assume a read
			}
			if so == off {
				return true
			}
			if so < off+16 && off < so+16 {
				return false
			}
			continue
		}
		if sm := fwdStpRe.FindStringSubmatch(t); sm != nil {
			so, serr := strconv.Atoi(sm[3])
			if serr != nil {
				return false
			}
			if so == off {
				return true
			}
			if so < off+16 && off < so+16 {
				return false
			}
			continue
		}
		for _, mm := range fwdRspAnyRe.FindAllStringSubmatch(t, -1) {
			n, nerr := strconv.Atoi(mm[1])
			if nerr != nil {
				return false
			}
			if n < off+16 && n+16 > off {
				return false // overlapping mention: treat as a read
			}
		}
	}
	return true // fell off the body: nothing read it
}

// fwdFindFreg finds a V register other than want that currently holds v.
func fwdFindFreg(st *fwdState, v, want int) (int, bool) {
	for n, val := range st.fregVal {
		if val == v && n != want {
			return n, true
		}
	}
	return 0, false
}
