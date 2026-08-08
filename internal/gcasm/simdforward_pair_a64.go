package gcasm

// Transfer forwarding between pair-form splices, arm64.
//
// After scalarization every v128 value lives in a GPR pair, and each
// spliced op moves its operands GPR→V (fmov+ins per operand) and its
// result V→GPR (fmov+umov). Two ops in a row therefore round-trip
// through the integer file even when the value never leaves the vector
// unit in spirit — a JIT would keep it in the V register.
//
// This pass value-numbers the GPRs and V registers within a basic block
// and deletes the build sequence (fmov dK, xN / mov vK.d[1], xM) when
// vK provably still holds that exact value from an earlier splice. The
// result moves stay: gc's code consumes them.
//
// The tracked instruction set is tiny and everything else invalidates
// what it could touch, in the same conservative style as the slot
// forwarding pass. All spliced lines carry their disassembly as a
// comment (`WORD $0x... // fmov d0, x0`), which is what the pass reads
// — the comment is part of the generator's own output contract, not a
// foreign format.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	pfWordRe = regexp.MustCompile(`^WORD \$0x[0-9a-f]+ // (.+)$`)
	// fmov dK, xN — build the low half.
	pfBuildLoRe = regexp.MustCompile(`^fmov d(\d+), x(\d+)$`)
	// mov vK.d[1], xN — build the high half.
	pfBuildHiRe = regexp.MustCompile(`^mov v(\d+)\.d\[1\], x(\d+)$`)
	// fmov xN, dK / mov xN, vK.d[1] — move a result out.
	pfOutLoRe = regexp.MustCompile(`^fmov x(\d+), d(\d+)$`)
	pfOutHiRe = regexp.MustCompile(`^mov x(\d+), v(\d+)\.d\[1\]$`)
	// A vector op names its destination first: `op vD.arr, ...`.
	pfVecDestRe = regexp.MustCompile(`^\S+ v(\d+)\.`)
	// gc's register moves.
	pfMovRegRe = regexp.MustCompile(`^MOVD\tR(\d+), R(\d+)$`)
	pfGprTokRe = regexp.MustCompile(`\b[RxXwW](\d+)\b`)
	pfVregRe   = regexp.MustCompile(`\b[vVF](\d+)\b`)
)

type pairFwd struct {
	nextID int
	gpr    map[int]int // GPR number → value id
	vlo    map[int]int // V register → value id of d[0]
	vhi    map[int]int // V register → value id of d[1]
}

func (p *pairFwd) fresh() int { p.nextID++; return p.nextID }

func (p *pairFwd) reset() {
	p.gpr = map[int]int{}
	p.vlo = map[int]int{}
	p.vhi = map[int]int{}
}

// pfNum parses a decimal register/slot capture. The regexes capture
// digit runs from this generator's own output, so the only possible
// failure is overflow; -1 then keys a register that never matches a
// real one, which costs at most a lost forward.
func pfNum(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// findVreg reports a V register other than skip currently holding the
// (lo, hi) value pair.
func (p *pairFwd) findVreg(lo, hi, skip int) (int, bool) {
	if lo == 0 || hi == 0 {
		return 0, false
	}
	for k, v := range p.vlo {
		if k < 0 {
			continue // overflow sentinel: not a real register
		}
		if k != skip && v == lo && p.vhi[k] == hi {
			return k, true
		}
	}
	return 0, false
}

func (p *pairFwd) gprOf(n int) int {
	if v, ok := p.gpr[n]; ok {
		return v
	}
	v := p.fresh()
	p.gpr[n] = v
	return v
}

// a64ForwardPairTransfers deletes redundant GPR→V build pairs in body.
func a64ForwardPairTransfers(body string) string {
	lines := strings.Split(body, "\n")
	p := &pairFwd{}
	p.reset()
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
			p.reset()
			out = append(out, l)
			continue
		case fwdBranchRe.MatchString(t):
			if strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") {
				p.reset()
			}
			out = append(out, l)
			continue
		}

		if m := pfWordRe.FindStringSubmatch(t); m != nil {
			dis := m[1]
			if bm := pfBuildLoRe.FindStringSubmatch(dis); bm != nil {
				vk := pfNum(bm[1])
				xn := pfNum(bm[2])
				want := p.gprOf(xn)
				// Pair with the following build-hi line when present.
				if i+1 < len(lines) {
					if hm := pfWordDis(lines[i+1], pfBuildHiRe); hm != nil {
						vk2 := pfNum(hm[1])
						xm := pfNum(hm[2])
						if vk2 == vk {
							wantHi := p.gprOf(xm)
							if p.vlo[vk] == want && p.vhi[vk] == wantHi && p.vlo[vk] != 0 {
								i++ // both builds redundant
								continue
							}
							// The value may live whole in ANOTHER V
							// register (the previous op's result that
							// gc round-tripped through GPRs): one
							// vector copy replaces both transfers.
							if src, ok := p.findVreg(want, wantHi, vk); ok && vk >= 0 {
								enc := 0x4EA01C00 | uint32(src)<<16 | uint32(src)<<5 | uint32(vk)
								out = append(out, fmt.Sprintf("	WORD $0x%08x // mov v%d.16b, v%d.16b (pair fwd)", enc, vk, src))
								p.vlo[vk] = want
								p.vhi[vk] = wantHi
								i++
								continue
							}
							p.vlo[vk] = want
							p.vhi[vk] = wantHi
							out = append(out, l, lines[i+1])
							i++
							continue
						}
					}
				}
				// Lone build-lo: fmov dK zeroes the high half.
				p.vlo[vk] = want
				p.vhi[vk] = p.fresh()
				out = append(out, l)
				continue
			}
			if bm := pfBuildHiRe.FindStringSubmatch(dis); bm != nil {
				vk := pfNum(bm[1])
				xn := pfNum(bm[2])
				p.vhi[vk] = p.gprOf(xn)
				out = append(out, l)
				continue
			}
			if om := pfOutLoRe.FindStringSubmatch(dis); om != nil {
				xn := pfNum(om[1])
				vk := pfNum(om[2])
				if p.vlo[vk] == 0 {
					p.vlo[vk] = p.fresh()
				}
				p.gpr[xn] = p.vlo[vk]
				out = append(out, l)
				continue
			}
			if om := pfOutHiRe.FindStringSubmatch(dis); om != nil {
				xn := pfNum(om[1])
				vk := pfNum(om[2])
				if p.vhi[vk] == 0 {
					p.vhi[vk] = p.fresh()
				}
				p.gpr[xn] = p.vhi[vk]
				out = append(out, l)
				continue
			}
			// Any other spliced instruction: clobber the GPRs and the
			// vector destination it names.
			if vm := pfVecDestRe.FindStringSubmatch(dis); vm != nil {
				vk := pfNum(vm[1])
				p.vlo[vk] = p.fresh()
				p.vhi[vk] = p.fresh()
			} else {
				// Scalar-destination WORD (csel/lsr/... x0) — clobber
				// every GPR it names; first-named is the destination.
				for _, g := range pfGprTokRe.FindAllStringSubmatch(dis, -1) {
					n := pfNum(g[1])
					delete(p.gpr, n)
				}
			}
			out = append(out, l)
			continue
		}

		if m := pfMovRegRe.FindStringSubmatch(t); m != nil {
			src := pfNum(m[1])
			dst := pfNum(m[2])
			p.gpr[dst] = p.gprOf(src)
			out = append(out, l)
			continue
		}

		// Generic gc instruction: clobber whatever it names. The LAST
		// register token of a load/move is its destination; being
		// imprecise here only loses forwards, never correctness,
		// because clobbering is the conservative direction.
		for _, g := range pfGprTokRe.FindAllStringSubmatch(t, -1) {
			n := pfNum(g[1])
			delete(p.gpr, n)
		}
		for _, v := range pfVregRe.FindAllStringSubmatch(t, -1) {
			n := pfNum(v[1])
			delete(p.vlo, n)
			delete(p.vhi, n)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// pfWordDis matches a WORD line's disassembly comment against re.
func pfWordDis(line string, re *regexp.Regexp) []string {
	m := pfWordRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}
	return re.FindStringSubmatch(m[1])
}
