package gcasm

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// arm64 peephole for the software fp32→fp16 rounding idiom.
//
// llama.cpp inlines ggml's fp32→fp16 conversion (the Giesen
// round-to-nearest-even algorithm) at every f16 store, and gc
// compiles each site to a fixed ~30-instruction shape — float
// scaling by 0x1.0p+112/0x1.0p-110, a bias clamp, a NaN branch and
// exponent/mantissa reassembly — differing between sites only in
// register allocation and operand order. Hardware does the whole
// thing in one FCVT.
//
// a64F16Peephole matches the shape by DATAFLOW (values may hop
// registers, multiply/add operands commute) and rewrites each site to
// the native convert plus a branchless NaN select that reproduces the
// software path's exact sign|0x7E00 NaN result, so the rewrite is
// bit-identical for every input. For every register the region
// writes, the rewrite either leaves the exact final value the
// original left (the result, the sign bits, shl1, the abs mask and
// every constant, at the cost of a few immediate loads) or — for the
// handful of registers whose original final was an intermediate of
// the deleted arithmetic — proves the register dead by a conservative
// forward scan before touching the site.
//
// This runs on the raw -S capture BEFORE the transform's main loop,
// so branch offsets are still numeric and float constants still use
// the $f32.<bits>(SB) spelling.

// f16Debug enables near-miss reporting on stderr: candidates that
// matched past the first float-constant anchor but failed later print
// the failing step and instruction. Diagnostic aid only.
var f16Debug = os.Getenv("WASM2GO_F16_DEBUG") != ""

// f16Blocker records, under f16Debug, the instruction that defeated
// the last deadness scan.
var f16Blocker string

var (
	f16IntRegRe = regexp.MustCompile(`^R(?:[0-9]|1[0-9]|2[0-9]|30)$`)
	f16FRegRe   = regexp.MustCompile(`^F(?:[0-9]|1[0-9]|2[0-9]|3[01])$`)
)

type f16Site struct {
	idxs []int // insn indices matched, in order
	// registers the replacement builds on: input, shl1, abs mask,
	// sign, arm temp, 0x1000000, the pre-merge nonsign register and
	// the register the merged result actually lands in (the ORR
	// destination — gc uses either the nonsign or the sign register).
	w, s, a, x, y, n, r, res string
	fAcc                     string   // float reg carrying the converted bits
	ints                     []string // every integer register the region bound
	// skipped are interleaved instruction indices inside the region
	// that are not part of the idiom: they are kept in place, and the
	// site is safe only if they touch none of the bound registers,
	// never touch or read the flags, and are not branch targets.
	skipped []int
	// lastWrite maps every region-written register to its final
	// value: "$<imm>" for a constant, or "" for an arithmetic
	// intermediate (needs a deadness proof).
	lastWrite map[string]string
}

// a64F16Peephole rewrites every provable idiom site and returns the
// new instruction list (unchanged when nothing matches). resolve is
// the transform's callee-signature lookup: the deadness scan uses it
// to treat an ABI call as reading exactly the callee's argument
// registers and killing every other caller-saved register.
func a64F16Peephole(insns []Insn, resolve func(string) ([]ArgKind, bool, ArgKind, string, bool), resultReg string) []Insn {
	var sites []f16Site
	for i := 0; i < len(insns); i++ {
		if !strings.HasPrefix(insns[i].Text, "ADD\t") {
			continue
		}
		if site, ok := f16Match(insns, i); ok {
			sites = append(sites, site)
			i = site.idxs[len(site.idxs)-1]
		}
	}
	if len(sites) == 0 {
		return insns
	}
	drop := map[int]bool{}
	replAt := map[int][]string{}
	for _, s := range sites {
		if !f16SiteSafe(insns, s, resolve, resultReg) {
			if f16Debug {
				fmt.Fprintf(os.Stderr, "f16-reject at +%d: unsafe (interleave, inbound branch, or scratch not provably dead)\n", insns[s.idxs[0]].Off)
			}
			continue
		}
		for _, idx := range s.idxs {
			drop[idx] = true
		}
		last := s.idxs[len(s.idxs)-1]
		// NaN-value scratch: any bound integer register that is dead
		// by the point it is written (reads of %n and %s are done) and
		// whose ledger final survives the borrow — a constant (re-
		// emitted below), the nonsign fix-up, or a dyn intermediate
		// (already requires a deadness proof). Registers carrying
		// finals the prefix established earlier (shl1, abs, sign, the
		// result) are ineligible.
		tmp := ""
		for _, cand := range append([]string{s.n, s.r, s.s}, s.ints...) {
			if cand == s.res || cand == s.x || cand == s.w {
				continue
			}
			switch tag := s.lastWrite[cand]; {
			case tag == "" || strings.HasPrefix(tag, "$") || tag == "nonsign":
				tmp = cand
			default:
				continue
			}
			break
		}
		ledgerOK := tmp != ""
		var repl []string
		// The shl1 and abs values are recomputed only when the ledger
		// says a register actually carries them out of the region. %w
		// stays readable up to the sign extraction: the only region
		// writes that can hit its register are the sign/result aliases,
		// which the ledger consistency checks pin to exactly those
		// roles.
		if s.lastWrite[s.s] == "shl1" {
			repl = append(repl, "ADD\t"+s.w+", "+s.w+", "+s.s)
		}
		if s.lastWrite[s.a] == "abs" {
			repl = append(repl, "AND\t$2147483647, "+s.w+", "+s.a)
		}
		repl = append(repl,
			// The native convert: fcvt bits ARE sign|nonsign, the
			// merged result. Writing the H view zeroes the rest of
			// the vector register, so the S-view move reads the
			// zero-extended binary16 bits.
			"FMOVS\t"+s.w+", "+s.fAcc,
			"FCMPS\t"+s.fAcc+", "+s.fAcc,
			"FCVTSH\t"+s.fAcc+", "+s.fAcc,
			// NaN test (HI after CMN with 0x1000000 ⇔ shl1 >
			// 0xFF000000, the deleted branch's polarity); nothing
			// below touches the flags.

			// sign bits (the last read of %w), the NaN result
			// sign|0x7E00 in the scratch, the converted bits, and
			// the select.
			"UBFX\t$16, "+s.w+", $16, "+s.x,
			"AND\t$32768, "+s.x+", "+s.x,
			"ORR\t$32256, "+s.x+", "+tmp,
			"FMOVS\t"+s.fAcc+", "+s.res,
			"CSEL\tVS, "+tmp+", "+s.res+", "+s.res,
		)
		// Ledger consistency — every tagged final must belong to the
		// register the replacement leaves it in — plus the post fix-
		// ups for the ones the replacement scratched. Post lines read
		// only the result register, so they commute; sorted for
		// determinism.
		var post []string
		for reg, tag := range s.lastWrite {
			switch {
			case tag == "result":
				ledgerOK = ledgerOK && reg == s.res
			case tag == "sign":
				ledgerOK = ledgerOK && reg == s.x
			case tag == "shl1":
				ledgerOK = ledgerOK && reg == s.s && reg != tmp
			case tag == "abs":
				ledgerOK = ledgerOK && reg == s.a && reg != tmp && reg != s.x && reg != s.res && reg != s.n
			case tag == "nonsign":
				// Pre-merge nonsign = result & 0x7FFF on both paths
				// (0x7E00 on the NaN path, like the software arm).
				ledgerOK = ledgerOK && reg == s.r && reg != s.res
				post = append(post, "AND\t$32767, "+s.res+", "+reg)
			case strings.HasPrefix(tag, "$"):
				post = append(post, "MOVD\t"+tag+", "+reg)
			}
		}
		if !ledgerOK {
			if f16Debug {
				fmt.Fprintf(os.Stderr, "f16-reject at +%d: ledger %v w=%s s=%s a=%s x=%s n=%s r=%s res=%s tmp=%s\n",
					insns[s.idxs[0]].Off, s.lastWrite, s.w, s.s, s.a, s.x, s.n, s.r, s.res, tmp)
			}
			for _, idx := range s.idxs {
				delete(drop, idx)
			}
			continue
		}
		for i := 0; i < len(post); i++ {
			for j := i + 1; j < len(post); j++ {
				if post[j] < post[i] {
					post[i], post[j] = post[j], post[i]
				}
			}
		}
		replAt[last] = append(repl, post...)
	}
	if len(replAt) == 0 {
		return insns
	}
	var out []Insn
	for i, in := range insns {
		if repl, ok := replAt[i]; ok {
			// The replacement inherits the join instruction's offset:
			// no branch targets the region interior (checked), and
			// downstream labeling only needs offsets to stay ordered.
			for _, txt := range repl {
				out = append(out, Insn{Off: in.Off, Text: txt})
			}
			continue
		}
		if drop[i] {
			continue
		}
		out = append(out, in)
	}
	return out
}

// f16Skippable reports whether an interleaved instruction may be
// stepped over during matching: plain data movement or flag-neutral
// arithmetic only — no branches, calls, or anything that reads or
// writes NZCV (a skipped instruction executes BEFORE the rewritten
// sequence instead of at its original position, so it must commute
// with the deleted computation and with the flag window).
func f16Skippable(t string) bool {
	tab := strings.Index(t, "\t")
	if tab < 0 {
		return false
	}
	switch t[:tab] {
	case "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU",
		"FMOVS", "FMOVD", "ADD", "ADDW", "SUB", "SUBW", "AND", "ANDW",
		"ORR", "ORRW", "EOR", "EORW", "LSL", "LSLW", "LSR", "LSRW",
		"UBFX", "UBFXW", "SBFX", "SBFXW", "MUL", "MULW", "SXTW", "SXTH", "SXTB":
		return true
	}
	return false
}

// f16Match tries to bind the idiom starting at insns[start] (which
// must be its leading ADD), skipping NOP/HINT padding between steps.
func f16Match(insns []Insn, start int) (f16Site, bool) {
	s := f16Site{lastWrite: map[string]string{}}
	pos := start
	steps := 0
	fail := func(why string) (f16Site, bool) {
		if f16Debug && steps > 1 {
			got := ""
			if pos-1 >= 0 && pos-1 < len(insns) {
				got = insns[pos-1].Text
			}
			fmt.Fprintf(os.Stderr, "f16-miss at +%d: step %d (%s) got %q\n", insns[start].Off, steps, why, got)
		}
		return s, false
	}
	next := func() (string, bool) {
		for pos < len(insns) && (insns[pos].Text == "NOP" || strings.HasPrefix(insns[pos].Text, "HINT\t")) {
			pos++
		}
		if pos >= len(insns) {
			return "", false
		}
		s.idxs = append(s.idxs, pos)
		pos++
		steps++
		return insns[pos-1].Text, true
	}
	// unconsume rolls the last consumed instruction back and records
	// it as a kept interleaved skip, when it qualifies (see
	// f16Skippable; f16SiteSafe later verifies it touches no bound
	// register). Matchers call it to retry a step over interleave.
	skipBudget := 12
	unconsume := func() bool {
		if len(s.idxs) == 0 || steps <= 2 || skipBudget <= 0 {
			return false
		}
		i := s.idxs[len(s.idxs)-1]
		if !f16Skippable(insns[i].Text) {
			return false
		}
		s.idxs = s.idxs[:len(s.idxs)-1]
		steps--
		skipBudget--
		s.skipped = append(s.skipped, i)
		return true
	}
	wrote := func(reg, final string) { s.lastWrite[reg] = final }
	// prefixed consumes the next instruction matching the prefix and
	// returns the remainder, retrying over interleaved skippable
	// instructions (see unconsume).
	prefixed := func(prefix string) (string, bool) {
		for {
			got, ok := next()
			if !ok {
				return "", false
			}
			if strings.HasPrefix(got, prefix) {
				return got[len(prefix):], true
			}
			if !unconsume() {
				return "", false
			}
		}
	}
	// op3 matches "OP\tx, y, dst" with {x,y} == {va, vb} in either
	// order, any register destination of class re; returns dst.
	op3 := func(op, va, vb string, re *regexp.Regexp, final string) (string, bool) {
		for {
			got, ok := next()
			if !ok {
				return "", false
			}
			if strings.HasPrefix(got, op+"\t") {
				p := strings.Split(got[len(op)+1:], ", ")
				if len(p) == 3 {
					x, y, dst := p[0], p[1], p[2]
					if (x == va && y == vb || x == vb && y == va) && re.MatchString(dst) {
						wrote(dst, final)
						if strings.HasPrefix(dst, "R") {
							s.ints = append(s.ints, dst)
						}
						return dst, true
					}
				}
			}
			if !unconsume() {
				return "", false
			}
		}
	}
	// movConst matches "MOVD\t$imm, dst" and returns dst.
	movConst := func(imm string) (string, bool) {
		dst, ok := prefixed("MOVD\t" + imm + ", ")
		if !ok || !f16IntRegRe.MatchString(dst) {
			return "", false
		}
		wrote(dst, imm)
		s.ints = append(s.ints, dst)
		return dst, true
	}
	// exact matches one full instruction, recording dst as written.
	exact := func(txt, dst, final string) bool {
		if rest, ok := prefixed(txt); !ok || rest != "" {
			return false
		}
		if dst != "" {
			wrote(dst, final)
		}
		return true
	}
	// fload matches "FMOVS\tsrc, Fdst" and returns dst.
	fload := func(src string) (string, bool) {
		dst, ok := prefixed("FMOVS\t" + src + ", ")
		if !ok || !f16FRegRe.MatchString(dst) {
			return "", false
		}
		wrote(dst, "")
		return dst, true
	}

	// ADD w, w, s
	got, ok := next()
	if !ok {
		return fail("start")
	}
	p := strings.Split(strings.TrimPrefix(got, "ADD\t"), ", ")
	if len(p) != 3 || p[0] != p[1] || !f16IntRegRe.MatchString(p[0]) ||
		!f16IntRegRe.MatchString(p[2]) || p[2] == p[0] {
		return fail("shl1")
	}
	s.w, s.s = p[0], p[2]
	wrote(s.s, "shl1")
	// AND $2147483647, w, a
	if s.a, ok = prefixed("AND\t$2147483647, " + s.w + ", "); !ok {
		return fail("abs")
	}
	if !f16IntRegRe.MatchString(s.a) || s.a == s.w || s.a == s.s {
		return fail("abs reg")
	}
	wrote(s.a, "abs")
	acc, ok := fload(s.a)
	if !ok {
		return fail("abs to float")
	}
	c1, ok := fload("$f32.77800000(SB)")
	if !ok {
		return fail("const 2^112")
	}
	if acc, ok = op3("FMULS", acc, c1, f16FRegRe, ""); !ok {
		return fail("mul 2^112")
	}
	c2, ok := fload("$f32.08800000(SB)")
	if !ok || c2 == acc {
		return fail("const 2^-110")
	}
	if acc, ok = op3("FMULS", acc, c2, f16FRegRe, ""); !ok {
		return fail("mul 2^-110")
	}
	// Bias clamp chain (registers may hop at every step).
	t1, ok := movConst("$1895825408")
	if !ok {
		return fail("bias const 1")
	}
	if !exact("CMPW\t"+t1+", "+s.s, "", "") {
		return fail("bias cmp")
	}
	t2, ok := movConst("$1895825408")
	if !ok {
		return fail("bias const 2")
	}
	t3, ok := prefixed("CSEL\tLS, " + t2 + ", " + s.s + ", ")
	if !ok || !f16IntRegRe.MatchString(t3) {
		return fail("bias csel")
	}
	wrote(t3, "")
	s.ints = append(s.ints, t3)
	t4, ok := prefixed("UBFX\t$1, " + t3 + ", $31, ")
	if !ok || !f16IntRegRe.MatchString(t4) {
		return fail("bias shift")
	}
	wrote(t4, "")
	s.ints = append(s.ints, t4)
	t5, ok := prefixed("AND\t$2139095040, " + t4 + ", ")
	if !ok || !f16IntRegRe.MatchString(t5) {
		return fail("bias mask")
	}
	wrote(t5, "")
	s.ints = append(s.ints, t5)
	u, ok := movConst("$125829120")
	if !ok {
		return fail("bias add const")
	}
	t6, ok := op3("ADD", u, t5, f16IntRegRe, "")
	if !ok {
		return fail("bias add")
	}
	fb, ok := fload(t6)
	if !ok || fb == acc {
		return fail("bias to float")
	}
	if acc, ok = op3("FADDS", acc, fb, f16FRegRe, ""); !ok {
		return fail("add bias")
	}
	// NaN test and branch.
	if s.n, ok = movConst("$16777216"); !ok {
		return fail("nan const")
	}
	if !exact("CMNW\t"+s.n+", "+s.s, "", "") {
		return fail("nan cmp")
	}
	brA, ok := prefixed("BLS\t")
	if !ok {
		return fail("nan branch")
	}
	// NaN arm: r = 0x7E00.
	if s.r, ok = prefixed("MOVD\t$32256, "); !ok {
		return fail("nan result")
	}
	if !f16IntRegRe.MatchString(s.r) {
		return fail("nan result reg")
	}
	wrote(s.r, "")
	brB, ok := prefixed("JMP\t")
	if !ok {
		return fail("nan join jump")
	}
	// Not-NaN arm: bits out + exponent/mantissa reassembly.
	notNaNIdx := len(s.idxs)
	if !exact("FMOVS\t"+acc+", "+s.r, s.r, "") {
		return fail("bits out")
	}
	s.fAcc = acc
	if s.y, ok = prefixed("UBFX\t$13, " + s.r + ", $19, "); !ok {
		return fail("exp shift")
	}
	if !f16IntRegRe.MatchString(s.y) || s.y == s.r {
		return fail("exp shift dst")
	}
	wrote(s.y, "")
	if !exact("AND\t$31744, "+s.y+", "+s.y, s.y, "") {
		return fail("exp mask")
	}
	if !exact("AND\t$4095, "+s.r+", "+s.r, s.r, "") {
		return fail("mantissa mask")
	}
	if !exact("ADD\t"+s.y+", "+s.r+", "+s.r, s.r, "nonsign") {
		return fail("nonsign")
	}
	// Join: sign merge.
	joinIdx := len(s.idxs)
	if s.x, ok = prefixed("UBFX\t$16, " + s.w + ", $16, "); !ok {
		return fail("sign shift")
	}
	if !f16IntRegRe.MatchString(s.x) || s.x == s.r {
		return fail("sign shift dst")
	}
	wrote(s.x, "")
	if !exact("AND\t$32768, "+s.x+", "+s.x, s.x, "sign") {
		return fail("sign mask")
	}
	// Sign merge: ORR {x,r} into either the nonsign or the sign
	// register (gc uses both forms), or occasionally a third one.
	if s.res, ok = op3("ORR", s.x, s.r, f16IntRegRe, "result"); !ok {
		return fail("sign merge")
	}
	// The two branch targets must be exactly the matched not-NaN and
	// join instructions.
	if brA != fmt.Sprintf("%d", insns[s.idxs[notNaNIdx]].Off) ||
		brB != fmt.Sprintf("%d", insns[s.idxs[joinIdx]].Off) {
		return fail("branch targets")
	}
	// Replacement-order aliasing constraints (the matched code's own
	// dataflow is register-explicit, so only the REPLACEMENT imposes
	// these): see the emission order in a64F16Peephole.
	if s.n == s.s {
		return fail("replacement alias n/s " + s.n)
	}
	// %w must never be written inside the region: the replacement
	// (and its ledger fix-ups) read it end to end.
	return s, true
}

// f16SiteSafe verifies the rewrite cannot change anything outside the
// region: only NOP/HINT interleave inside it, no branch from outside
// targets its interior, and every region-written register whose
// original final value the replacement does not reproduce is provably
// dead afterwards.
func f16SiteSafe(insns []Insn, s f16Site, resolve func(string) ([]ArgKind, bool, ArgKind, string, bool), resultReg string) bool {
	first, last := s.idxs[0], s.idxs[len(s.idxs)-1]
	inRegion := map[int]bool{}
	for _, idx := range s.idxs {
		inRegion[idx] = true
	}
	skippedOK := map[int]bool{}
	for _, idx := range s.skipped {
		skippedOK[idx] = true
	}
	bound := map[string]bool{}
	for _, r := range []string{s.w, s.s, s.a, s.x, s.y, s.n, s.r, s.res, s.fAcc} {
		bound[r] = true
	}
	for r := range s.lastWrite {
		bound[r] = true
	}
	for i := first; i <= last; i++ {
		if inRegion[i] {
			continue
		}
		t := insns[i].Text
		if t == "NOP" || strings.HasPrefix(t, "HINT\t") {
			continue
		}
		if !skippedOK[i] || !f16Skippable(t) {
			if f16Debug {
				fmt.Fprintf(os.Stderr, "f16-interleave at +%d: unexpected %q\n", insns[first].Off, t)
			}
			return false
		}
		// The kept interleaved instruction must not touch any bound
		// register (whole-token match, both namespaces).
		for reg := range bound {
			if reads, writes, ok := f16RegRoles(t, reg); !ok || reads || writes {
				if f16Debug {
					fmt.Fprintf(os.Stderr, "f16-interleave at +%d: %q touches bound %s\n", insns[first].Off, t, reg)
				}
				return false
			}
		}
	}
	lo, hi := insns[first].Off, insns[last].Off
	for i, in := range insns {
		if i >= first && i <= last {
			continue
		}
		if m := a64BranchRe.FindStringSubmatch(in.Text); m != nil {
			var t int
			if _, err := fmt.Sscanf(m[3], "%d", &t); err == nil && t > lo && t <= hi {
				return false
			}
		}
	}
	// Every register whose ledger tag is "dyn" (an intermediate of
	// the deleted arithmetic, the float scratch included) must be
	// provably dead; all other finals are reproduced exactly.
	for reg, tag := range s.lastWrite {
		if tag != "" {
			continue
		}
		if !f16DeadAfter(insns, last, reg, resolve, resultReg) {
			if f16Debug {
				fmt.Fprintf(os.Stderr, "f16-unsafe at +%d: %s not provably dead (blocked by %q)\n", insns[first].Off, reg, f16Blocker)
			}
			return false
		}
	}
	return true
}

// f16DeadAfter reports whether reg's value at insns[from] can never
// be observed again: on every path forward, the register is rewritten
// or ABI-killed before any read. The walk follows branches through
// the numeric-offset CFG; an ABI call reads exactly its callee's
// argument registers and kills every other caller-saved register
// (gc spills anything it still needs before a call). Anything not
// fully understood — unresolvable callees, indirect jumps, targets
// outside the map — makes the answer "not provably dead".
func f16DeadAfter(insns []Insn, from int, reg string, resolve func(string) ([]ArgKind, bool, ArgKind, string, bool), resultReg string) bool {
	offIdx := map[int]int{}
	for i, in := range insns {
		offIdx[in.Off] = i
	}
	const visitCap = 4096
	visited := map[int]bool{}
	work := []int{from + 1}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if i >= len(insns) {
			return false
		}
		if visited[i] {
			continue
		}
		visited[i] = true
		if len(visited) > visitCap {
			return false
		}
		t := insns[i].Text
		if f16Debug {
			f16Blocker = t
		}
		if t == "NOP" || strings.HasPrefix(t, "HINT\t") {
			work = append(work, i+1)
			continue
		}
		if strings.HasPrefix(t, "RET") {
			continue // value dies with the return
		}
		if m := a64CallRe.FindStringSubmatch(t); m != nil {
			if strings.HasPrefix(m[1], "runtime.panic") || strings.Contains(m[1], "Wasm_trap") || strings.Contains(m[1], "wasm_trap") {
				continue // no-return: the value dies with the trap
			}
			if _, isPair := a64SplicePairOp(m[1]); isPair {
				// Pair-form SIMD helpers carry v128 values as GPR
				// pairs and never take float arguments; their exact
				// integer argument set is not tabulated here, so
				// float registers are ABI-killed and integer ones
				// stay unproven.
				if strings.HasPrefix(reg, "F") {
					continue
				}
				return false
			}
			params, hasRes, res, _, ok := resolve(m[1])
			if !ok {
				return false
			}
			args, _ := assignARM64(params, hasRes, res)
			for _, a := range args {
				if a.Reg == reg {
					return false
				}
			}
			continue // ABI kill: the register cannot carry a value across
		}
		if strings.HasPrefix(t, "JMP	(") {
			return false // jump table: targets unknown here
		}
		if m := a64BranchRe.FindStringSubmatch(t); m != nil {
			// Conditional register operands (CBZ/CBNZ/TBZ/TBNZ) read.
			if strings.Contains(m[2], reg) {
				if reads, _, ok := f16RegRoles("CMP\t"+strings.TrimSuffix(m[2], ", "), reg); !ok || reads {
					return false
				}
			}
			var tgt int
			if _, err := fmt.Sscanf(m[3], "%d", &tgt); err != nil {
				return false
			}
			ti, ok := offIdx[tgt]
			if !ok {
				// Branch into the stripped epilogue (only the ABI
				// result register is read there) or back into the
				// stripped prologue (the morestack retry restarts the
				// function: every non-argument register is dead, and
				// gc keeps arguments in their home slots for it).
				beyond := tgt > insns[len(insns)-1].Off && reg != resultReg
				before := tgt < insns[0].Off
				if beyond || before {
					if m[1] != "JMP" {
						work = append(work, i+1)
					}
					continue
				}
				// A target with no instruction is a branch into a
				// stripped early-return epilogue (frame restore +
				// RET): the first surviving instruction after it is
				// the RET. Nothing there reads anything but the ABI
				// result register.
				next := ""
				for _, in2 := range insns {
					if in2.Off > tgt {
						next = in2.Text
						break
					}
				}
				if strings.HasPrefix(next, "RET") && reg != resultReg {
					if m[1] != "JMP" {
						work = append(work, i+1)
					}
					continue
				}
				if f16Debug {
					fmt.Fprintf(os.Stderr, "f16-target-miss: %q -> %d (next %q)\n", t, tgt, next)
				}
				return false
			}
			work = append(work, ti)
			if m[1] != "JMP" {
				work = append(work, i+1)
			}
			continue
		}
		reads, writes, ok := f16RegRoles(t, reg)
		if !ok || reads {
			return false
		}
		if writes {
			continue // rewritten on this path
		}
		work = append(work, i+1)
	}
	return true
}

// f16RegRoles classifies reg's role in one instruction. ok=false
// means the instruction is not understood well enough to be sure.
// Only whole-token occurrences count (the substring gate in the
// caller can trip on e.g. "F1" inside "F10").
func f16RegRoles(text, reg string) (reads, writes, ok bool) {
	tab := strings.Index(text, "\t")
	if tab < 0 {
		return false, false, false
	}
	op, rest := text[:tab], text[tab+1:]
	count := 0
	for _, f := range strings.FieldsFunc(rest, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) {
		if f == reg {
			count++
		}
	}
	if count == 0 {
		return false, false, true
	}
	switch op {
	case "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU",
		"FMOVS", "FMOVD", "ADD", "ADDW", "SUB", "SUBW", "AND", "ANDW",
		"ORR", "ORRW", "EOR", "EORW", "LSL", "LSLW", "LSR", "LSRW",
		"ASR", "ASRW", "MUL", "MULW", "UBFX", "UBFXW", "SBFX", "SBFXW",
		"MVN", "MVNW", "FMULS", "FADDS", "FSUBS", "FDIVS", "FMULD",
		"FADDD", "FSUBD", "FDIVD", "FCVTSH", "FCVTHS", "NEG", "NEGW",
		"SCVTFS", "UCVTFS", "SCVTFD", "UCVTFD",
		"FCVTSD", "FCVTDS", "FNEGS", "FNEGD", "FSQRTS", "FSQRTD",
		"FMINS", "FMAXS", "FMIND", "FMAXD", "FABSS", "FABSD",
		"SXTB", "SXTBW", "SXTH", "SXTHW", "SXTW", "UXTB", "UXTH", "UXTW",
		"ROR", "RORW", "MADD", "MADDW", "MSUB", "MSUBW",
		"SMULL", "UMULL", "SMULH", "UMULH", "CLZ", "CLZW", "RBIT", "RBITW",
		"REV", "REVW", "REV16", "REV16W",
		"FCVTZSS", "FCVTZSSW", "FCVTZSD", "FCVTZSDW",
		"FCVTZUS", "FCVTZUSW", "FCVTZUD", "FCVTZUDW",
		"FRINTNS", "FRINTMS", "FRINTPS", "FRINTZS",
		"FRINTND", "FRINTMD", "FRINTPD", "FRINTZD",
		"SCVTFWS", "SCVTFWD", "UCVTFWS", "UCVTFWD":
		ops := strings.Split(rest, ", ")
		dst := ops[len(ops)-1]
		if strings.ContainsAny(dst, "()") {
			return true, false, true // store / memory destination: reads
		}
		if dst == reg && count == 1 {
			return false, true, true
		}
		return true, dst == reg, true
	case "CMP", "CMPW", "CMN", "CMNW", "TST", "TSTW", "FCMPS", "FCMPD",
		"CCMP", "CCMPW", "CCMN", "CCMNW":
		return true, false, true
	case "CSEL", "CSELW", "CSET", "CSETW", "CSINC", "CSINV":
		ops := strings.Split(rest, ", ")
		dst := ops[len(ops)-1]
		if dst == reg && count == 1 {
			return false, true, true
		}
		return true, dst == reg, true
	}
	return false, false, false
}
