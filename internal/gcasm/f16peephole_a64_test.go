package gcasm

import (
	"strings"
	"testing"
)

// f16TestSite is the canonical gc-compiled shape of the software
// fp32→fp16 idiom (register-allocated like the common llama sites:
// input R0, shl1 R9, result R3, sign/arm temp R4, scratch R10/R11,
// floats F1/F2). Branch targets are patched to instruction offsets
// by f16TestInsns.
var f16TestSite = []string{
	"ADD\tR0, R0, R9",
	"AND\t$2147483647, R0, R10",
	"FMOVS\tR10, F1",
	"FMOVS\t$f32.77800000(SB), F2",
	"FMULS\tF2, F1, F1",
	"FMOVS\t$f32.08800000(SB), F2",
	"FMULS\tF2, F1, F1",
	"NOP",
	"HINT\t$0",
	"MOVD\t$1895825408, R10",
	"CMPW\tR10, R9",
	"MOVD\t$1895825408, R10",
	"CSEL\tLS, R10, R9, R10",
	"UBFX\t$1, R10, $31, R10",
	"AND\t$2139095040, R10, R10",
	"MOVD\t$125829120, R11",
	"ADD\tR11, R10, R10",
	"FMOVS\tR10, F2",
	"FADDS\tF1, F2, F1",
	"MOVD\t$16777216, R10",
	"CMNW\tR10, R9",
	"BLS\t%A",
	"MOVD\t$32256, R3",
	"JMP\t%B",
	"FMOVS\tF1, R3", // %A
	"UBFX\t$13, R3, $19, R4",
	"AND\t$31744, R4, R4",
	"AND\t$4095, R3, R3",
	"ADD\tR4, R3, R3",
	"UBFX\t$16, R0, $16, R4", // %B
	"AND\t$32768, R4, R4",
	"ORR\tR4, R3, R3",
}

// f16TestInsns lays out pre + site + post with 4-byte offsets and
// patches the %A/%B branch targets to the right offsets.
func f16TestInsns(pre, post []string) []Insn {
	var lines []string
	lines = append(lines, pre...)
	siteStart := len(lines)
	lines = append(lines, f16TestSite...)
	lines = append(lines, post...)
	offA := 4 * (siteStart + 24) // FMOVS F1, R3
	offB := 4 * (siteStart + 29) // UBFX $16, R0, $16, R4
	var insns []Insn
	for i, l := range lines {
		l = strings.ReplaceAll(l, "%A", itoa(offA))
		l = strings.ReplaceAll(l, "%B", itoa(offB))
		insns = append(insns, Insn{Off: 4 * i, Text: l})
	}
	return insns
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func f16NoResolve(string) ([]ArgKind, bool, ArgKind, string, bool) {
	return nil, false, 0, "", false
}

func TestF16PeepholeRewritesCanonicalSite(t *testing.T) {
	insns := f16TestInsns(
		[]string{"MOVW\t(R20)(R25), R0"},
		[]string{
			// Redefine the dyn scratch so the deadness walk passes.
			"FMOVS\tR5, F1",
			"FMOVS\tR5, F2",
			"MOVH\tR3, (R5)(R6)", // the store consuming the result
			"RET",
		})
	out := a64F16Peephole(insns, f16NoResolve, "")
	text := ""
	for _, in := range out {
		text += in.Text + "\n"
	}
	if !strings.Contains(text, "FCVTSH\tF1, F1") {
		t.Fatalf("no native convert emitted:\n%s", text)
	}
	for _, gone := range []string{"FMULS", "FADDS", "BLS", "$f32.77800000"} {
		if strings.Contains(text, gone) {
			t.Errorf("deleted idiom instruction %q still present:\n%s", gone, text)
		}
	}
	// Ledger finals: the shl1, sign, and constant registers must end
	// with their original values; the store must still read R3.
	for _, want := range []string{
		"ADD\tR0, R0, R9",
		"UBFX\t$16, R0, $16, R4",
		"AND\t$32768, R4, R4",
		"MOVD\t$16777216, R10",
		"MOVD\t$125829120, R11",
		"CSEL\tVS, ",
		"FCMPS\tF1, F1",
		"MOVH\tR3, (R5)(R6)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in rewrite:\n%s", want, text)
		}
	}
	if len(out) >= len(insns) {
		t.Errorf("rewrite did not shrink the site: %d -> %d insns", len(insns), len(out))
	}
}

func TestF16PeepholeKeepsSiteWhenScratchLive(t *testing.T) {
	insns := f16TestInsns(nil, []string{
		"FADDS\tF1, F0, F0", // reads the float scratch: not dead
		"RET",
	})
	out := a64F16Peephole(insns, f16NoResolve, "")
	for _, in := range out {
		if strings.Contains(in.Text, "FCVTSH") {
			t.Fatal("site rewritten although the float scratch is live afterwards")
		}
	}
	if len(out) != len(insns) {
		t.Fatalf("instruction count changed on a rejected site: %d -> %d", len(insns), len(out))
	}
}

func TestF16PeepholeKeepsSiteOnInboundBranch(t *testing.T) {
	// A branch from outside targeting the region interior must veto
	// the rewrite (the interior instructions disappear).
	interior := 4 * (1 + 9) // the first MOVD $1895825408 inside the site
	insns := f16TestInsns(
		[]string{"CBZW\tR7, " + itoa(interior)},
		[]string{"FMOVS\tR5, F1", "FMOVS\tR5, F2", "RET"})
	out := a64F16Peephole(insns, f16NoResolve, "")
	for _, in := range out {
		if strings.Contains(in.Text, "FCVTSH") {
			t.Fatal("site rewritten despite an inbound branch into the region")
		}
	}
}

func TestF16PeepholeMergeIntoSignRegister(t *testing.T) {
	// gc sometimes lands the sign merge in the SIGN register
	// (ORR x, r, x) and keeps the nonsign register's value live-out;
	// the rewrite must then reproduce the nonsign final too.
	site := make([]string, len(f16TestSite))
	copy(site, f16TestSite)
	site[len(site)-1] = "ORR\tR4, R3, R4"
	saved := f16TestSite
	defer func() { copy(f16TestSite, saved) }()
	copy(f16TestSite, site)
	insns := f16TestInsns(nil, []string{
		"FMOVS\tR5, F1",
		"FMOVS\tR5, F2",
		"MOVH\tR4, (R5)(R6)",
		"RET",
	})
	out := a64F16Peephole(insns, f16NoResolve, "")
	text := ""
	for _, in := range out {
		text += in.Text + "\n"
	}
	if !strings.Contains(text, "FCVTSH") {
		t.Fatalf("merge-into-sign form not rewritten:\n%s", text)
	}
	if !strings.Contains(text, "AND\t$32767, R4, R3") {
		t.Errorf("nonsign register final not reproduced:\n%s", text)
	}
}

// f16TestInsnsAt assembles pre + site + post like f16TestInsns but
// accepts an already-customized site (e.g. with interleaved
// instructions inserted); the %A/%B targets are located by content.
func f16TestInsnsAt(pre, site, post []string) []Insn {
	var lines []string
	lines = append(lines, pre...)
	lines = append(lines, site...)
	lines = append(lines, post...)
	offA, offB := -1, -1
	for i, l := range lines {
		if l == "FMOVS\tF1, R3" {
			offA = 4 * i
		}
		if l == "UBFX\t$16, R0, $16, R4" {
			offB = 4 * i
		}
	}
	var insns []Insn
	for i, l := range lines {
		l = strings.ReplaceAll(l, "%A", itoa(offA))
		l = strings.ReplaceAll(l, "%B", itoa(offB))
		insns = append(insns, Insn{Off: 4 * i, Text: l})
	}
	return insns
}

func TestF16PeepholeSkipsInterleavedInstructions(t *testing.T) {
	// gc may schedule unrelated arithmetic between idiom steps; the
	// matcher must retry over skippable instructions that touch no
	// bound register and keep them in the output.
	site := make([]string, 0, len(f16TestSite)+2)
	for _, l := range f16TestSite {
		site = append(site, l)
		if l == "FMULS\tF2, F1, F1" {
			site = append(site, "MOVWU\tR8, R12")
		}
		if l == "AND\t$2139095040, R10, R10" {
			site = append(site, "ADD\t$4, R13, R13")
		}
	}
	insns := f16TestInsnsAt(
		[]string{"MOVW\t(R20)(R25), R0"},
		site,
		[]string{
			"FMOVS\tR5, F1",
			"FMOVS\tR5, F2",
			"MOVH\tR3, (R5)(R6)",
			"RET",
		})
	out := a64F16Peephole(insns, f16NoResolve, "")
	text := ""
	for _, in := range out {
		text += in.Text + "\n"
	}
	if !strings.Contains(text, "FCVTSH\tF1, F1") {
		t.Fatalf("site with interleave not rewritten:\n%s", text)
	}
	for _, kept := range []string{"MOVWU\tR8, R12", "ADD\t$4, R13, R13"} {
		if !strings.Contains(text, kept) {
			t.Errorf("interleaved instruction %q dropped:\n%s", kept, text)
		}
	}
}

func TestF16PeepholeKeepsSiteWhenInterleaveTouchesBoundReg(t *testing.T) {
	// An interleaved instruction WRITING a bound register (the shl1
	// register R9) must veto the rewrite.
	site := make([]string, 0, len(f16TestSite)+1)
	for _, l := range f16TestSite {
		site = append(site, l)
		if l == "AND\t$2139095040, R10, R10" {
			site = append(site, "ADDW\t$1, R9, R9")
		}
	}
	insns := f16TestInsnsAt(nil, site, []string{
		"FMOVS\tR5, F1",
		"FMOVS\tR5, F2",
		"RET",
	})
	out := a64F16Peephole(insns, f16NoResolve, "")
	for _, in := range out {
		if strings.Contains(in.Text, "FCVTSH") {
			t.Fatal("site rewritten although interleave clobbers a bound register")
		}
	}
}

func TestF16PeepholeDeadnessAcrossBranches(t *testing.T) {
	// The scratch-deadness walk follows both arms of a forward
	// branch: both arms redefine the float scratches, so the site is
	// rewritable.
	nSite := len(f16TestSite) + 1 // pre line + site
	armA := 4 * (nSite + 4)       // first arm-A instruction
	join := 4 * (nSite + 6)       // join block
	insns := f16TestInsnsAt(
		[]string{"MOVW\t(R20)(R25), R0"},
		f16TestSite,
		[]string{
			"CBZW\tR7, " + itoa(armA),
			"FMOVS\tR5, F1",
			"FMOVS\tR5, F2",
			"JMP\t" + itoa(join),
			"FMOVS\tR6, F1", // armA
			"FMOVS\tR6, F2",
			"MOVH\tR3, (R5)(R6)", // join
			"RET",
		})
	out := a64F16Peephole(insns, f16NoResolve, "")
	text := ""
	for _, in := range out {
		text += in.Text + "\n"
	}
	if !strings.Contains(text, "FCVTSH\tF1, F1") {
		t.Fatalf("branchy-but-dead scratch not rewritten:\n%s", text)
	}
}

func TestF16PeepholeDeadnessBranchArmReads(t *testing.T) {
	// One arm reads the float scratch before redefining it: not dead,
	// no rewrite.
	nSite := len(f16TestSite) + 1
	armA := 4 * (nSite + 4)
	insns := f16TestInsnsAt(
		[]string{"MOVW\t(R20)(R25), R0"},
		f16TestSite,
		[]string{
			"CBZW\tR7, " + itoa(armA),
			"FMOVS\tR5, F1",
			"FMOVS\tR5, F2",
			"RET",
			"FADDS\tF1, F0, F0", // armA: reads F1
			"RET",
		})
	out := a64F16Peephole(insns, f16NoResolve, "")
	for _, in := range out {
		if strings.Contains(in.Text, "FCVTSH") {
			t.Fatal("site rewritten although one branch arm reads the scratch")
		}
	}
}

func TestF16Skippable(t *testing.T) {
	for _, yes := range []string{"MOVD\tR1, R2", "ADDW\t$1, R3, R3", "UBFX\t$1, R2, $3, R2", "SXTW\tR2, R2"} {
		if !f16Skippable(yes) {
			t.Errorf("%q should be skippable", yes)
		}
	}
	for _, no := range []string{"FADDS\tF1, F2, F1", "CBZW\tR1, 8", "RET", "NOP"} {
		if f16Skippable(no) {
			t.Errorf("%q should not be skippable", no)
		}
	}
}
