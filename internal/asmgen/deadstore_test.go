package asmgen

import (
	"strings"
	"testing"
)

func TestPeepholeDeadStoreFires(t *testing.T) {
	in := "\tMOVL $0, 40(SP)\n\tMOVL $0, 40(SP)\n\tRET"
	out := peepholeOpt(in)
	want := "\tMOVL $0, 40(SP)\n\tRET"
	if out != want {
		t.Errorf("peepholeOpt didn't drop dead store:\n input:\n%s\n got:\n%s\n want:\n%s", in, out, want)
	}
}

func TestPeepholeDeadStoreFullPipeline(t *testing.T) {
	// Mimics the L6 area of Fn39262 — peepholeOpt should drop one
	// of the two MOVL $0, 40(SP) writes.
	in := strings.Join([]string{
		"\tMOVL $-256, 36(SP)",
		"\tMOVL $0, 40(SP)",
		"\tMOVL $0, 40(SP)",
		"L7:",
		"\tMOVL 36(SP), DI",
		"",
	}, "\n")
	out := peepholeOpt(in)
	// Count occurrences of the dead store after peephole.
	n := strings.Count(out, "MOVL $0, 40(SP)")
	if n != 1 {
		t.Errorf("expected 1 occurrence of MOVL $0, 40(SP) after peephole, got %d. Output:\n%s", n, out)
	}
}
