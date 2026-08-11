package asmgen

import "testing"

// TestEliminateDeadStoresMultiLine_PhiEdgeAXStaging mirrors the exact
// pattern found in p9.Fn58's loop tail: two stores to slot 0x24(SP)
// separated by an AX-staging load for a different slot. The first
// store is dead — nothing between the two writes reads 0x24(SP), and
// the second store overwrites it before any consumer can observe.
func TestEliminateDeadStoresMultiLine_PhiEdgeAXStaging(t *testing.T) {
	in := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)", // <-- dead: 36(SP) is overwritten 2 lines below
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	want := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	got := eliminateDeadStoresMultiLine(in)
	if got != want {
		t.Errorf("dead store not eliminated:\ninput:\n%s\n got:\n%s\nwant:\n%s",
			in, got, want)
	}
}

// TestEliminateDeadStoresMultiLine_BlockBoundaryFlushes ensures the
// tracker does not eliminate stores across a label or branch — those
// boundary points may have inbound edges that observe the "dead"
// store from a path the tracker cannot see.
func TestEliminateDeadStoresMultiLine_BlockBoundaryFlushes(t *testing.T) {
	in := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)", // looks dead in isolation
		"L1:",               // <-- block boundary; cross-block consumer may read 36(SP)
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	got := eliminateDeadStoresMultiLine(in)
	if got != in {
		t.Errorf("unexpected elimination across label boundary:\nfrom:\n%s\nto:\n%s",
			in, got)
	}
}

// TestEliminateDeadStoresMultiLine_InterveningReadKeepsBoth ensures
// that a read of the target slot between the two writes saves the
// first write — its value is observed by the read, so it is NOT dead.
func TestEliminateDeadStoresMultiLine_InterveningReadKeepsBoth(t *testing.T) {
	in := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tMOVL 36(SP), BX", // <-- reads 36(SP); first store is now live.
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	got := eliminateDeadStoresMultiLine(in)
	if got != in {
		t.Errorf("unexpected elimination — intervening read saves first store:\nfrom:\n%s\nto:\n%s",
			in, got)
	}
}

// TestEliminateDeadStoresMultiLine_DifferentWidthsKeepBoth ensures the
// tracker requires both writes to use the same MOV width before
// declaring the earlier write dead. A MOVL followed by a MOVQ to the
// same offset may only touch the low 4 bytes the first time and the
// full 8 bytes the second; the high 4 bytes of the second write are a
// new value, but the first write's low bytes were still observable
// for the (hypothetical) read of just the low half. The emitter does
// not currently mix widths to the same slot, but the guard is cheap.
func TestEliminateDeadStoresMultiLine_DifferentWidthsKeepBoth(t *testing.T) {
	in := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tMOVQ $0, 36(SP)",
		"\tRET",
	)
	got := eliminateDeadStoresMultiLine(in)
	if got != in {
		t.Errorf("mixed-width stores must not be coalesced:\nfrom:\n%s\nto:\n%s",
			in, got)
	}
}

// TestEliminateDeadStoresMultiLine_CallFlushes ensures a CALL flushes
// the tracker — a CALL can observe any FP / SP slot through the
// callee's args (or via memory escape) and any pending store may be
// observed inside the callee.
func TestEliminateDeadStoresMultiLine_CallFlushes(t *testing.T) {
	in := joinLines(
		"L0:",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tCALL ·Foo(SB)",
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	got := eliminateDeadStoresMultiLine(in)
	if got != in {
		t.Errorf("dead-store tracker must not span a CALL:\nfrom:\n%s\nto:\n%s",
			in, got)
	}
}

func joinLines(lines ...string) string {
	s := ""
	for i, l := range lines {
		if i > 0 {
			s += "\n"
		}
		s += l
	}
	return s
}
