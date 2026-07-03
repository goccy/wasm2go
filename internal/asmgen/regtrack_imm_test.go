package asmgen

import (
	"strings"
	"testing"
)

// TestRegTrackPass_SlotImmForwarding covers the D-2 const-through-
// slot path: a `MOVL $imm, slot(SP)` store followed (after any
// number of non-conflicting lines) by a `MOVL slot(SP), reg` load
// should rewrite the load to read the immediate directly. The
// existing peepholeImmStore can then fold the load+store pair into
// a single `MOVL $imm, otherSlot(SP)` when the loaded register is
// immediately stashed back to another slot.
func TestRegTrackPass_SlotImmForwarding(t *testing.T) {
	in := joinLines(
		"\tMOVL $0, 80(SP)",
		"\tMOVL $0, 84(SP)",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tRET",
	)
	got := regTrackPass(in)
	if !strings.Contains(got, "\tMOVL $0, AX") {
		t.Errorf("expected slot load to be rewritten to immediate; got:\n%s", got)
	}
}

// TestRegTrackPass_SlotImmInvalidatedByReassign ensures that a later
// non-immediate write to the slot clears the immediate tracking — a
// load AFTER such a write must NOT be rewritten to the (now stale)
// immediate.
func TestRegTrackPass_SlotImmInvalidatedByReassign(t *testing.T) {
	in := joinLines(
		"\tMOVL $0, 80(SP)",
		"\tMOVL 36(SP), AX",
		"\tMOVL AX, 80(SP)", // <- non-imm write to slot80
		"\tMOVL 80(SP), BX", // <- must NOT become "MOVL $0, BX"
		"\tRET",
	)
	got := regTrackPass(in)
	if strings.Contains(got, "\tMOVL $0, BX") {
		t.Errorf("slotImm forwarding incorrectly fired after slot reassignment:\n%s", got)
	}
}

// TestRegTrackPass_SlotImmInvalidatedAtLabel ensures the slotImm
// tracker is cleared at a label (a block boundary may bring an
// inbound edge that wrote a different value to the slot).
func TestRegTrackPass_SlotImmInvalidatedAtLabel(t *testing.T) {
	in := joinLines(
		"\tMOVL $0, 80(SP)",
		"L1:",
		"\tMOVL 80(SP), AX", // <- crosses a label; must reload from memory
		"\tRET",
	)
	got := regTrackPass(in)
	if strings.Contains(got, "\tMOVL $0, AX") {
		t.Errorf("slotImm forwarding crossed a label boundary:\n%s", got)
	}
}

// TestRegTrackPass_SlotImmWidthMismatch ensures the tracker requires
// width agreement — a MOVQ-written slot must not feed a MOVL load
// as an immediate, because the load would only see the low 4 bytes
// and the immediate rewrite would change semantics for values that
// don't fit in 32 bits.
func TestRegTrackPass_SlotImmWidthMismatch(t *testing.T) {
	in := joinLines(
		"\tMOVQ $-1, 80(SP)",
		"\tMOVL 80(SP), AX", // <- MOVL load of MOVQ-written slot
		"\tRET",
	)
	got := regTrackPass(in)
	if strings.Contains(got, "\tMOVL $-1, AX") {
		t.Errorf("slotImm forwarding fired across width mismatch:\n%s", got)
	}
}

// TestRegTrackPass_SlotImmInvalidatedAtCall is a regression test
// for a bug found in D-2 downstream testing: the callee's argument
// area sits at the caller's K(SP) slots, so any callee is free to
// write into them. Without an invalidation at the CALL boundary,
// slotImm would forward a stale immediate across a CALL and the
// load AFTER the CALL would read the wrong value.
//
// Crash signature without the fix: initialisation reaches an
// `unreachable` trap inside p10.Fn20946 because an earlier callee
// had overwritten the slot we mistakenly forwarded as $1.
func TestRegTrackPass_SlotImmInvalidatedAtCall(t *testing.T) {
	in := joinLines(
		"\tMOVL $5, 8(SP)",
		"\tCALL ·Foo(SB)",
		"\tMOVL 8(SP), AX", // <- must reload from memory; callee may have rewritten 8(SP).
		"\tRET",
	)
	got := regTrackPass(in)
	if strings.Contains(got, "\tMOVL $5, AX") {
		t.Errorf("slotImm forwarded across a CALL — the callee may have overwritten the slot:\n%s", got)
	}
}

// TestRegTrackPass_SlotImmEndToEndFold demonstrates the D-2 win in
// the full pipeline: regTrackPass rewrites the load to an
// immediate, then peepholeImmStore (in peepholeOpt) folds the
// `MOV imm, reg; MOV reg, slot` pair to a single `MOV imm, slot`.
// This is the path entry-block constant-init code takes after D-2.
func TestRegTrackPass_SlotImmEndToEndFold(t *testing.T) {
	in := joinLines(
		"\tMOVL $0, 80(SP)",
		"\tMOVL $0, 84(SP)",
		"\tMOVL 80(SP), AX",
		"\tMOVL AX, 36(SP)",
		"\tMOVL 84(SP), AX",
		"\tMOVL AX, 40(SP)",
		"\tRET",
	)
	// The pipeline order: peepholeOpt -> regTrackPass -> dead-
	// store. Here we only assert regTrackPass's contribution
	// (the immediate-form load); the final fold is checked by
	// peepholeImmStore's own tests.
	got := regTrackPass(in)
	if count := strings.Count(got, "MOVL $0, AX"); count != 2 {
		t.Errorf("expected both slot loads to be rewritten to MOVL $0, AX; got %d:\n%s",
			count, got)
	}
}

// TestRegTrackPass_StaleSecondaryMirrorInvalidated is the regression
// for the Fn39269 128-bit-shift miscompile: a slot can be mirrored by
// MORE THAN ONE register at once (the store's source stays the
// canonical slotReg entry; a forwarded load binds its destination as
// a secondary mirror in regSlot). A later write to the slot must drop
// EVERY mirror. The buggy invalidateSlot only cleared the canonical
// entry, so the secondary register (CX below) kept its stale binding
// and the reload after the slot was overwritten got dropped by the
// "dst already mirrors src" check — leaving CX holding the PREVIOUS
// value (64-n instead of n) as the SHRQ shift count.
func TestRegTrackPass_StaleSecondaryMirrorInvalidated(t *testing.T) {
	in := joinLines(
		"\tMOVL l3+32(FP), AX",
		"\tMOVQ AX, 48(SP)", // slotReg[48]=AX
		"\tMOVQ 48(SP), CX", // forwarded to "MOVQ AX, CX"; CX becomes a secondary mirror of 48(SP)
		"\tSHLQ CX, R8",
		"\tMOVL l3+36(FP), AX", // AX invalidated (canonical mirror gone)
		"\tMOVQ AX, 48(SP)",    // slot overwritten — must ALSO clear CX's stale mirror
		"\tMOVQ 48(SP), CX",    // must NOT be dropped (CX holds the OLD slot value)
		"\tSHRQ CX, R9",
		"\tRET",
	)
	got := regTrackPass(in)
	// After the second store, CX must be (re)written before the SHRQ —
	// either the original slot load survives or it is forwarded to the
	// NEW canonical mirror (MOVQ AX, CX). What must NOT happen is the
	// line disappearing entirely.
	idx := strings.Index(got, "SHLQ CX, R8")
	tail := got[idx:]
	if !strings.Contains(tail, ", CX\n") {
		t.Errorf("reload of CX after the slot overwrite was dropped; CX would keep the stale value:\n%s", got)
	}
}
