package asmgen

import (
	"strings"
)

// regTrackPass walks the emitted asm with a per-register cache of
// which stack-slot value each general-purpose / SSE register
// currently holds, and rewrites later slot reads to take their
// source from the still-live register instead of issuing a fresh
// load. It is a generalisation of peepholeSlotForward (which only
// matched immediately-adjacent store/reload pairs) — the state
// machine here survives across an arbitrary number of intervening
// instructions until a clobber, label, CALL, or branch invalidates
// the relevant entries.
//
// Concretely the pass is a forward sweep that maintains two maps:
//
//	regSlot : reg → "<off>(SP)" — the slot whose value this reg
//	                              currently mirrors, or "" if the
//	                              reg's content is unknown / dirty
//	slotReg : "<off>(SP)" → reg — the inverse: one canonical reg
//	                              chosen as the source for future
//	                              loads from this slot
//
// On a `MOV<W> reg, slot(SP)` (a store) it records the binding;
// on a `MOV<W> slot(SP), reg2` (a load) where slotReg[slot] is a
// still-valid distinct register, it rewrites the line to read
// from that register instead. Anything that overwrites a reg
// (the destination of any MOV / ALU / SET / CMOV / LEA, a CALL,
// or a label / branch boundary) invalidates the affected
// bindings.
//
// The pass NEVER touches the FUNCTION SEMANTICS — it only
// changes the SOURCE of an existing load, replacing memory
// traffic with a reg-to-reg move. The destination register and
// width are preserved, so any downstream consumer that reads
// the reload's destination sees the same bytes.
//
// Why a post-emission pass: the current emit pipeline has no
// shared register state across SSA values, so every load /
// store goes through its own MOV pair. A real emit-time
// register allocator is the right answer for the next big perf
// step (the block-local regalloc itself), but this string-level cache picks up the
// same patterns that allocator would have eliminated when the
// patterns are reachable through line-local rewriting alone,
// without changing the emitters at all.
func regTrackPass(asm string) string {
	if asm == "" {
		return asm
	}
	lines := strings.Split(asm, "\n")
	out := make([]string, 0, len(lines))

	// regSlot[reg] = slot operand string (e.g. "24(SP)") if reg
	// currently mirrors that slot's bytes, else "".
	regSlot := map[string]string{}
	// slotReg[slot] = reg name chosen as the canonical source for
	// future reads from that slot.
	slotReg := map[string]string{}
	// slotImm[slot] = immediate-source operand string (e.g. "$0",
	// "$0x40") when the LAST write to slot was `MOV{L,Q} $imm,
	// slot(SP)`. Subsequent reads from slot can be rewritten to
	// read the immediate directly, which (a) removes one memory
	// load and (b) feeds peepholeImmStore so a downstream
	// `MOV{L,Q} <imm-loaded-reg>, otherSlot(SP)` can collapse to
	// `MOV{L,Q} $imm, otherSlot(SP)`.
	//
	// The map is invalidated whenever the slot is written by any
	// non-immediate source, at any boundary that would invalidate
	// regSlot / slotReg too, and (transitively) when a register
	// already mirroring the immediate via a forwarded load gets
	// clobbered — the register tracking already handles that case.
	slotImm := map[string]string{}
	// slotImmInstr[slot] = "MOVL" or "MOVQ" — the width of the
	// immediate-store. A later load of a DIFFERENT width must not
	// be rewritten to the immediate (a MOVL load reading a MOVQ-
	// written slot would only see the low 4 bytes, and vice versa).
	slotImmInstr := map[string]string{}

	invalidateReg := func(reg string) {
		if old := regSlot[reg]; old != "" {
			if slotReg[old] == reg {
				delete(slotReg, old)
			}
			delete(regSlot, reg)
		}
	}
	invalidateSlot := func(slot string) {
		if reg := slotReg[slot]; reg != "" {
			delete(regSlot, reg)
			delete(slotReg, slot)
		}
		delete(slotImm, slot)
		delete(slotImmInstr, slot)
	}
	// Drop bindings for every register the Go ABI0 declares as
	// caller-save (every GP except R14 and BP — Go uses R14 for
	// the goroutine pointer and BP as the frame pointer — plus
	// every SSE register). This is invoked at CALL sites because
	// the callee is free to clobber any caller-save reg.
	//
	// ALSO clear `slotImm` — the callee's argument area sits at
	// the caller's `K(SP)` slots and the callee may freely write
	// to it (Go's runtime morestack / argument-spill paths do,
	// and so does any callee that mutates its own arg slots
	// before reading them). Without this flush, a downstream
	// `MOV<W> K(SP), reg` would be rewritten to the pre-CALL
	// immediate even though the callee has since written a
	// different value to that slot.
	invalidateCallerSaves := func() {
		for _, r := range []string{
			"AX", "BX", "CX", "DX", "SI", "DI",
			"R8", "R9", "R10", "R11", "R12", "R13", "R15",
			"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
		} {
			invalidateReg(r)
		}
		slotImm = map[string]string{}
		slotImmInstr = map[string]string{}
	}
	invalidateAll := func() {
		regSlot = map[string]string{}
		slotReg = map[string]string{}
		slotImm = map[string]string{}
		slotImmInstr = map[string]string{}
	}

	for _, line := range lines {
		// Boundary handling: labels, control transfers, and CALLs
		// all break the linear assumption that the state from the
		// previous instruction still holds. A label is a join
		// point reachable from elsewhere in the function; we
		// conservatively wipe state because we don't track per-
		// label predecessor agreement. A CALL clobbers caller-
		// save regs. A branch (JMP / Jcc / RET) ends the
		// straight-line span.
		if isAsmLabel(line) {
			invalidateAll()
			out = append(out, line)
			continue
		}
		if isAsmCall(line) {
			invalidateCallerSaves()
			out = append(out, line)
			continue
		}
		if isAsmUnconditionalOrCondBranch(line) {
			out = append(out, line)
			invalidateAll()
			continue
		}
		if strings.TrimLeft(line, " \t") == "RET" {
			out = append(out, line)
			invalidateAll()
			continue
		}

		// Try the MOV-shape interpretation: this is what the
		// pass acts on. Everything else falls through to the
		// generic "destination register gets clobbered" path.
		if instr, src, dst, ok := parseMOV(line); ok {
			rewritten := line
			switch {
			case isRegOperand(src) && isMemSPOperand(dst):
				// Store form. Record the binding even if it
				// overwrote a previous one — slotReg picks the
				// LATEST writer because it is the most likely
				// to still be live for a future reader.
				invalidateSlot(dst)
				invalidateReg(src)
				regSlot[src] = dst
				slotReg[dst] = src
			case isMemSPOperand(src) && isRegOperand(dst):
				// Load form. Four cases:
				//
				//  1. dst already mirrors src. The MOV is a NO-OP
				//     (same bytes already sitting in the register
				//     we are about to load into). Drop the line
				//     entirely. This is the multi-line analogue of
				//     peepholeSkipReload, which only catches the
				//     adjacency-1 form.
				//
				//  2. src is tracked as holding a known immediate
				//     of the same MOV width. Rewrite the load to
				//     read that immediate directly. Hands the
				//     immediate off to downstream peepholeImmStore
				//     so a `MOV<W> imm, reg; MOV<W> reg, slot(SP)`
				//     pair can fold to a single
				//     `MOV<W> imm, slot(SP)`.
				//
				//  3. Some OTHER register r mirrors src. Forward
				//     the load to read from r instead of memory —
				//     the bytes are the same and the reg-to-reg
				//     move is faster than a memory hit.
				//
				//  4. No register mirrors src. Emit the load
				//     unchanged.
				if regSlot[dst] == src {
					// dst already holds these bytes. Don't change
					// any state — dst is still a mirror of src.
					continue
				}
				if imm, has := slotImm[src]; has && slotImmInstr[src] == instr {
					rewritten = "\t" + instr + " " + imm + ", " + dst
					// dst now holds the immediate — record it as
					// mirroring src so peepholeImmStore-equivalent
					// downstream folds find it, and so a follow-up
					// load of the same slot can also be replaced.
					invalidateReg(dst)
					regSlot[dst] = src
					if slotReg[src] == "" {
						slotReg[src] = dst
					}
					out = append(out, rewritten)
					continue
				}
				if r := slotReg[src]; r != "" && r != dst && instrFamilyMatches(instr, r) {
					rewritten = "\t" + instr + " " + r + ", " + dst
				}
				// dst now also holds src's slot value.
				invalidateReg(dst)
				regSlot[dst] = src
				// Keep slotReg's existing entry — the prior
				// writer is just as valid a source for future
				// reads.
				if slotReg[src] == "" {
					slotReg[src] = dst
				}
			case isRegOperand(src) && isRegOperand(dst):
				// Reg-to-reg move. dst now mirrors whatever
				// slot src was tracking (possibly nothing).
				srcSlot := regSlot[src]
				invalidateReg(dst)
				if srcSlot != "" && instrFamilyMatches(instr, dst) {
					regSlot[dst] = srcSlot
					// dst is a fresh mirror of the slot too.
					if slotReg[srcSlot] == "" {
						slotReg[srcSlot] = dst
					}
				}
			default:
				// Unknown MOV shape. The most useful subcase
				// here is `MOV{L,Q} $imm, slot(SP)` — that's
				// what peepholeImmStore folds into and what the
				// const-init blocks emit en masse. Record the
				// slotImm entry so a later load from the same
				// slot rewrites to the immediate.
				if isMemSPOperand(dst) {
					invalidateSlot(dst)
					if isImmOperand(src) && (instr == "MOVL" || instr == "MOVQ") {
						slotImm[dst] = src
						slotImmInstr[dst] = instr
					}
				}
				if isRegOperand(dst) {
					invalidateReg(dst)
				}
			}
			out = append(out, rewritten)
			continue
		}

		// Any non-MOV instruction may write a register. Find the
		// destination and invalidate it; conservative-but-correct.
		// Plan 9 amd64 syntax is uniformly `OP src, dst` so the
		// dst is the last comma-separated operand. The few special
		// forms we emit (TESTL, CMPL, JCC <label>, etc.) write no
		// register and pass through with no state change.
		out = append(out, line)
		invalidateNonMovDst(line, invalidateReg)
	}

	return strings.Join(out, "\n")
}

// isImmOperand reports whether s is a plan9 immediate operand —
// `$<digits>` (positive), `$-<digits>` (negative), or `$0x...`
// (hex). The asmgen emitter only produces these three forms for
// constant materialisation; arbitrary symbols-with-offset like
// `$sym+0(SB)` are deliberately NOT matched because the slotImm
// tracker would need extra string-equality care to forward them
// (a `$sym+4` is a different value from `$sym+0`).
func isImmOperand(s string) bool {
	if len(s) < 2 || s[0] != '$' {
		return false
	}
	body := s[1:]
	if body[0] == '-' {
		body = body[1:]
		if body == "" {
			return false
		}
	}
	if strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X") {
		body = body[2:]
		if body == "" {
			return false
		}
		for i := 0; i < len(body); i++ {
			c := body[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	return true
}

// instrFamilyMatches reports whether the given GP/SSE register can
// legally be the source of a MOV with the given mnemonic. MOVL /
// MOVQ require GP regs; MOVSS / MOVSD require SSE regs. Mixing
// either way would produce an instruction the assembler rejects.
func instrFamilyMatches(instr, reg string) bool {
	switch instr {
	case "MOVL", "MOVQ":
		return !isSSEReg(reg)
	case "MOVSS", "MOVSD":
		return isSSEReg(reg)
	}
	return false
}

// invalidateNonMovDst is the fallback for instructions parseMOV
// doesn't recognise. It pulls out the destination operand of any
// `OP <src>, <dst>` (the standard plan9 two-operand encoding) and
// invalidates dst when it is a register. Single-operand mnemonics
// that write a register — INCL/DECL/NEGL/NOTL/SETcc/JMP — are
// caught by the trailing whitespace-stripped tail.
func invalidateNonMovDst(line string, invalidateReg func(string)) {
	s := strings.TrimLeft(line, " \t")
	if s == "" {
		return
	}
	// Split mnemonic from operands.
	sp := strings.IndexAny(s, " \t")
	if sp < 0 {
		// No operands (e.g. "NOP", "RET" — already handled by
		// the boundary check, but harmless). Nothing to do.
		return
	}
	mnemonic := s[:sp]
	operands := strings.TrimLeft(s[sp:], " \t")
	// TESTL / CMPL set flags but don't write a register, so we
	// must not invalidate either operand. Likewise UCOMISS /
	// UCOMISD.
	switch mnemonic {
	case "TESTL", "TESTQ", "TESTB", "TESTW",
		"CMPL", "CMPQ", "CMPB", "CMPW",
		"UCOMISS", "UCOMISD":
		return
	}
	// JMP / Jcc / JCS / etc. take a label, not a register.
	if mnemonic == "JMP" || mnemonic == "JE" || mnemonic == "JNE" ||
		(len(mnemonic) >= 2 && mnemonic[0] == 'J') {
		return
	}
	// SET<cc> writes the LOW BYTE of the named register. The pass's
	// canonical register set tracks 64-bit names (AX/BX/CX/DX), so
	// "SETEQ AL" must invalidate AX — the low byte of AX is now the
	// 0/1 the SET wrote, while the upper 24/56 bits still hold
	// whatever was in AX before. If we leave AX still mapped to the
	// slot it used to mirror, a subsequent peephole rewrite of a
	// load from that slot to a reg-to-reg copy from AX would read
	// the corrupted low byte. Same story for AH/BH/CH/DH and the
	// REX-prefixed byte forms (SIL/DIL/BPL/SPL/R8B-R15B) — map them
	// back to their 64-bit parent and invalidate that.
	if strings.HasPrefix(mnemonic, "SET") {
		dst := strings.TrimRight(operands, " \t")
		if parent, ok := byteRegParent(dst); ok {
			invalidateReg(parent)
			return
		}
	}
	// Single-operand mnemonics: SET<cc>, INC/DEC/NEG/NOT (on a
	// register), MOVBLZX (already a MOV shape but with a
	// non-standard mnemonic that parseMOV didn't recognise),
	// MOVBQZX, MOVBLSX, MOVBQSX, MOVWLZX, MOVWLSX, MOVWQZX,
	// MOVWQSX, MOVLQSX, MOVLQZX. For all of these the
	// destination is the LAST comma-separated operand.
	last := operands
	if comma := strings.LastIndex(operands, ", "); comma >= 0 {
		last = operands[comma+2:]
	}
	last = strings.TrimRight(last, " \t")
	if isRegOperand(last) {
		invalidateReg(last)
	}
}

// byteRegParent returns the 64-bit GP register that contains the
// given byte-register name. plan9 amd64 spells the byte form as
// AL/AH/BL/BH/CL/CH/DL/DH and SIL/DIL/BPL/SPL plus R8B..R15B; each
// is a subregister of its 64-bit parent (AX, BX, ...). The parent
// is what regTrackPass tracks, so any byte write must invalidate
// the parent's mapping.
func byteRegParent(s string) (string, bool) {
	switch s {
	case "AL", "AH":
		return "AX", true
	case "BL", "BH":
		return "BX", true
	case "CL", "CH":
		return "CX", true
	case "DL", "DH":
		return "DX", true
	case "SIL":
		return "SI", true
	case "DIL":
		return "DI", true
	case "BPL":
		return "BP", true
	case "R8B":
		return "R8", true
	case "R9B":
		return "R9", true
	case "R10B":
		return "R10", true
	case "R11B":
		return "R11", true
	case "R12B":
		return "R12", true
	case "R13B":
		return "R13", true
	case "R14B":
		return "R14", true
	case "R15B":
		return "R15", true
	}
	return "", false
}
