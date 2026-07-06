package gcasm

import (
	"errors"
	"strings"
)

// errUnsupportedDuff signals that a captured body uses the DUFFZERO or
// DUFFCOPY pseudo-op. The gc backend picks these for medium-size stack
// zero/copy by frame size (which functions get one is toolchain- and
// arch-dependent). They cannot be re-emitted in hand-written asm: the
// assembler only populates the runtime.duffzero/duffcopy target symbol
// for compiler-generated progs, so a textual DUFFZERO/DUFFCOPY in a .s
// nil-dereferences cmd/internal/obj/x86 (reproduced on go1.25 and
// go1.26 alike). Build routes such functions to their pure fallback,
// which is transparent to callers — the ABI0 forward / //go:linkname
// used at call sites is identical for transformed and fallback fns.
var errUnsupportedDuff = errors.New("gcasm: DUFFZERO/DUFFCOPY pseudo-op unsupported in hand-written asm")

// hasDuffPseudo reports whether any instruction is a DUFFZERO/DUFFCOPY.
func hasDuffPseudo(insns []Insn) bool {
	for _, in := range insns {
		if strings.HasPrefix(in.Text, "DUFFZERO") || strings.HasPrefix(in.Text, "DUFFCOPY") {
			return true
		}
	}
	return false
}
