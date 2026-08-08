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

// errUnsupportedJumpTable signals that a captured body has a jump table whose
// consumed flag state cannot be replayed at the leaf assembly (the flag-setter
// is a memory compare, or there is no clean preceding setter). Like the duff
// case, Build routes such a function to its pure fallback (a Go switch handles
// the jump table fine) rather than aborting the whole bundle.
var errUnsupportedJumpTable = errors.New("gcasm: jump-table flag state not replayable in hand-written asm")

// hasDuffPseudo reports whether any instruction is a DUFFZERO/DUFFCOPY.
func hasDuffPseudo(insns []Insn) bool {
	for _, in := range insns {
		if strings.HasPrefix(in.Text, "DUFFZERO") || strings.HasPrefix(in.Text, "DUFFCOPY") {
			return true
		}
	}
	return false
}

// ehRuntimeCalls are the runtime symbols emitted by exception-handling /
// defer-recover Go bodies (a wasm try/catch or throw). A function that calls
// any of them cannot be lowered to leaf asm and must use the pure fallback.
var ehRuntimeCalls = []string{
	"runtime.newobject",      // &wasmExc{...} heap allocation
	"runtime.gopanic",        // panic(...)
	"runtime.gorecover",      // recover()
	"runtime.deferreturn",    // deferred recover
	"runtime.deferprocStack", // defer setup
	"runtime.deferproc",      // defer setup
}

func hasEHRuntimeCall(insns []Insn) bool {
	for _, in := range insns {
		for _, rc := range ehRuntimeCalls {
			if strings.Contains(in.Text, rc) {
				return true
			}
		}
		// A structured-EH function wraps its try body in a func literal and
		// calls it (`__exc := func() *wasmExc { ... }()`). The OUTER function
		// need not call any panic/recover runtime symbol itself — the defer /
		// recover lives inside the closure — so detect the closure call: gc
		// names function literals "<outer>.funcN".
		if strings.Contains(in.Text, "CALL") && strings.Contains(in.Text, ".func") {
			return true
		}
	}
	return false
}
