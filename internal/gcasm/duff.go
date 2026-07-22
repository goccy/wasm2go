package gcasm

import (
	"errors"
	"fmt"
	"os"
	"strconv"
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

// errLargeJumpTable signals that a captured body dispatches through a jump
// table large enough that the compare-tree rewrite (emitJumpTree /
// a64EmitJumpTree) is a measurable pessimization: gc's O(1) indirect jump
// becomes O(log n) compare+branch per dispatch. On interpreter-style guests
// (a dense several-hundred-case opcode switch executed once per VM
// instruction) the pure Go body — where gc keeps its real jump table —
// outruns the transformed asm, so Build routes such functions to their
// pure fallback like the duff case.
var errLargeJumpTable = errors.New("gcasm: jump table too large for the compare-tree rewrite")

// jtFallbackMinRuns is the default dispatch-run threshold above which a
// jump-table site routes its function to the pure fallback. Runs (not raw
// table entries) are what emitJumpTree compares over, so they set the tree
// depth: 32 runs ≈ 5 compares per dispatch vs gc's single indirect jump.
const jtFallbackMinRuns = 32

// jumpTableFallbackErr applies the large-jump-table fallback policy to the
// detected sites of one function. It returns an error wrapping
// errLargeJumpTable when any site's run count reaches the threshold, nil
// when the function should stay on the transform path.
//
// GCASM_JT_FALLBACK overrides the threshold: "off" disables the policy,
// a positive integer replaces jtFallbackMinRuns.
func jumpTableFallbackErr(sites map[int]*jtSite) error {
	min := jtFallbackMinRuns
	if v := os.Getenv("GCASM_JT_FALLBACK"); v != "" {
		if v == "off" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("bad GCASM_JT_FALLBACK %q: want a positive integer or \"off\"", v)
		}
		min = n
	}
	for _, s := range sites {
		if len(s.runs) >= min {
			return fmt.Errorf("%w: %d dispatch runs (threshold %d)", errLargeJumpTable, len(s.runs), min)
		}
	}
	return nil
}

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
	}
	return false
}
