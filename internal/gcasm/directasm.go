package gcasm

import (
	"fmt"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/asmgen"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// DirectAsmFn is a function whose finalized SSA the translator
// retained for direct emission (codegen Options.DirectAsmFuncs): the
// bundle emits its body straight from SSA via internal/asmgen instead
// of transforming the gc-captured listing. Emission failures fall
// back to the listing transform per function, so a retained function
// never breaks the bundle.
type DirectAsmFn struct {
	Fn  *ssa.Func
	Sig wasm.FuncType
}

// buildDirectAsm emits the direct-asm body for every retained
// function on one architecture. Returns name → asm text for
// buildPkg to swap in place of the listing transform; a name absent
// from the map keeps the normal transform path.
//
// The emitters hardcode the Module.M field offset, so the whole set
// is skipped unless the probe-extracted offsets confirm the layout.
// ForbidCalls keeps v1 to leaf functions: the bundle's callee symbols
// (per-chunk wrappers, base helpers) are not resolvable from asmgen's
// same-package CALL spelling yet, and a body that emits but fails to
// link would break the build instead of falling back.
func buildDirectAsm(mod *wasm.Module, funcs map[string]DirectAsmFn, archName string, modOffs *ModuleOffsets, stats *BuildStats) map[string][]byte {
	if len(funcs) == 0 {
		return nil
	}
	// A module with no memory emits no probe (and its functions can't
	// contain memory ops), so the layout check only applies when a
	// memory exists.
	if len(mod.Memories) > 0 && (modOffs == nil || modOffs.M != asmgen.ModuleMOffset) {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): Module layout unverified (probe %v); all %d functions fall back\n",
			archName, modOffs, len(funcs))
		return nil
	}
	emit := asmgen.EmitFuncAMD64
	if archName == "arm64" {
		emit = asmgen.EmitFuncARM64
	}
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	out := map[string][]byte{}
	for _, name := range names {
		df := funcs[name]
		asm, _, err := emit(name, df.Sig, df.Fn, asmgen.FuncOptions{
			Module:      mod,
			ForbidCalls: true,
		})
		if err != nil {
			// Fall back to the listing transform for this function.
			fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): %s falls back: %v\n", archName, name, err)
			stats.DirectAsmFallback++
			continue
		}
		// The marker line identifies direct-asm bodies in the bundle
		// (tests and humans reading the .s both key off it).
		out[name] = []byte("// direct-asm: " + name + "\n" + asm)
	}
	return out
}
