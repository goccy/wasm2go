package gcasm

import (
	"fmt"
	"os"
	"strings"

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

// emitDirectAsmBody emits one retained function's asm for the given
// architecture, or reports false to keep the listing-transform path.
// On arm64 a splicer backed by this package's splice tables and the
// bundle's per-package ConstPool inlines SIMD helper call sites; on
// amd64 (no per-op splice table) SIMD calls stay marshalled CALLs.
//
// The emitters hardcode the Module.M field offset, so emission is
// refused unless the probe-extracted offsets confirm the layout
// (modules without a memory have neither probe nor memory ops, and
// skip the check). ForbidCalls keeps v1 to functions without
// non-SIMD callees: the bundle's wrapper symbols are not resolvable
// from asmgen's same-package CALL spelling yet, and a body that
// emits but fails to link would break the build instead of falling
// back.
func emitDirectAsmBody(mod *wasm.Module, name string, df DirectAsmFn, archName string, modOffs *ModuleOffsets, pool *ConstPool, stats *BuildStats) (string, bool) {
	if len(mod.Memories) > 0 && (modOffs == nil || modOffs.M != asmgen.ModuleMOffset) {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): %s falls back: Module layout unverified (probe %v)\n",
			archName, name, modOffs)
		return "", false
	}
	emit := asmgen.EmitFuncAMD64
	opts := asmgen.FuncOptions{Module: mod, ForbidCalls: true}
	if archName == "arm64" {
		emit = asmgen.EmitFuncARM64
		opts.Splicer = &directAsmSplicer{pool: pool, offs: modOffs}
	}
	asm, _, err := emit(name, df.Sig, df.Fn, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): %s falls back: %v\n", archName, name, err)
		return "", false
	}
	// The marker line identifies direct-asm bodies in the bundle
	// (tests and humans reading the .s both key off it).
	return "// direct-asm: " + name + "\n" + asm, true
}

// directAsmSplicer adapts the arm64 splice tables to asmgen's
// SimdSplicer interface. asmgen provides operand locations (frame
// slots / parameter slots — its splice mode keeps nothing in
// registers); the splicer stages them per the same ABIInternal
// assignment the gc-capture transform uses, so the shared splice
// bodies (a64SpliceSimd) drop in unchanged: scalars in R0../F0..,
// v128 halves in the caller's scratch area at their sequence
// offsets.
type directAsmSplicer struct {
	pool *ConstPool
	offs *ModuleOffsets
}

// TrapStub returns the shared out-of-bounds stub the memory splices
// branch to. The trap helper panics, so control never returns; the
// RET only satisfies the assembler. Single-package bundles spell the
// helper lowercase (multi-package emission is rejected upstream).
func (s *directAsmSplicer) TrapStub() string {
	return a64SimdMemTrapLabel + ":\n\tCALL ·wasm_trap_simd_oob(SB)\n\tRET\n"
}

// spliceArgKind maps an asmgen operand to the ABI ArgKind the
// assignment machinery consumes.
func spliceArgKind(a asmgen.SimdSpliceOperand) (ArgKind, bool) {
	if a.IsPtr {
		return ArgPtr, true
	}
	switch a.Type {
	case ssa.TypeI32:
		return ArgI32, true
	case ssa.TypeI64:
		return ArgI64, true
	case ssa.TypeF32:
		return ArgF32, true
	case ssa.TypeF64:
		return ArgF64, true
	case ssa.TypeV128:
		return ArgV128, true
	}
	return 0, false
}

func (s *directAsmSplicer) Splice(b *strings.Builder, name string, args []asmgen.SimdSpliceOperand, ret *asmgen.SimdSpliceOperand, scratchBase int) (spliced, wantsTrap bool) {
	kinds := make([]ArgKind, len(args))
	for i, a := range args {
		k, ok := spliceArgKind(a)
		if !ok {
			return false, false
		}
		kinds[i] = k
	}
	hasRes := ret != nil
	resKind := ArgI32
	if hasRes {
		k, ok := spliceArgKind(*ret)
		if !ok {
			return false, false
		}
		resKind = k
	}
	cargs, cres := assignARM64(kinds, hasRes, resKind)

	// Everything goes through a scratch builder first: the splice
	// tables may decline this op (a64SpliceSimd reports false), and
	// the caller then emits the marshalled CALL — the staging below
	// must not leak into the output in that case.
	var tmp strings.Builder
	for i, a := range args {
		ra := cargs[i]
		switch {
		case ra.Kind == ArgV128:
			// Stack-assigned on both sides; the splice reads the
			// halves from the scratch area at the sequence offset.
			// R26 is a safe staging scratch: outside the int arg
			// sequence (R0–R15) and reloaded before any later use.
			fmt.Fprintf(&tmp, "\tMOVD %s, R26\n", a.Lo)
			fmt.Fprintf(&tmp, "\tMOVD R26, %d(RSP)\n", scratchBase+ra.SeqOf)
			fmt.Fprintf(&tmp, "\tMOVD %s, R26\n", a.Hi)
			fmt.Fprintf(&tmp, "\tMOVD R26, %d(RSP)\n", scratchBase+ra.SeqOf+8)
		case ra.Reg != "":
			// Scalars load straight into their ABIInternal registers
			// — the convention the splice bodies were generated
			// against (loadForARM64 gives the extending mnemonic).
			fmt.Fprintf(&tmp, "\t%s %s, %s\n", loadForARM64(ra.Kind), a.Lo, ra.Reg)
		default:
			// Register file exhausted (stack-assigned scalar): no
			// SIMD helper signature does this, but bail safely.
			return false, false
		}
	}
	ok, trap := a64SpliceSimd(&tmp, name, cargs, cres, hasRes, scratchBase, s.pool, s.offs)
	if !ok {
		return false, false
	}
	if hasRes {
		switch {
		case cres.Kind == ArgV128:
			fmt.Fprintf(&tmp, "\tMOVD %d(RSP), R26\n", scratchBase+cres.SeqOf)
			fmt.Fprintf(&tmp, "\tMOVD R26, %s\n", ret.Lo)
			fmt.Fprintf(&tmp, "\tMOVD %d(RSP), R26\n", scratchBase+cres.SeqOf+8)
			fmt.Fprintf(&tmp, "\tMOVD R26, %s\n", ret.Hi)
		case cres.Reg != "":
			mn := "MOVD"
			switch cres.Kind {
			case ArgI32, ArgU32:
				mn = "MOVW"
			case ArgF32:
				mn = "FMOVS"
			case ArgF64:
				mn = "FMOVD"
			}
			fmt.Fprintf(&tmp, "\t%s %s, %s\n", mn, cres.Reg, ret.Lo)
		default:
			return false, false
		}
	}
	b.WriteString(tmp.String())
	return true, trap
}
