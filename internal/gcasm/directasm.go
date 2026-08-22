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
	// Packed / PackedParams mirror the codegen retention: the packed
	// outlined-boundary form whose parameter values ride the Module's
	// outline-pack scratch (Sig is then results-only).
	Packed       bool
	PackedParams []ssa.Type
	// Windows mirrors the codegen retention's fused-window
	// descriptors: regions of the retained SSA the emission-time
	// fusion pass claimed, to be emitted as shared fused splice
	// bodies instead of per-op splices.
	Windows []asmgen.FusedWindow
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
func emitDirectAsmBody(mod *wasm.Module, name string, df DirectAsmFn, archName string, cfg Config, modOffs *ModuleOffsets, pool *ConstPool, importPath, rel string, calleeSig calleeResolver, fnOwner map[string]string, stats *BuildStats) (string, bool) {
	if len(mod.Memories) > 0 && (modOffs == nil || modOffs.M != asmgen.ModuleMOffset) {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): %s falls back: Module layout unverified (probe %v)\n",
			archName, name, modOffs)
		return "", false
	}
	emit := asmgen.EmitFuncAMD64
	opts := asmgen.FuncOptions{Module: mod, ForbidCalls: true}
	if df.Packed {
		opts.PackedParams = df.PackedParams
	}
	// The translator-computed struct offsets ride Config, not the
	// probe: a module without SIMD memory ops has no probe (modOffs
	// is nil) but its globals and exception state still inline.
	opts.GlobalOffsets = cfg.DirectAsmGlobals
	opts.Exc = cfg.DirectAsmExc
	opts.Windows = df.Windows
	if rel != "" {
		// Multi-package chunk: same-package helper CALL spellings do
		// not resolve here. Setting the prefix makes the emitters
		// fail any SIMD site that does not splice (per-function
		// fallback) instead of emitting an unresolvable CALL.
		opts.HelperPrefix = "base"
	}
	// Direct-call and memory-op callees resolve through the same
	// machinery the listing transform uses; resolution registers the
	// chunk-local forward wrapper as a side effect, so the returned
	// symbol always links in this package.
	opts.CalleeSymbol = func(idx uint32) (string, bool) {
		for _, bare := range []string{fmt.Sprintf("Fn%d", idx), fmt.Sprintf("fn%d", idx)} {
			owner, ok := fnOwner[bare]
			if !ok {
				continue
			}
			if _, _, _, localSym, ok2 := calleeSig(owner + "." + bare); ok2 {
				return strings.TrimPrefix(localSym, "·"), true
			}
		}
		return "", false
	}
	opts.MemHelperSymbol = func(helper string) (string, bool) {
		qualified := importPath + "." + helper
		if rel != "" {
			qualified = importPath + "/base." + strings.ToUpper(helper[:1]) + helper[1:]
		}
		if _, _, _, localSym, ok := calleeSig(qualified); ok {
			return strings.TrimPrefix(localSym, "·"), true
		}
		return "", false
	}
	if archName == "arm64" {
		// The out-of-bounds trap CALL target for spliced memory ops,
		// resolved through the same machinery the listing transform
		// uses (registering a chunk-local forward wrapper when the
		// helper lives in base). Unresolved → the splicer refuses
		// memory splices rather than emit a dangling branch.
		trapQualified := importPath + ".wasm_trap_simd_oob"
		if rel != "" {
			trapQualified = importPath + "/base.Wasm_trap_simd_oob"
		}
		trapSym := ""
		if _, _, _, localSym, ok := calleeSig(trapQualified); ok {
			trapSym = localSym
		}
		emit = asmgen.EmitFuncARM64
		spOffs := modOffs
		if modOffs != nil {
			// Clone with the hoist registers: the emitter keeps m in
			// R24 (its splice-safe m-cache), m.M in R23, and the
			// memSize pointer in R22, re-priming after real CALLs.
			// The listing-transform path shares modOffs and must not
			// see these.
			h := *modOffs
			h.HoistM, h.HoistMemSizePtr = "R23", "R22"
			spOffs = &h
		}
		opts.Splicer = &directAsmSplicer{pool: pool, offs: spOffs, trapSym: trapSym}
	}
	asm, _, err := emit(name, df.Sig, df.Fn, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm (%s): %s falls back: %v\n", archName, name, err)
		return "", false
	}
	if archName == "arm64" && strings.Contains(asm, "FMOVQ") {
		// Store-to-load forwarding over the v128 slots, same pass the
		// gc-captured bodies get (identical instruction vocabulary,
		// conservative whitelist tracking, never deletes a store).
		// a64DeadArgStores must NOT run here: it models the capture
		// shape, where arg-slot stores are redundant copies of a
		// value that also lives elsewhere — in the slot-direct shape
		// the "simd out" store IS the value's only definition, and
		// the pass deleted live stores (caught by the native NLL
		// parity gate).
		asm = a64ForwardSimdSlots(asm)
		asm = a64SpliceValueCache(asm)
		asm = a64DeadSimdOutStores(asm)
	}
	if archName == "arm64" {
		asm = a64ScalarSlotForward(asm)
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
	// trapSym is the resolved local CALL target of the out-of-bounds
	// trap helper ("·wasm_trap_simd_oob" single-package, a forward
	// wrapper symbol in chunks). Empty when unresolved — memory
	// splices are then refused.
	trapSym string
}

// calleeResolver is buildPkg's callee-resolution closure: qualified
// symbol → (param kinds, has-result, result kind, local asm symbol,
// ok), registering cross-package forward wrappers as a side effect.
type calleeResolver func(sym string) ([]ArgKind, bool, ArgKind, string, bool)

// HoistPrologue stages the module state the splice preambles consume:
// m.M into R23 and the memSize pointer into R22, both read off the
// emitter's R24 m-cache. All three live in the splice-safe register
// range (splice bodies confine themselves to R0–R15 / R25–R27 and
// the V registers).
func (s *directAsmSplicer) HoistPrologue() string {
	if s.offs == nil || s.offs.HoistM == "" {
		return ""
	}
	return fmt.Sprintf("\tMOVD %d(R24), %s\n\tMOVD %d(R24), %s\n",
		s.offs.M, s.offs.HoistM, s.offs.MemSize, s.offs.HoistMemSizePtr)
}

// TrapStub returns the shared out-of-bounds stub the memory splices
// branch to. The trap helper panics, so control never returns; the
// RET only satisfies the assembler.
func (s *directAsmSplicer) TrapStub() string {
	return a64SimdMemTrapLabel + ":\n\tCALL " + s.trapSym + "(SB)\n\tRET\n"
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
	//
	// v128 operands that live in frame slots skip staging entirely:
	// the splice reads them from (and writes the result to) the
	// values' own slots via the SpliceSlots overrides. Only a v128
	// without a slot (an unpacked FP parameter) still takes the
	// copy path into the scratch area.
	slots := &SpliceSlots{Out: -1}
	if ret != nil && ret.Type == ssa.TypeV128 {
		if ret.Reg != "" {
			slots.OutReg = ret.Reg
		} else if ret.InSlot {
			slots.Out = ret.SlotOff
		}
	}
	var tmp strings.Builder
	for i, a := range args {
		ra := cargs[i]
		switch {
		case ra.Kind == ArgV128:
			if a.Reg != "" {
				if slots.ArgRegs == nil {
					slots.ArgRegs = map[int]string{}
				}
				slots.ArgRegs[i] = a.Reg
				continue
			}
			if a.InSlot {
				if slots.Args == nil {
					slots.Args = map[int]int{}
				}
				slots.Args[i] = a.SlotOff
				continue
			}
			// Stack-assigned on both sides; the splice reads the
			// halves from the scratch area at the sequence offset.
			// R26 is a safe staging scratch: outside the int arg
			// sequence (R0–R15) and reloaded before any later use.
			fmt.Fprintf(&tmp, "\tMOVD %s, R26\n", a.Lo)
			fmt.Fprintf(&tmp, "\tMOVD R26, %d(RSP)\n", scratchBase+ra.SeqOf)
			fmt.Fprintf(&tmp, "\tMOVD %s, R26\n", a.Hi)
			fmt.Fprintf(&tmp, "\tMOVD R26, %d(RSP)\n", scratchBase+ra.SeqOf+8)
		case ra.Reg != "":
			if a.IsPtr && s.offs != nil && s.offs.HoistM != "" {
				// Hoisted module state: the memory preamble reads
				// R23/R22 directly, so m itself never has to reach
				// R0 for the splice.
				continue
			}
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
	ok, trap := a64SpliceSimd(&tmp, name, cargs, cres, hasRes, scratchBase, s.pool, s.offs, slots)
	if !ok {
		return false, false
	}
	if trap && s.trapSym == "" {
		// A memory splice needs the trap stub, but the trap helper
		// did not resolve in this package. Discard the staging and
		// keep the CALL path (or the per-function fallback).
		return false, false
	}
	if hasRes {
		switch {
		case cres.Kind == ArgV128 && (slots.Out >= 0 || slots.OutReg != ""):
			// The splice already wrote the value's own slot or its
			// register home.
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
