package gcasm

// SIMD memory-op splicing, arm64.
//
// The memory helpers (Simd_v128_load and family) are Go functions:
// bounds check via simdEA, then unsafe loads off m.M. Spliced inline
// they become the same ~9 instructions a wasm JIT emits — effective
// address, one bounds check against m.memSize, the vector access —
// with the out-of-bounds path branching to a per-function trap stub.
//
// The two Module field offsets the sequence hardcodes (M and memSize)
// come from the captured assembly of the gcasmMemProbe helper, so they
// are read out of the very compile being transformed rather than
// re-derived from Go's layout rules. No probe, no offsets → memory ops
// keep the marshalled call path.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/asmgen"
	"github.com/goccy/wasm2go/internal/simdfuse"
)

// Config is the build configuration the splice emitters consult.
type Config struct {
	// FastMath opts splice synthesis out of wasm bit-exactness: SDOT
	// lane grouping without the TBL permutation, and fused
	// multiply-adds. The output no longer matches the wasm program
	// bit-for-bit (like a native build vs the wasm), so integrators
	// gate it and validate with token-level equivalence instead of
	// the byte-equality probe.
	FastMath bool
	// AsmOverrides are the project-supplied bodies for exported
	// leaf functions (see asmoverride.go); nil when none.
	AsmOverrides *AsmOverrides
	// FuseLoopUnroll is the in-splice unroll factor: how many
	// iteration steps a fused loop's fast lane emits per branch.
	// 0 or 1 means no in-splice unrolling; 2..8 unroll.
	FuseLoopUnroll int
	// DirectAsm maps function names to the finalized SSA the
	// translator retained for direct emission via internal/asmgen;
	// those functions' asm bodies replace the listing transform per
	// architecture (see buildDirectAsm). Nil disables the path.
	DirectAsm map[string]DirectAsmFn
	// DirectAsmGlobals is the Module-struct byte offset of each wasm
	// global (-1 imported), computed by the translator that emitted
	// the struct and pinned by generated compile-time assertions;
	// direct-asm bodies inline global accesses through it.
	DirectAsmGlobals []int
	// DirectAsmExc is the Module-struct byte offset of each
	// exception-state field, computed and pinned the same way;
	// direct-asm bodies inline the branch-based EH ops through it.
	// Nil for modules without exception state.
	DirectAsmExc *asmgen.ExcOffsets
}

// ModuleOffsets are the *Module field offsets the memory-op splices
// hardcode, extracted per architecture from the captured probe, plus
// the build configuration they emit under.
type ModuleOffsets struct {
	M       int // unsafe.Pointer to linear memory (backing array)
	MemSize int // *atomic.Uint64 holding the current memory size
	Cfg     Config
	// HoistM / HoistMemSizePtr, when non-empty, name registers the
	// host keeps m.M and the memSize POINTER in across splices (the
	// direct-asm emitter re-primes them after real CALLs). The
	// memory preambles then skip their per-site m-relative loads.
	// The listing-transform path leaves them empty: at a gc call
	// site nothing survives in registers to hoist into.
	HoistM          string
	HoistMemSizePtr string
	// HoistMemSizeVal, when non-empty, names a register holding the
	// memSize VALUE. Valid only where memory cannot grow — inside one
	// fused region or fused loop (splices contain no calls) — where
	// the x64 emitters then bounds-check with a single CMPQ instead of
	// the pointer-load + dereference pair per checked access.
	HoistMemSizeVal string
}

// fastMath is the nil-safe read of Cfg.FastMath: error paths probe
// splice emitters with a nil ModuleOffsets.
func (o *ModuleOffsets) fastMath() bool { return o != nil && o.Cfg.FastMath }

// fuseLoopUnroll is the nil-safe, range-clamped in-splice unroll
// factor (1 = no unrolling).
func (o *ModuleOffsets) fuseLoopUnroll() int {
	if o == nil || o.Cfg.FuseLoopUnroll < 2 || o.Cfg.FuseLoopUnroll > 8 {
		return 1
	}
	return o.Cfg.FuseLoopUnroll
}

var (
	a64ProbeLoadRe = regexp.MustCompile(`^MOVD\t(\d+)\(R0\), R[0-9]+$`)
	x64ProbeLoadRe = regexp.MustCompile(`^MOVQ\t(\d+)\(AX\), [A-Z0-9]+$`)
)

// FindModuleOffsets extracts the Module field offsets from the probe's
// captured body: two loads off the receiver, m.M first, then m.memSize
// (the probe returns them in that order and gc does not reorder two
// independent loads feeding results). The M offset is additionally
// pinned by construction — memory/maxMem/M lead the struct precisely so
// generated assembly can hardcode them — which the extraction verifies;
// a probe that does not look like that yields nil, and memory ops stay
// on the call path.
func FindModuleOffsets(fns []*Fn, arch string) *ModuleOffsets {
	re := a64ProbeLoadRe
	if arch == "amd64" {
		re = x64ProbeLoadRe
	}
	for _, f := range fns {
		cname := f.Name[strings.LastIndex(f.Name, ".")+1:]
		if cname != "GcasmMemProbe" && cname != "gcasmMemProbe" {
			continue
		}
		var offs []int
		for _, in := range f.Insns {
			if m := re.FindStringSubmatch(in.Text); m != nil {
				n, err := strconv.Atoi(m[1])
				if err != nil {
					return nil
				}
				offs = append(offs, n)
			}
		}
		if len(offs) != 2 || offs[0] != 32 {
			return nil
		}
		return &ModuleOffsets{M: offs[0], MemSize: offs[1]}
	}
	return nil
}

// a64SimdMemTrapLabel is the per-function out-of-bounds stub label the
// memory splices branch to.
const a64SimdMemTrapLabel = "gcasmsimdoob"

// a64Addr64Guard branches to the trap stub when reg, a memory64 address
// or offset (or the OR of both), has a bit set at 48 or above. A
// memory64's memory.size never exceeds 2^48 (mem64HardCap, enforced by
// memoryGrow64 and the constructors), so such an access is out of bounds
// whatever else holds; and once both operands are below 2^48, their sum
// plus an access width cannot wrap a u64, which is what makes the
// ea+size ≤ memSize comparison after it exact. reg is clobbered.
func a64Addr64Guard(b *strings.Builder, reg string) {
	a64Addr64GuardFrom(b, reg, reg)
}

// a64Addr64GuardFrom is a64Addr64Guard on src through scratch, leaving
// src intact.
func a64Addr64GuardFrom(b *strings.Builder, src, scratch string) {
	fmt.Fprintf(b, "\tLSR $48, %s, %s\n", src, scratch)
	fmt.Fprintf(b, "\tCBNZ %s, %s\n", scratch, a64SimdMemTrapLabel)
}

// a64Addr64AddOff adds a fused memory64 member's memarg offset into R25
// (which holds the guarded address) after guarding it the same way: a
// scalar offset at or above 2^48 traps, and a constant one that does
// not fit below 2^31 — negative as the descriptor's int32, so a u64
// offset at or above 2^63 — names no byte of any memory, so the access
// traps unconditionally. Scratch: R26, R27.
func a64Addr64AddOff(b *strings.Builder, off simdfuse.Arg, scalarReg func(simdfuse.Arg) string) error {
	switch off.Kind {
	case simdfuse.ArgConst:
		switch {
		case off.Const == 0:
		case off.Const < 0:
			fmt.Fprintf(b, "\tJMP %s\n", a64SimdMemTrapLabel)
		case off.Const < 4096:
			fmt.Fprintf(b, "\tADD $%d, R25, R25\n", off.Const)
		default:
			fmt.Fprintf(b, "\tMOVD $%d, R26\n", int64(off.Const))
			b.WriteString("\tADD R26, R25, R25\n")
		}
	case simdfuse.ArgScalar:
		fmt.Fprintf(b, "\tMOVD %s, R26\n", scalarReg(off))
		a64Addr64GuardFrom(b, "R26", "R27")
		b.WriteString("\tADD R26, R25, R25\n")
	default:
		return fmt.Errorf("fused addr64: bad offset form")
	}
	return nil
}

// a64MemPreamble emits the effective-address computation and bounds
// check, leaving the checked HOST address in R27. m/addr/offset arrive
// in R0/R1/R2 (ABIInternal; the v128 store/lane params never displace
// them). Clobbers R25–R27 and the flags — all dead at a call site.
// addr64 selects the memory64 form: full-width i64 address operands
// with overflow-checked sums instead of zero-extended i32 ones.
func a64MemPreamble(b *strings.Builder, size int, offs *ModuleOffsets, addr64 bool) {
	a64MemPreambleRegs(b, size, offs, "R0", "R1", "R2", addr64)
}

// a64MemPreambleRegs is a64MemPreamble with the argument registers
// (m, addr, offset) as parameters, for callers whose arguments do not
// sit at the front of the ABI sequence (fused splices).
func a64MemPreambleRegs(b *strings.Builder, size int, offs *ModuleOffsets, mReg, addrReg, offReg string, addr64 bool) {
	// The address/offset operands are zero-extended from i32 (MOVWU)
	// on wasm32 and full i64 (MOVD) on memory64. A wasm32 sum of two
	// u32s cannot wrap a u64. A memory64 one can, so the memory64 form
	// first traps an address or offset at or above 2^48 (see
	// a64Addr64Guard); the ea+size ≤ memSize check that follows is then
	// exact on both widths.
	movAddr := "MOVWU"
	if addr64 {
		movAddr = "MOVD"
	}
	fmt.Fprintf(b, "\t%s %s, R25\n", movAddr, addrReg)
	fmt.Fprintf(b, "\t%s %s, R26\n", movAddr, offReg)
	if addr64 {
		b.WriteString("\tORR R26, R25, R27\n")
		a64Addr64Guard(b, "R27")
	}
	b.WriteString("\tADD R26, R25, R25\n")
	// A plain load of the atomic memSize is sound here: aligned 64-bit
	// loads are single-copy atomic on arm64, and reading a pre-grow
	// value only fails MORE accesses.
	if offs.HoistMemSizePtr != "" {
		fmt.Fprintf(b, "\tMOVD (%s), R26\n", offs.HoistMemSizePtr)
	} else {
		fmt.Fprintf(b, "\tMOVD %d(%s), R26\n", offs.MemSize, mReg)
		b.WriteString("\tMOVD (R26), R26\n")
	}
	fmt.Fprintf(b, "\tADD $%d, R25, R27\n", size)
	b.WriteString("\tCMP R27, R26\n")
	fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	if offs.HoistM != "" {
		fmt.Fprintf(b, "\tADD R25, %s, R27\n", offs.HoistM)
	} else {
		fmt.Fprintf(b, "\tMOVD %d(%s), R26\n", offs.M, mReg)
		b.WriteString("\tADD R25, R26, R27\n")
	}
}

// a64LaneMemElem maps a lane memory op to its element size log2 and the
// integer load/store mnemonics (the element moves through a GPR — its
// type does not matter, only its width).
func a64LaneMemElem(op string) (scale int, load, store string, ok bool) {
	switch {
	case strings.Contains(op, "8_lane"):
		return 0, "MOVBU", "MOVB", true
	case strings.Contains(op, "16_lane"):
		return 1, "MOVHU", "MOVH", true
	case strings.Contains(op, "32_lane"):
		return 2, "MOVWU", "MOVW", true
	case strings.Contains(op, "64_lane"):
		return 3, "MOVD", "MOVD", true
	}
	return 0, "", "", false
}

// a64SpliceSimdMem inlines a memory helper call. Reports (spliced,
// needsTrap): a true needsTrap obliges the caller to emit the trap stub
// at the end of the function body.
func a64SpliceSimdMem(b *strings.Builder, op string, addr64 bool, cargs []RegAssignment, cres *RegAssignment, hasRes bool, base int, offs *ModuleOffsets, slots *SpliceSlots) (bool, bool) {
	if offs == nil {
		return false, false
	}
	// Every memory helper starts (m *Module, addr, offset int32, ...)
	// — int64 on a memory64 module, same register assignment either
	// way: R0/R1/R2 by construction, but verify rather than assume.
	if len(cargs) < 3 || cargs[0].Reg != "R0" || cargs[1].Reg != "R1" || cargs[2].Reg != "R2" {
		return false, false
	}

	// Bounds-coalescing split forms (array-form twins of the pair
	// splices): the group-leading load carries the whole window's
	// range check, the other members drop theirs. rlo is SIGNED — a
	// negative start means a group member wrapped and must trap.
	memSizeInto26 := func() {
		if offs.HoistMemSizePtr != "" {
			fmt.Fprintf(b, "\tMOVD (%s), R26\n", offs.HoistMemSizePtr)
		} else {
			fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.MemSize)
			b.WriteString("\tMOVD (R26), R26\n")
		}
	}
	hostAddrInto27 := func() { // R27 = m.M + R25
		if offs.HoistM != "" {
			fmt.Fprintf(b, "\tADD R25, %s, R27\n", offs.HoistM)
		} else {
			fmt.Fprintf(b, "\tMOVD %d(R0), R26\n", offs.M)
			b.WriteString("\tADD R25, R26, R27\n")
		}
	}
	mStaged := offs.HoistM != ""
	switch op {
	case "v128_load_rng":
		// (m, addr, offset, rlo, span) → v128; trap unless
		// [addr+rlo, addr+rlo+span) fits.
		if len(cargs) != 5 || cargs[1].Reg != "R1" || cargs[2].Reg != "R2" ||
			cargs[3].Reg != "R3" || cargs[4].Reg != "R4" ||
			!hasRes || cres.Kind != ArgV128 {
			return false, false
		}
		if !mStaged && cargs[0].Reg != "R0" {
			return false, false
		}
		if addr64 {
			// The group shares one address (the pass groups memory64
			// loads by address value only), so an address at or above
			// 2^48 puts every member out of bounds.
			b.WriteString("\tMOVD R1, R25\n")
			b.WriteString("\tMOVD R1, R26\n")
			a64Addr64Guard(b, "R26")
			b.WriteString("\tADD R3, R25, R26\n")
			fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tADD R4, R26, R27\n")
			memSizeInto26()
			b.WriteString("\tCMP R27, R26\n")
			fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tADD R2, R25, R25\n")
		} else {
			b.WriteString("\tMOVWU R1, R25\n")
			b.WriteString("\tMOVW R3, R26\n")
			b.WriteString("\tADD R26, R25, R26\n")
			fmt.Fprintf(b, "\tTBNZ $63, R26, %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tMOVWU R4, R27\n")
			b.WriteString("\tADD R27, R26, R27\n")
			memSizeInto26()
			b.WriteString("\tCMP R27, R26\n")
			fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
			b.WriteString("\tMOVWU R2, R26\n")
			b.WriteString("\tADD R26, R25, R25\n")
		}
		hostAddrInto27()
		b.WriteString("\tWORD $0x3dc00360 // ldr q0, [x27]\n")
		if slots != nil && slots.OutReg != "" {
			fmt.Fprintf(b, "\tVORR V0.B16, V0.B16, %s.B16\n", slots.OutReg)
		} else {
			fmt.Fprintf(b, "\tFMOVQ F0, %d(RSP) // simd out\n", slots.outOff(base+cres.SeqOf))
		}
		return true, true
	case "v128_load_nc":
		// (m, addr, offset) → v128, no check (the group leader
		// already proved the whole window in-bounds).
		if len(cargs) != 3 || cargs[1].Reg != "R1" || cargs[2].Reg != "R2" ||
			!hasRes || cres.Kind != ArgV128 {
			return false, false
		}
		if !mStaged && cargs[0].Reg != "R0" {
			return false, false
		}
		if addr64 {
			b.WriteString("\tADD R2, R1, R25\n")
		} else {
			b.WriteString("\tMOVWU R1, R25\n")
			b.WriteString("\tMOVWU R2, R26\n")
			b.WriteString("\tADD R26, R25, R25\n")
		}
		hostAddrInto27()
		b.WriteString("\tWORD $0x3dc00360 // ldr q0, [x27]\n")
		if slots != nil && slots.OutReg != "" {
			fmt.Fprintf(b, "\tVORR V0.B16, V0.B16, %s.B16\n", slots.OutReg)
		} else {
			fmt.Fprintf(b, "\tFMOVQ F0, %d(RSP) // simd out\n", slots.outOff(base+cres.SeqOf))
		}
		return true, false
	}
	if ent, ok := a64SimdMemSpliceTab[op]; ok {
		switch op {
		case "v128_store":
			if len(cargs) != 4 || cargs[3].Kind != ArgV128 {
				return false, false
			}
			if r := slots.argReg(3); r != "" {
				fmt.Fprintf(b, "\tVORR %s.B16, %s.B16, V0.B16\n", r, r)
			} else {
				fmt.Fprintf(b, "\tFMOVQ %d(RSP), F0\n", slots.argOff(3, base+cargs[3].SeqOf))
			}
		default:
			if len(cargs) != 3 || !hasRes || cres.Kind != ArgV128 {
				return false, false
			}
		}
		a64MemPreamble(b, ent.Size, offs, addr64)
		for _, l := range ent.Lines {
			fmt.Fprintf(b, "\t%s\n", l)
		}
		if hasRes && cres.Kind == ArgV128 {
			if slots != nil && slots.OutReg != "" {
				fmt.Fprintf(b, "\tVORR V0.B16, V0.B16, %s.B16\n", slots.OutReg)
			} else {
				fmt.Fprintf(b, "\tFMOVQ F0, %d(RSP) // simd out\n", slots.outOff(base+cres.SeqOf))
			}
		}
		return true, true
	}

	// Lane loads/stores: (m, addr, offset, lane int32, v [2]uint64).
	// They index the v128's memory; register-resident operands spill
	// to their scratch slots first, and a register-destined result
	// loads back afterwards.
	laneOutReg := ""
	if slots != nil && (len(slots.ArgRegs) > 0 || slots.OutReg != "") {
		ns := &SpliceSlots{Out: -1}
		if slots.Args != nil {
			ns.Args = slots.Args
		}
		for i, r := range slots.ArgRegs {
			if i >= len(cargs) {
				return false, false
			}
			fmt.Fprintf(b, "\tFMOVQ F%s, %d(RSP)\n", strings.TrimPrefix(r, "V"), base+cargs[i].SeqOf)
		}
		laneOutReg = slots.OutReg
		slots = ns
	}
	scale, eload, estore, ok := a64LaneMemElem(op)
	if !ok || len(cargs) != 5 || cargs[3].Reg != "R3" || cargs[4].Kind != ArgV128 {
		return false, false
	}
	vSeq := slots.argOff(4, base+cargs[4].SeqOf)
	switch {
	case strings.Contains(op, "load"):
		if !hasRes || cres.Kind != ArgV128 {
			return false, false
		}
		a64MemPreamble(b, 1<<scale, offs, addr64)
		fmt.Fprintf(b, "\t%s (R27), R4\n", eload)
		// Copy v into the result slot, then overwrite the lane there.
		fmt.Fprintf(b, "\tFMOVQ %d(RSP), F16\n", vSeq)
		outLane := slots.outOff(base + cres.SeqOf)
		fmt.Fprintf(b, "\tFMOVQ F16, %d(RSP) // simd out\n", outLane)
		fmt.Fprintf(b, "\tADD $%d, RSP, R26\n", outLane)
		fmt.Fprintf(b, "\tADD R3<<%d, R26, R26\n", scale)
		fmt.Fprintf(b, "\t%s R4, (R26)\n", estore)
		if laneOutReg != "" {
			fmt.Fprintf(b, "\tFMOVQ %d(RSP), F%s\n", slots.outOff(base+cres.SeqOf), strings.TrimPrefix(laneOutReg, "V"))
		}
		return true, true
	case strings.Contains(op, "store"):
		fmt.Fprintf(b, "\tADD $%d, RSP, R26\n", vSeq)
		fmt.Fprintf(b, "\tADD R3<<%d, R26, R26\n", scale)
		fmt.Fprintf(b, "\t%s (R26), R4\n", eload)
		a64MemPreamble(b, 1<<scale, offs, addr64)
		fmt.Fprintf(b, "\t%s R4, (R27)\n", estore)
		return true, true
	}
	return false, false
}
