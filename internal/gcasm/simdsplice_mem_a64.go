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
	// FuseLoopUnroll is the in-splice unroll factor: how many
	// iteration steps a fused loop's fast lane emits per branch.
	// 0 or 1 means no in-splice unrolling; 2..8 unroll.
	FuseLoopUnroll int
}

// ModuleOffsets are the *Module field offsets the memory-op splices
// hardcode, extracted per architecture from the captured probe, plus
// the build configuration they emit under.
type ModuleOffsets struct {
	M       int // unsafe.Pointer to linear memory (backing array)
	MemSize int // *atomic.Uint64 holding the current memory size
	Cfg     Config
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
	// The ONLY width difference: the address/offset operands are
	// zero-extended from i32 (MOVWU) on wasm32 and full i64 (MOVD) on
	// memory64. The effective-address arithmetic and the ea+size ≤
	// memSize bounds check are identical, and neither width needs a
	// wrap guard — a memory64's memory is capped at 2^48 (mem64HardCap)
	// so every valid ea is well below 2^63, and the comparison catches
	// every out-of-range access. (The one address that could wrap a
	// u64 is one the guest builds near 2^64, which real code never
	// produces and which resolves within the module's own memory
	// slice anyway.)
	movAddr := "MOVWU"
	if addr64 {
		movAddr = "MOVD"
	}
	fmt.Fprintf(b, "\t%s %s, R25\n", movAddr, addrReg)
	fmt.Fprintf(b, "\t%s %s, R26\n", movAddr, offReg)
	b.WriteString("\tADD R26, R25, R25\n")
	// A plain load of the atomic memSize is sound here: aligned 64-bit
	// loads are single-copy atomic on arm64, and reading a pre-grow
	// value only fails MORE accesses.
	fmt.Fprintf(b, "\tMOVD %d(%s), R26\n", offs.MemSize, mReg)
	b.WriteString("\tMOVD (R26), R26\n")
	fmt.Fprintf(b, "\tADD $%d, R25, R27\n", size)
	b.WriteString("\tCMP R27, R26\n")
	fmt.Fprintf(b, "\tBLO %s\n", a64SimdMemTrapLabel)
	fmt.Fprintf(b, "\tMOVD %d(%s), R26\n", offs.M, mReg)
	b.WriteString("\tADD R25, R26, R27\n")
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
func a64SpliceSimdMem(b *strings.Builder, op string, addr64 bool, cargs []RegAssignment, cres *RegAssignment, hasRes bool, base int, offs *ModuleOffsets) (bool, bool) {
	if offs == nil {
		return false, false
	}
	// Every memory helper starts (m *Module, addr, offset int32, ...)
	// — int64 on a memory64 module, same register assignment either
	// way: R0/R1/R2 by construction, but verify rather than assume.
	if len(cargs) < 3 || cargs[0].Reg != "R0" || cargs[1].Reg != "R1" || cargs[2].Reg != "R2" {
		return false, false
	}

	if ent, ok := a64SimdMemSpliceTab[op]; ok {
		switch op {
		case "v128_store":
			if len(cargs) != 4 || cargs[3].Kind != ArgV128 {
				return false, false
			}
			fmt.Fprintf(b, "\tFMOVQ %d(RSP), F0\n", base+cargs[3].SeqOf)
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
			fmt.Fprintf(b, "\tFMOVQ F0, %d(RSP) // simd out\n", base+cres.SeqOf)
		}
		return true, true
	}

	// Lane loads/stores: (m, addr, offset, lane int32, v [2]uint64).
	scale, eload, estore, ok := a64LaneMemElem(op)
	if !ok || len(cargs) != 5 || cargs[3].Reg != "R3" || cargs[4].Kind != ArgV128 {
		return false, false
	}
	vSeq := base + cargs[4].SeqOf
	switch {
	case strings.Contains(op, "load"):
		if !hasRes || cres.Kind != ArgV128 {
			return false, false
		}
		a64MemPreamble(b, 1<<scale, offs, addr64)
		fmt.Fprintf(b, "\t%s (R27), R24\n", eload)
		// Copy v into the result slot, then overwrite the lane there.
		fmt.Fprintf(b, "\tFMOVQ %d(RSP), F16\n", vSeq)
		fmt.Fprintf(b, "\tFMOVQ F16, %d(RSP) // simd out\n", base+cres.SeqOf)
		fmt.Fprintf(b, "\tADD $%d, RSP, R26\n", base+cres.SeqOf)
		fmt.Fprintf(b, "\tADD R3<<%d, R26, R26\n", scale)
		fmt.Fprintf(b, "\t%s R24, (R26)\n", estore)
		return true, true
	case strings.Contains(op, "store"):
		fmt.Fprintf(b, "\tADD $%d, RSP, R26\n", vSeq)
		fmt.Fprintf(b, "\tADD R3<<%d, R26, R26\n", scale)
		fmt.Fprintf(b, "\t%s (R26), R24\n", eload)
		a64MemPreamble(b, 1<<scale, offs, addr64)
		fmt.Fprintf(b, "\t%s R24, (R27)\n", estore)
		return true, true
	}
	return false, false
}
