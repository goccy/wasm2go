package gcasm

// SIMD call splicing, arm64.
//
// The pure-Go emitter lowers every wasm v128 instruction to a call of a
// base.Simd_<op> helper, and the transform used to marshal that call
// like any other: spill the ABIInternal args to the ABI0 slots, CALL a
// forwarding wrapper, read the result back. For code that is almost
// nothing but v128 ops — ggml's kernels — the call machinery outweighed
// the work by more than an order of magnitude: one NEON instruction's
// worth of computation cost two forwarding hops and eight stack moves.
//
// A wasm runtime never pays this: its JIT emits the vector instruction
// directly. wasm2go translates ahead of time, with unlimited budget, so
// it can do strictly better than pattern-matching at run time: the op
// bodies are spliced INLINE at each call site.
//
// The splice works because everything about the site is known statically:
//
//   - v128 params and results are stack-assigned by Go's ABIInternal
//     (arrays of length 2 never get registers), so the values sit in the
//     caller's outgoing-argument area at offsets assignARM64 computes.
//     The splice loads them straight into V registers from there.
//   - Scalar params ride in ABIInternal registers, and because v128
//     params never consume integer registers, the first int param is
//     always in R0 and the first float param in F0 — exactly the
//     convention the helper bodies (and therefore the splice tables,
//     which are those bodies) were generated against.
//   - At a call site every caller-save register is dead: gc spilled
//     anything live because it believes a call happens. The splice may
//     clobber any V register and any of R0–R15/R25–R27 freely.
//
// Lane ops (extract/replace) are hand-rolled rather than table-driven:
// their NEON forms want the lane as an instruction immediate, but the
// helper signature carries it as a runtime value. Indexing the v128's
// own stack slot sidesteps that — a two-instruction sequence that works
// for any lane value, constant or not.
//
// Ops the tables do not cover fall back to the marshalled call,
// unchanged. Correctness never depends on the splice firing.

import (
	"fmt"
	"regexp"
	"strings"
)

var simdSpliceConstRe = regexp.MustCompile(`·(simdConst[A-Za-z0-9]+)\(SB\)`)

// simdSpliceOp extracts the op name from a captured callee symbol, e.g.
// "github.com/x/llamawasm2go/base.Simd_i32x4_add" → "i32x4_add". The
// helpers are Simd_-prefixed in the multi-package bundle (exported for
// cross-chunk linkname) and simd_-prefixed in single-package mode; only
// they use either prefix, so the name alone identifies them regardless
// of the bundle's package layout.
//
// A memory64 module's memory helpers carry an extra m64_ marker
// ("Simd_m64_v128_load", pair form "Simd_p_m64_v128_load"); it is
// stripped here and reported as addr64 so the memory splices widen the
// i64 address operands instead of zero-extending i32 ones. The op name
// after stripping indexes the SAME tables — the vector bodies are
// identical, only the effective-address glue differs.
func simdSpliceOp(sym string) (op string, addr64, ok bool) {
	cname := sym[strings.LastIndex(sym, ".")+1:]
	op, ok = strings.CutPrefix(cname, "Simd_")
	if !ok {
		op, ok = strings.CutPrefix(cname, "simd_")
	}
	if !ok {
		return "", false, false
	}
	if rest, m64 := strings.CutPrefix(op, "m64_"); m64 {
		return rest, true, true
	}
	if rest, m64 := strings.CutPrefix(op, "p_m64_"); m64 {
		return "p_" + rest, true, true
	}
	return op, false, true
}

// simdSpliceRewriteConsts rewrites the helper bodies' ·simdConst*
// references onto ConstPool blobs. The splice lands in a transformed
// package that cannot name the helper package's data symbols from
// Plan9 asm, so the constants are interned per package instead. Reports
// false for a reference the const table does not know, which means the
// table and the bodies have drifted — the caller falls back to the
// marshalled call rather than emit asm that cannot assemble.
func simdSpliceRewriteConsts(lines []string, pool *ConstPool) ([]string, bool) {
	out := make([]string, len(lines))
	for i, l := range lines {
		bad := false
		out[i] = simdSpliceConstRe.ReplaceAllStringFunc(l, func(m string) string {
			name := simdSpliceConstRe.FindStringSubmatch(m)[1]
			blob, ok := simdSpliceConsts[name]
			if !ok {
				bad = true
				return m
			}
			return "·" + pool.addBlob(blob) + "(SB)"
		})
		if bad {
			return nil, false
		}
	}
	return out, true
}

// a64SpliceSimd emits the inline arm64 body for a call to sym if it is
// a spliceable Simd_* helper. It reports whether it spliced, and
// whether the splice branches to the per-function trap stub (memory
// ops), which the caller must then emit at the end of the body.
// cargs/cres describe the site's ABIInternal assignment; base is the
// RSP offset of the caller's outgoing ABIInternal argument area
// (8+maxOut).
// SpliceSlots overrides where a splice reads its v128 arguments and
// writes its v128 result: absolute RSP byte offsets of the VALUES'
// own frame slots, replacing the ABIInternal scratch-area staging.
// Args is keyed by the call-order argument index; Out < 0 keeps the
// default scratch slot. nil keeps every default (the listing-
// transform path, where the values genuinely live in the scratch).
type SpliceSlots struct {
	Args map[int]int
	Out  int
}

func (s *SpliceSlots) argOff(i, def int) int {
	if s != nil {
		if off, ok := s.Args[i]; ok {
			return off
		}
	}
	return def
}

func (s *SpliceSlots) outOff(def int) int {
	if s != nil && s.Out >= 0 {
		return s.Out
	}
	return def
}

func a64SpliceSimd(b *strings.Builder, sym string, cargs []RegAssignment, cres *RegAssignment, hasRes bool, base int, pool *ConstPool, offs *ModuleOffsets, slots *SpliceSlots) (bool, bool) {
	op, addr64, ok := simdSpliceOp(sym)
	if !ok {
		return false, false
	}
	if strings.HasPrefix(op, "v128_load") || strings.HasPrefix(op, "v128_store") {
		return a64SpliceSimdMem(b, op, addr64, cargs, cres, hasRes, base, offs, slots)
	}
	if strings.Contains(op, "extract_lane") {
		return a64SpliceExtractLane(b, op, cargs, base, slots), false
	}
	if strings.Contains(op, "replace_lane") {
		return a64SpliceReplaceLane(b, op, cargs, cres, hasRes, base, slots), false
	}
	lines, ok := a64SimdSpliceTab[op]
	if !ok {
		return false, false
	}
	lines, ok = simdSpliceRewriteConsts(lines, pool)
	if !ok {
		return false, false
	}
	// Load the v128 args into F0..F2 in declaration order and verify the
	// scalars already sit where the body expects them.
	vord := 0
	for i, ca := range cargs {
		switch ca.Kind {
		case ArgV128:
			fmt.Fprintf(b, "\tFMOVQ %d(RSP), F%d\n", slots.argOff(i, base+ca.SeqOf), vord)
			vord++
		case ArgF32, ArgF64:
			// Float scalars are only present on ops without v128 params
			// (the splats); a body that wanted both would collide in F0.
			if ca.Reg != "F0" || vord != 0 {
				return false, false
			}
		default:
			if ca.Reg != "R0" {
				return false, false
			}
		}
	}
	if vord > 3 {
		return false, false
	}
	for _, l := range lines {
		fmt.Fprintf(b, "\t%s\n", l)
	}
	if hasRes && cres.Kind == ArgV128 {
		fmt.Fprintf(b, "\tFMOVQ F0, %d(RSP) // simd out\n", slots.outOff(base+cres.SeqOf))
	}
	// Scalar results are already in R0: the sequences end there, which
	// is also ABIInternal's first result register.
	return true, false
}

// a64LaneElem maps a lane op's shape to the element's log2 size and the
// load/store mnemonics plus destination register class.
func a64LaneElem(op string) (scale int, load, store, reg string, ok bool) {
	switch {
	case strings.HasPrefix(op, "i8x16_") && strings.HasSuffix(op, "_s"):
		return 0, "MOVB", "MOVB", "R0", true
	case strings.HasPrefix(op, "i8x16_"):
		return 0, "MOVBU", "MOVB", "R0", true
	case strings.HasPrefix(op, "i16x8_") && strings.HasSuffix(op, "_s"):
		return 1, "MOVH", "MOVH", "R0", true
	case strings.HasPrefix(op, "i16x8_"):
		return 1, "MOVHU", "MOVH", "R0", true
	case strings.HasPrefix(op, "i32x4_"):
		return 2, "MOVW", "MOVW", "R0", true
	case strings.HasPrefix(op, "i64x2_"):
		return 3, "MOVD", "MOVD", "R0", true
	case strings.HasPrefix(op, "f32x4_"):
		return 2, "FMOVS", "FMOVS", "F0", true
	case strings.HasPrefix(op, "f64x2_"):
		return 3, "FMOVD", "FMOVD", "F0", true
	}
	return 0, "", "", "", false
}

// a64SpliceExtractLane inlines Simd_<shape>_extract_lane[_s|_u]:
// (v [2]uint64, lane int32) → elem. The vector is in its stack slot and
// the lane in R0, so the element is one indexed load away — no vector
// register needed at all, and the lane may be any runtime value.
func a64SpliceExtractLane(b *strings.Builder, op string, cargs []RegAssignment, base int, slots *SpliceSlots) bool {
	if len(cargs) != 2 || cargs[0].Kind != ArgV128 || cargs[1].Reg != "R0" {
		return false
	}
	scale, load, _, reg, ok := a64LaneElem(op)
	if !ok {
		return false
	}
	fmt.Fprintf(b, "\tADD $%d, RSP, R27\n", slots.argOff(0, base+cargs[0].SeqOf))
	fmt.Fprintf(b, "\tADD R0<<%d, R27, R27\n", scale)
	fmt.Fprintf(b, "\t%s (R27), %s\n", load, reg)
	return true
}

// a64SpliceReplaceLane inlines Simd_<shape>_replace_lane:
// (v [2]uint64, lane int32, val T) → [2]uint64. Copy the vector into
// the result slot, then store the element over the lane in place.
func a64SpliceReplaceLane(b *strings.Builder, op string, cargs []RegAssignment, cres *RegAssignment, hasRes bool, base int, slots *SpliceSlots) bool {
	if len(cargs) != 3 || cargs[0].Kind != ArgV128 || cargs[1].Reg != "R0" ||
		!hasRes || cres.Kind != ArgV128 {
		return false
	}
	scale, _, store, _, ok := a64LaneElem(op)
	if !ok {
		return false
	}
	val := cargs[2]
	valReg := val.Reg
	switch val.Kind {
	case ArgF32, ArgF64:
		if valReg != "F0" {
			return false
		}
	default:
		if valReg != "R1" {
			return false
		}
	}
	// F16 is outside the F0–F15 ABIInternal argument file and dead at a
	// call site, so it cannot collide with the float val in F0.
	out := slots.outOff(base + cres.SeqOf)
	fmt.Fprintf(b, "\tFMOVQ %d(RSP), F16\n", slots.argOff(0, base+cargs[0].SeqOf))
	fmt.Fprintf(b, "\tFMOVQ F16, %d(RSP) // simd out\n", out)
	fmt.Fprintf(b, "\tADD $%d, RSP, R27\n", out)
	fmt.Fprintf(b, "\tADD R0<<%d, R27, R27\n", scale)
	fmt.Fprintf(b, "\t%s %s, (R27)\n", store, valReg)
	return true
}
