package codegen

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// The f16 load-convert selection (see the scalarizer's gather rewrite)
// replaces reads of a module-resident f16->f32 lookup table with the
// FCVTL instruction. That is only sound when the table IS the IEEE
// conversion: the transpiler verifies the module's initial memory
// image byte-for-byte before enabling the rewrite. No pattern of
// table CONTENT is assumed — a module with any other table keeps the
// literal loads.

// f16BitsToF32Bits is the IEEE binary16 -> binary32 conversion,
// bit-exact including subnormals, infinities and NaN payloads
// (payload shifts left by 13; the quiet bit rides along). This is
// what FCVTL computes per lane and what such a table holds.
func f16BitsToF32Bits(h uint16) uint32 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1F
	man := uint32(h) & 0x3FF
	switch exp {
	case 0:
		if man == 0 {
			return sign // ±0
		}
		// Subnormal: value = man * 2^-24. Normalize into a binary32
		// exponent.
		e := uint32(113)
		for man&0x400 == 0 {
			man <<= 1
			e--
		}
		return sign | e<<23 | (man&0x3FF)<<13
	case 0x1F:
		return sign | 0xFF<<23 | man<<13 // ±inf / NaN
	}
	return sign | (exp+112)<<23 | man<<13
}

// hasIEEEF16TableAt reports whether the module's data segments
// (active, or passive with a recovered start-section placement)
// fully populate [base, base+65536*4) with table[i] == the IEEE
// conversion of i. Bytes not covered by any active segment default to
// zero in the initial image; the table has almost no zero entries, so
// coverage gaps fail the comparison naturally.
func (t *translator) hasIEEEF16TableAt(base uint32) bool {
	const tableLen = 65536 * 4
	img := make([]byte, tableLen)
	covered := 0
	placements := t.passiveSegmentPlacements()
	for segIdx, ds := range t.mod.Datas {
		var off int64
		if ds.Passive {
			// Shared-memory (threads) links make every segment
			// passive; the recovered start-section placement stands in
			// for the active-segment offset (see
			// passiveSegmentPlacements).
			po, ok := placements[segIdx]
			if !ok {
				continue
			}
			off = po
		} else {
			eo, err := evalConstExprI64(ds.Offset, t.mod)
			if err != nil {
				continue
			}
			off = eo
		}
		segEnd := off + int64(len(ds.Bytes))
		lo, hi := int64(base), int64(base)+tableLen
		if segEnd <= lo || off >= hi {
			continue
		}
		s, e := max64(off, lo), min64(segEnd, hi)
		copy(img[s-lo:e-lo], ds.Bytes[s-off:e-off])
		covered += int(e - s)
	}
	if covered == 0 {
		return false
	}
	for i := 0; i < 65536; i++ {
		if binary.LittleEndian.Uint32(img[i*4:]) != f16BitsToF32Bits(uint16(i)) {
			return false
		}
	}
	return true
}

// checkStaleF16Table fails the build, once translation is done, when
// f16 gather sites exist whose base verified NEITHER statically nor
// through init-loop detection. Left as a warning this state is the
// silent-degradation trap (the rewrites stay off and nothing in a
// long pipeline log demands attention); as an error it forces a
// decision — fix whatever broke the detection, or declare that the
// module has no f16 table by disabling the rewrites outright.
func (t *translator) checkStaleF16Table() error {
	if msg := unverifiedF16GatherMsg(t.opts.DisableF16Table, t.f16TablesOK); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// unverifiedF16GatherMsg is checkStaleF16Table's decision: empty
// means the rewrites are disabled, no gather sites exist, or every
// queried base verified.
func unverifiedF16GatherMsg(disabled bool, tables map[uint32]bool) string {
	if disabled {
		return ""
	}
	var unverified []uint32
	for base, ok := range tables {
		if !ok {
			unverified = append(unverified, base)
		}
	}
	if len(unverified) == 0 {
		return ""
	}
	sort.Slice(unverified, func(i, j int) bool { return unverified[i] < unverified[j] })
	return fmt.Sprintf(
		"wasm2go: f16 gather sites at bases %v were not verified (no static table image, no init-loop coverage): the table-keyed rewrites cannot prove themselves applicable — fix the table initialization so detection sees it, or pass -no-f16-table if this module has no runtime f16 table",
		unverified)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// f16TableOK is the cached table check, shaped as the callback the
// SSA gather pass takes. Two ways a table qualifies:
//
//   - the module's initial data image holds the IEEE map at base
//     (verified byte-for-byte), or
//   - the module's own code provably initializes the whole range at
//     base (an init loop streaming constant-strided stores — the
//     ggml_init shape; see detectRuntimeTables).
//
// There is no external address input: verification is derived from
// the module alone, and Options.DisableF16Table turns the whole
// mechanism off.
func (t *translator) f16TableOK(base uint32) bool {
	if t.opts.DisableF16Table {
		return false
	}
	if t.f16TablesOK == nil {
		t.f16TablesOK = map[uint32]bool{}
	}
	ok, seen := t.f16TablesOK[base]
	if seen {
		return ok
	}
	switch {
	case t.hasIEEEF16TableAt(base):
		ok = true
	default:
		t.detectRuntimeTables()
		if t.runtimeInitCovered(base) {
			ok = true
			t.noteF16TableDetection(base)
		}
	}
	t.f16TablesOK[base] = ok
	return ok
}
