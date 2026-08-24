package codegen

import (
	"encoding/binary"
	"fmt"
	"os"
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

// checkStaleF16Table decides, once translation is done, what a set
// Options.F16TableAddr that matched no verified gather base means.
// When the module itself verified a DIFFERENT base (the runtime
// init-loop detection or the static image), the assertion is
// provably stale and the build FAILS — a silent mismatch either
// disables the table-keyed rewrites or blesses whatever now lives at
// the old address. With no verified base to contradict it, the old
// warning remains: the address may simply appear in a module with no
// gather sites at all.
func (t *translator) checkStaleF16Table() error {
	msg, fatal := staleF16TableIssue(t.opts.F16TableAddr, t.f16TablesOK)
	if msg == "" {
		return nil
	}
	if fatal {
		return fmt.Errorf("%s", msg)
	}
	fmt.Fprintln(os.Stderr, msg)
	return nil
}

// staleF16TableIssue is checkStaleF16Table's decision: empty means
// the assertion is unset or matched a verified base.
func staleF16TableIssue(addr uint32, tables map[uint32]bool) (msg string, fatal bool) {
	if addr == 0 || tables[addr] {
		return "", false
	}
	var verified, unverified []uint32
	for base, ok := range tables {
		if base == addr {
			continue
		}
		if ok {
			verified = append(verified, base)
		} else {
			unverified = append(unverified, base)
		}
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i] < verified[j] })
	sort.Slice(unverified, func(i, j int) bool { return unverified[i] < unverified[j] })
	if len(verified) > 0 {
		return fmt.Sprintf(
			"wasm2go: F16TableAddr %d is stale — the module verifies its f16 table at %v; update or drop the assertion (auto-detection covers this module)",
			addr, verified), true
	}
	if _, seen := tables[addr]; seen {
		return "", false
	}
	return fmt.Sprintf(
		"wasm2go: F16TableAddr %d matches no f16 gather site — the table has likely moved and the gather rewrite stayed OFF; unverified gather bases seen: %v",
		addr, unverified), false
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
// SSA gather pass takes. Three ways a table qualifies:
//
//   - the module's initial data image holds the IEEE map at base
//     (verified byte-for-byte), or
//   - the module's own code provably initializes the whole range at
//     base (an init loop streaming constant-strided stores — the
//     ggml_init shape; see detectRuntimeTables), or
//   - the integrator asserted it: Options.F16TableAddr names the
//     base explicitly. The assertion is cross-checked against the
//     detection at the end of translation — a stale address fails
//     the build instead of silently disabling rewrites.
func (t *translator) f16TableOK(base uint32) bool {
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
		} else if t.opts.F16TableAddr != 0 && t.opts.F16TableAddr == base {
			ok = true
		}
	}
	t.f16TablesOK[base] = ok
	return ok
}
