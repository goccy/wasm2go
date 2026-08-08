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
// what FCVTL computes per lane and what ggml's table_f32_f16 holds.
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

// hasIEEEF16TableAt reports whether the module's ACTIVE data segments
// fully populate [base, base+65536*4) with table[i] == the IEEE
// conversion of i. Bytes not covered by any active segment default to
// zero in the initial image; the table has almost no zero entries, so
// coverage gaps fail the comparison naturally.
func (t *translator) hasIEEEF16TableAt(base uint32) bool {
	const tableLen = 65536 * 4
	img := make([]byte, tableLen)
	covered := 0
	for _, ds := range t.mod.Datas {
		if ds.Passive {
			continue
		}
		off, err := evalConstExprI64(ds.Offset, t.mod)
		if err != nil {
			continue
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

// warnStaleF16Table reports, once translation is done, an
// Options.F16TableAddr assertion that no gather site ever queried:
// the module's data layout has shifted and the asserted address no
// longer matches the table, so the f16 gather rewrite silently
// stayed off — a pure performance loss that is otherwise invisible.
// The bases that WERE queried and failed verification are the
// candidates the integrator should re-point the assertion at.
func (t *translator) warnStaleF16Table() {
	if msg := staleF16TableMsg(t.opts.F16TableAddr, t.f16TablesOK); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// staleF16TableMsg is warnStaleF16Table's decision: empty means the
// assertion is unset or was queried by some gather site (matched or
// not — being queried means the address still appears in code).
func staleF16TableMsg(addr uint32, tables map[uint32]bool) string {
	if addr == 0 {
		return ""
	}
	if _, seen := tables[addr]; seen {
		return ""
	}
	var cands []uint32
	for base, ok := range tables {
		if !ok {
			cands = append(cands, base)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i] < cands[j] })
	return fmt.Sprintf(
		"wasm2go: F16TableAddr %d matches no f16 gather site — the table has likely moved and the gather rewrite stayed OFF; unverified gather bases seen: %v",
		addr, cands)
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
//   - the integrator asserted it: Options.F16TableAddr names the
//     base of a table the module BUILDS AT RUNTIME (ggml computes its
//     f16->f32 table in an init function, so the data segment holds
//     only zeros and no static check can see it). The assertion is a
//     build-input contract, not a guess — a wrong address changes
//     numeric results, which the integrator's bit-equality gates
//     catch.
func (t *translator) f16TableOK(base uint32) bool {
	if t.f16TablesOK == nil {
		t.f16TablesOK = map[uint32]bool{}
	}
	ok, seen := t.f16TablesOK[base]
	if seen {
		return ok
	}
	ok = t.hasIEEEF16TableAt(base) || (t.opts.F16TableAddr != 0 && t.opts.F16TableAddr == base)
	t.f16TablesOK[base] = ok
	return ok
}
