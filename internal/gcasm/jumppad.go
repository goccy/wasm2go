package gcasm

import (
	"fmt"
	"strings"
)

// O(1) jump-table dispatch for hand-written asm.
//
// Plan9 asm cannot express address-of-label DATA, so gc's captured
// `LEAQ table(SB) + JMP (base)(idx*8)` cannot be reproduced literally.
// The historical rewrite (emitJumpTree) degrades the O(1) indirect
// jump into an O(log n) compare tree — a measured pessimization on
// interpreter-style dispatch. This file restores O(1):
//
//   - The dispatch keeps gc's ORIGINAL shape, retargeted at a
//     Go-declared table var:
//
//     amd64:  LEAQ ·tab(SB), base           (RIP-relative, PIE-safe)
//             JMP  (base)(idx*8)
//     arm64:  MOVD $·tab(SB), R16
//             MOVD (R16)(idx<<3), R17
//             JMP  (R17)
//
//     Exactly the registers gc's own dispatch clobbered, and — like
//     gc's dispatch — NO flag-register writes: the pre-dispatch flag
//     state gc lets targets consume arrives intact, so the whole
//     flag-replay machinery the compare tree needed does not apply.
//
//   - Each distinct dispatch target gets a STUB right after the
//     dispatch: a signature marker and a direct jump to the real pcN
//     label. Entries hold the stubs' ABSOLUTE addresses — computed and
//     written at init, never baked, so PIE/relocation is a non-issue.
//
//   - Stub addresses cannot be known at generation time (the consumer's
//     assembler picks final encodings), so the table is FILLED AT INIT:
//     each stub starts with an executable no-op signature unique to
//     (function, site, target), and a generated package init() scans
//     the function's code bytes for those signatures and writes the
//     entries. A missing signature panics at init — a mis-set table can
//     never silently wild-jump.
//
// Signature encodings (executable no-ops, checked byte-for-byte by the
// scanner):
//
//	amd64: two long NOPs `0F 1F 80 <sig32>` + `0F 1F 80 <^sig32>`
//	       (14 bytes; the complement pair rules out accidental matches)
//	arm64: MOVZ/MOVK/MOVK into R17 (a dispatch scratch) carrying a
//	       48-bit signature across three fixed-form instructions.

// JTTable accumulates jump-table dispatch sites for one output .s
// file, like ConstPool/TypeTable. The caller appends EmitAsm() to the
// .s and EmitGo() to the same package's Go declarations file.
type JTTable struct {
	Fns []JTFn
}

// JTFn is one transformed function's jump-table metadata.
type JTFn struct {
	Sym   string // asm/Go symbol (e.g. "Fn6321")
	Sites []JTSite
}

// JTSite is one dispatch site.
type JTSite struct {
	TabVar  string   // Go table var name (·TabVar(SB) from asm)
	Entries []uint16 // selector k → index into Sigs
	Sigs    []uint64 // distinct-target signatures (amd64: 32-bit; arm64: 48-bit)
}

func (jt *JTTable) fn(sym string) *JTFn {
	if n := len(jt.Fns); n > 0 && jt.Fns[n-1].Sym == sym {
		return &jt.Fns[n-1]
	}
	jt.Fns = append(jt.Fns, JTFn{Sym: sym})
	return &jt.Fns[len(jt.Fns)-1]
}

// jtSig derives the deterministic signature for one dispatch target.
// bits selects the architecture's signature width.
func jtSig(fnSym string, siteOff, target, bits int) uint64 {
	key := fmt.Sprintf("%s+%d>%d", fnSym, siteOff, target)
	h := uint64(14695981039346656037) // FNV-1a 64
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	s := h & (1<<bits - 1)
	// All-zero / all-one signatures resemble alignment padding; nudge.
	if s == 0 || s == 1<<bits-1 {
		s = 0x5A5A5A5A & (1<<bits - 1)
	}
	return s
}

// jtExpandEntries expands run-compressed targets to a per-selector
// stub-index list plus the distinct-target order.
func jtExpandEntries(site *jtSite) (entries []uint16, targets []int) {
	tIndex := map[int]int{}
	for _, r := range site.runs {
		if _, ok := tIndex[r.target]; !ok {
			tIndex[r.target] = len(targets)
			targets = append(targets, r.target)
		}
	}
	entries = make([]uint16, site.entryCount)
	for i, r := range site.runs {
		end := site.entryCount
		if i+1 < len(site.runs) {
			end = site.runs[i+1].start
		}
		for k := r.start; k < end; k++ {
			entries[k] = uint16(tIndex[r.target])
		}
	}
	return entries, targets
}

// emitJumpPad writes the amd64 O(1) dispatch + stubs for one site and
// registers its table metadata on jt.
func emitJumpPad(b *strings.Builder, jt *JTTable, symName string, site *jtSite, siteOff int) {
	fn := jt.fn(symName)
	tab := fmt.Sprintf("%s_jt%d", symName, siteOff)
	entries, targets := jtExpandEntries(site)

	fmt.Fprintf(b, "\tLEAQ ·%s(SB), %s\n", tab, site.baseReg)
	fmt.Fprintf(b, "\tJMP (%s)(%s*8)\n", site.baseReg, site.idxReg)

	sigs := make([]uint64, len(targets))
	for i, t := range targets {
		sig := jtSig(symName, siteOff, t, 32)
		sigs[i] = sig
		writeAmd64SigNop(b, uint32(sig))
		writeAmd64SigNop(b, ^uint32(sig))
		fmt.Fprintf(b, "\tJMP pc%d\n", t)
	}
	fn.Sites = append(fn.Sites, JTSite{TabVar: tab, Entries: entries, Sigs: sigs})
}

// writeAmd64SigNop emits `0F 1F 80 imm32` — NOPL imm32(AX), a 7-byte
// executable no-op carrying a 4-byte signature.
func writeAmd64SigNop(b *strings.Builder, imm uint32) {
	fmt.Fprintf(b, "\tBYTE $0x0F; BYTE $0x1F; BYTE $0x80\n")
	for i := 0; i < 4; i++ {
		fmt.Fprintf(b, "\tBYTE $0x%02X\n", byte(imm>>(8*i)))
	}
}

// a64EmitJumpPad is the arm64 twin — the same triple gc emitted,
// pointed at the Go table var.
func a64EmitJumpPad(b *strings.Builder, jt *JTTable, symName string, site *jtSite, siteOff int) {
	fn := jt.fn(symName)
	tab := fmt.Sprintf("%s_jt%d", symName, siteOff)
	entries, targets := jtExpandEntries(site)

	fmt.Fprintf(b, "\tMOVD $·%s(SB), R16\n", tab)
	fmt.Fprintf(b, "\tMOVD (R16)(%s<<3), R17\n", site.idxReg)
	fmt.Fprintf(b, "\tJMP (R17)\n")

	sigs := make([]uint64, len(targets))
	for i, t := range targets {
		sig := jtSig(symName, siteOff, t, 48)
		sigs[i] = sig
		// MOVZ x17,#lo / MOVK x17,#mid,lsl16 / MOVK x17,#hi,lsl32 —
		// three fixed-form writes to the R17 scratch the dispatch
		// already clobbers, carrying the 48-bit signature.
		fmt.Fprintf(b, "\tWORD $0x%08X\n", 0xD2800011|uint32(sig&0xFFFF)<<5)
		fmt.Fprintf(b, "\tWORD $0x%08X\n", 0xF2A00011|uint32(sig>>16&0xFFFF)<<5)
		fmt.Fprintf(b, "\tWORD $0x%08X\n", 0xF2C00011|uint32(sig>>32&0xFFFF)<<5)
		fmt.Fprintf(b, "\tJMP pc%d\n", t)
	}
	fn.Sites = append(fn.Sites, JTSite{TabVar: tab, Entries: entries, Sigs: sigs})
}

// EmitAsm renders the per-function address helpers (`<Sym>_jtpc`) the
// generated init uses as its scan origin. Tables themselves are Go
// vars (see EmitGo) — asm references them, Go owns the storage.
func (jt *JTTable) EmitAsm(arch string) string {
	var b strings.Builder
	for _, fn := range jt.Fns {
		if arch == "arm64" {
			fmt.Fprintf(&b, "TEXT ·%s_jtpc(SB), NOSPLIT|NOFRAME, $0-8\n\tMOVD $·%s(SB), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n", fn.Sym, fn.Sym)
			continue
		}
		fmt.Fprintf(&b, "TEXT ·%s_jtpc(SB), NOSPLIT, $0-8\n\tLEAQ ·%s(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n", fn.Sym, fn.Sym)
	}
	return b.String()
}

// EmitGo renders the table vars, the init() that fills them, and (once
// per file) the code-byte scanner. The output belongs in the same
// package as the .s file, in an arch-tagged Go file.
func (jt *JTTable) EmitGo(arch string) string {
	if len(jt.Fns) == 0 {
		return ""
	}
	var b strings.Builder
	for _, fn := range jt.Fns {
		fmt.Fprintf(&b, "func %s_jtpc() unsafe.Pointer\n\n", fn.Sym)
		for _, s := range fn.Sites {
			fmt.Fprintf(&b, "var %s [%d]uint64\n", s.TabVar, len(s.Entries))
		}
	}
	b.WriteString("\nfunc init() {\n")
	for _, fn := range jt.Fns {
		fmt.Fprintf(&b, "\tgcasmJTInit(%s_jtpc(), []gcasmJTSpec{\n", fn.Sym)
		for _, s := range fn.Sites {
			fmt.Fprintf(&b, "\t\t{tab: %s[:], entries: %#v, sigs: %#v},\n", s.TabVar, s.Entries, s.Sigs)
		}
		b.WriteString("\t})\n")
	}
	b.WriteString("}\n\n")
	if arch == "arm64" {
		b.WriteString(jtScannerGoARM64)
	} else {
		b.WriteString(jtScannerGoAMD64)
	}
	return b.String()
}

// jtScannerGoAMD64 locates each stub by its 14-byte double-NOP
// signature and writes the stubs' absolute addresses.
const jtScannerGoAMD64 = `type gcasmJTSpec struct {
	tab     []uint64
	entries []uint16
	sigs    []uint64
}

func gcasmJTInit(pc unsafe.Pointer, specs []gcasmJTSpec) {
	need := 0
	for _, s := range specs {
		need += len(s.sigs)
	}
	found := make(map[uint64]unsafe.Pointer, need)
	const maxScan = 1 << 26
	for off, n := 0, 0; n < need; off++ {
		if off >= maxScan {
			panic("gcasm: jump-table signature scan overflow")
		}
		p := (*[14]byte)(unsafe.Add(pc, off))
		if p[0] != 0x0F || p[1] != 0x1F || p[2] != 0x80 || p[7] != 0x0F || p[8] != 0x1F || p[9] != 0x80 {
			continue
		}
		sig := uint32(p[3]) | uint32(p[4])<<8 | uint32(p[5])<<16 | uint32(p[6])<<24
		inv := uint32(p[10]) | uint32(p[11])<<8 | uint32(p[12])<<16 | uint32(p[13])<<24
		if inv != ^sig {
			continue
		}
		if _, dup := found[uint64(sig)]; !dup {
			found[uint64(sig)] = unsafe.Add(pc, off)
			n++
		}
	}
	for _, s := range specs {
		for k, ti := range s.entries {
			stub, ok := found[s.sigs[ti]]
			if !ok {
				panic("gcasm: jump-table signature missing")
			}
			s.tab[k] = uint64(uintptr(stub))
		}
	}
}
`

// jtScannerGoARM64 locates each stub by its MOVZ/MOVK/MOVK triple.
const jtScannerGoARM64 = `type gcasmJTSpec struct {
	tab     []uint64
	entries []uint16
	sigs    []uint64
}

func gcasmJTInit(pc unsafe.Pointer, specs []gcasmJTSpec) {
	need := 0
	for _, s := range specs {
		need += len(s.sigs)
	}
	found := make(map[uint64]unsafe.Pointer, need)
	const maxScan = 1 << 26
	for off, n := 0, 0; n < need; off += 4 {
		if off >= maxScan {
			panic("gcasm: jump-table signature scan overflow")
		}
		w := (*[3]uint32)(unsafe.Add(pc, off))
		if w[0]&0xFFE0001F != 0xD2800011 || w[1]&0xFFE0001F != 0xF2A00011 || w[2]&0xFFE0001F != 0xF2C00011 {
			continue
		}
		sig := uint64(w[0]>>5&0xFFFF) | uint64(w[1]>>5&0xFFFF)<<16 | uint64(w[2]>>5&0xFFFF)<<32
		if _, dup := found[sig]; !dup {
			found[sig] = unsafe.Add(pc, off)
			n++
		}
	}
	for _, s := range specs {
		for k, ti := range s.entries {
			stub, ok := found[s.sigs[ti]]
			if !ok {
				panic("gcasm: jump-table signature missing")
			}
			s.tab[k] = uint64(uintptr(stub))
		}
	}
}
`
