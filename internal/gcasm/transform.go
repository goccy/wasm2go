package gcasm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// TransformOptions parameterize one function's transform.
type TransformOptions struct {
	// SymName is the local asm symbol to emit (e.g. "Fn3247" →
	// `TEXT ·Fn3247(SB)`).
	SymName string
	// CalleeSig resolves an internal callee symbol (as it appears in
	// the captured CALL, e.g. "github.com/x/pkg.Fn12") to its
	// signature, or ok=false for external/runtime calls that are
	// left untouched.
	CalleeSig func(sym string) (params []ArgKind, hasResult bool, result ArgKind, localSym string, ok bool)
	// Params/result of the function being transformed.
	Params    []ArgKind
	HasResult bool
	Result    ArgKind
	// ArgNames / ResName are the Go declaration's parameter and
	// result identifiers — FP operand names must match them or `go
	// vet`'s asmdecl check fails the consumer build. Defaults: aN/r0.
	ArgNames []string
	ResName  string
	// Datas resolves captured data symbols by name. Required when
	// the body dispatches through a gc jump table (`LEAQ
	// pkg.fn.jumpN(SB), Rt; JMP (Rt)(Ri*8)`): the table's R_ADDR
	// relocs give entryIndex → captured byte offset, and the pair is
	// rewritten into a binary search tree over pcN labels (Plan9 asm
	// cannot express label addresses in DATA).
	Datas map[string]*DataSym
	// Consts collects float-constant rodata referenced by captured
	// bodies (`$f32.<bits>(SB)` / `$f64.<bits>(SB)` operands, which
	// Plan9 asm cannot name). Shared across all Transform calls that
	// land in one .s file; append Consts.Emit() after the last body.
	// When nil, each transform emits its own trailer (single-function
	// files only — duplicate GLOBLs fail to assemble).
	Consts *ConstPool
	// Types collects runtime type descriptors referenced by captured
	// bodies (`LEAQ type:F(SB), R` from interface assertions — the
	// call_indirect lowering). Each becomes a load from a generated
	// package var `gcasmTypeN` that the decls file initialises with
	// the type's descriptor pointer (extracted from an eface). nil ⇒
	// type references are a transform error.
	Types *TypeTable
	// JT, when non-nil, selects the O(1) jump-pad dispatch for gc jump
	// tables (see jumppad.go) and accumulates the table metadata the
	// caller must render: EmitAsm() into the same .s file and EmitGo()
	// into the same package's arch-tagged Go file (the generated init
	// fills the tables). nil ⇒ the legacy O(log n) compare tree.
	JT *JTTable
	// SpliceStats, when non-nil, counts SIMD helper calls that were
	// spliced inline vs left as marshalled calls (table gaps). Purely
	// observability — the build summary reports the ratio.
	SpliceStats *SpliceStats
	// ModOffsets are the Module field offsets the SIMD memory-op
	// splices hardcode, extracted from the captured probe (see
	// FindModuleOffsets). nil keeps memory ops on the call path.
	ModOffsets *ModuleOffsets
	// FusedSimd resolves synthetic fused-region helper names
	// (simd_p_fx*) to their tree descriptors; the pair splicers
	// synthesize the inline body from the tree (see the
	// simdsplice_fuse files). A fused call with no entry here is a
	// build error, like any pair-table miss.
	FusedSimd map[string]*simdfuse.Tree
	// FusedLoops resolves synthetic fused-LOOP helper names.
	FusedLoops map[string]*simdfuse.Loop
	// PortableSIMD restricts splice synthesis to the architecture's
	// baseline instruction set (no FEAT_DotProd on arm64). Build uses
	// it to emit the portable twin of a feature-gated body; the
	// generated Go wrapper picks a body at runtime from the CPU
	// feature vars in the base package.
	PortableSIMD bool
}

// SpliceStats counts SIMD call-site outcomes across one build.
type SpliceStats struct {
	Spliced int // helper calls replaced by inline op bodies
	Kept    int // Simd_* calls left marshalled (no table entry)
}

// TypeTable accumulates runtime-type references for one output file.
type TypeTable struct {
	// Names holds the captured type strings (Go syntax with
	// import-path-qualified identifiers) in first-reference order.
	Names []string
	index map[string]int
}

func (tt *TypeTable) add(typ string) int {
	if tt.index == nil {
		tt.index = map[string]int{}
	}
	if i, ok := tt.index[typ]; ok {
		return i
	}
	i := len(tt.Names)
	tt.index[typ] = i
	tt.Names = append(tt.Names, typ)
	return i
}

// ConstPool accumulates float constants for one output .s file.
type ConstPool struct {
	names []string // emission order (first reference)
	seen  map[string]constEntry
}

type constEntry struct {
	size int
	bits string // hex, as embedded in gc's symbol name
	// blob holds the literal bytes for a captured rodata constant
	// (gc's `..stmp_N` statics, e.g. the 16-byte v128 literals the
	// SIMD lowering emits). When set, bits is unused.
	blob []byte
}

func (p *ConstPool) add(width, bits string) string {
	name := "gcf" + width + "_" + bits
	if p.seen == nil {
		p.seen = map[string]constEntry{}
	}
	if _, ok := p.seen[name]; !ok {
		sz := 4
		if width == "64" {
			sz = 8
		}
		p.seen[name] = constEntry{size: sz, bits: bits}
		p.names = append(p.names, name)
	}
	return name
}

// addBlob interns a captured rodata constant by CONTENT (so identical
// literals from different packages/functions share one symbol) and
// returns the pool-local name to reference it by.
func (p *ConstPool) addBlob(blob []byte) string {
	name := fmt.Sprintf("gcb%d_%x", len(blob), blob)
	if p.seen == nil {
		p.seen = map[string]constEntry{}
	}
	if _, ok := p.seen[name]; !ok {
		p.seen[name] = constEntry{size: len(blob), blob: blob}
		p.names = append(p.names, name)
	}
	return name
}

// Emit renders the pool's DATA/GLOBL trailer (deterministic:
// first-reference order).
func (p *ConstPool) Emit() string {
	var b strings.Builder
	for _, name := range p.names {
		e := p.seen[name]
		if e.blob != nil {
			// 8-byte DATA chunks, zero-padded to the declared size.
			for off := 0; off < e.size; off += 8 {
				end := off + 8
				if end > e.size {
					end = e.size
				}
				var w uint64
				for i := end - 1; i >= off; i-- {
					w = w<<8 | uint64(e.blob[i])
				}
				fmt.Fprintf(&b, "DATA ·%s+%d(SB)/%d, $0x%016x\n", name, off, end-off, w)
			}
			fmt.Fprintf(&b, "GLOBL ·%s(SB), RODATA|NOPTR, $%d\n", name, e.size)
			continue
		}
		fmt.Fprintf(&b, "DATA ·%s+0(SB)/%d, $0x%s\n", name, e.size, e.bits)
		fmt.Fprintf(&b, "GLOBL ·%s(SB), RODATA|NOPTR, $%d\n", name, e.size)
	}
	return b.String()
}

// stmpRe matches a reference to one of gc's static-temp rodata symbols
// (`<pkgpath>..stmp_N`, optionally with a byte offset). Plan9 asm
// cannot name them, so the transform re-materialises their captured
// bytes in the const pool.
var stmpRe = regexp.MustCompile(`([A-Za-z0-9_./\-]+)\.\.stmp_(\d+)((?:[+\-]\d+)?)\(SB\)`)

// rewriteStmpRefs replaces every `..stmp_N(SB)` operand with a const-pool
// symbol carrying the same bytes. Returns an error when the symbol was
// not captured or no pool is available (silently keeping the reference
// would emit unassemblable asm).
func rewriteStmpRefs(txt string, datas map[string]*DataSym, pool *ConstPool) (string, error) {
	var err error
	out := stmpRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := stmpRe.FindStringSubmatch(m)
		sym := sub[1] + "..stmp_" + sub[2]
		d := datas[sym]
		if d == nil || pool == nil {
			if err == nil {
				err = fmt.Errorf("rodata constant %s not captured", sym)
			}
			return m
		}
		if len(d.Relocs) > 0 {
			if err == nil {
				err = fmt.Errorf("rodata constant %s carries relocations", sym)
			}
			return m
		}
		return "·" + pool.addBlob(d.Bytes) + sub[3] + "(SB)"
	})
	return out, err
}

func (o *TransformOptions) argName(i int) string {
	if i < len(o.ArgNames) {
		return o.ArgNames[i]
	}
	return fmt.Sprintf("a%d", i)
}

func (o *TransformOptions) resName() string {
	if o.ResName != "" {
		return o.ResName
	}
	return "r0"
}

var (
	branchNumRe = regexp.MustCompile(`^(J[A-Z]+|JMP)\t(\d+)$`)
	callRe      = regexp.MustCompile(`^CALL\t([^\s(]+)\(SB\)$`)
	// Named frame slots: `pkg.v3+16(SP)` — and, for slots at frame
	// offset 0, `pkg.v3(SP)` with no +N part. The name must start
	// with a non-digit so plain `16(SP)` operands don't match.
	namedSlotRe = regexp.MustCompile(`[A-Za-z_.·~<>@][A-Za-z0-9_./·~<>@\-]*(?:\+(-?\d+))?\(SP\)`)
	runtimeRe   = regexp.MustCompile(`\bruntime\.([A-Za-z0-9_]+)\(SB\)`)
	jtLeaqRe    = regexp.MustCompile(`^LEAQ\t([^\s(]+\.jump\d+)\(SB\), ([A-Z][A-Z0-9]*)$`)
	jtJmpRe     = regexp.MustCompile(`^JMP\t\(([A-Z][A-Z0-9]*)\)\(([A-Z][A-Z0-9]*)\*8\)$`)
	// Register-indirect calls: interface methods and func values
	// (`CALL DX`, `CALL R8`, ...). These stay ABIInternal end-to-end.
	indirectCallRe = regexp.MustCompile(`^CALL\t(?:\()?[A-Z][A-Z0-9]*(?:\))?$`)
	// Float-constant rodata operands: gc prints them as
	// `$f32.<bits>(SB)` / `$f64.<bits>(SB)`; the bits ARE the value.
	fconstRe = regexp.MustCompile(`\$f(32|64)\.([0-9a-f]+)\(SB\)`)
	// Cross-package data symbol operands (e.g. gc's CPU-feature gate
	// `internal/cpu.X86+108(SB)`): the '/' cannot be lexed by the
	// assembler — respell with U+2215 ∕ and the package·name dot.
	crossSymRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_./]*)((?:\+-?\d+)?\(SB\))`)
	// Runtime type descriptor loads (interface assertions from the
	// call_indirect lowering).
	typeLeaqRe = regexp.MustCompile(`^LEAQ\ttype:(.+)\(SB\), ([A-Z][A-Z0-9]*)$`)
)

// respellCrossSym converts a captured import-path-qualified symbol to
// assembler spelling: slashes to U+2215 and the path/name separator
// dot to U+00B7.
func respellCrossSym(sym string) string {
	lastSlash := strings.LastIndex(sym, "/")
	if lastSlash < 0 {
		return sym
	}
	dot := strings.Index(sym[lastSlash:], ".")
	if dot < 0 {
		return sym
	}
	dot += lastSlash
	return strings.ReplaceAll(sym[:dot], "/", "∕") + "·" + sym[dot+1:]
}

// runtimeCallRewrites maps gc-inserted niladic runtime panic calls to
// never-returning trap helpers that the gcasm decls file defines in
// EVERY package (the wasm_trap_* helpers live in base only under the
// multi-package layout, so asm in chunk packages cannot name them).
// The generated pure code guards every div/rem/shift through its own
// trap checks, so the gc-inserted re-checks are dynamically
// unreachable — but they must assemble, and asm references only
// resolve against ABI0 symbols, which runtime's Go panic entries
// don't provide.
var runtimeCallRewrites = map[string]string{
	"runtime.panicdivide":   "·gcasmTrapDivZero",
	"runtime.panicoverflow": "·gcasmTrapOverflow",
	"runtime.panicshift":    "·gcasmTrapUnreachable",
	// Reachable traps carrying ABIInternal register arguments the
	// transform cannot marshal: the argument detail (index/length,
	// concrete types) is dropped, the never-returning panic is kept.
	// Both target helpers live in the generated gcasm decls file.
	"runtime.panicIndex":    "·gcasmTrapBounds",
	"runtime.panicIndexU":   "·gcasmTrapBounds",
	"runtime.panicBounds":   "·gcasmTrapBounds",
	"runtime.panicdottypeE": "·gcasmTrapIndirectSig",
	"runtime.panicdottypeI": "·gcasmTrapIndirectSig",
}

// runtimeAsmCallees are runtime entry points that are legitimately
// callable from assembly (asm-defined, register conventions fixed by
// contract rather than by the Go ABI).
var runtimeAsmCallees = map[string]bool{
	"runtime.duffzero": true,
	"runtime.duffcopy": true,
}

// runtimeMarshalled are runtime callees with known signatures that the
// transform marshals like any internal boundary: the linker
// materialises an ABI0 wrapper for the asm reference, and that wrapper
// reads STACK arguments (probed: reg-args fault, stack-args work).
var runtimeMarshalled = map[string]struct {
	params []ArgKind
	hasRes bool
	res    ArgKind
}{
	"runtime.memmove": {params: []ArgKind{ArgPtr, ArgPtr, ArgI64}},
}

// jtRun is one run of consecutive jump-table entries sharing a
// target: selector indices [start, …] dispatch to the captured byte
// offset target.
type jtRun struct {
	start  int
	target int
}

// jtSite is one detected jump-table dispatch: insns[idx] is the
// table LEAQ, insns[jmpIdx] the indirect JMP (NOPs may sit between).
type jtSite struct {
	idx    int
	jmpIdx int
	idxReg string
	// baseReg is the captured table-base register (the LEAQ/MOVD
	// destination) and tReg (arm64) the captured jump-target register —
	// both dead after the dispatch, so the O(1) jump pad clobbers
	// exactly these and nothing else.
	baseReg string
	tReg    string
	// entryCount is the table's total selector count (len(Relocs)).
	entryCount int
	// replay is the captured flag-setting instruction to re-execute
	// on every tree leaf / pad stub, when some dispatch target
	// consumes EFLAGS (see findJumpTables). Empty when no target
	// reads flags.
	replay string
	runs   []jtRun
}

// flagWriters / flagReaders classify mnemonics for the jump-table
// EFLAGS analysis. Writers SET flags; readers (Jcc/SETcc/CMOVcc)
// consume them without writing.
var flagWriterPrefixes = []string{
	"ADD", "ADC", "SUB", "SBB", "CMP", "TEST", "AND", "OR", "XOR",
	"INC", "DEC", "NEG", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL",
	"RCR", "BT", "IMUL", "MUL", "DIV", "IDIV", "POPCNT", "LZCNT",
	"TZCNT", "BSF", "BSR", "XADD", "UCOMIS", "COMIS",
}

func writesFlags(txt string) bool {
	mn := txt
	if i := strings.IndexByte(mn, '	'); i >= 0 {
		mn = mn[:i]
	}
	// CMOV/SETcc read flags; CMPXCHG writes. Distinguish before the
	// prefix scan (CMOV shares the CMP prefix).
	if strings.HasPrefix(mn, "CMOV") || strings.HasPrefix(mn, "SET") {
		return false
	}
	// BMI2 shifts (SARX/SHRX/SHLX, spelled SARXQ/SARXL etc. with the
	// size suffix LAST) do not touch flags. Misclassifying them as
	// writers would let the jump-table flag-liveness analysis treat
	// live flags as clobbered — an unsafe rewrite, not a conservative
	// one.
	if strings.HasPrefix(mn, "SARX") || strings.HasPrefix(mn, "SHRX") || strings.HasPrefix(mn, "SHLX") {
		return false
	}
	for _, p := range flagWriterPrefixes {
		if strings.HasPrefix(mn, p) {
			return true
		}
	}
	return false
}

func readsFlags(txt string) bool {
	mn := txt
	if i := strings.IndexByte(mn, '	'); i >= 0 {
		mn = mn[:i]
	}
	if mn == "JMP" {
		return false
	}
	return (strings.HasPrefix(mn, "J") && len(mn) <= 4) ||
		strings.HasPrefix(mn, "SET") || strings.HasPrefix(mn, "CMOV") ||
		strings.HasPrefix(mn, "ADC") || strings.HasPrefix(mn, "SBB")
}

// findJumpTables detects gc jump-table dispatch pairs and resolves
// their tables to run-compressed target lists.
//
// flagTransparent declares that the dispatch REWRITE preserves EFLAGS
// (the O(1) jump pad — LEAQ + memory-operand JMP, like gc's original),
// making the flag-liveness analysis moot: no replay is captured and no
// site can fail as unreplayable. The compare tree passes false.
func findJumpTables(fnName string, insns []Insn, datas map[string]*DataSym, flagTransparent bool) (map[int]*jtSite, error) {
	sites := map[int]*jtSite{}
	for i, in := range insns {
		lm := jtLeaqRe.FindStringSubmatch(in.Text)
		if lm == nil {
			continue
		}
		// The indirect JMP follows the LEAQ, possibly across NOPs
		// (gc pads alignment between them).
		j := i + 1
		for j < len(insns) && insns[j].Text == "NOP" {
			j++
		}
		if j >= len(insns) {
			return nil, fmt.Errorf("jump-table LEAQ %q at end of body", in.Text)
		}
		jm := jtJmpRe.FindStringSubmatch(insns[j].Text)
		if jm == nil || jm[1] != lm[2] {
			return nil, fmt.Errorf("jump-table LEAQ %q not followed by indirect JMP (got %q)", in.Text, insns[j].Text)
		}
		tab, ok := datas[lm[1]]
		if !ok {
			return nil, fmt.Errorf("jump table %s not captured", lm[1])
		}
		if len(tab.Relocs) == 0 || len(tab.Relocs)*8 != tab.Size {
			return nil, fmt.Errorf("jump table %s: %d relocs for size %d", lm[1], len(tab.Relocs), tab.Size)
		}
		site := &jtSite{idx: i, jmpIdx: j, idxReg: jm[2], baseReg: lm[2], entryCount: len(tab.Relocs)}
		for k, r := range tab.Relocs {
			if r.Off != k*8 {
				return nil, fmt.Errorf("jump table %s: reloc %d at offset %d", lm[1], k, r.Off)
			}
			if r.Sym != fnName {
				return nil, fmt.Errorf("jump table %s: reloc targets %s, not %s", lm[1], r.Sym, fnName)
			}
			if n := len(site.runs); n > 0 && site.runs[n-1].target == r.Addend {
				continue
			}
			site.runs = append(site.runs, jtRun{start: k, target: r.Addend})
		}
		// EFLAGS liveness across the dispatch: if any target begins
		// consuming flags before writing them, the captured
		// flag-setter preceding the LEAQ must be replayed at the
		// tree leaves.
		offIndex := map[int]int{}
		for k, in2 := range insns {
			offIndex[in2.Off] = k
		}
		// The compare tree the transform emits CLOBBERS EFLAGS, whereas
		// gc's captured LEAQ+indirect-JMP dispatch PRESERVES them — and
		// gc exploits that by letting a dispatch target consume flags set
		// before the dispatch (typically the `CMP idx,$max` of the bounds
		// check gc emits just ahead of the table jump). So at every tree
		// leaf we must RESTORE the exact pre-dispatch flag state.
		//
		// Rather than try to PROVE which targets consume flags — a
		// forward linear scan cannot do that soundly (a target may reach
		// flag-consuming code across an unconditional JMP, or via an
		// offset the capture never recorded), and the old "detect
		// consumption, else skip" logic had exactly those false-negative
		// holes: an undetected flag-consuming target got no replay, the
		// tree's leftover flags leaked in, and a downstream branch went
		// the wrong way (surfacing as a wild-pointer SIGSEGV once inlining
		// enlarged a dispatch-heavy function enough to expose it) — we
		// take the robust route: if a CLEAN, replayable flag-setter sits
		// immediately before the dispatch, ALWAYS replay it at the leaves.
		// Replaying a compare no target reads is harmless (it only
		// recomputes flags; no register or memory is touched), so this is
		// unconditionally correct and detection-free. Only when the
		// nearest pre-dispatch flag-writer is NOT cleanly replayable do we
		// need to know whether any target actually consumes flags; there
		// we keep the conservative scan and fall back to pure if it might.
		if flagTransparent {
			sites[i] = site
			continue
		}
		replay, replayClean := "", false
		for k := i - 1; k >= 0 && i-k <= 8; k-- {
			t := insns[k].Text
			if writesFlags(t) {
				// Only pure register compares replay verbatim — memory
				// operands would need the frame-shift rewrite, which
				// does not apply at the leaves.
				if (strings.HasPrefix(t, "CMP") || strings.HasPrefix(t, "TEST")) &&
					!strings.Contains(t, "(SP)") && !strings.Contains(t, "(SB)") {
					replay, replayClean = t, true
				}
				break
			}
			if strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") {
				break
			}
		}
		if replayClean {
			// Always safe: restore the dispatch-entry flags at every leaf.
			site.replay = replay
		} else {
			// No cleanly-replayable flag-setter. Fall back to pure unless
			// we can prove NO target consumes flags (conservative: any
			// unverifiable target counts as consuming).
			consumes := false
			for _, r := range site.runs {
				k, ok := offIndex[r.target]
				if !ok {
					consumes = true
					break
				}
				for ; k < len(insns); k++ {
					t := insns[k].Text
					if readsFlags(t) {
						consumes = true
						break
					}
					if writesFlags(t) || strings.HasPrefix(t, "CALL") || strings.HasPrefix(t, "RET") || strings.HasPrefix(t, "JMP") {
						break
					}
				}
				if consumes {
					break
				}
			}
			if consumes {
				return nil, fmt.Errorf("%w: jump table at +%d: flags consumed by targets but no replayable flag-setter found", errUnsupportedJumpTable, in.Off)
			}
		}
		sites[i] = site
	}
	// Any indexed indirect JMP outside a detected site would be a
	// missed dispatch — fail loudly rather than assemble a jump into
	// data.
	jmpOwned := map[int]bool{}
	for _, site := range sites {
		jmpOwned[site.jmpIdx] = true
	}
	for i, in := range insns {
		if jtJmpRe.MatchString(in.Text) && !jmpOwned[i] {
			return nil, fmt.Errorf("unmatched indexed indirect JMP %q at +%d", in.Text, in.Off)
		}
	}
	return sites, nil
}

// emitJumpTree writes a binary search tree over the site's runs:
// O(log n) compares dispatching to pcN labels. The selector is
// already bounds-checked by the captured code (gc emits CMP/JHI to
// the default label before the table jump), so indices outside
// [0, lastEntry] cannot reach here. Right-branch labels derive from
// the LEAQ's captured offset and a deterministic traversal counter.
func emitJumpTree(b *strings.Builder, site *jtSite, leaqOff int) {
	// The captured dispatch (LEAQ table / indirect JMP) PRESERVES
	// EFLAGS, and gc exploits that: it can place a flag-setting
	// instruction before the dispatch and branch on those flags
	// INSIDE the targets. The compare tree clobbers flags, so when a
	// target consumes them the captured flag-setter is REPLAYED on
	// each leaf (the tree writes nothing but flags, so its operands
	// are unchanged). Register/stack flag saves don't work here:
	// PUSHFQ is outside the assembler's SP tracking (SPWRITE → the
	// runtime refuses to unwind) and LAHF/SAHF miss OF.
	labelID := 0
	var rec func(lo, hi int)
	rec = func(lo, hi int) {
		if lo == hi {
			if site.replay != "" {
				fmt.Fprintf(b, "\t%s\n", site.replay)
			}
			fmt.Fprintf(b, "\tJMP pc%d\n", site.runs[lo].target)
			return
		}
		mid := (lo + hi + 1) / 2
		labelID++
		lbl := fmt.Sprintf("jt%d_%d", leaqOff, labelID)
		fmt.Fprintf(b, "\tCMPQ %s, $%d\n", site.idxReg, site.runs[mid].start)
		fmt.Fprintf(b, "\tJCC %s\n", lbl)
		rec(lo, mid-1)
		fmt.Fprintf(b, "%s:\n", lbl)
		rec(mid, hi)
	}
	rec(0, len(site.runs)-1)
}

// Transform rewrites one captured ABIInternal function into an ABI0
// .s body:
//
//   - the captured prologue/epilogue/stacksplit are STRIPPED and the
//     real frame size is declared on the TEXT line, so the assembler
//     regenerates them with correct pcsp/unwind metadata (this also
//     keeps arguments in their ABI0 stack slots across stack growth,
//     dodging the ABI0-morestack register-clobber trap);
//   - arguments are loaded from their FP slots into the ABIInternal
//     registers once at entry;
//   - every internal CALL gains register→outgoing-stack-arg stores
//     before it and a result load after it (the bundle keeps the
//     ABI0 stack convention at ALL call boundaries; signatures of
//     every internal callee are known);
//   - the frame grows by the outgoing-argument area, and every
//     captured SP-relative offset shifts up by that delta;
//   - numeric branch offsets become pcN labels (offset-derived —
//     deterministic), named stack slots collapse to bare offsets,
//     and RET epilogues collapse back to plain RET.
func Transform(fn *Fn, opts TransformOptions) (string, error) {
	// DUFFZERO/DUFFCOPY cannot be hand-assembled (see errUnsupportedDuff);
	// such functions are routed to their pure fallback by Build.
	if hasDuffPseudo(fn.Insns) {
		return "", errUnsupportedDuff
	}
	// Directive pseudo-instructions confuse positional prologue
	// detection and are re-derived by the assembler anyway.
	var meat []Insn
	for _, in := range fn.Insns {
		if strings.HasPrefix(in.Text, "FUNCDATA") || strings.HasPrefix(in.Text, "PCDATA") {
			continue
		}
		meat = append(meat, in)
	}
	insns, err := stripPrologueEpilogue(meat)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fn.Name, err)
	}

	// Callee resolution: the caller's table first, then the built-in
	// runtime marshal table (memmove & co).
	resolveCallee := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if params, hasRes, res, localSym, ok := opts.CalleeSig(sym); ok {
			return params, hasRes, res, localSym, true
		}
		if rm, ok := runtimeMarshalled[sym]; ok {
			return rm.params, rm.hasRes, rm.res, runtimeRe.ReplaceAllString(sym+"(SB)", "runtime·$1"), true
		}
		return nil, false, 0, "", false
	}

	// Outgoing argument area: max over internal callees.
	maxOut := 0
	for _, in := range insns {
		if m := callRe.FindStringSubmatch(in.Text); m != nil {
			if params, hasRes, res, _, ok := resolveCallee(m[1]); ok {
				sz := abi0ArgSize(params, hasRes, res)
				if sz > maxOut {
					maxOut = sz
				}
			}
		}
	}
	maxOut = (maxOut + 7) &^ 7
	frame := fn.FrameSize + maxOut

	var b strings.Builder
	// The TEXT argsize is the ABI0 layout (args + pointer-aligned
	// results), NOT the captured ABIInternal argsize (which excludes
	// stack results entirely).
	abi0Args := abi0ArgSize(opts.Params, opts.HasResult, opts.Result)
	fmt.Fprintf(&b, "TEXT ·%s(SB), $%d-%d\n", opts.SymName, frame, abi0Args)
	b.WriteString("\tNO_LOCAL_POINTERS\n")

	// ABIInternal keeps X15 permanently zeroed and captured bodies
	// use it as a vector-zero source (e.g. duff-style clears). The
	// invariant holds across Go execution in practice, but ABI0
	// makes no such promise — re-establish it explicitly when the
	// body relies on it.
	usesX15 := false
	for _, in := range insns {
		if strings.Contains(in.Text, "X15") {
			usesX15 = true
			break
		}
	}
	if usesX15 {
		b.WriteString("\tPXOR X15, X15\n")
	}

	// Entry: FP args → ABIInternal registers. A signature that
	// stack-assigns under ABIInternal is not transformable — the
	// pipeline keeps such functions as pure Go (per-function
	// fallback), so reject here.
	args, res, err := AssignABIInternal(opts.Params, opts.HasResult, opts.Result)
	if err != nil {
		return "", err
	}
	for i, a := range args {
		if a.Reg == "" {
			return "", fmt.Errorf("gcasm: param %d exceeds ABIInternal registers (pure fallback)", i)
		}
		fmt.Fprintf(&b, "\t%s %s+%d(FP), %s\n", LoadFor(a.Kind), opts.argName(i), a.StackOf, a.Reg)
	}

	// Jump-table dispatch sites: LEAQ+JMP pairs replaced by binary
	// search trees over the table's captured target offsets.
	jtSites, err := findJumpTables(fn.Name, insns, opts.Datas, opts.JT != nil)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fn.Name, err)
	}

	// Const pool (shared across the file when the caller provides
	// one) and the in-package symbol operand rewrite.
	pool := opts.Consts
	ownPool := false
	if pool == nil {
		pool = &ConstPool{}
		ownPool = true
	}
	pkgPrefix := fn.Name[:strings.LastIndex(fn.Name, ".")+1]
	pkgSymRe := regexp.MustCompile(regexp.QuoteMeta(pkgPrefix) + `([A-Za-z_][A-Za-z0-9_]*)((?:\+-?\d+)?\(SB\))`)

	// Branch targets.
	targets := map[int]bool{}
	for _, in := range insns {
		if m := branchNumRe.FindStringSubmatch(in.Text); m != nil {
			var t int
			if _, err := fmt.Sscanf(m[2], "%d", &t); err != nil {
				continue
			}
			targets[t] = true
		}
	}
	for _, site := range jtSites {
		for _, r := range site.runs {
			targets[r.target] = true
		}
	}

	// Emit labels via a sorted pending list: a branch target whose
	// instruction was STRIPPED (epilogue ADDQ/POPQ before a RET, the
	// jump-table pair's padding) must land on the next surviving
	// instruction — gc branches to epilogues, and with the epilogue
	// regenerated by the assembler the correct landing site is the
	// RET (results are already in the ABIInternal result register at
	// the branch).
	targetList := make([]int, 0, len(targets))
	for off := range targets {
		targetList = append(targetList, off)
	}
	sort.Ints(targetList)
	tptr := 0
	emitPending := func(upTo int) {
		for tptr < len(targetList) && targetList[tptr] <= upTo {
			fmt.Fprintf(&b, "pc%d:\n", targetList[tptr])
			tptr++
		}
	}
	// trapCallee, once set, marks that at least one memory splice
	// branched to the shared out-of-bounds stub, emitted after the body.
	trapCallee := ""
	for idx := 0; idx < len(insns); idx++ {
		in := insns[idx]
		emitPending(in.Off)
		if site, ok := jtSites[idx]; ok {
			if opts.JT != nil {
				emitJumpPad(&b, opts.JT, opts.SymName, site, in.Off)
			} else {
				emitJumpTree(&b, site, in.Off)
			}
			idx = site.jmpIdx // swallow padding NOPs + the indirect JMP
			continue
		}
		txt := in.Text
		switch {
		case strings.HasPrefix(txt, "FUNCDATA") || strings.HasPrefix(txt, "PCDATA"):
			continue
		}
		if m := branchNumRe.FindStringSubmatch(txt); m != nil {
			txt = m[1] + "\tpc" + m[2]
		}
		// SP-relative rewrites: offsets pointing above the captured
		// frame are INCOMING argument slots (gc spills ABIInternal
		// args to their stack homes, which coincide with our ABI0
		// arg layout) — rewrite them to named FP references. Offsets
		// inside the frame shift up by the new outgoing-arg area.
		txt = rewriteSPOffsets(txt, fn.FrameSize, maxOut, args, opts)
		if m := callRe.FindStringSubmatch(txt); m != nil {
			// Pair-form SIMD calls splice BEFORE callee resolution:
			// their two-result signatures have no marshalling, by the
			// simdPairOps contract. See simdsplice_pair_amd64.go.
			if pop, isPair := a64SplicePairOp(m[1]); isPair {
				var spliced, wantsTrap bool
				var perr error
				if lp, isLoop := opts.FusedLoops["simd_p_"+pop]; isLoop {
					spliced, wantsTrap, perr = x64SpliceLoop(&b, lp, pool, opts.ModOffsets, fmt.Sprintf("%d", in.Off), maxOut)
				} else if tree, isFused := opts.FusedSimd["simd_p_"+pop]; isFused {
					spliced, wantsTrap, perr = x64SpliceFused(&b, tree, pool, opts.ModOffsets, maxOut)
				} else {
					spliced, wantsTrap, perr = x64SplicePair(&b, pop, pool, opts.ModOffsets)
				}
				if perr != nil {
					return "", fmt.Errorf("%s at +%d: %w", m[1], in.Off, perr)
				}
				if spliced {
					if wantsTrap && trapCallee == "" {
						trapSym := m[1][:strings.LastIndex(m[1], ".")+1] + "Wasm_trap_simd_oob"
						if strings.Contains(m[1], ".simd_") {
							trapSym = m[1][:strings.LastIndex(m[1], ".")+1] + "wasm_trap_simd_oob"
						}
						if _, _, _, localSym, ok := resolveCallee(trapSym); ok {
							trapCallee = localSym
						} else {
							return "", fmt.Errorf("simd mem splice: cannot resolve %s", trapSym)
						}
					}
					if opts.SpliceStats != nil {
						opts.SpliceStats.Spliced++
					}
					continue
				}
			}
			if params, hasRes, res2, localSym, ok := resolveCallee(m[1]); ok {
				// Marshal ABIInternal registers to the callee's ABI0
				// outgoing stack slots, call, then load the result.
				cargs, cres, aerr := AssignABIInternal(params, hasRes, res2)
				if aerr != nil {
					return "", aerr
				}
				for _, ca := range cargs {
					if ca.Kind == ArgV128 {
						// 16-byte stack-to-stack copy through R12.
						fmt.Fprintf(&b, "\tMOVQ %d(SP), R12\n", ca.SeqOf+maxOut)
						fmt.Fprintf(&b, "\tMOVQ R12, %d(SP)\n", ca.StackOf)
						fmt.Fprintf(&b, "\tMOVQ %d(SP), R12\n", ca.SeqOf+maxOut+8)
						fmt.Fprintf(&b, "\tMOVQ R12, %d(SP)\n", ca.StackOf+8)
						continue
					}
					if ca.Reg != "" {
						fmt.Fprintf(&b, "\t%s %s, %d(SP)\n", StoreFor(ca.Kind), ca.Reg, ca.StackOf)
						continue
					}
					// Stack-assigned under ABIInternal: the captured
					// caller already wrote the value into its outgoing
					// sequence at SeqOf(SP) — shifted by the new
					// outgoing area like every in-frame offset. Copy it
					// to the ABI0 slot through R12, which is dead at
					// ABIInternal call sites (caller-saved, never an
					// argument register). Widths copy bitwise.
					mov := "MOVQ"
					if ca.Kind == ArgI32 || ca.Kind == ArgU32 || ca.Kind == ArgF32 {
						mov = "MOVL"
					}
					fmt.Fprintf(&b, "\t%s %d(SP), R12\n", mov, ca.SeqOf+maxOut)
					fmt.Fprintf(&b, "\t%s R12, %d(SP)\n", mov, ca.StackOf)
				}
				fmt.Fprintf(&b, "\tCALL %s(SB)\n", localSym)
				if hasRes {
					if cres.Kind == ArgV128 {
						// Stack result: copy it back to where the captured
						// ABIInternal caller reads it (its outgoing
						// sequence, shifted like every in-frame offset).
						fmt.Fprintf(&b, "\tMOVQ %d(SP), R12\n", cres.StackOf)
						fmt.Fprintf(&b, "\tMOVQ R12, %d(SP)\n", cres.SeqOf+maxOut)
						fmt.Fprintf(&b, "\tMOVQ %d(SP), R12\n", cres.StackOf+8)
						fmt.Fprintf(&b, "\tMOVQ R12, %d(SP)\n", cres.SeqOf+maxOut+8)
					} else {
						fmt.Fprintf(&b, "\t%s %d(SP), %s\n", LoadFor(cres.Kind), cres.StackOf, cres.Reg)
					}
				}
				continue
			}
			// External (runtime) call. The linker resolves asm
			// references against ABI0 symbols only, and runtime's Go
			// panic entries have no ABI0 alias — route the niladic
			// panic checks gc inserted (all dominated by our own trap
			// checks, so unreachable at runtime, but they must still
			// assemble and link) to the module's never-returning trap
			// helpers. Anything not on the map is a silent ABI
			// mismatch waiting to happen — fail the transform.
			if strings.HasPrefix(m[1], "runtime.") {
				if repl, ok := runtimeCallRewrites[m[1]]; ok {
					txt = "CALL\t" + repl + "(SB)"
				} else if runtimeAsmCallees[m[1]] {
					txt = runtimeRe.ReplaceAllString(txt, "runtime·$1(SB)")
				} else {
					return "", fmt.Errorf("unhandled runtime call %q at +%d", m[1], in.Off)
				}
			} else {
				// A direct CALL the callee table doesn't cover would
				// keep its ABIInternal register arguments while the
				// linker binds the ABI0 symbol — a silent mismatch.
				return "", fmt.Errorf("unmarshalled direct call %q at +%d", m[1], in.Off)
			}
		}
		// Runtime type descriptor loads: `type:F` symbols cannot be
		// named from user asm; load the generated package var that the
		// decls file initialises with the same descriptor pointer.
		if m := typeLeaqRe.FindStringSubmatch(txt); m != nil {
			if opts.Types == nil {
				return "", fmt.Errorf("type reference %q at +%d with no TypeTable", m[1], in.Off)
			}
			txt = fmt.Sprintf("MOVQ\t·gcasmType%d(SB), %s", opts.Types.add(m[1]), m[2])
		} else if strings.Contains(txt, "type:") {
			return "", fmt.Errorf("unhandled type-descriptor operand %q at +%d", txt, in.Off)
		}
		// gc static-temp rodata (composite-literal constants, e.g. the
		// 16-byte v128 literals) cannot be named from user asm — the
		// pool re-materialises their captured bytes.
		if strings.Contains(txt, "..stmp_") {
			var serr error
			if txt, serr = rewriteStmpRefs(txt, opts.Datas, pool); serr != nil {
				return "", fmt.Errorf("%w at +%d", serr, in.Off)
			}
		}
		// Float-constant rodata operands ($f32.<bits>(SB)) cannot be
		// named from user asm — route them through the const pool.
		txt = fconstRe.ReplaceAllStringFunc(txt, func(m string) string {
			sub := fconstRe.FindStringSubmatch(m)
			return "·" + pool.add(sub[1], sub[2]) + "(SB)"
		})
		// runtime DATA operands (CPU feature gates like
		// runtime.x86HasSSE41): plain dot-rewrite, no ABI concerns
		// for data symbols. runtime CALLs never reach here — they
		// were rewritten or rejected above.
		txt = runtimeRe.ReplaceAllString(txt, "runtime·$1(SB)")
		// Remaining in-package symbol operands (globals, rodata): the
		// captured spelling embeds the import path, whose '/' the
		// assembler cannot lex — collapse to the package-local ·name.
		txt = pkgSymRe.ReplaceAllString(txt, "·$1$2")
		// Cross-package data symbols keep their import path, respelt
		// with ∕ and · so the assembler can lex it. Paths with a DOT
		// (github.com/...) cannot be spelt in Plan9 asm at all — any
		// such reference must have been rewritten earlier (in-package
		// collapse or callee marshalling); error rather than emit an
		// unparseable operand.
		var crossErr error
		txt = crossSymRe.ReplaceAllStringFunc(txt, func(m string) string {
			sub := crossSymRe.FindStringSubmatch(m)
			if !strings.Contains(sub[1], "/") {
				return m
			}
			re := respellCrossSym(sub[1])
			if pkg, _, ok := strings.Cut(re, "·"); ok && strings.Contains(pkg, ".") {
				crossErr = fmt.Errorf("unrepresentable cross-package symbol %q at +%d (dotted import path)", sub[1], in.Off)
			}
			return re + sub[2]
		})
		if crossErr != nil {
			return "", crossErr
		}
		if maxOut > 0 && indirectCallRe.MatchString(txt) {
			// ABIInternal pass-through call (interface method / func
			// value). Its stack-assigned arguments were stored by the
			// captured code at outgoing offsets which the frame-shift
			// moved UP by maxOut — but the callee reads them relative
			// to the CALL-time SP. Raise SP by the shift for the call
			// so the callee sees them at the captured offsets; the
			// pushed return address lands inside our (dead between
			// marshalled calls) ABI0 outgoing scratch. The assembler
			// tracks the explicit SP arithmetic (Spadj), so
			// pcsp/traceback stay correct, and the callee's own arg
			// stack map covers the (correctly positioned) argument
			// words during GC.
			// ADJSP is the assembler's tracked SP adjustment: plain
			// ADDQ/SUBQ on SP marks the function SPWRITE, and the
			// runtime refuses to unwind through SPWRITE frames when
			// the callee grows the stack (fatal: traceback).
			fmt.Fprintf(&b, "\tADJSP $-%d\n\t%s\n\tADJSP $%d\n", maxOut, txt, maxOut)
			continue
		}
		if strings.HasPrefix(txt, "RET") && opts.HasResult {
			// ABIInternal returns in AX/X0; ABI0 returns on the stack.
			fmt.Fprintf(&b, "\t%s %s, %s+%d(FP)\n", StoreFor(res.Kind), res.Reg, opts.resName(), res.StackOf)
		}
		fmt.Fprintf(&b, "\t%s\n", txt)
	}
	if tptr < len(targetList) {
		return "", fmt.Errorf("branch target +%d beyond last surviving instruction", targetList[tptr])
	}
	if trapCallee != "" {
		// The shared out-of-bounds stub. The trap helper panics, so
		// control never returns; the RET only satisfies the assembler.
		fmt.Fprintf(&b, "%s:\n", x64SimdMemTrapLabel)
		fmt.Fprintf(&b, "\tCALL %s(SB)\n", trapCallee)
		b.WriteString("\tRET\n")
	}
	// No raw SP arithmetic may survive: a missed prologue/epilogue
	// variant corrupts SP (and marks the function SPWRITE, which the
	// runtime refuses to unwind through). Our own adjustments use
	// ADJSP.
	for _, ln := range strings.Split(b.String(), "\n") {
		t := strings.TrimPrefix(ln, "\t")
		if (strings.HasPrefix(t, "ADDQ\t$") || strings.HasPrefix(t, "SUBQ\t$")) && strings.HasSuffix(t, ", SP") {
			return "", fmt.Errorf("raw SP arithmetic survived the transform: %q", t)
		}
	}
	if ownPool && len(pool.names) > 0 {
		b.WriteString("\n")
		b.WriteString(pool.Emit())
	}
	return b.String(), nil
}

// abi0ArgSize computes the ABI0 stack argument area (args + results).
func abi0ArgSize(params []ArgKind, hasRes bool, res ArgKind) int {
	off := 0
	al := func(n, a int) int { return (n + a - 1) &^ (a - 1) }
	sz := func(k ArgKind) (int, int) {
		switch k {
		case ArgI32, ArgU32, ArgF32:
			return 4, 4
		case ArgV128:
			return 16, 8
		default:
			return 8, 8
		}
	}
	for _, p := range params {
		s, a := sz(p)
		off = al(off, a) + s
	}
	if hasRes {
		s, _ := sz(res)
		off = al(off, 8) + s // results area is pointer-aligned (ABI0)
	}
	return off
}

var (
	spOffRe  = regexp.MustCompile(`(^|[\s,(])(-?\d+)\(SP\)`)
	bareSPRe = regexp.MustCompile(`(^|[\s,])\(SP\)`)
)

// rewriteSPOffsets collapses named slots to bare offsets, rewrites
// above-frame references (incoming args at capturedFrame+8+k under
// gc's frame-pointer layout) into named FP operands, and shifts
// in-frame offsets up by the outgoing-arg delta.
func rewriteSPOffsets(txt string, capturedFrame, delta int, args []RegAssignment, opts TransformOptions) string {
	// Frame offset 0 prints as a bare `(SP)` — normalise so the
	// shift below sees it (it slipped through once as an unshifted
	// outgoing stack-arg store that collided with the marshal area).
	txt = bareSPRe.ReplaceAllString(txt, "${1}0(SP)")
	txt = namedSlotRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := namedSlotRe.FindStringSubmatch(m)
		if sub[1] == "" {
			return "0(SP)"
		}
		return sub[1] + "(SP)"
	})
	return spOffRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := spOffRe.FindStringSubmatch(m)
		var n int
		if _, err := fmt.Sscanf(sub[2], "%d", &n); err != nil {
			return m
		}
		argBase := capturedFrame + 8 // +8: saved BP inside gc's frame
		if n >= argBase {
			fpOff := n - argBase
			for i, a := range args {
				if a.StackOf == fpOff {
					return fmt.Sprintf("%s%s+%d(FP)", sub[1], opts.argName(i), fpOff)
				}
			}
			// Result slot or padding.
			return fmt.Sprintf("%s%s+%d(FP)", sub[1], opts.resName(), fpOff)
		}
		return fmt.Sprintf("%s%d(SP)", sub[1], n+delta)
	})
}

// stripPrologueEpilogue removes the captured stacksplit block, the
// frame push/allocate at entry, and the frame release before every
// RET — the assembler regenerates all of them from the declared
// frame size with correct pcsp metadata.
func stripPrologueEpilogue(insns []Insn) ([]Insn, error) {
	drop := map[int]bool{}
	// Entry prologue: optional stack check jump-in, then
	// PUSHQ BP / MOVQ SP, BP / SUBQ $n, SP.
	i := 0
	// Leading stack-check, one of gc's three shapes by frame size:
	//   small:  CMPQ SP, 16(R14) / JLS k
	//   medium: LEAQ -n(SP), Rx / CMPQ Rx, 16(R14) / JLS k
	//   large:  MOVQ SP, R12 / SUBQ $n, R12 / JCS k (wraparound)
	//           / CMPQ R12, 16(R14) / JLS k
	splitJump := -1
	if i+2 < len(insns) && insns[i].Text == "MOVQ\tSP, R12" &&
		strings.HasPrefix(insns[i+1].Text, "SUBQ\t$") && strings.HasSuffix(insns[i+1].Text, ", R12") &&
		strings.HasPrefix(insns[i+2].Text, "JCS\t") {
		var t int
		if _, err := fmt.Sscanf(strings.TrimPrefix(insns[i+2].Text, "JCS\t"), "%d", &t); err == nil {
			splitJump = t
		}
		drop[i], drop[i+1], drop[i+2] = true, true, true
		i += 3
	}
	if i+1 < len(insns) && strings.HasPrefix(insns[i].Text, "LEAQ\t") && strings.Contains(insns[i+1].Text, "16(R14)") {
		drop[i], drop[i+1] = true, true
		i += 2
	} else if i < len(insns) && (strings.HasPrefix(insns[i].Text, "CMPQ\tSP, 16(R14)") ||
		strings.HasPrefix(insns[i].Text, "CMPQ\tR12, 16(R14)")) {
		drop[i] = true
		i++
	}
	if i < len(insns) && strings.HasPrefix(insns[i].Text, "JLS\t") {
		var t int
		if _, err := fmt.Sscanf(strings.TrimPrefix(insns[i].Text, "JLS\t"), "%d", &t); err == nil {
			if splitJump >= 0 && splitJump != t {
				return nil, fmt.Errorf("stack-check jumps disagree: %d vs %d", splitJump, t)
			}
			splitJump = t
		}
		drop[i] = true
		i++
	}
	if i < len(insns) && insns[i].Text == "PUSHQ\tBP" {
		drop[i] = true
		i++
		if i < len(insns) && insns[i].Text == "MOVQ\tSP, BP" {
			drop[i] = true
			i++
		}
		// Frame allocation: SUBQ $n, SP — or ADDQ $-n, SP when -n
		// fits in imm8 (gc's shorter encoding for 128-byte frames).
		if i < len(insns) && strings.HasSuffix(insns[i].Text, ", SP") &&
			(strings.HasPrefix(insns[i].Text, "SUBQ\t$") || strings.HasPrefix(insns[i].Text, "ADDQ\t$-")) {
			drop[i] = true
		}
	}
	// Epilogues: ADDQ $n, SP / POPQ BP (or MOVQ (SP),BP forms)
	// before RET, possibly interleaved with alignment NOPs (the NOPs
	// stay — only the frame release is regenerated).
	for k, in := range insns {
		if !strings.HasPrefix(in.Text, "RET") {
			continue
		}
		for back := k - 1; back >= 0 && back >= k-6; back-- {
			t := insns[back].Text
			if t == "NOP" {
				continue
			}
			if (strings.HasPrefix(t, "ADDQ\t$") || strings.HasPrefix(t, "SUBQ\t$-")) && strings.HasSuffix(t, ", SP") ||
				t == "POPQ\tBP" || t == "MOVQ\t(SP), BP" {
				drop[back] = true
				continue
			}
			break
		}
	}
	// The morestack tail: from the split target to end (spill / CALL
	// morestack / unspill / JMP 0).
	if splitJump >= 0 {
		on := false
		for k, in := range insns {
			if in.Off == splitJump {
				on = true
			}
			if on {
				drop[k] = true
			}
		}
	}
	var out []Insn
	for k, in := range insns {
		if drop[k] {
			continue
		}
		out = append(out, in)
	}
	return out, nil
}
