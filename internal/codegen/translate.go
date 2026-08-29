// Package codegen translates a parsed wasm Module into a single Go source
// file printed via go/format.
package codegen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/codegen/sharedimage"
	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/simdfuse"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/ssa/pass"
	"github.com/goccy/wasm2go/internal/wasm"
)

// defaultMultiPackageThreshold is the total wasm-function-body byte
// budget above which Translate switches from single-file to multi-
// package + linkname-split output. Modules below the threshold are
// emitted as a single Go file; modules at or above the threshold
// auto-derive the multi-package layout with chunks of the same size.
const defaultMultiPackageThreshold = 1 << 20 // 1 MiB

// multiPackageThresholdOverride lets callers override the auto-derived
// threshold above which Translate switches to the multi-package +
// linkname-split layout. -1 means "unset; fall back to the env var or
// the default". The defaults are auto-derived from wasm size and most
// callers should not touch this — but for diagnostics, build-time
// memory tuning, and exercising the multi-package path on small
// fixtures in tests, the override is a supported escape hatch.
//
// Modify via SetMultiPackageThreshold.
var multiPackageThresholdOverride = -1

// currentMultiPackageThreshold resolves the active byte budget: the
// in-process override when set, the production default otherwise.
func currentMultiPackageThreshold() int {
	if multiPackageThresholdOverride >= 0 {
		return multiPackageThresholdOverride
	}
	return defaultMultiPackageThreshold
}

// SetMultiPackageThreshold overrides the auto-multi-package decision
// threshold to b bytes for the rest of the current process. Pass 0 to
// always select the multi-package + linkname-split layout regardless
// of wasm size; pass -1 to restore the default (auto-derived from
// wasm size). The returned closure restores the previous value and
// should be invoked via defer:
//
//	defer codegen.SetMultiPackageThreshold(0)()
//
// The defaults are auto-derived and most callers should not touch
// this. The override is supported for diagnostics, build-time memory
// tuning, and exercising the multi-package path on small fixtures in
// tests.
func SetMultiPackageThreshold(b int) func() {
	prev := multiPackageThresholdOverride
	multiPackageThresholdOverride = b
	return func() { multiPackageThresholdOverride = prev }
}

// Options controls code generation.
//
// Several previously-public knobs (DataSidecar, MultiPackage,
// MultiPackageBaseImport, MultiPackageChunkBytes, LinknameSplit,
// NativeWASI, UseSSA, PerExportDispatch) are now auto-derived:
//
//   - SSA lowering, the data sidecar layout, and native wasip1 are
//     always on. They are the only supported configuration; if SSA
//     cannot lower a function, Translate fails with a clear error
//     identifying the function index and the offending opcode.
//   - Multi-package + linkname-split is selected automatically when
//     the sum of wasm function-body bytes exceeds the internal 1 MiB
//     threshold; below that threshold a single Go file is emitted.
//   - Per-export dispatch is auto-on whenever BulkExportPrefix is set
//     (no remaining caller wanted the consolidated InvokeExport
//     switch — that form is gone).
type Options struct {
	// Package is the Go package name to emit. Required.
	Package string
	// OutputImportPath is the Go import path the generated package
	// lives at — e.g. "example.com/myproj/internal/wasm". Required
	// for every Translate call. In single-file mode the path is the
	// package's own import path; in the auto-multi-package layout it
	// is used as the base import for the chained sub-packages
	// (<path>/base, <path>/p0, <path>/p1, ...).
	OutputImportPath string
	// BulkExportPrefix opts a subset of exports into a compact
	// dispatch shape. Exports whose names match `<prefix><svc>_<mt>`
	// (svc and mt decimal integers) are emitted as standalone
	// `Inv_<svc>_<mt>` functions so the Go linker can prune unused
	// ones. Exports that do not match the prefix get the usual
	// per-export method. An empty prefix disables bulk dispatch.
	BulkExportPrefix string
	// EntryExports narrows the export root set for whole-function
	// dead-code elimination.
	//
	//   - nil: every export is a DCE root.
	//   - empty slice (non-nil, length 0): no export is a root; only
	//     start + table-installed functions + reachable calls survive.
	//   - non-empty: only the named exports are roots (others may
	//     still survive via the table or transitive calls).
	EntryExports []string
	// KeepDeadFuncs disables whole-function dead-code elimination.
	// Useful for diffing / debugging.
	KeepDeadFuncs bool
	// PromotionReportPath, when non-empty, writes the SSA memory-
	// promotion report (JSON: per-function frame/rodata/slab
	// classification) to this path.
	PromotionReportPath string
	// PureOnly emits the pure-Go backend only: function bodies are
	// written without the `!amd64 && !arm64` build gate (so they compile
	// on every GOARCH) and the caller (transpile.Translate) skips the
	// gcasm asm bundle entirely. The result is ABIInternal everywhere —
	// slower to compile / heavier on tooling for large modules, but the
	// reference backend for benchmarking codegen quality without the
	// gcasm ABI0 marshalling.
	PureOnly bool

	// OutlineMinValues enables outlining of large loops into their own
	// functions and sets the minimum loop body size (in SSA values)
	// worth extracting. 0 disables outlining. Modules whose hot
	// functions exceed gc's pattern-matching appetite (kernel-library-sized)
	// want a low threshold like 100; small modules gain nothing.
	OutlineMinValues int
	// SIMDUnroll unrolls eligible SIMD loops by this factor before
	// scalarization, with exact trip routing. 0 disables.
	SIMDUnroll int
	// FuseLoops fuses whole countdown loops around fused SIMD regions
	// into single asm splices; FuseLoopUnroll adds an in-splice unroll
	// lane by that factor (0 = no in-splice unroll).
	FuseLoops      bool
	FuseLoopUnroll int
	// DisableF16Table opts out of the f16-table-keyed rewrites.
	// Tables are verified automatically — statically when the data
	// image holds the IEEE map, otherwise by detecting the module's
	// own initialization loop (full-range constant-strided store
	// coverage) — so there is no address to configure; this switch
	// exists only to disable the rewrites outright.
	DisableF16Table bool
	// FastMath opts asm splice synthesis out of wasm bit-exactness:
	// SDOT lane grouping without the TBL permutation, fused
	// multiply-adds, dual accumulators, and the SMMLA tile kernel for
	// paired q8_0 rows. The output no longer matches the wasm program
	// bit for bit (like a native build vs the wasm), so integrators
	// gate it and validate with token-level equivalence instead of
	// byte-equality probes.
	FastMath bool
	// VecDotPairEntry opts into vec_dot row/column pairing: it names
	// the per-type trait-table entry (the source runtime's type-enum
	// value) whose self-dot should run two rows and columns per call
	// (see the nrc2 recognizer's package comment for the verified
	// structural contract). Zero — the default — disables the scan
	// and leaves every module untouched.
	VecDotPairEntry int
	// VecDotRows additionally batches the verified vec_dot's caller
	// row loops: the translator emits a row-looped companion of the
	// verified function and rewrites matching driver loops into one
	// guarded companion call per chunk (the original loop stays as
	// the guard-miss branch, so semantics are preserved for every
	// runtime type). Requires VecDotPairEntry; off by default and
	// inert without it.
	VecDotRows bool
	// FuseDebug prints SIMD fusion diagnostics to stderr: failed
	// window-trial refusals and loop-upgrade rejections, tagged by
	// the refusing check. Diagnosis only; no effect on output.
	FuseDebug bool
	// DirectAsmFuncs names functions (post-rename FnN / fnN symbols,
	// or outlined-loop names like Fn1016l13807) whose finalized SSA
	// should be retained in Result.DirectAsmSSA for the asm bundle to
	// emit directly via internal/asmgen instead of transforming the
	// gc-captured listing. Retention is opt-in per function; a name
	// the direct emitter cannot handle later falls back to the normal
	// transform path, so listing a function here never breaks the
	// build. Empty disables retention entirely.
	DirectAsmFuncs []string
}

// DirectAsmFn is a function retained for direct-asm emission: its
// finalized SSA (post optimization fixpoint, idiom rewrites, and
// outlining) plus the wasm-typed signature the asm frame layout needs.
// Packed marks the outlined packed-boundary form: the Go-side
// signature carries only the module pointer (Sig is then
// results-only) and the parameter values ride the Module's
// outline-pack scratch, PackedParams giving their SSA types in slot
// order (v128 = two slots).
type DirectAsmFn struct {
	Fn           *ssa.Func
	Sig          wasm.FuncType
	Packed       bool
	PackedParams []ssa.Type
	// Windows lists the fused windows the emission-time fusion pass
	// claimed inside this function, so the asm bundle can emit the
	// shared fused splice bodies instead of per-op splices. Recorded
	// only when every member, root and parameter source is nameable
	// in the retained SSA (see addDirectAsmWindow).
	Windows []DirectAsmWindow
}

// Result returns auxiliary outputs from Translate beyond the main Go source.
type Result struct {
	// Sidecars maps base filenames (e.g. "data0.bin") to raw byte contents.
	// Populated when Options.DataSidecar is true.
	Sidecars map[string][]byte
	// Files maps relative output path → contents. Populated only when
	// Options.MultiPackage is true; otherwise nil. The caller writes each
	// entry to <outDir>/<key>.
	Files map[string][]byte
	// AuxFiles maps relative output path → raw Go source that must be
	// written alongside the main output but NOT routed through //go:embed
	// (unlike Sidecars). The WASI runtime uses this for the per-platform
	// wasip1_native_*.go companions whose //go:build tags are load-bearing.
	AuxFiles map[string][]byte
	// FusedLoops maps synthetic fused-LOOP helper names to their loop
	// descriptors.
	FusedLoops map[string]*simdfuse.Loop
	// FusedSimd maps synthetic fused-SIMD helper names to their region
	// descriptors, for the gcasm backend to synthesize inline bodies
	// from. Nil when the scalarizer fused nothing. See internal/simdfuse.
	FusedSimd map[string]*simdfuse.Tree
	// Outlined maps chunk dir ("" single-package) to the names of loop
	// functions extracted there (see internal/ssa/outline.go). The asm
	// bundle keeps their pure-Go bodies on every GOARCH.
	Outlined map[string][]string
	// Nrc2VecDot / Nrc2Companion name the paired vec_dot and its
	// paired-tile companion when the row/column pairing rewrite fired
	// (see nrc2.go); empty when off. The asm bundle may retarget the
	// fast-math feature body's companion call to a native tile kernel.
	Nrc2VecDot    string
	Nrc2Companion string
	// OutlinedSigs maps each extracted function name to its signature,
	// letting the asm bundle transform its body like a translated
	// function.
	OutlinedSigs map[string]OutlinedSig
	// DirectAsmSSA maps function names listed in Options.DirectAsmFuncs
	// to their retained finalized SSA, for the asm bundle to emit via
	// internal/asmgen. Names the translator never saw (or whose SSA is
	// ineligible for retention) are simply absent.
	DirectAsmSSA map[string]DirectAsmFn
	// DirectAsmGlobals is the byte offset of each wasm global within
	// the generated Module struct (-1 for imported globals), for
	// direct-asm bodies to inline global accesses. Nil unless
	// direct-asm retention is active. The generated bundle carries
	// compile-time assertions pinning these offsets.
	DirectAsmGlobals []int
	// DirectAsmExc is the byte offset of each exception-state field
	// within the generated Module struct, for direct-asm bodies to
	// inline OpExc* accesses. Nil unless direct-asm retention is
	// active and the module has exception state. Pinned by the same
	// generated compile-time assertions as DirectAsmGlobals.
	DirectAsmExc *DirectAsmExcLayout
}

// Translate parses helpers, walks the module, and emits Go source for
// module m. When the wasm module's function-body total fits in the
// internal single-file budget, source is written to w and Result.Files
// is nil. When the budget is exceeded, w is unused and
// Result.Files holds the multi-package chain (relative path → bytes)
// the caller must write to disk under the directory that maps to
// opts.OutputImportPath.
//
// Required options: opts.Package and opts.OutputImportPath. Any other
// configuration (SSA, sidecar layout, native wasip1, multi-package,
// linkname-split, per-export dispatch) is auto-derived.
//
// EntryExports narrows the whole-function DCE root set; see the
// Options.EntryExports doc comment for the empty-slice vs nil
// distinction.
func Translate(w io.Writer, m *wasm.Module, opts Options) (Result, error) {
	if opts.Package == "" {
		return Result{}, fmt.Errorf("wasm2go: Options.Package is required")
	}
	fuseDebugEnabled = opts.FuseDebug
	if m.Memory64() {
		for _, mem := range m.Memories {
			// A shared memory is allocated at its ceiling once (see the
			// New() emission): other agents deref its data pointer
			// concurrently, so the backing array must never move. On a
			// memory64 the fallback ceiling would be the mem64 hard cap —
			// absurd to reserve — so the declared maximum (which the
			// threads proposal requires anyway; the parser tolerates its
			// absence) becomes mandatory here.
			if mem.Limits.Shared && !mem.Limits.HasMax {
				return Result{}, fmt.Errorf("wasm2go: shared memory64 requires a declared maximum (it is reserved in full as the relocation-free growth ceiling)")
			}
		}
	}
	if opts.OutputImportPath == "" {
		return Result{}, fmt.Errorf("wasm2go: Options.OutputImportPath is required")
	}
	// Auto-derive the multi-package decision from the total wasm
	// function-body byte size. Anything strictly above the threshold
	// goes through the multi-package + linkname-split layout; anything
	// at or below the threshold is a single Go file. The boundary is
	// internal (no public knob) — callers control output shape only
	// through the import path and BulkExportPrefix.
	totalBodyBytes := 0
	for i := range m.Functions {
		totalBodyBytes += len(m.Functions[i].Body)
	}
	threshold := currentMultiPackageThreshold()
	autoMultiPackage := totalBodyBytes > threshold

	t := &translator{
		mod:          m,
		opts:         opts,
		fset:         token.NewFileSet(),
		imports:      map[string]string{},
		helpers:      map[string]bool{},
		sidecars:     map[string][]byte{},
		multiPackage: autoMultiPackage,
	}
	if len(opts.DirectAsmFuncs) > 0 {
		t.directAsmSet = make(map[string]bool, len(opts.DirectAsmFuncs))
		for _, name := range opts.DirectAsmFuncs {
			t.directAsmSet[name] = true
		}
		// Direct-asm bodies hardcode the Module.M field offset; the
		// bundle verifies it against this probe's captured assembly
		// before swapping any body in (SIMD modules emit the probe
		// anyway — this covers scalar-only modules). A module with no
		// memory has no M field to probe and no memory ops to verify.
		if len(m.Memories) > 0 {
			t.helpers["gcasmMemProbe"] = true
		}
	}
	// SSA pipeline is always on; an unsupported wasm feature is a hard
	// error from Translate (the legacy direct-opcode compiler is gone).
	t.memMetrics = ssa.NewMemMetrics()
	// In multi-package mode an external bridge that imports `base`
	// expects the trivial identity helpers (base.I32 / base.I64 /
	// base.F32 / base.F64) to exist so its `_ = base.I32` keep-alive
	// reference resolves. Single-package mode only emits helpers that
	// the bytecode actually triggers, so we don't need to force them
	// there.
	if autoMultiPackage {
		t.helpers["i32"] = true
		t.helpers["i64"] = true
		t.helpers["f32"] = true
		t.helpers["f64"] = true
	}

	// Asm always-on needs the wasm-trap panic helpers
	// available because the inline div/rem/trunc emit short-circuits to
	// them on the trap path. Without these, the asm fails to link
	// (·wasm_trap_div_zero(SB) etc. resolve to nothing) — or worse,
	// silently nil-derefs instead of panicking with the spec message.
	// Register them up front; emitHelpers filters out unused ones.
	t.helpers["wasm_trap_div_zero"] = true
	t.helpers["wasm_trap_int_overflow"] = true
	t.helpers["wasm_trap_invalid_conv"] = true
	// wasm_trap_unreachable is referenced by fn bodies emitted AFTER
	// emitHelpers runs (the pure fallback render), so lazy helperRef
	// registration is too late — pre-register like the others.
	t.helpers["wasm_trap_unreachable"] = true

	// accessMemory is the host-facing synchronised window into linear
	// memory (out-of-band writers like go-python's interrupter use it;
	// nothing in the generated code calls it). Pull it whenever the
	// module has a memory so the API is uniformly available.
	if len(m.Memories) > 0 {
		t.helpers["accessMemory"] = true
		// The Module struct's memMu field needs "sync" — register it
		// HERE, not only in emitModuleStruct: the multi-package path
		// snapshots base's import set after emitHelpers but BEFORE
		// emitModuleStruct runs, so a use() from inside the struct
		// emitter is too late for base/base.go.
		t.use("sync")
	}

	// Compute the call graph once and thread it through reachability
	// + multi-package planning. The bytecode scan is the same for all
	// three consumers; running it three times wastes a substantial
	// fraction of Translate's wall time on large modules.
	callees, err := buildCallGraph(m)
	if err != nil {
		return Result{}, fmt.Errorf("call graph: %w", err)
	}
	t.callees = callees

	// Widest exception-tag arity in the module: the operand-slot count the
	// Module's exception state needs. Zero when the module declares no
	// tags, which also switches the whole EH machinery off.
	t.excSlots = maxTagArity(m)
	if t.excSlots > 0 {
		// Which functions can leave an exception pending — the set the
		// lowering consults to decide where a post-call check is needed.
		abs := map[uint32][]uint32{}
		for i, cs := range callees {
			idx := m.NumImportedFuncs + uint32(i)
			out := make([]uint32, 0, len(cs))
			for _, c := range cs {
				out = append(out, m.NumImportedFuncs+c)
			}
			abs[idx] = out
		}
		ts, err := lower.ComputeThrowSet(m, abs)
		if err != nil {
			return Result{}, fmt.Errorf("throw analysis: %w", err)
		}
		t.throwSet = ts
	}

	// Whole-function dead-code elimination: compute which functions are
	// reachable from the module's entry points, so the dead ones (a
	// C++→wasm build leaves thousands) are never emitted.
	if !opts.KeepDeadFuncs {
		// EntryExports narrows the export root set for DCE. A nil
		// slice means "every export is a root"; an explicit empty
		// slice means "no export is a root" (only start + table +
		// transitively reachable calls).
		var entryExports map[string]bool
		if opts.EntryExports != nil {
			entryExports = map[string]bool{}
			for _, name := range opts.EntryExports {
				entryExports[name] = true
			}
		}
		reachable, err := computeReachableFuncs(m, entryExports, t.callees)
		if err != nil {
			return Result{}, fmt.Errorf("reachability analysis: %w", err)
		}
		t.reachable = reachable
		dropped := len(m.Functions) - len(reachable)
		if dropped > 0 {
			fmt.Fprintf(os.Stderr, "wasm2go: dead-function elimination — dropped %d of %d defined functions (%.1f%%)\n",
				dropped, len(m.Functions), 100*float64(dropped)/float64(len(m.Functions)))
		}
	}
	t.collectImportModules()
	if t.opts.VecDotPairEntry > 0 {
		t.scanVecDotPairing()
	}

	// BulkExportPrefix with zero matches is almost always a typo;
	// surface a warning so the caller can fix it instead of silently
	// getting back the per-export wrapper for every export.
	if opts.BulkExportPrefix != "" {
		any := false
		for _, exp := range m.Exports {
			if exp.Kind != wasm.ExportFunc {
				continue
			}
			if _, _, ok := parseBulkExportName(exp.Name, opts.BulkExportPrefix); ok {
				any = true
				break
			}
		}
		if !any {
			fmt.Fprintf(os.Stderr, "wasm2go: BulkExportPrefix %q matched zero exports\n", opts.BulkExportPrefix)
		}
	}

	if t.multiPackage {
		// Linkname-split is the only multi-package variant emitted in
		// auto-derived mode — it is what lets the partitioner bin-pack
		// on byte budget alone without paying for the call-graph DAG
		// constraint.
		return t.translateLinknameMulti()
	}

	out := &ast.File{Name: newID(opts.Package)}

	// Type & value decls.
	out.Decls = append(out.Decls, t.emitImportInterfaces()...)
	out.Decls = append(out.Decls, t.emitModuleStruct())
	// Native wasi impl (only when -native-wasi is set and the wasm
	// imports wasi_snapshot_preview1). DefaultWASI() must be declared
	// before emitNewFuncs so the simple-form New() wrapper can refer
	// to it.
	wasiDecls, wasiImports, err := t.emitWasip1Native()
	if err != nil {
		return Result{}, err
	}
	out.Decls = append(out.Decls, wasiDecls...)
	for _, p := range wasiImports {
		t.use(p)
	}
	out.Decls = append(out.Decls, t.emitNewFuncs()...)
	// Element-segment init helpers chunked out of New() to keep its SSA
	// bitmap below the Go compiler's NewBulk limit.
	out.Decls = append(out.Decls, t.elemInitChunks...)

	// Function bodies. Any per-function SSA failure is surfaced as a
	// hard error here — there is no legacy fallback. The error message
	// already carries the function index + failing opcode.
	bodyDecls, err := t.emitDefinedFunctions()
	if err != nil {
		return Result{}, err
	}
	out.Decls = append(out.Decls, bodyDecls...)

	// Package-level constant table for large memory offsets.
	// Single-package mode uses currentChunk == 0 (its zero value); the
	// table groups every large constant the body functions emitted.
	// See useLargeConst for why this routes through a runtime-loaded
	// slot instead of an inline literal.
	if decl := t.emitLargeConstsDecl(t.currentChunk); decl != nil {
		out.Decls = append(out.Decls, decl)
	}

	// Export wrappers.
	exportDecls, err := t.emitExportWrappers()
	if err != nil {
		return Result{}, err
	}
	out.Decls = append(out.Decls, exportDecls...)

	// Helpers (only those that were used).
	helpers, err := t.emitHelpers()
	if err != nil {
		return Result{}, err
	}
	out.Decls = append(out.Decls, helpers...)

	// Globals save/restore — see emitGlobalsSnapshot; NewFromSnapshot calls it.
	globalsSnap, err := t.emitGlobalsSnapshot()
	if err != nil {
		return Result{}, err
	}
	out.Decls = append(out.Decls, globalsSnap...)

	// //go:embed declarations for data sidecars (if any).
	out.Decls = append(out.Decls, t.emitSidecarDecls()...)

	// Final imports.
	if len(t.imports) > 0 {
		paths := make([]string, 0, len(t.imports))
		for p := range t.imports {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		gd := &ast.GenDecl{Tok: token.IMPORT}
		for _, p := range paths {
			spec := &ast.ImportSpec{
				Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(p)},
			}
			if alias := t.imports[p]; alias != "" {
				spec.Name = newID(alias)
			}
			gd.Specs = append(gd.Specs, spec)
		}
		out.Decls = append([]ast.Decl{gd}, out.Decls...)
	}

	// Render the Go source into a buffer first so the asm-bundle
	// post-process can split it into a shared file (written to w)
	// and a fallback `<pkg>_pure.go` file (in Result.Files, gated
	// !amd64 && !arm64).
	var goBuf bytes.Buffer
	if err := format.Node(&goBuf, t.fset, out); err != nil {
		return Result{}, err
	}
	t.reportMemMetrics()
	shared, err := t.emitSharedImage(opts.Package)
	if err != nil {
		return Result{}, err
	}
	for name, content := range shared {
		if t.auxFiles == nil {
			t.auxFiles = map[string][]byte{}
		}
		t.auxFiles[name] = content
	}
	res, err := finalizeSinglePkgWithAsm(m, opts, w, goBuf.Bytes(), t.sidecars, t.auxFiles)
	if err != nil {
		return res, err
	}
	t.appendSimdHelperFiles(res.Files)
	t.appendDirectAsmLayoutFile(res.Files)
	res.FusedSimd = t.FusedTrees()
	res.FusedLoops = t.FusedLoops()
	res.Outlined = t.outlinedByChunk
	res.OutlinedSigs = t.outlinedSigs
	res.DirectAsmSSA = t.directAsmSSA
	if len(t.directAsmSSA) > 0 {
		res.DirectAsmGlobals = t.moduleGlobalOffsets()
		res.DirectAsmExc = t.moduleExcOffsets()
	}
	if t.nrc2 != nil {
		res.Nrc2VecDot = t.funcName(t.nrc2.funcIdx)
		res.Nrc2Companion = t.nrc2CompanionName()
	}
	if err := t.checkStaleF16Table(); err != nil {
		return Result{}, err
	}
	return res, nil
}

// maxTagArity returns the largest operand count over every tag the module
// declares or imports, or 0 when it has none.
func maxTagArity(m *wasm.Module) int {
	n := 0
	consider := func(typeIdx uint32) {
		if int(typeIdx) >= len(m.Types) {
			return
		}
		if c := len(m.Types[typeIdx].Params); c > n {
			n = c
		}
	}
	for _, imp := range m.Imports {
		if imp.Kind == wasm.ImportTag {
			consider(imp.Tag.TypeIdx)
		}
	}
	for _, tg := range m.Tags {
		consider(tg.TypeIdx)
	}
	// A module can declare a tag with no operands (`(tag)`), which still
	// needs the flag and tag fields — give it a single unused slot rather
	// than special-casing an empty array type.
	if n == 0 && (m.NumImportedTags > 0 || len(m.Tags) > 0) {
		n = 1
	}
	return n
}

// emitGlobalsSnapshot emits SaveGlobals/RestoreGlobals over the module's
// MUTABLE globals. They belong to the package that holds the Module struct,
// because they are the only code that can see the gN fields.
//
// Globals live outside linear memory, so an image of an initialized instance's
// memory is not by itself enough to reconstruct that instance: the guest's TLS
// base and stack pointer are globals, and a Module built fresh would have them
// at their declared init values (typically zero) with the memory saying
// otherwise. These two carry them across. Immutable globals are skipped — they
// cannot have moved, and the fresh Module already has them right.
func (t *translator) emitGlobalsSnapshot() ([]ast.Decl, error) {
	if len(t.mod.Memories) == 0 {
		return nil, nil // no memory, no image, nobody to snapshot for
	}
	type gl struct {
		field string
		typ   wasm.ValType
	}
	var gs []gl
	for i, g := range t.mod.Globals {
		if !g.Type.Mutable {
			continue
		}
		gs = append(gs, gl{
			field: t.fieldName(fmt.Sprintf("g%d", int(t.mod.NumImportedGlobals)+i)),
			typ:   g.Type.Type,
		})
	}

	save := &strings.Builder{}
	restore := &strings.Builder{}
	needMath := false
	for i, g := range gs {
		switch g.typ {
		case wasm.ValI32:
			fmt.Fprintf(save, "\tg[%d] = uint64(uint32(m.%s))\n", i, g.field)
			fmt.Fprintf(restore, "\tm.%s = int32(uint32(g[%d]))\n", g.field, i)
		case wasm.ValI64:
			fmt.Fprintf(save, "\tg[%d] = uint64(m.%s)\n", i, g.field)
			fmt.Fprintf(restore, "\tm.%s = int64(g[%d])\n", g.field, i)
		case wasm.ValF32:
			needMath = true
			fmt.Fprintf(save, "\tg[%d] = uint64(math.Float32bits(m.%s))\n", i, g.field)
			fmt.Fprintf(restore, "\tm.%s = math.Float32frombits(uint32(g[%d]))\n", g.field, i)
		case wasm.ValF64:
			needMath = true
			fmt.Fprintf(save, "\tg[%d] = math.Float64bits(m.%s)\n", i, g.field)
			fmt.Fprintf(restore, "\tm.%s = math.Float64frombits(g[%d])\n", g.field, i)
		default:
			// A reference-typed global cannot be snapshotted as a scalar; it
			// also cannot survive a process boundary. Leave it to the fresh
			// Module's own initializer.
			fmt.Fprintf(save, "\t// g%d: reference type, not snapshottable\n", i)
		}
	}
	if needMath {
		t.use("math")
	}

	saveName, restoreName := "saveGlobals", "restoreGlobals"
	if t.multiPackage {
		saveName, restoreName = "SaveGlobals", "RestoreGlobals"
	}
	src := fmt.Sprintf(`package p

%s

// %s returns the module's mutable globals, in a form that can be handed back
// to %s. It is how a snapshot of an instance captures the state that does not
// live in linear memory.
func %s(m *Module) []uint64 {
	g := make([]uint64, %d)
%s	return g
}

// %s puts a snapshot's globals back. A snapshot from a different module (or a
// different build of the same one) has a different global count; rather than
// index out of bounds, take what fits and leave the rest at their declared
// initializers.
func %s(m *Module, g []uint64) {
	if len(g) != %d {
		return
	}
%s}
`,
		mathImport(needMath),
		saveName, restoreName, saveName, len(gs), save.String(),
		restoreName, restoreName, len(gs), restore.String())

	f, err := parser.ParseFile(t.fset, "globals_snapshot.go", src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("wasm2go: emitting the globals snapshot: %w", err)
	}
	var decls []ast.Decl
	for _, d := range f.Decls {
		if _, ok := d.(*ast.FuncDecl); ok {
			decls = append(decls, d)
		}
	}
	return decls, nil
}

// mathImport is the import block emitGlobalsSnapshot's synthetic file needs to
// parse; the decls are then lifted out and the import is registered on the real
// file through t.use.
func mathImport(need bool) string {
	if need {
		return `import "math"`
	}
	return ""
}

// emitSharedImage renders the copy-on-write shared-memory-image runtime into
// the package that holds the Module struct. It reads three of that struct's
// fields, and their names differ between single- and multi-package output
// (multi-package exports them), so the source is a template rather than a
// fixed file. A module with no linear memory has nothing to share.
func (t *translator) emitSharedImage(pkg string) (map[string][]byte, error) {
	if len(t.mod.Memories) == 0 {
		return nil, nil
	}
	saveGlobals := "saveGlobals"
	if t.multiPackage {
		saveGlobals = "SaveGlobals"
	}
	return sharedimage.Files(sharedimage.Names{
		Pkg:         pkg,
		Module:      "Module",
		Memory:      t.fieldName("memory"),
		MemSize:     t.fieldName("memSize"),
		DataEnd:     t.fieldName("dataEnd"),
		SaveGlobals: saveGlobals,
	})
}

// finalizeSinglePkgWithAsm is the asm-always-on tail of single-package
// Translate. It splits the Go source produced by the translator into
// a shared file (Module struct, helpers, exports, ...) — written to
// the caller's w — and a `<pkg>_pure.go` file holding the function
// bodies under `//go:build !amd64 && !arm64`. The asm bundle goes
// into Result.Files. On asm-target GOARCHs the pure file is dormant
// and the asm bodies in `<pkg>/amd64.s` (and arm64.s) take over.
func finalizeSinglePkgWithAsm(m *wasm.Module, opts Options, w io.Writer, goSrc []byte, sidecars map[string][]byte, auxFiles map[string][]byte) (Result, error) {
	shared, fallback, err := splitForAsm(goSrc, opts.Package, pureFallbackTag(opts))
	if err != nil {
		return Result{}, fmt.Errorf("asm-bundle split: %w", err)
	}
	if _, err := w.Write(shared); err != nil {
		return Result{}, err
	}
	// The gcasm backend (transpile.Translate) captures these pure bodies
	// and emits the per-arch asm that replaces them; codegen produces the
	// shared file (to w) and the `<pkg>_pure.go` fallback only.
	files := map[string][]byte{
		opts.Package + "_pure.go": fallback,
	}
	return Result{
		Files:    files,
		Sidecars: sidecars,
		AuxFiles: auxFiles,
	}, nil
}

// pureFallbackTag returns the `//go:build` directive for the pure
// function-body files: the asm-dormancy gate normally, empty (compile
// everywhere) in PureOnly mode where no asm bundle will exist.
func pureFallbackTag(opts Options) string {
	if opts.PureOnly {
		return ""
	}
	// The asm bundle covers arm64 and amd64/v2 (its SIMD splices are
	// SSE4.1); every other target — including GOAMD64=v1 — runs pure.
	return "//go:build !arm64 && (!amd64 || !amd64.v2)"
}

// emitSidecarDecls returns //go:embed var decls for each registered sidecar.
func (t *translator) emitSidecarDecls() []ast.Decl {
	if len(t.sidecars) == 0 {
		return nil
	}
	t.imports["embed"] = "_"
	names := make([]string, 0, len(t.sidecars))
	for n := range t.sidecars {
		names = append(names, n)
	}
	sort.Strings(names)
	var decls []ast.Decl
	for _, name := range names {
		varName := "wasm2goData_" + sanitizeFilename(name)
		spec := &ast.ValueSpec{
			Names: []*ast.Ident{newID(varName)},
			Type:  &ast.ArrayType{Elt: newID("byte")},
		}
		gd := &ast.GenDecl{
			Tok:   token.VAR,
			Specs: []ast.Spec{spec},
			Doc: &ast.CommentGroup{List: []*ast.Comment{
				{Text: "//go:embed " + name},
			}},
		}
		decls = append(decls, gd)
	}
	return decls
}

func sanitizeFilename(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			out[i] = '_'
		}
	}
	return string(out)
}

// Sentinel values for translator.currentChunk in multi-package mode. Numbered
// chunk files use their index (0..N-1); these two negative sentinels name the
// packages that are not numbered chunks. In single-package mode currentChunk is
// unused and stays at its zero value.
const (
	// chunkMain is the root package — the module's top-level .go file that
	// callers import (the one carrying the public API and Module type).
	chunkMain = -1
	// chunkBase is the shared base package that holds the common runtime types
	// (base.Module, base.WasmExc, the import interfaces) the numbered chunks and
	// main all reference.
	chunkBase = -2
)

// translator carries codegen state for one module.
type translator struct {
	mod  *wasm.Module
	opts Options
	fset *token.FileSet

	// f16TablesOK caches per-base verification of module-resident
	// f16->f32 tables (see hasIEEEF16TableAt / the gather rewrite).
	f16TablesOK map[uint32]bool
	// runtimeTables holds the store intervals of detected init loops
	// (nil until the first f16TableOK query triggers the scan); a
	// gather base covered by one verifies without any assertion.
	runtimeTables []initStoreRegion
	// f16Announced dedups the auto-detection log line per base.
	f16Announced map[uint32]bool

	// pendingOutlined holds loops extracted from the function being
	// compiled, emitted as sibling decls in the same chunk.
	pendingOutlined []ssa.OutlinedFunc
	// outlinedByChunk records extracted-function names per chunk dir
	// ("" single-package) so the asm bundle can register them as
	// pure-Go fallbacks on the asm GOARCHs.
	outlinedByChunk map[string][]string
	// curOutlineFunc is the wasm index of the function currently in
	// compileBodyViaSSA (chunk lookup for the extraction bookkeeping).
	curOutlineFunc uint32
	// outlinedSigs collects extraction signatures for Result.OutlinedSigs.
	outlinedSigs map[string]OutlinedSig
	// directAsmSet is the Options.DirectAsmFuncs opt-in as a set;
	// directAsmSSA collects the retained SSA for Result.DirectAsmSSA.
	directAsmSet map[string]bool
	directAsmSSA map[string]DirectAsmFn

	// multiPackage records the auto-derived decision to emit the
	// chunked, linkname-split layout. Set in Translate based on the
	// total wasm function-body byte size; chunk packages, helper
	// methods, base/main split and forward declarations all branch on
	// this flag (previously opts.MultiPackage).
	multiPackage bool

	// callees caches the direct-call adjacency produced by
	// buildCallGraph. Computed once per Translate call so the multi-
	// package planner and the reachability analysis don't each pay
	// the bytecode-scan cost.
	callees [][]uint32

	// importedModules: distinct wasm import-module names in a fixed, prescribed
	// order (knownImportModuleOrder; see collectImportModules). The constructor
	// parameter order and the Module struct's import-field layout derive from
	// this, so it must not depend on the wasm's import-declaration order.
	importedModules []string

	// imports: stdlib import paths used by generated code, mapped to alias
	// (empty alias = none). Add via use().
	imports map[string]string
	// helpers: helper names that have been requested. Filled by codegen during
	// function-body emission and resolved at the end.
	helpers map[string]bool

	// usesWasmExc is set when the module emits a wasm `throw` (panic with a
	// wasmExc) or a try/catch: the wasmExc type declaration must then be
	// pulled into the output even if no func helper is used.
	usesWasmExc bool
	// usesSimd is set when any simd_* helper is referenced; it pulls the
	// whole-file SIMD helper set (simd_scalar.go + per-arch asm) into the
	// output tree. See appendSimdHelperFiles.
	usesSimd bool
	// fusedShapes interns the fused SIMD regions the scalarizer
	// creates; see simd_fuse.go and internal/simdfuse.
	fusedShapes *fusedShapeState
	fusedLoops  *fusedLoopState
	// segPlacements caches passiveSegmentPlacements' result (nil until
	// first use; empty map = scanned, nothing found).
	segPlacements map[int]int64
	// excSlots is the operand-slot count the module's exception state
	// needs: the widest tag arity, or 0 when the module has no EH (the
	// state fields are then omitted entirely). See emitModuleStruct.
	excSlots int
	// throwSet answers "can a call to this function leave an exception
	// pending?" for the EH lowering. Nil when the module has no tags.
	throwSet *lower.ThrowSet

	// helpersFile is parsed lazily by emitHelpers.
	helpersFile *ast.File

	// passiveLocs maps original data-segment index → its span in the data.bin
	// blob, for passive segments only (dataSegs views are sliced from these).
	passiveLocs map[int]blobSpan

	// sidecars maps sidecar filename → bytes (populated when DataSidecar is true).
	sidecars map[string][]byte

	// auxFiles maps additional Go source filename → bytes that must be
	// written alongside the main output without going through //go:embed.
	// Populated for example by the WASI runtime to drop per-platform
	// build-tagged companions next to the generated package.
	auxFiles map[string][]byte

	// elemInitChunks holds the helper FuncDecls that emitNewFunc factors out
	// of the element-segment population loop. They get appended at top level
	// alongside the rest of the function decls.
	elemInitChunks []ast.Decl

	// Multi-package state. plan != nil iff opts.MultiPackage is true.
	// currentChunk is the chunk being emitted: chunkMain, chunkBase, or a
	// numbered chunk index (0..N-1).
	plan         *MultiPackagePlan
	currentChunk int

	// linknameForwards records, per caller chunk, every funcIdx the caller
	// references that is owned by a different chunk. The forward-decl
	// emitter consumes this map to produce //go:linkname directives and
	// header-only func decls at the top of each chunk file. Populated by
	// funcRef() during body emission; only used when opts.LinknameSplit
	// is true. Key: caller chunk index (-1 = main); inner key: funcIdx;
	// value: target chunk index.
	linknameForwards map[int]map[uint32]int

	// chunkExtraDecls carries decls that need to live in a specific chunk's
	// file even though they're produced by main-package emission (e.g.
	// InvokeExportShard_K, InitElemSeg_K_*). Used only in linkname-split
	// mode. Key: target chunk index.
	chunkExtraDecls map[int][]ast.Decl

	// linknameSymbolForwards records, per caller chunk, a set of arbitrary
	// (localName -> targetChunk) entries for symbols that aren't a
	// funcIdx-keyed function (e.g. InvokeExportShard_K). Drives a separate
	// emission path because the target name is fixed by us, not derived
	// from a wasm function index. Local + target name are identical; only
	// the target chunk differs.
	linknameSymbolForwards map[int]map[string]linknameSymbol

	// largeConsts records, per emitted file, the unique large memory-
	// offset constants used in load/store instructions. Storing them in
	// a package-level `var _consts = [...]uintptr{...}` table moves the
	// values out of the per-function literal pool (which the ARM64
	// assembler can fail to reach inside very large transpiled
	// functions). Each access then becomes
	// `unsafe.Add(m.M, _consts[<idx>])` — the table lookup is a global
	// memory load that the Go compiler cannot fold back into the LDR's
	// immediate, forcing register-offset addressing with effectively
	// unlimited range.
	//
	// Key: file index. -1 == single-package main file; -2 == base file;
	// 0..N-1 == chunk indices in the linkname-split layout. Each map
	// runs <const value> -> <slot index in the table>.
	largeConsts map[int]map[uint64]int

	// memMetrics accumulates the memory-promotion observability
	// data: every SSA-lowered function's load/store classification is
	// folded in here, then reported once codegen finishes.
	memMetrics *ssa.MemMetrics

	// reachable is the whole-function dead-code-elimination result:
	// keyed by LOCAL (defined-relative) function index, true iff that
	// function is reachable from an entry point. nil ⇒ keep every
	// function (KeepDeadFuncs, or no module parsed yet).
	reachable map[uint32]bool

	// nrc2 is the verified vec_dot traits entry when the row/column
	// pairing rewrite is active (see nrc2.go); nil ⇒ feature off.
	nrc2 *nrc2Info
}

// funcReachable reports whether the function at the given global index
// should be emitted. Imported functions and the "keep all" case
// (reachable == nil) always return true.
func (t *translator) funcReachable(funcIdx uint32) bool {
	if t.reachable == nil {
		return true
	}
	if funcIdx < t.mod.NumImportedFuncs {
		return true
	}
	return t.reachable[funcIdx-t.mod.NumImportedFuncs]
}

// linknameSymbol describes a named symbol forwarded via //go:linkname (one
// that's not a plain wasm function — e.g. an InvokeExportShard or
// InitElemSeg helper). The localName matches the target name; the signature
// is captured up-front so the forward-decl emitter doesn't have to reach
// back into module state.
type linknameSymbol struct {
	targetChunk int
	signature   *ast.FuncType
}

// fieldName returns the Module struct field name. Single-package mode keeps
// names lowercase (package-private). Multi-package mode capitalizes them so
// chunk packages and main can reference fields on `*base.Module`.
func (t *translator) fieldName(s string) string {
	if t.multiPackage {
		return capitalize(s)
	}
	return s
}

// fieldRef returns `m.<field>`.
func (t *translator) fieldRef(field string) ast.Expr {
	return &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName(field))}
}

// moduleType returns the AST expression for `*Module`.
func (t *translator) moduleType() ast.Expr {
	if t.multiPackage && t.currentChunk != chunkBase {
		// Chunks and the main package both reference base.Module.
		// currentChunk == chunkBase is reserved for the base package itself.
		return &ast.StarExpr{X: &ast.SelectorExpr{X: newID("base"), Sel: newID("Module")}}
	}
	return &ast.StarExpr{X: newID("Module")}
}

// moduleTypeName returns the AST node for the bare Module type (no `*`),
// suitable for composite literals like `&Module{...}`.
func (t *translator) moduleTypeName() ast.Expr {
	if t.multiPackage && t.currentChunk != chunkBase {
		return &ast.SelectorExpr{X: newID("base"), Sel: newID("Module")}
	}
	return newID("Module")
}

// importIfaceTypeRef returns the AST type reference for an import-module
// interface (e.g. `EnvImports` in single-pkg, `base.EnvImports` in
// multi-pkg outside base).
func (t *translator) importIfaceTypeRef(mod string) ast.Expr {
	name := t.importIfaceName(mod)
	if t.multiPackage && t.currentChunk != chunkBase {
		return &ast.SelectorExpr{X: newID("base"), Sel: newID(name)}
	}
	return newID(name)
}

// funcName returns the bare function name for a wasm function index. In
// multi-package mode the name is exported (capitalized) so it crosses
// package boundaries; in single-package mode it stays lowercase.
func (t *translator) funcName(funcIdx uint32) string {
	if t.multiPackage {
		return fmt.Sprintf("Fn%d", funcIdx)
	}
	return fmt.Sprintf("fn%d", funcIdx)
}

// importMethodName returns the method name for a wasm import. Always
// capitalized so the interface remains satisfiable from outside the
// generated package (callers in another package implementing the host
// imports). C++ mangled names starting with `_` (e.g. `_ZN4absl...`) get
// an `X` prefix added by capitalize().
func (t *translator) importMethodName(imp wasm.Import) string {
	name := capitalize(MangleID(imp.Name))
	// A memory64 module speaks the widened wasip1 ABI (every import
	// argument is pointer-width i64), so its imports bind to the *64
	// variants in the wasip1 shim — the 32-bit methods keep their
	// signatures for every existing wasm32 module.
	if imp.Module == "wasi_snapshot_preview1" && t.mod.Memory64() {
		name += "64"
	}
	return name
}

// importIfaceName returns the Go type name for the interface that represents
// an imported wasm module (one per distinct import-module name). Capitalized
// for the same reason as importMethodName.
func (t *translator) importIfaceName(modName string) string {
	return capitalize(MangleModuleType(modName))
}

// capitalize ensures the identifier is exported (starts with [A-Z]). For
// names starting with [a-z], the first letter is uppercased. For names
// starting with `_` or a digit (e.g. C++ mangled `_ZN4absl...`), prepend
// `X` so the result is a legal Go exported identifier.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
		return string(r)
	}
	if r[0] >= 'A' && r[0] <= 'Z' {
		return s
	}
	return "X" + s
}

// wasmExcTypeExpr returns the type-name expression for the wasmExc exception
// struct. Single-package output keeps it unexported (`wasmExc`). Multi-package
// output puts the type in `base` and exports it as `WasmExc`, so non-base chunks
// reference `base.WasmExc` and base itself (currentChunk == chunkBase) uses the bare
// exported name. Keep in sync with the type-decl capitalization in emitHelpers
// and the helper-body rewrite (both switch to WasmExc when multiPackage).
func (t *translator) wasmExcTypeExpr() ast.Expr {
	if t.multiPackage {
		if t.currentChunk == chunkBase {
			return newID("WasmExc")
		}
		return &ast.SelectorExpr{X: newID("base"), Sel: newID("WasmExc")}
	}
	return newID("wasmExc")
}

// threadPoolTypeExpr names the wasi-threads pool type, mirroring
// wasmExcTypeExpr: exported and homed in `base` under multi-package output.
func (t *translator) threadPoolTypeExpr() ast.Expr {
	if t.multiPackage {
		if t.currentChunk == chunkBase {
			return newID("ThreadPool")
		}
		return &ast.SelectorExpr{X: newID("base"), Sel: newID("ThreadPool")}
	}
	return newID("threadPool")
}

// helperRef returns the AST expression that names a helper function. In
// multi-package mode helpers live in `base` so non-base callers prefix:
// `base.Subg`. In base itself (currentChunk == chunkBase) and in single-package
// mode, the bare uppercase name is used.
func (t *translator) helperRef(name string) ast.Expr {
	if t.multiPackage {
		up := capitalize(name)
		if t.currentChunk == chunkBase {
			return newID(up)
		}
		return &ast.SelectorExpr{X: newID("base"), Sel: newID(up)}
	}
	return newID(name)
}

// funcRef returns the AST expression that names a defined-function call
// target, qualified by chunk package if needed. In LinknameSplit mode,
// cross-chunk calls are emitted as bare names — the chunk-file assembler
// later adds //go:linkname forward declarations registered by this call.
func (t *translator) funcRef(funcIdx uint32) ast.Expr {
	if !t.multiPackage || t.plan == nil {
		return newID(t.funcName(funcIdx))
	}
	targetChunk, ok := t.plan.FuncToChunk[funcIdx]
	if !ok {
		// Imported function or unknown — bare name (will fail later if real
		// problem, but most likely a cross-cutting helper.)
		return newID(t.funcName(funcIdx))
	}
	if targetChunk == t.currentChunk {
		return newID(t.funcName(funcIdx))
	}
	// Multi-package mode is always linkname-split in the new layout —
	// register the forward declaration and emit a bare call so the
	// chunk-file assembler can attach the //go:linkname directive.
	t.registerLinknameForward(t.currentChunk, funcIdx, targetChunk)
	return newID(t.funcName(funcIdx))
}

// registerLinknameForward records that callerChunk needs a //go:linkname
// forward declaration for funcIdx (owned by targetChunk). Caller chunk
// indices: 0..N for chunks, chunkMain for main, chunkBase for base (base never
// references chunk functions directly so calls with callerChunk==chunkBase are
// an error path
// surfaced at emit time).
func (t *translator) registerLinknameForward(callerChunk int, funcIdx uint32, targetChunk int) {
	if t.linknameForwards == nil {
		t.linknameForwards = map[int]map[uint32]int{}
	}
	if t.linknameForwards[callerChunk] == nil {
		t.linknameForwards[callerChunk] = map[uint32]int{}
	}
	t.linknameForwards[callerChunk][funcIdx] = targetChunk
}

// largeConstThreshold is the smallest absolute offset that gets routed
// through the package-level _consts table instead of being emitted
// as an inline literal. Below the threshold, ARM64 LDR's 12-bit
// scaled immediate (up to 16 KiB for 4-byte loads, smaller for LDP
// pair loads) covers the value cleanly; the compiler folds the
// literal into the instruction with no detour through the literal
// pool. Above the threshold, the assembler would try to place the
// constant in a PC-relative literal pool — which, inside very large
// transpiled functions, can become unreachable. Routing through the
// table forces a register-offset access that has no immediate
// dependency on the constant magnitude.
//
// 4096 is the LDR-scaled cap for 4-byte loads; we keep the same cap
// for pair / wider loads even though their immediates are smaller,
// trading a few extra table entries for a single uniform threshold.
const largeConstThreshold uint64 = 4096

// useLargeConst registers a constant memory offset for the current
// file's _consts table and returns the table index. Same value used
// twice returns the same index so the table stays compact. The
// "file" the constant is scoped to is identified by t.currentChunk:
// chunk index ≥ 0 in the linkname-split layout, -1 == main, -2 ==
// base. Single-package mode never sets currentChunk so it stays at
// the zero value, which is also fine — only one file emits.
func (t *translator) useLargeConst(value uint64) int {
	if t.largeConsts == nil {
		t.largeConsts = map[int]map[uint64]int{}
	}
	file := t.currentChunk
	tbl := t.largeConsts[file]
	if tbl == nil {
		tbl = map[uint64]int{}
		t.largeConsts[file] = tbl
	}
	if idx, ok := tbl[value]; ok {
		return idx
	}
	idx := len(tbl)
	tbl[value] = idx
	return idx
}

// emitLargeConstsDecl returns the `var _consts = [N]uintptr{...}`
// declaration for the given file, or nil when the file has no
// large constants. Values are emitted in ascending slot order so
// the generated file is diff-stable.
func (t *translator) emitLargeConstsDecl(file int) ast.Decl {
	tbl := t.largeConsts[file]
	if len(tbl) == 0 {
		return nil
	}
	sorted := make([]uint64, len(tbl))
	for v, i := range tbl {
		sorted[i] = v
	}
	values := make([]ast.Expr, len(sorted))
	for i, v := range sorted {
		values[i] = uintLit(v)
	}
	arrType := &ast.ArrayType{
		Len: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(len(sorted))},
		Elt: newID("uintptr"),
	}
	return &ast.GenDecl{
		Tok: token.VAR,
		Specs: []ast.Spec{&ast.ValueSpec{
			Names:  []*ast.Ident{newID("_consts")},
			Values: []ast.Expr{&ast.CompositeLit{Type: arrType, Elts: values}},
		}},
	}
}

// Two kinds of cross-chunk forward live behind these helpers:
//
//   - wasm-function-index forwards (registered via
//     registerLinknameForward during funcRef calls). Local + target
//     name are both Fn<idx>. Emitted by emitWasmFnForwards in either
//     the bare-alias or the wrapper-pair shape (see linknameForwardKind).
//   - named-symbol forwards (registered via registerLinknameSymbol for
//     things like InvokeExportShard_K and InitElemSeg_K_n that aren't a
//     plain wasm function). Local + target name are identical;
//     signature was captured at registration time. Always bare alias —
//     no asm callers, no ABI0 wrapper requirement.
//
// The order is deterministic (ascending funcIdx, then alphabetical
// symbol name) so generated output is diff-stable across runs.
//
// linknameForwardKind selects the source shape emitWasmFnForwards
// produces for each wasm-function forward.
type linknameForwardKind int

const (
	// linknameForwardBare emits a single bare //go:linkname alias
	// with no body. The Go compiler then aliases <local>.FnN
	// directly to the cross-chunk target at link time, with no
	// trampoline frame and no auto-generated ABI0 wrapper.
	// Sufficient when every caller of <local>.FnN is itself Go (the
	// main wasm2go.go file, or the pure-Go fallback bodies in
	// pN_pure.go).
	linknameForwardBare linknameForwardKind = iota
	// linknameForwardWrapperPair emits `_x<fnName>` (linkname-only
	// decl) + `<fnName>` (Go body that tail-calls _x<fnName>).
	// The Go body forces the Go compiler to emit a local ABI0
	// wrapper at <local>.<fnName>.abi0, which the chunk's amd64.s
	// / arm64.s body needs because `CALL ·<fnName>(SB)` resolves
	// into the ABI0 slot. Bare //go:linkname does NOT generate
	// that wrapper (verified on go 1.26.2: every per-chunk asm
	// caller fails to link with `relocation target <pX>.<fnName>
	// not defined` when the wrapper body is absent), so wrapper
	// pairs are required whenever the chunk's asm bundle CALLs
	// the local symbol.
	linknameForwardWrapperPair
	// linknameForwardDeclOnly emits a bare Go function declaration
	// (`func <fnName>(...) ...`) with NO //go:linkname directive
	// and NO body. The chunk's <arch>.s file is expected to provide
	// the body — the gcasm backend emits the per-arch asm that
	// provides that local symbol (transpile.Translate runs gcasm over
	// the pure bodies). Used when the host import path is plan-9-asm-
	// safe: there is no //go:linkname for the Go linker to fuse
	// with the asm-side cross-package CALL — which would otherwise
	// trip the nosplit wrapper cycle observed empirically with
	// linkname + asm-body + function-value-reference + cross-pkg
	// asm CALL all in play — and Go callers route through the
	// auto-generated ABIInternal wrapper that calls the asm TEXT.
	linknameForwardDeclOnly
)

// emitWasmFnForwards returns the //go:linkname forward declarations
// for the cross-chunk wasm functions registered against callerChunk
// during translation. kind picks between the bare-alias and the
// wrapper-pair source shapes (see linknameForwardKind). Returns nil
// when no forwards are registered for the caller.
func (t *translator) emitWasmFnForwards(callerChunk int, kind linknameForwardKind) []ast.Decl {
	forwards := t.linknameForwards[callerChunk]
	if len(forwards) == 0 {
		return nil
	}
	prevChunk := t.currentChunk
	t.currentChunk = callerChunk
	defer func() { t.currentChunk = prevChunk }()

	var decls []ast.Decl
	keys := make([]uint32, 0, len(forwards))
	for k := range forwards {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, funcIdx := range keys {
		targetChunk := forwards[funcIdx]
		fnName := t.funcName(funcIdx)
		linknameTarget := fmt.Sprintf("%s/p%d.%s", t.opts.OutputImportPath, targetChunk, fnName)
		ft := t.mod.FuncTypeOf(funcIdx)

		if kind == linknameForwardBare {
			decls = append(decls, &ast.FuncDecl{
				Doc: &ast.CommentGroup{List: []*ast.Comment{
					{Text: fmt.Sprintf("//go:linkname %s %s", fnName, linknameTarget)},
				}},
				Name: newID(fnName),
				Type: t.funcSignature(ft, true /*withModuleParam*/),
			})
			continue
		}

		if kind == linknameForwardDeclOnly {
			decls = append(decls, &ast.FuncDecl{
				Name: newID(fnName),
				Type: t.funcSignature(ft, true /*withModuleParam*/),
			})
			continue
		}

		hiddenName := "_x" + fnName
		decls = append(decls, &ast.FuncDecl{
			Doc: &ast.CommentGroup{List: []*ast.Comment{
				{Text: fmt.Sprintf("//go:linkname %s %s", hiddenName, linknameTarget)},
			}},
			Name: newID(hiddenName),
			Type: t.funcSignature(ft, true /*withModuleParam*/),
		})
		// Build the trampoline body. Parameter names are m, l0, l1, ...
		params := []*ast.Ident{newID("m")}
		for i := range ft.Params {
			params = append(params, newID(fmt.Sprintf("l%d", i)))
		}
		callArgs := make([]ast.Expr, len(params))
		for i, p := range params {
			callArgs[i] = p
		}
		var bodyStmt ast.Stmt
		if len(ft.Results) > 0 {
			bodyStmt = &ast.ReturnStmt{Results: []ast.Expr{
				&ast.CallExpr{Fun: newID(hiddenName), Args: callArgs},
			}}
		} else {
			bodyStmt = &ast.ExprStmt{X: &ast.CallExpr{Fun: newID(hiddenName), Args: callArgs}}
		}
		// //go:noinline prevents the Go inliner from collapsing the
		// trampoline into its caller. Inlining would erase the
		// runtime call boundary that the linker uses to set up the
		// ABI0↔ABIInternal bridge between the asm caller and the
		// linkname-aliased asm callee, leading to scrambled
		// arguments at the target.
		decls = append(decls, &ast.FuncDecl{
			Doc: &ast.CommentGroup{List: []*ast.Comment{
				{Text: "//go:noinline"},
			}},
			Name: newID(fnName),
			Type: t.funcSignature(ft, true /*withModuleParam*/),
			Body: &ast.BlockStmt{List: []ast.Stmt{bodyStmt}},
		})
	}
	return decls
}

// emitNamedSymbolForwards returns the //go:linkname forward
// declarations for the per-callerChunk named-symbol forwards
// (InvokeExportShard_K, InitElemSeg_K_n, …). Always a bare alias —
// these symbols are Go helpers with no asm-side callers, so the
// ABI0-wrapper requirement that drives the wasm-function
// wrapper-pair form does not apply. Returns nil when no
// named-symbol forwards are registered.
func (t *translator) emitNamedSymbolForwards(callerChunk int) []ast.Decl {
	symForwards := t.linknameSymbolForwards[callerChunk]
	if len(symForwards) == 0 {
		return nil
	}
	prevChunk := t.currentChunk
	t.currentChunk = callerChunk
	defer func() { t.currentChunk = prevChunk }()

	symKeys := make([]string, 0, len(symForwards))
	for k := range symForwards {
		symKeys = append(symKeys, k)
	}
	sort.Strings(symKeys)
	var decls []ast.Decl
	for _, name := range symKeys {
		sym := symForwards[name]
		linknameTarget := fmt.Sprintf("%s/p%d.%s", t.opts.OutputImportPath, sym.targetChunk, name)
		decls = append(decls, &ast.FuncDecl{
			Doc: &ast.CommentGroup{List: []*ast.Comment{
				{Text: fmt.Sprintf("//go:linkname %s %s", name, linknameTarget)},
			}},
			Name: newID(name),
			Type: sym.signature,
		})
	}
	return decls
}

// registerLinknameSymbol records a //go:linkname forward whose local name and
// target name are identical (different from registerLinknameForward, which
// works off wasm function indices). Used for helper symbols like
// InvokeExportShard_K and InitElemSeg_K_n that are created by the codegen.
func (t *translator) registerLinknameSymbol(callerChunk int, name string, targetChunk int, signature *ast.FuncType) {
	if t.linknameSymbolForwards == nil {
		t.linknameSymbolForwards = map[int]map[string]linknameSymbol{}
	}
	if t.linknameSymbolForwards[callerChunk] == nil {
		t.linknameSymbolForwards[callerChunk] = map[string]linknameSymbol{}
	}
	t.linknameSymbolForwards[callerChunk][name] = linknameSymbol{targetChunk: targetChunk, signature: signature}
}

// addChunkExtraDecl attaches a decl to a specific chunk's file. Used by
// linkname-split mode to land shard funcs and per-chunk init helpers in the
// chunk that owns their underlying wasm functions.
func (t *translator) addChunkExtraDecl(chunkIdx int, decl ast.Decl) {
	if t.chunkExtraDecls == nil {
		t.chunkExtraDecls = map[int][]ast.Decl{}
	}
	t.chunkExtraDecls[chunkIdx] = append(t.chunkExtraDecls[chunkIdx], decl)
}

// wasmMemHardCapBytes mirrors the helpers' wasmMemHardCap: the
// implementation limit memoryGrow enforces on linear-memory size,
// 65534 pages. The two must stay equal — the bounds-coalescing gate
// below and the memFromArg constructor guard both reason with this
// value about a cap the runtime side enforces.
const wasmMemHardCapBytes = (1 << 32) - (1 << 17)

// simdBoundsMemOK reports whether the module's memory can never exceed
// wasmMemHardCapBytes, which the coalesced SIMD bounds check requires
// for exactness. Growth is capped by memoryGrow and the memFromArg
// constructor rejects oversized images, so only a declared MINIMUM
// past the cap (65535/65536 pages) disqualifies a module.
func (t *translator) simdBoundsMemOK() bool {
	if t.mod.Memory64() {
		// The coalesced range check is exact on memory64 without any
		// size precondition: linear memory is capped at 2^48
		// (mem64HardCap, enforced by memoryGrow and the constructor),
		// so ea+span can never wrap a u64 and ea+span ≤ memSize is the
		// same exact bound the wasm32 form relies on. The m64
		// load_rng/load_nc splices mirror the wasm32 ones with the
		// address load widened MOVWU→MOVD.
		return true
	}
	for _, mem := range t.mod.Memories {
		if uint64(mem.Limits.Min)*65536 > wasmMemHardCapBytes {
			return false
		}
	}
	return true
}

// use marks a stdlib package as needed by the output.
func (t *translator) use(pkg string) { t.imports[pkg] = "" }

// useHelper marks a helper as needed.
func (t *translator) useHelper(name string) {
	t.helpers[name] = true
	if strings.HasPrefix(name, "simd_") {
		// The pure lane ops live in the whole-file SIMD set (scalar
		// reference + per-arch asm), shipped by appendSimdHelperFiles;
		// emitHelpers ignores their names.
		t.usesSimd = true
		// The gcasm memory-op splices need the Module field offsets,
		// which they extract from this probe's captured assembly.
		t.helpers["gcasmMemProbe"] = true
	}
}

// importHandledInternally reports whether a wasm import never surfaces to the
// host because the code generator implements it inline (today: wasi-threads'
// thread-spawn, which becomes a goroutine).
func importHandledInternally(imp wasm.Import) bool {
	return (imp.Module == "wasi" && imp.Name == "thread-spawn") ||
		(imp.Module == "wasi_snapshot_preview1" && imp.Name == "thread_spawn")
}

// knownImportModuleOrder is the fixed parameter order for the host-import
// modules the wasmify pipeline emits: the WASI host interface first, then env,
// then the wasmify bridge module. The generated constructor (New / NewWithWASI)
// takes one parameter per module the wasm imports, always in this order, and the
// Module struct lays out its import fields the same way — so the signature never
// depends on the wasm's import-declaration order.
var knownImportModuleOrder = []string{"wasi_snapshot_preview1", "env", "wasmify"}

// collectImportModules records the distinct host-import modules the wasm uses.
// Only WHICH modules appear is wasm-specific (a wasm that never calls a
// wasmify-bridge import gets no "wasmify" entry, and therefore no such
// constructor parameter); the ORDER is prescribed by knownImportModuleOrder, not
// derived from the wasm — so there is no need to sort or otherwise compute it.
func (t *translator) collectImportModules() {
	present := map[string]bool{}
	for _, imp := range t.mod.Imports {
		if importHandledInternally(imp) {
			// wasi-threads' thread-spawn never reaches the host — the emitter
			// maps it onto a goroutine spawn — so it must not surface as a
			// constructor parameter / host interface either. A module whose
			// imports are ALL internal disappears from the signature.
			continue
		}
		present[imp.Module] = true
	}
	// Emit the known modules first, in the prescribed order, if the wasm uses them.
	for _, mod := range knownImportModuleOrder {
		if present[mod] {
			t.importedModules = append(t.importedModules, mod)
			delete(present, mod)
		}
	}
	// wasm2go also transpiles wasm outside the wasmify pipeline, which may import
	// from other modules; each still needs its own interface + constructor
	// parameter, so append any leftover module in first-seen order (no
	// hand-written binding targets these, so only per-wasm determinism matters).
	for _, imp := range t.mod.Imports {
		if present[imp.Module] {
			t.importedModules = append(t.importedModules, imp.Module)
			delete(present, imp.Module)
		}
	}
}

// emitImportInterfaces returns one type-decl per distinct import module.
func (t *translator) emitImportInterfaces() []ast.Decl {
	if len(t.mod.Imports) == 0 {
		return nil
	}
	// Group imports by module name (internal ones — goroutine-backed
	// thread-spawn — never surface as interface methods).
	byMod := map[string][]wasm.Import{}
	for _, imp := range t.mod.Imports {
		if importHandledInternally(imp) {
			continue
		}
		byMod[imp.Module] = append(byMod[imp.Module], imp)
	}
	var decls []ast.Decl
	for _, mod := range t.importedModules {
		ifaceName := t.importIfaceName(mod)
		var methods []*ast.Field
		for _, imp := range byMod[mod] {
			// Only FUNCTION imports become interface methods — those are the
			// host callables the Go embedder implements. Non-func imports
			// (tags for EH, e.g. __c_longjmp, plus table/memory/global) are not
			// callable and must not appear as a named method (a named interface
			// method's type must be a func signature, not `any`).
			if imp.Kind != wasm.ImportFunc {
				continue
			}
			methods = append(methods, t.importMethodField(imp))
		}
		decls = append(decls, &ast.GenDecl{
			Tok: token.TYPE,
			Specs: []ast.Spec{&ast.TypeSpec{
				Name: newID(ifaceName),
				Type: &ast.InterfaceType{Methods: &ast.FieldList{List: methods}},
			}},
		})
	}
	return decls
}

// importMethodField returns an interface method field for a single wasm import.
// Currently only function imports are translated as methods; table/memory/global
// imports are not yet supported.
func (t *translator) importMethodField(imp wasm.Import) *ast.Field {
	switch imp.Kind {
	case wasm.ImportFunc:
		ft := t.mod.Types[imp.TypeIdx]
		return &ast.Field{
			Names: []*ast.Ident{newID(t.importMethodName(imp))},
			Type:  t.funcSignature(ft, true /*withModuleParam*/),
		}
	default:
		return &ast.Field{
			Names: []*ast.Ident{newID(t.importMethodName(imp))},
			Type:  newID("/* unsupported import kind */ any"),
		}
	}
}

// funcSignature returns a *ast.FuncType for the given wasm signature. If
// withModuleParam is true, the first parameter is `m *Module` (or
// `*mod.Module` in chunk context). Parameter names are emitted only for
// function declarations (where the body needs to reference them); call sites
// that need a typed function value should use funcSignatureUnnamed instead.
func (t *translator) funcSignature(ft wasm.FuncType, withModuleParam bool) *ast.FuncType {
	return t.funcSignatureNamed(ft, withModuleParam, true)
}

// funcSignatureUnnamed returns a *ast.FuncType without parameter names.
// Used in call_indirect type assertions where names are decorative — Go
// allows e.g. `func(*Module, int32, int32) int32` and gofmt prefers the
// unnamed form for type expressions inside type assertions.
func (t *translator) funcSignatureUnnamed(ft wasm.FuncType, withModuleParam bool) *ast.FuncType {
	return t.funcSignatureNamed(ft, withModuleParam, false)
}

func (t *translator) funcSignatureNamed(ft wasm.FuncType, withModuleParam, named bool) *ast.FuncType {
	params := &ast.FieldList{}
	if withModuleParam {
		field := &ast.Field{Type: t.moduleType()}
		if named {
			field.Names = []*ast.Ident{newID("m")}
		}
		params.List = append(params.List, field)
	}
	for i, p := range ft.Params {
		field := &ast.Field{Type: goTypeOf(p)}
		if named {
			field.Names = []*ast.Ident{newID(fmt.Sprintf("l%d", i))}
		}
		params.List = append(params.List, field)
	}
	var results *ast.FieldList
	if len(ft.Results) > 0 {
		results = &ast.FieldList{}
		for _, r := range ft.Results {
			results.List = append(results.List, &ast.Field{Type: goTypeOf(r)})
		}
	}
	return &ast.FuncType{Params: params, Results: results}
}

// emitModuleStruct returns the Module type declaration.
func (t *translator) emitModuleStruct() ast.Decl {
	var fields []*ast.Field

	if len(t.mod.Memories) > 0 {
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("memory"))},
			Type:  &ast.ArrayType{Elt: newID("byte")},
		})
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("maxMem"))},
			Type:  newID("uint64"),
		})
		// M caches unsafe.Pointer(unsafe.SliceData(memory)) so every
		// load/store can deref through m.M without re-fetching the
		// slice header per access. New() initialises it; memoryGrow
		// updates it whenever it reallocates the backing array.
		// Reslice grows leave m.M alone (slice header data pointer
		// is stable under append-within-cap).
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID("M")},
			Type:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Pointer")},
		})
		t.use("unsafe")
	}
	if t.opts.OutlineMinValues > 0 {
		// Boundary scratch for packed outlined-loop calls: the caller
		// fills, the callee prologue drains, so one per-module array
		// suffices at any nesting depth.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("outlinePack"))},
			Type: &ast.ArrayType{
				Len: &ast.BasicLit{Kind: token.INT, Value: "128"},
				Elt: newID("uint64"),
			},
		})
	}

	// The propagating-exception state, when the module uses EH. A wasm
	// exception travels as module state plus a check-and-branch after every
	// call that may raise one, so EH code stays ordinary straight-line Go.
	// Value fields on purpose: a wasi-threads agent runs on a struct COPY,
	// which makes the state per-execution-context for free (an exception
	// belongs to one thread, exactly like a global). Declared here, in the
	// fixed-offset leading region right after outlinePack, so direct-asm
	// bodies can address it with a trivially modeled offset
	// (moduleExcOffsets) instead of modeling the whole struct tail; the
	// generated compile-time pins assert the model.
	if t.excSlots > 0 {
		fields = append(fields,
			&ast.Field{
				Names: []*ast.Ident{newID(t.fieldName("excPending"))},
				Type:  newID("int32"),
			},
			&ast.Field{
				Names: []*ast.Ident{newID(t.fieldName("excTag"))},
				Type:  newID("uint32"),
			},
			&ast.Field{
				Names: []*ast.Ident{newID(t.fieldName("excVals"))},
				Type:  &ast.ArrayType{Len: intLit(int64(t.excSlots)), Elt: newID("uint64")},
			})
	}

	for i := range t.mod.Tables {
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName(fmt.Sprintf("t%d", i)))},
			Type:  &ast.ArrayType{Elt: newID("any")},
		})
	}

	for i, g := range t.mod.Globals {
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName(fmt.Sprintf("g%d", int(t.mod.NumImportedGlobals)+i)))},
			Type:  goTypeOf(g.Type.Type),
		})
	}

	for _, mod := range t.importedModules {
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName(MangleModuleField(mod)))},
			Type:  newID(t.importIfaceName(mod)),
		})
	}

	// memMu serialises memory-slice-header mutations (memoryGrow) against
	// out-of-band host access (accessMemory). Declared LAST so the
	// memory/maxMem/M offsets the generated asm hardcodes (moduleMOffset)
	// are unaffected.
	if len(t.mod.Memories) > 0 {
		// memMu/memSize/threads are pointers: a wasi-threads agent runs on
		// a struct COPY of the Module (own globals, shared everything else),
		// and this state must stay shared across the copies.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("memMu"))},
			Type:  &ast.StarExpr{X: &ast.SelectorExpr{X: newID("sync"), Sel: newID("Mutex")}},
		})
		t.use("sync")

		// memSize is the CURRENT linear-memory size in bytes. For a shared
		// memory (threads proposal) the slice header is immutable after
		// New() — len == cap == the declared maximum, reserved once as
		// virtual address space that only becomes resident as the guest
		// touches it — so growth is a lone atomic store here and the data
		// pointer other agents deref through never moves. Size-consulting
		// helpers read this atomically; the hot load/store path reads
		// neither (it derefs m.M), so threads cost it nothing.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("memSize"))},
			Type:  &ast.StarExpr{X: &ast.SelectorExpr{X: newID("atomic"), Sel: newID("Uint64")}},
		})
		t.use("sync/atomic")
		// dataSegs are the module's PASSIVE data segments (views into the
		// embedded data blob), indexed by their original data-section index —
		// memory.init names them by that index. Active segments hold nil (a
		// memory.init on one traps, same as post-drop). data.drop nils the
		// entry out.
		if t.hasPassiveData() {
			fields = append(fields, &ast.Field{
				Names: []*ast.Ident{newID(t.fieldName("dataSegs"))},
				Type:  &ast.ArrayType{Elt: &ast.ArrayType{Elt: newID("byte")}},
			})
		}
		// dataEnd is where the data segments stop and BSS begins. The
		// constructor seeds it from the ACTIVE segments (their extent is known
		// here, at compile time) and memoryInit raises it for the PASSIVE ones,
		// whose destinations are wasm constants the host cannot see until the
		// start section runs them. SharedImage is the consumer: it may share
		// everything below this line and must zero everything above it.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("dataEnd"))},
			Type:  newID("uint32"),
		})
		// memShared records whether the memory was declared shared, which
		// is what makes the reslice-free grow above legal.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("memShared"))},
			Type:  newID("bool"),
		})
		// threads holds the wasi-threads agents (a wasm thread is a
		// goroutine) and the wait/notify parking lot. Zero-sized until the
		// guest actually spawns or blocks.
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("threads"))},
			Type:  &ast.StarExpr{X: t.threadPoolTypeExpr()},
		})
		// threadStart carries the wasi_thread_start export as a function
		// value: multi-package output emits exports as free functions in the
		// main package, so base's threadSpawn helper cannot reach them any
		// other way (no method to assert, no upward import). The field name
		// and the start_arg width follow the memory width: a memory64
		// module's start_arg is an i64 linear-memory pointer, read by the
		// threadSpawn_m64 helper through the threadStart64 field.
		threadStartField, argType := "threadStart", "int32"
		if t.mod.Memory64() {
			threadStartField, argType = "threadStart64", "int64"
		}
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName(threadStartField))},
			Type: &ast.FuncType{Params: &ast.FieldList{List: []*ast.Field{
				{Type: t.moduleType()}, {Type: newID("int32")}, {Type: newID(argType)},
			}}},
		})
	}

	return &ast.GenDecl{
		Tok: token.TYPE,
		Specs: []ast.Spec{&ast.TypeSpec{
			Name: newID("Module"),
			Type: &ast.StructType{Fields: &ast.FieldList{List: fields}},
		}},
	}
}

// blobSpan is a byte range in the embedded data.bin blob.
type blobSpan struct {
	start  int
	length int
}

// hasPassiveData reports whether the module carries passive data segments
// (LLVM's shared-memory output always does).
func (t *translator) hasPassiveData() bool {
	for _, ds := range t.mod.Datas {
		if ds.Passive {
			return true
		}
	}
	return false
}

// newMode selects which constructor emitNewFuncsMode is building.
type newMode int

const (
	// newAlloc allocates and initializes the linear memory itself: New,
	// NewWithWASI, NewWithWASIReserve.
	newAlloc newMode = iota
	// newFromMemory takes the memory from the caller (NewWithMemory) and skips
	// copying the active data segments into it — the caller's memory already
	// holds them. The start section still runs, because the caller's memory is
	// an image of the data segments and nothing more.
	newFromMemory
	// newFromSnapshot takes the memory AND the wasm globals from the caller
	// (NewFromSnapshot): a snapshot of an instance that has already been fully
	// initialized. Nothing is re-run — not the data segments, not the start
	// section — because everything they would do is already in the snapshot,
	// and re-running the start section over it would trap on its own
	// already-ran flag.
	newFromSnapshot
)

// emitNewFuncs emits the constructor family: the allocating ones, plus the two
// that take the linear memory from the caller. Those two are the hook an
// embedding needs to share memory across instances (map an image copy-on-write
// and its unwritten pages cost nothing per instance) — NewWithMemory for an
// image of the data segments, NewFromSnapshot for an image of a whole
// initialized instance.
func (t *translator) emitNewFuncs() []ast.Decl {
	decls := t.emitNewFuncsMode(newAlloc)
	if len(t.mod.Memories) > 0 {
		decls = append(decls, t.initialMemoryBytesConst())
		decls = append(decls, t.emitNewFuncsMode(newFromMemory)...)
		decls = append(decls, t.emitNewFuncsMode(newFromSnapshot)...)
	}
	return decls
}

// initialMemoryBytesConst emits the module's declared initial linear-memory
// size as an exported constant. It is what NewWithMemory's memSize parameter
// must be when the caller-provided memory is FRESH (all zeros, e.g. a
// MAP_SHARED mapping handed to an in-place image builder): the constructor
// then installs the data segments and runs initialization exactly as the
// allocating constructor would.
func (t *translator) initialMemoryBytesConst() ast.Decl {
	return &ast.GenDecl{
		Tok: token.CONST,
		Specs: []ast.Spec{&ast.ValueSpec{
			Names:  []*ast.Ident{newID("InitialMemoryBytes")},
			Values: []ast.Expr{uintLit(t.mod.Memories[0].Limits.Min * 65536)},
		}},
	}
}

// memLenExpr is uint64(len(memory)): with a caller-supplied memory the
// allocation itself is the ceiling, so the wasm's declared maximum does not
// enter into it.
func memLenExpr() ast.Expr {
	return &ast.CallExpr{
		Fun:  newID("uint64"),
		Args: []ast.Expr{&ast.CallExpr{Fun: newID("len"), Args: []ast.Expr{newID("memory")}}},
	}
}

// emitNewFuncsMode builds the constructors. With memFromArg, it emits ONLY
// NewWithMemory: the same body, except the linear memory (and the size the
// guest sees) come from parameters.
func (t *translator) emitNewFuncsMode(mode newMode) []ast.Decl {
	memFromArg := mode != newAlloc
	primaryName := "New"
	emitNativeWASIWrapper := false
	wasiIdx := -1
	if t.wasmImportsWasi() {
		// The function that actually does all the setup work is renamed
		// to NewWithWASI; the simple-form New() will be appended below
		// as a thin delegator.
		primaryName = "NewWithWASI"
		emitNativeWASIWrapper = true
		for i, mod := range t.importedModules {
			if mod == "wasi_snapshot_preview1" {
				wasiIdx = i
				break
			}
		}
	}

	// When the module has linear memory and we're emitting the WASI-wrapper
	// family, the full-body constructor becomes
	// NewWithWASIReserve(..., reserveBytes int): callers pre-size the initial
	// linear-memory slice capacity so the first memory.grow calls extend len
	// into spare capacity (a zero-copy reslice) instead of reallocating and
	// copying the whole linear memory. NewWithWASI delegates with a default
	// headroom. See the memory-init block below for why this matters.
	emitReserve := emitNativeWASIWrapper && len(t.mod.Memories) > 0
	if emitReserve {
		primaryName = "NewWithWASIReserve"
	}

	var params []*ast.Field
	for _, mod := range t.importedModules {
		params = append(params, &ast.Field{
			Names: []*ast.Ident{newID(MangleModuleField(mod))},
			Type:  t.importIfaceTypeRef(mod),
		})
	}
	// modParams is the import-only signature (no reserveBytes), used to build
	// the thin NewWithWASI / New delegators. The primary gets reserveBytes
	// appended when emitReserve.
	modParams := params
	if memFromArg {
		primaryName = "NewWithMemory"
		emitReserve = false
		params = append(append([]*ast.Field{}, params...),
			&ast.Field{Names: []*ast.Ident{newID("memory")}, Type: &ast.ArrayType{Elt: newID("byte")}},
			&ast.Field{Names: []*ast.Ident{newID("memSize")}, Type: newID("uint64")},
		)
		if mode == newFromSnapshot {
			primaryName = "NewFromSnapshot"
			params = append(params, &ast.Field{
				Names: []*ast.Ident{newID("globals")},
				Type:  &ast.ArrayType{Elt: newID("uint64")},
			})
		}
	} else if emitReserve {
		params = append(append([]*ast.Field{}, params...), &ast.Field{
			Names: []*ast.Ident{newID("reserveBytes")},
			Type:  newID("int"),
		})
	}

	body := &ast.BlockStmt{}

	// m := &Module{<host imports>}
	composite := &ast.CompositeLit{Type: t.moduleTypeName()}
	for _, mod := range t.importedModules {
		composite.Elts = append(composite.Elts, &ast.KeyValueExpr{
			Key:   newID(t.fieldName(MangleModuleField(mod))),
			Value: newID(MangleModuleField(mod)),
		})
	}
	body.List = append(body.List, &ast.AssignStmt{
		Tok: token.DEFINE,
		Lhs: []ast.Expr{newID("m")},
		Rhs: []ast.Expr{&ast.UnaryExpr{Op: token.AND, X: composite}},
	})

	// defaultReserveCap is the initial linear-memory slice capacity that
	// NewWithWASI (and the non-WASI New) pass when emitReserve: minBytes plus
	// a 25% headroom, so typical start-up grows are zero-copy reslices.
	var defaultReserveCap uint64

	// Memory init.
	if len(t.mod.Memories) > 0 {
		mem := t.mod.Memories[0]
		// wasm32 caps linear memory at 65536 pages × 64 KiB = 4 GiB;
		// a memory64's declared minimum is capped by the mem64 hard
		// cap instead. A malformed module that declares a larger Min
		// would otherwise have us emit `make([]byte, huge)` and
		// either panic at init time or quietly succeed and OOM.
		maxPages := uint64(1) << 16
		if mem.Is64 {
			maxPages = 1 << 32 // mem64HardCap >> 16
		}
		if mem.Limits.Min > maxPages {
			return []ast.Decl{&ast.FuncDecl{
				Name: newID("New"),
				Type: &ast.FuncType{Params: &ast.FieldList{List: params},
					Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}}},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
						stringLit(fmt.Sprintf("wasm2go: memory min %d exceeds the %d-page maximum", mem.Limits.Min, maxPages)),
					}}},
				}},
			}}
		}
		minBytesU := mem.Limits.Min * 65536
		defaultReserveCap = minBytesU + minBytesU/4
		// Choose the make() capacity arg. NewWithWASIReserve uses the caller's
		// reserveBytes clamped up to minBytes (make panics if cap < len);
		// every other constructor uses the default headroom literal.
		var capArg ast.Expr
		if emitReserve {
			body.List = append(body.List,
				&ast.AssignStmt{
					Tok: token.DEFINE,
					Lhs: []ast.Expr{newID("__memcap")},
					Rhs: []ast.Expr{newID("reserveBytes")},
				},
				&ast.IfStmt{
					Cond: &ast.BinaryExpr{X: newID("__memcap"), Op: token.LSS, Y: uintLit(minBytesU)},
					Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
						Tok: token.ASSIGN,
						Lhs: []ast.Expr{newID("__memcap")},
						Rhs: []ast.Expr{uintLit(minBytesU)},
					}}},
				},
			)
			capArg = newID("__memcap")
		} else {
			capArg = uintLit(defaultReserveCap)
		}
		// A SHARED memory (threads proposal, which requires a declared
		// maximum) is allocated at its ceiling LENGTH once: other agents
		// deref the data pointer concurrently, so the backing array must
		// never move and the slice must never be re-made. Growth is then a
		// lone atomic store (memSize), and the hot load/store path stays
		// lock- and atomic-free.
		//
		// The ceiling is a RUNTIME value, not the wasm's declared maximum:
		// NewWithReserve's caller passes the memory cap it wants to enforce,
		// and a host that means to allow more than the module declares is
		// entitled to — the declared max is a property of the binary, not a
		// policy. Untouched pages of the allocation never become resident
		// (Go mmaps a large slice; the OS pages it in on demand), so a
		// generous ceiling costs address space, not memory.
		lenArg := ast.Expr(uintLit(minBytesU))
		if memFromArg {
			// The caller owns the allocation: it may be a copy-on-write map
			// of a pre-initialized image shared by every instance. Nothing
			// here may touch it — a write would fault in a private copy of
			// the page and undo the sharing.
			lenArg = nil
			capArg = nil
		} else if mem.Limits.Shared {
			ceiling := ast.Expr(uintLit(defaultReserveCap))
			if mem.Limits.HasMax {
				ceiling = uintLit(mem.Limits.Max * 65536)
			}
			if emitReserve {
				// __memcap is reserveBytes clamped up to minBytes; for a
				// shared memory it IS the ceiling, so a caller passing 0
				// falls back to the declared maximum rather than to a
				// headroom that could not grow later.
				body.List = append(body.List, &ast.IfStmt{
					Cond: &ast.BinaryExpr{
						X:  newID("__memcap"),
						Op: token.LSS,
						Y:  ceiling,
					},
					Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
						Tok: token.ASSIGN,
						Lhs: []ast.Expr{newID("__memcap")},
						Rhs: []ast.Expr{ceiling},
					}}},
				})
				lenArg = newID("__memcap")
				capArg = newID("__memcap")
			} else {
				lenArg = ceiling
				capArg = ceiling
			}
		}
		var memRhs ast.Expr
		if memFromArg {
			memRhs = newID("memory")
		} else {
			memRhs = &ast.CallExpr{
				Fun: newID("make"),
				Args: []ast.Expr{
					&ast.ArrayType{Elt: newID("byte")},
					lenArg,
					capArg,
				},
			}
		}
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef("memory")},
			Rhs: []ast.Expr{memRhs},
		})
		// memSize is the size the guest sees; for a shared memory it is the
		// only thing growth changes.
		// The pointered shared-state fields exist exactly once, on the
		// PRIMARY module; agent clones copy the pointers and share them.
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef("memMu")},
			Rhs: []ast.Expr{&ast.UnaryExpr{Op: token.AND, X: &ast.CompositeLit{
				Type: &ast.SelectorExpr{X: newID("sync"), Sel: newID("Mutex")},
			}}},
		})
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef("memSize")},
			Rhs: []ast.Expr{&ast.UnaryExpr{Op: token.AND, X: &ast.CompositeLit{
				Type: &ast.SelectorExpr{X: newID("atomic"), Sel: newID("Uint64")},
			}}},
		})
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef("threads")},
			Rhs: []ast.Expr{&ast.UnaryExpr{Op: token.AND, X: &ast.CompositeLit{
				Type: t.threadPoolTypeExpr(),
			}}},
		})
		sizeArg := ast.Expr(uintLit(minBytesU))
		if memFromArg {
			// The image the caller handed us is already initialized; its
			// grown size travels with it. It must respect the same
			// implementation limit memoryGrow enforces — the coalesced
			// SIMD bounds check is only exact below it. A memory64 uses
			// the mem64 hard cap instead.
			capBytes := uint64(wasmMemHardCapBytes)
			if mem.Is64 {
				capBytes = 1 << 48 // mem64HardCap
			}
			sizeArg = newID("memSize")
			body.List = append(body.List, &ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X:  newID("memSize"),
					Op: token.GTR,
					Y:  uintLit(capBytes),
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
						stringLit(fmt.Sprintf("wasm2go: memory size exceeds the implementation limit (%d bytes)", capBytes)),
					}}},
				}},
			})
		}
		body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName("memSize"))},
				Sel: newID("Store"),
			},
			Args: []ast.Expr{sizeArg},
		}})
		if mem.Limits.Shared {
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{t.fieldRef("memShared")},
				Rhs: []ast.Expr{newID("true")},
			})
		}
		// Prime the m.M cache so the first load/store doesn't need a
		// special-case "is M still nil" check. memoryGrow's reallocate
		// path keeps M in sync.
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID("M")}},
			Rhs: []ast.Expr{&ast.CallExpr{
				Fun: &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("Pointer")},
				Args: []ast.Expr{&ast.CallExpr{
					Fun:  &ast.SelectorExpr{X: newID("unsafe"), Sel: newID("SliceData")},
					Args: []ast.Expr{t.fieldRef("memory")},
				}},
			}},
		})
		t.use("unsafe")
		if mem.Limits.HasMax {
			// Cap Max at the wasm32 maximum too; values > 65536
			// don't make sense and the uint64 multiplication
			// (Max*65536) could overflow at uint64 itself for
			// extreme attacker-supplied values.
			if mem.Limits.Max > maxPages {
				return []ast.Decl{&ast.FuncDecl{
					Name: newID("New"),
					Type: &ast.FuncType{Params: &ast.FieldList{List: params},
						Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}}},
					Body: &ast.BlockStmt{List: []ast.Stmt{
						&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
							stringLit(fmt.Sprintf("wasm2go: memory max %d exceeds the %d-page maximum", mem.Limits.Max, maxPages)),
						}}},
					}},
				}}
			}
			maxRhs := ast.Expr(uintLit(mem.Limits.Max * 65536))
			if memFromArg {
				maxRhs = memLenExpr()
			}
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{t.fieldRef("maxMem")},
				Rhs: []ast.Expr{maxRhs},
			})
		} else {
			// No declared maximum: cap at the wasm32 4 GiB limit; a
			// memory64 is unlimited here (memoryGrow64 applies the
			// mem64 hard cap), which is the entire point of memory64.
			maxRhs := ast.Expr(uintLit(1 << 32))
			if mem.Is64 {
				maxRhs = uintLit(0)
			}
			if memFromArg {
				maxRhs = memLenExpr()
			}
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{t.fieldRef("maxMem")},
				Rhs: []ast.Expr{maxRhs},
			})
		}
	}

	for i, tab := range t.mod.Tables {
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef(fmt.Sprintf("t%d", i))},
			Rhs: []ast.Expr{&ast.CallExpr{
				Fun: newID("make"),
				Args: []ast.Expr{
					&ast.ArrayType{Elt: newID("any")},
					uintLit(tab.Limits.Min),
				},
			}},
		})
	}

	// Initialize defined globals from their constant init expressions.
	// Integer and float globals decode through distinct const-expr
	// evaluators — dispatching on the declared global type first avoids
	// feeding a float const-expr to the integer evaluator (which would
	// otherwise emit a panic stub for a perfectly valid module).
	for i, g := range t.mod.Globals {
		gIdx := int(t.mod.NumImportedGlobals) + i
		var rhs ast.Expr
		switch g.Type.Type {
		case wasm.ValI32, wasm.ValI64:
			v, err := evalConstExprI64(g.Init, t.mod)
			if err != nil {
				body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun:  newID("panic"),
					Args: []ast.Expr{stringLit(fmt.Sprintf("global[%d] init: %v", i, err))},
				}})
				continue
			}
			if g.Type.Type == wasm.ValI32 {
				rhs = &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{intLit(v)}}
			} else {
				rhs = &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{intLit(v)}}
			}
		case wasm.ValF32, wasm.ValF64:
			fv, err := evalConstExprFloat(g.Init)
			if err != nil {
				body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun:  newID("panic"),
					Args: []ast.Expr{stringLit(fmt.Sprintf("global[%d] init: %v", i, err))},
				}})
				continue
			}
			if fv == 0 && !math.Signbit(fv) {
				continue // zero value already correct (-0 == 0, but is not it)
			}
			// NaN/Inf/-0 initializers route through math.Float*frombits, so
			// the math import must be registered for the emitted file.
			if floatNeedsBitsEmission(fv) {
				t.use("math")
			}
			if g.Type.Type == wasm.ValF32 {
				rhs = floatInitExpr(float64(float32(fv)), true)
			} else {
				rhs = floatInitExpr(fv, false)
			}
		default:
			// v128/funcref — skip for now; zero is fine for most uses.
			continue
		}
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef(fmt.Sprintf("g%d", gIdx))},
			Rhs: []ast.Expr{rhs},
		})
	}

	// Element segments: populate each table from its const-expr offset.
	if t.multiPackage && t.plan != nil {
		// Linkname-split mode: distribute slot writes to the chunk that
		// owns each fnIdx. Each chunk emits one or more InitElemSeg_K_b(m)
		// helpers that only reference its own Fn<idx> values (zero linkname
		// forwards from chunk into other chunks). Main calls each helper
		// via linkname forward — bounded by num_chunks × num_batches.
		if err := t.emitShardedElementInit(body, memFromArg); err != nil {
			return []ast.Decl{&ast.FuncDecl{
				Name: newID("New"),
				Type: &ast.FuncType{
					Params:  &ast.FieldList{List: params},
					Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
						stringLit(fmt.Sprintf("element init: %v", err)),
					}}},
				}},
			}}
		}
	} else {
		for i, elem := range t.mod.Elements {
			off, err := evalConstExprI64(elem.Offset, t.mod)
			if err != nil {
				return []ast.Decl{&ast.FuncDecl{
					Name: newID("New"),
					Type: &ast.FuncType{
						Params:  &ast.FieldList{List: params},
						Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
					},
					Body: &ast.BlockStmt{List: []ast.Stmt{
						&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
							stringLit(fmt.Sprintf("element[%d] offset: %v", i, err)),
						}}},
					}},
				}}
			}
			// Element-segment population is HUGE for typical Emscripten output
			// (~17k entries). Inlining all assignments into New() produces a
			// 30k+ line function whose SSA bitmap blows up the Go compiler with
			// "NewBulk too big". Chunk into helper functions of fixed size so
			// each compile unit stays bounded.
			const elemChunkSize = 256
			var chunkDecls []ast.Decl
			nChunks := (len(elem.FuncIdxs) + elemChunkSize - 1) / elemChunkSize
			for c := 0; c < nChunks; c++ {
				start := c * elemChunkSize
				end := start + elemChunkSize
				if end > len(elem.FuncIdxs) {
					end = len(elem.FuncIdxs)
				}
				chunkBody := &ast.BlockStmt{}
				for j := start; j < end; j++ {
					fnIdx := elem.FuncIdxs[j]
					var rhs ast.Expr
					if fnIdx < t.mod.NumImportedFuncs {
						rhs = newID("nil")
					} else {
						rhs = t.funcRef(fnIdx)
					}
					chunkBody.List = append(chunkBody.List, &ast.AssignStmt{
						Tok: token.ASSIGN,
						Lhs: []ast.Expr{&ast.IndexExpr{
							X:     &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName(fmt.Sprintf("t%d", elem.TableIdx)))},
							Index: uintLit(uint64(off + int64(j))),
						}},
						Rhs: []ast.Expr{rhs},
					})
				}
				chunkName := fmt.Sprintf("initElem%d_%d", i, c)
				chunkDecls = append(chunkDecls, &ast.FuncDecl{
					Name: newID(chunkName),
					Type: &ast.FuncType{
						Params: &ast.FieldList{List: []*ast.Field{{
							Names: []*ast.Ident{newID("m")},
							Type:  t.moduleType(),
						}}},
					},
					Body: chunkBody,
				})
				body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun:  newID(chunkName),
					Args: []ast.Expr{newID("m")},
				}})
			}
			if !memFromArg {
				// Emitted once: building the body a second time (for
				// NewWithMemory) must not redeclare these.
				t.elemInitChunks = append(t.elemInitChunks, chunkDecls...)
			}
		}
	}

	// Data segments: copy bytes into m.memory at each const-expr offset.
	// When DataSidecar is on, all segments are concatenated into a single
	// `data.bin` file (//go:embed in the output package) and the generated
	// code slices it by offset/length per segment. This avoids producing
	// thousands of tiny sidecar files for wasm modules that emit one
	// segment per string literal.
	if len(t.mod.Datas) > 0 {
		// A C++→wasm build commonly emits one data segment per symbol —
		// modules can carry tens of thousands. Emitting one copy() per
		// segment bloats the generated code far past what the stripped
		// zero-gaps between them save.
		// Sort the segments by memory offset and coalesce any whose gap
		// is below dataCoalesceGap: the gap is filled with zero bytes in
		// the blob so the run is one contiguous copy. A genuinely large
		// gap (a BSS-style hole) stays a separate copy so the blob does
		// not embed megabytes of zeros.
		const dataCoalesceGap = 1024
		type rawSeg struct {
			memOff int64
			bytes  []byte
		}
		raws := make([]rawSeg, 0, len(t.mod.Datas))
		for i, ds := range t.mod.Datas {
			if ds.Passive {
				continue // becomes a dataSegs view below, not a New()-time copy
			}
			off, err := evalConstExprI64(ds.Offset, t.mod)
			if err != nil {
				body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun:  newID("panic"),
					Args: []ast.Expr{stringLit(fmt.Sprintf("data[%d] offset: %v", i, err))},
				}})
				continue
			}
			raws = append(raws, rawSeg{memOff: off, bytes: t.nrc2SegBytes(i, ds.Bytes)})
		}
		sort.Slice(raws, func(i, j int) bool { return raws[i].memOff < raws[j].memOff })
		// Seed dataEnd with the active segments' extent. Passive segments are
		// added by memoryInit when the start section installs them; an active
		// one is copied right here, so its end is known now. Emitted even when
		// the memory came from the caller (memFromArg) and the copies below are
		// skipped: the bytes are in that memory already, and dataEnd describes
		// the memory, not the copying.
		if len(raws) > 0 {
			var maxEnd int64
			for _, r := range raws {
				if end := r.memOff + int64(len(r.bytes)); end > maxEnd {
					maxEnd = end
				}
			}
			body.List = append(body.List, &ast.AssignStmt{
				Lhs: []ast.Expr{t.fieldRef("dataEnd")},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{uintLit(uint64(maxEnd))},
			})
		}
		// Coalescing reorders writes by offset, which is only safe when
		// no two segments overlap (overlapping active segments must be
		// applied in data-section order). Real C++→wasm output never
		// overlaps; if it does, fall back to one copy per segment.
		overlap := false
		for i := 1; i < len(raws); i++ {
			if raws[i].memOff < raws[i-1].memOff+int64(len(raws[i-1].bytes)) {
				overlap = true
				break
			}
		}
		var concat []byte
		type segLoc struct {
			memOff int64
			start  int
			length int
		}
		var segs []segLoc
		for i := 0; i < len(raws); {
			spanMemOff := raws[i].memOff
			spanStart := len(concat)
			concat = append(concat, raws[i].bytes...)
			spanEnd := raws[i].memOff + int64(len(raws[i].bytes))
			j := i + 1
			if !overlap {
				for j < len(raws) {
					gap := raws[j].memOff - spanEnd
					if gap < 0 || gap >= dataCoalesceGap {
						break
					}
					concat = append(concat, make([]byte, gap)...)
					concat = append(concat, raws[j].bytes...)
					spanEnd = raws[j].memOff + int64(len(raws[j].bytes))
					j++
				}
			}
			segs = append(segs, segLoc{memOff: spanMemOff, start: spanStart, length: len(concat) - spanStart})
			i = j
		}
		// Passive segments ride in the same blob, after the active spans.
		// They are NOT copied into memory here — memory.init does that at the
		// guest's request (for LLVM shared-memory output, from the
		// __wasm_init_memory start function, exactly once).
		t.passiveLocs = make(map[int]blobSpan)
		for i, ds := range t.mod.Datas {
			if !ds.Passive {
				continue
			}
			t.passiveLocs[i] = blobSpan{start: len(concat), length: len(ds.Bytes)}
			concat = append(concat, ds.Bytes...)
		}
		t.sidecars["data.bin"] = concat
		blobIdent := newID("wasm2goData_" + sanitizeFilename("data.bin"))
		const dataChunkSize = 256
		nChunks := (len(segs) + dataChunkSize - 1) / dataChunkSize
		for c := 0; c < nChunks; c++ {
			start := c * dataChunkSize
			end := start + dataChunkSize
			if end > len(segs) {
				end = len(segs)
			}
			chunkBody := &ast.BlockStmt{}
			for _, s := range segs[start:end] {
				chunkBody.List = append(chunkBody.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun: newID("copy"),
					Args: []ast.Expr{
						&ast.SliceExpr{
							X:   &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName("memory"))},
							Low: uintLit(uint64(s.memOff)),
						},
						&ast.SliceExpr{
							X:    blobIdent,
							Low:  uintLit(uint64(s.start)),
							High: uintLit(uint64(s.start + s.length)),
						},
					},
				}})
			}
			chunkName := fmt.Sprintf("initData_%d", c)
			if memFromArg {
				// See above: definitions once, calls per constructor.
				continue
			}
			t.elemInitChunks = append(t.elemInitChunks, &ast.FuncDecl{
				Name: newID(chunkName),
				Type: &ast.FuncType{
					Params: &ast.FieldList{List: []*ast.Field{{
						Names: []*ast.Ident{newID("m")},
						Type:  t.moduleType(),
					}}},
				},
				Body: chunkBody,
			})
			body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
				Fun:  newID(chunkName),
				Args: []ast.Expr{newID("m")},
			}})
		}
	}

	// Passive data segments: register blob views under their ORIGINAL
	// data-section indices so memory.init can name them. The blob is the same
	// embedded data.bin the active segments use; passive bytes were appended
	// after the active spans by the emission above.
	if t.hasPassiveData() {
		elts := make([]ast.Expr, len(t.mod.Datas))
		for i, ds := range t.mod.Datas {
			if !ds.Passive {
				elts[i] = newID("nil")
				continue
			}
			loc := t.passiveLocs[i]
			elts[i] = &ast.SliceExpr{
				X:    newID("wasm2goData_" + sanitizeFilename("data.bin")),
				Low:  uintLit(uint64(loc.start)),
				High: uintLit(uint64(loc.start + loc.length)),
			}
		}
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName("dataSegs"))}},
			Rhs: []ast.Expr{&ast.CompositeLit{
				Type: &ast.ArrayType{Elt: &ast.ArrayType{Elt: newID("byte")}},
				Elts: elts,
			}},
		})
	}

	// Wire the wasi_thread_start export into the Module so threadSpawn (in
	// base) can launch agents without reaching into this package. The field
	// follows the memory width (threadStart64 with an i64 start_arg on a
	// memory64 module), matching the struct declaration.
	for _, exp := range t.mod.Exports {
		if exp.Kind != wasm.ExportFunc || exp.Name != "wasi_thread_start" || !t.funcReachable(exp.Index) {
			continue
		}
		threadStartField := "threadStart"
		if t.mod.Memory64() {
			threadStartField = "threadStart64"
		}
		// The export already takes the module as its first parameter, so the
		// function value itself is what goes in the field — a closure over
		// the PRIMARY module here would defeat the per-agent clone that
		// threadSpawn passes in.
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName(threadStartField))}},
			Rhs: []ast.Expr{t.funcRef(exp.Index)},
		})
		break
	}

	// The wasm start section runs at instantiation, before any export is
	// callable. Under LLVM's shared-memory scheme this is __wasm_init_memory:
	// it memory.inits every passive segment exactly once (guarded by an
	// atomic flag) and data.drops them.
	//
	// A snapshot skips it, and must: the snapshot was taken from an instance
	// that already ran it, so the flag it guards itself with is set in the
	// snapshotted memory and a second run would trap on it. Everything the
	// start section does is in the snapshot already.
	if t.mod.Start != nil && *t.mod.Start >= t.mod.NumImportedFuncs && mode != newFromSnapshot {
		body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  t.funcRef(*t.mod.Start),
			Args: []ast.Expr{newID("m")},
		}})
	}

	// A snapshot's globals are as load-bearing as its memory: the guest's TLS
	// base, its shadow-stack pointer, anything else the initialization moved
	// off its declared value. They live outside linear memory, so the image
	// cannot carry them — the caller passes them alongside it.
	if mode == newFromSnapshot {
		body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
			Fun:  t.helperRef("restoreGlobals"),
			Args: []ast.Expr{newID("m"), newID("globals")},
		}})
	}

	body.List = append(body.List, &ast.ReturnStmt{Results: []ast.Expr{newID("m")}})

	primary := &ast.FuncDecl{
		Name: newID(primaryName),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: params},
			Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
		},
		Body: body,
	}
	if memFromArg {
		// NewWithMemory only: the delegators (New / NewWithWASI) exist to
		// pick an allocation for the caller, and this variant's caller has
		// already made that choice.
		return []ast.Decl{primary}
	}
	if !emitNativeWASIWrapper {
		return []ast.Decl{primary}
	}

	// Build the simple-form `New(env, ...)` that omits the wasi
	// parameter and delegates to NewWithWASI with DefaultWASI()
	// inserted at the wasi position.
	var wrapperParams []*ast.Field
	var wrapperArgs []ast.Expr
	// In multi-package mode the WasiStubs + DefaultWASI live in base/;
	// callers outside base reference them through the `base.` prefix.
	var defaultWASICall ast.Expr = &ast.CallExpr{Fun: newID("DefaultWASI")}
	if t.multiPackage && t.currentChunk != chunkBase {
		defaultWASICall = &ast.CallExpr{Fun: &ast.SelectorExpr{X: newID("base"), Sel: newID("DefaultWASI")}}
	}
	for i, mod := range t.importedModules {
		if i == wasiIdx {
			wrapperArgs = append(wrapperArgs, defaultWASICall)
			continue
		}
		wrapperParams = append(wrapperParams, &ast.Field{
			Names: []*ast.Ident{newID(MangleModuleField(mod))},
			Type:  t.importIfaceTypeRef(mod),
		})
		wrapperArgs = append(wrapperArgs, newID(MangleModuleField(mod)))
	}
	wrapperBody := &ast.BlockStmt{List: []ast.Stmt{
		&ast.ReturnStmt{Results: []ast.Expr{&ast.CallExpr{
			Fun:  newID("NewWithWASI"),
			Args: wrapperArgs,
		}}},
	}}
	wrapper := &ast.FuncDecl{
		Doc: &ast.CommentGroup{List: []*ast.Comment{{
			Text: "// New constructs a *Module using DefaultWASI() for the\n" +
				"// wasi_snapshot_preview1 import. Use NewWithWASI to plug in a\n" +
				"// custom implementation (sandboxed FS, captured stdout, ...).",
		}}},
		Name: newID("New"),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: wrapperParams},
			Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
		},
		Body: wrapperBody,
	}
	if !emitReserve {
		return []ast.Decl{primary, wrapper}
	}

	// NewWithWASI: thin delegator to NewWithWASIReserve with the default
	// headroom capacity, so existing callers keep the same signature while
	// still benefiting from the zero-copy-grow reservation.
	var reserveFwdArgs []ast.Expr
	for _, mod := range t.importedModules {
		reserveFwdArgs = append(reserveFwdArgs, newID(MangleModuleField(mod)))
	}
	reserveFwdArgs = append(reserveFwdArgs, uintLit(defaultReserveCap))
	newWithWASI := &ast.FuncDecl{
		Doc: &ast.CommentGroup{List: []*ast.Comment{{
			Text: "// NewWithWASI constructs a *Module with a custom\n" +
				"// wasi_snapshot_preview1 implementation and a default initial\n" +
				"// linear-memory reservation. Use NewWithWASIReserve to pre-size\n" +
				"// the reservation (e.g. to cover an interpreter's whole boot and\n" +
				"// avoid reallocating/copying linear memory on the first grow).",
		}}},
		Name: newID("NewWithWASI"),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: modParams},
			Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{Results: []ast.Expr{&ast.CallExpr{
				Fun:  newID("NewWithWASIReserve"),
				Args: reserveFwdArgs,
			}}},
		}},
	}
	return []ast.Decl{primary, newWithWASI, wrapper}
}

// emitDefinedFunctions emits one Go function per defined wasm function.
// Function names are capitalized in multi-package mode so chunks can call
// across packages. For void-return functions whose body matches the
// "switch dispatcher" pattern (a single big switch where each case is just
// `goto LeN` and the LeN sections are independent), the body is split
// into per-case sub-functions plus a small parent dispatcher. This
// collapses the SSA-memory-per-function term that otherwise dominates
// compile RSS for Emscripten-built wasm.
//
// Any per-function SSA failure surfaces as a hard error; the legacy
// direct-opcode compiler that used to back-stop SSA gaps is gone, so
// callers must either extend SSA or stop building until the unsupported
// opcode is added.
func (t *translator) emitDefinedFunctions() ([]ast.Decl, error) {
	out := make([]ast.Decl, 0, len(t.mod.Functions))
	for i := range t.mod.Functions {
		funcIdx := t.mod.NumImportedFuncs + uint32(i)
		if !t.funcReachable(funcIdx) {
			continue // dead function — dropped by whole-function DCE
		}
		decls, err := t.emitOneDefinedFunction(funcIdx)
		if err != nil {
			return nil, err
		}
		out = append(out, decls...)
	}
	return out, nil
}

// emitOneDefinedFunction compiles a single defined function and returns its
// FuncDecl, plus any dispatch-split sub-functions. In multi-package mode the
// caller is expected to set t.currentChunk to the chunk index that owns this
// function before calling, so the function body's call/helper references
// emit with the correct package qualifier.
//
// An SSA-side failure (unsupported opcode, verify mismatch, emit error) is
// returned as a wrapped error that includes the function index and name;
// the lower-level error already carries the opcode that failed.
func (t *translator) emitOneDefinedFunction(funcIdx uint32) ([]ast.Decl, error) {
	localIdx := funcIdx - t.mod.NumImportedFuncs
	fn := t.mod.Functions[localIdx]
	ft := t.mod.Types[fn.TypeIdx]
	body, err := t.compileBodyViaSSA(funcIdx, fn)
	if err != nil {
		return nil, fmt.Errorf("ssa: function %d (%s): %w", funcIdx, t.funcName(funcIdx), err)
	}
	fnName := t.funcName(funcIdx)
	// NOTE: the dispatcher-splitter previously fired here on the
	// legacy compiler's switch-shape br_table emission. The SSA
	// pipeline emits br_table as a chain of equality-If blocks, which
	// the splitter does not yet recognise, so this is a no-op until
	// that gap is closed (either by emitting a Go switch from the
	// chain or by introducing a BlockSwitch SSA op).
	if t.opts.VecDotRows && t.nrc2 != nil {
		t.rewriteVecDotRowLoops(body)
	}
	var rowsDecl ast.Decl
	if t.opts.VecDotRows && t.nrc2 != nil && funcIdx == t.nrc2.funcIdx {
		// Clone before the prelude prepend: the companion pins nrc
		// to 1, so the paired-tile dispatch would be dead weight.
		clone, cerr := cloneBlockStmt(body)
		if cerr != nil {
			return nil, fmt.Errorf("vec-dot-rows companion: %w", cerr)
		}
		rowsDecl = t.rowsCompanion(clone)
	}
	if t.nrc2 != nil && funcIdx == t.nrc2.funcIdx {
		// The paired-tile prelude and its companion (see nrc2.go).
		body.List = append([]ast.Stmt{t.nrc2Prelude()}, body.List...)
	}
	out := []ast.Decl{&ast.FuncDecl{
		Name: newID(fnName),
		Type: t.funcSignature(ft, true /*withModuleParam*/),
		Body: body,
	}}
	if t.nrc2 != nil && funcIdx == t.nrc2.funcIdx {
		out = append(out, t.nrc2Companion())
	}
	if rowsDecl != nil {
		out = append(out, rowsDecl)
	}
	outlined, err := t.emitOutlinedDecls()
	if err != nil {
		return nil, fmt.Errorf("ssa: function %d (%s): %w", funcIdx, fnName, err)
	}
	out = append(out, outlined...)
	return out, nil
}

// compileBodyViaSSA runs the SSA pipeline end-to-end for a single
// function: lowering → optimization → verify → emit. Any failure at any
// stage is returned to the caller; there is no legacy fallback, so an
// unsupported wasm feature surfaces as a hard build error instead of
// quietly degrading to a non-SSA codegen path.
//
// Optimization pipeline, run to a fixpoint:
//
//	ConstProp  — fold constant arithmetic / comparisons
//	BranchFold — turn If(const) into an unconditional jump
//	Simplify   — copy propagation + trivial-phi elimination
//	CSE        — merge duplicate pure subexpressions
//	DCE        — drop values with no users and no side effect
//
// then Compact sweeps the values marked dead. The before/after live-
// value counts feed the optimization metrics.
// memoryIsShared reports whether this module's linear memory is declared
// shared (threads proposal, limits flag 0x02) — as a defined memory or an
// imported one. Memory-optimization passes that assume single-writer
// semantics must be skipped for such modules.
func (t *translator) memoryIsShared() bool {
	for _, m := range t.mod.Memories {
		if m.Limits.Shared {
			return true
		}
	}
	for _, imp := range t.mod.Imports {
		if imp.Kind == wasm.ImportMemory && imp.Memory.Limits.Shared {
			return true
		}
	}
	return false
}

func (t *translator) compileBodyViaSSA(funcIdx uint32, fn wasm.Function) (*ast.BlockStmt, error) {
	_ = fn // body bytes live on the *wasm.Module; kept for API symmetry.
	ssaFn, err := lower.LowerFunction(t.mod, funcIdx, t.funcName(funcIdx), t.throwSet)
	if err != nil {
		return nil, err
	}
	insBefore := ssa.CountValues(ssaFn)
	// MemOpt (redundant-load elimination + store-to-load forwarding) is
	// UNSOUND on a shared linear memory: it assumes this agent is the only
	// writer between two accesses, but the threads proposal lets another
	// agent store to the same address at any point. wasm2go's non-atomic
	// loads deliberately re-read memory on every access so a peer's store
	// stays visible (see emitMemLoadExpr); eliding or forwarding a load
	// would drop that read. Disable the pass whole-module when the memory
	// is shared. (Atomic ops are OpAtomicCall — MemOpt already treats them
	// as barriers and never touches them.)
	memOptOK := !t.memoryIsShared()
	// SIMD loop unrolling runs BEFORE the fixpoint so its cloned
	// pointer-bump chains constant-fold and the bounds/window passes
	// see the unrolled straight-line body. OPT-IN via Options.SIMDUnroll:
	// the guard CFG it builds still pushes hot functions from the
	// structured emitter to the goto form, whose flattened statements
	// defeat tree fusion — a net loss until the structurer accepts the
	// shape.
	if k := t.opts.SIMDUnroll; k >= 2 {
		if k > 8 {
			k = 8
		}
		pass.UnrollSimdLoops(ssaFn, k, t.mod.Memory64())
	}
	const optFixpointCap = 8
	fixpointReached := false
	for i := 0; i < optFixpointCap; i++ {
		changed := false
		if pass.ConstProp(ssaFn) {
			changed = true
		}
		if pass.BranchFold(ssaFn) {
			changed = true
		}
		if pass.ReassocConstAdds(ssaFn, t.mod.Memory64()) {
			changed = true
		}
		if pass.Simplify(ssaFn) {
			changed = true
		}
		if pass.CSE(ssaFn) {
			changed = true
		}
		if memOptOK && pass.MemOpt(ssaFn) {
			changed = true
		}
		if pass.DCE(ssaFn) {
			changed = true
		}
		if !changed {
			fixpointReached = true
			break
		}
	}
	if !fixpointReached {
		// The fixpoint cap is generous; hitting it almost always means
		// a pass is oscillating, so surface a warning rather than
		// silently shipping a sub-optimal SSA. Cosmetic — the body
		// emits correctly either way.
		fmt.Fprintf(os.Stderr, "wasm2go: SSA fixpoint cap reached at function %s\n", t.funcName(funcIdx))
	}
	// FoldMemAddend runs ONCE after the fixpoint, never inside it: it
	// requires that no later ConstProp can constify the base it leaves
	// behind (see the pass doc for the wraparound hazard). It moves
	// large constant addends of access bases into the AuxInt offset so
	// the emitter's _consts-table guard sees them — a constant that
	// stays in the base sum bypasses the guard and can fail to
	// assemble on arm64 ("constant is not in pool").
	if pass.FoldMemAddend(ssaFn, largeConstThreshold) {
		pass.DCE(ssaFn)
	}
	// Bounds-check coalescing for v128 load groups. After the fixpoint
	// and FoldMemAddend so the address expressions it groups on are in
	// their final constant-folded shape. The coalesced check is exact
	// only while memSize stays below the wasmMemHardCap margin under
	// 2^32 (see the helper's doc); growth is capped there by
	// memoryGrow, but a module whose declared MINIMUM already exceeds
	// the cap would start out past it, so such modules keep per-load
	// checks.
	if t.simdBoundsMemOK() && pass.CoalesceSimdBounds(ssaFn) {
		if t.mod.Memory64() {
			t.useHelper("simd_m64_v128_load_rng")
			t.useHelper("simd_m64_v128_load_nc")
		} else {
			t.useHelper("simd_v128_load_rng")
			t.useHelper("simd_v128_load_nc")
		}
	}
	// f16 table-gather idiom -> pure lane conversion (bit-exact only
	// against a verified IEEE table; see pass.RecognizeF16Gather).
	if pass.RecognizeF16Gather(ssaFn, t.f16TableOK) {
		pass.DCE(ssaFn)
	}
	// f16 store-side idiom -> one packed conversion per four lanes
	// (bit-exact: the packed op reproduces the idiom's rounding and
	// NaN forcing; see pass.RecognizeF16Store). Default ON since the
	// empty-diamond fold below landed: the rewrite alone measured a
	// ~2% tg regression (the emptied NaN-select diamonds kept
	// evaluating their conditions), and folding them flips it to a
	// measured ~1% gain on the largest integration module.
	// The f16 store-side idiom chain runs at both pointer widths: the
	// value-side recognition and diamond folding are width-neutral,
	// the store-merge walks Add64 chains, and the fused cvt+store op
	// takes the module's own address width (simd_m64_* on memory64).
	if pass.RecognizeF16Store(ssaFn) {
		pass.DCE(ssaFn)
	}
	// Idiom rewrites above delete the phis that justified their branch
	// diamonds; fold the emptied control structure so the conditions
	// die too. Fixpoint with DCE: an inner fold empties the enclosing
	// arm for the next round.
	for pass.FoldEmptyDiamonds(ssaFn) {
		pass.DCE(ssaFn)
	}
	// With the diamonds gone the packed store groups sit on straight
	// lines; collapse each into one 64-bit store of the packed word,
	// then fuse the conversion INTO the store so both ride inside the
	// fused region (no vector -> GPR-pair round trip at the boundary).
	if pass.MergeF16Stores(ssaFn) {
		pass.DCE(ssaFn)
	}
	if pass.FuseF16CvtStores(ssaFn, t.mod.Memory64()) {
		pass.DCE(ssaFn)
	}
	ssa.Compact(ssaFn)
	t.curOutlineFunc = funcIdx
	if err := t.maybeOutline(ssaFn); err != nil {
		return nil, fmt.Errorf("outline: %w", err)
	}
	insAfter := ssa.CountValues(ssaFn)
	// A pass bug that produced a malformed CFG must not reach emit;
	// surface the verify failure so the SSA bug is fixed at its source.
	if err := ssa.Verify(ssaFn); err != nil {
		return nil, fmt.Errorf("%w: post-opt verify: %w", lower.ErrSSAUnsupported, err)
	}
	t.retainDirectAsm(ssaFn, t.mod.Types[fn.TypeIdx])
	body, err := newSSAEmitter(t).emitFuncBody(ssaFn)
	if err != nil {
		return nil, fmt.Errorf("%w: emit: %w", lower.ErrSSAUnsupported, err)
	}
	if t.memMetrics != nil {
		t.memMetrics.AddOpt(insBefore, insAfter)
	}
	// Memory-promotion observability: classify this function's memory accesses
	// (frame / rodata / slab) and fold the counts into the module-wide
	// metrics.
	if t.memMetrics != nil {
		t.memMetrics.Add(ssaFn, ssa.ClassifyMemory(ssaFn))
	}
	return body, nil
}

// reportMemMetrics writes the memory-promotion summary to
// stderr once codegen has finished. No-op when no memory accesses were
// seen. Called by each translate* path.
func (t *translator) reportMemMetrics() {
	if t.memMetrics == nil || t.memMetrics.Total == 0 {
		return
	}
	fmt.Fprint(os.Stderr, "\n"+t.memMetrics.Summary())
	// Surface the worst-offender functions so the user knows where the
	// un-promoted traffic concentrates.
	top := t.memMetrics.TopSlabFunctions(5)
	if len(top) > 0 && top[0].Slab > 0 {
		fmt.Fprintln(os.Stderr, "  top un-promoted functions:")
		for _, r := range top {
			if r.Slab == 0 {
				break
			}
			fmt.Fprintf(os.Stderr, "    %-28s slab=%-6d frame=%-5d total=%d\n",
				r.Name, r.Slab, r.Frame, r.Total)
		}
	}
	fmt.Fprintln(os.Stderr)

	// Optional machine-readable sidecar.
	if t.opts.PromotionReportPath != "" {
		data, err := t.memMetrics.JSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "wasm2go: promotion report marshal: %v\n", err)
			return
		}
		if err := os.WriteFile(t.opts.PromotionReportPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "wasm2go: write promotion report: %v\n", err)
		}
	}
}

// parseBulkExportName recognises the bulk-dispatch export naming
// convention `<prefix><svc>_<mt>` where svc and mt are decimal integers.
// The prefix is configured by Options.BulkExportPrefix; when empty no
// export is treated as bulk. Returns (svc, mt, true) on a match.
func parseBulkExportName(name, prefix string) (int32, int32, bool) {
	if prefix == "" || !strings.HasPrefix(name, prefix) {
		return 0, 0, false
	}
	rest := name[len(prefix):]
	sep := -1
	for i, c := range rest {
		if c == '_' {
			sep = i
			break
		}
		if c < '0' || c > '9' {
			return 0, 0, false
		}
	}
	if sep <= 0 || sep == len(rest)-1 {
		return 0, 0, false
	}
	svcStr := rest[:sep]
	mtStr := rest[sep+1:]
	for _, c := range mtStr {
		if c < '0' || c > '9' {
			return 0, 0, false
		}
	}
	svc, err := strconv.ParseInt(svcStr, 10, 32)
	if err != nil || svc < 0 {
		return 0, 0, false
	}
	mt, err := strconv.ParseInt(mtStr, 10, 32)
	if err != nil || mt < 0 {
		return 0, 0, false
	}
	return int32(svc), int32(mt), true
}

// wexpEntry records one (svc, mt) bulk-dispatched export and the wasm
// function it forwards to.
type wexpEntry struct {
	svc, mt   int32
	funcIndex uint32
}

// shardInitElemName returns the per-(chunk, batch) element-segment init
// helper name.
func shardInitElemName(chunkIdx, batch int) string {
	return fmt.Sprintf("InitElemSeg_%d_%d", chunkIdx, batch)
}

// emitShardedElementInit populates the New() body with calls to per-chunk
// element-segment init helpers and attaches the helpers to their owning
// chunk's file. Each helper writes only slots whose underlying funcIdx is
// owned by the same chunk — bare Fn<idx> references inside the helper need
// no linkname forwards. Imports (fnIdx < NumImportedFuncs) leave the slot
// untouched because make([]any, N) already zero-initializes to nil.
//
// initBody is the statement list of New()'s body; helper-call statements
// are appended in chunk-order, batch-order.
// defsEmitted: the constructor body is built twice (New* and NewWithMemory),
// and the per-chunk InitElemSeg_* helpers must be DEFINED once while both
// bodies CALL them. The element segments populate the function table — a Go
// slice, not linear memory — so even an instance whose memory came from the
// shared image has to run them.
func (t *translator) emitShardedElementInit(initBody *ast.BlockStmt, defsEmitted bool) error {
	// Per-chunk slot writes: chunkIdx -> []slotWrite (one entry per slot
	// whose funcIdx is owned by that chunk).
	type slotWrite struct {
		table   uint32
		slot    int64
		funcIdx uint32
	}
	byChunk := map[int][]slotWrite{}
	for i, elem := range t.mod.Elements {
		off, err := evalConstExprI64(elem.Offset, t.mod)
		if err != nil {
			return fmt.Errorf("element[%d] offset: %w", i, err)
		}
		for j, fnIdx := range elem.FuncIdxs {
			if fnIdx < t.mod.NumImportedFuncs {
				// nil slot — left to make()'s zero init.
				continue
			}
			ck, ok := t.plan.FuncToChunk[fnIdx]
			if !ok {
				return fmt.Errorf("element[%d] slot %d: fn%d has no owning chunk", i, j, fnIdx)
			}
			byChunk[ck] = append(byChunk[ck], slotWrite{
				table:   elem.TableIdx,
				slot:    off + int64(j),
				funcIdx: fnIdx,
			})
		}
	}

	chunkOrder := make([]int, 0, len(byChunk))
	for k := range byChunk {
		chunkOrder = append(chunkOrder, k)
	}
	sort.Ints(chunkOrder)

	helperSig := &ast.FuncType{
		Params: &ast.FieldList{List: []*ast.Field{{
			Names: []*ast.Ident{newID("m")},
			Type:  t.moduleType(),
		}}},
	}

	const batchSize = 256
	for _, ck := range chunkOrder {
		writes := byChunk[ck]
		nBatches := (len(writes) + batchSize - 1) / batchSize
		for b := 0; b < nBatches; b++ {
			start := b * batchSize
			end := start + batchSize
			if end > len(writes) {
				end = len(writes)
			}
			// Build helper body — runs in chunk context so funcRef returns
			// bare Fn<idx>.
			prev := t.currentChunk
			t.currentChunk = ck
			helperBody := &ast.BlockStmt{}
			for _, sw := range writes[start:end] {
				helperBody.List = append(helperBody.List, &ast.AssignStmt{
					Tok: token.ASSIGN,
					Lhs: []ast.Expr{&ast.IndexExpr{
						X:     &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName(fmt.Sprintf("t%d", sw.table)))},
						Index: uintLit(uint64(sw.slot)),
					}},
					Rhs: []ast.Expr{t.funcRef(sw.funcIdx)},
				})
			}
			helperName := shardInitElemName(ck, b)
			if !defsEmitted {
				t.addChunkExtraDecl(ck, &ast.FuncDecl{
					Name: newID(helperName),
					Type: helperSig,
					Body: helperBody,
				})
				t.registerLinknameSymbol(-1, helperName, ck, helperSig)
			}
			t.currentChunk = prev

			// The CALL goes into every constructor body; the definition above
			// is emitted once (see the doc comment).
			initBody.List = append(initBody.List, &ast.ExprStmt{X: &ast.CallExpr{
				Fun:  newID(helperName),
				Args: []ast.Expr{newID("m")},
			}})
		}
	}
	return nil
}

// buildSafeInvokeBody constructs the body statements that wrap a single
// `packed = <callExpr>` line with global-snapshot save/restore and a
// recover-into-err defer. Used by emitOneExportFunc to inline the same
// trap-recovery sequence that the historical safeInvokeWrap helper
// implemented, but without the closure + extra Go call frame: each
// per-export Inv_<svc>_<mt> now contains the snapshot+defer+call+return
// directly, so the bulk-dispatch → Inv → asm path drops two Go frames
// (the closure and the wrapper) plus the closure allocation per call.
//
// The emitted shape is:
//
//	savedG0 := m.G0   // and every other mutable global
//	defer func() {
//	    if r := recover(); r != nil { m.G0 = savedG0; ...; err = ... }
//	}()
//	packed = <callExpr>
//	return
func (t *translator) buildSafeInvokeBody(callExpr ast.Expr) []ast.Stmt {
	t.use("fmt")
	var stmts []ast.Stmt
	type snap struct{ saved, field string }
	var snaps []snap
	for i := range t.mod.Globals {
		if !t.mod.Globals[i].Type.Mutable {
			continue
		}
		idx := int(t.mod.NumImportedGlobals) + i
		fld := t.fieldName(fmt.Sprintf("g%d", idx))
		sav := fmt.Sprintf("savedG%d", idx)
		snaps = append(snaps, snap{saved: sav, field: fld})
		stmts = append(stmts, &ast.AssignStmt{
			Tok: token.DEFINE,
			Lhs: []ast.Expr{newID(sav)},
			Rhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID(fld)}},
		})
	}
	recoverBody := &ast.BlockStmt{}
	recoverBody.List = append(recoverBody.List, &ast.AssignStmt{
		Tok: token.DEFINE,
		Lhs: []ast.Expr{newID("r")},
		Rhs: []ast.Expr{&ast.CallExpr{Fun: newID("recover")}},
	})
	ifBody := &ast.BlockStmt{}
	for _, s := range snaps {
		ifBody.List = append(ifBody.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{&ast.SelectorExpr{X: newID("m"), Sel: newID(s.field)}},
			Rhs: []ast.Expr{newID(s.saved)},
		})
	}
	// Preserve the recovered value's error chain: a *WasiExitError from
	// proc_exit (or any other error-typed panic) is wrapped with %w so the
	// caller's errors.As/Is still reach it through the "wasm trap:" prefix;
	// non-error panic values keep the plain %v formatting.
	trapErrf := func(verb string, arg ast.Expr) *ast.AssignStmt {
		return &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{newID("err")},
			Rhs: []ast.Expr{&ast.CallExpr{
				Fun:  &ast.SelectorExpr{X: newID("fmt"), Sel: newID("Errorf")},
				Args: []ast.Expr{stringLit("wasm trap: " + verb), arg},
			}},
		}
	}
	ifBody.List = append(ifBody.List, &ast.IfStmt{
		Init: &ast.AssignStmt{
			Tok: token.DEFINE,
			Lhs: []ast.Expr{newID("trapErr"), newID("trapIsErr")},
			Rhs: []ast.Expr{&ast.TypeAssertExpr{X: newID("r"), Type: newID("error")}},
		},
		Cond: newID("trapIsErr"),
		Body: &ast.BlockStmt{List: []ast.Stmt{trapErrf("%w", newID("trapErr"))}},
		Else: &ast.BlockStmt{List: []ast.Stmt{trapErrf("%v", newID("r"))}},
	})
	recoverBody.List = append(recoverBody.List, &ast.IfStmt{
		Cond: &ast.BinaryExpr{X: newID("r"), Op: token.NEQ, Y: newID("nil")},
		Body: ifBody,
	})
	stmts = append(stmts, &ast.DeferStmt{Call: &ast.CallExpr{Fun: &ast.FuncLit{
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: recoverBody,
	}}})
	stmts = append(stmts, &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{newID("packed")},
		Rhs: []ast.Expr{callExpr},
	})
	stmts = append(stmts, &ast.ReturnStmt{})
	return stmts
}

// emitOneExportFunc emits one standalone dispatch function for a single
// bulk-dispatch export:
//
//	func Inv_<svc>_<mt>(m *Module, l0, l1 int32) (packed int64, err error) {
//	    savedG0 := m.G0   // and every other mutable global
//	    defer func() {
//	        if r := recover(); r != nil { m.G0 = savedG0; err = ... }
//	    }()
//	    packed = FnN(m, l0, l1)
//	    return
//	}
//
// The snapshot+defer+call sequence is inlined per-Inv (rather than
// routed through a shared safeInvokeWrap helper that took a closure)
// so the dispatch path is two Go frames + one closure allocation
// shorter per bulk-dispatch call: the closure that captured
// (m, l0, l1) and the safeInvokeWrap frame itself are both gone.
// Each Inv_*
// remains independently DCE-able because the FnN call is still
// only reachable through its own function body.
func (t *translator) emitOneExportFunc(w wexpEntry) ast.Decl {
	call := &ast.CallExpr{
		Fun:  t.funcRef(w.funcIndex),
		Args: []ast.Expr{newID("m"), newID("l0"), newID("l1")},
	}
	body := &ast.BlockStmt{List: t.buildSafeInvokeBody(call)}
	// The (req_ptr, req_len) pair is pointer-width: i32 on wasm32, i64
	// on a memory64 module (the C bridge declares them void*/size_t).
	ptrType := "int32"
	if t.mod.Memory64() {
		ptrType = "int64"
	}
	params := &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()},
		{Names: []*ast.Ident{newID("l0"), newID("l1")}, Type: newID(ptrType)},
	}}
	results := &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{newID("packed")}, Type: newID("int64")},
		{Names: []*ast.Ident{newID("err")}, Type: newID("error")},
	}}
	return &ast.FuncDecl{
		Name: newID(fmt.Sprintf("Inv_%d_%d", w.svc, w.mt)),
		Type: &ast.FuncType{Params: params, Results: results},
		Body: body,
	}
}

// emitExportWrappers emits *Module methods for wasm exports.
//
// Exports whose names do not match Options.BulkExportPrefix get one
// direct method each (e.g. `Initialize`, `WasmAlloc`, `WasmFree`),
// mangled from the export name via ExportMethodName.
//
// Exports that do match the bulk-export naming convention are grouped
// into a single dispatch helper instead of one method each:
//
//	func (m *Module) InvokeExport(svc, mt int32, l0, l1 int32) int64
//
// The helper switches on `(svc<<32 | mt)` and tail-calls the
// corresponding fnN. This consolidates a potentially huge wrapper batch
// into one compact function, sidesteps duplicate-method-name risks from
// the export-name mangler, and gives the consumer a single entry point
// keyed by (svc, mt). When Options.PerExportDispatch is true the
// consolidated switch is replaced with one standalone Inv_<svc>_<mt>
// function per bulk export so the linker can prune unused ones.
func (t *translator) emitExportWrappers() ([]ast.Decl, error) {
	var out []ast.Decl
	var wexports []wexpEntry
	emittedMethods := map[string]string{} // mangledName -> originating export name
	for _, exp := range t.mod.Exports {
		if exp.Kind != wasm.ExportFunc {
			continue
		}
		// Skip exports whose function was dropped by whole-function DCE
		// — emitting a wrapper or dispatch case for a non-existent FnN
		// would not compile.
		if !t.funcReachable(exp.Index) {
			continue
		}
		if svc, mt, ok := parseBulkExportName(exp.Name, t.opts.BulkExportPrefix); ok {
			wexports = append(wexports, wexpEntry{svc: svc, mt: mt, funcIndex: exp.Index})
			continue
		}
		ft := t.mod.FuncTypeOf(exp.Index)
		methodName := ExportMethodName(exp.Name)
		if prev, dup := emittedMethods[methodName]; dup {
			return nil, fmt.Errorf("wasm2go: exports %q and %q both mangle to method name %q; rename one in the wasm to avoid the collision",
				prev, exp.Name, methodName)
		}
		emittedMethods[methodName] = exp.Name

		callArgs := []ast.Expr{newID("m")}
		for i := range ft.Params {
			callArgs = append(callArgs, newID(fmt.Sprintf("l%d", i)))
		}
		callExpr := &ast.CallExpr{
			Fun:  t.funcRef(exp.Index),
			Args: callArgs,
		}

		var bodyStmt ast.Stmt
		if len(ft.Results) > 0 {
			bodyStmt = &ast.ReturnStmt{Results: []ast.Expr{callExpr}}
		} else {
			bodyStmt = &ast.ExprStmt{X: callExpr}
		}

		params := &ast.FieldList{}
		// In multi-package mode the Module type lives in `base` so we can't
		// declare methods on it from main. Emit free functions instead with
		// the receiver as the first parameter.
		var recv *ast.FieldList
		if t.multiPackage {
			params.List = append(params.List, &ast.Field{
				Names: []*ast.Ident{newID("m")},
				Type:  t.moduleType(),
			})
		} else {
			recv = &ast.FieldList{List: []*ast.Field{{
				Names: []*ast.Ident{newID("m")},
				Type:  t.moduleType(),
			}}}
		}
		for i, p := range ft.Params {
			params.List = append(params.List, &ast.Field{
				Names: []*ast.Ident{newID(fmt.Sprintf("l%d", i))},
				Type:  goTypeOf(p),
			})
		}
		var results *ast.FieldList
		if len(ft.Results) > 0 {
			results = &ast.FieldList{}
			for _, r := range ft.Results {
				results.List = append(results.List, &ast.Field{Type: goTypeOf(r)})
			}
		}

		out = append(out, &ast.FuncDecl{
			Recv: recv,
			Name: newID(methodName),
			Type: &ast.FuncType{Params: params, Results: results},
			Body: &ast.BlockStmt{List: []ast.Stmt{bodyStmt}},
		})
	}
	// Per-export dispatch is always on whenever BulkExportPrefix
	// matched any export — emit one standalone Inv_<svc>_<mt> function
	// per bulk export. Each Inv_* contains its own inlined trap-recovery
	// (no shared safeInvokeWrap helper, no closure allocation) so the
	// dispatch path goes straight Inv_<svc>_<mt> → FnN with no
	// intermediate Go frames. The Go linker drops whichever Inv_* the
	// consumer never calls. The previously-emitted consolidated
	// InvokeExport switch (which kept every bulk export alive against
	// DCE) has no remaining users in the new dispatch codegen and has
	// been removed entirely.
	if len(wexports) > 0 {
		for _, w := range wexports {
			out = append(out, t.emitOneExportFunc(w))
		}
	}

	// Also emit Memory() — method in single-pkg mode, free function in
	// multi-pkg mode (Module lives in `base`, can't add methods from main).
	if len(t.mod.Memories) > 0 {
		var recv *ast.FieldList
		params := &ast.FieldList{}
		if t.multiPackage {
			params.List = append(params.List, &ast.Field{
				Names: []*ast.Ident{newID("m")},
				Type:  t.moduleType(),
			})
		} else {
			recv = &ast.FieldList{List: []*ast.Field{{
				Names: []*ast.Ident{newID("m")},
				Type:  t.moduleType(),
			}}}
		}
		out = append(out, &ast.FuncDecl{
			Recv: recv,
			Name: newID("Memory"),
			Type: &ast.FuncType{
				Params:  params,
				Results: &ast.FieldList{List: []*ast.Field{{Type: &ast.ArrayType{Elt: newID("byte")}}}},
			},
			Body: &ast.BlockStmt{List: []ast.Stmt{
				&ast.ReturnStmt{Results: []ast.Expr{
					&ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName("memory"))},
				}},
			}},
		})
	}

	return out, nil
}

// helpersSrc is the embedded helpers.go source.
//
// Implemented in helpers.go (sibling file); this is just the declaration.
var helpersSrc string

// emitHelpers parses helpers.go (lazily) and pulls out only the requested
// helpers. Resolves their stdlib package usage and registers them into t.imports.
func (t *translator) emitHelpers() ([]ast.Decl, error) {
	if len(t.helpers) == 0 && !t.usesWasmExc {
		return nil, nil
	}
	if t.helpersFile == nil {
		f, err := parser.ParseFile(t.fset, "helpers.go", helpersSrc, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse embedded helpers: %w", err)
		}
		// Synthetic fused-SIMD helpers (simd_fuse.go) join the embedded
		// set here so name resolution, transitive dependency closure,
		// and the multi-package export rename all treat them like any
		// other helper. All shapes are interned by now: emitHelpers
		// runs after every function body has been emitted.
		f.Decls = append(f.Decls, t.fusedHelperDecls()...)
		t.helpersFile = f
	}
	// Build the set of helper-function names defined in helpers.go so
	// we can resolve transitive dependencies between helpers (e.g.
	// i32_div_u_s calls i32_div_u, mstore8 references store8, ...).
	helperNames := map[string]bool{}
	for _, decl := range t.helpersFile.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			helperNames[fn.Name.Name] = true
		}
	}
	// Fixed-point: include every helper that any already-requested
	// helper transitively calls. Iterate until the request set stops
	// growing — typical chains are 1–2 hops, so we converge fast.
	for {
		changed := false
		for _, decl := range t.helpersFile.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if !t.helpers[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				if !helperNames[id.Name] {
					return true
				}
				if !t.helpers[id.Name] {
					t.helpers[id.Name] = true
					changed = true
				}
				return true
			})
		}
		if !changed {
			break
		}
	}
	var out []ast.Decl
	for _, decl := range t.helpersFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		if !t.helpers[fn.Name.Name] {
			continue
		}
		// Resolve which stdlib packages this helper references.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "math":
				t.use("math")
			case "bits":
				t.use("math/bits")
			case "binary":
				t.use("encoding/binary")
			case "runtime":
				t.use("runtime")
			case "unsafe":
				t.use("unsafe")
			case "atomic":
				t.use("sync/atomic")
			case "time":
				t.use("time")
			case "bytes":
				t.use("bytes")
			case "sync":
				t.use("sync")
			}
			return true
		})
		// In multi-package mode helpers live in `base` and must be exported
		// to be callable from chunk packages. Rename the function, any
		// `m.memory`/`m.maxMem` field accesses, and any bare-name calls
		// to other helpers (e.g. i32_div_u_s → i32_div_u) in the body
		// to their capitalized form. The rewrite set also carries the wasmExc
		// TYPE name so the EH helpers (wasm_catch/wasm_throw) reference the
		// exported `WasmExc` in both their SIGNATURE and BODY — matching the
		// exported type decl emitted below and the base.WasmExc references the
		// chunk bodies use.
		if t.multiPackage {
			rewriteNames := make(map[string]bool, len(helperNames)+1)
			for k := range helperNames {
				rewriteNames[k] = true
			}
			rewriteNames["wasmExc"] = true
			// The threads types live in base and are exported there
			// (ThreadPool/WasiThreadStarter); helper bodies that name them
			// (threadSpawn's interface assertion, the pool methods) must
			// follow, or base won't compile.
			rewriteNames["threadPool"] = true
			rewriteNames["wasiThreadStarter"] = true
			renamed := *fn
			renamed.Name = newID(capitalize(fn.Name.Name))
			// Only rebuild the signature when it actually references a rewritten
			// name (e.g. wasm_catch returns *wasmExc). rewriteHelperNode emits
			// position-less nodes, which would displace any //go: directive
			// comment on the FuncDecl — so leave untouched signatures alone.
			if funcTypeRefsAny(fn.Type, rewriteNames) {
				renamed.Type = rewriteHelperNode(fn.Type, rewriteNames).(*ast.FuncType)
			}
			renamed.Body = rewriteHelperBody(fn.Body, rewriteNames)
			fn = &renamed
		}
		out = append(out, fn)
	}
	// spinRelax carries package-level state the function-only extraction
	// above cannot see: emit its Gosched rate-limit counter alongside it.
	// The name stays unexported even in multi-package mode — only the
	// helper itself is called cross-package, the counter is base-internal.
	if t.helpers["spinRelax"] {
		out = append(out, &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{&ast.ValueSpec{
				Names: []*ast.Ident{newID("spinRelaxColdCalls")},
				Type:  newID("uint32"),
			}},
		})
	}
	// The wasmExc type is not a FuncDecl, so pull it in explicitly whenever the
	// module throws or catches. In multi-package mode the type lives in base and
	// must be exported (WasmExc) so chunk packages can name it; single-package
	// keeps it unexported (wasmExc). Field names (Tag, Vals) are already
	// exported, so only the type name needs capitalizing.
	// Memory-bearing modules always carry the threads types: the Module struct
	// embeds threadPool (memSize/memShared/threads are declared together), and
	// threadSpawn asserts the module against wasiThreadStarter. Both are
	// zero-cost when the guest never spawns.
	if len(t.mod.Memories) > 0 {
		for _, decl := range t.helpersFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || (ts.Name.Name != "threadPool" && ts.Name.Name != "wasiThreadStarter") {
					continue
				}
				emitted := ts
				if t.multiPackage {
					renamed := *ts
					renamed.Name = newID(capitalize(ts.Name.Name))
					emitted = &renamed
				}
				out = append(out, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{emitted}})
			}
		}
		// threadPool's methods (wake) ride along with the type.
		for _, decl := range t.helpersFile.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok || id.Name != "threadPool" {
				continue
			}
			if t.multiPackage {
				// The receiver type was exported above; the methods must
				// follow it (and their bodies may name other helpers).
				renamed := *fn
				recv := *fn.Recv.List[0]
				recv.Type = &ast.StarExpr{X: newID("ThreadPool")}
				renamed.Recv = &ast.FieldList{List: []*ast.Field{&recv}}
				renamed.Body = rewriteHelperBody(fn.Body, map[string]bool{
					"threadPool": true, "wasiThreadStarter": true,
				})
				out = append(out, &renamed)
				continue
			}
			out = append(out, fn)
		}
	}
	if t.usesWasmExc {
		for _, decl := range t.helpersFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "wasmExc" {
					continue
				}
				emitted := ts
				if t.multiPackage {
					renamedTS := *ts
					renamedTS.Name = newID("WasmExc")
					emitted = &renamedTS
				}
				out = append(out, &ast.GenDecl{Tok: token.TYPE, Specs: []ast.Spec{emitted}})
			}
		}
	}
	// One stdlib scan over EVERYTHING emitHelpers emits — functions, type
	// decls, methods. The per-function scan above misses types: ThreadPool
	// carries atomic.Int32/sync.WaitGroup fields, and emitting it into base
	// without registering sync/atomic left the base package uncompilable
	// (the base import snapshot is taken before the Module struct's own
	// use() calls run).
	for _, decl := range out {
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "math":
				t.use("math")
			case "bits":
				t.use("math/bits")
			case "binary":
				t.use("encoding/binary")
			case "runtime":
				t.use("runtime")
			case "unsafe":
				t.use("unsafe")
			case "atomic":
				t.use("sync/atomic")
			case "time":
				t.use("time")
			case "sync":
				t.use("sync")
			}
			return true
		})
	}
	return out, nil
}

// funcTypeRefsAny reports whether a helper's signature (params/results)
// references any identifier in names — used to decide whether the signature
// must be rebuilt for multi-package export (which would otherwise strip
// position info from an otherwise-unchanged signature).
func funcTypeRefsAny(ft *ast.FuncType, names map[string]bool) bool {
	found := false
	ast.Inspect(ft, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

// capitalizeModuleFieldRefs rewrites `m.<lowercase>` selectors to
// `m.<Capitalized>` (only). Used by the native-wasi emission path which
// has no helper-to-helper calls; helper bodies from helpers.go go
// through rewriteHelperBody instead.
func capitalizeModuleFieldRefs(body *ast.BlockStmt) *ast.BlockStmt {
	return rewriteHelperBody(body, nil)
}

// rewriteHelperBody rewrites a helper body for multi-package output, IN
// PLACE: `m.<field>` selectors get exported field names, and bare identifiers
// in the rename set (helper functions, the wasmExc/threads types) get
// capitalized. A previous version hand-walked the AST node by node and
// silently skipped every node type it didn't enumerate — helpers using
// select/go/defer (the atomics wait/park helpers) kept lowercase references
// and broke the base package. ast.Inspect visits everything.
//
// Two passes: the first records every SelectorExpr.Sel identifier so the
// second never confuses a field/method selector with a bare name — `x.wake`
// must not become `x.Wake` just because a helper is named wake.
func rewriteHelperBody(body *ast.BlockStmt, helperNames map[string]bool) *ast.BlockStmt {
	rewriteHelperInPlace(body, helperNames)
	return body
}

// rewriteHelperNode applies the same rewrite to any node (used for helper
// signatures whose types name wasmExc etc.); returns the node for
// call-site convenience.
func rewriteHelperNode(n ast.Node, helperNames map[string]bool) ast.Node {
	rewriteHelperInPlace(n, helperNames)
	return n
}

func rewriteHelperInPlace(n ast.Node, helperNames map[string]bool) {
	if n == nil {
		return
	}
	sels := map[*ast.Ident]bool{}
	ast.Inspect(n, func(c ast.Node) bool {
		if se, ok := c.(*ast.SelectorExpr); ok {
			sels[se.Sel] = true
		}
		return true
	})
	ast.Inspect(n, func(c ast.Node) bool {
		switch v := c.(type) {
		case *ast.SelectorExpr:
			if id, ok := v.X.(*ast.Ident); ok && id.Name == "m" {
				if len(v.Sel.Name) > 0 && v.Sel.Name[0] >= 'a' && v.Sel.Name[0] <= 'z' {
					v.Sel.Name = capitalize(v.Sel.Name)
				}
			}
		case *ast.Ident:
			if !sels[v] && helperNames[v.Name] {
				v.Name = capitalize(v.Name)
			}
		}
		return true
	})
}
