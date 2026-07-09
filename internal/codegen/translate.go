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

	"github.com/goccy/wasm2go/internal/lower"
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
// Modify in-process via SetMultiPackageThreshold; from a subprocess
// (e.g. a wasm2go-using protoc plugin invoked by buf generate), set
// the WASM2GO_MULTIPACKAGE_THRESHOLD environment variable. The
// in-process override takes priority when both are set.
var multiPackageThresholdOverride = -1

// currentMultiPackageThreshold resolves the active byte budget. The
// in-process override wins; otherwise the env-var fallback is parsed;
// otherwise the production default is used.
func currentMultiPackageThreshold() int {
	if multiPackageThresholdOverride >= 0 {
		return multiPackageThresholdOverride
	}
	if env := os.Getenv("WASM2GO_MULTIPACKAGE_THRESHOLD"); env != "" {
		b, err := strconv.Atoi(env)
		if err != nil || b < 0 {
			// Malformed env var. Surface so the user sees why their
			// override was ignored, then fall back to the default.
			fmt.Fprintf(os.Stderr,
				"wasm2go: invalid WASM2GO_MULTIPACKAGE_THRESHOLD=%q (using default %d): %v\n",
				env, defaultMultiPackageThreshold, err)
		} else {
			return b
		}
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
	return finalizeSinglePkgWithAsm(m, opts, w, goBuf.Bytes(), t.sidecars, t.auxFiles)
}

// finalizeSinglePkgWithAsm is the asm-always-on tail of single-package
// Translate. It splits the Go source produced by the translator into
// a shared file (Module struct, helpers, exports, ...) — written to
// the caller's w — and a `<pkg>_pure.go` file holding the function
// bodies under `//go:build !amd64 && !arm64`. The asm bundle goes
// into Result.Files. On asm-target GOARCHs the pure file is dormant
// and the asm bodies in `<pkg>/amd64.s` (and arm64.s) take over.
func finalizeSinglePkgWithAsm(m *wasm.Module, opts Options, w io.Writer, goSrc []byte, sidecars map[string][]byte, auxFiles map[string][]byte) (Result, error) {
	shared, fallback, err := splitForAsm(goSrc, opts.Package)
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

	// helpersFile is parsed lazily by emitHelpers.
	helpersFile *ast.File

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
	return capitalize(MangleID(imp.Name))
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

// use marks a stdlib package as needed by the output.
func (t *translator) use(pkg string) { t.imports[pkg] = "" }

// useHelper marks a helper as needed.
func (t *translator) useHelper(name string) { t.helpers[name] = true }

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
	// Group imports by module name.
	byMod := map[string][]wasm.Import{}
	for _, imp := range t.mod.Imports {
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
		fields = append(fields, &ast.Field{
			Names: []*ast.Ident{newID(t.fieldName("memMu"))},
			Type:  &ast.SelectorExpr{X: newID("sync"), Sel: newID("Mutex")},
		})
		t.use("sync")
	}

	return &ast.GenDecl{
		Tok: token.TYPE,
		Specs: []ast.Spec{&ast.TypeSpec{
			Name: newID("Module"),
			Type: &ast.StructType{Fields: &ast.FieldList{List: fields}},
		}},
	}
}

// emitNewFuncs is the underlying constructor emitter; see emitNewFunc.
func (t *translator) emitNewFuncs() []ast.Decl {
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
	if emitReserve {
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
		// wasm32 caps linear memory at 65536 pages × 64 KiB = 4 GiB.
		// A malformed module that declares a Min larger than this
		// would otherwise have us emit `make([]byte, huge)` and
		// either panic at init time or quietly succeed and OOM.
		const wasm32MaxPages = 1 << 16
		if mem.Limits.Min > wasm32MaxPages {
			return []ast.Decl{&ast.FuncDecl{
				Name: newID("New"),
				Type: &ast.FuncType{Params: &ast.FieldList{List: params},
					Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}}},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
						stringLit(fmt.Sprintf("wasm2go: memory min %d exceeds wasm32 maximum (%d) pages", mem.Limits.Min, wasm32MaxPages)),
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
		body.List = append(body.List, &ast.AssignStmt{
			Tok: token.ASSIGN,
			Lhs: []ast.Expr{t.fieldRef("memory")},
			Rhs: []ast.Expr{&ast.CallExpr{
				Fun: newID("make"),
				Args: []ast.Expr{
					&ast.ArrayType{Elt: newID("byte")},
					uintLit(minBytesU),
					capArg,
				},
			}},
		})
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
			if mem.Limits.Max > wasm32MaxPages {
				return []ast.Decl{&ast.FuncDecl{
					Name: newID("New"),
					Type: &ast.FuncType{Params: &ast.FieldList{List: params},
						Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}}},
					Body: &ast.BlockStmt{List: []ast.Stmt{
						&ast.ExprStmt{X: &ast.CallExpr{Fun: newID("panic"), Args: []ast.Expr{
							stringLit(fmt.Sprintf("wasm2go: memory max %d exceeds wasm32 maximum (%d) pages", mem.Limits.Max, wasm32MaxPages)),
						}}},
					}},
				}}
			}
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{t.fieldRef("maxMem")},
				Rhs: []ast.Expr{uintLit(mem.Limits.Max * 65536)},
			})
		} else {
			// 4 GiB default cap (wasm32 limit).
			body.List = append(body.List, &ast.AssignStmt{
				Tok: token.ASSIGN,
				Lhs: []ast.Expr{t.fieldRef("maxMem")},
				Rhs: []ast.Expr{uintLit(1 << 32)},
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
			if fv == 0 {
				continue // zero value already correct
			}
			// NaN/Inf initializers route through math.Float*frombits, so
			// the math import must be registered for the emitted file.
			if math.IsNaN(fv) || math.IsInf(fv, 0) {
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
		if err := t.emitShardedElementInit(body); err != nil {
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
			t.elemInitChunks = append(t.elemInitChunks, chunkDecls...)
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
			off, err := evalConstExprI64(ds.Offset, t.mod)
			if err != nil {
				body.List = append(body.List, &ast.ExprStmt{X: &ast.CallExpr{
					Fun:  newID("panic"),
					Args: []ast.Expr{stringLit(fmt.Sprintf("data[%d] offset: %v", i, err))},
				}})
				continue
			}
			raws = append(raws, rawSeg{memOff: off, bytes: ds.Bytes})
		}
		sort.Slice(raws, func(i, j int) bool { return raws[i].memOff < raws[j].memOff })
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

	body.List = append(body.List, &ast.ReturnStmt{Results: []ast.Expr{newID("m")}})

	primary := &ast.FuncDecl{
		Name: newID(primaryName),
		Type: &ast.FuncType{
			Params:  &ast.FieldList{List: params},
			Results: &ast.FieldList{List: []*ast.Field{{Type: t.moduleType()}}},
		},
		Body: body,
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
	out := []ast.Decl{&ast.FuncDecl{
		Name: newID(fnName),
		Type: t.funcSignature(ft, true /*withModuleParam*/),
		Body: body,
	}}
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
func (t *translator) compileBodyViaSSA(funcIdx uint32, fn wasm.Function) (*ast.BlockStmt, error) {
	_ = fn // body bytes live on the *wasm.Module; kept for API symmetry.
	ssaFn, err := lower.LowerFunction(t.mod, funcIdx, t.funcName(funcIdx))
	if err != nil {
		return nil, err
	}
	insBefore := ssa.CountValues(ssaFn)
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
		if pass.Simplify(ssaFn) {
			changed = true
		}
		if pass.CSE(ssaFn) {
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
	ssa.Compact(ssaFn)
	insAfter := ssa.CountValues(ssaFn)
	// A pass bug that produced a malformed CFG must not reach emit;
	// surface the verify failure so the SSA bug is fixed at its source.
	if err := ssa.Verify(ssaFn); err != nil {
		return nil, fmt.Errorf("%w: post-opt verify: %w", lower.ErrSSAUnsupported, err)
	}
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
func (t *translator) emitShardedElementInit(initBody *ast.BlockStmt) error {
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
			t.addChunkExtraDecl(ck, &ast.FuncDecl{
				Name: newID(helperName),
				Type: helperSig,
				Body: helperBody,
			})
			t.currentChunk = prev

			// Main: register linkname forward + emit call.
			t.registerLinknameSymbol(-1, helperName, ck, helperSig)
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
	ifBody.List = append(ifBody.List, &ast.AssignStmt{
		Tok: token.ASSIGN,
		Lhs: []ast.Expr{newID("err")},
		Rhs: []ast.Expr{&ast.CallExpr{
			Fun:  &ast.SelectorExpr{X: newID("fmt"), Sel: newID("Errorf")},
			Args: []ast.Expr{stringLit("wasm trap: %v"), newID("r")},
		}},
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
	params := &ast.FieldList{List: []*ast.Field{
		{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()},
		{Names: []*ast.Ident{newID("l0"), newID("l1")}, Type: newID("int32")},
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
	// The wasmExc type is not a FuncDecl, so pull it in explicitly whenever the
	// module throws or catches. In multi-package mode the type lives in base and
	// must be exported (WasmExc) so chunk packages can name it; single-package
	// keeps it unexported (wasmExc). Field names (Tag, Vals) are already
	// exported, so only the type name needs capitalizing.
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

// rewriteHelperBody rewrites a helper-function body for emission in
// multi-package mode. Two changes are applied recursively across the
// AST:
//
//  1. `m.<lowercase>` selectors become `m.<Capitalized>` so helper code
//     keeps referencing the (now-exported) Module fields.
//  2. Bare-ident calls whose name matches another helper get
//     capitalized (e.g. i32_div_u_s's body calls i32_div_u → I32_div_u)
//     so the helper-to-helper edges resolve inside the base package.
//
// Returns a fresh AST so the shared helpersFile isn't mutated across
// calls.
func rewriteHelperBody(body *ast.BlockStmt, helperNames map[string]bool) *ast.BlockStmt {
	return rewriteHelperNode(body, helperNames).(*ast.BlockStmt)
}

// rewriteHelperNode is the recursive worker for rewriteHelperBody.
func rewriteHelperNode(n ast.Node, helperNames map[string]bool) ast.Node {
	if n == nil {
		return nil
	}
	switch v := n.(type) {
	case *ast.Ident:
		// Bare ident inside an expression — capitalize iff it's a
		// helper name. (Call sites are handled in CallExpr below, but
		// helpers may also pass other helpers as values; treat both.)
		if helperNames[v.Name] {
			return newID(capitalize(v.Name))
		}
		return v
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok && id.Name == "m" {
			if len(v.Sel.Name) > 0 && v.Sel.Name[0] >= 'a' && v.Sel.Name[0] <= 'z' {
				return &ast.SelectorExpr{X: id, Sel: newID(capitalize(v.Sel.Name))}
			}
		}
		return &ast.SelectorExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr), Sel: v.Sel}
	case *ast.CallExpr:
		// Recurse into Fun so a bare-ident helper call gets renamed.
		fun := rewriteHelperNode(v.Fun, helperNames).(ast.Expr)
		args := make([]ast.Expr, len(v.Args))
		for i, a := range v.Args {
			args[i] = rewriteHelperNode(a, helperNames).(ast.Expr)
		}
		return &ast.CallExpr{Fun: fun, Args: args, Ellipsis: v.Ellipsis}
	case *ast.IndexExpr:
		return &ast.IndexExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr), Index: rewriteHelperNode(v.Index, helperNames).(ast.Expr)}
	case *ast.SliceExpr:
		out := &ast.SliceExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr), Slice3: v.Slice3}
		if v.Low != nil {
			out.Low = rewriteHelperNode(v.Low, helperNames).(ast.Expr)
		}
		if v.High != nil {
			out.High = rewriteHelperNode(v.High, helperNames).(ast.Expr)
		}
		if v.Max != nil {
			out.Max = rewriteHelperNode(v.Max, helperNames).(ast.Expr)
		}
		return out
	case *ast.BinaryExpr:
		return &ast.BinaryExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr), Op: v.Op, Y: rewriteHelperNode(v.Y, helperNames).(ast.Expr)}
	case *ast.UnaryExpr:
		return &ast.UnaryExpr{Op: v.Op, X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
	case *ast.ParenExpr:
		return &ast.ParenExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
	case *ast.AssignStmt:
		out := &ast.AssignStmt{Tok: v.Tok, Lhs: make([]ast.Expr, len(v.Lhs)), Rhs: make([]ast.Expr, len(v.Rhs))}
		for i, e := range v.Lhs {
			out.Lhs[i] = rewriteHelperNode(e, helperNames).(ast.Expr)
		}
		for i, e := range v.Rhs {
			out.Rhs[i] = rewriteHelperNode(e, helperNames).(ast.Expr)
		}
		return out
	case *ast.ExprStmt:
		return &ast.ExprStmt{X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
	case *ast.ReturnStmt:
		out := &ast.ReturnStmt{Results: make([]ast.Expr, len(v.Results))}
		for i, e := range v.Results {
			out.Results[i] = rewriteHelperNode(e, helperNames).(ast.Expr)
		}
		return out
	case *ast.IfStmt:
		out := &ast.IfStmt{Cond: rewriteHelperNode(v.Cond, helperNames).(ast.Expr)}
		if v.Init != nil {
			out.Init = rewriteHelperNode(v.Init, helperNames).(ast.Stmt)
		}
		out.Body = rewriteHelperNode(v.Body, helperNames).(*ast.BlockStmt)
		if v.Else != nil {
			out.Else = rewriteHelperNode(v.Else, helperNames).(ast.Stmt)
		}
		return out
	case *ast.ForStmt:
		out := &ast.ForStmt{Body: rewriteHelperNode(v.Body, helperNames).(*ast.BlockStmt)}
		if v.Init != nil {
			out.Init = rewriteHelperNode(v.Init, helperNames).(ast.Stmt)
		}
		if v.Cond != nil {
			out.Cond = rewriteHelperNode(v.Cond, helperNames).(ast.Expr)
		}
		if v.Post != nil {
			out.Post = rewriteHelperNode(v.Post, helperNames).(ast.Stmt)
		}
		return out
	case *ast.RangeStmt:
		out := &ast.RangeStmt{
			Tok:  v.Tok,
			X:    rewriteHelperNode(v.X, helperNames).(ast.Expr),
			Body: rewriteHelperNode(v.Body, helperNames).(*ast.BlockStmt),
		}
		if v.Key != nil {
			out.Key = rewriteHelperNode(v.Key, helperNames).(ast.Expr)
		}
		if v.Value != nil {
			out.Value = rewriteHelperNode(v.Value, helperNames).(ast.Expr)
		}
		return out
	case *ast.BlockStmt:
		out := &ast.BlockStmt{List: make([]ast.Stmt, len(v.List))}
		for i, s := range v.List {
			out.List[i] = rewriteHelperNode(s, helperNames).(ast.Stmt)
		}
		return out
	case *ast.IncDecStmt:
		return &ast.IncDecStmt{Tok: v.Tok, X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
	case *ast.DeclStmt:
		return v
	case *ast.SwitchStmt:
		out := &ast.SwitchStmt{Body: rewriteHelperNode(v.Body, helperNames).(*ast.BlockStmt)}
		if v.Init != nil {
			out.Init = rewriteHelperNode(v.Init, helperNames).(ast.Stmt)
		}
		if v.Tag != nil {
			out.Tag = rewriteHelperNode(v.Tag, helperNames).(ast.Expr)
		}
		return out
	case *ast.CaseClause:
		out := &ast.CaseClause{Body: make([]ast.Stmt, len(v.Body))}
		if v.List != nil {
			out.List = make([]ast.Expr, len(v.List))
			for i, e := range v.List {
				out.List[i] = rewriteHelperNode(e, helperNames).(ast.Expr)
			}
		}
		for i, s := range v.Body {
			out.Body[i] = rewriteHelperNode(s, helperNames).(ast.Stmt)
		}
		return out
	case *ast.TypeAssertExpr:
		out := &ast.TypeAssertExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
		if v.Type != nil {
			out.Type = rewriteHelperNode(v.Type, helperNames).(ast.Expr)
		}
		return out
	case *ast.DeferStmt:
		return &ast.DeferStmt{Call: rewriteHelperNode(v.Call, helperNames).(*ast.CallExpr)}
	case *ast.BranchStmt:
		return v
	case *ast.LabeledStmt:
		return &ast.LabeledStmt{Label: v.Label, Stmt: rewriteHelperNode(v.Stmt, helperNames).(ast.Stmt)}
	case *ast.StarExpr:
		return &ast.StarExpr{X: rewriteHelperNode(v.X, helperNames).(ast.Expr)}
	case *ast.CompositeLit:
		out := &ast.CompositeLit{Elts: make([]ast.Expr, len(v.Elts))}
		if v.Type != nil {
			out.Type = rewriteHelperNode(v.Type, helperNames).(ast.Expr)
		}
		for i, e := range v.Elts {
			out.Elts[i] = rewriteHelperNode(e, helperNames).(ast.Expr)
		}
		return out
	case *ast.KeyValueExpr:
		return &ast.KeyValueExpr{Key: rewriteHelperNode(v.Key, helperNames).(ast.Expr), Value: rewriteHelperNode(v.Value, helperNames).(ast.Expr)}
	case *ast.Ellipsis:
		out := &ast.Ellipsis{}
		if v.Elt != nil {
			out.Elt = rewriteHelperNode(v.Elt, helperNames).(ast.Expr)
		}
		return out
	case *ast.FuncType:
		// Rewrite parameter/result type references (e.g. a helper whose
		// signature names wasmExc) so a renamed type stays consistent between
		// the declaration and its uses. Params/Results are FieldLists.
		out := &ast.FuncType{}
		if v.Params != nil {
			out.Params = rewriteHelperNode(v.Params, helperNames).(*ast.FieldList)
		}
		if v.Results != nil {
			out.Results = rewriteHelperNode(v.Results, helperNames).(*ast.FieldList)
		}
		return out
	case *ast.FieldList:
		out := &ast.FieldList{List: make([]*ast.Field, len(v.List))}
		for i, f := range v.List {
			out.List[i] = rewriteHelperNode(f, helperNames).(*ast.Field)
		}
		return out
	case *ast.Field:
		out := &ast.Field{Names: v.Names, Tag: v.Tag}
		if v.Type != nil {
			out.Type = rewriteHelperNode(v.Type, helperNames).(ast.Expr)
		}
		return out
	}
	return n
}
