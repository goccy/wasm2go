package asmgen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// BuildPackageOptions parameterises BuildPackageFiles.
//
// Single-package use only needs Package + optional FuncSymbol. The
// remaining fields wire the multi-package + linkname-split layout the
// codegen translator emits for large wasm modules: emit one
// BuildPackageFiles call per chunk (using FuncIdxs to restrict which
// wasm functions land in the chunk), set MultiPackage so the
// chunk's decls reference *base.Module + the helpers route to
// base·X*(SB), and set SkipWrappers so the dispatch wrappers
// (callImport_N, loadGlobal_N, ...) aren't duplicated per chunk —
// the caller emits them once into base via BuildWrappers.
type BuildPackageOptions struct {
	Package string
	// FuncSymbol returns the Go-side qualified name for a wasm
	// function index, as it should appear at a call site within
	// THIS package's asm. Same-package callees → bare "Fn<idx>";
	// cross-chunk callees in multi-package mode → "p3.Fn42". nil
	// defaults to "export-name when present, Fn<idx> otherwise"
	// (single-package convention).
	FuncSymbol func(funcIdx uint32) string

	// FuncIdxs restricts emission to the listed wasm function
	// indices. nil means "every defined function in mod". The
	// multi-package driver supplies the per-chunk slice from the
	// codegen plan.
	FuncIdxs []uint32

	// MultiPackage selects between the single-package and the
	// multi-package + linkname-split layouts the codegen
	// translator produces. Setting this affects:
	//   - decls reference *base.Module instead of *Module
	//   - helper CALLs route to base·X*(SB) instead of ·name(SB)
	//   - wrapper bodies reference capitalised Module fields
	MultiPackage bool

	// BasePkgImport is the import path of the base package
	// (e.g. "example.com/mymod/base"). Required when MultiPackage
	// is true; the chunk-side decl file uses it in its import
	// block so `*base.Module` resolves.
	BasePkgImport string

	// SkipWrappers, when true, omits the wrappers.go entry from
	// the returned file map. In multi-package mode the caller
	// emits wrappers separately into base via BuildWrappers; each
	// chunk does NOT carry its own copy.
	SkipWrappers bool
}

// BuildPackageFiles produces the complete asm bundle for one Go
// package containing the wasm module's defined functions. The
// output is a map from filename → file content; the caller writes
// each entry into the package's directory alongside the existing
// Go fallback source (which the codegen translator produces).
//
// The bundle consists of:
//   - decls_amd64.go / decls_arm64.go: function declarations (no
//     bodies), build-tagged per-arch
//   - amd64.s / arm64.s: plan9 asm bodies, same tags
//   - wrappers.go: Go-side dispatch wrappers for OpCallImport,
//     OpGlobalGet/Set, OpCallIndirect, OpMemSize/Grow/Copy/Fill,
//     gated `//go:build amd64 || arm64`
//
// Functions whose ops the emitter doesn't yet support produce a
// Go-source panic stub (in a stubs file with the same build tag as
// the decls) — this matches the test driver's behavior and lets the
// package still compile end-to-end even when not every wasm op is
// covered.
//
// Naming conventions are the single-package codegen-translator
// defaults: lowercase Module field names ("memory", "g0", "t0",
// "<modName>"), lowercase function names except for the M field
// (which the translator pins as uppercase by convention).
func BuildPackageFiles(mod *wasm.Module, opts BuildPackageOptions) (map[string]string, error) {
	if opts.Package == "" {
		return nil, fmt.Errorf("BuildPackageOptions.Package is required")
	}
	if opts.MultiPackage && opts.BasePkgImport == "" {
		return nil, fmt.Errorf("MultiPackage=true requires BasePkgImport")
	}
	pkg := opts.Package

	// Default name resolver: export name if exported, else Fn<idx>.
	exportNames := map[uint32]string{}
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc {
			exportNames[e.Index] = e.Name
		}
	}
	funcSymbol := opts.FuncSymbol
	if funcSymbol == nil {
		funcSymbol = func(idx uint32) string {
			if n, ok := exportNames[idx]; ok {
				return n
			}
			return fmt.Sprintf("Fn%d", idx)
		}
	}

	// Build the wasm function index set this call emits. nil
	// FuncIdxs means "all defined functions" (single-package). A
	// non-nil slice restricts emission to one chunk.
	include := map[uint32]bool{}
	if opts.FuncIdxs == nil {
		for i := range mod.Functions {
			include[mod.NumImportedFuncs+uint32(i)] = true
		}
	} else {
		for _, idx := range opts.FuncIdxs {
			include[idx] = true
		}
	}

	modulePkgRef := "*Module"
	helperPrefix := ""
	if opts.MultiPackage {
		modulePkgRef = "*base.Module"
		helperPrefix = "base"
	}

	// Per-target accumulators.
	type target struct {
		archName string
		emit     func(name string, sig wasm.FuncType, f *ssa.Func, fo FuncOptions) (string, string, error)
		buildTag string
		asmBuf   strings.Builder
		declBuf  strings.Builder
		stubBuf  strings.Builder
	}
	targets := []*target{
		{archName: "amd64", emit: EmitFuncAMD64, buildTag: "//go:build amd64"},
		{archName: "arm64", emit: EmitFuncARM64, buildTag: "//go:build arm64"},
	}

	// Aggregate the wrapper-emission decisions: which OpCallIndirect
	// type indices appear, whether mem.size/grow/copy/fill are used.
	indirectTypes := map[uint32]bool{}
	useMemSize := false
	useMemGrow := false
	useMemoryCopy := false
	useMemoryFill := false
	// Collect codegen-emitted helpers (i32_eqz, f32_add, etc.) the
	// chunk asm CALLs. In multi-package mode each chunk gets a
	// //go:linkname trampoline per used helper because asm can't
	// CALL into base directly.
	helpersUsed := map[string]bool{}

	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		if !include[idx] {
			continue
		}
		// The local name (TEXT directive + Go decl) for an own
		// chunk function. The funcSymbol callback returns the
		// *callee* name as it appears at a call site in this
		// package — for the own chunk that is just the bare name
		// (no "pkg." prefix). The multi-package driver is
		// responsible for picking funcSymbol such that own-chunk
		// callees return bare and cross-chunk ones return "pX.Fn42".
		localName := funcSymbol(idx)
		if dot := strings.IndexByte(localName, '.'); dot >= 0 {
			// Defensive: a caller's funcSymbol shouldn't return a
			// dotted name for an own-chunk function, but if it
			// does, take the last segment.
			localName = localName[dot+1:]
		}
		fn, err := lower.LowerFunction(mod, idx, localName)
		if err != nil {
			return nil, fmt.Errorf("lower %s (fn%d): %w", localName, idx, err)
		}
		sig := mod.FuncTypeOf(idx)
		// Collect cross-cutting wrapper requirements while the SSA is
		// in hand.
		for _, blk := range fn.Blocks {
			for _, v := range blk.Values {
				switch v.Op {
				case ssa.OpCallIndirect:
					indirectTypes[uint32(v.AuxInt)] = true
				case ssa.OpMemSize:
					useMemSize = true
				case ssa.OpMemGrow:
					useMemGrow = true
				case ssa.OpMemoryCopy:
					useMemoryCopy = true
				case ssa.OpMemoryFill:
					useMemoryFill = true
				case ssa.OpHelperCall:
					if name, ok := v.Aux.(string); ok {
						helpersUsed[name] = true
					}
				}
			}
		}

		for _, t := range targets {
			asm, decl, err := t.emit(localName, sig, fn, FuncOptions{
				ModulePkgRef: modulePkgRef,
				HelperPrefix: helperPrefix,
				Module:       mod,
				FuncSymbol:   funcSymbol,
			})
			if err != nil {
				fmt.Fprintf(&t.stubBuf, "func %s%s { panic(%q) }\n",
					localName, goSignature(sig, modulePkgRef), "asm stub: "+localName)
				continue
			}
			t.asmBuf.WriteString(asm)
			t.declBuf.WriteString(decl)
		}
	}

	// Decls files import base when in multi-package mode so
	// *base.Module resolves. Single-package decls need no imports.
	declImport := ""
	if opts.MultiPackage {
		declImport = fmt.Sprintf("\nimport base %q\n", opts.BasePkgImport)
	}

	files := map[string]string{}
	// Decls collapse: if every target emitted the same decl block
	// (no per-arch stubs needed), write a single shared decls.go
	// gated on the union of arch tags. The bare declarations are
	// arch-independent (they're just `func FnN(...) ret`); only the
	// asm bodies differ. When one arch needed stubs, the union is
	// no longer safe (the stubs file owns the FnN symbol on that
	// arch), so we fall back to the per-arch decls_<arch>.go layout.
	declsAreUniform := func() bool {
		if len(targets) < 2 {
			return false
		}
		base := targets[0].declBuf.String()
		for _, t := range targets[1:] {
			if t.declBuf.String() != base {
				return false
			}
			if t.stubBuf.Len() != 0 {
				return false
			}
		}
		return targets[0].stubBuf.Len() == 0
	}
	if declsAreUniform() && targets[0].declBuf.Len() > 0 {
		tagsOR := make([]string, len(targets))
		for i, t := range targets {
			tagsOR[i] = t.archName
		}
		buildTag := "//go:build " + strings.Join(tagsOR, " || ")
		head := fmt.Sprintf("%s\n\npackage %s\n%s\n", buildTag, pkg, declImport)
		files["decls.go"] = head + targets[0].declBuf.String()
	}
	for _, t := range targets {
		head := fmt.Sprintf("%s\n\npackage %s\n%s\n", t.buildTag, pkg, declImport)
		if _, ok := files["decls.go"]; !ok {
			if t.declBuf.Len() > 0 {
				files["decls_"+t.archName+".go"] = head + t.declBuf.String()
			}
		}
		if t.asmBuf.Len() > 0 {
			asmHead := fmt.Sprintf("%s\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n", t.buildTag)
			files[t.archName+".s"] = asmHead + t.asmBuf.String()
		}
		if t.stubBuf.Len() > 0 {
			files["stubs_"+t.archName+".go"] = head + t.stubBuf.String()
		}
	}

	// Wrappers — emitted alongside the decls in single-package
	// mode, or skipped here when the multi-package caller will
	// emit them into base via BuildWrappers.
	if !opts.SkipWrappers {
		wrappers := buildWrappers(mod, indirectTypes, useMemSize, useMemGrow, useMemoryCopy, useMemoryFill, opts.MultiPackage, modulePkgRef)
		if wrappers != "" {
			head := fmt.Sprintf("//go:build amd64 || arm64\n\npackage %s\n", pkg)
			if opts.MultiPackage {
				head += fmt.Sprintf("\nimport base %q\n", opts.BasePkgImport)
			}
			files["wrappers.go"] = head + "\n" + wrappers
		}
	}

	// Trampolines for codegen-emitted helpers used by the asm bodies
	// (i32_eqz, divs64, memorySize, memoryCopy, ...). In multi-
	// package mode the canonical implementations live in `base`,
	// but plan9 asm CALL cannot cross package boundaries in user
	// code, so each chunk gets a local //go:linkname stub per
	// helper it actually uses. Single-package mode doesn't need
	// the trampoline — the helpers live in the same package.
	if opts.MultiPackage && opts.BasePkgImport != "" {
		// memorySize/memoryGrow/memoryCopy/memoryFill aren't in
		// helperSigs (they have their own signatures); thread the
		// usage flags through so the trampoline file picks them up.
		memHelpers := map[string]bool{}
		if useMemSize {
			memHelpers["memorySize"] = true
		}
		if useMemGrow {
			memHelpers["memoryGrow"] = true
		}
		if useMemoryCopy {
			memHelpers["memoryCopy"] = true
		}
		if useMemoryFill {
			memHelpers["memoryFill"] = true
		}
		tramp := buildHelperTrampolines(helpersUsed, memHelpers, opts.BasePkgImport)
		if tramp != "" {
			baseImport := ""
			if len(memHelpers) > 0 {
				// memHelpers' signatures reference *base.Module.
				baseImport = fmt.Sprintf("\nimport base %q\n", opts.BasePkgImport)
			}
			files["helpers_trampolines.go"] = fmt.Sprintf("//go:build amd64 || arm64\n\npackage %s\n\nimport _ %q\n%s\n%s", pkg, "unsafe", baseImport, tramp)
		}
	}
	return files, nil
}

// buildHelperTrampolines emits one //go:linkname-aliased local
// trampoline per codegen helper the chunk's asm references. Each
// trampoline forwards to the canonical implementation in base, e.g.
//
//	//go:linkname _xI32_eqz <basePath>.I32_eqz
//	func _xI32_eqz(x int32) int32
//	func i32_eqz(x int32) int32 { return _xI32_eqz(x) }
//
// The asm CALLs `·i32_eqz(SB)` which resolves locally to the
// trampoline, and the trampoline jumps to the linkname-aliased
// remote target. Mem helpers (memorySize, memoryCopy, memoryFill,
// memoryGrow) use their own signatures and are wired the same way.
func buildHelperTrampolines(helpersUsed, memHelpers map[string]bool, basePath string) string {
	if len(helpersUsed) == 0 && len(memHelpers) == 0 {
		return ""
	}
	names := make([]string, 0, len(helpersUsed)+len(memHelpers))
	for n := range helpersUsed {
		names = append(names, n)
	}
	for n := range memHelpers {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		exportedName := capitalizeHelperName(name)
		linkTarget := fmt.Sprintf("%s.%s", basePath, exportedName)
		hidden := "_x" + exportedName
		var params, results, callArgs string
		if memHelpers[name] {
			params, results, callArgs = helperMemSignature(name)
		} else {
			spec, ok := helperSig(name)
			if !ok {
				continue
			}
			params, results, callArgs = helperGoSignature(spec)
		}
		fmt.Fprintf(&b, "//go:linkname %s %s\n", hidden, linkTarget)
		fmt.Fprintf(&b, "func %s%s%s\n", hidden, params, results)
		// Trampoline body: forward to the linkname-aliased helper.
		if results == "" {
			fmt.Fprintf(&b, "func %s%s%s { %s(%s) }\n\n", name, params, results, hidden, callArgs)
		} else {
			fmt.Fprintf(&b, "func %s%s%s { return %s(%s) }\n\n", name, params, results, hidden, callArgs)
		}
	}
	return b.String()
}

// helperGoSignature renders the Go-source parameter list, results,
// and forwarding-call argument list for a helperSig entry. The
// shapes are independent of arch.
func helperGoSignature(spec helperSpec) (params, results, callArgs string) {
	var pb, ab strings.Builder
	pb.WriteByte('(')
	for i, t := range spec.params {
		if i > 0 {
			pb.WriteString(", ")
			ab.WriteString(", ")
		}
		fmt.Fprintf(&pb, "x%d %s", i, helperTypeName(t))
		fmt.Fprintf(&ab, "x%d", i)
	}
	pb.WriteByte(')')
	r := ""
	if spec.ret != ssa.TypeInvalid {
		r = " " + helperTypeName(spec.ret)
	}
	return pb.String(), r, ab.String()
}

// helperMemSignature returns the parameter list / result / forward
// call args for the memorySize / memoryGrow / memoryCopy /
// memoryFill helpers. These don't go through helperSig because
// their signatures include the *base.Module receiver, which the
// generic helperSpec doesn't model.
func helperMemSignature(name string) (params, results, callArgs string) {
	switch name {
	case "memorySize":
		return "(m *base.Module)", " int32", "m"
	case "memoryGrow":
		return "(m *base.Module, n int32)", " int32", "m, n"
	case "memoryCopy":
		return "(m *base.Module, dst int32, src int32, n int32)", "", "m, dst, src, n"
	case "memoryFill":
		return "(m *base.Module, dst int32, val int32, n int32)", "", "m, dst, val, n"
	}
	return "()", "", ""
}

// helperTypeName maps an ssa.Type to the Go-source type name used
// in helper signatures.
func helperTypeName(t ssa.Type) string {
	switch t {
	case ssa.TypeI32:
		return "int32"
	case ssa.TypeI64:
		return "int64"
	case ssa.TypeF32:
		return "float32"
	case ssa.TypeF64:
		return "float64"
	}
	return "<?>"
}

// BuildWrappers emits the Go-source dispatch wrappers for an entire
// wasm module as a single file body. Used by the multi-package
// driver to place all wrappers into base/ once, regardless of how
// many chunks reference them. multiPackage selects between
// lowercase (single-package codegen convention) and capitalised
// (multi-package, cross-package-visible) Module field names.
//
// The returned string is the file body only — no package header,
// build tags, or imports. Caller composes it with the rest.
func BuildWrappers(mod *wasm.Module, multiPackage bool) string {
	indirectTypes := map[uint32]bool{}
	useMemSize := false
	useMemGrow := false
	useMemoryCopy := false
	useMemoryFill := false
	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		fn, err := lower.LowerFunction(mod, idx, "")
		if err != nil {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, v := range blk.Values {
				switch v.Op {
				case ssa.OpCallIndirect:
					indirectTypes[uint32(v.AuxInt)] = true
				case ssa.OpMemSize:
					useMemSize = true
				case ssa.OpMemGrow:
					useMemGrow = true
				case ssa.OpMemoryCopy:
					useMemoryCopy = true
				case ssa.OpMemoryFill:
					useMemoryFill = true
				}
			}
		}
	}
	modulePkgRef := "*Module"
	if multiPackage {
		modulePkgRef = "*Module" // BuildWrappers is invoked when wrappers live in base, where the type is just Module
	}
	return buildWrappers(mod, indirectTypes, useMemSize, useMemGrow, useMemoryCopy, useMemoryFill, multiPackage, modulePkgRef)
}

// buildWrappers renders all the Go-side dispatch wrappers the asm
// bodies CALL. The set is computed from what the SSA actually uses:
//   - one callImport_<funcIdx> per ImportFunc actually referenced
//     (we emit all of them — they're cheap, and the linker drops
//     unused ones from the final binary anyway);
//   - one loadGlobal_<idx> / storeGlobal_<idx> pair per defined
//     global;
//   - one callIndirect_type<typeIdx> per wasm type that appears in
//     an OpCallIndirect anywhere in the module;
//   - memSize / memGrow / memoryCopy / memoryFill iff used.
func buildWrappers(mod *wasm.Module, indirectTypes map[uint32]bool, useMemSize, useMemGrow, useMemoryCopy, useMemoryFill, multiPackage bool, modulePkgRef string) string {
	var b strings.Builder

	// Field-name helper: codegen lowercases struct fields in
	// single-package mode (where Module is package-private) and
	// capitalises them in multi-package mode (where chunks across
	// packages must read the same struct).
	fieldName := func(s string) string {
		if multiPackage {
			return capitalizeExported(s)
		}
		return s
	}
	memoryField := fieldName("memory")
	maxMemField := fieldName("maxMem")

	// Wrapper function names stay lowercase — every chunk now
	// carries its own copy of these wrappers (SkipWrappers=false
	// for multi-package), so they don't need cross-package
	// visibility. The asm side CALLs `·callImport_0(SB)` and
	// similar same-package symbols.
	wname := func(s string) string { return s }
	_ = multiPackage

	// --- callImport_N ---
	var fIdx uint32
	for _, imp := range mod.Imports {
		if imp.Kind != wasm.ImportFunc {
			continue
		}
		sig := mod.Types[imp.TypeIdx]
		fmt.Fprintf(&b, "func %s", wname(fmt.Sprintf("callImport_%d", fIdx)))
		b.WriteString(goSignature(sig, modulePkgRef))
		b.WriteString(" {\n\t")
		if len(sig.Results) > 0 {
			b.WriteString("return ")
		}
		method := capitalizeExported(imp.Name)
		modField := fieldName(imp.Module)
		fmt.Fprintf(&b, "m.%s.%s(m", modField, method)
		for i := range sig.Params {
			fmt.Fprintf(&b, ", l%d", i)
		}
		b.WriteString(")\n}\n\n")
		fIdx++
	}

	// --- loadGlobal_N / storeGlobal_N ---
	for i := range mod.Globals {
		idx := mod.NumImportedGlobals + uint32(i)
		g := mod.Globals[i]
		gt := goTypeName(g.Type.Type)
		gField := fieldName(fmt.Sprintf("g%d", idx))
		fmt.Fprintf(&b, "func %s(m %s) %s { return m.%s }\n", wname(fmt.Sprintf("loadGlobal_%d", idx)), modulePkgRef, gt, gField)
		fmt.Fprintf(&b, "func %s(m %s, v %s) { m.%s = v }\n\n", wname(fmt.Sprintf("storeGlobal_%d", idx)), modulePkgRef, gt, gField)
	}

	// --- callIndirect_typeN ---
	if len(indirectTypes) > 0 {
		var keys []uint32
		for k := range indirectTypes {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, tIdx := range keys {
			ft := mod.Types[tIdx]
			fmt.Fprintf(&b, "func %s(m %s, idx int32", wname(fmt.Sprintf("callIndirect_type%d", tIdx)), modulePkgRef)
			for i, p := range ft.Params {
				fmt.Fprintf(&b, ", p%d %s", i, goTypeName(p))
			}
			b.WriteByte(')')
			switch len(ft.Results) {
			case 0:
			case 1:
				fmt.Fprintf(&b, " %s", goTypeName(ft.Results[0]))
			default:
				return "" // multi-result indirect not supported in MVP
			}
			b.WriteString(" {\n\t")
			if len(ft.Results) > 0 {
				b.WriteString("return ")
			}
			tField := fieldName("t0")
			// Build the func-type assertion: (func(*Module, P0, P1) R)
			fmt.Fprintf(&b, "m.%s[idx].(func(%s", tField, modulePkgRef)
			for _, p := range ft.Params {
				fmt.Fprintf(&b, ", %s", goTypeName(p))
			}
			b.WriteByte(')')
			if len(ft.Results) == 1 {
				fmt.Fprintf(&b, " %s", goTypeName(ft.Results[0]))
			}
			b.WriteString(")(m")
			for i := range ft.Params {
				fmt.Fprintf(&b, ", p%d", i)
			}
			b.WriteString(")\n}\n\n")
		}
	}

	// Note: OpMemSize / OpMemGrow / OpMemoryCopy / OpMemoryFill
	// are NOT emitted here — they route directly to codegen's
	// memorySize / memoryGrow / memoryCopy / memoryFill helpers
	// (see planFunc). Emitting our own would conflict with
	// codegen's helper functions at link time.
	_, _, _, _ = useMemSize, useMemGrow, useMemoryCopy, useMemoryFill
	_ = maxMemField
	_ = memoryField

	return b.String()
}

// capitalizeExported turns a wasm name into the exported Go method
// name codegen would use (capitalised first letter; leading-digit /
// underscore names get an X prefix). Mirrors codegen.capitalize.
func capitalizeExported(s string) string {
	if s == "" {
		return "_"
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
