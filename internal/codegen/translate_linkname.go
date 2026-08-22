package codegen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"path"
	"strconv"

	"github.com/goccy/wasm2go/internal/wasm"
)

// translateLinknameMulti emits the linkname-split multi-package layout. It
// mirrors translateMulti but wires cross-chunk function calls via
// //go:linkname forward declarations instead of Go imports.
//
// The output structure is:
//
//	base/base.go        — Module struct, EnvImports, helpers
//	p0/p0.go            — chunk 0 (imports only base + stdlib)
//	p1/p1.go            — chunk 1 (imports only base + stdlib; calls Fn123
//	                      in p0 are wired via //go:linkname)
//	...
//	pN/pN.go
//	<package>.go        — main: New(), exports, InvokeExport (also uses
//	                      //go:linkname for cross-chunk dispatch)
//
// Each chunk file declares `import _ "unsafe"` and one //go:linkname forward
// per cross-chunk function it references. The chunks still chain via blank
// `_ "<prev>"` import so the Go toolchain compiles them strictly in series —
// this is what bounds peak compiler RSS, not the call-graph DAG (which
// linkname has removed).
//
// Pass order is unusual because:
//
//   - per-chunk shard funcs (InvokeExportShard_K, InitElemSeg_K_*) are
//     emitted by the main pass but must land in the owning chunk's file.
//     So main must run BEFORE chunks are serialized to disk.
//   - the main pass also pulls in stdlib imports (e.g. "fmt" via
//     SafeInvokeExport) that base must NOT include. So base's imports
//     must be snapshotted BEFORE the main pass runs.
//   - emitHelpers populates t.helpers stdlib needs and depends on
//     chunk-body compilation having registered the helper set.
//
// The sequence below threads these constraints:
//
//  1. Compile chunk bodies (registers t.helpers, t.imports for body needs)
//  2. emitHelpers (adds helpers' stdlib needs to t.imports)
//  3. Snapshot t.imports as base's view
//  4. Run main pass (mutates t.imports, populates chunkExtraDecls and
//     linkname forwards under callerChunk == chunkMain)
//  5. Serialize per-chunk files (bodies + extras + linkname forwards)
//  6. Serialize base file (using snapshot)
//  7. Serialize main file (using full t.imports for stdlib)
func (t *translator) translateLinknameMulti() (Result, error) {
	if t.opts.OutputImportPath == "" {
		return Result{}, fmt.Errorf("linkname-split mode requires Options.OutputImportPath")
	}
	chunkBytes := currentMultiPackageThreshold()
	plan, err := planLinknamePackagesWith(t.mod, chunkBytes, t.reachable, t.callees)
	if err != nil {
		return Result{}, fmt.Errorf("linkname-split plan: %w", err)
	}
	t.plan = plan

	files := map[string][]byte{}

	// Step 1: compile all chunk bodies (no serialization yet).
	chunkBodies := make(map[int][]ast.Decl, len(plan.Chunks))
	for chunkIdx, chunk := range plan.Chunks {
		t.currentChunk = chunkIdx
		var bodies []ast.Decl
		for _, fIdx := range chunk.FuncIdxs {
			decls, err := t.emitOneDefinedFunction(fIdx)
			if err != nil {
				return Result{}, err
			}
			bodies = append(bodies, decls...)
		}
		chunkBodies[chunkIdx] = bodies
	}

	// Step 2: emit helpers (adds helpers' stdlib imports to t.imports).
	helpers, err := t.emitHelpers()
	if err != nil {
		return Result{}, err
	}

	// Step 2b: native wasi impl (only when -native-wasi is on and the
	// wasm imports wasi_snapshot_preview1). Lives in base/ so DefaultWASI
	// can return *WasiStubs alongside *Module. Imports merged into
	// t.imports so they land in the snapshot below.
	t.currentChunk = chunkBase
	wasiDecls, wasiImports, err := t.emitWasip1Native()
	if err != nil {
		return Result{}, err
	}
	for _, p := range wasiImports {
		t.use(p)
	}

	// Globals save/restore lands in base (it reads the Module's gN fields), so
	// it has to register its imports before the snapshot below freezes base's
	// import set. See emitGlobalsSnapshot; NewFromSnapshot calls it.
	globalsSnap, err := t.emitGlobalsSnapshot()
	if err != nil {
		return Result{}, err
	}

	// Step 3: snapshot t.imports as base's view BEFORE main pass adds
	// any further dependencies (e.g. "fmt" via SafeInvokeExport).
	baseImportSnapshot := make(map[string]string, len(t.imports))
	for k, v := range t.imports {
		baseImportSnapshot[k] = v
	}

	// Step 4: main pass. Populates chunkExtraDecls + linkname forwards
	// on callerChunk == chunkMain. Mutates t.imports with main's own needs.
	t.currentChunk = chunkMain
	mainDecls := []ast.Decl{}
	mainDecls = append(mainDecls, t.emitNewFuncs()...)
	mainDecls = append(mainDecls, t.elemInitChunks...)
	exportDecls, err := t.emitExportWrappers()
	if err != nil {
		return Result{}, err
	}
	mainDecls = append(mainDecls, exportDecls...)
	mainDecls = append(mainDecls, t.emitSidecarDecls()...)

	// Step 5: serialize per-chunk files.
	for chunkIdx := range plan.Chunks {
		t.currentChunk = chunkIdx
		pkgFile := &ast.File{Name: newID(fmt.Sprintf("p%d", chunkIdx))}
		bodies := chunkBodies[chunkIdx]
		if extras := t.chunkExtraDecls[chunkIdx]; len(extras) > 0 {
			bodies = append(bodies, extras...)
		}
		// Stdlib refs from bodies + extras (extras can call funcRef which
		// is bare for own-chunk; no extra stdlib usage).
		stdlibUsed := scanStdlibRefs(bodies)

		var imports []*ast.ImportSpec
		imports = append(imports, &ast.ImportSpec{
			Name: newID("base"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(t.opts.OutputImportPath + "/base")},
		})
		for _, p := range stdlibUsed {
			imports = append(imports, &ast.ImportSpec{
				Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(p)},
			})
		}
		// Blank-import previous chunk to chain compile order (bounds peak
		// per-package Go-compiler memory). The chain is functionally inert
		// because cross-chunk calls go through linkname, not selectors.
		if chunkIdx > 0 {
			imports = append(imports, &ast.ImportSpec{
				Name: newID("_"),
				Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(fmt.Sprintf("%s/p%d", t.opts.OutputImportPath, chunkIdx-1))},
			})
		}
		pkgFile.Decls = append(pkgFile.Decls, &ast.GenDecl{
			Tok:   token.IMPORT,
			Specs: importsAsSpecs(imports),
		})
		// Package-level constant table — see translate.go's
		// useLargeConst comment for why large memory offsets are
		// routed through a runtime-loaded table instead of inline
		// literals.
		if decl := t.emitLargeConstsDecl(chunkIdx); decl != nil {
			pkgFile.Decls = append(pkgFile.Decls, decl)
		}
		pkgFile.Decls = append(pkgFile.Decls, bodies...)

		path := fmt.Sprintf("p%d/p%d.go", chunkIdx, chunkIdx)
		buf := &bytes.Buffer{}
		if err := format.Node(buf, t.fset, pkgFile); err != nil {
			return Result{}, fmt.Errorf("format chunk p%d: %w", chunkIdx, err)
		}
		files[path] = buf.Bytes()

		// Per-chunk alias files — see emitChunkAliasFiles for the
		// per-arch split (wrapper-pair on amd64/arm64, bare alias on
		// pure-Go). The trampoline source shape lives next to the
		// chunk's other files rather than inline in pN.go so the
		// cross-chunk routing surface is easy to find / audit /
		// regenerate independently of the function table and init
		// code.
		aliasFiles, err := t.emitChunkAliasFiles(fmt.Sprintf("p%d", chunkIdx), chunkIdx, fmt.Sprintf("p%d", chunkIdx))
		if err != nil {
			return Result{}, err
		}
		for rel, content := range aliasFiles {
			files[rel] = content
		}
	}

	// Step 6: serialize base file.
	t.currentChunk = chunkBase
	baseFile := &ast.File{Name: newID("base")}
	baseFile.Decls = append(baseFile.Decls, t.emitImportInterfaces()...)
	baseFile.Decls = append(baseFile.Decls, t.emitModuleStruct())
	baseFile.Decls = append(baseFile.Decls, helpers...)
	baseFile.Decls = append(baseFile.Decls, globalsSnap...)
	baseFile.Decls = append(baseFile.Decls, wasiDecls...)
	baseFile.Decls = prependImportsForBase(baseFile.Decls, baseImportSnapshot)
	{
		buf := &bytes.Buffer{}
		if err := format.Node(buf, t.fset, baseFile); err != nil {
			return Result{}, fmt.Errorf("format base: %w", err)
		}
		files["base/base.go"] = buf.Bytes()
	}

	// The copy-on-write shared-image runtime rides along in base, next to the
	// Module whose fields it reads. It is inert unless an embedder calls
	// NewSharedImage.
	shared, err := t.emitSharedImage("base")
	if err != nil {
		return Result{}, err
	}
	for name, content := range shared {
		files["base/"+name] = content
	}

	// Step 7: serialize main file.
	t.currentChunk = chunkMain
	mainStdlib := scanStdlibRefs(mainDecls)
	mainImports := []*ast.ImportSpec{
		{Name: newID("base"), Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(t.opts.OutputImportPath + "/base")}},
	}
	for _, p := range mainStdlib {
		mainImports = append(mainImports, &ast.ImportSpec{
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(p)},
		})
	}
	if len(plan.Chunks) > 0 {
		last := len(plan.Chunks) - 1
		mainImports = append(mainImports, &ast.ImportSpec{
			Name: newID("_"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(fmt.Sprintf("%s/p%d", t.opts.OutputImportPath, last))},
		})
	}
	if len(t.sidecars) > 0 {
		mainImports = append(mainImports, &ast.ImportSpec{
			Name: newID("_"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("embed")},
		})
	}
	mainFile := &ast.File{Name: newID(t.opts.Package)}
	mainFile.Decls = append(mainFile.Decls, &ast.GenDecl{Tok: token.IMPORT, Specs: importsAsSpecs(mainImports)})
	if decl := t.emitLargeConstsDecl(-1); decl != nil {
		mainFile.Decls = append(mainFile.Decls, decl)
	}
	mainFile.Decls = append(mainFile.Decls, mainDecls...)
	{
		buf := &bytes.Buffer{}
		if err := format.Node(buf, t.fset, mainFile); err != nil {
			return Result{}, fmt.Errorf("format main: %w", err)
		}
		files[t.opts.Package+".go"] = buf.Bytes()
	}

	// Main-file alias.go — bare //go:linkname aliases only (no asm
	// in the main file, so no wrapper-pair is needed). Emitted with
	// no build tag because the same shape works on every arch.
	mainAlias, err := t.emitChunkAliasFiles(t.opts.Package, -1, "")
	if err != nil {
		return Result{}, err
	}
	for rel, content := range mainAlias {
		files[rel] = content
	}

	sidecars := map[string][]byte{}
	for k, v := range t.sidecars {
		sidecars[k] = v
	}
	// Aux files (WASI per-platform companions etc.) land inside base/.
	for k, v := range t.auxFiles {
		files["base/"+k] = v
	}

	// Asm-always-on tail: emit per-chunk asm + decls, split each
	// chunk's pN.go into pN.go (shared imports/decls/wrappers, always
	// compiled) and pN_pure.go (the function bodies, gated
	// `!amd64 && !arm64`). The gcasm backend (see transpile.Translate)
	// captures the pure bodies and emits the per-arch asm that replaces
	// them; codegen itself no longer produces any assembly.
	for chunkIdx := range plan.Chunks {
		origPath := fmt.Sprintf("p%d/p%d.go", chunkIdx, chunkIdx)
		orig, ok := files[origPath]
		if !ok {
			return Result{}, fmt.Errorf("missing %s after chunk serialization", origPath)
		}
		shared, fallback, err := splitForAsm(orig, fmt.Sprintf("p%d", chunkIdx), pureFallbackTag(t.opts))
		if err != nil {
			return Result{}, fmt.Errorf("split %s: %w", origPath, err)
		}
		files[origPath] = shared
		files[fmt.Sprintf("p%d/p%d_pure.go", chunkIdx, chunkIdx)] = fallback
	}

	t.reportMemMetrics()
	t.appendSimdHelperFiles(files)
	t.appendDirectAsmLayoutFile(files)
	res := Result{Files: files, Sidecars: sidecars, FusedSimd: t.FusedTrees(), FusedLoops: t.FusedLoops(), Outlined: t.outlinedByChunk, OutlinedSigs: t.outlinedSigs, DirectAsmSSA: t.directAsmSSA}
	if len(t.directAsmSSA) > 0 {
		res.DirectAsmGlobals = t.moduleGlobalOffsets()
		res.DirectAsmExc = t.moduleExcOffsets()
	}
	if t.nrc2 != nil {
		res.Nrc2VecDot = t.funcName(t.nrc2.funcIdx)
		res.Nrc2Companion = t.nrc2CompanionName()
	}
	return res, nil
}

// formatAliasFile renders a per-package alias file from a given list
// of //go:linkname forward declarations. buildTag, when non-empty,
// becomes a `//go:build <tag>` directive at the top so the file is
// only compiled on matching targets. The file declares pkgName so
// every alias is name-callable from other files in the same package
// without qualification. It imports `base` (for *base.Module typed
// parameters) and the blank `unsafe` (required by //go:linkname).
// Returns nil if forwards is empty so callers can skip writing the
// file altogether.
func (t *translator) formatAliasFile(pkgName string, buildTag string, forwards []ast.Decl) ([]byte, error) {
	if len(forwards) == 0 {
		return nil, nil
	}
	imports := []*ast.ImportSpec{
		{
			Name: newID("base"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(t.opts.OutputImportPath + "/base")},
		},
		{
			// `_ "unsafe"` is required by the //go:linkname directive.
			Name: newID("_"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("unsafe")},
		},
	}

	file := &ast.File{Name: newID(pkgName)}
	file.Decls = append(file.Decls, &ast.GenDecl{
		Tok:   token.IMPORT,
		Specs: importsAsSpecs(imports),
	})
	file.Decls = append(file.Decls, forwards...)

	var buf bytes.Buffer
	if err := format.Node(&buf, t.fset, file); err != nil {
		return nil, fmt.Errorf("format alias file for %s: %w", pkgName, err)
	}
	if buildTag == "" {
		return buf.Bytes(), nil
	}
	// Build tag has to appear BEFORE the package clause, so prepend
	// rather than wedging it into the AST (the AST printer would put
	// it on the wrong line).
	return append([]byte(fmt.Sprintf("//go:build %s\n\n", buildTag)), buf.Bytes()...), nil
}

// emitChunkAliasFiles emits the per-chunk alias files for callerChunk
// (>= 0 for a chunk, -1 for the main file). It splits the wasm-
// function forwards by build tag so the wrapper-pair shape — which
// exists solely to provide the ABI0 wrapper that pN/amd64.s and
// pN/arm64.s need for `CALL ·FnN(SB)` — never reaches a pure-Go
// build, and conversely the bare-alias shape (cheaper, no Go
// trampoline frame) is used on pure-Go where there is no asm caller
// to satisfy.
//
//	pN/alias.go        ← //go:build amd64 || arm64
//	                     wrapper pair (`_xFnN` linkname + `FnN`
//	                     Go body) + named-symbol bare aliases
//	pN/alias_pure.go   ← //go:build !amd64 && !arm64
//	                     wasm-fn bare aliases + named-symbol bare
//	                     aliases (the named symbols also satisfy
//	                     pure-Go fallback callers in pN_pure.go)
//
// For callerChunk == chunkMain (main file) there is no asm caller, so only
// one file is emitted with no build tag — the bare aliases work for
// every arch.
//
// Returns the rendered files keyed by their on-disk path relative to
// the wasm2go package root.
func (t *translator) emitChunkAliasFiles(pkgName string, callerChunk int, dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	named := t.emitNamedSymbolForwards(callerChunk)

	// The main file has no asm caller, so bare aliases with no build
	// tag serve every arch. PureOnly mode is the same situation for
	// EVERY chunk — no asm bundle will exist anywhere — so the chunks
	// collapse to the same single untagged bare-alias shape.
	if callerChunk == chunkMain || t.opts.PureOnly {
		bare := t.emitWasmFnForwards(callerChunk, linknameForwardBare)
		decls := append([]ast.Decl{}, bare...)
		decls = append(decls, named...)
		out, err := t.formatAliasFile(pkgName, "", decls)
		if err != nil {
			return nil, err
		}
		if out != nil {
			files[path.Join(dir, "alias.go")] = out
		}
		return files, nil
	}

	// Per-chunk amd64||arm64 alias file. When the host import path
	// is plan-9-asm-safe, the gcasm backend's per-arch asm provides
	// the local ABI0 entry, so the Go-side decl is body-less and
	// linkname-less (decl-only). Otherwise the historical
	// wrapper-pair shape forces the Go compiler to emit the local
	// ABI0 wrapper that asm `CALL ·FnN(SB)` resolves through.
	asmKind := linknameForwardWrapperPair
	if isPlan9AsmSafe(t.opts.OutputImportPath) {
		asmKind = linknameForwardDeclOnly
	}
	asmForwards := t.emitWasmFnForwards(callerChunk, asmKind)
	asmDecls := append([]ast.Decl{}, asmForwards...)
	asmDecls = append(asmDecls, named...)
	asmFile, err := t.formatAliasFile(pkgName, "amd64 || arm64", asmDecls)
	if err != nil {
		return nil, err
	}
	if asmFile != nil {
		files[path.Join(dir, "alias.go")] = asmFile
	}

	bareWasm := t.emitWasmFnForwards(callerChunk, linknameForwardBare)
	pureDecls := append([]ast.Decl{}, bareWasm...)
	pureDecls = append(pureDecls, named...)
	pureFile, err := t.formatAliasFile(pkgName, "!arm64 && (!amd64 || !amd64.v2)", pureDecls)
	if err != nil {
		return nil, err
	}
	if pureFile != nil {
		files[path.Join(dir, "alias_pure.go")] = pureFile
	}
	return files, nil
}

// Compile-time tether so the wasm import path remains hot if future edits
// drop the direct reference. The translator state threads wasm types
// through transiently.
var _ = wasm.ValI32
