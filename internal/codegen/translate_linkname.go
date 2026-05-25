package codegen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
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
//     linkname forwards under callerChunk == -1)
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

	// Phase 1: compile all chunk bodies (no serialization yet).
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

	// Phase 2: emit helpers (adds helpers' stdlib imports to t.imports).
	helpers, err := t.emitHelpers()
	if err != nil {
		return Result{}, err
	}

	// Phase 2b: native wasi impl (only when -native-wasi is on and the
	// wasm imports wasi_snapshot_preview1). Lives in base/ so DefaultWASI
	// can return *WasiStubs alongside *Module. Imports merged into
	// t.imports so they land in the snapshot below.
	t.currentChunk = -2
	wasiDecls, wasiImports, err := t.emitWasip1Native()
	if err != nil {
		return Result{}, err
	}
	for _, p := range wasiImports {
		t.use(p)
	}

	// Phase 3: snapshot t.imports as base's view BEFORE main pass adds
	// any further dependencies (e.g. "fmt" via SafeInvokeExport).
	baseImportSnapshot := make(map[string]string, len(t.imports))
	for k, v := range t.imports {
		baseImportSnapshot[k] = v
	}

	// Phase 4: main pass. Populates chunkExtraDecls + linkname forwards
	// on callerChunk == -1. Mutates t.imports with main's own needs.
	t.currentChunk = -1
	mainDecls := []ast.Decl{}
	mainDecls = append(mainDecls, t.emitNewFuncs()...)
	mainDecls = append(mainDecls, t.elemInitChunks...)
	exportDecls, err := t.emitExportWrappers()
	if err != nil {
		return Result{}, err
	}
	mainDecls = append(mainDecls, exportDecls...)
	mainDecls = append(mainDecls, t.emitSidecarDecls()...)

	// Phase 5: serialize per-chunk files.
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
		// `_ "unsafe"` required for //go:linkname directives in this file.
		imports = append(imports, &ast.ImportSpec{
			Name: newID("_"),
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("unsafe")},
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
		// Linkname forward decls after imports, before bodies.
		pkgFile.Decls = append(pkgFile.Decls, t.emitLinknameForwards(chunkIdx)...)
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
	}

	// Phase 6: serialize base file.
	t.currentChunk = -2
	baseFile := &ast.File{Name: newID("base")}
	baseFile.Decls = append(baseFile.Decls, t.emitImportInterfaces()...)
	baseFile.Decls = append(baseFile.Decls, t.emitModuleStruct())
	baseFile.Decls = append(baseFile.Decls, helpers...)
	baseFile.Decls = append(baseFile.Decls, wasiDecls...)
	baseFile.Decls = prependImportsForBase(baseFile.Decls, baseImportSnapshot)
	{
		buf := &bytes.Buffer{}
		if err := format.Node(buf, t.fset, baseFile); err != nil {
			return Result{}, fmt.Errorf("format base: %w", err)
		}
		files["base/base.go"] = buf.Bytes()
	}

	// Phase 7: serialize main file.
	t.currentChunk = -1
	mainStdlib := scanStdlibRefs(mainDecls)
	mainImports := []*ast.ImportSpec{
		{Name: newID("base"), Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(t.opts.OutputImportPath + "/base")}},
	}
	mainImports = append(mainImports, &ast.ImportSpec{
		Name: newID("_"),
		Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("unsafe")},
	})
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
	mainFile.Decls = append([]ast.Decl{
		&ast.GenDecl{Tok: token.IMPORT, Specs: importsAsSpecs(mainImports)},
	}, t.emitLinknameForwards(-1)...)
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

	sidecars := map[string][]byte{}
	for k, v := range t.sidecars {
		sidecars[k] = v
	}
	// Aux files (WASI per-platform companions etc.) land inside base/.
	for k, v := range t.auxFiles {
		files["base/"+k] = v
	}
	t.reportMemMetrics()
	return Result{Files: files, Sidecars: sidecars}, nil
}

// Compile-time tether so the wasm import path remains hot if future edits
// drop the direct reference. The translator state threads wasm types
// through transiently.
var _ = wasm.ValI32
