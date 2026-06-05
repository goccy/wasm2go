package codegen

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/asmgen"
	"github.com/goccy/wasm2go/internal/wasm"
)

// buildAsmFilesSingle produces the amd64/arm64 asm bundle for a
// single-package translation. The returned map contains:
//
//   - decls_amd64.go / decls_arm64.go: function declarations the
//     asm bodies fill in
//   - amd64.s / arm64.s: plan9 asm bodies
//   - wrappers.go: Go dispatch wrappers (callImport_N, loadGlobal_N,
//     callIndirect_typeN, memSize/Grow/Copy/Fill) — gated
//     `//go:build amd64 || arm64`
//
// The single-pkg Go fallback bodies live in `<pkg>_pure.go` which the
// caller adds separately (gated `//go:build !amd64 && !arm64`).
//
// Functions whose ops the emitter doesn't yet support emit a Go-side
// panic stub instead of asm — this keeps the package buildable when
// a wasm input touches an op outside the prototype coverage.
func buildAsmFilesSingle(m *wasm.Module, opts Options) (map[string][]byte, error) {
	files, err := asmgen.BuildPackageFiles(m, asmgen.BuildPackageOptions{
		Package: opts.Package,
		// Codegen single-pkg uses lowercase fn<idx> for function
		// bodies; the asm side must agree so the export wrappers
		// in the shared file resolve to the right symbols.
		FuncSymbol: func(idx uint32) string {
			return fmt.Sprintf("fn%d", idx)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("asmgen: %w", err)
	}
	out := make(map[string][]byte, len(files))
	for p, c := range files {
		out[p] = []byte(c)
	}
	return out, nil
}

// buildAsmFilesMultiChunk produces the amd64/arm64 asm bundle for one
// chunk of the linkname-split multi-package layout. It is called once
// per chunk from translateLinknameMulti and returns the chunk-local
// file map (paths like "decls_amd64.go", "amd64.s") which the caller
// composes under `pN/` in the package directory.
func buildAsmFilesMultiChunk(m *wasm.Module, opts Options, chunkIdx int, chunk MultiPackageChunk, plan *MultiPackagePlan) (map[string][]byte, error) {
	// For own-chunk callees emit the bare local name (the asm body
	// of FnN is in this chunk's amd64.s, so ·FnN(SB) resolves
	// directly). For cross-chunk callees, if the host import path
	// is plan-9-asm-safe (every byte is a letter, digit, "_", "/",
	// or "."), emit the FULL Go-side qualified path (e.g.
	// "github.com/foo/bar/pX.FnN") so the asm emitter's
	// goAsmSymbol can render a direct cross-package CALL by
	// mapping "/" → U+2215 ("∕") and intra-component "."
	// → U+00B7 ("·"). Plan 9 asm's scanner only accepts those
	// two non-ASCII runes as identifier characters (see
	// src/cmd/asm/internal/lex/tokenizer.go: isIdentRune); the
	// hyphen, plus sign, and every other punctuation that can
	// otherwise appear in a Go module path has no identifier
	// equivalent. When the path is not safe we fall back to the
	// bare local name so the asm CALL routes through the
	// per-chunk Go-body trampoline (one extra Go frame) instead
	// of producing an unparseable plan 9 symbol.
	canCrossPkg := isPlan9AsmSafe(opts.OutputImportPath)
	funcSymbol := func(idx uint32) string {
		if canCrossPkg && plan != nil {
			if targetChunk, ok := plan.FuncToChunk[idx]; ok && targetChunk != chunkIdx {
				return fmt.Sprintf("%s/p%d.Fn%d", opts.OutputImportPath, targetChunk, idx)
			}
		}
		return fmt.Sprintf("Fn%d", idx)
	}
	files, err := asmgen.BuildPackageFiles(m, asmgen.BuildPackageOptions{
		Package:       fmt.Sprintf("p%d", chunkIdx),
		FuncSymbol:    funcSymbol,
		FuncIdxs:      chunk.FuncIdxs,
		MultiPackage:  true,
		BasePkgImport: opts.OutputImportPath + "/base",
		// Each chunk gets its OWN copy of the dispatch wrappers
		// (callImport_N, loadGlobal_N, callIndirect_typeN,
		// storeGlobal_N). Plan9 asm cannot CALL a function in
		// another package directly — that path returned
		// "relocation target base.LoadGlobal_0 not defined" — so
		// the asm has to land on a same-package symbol. The
		// wrappers are small Go-source bodies (~10s of lines per
		// chunk total) and the duplication overhead is negligible
		// next to the asm bundle itself.
		SkipWrappers: false,
	})
	if err != nil {
		return nil, fmt.Errorf("asmgen chunk %d: %w", chunkIdx, err)
	}
	out := make(map[string][]byte, len(files))
	for p, c := range files {
		out[p] = []byte(c)
	}
	return out, nil
}

// isPlan9AsmSafe reports whether path can be embedded verbatim into a
// plan 9 asm symbol operand by mapping "/" to U+2215 and intra-
// component "." to U+00B7. The asm scanner only treats letters,
// digits (after the first character), "_", U+00B7, and U+2215 as
// identifier runes (src/cmd/asm/internal/lex/tokenizer.go:
// isIdentRune). Any other byte — hyphen, plus, tilde, etc. — has
// no identifier-rune substitute and forces us to fall back to the
// per-chunk Go-body trampoline (so the asm CALL stays a local
// ·FnN(SB) reference). Empty path is rejected so the caller treats
// it as unsafe.
func isPlan9AsmSafe(path string) bool {
	if path == "" {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '/':
		default:
			return false
		}
	}
	return true
}

// buildAsmWrappersFile produces base/wrappers.go for a multi-package
// translation. The wrappers are emitted once per module and shared
// across every chunk's asm via `base·callImport_N(SB)` references.
func buildAsmWrappersFile(m *wasm.Module) []byte {
	body := asmgen.BuildWrappers(m, true)
	if body == "" {
		return nil
	}
	return []byte(fmt.Sprintf("//go:build amd64 || arm64\n\npackage base\n\n%s", body))
}

// wasmFuncBodyName matches the identifiers codegen uses for wasm
// function bodies — `Fn<N>` in multi-package mode, `fn<N>` in
// single-package mode. Anything else (export wrappers, helpers,
// New, init functions) keeps its name unchanged and falls through
// to the shared file.
var wasmFuncBodyName = regexp.MustCompile(`^[Ff]n\d+$`)

// isLinknameTrampolineBody reports whether body is the single-stmt
// forwarding pattern emitLinknameForwards emits for cross-chunk
// trampolines. That pattern is either `return _x<Name>(...)` (for
// functions with a result) or `_x<Name>(...)` (for void functions),
// where `_x<Name>` is the linkname-aliased helper. The check is
// shape-only so it stays cheap and resists incidental matches.
func isLinknameTrampolineBody(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	var call *ast.CallExpr
	switch s := body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(s.Results) != 1 {
			return false
		}
		c, ok := s.Results[0].(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
	case *ast.ExprStmt:
		c, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
	default:
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return strings.HasPrefix(id.Name, "_x")
}

// splitForAsm parses the Go source the translator produced,
// partitions its top-level declarations into shared vs body, and
// re-emits each half as a self-contained Go file with the right
// build tag and minimum-required imports. The body file's tag
// (!amd64 && !arm64) makes it dormant on the asm-target GOARCHs,
// where the asm files supply the function bodies instead.
func splitForAsm(src []byte, pkg string) (shared, fallback []byte, err error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "translate.go", src, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parse: %w", err)
	}

	var sharedDecls, bodyDecls []ast.Decl
	var importDecls []*ast.GenDecl
	for _, d := range file.Decls {
		// Pull import decls aside so we can recompute per-file
		// later. Anything else slots into one of the two buckets.
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.IMPORT {
			importDecls = append(importDecls, g)
			continue
		}
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil &&
			wasmFuncBodyName.MatchString(fd.Name.Name) {
			// Three Fn-named declarations exist in multi-pkg
			// linkname-split mode:
			//   1. Forward declarations (Body == nil) emitted by
			//      single-pkg linkname forwards (legacy path).
			//   2. Cross-chunk trampolines (Body != nil; calls a
			//      _x-prefixed linkname helper) emitted by
			//      emitLinknameForwards. The local symbol must
			//      exist on every arch so asm `·Fn48(SB)` resolves
			//      to it.
			//   3. Real own-chunk function bodies (Body != nil;
			//      arbitrary code). These belong only in the
			//      pure-Go fallback file; the asm bundle provides
			//      them on amd64/arm64.
			//
			// Detect trampolines by checking whether the body is a
			// single statement that delegates to a `_x`-prefixed
			// helper — every trampoline emitLinknameForwards
			// produces matches this shape and nothing else does.
			if fd.Body == nil || isLinknameTrampolineBody(fd.Body) {
				sharedDecls = append(sharedDecls, fd)
			} else {
				bodyDecls = append(bodyDecls, fd)
			}
			continue
		}
		sharedDecls = append(sharedDecls, d)
	}

	imports := collectImports(importDecls)

	sharedSrc, err := renderFile(fset, pkg, "", sharedDecls, imports)
	if err != nil {
		return nil, nil, fmt.Errorf("render shared: %w", err)
	}
	fallbackSrc, err := renderFile(fset, pkg, "//go:build !amd64 && !arm64", bodyDecls, imports)
	if err != nil {
		return nil, nil, fmt.Errorf("render fallback: %w", err)
	}
	return sharedSrc, fallbackSrc, nil
}

// importInfo is one parsed import: its path and (when present) its
// alias. The alias is what the Go source refers to in
// `<alias>.<member>` selector expressions; an empty alias means the
// default package name, computed via path.Base.
type importInfo struct {
	path  string
	alias string
}

func (ii importInfo) ident() string {
	if ii.alias != "" {
		return ii.alias
	}
	return path.Base(ii.path)
}

func collectImports(genDecls []*ast.GenDecl) []importInfo {
	var out []importInfo
	for _, g := range genDecls {
		for _, spec := range g.Specs {
			s, ok := spec.(*ast.ImportSpec)
			if !ok || s.Path == nil {
				continue
			}
			p, err := strconv.Unquote(s.Path.Value)
			if err != nil {
				continue
			}
			ii := importInfo{path: p}
			if s.Name != nil {
				ii.alias = s.Name.Name
			}
			out = append(out, ii)
		}
	}
	return out
}

// renderFile formats one file: build tag (if non-empty), package
// header, an import block restricted to the packages the file's
// decls actually reference, and the decls themselves.
//
// Imports are recomputed per file because Go rejects unused
// imports: a file that doesn't reference `math` cannot include
// its import even though the original combined file did.
//
// Blank-imported packages (alias `_`) are kept regardless of
// reference because their import is for side effects (init()
// functions) — they don't need to be referenced by name.
func renderFile(fset *token.FileSet, pkg, buildTag string, decls []ast.Decl, imports []importInfo) ([]byte, error) {
	used := computeUsedIdents(decls)
	var keep []importInfo
	for _, ii := range imports {
		if ii.alias == "_" {
			keep = append(keep, ii)
			continue
		}
		if used[ii.ident()] {
			keep = append(keep, ii)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].path < keep[j].path })

	file := &ast.File{Name: ast.NewIdent(pkg)}
	if len(keep) > 0 {
		gd := &ast.GenDecl{Tok: token.IMPORT}
		for _, ii := range keep {
			spec := &ast.ImportSpec{
				Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(ii.path)},
			}
			if ii.alias != "" {
				spec.Name = ast.NewIdent(ii.alias)
			}
			gd.Specs = append(gd.Specs, spec)
		}
		file.Decls = append(file.Decls, gd)
	}
	file.Decls = append(file.Decls, decls...)

	var buf bytes.Buffer
	if buildTag != "" {
		fmt.Fprintf(&buf, "%s\n\n", buildTag)
	}
	if err := format.Node(&buf, fset, file); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// computeUsedIdents walks decls and returns the set of identifier
// names that appear on the left side of a SelectorExpr — i.e. the
// package qualifiers in `<id>.<member>` expressions. This is the
// set of imports the decls require.
func computeUsedIdents(decls []ast.Decl) map[string]bool {
	used := map[string]bool{}
	for _, d := range decls {
		ast.Inspect(d, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			used[id.Name] = true
			return true
		})
	}
	return used
}
