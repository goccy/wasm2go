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
)

// isPlan9AsmSafe reports whether path can be embedded into a plan 9
// asm symbol operand by mapping "/" → U+2215 ("∕") and "." →
// U+00B7 ("·"). The plan 9 asm lexer is the source of truth:
//
//   - src/cmd/asm/internal/lex/tokenizer.go: isIdentRune accepts
//     unicode.IsLetter, digits (after the first character), "_",
//     U+00B7, and U+2215 — and nothing else.
//
//   - src/cmd/asm/internal/lex/lex.go: lex.Make post-processes
//     identifier tokens with `strings.ReplaceAll`, mapping U+00B7
//     back to "." and U+2215 back to "/" before the name is
//     handed to the symbol-lookup pass. So the only ASCII
//     punctuation that survives a round-trip through the scanner
//     into a symbol operand is "." and "/" — every other character
//     ("-", "+", "~", " ", ...) has no plan 9 substitute and is
//     simply unrepresentable in an asm CALL operand. There is no
//     escape syntax: macros must themselves be alphanumeric
//     identifiers (input.go: macroName) and string literals are
//     immediate-only ("string constant must be an immediate").
//
// Any byte outside [A-Za-z0-9_./] therefore forces a fall back to
// the per-chunk Go-body trampoline so the asm CALL stays a local
// ·FnN(SB) reference. Empty path is rejected so the caller treats
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

// wasmFuncBodyName matches the identifiers codegen uses for wasm
// function bodies — `Fn<N>` in multi-package mode, `fn<N>` in
// single-package mode. Anything else (export wrappers, helpers,
// New, init functions) keeps its name unchanged and falls through
// to the shared file.
// The `l<blockID>` suffix names a loop outlined from that function
// (see internal/ssa/outline.go); those bodies route with their parent.
var wasmFuncBodyName = regexp.MustCompile(`^[Ff]n\d+(l\d+|rows)?$`)

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
// build tag and minimum-required imports. fallbackTag is the
// `//go:build` directive for the body file: normally
// `//go:build !amd64 && !arm64` so it is dormant on the asm-target
// GOARCHs (where the asm files supply the bodies); in PureOnly mode
// the empty string, so the pure bodies compile everywhere.
func splitForAsm(src []byte, pkg string, fallbackTag string) (shared, fallback []byte, err error) {
	fset := token.NewFileSet()
	// SkipObjectResolution: this split only reshuffles top-level decls
	// and never inspects ident.Obj / file.Scope, so the parser's
	// (deprecated) identifier resolver is dead work here — and its
	// hard-coded maxScopeDepth=1000 bailout would reject legitimately
	// deep control flow (e.g. the nested dispatch setjmp/longjmp
	// translation emits) that gc itself compiles fine.
	file, err := parser.ParseFile(fset, "translate.go", src, parser.ParseComments|parser.SkipObjectResolution)
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
	fallbackSrc, err := renderFile(fset, pkg, fallbackTag, bodyDecls, imports)
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
