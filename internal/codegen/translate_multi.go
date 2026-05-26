package codegen

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
)

// parseFnDeclName extracts the funcIdx from `Fn<N>` or `fn<N>`.
func parseFnDeclName(name string) (uint32, bool) {
	if len(name) < 3 {
		return 0, false
	}
	prefix := 0
	if name[0] == 'f' && name[1] == 'n' {
		prefix = 2
	} else if name[0] == 'F' && name[1] == 'n' {
		prefix = 2
	} else {
		return 0, false
	}
	v, err := strconv.ParseUint(name[prefix:], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// chunkUsedDeps scans `decls` for `pK.X` selector references and returns the
// sorted set of K values found — i.e., the prior-chunk packages this chunk's
// bodies actually call. Imports for chunks not in this set are omitted to
// satisfy Go's no-unused-import rule.
func chunkUsedDeps(decls []ast.Decl) []int {
	used := map[int]bool{}
	for _, d := range decls {
		ast.Inspect(d, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if !isChunkPkgName(pkg.Name) {
				return true
			}
			// isChunkPkgName has already verified pkg.Name == "p" +
			// digits; Atoi failing here would mean isChunkPkgName let a
			// non-numeric suffix through — an invariant violation in
			// this file's chunker, not a runtime input condition.
			depIdx, err := strconv.Atoi(pkg.Name[1:])
			if err != nil {
				panic(fmt.Sprintf("isChunkPkgName(%q) accepted a non-numeric chunk suffix: %v", pkg.Name, err))
			}
			used[depIdx] = true
			return true
		})
	}
	out := make([]int, 0, len(used))
	for k := range used {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// scanStdlibRefs returns the sorted list of stdlib import paths that the
// given decls reference via SelectorExpr like `bits.TrailingZeros32`. Maps
// known short names (bits, math, binary, runtime, unsafe, fmt) to their
// import paths.
func scanStdlibRefs(decls []ast.Decl) []string {
	pkgs := map[string]string{
		"bits":    "math/bits",
		"math":    "math",
		"binary":  "encoding/binary",
		"runtime": "runtime",
		"unsafe":  "unsafe",
		"fmt":     "fmt",
	}
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
			if path, ok := pkgs[id.Name]; ok {
				used[path] = true
			}
			return true
		})
	}
	out := make([]string, 0, len(used))
	for p := range used {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func isChunkPkgName(name string) bool {
	if len(name) < 2 || name[0] != 'p' {
		return false
	}
	for i := 1; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

func importsAsSpecs(imports []*ast.ImportSpec) []ast.Spec {
	out := make([]ast.Spec, len(imports))
	for i, imp := range imports {
		out[i] = imp
	}
	return out
}

// importShortName returns the identifier under which a package is referenced
// in source: the explicit alias when set, otherwise the final path segment.
func importShortName(path, alias string) string {
	if alias != "" && alias != "_" {
		return alias
	}
	seg := path
	if i := lastSlash(path); i >= 0 {
		seg = path[i+1:]
	}
	return seg
}

// lastSlash returns the index of the final '/' in s, or -1.
func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

// declsRefShortName reports whether any decl references `name` as the base of
// a selector expression (e.g. `name.Foo`).
func declsRefShortName(decls []ast.Decl, name string) bool {
	found := false
	for _, d := range decls {
		ast.Inspect(d, func(n ast.Node) bool {
			if found {
				return false
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
				found = true
				return false
			}
			return true
		})
	}
	return found
}

// prependImportsForBase prepends an import block for stdlib packages used by
// helpers. Doesn't include any wasm-generated package imports. Packages in
// `imports` that the base decls never actually reference are dropped — the
// global import set is polluted by inline numeric ops compiled into chunk
// packages (which carry their own import block), and Go rejects unused
// imports.
func prependImportsForBase(decls []ast.Decl, imports map[string]string) []ast.Decl {
	if len(imports) == 0 {
		return decls
	}
	paths := make([]string, 0, len(imports))
	for p := range imports {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	gd := &ast.GenDecl{Tok: token.IMPORT}
	for _, p := range paths {
		alias := imports[p]
		// Blank imports (alias "_") are kept verbatim — they're deliberate
		// side-effect imports, not subject to the unused-import rule.
		if alias != "_" && !declsRefShortName(decls, importShortName(p, alias)) {
			continue
		}
		spec := &ast.ImportSpec{
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(p)},
		}
		if alias != "" {
			spec.Name = newID(alias)
		}
		gd.Specs = append(gd.Specs, spec)
	}
	if len(gd.Specs) == 0 {
		return decls
	}
	return append([]ast.Decl{gd}, decls...)
}
