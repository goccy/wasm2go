package gcasm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

func TestAsmSpellPath(t *testing.T) {
	got := asmSpellPath("github.com/goccy/llamawasm2go/p1")
	want := "github·com∕goccy∕llamawasm2go∕p1"
	if got != want {
		t.Fatalf("asmSpellPath = %q, want %q", got, want)
	}
}

// buildMultiChunk translates a fixture in linkname-split
// multi-package mode under importPath and hands it to Build. The
// tiny 64-byte chunk budget forces the fixture across several chunk
// packages, so transformed bodies make cross-chunk calls.
func buildMultiChunk(t *testing.T, fixture, importPath string) map[string][]byte {
	t.Helper()
	defer codegen.SetMultiPackageThreshold(64)()
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: importPath})
	if err != nil {
		t.Fatal(err)
	}
	treeIn := map[string][]byte{}
	for name, data := range res.Sidecars {
		treeIn[name] = data
	}
	for name, data := range res.Files {
		treeIn[name] = data
	}
	files, _, err := Build(mod, buf.Bytes(), treeIn, importPath, nil, nil, nil, nil, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestCrossChunkDirectCalls: a plan-9-spellable import path (dots and
// slashes only, like the production bundles) gets direct cross-chunk
// asm CALLs — the spelled remote symbol appears in the emitted asm and
// no gcasmFwdFn forwarding wrapper is generated.
func TestCrossChunkDirectCalls(t *testing.T) {
	files := buildMultiChunk(t, "cg_crosscall", "github.com/gentest/pkg")
	var direct, wrappers int
	for name, data := range files {
		if strings.HasSuffix(name, ".s") {
			direct += strings.Count(string(data), "CALL github·com∕gentest∕pkg")
		}
		if strings.HasSuffix(name, ".go") {
			wrappers += strings.Count(string(data), "func gcasmFwdFn")
		}
	}
	if direct == 0 {
		t.Error("no spelled direct cross-chunk CALL emitted")
	}
	if wrappers != 0 {
		t.Errorf("%d gcasmFwdFn forwarding wrappers emitted; want 0 (direct calls should replace them)", wrappers)
	}
	// The fixture's wide-signature fn falls back to its pure Go body,
	// so its package must anchor the ABI0 wrapper the remote direct
	// CALL links against.
	var anchors int
	for name, data := range files {
		if strings.HasSuffix(name, ".s") {
			anchors += strings.Count(string(data), "TEXT ·gcasmABI0Keep(SB)")
		}
	}
	if anchors == 0 {
		t.Error("no gcasmABI0Keep anchor emitted for the fallback fn's package")
	}
}

// TestCrossChunkWrapperFallback: an import path plan 9 asm cannot
// spell keeps the historical Go-wrapper forwarding shape. Both
// unspellable classes are covered: a hyphenated host path, and a
// digit-leading host path (the asm lexer accepts digits only after
// the first identifier rune, so "4d63·com∕..." would lex as a
// number, not a symbol).
func TestCrossChunkWrapperFallback(t *testing.T) {
	for _, importPath := range []string{"github.com/gen-test/pkg", "4d63.com/gentest/pkg"} {
		t.Run(importPath, func(t *testing.T) { assertWrapperFallback(t, importPath) })
	}
}

func assertWrapperFallback(t *testing.T, importPath string) {
	files := buildMultiChunk(t, "cg_crosscall", importPath)
	var spelled, wrappers, anchors int
	for name, data := range files {
		if strings.HasSuffix(name, ".s") {
			spelled += strings.Count(string(data), "∕")
			anchors += strings.Count(string(data), "TEXT ·gcasmABI0Keep(SB)")
		}
		if strings.HasSuffix(name, ".go") {
			wrappers += strings.Count(string(data), "func gcasmFwdFn")
		}
	}
	if spelled != 0 {
		t.Errorf("%d spelled path references emitted for an unspellable import path", spelled)
	}
	if wrappers == 0 {
		t.Error("no gcasmFwdFn wrappers emitted; the unspellable path must keep the forwarding shape")
	}
	// No direct CALL is ever made on this path, so the ABI0 keep
	// anchor would be pure dead weight — it must not be emitted.
	if anchors != 0 {
		t.Errorf("%d gcasmABI0Keep anchors emitted for an unspellable path; none should be (no direct calls)", anchors)
	}
}

// TestCrossChunkDirectAsmCallSymbols: a function retained for
// direct-asm emission whose body makes cross-chunk calls must emit
// the same CALL operand shapes the listing transform does — a
// spelled remote symbol on a spellable path, never a
// current-package-qualified mangling of it ("CALL ·github·com∕...")
// that could not link.
func TestCrossChunkDirectAsmCallSymbols(t *testing.T) {
	defer codegen.SetMultiPackageThreshold(64)()
	bin := testfixture.Wasm(t, "cg_crosscall_directasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	const importPath = "github.com/gentest/pkg"
	var buf bytes.Buffer
	// Fn2 ($mid) calls Fn0/Fn1 across chunks; Fn4 (the export) also
	// calls the fallback fn Fn3 ($wide), covering the anchor-resolved
	// shape from a direct-asm body too.
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: importPath,
		DirectAsmFuncs: []string{"Fn2", "Fn4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.DirectAsmSSA) == 0 {
		t.Fatal("translator retained no direct-asm SSA; the direct-asm path is not exercised")
	}
	directAsm := map[string]DirectAsmFn{}
	for name, df := range res.DirectAsmSSA {
		directAsm[name] = DirectAsmFn{Fn: df.Fn, Sig: df.Sig, Packed: df.Packed, PackedParams: df.PackedParams}
	}
	treeIn := map[string][]byte{}
	for name, data := range res.Sidecars {
		treeIn[name] = data
	}
	for name, data := range res.Files {
		treeIn[name] = data
	}
	files, stats, err := Build(mod, buf.Bytes(), treeIn, importPath, nil, nil, nil, nil, nil,
		Config{DirectAsm: directAsm, DirectAsmGlobals: res.DirectAsmGlobals})
	if err != nil {
		t.Fatal(err)
	}
	if stats.DirectAsm == 0 {
		t.Fatal("no direct-asm body emitted; the direct-asm path is not exercised")
	}
	var directBodies, spelledInDirect int
	for name, data := range files {
		if !strings.HasSuffix(name, ".s") {
			continue
		}
		s := string(data)
		// A spelled remote symbol re-wrapped as current-package-local
		// can never link; it must not appear anywhere in the bundle.
		if strings.Contains(s, "·github·com") {
			t.Errorf("%s: current-package-mangled spelled symbol (CALL ·github·com...) emitted", name)
		}
		if !strings.Contains(s, "// direct-asm: ") {
			continue
		}
		directBodies++
		spelledInDirect += strings.Count(s, "CALL github·com∕gentest∕pkg")
	}
	if directBodies == 0 {
		t.Fatal("no .s file carries a direct-asm body marker")
	}
	if spelledInDirect == 0 {
		t.Error("no spelled cross-chunk CALL emitted from a direct-asm body")
	}
}

// finalBundleTree returns the file set an amd64/arm64 consumer would
// actually compile: the codegen multi-package output with the gcasm
// backend's delta merged in (a nil gcasm entry deletes the file).
func finalBundleTree(t *testing.T, fixture, importPath string) map[string][]byte {
	t.Helper()
	defer codegen.SetMultiPackageThreshold(64)()
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: importPath})
	if err != nil {
		t.Fatal(err)
	}
	tree := map[string][]byte{}
	for name, data := range res.Sidecars {
		tree[name] = data
	}
	for name, data := range res.Files {
		tree[name] = data
	}
	delta, _, err := Build(mod, buf.Bytes(), tree, importPath, nil, nil, nil, nil, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range delta {
		if data == nil {
			delete(tree, name)
			continue
		}
		tree[name] = data
	}
	return tree
}

// buildDirectiveOf returns the first //go:build expression in a Go
// source file, or "" for an untagged (all-arch) file.
func buildDirectiveOf(src []byte) string {
	for _, ln := range strings.Split(string(src), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "//go:build ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "//go:build "))
		}
		if strings.HasPrefix(ln, "package ") {
			break
		}
	}
	return ""
}

// TestPlan9SafeBundleFileStructure asserts the final bundle a
// plan-9-spellable consumer compiles has no amd64/arm64 linkname
// alias file: the codegen amd64||arm64 alias.go is deleted by the
// gcasm backend, its cross-chunk declarations fold into the
// decls_<arch>.go the asm bodies need anyway, and every remaining
// linkname-only alias file is guarded off the asm arches. This is the
// file-set contract the direct-call path relies on for parse economy.
func TestPlan9SafeBundleFileStructure(t *testing.T) {
	// The file-set contract (no separate amd64/arm64 linkname alias
	// file; cross-chunk decls in decls_<arch>.go) holds for BOTH the
	// spellable and the hyphenated path — only the CONTENT of
	// decls_<arch>.go differs (direct symbols vs gcasmFwd wrappers).
	for _, importPath := range []string{"github.com/gentest/pkg", "github.com/gen-test/pkg"} {
		t.Run(importPath, func(t *testing.T) { assertBundleFileStructure(t, importPath) })
	}
}

func assertBundleFileStructure(t *testing.T, importPath string) {
	tree := finalBundleTree(t, "cg_indirect", importPath)

	// Collect the chunk packages (pN directories).
	chunkDirs := map[string]bool{}
	for name := range tree {
		if i := strings.IndexByte(name, '/'); i > 0 && strings.HasPrefix(name[:i], "p") {
			chunkDirs[name[:i]] = true
		}
	}
	if len(chunkDirs) < 2 {
		t.Fatalf("fixture did not split into multiple chunks: %v", chunkDirs)
	}

	for dir := range chunkDirs {
		// No amd64||arm64 alias.go survives — it was deleted, its
		// decls folded into decls_<arch>.go.
		if _, ok := tree[dir+"/alias.go"]; ok {
			t.Errorf("%s/alias.go survived; the gcasm backend must delete the amd64||arm64 alias", dir)
		}
		hasArchDecls := false
		for _, arch := range []string{"amd64", "arm64"} {
			if data, ok := tree[dir+"/decls_"+arch+".go"]; ok {
				hasArchDecls = true
				if d := buildDirectiveOf(data); !strings.Contains(d, arch) {
					t.Errorf("%s/decls_%s.go build guard %q does not restrict to %s", dir, arch, d, arch)
				}
			}
		}
		if !hasArchDecls {
			t.Errorf("%s: no decls_amd64.go/decls_arm64.go to carry the asm-body and cross-chunk decls", dir)
		}
		// Every linkname-only alias file left in the chunk must be
		// guarded OFF the asm arches (the pure fallback path only).
		for name, data := range tree {
			if !strings.HasPrefix(name, dir+"/") || !strings.HasSuffix(name, ".go") {
				continue
			}
			if !strings.Contains(string(data), "//go:linkname") {
				continue
			}
			d := buildDirectiveOf(data)
			// The arch decls legitimately carry linkname forwards; the
			// concern is a SEPARATE alias file compiled on the asm arch.
			if strings.HasSuffix(name, "/decls_amd64.go") || strings.HasSuffix(name, "/decls_arm64.go") {
				continue
			}
			if !strings.Contains(d, "!amd64") && !strings.Contains(d, "!arm64") {
				t.Errorf("%s carries //go:linkname but is not guarded off the asm arches (build %q)", name, d)
			}
		}
	}
}
