package gcasm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

func TestPlan9AsmPathSafe(t *testing.T) {
	for path, want := range map[string]bool{
		"":                                  false,
		"gentest/pkg":                       true,
		"github.com/goccy/llamawasm2go/p1":  true,
		"github.com/goccy/some-hyphen/pkg":  false,
		"example.org/x_y/v2":                true,
		"host.tld/a+b":                      false,
		"host.tld/sp ace":                   false,
		"github.com/goccy/wasm2go/internal": true,
	} {
		if got := plan9AsmPathSafe(path); got != want {
			t.Errorf("plan9AsmPathSafe(%q) = %v, want %v", path, got, want)
		}
	}
}

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
// spell (a hyphen) keeps the historical Go-wrapper forwarding shape.
func TestCrossChunkWrapperFallback(t *testing.T) {
	files := buildMultiChunk(t, "cg_crosscall", "github.com/gen-test/pkg")
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
