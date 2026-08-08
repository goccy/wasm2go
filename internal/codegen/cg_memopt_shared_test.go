package codegen_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// fn0Body concatenates the main buffer and every generated file, then
// returns the body of fn0 — the single function lowered from the fixture,
// which holds the two loads.
var fn0Re = regexp.MustCompile(`(?s)func fn0\b.*?\n}`)

func fn0Body(t *testing.T) string {
	t.Helper()
	bin := testfixture.Wasm(t, "cg_memopt_shared.wat")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var all strings.Builder
	all.Write(buf.Bytes())
	for _, content := range res.Files {
		all.Write(content)
	}
	body := fn0Re.FindString(all.String())
	if body == "" {
		t.Fatalf("fn0 not found in generated output:\n%s", all.String())
	}
	return body
}

// loadCount counts linear-memory load derefs in a function body (each
// wasm load lowers to one `unsafe.Add(...)` deref here).
func loadCount(body string) int { return strings.Count(body, "unsafe.Add") }

// TestMemOptSkippedOnSharedMemory pins the correctness gate: on a shared
// linear memory MemOpt must NOT eliminate the second of two identical
// loads, because a peer agent may write the address in between and each
// non-atomic load must re-read memory. Both derefs must survive.
func TestMemOptSkippedOnSharedMemory(t *testing.T) {
	if n := loadCount(fn0Body(t)); n != 2 {
		t.Errorf("shared memory: expected both loads preserved (2 derefs), got %d", n)
	}
}
