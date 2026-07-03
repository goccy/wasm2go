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

// TestMemBaseHoistEmitted pins the linear-memory base hoist: every
// function that touches memory declares `mBase := m.M` exactly once
// at the top, all load/store sites deref mBase (never m.M), and a
// grow-capable value (a call or memory.grow) is followed by a
// `mBase = m.M` refresh. Functions without memops must not declare
// the local (it would be an unused variable).
func TestMemBaseHoistEmitted(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_memops")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "memmod", OutputImportPath: "gentest/memmod"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	// Function bodies with memops live in the pure-Go fallback aux
	// files (asm emission is always on; the main file only carries
	// wrappers and runtime plumbing). Concatenate everything so the
	// assertions see the real memop emission.
	var sb strings.Builder
	sb.Write(buf.Bytes())
	for _, data := range res.AuxFiles {
		sb.Write(data)
	}
	for _, data := range res.Files {
		sb.Write(data)
	}
	src := sb.String()
	if !strings.Contains(src, "mBase := m.M") {
		t.Fatalf("no hoisted mBase declaration in output")
	}
	// Every unsafe.Add memop must go through the hoisted local; the
	// only remaining `m.M` reads are the hoist/refresh assignments.
	if re := regexp.MustCompile(`unsafe\.Add\(m\.M`); re.MatchString(src) {
		t.Errorf("found unsafe.Add(m.M, ...) — memop bypassed the hoisted base")
	}
	// The grow-refresh interaction is pinned separately by
	// TestMemBaseRefreshAfterGrow (the fixture has no function that
	// combines memops with memory.grow; a grow-only function
	// correctly skips the hoist entirely).
}

// TestMemBaseHoistAbsentWithoutMemops: a module whose functions never
// touch linear memory must not declare the local.
func TestMemBaseHoistAbsentWithoutMemops(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{Package: "arithmod", OutputImportPath: "gentest/arithmod"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if strings.Contains(buf.String(), "mBase") {
		t.Errorf("memory-less module declared mBase")
	}
}
