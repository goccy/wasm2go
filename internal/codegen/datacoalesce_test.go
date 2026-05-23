package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestDataSegmentCoalescing verifies that adjacent data segments with a
// small inter-segment gap are merged into a single copy() (the gap
// zero-filled in the blob), while a segment separated by a large gap
// stays its own copy.
//
// datacoalesce.wasm has three segments: "AAAA"@0, "BBBB"@8 (gap 4 — must
// coalesce) and "CC"@100000 (gap ~100k — must stay separate).
func TestDataSegmentCoalescing(t *testing.T) {
	bin := testfixture.Wasm(t, "datacoalesce")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	out := buf.String()

	// Two data copies: the coalesced AAAA+gap+BBBB span and CC.
	n := strings.Count(out, "copy(m.memory[")
	if n != 2 {
		t.Errorf("data copy count = %d, want 2 (one coalesced span + one far segment)\n%s", n, out)
	}

	// data.bin: span1 = AAAA(4) + 4 zero gap + BBBB(4) = 12, span2 = CC(2).
	blob := res.Sidecars["data.bin"]
	if len(blob) != 14 {
		t.Fatalf("data.bin length = %d, want 14", len(blob))
	}
	want := []byte("AAAA\x00\x00\x00\x00BBBBCC")
	if !bytes.Equal(blob, want) {
		t.Errorf("data.bin = %q, want %q", blob, want)
	}
}
