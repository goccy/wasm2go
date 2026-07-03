package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestAccessMemoryEmitted pins the host-facing synchronised memory
// window: every module WITH a linear memory must emit the accessMemory
// helper, the memMu field it locks, and a memoryGrow that takes the
// same lock — that trio is what makes out-of-band writers (e.g. an
// interrupt watchdog) sound against concurrent grows. The memMu field
// must sit AFTER the M field so the memory/maxMem/M offsets the asm
// hardcodes (moduleMOffset) stay put.
func TestAccessMemoryEmitted(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_memops")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{Package: "memmod", OutputImportPath: "gentest/memmod"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	src := buf.String()
	for _, expect := range []string{
		"func accessMemory(m *Module, f func(mem []byte))",
		// gofmt aligns struct fields, so match name and type separately.
		"memMu",
		"sync.Mutex",
		"m.memMu.Lock()",
	} {
		if !strings.Contains(src, expect) {
			t.Errorf("output missing %q", expect)
		}
	}
	if mIdx, muIdx := strings.Index(src, "M      unsafe.Pointer"), strings.Index(src, "memMu"); mIdx >= 0 && muIdx >= 0 && muIdx < mIdx {
		t.Errorf("memMu declared before M — the moduleMOffset layout contract requires new fields AFTER M")
	}
}

// TestAccessMemoryNotEmittedWithoutMemory: a memory-less module must
// not pull the helper (its body references memory fields the struct
// would not have).
func TestAccessMemoryNotEmittedWithoutMemory(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, mod, codegen.Options{Package: "arithmod", OutputImportPath: "gentest/arithmod"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	if src := buf.String(); strings.Contains(src, "accessMemory") {
		t.Errorf("memory-less module emitted accessMemory")
	}
}
