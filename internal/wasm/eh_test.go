package wasm_test

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// TestParseExceptionHandling covers the parser/decoder additions for the legacy
// exception-handling proposal (the shape clang emits for setjmp/longjmp under
// -mllvm -wasm-enable-sjlj): the tag section, and the try/catch/catch_all/
// throw/rethrow/delegate opcodes. Stage 1 only requires that these parse and
// decode without error — lowering/emit are separate stages.
func TestParseExceptionHandling(t *testing.T) {
	m := mustParseFile(t, "eh_trycatch.wat")

	// The tag section must yield exactly one tag whose type has a single i32
	// param (the exception operand).
	if len(m.Tags) != 1 {
		t.Fatalf("tags: got %d, want 1", len(m.Tags))
	}
	tag := m.Tags[0]
	if int(tag.TypeIdx) >= len(m.Types) {
		t.Fatalf("tag type index %d out of range (%d types)", tag.TypeIdx, len(m.Types))
	}
	ft := m.Types[tag.TypeIdx]
	if len(ft.Params) != 1 || ft.Params[0] != wasm.ValI32 || len(ft.Results) != 0 {
		t.Fatalf("tag type: got params=%v results=%v, want [i32]->[]", ft.Params, ft.Results)
	}

	// Every function body must decode end-to-end; collectively the fixture
	// must exercise each new EH opcode at least once.
	seen := map[byte]bool{}
	for i, fn := range m.Functions {
		r := wasm.NewInstrReader(fn.Body)
		skipLocals(t, r)
		for !r.EOF() {
			op, err := r.ReadByte()
			if err != nil {
				t.Fatalf("function[%d]: read op: %v", i, err)
			}
			switch op {
			case wasm.OpTry, wasm.OpCatch, wasm.OpThrow, wasm.OpCatchAll,
				wasm.OpRethrow, wasm.OpDelegate:
				seen[op] = true
			}
			if err := r.SkipImmediates(op); err != nil {
				t.Fatalf("function[%d]: SkipImmediates(0x%02x): %v", i, op, err)
			}
		}
	}

	for _, want := range []struct {
		op   byte
		name string
	}{
		{wasm.OpTry, "try"}, {wasm.OpCatch, "catch"}, {wasm.OpThrow, "throw"},
		{wasm.OpCatchAll, "catch_all"}, {wasm.OpRethrow, "rethrow"},
		{wasm.OpDelegate, "delegate"},
	} {
		if !seen[want.op] {
			t.Errorf("opcode %s (0x%02x) never decoded from the fixture", want.name, want.op)
		}
	}
}

// skipLocals advances r past a code entry's locals declaration
// (vec of (count, valtype)) so the reader is positioned at the first
// instruction.
func skipLocals(t *testing.T, r *wasm.InstrReader) {
	t.Helper()
	n, err := r.ReadU32()
	if err != nil {
		t.Fatalf("read locals count: %v", err)
	}
	for i := uint32(0); i < n; i++ {
		if _, err := r.ReadU32(); err != nil {
			t.Fatalf("read local[%d] count: %v", i, err)
		}
		if _, err := r.ReadByte(); err != nil {
			t.Fatalf("read local[%d] valtype: %v", i, err)
		}
	}
}
