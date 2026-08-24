package asmgen

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// TestComputeExcOffsets pins the exception-state layout model against
// the field order codegen's emitModuleStruct declares: the exc block
// sits right after the memory trio (or at offset 0 for a memory-less
// module) and shifts every table/global field behind it.
func TestComputeExcOffsets(t *testing.T) {
	tagged := func(mem bool) *wasm.Module {
		m := &wasm.Module{
			Types: []wasm.FuncType{{Params: []wasm.ValType{wasm.ValI32, wasm.ValI64}}},
			Tags:  []wasm.Tag{{TypeIdx: 0}},
		}
		if mem {
			m.Memories = []wasm.MemoryType{{}}
		}
		return m
	}

	if got := ComputeExcOffsets(&wasm.Module{}); got != nil {
		t.Errorf("tag-free module: got %+v, want nil", got)
	}
	if got := ComputeExcOffsets(tagged(false)); got == nil || got.Pending != 0 || got.Tag != 4 || got.Vals != 8 {
		t.Errorf("memory-less module: got %+v, want {0 4 8}", got)
	}
	if got := ComputeExcOffsets(tagged(true)); got == nil || got.Pending != 40 || got.Tag != 44 || got.Vals != 48 {
		t.Errorf("memory module: got %+v, want {40 44 48}", got)
	}

	// A module with only nullary tags still carries the state, with a
	// single unused operand slot.
	nullary := &wasm.Module{
		Types: []wasm.FuncType{{}},
		Tags:  []wasm.Tag{{TypeIdx: 0}},
	}
	if got := excSlotCount(nullary); got != 1 {
		t.Errorf("nullary tag slot count: got %d, want 1", got)
	}
	if got := excSlotCount(tagged(false)); got != 2 {
		t.Errorf("binary tag slot count: got %d, want 2", got)
	}

	// The global-offset model must account for the exc block: with the
	// 2-slot state above (8 header + 16 slots), a lone i32 global in a
	// memory module lands at 40 + 24 = 64.
	gm := tagged(true)
	gm.Globals = []wasm.Global{{Type: wasm.GlobalType{Type: wasm.ValI32}}}
	offs := ComputeGlobalOffsets(gm)
	if len(offs) != 1 || offs[0] != 64 {
		t.Errorf("global offset behind exc block: got %v, want [64]", offs)
	}
}
