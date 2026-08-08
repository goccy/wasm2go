package lower

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestLowerSwitch3 covers the switch3 export — a br_table dispatcher.
// br_table lowers to a chain of equality-If blocks, so the lowering
// should succeed and produce a CFG dominated by goto-based emission.
func TestLowerSwitch3(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	idx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "switch3" {
			idx = e.Index
			break
		}
	}
	if idx == ^uint32(0) {
		t.Skip("switch3 not exported")
	}
	if _, err := LowerFunction(mod, idx, "switch3", testThrowSet(mod)); err != nil {
		t.Fatalf("lower switch3: %v", err)
	}
}

// TestLowerBrTableLoopArity is a regression test for a br_table whose
// targets have different RESULT arities but the same BRANCH (label) arity —
// the pattern a computed-goto dispatch emits and which previously
// made lowering fail with "br_table target N has arity 0, default has 1".
//
// The hand-built function is:
//
//	(func (param i32) (result i32)
//	  (block            ;; $b: result [] -> branch arity 0
//	    (loop (result i32)   ;; $l: result [i32] -> resultCount 1, but branch
//	                         ;;     arity 0 (a branch jumps to the header,
//	                         ;;     which consumes the loop's 0 params)
//	      local.get 0
//	      br_table 1 0   ;; case0 -> $b (block), default -> $l (loop)
//	    )
//	  )
//	  i32.const 0)
//
// The br_table mixes a block target (result arity 0) with a loop default
// (result arity 1). Before the fix the validator compared result arities
// (0 != 1) and rejected it; with branchArity() both are 0, so it lowers.
func TestLowerBrTableLoopArity(t *testing.T) {
	bin := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
		// type section: (param i32) (result i32)
		0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
		// function section: func0 : type0
		0x03, 0x02, 0x01, 0x00,
		// export section: "f" = func0
		0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
		// code section
		0x0a, 0x12, 0x01, // section id, size, func count
		0x10,       // body size
		0x00,       // 0 local decls
		0x02, 0x40, // block (empty blocktype)
		0x03, 0x7f, // loop (result i32)
		0x20, 0x00, // local.get 0
		0x0e, 0x01, 0x01, 0x00, // br_table [1] default 0
		0x0b,       // end loop
		0x0b,       // end block
		0x41, 0x00, // i32.const 0
		0x0b, // end func
	}
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := LowerFunction(mod, 0, "f", testThrowSet(mod)); err != nil {
		t.Fatalf("lower br_table-loop-arity func: %v", err)
	}
}

// TestLowerBrTableBlockKind pins the arity-0 br_table lowering to a
// single BlockBrTable: one successor per UNIQUE target, TableCases
// mapping selector values to successors, and the default index set.
// The hand-built function reuses TestLowerBrTableLoopArity's shape
// with a 3-case table where two cases and the default share targets:
//
//	br_table [1 1 0] default 0
//	  case 0, case 1 -> $b (block)   — one succ, cases [0 1]
//	  case 2, default -> $l (loop)   — one succ, cases [2] + default
func TestLowerBrTableBlockKind(t *testing.T) {
	bin := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
		// type section: (param i32) (result i32)
		0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
		// function section: func0 : type0
		0x03, 0x02, 0x01, 0x00,
		// export section: "f" = func0
		0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
		// code section
		0x0a, 0x14, 0x01, // section id, size, func count
		0x12,       // body size
		0x00,       // 0 local decls
		0x02, 0x40, // block (empty blocktype)
		0x03, 0x7f, // loop (result i32)
		0x20, 0x00, // local.get 0
		0x0e, 0x03, 0x01, 0x01, 0x00, 0x00, // br_table [1 1 0] default 0
		0x0b,       // end loop
		0x0b,       // end block
		0x41, 0x00, // i32.const 0
		0x0b, // end func
	}
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f, err := LowerFunction(mod, 0, "f", testThrowSet(mod))
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	var bt *ssa.Block
	for _, b := range f.Blocks {
		if b.Kind == ssa.BlockBrTable {
			if bt != nil {
				t.Fatalf("more than one BlockBrTable")
			}
			bt = b
		}
	}
	if bt == nil {
		t.Fatalf("no BlockBrTable produced; arity-0 br_table should not lower to an If chain:\n%s", ssa.FuncString(f))
	}
	if len(bt.Succs) != 2 {
		t.Fatalf("want 2 deduped successors, got %d:\n%s", len(bt.Succs), ssa.FuncString(f))
	}
	if bt.Control == nil || bt.Control.Type != ssa.TypeI32 {
		t.Fatalf("BrTable control missing or not i32")
	}
	// Succ 0 = the block target (cases 0,1); succ 1 = the loop header
	// (case 2 + default).
	if got := bt.TableCases[0]; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("succ0 cases = %v, want [0 1]", got)
	}
	if got := bt.TableCases[1]; len(got) != 1 || got[0] != 2 {
		t.Fatalf("succ1 cases = %v, want [2]", got)
	}
	if bt.TableDefault != 1 {
		t.Fatalf("TableDefault = %d, want 1", bt.TableDefault)
	}
	if err := ssa.Verify(f); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
