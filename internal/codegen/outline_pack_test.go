package codegen

import (
	"bytes"
	"go/printer"
	"go/token"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

func renderExpr(t *testing.T, e interface{ Pos() token.Pos }) string {
	t.Helper()
	var b bytes.Buffer
	if err := printer.Fprint(&b, token.NewFileSet(), e); err != nil {
		t.Fatalf("print: %v", err)
	}
	return b.String()
}

// The packed outline boundary spells reads and writes of the
// per-module scratch with exact reinterpret round-trips per type.
func TestPackSlotReadWriteSpelling(t *testing.T) {
	tr := &translator{}
	if got := renderExpr(t, tr.packSlot(3)); got != "m."+tr.fieldName("outlinePack")+"[3]" {
		t.Errorf("packSlot = %s", got)
	}
	reads := map[ssa.Type]string{
		ssa.TypeI32: "int32(uint32(",
		ssa.TypeI64: "int64(",
		ssa.TypeF32: "f32_reinterpret_i32(int32(uint32(",
		ssa.TypeF64: "f64_reinterpret_i64(int64(",
	}
	for typ, want := range reads {
		got := renderExpr(t, tr.packSlotRead(0, typ))
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Errorf("packSlotRead(%v) = %s, want fragment %q", typ, got, want)
		}
	}
	arg := newID("v")
	writes := map[ssa.Type]string{
		ssa.TypeI32: "uint64(uint32(v))",
		ssa.TypeI64: "uint64(v)",
		ssa.TypeF32: "uint64(uint32(i32_reinterpret_f32(v)))",
		ssa.TypeF64: "uint64(i64_reinterpret_f64(v))",
	}
	for typ, want := range writes {
		if got := renderExpr(t, tr.packSlotWrite(arg, typ)); got != want {
			t.Errorf("packSlotWrite(%v) = %s, want %s", typ, got, want)
		}
	}
}
