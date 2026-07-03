package codegen

import (
	"bytes"
	"go/format"
	"go/token"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestMemBaseRefreshAfterGrow pins the exact soundness contract of the
// base hoist at the emitter level: in a function that both touches
// memory and can grow it, the emitted body must (1) declare the
// hoisted base first, (2) route every load/store through it, and
// (3) re-read m.M immediately after each grow-capable value — the
// only points where the backing array can relocate.
func TestMemBaseRefreshAfterGrow(t *testing.T) {
	fsig := ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}}
	b := ssa.NewFuncBuilder("growmix", fsig)
	b0 := b.NewBlock(ssa.BlockRet)
	b.SetEntry(b0)
	b.SetCurrent(b0)
	addr := b.Param(0, ssa.TypeI32)
	before := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, addr)
	pages := b.Const32(1)
	grown := b.NewValue(ssa.OpMemGrow, ssa.TypeI32, pages)
	after := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 4, addr)
	sum := b.NewValue(ssa.OpAdd32, ssa.TypeI32, before, after)
	sum2 := b.NewValue(ssa.OpAdd32, ssa.TypeI32, sum, grown)
	b.FinishRet(sum2)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	body, err := emitSSAFuncBody(b.Func())
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, token.NewFileSet(), body); err != nil {
		t.Fatalf("format: %v", err)
	}
	src := buf.String()

	declIdx := strings.Index(src, "mBase := m.M")
	if declIdx < 0 {
		t.Fatalf("no hoisted declaration:\n%s", src)
	}
	growIdx := strings.Index(src, "memoryGrow(m")
	if growIdx < 0 {
		// nil-translator emission spells the helper differently only
		// if helperRef changes; pin failure loudly either way.
		t.Fatalf("no grow site found:\n%s", src)
	}
	refreshIdx := strings.Index(src, "mBase = m.M")
	if refreshIdx < 0 {
		t.Fatalf("no refresh after grow:\n%s", src)
	}
	if declIdx >= growIdx || growIdx >= refreshIdx {
		t.Fatalf("order wrong (decl=%d grow=%d refresh=%d):\n%s", declIdx, growIdx, refreshIdx, src)
	}
	if strings.Contains(src, "unsafe.Add(m.M") {
		t.Fatalf("memop bypassed hoisted base:\n%s", src)
	}
	// The load AFTER the grow must read through the refreshed base —
	// i.e. appear after the refresh in statement order.
	lastLoad := strings.LastIndex(src, "unsafe.Add(mBase")
	if lastLoad < refreshIdx {
		t.Fatalf("post-grow load precedes the refresh:\n%s", src)
	}
}
