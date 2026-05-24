package ssa

import "testing"

// buildFrameFunc constructs a single-block function with the standard
// stack-frame prologue (g0 - N), one frame store + one frame load, and
// an epilogue. escape, when true, additionally passes the frame
// pointer to a call so the escape analysis trips.
func buildFrameFunc(escape bool) *Func {
	b := NewFuncBuilder("frametest", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := b.NewBlock(BlockPlain)
	b.SetEntry(entry)
	b.SetCurrent(entry)

	p0 := b.Param(0, TypeI32)
	g0 := b.NewValueAuxInt(OpGlobalGet, TypeI32, 0)  // global.get 0
	n := b.Const32(16)                               // frame size
	fp := b.NewValue(OpSub32, TypeI32, g0, n)        // fp = g0 - 16
	b.NewValueAuxInt(OpGlobalSet, TypeMem, 0, fp)    // global.set 0
	b.NewValueAuxInt(OpStore32, TypeMem, 0, fp, p0)  // store [fp+0] = p0
	ld := b.NewValueAuxInt(OpLoad32, TypeI32, 0, fp) // load  [fp+0]
	if escape {
		// call f(fp) — passing the frame pointer escapes the frame.
		b.NewValueAux(OpCallDirect, TypeI32, nil, fp)
	}
	restore := b.NewValue(OpAdd32, TypeI32, fp, b.Const32(16))
	b.NewValueAuxInt(OpGlobalSet, TypeMem, 0, restore) // global.set 0 (epilogue)
	b.FinishRet(ld)
	return b.Func()
}

func TestClassifyMemoryFrameNonEscaping(t *testing.T) {
	f := buildFrameFunc(false)
	mc := ClassifyMemory(f)
	if mc.FramePtr == nil {
		t.Fatal("frame pointer not detected")
	}
	if mc.FrameSize != 16 {
		t.Errorf("FrameSize = %d, want 16", mc.FrameSize)
	}
	if mc.FrameEscapes {
		t.Errorf("frame wrongly reported as escaping: %s", mc.EscapeReason)
	}
	frame := 0
	for _, c := range mc.Class {
		if c == AliasFrame {
			frame++
		}
	}
	if frame != 2 {
		t.Errorf("expected 2 frame-classified accesses (1 store + 1 load), got %d", frame)
	}
}

func TestClassifyMemoryFrameEscaping(t *testing.T) {
	f := buildFrameFunc(true)
	mc := ClassifyMemory(f)
	if mc.FramePtr == nil {
		t.Fatal("frame pointer not detected")
	}
	if !mc.FrameEscapes {
		t.Fatal("frame should escape when fp is passed to a call")
	}
	// Escaping frame demotes every access back to slab.
	for id, c := range mc.Class {
		if c != AliasSlab {
			t.Errorf("v%d classified %s, want slab (frame escaped)", id, c)
		}
	}
}

func TestMemMetricsAggregate(t *testing.T) {
	m := NewMemMetrics()
	f1 := buildFrameFunc(false) // 2 frame accesses
	f1.Name = "kept"
	f2 := buildFrameFunc(true) // 2 slab accesses (escaped)
	f2.Name = "escaped"
	m.Add(f1, ClassifyMemory(f1))
	m.Add(f2, ClassifyMemory(f2))

	if m.Total != 4 {
		t.Errorf("Total = %d, want 4", m.Total)
	}
	if m.Frame != 2 {
		t.Errorf("Frame = %d, want 2", m.Frame)
	}
	if m.Slab != 2 {
		t.Errorf("Slab = %d, want 2", m.Slab)
	}
	if m.FuncsWithFrame != 2 || m.FuncsFrameKept != 1 {
		t.Errorf("FuncsWithFrame=%d FuncsFrameKept=%d, want 2/1", m.FuncsWithFrame, m.FuncsFrameKept)
	}
	if got := m.Rate(); got != 0.5 {
		t.Errorf("Rate = %v, want 0.5", got)
	}
	if _, err := m.JSON(); err != nil {
		t.Errorf("JSON: %v", err)
	}
}
