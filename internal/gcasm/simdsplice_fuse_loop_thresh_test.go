package gcasm

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// floorLoop is carryLoop rewritten as a do-while with a signed floor
// exit: repeat while counter > 1 (the rotated count-down-to-K shape).
func floorLoop() *simdfuse.Loop {
	l := carryLoop()
	l.PreTest = false
	l.ExitGT = true
	l.ExitThresh = 1
	return l
}

// The floor form must exit on a SIGNED compare against the threshold,
// not the exact-zero test: a counter that skips past the floor (or
// starts at/below it) still terminates after the mandatory first
// iteration.
func TestX64LoopFloorBackedge(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceLoop(&b, floorLoop(), &ConstPool{}, fuseTestOffs, "0", false, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if !strings.Contains(body, "$1") || !strings.Contains(body, "JGT gcasmfxl0") {
		t.Errorf("no signed floor backedge:\n%s", body)
	}
	if strings.Contains(body, "JNE gcasmfxl0") {
		t.Errorf("exact-zero backedge left in floor loop:\n%s", body)
	}
}

func TestA64LoopFloorBackedge(t *testing.T) {
	var b strings.Builder
	spliced, _, err := a64SpliceLoop(&b, floorLoop(), &ConstPool{}, fuseTestOffs, "0", false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	if !strings.Contains(body, "CMPW $1,") || !strings.Contains(body, "BGT gcasmfxl0") {
		t.Errorf("no signed floor backedge:\n%s", body)
	}
	if strings.Contains(body, "CBNZW") {
		t.Errorf("exact-zero backedge left in floor loop:\n%s", body)
	}
}

// A floor on the pre-tested while form has no emitted meaning; the
// splicers must refuse it rather than silently emit the wrong exit.
func TestLoopFloorRejectsPreTest(t *testing.T) {
	l := floorLoop()
	l.PreTest = true
	var b strings.Builder
	if _, _, err := x64SpliceLoop(&b, l, &ConstPool{}, fuseTestOffs, "0", false, 0); err == nil {
		t.Error("x64: pre-tested floor loop not refused")
	}
	if _, _, err := a64SpliceLoop(&b, l, &ConstPool{}, fuseTestOffs, "0", false); err == nil {
		t.Error("a64: pre-tested floor loop not refused")
	}
}
