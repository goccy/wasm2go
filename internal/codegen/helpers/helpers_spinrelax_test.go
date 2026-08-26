package helpers

import "testing"

// TestSpinRelax exercises the preemption valve the emitters plant in
// bare atomic spin loops: the counter advances on every call, and
// driving it far past the yield period (every 1024th call reaches
// runtime.Gosched) completes without stalling — the guard must never
// block the spinning goroutine, only donate the core.
func TestSpinRelax(t *testing.T) {
	var c uint32
	for i := 0; i < 4096; i++ {
		spinRelax(&c)
	}
	if c != 4096 {
		t.Errorf("spinRelax counter = %d, want 4096", c)
	}
}
