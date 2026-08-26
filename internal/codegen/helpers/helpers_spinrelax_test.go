package helpers

import "testing"

// TestSpinRelax exercises the cold half of the spin-loop preemption
// guard: reaching runtime.Gosched must never block the caller, only
// donate the core.
func TestSpinRelax(t *testing.T) {
	for i := 0; i < 64; i++ {
		spinRelax()
	}
}
