package helpers

import (
	"runtime"
	"sync/atomic"
	"testing"
)

// TestSpinRelax exercises the cold half of the spin-loop preemption
// guard: reaching runtime.Gosched must never block the caller, only
// donate the core.
func TestSpinRelax(t *testing.T) {
	for i := 0; i < 64; i++ {
		spinRelax()
	}
}

// TestSpinRelaxOversubscribed: with more live agents than processors
// every cold call yields (the barrier-latency fix); the call still
// returns promptly and leaves the gauge untouched.
func TestSpinRelaxOversubscribed(t *testing.T) {
	procs := int32(runtime.GOMAXPROCS(0))
	spinAgentsAdd(procs - 1)
	if atomic.LoadUint32(&spinOversubscribed) != 0 {
		t.Fatalf("%d agents on %d procs flagged as oversubscribed", procs-1, procs)
	}
	spinAgentsAdd(1)
	if atomic.LoadUint32(&spinOversubscribed) == 0 {
		t.Fatalf("%d agents on %d procs not flagged", procs, procs)
	}
	for i := 0; i < 64; i++ {
		spinRelax()
	}
	spinAgentsAdd(-procs)
	if got := atomic.LoadInt32(&spinAgents); got != 0 {
		t.Errorf("spinAgents = %d after every agent left", got)
	}
	if atomic.LoadUint32(&spinOversubscribed) != 0 {
		t.Error("still flagged with no agents")
	}
}
