package helpers

import (
	"testing"
)

// waitEnd runs wait and returns what it panics with, or nil if it returns.
func waitEnd(wait func()) (end any) {
	defer func() { end = recover() }()
	wait()
	return nil
}

// Once the instance has ended (stopAgents), a parked wait — forever or with a
// timeout — and a wait that begins later panic with the end instead of
// returning, and the first end is the one.
func TestStopAgentsEndsTheWaits(t *testing.T) {
	m := newMemModuleM(64)
	m.memShared = true
	m.threads.nextTID.Store(1) // a sibling agent exists to notify
	parked := make(chan uint64)
	m.threads.parkedHook = parked
	atomicStore32(m, 0, 0, 0)
	ended := make(chan any, 2)
	go func() { ended <- waitEnd(func() { atomicWait32(m, 0, 0, 0, -1) }) }()
	go func() { ended <- waitEnd(func() { atomicWait32(m, 0, 0, 0, 1<<62) }) }()
	<-parked
	<-parked
	m.threads.parkedHook = nil
	end := &struct{ code int }{7}
	stopAgents(m, end)
	stopAgents(m, &struct{ code int }{8})
	for range 2 {
		if got := <-ended; got != end {
			t.Fatalf("a parked wait ended with %v, want %v", got, end)
		}
	}
	if got := waitEnd(func() { atomicWait32(m, 0, 0, 0, -1) }); got != end {
		t.Fatalf("a wait after the end ended with %v, want %v", got, end)
	}
}
