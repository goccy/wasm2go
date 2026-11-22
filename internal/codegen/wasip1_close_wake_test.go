package codegen

import (
	"net"
	"testing"
	"time"
)

// closeConn is a connection whose Close tells closing that it was called
// and then waits for release.
type closeConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
}

func (c *closeConn) Close() error {
	close(c.closing)
	<-c.release
	return c.Conn.Close()
}

// woken reports whether a byte waits in the wake pipe wk.
func woken(t *testing.T, wk *wasiWake) bool {
	t.Helper()
	ready := []bool{false}
	if err := hostWaitReady([]uintptr{uintptr(wk.r)}, []int{hostWantInput}, ready, time.Now(), -1); err != nil {
		t.Fatal(err)
	}
	return ready[0]
}

// A close of a descriptor wakes the waits in poll(2) for it once it is
// closed, not before.
func TestWasi_CloseWakesWaitsOnceClosed(t *testing.T) {
	if !hostPolls {
		t.Skip("the host has no poll(2)")
	}
	w, m := newTestStubs(t, t.TempDir())
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close the peer: %v", err)
		}
	})
	conn := &closeConn{Conn: local, closing: make(chan struct{}), release: make(chan struct{})}
	w.mu.Lock()
	fd := w.addFDLocked(&wasiOpen{conn: conn})
	op := w.openLocked(fd)
	w.mu.Unlock()
	wk, err := w.takeWake()
	if err != nil {
		t.Fatal(err)
	}
	op.addWaiter(wk)
	closed := make(chan int32, 1)
	go func() { closed <- w.Fd_close(m, fd) }()
	<-conn.closing
	if woken(t, wk) {
		t.Fatal("the wait was woken before its descriptor was closed")
	}
	close(conn.release)
	if rc := <-closed; rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	if !woken(t, wk) {
		t.Fatal("the wait was not woken once its descriptor was closed")
	}
	if err := w.giveWake(wk, []hostWaitFD{{op: op}}); err != nil {
		t.Fatal(err)
	}
}
