package codegen

import (
	"errors"
	"net"
	"sync"
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

// newCloseConn returns a closeConn on one end of a pipe, and release, which
// lets its close through; it runs when the test ends too.
func newCloseConn(t *testing.T) (conn *closeConn, release func()) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close the peer: %v", err)
		}
	})
	conn = &closeConn{Conn: local, closing: make(chan struct{}), release: make(chan struct{})}
	release = sync.OnceFunc(func() { close(conn.release) })
	t.Cleanup(release)
	return conn, release
}

// closeAllAtCleanup closes the descriptors of w when the test ends.
func closeAllAtCleanup(t *testing.T, w *WasiStubs) {
	t.Helper()
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
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
	closeAllAtCleanup(t, w)
	conn, release := newCloseConn(t)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: conn})
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
	release()
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

// Only the clearing of a descriptor's last slot wakes the waits in poll(2)
// for it: a renumbering, a close of a duplicate, and a forked instance's
// closing of the slots it inherited leave the descriptor open, and its
// waits waiting.
func TestWasi_OnlyTheLastSlotWakesWaits(t *testing.T) {
	if !hostPolls {
		t.Skip("the host has no poll(2)")
	}
	w, m := newTestStubs(t, t.TempDir())
	closeAllAtCleanup(t, w)
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := errors.Join(local.Close(), peer.Close()); err != nil {
			t.Errorf("close the pipe: %v", err)
		}
	})
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: local})
	op := w.openLocked(fd)
	w.mu.Unlock()
	wk, err := w.takeWake()
	if err != nil {
		t.Fatal(err)
	}
	op.addWaiter(wk)
	if rc := w.Fd_dup(m, fd, 900); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	dup := int32(readU32(m.memory, 900))
	if rc := w.Fd_renumber(m, fd, 40); rc != _wasiESUCCESS {
		t.Fatalf("Fd_renumber rc=%d", rc)
	}
	if woken(t, wk) {
		t.Fatal("a renumbering woke the wait")
	}
	child := w.Fork()
	if rc := child.Fd_closefrom(newForkTestModule(), 0); rc != _wasiESUCCESS {
		t.Fatalf("the child's Fd_closefrom rc=%d", rc)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatalf("the child's CloseAll: %v", err)
	}
	if woken(t, wk) {
		t.Fatal("the child's closing of its slots woke the parent's wait")
	}
	if rc := w.Fd_close(m, 40); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	if woken(t, wk) {
		t.Fatal("the close of a duplicate woke the wait")
	}
	if rc := w.Fd_close(m, dup); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close of the last slot rc=%d", rc)
	}
	if !woken(t, wk) {
		t.Fatal("the close of the last slot did not wake the wait")
	}
	if err := w.giveWake(wk, []hostWaitFD{{op: op}}); err != nil {
		t.Fatal(err)
	}
}

// Clearing a slot clears its close-on-exec mark, whichever call clears it.
func TestWasi_ClearedSlotsAreNotCloseOnExec(t *testing.T) {
	for _, c := range []struct {
		name  string
		clear func(w *WasiStubs, m *Module, fd int32) int32
	}{
		{"fd_close", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_close(m, fd) }},
		{"fd_closefrom", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_closefrom(m, fd) }},
		{"fd_renumber", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_renumber(m, fd, fd+1) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			closeAllAtCleanup(t, w)
			fd := pipeSlot(t, w, false)
			if rc := w.Fd_cloexec(m, fd, 1, 1, 900); rc != _wasiESUCCESS {
				t.Fatalf("Fd_cloexec rc=%d", rc)
			}
			if rc := c.clear(w, m, fd); rc != _wasiESUCCESS {
				t.Fatalf("%s rc=%d", c.name, rc)
			}
			w.mu.Lock()
			marked := w.cloexec[fd]
			w.mu.Unlock()
			if marked {
				t.Errorf("%s left fd %d close-on-exec", c.name, fd)
			}
		})
	}
}

// failingConn is a connection whose Close fails with errCloseFailed.
type failingConn struct{ net.Conn }

var errCloseFailed = errors.New("close failed")

func (c failingConn) Close() error { return errors.Join(c.Conn.Close(), errCloseFailed) }

// A dup2 or renumbering onto a slot is done once the slot holds the other
// descriptor: it returns 0, and a failure to close what the slot held goes
// to WASIConfig.Errors.
func TestWasi_ReplacingASlotReportsTheCloseFailure(t *testing.T) {
	for _, c := range []struct {
		call    string
		replace func(w *WasiStubs, m *Module, from, to int32) int32
	}{
		{"fd_dup2", func(w *WasiStubs, m *Module, from, to int32) int32 { return w.Fd_dup2(m, from, to) }},
		{"fd_renumber", func(w *WasiStubs, m *Module, from, to int32) int32 { return w.Fd_renumber(m, from, to) }},
	} {
		t.Run(c.call, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			closeAllAtCleanup(t, w)
			var reported []string
			w.cfg.Errors = func(op string, err error) {
				if errors.Is(err, errCloseFailed) {
					reported = append(reported, op)
				}
			}
			from, to := pipeSlot(t, w, false), pipeSlot(t, w, true)
			if rc := c.replace(w, m, from, to); rc != _wasiESUCCESS {
				t.Fatalf("%s rc=%d", c.call, rc)
			}
			if len(reported) != 1 || reported[0] != c.call {
				t.Fatalf("reported %v, want the close failure of %s", reported, c.call)
			}
		})
	}
}

// pipeSlot adds a slot for one end of a pipe, whose close fails when
// failing is set, and returns its number.
func pipeSlot(t *testing.T, w *WasiStubs, failing bool) int32 {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close the peer: %v", err)
		}
	})
	conn := local
	if failing {
		conn = failingConn{local}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return addTestFD(w, &wasiOpen{conn: conn})
}

// A close does not hold the instance's lock while the descriptor closes,
// whichever import closes it.
func TestWasi_CloseLetsOtherCallsGoOn(t *testing.T) {
	for _, c := range []struct {
		name  string
		close func(w *WasiStubs, m *Module, fd int32) int32
		// want is what fd_fdstat_get of fd 0 returns meanwhile.
		want int32
	}{
		{"fd_close", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_close(m, fd) }, _wasiESUCCESS},
		{"fd_closefrom", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_closefrom(m, fd) }, _wasiESUCCESS},
		{"fd_dup2", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_dup2(m, 1, fd) }, _wasiESUCCESS},
		{"fd_renumber", func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_renumber(m, 1, fd) }, _wasiESUCCESS},
		{"CloseAll", func(w *WasiStubs, m *Module, fd int32) int32 { return errnoOfError(w.CloseAll()) }, _wasiEBADF},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, _ := newProcTestStubs(t)
			closeAllAtCleanup(t, w)
			conn, release := newCloseConn(t)
			w.mu.Lock()
			fd := addTestFD(w, &wasiOpen{conn: conn})
			w.mu.Unlock()
			closed := make(chan int32, 1)
			go func() { closed <- c.close(w, newForkTestModule(), fd) }()
			<-conn.closing
			// The descriptor is closing: the instance's lock is free.
			if !w.mu.TryLock() {
				t.Fatal("the close holds the instance's lock")
			}
			w.mu.Unlock()
			if rc := w.Fd_fdstat_get(newForkTestModule(), 0, 0); rc != c.want {
				t.Fatalf("fd_fdstat_get while the descriptor closes rc=%d, want %d", rc, c.want)
			}
			release()
			if rc := <-closed; rc != _wasiESUCCESS {
				t.Fatalf("close rc=%d", rc)
			}
		})
	}
}
