//go:build darwin || linux

package codegen

import (
	"syscall"
	"testing"
	"time"
)

// blocks reports whether f, run on a goroutine, is still running after a
// while, and waits for it to end once release has been called.
func blocks(t *testing.T, f func(), release func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	var blocked bool
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		blocked = true
	}
	release()
	<-done
	return blocked
}

// The runtime makes the pipes of its own (a waiting call's waker, the pipe
// a poll that ends when the embedder's stream is ready waits on) under
// hostTable.making: while they have low numbers, nobody's and the waker's
// not close-on-exec, they are not to be taken for descriptors that code
// outside the guest left open for a command. While a take-over holds it,
// neither is made; once made, both are above the range programs use.
// Before, a command another process of the family started could be given
// the waker's end under its low number (Run's t/fdtable.t: a command found
// descriptor 5 open after the program had closed it).
func TestHostDescriptors_TheRuntimesPipesAreMadeUnderTheMakingLock(t *testing.T) {
	w, _ := newHostGuest(t, t.TempDir())
	var waker *hostWaker
	hostTable.making.Lock()
	if !blocks(t, func() {
		w.mu.Lock()
		waker, _ = w.hostWakerLocked()
		w.mu.Unlock()
	}, hostTable.making.Unlock) {
		t.Errorf("the waker was made while a take-over held hostTable.making")
	}
	if waker == nil || waker.r < hostFloor() || waker.w < hostFloor() {
		t.Fatalf("the waker's ends are %v, below %d", waker, hostFloor())
	}
	stop := make(chan struct{})
	close(stop)
	hostTable.making.Lock()
	if !blocks(t, func() {
		hostPollStoppable([]hostPoll{{fd: int32(waker.r), events: hostPollIn}}, time.Now().Add(time.Second), stop)
	}, hostTable.making.Unlock) {
		t.Errorf("the pipe of a stoppable poll was made while a take-over held hostTable.making")
	}
}

// The descriptors code outside the guest left open for a command are looked
// for under hostTable.making held for writing: one the runtime is making
// at the moment, open under a low number and not close-on-exec, is not
// among them.
func TestHostDescriptors_ACommandIsNotGivenADescriptorTheRuntimeIsMaking(t *testing.T) {
	w, _ := newHostGuest(t, t.TempDir())
	hostTable.making.RLock()
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		hostTable.making.RUnlock()
		t.Fatal(err)
	}
	var given []*hostFile
	if !blocks(t, func() {
		w.mu.Lock()
		given = w.inheritableOutsideLocked()
		w.mu.Unlock()
	}, func() {
		// made: moved away from the low numbers, as the waker's ends are
		_ = syscall.Close(p[0])
		_ = syscall.Close(p[1])
		hostTable.making.RUnlock()
	}) {
		t.Errorf("descriptors left open outside the guest were looked for while one was being made")
	}
	for _, h := range given {
		if fd := int(h.fd.Load()); fd == p[0] || fd == p[1] {
			t.Errorf("a command is given descriptor %d, which the runtime was making", fd)
		}
	}
}
