package codegen

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// loadSignalFlag reads the guest's flag word as the guest does, atomically.
func loadSignalFlag(m *Module) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&m.memory[sigFlagOff])))
}

// The wake of a blocking call runs without a lock of the instance held: the
// instance goes on — its descriptors, its signal state — while one runs.
func TestSignal_AWakeRunsWithoutALockOfTheInstance(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	entered, release := make(chan struct{}), make(chan struct{})
	b, ok := w.beginBlocking(func() {
		close(entered)
		<-release
	})
	if !ok {
		t.Fatal("beginBlocking refused with no signal posted")
	}
	posted := make(chan struct{})
	go func() {
		defer close(posted)
		w.PostSignal(wasiSIGUSR1)
	}()
	<-entered
	returnsWithin(t, "Fd_fdstat_get while a wake runs", func() {
		if rc := w.Fd_fdstat_get(m, 1, sigValueOff); rc != _wasiESUCCESS {
			t.Errorf("Fd_fdstat_get rc=%d", rc)
		}
	})
	returnsWithin(t, "PostSignal while a wake runs", func() { w.PostSignal(wasiSIGUSR2) })
	close(release)
	<-posted
	if !w.endBlocking(b) {
		t.Fatal("the call the signal woke was not interrupted")
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1, wasiSIGUSR2); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}
}

// A blocking call whose wake was called ends once the wake has returned, so
// that the wake does nothing to what the caller does next.
func TestSignal_ABlockingCallEndsAfterItsWake(t *testing.T) {
	w, _ := newSignalGuest(t, wasiSIGUSR1)
	entered, release := make(chan struct{}), make(chan struct{})
	woke := 0
	b, ok := w.beginBlocking(func() {
		close(entered)
		<-release
		woke++
	})
	if !ok {
		t.Fatal("beginBlocking refused with no signal posted")
	}
	go w.PostSignal(wasiSIGUSR1)
	<-entered
	close(release)
	if !w.endBlocking(b) {
		t.Fatal("the call the signal woke was not interrupted")
	}
	if woke != 1 {
		t.Fatalf("endBlocking returned before the wake (%d returns)", woke)
	}
}

// The interrupt of the code outside the guest runs without a lock of the
// instance held, so it may post a signal itself; and a registration that is
// replaced has no call left running once SetOutsideInterrupt has returned.
func TestSignal_OutsideInterruptRunsWithoutALockOfTheInstance(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	again := false
	w.SetOutsideInterrupt(func() {
		if !again {
			again = true
			w.PostSignal(wasiSIGUSR2)
		}
	})
	returnsWithin(t, "PostSignal of an interrupt that posts", func() { w.PostSignal(wasiSIGUSR1) })
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1, wasiSIGUSR2); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	w.SetOutsideInterrupt(func() {
		close(entered)
		<-release
		calls++
	})
	go w.PostSignal(wasiSIGUSR1)
	<-entered
	close(release)
	w.SetOutsideInterrupt(nil)
	if calls != 1 {
		t.Fatalf("SetOutsideInterrupt returned before the call of the interrupt it replaced (%d returns)", calls)
	}
}

// The flag word is stored atomically, for a guest that loads it atomically
// while a signal is posted from another goroutine: the guest spins on the
// word until it is raised.
func TestSignal_FlagIsStoredAtomically(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	raised := make(chan struct{})
	go func() {
		defer close(raised)
		for loadSignalFlag(m) != 1 {
			runtime.Gosched()
		}
	}()
	w.PostSignal(wasiSIGUSR1)
	<-raised
	if rc := w.Proc_signal_register(m, sigFlagOff+1); rc != -_wasiEINVAL {
		t.Fatalf("Proc_signal_register of an unaligned word rc=%d, want -EINVAL", rc)
	}
}

// A blocking call that a signal interrupts ends with the flag word up: the
// guest, looking for the signal, finds it.
func TestSignal_AnInterruptedCallEndsWithTheFlagUp(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	// The flag is not raised until the test lets it: the post is on its way.
	w.sig.flagMu.Lock()
	go w.PostSignal(wasiSIGUSR1)
	for {
		w.sig.mu.Lock()
		pending := w.sig.pending
		w.sig.mu.Unlock()
		if pending != 0 {
			break
		}
		runtime.Gosched()
	}
	type end struct {
		rc   int32
		flag uint32
	}
	ended := make(chan end, 1)
	go func() {
		writeSubClock(m, pollSubsOff, 1, int64(time.Hour))
		rc := w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff)
		ended <- end{rc, loadSignalFlag(m)}
	}()
	for {
		w.sig.mu.Lock()
		blocked := len(w.sig.wakes)
		w.sig.mu.Unlock()
		if blocked == 1 {
			break
		}
		select {
		case e := <-ended:
			t.Fatalf("the sleep ended (rc=%d, flag %d) before the flag was raised", e.rc, e.flag)
		default:
		}
		runtime.Gosched()
	}
	w.sig.flagMu.Unlock()
	if e := <-ended; e.rc != _wasiEINTR || e.flag != 1 {
		t.Fatalf("the sleep ended with rc=%d and flag %d, want EINTR and 1", e.rc, e.flag)
	}
}

// The configuration and the start of the monotonic clock never change, and
// are read without the lock of the instance.
func TestWasi_ConfigIsReadWithoutTheLock(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.cfg.Resolve = func(string) bool { return false }
	w.mu.Lock()
	defer w.mu.Unlock()
	returnsWithin(t, "Clock_time_get(MONOTONIC)", func() {
		if rc := w.Clock_time_get(m, 1, 0, sigValueOff); rc != _wasiESUCCESS {
			t.Errorf("Clock_time_get rc=%d", rc)
		}
	})
	returnsWithin(t, "allowedPath", func() { w.allowedPath("x", false) })
	returnsWithin(t, "checkNet", func() { w.checkNet("connect") })
	host, n := putPath(m, pollSubsOff, "example.invalid")
	returnsWithin(t, "Sock_getaddrinfo", func() {
		if rc := w.Sock_getaddrinfo(m, host, n, sigValueOff); rc != -_wasiEACCES {
			t.Errorf("Sock_getaddrinfo of a refused name rc=%d, want -EACCES", rc)
		}
	})
}
