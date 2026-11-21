package codegen

import (
	"testing"
	"time"
)

// Several processes of a fork family waiting on ONE descriptor — readers of
// one pipe — are each reached by a signal of their own.

// sharedWaiters forks n instances of w, each with a guest that has
// registered for signals and handles SIGTERM.
func sharedWaiters(t *testing.T, w *WasiStubs, n int) (instances []*WasiStubs, modules []*Module) {
	t.Helper()
	for i := 0; i < n; i++ {
		child, cm := w.Fork(), newForkTestModule()
		t.Cleanup(func() {
			if err := child.CloseAll(); err != nil {
				t.Error(err)
			}
		})
		if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
			t.Fatalf("Proc_signal_register rc=%d", rc)
		}
		setDispositions(t, child, cm, signalMask(wasiSIGTERM), 0, 0)
		instances = append(instances, child)
		modules = append(modules, cm)
	}
	return instances, modules
}

// waitAll starts wait for every instance, lets them block, signals each one
// and requires every wait to end with EINTR.
func waitAll(t *testing.T, instances []*WasiStubs, modules []*Module, what string, wait func(w *WasiStubs, m *Module) int32) {
	t.Helper()
	results := make(chan int32, len(instances))
	for i := range instances {
		go func(w *WasiStubs, m *Module) { results <- wait(w, m) }(instances[i], modules[i])
	}
	select {
	case rc := <-results:
		t.Fatalf("%s returned %d with nothing to wait for", what, rc)
	case <-time.After(100 * time.Millisecond):
	}
	for _, w := range instances {
		w.PostSignal(wasiSIGTERM)
	}
	timeout := time.After(waitLimit)
	for done := 0; done < len(instances); done++ {
		select {
		case rc := <-results:
			if rc != _wasiEINTR {
				t.Errorf("%s rc=%d, want EINTR", what, rc)
			}
		case <-timeout:
			t.Fatalf("%d of %d processes are still in %s after their signal", len(instances)-done, len(instances), what)
		}
	}
	for i := range instances {
		takeSignals(t, instances[i], modules[i])
	}
}

func TestSignal_EveryProcessBlockedReadingOnePipeTakesItsSignal(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	instances, modules := sharedWaiters(t, w, 5)
	read := func(w *WasiStubs, m *Module) int32 {
		_, rc := fdReadString(w, m, readFd, 16)
		return rc
	}
	for round := 0; round < 3; round++ {
		waitAll(t, instances, modules, "read", read)
	}
	// Input written now reaches a reader.
	got := make(chan string, 1)
	go func() {
		s, rc := fdReadString(instances[0], modules[0], readFd, 16)
		if rc != _wasiESUCCESS {
			s = "error"
		}
		got <- s
	}()
	if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	select {
	case s := <-got:
		if s != "data" {
			t.Fatalf("read %q, want %q", s, "data")
		}
	case <-time.After(waitLimit):
		t.Fatal("the input did not reach the reader")
	}
}

func TestSignal_EveryProcessPollingOnePipeTakesItsSignal(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	instances, modules := sharedWaiters(t, w, 5)
	poll := func(w *WasiStubs, m *Module) int32 {
		writeSubFd(m, pollSubsOff, 7, 1 /* fd_read */, readFd)
		return w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff)
	}
	for round := 0; round < 3; round++ {
		waitAll(t, instances, modules, "poll", poll)
	}
}

// A process polling a descriptor that another process is blocked reading
// gets its timeout, and does not disturb the reader.
func TestWasi_PollTimesOutBesideABlockedReader(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	instances, modules := sharedWaiters(t, w, 2)
	read := make(chan string, 1)
	go func() {
		s, rc := fdReadString(instances[0], modules[0], readFd, 16)
		if rc != _wasiESUCCESS {
			s = "error"
		}
		read <- s
	}()
	time.Sleep(50 * time.Millisecond)

	pm := modules[1]
	writeSubFd(pm, pollSubsOff, 7, 1 /* fd_read */, readFd)
	writeSubClock(pm, pollSubsOff+48, 9, int64(60*time.Millisecond))
	start := time.Now()
	var rc int32
	returnsWithin(t, "Poll_oneoff", func() { rc = instances[1].Poll_oneoff(pm, pollSubsOff, pollEvOff, 2, pollNevOff) })
	if rc != _wasiESUCCESS {
		t.Fatalf("Poll_oneoff rc=%d", rc)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the poll took %v, its timeout is 60ms", waited)
	}
	if n := readU32(pm.memory, int(pollNevOff)); n != 1 || readU64(pm.memory, int(pollEvOff)) != 9 {
		t.Fatalf("poll reported %d events, first userdata %d; want the timeout only", n, readU64(pm.memory, int(pollEvOff)))
	}
	// A non-blocking read beside the blocked reader finds nothing.
	if rc := instances[1].Fd_fdstat_set_flags(pm, readFd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	returnsWithin(t, "a read that does not wait", func() { _, rc = fdReadString(instances[1], pm, readFd, 16) })
	if rc != _wasiEAGAIN {
		t.Fatalf("read without waiting rc=%d, want EAGAIN", rc)
	}
	select {
	case s := <-read:
		t.Fatalf("the blocked reader returned %q", s)
	default:
	}
	if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	select {
	case s := <-read:
		if s != "data" {
			t.Fatalf("the reader got %q, want %q", s, "data")
		}
	case <-time.After(waitLimit):
		t.Fatal("the blocked reader did not get the input")
	}
}
