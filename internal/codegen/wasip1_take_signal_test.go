package codegen

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// offeredSignal is one call of a WASIConfig.TakeSignal.
type offeredSignal struct {
	target SignalTarget
	sig    int32
}

// recordingTaker is a WASIConfig.TakeSignal that records what it is
// offered, runs during (when set) inside each call, and answers take, err.
type recordingTaker struct {
	mu     sync.Mutex
	offers []offeredSignal
	take   bool
	err    error
	during func(target SignalTarget, sig int32)
}

func (r *recordingTaker) takeSignal(target SignalTarget, sig int32) (bool, error) {
	r.mu.Lock()
	r.offers = append(r.offers, offeredSignal{target, sig})
	during, take, err := r.during, r.take, r.err
	r.mu.Unlock()
	if during != nil {
		during(target, sig)
	}
	return take, err
}

// offered returns what the taker has been offered so far.
func (r *recordingTaker) offered() []offeredSignal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]offeredSignal(nil), r.offers...)
}

// newTakingGuest returns a guest that handles the given signals, whose
// TakeSignal is a recordingTaker answering take.
func newTakingGuest(t *testing.T, take bool, handled ...int32) (*WasiStubs, *Module, *recordingTaker) {
	t.Helper()
	w, m := newSignalGuest(t, handled...)
	r := &recordingTaker{take: take}
	w.cfg.TakeSignal = r.takeSignal
	return w, m, r
}

// The firing of the interval timer is offered TakeSignal, without a lock of
// the instance held: one it takes is not the guest's, and the timer goes on
// to its next firing; one it does not take is posted as before.
func TestTakeSignal_TimerAlarm(t *testing.T) {
	w, m, r := newTakingGuest(t, true, wasiSIGALRM, wasiSIGUSR2)
	// The taker posts a signal of its own, which it could not with the
	// lock of the instance's signals held: that one ends the sleep.
	r.during = func(target SignalTarget, sig int32) { target.PostSignal(wasiSIGUSR2) }
	setTimer(t, w, m, 20*time.Millisecond, 20*time.Millisecond)
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep under a timer rc=%d, want EINTR", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("taken = %#x, want the taker's SIGUSR2 alone (%#x)", got, want)
	}
	if got := r.offered(); len(got) == 0 || got[0] != (offeredSignal{w, wasiSIGALRM}) {
		t.Fatalf("offered %v, want SIGALRM for the guest", got)
	}
	// The interval goes on.
	before := len(r.offered())
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep under the repeating timer rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	if after := len(r.offered()); after <= before {
		t.Fatalf("offers %d after the next firing, want more than %d", after, before)
	}
	setTimer(t, w, m, 0, 0)

	w, m, r = newTakingGuest(t, false, wasiSIGALRM)
	setTimer(t, w, m, 20*time.Millisecond, 0)
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep under a timer not taken rc=%d, want EINTR", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM (%#x)", got, want)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGALRM}) {
		t.Fatalf("offered %v, want SIGALRM once", got)
	}
}

// A timer that came due when a blocking call of the guest's ends is offered
// before the call reports what interrupted it: one taken interrupts
// nothing; one not taken interrupts the call, and not the code outside the
// guest, as a post for the guest alone. The host's timer that fires while
// code outside the guest runs interrupts that code when the signal is not
// taken.
func TestTakeSignal_DueTimerInAGuestsCall(t *testing.T) {
	overdue := func(w *WasiStubs) {
		w.sig.mu.Lock()
		w.sig.timerAt = 0
		w.sig.mu.Unlock()
	}
	for _, take := range []bool{true, false} {
		w, m, r := newTakingGuest(t, take, wasiSIGALRM)
		outside := 0
		c := w.BeginOutside(m, func() { outside++ })
		setTimer(t, w, m, time.Hour, 0)
		key, ok := w.beginBlocking(m, func() {})
		if !ok {
			t.Fatal("a wait before the timer is due did not begin")
		}
		overdue(w)
		if interrupted := w.endBlocking(key); interrupted == take {
			t.Fatalf("taken %v: the wait interrupted %v", take, interrupted)
		}
		if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGALRM}) {
			t.Fatalf("taken %v: offered %v, want SIGALRM once", take, got)
		}
		want := signalMask(wasiSIGALRM)
		if take {
			want = 0
		}
		if got := takeSignals(t, w, m); got != want {
			t.Fatalf("taken %v: the guest took %#x, want %#x", take, got, want)
		}
		c.End()
		if outside != 0 {
			t.Fatalf("taken %v: the interrupt of the code outside was called %d times", take, outside)
		}
	}

	w, m, _ := newTakingGuest(t, false, wasiSIGALRM)
	interrupted := make(chan struct{}, 1)
	c := w.BeginOutside(m, func() {
		select {
		case interrupted <- struct{}{}:
		default:
		}
	})
	setTimer(t, w, m, 10*time.Millisecond, 0)
	select {
	case <-interrupted:
	case <-time.After(waitLimit):
		t.Fatalf("the timer not taken has not interrupted the code outside after %v", waitLimit)
	}
	c.End()
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM (%#x)", got, want)
	}
}

// A child's end is offered as SIGCHLD for its parent once its status can be
// waited for. One taken is not posted.
func TestTakeSignal_ChildEnd(t *testing.T) {
	w, m, r := newTakingGuest(t, true, wasiSIGCHLD)
	pid, exited := w.NewProc(nil)
	waited := make(chan int32, 1)
	r.during = func(SignalTarget, int32) { waited <- w.Proc_wait(m, pid, 1, sigValueOff) }
	exited(3 << 8)
	if rc := <-waited; rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait during TakeSignal rc=%d, want the status", rc)
	}
	if status := readU32(m.memory, int(sigValueOff)); status != 3<<8 {
		t.Fatalf("status = %#x, want %#x", status, 3<<8)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x, want no SIGCHLD", got)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGCHLD}) {
		t.Fatalf("offered %v, want SIGCHLD for the parent", got)
	}

	// The child of a fork is offered for the instance that forked it.
	child, _, childExited := w.ForkProc()
	_ = registeredFork(t, child)
	r.during = nil
	childExited(0)
	if got := r.offered(); len(got) != 2 || got[1] != (offeredSignal{w, wasiSIGCHLD}) {
		t.Fatalf("offered %v, want the fork's SIGCHLD for its parent", got)
	}

	w, m, _ = newTakingGuest(t, false, wasiSIGCHLD)
	_, exited = w.NewProc(nil)
	exited(0)
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGCHLD); got != want {
		t.Fatalf("taken = %#x, want SIGCHLD (%#x)", got, want)
	}
}

// The guest's kill of its own pid is offered TakeSignal, for the instance
// that kills, but sig 0, SIGKILL and SIGSTOP; one taken is not the guest's.
func TestTakeSignal_KillOwnPid(t *testing.T) {
	w, m, r := newTakingGuest(t, true, wasiSIGUSR1, wasiSIGUSR2)
	r.during = func(target SignalTarget, sig int32) { target.PostSignal(wasiSIGUSR2) }
	self := w.guestPID()
	if rc := w.Proc_kill(m, self, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the own pid rc=%d", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("taken = %#x, want the taker's SIGUSR2 alone (%#x)", got, want)
	}
	r.during = nil
	if rc := w.Proc_kill(m, self, 0); rc != _wasiESUCCESS {
		t.Fatalf("kill of the own pid with 0 rc=%d", rc)
	}
	if rc := w.Proc_kill(m, self, wasiSIGSTOP); rc != _wasiESUCCESS {
		t.Fatalf("kill of the own pid with SIGSTOP rc=%d", rc)
	}
	if sig := killEnd(func() { w.Proc_kill(m, self, wasiSIGKILL) }); sig != wasiSIGKILL {
		t.Fatalf("kill of the own pid with SIGKILL ended the guest by %d, want SIGKILL", sig)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGUSR1}) {
		t.Fatalf("offered %v, want SIGUSR1 alone", got)
	}

	root, _, r := newTakingGuest(t, true)
	child, childPID, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child, wasiSIGUSR1)
	if rc := child.Proc_kill(cm, childPID, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the fork's own pid rc=%d", rc)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{child, wasiSIGUSR1}) {
		t.Fatalf("offered %v, want SIGUSR1 for the fork", got)
	}

	w, m, _ = newTakingGuest(t, false, wasiSIGUSR1)
	if rc := w.Proc_kill(m, w.guestPID(), wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the own pid rc=%d", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want SIGUSR1 (%#x)", got, want)
	}
}

// An error of TakeSignal is told Errors, and the guest is given the signal.
func TestTakeSignal_Error(t *testing.T) {
	failed := errors.New("take failed")
	newFailing := func(t *testing.T, handled ...int32) (*WasiStubs, *Module, *[]error) {
		w, m, r := newTakingGuest(t, true, handled...)
		r.err = failed
		var mu sync.Mutex
		told := &[]error{}
		w.cfg.Errors = func(op string, err error) {
			if op != "take_signal" {
				t.Errorf("Errors told op %q", op)
			}
			mu.Lock()
			*told = append(*told, err)
			mu.Unlock()
		}
		return w, m, told
	}
	cases := map[string]func(w *WasiStubs, m *Module) int32{
		"timer": func(w *WasiStubs, m *Module) int32 {
			setTimer(t, w, m, 10*time.Millisecond, 0)
			if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
				t.Fatalf("sleep under a timer rc=%d, want EINTR", rc)
			}
			return wasiSIGALRM
		},
		"child": func(w *WasiStubs, m *Module) int32 {
			_, exited := w.NewProc(nil)
			exited(0)
			return wasiSIGCHLD
		},
		"kill": func(w *WasiStubs, m *Module) int32 {
			if rc := w.Proc_kill(m, w.guestPID(), wasiSIGUSR1); rc != _wasiESUCCESS {
				t.Fatalf("kill of the own pid rc=%d", rc)
			}
			return wasiSIGUSR1
		},
		"raise": func(w *WasiStubs, m *Module) int32 {
			if rc := w.Proc_raise(m, wasiSIGUSR1); rc != _wasiESUCCESS {
				t.Fatalf("raise rc=%d", rc)
			}
			return wasiSIGUSR1
		},
	}
	if hostStreamWrites {
		cases["sigpipe"] = func(w *WasiStubs, m *Module) int32 {
			readFd, writeFd := newTestPipe(t, w, m)
			if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
				t.Fatalf("close the read end rc=%d", rc)
			}
			if rc, _ := ioWriteCalls[0].run(w, m, writeFd, 1); rc != _wasiEPIPE {
				t.Fatalf("write without a reader rc=%d, want EPIPE", rc)
			}
			return wasiSIGPIPE
		}
	}
	for name, raise := range cases {
		w, m, told := newFailing(t, wasiSIGALRM, wasiSIGCHLD, wasiSIGUSR1, wasiSIGPIPE)
		sig := raise(w, m)
		if got, want := takeSignals(t, w, m), signalMask(sig); got != want {
			t.Errorf("%s: taken = %#x, want %#x", name, got, want)
		}
		if len(*told) != 1 || !errors.Is((*told)[0], failed) {
			t.Errorf("%s: Errors told %v, want the taker's error", name, *told)
		}
	}
}

// The guest's raise is offered TakeSignal as well; one taken is not the
// guest's.
func TestTakeSignal_Raise(t *testing.T) {
	for _, take := range []bool{true, false} {
		w, m, r := newTakingGuest(t, take, wasiSIGUSR1)
		if rc := w.Proc_raise(m, wasiSIGUSR1); rc != _wasiESUCCESS {
			t.Fatalf("taken %v: raise rc=%d", take, rc)
		}
		want := signalMask(wasiSIGUSR1)
		if take {
			want = 0
		}
		if got := takeSignals(t, w, m); got != want {
			t.Fatalf("taken %v: the guest took %#x, want %#x", take, got, want)
		}
		if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGUSR1}) {
			t.Fatalf("taken %v: offered %v, want SIGUSR1", take, got)
		}
	}
}

// The SIGPIPE of a write that fails with EPIPE is offered TakeSignal: one
// taken leaves the write EPIPE alone, also for a guest that has not
// registered for signals, which SIGPIPE would otherwise end; one not taken
// ends such a guest as before. A forked guest's is offered for the fork.
func TestTakeSignal_BrokenPipe(t *testing.T) {
	skipWithoutStreamWrites(t)
	closedPipe := func(w *WasiStubs, m *Module) int32 {
		readFd, writeFd := newTestPipe(t, w, m)
		if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
			t.Fatalf("close the read end rc=%d", rc)
		}
		return writeFd
	}
	w, m := newProcTestStubs(t)
	r := &recordingTaker{take: true}
	w.cfg.TakeSignal = r.takeSignal
	fd := closedPipe(w, m)
	if rc, n := ioWriteCalls[0].run(w, m, fd, 1); rc != _wasiEPIPE || n != 0 {
		t.Fatalf("write of an unregistered guest whose SIGPIPE is taken: rc=%d n=%d, want EPIPE 0", rc, n)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGPIPE}) {
		t.Fatalf("offered %v, want SIGPIPE", got)
	}

	w, m = newProcTestStubs(t)
	r = &recordingTaker{}
	w.cfg.TakeSignal = r.takeSignal
	fd = closedPipe(w, m)
	if sig := killEnd(func() { ioWriteCalls[0].run(w, m, fd, 1) }); sig != wasiSIGPIPE {
		t.Fatalf("the write with SIGPIPE not taken ended the guest by %d, want SIGPIPE", sig)
	}

	root, _, r := newTakingGuest(t, true)
	child, _, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	fd = closedPipe(child, cm)
	if rc, _ := ioWriteCalls[0].run(child, cm, fd, 1); rc != _wasiEPIPE {
		t.Fatalf("write of the fork: rc=%d, want EPIPE", rc)
	}
	if got := takeSignals(t, child, cm); got != 0 {
		t.Fatalf("the fork took %#x, want nothing", got)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{child, wasiSIGPIPE}) {
		t.Fatalf("offered %v, want SIGPIPE for the fork", got)
	}
}

// Once the guest has become a command (Proc_exec), nothing is offered: the
// command has the signals.
func TestTakeSignal_NoneAfterExec(t *testing.T) {
	w, _, r := newTakingGuest(t, true, wasiSIGUSR1)
	w.sig.mu.Lock()
	w.sig.execed = &execedCommand{done: make(chan struct{})}
	w.sig.mu.Unlock()
	if w.takeSignal(wasiSIGUSR1) {
		t.Fatal("a signal was taken after the exec")
	}
	if got := r.offered(); len(got) != 0 {
		t.Fatalf("offered %v after the exec, want nothing", got)
	}
}
