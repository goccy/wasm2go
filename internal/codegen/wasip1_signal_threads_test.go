package codegen

import (
	"encoding/binary"
	"testing"
	"time"
)

// Where a second thread of a test guest keeps its flag word, and a third
// thread its own.
const (
	sigFlag2Off int32 = 12024
	sigFlag3Off int32 = 12028
)

// flagAt reads the flag word at off and clears it, as the guest does at a
// safe point.
func flagAt(m *Module, off int32) uint32 {
	flag := readU32(m.memory, int(off))
	binary.LittleEndian.PutUint32(m.memory[off:], 0)
	return flag
}

// signalWaiter returns the module of a thread of w's guest that takes
// SIGUSR1, on a memory of its own.
func signalWaiter(t *testing.T, w *WasiStubs) *Module {
	t.Helper()
	m := newForkTestModule()
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d, want 0", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
	return m
}

// newSignalThread registers another thread of m's guest for signals, with its
// flag word at off and the mask blocked; the process handles handled.
func newSignalThread(t *testing.T, w *WasiStubs, m *Module, off int32, handled, blocked uint64) *Module {
	t.Helper()
	thread := newThreadModule(m)
	if rc := w.Proc_signal_register(thread, off); rc != 0 {
		t.Fatalf("Proc_signal_register of a new thread rc=%d, want 0", rc)
	}
	setDispositions(t, w, thread, handled, 0, blocked)
	return thread
}

// A signal of the process goes to a thread that does not block it, and ends
// that thread's blocking call alone: the wait of the thread that blocks every
// signal — the one that registered first — goes on, and its flag word stays
// down. The Signals is told the signals that every thread blocks.
func TestSignal_AThreadThatBlocksTheSignalIsPassedOver(t *testing.T) {
	handled := signalMask(wasiSIGTERM)
	w, m := newSignalGuest(t, wasiSIGTERM)
	s := &recordingSignals{}
	w.cfg.Signals = s
	setDispositions(t, w, m, handled, 0, ^uint64(0))
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, 0)
	if got := s.reports[len(s.reports)-1][2]; got != 0 {
		t.Fatalf("reported blocked = %#x while a thread blocks nothing, want 0", got)
	}

	posted := whenBlocked(w, func() { w.PostSignal(wasiSIGTERM) })
	start := time.Now()
	if rc := sleepPoll(t, w, m, 200*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("the sleep of the thread that blocks every signal rc=%d, want success", rc)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("the sleep of the thread that blocks every signal ended after %v", d)
	}
	<-posted
	if flag := signalFlag(m); flag != 0 {
		t.Fatalf("the flag of the thread that blocks the signal = %d, want 0", flag)
	}
	if flag := flagAt(worker, sigFlag2Off); flag != 1 {
		t.Fatalf("the flag of the thread that takes the signal = %d, want 1", flag)
	}
	if rc := sleepPoll(t, w, worker, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("the next sleep of the thread that takes the signal rc=%d, want EINTR", rc)
	}
	if got := takeSignals(t, w, worker); got != handled {
		t.Fatalf("taken = %#x, want %#x", got, handled)
	}

	setDispositions(t, w, worker, handled, 0, signalMask(wasiSIGHUP))
	if got, want := s.reports[len(s.reports)-1][2], signalMask(wasiSIGHUP); got != want {
		t.Fatalf("reported blocked = %#x, want the signals both threads block (%#x)", got, want)
	}
}

// A signal relayed to the guest alone (DeliverSignal with ReachGuest) goes
// to a thread that does not block it, as one posted to the process does.
func TestSignal_ARelayedSignalGoesToAThreadThatTakesIt(t *testing.T) {
	handled := signalMask(wasiSIGINT)
	w, m := newSignalGuest(t, wasiSIGINT)
	setDispositions(t, w, m, handled, 0, handled)
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, 0)
	w.DeliverSignal(wasiSIGINT, ReachGuest)
	if flag, flag2 := signalFlag(m), flagAt(worker, sigFlag2Off); flag != 0 || flag2 != 1 {
		t.Fatalf("flags = %d %d, want the thread that does not block it alone", flag, flag2)
	}
	if got := takeSignals(t, w, worker); got != handled {
		t.Fatalf("taken = %#x, want %#x", got, handled)
	}
}

// A signal every thread blocks waits for the process; the thread that
// unblocks it first has its flag raised and takes it.
func TestSignal_ASignalEveryThreadBlocksWaitsForTheFirstToUnblockIt(t *testing.T) {
	handled := signalMask(wasiSIGUSR1)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	setDispositions(t, w, m, handled, 0, handled)
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, handled)
	w.PostSignal(wasiSIGUSR1)
	if flag, flag2 := signalFlag(m), flagAt(worker, sigFlag2Off); flag != 0 || flag2 != 0 {
		t.Fatalf("flags = %d %d for a signal every thread blocks, want 0 0", flag, flag2)
	}
	setDispositions(t, w, worker, handled, 0, 0)
	if flag, flag2 := signalFlag(m), flagAt(worker, sigFlag2Off); flag != 0 || flag2 != 1 {
		t.Fatalf("flags = %d %d once the second thread unblocked the signal, want 0 1", flag, flag2)
	}
	if got := takeSignals(t, w, m); got != handled {
		t.Fatalf("the blocking thread's take wrote %#x, want the pending signal %#x", got, handled)
	}
	if got := takeSignals(t, w, worker); got != handled {
		t.Fatalf("the unblocking thread took %#x, want %#x", got, handled)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("pending after the take = %#x, want nothing", got)
	}

	// A thread that registers while the signal waits has its word raised.
	setDispositions(t, w, worker, handled, 0, handled)
	w.PostSignal(wasiSIGUSR1)
	late := newThreadModule(m)
	if rc := w.Proc_signal_register(late, sigFlag3Off); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d, want 0", rc)
	}
	if flag := flagAt(late, sigFlag3Off); flag != 1 {
		t.Fatalf("flag of the thread that registered = %d, want 1", flag)
	}
}

// A thread takes the signals it does not block, and writes those it blocks
// as pending: they stay for a thread that takes them.
func TestSignal_ATakeLeavesWhatTheThreadBlocks(t *testing.T) {
	both := signalMask(wasiSIGUSR1, wasiSIGUSR2)
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	setDispositions(t, w, m, both, 0, signalMask(wasiSIGUSR2))
	worker := newSignalThread(t, w, m, sigFlag2Off, both, 0)
	w.PostSignal(wasiSIGUSR1)
	w.PostSignal(wasiSIGUSR2)
	if got := takeSignals(t, w, m); got != both {
		t.Fatalf("first take wrote %#x, want both %#x", got, both)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("second take wrote %#x, want the blocked one left (%#x)", got, want)
	}
	if got, want := takeSignals(t, w, worker), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("the other thread took %#x, want %#x", got, want)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("pending after both takes = %#x, want nothing", got)
	}
}

// When the thread a signal went to blocks it before taking it, the signal
// goes to another thread that takes it, whose blocking call ends.
func TestSignal_BlockingASignalHandsItToAnotherThread(t *testing.T) {
	handled := signalMask(wasiSIGUSR1)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, 0)
	slept := make(chan int32)
	writeSubClock(worker, pollSubsOff, 1, int64(time.Hour))
	go func() { slept <- w.Poll_oneoff(worker, pollSubsOff, pollEvOff, 1, pollNevOff) }()
	awaitBlockedCalls(w, 1)
	w.PostSignal(wasiSIGUSR1)
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag of the first thread = %d, want 1", flag)
	}
	setDispositions(t, w, m, handled, 0, handled)
	if rc := <-slept; rc != _wasiEINTR {
		t.Fatalf("the other thread's sleep rc=%d, want EINTR", rc)
	}
	if flag := flagAt(worker, sigFlag2Off); flag != 1 {
		t.Fatalf("flag of the other thread = %d, want 1", flag)
	}
	if got := takeSignals(t, w, worker); got != handled {
		t.Fatalf("the other thread took %#x, want %#x", got, handled)
	}
}

// A thread that ends hands the signal it was given and has not taken to
// another thread that takes it; what was raised for it goes with it.
func TestSignal_AnEndedThreadsSignalGoesToAnother(t *testing.T) {
	handled := signalMask(wasiSIGUSR1, wasiSIGUSR2)
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	setDispositions(t, w, m, handled, 0, handled)
	first := newSignalThread(t, w, m, sigFlag2Off, handled, 0)
	second := newSignalThread(t, w, m, sigFlag3Off, handled, 0)
	w.PostSignal(wasiSIGUSR1)
	if flag, flag2 := flagAt(first, sigFlag2Off), flagAt(second, sigFlag3Off); flag != 1 || flag2 != 0 {
		t.Fatalf("flags = %d %d, want the first thread's alone", flag, flag2)
	}
	if rc := w.Proc_raise(first, wasiSIGUSR2); rc != _wasiESUCCESS {
		t.Fatalf("Proc_raise rc=%d", rc)
	}
	w.agentEnded(first)
	if flag := flagAt(second, sigFlag3Off); flag != 1 {
		t.Fatalf("flag of the thread left = %d, want 1", flag)
	}
	if got, want := takeSignals(t, w, second), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("the thread left took %#x, want %#x", got, want)
	}
	w.agentEnded(first) // told twice: nothing is left of it
}

// raise is the calling thread's: it interrupts no other thread, and no other
// thread takes it. A thread that has not registered raises a signal of the
// process.
func TestSignal_RaiseIsTheCallingThreads(t *testing.T) {
	handled := signalMask(wasiSIGUSR1)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, 0)
	slept := make(chan int32)
	writeSubClock(worker, pollSubsOff, 1, int64(200*time.Millisecond))
	go func() { slept <- w.Poll_oneoff(worker, pollSubsOff, pollEvOff, 1, pollNevOff) }()
	awaitBlockedCalls(w, 1)
	if rc := w.Proc_raise(m, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_raise rc=%d", rc)
	}
	if rc := <-slept; rc != _wasiESUCCESS {
		t.Fatalf("the other thread's sleep rc=%d, want success", rc)
	}
	if got := takeSignals(t, w, worker); got != 0 {
		t.Fatalf("the other thread took %#x of a raise, want nothing", got)
	}
	if got := takeSignals(t, w, m); got != handled {
		t.Fatalf("the raising thread took %#x, want %#x", got, handled)
	}

	unregistered := newThreadModule(m)
	if rc := w.Proc_raise(unregistered, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_raise of an unregistered thread rc=%d", rc)
	}
	if got := takeSignals(t, w, m); got != handled {
		t.Fatalf("a registered thread took %#x of an unregistered thread's raise, want %#x", got, handled)
	}
}

// The copy of a guest that has not registered for signals has not either: a
// signal that ends a process ends it, as it ends the root.
func TestSignal_AForkOfAnUnregisteredGuestHasTheDefaultActions(t *testing.T) {
	w, _ := newProcTestStubs(t)
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	child.PostSignal(wasiSIGTERM)
	if sig := killEnd(func() { child.Proc_wait_any(newForkTestModule(), 0, sigValueOff, sigValueOff+4) }); sig != wasiSIGTERM {
		t.Fatalf("the copy ended by %d, want SIGTERM", sig)
	}
}

// The copy has the registration and the mask of the thread that forks, and
// its first thread to call the host is that one: a signal posted before
// interrupts that call and raises the flag word the thread registered.
func TestSignal_AForkHasTheRegistrationOfTheThreadThatForks(t *testing.T) {
	handled := signalMask(wasiSIGUSR1, wasiSIGUSR2)
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	setDispositions(t, w, m, handled, 0, signalMask(wasiSIGUSR2))
	worker := newSignalThread(t, w, m, sigFlag2Off, handled, 0)

	// Fork: the first thread that registered.
	child := w.Fork()
	cm := newForkTestModule()
	child.PostSignal(wasiSIGUSR2)
	b, ok := child.beginBlocking(cm, func() {})
	if !ok {
		t.Fatal("a blocking call of the copy refused for a signal its thread blocks")
	}
	child.endBlocking(b)
	if err := child.CloseAll(); err != nil {
		t.Fatal(err)
	}

	// fork from the second thread, which blocks nothing.
	child = w.fork(worker)
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm = newForkTestModule()
	child.PostSignal(wasiSIGUSR2)
	if _, ok := child.beginBlocking(cm, func() {}); ok {
		t.Fatal("the copy's first blocking call began with a signal waiting for its thread")
	}
	if flag := flagAt(cm, sigFlag2Off); flag != 1 {
		t.Fatalf("the flag word the thread that forked registered = %d, want 1", flag)
	}
	if rc := child.Proc_signal_register(cm, sigFlag2Off); rc != 1 {
		t.Fatalf("Proc_signal_register of the inherited word rc=%d, want 1", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("the copy took %#x, want %#x", got, want)
	}
}
