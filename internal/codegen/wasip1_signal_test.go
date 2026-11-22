package codegen

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Where a test guest keeps its signal flag word and scratch values.
const (
	sigFlagOff  int32 = 12000
	sigMaskOff  int32 = 12008
	sigValueOff int32 = 12016
)

// newSignalGuest returns host state with a guest that has registered for
// signals and handles the given ones.
func newSignalGuest(t *testing.T, handled ...int32) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newProcTestStubs(t)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("first Proc_signal_register rc=%d, want 0 (new)", rc)
	}
	setDispositions(t, w, m, signalMask(handled...), 0, 0)
	return w, m
}
func signalMask(sigs ...int32) uint64 {
	var mask uint64
	for _, sig := range sigs {
		mask |= wasiSignalBit(sig)
	}
	return mask
}

func setDispositions(t *testing.T, w *WasiStubs, m *Module, handled, ignored, blocked uint64) {
	t.Helper()
	if rc := w.Proc_signal_dispositions(m, int64(handled), int64(ignored), int64(blocked)); rc != _wasiESUCCESS {
		t.Fatalf("Proc_signal_dispositions rc=%d", rc)
	}
}

// signalFlag reads the guest's flag word and clears it, as the guest does at
// a safe point.
func signalFlag(m *Module) uint32 {
	flag := readU32(m.memory, int(sigFlagOff))
	binary.LittleEndian.PutUint32(m.memory[sigFlagOff:], 0)
	return flag
}

// takeSignals is the guest taking its posted signals.
func takeSignals(t *testing.T, w *WasiStubs, m *Module) uint64 {
	t.Helper()
	if rc := w.Proc_signal_take(m, sigMaskOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_signal_take rc=%d", rc)
	}
	return readU64(m.memory, int(sigMaskOff))
}

// whenBlocked runs f on another goroutine once a blocking call of the guest
// is waiting (beginBlocking has registered its wake), and closes the channel
// it returns when f has returned.
func whenBlocked(w *WasiStubs, f func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		awaitBlockedCalls(w, 1)
		f()
	}()
	return done
}

// awaitBlockedCalls returns once n blocking calls of the guest are waiting.
func awaitBlockedCalls(w *WasiStubs, n int) {
	for {
		w.sig.mu.Lock()
		blocked := len(w.sig.wakes)
		w.sig.mu.Unlock()
		if blocked == n {
			return
		}
		runtime.Gosched()
	}
}

// postWhenBlocked posts sig once a blocking call of the guest is waiting.
func postWhenBlocked(w *WasiStubs, sig int32) {
	whenBlocked(w, func() { w.PostSignal(sig) })
}

// sleepPoll is a guest sleeping for d through poll_oneoff.
func sleepPoll(t *testing.T, w *WasiStubs, m *Module, d time.Duration) (rc int32) {
	t.Helper()
	writeSubClock(m, pollSubsOff, 1, int64(d))
	returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff) })
	return rc
}

// Before the guest registers, a signal that does nothing by default is
// dropped, and one that ends a process ends the guest at its registration.
func TestSignal_DroppedUntilTheGuestRegisters(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.PostSignal(wasiSIGWINCH)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d, want 0", rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("a signal posted before registration was kept: %#x", got)
	}
	ended, em := newProcTestStubs(t)
	ended.PostSignal(wasiSIGTERM)
	if sig := killEnd(func() { ended.Proc_signal_register(em, sigFlagOff) }); sig != wasiSIGTERM {
		t.Fatalf("registration after SIGTERM ended the guest by %d, want SIGTERM", sig)
	}
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 1 {
		t.Fatalf("second Proc_signal_register rc=%d, want 1 (known)", rc)
	}
	// Another module instance (a copy of the guest) is a new registration.
	if rc := w.Proc_signal_register(newForkTestModule(), sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register from another module rc=%d, want 0", rc)
	}
	if rc := w.Proc_signal_register(m, int32(len(m.memory))); rc != -_wasiEFAULT {
		t.Fatalf("flag word outside memory rc=%d, want -EFAULT", rc)
	}
}

func TestSignal_PostRaisesFlagAndIsTakenOnce(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	if flag := signalFlag(m); flag != 0 {
		t.Fatalf("flag = %d before any signal", flag)
	}
	w.PostSignal(wasiSIGUSR1)
	w.PostSignal(wasiSIGTERM) // not handled, not ignored: the guest's to act on
	w.PostSignal(0)
	w.PostSignal(65)
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d after a post, want 1", flag)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1, wasiSIGTERM); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken again = %#x, want nothing", got)
	}
}

func TestSignal_IgnoredSignalsAreDropped(t *testing.T) {
	w, m := newSignalGuest(t)
	w.PostSignal(wasiSIGCHLD)  // default action: nothing
	w.PostSignal(wasiSIGWINCH) // likewise
	if flag := signalFlag(m); flag != 0 {
		t.Fatalf("flag = %d after signals nobody would notice", flag)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x, want nothing", got)
	}
	// Ignoring a signal that is pending discards it.
	w.PostSignal(wasiSIGHUP)
	setDispositions(t, w, m, 0, wasiDefaultIgnoredSignals|signalMask(wasiSIGHUP), 0)
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x after ignoring the pending signal, want nothing", got)
	}
}

func TestSignal_BlockedSignalWaitsForItsUnblocking(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), wasiDefaultIgnoredSignals, signalMask(wasiSIGUSR1))
	w.PostSignal(wasiSIGUSR1)
	if flag := signalFlag(m); flag != 0 {
		t.Fatalf("flag = %d for a blocked signal", flag)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), wasiDefaultIgnoredSignals, 0)
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d after unblocking a pending signal, want 1", flag)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}
}

func TestSignal_InterruptsSleep(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	postWhenBlocked(w, wasiSIGUSR1)
	start := time.Now()
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("interrupted sleep rc=%d, want EINTR", rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("sleep ended after %v", d)
	}
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d, want 1", flag)
	}
	// One signal interrupts one call: the next sleep runs its course even
	// though the guest has not taken the signal yet.
	start = time.Now()
	if rc := sleepPoll(t, w, m, 40*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after the interruption rc=%d", rc)
	}
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("second sleep ended after %v", d)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}
}

func TestSignal_PendingSignalEndsTheNextBlockingCallAtOnce(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.PostSignal(wasiSIGUSR1)
	start := time.Now()
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep with a signal waiting rc=%d, want EINTR", rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("sleep ended after %v", d)
	}
	// A poll that does not wait is not interrupted.
	w.PostSignal(wasiSIGUSR1)
	if rc := sleepPoll(t, w, m, 0); rc != _wasiESUCCESS {
		t.Fatalf("zero-timeout poll rc=%d", rc)
	}
	// Once taken, nothing is left to interrupt for.
	takeSignals(t, w, m)
	if rc := sleepPoll(t, w, m, 10*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after take rc=%d", rc)
	}
}

// While the guest runs code outside it (a native library it called), a
// signal posted for it interrupts that code through what its runner
// registered, once per signal; the guest's own blocking calls that follow
// are not interrupted by it, and it is noticed as any signal is. A signal
// the guest blocks or discards does nothing to the code; a blocking call of
// the guest's own made from inside the code (a callback) is ended as
// always. Registrations nest.
func TestSignal_InterruptsCodeOutsideTheGuest(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	var outer, inner int
	if prev := w.SetOutsideInterrupt(func() { outer++ }); prev != nil {
		t.Fatal("something was registered before the first registration")
	}
	w.PostSignal(wasiSIGUSR1)
	if outer != 1 {
		t.Fatalf("interrupt called %d times for one signal, want 1", outer)
	}
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d, want 1", flag)
	}
	start := time.Now()
	if rc := sleepPoll(t, w, m, 40*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("a sleep after the signal interrupted the code outside rc=%d, want success", rc)
	}
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("the sleep ended after %v", d)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}

	// Blocked, and discarded by default.
	setDispositions(t, w, m, signalMask(wasiSIGUSR1, wasiSIGUSR2), 0, signalMask(wasiSIGUSR2))
	w.PostSignal(wasiSIGUSR2)
	w.PostSignal(wasiSIGCHLD)
	if outer != 1 {
		t.Fatalf("interrupt called for a blocked or discarded signal (%d calls)", outer)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1, wasiSIGUSR2), 0, 0)
	takeSignals(t, w, m)
	signalFlag(m)

	// A blocking call of the guest's made from inside the code.
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("a callback's sleep rc=%d, want EINTR", rc)
	}
	if outer != 1 {
		t.Fatalf("interrupt called while a blocking call of the guest's waited (%d calls)", outer)
	}
	takeSignals(t, w, m)

	// Nesting.
	if prev := w.SetOutsideInterrupt(func() { inner++ }); prev == nil {
		t.Fatal("the outer registration was not returned")
	} else {
		w.PostSignal(wasiSIGUSR1)
		if inner != 1 || outer != 1 {
			t.Fatalf("calls inner=%d outer=%d, want 1 1", inner, outer)
		}
		w.SetOutsideInterrupt(prev)
	}
	w.PostSignal(wasiSIGUSR1)
	if inner != 1 || outer != 2 {
		t.Fatalf("after the inner code returned: calls inner=%d outer=%d, want 1 2", inner, outer)
	}
	w.SetOutsideInterrupt(nil)
	w.PostSignal(wasiSIGUSR1)
	if outer != 2 {
		t.Fatalf("interrupt called after the code returned (%d calls)", outer)
	}
	// With nothing outside, the signal is left for the next blocking call.
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep with a signal waiting rc=%d, want EINTR", rc)
	}
}

func TestSignal_InterruptsPollOnAnIdlePipe(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	writeSubFd(m, pollSubsOff, 7, 1 /* fd_read */, readFd)
	postWhenBlocked(w, wasiSIGUSR1)
	var rc int32
	returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff) })
	if rc != _wasiEINTR {
		t.Fatalf("poll on an idle pipe rc=%d, want EINTR", rc)
	}
	// The pipe is as it was: input written now is polled and read.
	if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "data" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

func TestSignal_InterruptsBlockingPipeRead(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	postWhenBlocked(w, wasiSIGUSR1)
	if _, rc := readWithin(t, w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("read of an idle pipe rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	// The interruption left no deadline behind: the retried read waits for
	// the writer.
	writeSoon(t, w, writeFd, "late")
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("retried read = %q rc=%d, want %q", got, rc, "late")
	}
}

// A signal that is waiting for the guest to notice it interrupts the call
// that would have to wait, not the one that can be carried out at once: a
// pipe with room takes a write, input that is there is read — as the system
// calls behave for a process with a signal pending.
func TestSignal_PendingSignalLeavesACallThatNeedNotWaitAlone(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)

	w.PostSignal(wasiSIGUSR1)
	if rc := fdWriteString(w, m, writeFd, "more"); rc != _wasiESUCCESS {
		t.Fatalf("write to a pipe with room, a signal waiting: rc=%d, want success", rc)
	}
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "more" {
		t.Fatalf("read of input that is there, a signal waiting = %q rc=%d, want %q", got, rc, "more")
	}
	// The signal is still waiting: the read that has nothing to read is
	// interrupted, once.
	start := time.Now()
	if _, rc := readWithin(t, w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("read of an idle pipe, a signal waiting: rc=%d, want EINTR", rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the read ended after %v", d)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want SIGUSR1 (%#x)", got, want)
	}

	// The end of input is there to be read as well.
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	w.PostSignal(wasiSIGUSR1)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at the end of input, a signal waiting = %q rc=%d, want the end", got, rc)
	}
	takeSignals(t, w, m)

	// A pipe without room: the write would have to wait, and is interrupted.
	_, writeFd = newTestPipe(t, w, m)
	fillNonBlocking(t, w, m, writeFd)
	if rc := w.Fd_fdstat_set_flags(m, writeFd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	w.PostSignal(wasiSIGUSR1)
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiEINTR || n != 0 {
		t.Fatalf("write to a full pipe, a signal waiting: %d bytes rc=%d, want EINTR", n, rc)
	}
	takeSignals(t, w, m)
}

func TestSignal_NeverInterruptsRegularFileRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	fd := openTestFile(t, w, "f")
	w.PostSignal(wasiSIGTERM)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "content" {
		t.Fatalf("file read with a signal waiting = %q rc=%d", got, rc)
	}
}

func TestSignal_InterruptsWaitForAProcess(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	pid, exited := w.NewProc(nil)
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait rc=%d, want -EINTR", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Proc_wait_any(m, 0, sigValueOff, sigValueOff+4); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait_any rc=%d, want -EINTR", rc)
	}
	// A process that has finished is reported, signal waiting or not.
	exited(3 << 8)
	w.PostSignal(wasiSIGUSR1)
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait of a finished process rc=%d", rc)
	}
	if status := readU32(m.memory, int(sigValueOff)); status != 3<<8 {
		t.Fatalf("status = %#x", status)
	}
}

func TestSignal_ChildEndPostsSIGCHLD(t *testing.T) {
	// SIGCHLD does nothing by default, so it is dropped ...
	w, m := newSignalGuest(t)
	_, exited := w.NewProc(nil)
	exited(0)
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x without a SIGCHLD handler, want nothing", got)
	}
	// ... unless the guest handles it.
	w, m = newSignalGuest(t, wasiSIGCHLD)
	setDispositions(t, w, m, signalMask(wasiSIGCHLD), wasiDefaultIgnoredSignals&^signalMask(wasiSIGCHLD), 0)
	pid, exited := w.NewProc(nil)
	ended := whenBlocked(w, func() { exited(0) })
	// The wait is over because the process finished, not because of the
	// signal that says so.
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	// exited posts SIGCHLD after publishing the status, before it returns.
	<-ended
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGCHLD); got != want {
		t.Fatalf("taken = %#x, want SIGCHLD (%#x)", got, want)
	}
}

// setTimer replaces the guest's interval timer and returns what was left of
// the one before and its interval.
func setTimer(t *testing.T, w *WasiStubs, m *Module, value, interval time.Duration) (left, every time.Duration) {
	t.Helper()
	if rc := w.Proc_itimer(m, 1, int64(value), int64(interval), sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_itimer(set) rc=%d", rc)
	}
	return time.Duration(binary.LittleEndian.Uint64(m.memory[sigValueOff:])),
		time.Duration(binary.LittleEndian.Uint64(m.memory[sigValueOff+8:]))
}

// timerState reads the guest's interval timer without changing it.
func timerState(t *testing.T, w *WasiStubs, m *Module) (left, every time.Duration) {
	t.Helper()
	if rc := w.Proc_itimer(m, 0, 0, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_itimer(get) rc=%d", rc)
	}
	return time.Duration(binary.LittleEndian.Uint64(m.memory[sigValueOff:])),
		time.Duration(binary.LittleEndian.Uint64(m.memory[sigValueOff+8:]))
}

func TestSignal_TimerFiresOnce(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	if left, every := setTimer(t, w, m, 100*time.Second, 0); left != 0 || every != 0 {
		t.Fatalf("the first timer reported %v left (every %v) of none", left, every)
	}
	if left, _ := timerState(t, w, m); left <= 99*time.Second || left > 100*time.Second {
		t.Fatalf("a timer of 100s has %v left", left)
	}
	if left, _ := setTimer(t, w, m, 300*time.Millisecond, 0); left <= 99*time.Second || left > 100*time.Second {
		t.Fatalf("replacing the timer reported %v left, want about 100s", left)
	}
	start := time.Now()
	if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep under a timer rc=%d, want EINTR", rc)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 10*time.Second {
		t.Fatalf("the timer fired after %v, want about 300ms", d)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM", got)
	}
	if left, every := timerState(t, w, m); left != 0 || every != 0 {
		t.Fatalf("%v left (every %v) after a one-shot timer fired", left, every)
	}
	// A disarmed timer never fires.
	setTimer(t, w, m, 300*time.Millisecond, 0)
	if left, _ := setTimer(t, w, m, 0, 0); left <= 0 || left > 300*time.Millisecond {
		t.Fatalf("disarming reported %v left, want up to 300ms", left)
	}
	if rc := sleepPoll(t, w, m, 600*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after disarming the timer rc=%d", rc)
	}
}

func TestSignal_TimerRepeatsAtItsInterval(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	setTimer(t, w, m, 50*time.Millisecond, 100*time.Millisecond)
	if left, every := timerState(t, w, m); left <= 0 || left > 50*time.Millisecond || every != 100*time.Millisecond {
		t.Fatalf("state = %v left, every %v; want up to 50ms, every 100ms", left, every)
	}
	start := time.Now()
	for firing := 1; firing <= 3; firing++ {
		if rc := sleepPoll(t, w, m, 30*time.Second); rc != _wasiEINTR {
			t.Fatalf("sleep before firing %d rc=%d, want EINTR", firing, rc)
		}
		if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
			t.Fatalf("firing %d: taken = %#x, want SIGALRM", firing, got)
		}
	}
	// 50ms, then 150ms and 250ms.
	if d := time.Since(start); d < 240*time.Millisecond || d > 10*time.Second {
		t.Fatalf("three firings took %v, want about 250ms", d)
	}
	if _, every := timerState(t, w, m); every != 100*time.Millisecond {
		t.Fatalf("the interval is %v after three firings, want 100ms", every)
	}
	if _, every := setTimer(t, w, m, 0, 0); every != 100*time.Millisecond {
		t.Fatalf("disarming reported an interval of %v, want 100ms", every)
	}
	if rc := sleepPoll(t, w, m, 300*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after disarming the repeating timer rc=%d", rc)
	}
}

// A wait that ends by its timeout after the moment the interval timer was
// set for finds the signal posted, whether or not the host's own timer has
// run by then: the two happen in the order of their times. The test stands
// in for a host timer that is late by setting the timer far ahead and then
// moving the moment it is due into the past.
func TestSignal_TimerDueBeforeAWaitEndsIsPostedFirst(t *testing.T) {
	overdue := func(w *WasiStubs) {
		w.sig.mu.Lock()
		w.sig.timerAt = time.Now().Add(-time.Millisecond)
		w.sig.mu.Unlock()
	}

	// The wait was in progress when the timer came due.
	w, m := newSignalGuest(t, wasiSIGALRM)
	setTimer(t, w, m, time.Hour, 0)
	key, ok := w.beginBlocking(func() {})
	if !ok {
		t.Fatal("a wait before the timer is due did not begin")
	}
	overdue(w)
	if !w.endBlocking(key) {
		t.Fatal("a wait that ended after the timer was due was not interrupted")
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM", got)
	}
	if left, every := timerState(t, w, m); left != 0 || every != 0 {
		t.Fatalf("%v left (every %v) after a one-shot timer fired", left, every)
	}
}

func TestSignal_TimerRejectsNegativeTimes(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	if rc := w.Proc_itimer(m, 1, -1, 0, sigValueOff); rc != -_wasiEINVAL {
		t.Fatalf("negative value rc=%d, want -EINVAL", rc)
	}
	if rc := w.Proc_itimer(m, 1, 1, -1, sigValueOff); rc != -_wasiEINVAL {
		t.Fatalf("negative interval rc=%d, want -EINVAL", rc)
	}
	if left, _ := timerState(t, w, m); left != 0 {
		t.Fatalf("a refused call set a timer with %v left", left)
	}
}

func TestSignal_TerminatePanicsWithTheSignal(t *testing.T) {
	w, m := newSignalGuest(t)
	defer func() {
		var sigErr *WasiSignalError
		err, _ := recover().(error)
		if !errors.As(err, &sigErr) || sigErr.Signal != wasiSIGTERM {
			t.Fatalf("recovered %v, want a WasiSignalError for SIGTERM", err)
		}
		if sigErr.Error() != "wasi: terminated by signal 15" {
			t.Fatalf("message = %q", sigErr.Error())
		}
	}()
	w.Proc_terminate(m, wasiSIGTERM)
}
func TestSignal_ForkedStateStartsWithoutSignals(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	setTimer(t, w, m, 100*time.Second, 0)
	w.PostSignal(wasiSIGUSR1)
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
		t.Fatalf("the forked guest's registration rc=%d, want 0 (new)", rc)
	}
	if got := takeSignals(t, child, cm); got != 0 {
		t.Fatalf("the forked guest inherited pending signals: %#x", got)
	}
	if left, _ := timerState(t, child, cm); left != 0 {
		t.Fatalf("the forked guest inherited the timer (%v left)", left)
	}
	// The parent's are untouched.
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("parent taken = %#x, want %#x", got, want)
	}
}

// A signal sent to a forked guest before it has run — and so before it has
// registered — is not lost: it is there when the guest reports its
// dispositions, unless those say the signal is ignored.
func TestSignal_PostedToAForkedGuestBeforeItRegisters(t *testing.T) {
	w, _ := newSignalGuest(t)
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	child.PostSignal(wasiSIGTERM)
	child.PostSignal(wasiSIGCHLD)

	cm := newForkTestModule()
	if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, child, cm, 0, wasiDefaultIgnoredSignals, 0)
	if flag := signalFlag(cm); flag != 1 {
		t.Fatalf("flag = %d once the forked guest is ready, want 1", flag)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGTERM); got != want {
		t.Fatalf("taken = %#x, want SIGTERM only (%#x)", got, want)
	}

}

func TestSignal_CloseAllEndsDelivery(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	setTimer(t, w, m, time.Second, time.Second)
	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	// The guest's memory may be gone from here on.
	m.memory = nil
	w.PostSignal(wasiSIGALRM)
	w.sig.mu.Lock()
	timer := w.sig.timer
	w.sig.mu.Unlock()
	if timer != nil {
		t.Fatal("the timer survived CloseAll")
	}
}

// SIGKILL can be neither caught nor ignored nor blocked: a guest that says
// it does all three to every signal still has SIGKILL delivered.
func TestSignal_SIGKILLIsAlwaysDelivered(t *testing.T) {
	w, m := newSignalGuest(t)
	setDispositions(t, w, m, ^uint64(0), ^uint64(0), ^uint64(0))
	w.PostSignal(wasiSIGKILL)
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d after SIGKILL, want 1", flag)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGKILL); got != want {
		t.Fatalf("taken = %#x, want SIGKILL (%#x)", got, want)
	}
}

// A timer that is due when a blocking call of the guest's begins or ends
// interrupts that call, even while code outside the guest has an interrupt
// registered.
func TestSignal_DueTimerInterruptsTheGuestsOwnWait(t *testing.T) {
	overdue := func(w *WasiStubs) {
		w.sig.mu.Lock()
		w.sig.timerAt = time.Now().Add(-time.Millisecond)
		w.sig.mu.Unlock()
	}
	w, m := newSignalGuest(t, wasiSIGALRM)
	outside := 0
	w.SetOutsideInterrupt(func() { outside++ })
	pid, exited := w.NewProc(nil)
	defer exited(0)

	setTimer(t, w, m, time.Hour, 0)
	overdue(w)
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait with a due timer rc=%d, want -EINTR", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM", got)
	}

	setTimer(t, w, m, time.Hour, 0)
	key, ok := w.beginBlocking(func() {})
	if !ok {
		t.Fatal("a wait before the timer is due did not begin")
	}
	overdue(w)
	if !w.endBlocking(key) {
		t.Fatal("a wait that ended after the timer was due was not interrupted")
	}
	if outside != 0 {
		t.Fatalf("the interrupt of the code outside was called %d times", outside)
	}
	takeSignals(t, w, m)
}

// The guest's exit, normal or by a signal, ends the delivery of signals to
// the instance: the interval timer is disarmed, and what is posted raises
// no flag.
func TestSignal_ExitStopsTheTimer(t *testing.T) {
	for _, end := range []struct {
		name string
		call func(w *WasiStubs, m *Module)
	}{
		{"proc_exit", func(w *WasiStubs, m *Module) { w.Proc_exit(m, 0) }},
		{"proc_terminate", func(w *WasiStubs, m *Module) { w.Proc_terminate(m, wasiSIGTERM) }},
	} {
		w, m := newSignalGuest(t, wasiSIGALRM)
		setTimer(t, w, m, time.Hour, time.Hour)
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s returned", end.name)
				}
			}()
			end.call(w, m)
		}()
		w.PostSignal(wasiSIGALRM)
		if flag := signalFlag(m); flag != 0 {
			t.Fatalf("after %s a posted signal raised the flag", end.name)
		}
		w.sig.mu.Lock()
		timer := w.sig.timer
		w.sig.mu.Unlock()
		if timer != nil {
			t.Fatalf("the timer survived %s", end.name)
		}
	}
}

// Asking about or replacing the interval timer when it is overdue fires it
// first.
func TestSignal_TimerOverdueWhenAskedFires(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	setTimer(t, w, m, time.Hour, 0)
	w.sig.mu.Lock()
	w.sig.timerAt = time.Now().Add(-time.Millisecond)
	w.sig.mu.Unlock()
	if left, every := setTimer(t, w, m, 0, 0); left != 0 || every != 0 {
		t.Fatalf("an overdue one-shot timer reported %v left (every %v), want none", left, every)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM", got)
	}
}

// raise posts the signal to the guest itself, under the guest's number for
// the WASI signal it is given.
func TestSignal_RaisePostsToTheGuest(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGTERM, wasiSIGCHLD, wasiSIGSYS)
	// WASI's SIGTERM, SIGCHLD and SIGSYS
	for _, sig := range []int32{15, 16, 30} {
		if rc := w.Proc_raise(m, sig); rc != _wasiESUCCESS {
			t.Fatalf("Proc_raise(%d) rc=%d", sig, rc)
		}
	}
	if flag := signalFlag(m); flag != 1 {
		t.Fatalf("flag = %d after raise, want 1", flag)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGTERM, wasiSIGCHLD, wasiSIGSYS); got != want {
		t.Fatalf("taken = %#x, want SIGTERM, SIGCHLD and SIGSYS (%#x)", got, want)
	}
	for _, sig := range []int32{-1, 31} {
		if rc := w.Proc_raise(m, sig); rc != _wasiEINVAL {
			t.Fatalf("Proc_raise(%d) rc=%d, want EINVAL", sig, rc)
		}
	}
	if rc := w.Proc_raise(m, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_raise(0) rc=%d", rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x after raise(0), want nothing", got)
	}
}

// A signal that becomes deliverable when the guest unblocks it interrupts
// the next blocking call, as one that is posted unblocked does.
func TestSignal_UnblockedPendingSignalInterruptsTheNextWait(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGCHLD)
	setDispositions(t, w, m, signalMask(wasiSIGCHLD), wasiDefaultIgnoredSignals&^signalMask(wasiSIGCHLD), signalMask(wasiSIGCHLD))
	_, ended := w.NewProc(nil)
	ended(0)
	running, exited := w.NewProc(nil)
	defer exited(0)
	setDispositions(t, w, m, signalMask(wasiSIGCHLD), wasiDefaultIgnoredSignals&^signalMask(wasiSIGCHLD), 0)
	if rc := w.Proc_wait(m, running, 0, sigValueOff); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait with an unblocked signal pending rc=%d, want -EINTR", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGCHLD); got != want {
		t.Fatalf("taken = %#x, want SIGCHLD", got)
	}
}

// A signal that the guest blocks or comes to ignore before it took it
// interrupts no blocking call.
func TestSignal_UndeliverablePendingSignalInterruptsNothing(t *testing.T) {
	for _, disposition := range []struct {
		name             string
		ignored, blocked uint64
	}{
		{"ignored", signalMask(wasiSIGUSR1), 0},
		{"blocked", 0, signalMask(wasiSIGUSR1)},
	} {
		w, m := newSignalGuest(t, wasiSIGUSR1)
		w.PostSignal(wasiSIGUSR1)
		setDispositions(t, w, m, signalMask(wasiSIGUSR1), disposition.ignored, disposition.blocked)
		pid, exited := w.NewProc(nil)
		whenBlocked(w, func() { exited(0) })
		if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
			t.Fatalf("%s: Proc_wait rc=%d, want the status", disposition.name, rc)
		}
	}
}

// raise of a guest that has no flag word has the signal's default action.
func TestSignal_RaiseWithoutAFlagWordHasTheDefaultAction(t *testing.T) {
	w, m := newProcTestStubs(t)
	// none, and WASI's SIGCHLD and SIGWINCH
	for _, sig := range []int32{0, 16, 27} {
		if rc := w.Proc_raise(m, sig); rc != _wasiESUCCESS {
			t.Fatalf("Proc_raise(%d) rc=%d, want 0", sig, rc)
		}
	}
	// WASI's SIGTERM, SIGKILL, SIGABRT and SIGSYS, and the guest's numbers
	for sig, want := range map[int32]int32{15: wasiSIGTERM, 9: wasiSIGKILL, 6: wasiSIGABRT, 30: wasiSIGSYS} {
		func() {
			defer func() {
				var sigErr *WasiSignalError
				err, _ := recover().(error)
				if !errors.As(err, &sigErr) || sigErr.Signal != want {
					t.Fatalf("raise(%d) recovered %v, want a WasiSignalError for %d", sig, err, want)
				}
			}()
			w.Proc_raise(m, sig)
		}()
	}
}

// What the guest's own code posts — raise, an overdue timer it asks about —
// is left for the guest's next blocking call, also while code outside the
// guest has an interrupt registered.
func TestSignal_OwnPostsAreLeftForTheGuest(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGALRM)
	outside := 0
	w.SetOutsideInterrupt(func() { outside++ })
	pid, exited := w.NewProc(nil)
	defer exited(0)
	wait := func() int32 {
		return w.Proc_wait(m, pid, 0, sigValueOff)
	}

	if rc := w.Proc_raise(m, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_raise rc=%d", rc)
	}
	if rc := wait(); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait after raise rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)

	setTimer(t, w, m, time.Hour, 0)
	w.sig.mu.Lock()
	w.sig.timerAt = time.Now().Add(-time.Millisecond)
	w.sig.mu.Unlock()
	timerState(t, w, m)
	if rc := wait(); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait after the overdue timer fired rc=%d, want -EINTR", rc)
	}
	if outside != 0 {
		t.Fatalf("the interrupt of the code outside was called %d times", outside)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGALRM); got != want {
		t.Fatalf("taken = %#x, want SIGALRM", got)
	}
}

// A forked instance whose delivery has ended keeps nothing that is posted
// to it.
func TestSignal_DetachedForkedInstanceKeepsNothing(t *testing.T) {
	w, _ := newSignalGuest(t)
	child := w.Fork()
	if err := child.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	child.PostSignal(wasiSIGTERM)
	child.sig.mu.Lock()
	pending := child.sig.pending
	child.sig.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending = %#x after CloseAll, want none", pending)
	}
}

// recordingSignals is a Signals that records what it is given.
type recordingSignals struct {
	kills          [][2]int32
	killErr        error
	reports        [][3]uint64
	targets        []SignalTarget
	onDispositions func(target SignalTarget)
}

func (s *recordingSignals) Kill(pid, sig int32) error {
	s.kills = append(s.kills, [2]int32{pid, sig})
	return s.killErr
}

func (s *recordingSignals) Dispositions(target SignalTarget, handled, ignored, blocked uint64) {
	s.reports = append(s.reports, [3]uint64{handled, ignored, blocked})
	s.targets = append(s.targets, target)
	if s.onDispositions != nil {
		s.onDispositions(target)
	}
}

// A pid that is no process of the guest's goes to the configured Signals,
// under the guest's numbers, and its error is the errno the guest sees.
// Without one the pid names nothing.
func TestSignal_KillOutsideGoesToTheConfiguredSignals(t *testing.T) {
	m := newForkTestModule()
	if rc := NewWASI(WASIConfig{}).Proc_kill(m, 4242, wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("rc=%d without Signals, want -ESRCH", rc)
	}
	s := &recordingSignals{}
	w := NewWASI(WASIConfig{Signals: s})
	if rc := w.Proc_kill(m, 4242, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Errorf("Proc_kill rc=%d, want 0", rc)
	}
	if rc := w.Proc_kill(m, 4242, 0); rc != _wasiESUCCESS {
		t.Errorf("existence probe rc=%d, want 0", rc)
	}
	for err, want := range map[error]int32{
		syscall.ESRCH:      -_wasiESRCH,
		syscall.EPERM:      -_wasiEPERM,
		syscall.EINVAL:     -_wasiEINVAL,
		errors.New("lost"): -_wasiEIO,
	} {
		s.killErr = err
		if rc := w.Proc_kill(m, 4243, wasiSIGTERM); rc != want {
			t.Errorf("Kill error %v: rc=%d, want %d", err, rc, want)
		}
	}
	s.killErr = nil
	// A process of the guest's own is not one for the Signals.
	pid, exited := w.NewProc(func(int32) error { return nil })
	defer exited(0)
	if rc := w.Proc_kill(m, pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Errorf("Proc_kill of a child rc=%d", rc)
	}
	if len(s.kills) != 6 || s.kills[0] != [2]int32{4242, wasiSIGUSR1} || s.kills[1] != [2]int32{4242, 0} || s.kills[2] != [2]int32{4243, wasiSIGTERM} {
		t.Errorf("kills = %v", s.kills)
	}
}

// Every change of the dispositions is reported as the state has it; an
// implementation may post a signal from the report.
func TestSignal_DispositionsAreReported(t *testing.T) {
	w, m := newSignalGuest(t)
	s := &recordingSignals{onDispositions: func(target SignalTarget) { target.PostSignal(wasiSIGUSR1) }}
	w.cfg.Signals = s
	handled := signalMask(wasiSIGUSR1, wasiSIGKILL)
	ignored := signalMask(wasiSIGPIPE)
	blocked := signalMask(wasiSIGHUP, wasiSIGSTOP)
	setDispositions(t, w, m, handled, ignored, blocked)
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want the signal posted from the report (%#x)", got, want)
	}
	s.onDispositions = nil
	setDispositions(t, w, m, 0, 0, 0)
	want := [][3]uint64{
		{signalMask(wasiSIGUSR1), ignored, signalMask(wasiSIGHUP)},
		{0, 0, 0},
	}
	if len(s.reports) != len(want) || s.reports[0] != want[0] || s.reports[1] != want[1] {
		t.Fatalf("reports = %#x, want %#x", s.reports, want)
	}
	if len(s.targets) != 2 || s.targets[0] != w || s.targets[1] != w {
		t.Fatalf("targets = %v, want the reporting instance", s.targets)
	}
}

func TestSignal_ForkKeepsTheSignals(t *testing.T) {
	w, _ := newSignalGuest(t)
	s := &recordingSignals{}
	w.cfg.Signals = s
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	if rc := child.Proc_kill(cm, 4242, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill from the forked guest rc=%d", rc)
	}
	setDispositions(t, child, cm, signalMask(wasiSIGTERM), 0, 0)
	if len(s.kills) != 1 || len(s.reports) != 1 || s.reports[0][0] != signalMask(wasiSIGTERM) {
		t.Fatalf("kills = %v, reports = %#x", s.kills, s.reports)
	}
	if s.targets[0] != child {
		t.Fatal("the forked instance reported with another target")
	}
}

// kill of the guest's own pid is a raise; of its process group (0, minus
// its pid) every process of the family and the guest; of -1 the family but
// the guest. None of them is for the Signals; another group is.
func TestSignal_KillOfTheGuestAndItsGroup(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	s := &recordingSignals{}
	w.cfg.Signals = s
	self := w.guestPID()
	if rc := w.Proc_kill(m, self, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the guest's own pid rc=%d", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x after kill of the own pid, want %#x", got, want)
	}
	if rc := w.Proc_kill(m, -1, wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("kill(-1) with no other process rc=%d, want -ESRCH", rc)
	}

	var toChild []int32
	_, exited := w.NewProc(func(sig int32) error {
		toChild = append(toChild, sig)
		return nil
	})
	defer exited(0)
	for _, group := range []int32{0, -self} {
		if rc := w.Proc_kill(m, group, wasiSIGUSR2); rc != _wasiESUCCESS {
			t.Fatalf("kill(%d) rc=%d", group, rc)
		}
		if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR2); got != want {
			t.Fatalf("taken = %#x after kill(%d), want %#x", got, group, want)
		}
	}
	if rc := w.Proc_kill(m, -1, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(-1) rc=%d", rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("kill(-1) reached the guest itself: %#x", got)
	}
	if len(toChild) != 3 || toChild[0] != wasiSIGUSR2 || toChild[1] != wasiSIGUSR2 || toChild[2] != wasiSIGUSR1 {
		t.Fatalf("signals to the child = %v", toChild)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
	if rc := w.Proc_kill(m, -4242, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of another group rc=%d", rc)
	}
	if len(s.kills) != 1 || s.kills[0] != [2]int32{-4242, wasiSIGTERM} {
		t.Fatalf("kills = %v, want [[-4242 15]]", s.kills)
	}
}

// registeredFork registers the guest of a forked instance for signals and
// has it handle sigs.
func registeredFork(t *testing.T, child *WasiStubs, sigs ...int32) *Module {
	t.Helper()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, child, cm, signalMask(sigs...), 0, 0)
	return cm
}

// A copy made by Fork shares the root's pid, which names the copy itself
// there. A copy with a pid of its own (ForkProc) reaches the root by the
// root's pid, which names nothing once the root is closed and is never
// passed to the Signals.
func TestSignal_ForkChildKillsTheRoot(t *testing.T) {
	root, m := newSignalGuest(t, wasiSIGUSR1)
	s := &recordingSignals{}
	root.cfg.Signals = s
	plain := root.Fork()
	pm := registeredFork(t, plain, wasiSIGUSR1)
	if rc := plain.Proc_kill(pm, root.guestPID(), wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(getpid()) in a Fork copy rc=%d", rc)
	}
	if got, want := takeSignals(t, plain, pm), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("Fork copy taken = %#x, want its own signal %#x", got, want)
	}
	if got := takeSignals(t, root, m); got != 0 {
		t.Fatalf("root taken = %#x from the Fork copy's own pid", got)
	}

	child, _, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child, wasiSIGUSR1)
	if rc := child.Proc_kill(cm, root.guestPID(), wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the root rc=%d", rc)
	}
	if got, want := takeSignals(t, root, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("root taken = %#x, want %#x", got, want)
	}
	if err := root.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if rc := child.Proc_kill(cm, root.guestPID(), wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("kill of the closed root rc=%d, want -ESRCH", rc)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
}

// Neither the root's pid nor its ppid is handed out as a token, also when
// they lie where the tokens are.
func TestSignal_TokensAvoidTheRootsIDs(t *testing.T) {
	root, _ := newProcTestStubs(t)
	root.cfg.Process = testProcess{ids: ProcessIDs{PID: 1001, PPID: 1003}}
	child, first, exited := root.ForkProc()
	defer exited(0)
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	second, secondExited := child.NewProc(nil)
	defer secondExited(0)
	third, thirdExited := child.NewProc(nil)
	defer thirdExited(0)
	if first != 1000 || second != 1002 || third != 1004 {
		t.Fatalf("tokens = %d, %d, %d; want 1000, 1002, 1004", first, second, third)
	}
}

// A number handed out as a token before the root is entered stays a token
// when it is one of the root's ids: its process gone, it names nothing, and
// it is not passed to the Signals.
func TestSignal_RootIDsHandedOutStayTokens(t *testing.T) {
	root, m := newProcTestStubs(t)
	s := &recordingSignals{}
	root.cfg.Signals = s
	pid, exited := root.NewProc(nil)
	exited(0)
	if rc := root.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	root.cfg.Process = testProcess{ids: ProcessIDs{PID: 42, PPID: pid}}
	child := root.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	if rc := root.Proc_kill(m, pid, wasiSIGTERM); rc != -_wasiESRCH {
		t.Fatalf("kill of the reaped token %d rc=%d, want -ESRCH", pid, rc)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
}

// A ForkProc copy of a Fork copy has the root's pid as its ppid, and its
// kill of it reaches the root, not the Fork copy.
func TestSignal_ForkProcOfAForkCopyReachesTheRoot(t *testing.T) {
	root, m := newSignalGuest(t, wasiSIGUSR1)
	plain := root.Fork()
	pm := registeredFork(t, plain, wasiSIGUSR1)
	grand, _, exited := plain.ForkProc()
	defer exited(0)
	gm := registeredFork(t, grand, wasiSIGUSR1)
	ppid := grand.guestProcess().IDs().PPID
	if ppid != root.guestPID() {
		t.Fatalf("ppid = %d, want the root's pid %d", ppid, root.guestPID())
	}
	if rc := grand.Proc_kill(gm, ppid, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(getppid()) rc=%d", rc)
	}
	if got, want := takeSignals(t, root, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("root taken = %#x, want %#x", got, want)
	}
	if got := takeSignals(t, plain, pm); got != 0 {
		t.Fatalf("the Fork copy took %#x", got)
	}
}

// Two blocking calls in progress (threads of the guest share the instance)
// are both woken by a signal: one ends with EINTR, the other waits on.
func TestSignal_OneOfTwoWaitsEndsByASignal(t *testing.T) {
	w, _ := newSignalGuest(t, wasiSIGUSR1)
	first, firstExited := w.NewProc(nil)
	second, secondExited := w.NewProc(nil)
	results := make(chan int32, 2)
	for _, pid := range []int32{first, second} {
		go func() { results <- w.Proc_wait(newForkTestModule(), pid, 0, sigValueOff) }()
	}
	awaitBlockedCalls(w, 2)
	w.PostSignal(wasiSIGUSR1)
	if rc := <-results; rc != -_wasiEINTR {
		t.Fatalf("the first wait to end rc=%d, want -EINTR", rc)
	}
	awaitBlockedCalls(w, 1)
	firstExited(0)
	secondExited(0)
	if rc := <-results; rc != _wasiESUCCESS {
		t.Fatalf("the other wait rc=%d, want the status", rc)
	}
}

// killEnd returns the signal of the *WasiSignalError call panics with, or 0
// when it returns.
func killEnd(call func()) (sig int32) {
	defer func() {
		if r := recover(); r != nil {
			sigErr, ok := r.(*WasiSignalError)
			if !ok {
				panic(r)
			}
			sig = sigErr.Signal
		}
	}()
	call()
	return 0
}

// SIGKILL to a forked guest that has not registered for signals ends it at
// its next blocking call or spawn, and ends the blocking call it waits in.
func TestSignal_KillOfAnUnregisteredForkedGuestEndsIt(t *testing.T) {
	w, _ := newSignalGuest(t)
	waiting := w.Fork()
	t.Cleanup(func() {
		if err := waiting.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	pid, exited := waiting.NewProc(nil)
	defer exited(0)
	whenBlocked(waiting, func() { waiting.PostSignal(wasiSIGKILL) })
	if sig := killEnd(func() { waiting.Proc_wait(newForkTestModule(), pid, 0, sigValueOff) }); sig != wasiSIGKILL {
		t.Fatalf("the wait ended the guest by %d, want SIGKILL", sig)
	}

	for name, call := range map[string]func(*WasiStubs, *Module){
		"proc_wait_any": func(w *WasiStubs, m *Module) { w.Proc_wait_any(m, 0, sigValueOff, sigValueOff+4) },
		"proc_spawn": func(w *WasiStubs, m *Module) {
			w.Proc_spawn(m, writeCStr(m, 1000, "/bin/sh"), writeArgv(m, 2000, 3000, []string{"/bin/sh"}), 0, -1, -1, -1, 0, 4000)
		},
	} {
		killed := w.Fork()
		_, ended := killed.NewProc(nil)
		defer ended(0)
		killed.PostSignal(wasiSIGKILL)
		if sig := killEnd(func() { call(killed, newForkTestModule()) }); sig != wasiSIGKILL {
			t.Errorf("%s ended the guest by %d, want SIGKILL", name, sig)
		}
		if err := killed.CloseAll(); err != nil {
			t.Error(err)
		}
	}
}

// A signal that ends a process, posted to a root guest that has not
// registered, is kept and ends the guest at its next host call of those that
// look (endUnregistered), SIGKILL before any other; one that does nothing by
// default is dropped.
func TestSignal_KillOfAnUnregisteredRootEndsIt(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.PostSignal(wasiSIGCHLD)
	if rc := fdWriteString(w, m, 1, "x"); rc != _wasiESUCCESS {
		t.Fatalf("fd_write after a dropped SIGCHLD rc=%d", rc)
	}
	w.PostSignal(wasiSIGTERM)
	w.PostSignal(wasiSIGKILL)
	if sig := killEnd(func() { fdWriteString(w, m, 1, "x") }); sig != wasiSIGKILL {
		t.Fatalf("fd_write ended the guest by %d, want SIGKILL", sig)
	}
	other, om := newProcTestStubs(t)
	other.PostSignal(wasiSIGUSR1)
	other.PostSignal(wasiSIGTERM)
	if sig := killEnd(func() { other.Proc_umask(om, 0o22) }); sig != wasiSIGUSR1 {
		t.Fatalf("proc_umask ended the guest by %d, want the lowest pending, SIGUSR1", sig)
	}
	// Delivery has ended: a kill of the gone root fails.
	child, _, exited := w.ForkProc()
	defer exited(0)
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	if rc := child.Proc_kill(newForkTestModule(), w.guestPID(), wasiSIGTERM); rc != -_wasiESRCH {
		t.Fatalf("kill of the ended root rc=%d, want -ESRCH", rc)
	}
}

// kill(-1) is never the guest's own process group, also for pid 1.
func TestSignal_KillMinusOneWithPIDOne(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 1}}
	if rc := w.Proc_kill(m, -1, wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("kill(-1) rc=%d, want -ESRCH", rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("kill(-1) reached the guest: %#x", got)
	}
}

// A pid token of a process that has been waited for names nothing, and is
// not passed to the Signals.
func TestSignal_KillOfAReapedTokenIsESRCH(t *testing.T) {
	w, m := newProcTestStubs(t)
	s := &recordingSignals{}
	w.cfg.Signals = s
	pid, exited := w.NewProc(nil)
	exited(0)
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if rc := w.Proc_kill(m, pid, wasiSIGTERM); rc != -_wasiESRCH {
		t.Fatalf("kill of a reaped token rc=%d, want -ESRCH", rc)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
}

// poll_oneoff's sleep ends with EINTR by a signal posted to the guest.
func TestSignal_InterruptsAPollSleep(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	m.memory[8] = 0 // a clock subscription
	binary.LittleEndian.PutUint64(m.memory[24:], uint64(time.Hour))
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Poll_oneoff(m, 0, 200, 1, 400); rc != _wasiEINTR {
		t.Fatalf("Poll_oneoff rc=%d, want EINTR", rc)
	}
}

// A copy made by ForkProc is its parent's child under its token, which it
// knows as its own pid: its kill of it is a raise, its kill of its group
// reaches it once and the parent too.
func TestSignal_ForkProcChildKnowsItsToken(t *testing.T) {
	root, m := newSignalGuest(t, wasiSIGUSR1, wasiSIGUSR2)
	child, pid, exited := root.ForkProc()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, child, cm, signalMask(wasiSIGUSR1, wasiSIGUSR2), 0, 0)

	if rc := root.Proc_kill(m, pid, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the child by the parent rc=%d", rc)
	}
	if rc := child.Proc_kill(cm, pid, wasiSIGUSR2); rc != _wasiESUCCESS {
		t.Fatalf("kill of its own token by the child rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGUSR1, wasiSIGUSR2); got != want {
		t.Fatalf("child taken = %#x, want %#x", got, want)
	}
	if rc := child.Proc_kill(cm, 0, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(0) by the child rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("child taken = %#x after kill(0), want %#x", got, want)
	}
	if got, want := takeSignals(t, root, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("root taken = %#x after the child's kill(0), want %#x", got, want)
	}

	// Its identity: the token as pid, the parent's pid as ppid.
	ids := child.guestProcess().IDs()
	if ids.PID != pid || ids.PPID != root.guestPID() {
		t.Fatalf("child ids = %+v, want pid %d and ppid %d", ids, pid, root.guestPID())
	}
	if rc := child.Proc_kill(cm, ids.PPID, wasiSIGUSR2); rc != _wasiESUCCESS {
		t.Fatalf("kill(getppid()) rc=%d", rc)
	}
	if got, want := takeSignals(t, root, m), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("root taken = %#x after kill(getppid()), want %#x", got, want)
	}
	// Minus a token names no process group.
	s := &recordingSignals{}
	root.cfg.Signals = s
	if rc := root.Proc_kill(m, -pid, wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("kill(-token) rc=%d, want -ESRCH", rc)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
	// An ended copy is a zombie until its exited is called.
	if err := child.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if rc := root.Proc_kill(m, pid, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the ended copy rc=%d, want 0", rc)
	}
	if rc := root.Proc_kill(m, -1, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(-1) with the ended copy rc=%d, want 0", rc)
	}

	exited(3 << 8)
	if rc := root.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(sigValueOff)); status != 3<<8 {
		t.Fatalf("status = %#x", status)
	}
	if rc := root.Proc_kill(m, pid, wasiSIGUSR1); rc != -_wasiESRCH {
		t.Fatalf("kill of the reaped child rc=%d, want -ESRCH", rc)
	}
}
