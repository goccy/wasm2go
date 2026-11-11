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
	setDispositions(t, w, m, signalMask(handled...), wasiDefaultIgnoredSignals, 0)
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

// postSoon posts sig from another goroutine once the caller has had time to
// block.
func postSoon(w *WasiStubs, sig int32) {
	go func() {
		time.Sleep(30 * time.Millisecond)
		w.PostSignal(sig)
	}()
}

// sleepPoll is a guest sleeping for d through poll_oneoff.
func sleepPoll(w *WasiStubs, m *Module, d time.Duration) int32 {
	writeSubClock(m, pollSubsOff, 1, int64(d))
	return w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff)
}

func TestSignal_DroppedUntilTheGuestRegisters(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.PostSignal(wasiSIGTERM)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d, want 0", rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("a signal posted before registration was kept: %#x", got)
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
	// It interrupts nothing while blocked.
	start := time.Now()
	if rc := sleepPoll(w, m, 40*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep with a blocked signal pending rc=%d", rc)
	}
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("sleep ended after %v", d)
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
	postSoon(w, wasiSIGUSR1)
	start := time.Now()
	if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
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
	if rc := sleepPoll(w, m, 40*time.Millisecond); rc != _wasiESUCCESS {
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
	if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep with a signal waiting rc=%d, want EINTR", rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("sleep ended after %v", d)
	}
	// A poll that does not wait is not interrupted.
	w.PostSignal(wasiSIGUSR1)
	if rc := sleepPoll(w, m, 0); rc != _wasiESUCCESS {
		t.Fatalf("zero-timeout poll rc=%d", rc)
	}
	// Once taken, nothing is left to interrupt for.
	takeSignals(t, w, m)
	if rc := sleepPoll(w, m, 10*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after take rc=%d", rc)
	}
}

func TestSignal_InterruptsPollOnAnIdlePipe(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	writeSubFd(m, pollSubsOff, 7, 1 /* fd_read */, readFd)
	postSoon(w, wasiSIGUSR1)
	if rc := w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff); rc != _wasiEINTR {
		t.Fatalf("poll on an idle pipe rc=%d, want EINTR", rc)
	}
	// The pipe is as it was: input written now is polled and read.
	if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "data" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

func TestSignal_InterruptsBlockingPipeRead(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	postSoon(w, wasiSIGUSR1)
	if _, rc := fdReadString(w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("read of an idle pipe rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	// The interruption left no deadline behind: the retried read waits for
	// the writer.
	go func() {
		time.Sleep(30 * time.Millisecond)
		fdWriteString(w, newForkTestModule(), writeFd, "late")
	}()
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("retried read = %q rc=%d, want %q", got, rc, "late")
	}
	// Input that is there is returned even with a signal waiting.
	if rc := fdWriteString(w, m, writeFd, "more"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	w.PostSignal(wasiSIGUSR1)
	if _, rc := fdReadString(w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("read with a signal waiting rc=%d, want EINTR", rc)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "more" {
		t.Fatalf("read after the interruption = %q rc=%d, want %q", got, rc, "more")
	}
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
	if got, rc := fdReadString(w, m, fd, 16); rc != _wasiESUCCESS || got != "content" {
		t.Fatalf("file read with a signal waiting = %q rc=%d", got, rc)
	}
}

func TestSignal_InterruptsWaitForAProcess(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	pid, exited := w.NewProc(nil)
	postSoon(w, wasiSIGUSR1)
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != -_wasiEINTR {
		t.Fatalf("Proc_wait rc=%d, want -EINTR", rc)
	}
	postSoon(w, wasiSIGUSR1)
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
	go func() {
		time.Sleep(30 * time.Millisecond)
		exited(0)
	}()
	// The wait is over because the process finished, not because of the
	// signal that says so.
	if rc := w.Proc_wait(m, pid, 0, sigValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	// finishProc posts after publishing the status: give it the moment.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := takeSignals(t, w, m); got == signalMask(wasiSIGCHLD) {
			break
		} else if got != 0 {
			t.Fatalf("taken = %#x, want SIGCHLD", got)
		}
		if time.Now().After(deadline) {
			t.Fatal("no SIGCHLD after the process finished")
		}
		runtime.Gosched()
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
	if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
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
	if rc := sleepPoll(w, m, 600*time.Millisecond); rc != _wasiESUCCESS {
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
		if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
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
	if rc := sleepPoll(w, m, 300*time.Millisecond); rc != _wasiESUCCESS {
		t.Fatalf("sleep after disarming the repeating timer rc=%d", rc)
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

func TestSignal_InterruptsWaitingFlock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	holder := openTestFile(t, w, "lock")
	waiter := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, holder, 2, 0); rc != _wasiESUCCESS {
		skipWithoutPOSIXFiles(t)
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	postSoon(w, wasiSIGUSR1)
	if rc := w.Fd_flock(m, waiter, 2, 1); rc != -_wasiEINTR {
		t.Fatalf("waiting lock rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	// Without a signal the wait ends when the lock is released.
	go func() {
		time.Sleep(30 * time.Millisecond)
		w.Fd_flock(newForkTestModule(), holder, 0, 0)
	}()
	if rc := w.Fd_flock(m, waiter, 2, 1); rc != _wasiESUCCESS {
		t.Fatalf("waiting lock after release rc=%d", rc)
	}
}

func TestSignal_ForkedStateStartsWithoutSignals(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	setTimer(t, w, m, 100*time.Second, 0)
	w.PostSignal(wasiSIGUSR1)
	child := w.Fork()
	defer child.CloseAll()
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
	defer child.CloseAll()
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
	w.mu.Lock()
	timer := w.sig.timer
	w.mu.Unlock()
	if timer != nil {
		t.Fatal("the timer survived CloseAll")
	}
}

// As the host process, the guest receives the host process's signals it
// handles, the host process ignores the ones the guest ignores, and both
// stop when the instance is closed.
func TestSignal_HostProcessRelaysAndIgnores(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the runtime maps signals on darwin and linux only")
	}
	w, m := newSignalGuest(t)
	w.SetHostProcess(true)
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), wasiDefaultIgnoredSignals|signalMask(wasiSIGUSR2), 0)
	t.Cleanup(func() { w.CloseAll() })

	self := os.Getpid()
	// Ignored by the guest: the host process survives it (its default action
	// is to end the process).
	if err := syscall.Kill(self, syscall.SIGUSR2); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if err := syscall.Kill(self, syscall.SIGUSR1); err != nil {
		t.Fatalf("kill: %v", err)
	}
	// The relay runs on its own goroutine; a sleeping guest is woken by it.
	if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep rc=%d, want EINTR from the relayed signal", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want the guest's SIGUSR1 (%#x)", got, want)
	}

	// A signal that would end the program, but that the Go runtime swallows,
	// reaches the guest too: its default action is the guest's to take.
	setDispositions(t, w, m, 0, wasiDefaultIgnoredSignals, 0)
	if err := syscall.Kill(self, syscall.SIGUSR2); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if rc := sleepPoll(w, m, 30*time.Second); rc != _wasiEINTR {
		t.Fatalf("sleep rc=%d, want EINTR from the relayed signal", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR2); got != want {
		t.Fatalf("taken = %#x, want the guest's SIGUSR2 (%#x)", got, want)
	}
	// SIGTERM ends a Go program as it ends any process: not caught.
	w.mu.Lock()
	relayed := w.sig.relayed
	w.mu.Unlock()
	if relayed&signalMask(wasiSIGTERM, wasiSIGINT, wasiSIGHUP, wasiSIGCHLD, wasiSIGKILL) != 0 {
		t.Fatalf("relayed = %#x includes signals the runtime acts on itself", relayed)
	}

	// A forked instance is not the host process: it relays nothing.
	child := w.Fork()
	cm := newForkTestModule()
	if rc := child.Proc_signal_register(cm, sigFlagOff); rc != 0 {
		t.Fatalf("child registration rc=%d", rc)
	}
	setDispositions(t, child, cm, signalMask(wasiSIGUSR1), wasiDefaultIgnoredSignals, 0)
	child.mu.Lock()
	childRelay := child.sig.relay
	child.mu.Unlock()
	if childRelay != nil {
		t.Fatal("a forked instance subscribed to the host process's signals")
	}
	child.CloseAll()

	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	w.mu.Lock()
	relay, relayed, ignored := w.sig.relay, w.sig.relayed, w.sig.hostIgnored
	w.mu.Unlock()
	if relay != nil || relayed != 0 || ignored != 0 {
		t.Fatalf("after CloseAll: relay=%v relayed=%#x ignored=%#x, want none", relay, relayed, ignored)
	}
}
