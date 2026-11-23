//go:build darwin || linux

package codegen

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// newPipeStdin makes the instance's stdin the read end of an io.Pipe,
// which is no descriptor of the host's and whose Read waits for a Write,
// and returns the write end.
func newPipeStdin(t *testing.T, w *WasiStubs) *io.PipeWriter {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		if err := pw.Close(); err != nil {
			t.Error(err)
		}
	})
	w.cfg.Stdin = pr
	return pw
}

// writeLater writes s to pw on a goroutine of its own: the write returns
// once a Read has taken it.
func writeLater(t *testing.T, pw *io.PipeWriter, s string) {
	go func() {
		if _, err := pw.Write([]byte(s)); err != nil {
			t.Error(err)
		}
	}()
}

// A non-blocking read of a stream of the embedder's that the runtime has
// not read finds nothing and asks for a read; a poll then waits for it,
// and the next read takes what it got.
func TestEmbedderStdin_NonblockingReadAsksForARead(t *testing.T) {
	w, m := newProcTestStubs(t)
	writeLater(t, newPipeStdin(t, w), "x")
	if rc := w.Fd_fdstat_set_flags(m, 0, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking read before the stream was read = %q rc=%d, want EAGAIN", got, rc)
	}
	writeSubFd(m, pollSubsOff, 7, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read after the poll = %q rc=%d, want %q", got, rc, "x")
	}
}

// A signal ends a read that waits for a stream of the embedder's; what the
// stream returns after it is the next read's.
func TestEmbedderStdin_SignalEndsTheReadAndKeepsTheInput(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	pw := newPipeStdin(t, w)
	postWhenBlocked(w, wasiSIGUSR1)
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiEINTR {
		t.Fatalf("read = %q rc=%d, want EINTR", got, rc)
	}
	takeSignals(t, w, m)
	writeLater(t, pw, "y")
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiESUCCESS || got != "y" {
		t.Fatalf("read after the signal = %q rc=%d, want %q", got, rc, "y")
	}
}

// Input the reader has when a signal ends the wait is read all the same,
// and the signal is reported by the next call that waits.
func TestEmbedderStdin_InputWithASignal(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	newPipeStdin(t, w)
	whenBlocked(w, func() {
		// Input the wait is not woken for: the signal ends it.
		w.mu.Lock()
		r := w.streams.stdin
		w.mu.Unlock()
		r.mu.Lock()
		r.buf = append(r.buf, 'q')
		r.mu.Unlock()
		w.PostSignal(wasiSIGUSR1)
	})
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiESUCCESS || got != "q" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "q")
	}
	if _, rc := readWithin(t, w, m, 0, 4); rc != _wasiEINTR {
		t.Fatalf("the next read that waits rc=%d, want EINTR", rc)
	}
}

// A poll for input of a stream of the embedder's asks for a read, which
// ends the poll's wait.
func TestEmbedderStdin_PollAsksForARead(t *testing.T) {
	w, m := newProcTestStubs(t)
	writeLater(t, newPipeStdin(t, w), "x")
	writeSubFd(m, pollSubsOff, 7, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read after the poll = %q rc=%d, want %q", got, rc, "x")
	}
}

// deadlineRecorder is a stream of the embedder's that takes deadlines and
// counts the calls that set one.
type deadlineRecorder struct {
	io.Reader
	calls atomic.Int32
}

func (d *deadlineRecorder) SetReadDeadline(time.Time) error {
	d.calls.Add(1)
	return nil
}

// The runtime sets no deadline of a stream of the embedder's: not to read
// it, wait for it in a poll, or end a read a signal interrupts.
func TestEmbedderStdin_NoDeadlines(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		if err := pw.Close(); err != nil {
			t.Error(err)
		}
	})
	stdin := &deadlineRecorder{Reader: pr}
	w.cfg.Stdin = stdin
	postWhenBlocked(w, wasiSIGUSR1)
	if _, rc := readWithin(t, w, m, 0, 4); rc != _wasiEINTR {
		t.Fatalf("read rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	writeLater(t, pw, "z")
	writeSubFd(m, pollSubsOff, 7, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, 0, 4); rc != _wasiESUCCESS || got != "z" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "z")
	}
	if n := stdin.calls.Load(); n != 0 {
		t.Fatalf("SetReadDeadline was called %d times", n)
	}
}

// readerFile is a file of a filesystem of the embedder's whose reads can
// wait (it takes a deadline, as a stream does), read from r. Closing it
// closes nothing.
type readerFile struct {
	File
	r io.Reader
}

func (f *readerFile) Read(p []byte) (int, error)      { return f.r.Read(p) }
func (f *readerFile) SetReadDeadline(time.Time) error { return nil }
func (f *readerFile) Close() error                    { return nil }

// The close of the last descriptor of a stream read through a reader ends
// the read that waits for it, with EBADF.
func TestEmbedderStream_CloseEndsTheWaitingRead(t *testing.T) {
	w, m := newProcTestStubs(t)
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		if err := pw.Close(); err != nil {
			t.Error(err)
		}
	})
	w.mu.Lock()
	fd, errno := w.addFDLocked(&wasiOpen{f: &readerFile{r: pr}})
	w.mu.Unlock()
	if errno != _wasiESUCCESS {
		t.Fatalf("addFDLocked errno=%d", errno)
	}
	whenBlocked(w, func() { closeTestFd(t, w, newForkTestModule(), fd) })
	if _, rc := readWithin(t, w, m, fd, 4); rc != _wasiEBADF {
		t.Fatalf("read during the close rc=%d, want EBADF", rc)
	}
}

// blockingWriter is a Writer of the embedder's whose Write waits until
// release is closed, and that records two Writes at once.
type blockingWriter struct {
	entered  chan struct{}
	release  chan struct{}
	inFlight atomic.Int32
	overlap  atomic.Bool
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{entered: make(chan struct{}, 8), release: make(chan struct{})}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	if b.inFlight.Add(1) > 1 {
		b.overlap.Store(true)
	}
	defer b.inFlight.Add(-1)
	b.entered <- struct{}{}
	<-b.release
	return len(p), nil
}

// newWritingFamily returns an instance registered for signals whose stdout
// is out and stderr errOut, and a copy of it (Fork) whose write to fd is
// inside out's Write.
func newWritingFamily(t *testing.T, out *blockingWriter, errOut io.Writer) (*WasiStubs, *Module, <-chan int32) {
	t.Helper()
	w, m := newSignalGuestIn(t, t.TempDir())
	w.cfg.Stdout, w.cfg.Stderr = out, errOut
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	done := make(chan int32, 1)
	go func() { done <- fdWriteString(child, newForkTestModule(), 1, "c") }()
	<-out.entered
	return w, m, done
}

// A write of the guest's to the stdout another instance of its family is
// writing waits for that Write, and a signal ends the wait: the Writer is
// written one call at a time.
func TestEmbedderStdout_WriteWaitsForAnotherInterruptibly(t *testing.T) {
	out := newBlockingWriter()
	w, m, done := newWritingFamily(t, out, &bytes.Buffer{})
	postWhenBlocked(w, wasiSIGUSR1)
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 1, "p") })
	if rc != _wasiEINTR {
		t.Fatalf("write while another is in Write rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	close(out.release)
	if rc := <-done; rc != _wasiESUCCESS {
		t.Fatalf("the other write rc=%d", rc)
	}
	if out.overlap.Load() {
		t.Fatal("two Writes ran at once")
	}
}

// The stdout and the stderr that are two Writers are written independently.
func TestEmbedderStdout_StderrOfAnotherWriterDoesNotWait(t *testing.T) {
	out := newBlockingWriter()
	var errOut bytes.Buffer
	w, m, done := newWritingFamily(t, out, &errOut)
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 2, "e") })
	if rc != _wasiESUCCESS || errOut.String() != "e" {
		t.Fatalf("write to stderr rc=%d, wrote %q", rc, errOut.String())
	}
	close(out.release)
	if rc := <-done; rc != _wasiESUCCESS {
		t.Fatalf("the stdout write rc=%d", rc)
	}
}

// A write that does not wait finds the stdout busy with another instance's
// Write (EAGAIN); a poll for writing waits until that is done.
func TestEmbedderStdout_NonblockingWriteAndPoll(t *testing.T) {
	out := newBlockingWriter()
	w, m, done := newWritingFamily(t, out, &bytes.Buffer{})
	if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 1, "p") })
	if rc != _wasiEAGAIN {
		t.Fatalf("write that does not wait rc=%d, want EAGAIN", rc)
	}
	// Not writable while the other Write runs: a poll that does not wait
	// reports its timeout.
	writeSubClock(m, pollSubsOff, 1, 0)
	writeSubFd(m, pollSubsOff+48, 9, 2, 1)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	whenBlocked(w, func() { close(out.release) })
	writeSubFd(m, pollSubsOff, 9, 2, 1)
	wantUserdata(t, pollUserdata(t, w, m, 1), 9)
	if rc := <-done; rc != _wasiESUCCESS {
		t.Fatalf("the other write rc=%d", rc)
	}
}

// The stdout and the stderr that are one Writer are written one Write at a
// time, as os/exec writes them.
func TestEmbedderStdout_StderrOfTheSameWriterWaits(t *testing.T) {
	out := newBlockingWriter()
	w, m, done := newWritingFamily(t, out, out)
	postWhenBlocked(w, wasiSIGUSR1)
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 2, "e") })
	if rc != _wasiEINTR {
		t.Fatalf("write to the stderr that is the stdout in Write rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	close(out.release)
	if rc := <-done; rc != _wasiESUCCESS {
		t.Fatalf("the stdout write rc=%d", rc)
	}
	if out.overlap.Load() {
		t.Fatal("two Writes ran at once")
	}
}

// A command's stdin copied from the instance's stdin of the embedder's,
// read through a reader, leaves what the command did not read to the
// guest.
func TestEmbedderStdin_CommandLeavesTheRestToTheGuest(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	stdin := &struct{ io.Reader }{bytes.NewReader([]byte("abc\nrest\n"))}
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = stdin, &out, &bytes.Buffer{}
	pid := spawnWithStreams(t, w, m, -1, -1, -1, "/bin/sh", "-c", `read x; echo "got $x"`)
	waitExitsZero(t, w, m, pid)
	if out.String() != "got abc\n" {
		t.Fatalf("command output = %q, want its first line", out.String())
	}
	if got := readToEnd(t, w, m, 0); got != "rest\n" {
		t.Fatalf("the guest then reads %q, want what the command left", got)
	}
}

// A turn given back while a write waits for it is handed to that write: the
// giver cannot take it again first.
func TestEmbedderStdout_GiveHandsTheTurnToTheWaitingWrite(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdout = &out
	w.mu.Lock()
	turn := w.streamsLocked().stdout
	w.mu.Unlock()
	if !turn.tryTake() {
		t.Fatal("the turn is held")
	}
	whenBlocked(w, func() {
		if err := turn.give(); err != nil {
			t.Error(err)
		}
		if turn.tryTake() {
			t.Error("the giver took the turn again before the write that waits for it")
			if err := turn.give(); err != nil {
				t.Error(err)
			}
		}
	})
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 1, "w") })
	if rc != _wasiESUCCESS || out.String() != "w" {
		t.Fatalf("write rc=%d, wrote %q", rc, out.String())
	}
}

// A write that a signal ended while it waited for the turn leaves the
// turn's queue: the turn given back is free for the next write.
func TestEmbedderStdout_AnInterruptedWriteLeavesTheQueue(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdout = &out
	w.mu.Lock()
	turn := w.streamsLocked().stdout
	w.mu.Unlock()
	if !turn.tryTake() {
		t.Fatal("the turn is held")
	}
	postWhenBlocked(w, wasiSIGUSR1)
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 1, "p") })
	if rc != _wasiEINTR {
		t.Fatalf("write while the turn is held rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	if err := turn.give(); err != nil {
		t.Fatal(err)
	}
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, 1, "n") })
	if rc != _wasiESUCCESS || out.String() != "n" {
		t.Fatalf("write after the turn is given back rc=%d, wrote %q", rc, out.String())
	}
}

// The reader of a family's stdin is stopped by the CloseAll of the last of
// its instances: a copy (Fork) reads on after the instance it was made of
// is closed.
func TestEmbedderStdin_ACopyReadsAfterItsParentIsClosed(t *testing.T) {
	w, _ := newProcTestStubs(t)
	pw := newPipeStdin(t, w)
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	if err := w.CloseAll(); err != nil {
		t.Fatal(err)
	}
	writeLater(t, pw, "c")
	if got, rc := readWithin(t, child, newForkTestModule(), 0, 4); rc != _wasiESUCCESS || got != "c" {
		t.Fatalf("the copy's read after its parent is closed = %q rc=%d, want %q", got, rc, "c")
	}
}

// A write that waits for the turn and is unwound (the instance is stopped)
// leaves the turn's queue: the turn given back is free, not handed to it.
func TestEmbedderStdout_AnUnwoundWriteLeavesTheQueue(t *testing.T) {
	w, m := newSignalGuestIn(t, t.TempDir())
	w.cfg.Stdout = &bytes.Buffer{}
	w.mu.Lock()
	turn := w.streamsLocked().stdout
	w.mu.Unlock()
	if !turn.tryTake() {
		t.Fatal("the turn is held")
	}
	unwound := make(chan any, 1)
	go func() {
		defer func() { unwound <- recover() }()
		fdWriteString(w, m, 1, "p")
	}()
	awaitBlockedCalls(w, 1)
	w.sig.mu.Lock()
	w.requestStopLocked(nil, &WasiSignalError{Signal: wasiSIGKILL})
	w.unlockSignals()
	if v := within(t, "the write's unwinding", unwound); v == nil {
		t.Fatal("the write returned instead of being unwound")
	}
	if err := turn.give(); err != nil {
		t.Fatal(err)
	}
	if !turn.tryTake() {
		t.Fatal("the turn is held after it was given back with no write waiting")
	}
	if err := turn.give(); err != nil {
		t.Fatal(err)
	}
}
