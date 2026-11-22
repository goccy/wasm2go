package codegen

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Readiness of streams whose read can block (pipes): poll_oneoff must
// report them readable only when input is there.

const (
	pollSubsOff int32 = 9000
	pollEvOff   int32 = 9500
	pollNevOff  int32 = 9900
)

// waitLimit bounds every wait of the stream and poll tests: a call that has
// not returned by then fails the test instead of hanging it.
const waitLimit = 20 * time.Second

// returnsWithin runs call on a goroutine of its own and fails the test when
// it has not returned within waitLimit.
func returnsWithin(t *testing.T, what string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		call()
	}()
	select {
	case <-done:
	case <-time.After(waitLimit):
		t.Fatalf("%s has not returned after %v", what, waitLimit)
	}
}

// readWithin is fdReadString bounded by waitLimit.
func readWithin(t *testing.T, w *WasiStubs, m *Module, fd, n int32) (got string, rc int32) {
	t.Helper()
	returnsWithin(t, "fd_read", func() { got, rc = fdReadString(w, m, fd, n) })
	return got, rc
}

// writeSoon writes s to fd from another goroutine, with its own module
// memory, once the caller has had time to block.
func writeSoon(t *testing.T, w *WasiStubs, fd int32, s string) {
	go func() {
		time.Sleep(30 * time.Millisecond)
		if rc := fdWriteString(w, newForkTestModule(), fd, s); rc != _wasiESUCCESS {
			t.Errorf("write of %q rc=%d", s, rc)
		}
	}()
}

// pollUserdata runs Poll_oneoff over nsubs subscriptions at pollSubsOff and
// returns the userdata of the events it reported, in order.
func pollUserdata(t *testing.T, w *WasiStubs, m *Module, nsubs int32) []uint64 {
	t.Helper()
	var rc int32
	returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, nsubs, pollNevOff) })
	if rc != _wasiESUCCESS {
		t.Fatalf("Poll_oneoff rc=%d", rc)
	}
	n := int32(binary.LittleEndian.Uint32(m.memory[pollNevOff:]))
	out := make([]uint64, 0, n)
	for i := int32(0); i < n; i++ {
		out = append(out, binary.LittleEndian.Uint64(m.memory[pollEvOff+i*32:]))
	}
	return out
}

func wantUserdata(t *testing.T, got []uint64, want ...uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}

func TestWasi_PollEmptyPipeWaitsForTimeout(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)

	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, readFd)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1) // the timeout, not the pipe
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll on an empty pipe returned after %v, before its timeout", d)
	}

	// The probe left no deadline behind: a later read blocks until the
	// writer delivers, instead of failing or reporting end-of-file.
	writeSoon(t, w, writeFd, "late")
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("read after timed-out poll = %q rc=%d, want %q", got, rc, "late")
	}
}

func TestWasi_PollPipeWithInput(t *testing.T) {
	w, m := newProcTestStubs(t)
	idleRead, _ := newTestPipe(t, w, m)
	busyRead, busyWrite := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, busyWrite, "hello"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}

	// Only the pipe that has input is reported, without waiting out the
	// timeout.
	writeSubClock(m, pollSubsOff, 1, int64(5*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1, idleRead)
	writeSubFd(m, pollSubsOff+96, 3, 1, busyRead)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 3), 3)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("poll with a readable pipe took %v", d)
	}

	// The input is what the next reads return, in order and split as the
	// reader asks; then the pipe is empty again.
	if got, rc := readWithin(t, w, m, busyRead, 2); rc != _wasiESUCCESS || got != "he" {
		t.Fatalf("first read = %q rc=%d", got, rc)
	}
	if got, rc := readWithin(t, w, m, busyRead, 16); rc != _wasiESUCCESS || got != "llo" {
		t.Fatalf("second read = %q rc=%d", got, rc)
	}
	writeSubClock(m, pollSubsOff, 1, int64(20*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 3, 1, busyRead)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
}

// A pipe with no timeout to fall back on blocks the poll until input
// arrives on one of the streams.
func TestWasi_PollBlocksUntilInput(t *testing.T) {
	w, m := newProcTestStubs(t)
	aRead, _ := newTestPipe(t, w, m)
	bRead, bWrite := newTestPipe(t, w, m)
	writeSoon(t, w, bWrite, "x")
	writeSubFd(m, pollSubsOff, 10, 1, aRead)
	writeSubFd(m, pollSubsOff+48, 11, 1, bRead)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 11)
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Fatalf("poll returned after %v, before any input existed", d)
	}
	if got, rc := readWithin(t, w, m, bRead, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

// End of input makes a pipe readable: the read that follows returns zero
// bytes.
func TestWasi_PollPipeAtEndOfInput(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "tail"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	writeSubFd(m, pollSubsOff, 7, 1, readFd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "tail" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at end of input = %q rc=%d, want zero bytes", got, rc)
	}
}

// A regular file next to an idle pipe: the file is ready at once and the
// pipe is not reported.
func TestWasi_PollRegularFileBesideIdlePipe(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fileFd, errno := w.pathOpen(m, "f.txt", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	pipeRead, pipeWrite := newTestPipe(t, w, m)

	writeSubFd(m, pollSubsOff, 20, 1, pipeRead)
	writeSubFd(m, pollSubsOff+48, 21, 1, fileFd)
	writeSubFd(m, pollSubsOff+96, 22, 2 /* fd_write */, pipeWrite)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 3), 21, 22)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("poll with ready descriptors took %v", d)
	}
}

// endThenInput is a stream the host cannot poll whose end of input is not
// its end, as a terminal's after its end-of-file character: its reads return
// steps in turn, "" as the end of input, and wait out their deadline once
// there are no more.
type endThenInput struct {
	mu    sync.Mutex
	steps []string
}

func (r *endThenInput) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.steps) == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	if step == "" {
		return 0, io.EOF
	}
	return copy(p, step), nil
}

func (r *endThenInput) SetReadDeadline(time.Time) error { return nil }

// The end of input a poll ran into is one read's: the read after it goes to
// the stream again.
func TestWasi_EndOfInputAPollFoundIsReadOnce(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = &endThenInput{steps: []string{"", "more", "late"}}
	writeSubFd(m, pollSubsOff, 7, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at the end of input = %q rc=%d, want zero bytes", got, rc)
	}
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "more" {
		t.Fatalf("read after the end of input = %q rc=%d, want %q", got, rc, "more")
	}
	// A non-blocking read of such a stream takes what a probe finds.
	if rc := w.Fd_fdstat_set_flags(m, 0, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("non-blocking read = %q rc=%d, want %q", got, rc, "late")
	}
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking read of nothing = %q rc=%d, want EAGAIN", got, rc)
	}
}
