package codegen

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Input a readiness probe keeps on the entry of a standard stream belongs to
// the stream it was read from.

// endOnceReader is a stream that reports end of input once and then has more,
// as a terminal does after an end-of-file key.
type endOnceReader struct {
	mu    sync.Mutex
	ended bool
}

func (r *endOnceReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ended {
		r.ended = true
		return 0, io.EOF
	}
	return copy(p, "more"), nil
}

func (r *endOnceReader) SetReadDeadline(time.Time) error { return nil }

// pollStdin polls fd 0 for reading with no timeout and fails unless it is
// reported readable.
func pollStdin(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	writeSubFd(m, pollSubsOff, 9, 1 /* fd_read */, 0)
	wantUserdata(t, pollUserdata(t, w, m, 1), 9)
}

// The end of input a probe ran into is reported once, by the read that comes
// next, as the stream itself would have: the read after that goes to the
// stream again. Before, every later read reported end of input.
func TestWasi_ProbedEndOfInputIsReportedOnce(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetStdin(&endOnceReader{})
	pollStdin(t, w, m)
	if s, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || s != "" {
		t.Fatalf("first read = %q rc=%d, want end of input", s, rc)
	}
	if s, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || s != "more" {
		t.Fatalf("second read = %q rc=%d, want %q", s, rc, "more")
	}
}

// SetStdin gives fd 0 the new stream with nothing a probe of the old one
// kept: before, the end of input probed on the old stdin was reported for
// the new one.
func TestWasi_SetStdinDropsWhatAProbeOfTheOldStreamKept(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	wr.Close()
	w.SetStdin(r)
	pollStdin(t, w, m) // the probe meets the end of the pipe
	w.SetStdin(strings.NewReader("new"))
	if s, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || s != "new" {
		t.Fatalf("read after SetStdin = %q rc=%d, want %q", s, rc, "new")
	}
}

// After Fork, a forked instance given a stdin of its own reads that, not the
// input its parent's probe kept on the fd 0 entry the two shared; the parent
// still gets what its probe kept. Before, the child got the parent's input.
func TestWasi_ForkedSetStdinDoesNotReadTheParentsProbedInput(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer wr.Close()
	w.SetStdin(r)
	if _, err := wr.WriteString("parent"); err != nil {
		t.Fatal(err)
	}
	pollStdin(t, w, m) // the probe keeps "parent" on the fd 0 entry
	child := w.Fork()
	defer child.CloseAll()
	child.SetStdin(strings.NewReader("child"))
	cm := newForkTestModule()
	if s, rc := fdReadString(child, cm, 0, 16); rc != _wasiESUCCESS || s != "child" {
		t.Fatalf("the child read %q rc=%d, want %q", s, rc, "child")
	}
	if s, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || s != "parent" {
		t.Fatalf("the parent read %q rc=%d, want %q", s, rc, "parent")
	}
}
