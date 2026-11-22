//go:build linux

package codegen

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	fifoRightsRead  = 1 << 1
	fifoRightsWrite = 1 << 6
	fifoFdOut       = 200
)

// newTestFIFO makes the FIFO "queue" in dir and returns its host path.
func newTestFIFO(t *testing.T, dir string) string {
	t.Helper()
	fifo := filepath.Join(dir, "queue")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	return fifo
}

// openOutside opens fifo outside the instance with flag, until the test
// ends.
func openOutside(t *testing.T, fifo string, flag int) *os.File {
	t.Helper()
	f, err := os.OpenFile(fifo, flag, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, f)
	return f
}

// fifoHadWriter reports whether r, a read end of a FIFO opened without
// waiting, has had a writer since it was opened.
func fifoHadWriter(t *testing.T, r *os.File) bool {
	t.Helper()
	fw, err := newFIFOWatch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fw.Close(); err != nil {
			t.Error(err)
		}
	}()
	found, err := fw.hasWriter(r)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// A read end of a FIFO opened without waiting has had a writer once one
// opened the FIFO after it, also when that one has gone again, and when
// one was there at its open and has gone; not before.
func TestFIFOHasWriter(t *testing.T) {
	fifo := newTestFIFO(t, t.TempDir())
	reader := openOutside(t, fifo, os.O_RDONLY|syscall.O_NONBLOCK)
	if fifoHadWriter(t, reader) {
		t.Fatal("a writer before any opened the FIFO")
	}
	writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !fifoHadWriter(t, reader) {
		t.Fatal("no writer while one has the FIFO open")
	}
	// A reader opened while the writer is there.
	second := openOutside(t, fifo, os.O_RDONLY|syscall.O_NONBLOCK)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*os.File{reader, second} {
		if !fifoHadWriter(t, r) {
			t.Fatalf("%s: no writer after one came and went", r.Name())
		}
	}
}

// guestFIFOOpen is the guest's open of "queue" with rights, bounded by
// waitLimit.
func guestFIFOOpen(t *testing.T, w *WasiStubs, m *Module, rights int64) (rc int32) {
	t.Helper()
	path, pathLen := putPath(m, 1000, "queue")
	returnsWithin(t, "path_open", func() { rc = w.Path_open(m, 3, 1, path, pathLen, 0, rights, 0, 0, fifoFdOut) })
	return rc
}

// An open for reading that a signal interrupts opens no other end of the
// FIFO: a reader outside sees no writer come and go.
func TestFIFOOpenForReadingInterruptedOpensNoWriter(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	outside := openOutside(t, newTestFIFO(t, dir), os.O_RDONLY|syscall.O_NONBLOCK)
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := guestFIFOOpen(t, w, m, fifoRightsRead); rc != _wasiEINTR {
		t.Fatalf("open for reading rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	if fifoHadWriter(t, outside) {
		t.Fatal("a writer came to the FIFO while the open for reading was interrupted")
	}
}

// The open for reading is done when a writer opens the FIFO, before it
// writes anything.
func TestFIFOOpenForReadingDoneByAWritersOpen(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	fifo := newTestFIFO(t, dir)
	writers := make(chan *os.File, 1)
	whenBlocked(w, func() {
		// The guest's open makes it a reader: this open does not wait.
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
		}
		writers <- f
	})
	if rc := guestFIFOOpen(t, w, m, fifoRightsRead); rc != _wasiESUCCESS {
		t.Fatalf("open for reading rc=%d", rc)
	}
	writer := <-writers
	if writer == nil {
		t.FailNow()
	}
	closeAtEnd(t, writer)
	if _, err := writer.WriteString("y"); err != nil {
		t.Fatal(err)
	}
	if got, rc := readWithin(t, w, m, int32(readU32(m.memory, fifoFdOut)), 4); rc != _wasiESUCCESS || got != "y" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

// A writer that opens the FIFO and closes it again while the open for
// reading waits has done the open, as for open(2): the read then finds
// the end of input.
func TestFIFOOpenForReadingDoneByAWriterGone(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	fifo := newTestFIFO(t, dir)
	whenBlocked(w, func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	if rc := guestFIFOOpen(t, w, m, fifoRightsRead); rc != _wasiESUCCESS {
		t.Fatalf("open for reading rc=%d", rc)
	}
	if got, rc := readWithin(t, w, m, int32(readU32(m.memory, fifoFdOut)), 4); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read = %q rc=%d, want the end of input", got, rc)
	}
}

// A FIFO with a writer is opened for reading without waiting, its input
// left to the read.
func TestFIFOOpenForReadingWithAWriter(t *testing.T) {
	for _, input := range []string{"", "z"} {
		dir := t.TempDir()
		w, m := newSignalGuestIn(t, dir)
		fifo := newTestFIFO(t, dir)
		openOutside(t, fifo, os.O_RDONLY|syscall.O_NONBLOCK)
		writer := openOutside(t, fifo, os.O_WRONLY|syscall.O_NONBLOCK)
		if input != "" {
			if _, err := writer.WriteString(input); err != nil {
				t.Fatal(err)
			}
		}
		if rc := guestFIFOOpen(t, w, m, fifoRightsRead); rc != _wasiESUCCESS {
			t.Fatalf("input %q: open for reading rc=%d", input, rc)
		}
		if input == "" {
			continue
		}
		if got, rc := readWithin(t, w, m, int32(readU32(m.memory, fifoFdOut)), 4); rc != _wasiESUCCESS || got != input {
			t.Fatalf("read = %q rc=%d, want %q", got, rc, input)
		}
	}
}

// A writer that comes with a signal does the open, whichever ends the wait
// first; the signal is reported by the next call that waits.
func TestFIFOOpenForReadingDoneWithASignal(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	fifo := newTestFIFO(t, dir)
	writers := make(chan *os.File, 1)
	whenBlocked(w, func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
		}
		writers <- f
		w.PostSignal(wasiSIGUSR1)
	})
	if rc := guestFIFOOpen(t, w, m, fifoRightsRead); rc != _wasiESUCCESS {
		t.Fatalf("open for reading rc=%d", rc)
	}
	writer := <-writers
	if writer == nil {
		t.FailNow()
	}
	closeAtEnd(t, writer)
	// The FIFO is empty and has a writer: the read waits.
	if _, rc := readWithin(t, w, m, int32(readU32(m.memory, fifoFdOut)), 4); rc != _wasiEINTR {
		t.Fatalf("the next read that waits rc=%d, want EINTR", rc)
	}
}

// What open(2) opens when the name was given to another file after it was
// looked up is that file, at once.
func TestFIFOOpenForReadingOfAnotherFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("p"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, _ := newSignalGuestIn(t, dir)
	f, errno, watched := w.openFIFOWatched(w.fs().OpenFile, "plain", os.O_RDONLY, 0)
	if !watched || errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d watched=%v", errno, watched)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// An open of a FIFO for reading is the open the guest asked for: one that
// creates the file exclusively finds the FIFO there (EEXIST) without
// waiting.
func TestFIFOOpenForReadingWithTheGuestsFlags(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	newTestFIFO(t, dir)
	path, pathLen := putPath(m, 1000, "queue")
	const creat, excl = 0x1, 0x4
	var rc int32
	returnsWithin(t, "path_open", func() { rc = w.Path_open(m, 3, 1, path, pathLen, creat|excl, fifoRightsRead, 0, 0, fifoFdOut) })
	if rc != _wasiEEXIST {
		t.Fatalf("exclusive creation of the FIFO there rc=%d, want EEXIST", rc)
	}
}

// A guest that ends while an open of a FIFO waits leaves no end of the
// FIFO open behind: for writing, the open is made to return; for reading,
// the end is closed.
func TestFIFOOpenOfAnEndingGuest(t *testing.T) {
	for _, rights := range []int64{fifoRightsWrite, fifoRightsRead} {
		dir := t.TempDir()
		w, m := newTestStubs(t, dir)
		fifo := newTestFIFO(t, dir)
		path, pathLen := putPath(m, 1000, "queue")
		before := openFDs(t)
		postWhenBlocked(w, wasiSIGTERM)
		var sigErr *WasiSignalError
		returnsWithin(t, "path_open", func() {
			sigErr = signalErrorOf(func() { w.Path_open(m, 3, 1, path, pathLen, 0, rights, 0, 0, fifoFdOut) })
		})
		if sigErr == nil || sigErr.Signal != wasiSIGTERM {
			t.Fatalf("rights %#x: the open ended with %v, want a WasiSignalError for SIGTERM", rights, sigErr)
		}
		if rights == fifoRightsWrite {
			if fifoHadWriter(t, openOutside(t, fifo, os.O_RDONLY|syscall.O_NONBLOCK)) {
				t.Fatal("the open for writing of the ended guest still waits as a writer")
			}
			continue
		}
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			t.Fatalf("the open for reading of the ended guest left a reader (close: %v)", f.Close())
		} else if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("open for writing after the ended open for reading: %v, want ENXIO", err)
		}
		// The call's wake pipe went back to the pool; nothing else is open.
		if n := openFDs(t); n != before+2 {
			t.Fatalf("%d descriptors are open, %d before the open", n, before)
		}
	}
}
