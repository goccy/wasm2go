//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A guest that is the host process has the host process's descriptors as
// its own: the number the guest knows a descriptor by is the number the
// host knows it by, and what the kernel keeps for it is the guest's state.

// newHostGuest returns host state whose descriptors are the host process's,
// with dir as the root of its filesystem and streams of its own. The
// identity is set without SetHostProcess, which would also take over the
// test process's signals.
func newHostGuest(t *testing.T, dir string) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	// As SetHostProcess does: what the test process has open for itself is
	// not the guest's.
	KeepRuntimeDescriptorsHigh()
	w.hostProcess = true
	t.Cleanup(func() { _ = w.CloseAll() })
	return w, m
}

// guestIsHost returns the descriptor of the host the guest's fd is, which
// must be fd itself.
func guestIsHost(t *testing.T, w *WasiStubs, fd int32) int {
	t.Helper()
	host, ok := w.HostDescriptor(fd)
	if !ok {
		t.Fatalf("descriptor %d has no descriptor of the host", fd)
	}
	if int32(host) != fd {
		t.Fatalf("descriptor %d of the guest is descriptor %d of the host", fd, host)
	}
	return int(host)
}

// sameFile reports whether a descriptor of the host is the file at path.
func sameFile(t *testing.T, fd int, path string) bool {
	t.Helper()
	var a, b syscall.Stat_t
	if err := syscall.Fstat(fd, &a); err != nil {
		t.Fatalf("fstat(%d): %v", fd, err)
	}
	if err := syscall.Stat(path, &b); err != nil {
		t.Fatalf("stat(%s): %v", path, err)
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

func hostStatusFlags(t *testing.T, fd int) int {
	t.Helper()
	flags, err := descriptorFlags(fd, syscall.F_GETFL)
	if err != nil {
		t.Fatalf("F_GETFL(%d): %v", fd, err)
	}
	return flags
}

func TestHostDescriptors_AnOpenedFileHasTheHostsNumber(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	fd := createTestFile(t, w, "a.txt")
	host := guestIsHost(t, w, fd)
	if !sameFile(t, host, filepath.Join(dir, "a.txt")) {
		t.Fatalf("descriptor %d of the host is not the file the guest opened", host)
	}
	// What the guest writes is written through that descriptor, and what
	// code outside the guest writes to the number lands in the same file.
	if rc := fdWriteString(w, m, fd, "guest,"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if _, err := syscall.Write(host, []byte("native")); err != nil {
		t.Fatalf("write(%d): %v", host, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil || string(got) != "guest,native" {
		t.Fatalf("file holds %q (%v), want %q", got, err, "guest,native")
	}
	closeTestFd(t, w, m, fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(host, &st); err != syscall.EBADF {
		t.Fatalf("after the guest closed it, fstat(%d) = %v, want EBADF", host, err)
	}
}

func TestHostDescriptors_NewDescriptorsTakeTheHostsLowestFreeNumber(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	a := createTestFile(t, w, "a")
	b := createTestFile(t, w, "b")
	c := createTestFile(t, w, "c")
	guestIsHost(t, w, a)
	guestIsHost(t, w, b)
	guestIsHost(t, w, c)
	// The host gives the lowest free number: the one just closed.
	closeTestFd(t, w, m, b)
	if again := createTestFile(t, w, "d"); again != b {
		t.Fatalf("the descriptor opened after closing %d is %d", b, again)
	}
}

func TestHostDescriptors_TheRootDirectoryHasNoNumber(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	// Whatever the host has under 3 in this test process, the guest has
	// nothing there until it opens something.
	if rc := w.Fd_fdstat_get(m, wasiPreopenFD, 5200); rc != _wasiEBADF {
		t.Fatalf("Fd_fdstat_get(3) rc=%d, want EBADF", rc)
	}
	if rc := w.Fd_filestat_get(m, wasiPreopenFD, 5200); rc != _wasiEBADF {
		t.Fatalf("Fd_filestat_get(3) rc=%d, want EBADF", rc)
	}
	// A libc still finds the root there, and can name it by a number that
	// is no descriptor's: the path calls take it, and it is a directory to
	// whoever asks.
	if rc := w.Fd_prestat_get(m, wasiPreopenFD, 5200); rc != _wasiESUCCESS {
		t.Fatalf("Fd_prestat_get(3) rc=%d", rc)
	}
	if got := fdFiletype(t, w, m, wasiRootFD); got != 3 {
		t.Fatalf("the root's number has file type %d, want 3 (directory)", got)
	}
	copy(m.memory[6000:], "made")
	if rc := w.Path_create_directory(m, wasiRootFD, 6000, 4); rc != _wasiESUCCESS {
		t.Fatalf("Path_create_directory under the root's number rc=%d", rc)
	}
	if rc := w.Path_open(m, wasiRootFD, 0, 6000, 4, 0x2, 1<<1, 0, 0, 6100); rc != _wasiESUCCESS {
		t.Fatalf("Path_open under the root's number rc=%d", rc)
	}
	// The first descriptors the guest opens are the lowest the host has
	// free, 3 among them when the host has it free.
	fd := int32(readU32(m.memory, 6100))
	if host := guestIsHost(t, w, fd); host < 3 {
		t.Fatalf("a directory was opened as descriptor %d", host)
	}
}

func TestHostDescriptors_BlockingModeIsTheOpenFiles(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, writeFd := newTestPipe(t, w, m)
	r, wr := guestIsHost(t, w, readFd), guestIsHost(t, w, writeFd)
	for _, fd := range []int{r, wr} {
		if hostStatusFlags(t, fd)&syscall.O_NONBLOCK != 0 {
			t.Fatalf("descriptor %d of a new pipe is in non-blocking mode", fd)
		}
	}
	// The guest sets O_NONBLOCK: it is the mode of the host's open file.
	if rc := w.Fd_fdstat_set_flags(m, readFd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	if hostStatusFlags(t, r)&syscall.O_NONBLOCK == 0 {
		t.Fatalf("O_NONBLOCK the guest set is not set on the host's descriptor")
	}
	if _, rc := fdReadString(w, m, readFd, 8); rc != _wasiEAGAIN {
		t.Fatalf("read of an empty non-blocking pipe rc=%d, want EAGAIN", rc)
	}
	// Code outside the guest clears it: the guest sees that.
	if err := syscall.SetNonblock(r, false); err != nil {
		t.Fatal(err)
	}
	if rc := w.Fd_fdstat_get(m, readFd, 5200); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_get rc=%d", rc)
	}
	if flags := readU32(m.memory, 5200) >> 16; int32(flags)&wasiFdflagNonblock != 0 {
		t.Fatalf("fdflags = %#x after the mode was cleared on the host", flags)
	}
}

func TestHostDescriptors_PollTakesNothingOffTheDescriptor(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "hello"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	writeSubClock(m, pollSubsOff, 1, int64(5*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, readFd)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	// Whoever reads the number next gets every byte: here code outside the
	// guest.
	buf := make([]byte, 16)
	n, err := syscall.Read(guestIsHost(t, w, readFd), buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("read after poll = %q, %v; want %q", buf[:n], err, "hello")
	}
}

func TestHostDescriptors_PollWaitsForItsTimeout(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, _ := newTestPipe(t, w, m)
	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, readFd)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll on an empty pipe returned after %v, before its timeout", d)
	}
}

func TestHostDescriptors_WriteEndIsWritableAndNeverReadable(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, writeFd := newTestPipe(t, w, m)
	writeSubClock(m, pollSubsOff, 1, int64(30*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, writeFd)
	writeSubFd(m, pollSubsOff+96, 3, 2 /* fd_write */, readFd)
	writeSubFd(m, pollSubsOff+144, 4, 2 /* fd_write */, writeFd)
	wantUserdata(t, pollUserdata(t, w, m, 4), 4)
}

func TestHostDescriptors_BlockingReadWaitsAndASignalEndsIt(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
	readFd, writeFd := newTestPipe(t, w, m)

	// Input that arrives ends the wait.
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = syscall.Write(int(writeFd), []byte("late"))
	}()
	start := time.Now()
	got, rc := fdReadString(w, m, readFd, 16)
	if rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("blocking read = %q rc=%d", got, rc)
	}
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Fatalf("the read returned after %v, before the input was written", d)
	}

	// A signal ends it with EINTR, and leaves the descriptor as it was.
	postSoon(w, wasiSIGUSR1)
	if _, rc := fdReadString(w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("interrupted read rc=%d, want EINTR", rc)
	}
	if hostStatusFlags(t, int(readFd))&syscall.O_NONBLOCK != 0 {
		t.Fatalf("waiting left the descriptor in non-blocking mode")
	}
	takeSignals(t, w, m)

	// The end of input is a read of nothing.
	closeTestFd(t, w, m, writeFd)
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at the end of input = %q rc=%d", got, rc)
	}
}

func TestHostDescriptors_BlockingWriteOfMoreThanThePipeHolds(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	big := &Module{memory: make([]byte, 1<<21)}
	readFd, writeFd := newTestPipe(t, w, m)
	const size = 1 << 20
	for i := 0; i < size; i++ {
		big.memory[4096+i] = byte(i)
	}
	makeIovec(big, 64, 4096, size)
	read := make(chan int, 1)
	go func() {
		total := 0
		buf := make([]byte, 64<<10)
		for total < size {
			n, err := syscall.Read(int(readFd), buf)
			if err != nil || n == 0 {
				break
			}
			for i := 0; i < n; i++ {
				if buf[i] != byte(total+i) {
					read <- -1
					return
				}
			}
			total += n
		}
		read <- total
	}()
	if rc := w.Fd_write(big, writeFd, 64, 1, 128); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if n := readU32(big.memory, 128); n != size {
		t.Fatalf("a blocking write wrote %d of %d bytes", n, size)
	}
	if got := <-read; got != size {
		t.Fatalf("the reader got %d bytes, want %d", got, size)
	}
}

func TestHostDescriptors_DupIsADescriptorOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	fd := createTestFile(t, w, "a.txt")
	dup := dupTestFd(t, w, m, fd)
	if dup == fd {
		t.Fatalf("dup returned the descriptor itself")
	}
	if !sameFile(t, guestIsHost(t, w, dup), filepath.Join(dir, "a.txt")) {
		t.Fatalf("the duplicate is not the same file")
	}
	// They share the open file: the offset moves for both.
	if rc := fdWriteString(w, m, fd, "abc"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if off, err := syscall.Seek(int(dup), 0, 1); err != nil || off != 3 {
		t.Fatalf("offset of the duplicate = %d, %v; want 3", off, err)
	}
	closeTestFd(t, w, m, fd)
	if rc := fdWriteString(w, m, dup, "def"); rc != _wasiESUCCESS {
		t.Fatalf("write to the duplicate after the original was closed rc=%d", rc)
	}
}

func TestHostDescriptors_Dup2PutsTheFileUnderTheHostsNumber(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	a := createTestFile(t, w, "a.txt")
	b := createTestFile(t, w, "b.txt")
	if rc := w.Fd_dup2(m, a, b); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	if !sameFile(t, guestIsHost(t, w, b), filepath.Join(dir, "a.txt")) {
		t.Fatalf("after dup2, descriptor %d of the host is not the source file", b)
	}
	// Onto a number that is not open.
	free := dupTestFd(t, w, m, a)
	closeTestFd(t, w, m, free)
	if rc := w.Fd_dup2(m, a, free); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 onto a free number rc=%d", rc)
	}
	if !sameFile(t, guestIsHost(t, w, free), filepath.Join(dir, "a.txt")) {
		t.Fatalf("after dup2, descriptor %d of the host is not the source file", free)
	}
}

func TestHostDescriptors_ForkedProcessesShareNumbersUntilTheyDiverge(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	shared := createTestFile(t, w, "shared.txt")
	child := w.Fork()
	defer child.CloseAll()
	cm := newForkTestModule()

	// Both write through the same descriptor of the host.
	if rc := fdWriteString(w, m, shared, "parent,"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if rc := fdWriteString(child, cm, shared, "child"); rc != _wasiESUCCESS {
		t.Fatalf("child write rc=%d", rc)
	}
	guestIsHost(t, child, shared)

	// The child puts another file under the number. The parent's stays
	// what it was, under the host's number; the child's own file has no
	// number outside the child.
	other := createTestFile(t, child, "other.txt")
	if rc := child.Fd_dup2(cm, other, shared); rc != _wasiESUCCESS {
		t.Fatalf("child Fd_dup2 rc=%d", rc)
	}
	if _, ok := child.HostDescriptor(shared); ok {
		t.Fatalf("the child's own file has a number of the host's under the parent's")
	}
	if rc := fdWriteString(child, cm, shared, "elsewhere"); rc != _wasiESUCCESS {
		t.Fatalf("child write after dup2 rc=%d", rc)
	}
	if rc := fdWriteString(w, m, shared, ",parent"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "shared.txt")); string(got) != "parent,child,parent" {
		t.Fatalf("the parent's file holds %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "other.txt")); string(got) != "elsewhere" {
		t.Fatalf("the child's file holds %q", got)
	}

}

// A new descriptor above the standard ones is a descriptor of the host
// under its number, whatever the other processes of the family hold: the
// number is what a program hands to a native library. A parent that closed
// a descriptor its fork child still has does not get that number for its
// next one — under it the host has the child's file.
func TestHostDescriptors_ANewDescriptorIsTheHostsWhileAnotherProcessHoldsALowerNumber(t *testing.T) {
	const out int32 = 5300
	for _, tc := range []struct {
		name string
		// make returns the descriptors a call makes.
		make func(t *testing.T, w *WasiStubs, m *Module) []int32
	}{
		{"open", func(t *testing.T, w *WasiStubs, m *Module) []int32 {
			return []int32{createTestFile(t, w, "next.txt")}
		}},
		{"dup", func(t *testing.T, w *WasiStubs, m *Module) []int32 {
			if rc := w.Fd_dup(m, 0, out); rc != _wasiESUCCESS {
				t.Fatalf("Fd_dup rc=%d", rc)
			}
			return []int32{int32(binary.LittleEndian.Uint32(m.memory[out:]))}
		}},
		{"pipe", func(t *testing.T, w *WasiStubs, m *Module) []int32 {
			if rc := w.Pipe(m, out); rc != 0 {
				t.Fatalf("Pipe rc=%d", rc)
			}
			return []int32{int32(binary.LittleEndian.Uint32(m.memory[out:])), int32(binary.LittleEndian.Uint32(m.memory[out+4:]))}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			w, m := newHostGuest(t, dir)
			// Standard input that is a descriptor of the host, for dup.
			source := createTestFile(t, w, "source.txt")
			if rc := w.Fd_dup2(m, source, 0); rc != _wasiESUCCESS {
				t.Fatalf("Fd_dup2 onto 0 rc=%d", rc)
			}
			closeTestFd(t, w, m, source)
			kept := createTestFile(t, w, "kept.txt")
			above := createTestFile(t, w, "above.txt")
			child := w.Fork()
			defer child.CloseAll()
			cm := newForkTestModule()

			// The parent closes a descriptor the child still has.
			closeTestFd(t, w, m, kept)
			made := tc.make(t, w, m)
			for _, fd := range made {
				if fd == kept {
					t.Fatalf("after closing %d the parent's new descriptors are %v: under %d the host has the child's file", kept, made, kept)
				}
				guestIsHost(t, w, fd)
			}
			// The child's descriptor is what it was, and is the host's
			// under the number.
			if rc := fdWriteString(child, cm, kept, "still open"); rc != _wasiESUCCESS {
				t.Fatalf("child's write through the descriptor the parent closed rc=%d", rc)
			}
			if got, _ := os.ReadFile(filepath.Join(dir, "kept.txt")); string(got) != "still open" {
				t.Fatalf("the child's file holds %q", got)
			}
			if !sameFile(t, guestIsHost(t, child, kept), filepath.Join(dir, "kept.txt")) {
				t.Fatalf("descriptor %d of the host is no longer the child's file", kept)
			}
			guestIsHost(t, w, above)

			// Once every process has closed the descriptor, the number is
			// free in the process, and the next descriptor is the host's
			// under its number.
			closeTestFd(t, child, cm, kept)
			if again := createTestFile(t, child, "again.txt"); again != kept {
				t.Fatalf("the child's next descriptor is %d, want %d", again, kept)
			} else {
				guestIsHost(t, child, again)
			}
		})
	}
}

// A descriptor another process of the family closes is never taken in by
// the guest as one that code outside it made, whenever the guest asks
// about the number (a program that maps its open descriptors dups each
// number in turn): until the host has closed the descriptor, the number is
// the other process's; after, nothing is open under it.
func TestHostDescriptors_ADescriptorAnotherProcessClosesIsNeverTakenIn(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	const out int32 = 5300
	names := []string{"a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "f.txt", "g.txt", "h.txt"}
	for round := 0; round < 300; round++ {
		child := w.Fork()
		var made []int32
		for _, name := range names {
			made = append(made, createTestFile(t, child, name))
		}
		closed := make(chan struct{})
		go func() {
			_ = child.CloseAll()
			close(closed)
		}()
		for open := true; open; {
			select {
			case <-closed:
				open = false
			default:
			}
			for _, fd := range made {
				if rc := w.Fd_dup(m, fd, out); rc == _wasiESUCCESS {
					t.Fatalf("round %d: descriptor %d of the forked process, which it was closing, became its parent's", round, fd)
				}
			}
		}
	}
}

// What the Go runtime keeps in the process for a command the guest started
// — the handle of the process (a pidfd, where the kernel has them) — has a
// low number, and is the runtime's: a guest that maps its open descriptors
// by dup'ing each number does not get it while the command runs.
func TestHostDescriptors_WhatTheRuntimeKeepsForACommandIsNotTakenIn(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	const out int32 = 5300
	// The numbers a dup of which works: what the guest has, and what is
	// taken in as made outside it (the test process's own).
	openNumbers := func() []int32 {
		var got []int32
		for fd := int32(3); fd < 64; fd++ {
			if rc := w.Fd_dup(m, fd, out); rc == _wasiESUCCESS {
				got = append(got, fd)
				closeTestFd(t, w, m, int32(binary.LittleEndian.Uint32(m.memory[out:])))
			}
		}
		return got
	}
	before := openNumbers()
	pid := spawnTestProc(t, w, m, "/bin/sleep", "2")
	during := openNumbers()
	if len(during) != len(before) {
		t.Errorf("while the command runs the guest has %v, before it had %v", during, before)
	}
	const statusOff int32 = 4100
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
}

// What a forked process does to a standard descriptor is its own: it closes
// standard output and opens a file, which is its descriptor 1, and the
// parent's standard output is untouched.
func TestHostDescriptors_AForkedProcessReopensStandardOutput(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	// A standard output that is a descriptor of the host, as a program run
	// as the process has: a file in place of the stream of the embedder's.
	first := createTestFile(t, w, "stdout.txt")
	if rc := w.Fd_dup2(m, first, 1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 onto 1 rc=%d", rc)
	}
	closeTestFd(t, w, m, first)
	child := w.Fork()
	defer child.CloseAll()
	cm := newForkTestModule()

	closeTestFd(t, child, cm, 1)
	if fd := createTestFile(t, child, "child.txt"); fd != 1 {
		t.Fatalf("the child's file after closing standard output is descriptor %d, want 1", fd)
	}
	if rc := fdWriteString(child, cm, 1, "child"); rc != _wasiESUCCESS {
		t.Fatalf("child write rc=%d", rc)
	}
	if rc := fdWriteString(w, m, 1, "parent"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "stdout.txt")); string(got) != "parent" {
		t.Fatalf("the parent's standard output holds %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "child.txt")); string(got) != "child" {
		t.Fatalf("the child's file holds %q", got)
	}
}

func TestHostDescriptors_AnEndedInstanceClosesItsDescriptors(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	fd := createTestFile(t, w, "a.txt")
	readFd, writeFd := newTestPipe(t, w, m)
	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	for _, n := range []int32{fd, readFd, writeFd} {
		var st syscall.Stat_t
		if err := syscall.Fstat(int(n), &st); err != syscall.EBADF {
			t.Errorf("descriptor %d is still open after the instance ended (%v)", n, err)
		}
	}
}

func TestHostDescriptors_ACommandGetsTheGuestsTable(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "in.txt"), []byte("from five"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, errno := w.pathOpen("in.txt", 0, 0, 1<<1 /* FD_READ */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	out := createTestFile(t, w, "out.txt")
	hidden := createTestFile(t, w, "hidden.txt")
	// The command reads descriptor `in` and writes descriptor `out`, under
	// the guest's numbers; `hidden` is close-on-exec.
	if rc := w.Fd_cloexec(m, hidden, 1, 1, 5300); rc != _wasiESUCCESS {
		t.Fatalf("Fd_cloexec rc=%d", rc)
	}
	// The descriptors are named by their files in /dev/fd: not every shell
	// takes a number of two digits in a redirection.
	script := "cat /dev/fd/" + itoa32(in) + " > /dev/fd/" + itoa32(out) + "; if test -e /dev/fd/" + itoa32(hidden) + "; then echo leaked > /dev/fd/" + itoa32(out) + "; fi"
	pid := spawnTestProc(t, w, m, "/bin/sh", "-c", script)
	const statusOff int32 = 5400
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 0 {
		t.Fatalf("the command ended with status %#x", status)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "out.txt")); string(got) != "from five" {
		t.Fatalf("the command wrote %q", got)
	}
}

func TestHostDescriptors_ADirectoryIsReadThroughItsDescriptor(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, _ := newHostGuest(t, dir)
	fd, errno := w.pathOpen("", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	guestIsHost(t, w, fd)
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	entries, err := op.readDirCached(true)
	if err != nil {
		t.Fatalf("readDirCached: %v", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	want := []string{"./", "../", "one", "sub/", "two"}
	if len(names) != len(want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("entries = %v, want %v", names, want)
		}
	}
}

func TestHostDescriptors_RuntimeDescriptorsAreNotTheGuests(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	readFd, _ := newTestPipe(t, w, m)
	// A wait makes the pipe signals wake it through.
	writeSubClock(m, pollSubsOff, 1, int64(time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1, readFd)
	pollUserdata(t, w, m, 2)
	w.mu.Lock()
	waker := w.waker
	w.mu.Unlock()
	if waker == nil {
		t.Fatalf("waiting made no waker")
	}
	for _, fd := range []int{waker.r, waker.w} {
		if fd < hostFloor() {
			t.Errorf("descriptor %d of the runtime is below %d", fd, hostFloor())
		}
		w.mu.Lock()
		free := w.hostNumberFreeLocked(fd)
		w.mu.Unlock()
		if free {
			t.Errorf("descriptor %d of the runtime counts as free for a guest", fd)
		}
	}
}

// descriptorIdentity returns what tells one open file of the host from
// another well enough for a test: its device and inode.
func descriptorIdentity(t *testing.T, fd int) [2]uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat(%d): %v", fd, err)
	}
	return [2]uint64{uint64(st.Dev), uint64(st.Ino)}
}

func TestHostDescriptors_StandardDescriptorsAreTheProcesssAndAreGivenBack(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	// The instance's standard output is the process's own.
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), os.Stdout, &bytes.Buffer{}
	KeepRuntimeDescriptorsHigh()
	w.hostProcess = true
	before := descriptorIdentity(t, 1)

	if host, ok := w.HostDescriptor(1); !ok || host != 1 {
		t.Fatalf("standard output is descriptor %d of the host (%v), want 1", host, ok)
	}
	// The guest redirects it: descriptor 1 of the process is the file.
	file := createTestFile(t, w, "out.txt")
	if rc := w.Fd_dup2(m, file, 1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	if !sameFile(t, 1, filepath.Join(dir, "out.txt")) {
		t.Fatalf("after dup2 onto 1, descriptor 1 of the process is not the file")
	}
	if _, err := syscall.Write(1, []byte("written outside the guest\n")); err != nil {
		t.Fatalf("write(1): %v", err)
	}
	if flags, err := descriptorFlags(1, syscall.F_GETFD); err != nil || flags&syscall.FD_CLOEXEC != 0 {
		t.Fatalf("descriptor 1 is close-on-exec after dup2 (%#x, %v)", flags, err)
	}
	// It closes it: the process's descriptor is closed.
	closeTestFd(t, w, m, 1)
	var st syscall.Stat_t
	if err := syscall.Fstat(1, &st); err != syscall.EBADF {
		t.Fatalf("after the guest closed 1, fstat(1) = %v, want EBADF", err)
	}
	// When the instance ends, the process has its standard output back.
	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if after := descriptorIdentity(t, 1); after != before {
		t.Fatalf("descriptor 1 of the process is %v after the instance ended, was %v", after, before)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "out.txt")); string(got) != "written outside the guest\n" {
		t.Fatalf("the file holds %q", got)
	}
}

// A forked process that ends while its family runs on closes what it has
// under the numbers of the standard descriptors like its other descriptors:
// the number is free in the process again, and the process that next closes
// its standard output and opens a file gets the file as descriptor 1 of the
// host. When the first process ends, the host process has its own standard
// output back.
func TestHostDescriptors_AForkedProcessThatEndsFreesTheStandardNumbers(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	// The instance's standard output is the process's own.
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), os.Stdout, &bytes.Buffer{}
	KeepRuntimeDescriptorsHigh()
	w.hostProcess = true
	before := descriptorIdentity(t, 1)
	ended := false
	defer func() {
		if !ended {
			_ = w.CloseAll()
		}
	}()

	// The program captures its standard output in a file, then forks.
	capture := createTestFile(t, w, "capture.txt")
	if rc := w.Fd_dup2(m, capture, 1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	closeTestFd(t, w, m, capture)
	child := w.Fork()
	cm := newForkTestModule()

	// Each of the two puts a file of its own in the place of standard
	// output: the parent first, while the child still has the capture
	// there, then the child, which is the last to close it.
	closeTestFd(t, w, m, 1)
	if fd := createTestFile(t, w, "parent.txt"); fd != 1 {
		_ = child.CloseAll()
		t.Fatalf("the parent's file is descriptor %d, want 1", fd)
	}
	closeTestFd(t, child, cm, 1)
	if fd := createTestFile(t, child, "child.txt"); fd != 1 {
		_ = child.CloseAll()
		t.Fatalf("the child's file is descriptor %d, want 1", fd)
	}
	if !sameFile(t, guestIsHost(t, child, 1), filepath.Join(dir, "child.txt")) {
		_ = child.CloseAll()
		t.Fatalf("descriptor 1 of the host is not the child's file")
	}

	// The child ends: nothing is left under the number.
	if err := child.CloseAll(); err != nil {
		t.Fatalf("the child's CloseAll: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(1, &st); err != syscall.EBADF {
		t.Fatalf("after the forked process ended, fstat(1) = %v, want EBADF", err)
	}
	closeTestFd(t, w, m, 1)
	if fd := createTestFile(t, w, "again.txt"); fd != 1 {
		t.Fatalf("the parent's next file is descriptor %d, want 1", fd)
	}
	if !sameFile(t, guestIsHost(t, w, 1), filepath.Join(dir, "again.txt")) {
		t.Fatalf("descriptor 1 of the host is not the parent's file")
	}

	ended = true
	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if after := descriptorIdentity(t, 1); after != before {
		t.Fatalf("descriptor 1 of the process is %v after the first process ended, was %v", after, before)
	}
}

// A forked process that outlives the first process of its family leaves the
// standard descriptors alone when it ends: they are the host process's
// again.
func TestHostDescriptors_AForkedProcessThatOutlivesTheFirstLeavesStandardOutput(t *testing.T) {
	dir := t.TempDir()
	w, _ := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), os.Stdout, &bytes.Buffer{}
	KeepRuntimeDescriptorsHigh()
	w.hostProcess = true
	before := descriptorIdentity(t, 1)
	if host, ok := w.HostDescriptor(1); !ok || host != 1 {
		t.Fatalf("standard output is descriptor %d of the host (%v), want 1", host, ok)
	}
	child := w.Fork()
	if err := w.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatalf("the child's CloseAll: %v", err)
	}
	if after := descriptorIdentity(t, 1); after != before {
		t.Fatalf("descriptor 1 of the process is %v after the family ended, was %v", after, before)
	}
}

func TestHostDescriptors_StandardDescriptorsOfTheProcessAreNotTakenUnasked(t *testing.T) {
	dir := t.TempDir()
	// The instance's standard streams are the embedder's: descriptors 0, 1
	// and 2 of the process are none of its business.
	w, m := newHostGuest(t, dir)
	before := descriptorIdentity(t, 1)
	file := createTestFile(t, w, "out.txt")
	child := w.Fork()
	t.Cleanup(func() { _ = child.CloseAll() })
	for _, guest := range []*WasiStubs{w, child} {
		if rc := guest.Fd_dup2(m, file, 1); rc != _wasiESUCCESS {
			t.Fatalf("Fd_dup2 rc=%d", rc)
		}
		if after := descriptorIdentity(t, 1); after != before {
			t.Fatalf("dup2 onto the guest's 1 replaced descriptor 1 of the process")
		}
		if _, ok := guest.HostDescriptor(1); ok {
			t.Fatalf("the guest's 1 has a number of the host's")
		}
		if rc := fdWriteString(guest, m, 1, "x"); rc != _wasiESUCCESS {
			t.Fatalf("write to the redirected 1 rc=%d", rc)
		}
		closeTestFd(t, guest, m, 1)
		if after := descriptorIdentity(t, 1); after != before {
			t.Fatalf("closing the guest's 1 closed descriptor 1 of the process")
		}
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "out.txt")); string(got) != "xx" {
		t.Fatalf("the file holds %q", got)
	}
}

// A socket is the host's socket from the moment it is made: the number is
// the host's, its mode and its options are the kernel's, and where hosts
// differ the guest gets the answer of the host it runs on.
func TestHostDescriptors_SocketsAnswerAsTheHost(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	listener, port := newListener(t, w, m)
	host := guestIsHost(t, w, listener)
	if typ, err := syscall.GetsockoptInt(host, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil || typ != syscall.SOCK_STREAM {
		t.Fatalf("descriptor %d of the host is not the stream socket (%d, %v)", host, typ, err)
	}
	if sa, err := syscall.Getsockname(host); err != nil || sa.(*syscall.SockaddrInet4).Port != int(port) {
		t.Fatalf("the host's socket is bound to %v (%v), the guest's to port %d", sa, err, port)
	}
	client := dialLoopback(t, w, m, port)
	server, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	for _, fd := range []int32{client, server} {
		if hostStatusFlags(t, guestIsHost(t, w, fd))&syscall.O_NONBLOCK != 0 {
			t.Fatalf("socket %d is in non-blocking mode", fd)
		}
	}
	// Code outside the guest reads what the guest sent, through the number.
	if rc := sockSend(w, m, client, "to native code"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	buf := make([]byte, 32)
	if n, err := syscall.Read(int(server), buf); err != nil || string(buf[:n]) != "to native code" {
		t.Fatalf("read on the host's descriptor = %q, %v", buf[:n], err)
	}
	// And the guest what that code sends.
	if _, err := syscall.Write(int(server), []byte("from native code")); err != nil {
		t.Fatal(err)
	}
	if got, rc := sockRecv(w, m, client); rc != _wasiESUCCESS || got != "from native code" {
		t.Fatalf("Sock_recv = %q rc=%d", got, rc)
	}
	// An option the guest sets is the socket's.
	if rc := w.Sock_setopt(m, client, wasiSockOptKeepAlive, 1); rc != _wasiESUCCESS {
		t.Fatalf("Sock_setopt rc=%d", rc)
	}
	if v, err := syscall.GetsockoptInt(int(client), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); err != nil || v == 0 {
		t.Fatalf("SO_KEEPALIVE of the host's socket = %d, %v", v, err)
	}
	// A timeout the guest sets is the socket's, and ends its own wait.
	if rc := w.Sock_timeout(m, client, wasiSockTimeoutReceive, 1, int64(60*time.Millisecond), sockValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_timeout rc=%d", rc)
	}
	if got := hostSocketTimeout(int(client), syscall.SO_RCVTIMEO); got < 50*time.Millisecond || got > 100*time.Millisecond {
		t.Fatalf("SO_RCVTIMEO of the host's socket = %v", got)
	}
	start := time.Now()
	if _, rc := sockRecv(w, m, client); rc != _wasiEAGAIN {
		t.Fatalf("receive with a timeout rc=%d, want EAGAIN", rc)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > 2*time.Second {
		t.Fatalf("the receive gave up after %v", d)
	}
	// A datagram without a destination fails with the host's own error.
	lonely := newDatagramSocket(t, w, m)
	want := mapOSError(syscall.Sendto(guestIsHost(t, w, lonely), []byte("x"), 0, nil))
	if rc := sockSend(w, m, lonely, "x"); rc != want || rc == _wasiESUCCESS {
		t.Fatalf("send on an unconnected datagram socket rc=%d, the host says %d", rc, want)
	}
	// What poll says of a socket that is neither connected nor listening
	// is the host's answer too.
	fresh := w.Sock_socket(m, 2, wasiSockTypeStream)
	ask := [1]hostPoll{{fd: int32(guestIsHost(t, w, fresh)), events: hostPollOut}}
	hostPollUntil(ask[:], time.Now())
	if ok, rc := pollWritable(w, m, fresh, 0); rc != _wasiESUCCESS || ok != hostPollReady(false, ask[0].revents) {
		t.Fatalf("an unconnected socket polled writable=%v rc=%d, the host says %#x", ok, rc, ask[0].revents)
	}
	// Closing the guest's descriptor closes the host's socket.
	closeTestFd(t, w, m, server)
	if _, err := syscall.Getsockname(int(server)); err != syscall.EBADF {
		t.Fatalf("the host's socket after the guest closed it: %v", err)
	}
}

// A descriptor that code outside the guest made — a native library — is
// the guest's under its number, like one it opened itself.
func TestHostDescriptors_ADescriptorMadeOutsideTheGuestIsTheGuests(t *testing.T) {
	// The host names a directory by its path without symbolic links.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, m := newHostGuest(t, dir)
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	r, wr := int32(p[0]), int32(p[1])
	// The guest finds both ends, for what they are open for.
	if got := fdFiletype(t, w, m, r); got != 4 {
		t.Fatalf("file type of the pipe = %d", got)
	}
	if rc := fdWriteString(w, m, r, "x"); rc != _wasiEBADF {
		t.Fatalf("write to the read end rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, wr, "through"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, r, 16); rc != _wasiESUCCESS || got != "through" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	guestIsHost(t, w, r)
	// Its close-on-exec flag is the host's own, read and set.
	if rc := w.Fd_cloexec(m, r, 1, 1, 5300); rc != _wasiESUCCESS || readU32(m.memory, 5300) != 0 {
		t.Fatalf("Fd_cloexec rc=%d flag=%d, want the flag clear", rc, readU32(m.memory, 5300))
	}
	if flags, err := descriptorFlags(int(r), syscall.F_GETFD); err != nil || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("the flag the guest set is not the host's (%#x, %v)", flags, err)
	}
	if rc := w.Fd_cloexec(m, r, 0, 0, 5300); rc != _wasiESUCCESS || readU32(m.memory, 5300) != 1 {
		t.Fatalf("Fd_cloexec rc=%d flag=%d, want the flag set", rc, readU32(m.memory, 5300))
	}
	// The guest waits on it and duplicates it like any other.
	writeSubClock(m, pollSubsOff, 1, int64(20*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, r)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	dup := dupTestFd(t, w, m, wr)
	if rc := fdWriteString(w, m, dup, "again"); rc != _wasiESUCCESS {
		t.Fatalf("write to the duplicate rc=%d", rc)
	}
	// Closing it closes the host's.
	closeTestFd(t, w, m, r)
	var st syscall.Stat_t
	if err := syscall.Fstat(int(r), &st); err != syscall.EBADF {
		t.Fatalf("the descriptor after the guest closed it: %v", err)
	}

	// A command the guest starts inherits a descriptor that code outside
	// the guest left for commands to inherit, though the guest never used
	// it, and not one that is close-on-exec.
	if _, err := os.Stat("/bin/sh"); err == nil {
		var left, kept [2]int
		if err := syscall.Pipe(left[:]); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Pipe(kept[:]); err != nil {
			t.Fatal(err)
		}
		syscall.CloseOnExec(kept[1])
		// The descriptors are named by their files in /dev/fd: not every
		// shell takes a number of two digits in a redirection.
		out := "/dev/fd/" + itoa32(int32(left[1]))
		script := "echo inherited > " + out + "; if test -e /dev/fd/" + itoa32(int32(kept[1])) + "; then echo leaked > " + out + "; fi"
		pid := spawnTestProc(t, w, m, "/bin/sh", "-c", script)
		if rc := w.Proc_wait(m, pid, 0, 5400); rc != _wasiESUCCESS || readU32(m.memory, 5400) != 0 {
			t.Fatalf("the command: Proc_wait rc=%d status=%#x", rc, readU32(m.memory, 5400))
		}
		closeTestFd(t, w, m, int32(left[1]))
		buf := make([]byte, 64)
		n, _ := syscall.Read(left[0], buf)
		if string(buf[:n]) != "inherited\n" {
			t.Fatalf("the command wrote %q to the inherited descriptor", buf[:n])
		}
		for _, fd := range []int{left[0], kept[0], kept[1]} {
			_ = syscall.Close(fd)
		}
		// The code that made a descriptor may close it and get the number
		// again for something else: the guest finds what is there now.
		reused, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range reused {
			if got := fdFiletype(t, w, m, int32(fd)); got != 5 {
				t.Fatalf("descriptor %d, now a datagram socket, has file type %d", fd, got)
			}
			_ = syscall.Close(fd)
		}
	}

	// A process forked from the guest shares a descriptor the guest took
	// in: closing it in the child leaves the parent's open, and the host's
	// descriptor goes when the last of them has closed it.
	var shared [2]int
	if err := syscall.Pipe(shared[:]); err != nil {
		t.Fatal(err)
	}
	if rc := fdWriteString(w, m, int32(shared[1]), "before the fork,"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	child := w.Fork()
	cm := newForkTestModule()
	if rc := fdWriteString(child, cm, int32(shared[1]), "from the child"); rc != _wasiESUCCESS {
		t.Fatalf("the child's write rc=%d", rc)
	}
	closeTestFd(t, child, cm, int32(shared[1]))
	if rc := fdWriteString(w, m, int32(shared[1]), ",after"); rc != _wasiESUCCESS {
		t.Fatalf("the parent's write after the child closed the descriptor rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, int32(shared[0]), 64); rc != _wasiESUCCESS || got != "before the fork,from the child,after" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	_ = child.CloseAll()
	closeTestFd(t, w, m, int32(shared[1]))
	if err := syscall.Fstat(shared[1], &st); err != syscall.EBADF {
		t.Fatalf("the descriptor after the last of them closed it: %v", err)
	}
	closeTestFd(t, w, m, int32(shared[0]))

	// A socket, with what it is.
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(pair[1], []byte("on a socket")); err != nil {
		t.Fatal(err)
	}
	if got, rc := sockRecv(w, m, int32(pair[0])); rc != _wasiESUCCESS || got != "on a socket" {
		t.Fatalf("Sock_recv on a socket made outside = %q rc=%d", got, rc)
	}
	if got := nameOf(t, w, m, int32(pair[0]), 0); got.family != wasiSockFamilyUnix {
		t.Fatalf("family of the socket = %d", got.family)
	}

	// A directory, with its name.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub, err := syscall.Open(filepath.Join(dir, "sub"), syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rc := w.Fd_path(m, int32(sub), metaPathOff, 256, metaOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_path of a directory opened outside rc=%d", rc)
	}
	if got := string(m.memory[metaPathOff : metaPathOff+int32(readU32(m.memory, int(metaOutOff)))]); got != "/sub" {
		t.Fatalf("Fd_path = %q, want /sub", got)
	}
}

// What is not the guest's to take: a number that is not open, another
// guest's descriptor, the runtime's, and a standard descriptor of the
// process that the instance was not given.
func TestHostDescriptors_OtherDescriptorsAreOutOfReach(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	other, om := newHostGuest(t, t.TempDir())
	theirs := createTestFile(t, other, "theirs.txt")
	for name, fd := range map[string]int32{"another guest's descriptor": theirs, "a number that is not open": 250} {
		if rc := w.Fd_fdstat_get(m, fd, 5200); rc != _wasiEBADF {
			t.Errorf("%s: Fd_fdstat_get rc=%d, want EBADF", name, rc)
		}
		if rc := w.Fd_close(m, fd); rc != _wasiEBADF {
			t.Errorf("%s: Fd_close rc=%d, want EBADF", name, rc)
		}
	}
	if rc := fdWriteString(other, om, theirs, "still theirs"); rc != _wasiESUCCESS {
		t.Fatalf("the other guest's descriptor after this one asked for it: write rc=%d", rc)
	}
	// The runtime's waker.
	readFd, _ := newTestPipe(t, w, m)
	writeSubClock(m, pollSubsOff, 1, int64(time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1, readFd)
	pollUserdata(t, w, m, 2)
	w.mu.Lock()
	waker := w.waker
	w.mu.Unlock()
	if rc := w.Fd_close(m, int32(waker.r)); rc != _wasiEBADF {
		t.Fatalf("Fd_close of a descriptor of the runtime rc=%d, want EBADF", rc)
	}
	// Standard output of the process: the instance's is a buffer.
	before := descriptorIdentity(t, 1)
	closeTestFd(t, w, m, 1)
	if rc := w.Fd_fdstat_get(m, 1, 5200); rc != _wasiEBADF {
		t.Fatalf("Fd_fdstat_get(1) after the guest closed its own rc=%d, want EBADF", rc)
	}
	if after := descriptorIdentity(t, 1); after != before {
		t.Fatalf("descriptor 1 of the process changed")
	}
}

// A terminal is a terminal to the guest's libc, which tells one by what
// fd_fdstat_get says: a character device that cannot be sought on.
func TestHostDescriptors_ATerminalIsToldFromOtherDevices(t *testing.T) {
	w, m := newHostGuest(t, "/")
	seekable := func(fd int32) (filetype byte, seek bool) {
		t.Helper()
		if rc := w.Fd_fdstat_get(m, fd, 5200); rc != _wasiESUCCESS {
			t.Fatalf("Fd_fdstat_get(%d) rc=%d", fd, rc)
		}
		rights := readU64(m.memory, 5208)
		return m.memory[5200], rights&(wasiRightFdSeek|wasiRightFdTell) != 0
	}
	null, errno := w.pathOpen("dev/null", 1, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open /dev/null errno=%d", errno)
	}
	if filetype, seek := seekable(null); filetype != 2 || !seek {
		t.Fatalf("/dev/null: file type %d, may seek %v; want a character device that may", filetype, seek)
	}
	pty, errno := w.pathOpen("dev/ptmx", 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Skipf("no pseudo-terminal to open (errno %d)", errno)
	}
	if filetype, seek := seekable(pty); filetype != 2 || seek {
		t.Fatalf("a pseudo-terminal: file type %d, may seek %v; want a character device that may not", filetype, seek)
	}
}

// Whatever the runtime reads and writes a pipe through, the pipe ends when
// the guest closes its descriptors: nothing of the runtime's keeps an end
// open, and the mode of the guest's descriptors is as the guest left it.
func TestHostDescriptors_APipeEndsWhenTheGuestClosesIt(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, writeFd := newTestPipe(t, w, m)
	for i := 0; i < 3; i++ {
		if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
			t.Fatalf("write rc=%d", rc)
		}
		if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "data" {
			t.Fatalf("read = %q rc=%d", got, rc)
		}
	}
	for _, fd := range []int32{readFd, writeFd} {
		if hostStatusFlags(t, int(fd))&syscall.O_NONBLOCK != 0 {
			t.Fatalf("descriptor %d is in non-blocking mode after the guest used it", fd)
		}
	}
	// The writer goes: a reader outside the guest is at the end of input.
	reader, err := syscall.Dup(int(readFd))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(reader)
	closeTestFd(t, w, m, writeFd)
	if err := syscall.SetNonblock(reader, true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := syscall.Read(reader, buf); n != 0 || err != nil {
		t.Fatalf("read after the guest closed the write end = %d, %v; want the end of input", n, err)
	}
	// The reader goes: a writer outside the guest has nobody to write to.
	r2, w2 := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, w2, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, r2, 4); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	writer, err := syscall.Dup(int(w2))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(writer)
	closeTestFd(t, w, m, r2)
	if _, err := syscall.Write(writer, []byte("y")); err != syscall.EPIPE {
		t.Fatalf("write after the guest closed the read end: %v, want EPIPE", err)
	}
}
