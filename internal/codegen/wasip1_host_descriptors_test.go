//go:build darwin || linux

package codegen

import (
	"bytes"
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

	// The parent closes a descriptor the child still has: the host keeps
	// it for the child, and the parent's next descriptor is elsewhere.
	kept := createTestFile(t, w, "kept.txt")
	grandchild := w.Fork()
	defer grandchild.CloseAll()
	closeTestFd(t, w, m, kept)
	if rc := fdWriteString(grandchild, cm, kept, "still open"); rc != _wasiESUCCESS {
		t.Fatalf("write through a descriptor the parent closed rc=%d", rc)
	}
	if next := createTestFile(t, w, "next.txt"); next == kept {
		t.Fatalf("the parent got number %d again while its child still uses it", kept)
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
	script := "cat <&" + itoa32(in) + " >&" + itoa32(out) + "; if (: >&" + itoa32(hidden) + ") 2>/dev/null; then echo leaked >&" + itoa32(out) + "; fi"
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

func TestHostDescriptors_StandardDescriptorsOfTheProcessAreNotTakenUnasked(t *testing.T) {
	dir := t.TempDir()
	// The instance's standard streams are the embedder's: descriptors 0, 1
	// and 2 of the process are none of its business.
	w, m := newHostGuest(t, dir)
	before := descriptorIdentity(t, 1)
	file := createTestFile(t, w, "out.txt")
	for _, guest := range []*WasiStubs{w, w.Fork()} {
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
