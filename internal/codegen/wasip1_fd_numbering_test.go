package codegen

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// dupTestFd duplicates fd through Fd_dup and returns the new fd.
func dupTestFd(t *testing.T, w *WasiStubs, m *Module, fd int32) int32 {
	t.Helper()
	const out int32 = 5100
	if rc := w.Fd_dup(m, fd, out); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup(%d) rc=%d", fd, rc)
	}
	return int32(readU32(m.memory, int(out)))
}

// createTestFile opens name for writing through pathOpen, creating it, and
// returns the new fd.
func createTestFile(t *testing.T, w *WasiStubs, name string) int32 {
	t.Helper()
	fd, errno := w.pathOpen(name, 0, 0x1 /* O_CREAT */, 1<<6 /* FD_WRITE */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen(%s) errno=%d", name, errno)
	}
	return fd
}

// closeTestFd closes fd and fails the test when that does not succeed.
func closeTestFd(t *testing.T, w *WasiStubs, m *Module, fd int32) {
	t.Helper()
	if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close(%d) rc=%d", fd, rc)
	}
}

// fdFiletype returns the filetype Fd_fdstat_get reports for fd.
func fdFiletype(t *testing.T, w *WasiStubs, m *Module, fd int32) byte {
	t.Helper()
	const out int32 = 5200
	if rc := w.Fd_fdstat_get(m, fd, out); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_get(%d) rc=%d", fd, rc)
	}
	return m.memory[out]
}

func TestWasi_NewDescriptorsTakeLowestFreeNumber(t *testing.T) {
	w, m := newProcTestStubs(t)

	// 0/1/2 are the standard streams and 3 is the preopened directory, so
	// the first descriptors are 4, 5, 6, ...
	file := createTestFile(t, w, "a.txt")
	if file != 4 {
		t.Fatalf("first open = %d, want 4", file)
	}
	readFd, writeFd := newTestPipe(t, w, m)
	if readFd != 5 || writeFd != 6 {
		t.Fatalf("pipe = %d,%d, want 5,6", readFd, writeFd)
	}
	if got := dupTestFd(t, w, m, 0); got != 7 {
		t.Fatalf("dup(0) = %d, want 7", got)
	}
	if got := w.Sock_socket(m, 0, 0); got != 8 {
		t.Fatalf("socket = %d, want 8", got)
	}

	// A closed number is the next one handed out, lowest first.
	closeTestFd(t, w, m, 7)
	closeTestFd(t, w, m, 5)
	if got := dupTestFd(t, w, m, 0); got != 5 {
		t.Fatalf("dup after closing 5 and 7 = %d, want 5", got)
	}
	if got := createTestFile(t, w, "b.txt"); got != 7 {
		t.Fatalf("open after closing 7 = %d, want 7", got)
	}
	if got := w.Sock_socket(m, 0, 0); got != 9 {
		t.Fatalf("socket with nothing free below = %d, want 9", got)
	}

	// dup+close gives the same number every time, however much opening and
	// closing happened in between.
	before := dupTestFd(t, w, m, 0)
	closeTestFd(t, w, m, before)
	for i := 0; i < 50; i++ {
		r, wr := newTestPipe(t, w, m)
		closeTestFd(t, w, m, r)
		closeTestFd(t, w, m, wr)
	}
	after := dupTestFd(t, w, m, 0)
	if after != before {
		t.Fatalf("dup(0) = %d after churn, %d before", after, before)
	}

	// A pipe fills the two lowest holes.
	closeTestFd(t, w, m, 4)
	closeTestFd(t, w, m, 8)
	if r, wr := newTestPipe(t, w, m); r != 4 || wr != 8 {
		t.Fatalf("pipe into holes = %d,%d, want 4,8", r, wr)
	}
}

func TestWasi_PreopenNumberIsNeverHandedOut(t *testing.T) {
	w, m := newProcTestStubs(t)
	if rc := w.Fd_closefrom(m, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_closefrom rc=%d", rc)
	}
	var got []int32
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		got = append(got, createTestFile(t, w, name))
	}
	want := []int32{0, 1, 2, 4, 5}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fds on an empty table = %v, want %v", got, want)
		}
	}
	if ft := fdFiletype(t, w, m, 3); ft != 3 {
		t.Fatalf("fd 3 filetype = %d, want directory", ft)
	}
}

func TestWasi_AcceptTakesLowestFreeNumber(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen tcp: %v", err)
	}
	w, m := newProcTestStubs(t)
	w.mu.Lock()
	w.fdsLocked()[7] = &wasiOpen{listener: ln}
	w.mu.Unlock()
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	closeTestFd(t, w, m, 0)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})
	const out int32 = 5300
	if rc := w.Sock_accept(m, 7, 0, out); rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	if got := int32(readU32(m.memory, int(out))); got != 0 {
		t.Fatalf("accepted fd = %d, want 0", got)
	}
	if ft := fdFiletype(t, w, m, 0); ft != 6 {
		t.Fatalf("accepted fd filetype = %d, want socket", ft)
	}
}

func TestWasi_ClosedStandardOutputIsReusedByOpen(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	var out bytes.Buffer
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}

	if ft := fdFiletype(t, w, m, 1); ft != 2 {
		t.Fatalf("stdout filetype = %d, want character device", ft)
	}
	if rc := fdWriteString(w, m, 1, "to-stream"); rc != _wasiESUCCESS {
		t.Fatalf("write to stdout rc=%d", rc)
	}

	closeTestFd(t, w, m, 1)
	if fd := createTestFile(t, w, "out.txt"); fd != 1 {
		t.Fatalf("open after close(1) = %d, want 1", fd)
	}
	if rc := fdWriteString(w, m, 1, "to-file"); rc != _wasiESUCCESS {
		t.Fatalf("write to reopened fd 1 rc=%d", rc)
	}

	// fd 1 is the file now, in every call that looks at it.
	if ft := fdFiletype(t, w, m, 1); ft != 4 {
		t.Fatalf("reopened fd 1 filetype = %d, want regular file", ft)
	}
	const statOff, offOff int32 = 6000, 6100
	if rc := w.Fd_filestat_get(m, 1, statOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_get rc=%d", rc)
	}
	if ft := m.memory[statOff+16]; ft != 4 {
		t.Fatalf("filestat filetype = %d, want regular file", ft)
	}
	if size := readU64(m.memory, int(statOff)+32); size != uint64(len("to-file")) {
		t.Fatalf("filestat size = %d, want %d", size, len("to-file"))
	}
	if rc := w.Fd_seek(m, 1, 0, 1 /* SEEK_CUR */, offOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_seek rc=%d", rc)
	}
	if pos := readU64(m.memory, int(offOff)); pos != uint64(len("to-file")) {
		t.Fatalf("offset = %d, want %d", pos, len("to-file"))
	}
	w.mu.Lock()
	cw := w.childWriterLocked(1, w.stdout)
	w.mu.Unlock()
	if _, isFile := cw.(File); !isFile {
		t.Fatalf("spawned child's stdout = %T, want the file", cw)
	}

	closeTestFd(t, w, m, 1)
	if got, err := os.ReadFile(filepath.Join(dir, "out.txt")); err != nil || string(got) != "to-file" {
		t.Fatalf("out.txt = %q, %v; want %q", got, err, "to-file")
	}
	if out.String() != "to-stream" {
		t.Fatalf("stdout stream = %q, want %q", out.String(), "to-stream")
	}
}

func TestWasi_ClosedStandardDescriptorsAreBad(t *testing.T) {
	w, m := newProcTestStubs(t)
	for fd := int32(0); fd <= 2; fd++ {
		closeTestFd(t, w, m, fd)
	}
	const out int32 = 6000
	for fd := int32(0); fd <= 2; fd++ {
		if rc := w.Fd_close(m, fd); rc != _wasiEBADF {
			t.Errorf("second Fd_close(%d) rc=%d, want EBADF", fd, rc)
		}
		if _, rc := fdReadString(w, m, fd, 4); rc != _wasiEBADF {
			t.Errorf("Fd_read(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := fdWriteString(w, m, fd, "x"); rc != _wasiEBADF {
			t.Errorf("Fd_write(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_fdstat_get(m, fd, out); rc != _wasiEBADF {
			t.Errorf("Fd_fdstat_get(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_fdstat_set_flags(m, fd, 0); rc != _wasiEBADF {
			t.Errorf("Fd_fdstat_set_flags(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_fdstat_set_rights(m, fd, 0, 0); rc != _wasiEBADF {
			t.Errorf("Fd_fdstat_set_rights(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_filestat_get(m, fd, out); rc != _wasiEBADF {
			t.Errorf("Fd_filestat_get(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_seek(m, fd, 0, 0, out); rc != _wasiEBADF {
			t.Errorf("Fd_seek(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_dup(m, fd, out); rc != _wasiEBADF {
			t.Errorf("Fd_dup(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_dup2(m, fd, 9); rc != _wasiEBADF {
			t.Errorf("Fd_dup2(%d, 9) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_renumber(m, fd, 9); rc != _wasiEBADF {
			t.Errorf("Fd_renumber(%d, 9) rc=%d, want EBADF", fd, rc)
		}
	}

	// poll_oneoff reports each closed descriptor as an EBADF event.
	writeSubFd(m, pollSubsOff, 10, 1, 0)
	writeSubFd(m, pollSubsOff+48, 11, 2, 1)
	wantUserdata(t, pollUserdata(t, w, m, 2), 10, 11)
	for i := int32(0); i < 2; i++ {
		if errno := binary.LittleEndian.Uint16(m.memory[pollEvOff+i*32+8:]); errno != uint16(_wasiEBADF) {
			t.Errorf("poll event %d errno=%d, want EBADF", i, errno)
		}
	}

	// A spawned process gets no stream for a closed descriptor, and the
	// instance's own stream when the guest asks for it with -1.
	w.mu.Lock()
	cin := w.childReaderLocked(0)
	cout := w.childWriterLocked(1, w.stdout)
	cerr := w.childWriterLocked(2, w.stderr)
	inherited := w.childWriterLocked(-1, w.stdout)
	w.mu.Unlock()
	if cin != nil || cout != nil || cerr != nil {
		t.Errorf("child streams for closed fds = %v, %v, %v; want none", cin, cout, cerr)
	}
	if inherited != w.stdout {
		t.Errorf("child stream for fd -1 = %v, want the instance's stdout", inherited)
	}
}

func TestWasi_SpawnWithClosedStandardOutput(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	closeTestFd(t, w, m, 1)

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "discarded"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, 0, 1, 2, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(readU32(m.memory, int(pidOff)))
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 0 {
		t.Fatalf("wait status = %#x, want 0", status)
	}
	if out.Len() != 0 {
		t.Fatalf("instance stdout received %q from a child whose stdout was closed", out.String())
	}
}

func TestWasi_ForkCopiesClosedStandardDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	closeTestFd(t, w, m, 1)

	child := w.Fork()
	cm := newForkTestModule()
	if rc := fdWriteString(child, cm, 1, "x"); rc != _wasiEBADF {
		t.Fatalf("child write to fd 1 closed before fork rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(child, cm, 2, "err"); rc != _wasiESUCCESS {
		t.Fatalf("child write to fd 2 rc=%d", rc)
	}
	if got := w.stderr.(*bytes.Buffer).String(); got != "err" {
		t.Fatalf("stderr stream = %q, want %q", got, "err")
	}
	// The child numbers its descriptors on its own, from its own table.
	if got := dupTestFd(t, child, cm, 2); got != 1 {
		t.Fatalf("child dup(2) = %d, want 1", got)
	}
	if rc := fdWriteString(w, m, 1, "x"); rc != _wasiEBADF {
		t.Fatalf("parent write to closed fd 1 rc=%d, want EBADF", rc)
	}

	// Closing after the fork affects only the side that closed.
	closeTestFd(t, child, cm, 0)
	if _, rc := fdReadString(w, m, 0, 4); rc != _wasiESUCCESS {
		t.Fatalf("parent read of fd 0 after the child closed its own rc=%d", rc)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if rc := fdWriteString(child, cm, 2, "x"); rc != _wasiEBADF {
		t.Fatalf("child write after CloseAll rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, 2, "more"); rc != _wasiESUCCESS {
		t.Fatalf("parent write to fd 2 after the child's CloseAll rc=%d", rc)
	}
}

func TestWasi_HandBuiltStubsStartWithStandardDescriptors(t *testing.T) {
	var out, errOut bytes.Buffer
	w := &WasiStubs{stdin: bytes.NewReader([]byte("in")), stdout: &out, stderr: &errOut}
	w.SetPreopenDir(t.TempDir())
	m := newForkTestModule()

	if got, rc := fdReadString(w, m, 0, 8); rc != _wasiESUCCESS || got != "in" {
		t.Fatalf("read fd 0 = %q rc=%d", got, rc)
	}
	if rc := fdWriteString(w, m, 1, "out"); rc != _wasiESUCCESS || out.String() != "out" {
		t.Fatalf("write fd 1 rc=%d, stream %q", rc, out.String())
	}
	if rc := fdWriteString(w, m, 2, "err"); rc != _wasiESUCCESS || errOut.String() != "err" {
		t.Fatalf("write fd 2 rc=%d, stream %q", rc, errOut.String())
	}
	if fd := createTestFile(t, w, "a.txt"); fd != 4 {
		t.Fatalf("first open = %d, want 4", fd)
	}
	closeTestFd(t, w, m, 2)
	if got := dupTestFd(t, w, m, 1); got != 2 {
		t.Fatalf("dup(1) after close(2) = %d, want 2", got)
	}

	// Each of these is the first call on a table that was never set up.
	if r, wr := newTestPipe(t, &WasiStubs{}, m); r != 4 || wr != 5 {
		t.Fatalf("pipe on fresh stubs = %d,%d, want 4,5", r, wr)
	}
	if fd := (&WasiStubs{}).Sock_socket(m, 0, 0); fd != 4 {
		t.Fatalf("socket on fresh stubs = %d, want 4", fd)
	}
	if rc := (&WasiStubs{}).Fd_close(m, 1); rc != _wasiESUCCESS {
		t.Fatalf("close(1) on fresh stubs rc=%d", rc)
	}
	forked := (&WasiStubs{stdout: &out}).Fork()
	if rc := fdWriteString(forked, m, 1, "+child"); rc != _wasiESUCCESS || out.String() != "out+child" {
		t.Fatalf("write fd 1 of a fork of fresh stubs rc=%d, stream %q", rc, out.String())
	}
	closed := &WasiStubs{stdout: &out}
	if err := closed.CloseAll(); err != nil {
		t.Fatalf("CloseAll on fresh stubs: %v", err)
	}
	if rc := fdWriteString(closed, m, 1, "x"); rc != _wasiEBADF {
		t.Fatalf("write after CloseAll on fresh stubs rc=%d, want EBADF", rc)
	}
}

func TestWasi_StreamRedirectionReachesOpenStandardDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	saved := dupTestFd(t, w, m, 1)
	closeTestFd(t, w, m, 2)
	file := createTestFile(t, w, "err.txt")
	if file != 2 {
		t.Fatalf("open after close(2) = %d, want 2", file)
	}

	var out, errOut bytes.Buffer
	w.SetStdout(&out)
	w.SetStderr(&errOut)
	w.SetStdin(bytes.NewReader([]byte("later")))

	if rc := fdWriteString(w, m, 1, "a"); rc != _wasiESUCCESS {
		t.Fatalf("write fd 1 rc=%d", rc)
	}
	if rc := fdWriteString(w, m, saved, "b"); rc != _wasiESUCCESS {
		t.Fatalf("write dup of fd 1 rc=%d", rc)
	}
	if out.String() != "ab" {
		t.Fatalf("redirected stdout = %q, want %q", out.String(), "ab")
	}
	if got, rc := fdReadString(w, m, 0, 8); rc != _wasiESUCCESS || got != "later" {
		t.Fatalf("read fd 0 = %q rc=%d", got, rc)
	}
	// fd 2 no longer refers to the standard error stream.
	if rc := fdWriteString(w, m, 2, "file"); rc != _wasiESUCCESS {
		t.Fatalf("write fd 2 rc=%d", rc)
	}
	if errOut.Len() != 0 {
		t.Fatalf("redirected stderr received %q through a descriptor reopened onto a file", errOut.String())
	}
}

func TestWasi_Dup2OntoClosedStandardDescriptor(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	var out bytes.Buffer
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}

	saved := dupTestFd(t, w, m, 1)
	closeTestFd(t, w, m, 1)
	file := createTestFile(t, w, "log.txt")
	if file != 1 {
		t.Fatalf("open after close(1) = %d, want 1", file)
	}
	if rc := fdWriteString(w, m, 1, "file"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	// Restoring the saved descriptor closes the file and brings the
	// stream back.
	if rc := w.Fd_dup2(m, saved, 1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	closeTestFd(t, w, m, saved)
	if rc := fdWriteString(w, m, 1, "stream"); rc != _wasiESUCCESS {
		t.Fatalf("write after restore rc=%d", rc)
	}
	if ft := fdFiletype(t, w, m, 1); ft != 2 {
		t.Fatalf("restored fd 1 filetype = %d, want character device", ft)
	}
	if out.String() != "stream" {
		t.Fatalf("stdout stream = %q, want %q", out.String(), "stream")
	}
	if got, err := os.ReadFile(filepath.Join(dir, "log.txt")); err != nil || string(got) != "file" {
		t.Fatalf("log.txt = %q, %v; want %q", got, err, "file")
	}
	if got := dupTestFd(t, w, m, 1); got != saved {
		t.Fatalf("dup(1) = %d, want the freed number %d", got, saved)
	}
}
