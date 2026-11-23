//go:build darwin || linux

package codegen

import (
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// spawnWithStreams starts argv with the guest's descriptors stdin, stdout
// and stderr as its standard streams (-1 for the instance's) and returns
// its pid token. w's FS becomes the whole host filesystem, in which argv[0]
// is a name.
func spawnWithStreams(t *testing.T, w *WasiStubs, m *Module, stdin, stdout, stderr int32, argv ...string) int32 {
	t.Helper()
	if _, err := os.Stat(argv[0]); err != nil {
		t.Skipf("%s not available", argv[0])
	}
	w.cfg.FS = osFS{}
	pathOff := writeCStr(m, 1000, argv[0])
	argvOff := writeArgv(m, 2000, 3000, argv)
	const pidOff int32 = 4000
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, stdin, stdout, stderr, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	return int32(readU32(m.memory, int(pidOff)))
}

// waitExitsZero waits for the process pid and fails the test unless it
// exited with 0.
func waitExitsZero(t *testing.T, w *WasiStubs, m *Module, pid int32) {
	t.Helper()
	const statusOff int32 = 4004
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 0 {
		t.Fatalf("wait status = %#x, want 0", status)
	}
}

// readToEnd reads fd through Fd_read until the end of its input.
func readToEnd(t *testing.T, w *WasiStubs, m *Module, fd int32) string {
	t.Helper()
	var got strings.Builder
	for {
		s, rc := fdReadString(w, m, fd, 512)
		if rc != _wasiESUCCESS {
			t.Fatalf("Fd_read(%d) rc=%d", fd, rc)
		}
		if s == "" {
			return got.String()
		}
		got.WriteString(s)
	}
}

// hostNonblock reports whether the host's open file description behind the
// guest's descriptor fd, a file of the host, is in non-blocking mode.
func hostNonblock(t *testing.T, w *WasiStubs, fd int32) bool {
	t.Helper()
	w.mu.Lock()
	op := w.fdTable[fd]
	w.mu.Unlock()
	var flags int
	if err := withHostDescriptor(op.f.(*os.File), func(raw uintptr) error {
		var err error
		flags, err = descriptorFlags(int(raw), syscall.F_GETFL)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return flags&syscall.O_NONBLOCK != 0
}

// A pipe end of the guest's given to a command keeps the mode the runtime
// polls it in, and the guest, which closes its own write end once the
// command has it, reads what the command wrote up to the end.
func TestSpawn_GuestPipeKeepsItsMode(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	r, wr := newTestPipe(t, w, m)
	pid := spawnWithStreams(t, w, m, -1, wr, -1, "/bin/echo", "hello")
	if !hostNonblock(t, w, wr) {
		t.Fatal("the guest's write end is in blocking mode after the spawn")
	}
	closeTestFd(t, w, m, wr)
	if got := readToEnd(t, w, m, r); got != "hello\n" {
		t.Fatalf("read %q from the pipe, want the command's output", got)
	}
	waitExitsZero(t, w, m, pid)
}

// The wait for a command whose output the runtime copies returns once the
// command has ended, with what it wrote delivered, though a process it left
// behind holds the output open.
func TestSpawn_CopiedOutputEndsWithTheCommand(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	pid := spawnWithStreams(t, w, m, -1, -1, -1, "/bin/sh", "-c", "echo hi; sleep 1000 & echo $!")
	waitExitsZero(t, w, m, pid)
	got := out.String()
	left, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(got, "hi\n"), "\n"))
	if err != nil {
		t.Fatalf("output %q, want hi and the pid left behind: %v", got, err)
	}
	if err := syscall.Kill(left, syscall.SIGKILL); err != nil {
		t.Fatalf("kill the process left behind: %v", err)
	}
}

// Input of a guest's pipe a command did not read is the guest's to read.
func TestSpawn_UnreadPipeInputStaysTheGuests(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	r, wr := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, wr, "abc\nrest\n"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	pid := spawnWithStreams(t, w, m, r, -1, -1, "/bin/sh", "-c", `read x; echo "got $x"`)
	waitExitsZero(t, w, m, pid)
	if out.String() != "got abc\n" {
		t.Fatalf("command output = %q, want its first line", out.String())
	}
	closeTestFd(t, w, m, wr)
	if got := readToEnd(t, w, m, r); got != "rest\n" {
		t.Fatalf("the guest then reads %q from the pipe, want what the command left", got)
	}
}

// spawnedSocketOutput is a command whose output is more than a socket's
// and a copy's buffers hold.
var spawnedSocketOutput = []string{"/bin/sh", "-c", "head -c 200000 /dev/zero"}

// A socket the guest made, as a command's stdout, gets everything the
// command writes, up to the end.
func TestSpawn_GuestSocketGetsTheCommandsOutput(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	const fdsOff int32 = 5100
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, fdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
	pid := spawnWithStreams(t, w, m, -1, a, -1, spawnedSocketOutput...)
	closeTestFd(t, w, m, a)
	if got := readToEnd(t, w, m, b); got != string(make([]byte, 200000)) || out.Len() != 0 {
		t.Fatalf("the other socket read %d bytes, instance stdout %d; want the 200000 bytes at the socket", len(got), out.Len())
	}
	waitExitsZero(t, w, m, pid)
}

// A connection of package net's, as a command's stdout, gets everything
// the command writes, up to the end.
func TestSpawn_ConnGetsTheCommandsOutput(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := os.NewFile(uintptr(pair[0]), "local")
	peer := os.NewFile(uintptr(pair[1]), "peer")
	conn, err := net.FileConn(local)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	sock := addTestFD(w, &wasiOpen{conn: conn})
	w.mu.Unlock()
	pid := spawnWithStreams(t, w, m, -1, sock, -1, spawnedSocketOutput...)
	closeTestFd(t, w, m, sock)
	got, err := io.ReadAll(peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, 200000)) || out.Len() != 0 {
		t.Fatalf("peer read %d bytes, instance stdout %d; want the 200000 bytes at the peer", len(got), out.Len())
	}
	waitExitsZero(t, w, m, pid)
}

// A command's stdout and stderr of one destination — one writer of the
// embedder's, or one descriptor of the guest's given twice — keep the order
// the command wrote in.
func TestSpawn_StdoutAndStderrOfOneDestinationKeepTheirOrder(t *testing.T) {
	const script = `i=0; while [ $i -lt 200 ]; do echo o$i; echo e$i >&2; i=$((i+1)); done`
	var want strings.Builder
	for i := range 200 {
		want.WriteString("o" + strconv.Itoa(i) + "\ne" + strconv.Itoa(i) + "\n")
	}
	for _, dup := range []bool{false, true} {
		w, m := newTestStubs(t, t.TempDir())
		var out bytes.Buffer
		w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &out
		stdout, stderr := int32(-1), int32(-1)
		if dup {
			// The guest's stderr becomes its stdout, as open(STDERR, ">&STDOUT").
			w.cfg.Stderr = &bytes.Buffer{}
			if rc := w.Fd_dup2(m, 1, 2); rc != _wasiESUCCESS {
				t.Fatalf("Fd_dup2 rc=%d", rc)
			}
			stdout, stderr = 1, 2
		}
		pid := spawnWithStreams(t, w, m, -1, stdout, stderr, "/bin/sh", "-c", script)
		waitExitsZero(t, w, m, pid)
		if out.String() != want.String() {
			t.Fatalf("dup2=%v: the output is out of order: %.80q...", dup, out.String())
		}
	}
}

// A socket as a command's stdin: what the command did not read is the
// guest's to receive, and the runtime holds the socket no longer than the
// command runs.
func TestSpawn_SocketAsStdinLeavesTheRestToTheGuest(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	const fdsOff int32 = 5100
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, fdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
	if rc := fdWriteString(w, m, b, "abc\nrest\n"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	pid := spawnWithStreams(t, w, m, a, -1, -1, "/bin/sh", "-c", `read x; echo "got $x"`)
	waitExitsZero(t, w, m, pid)
	if out.String() != "got abc\n" {
		t.Fatalf("command output = %q, want its first line", out.String())
	}
	if got, rc := fdReadString(w, m, a, 3); rc != _wasiESUCCESS || got != "res" {
		t.Fatalf("the guest then reads %q rc=%d, want the first of what the command left", got, rc)
	}
	if got, _, rc := recvFrom(w, m, a, 2, wasiMsgPeek); rc != _wasiESUCCESS || got != "t\n" {
		t.Fatalf("a peek then sees %q rc=%d, want the rest of what the command left", got, rc)
	}
	if rc := fdWriteString(w, m, b, "more"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if got, _, rc := recvFrom(w, m, a, 6, wasiMsgWaitAll); rc != _wasiESUCCESS || got != "t\nmore" {
		t.Fatalf("a receive that waits for all gets %q rc=%d, want what the command left and the socket's", got, rc)
	}
	closeTestFd(t, w, m, a)
	if got := readToEnd(t, w, m, b); got != "" {
		t.Fatalf("the other socket read %q, want the end of the stream", got)
	}
}

// A copy of a command's input that has ended has closed the pipe it wrote
// to and the duplicate it read: finish finds nothing to end there, which is
// no failure.
func TestSpawn_FinishOfAnEndedInputCopyIsNoFailure(t *testing.T) {
	src, srcEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := srcEnd.Close(); err != nil {
		t.Fatal(err)
	}
	r, wr, err := runtimePipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r)
	c := &inputCopy{src: src, srcFile: src, dst: wr, owned: src, done: make(chan struct{}), report: func(err error) {
		if err != nil {
			t.Error(err)
		}
	}}
	c.run()
	c.finish()
}
