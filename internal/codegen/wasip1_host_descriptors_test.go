//go:build darwin || linux

package codegen

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// hostDescriptorsEnv marks the process TestHostDescriptors starts to run
// TestHostDescriptorsInAProcess in: an instance whose descriptors are the
// host's changes where the runtime puts its descriptors for the rest of
// the process.
const hostDescriptorsEnv = "WASM2GO_HOST_DESCRIPTORS"

// TestHostDescriptors runs TestHostDescriptorsInAProcess in a process of
// its own, with a file of the test's as its standard input.
func TestHostDescriptors(t *testing.T) {
	if os.Getenv(hostDescriptorsEnv) != "" {
		t.Skip("this is the process of the tests")
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("standard input"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, in)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostDescriptorsInAProcess$", "-test.v")
	cmd.Env = append(os.Environ(), hostDescriptorsEnv+"=1")
	cmd.Stdin = in
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the process of the tests: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// newHostNumberedStubs returns an instance whose descriptors are the
// host's, with files as its Files and stdin as its standard input, closed
// when the test ends.
func newHostNumberedStubs(t *testing.T, files map[int32]*os.File, stdin *os.File) (*WasiStubs, *Module) {
	t.Helper()
	cfg := WASIConfig{
		FS:              newHostFS(t, t.TempDir()),
		Stdin:           bytes.NewReader(nil),
		Stdout:          &bytes.Buffer{},
		Stderr:          &bytes.Buffer{},
		Files:           files,
		HostDescriptors: true,
		Errors:          func(op string, err error) { t.Errorf("%s: %v", op, err) },
	}
	if stdin != nil {
		cfg.Stdin = stdin
	}
	w := NewWASI(cfg)
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	return w, newGuestModule(1 << 16)
}

// lowestFreeHost returns the lowest number the host process has free.
func lowestFreeHost(t *testing.T) int32 {
	t.Helper()
	for fd := 0; fd < hostDescriptorFloor; fd++ {
		if _, err := descriptorFlags(fd, syscall.F_GETFD); err != nil {
			return int32(fd)
		}
	}
	t.Fatal("no free number below the floor")
	return -1
}

// hostOpen reports whether the host process has descriptor fd open.
func hostOpen(fd int32) bool {
	_, err := descriptorFlags(int(fd), syscall.F_GETFD)
	return err == nil
}

// sameHostFile reports whether host descriptors a and b are open on one
// file.
func sameHostFile(t *testing.T, a, b int) bool {
	t.Helper()
	var sa, sb syscall.Stat_t
	if err := syscall.Fstat(a, &sa); err != nil {
		t.Fatalf("fstat %d: %v", a, err)
	}
	if err := syscall.Fstat(b, &sb); err != nil {
		t.Fatalf("fstat %d: %v", b, err)
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

// entryHostNumber returns the number of the descriptor of the entry behind
// the guest's fd.
func entryHostNumber(t *testing.T, w *WasiStubs, fd int32) int {
	t.Helper()
	w.mu.Lock()
	conn := w.entryHostConnLocked(w.fdTable[fd])
	w.mu.Unlock()
	if conn == nil {
		t.Fatalf("fd %d has no descriptor of the host", fd)
	}
	n := -1
	if err := withHostDescriptor(conn, func(d uintptr) error {
		n = int(d)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHostDescriptorsInAProcess is the process of TestHostDescriptors.
func TestHostDescriptorsInAProcess(t *testing.T) {
	if os.Getenv(hostDescriptorsEnv) == "" {
		t.Skip("run by TestHostDescriptors")
	}
	// A descriptor of the process's own, open before the first instance.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	reserved := -1
	if err := withHostDescriptor(null, func(fd uintptr) error {
		reserved, err = dupFrom(int(fd), 100)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := null.Close(); err != nil {
		t.Fatal(err)
	}

	// The end of an instance leaves the process's standard descriptors.
	t.Run("EndLeavesStandardStreams", func(t *testing.T) {
		w, _ := newHostNumberedStubs(t, nil, os.Stdin)
		if err := w.CloseAll(); err != nil {
			t.Fatal(err)
		}
		if !hostOpen(0) {
			t.Fatal("CloseAll closed the process's standard input")
		}
	})

	// The standard input of the process is the guest's descriptor 0, and
	// the guest's close of it closes the host's; a stream that is no file
	// of the host's under its number is no descriptor of the host's.
	t.Run("StandardStreams", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, os.Stdin)
		if host, ok := w.HostDescriptor(0); !ok || host != 0 {
			t.Fatalf("HostDescriptor(0) = %d, %v, want 0, true", host, ok)
		}
		if n := entryHostNumber(t, w, 0); n < hostDescriptorFloor {
			t.Fatalf("the entry of fd 0 is at %d, below the floor", n)
		}
		if _, ok := w.HostDescriptor(1); ok {
			t.Fatal("HostDescriptor(1) of a buffer is a descriptor")
		}
		if got, rc := fdReadString(w, m, 0, 64); rc != _wasiESUCCESS || got != "standard input" {
			t.Fatalf("read of fd 0 = %q, rc %d", got, rc)
		}
		closeTestFd(t, w, m, 0)
		if hostOpen(0) {
			t.Fatal("the host's descriptor 0 is open after the guest closed it")
		}
		if fd := createTestFile(t, w, "zero"); fd != 0 {
			t.Fatalf("the next file is %d, want 0", fd)
		}
		// (the end of the instance would leave it the process's)
		closeTestFd(t, w, m, 0)
	})

	// A standard stream that is a writer of the embedder's leaves the
	// process's descriptor 1 alone: a file the guest puts at 1 is its own.
	t.Run("StandardNumberOfTheGuestsOwn", func(t *testing.T) {
		before, ok := hostIdentityOf(1)
		if !ok {
			t.Skip("the process has no descriptor 1")
		}
		w, m := newHostNumberedStubs(t, nil, nil)
		fd := createTestFile(t, w, "out.txt")
		if rc := w.Fd_dup2(m, fd, 1); rc != _wasiESUCCESS {
			t.Fatalf("dup2 onto 1 rc=%d", rc)
		}
		if after, _ := hostIdentityOf(1); after != before {
			t.Fatal("the process's descriptor 1 was replaced")
		}
		if _, ok := w.HostDescriptor(1); ok {
			t.Fatal("HostDescriptor(1) names the process's descriptor")
		}
		if rc := fdWriteString(w, m, 1, "guest"); rc != _wasiESUCCESS {
			t.Fatalf("write rc=%d", rc)
		}
		closeTestFd(t, w, m, 1)
		if !hostOpen(1) {
			t.Fatal("the guest's close closed the process's descriptor 1")
		}
		if got, rc := fdReadString(w, m, mustOpenTestFile(t, w, "out.txt"), 16); rc != _wasiESUCCESS || got != "guest" {
			t.Fatalf("out.txt = %q, rc %d", got, rc)
		}
	})

	// The process's descriptor 0 is closed now (StandardStreams): a new
	// descriptor the host would give 0 leaves the guest's standard input
	// where it is.
	t.Run("StandardSlotWhoseNumberIsFree", func(t *testing.T) {
		// 0 is kept free while the instance's filesystem opens its root.
		keep, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		if entryHostNumberOf(t, keep) != 0 {
			t.Fatal("the process's descriptor 0 is open")
		}
		w, m := newHostNumberedStubs(t, nil, nil)
		if err := keep.Close(); err != nil {
			t.Fatal(err)
		}
		if fd := createTestFile(t, w, "a.txt"); fd == 0 {
			t.Fatal("the new file took the guest's standard input's number")
		}
		if got, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || got != "" {
			t.Fatalf("read of the standard input = %q, rc %d", got, rc)
		}
		if err := w.CloseAll(); err != nil {
			t.Fatal(err)
		}
		if hostOpen(0) {
			t.Fatal("the end of the instance left its descriptor 0 open")
		}
	})

	// The process's standard error is every instance's that has it: each
	// may put a file over it, and it is closed once none has it.
	t.Run("SharedStandardNumbers", func(t *testing.T) {
		saved, err := dupFrom(2, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := errors.Join(hostDupTo(saved, 2), syscall.Close(saved)); err != nil {
				t.Error(err)
			}
		})
		var ws [2]*WasiStubs
		var ms [2]*Module
		for i := range ws {
			ws[i], ms[i] = newHostNumberedStubs(t, nil, nil)
			ws[i].cfg.Stderr = os.Stderr
		}
		// both have it before either puts a file there
		for i, w := range ws {
			if host, ok := w.HostDescriptor(2); !ok || host != 2 {
				t.Fatalf("instance %d: HostDescriptor(2) = %d, %v before dup2", i, host, ok)
			}
		}
		for i, w := range ws {
			name := fmt.Sprintf("log%d.txt", i)
			fd := createTestFile(t, w, name)
			if rc := w.Fd_dup2(ms[i], fd, 2); rc != _wasiESUCCESS {
				t.Fatalf("instance %d: dup2 onto 2 rc=%d", i, rc)
			}
			if !sameHostFile(t, 2, int(fd)) {
				t.Fatalf("instance %d: the process's 2 is not %s", i, name)
			}
			if host, ok := w.HostDescriptor(2); !ok || host != 2 {
				t.Fatalf("instance %d: HostDescriptor(2) = %d, %v", i, host, ok)
			}
			closeTestFd(t, w, ms[i], fd)
		}
		closeTestFd(t, ws[0], ms[0], 2)
		if !hostOpen(2) {
			t.Fatal("one instance's close closed the descriptor the other has")
		}
		closeTestFd(t, ws[1], ms[1], 2)
		if hostOpen(2) {
			t.Fatal("the descriptor is open after every instance closed it")
		}
	})

	t.Run("NewDescriptors", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		want := lowestFreeHost(t)
		fd := createTestFile(t, w, "a.txt")
		if fd != want {
			t.Fatalf("first file = %d, want %d, the host's lowest free", fd, want)
		}
		if !sameHostFile(t, int(fd), entryHostNumber(t, w, fd)) {
			t.Fatal("the host's descriptor is not the file")
		}
		if n := entryHostNumber(t, w, fd); n < hostDescriptorFloor {
			t.Fatalf("the entry's own descriptor is at %d, below the floor", n)
		}
		if host, ok := w.HostDescriptor(fd); !ok || host != uintptr(fd) {
			t.Fatalf("HostDescriptor(%d) = %d, %v", fd, host, ok)
		}
		want = lowestFreeHost(t)
		r, wr := newTestPipe(t, w, m)
		if r != want || !hostOpen(r) || !hostOpen(wr) {
			t.Fatalf("pipe = %d, %d, want the read end at %d", r, wr, want)
		}
		// a write through the host's descriptor is read by the guest
		if _, err := syscall.Write(int(wr), []byte("host")); err != nil {
			t.Fatal(err)
		}
		if got, rc := fdReadString(w, m, r, 16); rc != _wasiESUCCESS || got != "host" {
			t.Fatalf("read = %q, rc %d", got, rc)
		}
		// an entry without a descriptor of the host's has a number of the
		// host's all the same, which no native code is given
		want = lowestFreeHost(t)
		w.mu.Lock()
		none := addTestFD(w, &wasiOpen{isSocket: true})
		w.mu.Unlock()
		if none != want || !hostOpen(none) {
			t.Fatalf("entry without a descriptor at %d, want %d, open", none, want)
		}
		if _, ok := w.HostDescriptor(none); ok {
			t.Fatal("HostDescriptor of an entry without a descriptor")
		}
		closeTestFd(t, w, m, none)
		if hostOpen(none) {
			t.Fatal("the number of a closed entry without a descriptor is open")
		}
		dup := dupTestFd(t, w, m, fd)
		if !sameHostFile(t, int(dup), int(fd)) {
			t.Fatal("the duplicate's host descriptor is not the file")
		}
		// closing the original, its duplicate open, frees the number
		closeTestFd(t, w, m, fd)
		if hostOpen(fd) {
			t.Fatalf("host's %d is open after the guest closed it", fd)
		}
		if again := createTestFile(t, w, "b.txt"); again != fd {
			t.Fatalf("next file = %d, want %d", again, fd)
		}
	})

	// An open that does not follow a link, of the whole host filesystem as
	// of a root, keeps the entry's own descriptor above the floor.
	t.Run("NoFollowOpen", func(t *testing.T) {
		w, _ := newHostNumberedStubs(t, nil, nil)
		w.cfg.FS = newHostFS(t, "/")
		fd := createTestFile(t, w, hostRelative(t, filepath.Join(t.TempDir(), "a.txt")))
		if n := entryHostNumber(t, w, fd); n < hostDescriptorFloor {
			t.Fatalf("the entry's own descriptor is at %d, below the floor", n)
		}
	})

	t.Run("Dup2", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		fd := createTestFile(t, w, "a.txt")
		if rc := w.Fd_dup2(m, fd, 20); rc != _wasiESUCCESS {
			t.Fatalf("dup2 onto 20 rc=%d", rc)
		}
		if !sameHostFile(t, 20, int(fd)) {
			t.Fatal("host's 20 is not the file")
		}
		other := createTestFile(t, w, "b.txt")
		if rc := w.Fd_dup2(m, other, 20); rc != _wasiESUCCESS {
			t.Fatalf("dup2 onto 20 again rc=%d", rc)
		}
		if !sameHostFile(t, 20, int(other)) {
			t.Fatal("host's 20 is not the second file")
		}
		if rc := w.Fd_renumber(m, 20, 21); rc != _wasiESUCCESS {
			t.Fatalf("renumber rc=%d", rc)
		}
		if hostOpen(20) || !sameHostFile(t, 21, int(other)) {
			t.Fatal("renumber left host's 20 open or 21 not the file")
		}
		if rc := w.Fd_dup2(m, fd, hostDescriptorFloor); rc != _wasiEBADF {
			t.Fatalf("dup2 onto the floor rc=%d, want EBADF", rc)
		}
		if rc := w.Fd_dup2(m, fd, int32(reserved)); rc != _wasiEBUSY {
			t.Fatalf("dup2 onto the process's %d rc=%d, want EBUSY", reserved, rc)
		}
	})

	// The guest's fd 3 is a number like any other, and a path call of
	// its root's number still names the root.
	t.Run("RootNumber", func(t *testing.T) {
		// 3 is kept free while the instance's filesystem opens its root, and
		// the free numbers below it are filled.
		var keep *os.File
		for keep == nil || entryHostNumberOf(t, keep) < 3 {
			if keep != nil {
				closeAtEnd(t, keep)
			}
			var err error
			if keep, err = os.Open(os.DevNull); err != nil {
				t.Fatal(err)
			}
		}
		if entryHostNumberOf(t, keep) != 3 {
			closeAtEnd(t, keep)
			t.Skip("the process has 3 open")
		}
		w, m := newHostNumberedStubs(t, nil, nil)
		if err := keep.Close(); err != nil {
			t.Fatal(err)
		}
		fd := createTestFile(t, w, "a.txt")
		if fd != wasiPreopenFD {
			t.Fatalf("first file = %d, want 3", fd)
		}
		if !w.preopened(wasiPreopenFD) {
			t.Fatal("3 no longer names the root for a path call")
		}
		if _, errno := w.pathOpen(nil, "a.txt", 0, 0, 1<<1, 0); errno != _wasiESUCCESS {
			t.Fatalf("open through the root errno=%d", errno)
		}
		// a forked instance's path calls name the root by 3 as well, and
		// 3 is a number like any other to it too
		child := w.Fork()
		t.Cleanup(func() {
			if err := child.CloseAll(); err != nil {
				t.Errorf("child CloseAll: %v", err)
			}
		})
		cm := newForkTestModule()
		if rc := pathOpenAt(child, cm, wasiPreopenFD, "a.txt"); rc != _wasiESUCCESS {
			t.Fatalf("the child's open through 3 rc=%d", rc)
		}
		closeTestFd(t, child, cm, wasiPreopenFD)
		if got := createTestFile(t, child, "c.txt"); got != wasiPreopenFD {
			t.Fatalf("the child's next file after closing 3 is %d", got)
		}
		closeTestFd(t, w, m, wasiPreopenFD)
		want := lowestFreeHost(t)
		if got := createTestFile(t, w, "b.txt"); got != want {
			t.Fatalf("the next file is %d, want %d", got, want)
		}
	})

	t.Run("RuntimeDescriptors", func(t *testing.T) {
		w, _ := newHostNumberedStubs(t, nil, nil)
		wk, err := w.takeWake()
		if err != nil {
			t.Fatal(err)
		}
		if wk.r < hostDescriptorFloor || wk.w < hostDescriptorFloor {
			t.Fatalf("wake pipe at %d, %d", wk.r, wk.w)
		}
		if err := w.giveWake(wk, nil); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, f)
		dup, err := duplicateDescriptor(f)
		if err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, dup)
		if dup < hostDescriptorFloor {
			t.Fatalf("duplicate at %d", dup)
		}
		r, wr, err := runtimePipe()
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, r)
		closeAtEnd(t, wr)
		for _, f := range []*os.File{r, wr} {
			if n := entryHostNumberOf(t, f); n < hostDescriptorFloor {
				t.Fatalf("command pipe at %d", n)
			}
		}
	})

	// The sockets of the guest's — made, of a pair, accepted — are the
	// guest's numbers, their own descriptors above the floor.
	t.Run("GuestSockets", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lf, err := listener.(*net.TCPListener).File()
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		w, m := newHostNumberedStubs(t, map[int32]*os.File{40: lf}, nil)
		w.cfg.NetAccess = AllowAllNetAccess
		s := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
		if s < 0 {
			t.Fatalf("Sock_open = %d", s)
		}
		if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, 5000); rc != _wasiESUCCESS {
			t.Fatalf("Sock_socketpair rc=%d", rc)
		}
		a, b := int32(readU32(m.memory, 5000)), int32(readU32(m.memory, 5004))
		conn, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		})
		if rc := w.Sock_accept(m, 40, 0, 5100); rc != _wasiESUCCESS {
			t.Fatalf("Sock_accept rc=%d", rc)
		}
		accepted := int32(readU32(m.memory, 5100))
		for _, fd := range []int32{s, a, b, accepted} {
			if n := entryHostNumber(t, w, fd); n < hostDescriptorFloor || !sameHostFile(t, n, int(fd)) {
				t.Fatalf("socket %d: its own descriptor is at %d", fd, n)
			}
		}
	})

	// What the runtime keeps of a running command is above the guests'
	// numbers: a guest that closes every number of its own does not take
	// the command's status from its wait.
	t.Run("RunningCommand", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		w.cfg.Exec = AllowAllExec
		// The copy of the command's input tells Errors of its end as a
		// failure (inputCopy.finish), a fault of its own: not looked at here.
		w.cfg.Errors = nil
		r, wr := newTestPipe(t, w, m)
		_, out := newTestPipe(t, w, m)
		before, err := openHostDescriptors()
		if err != nil {
			t.Fatal(err)
		}
		pid := spawnWithStreams(t, w, m, r, out, out, "/bin/sh", "-c", "read x; exit 7")
		after, err := openHostDescriptors()
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range after {
			if fd < hostDescriptorFloor && !slices.Contains(before, fd) {
				t.Errorf("descriptor %d below the floor made for the running command", fd)
			}
		}
		for fd := int32(3); fd < hostDescriptorFloor; fd++ {
			if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS && rc != _wasiEBADF {
				t.Fatalf("close of %d rc=%d", fd, rc)
			}
		}
		_ = wr // closed by the loop: the command's input ends
		const statusOff int32 = 4004
		if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
		if status := readU32(m.memory, int(statusOff)); status != 7<<8 {
			t.Fatalf("wait status = %#x, want an exit of 7", status)
		}
	})

	// A descriptor made outside the guest after the instance is the
	// guest's by its number; one the process had before is not.
	t.Run("Adopt", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		var p [2]int
		if err := syscall.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, p[1])
		if _, err := syscall.Write(p[1], []byte("native")); err != nil {
			t.Fatal(err)
		}
		if got, rc := fdReadString(w, m, int32(p[0]), 16); rc != _wasiESUCCESS || got != "native" {
			t.Fatalf("read of the outside descriptor = %q, rc %d", got, rc)
		}
		closeTestFd(t, w, m, int32(p[0]))
		if hostOpen(int32(p[0])) {
			t.Fatal("the guest's close left the outside descriptor open")
		}
		if rc := w.Fd_close(m, int32(reserved)); rc != _wasiEBADF || !hostOpen(int32(reserved)) {
			t.Fatalf("close of the process's %d rc=%d", reserved, rc)
		}
		// Once the process closed it, its number is nobody's: what is made
		// there next is the guest's to take.
		if err := syscall.Close(reserved); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, p[1])
		if err := hostDupTo(p[0], reserved); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Close(p[0]); err != nil {
			t.Fatal(err)
		}
		closeTestFd(t, w, m, int32(reserved))
		if hostOpen(int32(reserved)) {
			t.Fatal("the guest's close left the new descriptor open")
		}
	})

	// A descriptor taken in that code outside the guest closes is the
	// guest's no longer: the guest finds what the host has under the number
	// now, and its close of a number the host has nothing under closes
	// nothing. A socket taken in keeps its mode.
	t.Run("AdoptedAndClosedOutside", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		var p [2]int
		if err := syscall.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		if ft := fdFiletype(t, w, m, int32(p[0])); ft == 0 {
			t.Fatal("the outside descriptor was not taken in")
		}
		if err := errors.Join(syscall.Close(p[0]), syscall.Close(p[1])); err != nil {
			t.Fatal(err)
		}
		var q [2]int
		if err := syscall.Pipe(q[:]); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, q[1])
		if q[0] != p[0] {
			t.Fatalf("the new pipe is at %d, not %d", q[0], p[0])
		}
		if _, err := syscall.Write(q[1], []byte("new")); err != nil {
			t.Fatal(err)
		}
		if got, rc := fdReadString(w, m, int32(q[0]), 16); rc != _wasiESUCCESS || got != "new" {
			t.Fatalf("read = %q, rc %d: not what the host has now", got, rc)
		}
		// closed outside again, nothing under the number: the guest's
		// close is EBADF, and the number the host gives next is untouched
		w.mu.Lock()
		taken := w.openLocked(int32(q[0])) != nil
		w.mu.Unlock()
		if !taken {
			t.Fatal("the new descriptor was not taken in")
		}
		if err := syscall.Close(q[0]); err != nil {
			t.Fatal(err)
		}
		if rc := w.Fd_close(m, int32(q[0])); rc != _wasiEBADF {
			t.Fatalf("close of a number closed outside rc=%d, want EBADF", rc)
		}
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, fds[1])
		if ft := fdFiletype(t, w, m, int32(fds[0])); ft != 6 { // SOCKET_STREAM
			t.Fatalf("the outside socket's filetype %d", ft)
		}
		if flags, err := descriptorFlags(fds[0], syscall.F_GETFL); err != nil || flags&syscall.O_NONBLOCK != 0 {
			t.Fatalf("the outside socket's flags %#x, %v: its mode changed", flags, err)
		}
		closeTestFd(t, w, m, int32(fds[0]))
		// a listening socket taken in, in blocking mode, accepts; the
		// connection is above the floor
		lfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Bind(lfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Listen(lfd, 1); err != nil {
			t.Fatal(err)
		}
		sa, err := syscall.Getsockname(lfd)
		if err != nil {
			t.Fatal(err)
		}
		dialed, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", sa.(*syscall.SockaddrInet4).Port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := dialed.Close(); err != nil {
				t.Error(err)
			}
		})
		w.cfg.NetAccess = AllowAllNetAccess
		if rc := w.Sock_accept(m, int32(lfd), 0, 5100); rc != _wasiESUCCESS {
			t.Fatalf("accept on the outside listening socket rc=%d", rc)
		}
		if n := entryHostNumber(t, w, int32(readU32(m.memory, 5100))); n < hostDescriptorFloor {
			t.Fatalf("the accepted connection's own descriptor is at %d", n)
		}
		closeTestFd(t, w, m, int32(lfd))
		// taken in and closed outside, then never used: the end of the
		// instance closes nothing under the number (CloseAll, at cleanup)
		var gone [2]int
		if err := syscall.Pipe(gone[:]); err != nil {
			t.Fatal(err)
		}
		if ft := fdFiletype(t, w, m, int32(gone[0])); ft == 0 {
			t.Fatal("the outside descriptor was not taken in")
		}
		if err := errors.Join(syscall.Close(gone[0]), syscall.Close(gone[1])); err != nil {
			t.Fatal(err)
		}
	})

	// The guest that closed the process's standard error and opened a file
	// there leaves it the process's at its end; another instance whose
	// stream that is takes the number as its own stream's when an instance
	// holds a descriptor of its own there.
	t.Run("StandardNumberReopened", func(t *testing.T) {
		saved, err := dupFrom(2, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := errors.Join(hostDupTo(saved, 2), syscall.Close(saved)); err != nil {
				t.Error(err)
			}
		})
		w, m := newHostNumberedStubs(t, nil, nil)
		w.cfg.Stderr = os.Stderr
		closeTestFd(t, w, m, 2)
		if fd := createTestFile(t, w, "err.txt"); fd != 2 {
			t.Fatalf("the file after closing 2 is %d", fd)
		}
		if err := w.CloseAll(); err != nil {
			t.Fatal(err)
		}
		if !hostOpen(2) {
			t.Fatal("the end of the instance closed the process's 2")
		}
		// the process's 2 closed again; an instance of its own standard
		// error gets it as a placeholder, then puts a file over it
		a, am := newHostNumberedStubs(t, nil, nil)
		b, _ := newHostNumberedStubs(t, nil, nil)
		b.cfg.Stderr = os.Stderr
		if err := syscall.Close(2); err != nil {
			t.Fatal(err)
		}
		if fd := createTestFile(t, a, "a.txt"); fd == 2 {
			t.Fatal("a's file took its own standard error's number")
		}
		if _, ok := b.HostDescriptor(2); ok {
			t.Fatal("b took a's placeholder at 2 for its standard error")
		}
		fd := createTestFile(t, a, "a2.txt")
		if rc := a.Fd_dup2(am, fd, 2); rc != _wasiESUCCESS {
			t.Fatalf("a's dup2 onto 2 rc=%d", rc)
		}
		if host, ok := a.HostDescriptor(2); !ok || host != 2 || !sameHostFile(t, 2, int(fd)) {
			t.Fatalf("a's HostDescriptor(2) = %d, %v: not its file", host, ok)
		}
	})

	// A file of Files that cannot be taken in when the instance is made is
	// told Errors with no lock held.
	t.Run("StartFailure", func(t *testing.T) {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		var told []string
		w := NewWASI(WASIConfig{
			FS:              newHostFS(t, t.TempDir()),
			Files:           map[int32]*os.File{60: f},
			HostDescriptors: true,
			Errors: func(op string, err error) {
				told = append(told, op)
				if !hostTable.mu.TryLock() {
					t.Errorf("%s: Errors told with hostTable.mu held", op)
					return
				}
				hostTable.mu.Unlock()
			},
		})
		if len(told) == 0 || told[0] != "host_descriptors" {
			t.Fatalf("told %q, want host_descriptors first", told)
		}
		if err := w.CloseAll(); err != nil {
			t.Fatal(err)
		}
	})

	// A file of Files is the guest's under its number, at a standard
	// number as well (0, which StandardStreams closed).
	for _, at := range []int32{50, 0} {
		t.Run(fmt.Sprintf("Files%d", at), func(t *testing.T) {
			if hostOpen(at) {
				t.Fatalf("the process has %d open", at)
			}
			var p [2]int
			if err := syscall.Pipe(p[:]); err != nil {
				t.Fatal(err)
			}
			closeFDAtEnd(t, p[1])
			if p[0] != int(at) {
				if err := errors.Join(hostDupTo(p[0], int(at)), syscall.Close(p[0])); err != nil {
					t.Fatal(err)
				}
			}
			w, m := newHostNumberedStubs(t, map[int32]*os.File{at: os.NewFile(uintptr(at), "inherited")}, nil)
			if _, err := syscall.Write(p[1], []byte("inherited")); err != nil {
				t.Fatal(err)
			}
			if got, rc := fdReadString(w, m, at, 16); rc != _wasiESUCCESS || got != "inherited" {
				t.Fatalf("read of the file = %q, rc %d", got, rc)
			}
			if n := entryHostNumber(t, w, at); n < hostDescriptorFloor || !sameHostFile(t, n, int(at)) {
				t.Fatalf("the entry's descriptor %d", n)
			}
			closeTestFd(t, w, m, at)
			if hostOpen(at) {
				t.Fatal("the guest's close left the file's descriptor open")
			}
		})
	}

	// A forked instance numbers its own descriptors; its close of one it
	// inherited leaves the parent's descriptor of the host.
	t.Run("Fork", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		fd := createTestFile(t, w, "a.txt")
		child := w.Fork()
		t.Cleanup(func() {
			if err := child.CloseAll(); err != nil {
				t.Errorf("child CloseAll: %v", err)
			}
		})
		cm := newForkTestModule()
		closeTestFd(t, child, cm, fd)
		if !hostOpen(fd) {
			t.Fatal("the child's close closed the parent's descriptor")
		}
		// the lowest number free in the child's own table, whatever the
		// host has there; 3 is a number like any other
		want := int32(0)
		child.mu.Lock()
		for child.fdTable[want] != nil {
			want++
		}
		child.mu.Unlock()
		got := createTestFile(t, child, "b.txt")
		if got != want {
			t.Fatalf("the child's next file is %d, want %d, its own lowest", got, want)
		}
		if n := entryHostNumber(t, child, got); n < hostDescriptorFloor {
			t.Fatalf("the child's entry is at %d", n)
		}
		if !sameHostFile(t, int(fd), entryHostNumber(t, w, fd)) {
			t.Fatal("the parent's descriptor is not its file")
		}
		closeTestFd(t, w, m, fd)
	})

	// A FIFO opened without waiting, whose file is made anew when it is
	// moved up: where poll(2) reports the end of a FIFO's input the Go
	// runtime polls it in non-blocking mode; elsewhere it is in blocking
	// mode and not polled. Either way the close of the FIFO while a read
	// waits for it returns.
	t.Run("FIFOOpenedWithoutWaiting", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fifo")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		w := NewWASI(WASIConfig{
			FS:              newHostFS(t, dir),
			Stdin:           bytes.NewReader(nil),
			Stdout:          &bytes.Buffer{},
			Stderr:          &bytes.Buffer{},
			HostDescriptors: true,
			Errors:          func(op string, err error) { t.Errorf("%s: %v", op, err) },
		})
		t.Cleanup(func() {
			if err := w.CloseAll(); err != nil {
				t.Errorf("CloseAll: %v", err)
			}
		})
		m := newGuestModule(1 << 16)
		fd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<1, wasiFdflagNonblock)
		if errno != _wasiESUCCESS {
			t.Fatalf("open errno=%d", errno)
		}
		writer, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, writer)
		op := entryOf(t, w, fd)
		polled := true
		switch err := op.f.(*os.File).SetReadDeadline(time.Time{}); {
		case errors.Is(err, os.ErrNoDeadline):
			polled = false
		case err != nil:
			t.Fatal(err)
		}
		nonblocking := openFileFlags(t, w, fd)&syscall.O_NONBLOCK != 0
		if polled != hostPollReportsFIFOEnd || op.polled != polled || nonblocking != polled {
			t.Fatalf("the FIFO's file is polled %v (entry %v), non-blocking %v; want all %v", polled, op.polled, nonblocking, hostPollReportsFIFOEnd)
		}
		if rc := w.Fd_fdstat_set_flags(m, fd, 0); rc != _wasiESUCCESS {
			t.Fatalf("clear O_NONBLOCK rc=%d", rc)
		}
		read := readAsync(w, newForkTestModule(), fd)
		// The read waits: in the Go runtime's poller as a blocking call, or
		// in the read itself, holding the turn at the input.
		waiting := make(chan struct{})
		go func() {
			defer close(waiting)
			if polled {
				awaitBlockedCalls(w, 1)
				return
			}
			for len(op.inputTurn()) == 0 {
				runtime.Gosched()
			}
		}()
		within(t, "the read's wait", waiting)
		closed := make(chan int32, 1)
		go func() { closed <- w.Fd_close(m, fd) }()
		if rc := within(t, "fd_close while a read waits", closed); rc != _wasiESUCCESS {
			t.Fatalf("close rc=%d", rc)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		within(t, "the read", read)
	})
}

// mustOpenTestFile opens name for reading through pathOpen and returns the
// new fd.
func mustOpenTestFile(t *testing.T, w *WasiStubs, name string) int32 {
	t.Helper()
	fd, errno := w.pathOpen(nil, name, 0, 0, 1<<1 /* FD_READ */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen(%s) errno=%d", name, errno)
	}
	return fd
}

// pathOpenAt opens name for reading relative to directory descriptor dir
// through Path_open and returns the errno.
func pathOpenAt(w *WasiStubs, m *Module, dir int32, name string) int32 {
	off, n := putPath(m, 6000, name)
	return w.Path_open(m, dir, 0, off, n, 0, 1<<1, 0, 0, 6100)
}

// closeFDAtEnd closes descriptor fd when the test ends.
func closeFDAtEnd(t *testing.T, fd int) {
	t.Cleanup(func() {
		if err := syscall.Close(fd); err != nil {
			t.Error(err)
		}
	})
}

// entryHostNumberOf returns the number of f's descriptor.
func entryHostNumberOf(t *testing.T, f *os.File) int {
	t.Helper()
	n := -1
	if err := withHostDescriptor(f, func(d uintptr) error {
		n = int(d)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// A file of Files is the guest's under its number, a socket a socket of the
// host's in non-blocking mode, in an instance with descriptors of its own.
func TestFilesAreTheGuests(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeFDAtEnd(t, fds[1])
	w, m := newProcTestStubs(t)
	w.cfg.Files = map[int32]*os.File{7: os.NewFile(uintptr(fds[0]), "socket")}
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	if ft := fdFiletype(t, w, m, 7); ft != 6 { // SOCKET_STREAM
		t.Fatalf("filetype of 7 = %d, want a stream socket", ft)
	}
	if hostOpen(int32(fds[0])) {
		t.Fatal("the given file is still open: the instance did not take it over")
	}
	host, ok := w.HostDescriptor(7)
	if !ok {
		t.Fatal("HostDescriptor(7) is none")
	}
	if flags, err := descriptorFlags(int(host), syscall.F_GETFL); err != nil || flags&syscall.O_NONBLOCK == 0 {
		t.Fatalf("the socket's flags %#x, %v: not non-blocking", flags, err)
	}
	if _, err := syscall.Write(fds[1], []byte("given")); err != nil {
		t.Fatal(err)
	}
	if got, rc := fdReadString(w, m, 7, 16); rc != _wasiESUCCESS || got != "given" {
		t.Fatalf("read of 7 = %q, rc %d", got, rc)
	}
	closeTestFd(t, w, m, 7)
	if hostOpen(int32(host)) {
		t.Fatal("the guest's close left the socket open")
	}
}

// A failure found with the instance's lock held, a file of Files that
// cannot be taken over, is told Errors as soon as the lock is let go.
func TestFilesFailureIsToldWithoutTheLock(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	var told []string
	var w *WasiStubs
	w = NewWASI(WASIConfig{
		Files: map[int32]*os.File{-1: f},
		Errors: func(op string, err error) {
			told = append(told, op)
			if !w.mu.TryLock() {
				t.Errorf("%s: Errors told with the lock held", op)
				return
			}
			w.mu.Unlock()
		},
	})
	m := newGuestModule(1 << 16)
	if rc := w.Fd_close(m, 9); rc != _wasiEBADF {
		t.Fatalf("close of 9 rc=%d", rc)
	}
	if len(told) != 1 || told[0] != "files" {
		t.Fatalf("told %q once the call let the lock go, want files", told)
	}
	if err := w.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the file of a number out of range is not closed: %v", err)
	}
}

// hostPollerEnv marks the process TestHostDescriptorsPoller starts.
const hostPollerEnv = "WASM2GO_HOST_DESCRIPTORS_POLLER"

// The descriptors the Go runtime makes for its poller are made, and
// recorded as the process's own, when the first instance whose descriptors
// are the host's is made: a file polled afterwards makes none below the
// guests' numbers. It runs in a process of its own that has polled nothing
// before.
func TestHostDescriptorsPoller(t *testing.T) {
	if os.Getenv(hostPollerEnv) != "" {
		t.Skip("this is the process of the test")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostDescriptorsPollerInAProcess$", "-test.v")
	cmd.Env = append(os.Environ(), hostPollerEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the process of the test: %v\n%s", err, out)
	}
}

// TestHostDescriptorsPollerInAProcess is the process of
// TestHostDescriptorsPoller.
func TestHostDescriptorsPollerInAProcess(t *testing.T) {
	if os.Getenv(hostPollerEnv) == "" {
		t.Skip("run by TestHostDescriptorsPoller")
	}
	w := NewWASI(WASIConfig{HostDescriptors: true, Errors: func(op string, err error) { t.Errorf("%s: %v", op, err) }})
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	before, err := openHostDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(r.Close(), wr.Close()); err != nil {
		t.Fatal(err)
	}
	after, err := openHostDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before, after) {
		t.Fatalf("descriptors before a pipe %v, after %v: the poller was made later", before, after)
	}
}
