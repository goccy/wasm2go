//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

	// The directories of the FS tests below: d, with a link out of it to a
	// file of the root beside it.
	rootDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../f", filepath.Join(rootDir, "d", "up")); err != nil {
		t.Fatal(err)
	}

	// Once an instance has the host's descriptors, the descriptors of the
	// FSes of directories of HostFS's, and of a HostFS of a directory, are
	// open above the guests' numbers, and work as they do before.
	t.Run("DirectoryFSes", func(t *testing.T) {
		newHostNumberedStubs(t, nil, nil)
		closeFS := func(fsys FS) {
			t.Cleanup(func() {
				if err := fsys.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		whole, err := osFS{}.OpenRoot(hostRelative(t, rootDir) + "/d")
		if err != nil {
			t.Fatal(err)
		}
		closeFS(whole)
		hostFS, err := HostFS(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		closeFS(hostFS)
		confined, err := hostFS.(OpenRootFS).OpenRoot("d")
		if err != nil {
			t.Fatal(err)
		}
		closeFS(confined)
		for name, f := range map[string]*os.File{"the whole host's directory FS": whole.(osDir).f, "a HostFS of a directory's root": hostFS.(rootFS).at, "its directory FS": confined.(hostDir).f} {
			if n := entryHostNumberOf(t, f); n < hostDescriptorFloor {
				t.Errorf("%s is at %d, below the floor", name, n)
			}
		}
		if _, err := confined.Stat("up"); err != nil {
			t.Errorf("Stat(up) of a HostFS of a directory's directory FS: %v", err)
		}
		// Without the os.Root of the directory, whose descriptor cannot be
		// moved above them, its names are found from the root as the name
		// the directory has now: renamed, another directory taking its old
		// name, a file it makes is made in it.
		if confined.(hostDir).in != nil {
			t.Error("a HostFS of a directory's directory FS holds an os.Root of it")
		}
		if err := os.Rename(filepath.Join(rootDir, "d"), filepath.Join(rootDir, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(rootDir, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := confined.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(rootDir, "moved", "x")); err != nil {
			t.Errorf("x is not in the directory the FS is of: %v", err)
		}
		if err := errors.Join(os.Remove(filepath.Join(rootDir, "d")), os.Rename(filepath.Join(rootDir, "moved"), filepath.Join(rootDir, "d")), os.Remove(filepath.Join(rootDir, "d", "x"))); err != nil {
			t.Fatal(err)
		}
	})

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
		// given in blocking mode, which the guest keeps
		if err := syscall.SetNonblock(entryHostNumberOf(t, lf), false); err != nil {
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
		if blocking, err := descriptorBlocks(40); err != nil || !blocking {
			t.Fatalf("the listening socket of Files is not in blocking mode (%v)", err)
		}
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
		r, wr := newTestPipe(t, w, m)
		_, out := newTestPipe(t, w, m)
		// the command is not to have the input's other end
		if rc := w.Fd_cloexec(m, wr, 1, 1, 6200); rc != _wasiESUCCESS {
			t.Fatalf("Fd_cloexec rc=%d", rc)
		}
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

	// The guest's mode is its descriptions': what it makes is in blocking
	// mode until it asks for non-blocking, and code outside the guest finds
	// the mode the guest set. A call that waits on a description in
	// blocking mode waits in the runtime, where a signal ends it.
	t.Run("GuestModes", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		w.cfg.NetAccess, w.cfg.Listen, w.cfg.Dial = AllowAllNetAccess, AllowAllListen, AllowAllDial
		if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
			t.Fatalf("Proc_signal_register rc=%d", rc)
		}
		setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
		blocks := func(fd int32) bool {
			t.Helper()
			blocking, err := descriptorBlocks(int(fd))
			if err != nil {
				t.Fatal(err)
			}
			return blocking
		}
		r, wr := newTestPipe(t, w, m)
		if !blocks(r) || !blocks(wr) {
			t.Fatal("a pipe of the guest's is not in blocking mode")
		}
		if rc := w.Fd_fdstat_set_flags(m, r, wasiFdflagNonblock); rc != _wasiESUCCESS || blocks(r) {
			t.Fatalf("NONBLOCK rc=%d: the description is not non-blocking", rc)
		}
		if _, rc := fdReadString(w, m, r, 8); rc != _wasiEAGAIN {
			t.Fatalf("read of an empty non-blocking pipe rc=%d, want EAGAIN", rc)
		}
		if rc := w.Fd_fdstat_set_flags(m, r, 0); rc != _wasiESUCCESS || !blocks(r) {
			t.Fatalf("clearing NONBLOCK rc=%d: the description is not blocking", rc)
		}
		postWhenBlocked(w, wasiSIGUSR1)
		if _, rc := fdReadString(w, m, r, 8); rc != _wasiEINTR {
			t.Fatalf("read of an empty blocking pipe with a signal rc=%d, want EINTR", rc)
		}
		takeSignals(t, w, m)
		if _, err := syscall.Write(int(wr), []byte("data")); err != nil {
			t.Fatal(err)
		}
		if got, rc := fdReadString(w, m, r, 8); rc != _wasiESUCCESS || got != "data" {
			t.Fatalf("read = %q, rc %d", got, rc)
		}
		if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, 5000); rc != _wasiESUCCESS {
			t.Fatalf("Sock_socketpair rc=%d", rc)
		}
		pa := int32(readU32(m.memory, 5000))
		if !blocks(pa) || !blocks(int32(readU32(m.memory, 5004))) {
			t.Fatal("a socket pair of the guest's is not in blocking mode")
		}
		// a send that finds no room waits in the runtime
		if rc := w.Fd_fdstat_set_flags(m, pa, wasiFdflagNonblock); rc != _wasiESUCCESS {
			t.Fatalf("NONBLOCK rc=%d", rc)
		}
		chunk := string(make([]byte, 4096))
		for {
			rc := fdWriteString(w, m, pa, chunk)
			if rc == _wasiEAGAIN {
				break
			}
			if rc != _wasiESUCCESS {
				t.Fatalf("write rc=%d", rc)
			}
		}
		if rc := w.Fd_fdstat_set_flags(m, pa, 0); rc != _wasiESUCCESS {
			t.Fatalf("clearing NONBLOCK rc=%d", rc)
		}
		// (darwin's send that waits waits in the kernel, as MSG_DONTWAIT
		// does not keep it from waiting there)
		if hostSendsWithoutWaiting {
			postWhenBlocked(w, wasiSIGUSR1)
			if rc := fdWriteString(w, m, pa, chunk); rc != _wasiEINTR {
				t.Fatalf("write to a full blocking socket with a signal rc=%d, want EINTR", rc)
			}
			takeSignals(t, w, m)
		}
		listener, port := newIPListener(t, w, m)
		if !blocks(listener) {
			t.Fatal("a listening socket of the guest's is not in blocking mode")
		}
		postWhenBlocked(w, wasiSIGUSR1)
		if rc := w.Sock_accept(m, listener, 0, 5100); rc != _wasiEINTR {
			t.Fatalf("accept with nobody connecting and a signal rc=%d, want EINTR", rc)
		}
		takeSignals(t, w, m)
		client := connectTo(t, w, m, port)
		if !blocks(client) {
			t.Fatal("the connected socket is not in blocking mode")
		}
		if rc := w.Sock_accept(m, listener, 0, 5100); rc != _wasiESUCCESS {
			t.Fatalf("accept rc=%d", rc)
		}
		if !blocks(listener) || !blocks(int32(readU32(m.memory, 5100))) {
			t.Fatal("the listening or the accepted socket is not in blocking mode")
		}
		fd, errno := w.pathOpen(nil, "plain.txt", 0, 0x1 /* O_CREAT */, 1<<6, wasiFdflagNonblock)
		if errno != _wasiESUCCESS || blocks(fd) {
			t.Fatalf("open with NONBLOCK errno=%d: the description is not non-blocking", errno)
		}
		// A file whose descriptor is above the guests' numbers already is
		// given to package os anew all the same, once in the guest's mode.
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, pw)
		high := -1
		rc, err := pr.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var dupErr error
		if err := rc.Control(func(d uintptr) { high, dupErr = dupFrom(int(d), hostDescriptorFloor+100) }); err != nil || dupErr != nil {
			t.Fatal(err, dupErr)
		}
		if err := pr.Close(); err != nil {
			t.Fatal(err)
		}
		gf, err := w.guestFile(os.NewFile(uintptr(high), "high"), false)
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, gf)
		if err := gf.SetReadDeadline(time.Time{}); !errors.Is(err, os.ErrNoDeadline) {
			t.Fatalf("a file put in blocking mode is still polled by the Go runtime (%v)", err)
		}
	})

	// A call of the guest's that waits does so in the runtime, never in
	// the kernel, whatever the mode of the description, so that a signal
	// ends it: where the host has a write that does not wait in one call
	// (Linux), a write to a full pipe in blocking mode, which reports what
	// it wrote once it wrote something; an accept and, where MSG_DONTWAIT
	// does not keep a send from waiting, a send that is not to wait, each
	// made by the holder of a turn; a send with room for it whole; and on Linux, a read of a FIFO the guest put in blocking mode
	// after the Go runtime's poller took it, and a connect the host waits
	// in, which goes on in the host.
	t.Run("WaitsInTheRuntime", func(t *testing.T) {
		w, m := newHostNumberedStubs(t, nil, nil)
		w.cfg.FS, w.cfg.NetAccess, w.cfg.Listen, w.cfg.Dial = osFS{}, AllowAllNetAccess, AllowAllListen, AllowAllDial
		if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
			t.Fatalf("Proc_signal_register rc=%d", rc)
		}
		setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)

		// writes of more than the pipe's buffer holds at first, which the
		// host grows for them, go through before anything is read, and are
		// read whole
		big0, big1 := newTestPipe(t, w, m)
		const big, piece = 20000, 1000
		chunk := string(make([]byte, piece))
		for written := 0; written < big; written += piece {
			var rc int32
			returnsWithin(t, "Fd_write", func() { rc = fdWriteString(w, m, big1, chunk) })
			if rc != _wasiESUCCESS {
				t.Fatalf("write after %d bytes to a blocking pipe rc=%d", written, rc)
			}
		}
		for got := 0; got < big; {
			s, rc := fdReadString(w, m, big0, 8192)
			if rc != _wasiESUCCESS || s == "" {
				t.Fatalf("read after %d bytes rc=%d", got, rc)
			}
			got += len(s)
		}

		// where a write that waits is made in steps (hostWritesWithoutWaiting)
		if hostWritesWithoutWaiting {
			r, wr := newTestPipe(t, w, m)
			// filled through the host's descriptor (the guest's number), in
			// non-blocking mode for the fill only
			if err := syscall.SetNonblock(int(wr), true); err != nil {
				t.Fatal(err)
			}
			for {
				if _, err := syscall.Write(int(wr), []byte{0}); errors.Is(err, syscall.EAGAIN) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.SetNonblock(int(wr), false); err != nil {
				t.Fatal(err)
			}
			postWhenBlocked(w, wasiSIGUSR1)
			if rc := fdWriteString(w, m, wr, "x"); rc != _wasiEINTR {
				t.Fatalf("write to a full blocking pipe with a signal rc=%d, want EINTR", rc)
			}
			takeSignals(t, w, m)
			if _, err := syscall.Read(int(r), make([]byte, 8192)); err != nil {
				t.Fatal(err)
			}
			postWhenBlocked(w, wasiSIGUSR1)
			if n, rc := writeChunk(t, w, m, wr); rc != _wasiESUCCESS || n == 0 || n >= uint32(wsChunk) {
				t.Fatalf("interrupted write to a blocking pipe: %d bytes rc=%d, want part of %d", n, rc, wsChunk)
			}
			takeSignals(t, w, m)
		}

		listener, port := newIPListener(t, w, m)
		connectTo(t, w, m, port)
		turn := entryOf(t, w, listener).inputTurn()
		turn <- struct{}{} // another accept of the guest's is being made
		accepted := make(chan int32, 1)
		go func() { accepted <- w.Sock_accept(newForkTestModule(), listener, 0, 5100) }()
		if blocked, rc := blockedOrDone(t, w, accepted); !blocked {
			t.Fatalf("the accept went through (rc=%d) while another held the turn", rc)
		}
		<-turn
		if rc := within(t, "sock_accept", accepted); rc != _wasiESUCCESS {
			t.Fatalf("accept rc=%d", rc)
		}

		// a send to a socket in blocking mode with room for it whole goes
		// through, however little room it has
		if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, 5000); rc != _wasiESUCCESS {
			t.Fatalf("Sock_socketpair rc=%d", rc)
		}
		qa, qb := int32(readU32(m.memory, 5000)), int32(readU32(m.memory, 5004))
		for _, size := range []int{6500, 500} {
			var rc int32
			returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, qa, string(make([]byte, size))) })
			if rc != _wasiESUCCESS {
				t.Fatalf("send of %d bytes rc=%d", size, rc)
			}
		}
		for got := 0; got < 7000; {
			s, rc := fdReadString(w, m, qb, 8192)
			if rc != _wasiESUCCESS || s == "" {
				t.Fatalf("receive after %d bytes rc=%d", got, rc)
			}
			got += len(s)
		}

		// where MSG_DONTWAIT does not keep a send from waiting (darwin), a
		// send that is not to wait to a description in blocking mode (the
		// guest's NONBLOCK, the description put back in blocking mode by
		// code outside the guest) is made by the holder of the turn once
		// poll(2) has found room, no more than the low-water mark at a time
		if !hostSendsWithoutWaiting {
			if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, 5000); rc != _wasiESUCCESS {
				t.Fatalf("Sock_socketpair rc=%d", rc)
			}
			pa, pb := int32(readU32(m.memory, 5000)), int32(readU32(m.memory, 5004))
			if rc := w.Fd_fdstat_set_flags(m, pa, wasiFdflagNonblock); rc != _wasiESUCCESS {
				t.Fatalf("NONBLOCK rc=%d", rc)
			}
			if err := syscall.SetNonblock(int(pa), false); err != nil {
				t.Fatal(err)
			}
			turn := entryOf(t, w, pa).outputTurn()
			turn <- struct{}{} // another send of the guest's is being made
			sent := make(chan int32, 1)
			go func() { sent <- fdWriteString(w, newForkTestModule(), pa, "x") }()
			if blocked, rc := blockedOrDone(t, w, sent); !blocked {
				t.Fatalf("the send went through (rc=%d) while another held the turn", rc)
			}
			<-turn
			if rc := within(t, "fd_write", sent); rc != _wasiESUCCESS {
				t.Fatalf("send rc=%d", rc)
			}
			if err := syscall.SetNonblock(int(pa), true); err != nil {
				t.Fatal(err)
			}
			for {
				if _, err := syscall.Write(int(pa), make([]byte, 512)); errors.Is(err, syscall.EAGAIN) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.SetNonblock(int(pa), false); err != nil {
				t.Fatal(err)
			}
			if _, err := syscall.Read(int(pb), make([]byte, 8192)); err != nil {
				t.Fatal(err)
			}
			if n, rc := writeChunk(t, w, m, pa); rc != _wasiESUCCESS || n == 0 || n >= uint32(wsChunk) {
				t.Fatalf("send that is not to wait with room for part of it: %d bytes rc=%d, want part of %d", n, rc, wsChunk)
			}
		}

		if runtime.GOOS != "linux" {
			// darwin's FIFO with a name is read as M5 has it, and darwin
			// refuses a connect to a full backlog at once
			return
		}
		fifo := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		rfifo, errno := w.pathOpen(nil, fifo[1:], 0, 0, 1<<1, wasiFdflagNonblock)
		if errno != _wasiESUCCESS {
			t.Fatalf("open of a FIFO with NONBLOCK errno=%d", errno)
		}
		writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, writer)
		if rc := w.Fd_fdstat_set_flags(m, rfifo, 0); rc != _wasiESUCCESS {
			t.Fatalf("clearing NONBLOCK rc=%d", rc)
		}
		if op := entryOf(t, w, rfifo); w.netpolled(op, op.f) {
			t.Fatal("a description the guest put in blocking mode is waited for in the Go runtime's poller")
		}
		postWhenBlocked(w, wasiSIGUSR1)
		if got, rc := readWithin(t, w, m, rfifo, 16); rc != _wasiEINTR {
			t.Fatalf("read of an empty FIFO the guest put in blocking mode = %q rc=%d, want EINTR", got, rc)
		}
		takeSignals(t, w, m)

		path := filepath.Join(t.TempDir(), "s")
		server := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
		n := putUnixAddr(m, sockAddrOff, path)
		if rc := w.Sock_bind_addr(m, server, sockAddrOff, sockPathOff, n); rc != _wasiESUCCESS {
			t.Fatalf("bind rc=%d", rc)
		}
		// a backlog of none: the first connection waits, the next connect
		// waits for room
		if rc := w.Sock_listen(m, server, 0); rc != _wasiESUCCESS {
			t.Fatalf("Sock_listen rc=%d", rc)
		}
		first := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
		if rc := w.Sock_connect_addr(m, first, sockAddrOff, sockPathOff, n); rc != _wasiESUCCESS {
			t.Fatalf("first connect rc=%d", rc)
		}
		// the connect that waited reported the connection: none is left to
		// report
		if fop := entryOf(t, w, first); fop.sock.connecting != nil {
			t.Fatal("a connection a connect waited for and reported is still to be reported")
		}
		next := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
		postWhenBlocked(w, wasiSIGUSR1)
		if rc := w.Sock_connect_addr(m, next, sockAddrOff, sockPathOff, n); rc != -_wasiEINTR {
			t.Fatalf("connect to a full backlog with a signal rc=%d, want -EINTR", rc)
		}
		takeSignals(t, w, m)
		if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
			t.Fatalf("accept rc=%d", rc)
		}
		// the connect that went on in the host makes the connection once
		// there is room, and the next connect reports it made, without a
		// connect of its own, which would wait for the listener's room
		op := entryOf(t, w, next)
		op.mu.Lock()
		c := op.sock.connecting
		op.mu.Unlock()
		if c == nil {
			t.Fatal("no connect under way in the host after the interrupted one")
		}
		within(t, "the connect in the host", c.done)
		// (the guest's NONBLOCK on a description code outside the guest put
		// back in blocking mode: the report does not wait either way)
		if rc := w.Fd_fdstat_set_flags(m, next, wasiFdflagNonblock); rc != _wasiESUCCESS {
			t.Fatalf("NONBLOCK rc=%d", rc)
		}
		if err := syscall.SetNonblock(int(next), false); err != nil {
			t.Fatal(err)
		}
		var rc int32
		returnsWithin(t, "sock_connect_addr", func() { rc = w.Sock_connect_addr(m, next, sockAddrOff, sockPathOff, n) })
		if rc != _wasiESUCCESS {
			t.Fatalf("connect after the connection was made in the host rc=%d", rc)
		}
		op.mu.Lock()
		reported := op.sock.connecting == nil
		op.mu.Unlock()
		if !reported {
			t.Fatal("the connection made in the host is still to be reported after a connect reported it")
		}
		if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
			t.Fatalf("accept of the connection made in the host rc=%d", rc)
		}
	})

	// A command gets the guest's descriptors above 2 that are not
	// close-on-exec under their numbers, as exec(2) passes them: of Files,
	// of the guest's own, taken in from outside the guest or not, in a
	// forked instance under its own numbers.
	t.Run("CommandsInherit", func(t *testing.T) {
		var given [2]int
		if err := syscall.Pipe(given[:]); err != nil {
			t.Fatal(err)
		}
		at := int32(70)
		if err := errors.Join(hostDupTo(given[0], int(at)), syscall.Close(given[0])); err != nil {
			t.Fatal(err)
		}
		if _, err := syscall.Write(given[1], []byte("given")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Close(given[1]); err != nil {
			t.Fatal(err)
		}
		w, m := newHostNumberedStubs(t, map[int32]*os.File{at: os.NewFile(uintptr(at), "given")}, nil)
		w.cfg.Exec = AllowAllExec
		// what a command finds under a number: the input there, or
		// "closed"
		probe := func(t *testing.T, w *WasiStubs, m *Module, fd int32) string {
			t.Helper()
			r, wr := newTestPipe(t, w, m)
			// (by name: dash takes no descriptor above 9 in a redirection)
			script := fmt.Sprintf("cat /dev/fd/%d 2>/dev/null || echo closed", fd)
			pid := spawnWithStreams(t, w, m, wr, wr, wr, "/bin/sh", "-c", script)
			closeTestFd(t, w, m, wr)
			waitExitsZero(t, w, m, pid)
			got := readToEnd(t, w, m, r)
			closeTestFd(t, w, m, r)
			// the last line: what the shell says of a closed number before
			// it is its own error output
			lines := strings.Split(strings.TrimSpace(got), "\n")
			return lines[len(lines)-1]
		}
		if got := probe(t, w, m, at); got != "given" {
			t.Fatalf("the command finds %q under the descriptor of Files", got)
		}
		r, wr := newTestPipe(t, w, m)
		if rc := w.Fd_dup2(m, r, 71); rc != _wasiESUCCESS {
			t.Fatalf("dup2 rc=%d", rc)
		}
		if rc := w.Fd_dup2(m, r, 72); rc != _wasiESUCCESS {
			t.Fatalf("dup2 rc=%d", rc)
		}
		if rc := w.Fd_cloexec(m, 72, 1, 1, 6200); rc != _wasiESUCCESS {
			t.Fatalf("Fd_cloexec rc=%d", rc)
		}
		closeTestFd(t, w, m, wr)
		if got := probe(t, w, m, 71); got != "" {
			t.Fatalf("the command finds %q under the guest's 71, want its (empty) input", got)
		}
		if !entryOf(t, w, 71).shared.Load() {
			t.Fatal("an entry a command inherited is not marked shared")
		}
		if got := probe(t, w, m, 72); got != "closed" {
			t.Fatalf("the command finds %q under the guest's close-on-exec 72", got)
		}
		var native, marked [2]int
		if err := errors.Join(syscall.Pipe(native[:]), syscall.Pipe(marked[:])); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Close(native[1]); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, native[0])
		closeFDAtEnd(t, marked[0])
		if _, err := syscall.Write(marked[1], []byte("marked")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Close(marked[1]); err != nil {
			t.Fatal(err)
		}
		syscall.CloseOnExec(marked[0])
		if got := probe(t, w, m, int32(native[0])); got != "" {
			t.Fatalf("the command finds %q under native code's %d", got, native[0])
		}
		// one the guest has not taken in is passed by the host's mark too
		var outside [2]int
		if err := syscall.Pipe(outside[:]); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, outside[0])
		closeFDAtEnd(t, outside[1])
		syscall.CloseOnExec(outside[0])
		if got := probe(t, w, m, int32(outside[0])); got != "closed" {
			t.Fatalf("the command finds %q under native code's close-on-exec %d", got, outside[0])
		}
		// one the guest has taken in keeps the host's mark
		if ft := fdFiletype(t, w, m, int32(marked[0])); ft == 0 {
			t.Fatal("native code's descriptor was not taken in")
		}
		if got := probe(t, w, m, int32(marked[0])); got != "closed" {
			t.Fatalf("the command finds %q under native code's close-on-exec %d", got, marked[0])
		}
		// the guest's F_GETFD of it is the host's mark
		if rc := w.Fd_cloexec(m, int32(marked[0]), 0, 0, 6200); rc != _wasiESUCCESS || readU32(m.memory, 6200) != 1 {
			t.Fatalf("Fd_cloexec of a close-on-exec descriptor taken in rc=%d, mark %d", rc, readU32(m.memory, 6200))
		}
		// a forked instance has the mark the host had at the fork
		child := w.Fork()
		t.Cleanup(func() {
			if err := child.CloseAll(); err != nil {
				t.Errorf("child CloseAll: %v", err)
			}
		})
		if got := probe(t, child, newForkTestModule(), 71); got != "" {
			t.Fatalf("the forked instance's command finds %q under 71", got)
		}
		if got := probe(t, child, newForkTestModule(), int32(marked[0])); got != "closed" {
			t.Fatalf("the forked instance's command finds %q under the close-on-exec %d it was taken in with", got, marked[0])
		}
		// and the guest's F_SETFD of it is the host's
		if rc := w.Fd_cloexec(m, int32(marked[0]), 1, 0, 6200); rc != _wasiESUCCESS || hostCloseOnExec(marked[0]) {
			t.Fatalf("Fd_cloexec clearing the mark rc=%d, the host's mark kept %v", rc, hostCloseOnExec(marked[0]))
		}
		if got := probe(t, w, m, int32(marked[0])); got != "marked" {
			t.Fatalf("the command finds %q under %d, whose mark the guest cleared", got, marked[0])
		}
		// one taken in that code outside the guest closed and put another
		// file under the number is that file's
		var stale, fresh [2]int
		if err := errors.Join(syscall.Pipe(stale[:]), syscall.Pipe(fresh[:])); err != nil {
			t.Fatal(err)
		}
		if _, err := syscall.Write(fresh[1], []byte("fresh")); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(syscall.Close(stale[1]), syscall.Close(fresh[1])); err != nil {
			t.Fatal(err)
		}
		closeFDAtEnd(t, stale[0])
		if ft := fdFiletype(t, w, m, int32(stale[0])); ft == 0 {
			t.Fatal("native code's descriptor was not taken in")
		}
		if err := errors.Join(dupTo(fresh[0], stale[0]), syscall.Close(fresh[0])); err != nil {
			t.Fatal(err)
		}
		if got := probe(t, w, m, int32(stale[0])); got != "fresh" {
			t.Fatalf("the command finds %q under %d, which code outside the guest reopened", got, stale[0])
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
	// moved up, is in the guest's mode, non-blocking: where poll(2) reports
	// the end of a FIFO's input the Go runtime polls it; elsewhere it does
	// not. Either way the close of the FIFO while a read waits for it
	// returns.
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
		if polled != hostPollReportsFIFOEnd || op.polled != polled || !nonblocking {
			t.Fatalf("the FIFO's file is polled %v (entry %v), non-blocking %v; want polled %v, non-blocking", polled, op.polled, nonblocking, hostPollReportsFIFOEnd)
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

// A file of Files that is no socket keeps the mode it was given in, which
// is the guest's: a pipe in blocking mode is not one the guest set
// non-blocking.
func TestFilesKeepTheirMode(t *testing.T) {
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	closeFDAtEnd(t, p[1])
	w, m := newProcTestStubs(t)
	w.cfg.Files = map[int32]*os.File{7: os.NewFile(uintptr(p[0]), "pipe")}
	t.Cleanup(func() {
		if err := w.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	const out int32 = 5200
	if rc := w.Fd_fdstat_get(m, 7, out); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_get(7) rc=%d", rc)
	}
	if flags := int32(binary.LittleEndian.Uint16(m.memory[out+2:])); flags&wasiFdflagNonblock != 0 {
		t.Fatalf("the fdflags of a pipe in blocking mode are %#x: NONBLOCK", flags)
	}
	host, ok := w.HostDescriptor(7)
	if !ok {
		t.Fatal("HostDescriptor(7) is none")
	}
	if flags, err := descriptorFlags(int(host), syscall.F_GETFL); err != nil || flags&syscall.O_NONBLOCK != 0 {
		t.Fatalf("the pipe's flags %#x, %v: not in blocking mode", flags, err)
	}
}

// A descriptor of the guest's whose entry was closed after it was collected
// for a command is closed in the command, as one closed before exec(2) is.
func TestCommandFilesOfAClosedEntry(t *testing.T) {
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	open, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, open)
	std := []uintptr{0, 1, 2}
	inherit := []commandDescriptor{{at: 4, conn: closed}, {at: 5, conn: open}, {at: 6}}
	if err := withCommandFiles(std, inherit, func(files []uintptr) error {
		if want := []uintptr{0, 1, 2, ^uintptr(0), ^uintptr(0), files[5], 6}; !slices.Equal(files, want) || files[5] == ^uintptr(0) {
			t.Errorf("files %v, want %v with the open entry's descriptor at 5", files, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
