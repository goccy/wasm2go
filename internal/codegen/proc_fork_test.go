package codegen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Offsets in a test module's linear memory used by the fd helpers below.
const (
	forkTestIovOff   int32 = 100
	forkTestCountOff int32 = 120
	forkTestBufOff   int32 = 200
)

// newForkTestModule returns a module with its own linear memory, standing in
// for the separate module instance a forked guest runs in.
func newForkTestModule() *Module {
	return newGuestModule(1 << 16)
}

// fdReadString reads up to n bytes from fd through Fd_read.
func fdReadString(w *WasiStubs, m *Module, fd, n int32) (string, int32) {
	makeIovec(m, forkTestIovOff, forkTestBufOff, n)
	rc := w.Fd_read(m, fd, forkTestIovOff, 1, forkTestCountOff)
	if rc != _wasiESUCCESS {
		return "", rc
	}
	got := int32(readU32(m.memory, int(forkTestCountOff)))
	return string(m.memory[forkTestBufOff : forkTestBufOff+got]), rc
}

// fdWriteString writes s to fd through Fd_write.
func fdWriteString(w *WasiStubs, m *Module, fd int32, s string) int32 {
	copy(m.memory[forkTestBufOff:], s)
	makeIovec(m, forkTestIovOff, forkTestBufOff, int32(len(s)))
	return w.Fd_write(m, fd, forkTestIovOff, 1, forkTestCountOff)
}

// newTestPipe creates a guest pipe and returns its read and write fds.
func newTestPipe(t *testing.T, w *WasiStubs, m *Module) (readFd, writeFd int32) {
	t.Helper()
	const out int32 = 5000
	if rc := w.Pipe(m, out); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	return int32(readU32(m.memory, int(out))), int32(readU32(m.memory, int(out)+4))
}

// slotRefs returns the number of table slots, of every instance, that hold
// the entry behind fd.
func slotRefs(t *testing.T, w *WasiStubs, fd int32) int32 {
	t.Helper()
	w.mu.Lock()
	op := w.fdTable[fd]
	w.mu.Unlock()
	if op == nil {
		t.Fatalf("fd %d has no table entry", fd)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.refs
}

// readEOFAsync reads from fd on another goroutine, with its own module
// memory, and delivers the result of the read.
func readEOFAsync(w *WasiStubs, fd int32) <-chan string {
	res := make(chan string, 1)
	go func() {
		s, rc := fdReadString(w, newForkTestModule(), fd, 16)
		if rc != _wasiESUCCESS {
			s = "error"
		}
		res <- s
	}()
	return res
}

func newProcTestStubs(t *testing.T) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	return w, m
}

func TestWasi_ForkSharesDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)

	child := w.Fork()
	cm := newForkTestModule()
	if child.fdTable[readFd] != w.fdTable[readFd] || child.fdTable[writeFd] != w.fdTable[writeFd] {
		t.Fatal("child slots do not refer to the parent's open descriptors")
	}

	// The child closing its copy of the read end leaves the parent's usable.
	if rc := child.Fd_close(cm, readFd); rc != _wasiESUCCESS {
		t.Fatalf("child close read end rc=%d", rc)
	}
	if rc := child.Fd_close(cm, readFd); rc != _wasiEBADF {
		t.Errorf("child second close rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, writeFd, "hi"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "hi" {
		t.Fatalf("parent read = %q rc=%d, want %q", got, rc, "hi")
	}

	// The reader sees EOF only after BOTH write ends are closed.
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("parent close write end rc=%d", rc)
	}
	eof := readEOFAsync(w, readFd)
	select {
	case got := <-eof:
		t.Fatalf("read returned %q while the child still holds the write end", got)
	case <-time.After(100 * time.Millisecond):
	}
	if rc := fdWriteString(child, cm, writeFd, "c"); rc != _wasiESUCCESS {
		t.Fatalf("child write rc=%d", rc)
	}
	select {
	case got := <-eof:
		if got != "c" {
			t.Fatalf("read = %q, want %q", got, "c")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not see the child's write")
	}
	if rc := child.Fd_close(cm, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("child close write end rc=%d", rc)
	}
	select {
	case got := <-readEOFAsync(w, readFd):
		if got != "" {
			t.Fatalf("read = %q, want EOF", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EOF after the last write end was closed")
	}
}

func TestWasi_ForkConfiguration(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.recordResolvedHost("127.0.0.1", "localhost")
	w.procs = map[int32]*wasiProc{1000: {done: make(chan struct{})}}
	if rc := w.Fd_cloexec(m, 2, 1, 1, 5300); rc != _wasiESUCCESS {
		t.Fatalf("Fd_cloexec rc=%d", rc)
	}

	child := w.Fork()
	if child.cfg.Stdin != w.cfg.Stdin || child.cfg.Stdout != w.cfg.Stdout || child.cfg.Stderr != w.cfg.Stderr {
		t.Error("stdio streams not inherited")
	}
	if len(child.cfg.Args) != len(w.cfg.Args) || len(child.cfg.Env) != len(w.cfg.Env) {
		t.Error("args/env not inherited")
	}
	if child.cfg.FS != w.cfg.FS || !child.monoStart.Equal(w.monoStart) {
		t.Error("filesystem or clock configuration not inherited")
	}
	if child.cfg.NetAccess == nil || child.cfg.Dial == nil ||
		child.cfg.Resolve == nil || child.cfg.Exec == nil {
		t.Error("hooks not inherited")
	}
	if len(child.procs) != 0 {
		t.Errorf("child inherited %d processes, want none", len(child.procs))
	}
	// The names lookups gave addresses for are the family's: the child's
	// connects are asked about the parent's, and the parent's about the
	// child's.
	var told []string
	dial := func(network, host, ip string, port int) bool {
		told = append(told, host)
		return false
	}
	w.cfg.Dial, child.cfg.Dial = dial, dial
	child.recordResolvedHost("10.0.0.1", "other")
	child.dialAllowed("tcp", "127.0.0.1", 80)
	w.dialAllowed("tcp", "10.0.0.1", 80)
	if !slices.Equal(told, []string{"localhost", "other"}) {
		t.Errorf("Dial was told %q, want localhost for the parent's lookup, other for the child's", told)
	}
	// The close-on-exec marks are copied, and each side's are its own.
	cm := newForkTestModule()
	if got := closeOnExec(t, child, cm, 2, 1, 0); got != 1 {
		t.Error("close-on-exec mark not copied")
	}
	if got := closeOnExec(t, w, m, 2, 0, 0); got != 1 {
		t.Error("the child cleared the parent's close-on-exec mark")
	}
}

func TestWasi_ForkDupSlotsCloseLast(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	const dupOut int32 = 5100
	if rc := w.Fd_dup(m, writeFd, dupOut); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	writeFd2 := int32(readU32(m.memory, int(dupOut)))
	file := w.fdTable[writeFd].f

	child := w.Fork()
	cm := newForkTestModule()
	if got := slotRefs(t, w, writeFd); got != 4 {
		t.Fatalf("slots = %d, want 4", got)
	}

	closes := []struct {
		w  *WasiStubs
		m  *Module
		fd int32
	}{{w, m, writeFd}, {child, cm, writeFd}, {w, m, writeFd2}}
	for i, c := range closes {
		if rc := c.w.Fd_close(c.m, c.fd); rc != _wasiESUCCESS {
			t.Fatalf("close %d rc=%d", i, rc)
		}
		if _, err := file.Write([]byte{'x'}); err != nil {
			t.Fatalf("descriptor closed after %d of 4 closes: %v", i+1, err)
		}
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "xxx" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "xxx")
	}
	if rc := child.Fd_close(cm, writeFd2); rc != _wasiESUCCESS {
		t.Fatalf("last close rc=%d", rc)
	}
	if _, err := file.Write([]byte{'x'}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after the last close: err=%v, want os.ErrClosed", err)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read = %q rc=%d, want EOF", got, rc)
	}
}

func TestWasi_ForkSharesFileOffset(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	const fdOut int32 = 5000
	pathPtr, pathLen := putPath(m, 6000, "f.txt")
	if rc := w.Path_open(m, 3, 0, pathPtr, pathLen, 0, 0x2, 0, 0, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("Path_open rc=%d", rc)
	}
	fd := int32(readU32(m.memory, int(fdOut)))

	child := w.Fork()
	cm := newForkTestModule()
	if got, rc := fdReadString(w, m, fd, 2); rc != _wasiESUCCESS || got != "ab" {
		t.Fatalf("parent read = %q rc=%d, want %q", got, rc, "ab")
	}
	if got, rc := fdReadString(child, cm, fd, 2); rc != _wasiESUCCESS || got != "cd" {
		t.Fatalf("child read = %q rc=%d, want %q", got, rc, "cd")
	}
	const tellOut int32 = 5200
	if rc := w.Fd_tell(m, fd, tellOut); rc != _wasiESUCCESS {
		t.Fatalf("Fd_tell rc=%d", rc)
	}
	if off := readU64(m.memory, int(tellOut)); off != 4 {
		t.Fatalf("parent offset = %d, want 4", off)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatalf("child CloseAll: %v", err)
	}
	if got, rc := fdReadString(w, m, fd, 2); rc != _wasiESUCCESS || got != "ef" {
		t.Fatalf("parent read after the child closed = %q rc=%d, want %q", got, rc, "ef")
	}
}

func TestWasi_CloseAll(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	child := w.Fork()
	if err := child.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatalf("second CloseAll: %v", err)
	}
	if len(child.fdTable) != 0 {
		t.Errorf("child still has %d fds", len(child.fdTable))
	}
	if got := slotRefs(t, w, readFd) + slotRefs(t, w, writeFd); got != 2 {
		t.Errorf("slots left = %d, want 2, the parent's", got)
	}
	if rc := fdWriteString(w, m, writeFd, "ok"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "ok" {
		t.Fatalf("parent read = %q rc=%d", got, rc)
	}
	file := w.fdTable[writeFd].f
	if err := w.CloseAll(); err != nil {
		t.Fatalf("parent CloseAll: %v", err)
	}
	if _, err := file.Write([]byte{'x'}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after CloseAll of the last instance: err=%v, want os.ErrClosed", err)
	}
}

func TestWasi_FdClosefrom(t *testing.T) {
	w, m := newProcTestStubs(t)
	keepRead, keepWrite := newTestPipe(t, w, m)
	goRead, goWrite := newTestPipe(t, w, m)
	child := w.Fork()

	// The child gives up everything from the second pipe on; the first
	// pipe, numbered lower, stays.
	if rc := child.Fd_closefrom(m, goRead); rc != _wasiESUCCESS {
		t.Fatalf("Fd_closefrom rc=%d", rc)
	}
	for _, fd := range []int32{goRead, goWrite} {
		if _, open := child.fdTable[fd]; open {
			t.Errorf("child fd %d survived closefrom", fd)
		}
	}
	for _, fd := range []int32{keepRead, keepWrite} {
		if _, open := child.fdTable[fd]; !open {
			t.Errorf("child fd %d below the bound was closed", fd)
		}
	}
	// The parent's slots are untouched and still usable.
	if rc := fdWriteString(w, m, goWrite, "ok"); rc != _wasiESUCCESS {
		t.Fatalf("parent write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, goRead, 16); rc != _wasiESUCCESS || got != "ok" {
		t.Fatalf("parent read = %q rc=%d", got, rc)
	}
	// Once the parent closes its write end too, the reader sees
	// end-of-file: the child holds no reference any more.
	if rc := w.Fd_close(m, goWrite); rc != _wasiESUCCESS {
		t.Fatalf("parent close rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, goRead, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read after last writer closed = %q rc=%d, want end-of-file", got, rc)
	}
	// Closing from 0 empties the table; doing it again is harmless.
	if rc := child.Fd_closefrom(m, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_closefrom(0) rc=%d", rc)
	}
	if len(child.fdTable) != 0 {
		t.Errorf("child still has %d fds", len(child.fdTable))
	}
	if rc := child.Fd_closefrom(m, 0); rc != _wasiESUCCESS {
		t.Fatalf("second Fd_closefrom(0) rc=%d", rc)
	}
}

// failingCloser is a file whose close fails.
type failingCloser struct {
	File
	err error
}

func (f failingCloser) Close() error { return errors.Join(f.err, f.File.Close()) }

// A close that fails is reported by whoever closes the last reference, and
// every descriptor is closed all the same.
func TestWasi_CloseErrorsAreReported(t *testing.T) {
	failing := func(t *testing.T, w *WasiStubs) int32 {
		t.Helper()
		f, err := os.Create(filepath.Join(t.TempDir(), "f"))
		if err != nil {
			t.Fatal(err)
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		return addTestFD(w, &wasiOpen{f: failingCloser{File: f, err: os.ErrPermission}})
	}
	w, m := newProcTestStubs(t)
	fd := failing(t, w)
	if rc := w.Fd_closefrom(m, fd); rc != errnoOfError(os.ErrPermission) {
		t.Fatalf("Fd_closefrom rc=%d, want the close's error", rc)
	}
	if rc := w.Fd_close(m, fd); rc != _wasiEBADF {
		t.Fatalf("Fd_close after Fd_closefrom rc=%d, want EBADF", rc)
	}
	failing(t, w)
	if err := w.CloseAll(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("CloseAll: %v, want the close's error", err)
	}
	if len(w.fdTable) != 0 {
		t.Errorf("%d fds left after CloseAll", len(w.fdTable))
	}
}

func spawnTestProc(t *testing.T, w *WasiStubs, m *Module, argv ...string) int32 {
	t.Helper()
	if _, err := os.Stat(argv[0]); err != nil {
		t.Skipf("%s not available", argv[0])
	}
	pathOff := writeCStr(m, 1000, argv[0])
	argvOff := writeArgv(m, 2000, 3000, argv)
	const pidOff int32 = 4000
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	return int32(readU32(m.memory, int(pidOff)))
}

func TestWasi_NewProcWait(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	pid, exited := w.NewProc(nil)
	if pid != wasiFirstPID {
		t.Errorf("first pid = %d, want %d", pid, wasiFirstPID)
	}
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG while running rc=%d, want -EAGAIN", rc)
	}
	go func() {
		exited(7 << 8)
		exited(1 << 8) // a repeated call is ignored
	}()
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, int(statusOff))); status != 7<<8 {
		t.Errorf("status = %#x, want %#x", status, 7<<8)
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != -_wasiECHILD {
		t.Errorf("wait after reap rc=%d, want -ECHILD", rc)
	}

	pid2, exited2 := w.NewProc(nil)
	exited2(2 << 8)
	if rc := w.Proc_wait(m, pid2, 1, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("WNOHANG after exit rc=%d", rc)
	}
	if status := int32(readU32(m.memory, int(statusOff))); status != 2<<8 {
		t.Errorf("status = %#x, want %#x", status, 2<<8)
	}
}

func TestWasi_ProcWaitAny(t *testing.T) {
	w, m := newProcTestStubs(t)
	const pidOut, statusOff int32 = 4100, 4104
	waitAny := func(options int32) (rc, pid, status int32) {
		rc = w.Proc_wait_any(m, options, pidOut, statusOff)
		return rc, int32(readU32(m.memory, int(pidOut))), int32(readU32(m.memory, int(statusOff)))
	}

	if rc, _, _ := waitAny(0); rc != -_wasiECHILD {
		t.Fatalf("no children rc=%d, want -ECHILD", rc)
	}
	if rc, _, _ := waitAny(1); rc != -_wasiECHILD {
		t.Fatalf("no children, WNOHANG rc=%d, want -ECHILD", rc)
	}

	ownPid, exited := w.NewProc(nil)
	if rc, _, _ := waitAny(1); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG with a running child rc=%d, want -EAGAIN", rc)
	}

	spawnedPid := spawnTestProc(t, w, m, "/bin/sh", "-c", "exit 3")
	rc, pid, status := waitAny(0)
	if rc != _wasiESUCCESS || pid != spawnedPid || status != 3<<8 {
		t.Fatalf("wait any = rc %d pid %d status %#x, want pid %d status %#x", rc, pid, status, spawnedPid, 3<<8)
	}
	if rc := w.Proc_wait(m, spawnedPid, 1, statusOff); rc != -_wasiECHILD {
		t.Errorf("reaped pid still waitable: rc=%d", rc)
	}

	if rc, _, _ := waitAny(1); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG with the embedder-run child running rc=%d, want -EAGAIN", rc)
	}
	exited(9) // killed by signal 9
	rc, pid, status = waitAny(1)
	if rc != _wasiESUCCESS || pid != ownPid || status != 9 {
		t.Fatalf("wait any = rc %d pid %d status %#x, want pid %d status 0x9", rc, pid, status, ownPid)
	}
	if rc, _, _ := waitAny(0); rc != -_wasiECHILD {
		t.Fatalf("all reaped rc=%d, want -ECHILD", rc)
	}

	// Several finished at once: the lowest pid is reported first.
	p1, e1 := w.NewProc(nil)
	p2, e2 := w.NewProc(nil)
	e2(2 << 8)
	e1(1 << 8)
	if rc, pid, status := waitAny(0); rc != _wasiESUCCESS || pid != p1 || status != 1<<8 {
		t.Fatalf("first of two = rc %d pid %d status %#x, want pid %d", rc, pid, status, p1)
	}
	if rc, pid, status := waitAny(0); rc != _wasiESUCCESS || pid != p2 || status != 2<<8 {
		t.Fatalf("second of two = rc %d pid %d status %#x, want pid %d", rc, pid, status, p2)
	}

	if rc := w.Proc_wait_any(m, 0, int32(len(m.memory)), statusOff); rc != -_wasiEFAULT {
		t.Errorf("bad pid pointer rc=%d, want -EFAULT", rc)
	}
}

// A process finishing at any point relative to the waiter's scan must wake
// the waiter.
func TestWasi_ProcWaitAnyConcurrentFinish(t *testing.T) {
	const iterations, procs = 300, 4
	const pidOut, statusOff int32 = 4100, 4104
	for iter := 0; iter < iterations; iter++ {
		w, m := newProcTestStubs(t)
		want := map[int32]int32{}
		var start sync.WaitGroup
		start.Add(1)
		for i := 0; i < procs; i++ {
			pid, exited := w.NewProc(nil)
			status := int32(i+1) << 8
			want[pid] = status
			go func() {
				start.Wait()
				exited(status)
			}()
		}
		reaped := make(chan map[int32]int32, 1)
		go func() {
			got := map[int32]int32{}
			for i := 0; i < procs; i++ {
				if i == 0 {
					start.Done()
				}
				if rc := w.Proc_wait_any(m, 0, pidOut, statusOff); rc != _wasiESUCCESS {
					got[-1] = rc
					break
				}
				got[int32(readU32(m.memory, int(pidOut)))] = int32(readU32(m.memory, int(statusOff)))
			}
			reaped <- got
		}()
		got := <-reaped
		if len(got) != len(want) {
			t.Fatalf("iteration %d: reaped %v, want %v", iter, got, want)
		}
		for pid, status := range want {
			if got[pid] != status {
				t.Fatalf("iteration %d: reaped %v, want %v", iter, got, want)
			}
		}
		if rc := w.Proc_wait_any(m, 0, pidOut, statusOff); rc != -_wasiECHILD {
			t.Fatalf("iteration %d: after reaping all rc=%d, want -ECHILD", iter, rc)
		}
	}
}

func TestWasi_ProcKill(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004

	if rc := w.Proc_kill(m, 4242, 15); rc != -_wasiESRCH {
		t.Fatalf("unknown pid rc=%d, want -ESRCH", rc)
	}
	if rc := w.Proc_kill(m, 4242, 0); rc != -_wasiESRCH {
		t.Fatalf("unknown pid, signal 0 rc=%d, want -ESRCH", rc)
	}

	var signals []int32
	var killErr error
	pid, exited := w.NewProc(func(sig int32) error {
		signals = append(signals, sig)
		return killErr
	})
	if rc := w.Proc_kill(m, pid, -1); rc != -_wasiEINVAL {
		t.Errorf("negative signal rc=%d, want -EINVAL", rc)
	}
	if rc := w.Proc_kill(m, pid, 0); rc != _wasiESUCCESS {
		t.Errorf("existence probe rc=%d", rc)
	}
	if rc := w.Proc_kill(m, pid, 15); rc != _wasiESUCCESS {
		t.Errorf("Proc_kill rc=%d", rc)
	}
	// The kill function's error is the errno.
	killErr = syscall.EPERM
	if rc := w.Proc_kill(m, pid, 2); rc != -_wasiEPERM {
		t.Errorf("kill failing with EPERM rc=%d, want -EPERM", rc)
	}
	killErr = errors.New("refused")
	if rc := w.Proc_kill(m, pid, 1); rc != -_wasiEIO {
		t.Errorf("kill failing with another error rc=%d, want -EIO", rc)
	}
	exited(15)
	if rc := w.Proc_kill(m, pid, 9); rc != _wasiESUCCESS {
		t.Errorf("signalling a finished, unreaped process rc=%d, want 0", rc)
	}
	if len(signals) != 3 || signals[0] != 15 || signals[1] != 2 || signals[2] != 1 {
		t.Errorf("signals delivered = %v, want [15 2 1]", signals)
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if rc := w.Proc_kill(m, pid, 15); rc != -_wasiESRCH {
		t.Errorf("reaped pid rc=%d, want -ESRCH", rc)
	}

	// A process registered without a kill function exists but cannot be
	// signalled.
	quiet, quietExited := w.NewProc(nil)
	if rc := w.Proc_kill(m, quiet, 0); rc != _wasiESUCCESS {
		t.Errorf("existence probe without kill rc=%d", rc)
	}
	if rc := w.Proc_kill(m, quiet, 15); rc != -_wasiEPERM {
		t.Errorf("signal without kill rc=%d, want -EPERM", rc)
	}
	quietExited(0)
}

func TestWasi_ProcKillSpawned(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	pid := spawnTestProc(t, w, m, "/bin/sleep", "30")
	t.Cleanup(func() {
		if rc := w.Proc_kill(m, pid, wasiSIGKILL); rc != _wasiESUCCESS && rc != -_wasiESRCH {
			t.Errorf("Proc_kill of the command at cleanup rc=%d", rc)
		}
	})
	if rc := w.Proc_kill(m, pid, 0); rc != _wasiESUCCESS {
		t.Fatalf("existence probe rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG before the signal rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Proc_kill(m, pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	status := int32(readU32(m.memory, int(statusOff)))
	if status&0x7f != wasiSIGTERM || status>>8 != 0 {
		t.Errorf("status = %#x, want death by signal %d", status, wasiSIGTERM)
	}
}

func TestWasi_ForkFamilyPidsUnique(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	first, _ := w.NewProc(nil)
	if first != wasiFirstPID {
		t.Errorf("first pid = %d, want %d", first, wasiFirstPID)
	}
	child := w.Fork()
	grandchild := child.Fork()
	seen := map[int32]bool{first: true}
	for i := 0; i < 3; i++ {
		for _, inst := range []*WasiStubs{grandchild, w, child} {
			pid, _ := inst.NewProc(nil)
			if seen[pid] {
				t.Fatalf("pid %d handed out twice in one fork family", pid)
			}
			seen[pid] = true
		}
	}
	// A child does not see its parent's children.
	if rc := child.Proc_wait(newForkTestModule(), first, 1, statusOff); rc != -_wasiECHILD {
		t.Errorf("child waiting for the parent's child rc=%d, want -ECHILD", rc)
	}
	if rc := w.Proc_wait(m, first, 1, statusOff); rc != -_wasiEAGAIN {
		t.Errorf("parent waiting for its own running child rc=%d, want -EAGAIN", rc)
	}

	// Forking before any pid was handed out still shares one allocator.
	fresh, _ := newProcTestStubs(t)
	freshChild := fresh.Fork()
	a, _ := freshChild.NewProc(nil)
	b, _ := fresh.NewProc(nil)
	if a != wasiFirstPID || b != wasiFirstPID+1 {
		t.Errorf("pids = %d, %d, want the first token and the next", a, b)
	}
}

// A process that several calls wait for at once is reported to one of them;
// the others find no such child.
func TestWasi_ProcWaitConcurrentWaiters(t *testing.T) {
	const statusOff, pidOut int32 = 4004, 4100
	waitPid := func(w *WasiStubs, pid int32) int32 {
		return w.Proc_wait(newForkTestModule(), pid, 0, statusOff)
	}
	waitAny := func(w *WasiStubs, pid int32) int32 {
		return w.Proc_wait_any(newForkTestModule(), 0, pidOut, statusOff)
	}
	for _, waiters := range [][]func(*WasiStubs, int32) int32{
		{waitPid, waitPid},
		{waitPid, waitAny},
		{waitPid, waitPid, waitAny, waitAny},
	} {
		for iter := 0; iter < 100; iter++ {
			w, _ := newProcTestStubs(t)
			pid, exited := w.NewProc(nil)
			results := make(chan int32, len(waiters))
			for _, wait := range waiters {
				go func() { results <- wait(w, pid) }()
			}
			exited(5 << 8)
			reported, missed := 0, 0
			for range waiters {
				switch rc := <-results; rc {
				case _wasiESUCCESS:
					reported++
				case -_wasiECHILD:
					missed++
				default:
					t.Fatalf("iteration %d: a waiter returned %d", iter, rc)
				}
			}
			if reported != 1 || missed != len(waiters)-1 {
				t.Fatalf("iteration %d: %d of %d waiters were given the process, %d found no child; want 1 and %d",
					iter, reported, len(waiters), missed, len(waiters)-1)
			}
		}
	}
}

// Any process of a fork family is signalled by its pid, whoever its parent
// is; only its parent waits for it.
func TestWasi_ProcKillAcrossTheFamily(t *testing.T) {
	root, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	recorder := func(into *[]int32) func(sig int32) error {
		return func(sig int32) error {
			*into = append(*into, sig)
			return nil
		}
	}

	// root has two children; the first has a child of its own.
	var toFirst, toSecond, toGrandchild []int32
	firstPid, firstExited := root.NewProc(recorder(&toFirst))
	first, firstModule := root.Fork(), newForkTestModule()
	secondPid, secondExited := root.NewProc(recorder(&toSecond))
	second, secondModule := root.Fork(), newForkTestModule()
	grandchildPid, grandchildExited := first.NewProc(recorder(&toGrandchild))
	grandchild, grandchildModule := first.Fork(), newForkTestModule()

	// a sibling, a grandchild, the parent of a fork child, an uncle
	if rc := second.Proc_kill(secondModule, firstPid, 10); rc != _wasiESUCCESS {
		t.Errorf("sibling rc=%d", rc)
	}
	if rc := root.Proc_kill(m, grandchildPid, 12); rc != _wasiESUCCESS {
		t.Errorf("grandchild rc=%d", rc)
	}
	if rc := grandchild.Proc_kill(grandchildModule, firstPid, 15); rc != _wasiESUCCESS {
		t.Errorf("parent rc=%d", rc)
	}
	if rc := grandchild.Proc_kill(grandchildModule, secondPid, 1); rc != _wasiESUCCESS {
		t.Errorf("uncle rc=%d", rc)
	}
	if rc := second.Proc_kill(secondModule, grandchildPid, 0); rc != _wasiESUCCESS {
		t.Errorf("existence probe of a nephew rc=%d", rc)
	}
	if len(toFirst) != 2 || toFirst[0] != 10 || toFirst[1] != 15 {
		t.Errorf("signals to the first child = %v, want [10 15]", toFirst)
	}
	if len(toSecond) != 1 || toSecond[0] != 1 {
		t.Errorf("signals to the second child = %v, want [1]", toSecond)
	}
	if len(toGrandchild) != 1 || toGrandchild[0] != 12 {
		t.Errorf("signals to the grandchild = %v, want [12]", toGrandchild)
	}

	// Waiting is the parent's alone.
	if rc := second.Proc_wait(secondModule, firstPid, 1, statusOff); rc != -_wasiECHILD {
		t.Errorf("waiting for a sibling rc=%d, want -ECHILD", rc)
	}
	if rc := root.Proc_wait(m, grandchildPid, 1, statusOff); rc != -_wasiECHILD {
		t.Errorf("waiting for a grandchild rc=%d, want -ECHILD", rc)
	}

	// A finished process is a zombie for the whole family until its parent
	// has waited for it, and nothing afterwards.
	secondExited(0)
	if rc := first.Proc_kill(firstModule, secondPid, 15); rc != _wasiESUCCESS {
		t.Errorf("signalling a sibling's zombie rc=%d, want 0", rc)
	}
	if rc := root.Proc_wait(m, secondPid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if rc := first.Proc_kill(firstModule, secondPid, 15); rc != -_wasiESRCH {
		t.Errorf("signalling a reaped sibling rc=%d, want -ESRCH", rc)
	}
	if len(toSecond) != 1 {
		t.Errorf("signals to the second child after its end = %v", toSecond)
	}

	// A process outlives its parent: it stays reachable until it ends, and
	// then nobody is left to wait for it.
	if err := first.CloseAll(); err != nil {
		t.Fatal(err)
	}
	firstExited(0)
	if rc := root.Proc_kill(m, grandchildPid, 2); rc != _wasiESUCCESS {
		t.Errorf("signalling an orphan rc=%d", rc)
	}
	if len(toGrandchild) != 2 || toGrandchild[1] != 2 {
		t.Errorf("signals to the orphan = %v, want [12 2]", toGrandchild)
	}
	grandchildExited(0)
	if rc := root.Proc_kill(m, grandchildPid, 0); rc != -_wasiESRCH {
		t.Errorf("probing an orphan that ended rc=%d, want -ESRCH", rc)
	}
}

// A number that is no signal is refused for every kind of process, before
// anything is delivered.
func TestWasi_ProcKillRefusesANumberThatIsNoSignal(t *testing.T) {
	w, m := newProcTestStubs(t)
	var signals []int32
	pid, exited := w.NewProc(func(sig int32) error {
		signals = append(signals, sig)
		return nil
	})
	defer exited(0)
	for _, sig := range []int32{-1, 65} {
		if rc := w.Proc_kill(m, pid, sig); rc != -_wasiEINVAL {
			t.Errorf("Proc_kill(%d) rc=%d, want -EINVAL", sig, rc)
		}
	}
	if rc := w.Proc_kill(m, pid, 64); rc != _wasiESUCCESS {
		t.Errorf("Proc_kill(64) rc=%d", rc)
	}
	if len(signals) != 1 || signals[0] != 64 {
		t.Errorf("signals delivered = %v, want [64]", signals)
	}
}
