package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
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
	return &Module{memory: make([]byte, 1<<16)}
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

// extraRefs returns the number of extra table slots referring to the entry
// behind fd.
func extraRefs(t *testing.T, w *WasiStubs, fd int32) int32 {
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

func newProcTestStubs(t *testing.T) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newTestStubs(t, t.TempDir())
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
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
	w, _ := newProcTestStubs(t)
	w.SetFSAccessHook(func(string, bool) bool { return true })
	w.SetNetAccessHook(func(string) bool { return true })
	w.SetDialHook(func(string, string, string, int) bool { return true })
	w.SetResolveHook(func(string) bool { return true })
	w.SetExecHook(func(string, []string) bool { return true })
	w.SetForkHook(func(*Module, *WasiStubs, int32, func(int32)) (func(int32) error, error) { return nil, nil })
	w.resolvedHosts = map[string]string{"127.0.0.1": "localhost"}
	w.NewProc(nil)

	child := w.Fork()
	if child.stdin != w.stdin || child.stdout != w.stdout || child.stderr != w.stderr {
		t.Error("stdio streams not inherited")
	}
	if len(child.args) != len(w.args) || len(child.env) != len(w.env) {
		t.Error("args/env not inherited")
	}
	if child.preopenDir != w.preopenDir || child.fsys != w.fsys || !child.monoStart.Equal(w.monoStart) {
		t.Error("filesystem or clock configuration not inherited")
	}
	if child.fsHook == nil || child.netHook == nil || child.dialHook == nil ||
		child.resolveHook == nil || child.execHook == nil || child.forkHook == nil {
		t.Error("hooks not inherited")
	}
	if len(child.procs) != 0 {
		t.Errorf("child inherited %d processes, want none", len(child.procs))
	}
	if child.resolvedHosts["127.0.0.1"] != "localhost" {
		t.Error("resolved hosts not copied")
	}
	child.resolvedHosts["10.0.0.1"] = "other"
	if _, ok := w.resolvedHosts["10.0.0.1"]; ok {
		t.Error("resolved hosts map is shared, want a copy")
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
	if got := extraRefs(t, w, writeFd); got != 3 {
		t.Fatalf("extra references = %d, want 3 (four slots)", got)
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
	if got := extraRefs(t, w, readFd) + extraRefs(t, w, writeFd); got != 0 {
		t.Errorf("extra references left = %d, want 0", got)
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

func TestWasi_NewProcWait(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	pid, exited := w.NewProc(nil)
	if pid != 1000 {
		t.Errorf("first pid = %d, want 1000", pid)
	}
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG while running rc=%d, want -EAGAIN", rc)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
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
		select {
		case got := <-reaped:
			if len(got) != len(want) {
				t.Fatalf("iteration %d: reaped %v, want %v", iter, got, want)
			}
			for pid, status := range want {
				if got[pid] != status {
					t.Fatalf("iteration %d: reaped %v, want %v", iter, got, want)
				}
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("iteration %d: a finished process did not wake the waiter", iter)
		}
		if rc := w.Proc_wait_any(m, 0, pidOut, statusOff); rc != -_wasiECHILD {
			t.Fatalf("iteration %d: after reaping all rc=%d, want -ECHILD", iter, rc)
		}
	}
}

func TestWasi_ProcForkNoHook(t *testing.T) {
	w, m := newProcTestStubs(t)
	const pidOff int32 = 4000
	if rc := w.Proc_fork(m, pidOff); rc != -_wasiENOSYS {
		t.Fatalf("no hook rc=%d, want -ENOSYS", rc)
	}
	if len(w.procs) != 0 {
		t.Errorf("process table has %d entries, want 0", len(w.procs))
	}
	if rc := w.Proc_fork(m, int32(len(m.memory))); rc != -_wasiEFAULT {
		t.Errorf("bad pid pointer rc=%d, want -EFAULT", rc)
	}
}

func TestWasi_ProcForkHook(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	const pidOff, statusOff int32 = 4000, 4004

	var (
		hookParent *Module
		hookChild  *WasiStubs
		hookPid    int32
		hookExited func(int32)
		signals    []int32
		pidAtHook  uint32
	)
	binary.LittleEndian.PutUint32(m.memory[pidOff:], 0xdeadbeef)
	w.SetForkHook(func(parent *Module, child *WasiStubs, pid int32, exited func(status int32)) (func(sig int32) error, error) {
		hookParent, hookChild, hookPid, hookExited = parent, child, pid, exited
		pidAtHook = readU32(parent.memory, int(pidOff))
		return func(sig int32) error {
			signals = append(signals, sig)
			return nil
		}, nil
	})
	if rc := w.Proc_fork(m, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_fork rc=%d", rc)
	}
	pid := int32(readU32(m.memory, int(pidOff)))
	if hookParent != m {
		t.Error("hook did not receive the calling module")
	}
	if pidAtHook != 0xdeadbeef {
		t.Errorf("pid was written before the hook ran (%#x)", pidAtHook)
	}
	if pid != hookPid || pid != 1000 {
		t.Errorf("pid = %d, hook saw %d, want 1000", pid, hookPid)
	}
	if hookChild == nil || hookChild == w {
		t.Fatal("hook did not receive a separate child state")
	}
	if hookChild.fdTable[readFd] != w.fdTable[readFd] || hookChild.fdTable[writeFd] != w.fdTable[writeFd] {
		t.Error("child does not share the parent's descriptors")
	}
	if len(hookChild.procs) != 0 {
		t.Error("child inherited the parent's process table")
	}

	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG while the child runs rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Proc_kill(m, pid, 15); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	if len(signals) != 1 || signals[0] != 15 {
		t.Errorf("signals delivered through the hook's kill = %v, want [15]", signals)
	}

	go func() {
		// The child writes through its inherited descriptor, then ends.
		status := int32(5) << 8
		if rc := fdWriteString(hookChild, newForkTestModule(), writeFd, "from-child"); rc != _wasiESUCCESS {
			status = 1 << 8
		}
		if err := hookChild.CloseAll(); err != nil {
			status = 2 << 8
		}
		hookExited(status)
	}()
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, int(statusOff))); status != 5<<8 {
		t.Errorf("status = %#x, want %#x", status, 5<<8)
	}
	if got, rc := fdReadString(w, m, readFd, 32); rc != _wasiESUCCESS || got != "from-child" {
		t.Errorf("parent read = %q rc=%d, want %q", got, rc, "from-child")
	}
	if got := extraRefs(t, w, readFd) + extraRefs(t, w, writeFd); got != 0 {
		t.Errorf("extra references left after the child closed = %d, want 0", got)
	}
	if len(w.procs) != 0 {
		t.Errorf("process table has %d entries after the reap, want 0", len(w.procs))
	}
}

func TestWasi_ProcForkHookFailure(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	const pidOff int32 = 4000
	binary.LittleEndian.PutUint32(m.memory[pidOff:], 0xdeadbeef)

	var hookChild *WasiStubs
	w.SetForkHook(func(parent *Module, child *WasiStubs, pid int32, exited func(status int32)) (func(sig int32) error, error) {
		hookChild = child
		return nil, errors.New("no room for another instance")
	})
	if rc := w.Proc_fork(m, pidOff); rc != -_wasiEAGAIN {
		t.Fatalf("failing hook rc=%d, want -EAGAIN", rc)
	}
	if got := readU32(m.memory, int(pidOff)); got != 0xdeadbeef {
		t.Errorf("pid written on failure: %#x", got)
	}
	if len(w.procs) != 0 {
		t.Errorf("process table has %d entries, want 0", len(w.procs))
	}
	if len(hookChild.fdTable) != 0 {
		t.Errorf("child still has %d fds", len(hookChild.fdTable))
	}
	if got := extraRefs(t, w, readFd) + extraRefs(t, w, writeFd); got != 0 {
		t.Errorf("leaked descriptor references = %d, want 0", got)
	}
	// With no reference leaked, closing the parent's write end is the last
	// close: the reader sees EOF.
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close write end rc=%d", rc)
	}
	select {
	case got := <-readEOFAsync(w, readFd):
		if got != "" {
			t.Fatalf("read = %q, want EOF", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EOF: the failed fork leaked a reference to the write end")
	}
	const pidOut, statusOff int32 = 4100, 4104
	if rc := w.Proc_wait_any(m, 0, pidOut, statusOff); rc != -_wasiECHILD {
		t.Errorf("wait any after a failed fork rc=%d, want -ECHILD", rc)
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
	killErr = errors.New("refused")
	if rc := w.Proc_kill(m, pid, 2); rc != -_wasiEPERM {
		t.Errorf("failing kill rc=%d, want -EPERM", rc)
	}
	exited(15)
	if rc := w.Proc_kill(m, pid, 9); rc != _wasiESUCCESS {
		t.Errorf("signalling a finished, unreaped process rc=%d, want 0", rc)
	}
	if len(signals) != 2 || signals[0] != 15 || signals[1] != 2 {
		t.Errorf("signals delivered = %v, want [15 2]", signals)
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
	if rc := w.Proc_kill(m, pid, 0); rc != _wasiESUCCESS {
		t.Fatalf("existence probe rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG before the signal rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Proc_kill(m, pid, int32(syscall.SIGTERM)); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	waited := make(chan int32, 1)
	go func() { waited <- w.Proc_wait(m, pid, 0, statusOff) }()
	select {
	case rc := <-waited:
		if rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the signalled process did not end")
	}
	status := int32(readU32(m.memory, int(statusOff)))
	if status&0x7f != int32(syscall.SIGTERM) || status>>8 != 0 {
		t.Errorf("status = %#x, want death by signal %d", status, int32(syscall.SIGTERM))
	}
}

func TestWasi_ForkFamilyPidsUnique(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statusOff int32 = 4004
	first, _ := w.NewProc(nil)
	if first != 1000 {
		t.Errorf("first pid = %d, want 1000", first)
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
	if a != 1000 || b != 1001 {
		t.Errorf("pids = %d, %d, want 1000, 1001", a, b)
	}
}

// The native stubs are spliced into generated bundles through an allow-list;
// every declaration the fork support needs must survive it.
func TestWasip1EmitKeepsForkSupport(t *testing.T) {
	tr := &translator{
		opts:            Options{Package: "x", OutputImportPath: "ex/x"},
		importedModules: []string{"wasi_snapshot_preview1"},
		fset:            token.NewFileSet(),
	}
	decls, _, err := tr.emitWasip1Native()
	if err != nil {
		t.Fatalf("emitWasip1Native: %v", err)
	}
	want := map[string]bool{
		"wasiPIDs": false, "wasiFirstPID": false, "_wasiESRCH": false,
		"alloc": false, "netConn": false, "addRef": false,
		"SetForkHook": false, "Fork": false, "CloseAll": false, "NewProc": false,
		"pidsLocked": false, "addProcLocked": false, "finishProc": false, "procExitFunc": false,
		"Proc_fork": false, "Proc_wait_any": false, "Proc_kill": false,
	}
	found := func(name string) {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for _, d := range decls {
		switch dd := d.(type) {
		case *ast.FuncDecl:
			found(dd.Name.Name)
		case *ast.GenDecl:
			for _, sp := range dd.Specs {
				switch s := sp.(type) {
				case *ast.TypeSpec:
					found(s.Name.Name)
				case *ast.ValueSpec:
					for _, n := range s.Names {
						found(n.Name)
					}
				}
			}
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("%s is missing from the emitted wasi runtime", name)
		}
	}
}
