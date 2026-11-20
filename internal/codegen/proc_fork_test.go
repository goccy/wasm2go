package codegen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	w, m := newProcTestStubs(t)
	w.SetFSAccessHook(func(string, bool) bool { return true })
	w.SetNetAccessHook(func(string) bool { return true })
	w.SetDialHook(func(string, string, string, int) bool { return true })
	w.SetResolveHook(func(string) bool { return true })
	w.SetExecHook(func(string, []string) bool { return true })
	w.resolvedHosts = map[string]string{"127.0.0.1": "localhost"}
	w.procs = map[int32]*wasiProc{1000: {done: make(chan struct{})}}
	if rc := w.Fd_cloexec(m, 2, 1, 1, 5300); rc != _wasiESUCCESS {
		t.Fatalf("Fd_cloexec rc=%d", rc)
	}

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
		child.resolveHook == nil || child.execHook == nil {
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
		return w.addFDLocked(&wasiOpen{f: failingCloser{File: f, err: os.ErrPermission}})
	}
	w, m := newProcTestStubs(t)
	fd := failing(t, w)
	if rc := w.Fd_closefrom(m, fd); rc != mapOSError(os.ErrPermission) {
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
