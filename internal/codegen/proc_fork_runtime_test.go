package codegen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Offsets in the memory of a forking test module.
const (
	forkPidOff    int32 = 8
	forkStatusOff int32 = 12
	forkCellOff   int32 = 100
)

// standInForkModule is the forkModule of a test module: the instance it
// builds has memory as its memory and the module's fork child.
func standInForkModule(m *Module, _ *WasiStubs, memory []byte, memSize uint64) *Module {
	c := &Module{memory: memory, memSize: &atomic.Uint64{}, forkChild: m.forkChild, forkModule: m.forkModule}
	c.memSize.Store(memSize)
	return c
}

// recordingForker is CopyForker that records the host state of each child
// instance it makes, for the child's code to call the runtime with, and
// returns done when it is set.
type recordingForker struct {
	mu       sync.Mutex
	children map[*Module]*WasiStubs
	done     func(status int32)
}

func (f *recordingForker) Fork(parent *Module, child *WasiStubs, pid int32) (*Module, func(status int32), error) {
	c, _, err := CopyForker.Fork(parent, child, pid)
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.children == nil {
		f.children = map[*Module]*WasiStubs{}
	}
	f.children[c] = child
	return c, f.done, nil
}

// wasi returns the host state of the child instance m.
func (f *recordingForker) wasi(m *Module) *WasiStubs {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.children[m]
}

// newForkingStubs returns a WasiStubs whose Fork is a recordingForker and a
// module whose fork child is child.
func newForkingStubs(t *testing.T, child func(f *recordingForker, m *Module) int32) (*WasiStubs, *Module, *recordingForker) {
	t.Helper()
	w, m := newProcTestStubs(t)
	f := &recordingForker{}
	w.cfg.Fork = f
	m.forkChild = func(c *Module) int32 { return child(f, c) }
	m.forkModule = standInForkModule
	return w, m, f
}

// forkAndWait forks the guest of w and waits for the child, and returns the
// child's pid and wait status.
func forkAndWait(t *testing.T, w *WasiStubs, m *Module) (pid, status int32) {
	t.Helper()
	if rc := w.Proc_fork(m, forkPidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_fork rc=%d", rc)
	}
	pid = int32(readU32(m.memory, int(forkPidOff)))
	if rc := w.Proc_wait(m, pid, 0, forkStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	return pid, int32(readU32(m.memory, int(forkStatusOff)))
}

// The child of a fork runs the fork child export in an instance of its own,
// whose memory is a copy of the parent's without the pid the parent is
// given, and whose pid is that token; its result is its exit status.
func TestProcForkRunsTheChildInACopy(t *testing.T) {
	type seen struct{ cell, pidOut, pid, ppid int32 }
	got := make(chan seen, 1)
	w, m, _ := newForkingStubs(t, func(f *recordingForker, c *Module) int32 {
		ids := f.wasi(c).guestProcess().IDs()
		got <- seen{int32(readU32(c.memory, int(forkCellOff))), int32(readU32(c.memory, int(forkPidOff))), ids.PID, ids.PPID}
		c.memory[forkCellOff] = 9
		return 7
	})
	m.memory[forkCellOff] = 5
	pid, status := forkAndWait(t, w, m)
	if status != 7<<8 {
		t.Errorf("status %#x, want %#x", status, 7<<8)
	}
	s := <-got
	if want := (seen{5, 0, pid, w.guestPID()}); s != want {
		t.Errorf("the child saw %+v, want %+v", s, want)
	}
	if m.memory[forkCellOff] != 5 {
		t.Errorf("the parent's cell is %d after the child changed its own", m.memory[forkCellOff])
	}
}

// CopyForker copies the memory the guest has into memory of its own, as
// long as the guest's memory, or for a shared memory as the parent's.
func TestCopyForkerCopiesTheMemory(t *testing.T) {
	const size = 2 << 16
	for _, tc := range []struct {
		name   string
		shared bool
		length int
	}{{"unshared", false, size}, {"shared", true, 3 << 16}} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newProcTestStubs(t)
			m := &Module{memory: make([]byte, 3<<16), memSize: &atomic.Uint64{}, memShared: tc.shared, forkModule: standInForkModule}
			m.memSize.Store(size)
			m.memory[size-1] = 1
			c, done, err := CopyForker.Fork(m, w.Fork(), 1000)
			if err != nil || done != nil {
				t.Fatalf("Fork: done %v, err %v", done != nil, err)
			}
			if len(c.memory) != tc.length || c.memSize.Load() != size {
				t.Fatalf("copy of length %d and size %d, want %d and %d", len(c.memory), c.memSize.Load(), tc.length, size)
			}
			if !bytes.Equal(c.memory, m.memory[:tc.length]) {
				t.Error("the copy's bytes are not the parent's")
			}
			c.memory[0] = 1
			if m.memory[0] != 0 {
				t.Error("the copy shares the parent's memory")
			}
		})
	}
}

// A fork fails with ENOSYS when the configuration names no Forker or the
// module has no fork child export, and with EFAULT when the pid cannot be
// written.
func TestProcForkRefused(t *testing.T) {
	w, m, _ := newForkingStubs(t, func(*recordingForker, *Module) int32 { return 0 })
	if rc := w.Proc_fork(m, int32(len(m.memory))); rc != -_wasiEFAULT {
		t.Errorf("Proc_fork past the memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Proc_fork64(m, highAddr); rc != -_wasiEFAULT {
		t.Errorf("Proc_fork64 past the memory rc=%d, want -EFAULT", rc)
	}
	w.cfg.Fork = nil
	if rc := w.Proc_fork(m, forkPidOff); rc != -_wasiENOSYS {
		t.Errorf("Proc_fork without a Forker rc=%d, want -ENOSYS", rc)
	}
	w.cfg.Fork = CopyForker
	m.forkChild = nil
	if rc := w.Proc_fork(m, forkPidOff); rc != -_wasiENOSYS {
		t.Errorf("Proc_fork without a fork child rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_wait_any(m, 1, forkPidOff, forkStatusOff); rc != -_wasiECHILD {
		t.Errorf("Proc_wait_any rc=%d, want -ECHILD", rc)
	}
}

// failingForker is a Forker that fails.
type failingForker struct{ err error }

func (f failingForker) Fork(*Module, *WasiStubs, int32) (*Module, func(status int32), error) {
	return nil, nil, f.err
}

// A fork whose Forker fails is EAGAIN, the error is told Errors, and no
// child is left: nothing to wait for, and the descriptors the child's host
// state shared are the parent's alone again.
func TestProcForkForkerFails(t *testing.T) {
	w, m := newProcTestStubs(t)
	m.forkChild = func(*Module) int32 { return 0 }
	failure := errors.New("no instance")
	w.cfg.Fork = failingForker{failure}
	var told []error
	w.cfg.Errors = func(op string, err error) {
		if op == "proc_fork" {
			told = append(told, err)
		}
	}
	_, writeFd := newTestPipe(t, w, m)
	if rc := w.Proc_fork(m, forkPidOff); rc != -_wasiEAGAIN {
		t.Fatalf("Proc_fork rc=%d, want -EAGAIN", rc)
	}
	if len(told) != 1 || !errors.Is(told[0], failure) {
		t.Errorf("Errors was told %v, want %v", told, failure)
	}
	if rc := w.Proc_wait_any(m, 1, forkPidOff, forkStatusOff); rc != -_wasiECHILD {
		t.Errorf("Proc_wait_any rc=%d, want -ECHILD", rc)
	}
	if refs := slotRefs(t, w, writeFd); refs != 1 {
		t.Errorf("the write end is in %d slots, want 1", refs)
	}
}

// The child ends with the status of its exit, of the signal that ended it,
// or of SIGABRT for a panic, which is told Errors (an error panicked with
// wrapped in it).
func TestProcForkChildEnds(t *testing.T) {
	panicked := errors.New("panicked")
	for _, tc := range []struct {
		name   string
		child  func(w *WasiStubs, m *Module) int32
		status int32
		told   bool
		err    error
	}{
		{"return", func(*WasiStubs, *Module) int32 { return 0x103 }, 3 << 8, false, nil},
		{"exit", func(w *WasiStubs, m *Module) int32 { w.Proc_exit(m, 5); return 0 }, 5 << 8, false, nil},
		{"terminate", func(w *WasiStubs, m *Module) int32 { w.Proc_terminate(m, wasiSIGTERM); return 0 }, wasiSIGTERM, false, nil},
		{"trap", func(*WasiStubs, *Module) int32 { panic("wasm: unreachable") }, wasiSIGABRT, true, nil},
		{"error", func(*WasiStubs, *Module) int32 { panic(panicked) }, wasiSIGABRT, true, panicked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m, _ := newForkingStubs(t, func(f *recordingForker, c *Module) int32 { return tc.child(f.wasi(c), c) })
			var told []error
			w.cfg.Errors = func(op string, err error) {
				if op == "proc_fork" {
					told = append(told, err)
				}
			}
			if _, status := forkAndWait(t, w, m); status != tc.status {
				t.Errorf("status %#x, want %#x", status, tc.status)
			}
			if got := len(told) == 1; got != tc.told {
				t.Errorf("Errors was told %v", told)
			}
			if tc.err != nil && (len(told) != 1 || !errors.Is(told[0], tc.err)) {
				t.Errorf("Errors was told %v, want %v wrapped", told, tc.err)
			}
		})
	}
}

// panickingForker is a Forker that panics with err.
type panickingForker struct{ err error }

func (f panickingForker) Fork(*Module, *WasiStubs, int32) (*Module, func(status int32), error) {
	panic(f.err)
}

// A Forker that panics leaves no child: the panic goes on through the
// guest's call, and the descriptors the child's host state shared are the
// parent's alone again.
func TestProcForkForkerPanics(t *testing.T) {
	w, m := newProcTestStubs(t)
	m.forkChild = func(*Module) int32 { return 0 }
	failure := errors.New("no instance")
	w.cfg.Fork = panickingForker{failure}
	_, writeFd := newTestPipe(t, w, m)
	func() {
		defer func() {
			r := recover()
			if err, ok := r.(error); !ok || !errors.Is(err, failure) {
				t.Errorf("Proc_fork panicked with %v, want %v", r, failure)
			}
		}()
		w.Proc_fork(m, forkPidOff)
	}()
	if refs := slotRefs(t, w, writeFd); refs != 1 {
		t.Errorf("the write end is in %d slots, want 1", refs)
	}
	if rc := w.Proc_wait_any(m, 1, forkPidOff, forkStatusOff); rc != -_wasiECHILD {
		t.Errorf("Proc_wait_any rc=%d, want -ECHILD", rc)
	}
}

// A done that panics is told Errors, and the child is closed and its
// status published all the same.
func TestProcForkDonePanics(t *testing.T) {
	w, m, f := newForkingStubs(t, func(*recordingForker, *Module) int32 { return 4 })
	panicked := errors.New("done panicked")
	f.done = func(int32) { panic(panicked) }
	var told []error
	w.cfg.Errors = func(op string, err error) {
		if op == "proc_fork" {
			told = append(told, err)
		}
	}
	_, writeFd := newTestPipe(t, w, m)
	if _, status := forkAndWait(t, w, m); status != 4<<8 {
		t.Errorf("status %#x, want %#x", status, 4<<8)
	}
	if len(told) != 1 || !errors.Is(told[0], panicked) {
		t.Errorf("Errors was told %v, want %v wrapped", told, panicked)
	}
	if refs := slotRefs(t, w, writeFd); refs != 1 {
		t.Errorf("the write end is in %d slots, want 1", refs)
	}
}

// A child killed before it registers for signals ends by SIGKILL at its
// next blocking call.
func TestProcForkChildKilled(t *testing.T) {
	var readFd int32
	w, m, _ := newForkingStubs(t, func(f *recordingForker, c *Module) int32 {
		got, rc := fdReadString(f.wasi(c), c, readFd, 1)
		t.Errorf("the child's read returned %q rc=%d instead of ending the child", got, rc)
		return 0
	})
	readFd, _ = newTestPipe(t, w, m)
	if rc := w.Proc_fork(m, forkPidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_fork rc=%d", rc)
	}
	pid := int32(readU32(m.memory, int(forkPidOff)))
	if rc := w.Proc_kill(m, pid, wasiSIGKILL); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 0, forkStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, int(forkStatusOff))); status != wasiSIGKILL {
		t.Errorf("status %#x, want SIGKILL", status)
	}
}

// hookedCloser is a file whose close calls closed first.
type hookedCloser struct {
	File
	closed func()
}

func (f hookedCloser) Close() error {
	f.closed()
	return f.File.Close()
}

// When the child has ended, done is called with its status, then its
// descriptors are closed, and only then can its status be waited for.
func TestProcForkEndsInOrder(t *testing.T) {
	w, m, f := newForkingStubs(t, func(*recordingForker, *Module) int32 { return 2 })
	events, release := make(chan string), make(chan struct{})
	hook := func(event string) {
		events <- event
		<-release
	}
	var given int32
	f.done = func(status int32) {
		given = status
		hook("done")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "f"))
	if err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{f: hookedCloser{File: file, closed: func() { hook("close") }}})
	w.mu.Unlock()
	if rc := w.Proc_fork(m, forkPidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_fork rc=%d", rc)
	}
	pid := int32(readU32(m.memory, int(forkPidOff)))
	for _, want := range []string{"done", "close"} {
		if got := <-events; got != want {
			t.Fatalf("%s came where %s was due", got, want)
		}
		if want == "done" {
			// The child's slot is the file's last one from here on.
			if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
				t.Fatalf("Fd_close rc=%d", rc)
			}
		}
		if rc := w.Proc_wait(m, pid, 1, forkStatusOff); rc != -_wasiEAGAIN {
			t.Errorf("Proc_wait while %s runs rc=%d, want -EAGAIN", want, rc)
		}
		release <- struct{}{}
	}
	if rc := w.Proc_wait(m, pid, 0, forkStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, int(forkStatusOff))); status != 2<<8 || given != status {
		t.Errorf("status %#x, done given %#x, want %#x", status, given, 2<<8)
	}
}
