//go:build linux

package codegen

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An instance's creation thread has its umask: the kernel takes it out of
// what the instance creates on the host's filesystem, exactly, the host
// process's umask staying as it is, and a command the instance starts
// inherits it — a forked instance's own, too.
func TestCreationThreadHasTheInstancesUmask(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	host := hostUmask(t)
	w, m := newProcTestStubs(t)
	rootOut := &bytes.Buffer{}
	w.cfg.Stdout = rootOut
	w.Proc_umask(m, 0)
	if got := createWithMode(t, w, m, "root", 0o666); got != 0o666 {
		t.Errorf("file 0666 of the root under umask 0: %o, want 666", got)
	}
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	copyOut := &bytes.Buffer{}
	child.cfg.Stdout = copyOut
	cm := newForkTestModule()
	child.Proc_umask(cm, 0o077)
	if got := createWithMode(t, child, cm, "copy", 0o666); got != 0o600 {
		t.Errorf("file 0666 of the copy under umask 077: %o, want 600", got)
	}
	if got := mkdirWithMode(t, w, m, "rootdir", 0o777); got != 0o777 {
		t.Errorf("directory 0777 of the root under umask 0: %o, want 777", got)
	}
	// A mask set once the thread is there is the thread's.
	w.Proc_umask(m, 0o027)
	if got := createWithMode(t, w, m, "later", 0o666); got != 0o640 {
		t.Errorf("file 0666 of the root under umask 027: %o, want 640", got)
	}
	w.Proc_umask(m, 0)
	if got := hostUmask(t); got != host {
		t.Errorf("the host process's umask is %o, want it left at %o", got, host)
	}
	for _, c := range []struct {
		w    *WasiStubs
		m    *Module
		out  *bytes.Buffer
		want string
	}{{w, m, rootOut, "0000"}, {child, cm, copyOut, "0077"}} {
		pid := spawnTestProc(t, c.w, c.m, "/bin/sh", "-c", "umask")
		if rc := c.w.Proc_wait(c.m, pid, 0, 4004); rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
		if got := strings.TrimSpace(c.out.String()); got != c.want {
			t.Errorf("umask of a command = %q, want the instance's %s", got, c.want)
		}
	}
}

// A command started on the creation thread runs in its directory, not in
// the working directory of the thread's unshare. After CloseAll the
// instance makes no creation thread.
func TestCreationThreadStartsCommandsInTheHostsDirectory(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	w, m := newProcTestStubs(t)
	out := &bytes.Buffer{}
	w.cfg.Stdout = out
	// The thread is made, in the working directory of now, for a mask that
	// is not the host process's.
	w.Proc_umask(m, int32(hostUmask(t)^0o077))
	createWithMode(t, w, m, "made", 0o666)
	later := t.TempDir()
	if err := os.Mkdir(filepath.Join(later, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(later)
	w.cfg.FS = osFS{}
	for _, c := range []struct{ dir, want string }{{later, later}, {filepath.Join(later, "sub"), filepath.Join(later, "sub")}} {
		out.Reset()
		pathOff := writeCStr(m, 1000, "/bin/sh")
		argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "pwd -P"})
		cwdOff := writeCStr(m, 3800, c.dir)
		if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, cwdOff, 4000); rc != _wasiESUCCESS {
			t.Fatalf("Proc_spawn rc=%d", rc)
		}
		if rc := w.Proc_wait(m, int32(readU32(m.memory, 4000)), 0, 4004); rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
		want, err := filepath.EvalSymlinks(c.want)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(out.String()); got != want {
			t.Errorf("the command of directory %q ran in %q, want %q", c.dir, got, want)
		}
	}
	if err := w.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if th := w.creationThread(); th != nil {
		t.Fatal("a creation thread was made after CloseAll")
	}
}

// close ends the thread without waiting for the call it runs: the call
// returns afterwards, and none is run after close.
func TestCreationThreadCloseWaitsForNoCall(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	th, err := newCreationThread(0o022)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	ran := make(chan error, 1)
	go func() {
		ran <- th.run(func() {
			close(entered)
			<-release
		})
	}()
	<-entered
	th.close()
	if err := th.run(func() { t.Error("a call ran after close") }); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("run after close: %v, want ErrClosed", err)
	}
	close(release)
	if err := <-ran; err != nil {
		t.Fatalf("the call in progress: %v", err)
	}
}

// A command is started on the creation thread whatever the instance's
// filesystem: it inherits the instance's umask with a HostRootFS of MemFS
// too.
func TestCreationThreadStartsCommandsOfAnyFilesystem(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	w, m, mem := memTestStubs(t)
	w.cfg.FS = hostRootedFS{mem, "/"}
	out := &bytes.Buffer{}
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = out, &bytes.Buffer{}, bytes.NewReader(nil)
	w.Proc_umask(m, 0o077)
	pathOff := writeCStr(m, 1000, "/bin/sh")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "umask"})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	if rc := w.Proc_wait(m, int32(readU32(m.memory, 4000)), 0, 4004); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if got := strings.TrimSpace(out.String()); got != "0077" {
		t.Errorf("umask of a command of an instance of MemFS = %q, want 0077", got)
	}
}

// Where the instance's mask is the host process's umask, the instance
// creates and starts commands on the calling thread, as without creation
// threads: none is made. One is made once the masks differ.
func TestCreationThreadOnlyForAnotherMask(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	w, m := newProcTestStubs(t)
	w.cfg.Process = HostProcessUmask(hostUmask(t))
	creations := func() *creationThread {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.creations
	}
	createWithMode(t, w, m, "same", 0o666)
	mkdirWithMode(t, w, m, "samedir", 0o777)
	pid := spawnTestProc(t, w, m, "/bin/true")
	if rc := w.Proc_wait(m, pid, 0, 4004); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if creations() != nil {
		t.Fatal("a creation thread was made for the host process's umask")
	}
	w.Proc_umask(m, int32(hostUmask(t)^0o077))
	createWithMode(t, w, m, "other", 0o666)
	if creations() == nil {
		t.Fatal("no creation thread was made for another mask")
	}
}
