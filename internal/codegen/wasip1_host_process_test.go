//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func hostOSName() string { return runtime.GOOS }

// spawnTestCommand starts a command with the instance's own streams and
// returns the pid the guest knows it by.
func spawnTestCommand(t *testing.T, w *WasiStubs, m *Module, argv ...string) int32 {
	t.Helper()
	return spawnTestProc(t, w, m, argv...)
}

func closeOnExec(t *testing.T, w *WasiStubs, m *Module, fd, set, value int32) uint32 {
	t.Helper()
	const oldOff int32 = 6000
	if rc := w.Fd_cloexec(m, fd, set, value, oldOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_cloexec(%d) rc=%d", fd, rc)
	}
	return binary.LittleEndian.Uint32(m.memory[oldOff:])
}

// A command inherits the descriptors above 2 that are not marked
// close-on-exec, under their numbers.
func TestSpawnedCommandInheritsDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	const pipeOut int32 = 5000
	if rc := w.Pipe(m, pipeOut); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	readFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut:]))
	writeFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut+4:]))
	if rc := w.Pipe(m, pipeOut); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	hiddenRead := int32(binary.LittleEndian.Uint32(m.memory[pipeOut:]))
	hiddenWrite := int32(binary.LittleEndian.Uint32(m.memory[pipeOut+4:]))

	if got := closeOnExec(t, w, m, hiddenWrite, 1, 1); got != 0 {
		t.Fatalf("a new descriptor is marked close-on-exec")
	}
	if got := closeOnExec(t, w, m, hiddenWrite, 0, 0); got != 1 {
		t.Fatalf("the mark did not stay")
	}
	if rc := w.Fd_cloexec(m, 999, 0, 0, 6000); rc != -_wasiEBADF {
		t.Fatalf("Fd_cloexec of a closed descriptor rc=%d, want -EBADF", rc)
	}

	script := "echo inherited >&" + itoa32(writeFd) + "; (echo leaked >&" + itoa32(hiddenWrite) + ") 2>/dev/null; exit 0"
	pid := spawnTestCommand(t, w, m, "/bin/sh", "-c", script)
	if rc := w.Proc_wait(m, pid, 0, 4004); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	for _, fd := range []int32{writeFd, hiddenWrite} {
		if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
			t.Fatalf("close rc=%d", rc)
		}
	}
	if got, rc := fdReadString(w, m, readFd, 64); rc != _wasiESUCCESS || got != "inherited\n" {
		t.Fatalf("through the inherited descriptor: %q rc=%d", got, rc)
	}
	if got, rc := fdReadString(w, m, hiddenRead, 64); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("through the close-on-exec descriptor: %q rc=%d, want end of file", got, rc)
	}

	// A duplicate does not carry the mark, and a number given out again
	// starts without it.
	if rc := w.Pipe(m, pipeOut); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	again := int32(binary.LittleEndian.Uint32(m.memory[pipeOut+4:]))
	closeOnExec(t, w, m, again, 1, 1)
	const dupOff int32 = 6100
	if rc := w.Fd_dup(m, again, dupOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	dup := int32(binary.LittleEndian.Uint32(m.memory[dupOff:]))
	if got := closeOnExec(t, w, m, dup, 0, 0); got != 0 {
		t.Fatal("a duplicate inherited the close-on-exec mark")
	}
	if rc := w.Fd_close(m, again); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	if rc := w.Fd_dup(m, dup, dupOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	if reused := int32(binary.LittleEndian.Uint32(m.memory[dupOff:])); reused != again {
		t.Fatalf("the number was not reused: %d, want %d", reused, again)
	}
	if got := closeOnExec(t, w, m, again, 0, 0); got != 0 {
		t.Fatal("a reused number kept the close-on-exec mark")
	}
}

// The children of a process that ignores SIGCHLD leave nothing to wait
// for: a wait lasts until they have ended and then reports ECHILD.
func TestIgnoredSIGCHLDLeavesNoZombies(t *testing.T) {
	w, m := newSignalGuest(t)
	setDispositions(t, w, m, 0, wasiSignalBit(wasiSIGCHLD), 0)
	const statusOff int32 = 4004

	pid, exited := w.NewProc(nil)
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("wait without hanging for a running child rc=%d, want -EAGAIN", rc)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		exited(3 << 8)
	}()
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != -_wasiECHILD {
		t.Fatalf("wait for the child rc=%d, want -ECHILD", rc)
	}
	if rc := w.Proc_kill(m, pid, 0); rc != -_wasiESRCH {
		t.Fatalf("the child is still a process: probe rc=%d", rc)
	}

	other, otherExited := w.NewProc(nil)
	go func() {
		time.Sleep(50 * time.Millisecond)
		otherExited(0)
	}()
	if rc := w.Proc_wait_any(m, 0, 4000, statusOff); rc != -_wasiECHILD {
		t.Fatalf("wait for any child rc=%d, want -ECHILD", rc)
	}
	if rc := w.Proc_kill(m, other, 0); rc != -_wasiESRCH {
		t.Fatalf("the child is still a process: probe rc=%d", rc)
	}

	// A child that ended before the signal was ignored is given up when it
	// is; with the default action restored a child is waited for again.
	setDispositions(t, w, m, 0, 0, 0)
	zombie, zombieExited := w.NewProc(nil)
	zombieExited(0)
	setDispositions(t, w, m, 0, wasiSignalBit(wasiSIGCHLD), 0)
	if rc := w.Proc_wait(m, zombie, 0, statusOff); rc != -_wasiECHILD {
		t.Fatalf("wait for a child given up rc=%d, want -ECHILD", rc)
	}
	setDispositions(t, w, m, 0, 0, 0)
	last, lastExited := w.NewProc(nil)
	lastExited(7 << 8)
	if rc := w.Proc_wait(m, last, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("wait with the default action rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 7<<8 {
		t.Fatalf("status = %#x", status)
	}
}

// A signal whose default action is to do nothing interrupts no blocking
// call, without the guest saying so.
func TestDefaultIgnoredSignalIsDropped(t *testing.T) {
	w, _ := newSignalGuest(t)
	w.PostSignal(wasiSIGCHLD)
	w.PostSignal(wasiSIGWINCH)
	w.mu.Lock()
	pending, interrupt := w.sig.pending, w.sig.interrupt
	w.mu.Unlock()
	if pending != 0 || interrupt {
		t.Fatalf("pending = %#x, interrupt = %v", pending, interrupt)
	}
}

func TestProcTimes(t *testing.T) {
	w, m := newProcTestStubs(t)
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, _ = os.Stat(".")
	}
	if rc := w.Proc_times(m, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_times rc=%d", rc)
	}
	user := binary.LittleEndian.Uint64(m.memory[64:])
	system := binary.LittleEndian.Uint64(m.memory[72:])
	if user == 0 || system == 0 {
		t.Fatalf("user = %dns, system = %dns: both are spent by now", user, system)
	}
}

// A guest that is the host process and has waited for a command it
// started finds the command off the host's process table, and its CPU
// time in the times of the children (as times after system shows them):
// the host adds a child's time to its parent's when it takes the child off
// the table, and the guest's wait does that before it returns. The
// command's streams are the host's, so that the runtime learns of its end
// from the host without waiting for it there and then (Linux).
func TestProcTimesCountTheChildrenWaitedFor(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	KeepRuntimeDescriptorsHigh()
	forwardSIGPIPEToIgnore()
	w.hostProcess = true
	t.Cleanup(func() { _ = w.CloseAll() })
	children := func() uint64 {
		t.Helper()
		if rc := w.Proc_times(m, 64); rc != _wasiESUCCESS {
			t.Fatalf("Proc_times rc=%d", rc)
		}
		return binary.LittleEndian.Uint64(m.memory[80:]) + binary.LittleEndian.Uint64(m.memory[88:])
	}
	before := children()
	pid := spawnTestProc(t, w, m, "/bin/sh", "-c", "i=0; while [ $i -lt 30000 ]; do i=$((i+1)); done")
	const statusOff int32 = 5000
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 0 {
		t.Fatalf("status = %#x, want a clean exit", status)
	}
	if err := syscall.Kill(int(pid), 0); err != syscall.ESRCH {
		t.Errorf("the command is still on the host's process table after the wait: kill(pid, 0) = %v", err)
	}
	if after := children(); after <= before {
		t.Errorf("the times of the children are %dns after the wait, %dns before it: the command's are not in them", after, before)
	}
}

// failingIDs is a HostIDs whose every call fails with err.
type failingIDs struct{ err error }

func (f failingIDs) Setuid(int) error              { return f.err }
func (f failingIDs) Seteuid(int) error             { return f.err }
func (f failingIDs) Setreuid(int, int) error       { return f.err }
func (f failingIDs) Setresuid(int, int, int) error { return f.err }
func (f failingIDs) Setgid(int) error              { return f.err }
func (f failingIDs) Setegid(int) error             { return f.err }
func (f failingIDs) Setregid(int, int) error       { return f.err }
func (f failingIDs) Setresgid(int, int, int) error { return f.err }
func (f failingIDs) Setgroups([]int) error         { return f.err }

// The error of the host's call that changes an id reaches the guest as the
// wasi errno of the same meaning, from the runtime's own call (EPERM for
// another user's id, to a user who is not the superuser) and from an
// embedder's (SetHostIDs).
func TestProcSetidsReportsTheErrorOfTheHostCall(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetHostProcess(true)
	defer w.SetHostProcess(false)
	if os.Getuid() != 0 {
		if rc := w.Proc_setids(m, wasiSetUID, int32(os.Getuid()+1), -1, -1); rc != -_wasiEPERM {
			t.Errorf("setuid to another user rc=%d, want -EPERM", rc)
		}
		if rc := w.Proc_setids(m, wasiSetREUID, -1, int32(os.Getuid()+1), -1); rc != -_wasiEPERM {
			t.Errorf("setreuid to another user rc=%d, want -EPERM", rc)
		}
	}
	for _, c := range []struct {
		err  error
		want int32
	}{
		{syscall.EPERM, _wasiEPERM},
		{syscall.EINVAL, _wasiEINVAL},
		{syscall.EAGAIN, _wasiEAGAIN},
		{errors.ErrUnsupported, _wasiENOSYS},
	} {
		w.SetHostIDs(failingIDs{c.err})
		for request := wasiSetUID; request <= wasiSetRESGID; request++ {
			if rc := w.Proc_setids(m, request, 1, 2, 3); rc != -c.want {
				t.Errorf("request %d failing with %v: rc=%d, want %d", request, c.err, rc, -c.want)
			}
		}
	}
	w.SetHostIDs(nil)
}

func TestMkfifoAndOwner(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	path := writeCStr(m, 1000, "queue")
	if rc := w.Path_mkfifo(m, path, 5, 0o600); rc != _wasiESUCCESS {
		t.Fatalf("Path_mkfifo rc=%d", rc)
	}
	fi, err := os.Stat(filepath.Join(dir, "queue"))
	if err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("no FIFO was made: %v %v", fi, err)
	}
	if rc := w.Path_mkfifo(m, path, 5, 0o600); rc != -_wasiEEXIST {
		t.Fatalf("a second FIFO of the name rc=%d, want -EEXIST", rc)
	}
	// Giving a file to its owner changes nothing and is allowed; giving it
	// away is the host's to refuse.
	if rc := w.Path_chown(m, path, 5, int32(os.Getuid()), -1, 1); rc != _wasiESUCCESS {
		t.Fatalf("Path_chown to the owner rc=%d", rc)
	}
	if os.Getuid() != 0 {
		if rc := w.Path_chown(m, path, 5, 0, -1, 1); rc != -_wasiEPERM {
			t.Fatalf("Path_chown to root rc=%d, want -EPERM", rc)
		}
	}
	missing := writeCStr(m, 1100, "nothing")
	if rc := w.Path_chown(m, missing, 7, -1, -1, 1); rc != -_wasiENOENT {
		t.Fatalf("Path_chown of a missing file rc=%d, want -ENOENT", rc)
	}
	// An in-memory filesystem has neither.
	w.SetFS(NewMemFS())
	if rc := w.Path_mkfifo(m, path, 5, 0o600); rc != -_wasiENOSYS {
		t.Fatalf("Path_mkfifo in memory rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Path_chown(m, path, 5, 0, 0, 1); rc != -_wasiENOSYS {
		t.Fatalf("Path_chown in memory rc=%d, want -ENOSYS", rc)
	}
}

func TestUnameAndPriorityAreTheHostProcesss(t *testing.T) {
	w, m := newProcTestStubs(t)
	if rc := w.Proc_uname(m, 1000, 1024, 64); rc != -_wasiENOSYS {
		t.Fatalf("Proc_uname of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_priority(m, 0, 0, 0, 0, 64); rc != -_wasiENOSYS {
		t.Fatalf("Proc_priority of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Proc_setids(m, wasiSetUID, int32(os.Getuid()), -1, -1); rc != -_wasiENOSYS {
		t.Fatalf("Proc_setids of an isolated guest rc=%d, want -ENOSYS", rc)
	}
	w.SetHostProcess(true)
	defer w.SetHostProcess(false)
	if rc := w.Proc_uname(m, 1000, 1024, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_uname rc=%d", rc)
	}
	rec := &wasiRecordReader{t: t, rec: m.memory[1000 : 1000+binary.LittleEndian.Uint32(m.memory[64:])]}
	sysname, nodename := rec.str(), rec.str()
	host, _ := os.Hostname()
	if !strings.EqualFold(sysname, map[string]string{"darwin": "Darwin", "linux": "Linux"}[hostOSName()]) {
		t.Errorf("system name = %q", sysname)
	}
	if nodename != host {
		t.Errorf("node name = %q, want %q", nodename, host)
	}
	if rc := w.Proc_priority(m, 0, 0, 0, 0, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_priority rc=%d", rc)
	}
	want, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hostOSName() == "linux" {
		want = 20 - want
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[64:])); int(got) != want {
		t.Errorf("nice value = %d, want %d", got, want)
	}
	// Changing an id to what it is is always allowed.
	if rc := w.Proc_setids(m, wasiSetUID, int32(os.Getuid()), -1, -1); rc != _wasiESUCCESS {
		t.Errorf("setuid to the current user rc=%d", rc)
	}
}

// An open of a FIFO that a signal interrupts leaves nothing behind: when
// the guest is told EINTR, no end of the FIFO is open any more — neither
// the one it asked for nor the one that made the host's open return — so
// the next open of the other end waits for a peer as the first did, and
// does not meet a leftover.
func TestOpenOfAFIFOInterruptedLeavesNoEndOpen(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir, wasiSIGUSR1)
	fifo := filepath.Join(dir, "queue")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeCStr(m, 1000, "queue")
	const rightsRead, rightsWrite, fdOut = 1 << 1, 1 << 6, 200
	for round := 0; round < 20; round++ {
		// Open for reading with nobody writing: interrupted.
		postSoon(w, wasiSIGUSR1)
		if rc := w.Path_open(m, 3, 1, path, 5, 0, rightsRead, 0, 0, fdOut); rc != _wasiEINTR {
			t.Fatalf("round %d: open for reading rc=%d, want EINTR", round, rc)
		}
		takeSignals(t, w, m)
		// No reader is left: a writer that does not wait is refused.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
			t.Fatalf("round %d: the FIFO still has a reader after the interrupted open for reading", round)
		} else if !strings.Contains(err.Error(), syscall.ENXIO.Error()) {
			t.Fatalf("round %d: open for writing without waiting: %v, want ENXIO", round, err)
		}

		// Open for writing with nobody reading: interrupted.
		postSoon(w, wasiSIGUSR1)
		if rc := w.Path_open(m, 3, 1, path, 5, 0, rightsWrite, 0, 0, fdOut); rc != _wasiEINTR {
			t.Fatalf("round %d: open for writing rc=%d, want EINTR", round, rc)
		}
		takeSignals(t, w, m)
		// No writer is left: a reader finds the end of input, not an
		// empty FIFO that someone may still write to.
		reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, err := syscall.Read(int(reader.Fd()), make([]byte, 1))
		reader.Close()
		if n != 0 || err != nil {
			t.Fatalf("round %d: read after the interrupted open for writing = %d, %v: the FIFO still has a writer", round, n, err)
		}
	}
	w.mu.Lock()
	open := len(w.fdsLocked())
	w.mu.Unlock()
	if open != 3 {
		t.Fatalf("%d descriptors are open after the interrupted opens, want the standard three", open)
	}
}

// A FIFO opened with O_NONBLOCK is opened without waiting for the other
// end: for reading it opens at once, for writing it is refused with ENXIO
// while nobody reads and opens once somebody does.
func TestOpenOfAFIFOWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	if err := syscall.Mkfifo(filepath.Join(dir, "queue"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeCStr(m, 1000, "queue")
	const rightsRead, rightsWrite, fdOut = 1 << 1, 1 << 6, 200
	done := make(chan int32, 1)
	go func() { done <- w.Path_open(m, 3, 1, path, 5, 0, rightsWrite, 0, wasiFdflagNonblock, fdOut) }()
	select {
	case rc := <-done:
		if rc != _wasiENXIO {
			t.Fatalf("open for writing without waiting, nobody reading: rc=%d, want ENXIO", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open for writing waited")
	}
	go func() { done <- w.Path_open(m, 3, 1, path, 5, 0, rightsRead, 0, wasiFdflagNonblock, fdOut) }()
	select {
	case rc := <-done:
		if rc != _wasiESUCCESS {
			t.Fatalf("open for reading without waiting rc=%d", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open for reading waited")
	}
	readFd := int32(readU32(m.memory, fdOut))
	if rc := w.Path_open(m, 3, 1, path, 5, 0, rightsWrite, 0, wasiFdflagNonblock, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("open for writing without waiting, somebody reading: rc=%d", rc)
	}
	writeFd := int32(readU32(m.memory, fdOut))
	// Nothing has been written: the read does not wait either.
	if _, rc := fdReadString(w, m, readFd, 8); rc != _wasiEAGAIN {
		t.Fatalf("read of the empty FIFO rc=%d, want EAGAIN", rc)
	}
	if rc := fdWriteString(w, m, writeFd, "through"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, readFd, 8); rc != _wasiESUCCESS || got != "through" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

// A readiness probe that has no time left still finds what is there: input
// in a pipe, a datagram, a connection waiting at a listener. The time a
// probe is given bounds its wait, not its look — a probe that is scheduled
// late must not report a descriptor that is ready as not ready.
func TestProbeWithNoTimeLeftFindsWhatIsThere(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetNetAccessHook(func(string) bool { return true })
	past := func() time.Time { return time.Now().Add(-time.Second) }
	entry := func(fd int32) *wasiOpen {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.fdsLocked()[fd]
	}

	// a pipe
	readFd, writeFd := newTestPipe(t, w, m)
	op := entry(readFd)
	w.mu.Lock()
	src, _ := w.fdSrcLocked(readFd)
	w.mu.Unlock()
	stream, blocks := op.readBlocks(src)
	if !blocks {
		t.Fatal("the read end of a pipe is not a stream")
	}
	if ready, _ := op.probeRead(stream, past(), nil); ready {
		t.Fatal("an empty pipe is ready")
	}
	if rc := fdWriteString(w, m, writeFd, "input"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if ready, refused := op.probeRead(stream, past(), nil); !ready || refused {
		t.Fatalf("a pipe with input: ready=%v refused=%v, want ready", ready, refused)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "input" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	// the end of input is there to be found as well
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	if ready, _ := op.probeRead(stream, past(), nil); !ready {
		t.Fatal("a pipe at its end is not ready")
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at the end = %q rc=%d", got, rc)
	}

	// a datagram socket
	server := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, server, int32(loopbackBE), 0); rc != 0 {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	serverName := localName(t, w, m, server)
	sop := entry(server)
	dgram, _ := sop.netConn().(datagramSocket)
	if dgram == nil {
		t.Fatal("the bound datagram socket has no host socket")
	}
	if sop.probeDatagram(dgram, past(), nil) {
		t.Fatal("a datagram socket nothing was sent to is ready")
	}
	client := newDatagramSocket(t, w, m)
	if sent, rc := sendTo(w, m, client, "datagram", uint32(loopbackBE), int32(serverName.port)); rc != 0 || sent != 8 {
		t.Fatalf("sendto: %d bytes rc=%d", sent, rc)
	}
	clientName := localName(t, w, m, client)
	if !sop.probeDatagram(dgram, past(), nil) {
		t.Fatal("a datagram socket with a datagram waiting is not ready")
	}
	if got, from, rc := recvFrom(w, m, server, 64); rc != 0 || got != "datagram" || from.port != clientName.port || from.ip != uint32(loopbackBE) {
		t.Fatalf("recvfrom = %q from %+v rc=%d, want the datagram from port %d", got, from, rc, clientName.port)
	}

	// a listening socket
	listener, port := newListener(t, w, m)
	lop := entry(listener)
	l, _ := lop.netListener()
	bounded, _ := l.(deadlineListener)
	if bounded == nil {
		t.Fatal("the listener cannot be bounded")
	}
	if lop.probeAccept(bounded, past(), nil) {
		t.Fatal("a listener nobody connected to is ready")
	}
	conn := dialLoopback(t, w, m, port)
	if !lop.probeAccept(bounded, past(), nil) {
		t.Fatal("a listener with a connection waiting is not ready")
	}
	accepted, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	if rc := sockSend(w, m, conn, "over"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, accepted); rc != _wasiESUCCESS || got != "over" {
		t.Fatalf("recv on the accepted connection = %q rc=%d", got, rc)
	}
}

// A guest that takes to ignoring SIGPIPE and stops again does not end the
// host process on the way: neither the signal's default action nor the
// action the Go runtime forwards a signal to while it is not handling it
// (the default action, unless forwardSIGPIPEToIgnore has run) is in place
// at any moment. The process writes into closed pipes all the while —
// another process of the family, the runtime, a library — and the default
// action of SIGPIPE ends a process at such a write.
//
// Linux only: on darwin, a Go program that has SIGPIPE ignored and taken
// back over and over while it writes into a closed pipe dies of SIGBUS
// inside the runtime, with no code of the runtime here involved (a program
// of a few lines that calls signal.Ignore, signal.Notify and signal.Stop in
// a loop does).
func TestHostProcessStopsIgnoringSIGPIPEWithoutEndingOnTheWay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("darwin's Go runtime does not survive SIGPIPE taken back over and over while it comes")
	}
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(p[0])
	defer syscall.Close(p[1])
	w, m := newSignalGuest(t)
	w.SetHostProcess(true)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = syscall.Write(p[1], []byte("x"))
		}
	}()
	for i := 0; i < 2000; i++ {
		setDispositions(t, w, m, 0, signalMask(wasiSIGPIPE), 0)
		setDispositions(t, w, m, 0, 0, 0)
	}
	close(stop)
	<-done
	w.CloseAll()
}

// A signal the guest ignores is ignored by the host process, and by the
// commands it starts meanwhile, which inherit that. When the guest stops
// ignoring the signal, and when the instance is closed, the signal has its
// default action again: for the host process, and for a command started
// from then on.
func TestHostProcessStopsIgnoringWhatTheGuestStopsIgnoring(t *testing.T) {
	// whether a command started now survives the signal it sends itself
	inherits := func(sig syscall.Signal) bool {
		return exec.Command("/bin/sh", "-c", "kill -"+strconv.Itoa(int(sig))+" $$; exit 0").Run() == nil
	}
	for _, sig := range []int32{wasiSIGHUP, wasiSIGINT, wasiSIGTERM, wasiSIGUSR2} {
		hostSig, _ := hostSignalOf(sig)
		if inherits(hostSig) {
			t.Skipf("the test process was started with signal %d ignored", sig)
		}
		w, m := newSignalGuest(t)
		w.SetHostProcess(true)
		setDispositions(t, w, m, 0, signalMask(sig), 0)
		if !inherits(hostSig) {
			t.Errorf("signal %d: a command started while the guest ignores it does not ignore it", sig)
		}
		setDispositions(t, w, m, 0, 0, 0)
		if inherits(hostSig) {
			t.Errorf("signal %d: still ignored by a command after the guest stopped ignoring it", sig)
		}
		if signal.Ignored(hostSig) {
			t.Errorf("signal %d: still ignored by the host process after the guest stopped ignoring it", sig)
		}
		setDispositions(t, w, m, 0, signalMask(sig), 0)
		w.CloseAll()
		if inherits(hostSig) {
			t.Errorf("signal %d: still ignored by a command after the instance was closed", sig)
		}
	}
}
