//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// onTerminalEnv marks the run of the test binary that runTestOnTerminal
// starts.
const onTerminalEnv = "WASM2GO_TEST_ON_TERMINAL"

// runTestOnTerminal runs the test name in a process of its own that leads
// a session whose controlling terminal is a pseudo-terminal, its stdin:
// a controlling terminal and its foreground group belong to the whole
// process. It reports whether the caller is that process, which then runs
// the test.
func runTestOnTerminal(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv(onTerminalEnv) != "" {
		return true
	}
	_, slave := openTestPty(t)
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), onTerminalEnv+"=1")
	var out bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s on a terminal: %v\n%s", name, err, out.Bytes())
	}
	return false
}

// tcpgrp makes the guest of w's tcgetpgrp of fd (fd_ioctl's TIOCGPGRP),
// and with set its tcsetpgrp of pgrp (TIOCSPGRP), and returns the group
// read and the errno.
func tcpgrp(w *WasiStubs, m *Module, fd int32, set bool, pgrp int32) (int32, int32) {
	request := int32(linuxTIOCGPGRP)
	if set {
		request = linuxTIOCSPGRP
		binary.LittleEndian.PutUint32(m.memory[jobOutOff:], uint32(pgrp))
	}
	if rc := w.Fd_ioctl(m, fd, request, jobOutOff); rc < 0 {
		return 0, rc
	}
	return int32(readU32(m.memory, int(jobOutOff))), _wasiESUCCESS
}

// hostForegroundOf returns the host's foreground group of the terminal f.
func hostForegroundOf(t *testing.T, f *os.File) int {
	t.Helper()
	var pgid int
	if err := withHostDescriptor(f, func(fd uintptr) error {
		var err error
		pgid, err = hostForeground(int(fd))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return pgid
}

// newProcTestStubsOn returns host state without a Process whose stdin is
// stdin.
func newProcTestStubsOn(t *testing.T, stdin *os.File) *WasiStubs {
	t.Helper()
	w, _ := newProcTestStubs(t)
	w.cfg.Stdin = stdin
	return w
}

// The foreground group of the controlling terminal is the family's: the
// group the host process is in stands for the host process's, another for
// its group of the host's, which a group that has none yet gets when its
// first command is started, in the foreground. The host process gets its
// terminal back though it is in the background then.
func TestTerminal_ForegroundGroupIsTheFamilys(t *testing.T) {
	if !runTestOnTerminal(t, "TestTerminal_ForegroundGroupIsTheFamilys") {
		return
	}
	root, m := newProcTestStubs(t)
	root.cfg.Stdin = os.Stdin
	// fd_ioctl has a terminal be the controlling terminal of an instance
	// with a Process only.
	root.cfg.Process = testProcess{ids: ProcessIDs{PID: 42, PPID: 1}}
	if _, rc := tcpgrp(newProcTestStubsOn(t, os.Stdin), m, 0, false, 0); rc != -_wasiENOTTY {
		t.Fatalf("tcgetpgrp without a Process rc=%d, want -ENOTTY", rc)
	}
	own := getpgid(t, root, m, 0)
	if got, rc := tcpgrp(root, m, 0, false, 0); rc != _wasiESUCCESS || got != own {
		t.Fatalf("tcgetpgrp = %d rc=%d, want the root's group %d", got, rc, own)
	}
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	if _, rc := tcpgrp(root, m, 0, true, pid); rc != _wasiESUCCESS {
		t.Fatalf("tcsetpgrp of a group without commands rc=%d", rc)
	}
	if got := hostForegroundOf(t, os.Stdin); got != hostProcessGroup() {
		t.Fatalf("the host's foreground group is %d before the group has a command, want the host process's %d", got, hostProcessGroup())
	}
	if got, _ := tcpgrp(root, m, 0, false, 0); got != pid {
		t.Fatalf("tcgetpgrp = %d, want the child's group %d", got, pid)
	}
	cmd, p := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	if got := hostForegroundOf(t, os.Stdin); got != p.Pid {
		t.Fatalf("the host's foreground group is %d, want the command's %d", got, p.Pid)
	}
	if got, _ := tcpgrp(root, m, 0, false, 0); got != pid {
		t.Fatalf("tcgetpgrp = %d after the command started, want %d", got, pid)
	}
	for _, c := range []struct {
		pgrp int32
		host int
	}{{own, hostProcessGroup()}, {pid, p.Pid}, {own, hostProcessGroup()}} {
		if _, rc := tcpgrp(root, m, 0, true, c.pgrp); rc != _wasiESUCCESS {
			t.Fatalf("tcsetpgrp(%d) rc=%d", c.pgrp, rc)
		}
		if got := hostForegroundOf(t, os.Stdin); got != c.host {
			t.Fatalf("the host's foreground group is %d after tcsetpgrp(%d), want %d", got, c.pgrp, c.host)
		}
	}
	other, _, oexited := root.ForkProc()
	defer oexited(0)
	om := registeredFork(t, other)
	if rc := other.Proc_setsid(om, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if _, rc := tcpgrp(other, om, 0, false, 0); rc != -_wasiENOTTY {
		t.Errorf("tcgetpgrp in a session without a terminal rc=%d, want -ENOTTY", rc)
	}
	if _, rc := tcpgrp(root, m, 0, true, other.guestPID()); rc != -_wasiEPERM {
		t.Errorf("tcsetpgrp of a group of another session rc=%d, want -EPERM", rc)
	}
	readFd, _ := newTestPipe(t, root, m)
	if _, rc := tcpgrp(root, m, readFd, false, 0); rc != -_wasiENOTTY {
		t.Errorf("tcgetpgrp of a pipe rc=%d, want -ENOTTY", rc)
	}
	if rc := root.Proc_kill(m, cmd, wasiSIGKILL); rc != _wasiESUCCESS {
		t.Fatalf("kill rc=%d", rc)
	}
	if got := waitStatus(t, child, cm, cmd); got != uint32(wasiSIGKILL) {
		t.Errorf("command status %#x, want killed by SIGKILL", got)
	}

	// The descriptor of the terminal kept for a group without commands is
	// closed with the root.
	later, lpid, lexited := root.ForkProc()
	defer lexited(0)
	lm := registeredFork(t, later)
	if rc := later.Proc_setpgid(lm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	if _, rc := tcpgrp(root, m, 0, true, lpid); rc != _wasiESUCCESS {
		t.Fatalf("tcsetpgrp rc=%d", rc)
	}
	kept := root.pids.terminal
	if err := root.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := descriptorFlags(kept, syscall.F_GETFD); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("the kept descriptor of the terminal after CloseAll: %v, want EBADF", err)
	}
}

// A process forked within the runtime that leads a session of its own
// takes a terminal for the session's controlling terminal (TIOCSCTTY):
// /dev/tty is that terminal for it from then on, and the command it
// becomes takes it for its own. A process that leads no session cannot
// take one, nor can another session take that one.
func TestTerminal_SessionOfTheFamilyTakesATerminal(t *testing.T) {
	master, slave := openTestPty(t)
	root, _ := newProcTestStubs(t)
	root.cfg.Stdin = slave
	take := func(w *WasiStubs, m *Module) int32 { return w.Fd_ioctl(m, 0, linuxTIOCSCTTY, 0) }
	openTerminal := func(w *WasiStubs, m *Module) (int32, int32) {
		n := copy(m.memory[1000:], "/dev/tty")
		rc := w.Path_open(m, 3, 0, 1000, int32(n), 0, 1<<1|1<<6, 0, 0, 300)
		return int32(readU32(m.memory, 300)), rc
	}
	child, _, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := take(child, cm); rc != -_wasiEPERM {
		t.Fatalf("TIOCSCTTY of a process that leads no session rc=%d, want -EPERM", rc)
	}
	if rc := child.Proc_setsid(cm, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if _, rc := openTerminal(child, cm); rc != _wasiENXIO {
		t.Fatalf("open of /dev/tty in a session without a terminal rc=%d, want ENXIO", rc)
	}
	for range 2 {
		if rc := take(child, cm); rc != _wasiESUCCESS {
			t.Fatalf("TIOCSCTTY of the leader of a session rc=%d", rc)
		}
	}
	if _, rc := tcpgrp(child, cm, 0, false, 0); rc != -_wasiENOSYS {
		t.Errorf("tcgetpgrp of the session's terminal rc=%d, want -ENOSYS", rc)
	}
	fd, rc := openTerminal(child, cm)
	if rc != _wasiESUCCESS {
		t.Fatalf("open of /dev/tty rc=%d", rc)
	}
	child.mu.Lock()
	op := child.openLocked(fd)
	child.mu.Unlock()
	if got, want := testDevice(t, child.opHostFile(op)), testDevice(t, slave); got != want {
		t.Errorf("/dev/tty is device %#x, want the terminal's %#x", got, want)
	}
	if got, errno := child.ownLinkTarget(op, false); errno != _wasiESUCCESS || got != slave.Name() {
		t.Errorf("the link of /dev/tty leads to %q (errno %d), want the terminal's name %q", got, errno, slave.Name())
	}
	closeFd(t, child, cm, fd)
	other, _, oexited := root.ForkProc()
	defer oexited(0)
	om := registeredFork(t, other)
	if rc := other.Proc_setsid(om, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if rc := take(other, om); rc != -_wasiEPERM {
		t.Errorf("TIOCSCTTY of another session's terminal rc=%d, want -EPERM", rc)
	}
	// The master is read meanwhile: a system may wait for the output of
	// a terminal to drain as its controlling process ends, and hang the
	// terminal up then (darwin), which ends what the master reads (EOF)
	// and refuses a write to the terminal (EIO). Otherwise what is there
	// once the command has ended is read up to a line written after it.
	read := make(chan []byte, 1)
	go func() {
		var got []byte
		buf := make([]byte, 256)
		for !bytes.Contains(got, []byte("end of the test")) {
			n, err := master.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Errorf("read of the master: %v", err)
				}
				break
			}
		}
		read <- got
	}()
	var exit *WasiExitError
	if end, _ := (<-execIn(t, child, cm, "/bin/sh", "-c", "echo from the command >/dev/tty")).(error); !errors.As(end, &exit) || exit.Code != 0 {
		t.Errorf("the guest ended with %v, want an exit of 0", end)
	}
	if _, err := slave.WriteString("end of the test\n"); err != nil && !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
	if got := <-read; !bytes.Contains(got, []byte("from the command")) {
		t.Errorf("the master read %q, want what the command wrote to /dev/tty", got)
	}
}

// testDevice returns the device the special file f stands for.
func testDevice(t *testing.T, f *os.File) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := withHostDescriptor(f, func(fd uintptr) error { return syscall.Fstat(int(fd), &st) }); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Rdev)
}
