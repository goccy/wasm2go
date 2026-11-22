//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
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
