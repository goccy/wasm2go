//go:build darwin || linux

package codegen

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// execIn runs the guest of w's exec of argv (Proc_exec) on another
// goroutine. What it ended with arrives on the channel: its errno when it
// returned, the value of its panic when the guest ended.
func execIn(t *testing.T, w *WasiStubs, m *Module, argv ...string) <-chan any {
	t.Helper()
	if _, err := os.Stat(argv[0]); err != nil {
		t.Skipf("%s not available", argv[0])
	}
	pathOff := writeCStr(m, 1000, argv[0])
	argvOff := writeArgv(m, 2000, 3000, argv)
	ended := make(chan any, 1)
	go func() {
		var end any
		defer func() {
			if p := recover(); p != nil {
				end = p
			}
			ended <- end
		}()
		end = w.Proc_exec(m, pathOff, argvOff, 0, 0)
	}()
	return ended
}

// execingChild returns a child of root's that is to exec a command whose
// stdin is the read end of a pipe of root's, and the write end: closing it
// ends a command that reads its stdin to the end. statusFd is a descriptor
// of root's that the child shares the other end of, and the child alone:
// it reads the end of its input once the child has become the command and
// closed its descriptors.
func execingChild(t *testing.T, root *WasiStubs, m *Module) (child *WasiStubs, cm *Module, pid, input, statusFd int32, exited func(int32)) {
	t.Helper()
	statusFd, statusW := newTestPipe(t, root, m)
	inR, inW := newTestPipe(t, root, m)
	child, pid, exited = root.ForkProc()
	cm = registeredFork(t, child, wasiSIGUSR1)
	for _, fd := range []int32{statusW, inR} {
		if rc := root.Fd_close(m, fd); rc != _wasiESUCCESS {
			t.Fatalf("Fd_close rc=%d", rc)
		}
	}
	if rc := child.Fd_close(cm, inW); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	if rc := child.Fd_renumber(cm, inR, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_renumber rc=%d", rc)
	}
	return child, cm, pid, inW, statusFd, exited
}

// awaitExeced returns once the child of execingChild has become its
// command: the status pipe reads its end.
func awaitExeced(t *testing.T, root *WasiStubs, m *Module, statusFd int32) {
	t.Helper()
	if got, rc := fdReadString(root, m, statusFd, 1); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("status pipe read %q rc=%d, want its end", got, rc)
	}
}

// closeFd closes fd of w.
func closeFd(t *testing.T, w *WasiStubs, m *Module, fd int32) {
	t.Helper()
	if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
		t.Errorf("Fd_close(%d) rc=%d", fd, rc)
	}
}

// execedProcess returns the host process of the command w's guest became.
func execedProcess(w *WasiStubs) *os.Process {
	w.sig.mu.Lock()
	defer w.sig.mu.Unlock()
	return w.sig.execed.process
}

// An exec starts the command, closes the guest's descriptors once it has
// started, waits for it and ends the guest as the command ended. The
// process keeps its pid and cannot be moved into another group from then
// on.
func TestExec_GuestBecomesTheCommand(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, cm, pid, input, statusFd, exited := execingChild(t, root, m)
	defer exited(0)
	ended := execIn(t, child, cm, "/bin/sh", "-c", "read x; exit 5")
	awaitExeced(t, root, m, statusFd)
	child.mu.Lock()
	left := len(child.fdTable)
	child.mu.Unlock()
	if left != 0 {
		t.Errorf("%d descriptors left after the exec", left)
	}
	if rc := root.Proc_setpgid(m, pid, 0); rc != -_wasiEACCES {
		t.Errorf("Proc_setpgid of a child that has become a command rc=%d, want -EACCES", rc)
	}
	closeFd(t, root, m, input)
	var exit *WasiExitError
	if end, _ := (<-ended).(error); !errors.As(end, &exit) || exit.Code != 5 {
		t.Fatalf("the guest ended with %v, want an exit of 5", end)
	}
}

// A signal for the process of a guest that has become a command is the
// command's, a signal pending for the guest when it became it as well,
// and the guest ends killed by the signal that killed the command.
func TestExec_SignalsAreTheCommands(t *testing.T) {
	for _, c := range []struct {
		name    string
		pending bool
	}{{"posted after", false}, {"pending before", true}} {
		t.Run(c.name, func(t *testing.T) {
			root, m := newProcTestStubs(t)
			child, cm, pid, input, statusFd, exited := execingChild(t, root, m)
			defer exited(0)
			defer closeFd(t, root, m, input)
			if c.pending {
				child.PostSignal(wasiSIGUSR1)
			}
			ended := execIn(t, child, cm, "/bin/sh", "-c", "read x")
			awaitExeced(t, root, m, statusFd)
			if !c.pending {
				if rc := root.Proc_kill(m, pid, wasiSIGUSR1); rc != _wasiESUCCESS {
					t.Fatalf("kill of the child rc=%d", rc)
				}
			}
			var killed *WasiSignalError
			if end, _ := (<-ended).(error); !errors.As(end, &killed) || killed.Signal != wasiSIGUSR1 {
				t.Fatalf("the guest ended with %v, want killed by SIGUSR1", end)
			}
		})
	}
}

// An exec that cannot start its command fails, and the guest goes on with
// its descriptors and its group as they were.
func TestExec_FailureLeavesTheGuest(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	before := len(child.fdTable)
	missing := t.TempDir() + "/missing"
	if err := os.WriteFile(missing, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := <-execIn(t, child, cm, missing); rc != any(int32(-_wasiEACCES)) {
		t.Fatalf("exec of a file that is not executable rc=%v, want -EACCES", rc)
	}
	if got := len(child.fdTable); got != before {
		t.Errorf("%d descriptors after a failed exec, want %d", got, before)
	}
	if rc := root.Proc_setpgid(m, pid, 0); rc != _wasiESUCCESS {
		t.Errorf("Proc_setpgid of a child whose exec failed rc=%d", rc)
	}
}

// The command a leader of a group becomes leads the host's group of the
// group, which a kill of the group reaches.
func TestExec_LeaderBecomesTheLeaderOfAGroupOfTheHosts(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, cm, pid, input, statusFd, exited := execingChild(t, root, m)
	defer exited(0)
	defer closeFd(t, root, m, input)
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	ended := execIn(t, child, cm, "/bin/sh", "-c", "read x")
	awaitExeced(t, root, m, statusFd)
	cmd := execedProcess(child)
	if got, err := syscall.Getpgid(cmd.Pid); err != nil || got != cmd.Pid {
		t.Errorf("the command is in the host's group %d (%v), want its own %d", got, err, cmd.Pid)
	}
	if rc := root.Proc_kill(m, -pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the group rc=%d", rc)
	}
	var killed *WasiSignalError
	if end, _ := (<-ended).(error); !errors.As(end, &killed) || killed.Signal != wasiSIGTERM {
		t.Fatalf("the guest ended with %v, want killed by SIGTERM", end)
	}
}

// The root instance's guest becomes a command as well, its descriptors
// closed.
func TestExec_RootBecomesTheCommand(t *testing.T) {
	root, m := newProcTestStubs(t)
	var exit *WasiExitError
	if end, _ := (<-execIn(t, root, m, "/bin/sh", "-c", "exit 7")).(error); !errors.As(end, &exit) || exit.Code != 7 {
		t.Fatalf("the root's guest ended with %v, want an exit of 7", end)
	}
	if left := len(root.fdTable); left != 0 {
		t.Errorf("%d descriptors left after the exec", left)
	}
}

// KillCommands ends the command the guest has become as well, and returns
// once the exec has waited for it.
func TestExec_KillCommandsEndsTheCommand(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, cm, _, input, statusFd, exited := execingChild(t, root, m)
	defer exited(0)
	defer closeFd(t, root, m, input)
	ended := execIn(t, child, cm, "/bin/sh", "-c", "read x")
	awaitExeced(t, root, m, statusFd)
	if err := child.KillCommands(); err != nil {
		t.Fatal(err)
	}
	var killed *WasiSignalError
	if end, _ := (<-ended).(error); !errors.As(end, &killed) || killed.Signal != wasiSIGKILL {
		t.Fatalf("the guest ended with %v, want killed by SIGKILL", end)
	}
}

// A SIGKILL that asked for the end of the instance while the command it
// becomes started is the command's.
func TestExec_KillDuringTheStartIsTheCommands(t *testing.T) {
	w, _ := newProcTestStubs(t)
	r, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAtEnd(t, r)
	p, err := os.StartProcess("/bin/sh", []string{"/bin/sh", "-c", "read x"}, &os.ProcAttr{Files: []*os.File{r}})
	if err != nil {
		t.Skip(err)
	}
	w.sig.mu.Lock()
	w.requestStopLocked(nil, &WasiSignalError{Signal: wasiSIGKILL})
	w.unlockSignals()
	w.becomeCommand(p)
	// The command's input ends: a command that was not killed exits.
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := p.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if ws, _ := st.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the command ended with %v, want killed by SIGKILL", st)
	}
}

// The interval timer of a guest that has become a command posts its
// SIGALRM to the command, as an alarm set before execve(2) does.
func TestExec_TimerIsTheCommands(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, cm, _, input, statusFd, exited := execingChild(t, root, m)
	defer exited(0)
	defer closeFd(t, root, m, input)
	ended := execIn(t, child, cm, "/bin/sh", "-c", "read x")
	awaitExeced(t, root, m, statusFd)
	if rc := child.Proc_itimer(cm, 1, 1, 0, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_itimer rc=%d", rc)
	}
	var killed *WasiSignalError
	if end, _ := (<-ended).(error); !errors.As(end, &killed) || killed.Signal != wasiSIGALRM {
		t.Fatalf("the guest ended with %v, want killed by SIGALRM", end)
	}
}

// The interval timer of a guest that has become a command and ignores
// SIGALRM sends the command nothing: an ignored signal stays ignored
// across execve(2).
func TestExec_IgnoredTimerIsNotTheCommands(t *testing.T) {
	w, m := newSignalGuest(t)
	setDispositions(t, w, m, 0, signalMask(wasiSIGALRM), 0)
	p, err := os.StartProcess("/bin/sleep", []string{"/bin/sleep", "1000"}, &os.ProcAttr{})
	if err != nil {
		t.Skip(err)
	}
	w.becomeCommand(p)
	w.sig.mu.Lock()
	w.sig.timer = time.AfterFunc(time.Hour, func() {})
	w.sig.timerAt = time.Now()
	w.fireDueTimerLocked()
	w.unlockSignals()
	// What the timer sent, it sent before unlockSignals returned.
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	st, err := p.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if ws, _ := st.Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Fatalf("the command ended with %v, want killed by SIGTERM: the ignored SIGALRM reached it", st)
	}
}
