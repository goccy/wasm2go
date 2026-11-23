//go:build darwin || linux

package codegen

import (
	"errors"
	"syscall"
	"testing"
)

// unreaped reports whether the host's process pid, a child of this
// process, has ended and is not reaped yet.
func unreaped(t *testing.T, pid int) bool {
	t.Helper()
	_, err := hostWaitExited(pid)
	switch {
	case err == nil:
		return true
	case errors.Is(err, syscall.ECHILD):
		return false
	}
	t.Fatalf("waitid(%d): %v", pid, err)
	return false
}

// awaitSIGCHLD returns once a SIGCHLD has been posted to the guest of w,
// which handles it: a child's end, whose finish has been made.
func awaitSIGCHLD(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	if w.awaitInterruptibly(m, make(chan struct{})) {
		t.Fatal("a wait for nothing ended without a signal")
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGCHLD); got != want {
		t.Fatalf("took %#x, want SIGCHLD", got)
	}
}

// recordingPriorityProcess is a Process that records whom Priority was
// asked about.
type recordingPriorityProcess struct {
	isolatedProcess
	who []int32
}

func (p *recordingPriorityProcess) Priority(which, who int32) (int32, error) {
	p.who = append(p.who, who)
	return 0, nil
}

// A command Children names by its host pid is known to the guest by it:
// the guest kills it, finds its group and asks about its priority by it,
// and the command stays unreaped once it has ended until the guest has
// waited for it. CommandPID is told what the command runs and its host
// pid.
func TestChildren_CommandKnownByItsHostPID(t *testing.T) {
	c := &recordingChildren{named: true}
	w, m := newSignalGuest(t, wasiSIGCHLD)
	w.cfg.Children = c
	proc := &recordingPriorityProcess{}
	w.cfg.Process = proc
	pid, host := spawnCommand(t, w, m, "/bin/sleep", "1000")
	if int(pid) != host.Pid {
		t.Fatalf("the guest knows the command by %d, want its host pid %d", pid, host.Pid)
	}
	if len(c.hostPIDs) != 1 || c.hostPIDs[0] != host.Pid || c.commands[0].Path != "/bin/sleep" {
		t.Errorf("CommandPID was asked about %v %v, want /bin/sleep and %d", c.commands, c.hostPIDs, host.Pid)
	}
	if got := getpgid(t, w, m, pid); got != getpgid(t, w, m, 0) {
		t.Errorf("the command is in group %d, want the guest's %d", got, getpgid(t, w, m, 0))
	}
	if rc := w.Proc_priority(m, 0, pid, 0, 0, jobOutOff); rc != _wasiESUCCESS {
		t.Errorf("Proc_priority of the command rc=%d", rc)
	}
	if len(proc.who) != 1 || proc.who[0] != pid {
		t.Errorf("Priority was asked about %v, want the host pid %d", proc.who, pid)
	}
	if rc := w.Proc_kill(m, pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the command rc=%d", rc)
	}
	awaitSIGCHLD(t, w, m)
	if !unreaped(t, host.Pid) {
		t.Fatal("the command was reaped before the guest waited for it")
	}
	if got := waitStatus(t, w, m, pid); got != uint32(wasiSIGTERM) {
		t.Errorf("status %#x, want killed by SIGTERM", got)
	}
	if unreaped(t, host.Pid) {
		t.Error("the command is unreaped after the guest waited for it")
	}
}

// The first command of a group, known by its host pid, stays unreaped
// after the guest waited for it while its group has another member: the
// group's number is its pid.
func TestChildren_LeaderKnownByItsHostPIDIsKeptForItsGroup(t *testing.T) {
	root, _ := newProcTestStubs(t)
	root.cfg.Children = &recordingChildren{named: true}
	child, _, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	leader, p1 := spawnCommand(t, child, cm, "/bin/sh", "-c", "exit 3")
	second, p2 := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	if int(leader) != p1.Pid || int(second) != p2.Pid {
		t.Fatalf("the commands are known by %d and %d, want their host pids %d and %d", leader, second, p1.Pid, p2.Pid)
	}
	if got := waitStatus(t, child, cm, leader); got != 3<<8 {
		t.Fatalf("leader status %#x, want an exit of 3", got)
	}
	if !unreaped(t, p1.Pid) {
		t.Fatal("the leader was reaped while its group has a member")
	}
	if rc := child.Proc_kill(cm, second, wasiSIGKILL); rc != _wasiESUCCESS {
		t.Fatalf("kill of the second rc=%d", rc)
	}
	if got := waitStatus(t, child, cm, second); got != uint32(wasiSIGKILL) {
		t.Errorf("second status %#x, want killed by SIGKILL", got)
	}
	if unreaped(t, p2.Pid) {
		t.Error("the second command is unreaped after the guest waited for it")
	}
}

// A command known by its host pid that the guest will not wait for is
// reaped all the same: once the guest ignores SIGCHLD, and when its
// instance is closed.
func TestChildren_CommandKnownByItsHostPIDIsReapedWhenNobodyWaits(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "SIGCHLD ignored"
		if closed {
			name = "instance closed"
		}
		t.Run(name, func(t *testing.T) {
			w, m := newSignalGuest(t, wasiSIGCHLD)
			w.cfg.Children = &recordingChildren{named: true}
			_, host := spawnCommand(t, w, m, "/bin/sh", "-c", "exit 0")
			awaitSIGCHLD(t, w, m)
			if !unreaped(t, host.Pid) {
				t.Fatal("the command was reaped before anybody let it go")
			}
			if closed {
				if err := w.CloseAll(); err != nil {
					t.Fatal(err)
				}
			} else {
				setDispositions(t, w, m, 0, signalMask(wasiSIGCHLD), 0)
			}
			if unreaped(t, host.Pid) {
				t.Error("the command is unreaped")
			}
		})
	}
}
