//go:build darwin || linux

package codegen

import (
	"os"
	"syscall"
	"testing"
)

// spawnCommand starts argv as a command of w and returns its pid token and
// its host process.
func spawnCommand(t *testing.T, w *WasiStubs, m *Module, argv ...string) (int32, *os.Process) {
	t.Helper()
	pid := spawnTestProc(t, w, m, argv...)
	w.mu.Lock()
	defer w.mu.Unlock()
	return pid, w.procs[pid].host
}

// waitStatus waits for the process pid of w and returns its wait status.
func waitStatus(t *testing.T, w *WasiStubs, m *Module, pid int32) uint32 {
	t.Helper()
	if rc := w.Proc_wait(m, pid, 0, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait(%d) rc=%d", pid, rc)
	}
	return readU32(m.memory, int(jobOutOff))
}

// hostPgidOf returns the host's process group of p.
func hostPgidOf(t *testing.T, p *os.Process) int {
	t.Helper()
	pgid, err := syscall.Getpgid(p.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return pgid
}

// The commands of a group the host process is not in are in a group of
// the host's that the first of them leads, which a kill of the group
// reaches. The commands of the host process's group are in its own.
func TestJobs_CommandsOfAGroupShareAGroupOfTheHosts(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	first, p1 := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	second, p2 := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	if got := hostPgidOf(t, p1); got != p1.Pid {
		t.Errorf("the first command is in the host's group %d, want one of its own %d", got, p1.Pid)
	}
	if got := hostPgidOf(t, p2); got != p1.Pid {
		t.Errorf("the second command is in the host's group %d, want the first's %d", got, p1.Pid)
	}
	third, p3 := spawnCommand(t, root, m, "/bin/sleep", "1000")
	if got := hostPgidOf(t, p3); got != syscall.Getpgrp() {
		t.Errorf("a command of the root's group is in the host's group %d, want the host process's %d", got, syscall.Getpgrp())
	}
	if got := getpgid(t, root, m, first); got != pid {
		t.Errorf("the first command is in group %d, want its parent's %d", got, pid)
	}
	if rc := root.Proc_kill(m, -pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the group rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGTERM); got != want {
		t.Errorf("the child in the group took %#x, want %#x", got, want)
	}
	for _, cmd := range []int32{first, second} {
		if got := waitStatus(t, child, cm, cmd); got != uint32(wasiSIGTERM) {
			t.Errorf("command %d status %#x, want killed by SIGTERM", cmd, got)
		}
	}
	if rc := root.Proc_kill(m, third, wasiSIGKILL); rc != _wasiESUCCESS {
		t.Fatalf("kill of the third rc=%d", rc)
	}
	if got := waitStatus(t, root, m, third); got != uint32(wasiSIGKILL) {
		t.Errorf("the third command status %#x, want killed by SIGKILL", got)
	}
}

// The leader of a group of the host's stays unreaped while its group has
// other members, so that its pid, the group's number, is not another
// process's, and a command started meanwhile joins the group. The guest
// has its wait status when it ends all the same.
func TestJobs_LeaderIsKeptWhileItsGroupHasMembers(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid rc=%d", rc)
	}
	leader, p1 := spawnCommand(t, child, cm, "/bin/sh", "-c", "exit 3")
	if got := waitStatus(t, child, cm, leader); got != 3<<8 {
		t.Fatalf("leader status %#x, want an exit of 3", got)
	}
	if _, err := hostWaitExited(p1.Pid); err != nil {
		t.Fatalf("the leader was reaped while its group has a member: %v", err)
	}
	second, p2 := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	if got := hostPgidOf(t, p2); got != p1.Pid {
		t.Errorf("a command started after the leader ended is in the host's group %d, want the leader's %d", got, p1.Pid)
	}
	if rc := root.Proc_kill(m, -pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the group rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGTERM); got != want {
		t.Errorf("the child in the group took %#x, want %#x", got, want)
	}
	if got := waitStatus(t, child, cm, second); got != uint32(wasiSIGTERM) {
		t.Errorf("second command status %#x, want killed by SIGTERM", got)
	}
	pids := root.pids
	pids.mu.Lock()
	held := pids.groups[pid] != nil
	pids.mu.Unlock()
	if !held {
		t.Fatal("the host's group was dropped while the group has a member")
	}
	if rc := root.Proc_setpgid(m, pid, getpgid(t, root, m, 0)); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid of the child into its parent's group rc=%d", rc)
	}
	pids.mu.Lock()
	defer pids.mu.Unlock()
	if pids.groups[pid] != nil {
		t.Fatal("the host's group was kept after its last member left")
	}
}

// A command of a session that is not the host process's leads a session
// of the host's of its own, and the host's group of its group.
func TestJobs_CommandOfAnotherSessionLeadsOneOfTheHosts(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setsid(cm, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	cmd, p := spawnCommand(t, child, cm, "/bin/sleep", "1000")
	// getsid(2): package syscall has no Getsid on Linux.
	if sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, uintptr(p.Pid), 0, 0); errno != 0 || int(sid) != p.Pid {
		t.Errorf("the command is in the host's session %d (%v), want one of its own %d", sid, errno, p.Pid)
	}
	if got := hostPgidOf(t, p); got != p.Pid {
		t.Errorf("the command is in the host's group %d, want one of its own %d", got, p.Pid)
	}
	if rc := root.Proc_kill(m, -pid, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the group rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGTERM); got != want {
		t.Errorf("the child in the group took %#x, want %#x", got, want)
	}
	if got := waitStatus(t, child, cm, cmd); got != uint32(wasiSIGTERM) {
		t.Errorf("command status %#x, want killed by SIGTERM", got)
	}
}

// The leader of a group of the host's that is kept unreaped has what the
// runtime copies from it delivered before its wait status is the guest's:
// awaitLeader finishes the copies before it returns the status.
func TestJobs_HeldLeaderDeliversItsOutputFirst(t *testing.T) {
	root, _ := newProcTestStubs(t)
	p, err := os.StartProcess("/bin/sh", []string{"/bin/sh", "-c", "exit 3"}, &os.ProcAttr{Sys: &syscall.SysProcAttr{Setpgid: true}})
	if err != nil {
		t.Skip(err)
	}
	leader := &wasiProc{host: p, done: make(chan struct{}), pgid: 5001}
	member := &wasiProc{done: make(chan struct{}), pgid: 5001}
	pids := &wasiPIDs{
		procs:  map[int32]*wasiProc{5001: leader, 5002: member},
		groups: map[int32]*jobGroup{5001: {host: p.Pid, leader: leader}},
	}
	delivered := false
	status, reap := root.awaitLeader(pids, leader, &hostCommand{process: p, finish: func() { delivered = true }})
	if reap == nil || status != 3<<8 {
		t.Fatalf("awaitLeader = %#x, %v; want an exit of 3, held", status, reap != nil)
	}
	if !delivered {
		t.Fatal("the status came before the copies were delivered")
	}
	pids.leave(5002)
	reap()
}
