package codegen

import (
	"errors"
	"testing"
)

// jobOutOff is where the job control tests have a pid written.
const jobOutOff int32 = 5000

// getpgid returns the process group of pid as the guest of w reads it.
func getpgid(t *testing.T, w *WasiStubs, m *Module, pid int32) int32 {
	t.Helper()
	if rc := w.Proc_getpgid(m, pid, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_getpgid(%d) rc=%d", pid, rc)
	}
	return int32(readU32(m.memory, int(jobOutOff)))
}

// A child moved into a group of its own is alone in it: a kill of that
// group reaches it, and not its parent, whose own group the child has left.
func TestJobs_SetpgidMovesAChildIntoAGroupOfItsOwn(t *testing.T) {
	root, m := newSignalGuest(t, wasiSIGUSR1)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child, wasiSIGUSR1)
	own := getpgid(t, root, m, 0)
	if got := getpgid(t, root, m, pid); got != own {
		t.Fatalf("the child starts in group %d, want its parent's %d", got, own)
	}
	if rc := root.Proc_setpgid(m, pid, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid(child, 0) rc=%d", rc)
	}
	if got := getpgid(t, root, m, pid); got != pid {
		t.Fatalf("the child is in group %d, want its own %d", got, pid)
	}
	if got := getpgid(t, child, cm, 0); got != pid {
		t.Fatalf("the child reads its group as %d, want %d", got, pid)
	}
	if got := getpgid(t, root, m, 0); got != own {
		t.Fatalf("the parent is in group %d, want %d still", got, own)
	}
	if rc := root.Proc_kill(m, -pid, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill of the child's group rc=%d", rc)
	}
	if got, want := takeSignals(t, child, cm), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("child taken = %#x, want %#x", got, want)
	}
	if got := takeSignals(t, root, m); got != 0 {
		t.Fatalf("the parent took %#x from a kill of the child's group", got)
	}
	if rc := root.Proc_kill(m, 0, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(0) rc=%d", rc)
	}
	if got := takeSignals(t, child, cm); got != 0 {
		t.Fatalf("the child took %#x from its parent's kill(0)", got)
	}
	if got, want := takeSignals(t, root, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("parent taken = %#x after its kill(0), want %#x", got, want)
	}
}

// setpgid refuses what Linux's does: a negative group, a process that is
// neither the caller nor a child of its, a group that is not there, a child
// that runs a program of its own, a leader of a session, and a child of
// another session.
func TestJobs_SetpgidRefuses(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	ran, ranExited := root.NewProc(nil)
	defer ranExited(0)
	for _, c := range []struct {
		name      string
		pid, pgid int32
		want      int32
	}{
		{"a negative group", pid, -1, -_wasiEINVAL},
		{"a process that is no child", 77777, 0, -_wasiESRCH},
		{"a group that is not there", pid, 77777, -_wasiEPERM},
		{"a process the embedder runs", ran, 0, -_wasiEACCES},
	} {
		if rc := root.Proc_setpgid(m, c.pid, c.pgid); rc != c.want {
			t.Errorf("Proc_setpgid of %s rc=%d, want %d", c.name, rc, c.want)
		}
	}
	if rc := child.Proc_setsid(cm, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid of the child rc=%d", rc)
	}
	if rc := child.Proc_setpgid(cm, 0, 0); rc != -_wasiEPERM {
		t.Errorf("Proc_setpgid of a session leader rc=%d, want -EPERM", rc)
	}
	// A process that starts a session leaves its children in the one it
	// was in.
	other, _, oexited := root.ForkProc()
	defer oexited(0)
	om := registeredFork(t, other)
	grand, gpid, gexited := other.ForkProc()
	defer gexited(0)
	registeredFork(t, grand)
	if rc := other.Proc_setsid(om, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if rc := other.Proc_setpgid(om, gpid, 0); rc != -_wasiEPERM {
		t.Errorf("Proc_setpgid of a child of another session rc=%d, want -EPERM", rc)
	}
}

// setsid makes a session, and a group, of the caller's pid, unless the
// caller leads a group; a child is in its parent's session, and the
// groups of another session are not for it.
func TestJobs_SetsidStartsASession(t *testing.T) {
	root, m := newProcTestStubs(t)
	if rc := root.Proc_setsid(m, jobOutOff); rc != -_wasiEPERM {
		t.Fatalf("Proc_setsid of a group's leader rc=%d, want -EPERM", rc)
	}
	child, pid, exited := root.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if rc := child.Proc_setsid(cm, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if got := int32(readU32(cm.memory, int(jobOutOff))); got != pid {
		t.Fatalf("session %d, want the child's pid %d", got, pid)
	}
	if got := getpgid(t, child, cm, 0); got != pid {
		t.Fatalf("group %d after setsid, want %d", got, pid)
	}
	grand, gpid, gexited := child.ForkProc()
	defer gexited(0)
	registeredFork(t, grand)
	if rc := child.Proc_setpgid(cm, gpid, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid of a child of the session rc=%d", rc)
	}
	if rc := child.Proc_setpgid(cm, gpid, pid); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid back into the session's group rc=%d", rc)
	}
	if rc := root.Proc_setpgid(m, 0, pid); rc != -_wasiEPERM {
		t.Fatalf("Proc_setpgid into a group of another session rc=%d, want -EPERM", rc)
	}
}

// jobChanges is a ProcessChanges that keeps a process group and a session
// of its own and records the changes of them.
type jobChanges struct {
	recordedChanges
	pgid, sid int32
	moves     [][2]int32
	asked     []int32
}

func (c *jobChanges) Pgid(pid int32) (int32, error) {
	c.asked = append(c.asked, pid)
	if pid == 0 {
		return c.pgid, nil
	}
	return pid + 1, nil
}

func (c *jobChanges) Setpgid(pid, pgid int32) error {
	c.moves = append(c.moves, [2]int32{pid, pgid})
	return nil
}

func (c *jobChanges) Setsid() (int32, error) { return c.sid, nil }

// The root's own group and session are its ProcessChanges's: the group
// the family starts in is the one it tells, and the root's changes of its
// own are made by it. A forked process's are the family's.
func TestJobs_RootChangesAreTheProcessChanges(t *testing.T) {
	w, m := newProcTestStubs(t)
	changes := &jobChanges{pgid: 555, sid: 42}
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 42, PPID: 1}}
	w.cfg.ProcessChanges = changes
	if got := getpgid(t, w, m, 0); got != 555 {
		t.Fatalf("root's group %d, want the ProcessChanges's 555", got)
	}
	if got := getpgid(t, w, m, 3000); got != 3001 {
		t.Fatalf("group of a process outside the family %d, want the ProcessChanges's 3001", got)
	}
	child, pid, exited := w.ForkProc()
	defer exited(0)
	cm := registeredFork(t, child)
	if got := getpgid(t, child, cm, 0); got != 555 {
		t.Fatalf("child's group %d, want 555", got)
	}
	if rc := child.Proc_setpgid(cm, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid of the child rc=%d", rc)
	}
	if rc := w.Proc_setpgid(m, 0, pid); rc != -_wasiEPERM {
		t.Fatalf("Proc_setpgid of the root into a group no host process can join rc=%d, want -EPERM", rc)
	}
	if rc := w.Proc_setpgid(m, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid of the root rc=%d", rc)
	}
	if got := getpgid(t, w, m, 0); got != 42 {
		t.Fatalf("root's group %d after setpgid(0, 0), want 42", got)
	}
	if rc := w.Proc_setsid(m, jobOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid of the root rc=%d", rc)
	}
	if len(changes.moves) != 1 || changes.moves[0] != [2]int32{0, 0} {
		t.Fatalf("ProcessChanges moves = %v, want [[0 0]] (the root's only)", changes.moves)
	}
	if len(changes.asked) != 2 || changes.asked[0] != 0 || changes.asked[1] != 3000 {
		t.Fatalf("ProcessChanges asked for the groups of %v, want [0 3000]", changes.asked)
	}
}

// A ProcessChanges that cannot tell the group the family starts in leaves
// it the root's pid; another error of it is told Errors.
func TestJobs_RootGroupUntold(t *testing.T) {
	for _, c := range []struct {
		err      error
		reported bool
	}{{errors.ErrUnsupported, false}, {errors.New("no group"), true}} {
		w, m := newProcTestStubs(t)
		var reported []error
		w.cfg.Errors = func(op string, err error) { reported = append(reported, err) }
		w.cfg.Process = testProcess{ids: ProcessIDs{PID: 42, PPID: 1}}
		w.cfg.ProcessChanges = &failingPgid{err: c.err}
		if got := getpgid(t, w, m, 0); got != 42 {
			t.Errorf("%v: root's group %d, want its pid 42", c.err, got)
		}
		if got := len(reported) == 1 && errors.Is(reported[0], c.err); got != c.reported {
			t.Errorf("%v: reported %v", c.err, reported)
		}
	}
}

// failingPgid is a ProcessChanges whose Pgid fails with err.
type failingPgid struct {
	recordedChanges
	err error
}

func (c *failingPgid) Pgid(pid int32) (int32, error) { return 0, c.err }

// kill(0) of a guest in the group 1 (one whose pid is 1, as in a
// container) is the guest's group, and never the kill of every process
// (-1) the Signals is given for kill(-1).
func TestJobs_KillOfGroupOne(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	s := &recordingSignals{}
	w.cfg.Signals = s
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 1}}
	if got := getpgid(t, w, m, 0); got != 1 {
		t.Fatalf("group %d, want 1", got)
	}
	if rc := w.Proc_kill(m, 0, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("kill(0) rc=%d", rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGUSR1); got != want {
		t.Fatalf("taken = %#x, want %#x", got, want)
	}
	if len(s.kills) != 0 {
		t.Fatalf("the Signals was given %v", s.kills)
	}
}

// A wait for a process group reaps the processes of that group only, the
// lowest pid first of those that have finished, and is refused for a group
// the guest has no process in and for a pgid that is not positive.
func TestJobs_WaitGroupReapsTheGroupsProcessesOnly(t *testing.T) {
	root, m := newProcTestStubs(t)
	const pidOut, statusOut = jobOutOff + 8, jobOutOff + 12
	waitGroup := func(pgid, options int32) (rc, pid, status int32) {
		rc = root.Proc_wait_group(m, pgid, options, pidOut, statusOut)
		return rc, int32(readU32(m.memory, int(pidOut))), int32(readU32(m.memory, int(statusOut)))
	}
	own := getpgid(t, root, m, 0)
	child, moved, movedExited := root.ForkProc()
	registeredFork(t, child)
	if rc := root.Proc_setpgid(m, moved, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setpgid(child, 0) rc=%d", rc)
	}
	first, firstExited := root.NewProc(nil)
	second, secondExited := root.NewProc(nil)
	for _, pgid := range []int32{0, -own} {
		if rc, _, _ := waitGroup(pgid, 0); rc != -_wasiEINVAL {
			t.Fatalf("wait for group %d rc=%d, want -EINVAL", pgid, rc)
		}
	}
	if rc, _, _ := waitGroup(77777, 0); rc != -_wasiECHILD {
		t.Fatalf("wait for a group of no process rc=%d, want -ECHILD", rc)
	}
	if rc, _, _ := waitGroup(moved, 1); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG with the group's process running rc=%d, want -EAGAIN", rc)
	}
	secondExited(2 << 8)
	firstExited(1 << 8)
	if rc, _, _ := waitGroup(moved, 1); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG with processes of another group finished rc=%d, want -EAGAIN", rc)
	}
	go movedExited(3 << 8)
	if rc, pid, status := waitGroup(moved, 0); rc != _wasiESUCCESS || pid != moved || status != 3<<8 {
		t.Fatalf("wait for the child's group = rc %d pid %d status %#x, want pid %d status %#x", rc, pid, status, moved, 3<<8)
	}
	if rc, _, _ := waitGroup(moved, 0); rc != -_wasiECHILD {
		t.Fatalf("wait for the reaped child's group rc=%d, want -ECHILD", rc)
	}
	if rc, pid, status := waitGroup(own, 0); rc != _wasiESUCCESS || pid != first || status != 1<<8 {
		t.Fatalf("first of the own group = rc %d pid %d status %#x, want pid %d status %#x", rc, pid, status, first, 1<<8)
	}
	if rc, pid, status := waitGroup(own, 0); rc != _wasiESUCCESS || pid != second || status != 2<<8 {
		t.Fatalf("second of the own group = rc %d pid %d status %#x, want pid %d status %#x", rc, pid, status, second, 2<<8)
	}
	if rc, _, _ := waitGroup(own, 1); rc != -_wasiECHILD {
		t.Fatalf("own group all reaped rc=%d, want -ECHILD", rc)
	}
}

// Proc_wait_group64 is Proc_wait_group with the pointers of a memory64
// guest.
func TestJobs_WaitGroup64(t *testing.T) {
	root, m := newProcTestStubs(t)
	const pidOut, statusOut = int64(jobOutOff) + 8, int64(jobOutOff) + 12
	own := getpgid(t, root, m, 0)
	if rc := root.Proc_wait_group64(m, 0, 1, pidOut, statusOut); rc != -_wasiEINVAL {
		t.Fatalf("wait for group 0 rc=%d, want -EINVAL", rc)
	}
	if rc := root.Proc_wait_group64(m, own, 1, pidOut, statusOut); rc != -_wasiECHILD {
		t.Fatalf("wait with no process rc=%d, want -ECHILD", rc)
	}
	pid, exited := root.NewProc(nil)
	if rc := root.Proc_wait_group64(m, own, 1, pidOut, statusOut); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG with the process running rc=%d, want -EAGAIN", rc)
	}
	exited(4 << 8)
	if rc := root.Proc_wait_group64(m, own, 1, pidOut, statusOut); rc != _wasiESUCCESS {
		t.Fatalf("wait for the finished process rc=%d", rc)
	}
	if got, status := int32(readU32(m.memory, int(pidOut))), int32(readU32(m.memory, int(statusOut))); got != pid || status != 4<<8 {
		t.Fatalf("reaped pid %d status %#x, want pid %d status %#x", got, status, pid, 4<<8)
	}
}
