package codegen

import (
	"errors"
	"sync"
	"syscall"
	"testing"
)

// adoptedPID stands for a child of the host process the runtime did not
// start: a pid below every pid token, which the tests' Children adopt
// without asking the host.
const adoptedPID int32 = 31337

// recordingChildren is a Children that records what it is asked: commands
// are known by their host pid when named is set, and Adopt answers with
// adopt (no child without one).
type recordingChildren struct {
	named bool
	adopt func(target SignalTarget, pid int32, exited func(status int32)) (func(sig int32) error, func() error, bool, error)

	mu       sync.Mutex
	commands []ExecRequest
	hostPIDs []int
	asked    []int32
	targets  []SignalTarget
}

func (c *recordingChildren) CommandPID(req ExecRequest, hostPID int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands = append(c.commands, req)
	c.hostPIDs = append(c.hostPIDs, hostPID)
	return c.named
}

func (c *recordingChildren) Adopt(target SignalTarget, pid int32, exited func(status int32)) (func(sig int32) error, func() error, bool, error) {
	c.mu.Lock()
	c.asked = append(c.asked, pid)
	c.targets = append(c.targets, target)
	adopt := c.adopt
	c.mu.Unlock()
	if adopt == nil {
		return nil, nil, false, nil
	}
	return adopt(target, pid, exited)
}

// askedPIDs returns the pids Adopt has been asked about.
func (c *recordingChildren) askedPIDs() []int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int32(nil), c.asked...)
}

// adoptedChild is a child a recordingChildren adopted: its exited, the
// signals its kill was given and how many times it was released.
type adoptedChild struct {
	mu       sync.Mutex
	exited   func(status int32)
	kills    []int32
	releases int
}

func (a *adoptedChild) released() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.releases
}

// adoptOnce returns an adopt that adopts the first pid it is asked about,
// as child, ending it with status at once when ended is set, and no other
// pid.
func adoptOnce(child *adoptedChild, ended bool, status int32) func(SignalTarget, int32, func(int32)) (func(int32) error, func() error, bool, error) {
	adopted := false
	return func(_ SignalTarget, _ int32, exited func(int32)) (func(int32) error, func() error, bool, error) {
		if adopted {
			return nil, nil, false, nil
		}
		adopted = true
		child.mu.Lock()
		child.exited = exited
		child.mu.Unlock()
		if ended {
			exited(status)
		}
		kill := func(sig int32) error {
			child.mu.Lock()
			defer child.mu.Unlock()
			child.kills = append(child.kills, sig)
			return nil
		}
		release := func() error {
			child.mu.Lock()
			defer child.mu.Unlock()
			child.releases++
			return nil
		}
		return kill, release, true, nil
	}
}

// newChildrenStubs returns stubs whose Children is c.
func newChildrenStubs(t *testing.T, c *recordingChildren) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newProcTestStubs(t)
	w.cfg.Children = c
	return w, m
}

const childStatusOff, childPidOff int32 = 4104, 4108

// A guest's wait for a pid that names no process of the family adopts it
// when Children says it is a child: the guest waits for it (WNOHANG
// included), signals it through its kill, finds it in its group, and
// collects its status, after which it is released once and the pid is
// no child any more.
func TestChildren_WaitAdoptsAChildOfTheHost(t *testing.T) {
	child := &adoptedChild{}
	c := &recordingChildren{adopt: adoptOnce(child, false, 0)}
	w, m := newChildrenStubs(t, c)
	if rc := w.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG wait of a running adopted child rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Proc_kill(m, adoptedPID, wasiSIGTERM); rc != _wasiESUCCESS {
		t.Fatalf("kill of the adopted child rc=%d", rc)
	}
	if got := getpgid(t, w, m, adoptedPID); got != getpgid(t, w, m, 0) {
		t.Errorf("the adopted child is in group %d, want the guest's %d", got, getpgid(t, w, m, 0))
	}
	child.mu.Lock()
	kills, exited := child.kills, child.exited
	child.mu.Unlock()
	if len(kills) != 1 || kills[0] != wasiSIGTERM {
		t.Errorf("the adopted child's kill was given %v, want [SIGTERM]", kills)
	}
	go exited(3 << 8)
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("wait of the adopted child rc=%d", rc)
	}
	if got := readU32(m.memory, int(childStatusOff)); got != 3<<8 {
		t.Errorf("status %#x, want an exit of 3", got)
	}
	if got := child.released(); got != 1 {
		t.Errorf("released %d times, want once", got)
	}
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != -_wasiECHILD {
		t.Errorf("wait after the status was collected rc=%d, want -ECHILD", rc)
	}
	if got := c.askedPIDs(); len(got) != 2 || got[0] != adoptedPID || got[1] != adoptedPID {
		t.Errorf("Adopt asked about %v, want the pid twice", got)
	}
	if c.targets[0] != SignalTarget(w) {
		t.Errorf("Adopt was given target %v, want the waiting instance", c.targets[0])
	}
}

// A child that ended before Adopt returned is waited for at once, and
// found by a wait for any child once adopted.
func TestChildren_ChildThatEndedBeforeItsAdoption(t *testing.T) {
	child := &adoptedChild{}
	w, m := newChildrenStubs(t, &recordingChildren{adopt: adoptOnce(child, true, 5<<8)})
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("wait rc=%d", rc)
	}
	if got := readU32(m.memory, int(childStatusOff)); got != 5<<8 {
		t.Errorf("status %#x, want an exit of 5", got)
	}
	if got := child.released(); got != 1 {
		t.Errorf("released %d times, want once", got)
	}

	other := &adoptedChild{}
	w, m = newChildrenStubs(t, &recordingChildren{adopt: adoptOnce(other, false, 0)})
	if rc := w.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG wait rc=%d, want -EAGAIN", rc)
	}
	other.exited(6 << 8)
	if rc := w.Proc_wait_any(m, 0, childPidOff, childStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait_any rc=%d", rc)
	}
	if pid, status := int32(readU32(m.memory, int(childPidOff))), readU32(m.memory, int(childStatusOff)); pid != adoptedPID || status != 6<<8 {
		t.Errorf("wait for any child got pid %d status %#x, want %d and an exit of 6", pid, status, adoptedPID)
	}
	if got := other.released(); got != 1 {
		t.Errorf("released %d times, want once", got)
	}
}

// A pid Children does not adopt fails the wait with ECHILD, and an error
// of Adopt with its errno. Without Children nothing is asked.
func TestChildren_PidThatIsNoChild(t *testing.T) {
	c := &recordingChildren{}
	w, m := newChildrenStubs(t, c)
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != -_wasiECHILD {
		t.Errorf("wait of a pid Children did not adopt rc=%d, want -ECHILD", rc)
	}
	c.adopt = func(SignalTarget, int32, func(int32)) (func(int32) error, func() error, bool, error) {
		return nil, nil, false, syscall.EPERM
	}
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != -_wasiEPERM {
		t.Errorf("wait whose Adopt failed with EPERM rc=%d, want -EPERM", rc)
	}
	if rc := w.Proc_wait(m, -1, 0, childStatusOff); rc != -_wasiECHILD {
		t.Errorf("wait of a negative pid rc=%d, want -ECHILD", rc)
	}
	if got := c.askedPIDs(); len(got) != 2 {
		t.Errorf("Adopt asked about %v, want the pid twice and nothing else", got)
	}

	plain, pm := newProcTestStubs(t)
	if rc := plain.Proc_wait(pm, adoptedPID, 0, childStatusOff); rc != -_wasiECHILD {
		t.Errorf("wait without Children rc=%d, want -ECHILD", rc)
	}
}

// Adopt is never asked about a pid of the fork family: the root's, a
// fork's, a process the embedder runs, or a child another process of the
// family adopted, which is no child of the one that asks.
func TestChildren_AdoptIsNotAskedAboutTheFamily(t *testing.T) {
	adopted := &adoptedChild{}
	c := &recordingChildren{adopt: adoptOnce(adopted, false, 0)}
	root, m := newChildrenStubs(t, c)
	fork, forkPID, forkExited := root.ForkProc()
	defer forkExited(0)
	fm := registeredFork(t, fork)
	sibling, siblingPID, siblingExited := root.ForkProc()
	defer siblingExited(0)
	sm := registeredFork(t, sibling)
	embedded, embeddedExited := root.NewProc(nil)
	defer embeddedExited(0)
	if rc := root.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG wait of the adopted child rc=%d, want -EAGAIN", rc)
	}
	for _, pid := range []int32{root.guestPID(), siblingPID, embedded, adoptedPID} {
		if rc := fork.Proc_wait(fm, pid, 1, childStatusOff); rc != -_wasiECHILD {
			t.Errorf("the fork's wait for %d rc=%d, want -ECHILD", pid, rc)
		}
	}
	if rc := sibling.Proc_wait(sm, forkPID, 1, childStatusOff); rc != -_wasiECHILD {
		t.Errorf("the sibling's wait for the fork rc=%d, want -ECHILD", rc)
	}
	if got := c.askedPIDs(); len(got) != 1 || got[0] != adoptedPID {
		t.Errorf("Adopt asked about %v, want only the adopted pid", got)
	}
	adopted.exited(0)
	if rc := root.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != _wasiESUCCESS {
		t.Errorf("the root's wait for its adopted child rc=%d", rc)
	}
}

// An adopted child the guest will not wait for is released all the same:
// the child of a guest that ignores SIGCHLD when it ends, and one that
// ended or ends after its instance is closed.
func TestChildren_AdoptedChildIsReleasedWhenNobodyWaits(t *testing.T) {
	t.Run("SIGCHLD ignored", func(t *testing.T) {
		child := &adoptedChild{}
		w, m := newChildrenStubs(t, &recordingChildren{adopt: adoptOnce(child, false, 0)})
		if rc := w.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
			t.Fatalf("WNOHANG wait rc=%d, want -EAGAIN", rc)
		}
		ignoreSIGCHLD(t, w, m)
		child.exited(0)
		if got := child.released(); got != 1 {
			t.Errorf("released %d times, want once", got)
		}
	})
	for _, ended := range []bool{true, false} {
		name := "running at the close"
		if ended {
			name = "ended before the close"
		}
		t.Run(name, func(t *testing.T) {
			child := &adoptedChild{}
			w, m := newChildrenStubs(t, &recordingChildren{adopt: adoptOnce(child, false, 0)})
			if rc := w.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
				t.Fatalf("WNOHANG wait rc=%d, want -EAGAIN", rc)
			}
			if ended {
				child.exited(0)
			}
			if err := w.CloseAll(); err != nil {
				t.Fatal(err)
			}
			if !ended {
				child.exited(0)
			}
			if got := child.released(); got != 1 {
				t.Errorf("released %d times, want once", got)
			}
		})
	}
}

// ignoreSIGCHLD has the guest of w ignore SIGCHLD, as a program that sets
// SIG_IGN for it.
func ignoreSIGCHLD(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	if rc := w.Proc_signal_register(m, sigFlagOff); rc < 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, w, m, 0, signalMask(wasiSIGCHLD), 0)
}

// A release's error is told Errors.
func TestChildren_ReleaseErrorIsTold(t *testing.T) {
	failed := errors.New("release failed")
	var exited func(int32)
	c := &recordingChildren{adopt: func(_ SignalTarget, _ int32, e func(int32)) (func(int32) error, func() error, bool, error) {
		exited = e
		return nil, func() error { return failed }, true, nil
	}}
	w, m := newChildrenStubs(t, c)
	var told []error
	w.cfg.Errors = func(op string, err error) { told = append(told, err) }
	if rc := w.Proc_wait(m, adoptedPID, 1, childStatusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG wait rc=%d, want -EAGAIN", rc)
	}
	exited(0)
	if rc := w.Proc_wait(m, adoptedPID, 0, childStatusOff); rc != _wasiESUCCESS {
		t.Fatalf("wait rc=%d", rc)
	}
	if len(told) != 1 || !errors.Is(told[0], failed) {
		t.Errorf("Errors told %v, want the release's error", told)
	}
}
