package codegen

import (
	"encoding/binary"
	"sync"
	"testing"
)

// forkedProcess is a process made by Proc_fork whose guest never runs: the
// test plays it through its host state.
type forkedProcess struct {
	pid    int32
	wasi   *WasiStubs
	exited func(status int32)
	mu     sync.Mutex
	got    []int32
}

func (p *forkedProcess) signals() []int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int32(nil), p.got...)
}

// forkProcess forks a process from parent, with a hook that records the
// signals it is sent.
func forkProcess(t *testing.T, parent *WasiStubs) *forkedProcess {
	t.Helper()
	m := newForkTestModule()
	p := &forkedProcess{}
	parent.SetForkHook(func(_ *Module, child *WasiStubs, pid int32, exited func(status int32)) (func(sig int32) error, error) {
		p.wasi, p.exited = child, exited
		return func(sig int32) error {
			p.mu.Lock()
			p.got = append(p.got, sig)
			p.mu.Unlock()
			return nil
		}, nil
	})
	const pidOff int32 = 128
	if rc := parent.Proc_fork(m, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_fork rc=%d", rc)
	}
	p.pid = int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	return p
}

func processGroup(t *testing.T, w *WasiStubs, pid int32) int32 {
	t.Helper()
	m := newForkTestModule()
	if rc := w.Proc_getpgid(m, pid, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_getpgid(%d) rc=%d", pid, rc)
	}
	return int32(binary.LittleEndian.Uint32(m.memory[64:]))
}

func TestForkedProcessKnowsItselfAndItsParent(t *testing.T) {
	root := DefaultWASI()
	child := forkProcess(t, root)
	grandchild := forkProcess(t, child.wasi)

	if got := procIDs(t, child.wasi); got[0] != uint32(child.pid) || got[1] != wasiIsolatedPID {
		t.Fatalf("child pid, ppid = %d, %d; want %d, %d", got[0], got[1], child.pid, wasiIsolatedPID)
	}
	if got := procIDs(t, grandchild.wasi); got[0] != uint32(grandchild.pid) || got[1] != uint32(child.pid) {
		t.Fatalf("grandchild pid, ppid = %d, %d; want %d, %d", got[0], got[1], grandchild.pid, child.pid)
	}
	// The process in the middle ends: its child is an orphan, adopted by
	// process 1.
	if err := child.wasi.CloseAll(); err != nil {
		t.Fatal(err)
	}
	child.exited(0)
	if got := procIDs(t, grandchild.wasi); got[0] != uint32(grandchild.pid) || got[1] != 1 {
		t.Fatalf("orphan pid, ppid = %d, %d; want %d, 1", got[0], got[1], grandchild.pid)
	}
}

func TestProcessGroupsOfAnIsolatedFamily(t *testing.T) {
	root := DefaultWASI()
	m := newForkTestModule()
	a := forkProcess(t, root)
	b := forkProcess(t, root)

	// Everyone starts in the first process's group, which is its own.
	for _, w := range []*WasiStubs{root, a.wasi, b.wasi} {
		if got := processGroup(t, w, 0); got != wasiIsolatedPID {
			t.Fatalf("group = %d, want %d", got, wasiIsolatedPID)
		}
	}
	if got := processGroup(t, root, a.pid); got != wasiIsolatedPID {
		t.Fatalf("group of a child, asked by its parent = %d", got)
	}
	if rc := root.Proc_getpgid(m, 4242, 64); rc != -_wasiESRCH {
		t.Fatalf("group of no process rc=%d, want -ESRCH", rc)
	}

	// A signal to the group reaches every member, the caller included.
	root.sig.flagModule, root.sig.flagAddr = m, 256
	if rc := a.wasi.Proc_kill(m, 0, 15); rc != _wasiESUCCESS {
		t.Fatalf("kill(0) rc=%d", rc)
	}
	if got := b.signals(); len(got) != 1 || got[0] != 15 {
		t.Fatalf("sibling got %v, want [15]", got)
	}
	if got := a.signals(); len(got) != 0 {
		t.Fatalf("the caller was signalled through its kill function: %v", got)
	}
	if root.sig.pending&wasiSignalBit(15) == 0 {
		t.Fatal("the first process of the family did not get the signal")
	}
	root.sig.pending = 0

	// b starts a group of its own; a child of it is born into that group.
	if rc := b.wasi.Proc_setpgid(m, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("setpgid(0, 0) rc=%d", rc)
	}
	c := forkProcess(t, b.wasi)
	if got := processGroup(t, c.wasi, 0); got != b.pid {
		t.Fatalf("group of the leader's child = %d, want %d", got, b.pid)
	}
	if rc := root.Proc_kill(m, -b.pid, 10); rc != _wasiESUCCESS {
		t.Fatalf("kill(-pgid) rc=%d", rc)
	}
	if got := b.signals(); len(got) != 2 || got[1] != 10 {
		t.Fatalf("leader got %v, want [15 10]", got)
	}
	if got := c.signals(); len(got) != 1 || got[0] != 10 {
		t.Fatalf("member got %v, want [10]", got)
	}
	if got := a.signals(); len(got) != 0 {
		t.Fatalf("a process outside the group got %v", got)
	}
	if root.sig.pending != 0 {
		t.Fatal("the first process is not in that group and was signalled")
	}
	// The first group no longer has b in it.
	if rc := root.Proc_kill(m, 0, 12); rc != _wasiESUCCESS {
		t.Fatalf("kill(0) rc=%d", rc)
	}
	if got := b.signals(); len(got) != 2 {
		t.Fatalf("b left the group and still got %v", got)
	}
	if got := a.signals(); len(got) != 1 || got[0] != 12 {
		t.Fatalf("a got %v, want [12]", got)
	}

	// A parent moves its child into an existing group; a group nobody is in
	// cannot be joined.
	if rc := root.Proc_setpgid(m, a.pid, b.pid); rc != _wasiESUCCESS {
		t.Fatalf("setpgid(child, group) rc=%d", rc)
	}
	if got := processGroup(t, a.wasi, 0); got != b.pid {
		t.Fatalf("group after the move = %d, want %d", got, b.pid)
	}
	if rc := root.Proc_setpgid(m, a.pid, 7777); rc != -_wasiEPERM {
		t.Fatalf("joining a group that does not exist rc=%d, want -EPERM", rc)
	}
	if rc := a.wasi.Proc_setpgid(m, b.pid, 0); rc != -_wasiESRCH {
		t.Fatalf("setpgid of a process that is not a child rc=%d, want -ESRCH", rc)
	}
	if rc := root.Proc_kill(m, -7777, 15); rc != -_wasiESRCH {
		t.Fatalf("signal to a group nobody is in rc=%d, want -ESRCH", rc)
	}
	if rc := root.Proc_kill(m, -b.pid, 0); rc != _wasiESUCCESS {
		t.Fatalf("probe of a group rc=%d", rc)
	}
}

func TestSetsidOfAForkedProcess(t *testing.T) {
	root := DefaultWASI()
	m := newForkTestModule()
	child := forkProcess(t, root)
	if rc := child.wasi.Proc_setsid(m, 64); rc != _wasiESUCCESS {
		t.Fatalf("setsid rc=%d", rc)
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[64:])); got != child.pid {
		t.Fatalf("session = %d, want %d", got, child.pid)
	}
	if got := processGroup(t, child.wasi, 0); got != child.pid {
		t.Fatalf("group after setsid = %d, want %d", got, child.pid)
	}
	// A group leader cannot start a session.
	if rc := child.wasi.Proc_setsid(m, 64); rc != -_wasiEPERM {
		t.Fatalf("setsid of a group leader rc=%d, want -EPERM", rc)
	}
	if rc := root.Proc_setsid(m, 64); rc != -_wasiEPERM {
		t.Fatalf("setsid of the first process rc=%d, want -EPERM", rc)
	}
}
