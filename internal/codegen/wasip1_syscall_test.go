//go:build linux && (arm64 || amd64)

package codegen

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"
)

// sys_syscall is the host's system call for the guest that is the host
// process, and none for a process forked from it, which is told so by its
// own status (sysSyscallForked) rather than an errno: a raw call acts on
// the operating system's process, which the forked process shares with
// its parent (getpid would name the parent; execve would replace both).
func TestSysSyscallIsRefusedToAForkedProcess(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	const argsOff, resultOff = 4096, 4200
	getpid := func(w *WasiStubs, m *Module) (int32, int64) {
		rc := w.Sys_syscall(m, int64(syscall.SYS_GETPID), argsOff, 0, 0, resultOff)
		return rc, int64(binary.LittleEndian.Uint64(m.memory[resultOff:]))
	}
	if rc, pid := getpid(w, m); rc != 0 || pid != int64(os.Getpid()) {
		t.Fatalf("the guest's getpid: rc %d result %d, want 0 and %d", rc, pid, os.Getpid())
	}
	child := w.Fork()
	defer child.CloseAll()
	cm := newForkTestModule()
	binary.LittleEndian.PutUint64(cm.memory[resultOff:], 0)
	if rc, result := getpid(child, cm); rc != sysSyscallForked || result != 0 {
		t.Fatalf("the forked process's getpid: rc %d result %d, want %d and no call made", rc, result, sysSyscallForked)
	}
	if rc, pid := getpid(w, m); rc != 0 || pid != int64(os.Getpid()) {
		t.Fatalf("the guest's getpid after the fork: rc %d result %d", rc, pid)
	}
}
