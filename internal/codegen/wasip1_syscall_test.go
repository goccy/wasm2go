//go:build linux && (arm64 || amd64)

package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// sys_syscall is the host's system call for the guest that is the host
// process. A process forked from it makes only the calls that depend on no
// state of the operating system's process, which it shares with its parent,
// and the numbers the architecture leaves unassigned, which the kernel
// answers as for the guest. Any other call it does not make, and is told so
// by its own status (sysSyscallForked) rather than an errno: getpid would
// name the parent, execve would replace both.
func TestSysSyscallOfAForkedProcess(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	const argsOff, resultOff, bufOff = 4096, 4200, 4300
	numbers := map[string]map[string]int64{
		"arm64": {"getrandom": 278, "clock_gettime": 113, "unassigned": 355, "pidfd_open": 434},
		"amd64": {"getrandom": 318, "clock_gettime": 228, "unassigned": 400, "pidfd_open": 434},
	}[runtime.GOARCH]
	call := func(w *WasiStubs, m *Module, number int64, ptrs int32, args ...uint64) (int32, int64) {
		for i, a := range args {
			binary.LittleEndian.PutUint64(m.memory[argsOff+8*i:], a)
		}
		binary.LittleEndian.PutUint64(m.memory[resultOff:], 0)
		rc := w.Sys_syscall(m, number, argsOff, int32(len(args)), ptrs, resultOff)
		return rc, int64(binary.LittleEndian.Uint64(m.memory[resultOff:]))
	}
	getpid := int64(syscall.SYS_GETPID)
	if rc, pid := call(w, m, getpid, 0); rc != 0 || pid != int64(os.Getpid()) {
		t.Fatalf("the guest's getpid: rc %d result %d, want 0 and %d", rc, pid, os.Getpid())
	}
	child := w.Fork()
	defer child.CloseAll()
	cm := newForkTestModule()

	// calls that act on the process, or read its state, are not made
	if rc, result := call(child, cm, getpid, 0); rc != sysSyscallForked || result != 0 {
		t.Errorf("the forked process's getpid: rc %d result %d, want %d and no call made", rc, result, sysSyscallForked)
	}
	const clockProcessCPUTime = 2
	if rc, _ := call(child, cm, numbers["clock_gettime"], 1<<1, clockProcessCPUTime, bufOff); rc != sysSyscallForked {
		t.Errorf("the forked process's clock_gettime(CLOCK_PROCESS_CPUTIME_ID): rc %d, want %d", rc, sysSyscallForked)
	}
	if rc, _ := call(child, cm, numbers["pidfd_open"], 0, uint64(os.Getpid()), 0); rc != sysSyscallForked {
		t.Errorf("the forked process's pidfd_open, a shared number not listed: rc %d, want %d", rc, sysSyscallForked)
	}

	// calls that depend on no state of the process are made
	copy(cm.memory[bufOff:bufOff+16], bytes.Repeat([]byte{' '}, 16))
	if rc, n := call(child, cm, numbers["getrandom"], 1<<0, bufOff, 16, 0); rc != 0 || n != 16 ||
		bytes.Equal(cm.memory[bufOff:bufOff+16], bytes.Repeat([]byte{' '}, 16)) {
		t.Errorf("the forked process's getrandom: rc %d result %d, bytes %q", rc, n, cm.memory[bufOff:bufOff+16])
	}
	const clockRealtime = 0
	var now syscall.Timeval
	_ = syscall.Gettimeofday(&now)
	if rc, r := call(child, cm, numbers["clock_gettime"], 1<<1, clockRealtime, bufOff); rc != 0 || r != 0 ||
		int64(binary.LittleEndian.Uint64(cm.memory[bufOff:])) < now.Sec {
		t.Errorf("the forked process's clock_gettime(CLOCK_REALTIME): rc %d result %d, seconds %d (now %d)",
			rc, r, binary.LittleEndian.Uint64(cm.memory[bufOff:]), now.Sec)
	}

	// a number that is no call gets what the guest gets for it (ENOSYS, or
	// what a seccomp filter says)
	guestRC, guestResult := call(w, m, numbers["unassigned"], 0)
	if guestRC == 0 || guestRC == sysSyscallForked {
		t.Fatalf("the guest's unassigned number %d: rc %d result %d, want an errno", numbers["unassigned"], guestRC, guestResult)
	}
	if rc, result := call(child, cm, numbers["unassigned"], 0); rc != guestRC || result != guestResult {
		t.Errorf("the forked process's unassigned number %d: rc %d result %d, want the guest's rc %d result %d",
			numbers["unassigned"], rc, result, guestRC, guestResult)
	}

	if rc, pid := call(w, m, getpid, 0); rc != 0 || pid != int64(os.Getpid()) {
		t.Errorf("the guest's getpid after the fork: rc %d result %d", rc, pid)
	}
}
