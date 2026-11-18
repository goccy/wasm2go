//go:build darwin || linux

package codegen

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// kernelCloexec is the kernel's close-on-exec flag of the host descriptor fd.
func kernelCloexec(t *testing.T, fd int) bool {
	t.Helper()
	flags, err := descriptorFlags(fd, syscall.F_GETFD)
	if err != nil {
		t.Fatalf("F_GETFD %d: %v", fd, err)
	}
	return flags&syscall.FD_CLOEXEC != 0
}

// outsideInherits reports whether a command code outside the guest starts
// (os/exec) is given the host descriptor fd.
func outsideInherits(t *testing.T, fd int) bool {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "test -e /dev/fd/"+strconv.Itoa(fd)).Run()
	if _, exited := err.(*exec.ExitError); err != nil && !exited {
		t.Fatalf("sh: %v", err)
	}
	return err == nil
}

// In the instance that is the host process, the close-on-exec flag of the
// guest's descriptor is the kernel's, as in a process of its own: a new
// descriptor is inheritable, fcntl's F_SETFD sets and clears the kernel's
// flag, which F_GETFD reads back, a dup2 onto a number is inheritable, and a
// command code outside the guest starts inherits by it. Before, the kernel
// kept every descriptor close-on-exec and the guest's flag lived in a table
// of the runtime's only.
func TestHostDescriptors_CloseOnExecIsTheKernels(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newHostGuest(t, dir)
	fd, errno := w.pathOpen("f", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	host := guestIsHost(t, w, fd)
	if kernelCloexec(t, host) {
		t.Errorf("a new descriptor is close-on-exec in the kernel")
	}
	const oldOff int32 = 5000
	set := func(value int32) {
		t.Helper()
		if rc := w.Fd_cloexec(m, fd, 1, value, oldOff); rc != _wasiESUCCESS {
			t.Fatalf("Fd_cloexec rc=%d", rc)
		}
	}
	get := func() uint32 {
		t.Helper()
		if rc := w.Fd_cloexec(m, fd, 0, 0, oldOff); rc != _wasiESUCCESS {
			t.Fatalf("Fd_cloexec rc=%d", rc)
		}
		return readU32(m.memory, int(oldOff))
	}
	set(1)
	if !kernelCloexec(t, host) || get() != 1 {
		t.Errorf("F_SETFD FD_CLOEXEC: kernel %v, F_GETFD %d", kernelCloexec(t, host), get())
	}
	if outsideInherits(t, host) {
		t.Errorf("a command started outside the guest got a close-on-exec descriptor")
	}
	set(0)
	if kernelCloexec(t, host) || get() != 0 {
		t.Errorf("F_SETFD 0: kernel %v, F_GETFD %d", kernelCloexec(t, host), get())
	}
	if !outsideInherits(t, host) {
		t.Errorf("a command started outside the guest did not get an inheritable descriptor")
	}
	set(1)
	to := int32(host + 7)
	if rc := w.Fd_dup2(m, fd, to); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	if dup := guestIsHost(t, w, to); kernelCloexec(t, dup) {
		t.Errorf("the duplicate dup2 made is close-on-exec")
	}
	closeTestFd(t, w, m, to)
	closeTestFd(t, w, m, fd)
}
