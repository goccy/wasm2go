package codegen

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// openTestPty opens a pseudo-terminal (posix_openpt, grantpt, unlockpt,
// ptsname) and returns its master and, in blocking mode as a terminal a
// process inherits is, its slave.
func openTestPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	closeAtEnd(t, master)
	var name [128]byte
	for _, req := range []struct {
		op  uintptr
		arg uintptr
	}{
		{syscall.TIOCPTYGRANT, 0},
		{syscall.TIOCPTYUNLK, 0},
		{syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))},
	} {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req.op, req.arg); errno != 0 {
			t.Skipf("no pseudo-terminal: ioctl %#x: %v", req.op, errno)
		}
	}
	path := string(name[:bytes.IndexByte(name[:], 0)])
	sfd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	slave = os.NewFile(uintptr(sfd), path)
	closeAtEnd(t, slave)
	return master, slave
}
