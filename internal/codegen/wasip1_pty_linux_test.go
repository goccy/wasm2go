package codegen

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// openTestPty opens a pseudo-terminal (posix_openpt, unlockpt, ptsname) and
// returns its master and, in blocking mode as a terminal a process inherits
// is, its slave.
func openTestPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	closeAtEnd(t, master)
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Skipf("no pseudo-terminal: unlockpt: %v", errno)
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		t.Skipf("no pseudo-terminal: ptsname: %v", errno)
	}
	path := fmt.Sprintf("/dev/pts/%d", n)
	sfd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	slave = os.NewFile(uintptr(sfd), path)
	closeAtEnd(t, slave)
	return master, slave
}
