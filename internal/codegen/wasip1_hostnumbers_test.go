//go:build darwin || linux

package codegen

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A failed system call is the error its number says, not the nearest kind
// package os knows.
func TestWasi_ErrorsKeepTheirNumber(t *testing.T) {
	for _, c := range []struct {
		err  syscall.Errno
		want int32
	}{
		{syscall.ENOTEMPTY, 55}, {syscall.ELOOP, 32}, {syscall.ENAMETOOLONG, 37},
		{syscall.EXDEV, 75}, {syscall.EMFILE, 33}, {syscall.ENOSPC, 51},
		{syscall.EROFS, 69}, {syscall.ENOENT, 44}, {syscall.EEXIST, 20},
		{syscall.EACCES, 2}, {syscall.EPERM, 63}, {syscall.EAGAIN, 6},
		{syscall.EWOULDBLOCK, 6}, {syscall.ENOTSUP, 58}, {syscall.EOPNOTSUPP, 58},
		{syscall.ETXTBSY, 74}, {syscall.EBUSY, 10}, {syscall.EMLINK, 34},
		{syscall.ESRCH, 71}, {syscall.ENXIO, 60}, {syscall.ECONNRESET, 15},
		{syscall.ETIMEDOUT, 73}, {syscall.ENOTCONN, 53},
	} {
		for _, err := range []error{c.err, &os.PathError{Op: "open", Path: "x", Err: c.err},
			fmt.Errorf("wrapped: %w", os.NewSyscallError("rename", c.err))} {
			if got := mapOSError(err); got != c.want {
				t.Errorf("mapOSError(%v) = %d, want %d", err, got, c.want)
			}
		}
	}
	// An error of the host's that wasi has no number for is an I/O error.
	if got := mapOSError(syscall.EHOSTDOWN); got != _wasiEIO {
		t.Errorf("EHOSTDOWN = %d, want EIO", got)
	}
	if got := mapOSError(&os.PathError{Op: "mount", Path: "x", Err: syscall.ENOTBLK}); got != _wasiEIO {
		t.Errorf("ENOTBLK = %d, want EIO", got)
	}
	// An error that is no system call's has its kind.
	if got := mapOSError(errors.New("no number")); got != _wasiEIO {
		t.Errorf("an error without a number = %d, want EIO", got)
	}
	if got := mapOSError(os.ErrNotExist); got != _wasiENOENT {
		t.Errorf("os.ErrNotExist = %d, want ENOENT", got)
	}
	if got := mapOSError(errors.ErrUnsupported); got != _wasiENOTSUP {
		t.Errorf("errors.ErrUnsupported = %d, want ENOTSUP", got)
	}

	// The system calls themselves.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := mapOSError(os.Remove(filepath.Join(dir, "d"))); got != 55 {
		t.Errorf("removing a directory that is not empty = %d, want ENOTEMPTY (55)", got)
	}
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Open(filepath.Join(dir, "loop")); mapOSError(err) != 32 {
		t.Errorf("opening a link to itself = %d, want ELOOP (32)", mapOSError(err))
	}
	if _, err := os.Open(filepath.Join(dir, strings.Repeat("n", 5000))); mapOSError(err) != 37 {
		t.Errorf("opening a name too long = %d, want ENAMETOOLONG (37)", mapOSError(err))
	}
}
