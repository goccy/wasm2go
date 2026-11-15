//go:build darwin || linux

package codegen

import (
	"encoding/binary"
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
	} {
		for _, err := range []error{c.err, &os.PathError{Op: "open", Path: "x", Err: c.err},
			fmt.Errorf("wrapped: %w", os.NewSyscallError("rename", c.err))} {
			if got := mapOSError(err); got != c.want {
				t.Errorf("mapOSError(%v) = %d, want %d", err, got, c.want)
			}
		}
	}
	// An error of the host's that wasi has no number for is carried as
	// the host's number, marked.
	if got := mapOSError(syscall.EHOSTDOWN); got != wasiErrnoHostOnly|int32(syscall.EHOSTDOWN) {
		t.Errorf("EHOSTDOWN = %#x, want the marked number %#x", got, wasiErrnoHostOnly|int32(syscall.EHOSTDOWN))
	}
	if got := mapOSError(&os.PathError{Op: "mount", Path: "x", Err: syscall.ENOTBLK}); got != wasiErrnoHostOnly|int32(syscall.ENOTBLK) {
		t.Errorf("ENOTBLK = %#x, want the marked number", got)
	}
	// An error that is no system call's has its kind, as before.
	if got := mapOSError(errors.New("no number")); got != _wasiEIO {
		t.Errorf("an error without a number = %d, want EIO", got)
	}
	if got := mapOSError(os.ErrNotExist); got != _wasiENOENT {
		t.Errorf("os.ErrNotExist = %d, want ENOENT", got)
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

// hostNumbersOf reads a whole family through the import.
func hostNumbersOf(t *testing.T, w *WasiStubs, family int32) map[string]int64 {
	t.Helper()
	m := newGuestModule(1 << 12)
	const namePtr, nameCap, lenPtr, valuePtr = 16, 64, 128, 136
	numbers := map[string]int64{}
	for index := int32(0); ; index++ {
		rc := w.Host_number_at(m, family, index, namePtr, nameCap, lenPtr, valuePtr)
		if rc == -_wasiENOENT {
			return numbers
		}
		if rc != 0 {
			t.Fatalf("host_number_at(%d, %d) = %d", family, index, rc)
		}
		n := binary.LittleEndian.Uint32(m.memory[lenPtr:])
		name := string(m.memory[namePtr : namePtr+n])
		if _, twice := numbers[name]; twice {
			t.Errorf("family %d names %s twice", family, name)
		}
		numbers[name] = int64(binary.LittleEndian.Uint64(m.memory[valuePtr:]))
	}
}

// The guest of the host process is shown the host's numbers and can ask for
// them, family by family; any other guest keeps its own.
func TestWasi_HostNumbers(t *testing.T) {
	w := DefaultWASI()
	m := newGuestModule(1 << 12)
	if got := w.Host_numbering(m); got != 0 {
		t.Errorf("host_numbering of a sandboxed guest = %d, want 0", got)
	}
	w.SetHostProcess(true)
	defer w.SetHostProcess(false)
	if got := w.Host_numbering(m); got != 1 {
		t.Errorf("host_numbering of the host process = %d, want 1", got)
	}

	errnos := hostNumbersOf(t, w, hostNumberFamilyErrno)
	for name, want := range map[string]syscall.Errno{
		"ENOENT": syscall.ENOENT, "EAGAIN": syscall.EAGAIN, "EWOULDBLOCK": syscall.EWOULDBLOCK,
		"ENOTEMPTY": syscall.ENOTEMPTY, "ETIMEDOUT": syscall.ETIMEDOUT, "ENOTBLK": syscall.ENOTBLK,
	} {
		if got, ok := errnos[name]; !ok || got != int64(want) {
			t.Errorf("errno %s = %d (%v), want %d", name, got, ok, want)
		}
	}
	// every wasi error the host has a name for is in the table under it
	for wasi, name := range wasiErrnoNames {
		if name == "" {
			continue
		}
		if value, ok := errnos[name]; ok {
			if got, known := wasiErrno(syscall.Errno(value)); !known || (got != int32(wasi) && name != "ENOTSUP") {
				t.Errorf("%s: host %d is wasi %d (%v), want %d", name, value, got, known, wasi)
			}
		}
	}
	signals := hostNumbersOf(t, w, 2)
	if signals["SIGUSR1"] != int64(syscall.SIGUSR1) || signals["SIGCHLD"] != int64(syscall.SIGCHLD) {
		t.Errorf("signals: USR1=%d CHLD=%d", signals["SIGUSR1"], signals["SIGCHLD"])
	}
	open := hostNumbersOf(t, w, 3)
	if open["O_CREAT"] != int64(syscall.O_CREAT) || open["O_NONBLOCK"] != int64(syscall.O_NONBLOCK) || open["O_ACCMODE"] != 3 {
		t.Errorf("open flags: %v", open)
	}
	poll := hostNumbersOf(t, w, 4)
	if poll["POLLIN"] != 1 || poll["POLLOUT"] != 4 || poll["POLLHUP"] != 0x10 {
		t.Errorf("poll bits: %v", poll)
	}
	if af := hostNumbersOf(t, w, 5); af["AF_INET"] != int64(syscall.AF_INET) || af["AF_INET6"] != int64(syscall.AF_INET6) {
		t.Errorf("address families: %v", af)
	}
	if len(hostNumbersOf(t, w, 9999)) != 0 {
		t.Error("a family that does not exist has numbers")
	}

	// A name that does not fit, and memory that is not there.
	if rc := w.Host_number_at(m, hostNumberFamilyErrno, 0, 16, 1, 128, 136); rc != -_wasiERANGE {
		t.Errorf("a name longer than its buffer: %d, want -ERANGE", rc)
	}
	if rc := w.Host_number_at(m, hostNumberFamilyErrno, 0, 16, 64, 128, 1<<20); rc != -_wasiEFAULT {
		t.Errorf("a value outside memory: %d, want -EFAULT", rc)
	}
}
