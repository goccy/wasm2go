package codegen

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// errnoOfError is the errno wasiErrnoOf gives err, for the tests that look
// at the errno alone.
func errnoOfError(err error) int32 {
	errno, _ := wasiErrnoOf(err)
	return errno
}

func TestWasiErrnoOf(t *testing.T) {
	cases := []struct {
		err   error
		want  int32
		known bool
	}{
		{nil, _wasiESUCCESS, true},
		{fs.ErrNotExist, _wasiENOENT, true},
		{fs.ErrExist, _wasiEEXIST, true},
		{fs.ErrPermission, _wasiEACCES, true},
		{fs.ErrInvalid, _wasiEINVAL, true},
		{syscall.ENOTDIR, _wasiENOTDIR, true},
		{syscall.EISDIR, _wasiEISDIR, true},
		{syscall.EINVAL, _wasiEINVAL, true},
		{syscall.EBADF, _wasiEBADF, true},
		{fs.ErrClosed, _wasiEBADF, true},
		{net.ErrClosed, _wasiEBADF, true},
		{syscall.ENOSPC, _wasiENOSPC, true},
		{syscall.EAGAIN, _wasiEAGAIN, true},
		{syscall.EPIPE, _wasiEPIPE, true},
		{io.ErrClosedPipe, _wasiEPIPE, true},
		{syscall.ENOSYS, _wasiENOSYS, true},
		{&os.PathError{Op: "op", Path: "x", Err: unnumberedENOSYS{}}, _wasiENOSYS, true},
		// What a value or the host does not implement is ENOSYS; a number
		// of the host's says which error it is.
		{errors.ErrUnsupported, _wasiENOSYS, true},
		{syscall.ENOTSUP, _wasiENOTSUP, true},
		{syscall.EOPNOTSUPP, _wasiENOTSUP, true},
		{&os.PathError{Op: "op", Path: "x", Err: unnumberedENOTSUP{}}, _wasiENOTSUP, true},
		{os.ErrDeadlineExceeded, _wasiETIMEDOUT, true},
		{fmt.Errorf("dial: %w", timeoutError{timeout: true}), _wasiETIMEDOUT, true},
		{exec.ErrNotFound, _wasiENOENT, true},
		{&exec.Error{Name: "cmd", Err: exec.ErrNotFound}, _wasiENOENT, true},
		// Wrapped errors must still map.
		{fmt.Errorf("open: %w", fs.ErrNotExist), _wasiENOENT, true},
		// An error that has no errno is EIO.
		{fmt.Errorf("anything else"), _wasiEIO, false},
		{timeoutError{}, _wasiEIO, false},
		{&exec.Error{Name: "cmd", Err: exec.ErrDot}, _wasiEIO, false},
	}
	for _, c := range cases {
		if got, known := wasiErrnoOf(c.err); got != c.want || known != c.known {
			t.Errorf("wasiErrnoOf(%v) = %d, %v, want %d, %v", c.err, got, known, c.want, c.known)
		}
	}
}

// timeoutError is a net.Error whose Timeout is timeout.
type timeoutError struct{ timeout bool }

func (timeoutError) Error() string   { return "timeout or not" }
func (e timeoutError) Timeout() bool { return e.timeout }
func (timeoutError) Temporary() bool { return false }

// unnumberedENOSYS is an error that is ENOSYS, and so errors.ErrUnsupported
// as well, without being a syscall.Errno.
type unnumberedENOSYS struct{}

func (unnumberedENOSYS) Error() string { return "not implemented" }
func (unnumberedENOSYS) Is(target error) bool {
	return target == syscall.ENOSYS || target == errors.ErrUnsupported
}

// unnumberedENOTSUP is unnumberedENOSYS for ENOTSUP: what errors of the kind
// are on a host whose numbers the runtime does not know.
type unnumberedENOTSUP struct{}

func (unnumberedENOTSUP) Error() string { return "not supported" }
func (unnumberedENOTSUP) Is(target error) bool {
	return target == syscall.ENOTSUP || target == errors.ErrUnsupported
}

// An error without an errno fails the call with EIO and is told Errors under
// the operation; an error with one is not.
func TestGuestErrnoReports(t *testing.T) {
	var told []string
	var toldErr error
	w := &WasiStubs{cfg: WASIConfig{Errors: func(op string, err error) { told, toldErr = append(told, op), err }}}
	if got := w.guestErrno("fd_read", fs.ErrNotExist); got != _wasiENOENT || len(told) != 0 {
		t.Errorf("guestErrno(ErrNotExist) = %d, told %q; want ENOENT, nothing told", got, told)
	}
	unknown := errors.New("no errno")
	if got := w.guestErrno("fd_read", unknown); got != _wasiEIO || len(told) != 1 || told[0] != "fd_read" || !errors.Is(toldErr, unknown) {
		t.Errorf("guestErrno(no errno) = %d, told %q %v; want EIO, fd_read and the error", got, told, toldErr)
	}
}

// The failure of a command's wait itself is a 127 exit, told Errors; the
// exit of the command is none.
func TestWaitStatusOfReports(t *testing.T) {
	var told []string
	w := &WasiStubs{cfg: WASIConfig{Errors: func(op string, err error) { told = append(told, op) }}}
	if got := w.waitStatusOf(nil, &exec.ExitError{}); got != 0 || len(told) != 0 {
		t.Errorf("waitStatusOf(an exit) = %d, told %q; want 0, nothing told", got, told)
	}
	if got := w.waitStatusOf(nil, syscall.ECHILD); got != 127<<8 || len(told) != 1 || told[0] != "proc_spawn" {
		t.Errorf("waitStatusOf(ECHILD) = %d, told %q; want 127 << 8 and proc_spawn", got, told)
	}
}

// Errors is told an error without an errno with no lock of the instance or
// of the descriptor held: of the priority a forked instance starts from, and
// of the failure a stream's reader ran into.
func TestGuestErrnoReportsWithoutLocks(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	op := &wasiOpen{reader: newStreamReader(nil, func(error) {})}
	var told []string
	w.cfg.Errors = func(name string, err error) {
		told = append(told, name)
		for _, mu := range []*sync.Mutex{&w.mu.Mutex, &op.mu, &op.reader.mu} {
			if !mu.TryLock() {
				t.Errorf("%s: Errors told with a lock held", name)
				continue
			}
			mu.Unlock()
		}
	}
	process := newIDsProcess()
	process.err = errors.New("no priority")
	w.cfg.Process = process
	if errno := w.setOwnNice(true, 0); errno != _wasiEIO {
		t.Errorf("setOwnNice errno=%d, want EIO", errno)
	}
	op.reader.end = errors.New("read failed")
	if _, errno := w.readThroughReader(m, "fd_read", op, op.reader, nil, true); errno != _wasiEIO {
		t.Errorf("readThroughReader errno=%d, want EIO", errno)
	}
	if len(told) != 2 || told[0] != "proc_priority" || told[1] != "fd_read" {
		t.Errorf("Errors was told %q, want proc_priority and fd_read", told)
	}
}

// An open that does not follow a symbolic link and meets one is ELOOP, as
// open(2) with O_NOFOLLOW is; one that creates the file exclusively is
// EEXIST, as with O_CREAT|O_EXCL, a link to nothing included.
func TestPathOpenNoFollowLoop(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "target"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, errno := w.pathOpen(m, "link", 0, 0, 1<<1, 0); errno != _wasiELOOP {
		t.Errorf("open of a link without following it errno=%d, want ELOOP", errno)
	}
	if _, errno := w.pathOpen(m, "link", 1, 0, 1<<1, 0); errno != _wasiESUCCESS {
		t.Errorf("open of a link following it errno=%d", errno)
	}
	if err := os.Symlink("none", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "dangling"} {
		// O_CREAT|O_EXCL, FD_WRITE
		if _, errno := w.pathOpen(m, name, 0, 0x5, 1<<6, 0); errno != _wasiEEXIST {
			t.Errorf("exclusive create of %s errno=%d, want EEXIST", name, errno)
		}
	}
}

// unsupportedFS is a MemFS that opens nothing (errors.ErrUnsupported) and
// keeps no owners (the host's ENOTSUP).
type unsupportedFS struct{ *MemFS }

func (unsupportedFS) OpenFile(string, int, os.FileMode) (File, error) {
	return nil, fmt.Errorf("open: %w", errors.ErrUnsupported)
}
func (unsupportedFS) Chown(string, int, int) error { return syscall.ENOTSUP }

// An FS's errors.ErrUnsupported is ENOSYS, as a configured value's is; a
// number of the host's is its own errno.
func TestFSUnsupportedErrno(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.FS = unsupportedFS{NewMemFS()}
	if _, errno := w.pathOpen(m, "f", 1, 0, 1<<1, 0); errno != _wasiENOSYS {
		t.Errorf("open errno=%d, want ENOSYS", errno)
	}
	path, pathLen := putPath(m, 1000, "f")
	if rc := w.Path_chown(m, path, pathLen, 0, 0, 1); rc != -_wasiENOTSUP {
		t.Errorf("chown rc=%d, want -ENOTSUP", rc)
	}
}

func TestEncodeWaitStatusNil(t *testing.T) {
	if got := encodeWaitStatus(nil); got != 0 {
		t.Fatalf("nil state = %d", got)
	}
}

func TestTotalBytesPlusNul(t *testing.T) {
	if n, ok := totalBytesPlusNul([]string{"ab", "c"}); !ok || n != 5 {
		t.Fatalf("got %d %v", n, ok)
	}
	if n, ok := totalBytesPlusNul(nil); !ok || n != 0 {
		t.Fatalf("empty: got %d %v", n, ok)
	}
	huge := string(make([]byte, 1<<20))
	ss := make([]string, 2048) // 2048 MiB + nuls > int32
	for i := range ss {
		ss[i] = huge
	}
	if _, ok := totalBytesPlusNul(ss); ok {
		t.Fatal("overflow not detected")
	}
}
