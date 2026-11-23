package codegen

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// dupTo makes descriptor to a duplicate of from, closing what it was
// (dup2). (Package syscall has Dup2 on some Linux architectures only.)
func dupTo(from, to int) error { return syscall.Dup3(from, to, 0) }

// hostTellsPipeRoom reports whether the host tells how to write to a pipe
// without waiting whatever its mode (hostPipeWriteNow): a kernel that takes
// RWF_NOWAIT for a pipe, on an architecture whose pwritev2 is known.
func hostTellsPipeRoom() bool {
	_, known := hostSysPwritev2()
	return known && !hostPipeNowaitRefused.Load()
}

// statusUmask reads the umask of a status file, and fails for one it cannot
// read: ErrUnsupported for a status without a umask.
func TestStatusUmask(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := statusUmask(write("ok", "Name:\tx\nUmask:\t0027\nState:\tR\n")); err != nil || got != 0o027 {
		t.Fatalf("statusUmask = %o, %v; want 027", got, err)
	}
	if _, err := statusUmask(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("statusUmask of a missing file: %v, want ErrNotExist", err)
	}
	if _, err := statusUmask(write("none", "Name:\tx\n")); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("statusUmask without a umask: %v, want ErrUnsupported", err)
	}
	if _, err := statusUmask(write("bad", "Umask:\t09\n")); err == nil || errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("statusUmask of a malformed umask: %v, want a parse error", err)
	}
}

// A write that does not wait to a pipe in blocking mode takes nothing from
// a full pipe, and from one with room the room the host has, more than
// PIPE_BUF, in one call (hostPipeWriteNow).
func TestHostPipeWriteNowTakesTheRoom(t *testing.T) {
	r, wr := blockingPipe(t)
	fillBlockingPipe(t, wr)
	rc, err := wr.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	write := func(size int) (int, bool) {
		t.Helper()
		var n int
		var again, done bool
		var writeErr error
		if err := rc.Control(func(fd uintptr) {
			n, again, done, writeErr = hostPipeWriteNow(fd, [][]byte{make([]byte, size)}, false)
		}); err != nil || writeErr != nil {
			t.Fatal(err, writeErr)
		}
		if !done {
			if hostTellsPipeRoom() {
				t.Fatal("the host takes RWF_NOWAIT for a pipe, and the write did not use it")
			}
			t.Skip("the host does not take RWF_NOWAIT for a pipe")
		}
		return n, again
	}
	if n, again := write(1); !again || n != 0 {
		t.Fatalf("write to a full pipe = %d, again %v; want nothing, again", n, again)
	}
	if _, err := io.ReadFull(r, make([]byte, 4*hostPipeBuf)); err != nil {
		t.Fatal(err)
	}
	if n, again := write(1 << 20); again || n <= hostPipeBuf {
		t.Fatalf("write to a pipe with room = %d, again %v; want more than PIPE_BUF (%d)", n, again, hostPipeBuf)
	}
}
