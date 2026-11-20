package codegen

import (
	"os"
	"path/filepath"
	"testing"
)

// A descriptor is open for reading, for writing or for both, and says so:
// in the rights fd_fdstat_get reports and in what a read or write of it
// answers.

const accessStatOff int32 = 15000

// accessOf returns whether fd_fdstat_get reports fd open for reading and
// for writing.
func accessOf(t *testing.T, w *WasiStubs, m *Module, fd int32) (read, write bool) {
	t.Helper()
	if rc := w.Fd_fdstat_get(m, fd, accessStatOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_get(%d) rc=%d", fd, rc)
	}
	rights := readU64(m.memory, int(accessStatOff)+8)
	return rights&(wasiRightFdRead|wasiRightFdReaddir) != 0, rights&wasiRightFdWrite != 0
}

func wantAccess(t *testing.T, w *WasiStubs, m *Module, what string, fd int32, read, write bool) {
	t.Helper()
	if r, wr := accessOf(t, w, m, fd); r != read || wr != write {
		t.Errorf("%s: read=%v write=%v, want read=%v write=%v", what, r, wr, read, write)
	}
}

// openWith opens name under the preopen with the given rights (read 1<<1,
// write 1<<6) and returns the fd.
func openWith(t *testing.T, w *WasiStubs, m *Module, name string, oflags int32, rights int64) int32 {
	t.Helper()
	pathOff, pathLen := putPath(m, 14000, name)
	const fdOff int32 = 14500
	if rc := w.Path_open(m, 3, 0x1, pathOff, pathLen, oflags, rights, 0, 0, fdOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_open(%s) rc=%d", name, rc)
	}
	return int32(readU32(m.memory, int(fdOff)))
}

func TestWasi_PipeEndsHaveOneDirection(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	wantAccess(t, w, m, "read end", readFd, true, false)
	wantAccess(t, w, m, "write end", writeFd, false, true)

	if _, rc := fdReadString(w, m, writeFd, 16); rc != _wasiEBADF {
		t.Errorf("read of the write end rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, readFd, "x"); rc != _wasiEBADF {
		t.Errorf("write to the read end rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, writeFd, "data"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "data" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

func TestWasi_FilesHaveTheAccessTheyWereOpenedWith(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	const read, write int64 = 1 << 1, 1 << 6

	readOnly := openWith(t, w, m, "f", 0, read)
	wantAccess(t, w, m, "read-only file", readOnly, true, false)
	if rc := fdWriteString(w, m, readOnly, "x"); rc != _wasiEBADF {
		t.Errorf("write to a read-only file rc=%d, want EBADF", rc)
	}
	makeIovec(m, forkTestIovOff, forkTestBufOff, 1)
	if rc := w.Fd_pwrite(m, readOnly, forkTestIovOff, 1, 0, forkTestCountOff); rc != _wasiEBADF {
		t.Errorf("pwrite to a read-only file rc=%d, want EBADF", rc)
	}
	if got, rc := fdReadString(w, m, readOnly, 16); rc != _wasiESUCCESS || got != "content" {
		t.Errorf("read of a read-only file = %q rc=%d", got, rc)
	}

	writeOnly := openWith(t, w, m, "f", 0, write)
	wantAccess(t, w, m, "write-only file", writeOnly, false, true)
	if _, rc := fdReadString(w, m, writeOnly, 16); rc != _wasiEBADF {
		t.Errorf("read of a write-only file rc=%d, want EBADF", rc)
	}
	if rc := w.Fd_pread(m, writeOnly, forkTestIovOff, 1, 0, forkTestCountOff); rc != _wasiEBADF {
		t.Errorf("pread of a write-only file rc=%d, want EBADF", rc)
	}
	if rc := fdWriteString(w, m, writeOnly, "CON"); rc != _wasiESUCCESS {
		t.Errorf("write to a write-only file rc=%d", rc)
	}

	both := openWith(t, w, m, "f", 0, read|write)
	wantAccess(t, w, m, "read-write file", both, true, true)
	// An open that names no access is a read-only open.
	wantAccess(t, w, m, "file opened without rights", openWith(t, w, m, "f", 0, 0), true, false)
	wantAccess(t, w, m, "directory", openWith(t, w, m, ".", 0x2, read), true, false)
}

func TestWasi_StandardStreamsAndSocketsAccess(t *testing.T) {
	w, m := newProcTestStubs(t)
	wantAccess(t, w, m, "stdin", 0, true, false)
	wantAccess(t, w, m, "stdout", 1, false, true)
	wantAccess(t, w, m, "stderr", 2, false, true)
	wantAccess(t, w, m, "socket", w.Sock_socket(m, 2, 1), true, true)
	// The duplicate of a descriptor has its access.
	const dupOff int32 = 15100
	_, writeFd := newTestPipe(t, w, m)
	if rc := w.Fd_dup(m, writeFd, dupOff); rc != 0 {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	wantAccess(t, w, m, "duplicate of a write end", int32(readU32(m.memory, int(dupOff))), false, true)
}
