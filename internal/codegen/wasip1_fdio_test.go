package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSubClock encodes a poll_oneoff clock subscription (relative
// timeout in ns) at off.
func writeSubClock(m *Module, off int32, userdata uint64, ns int64) {
	for i := int32(0); i < 48; i++ {
		m.memory[off+i] = 0
	}
	binary.LittleEndian.PutUint64(m.memory[off:], userdata)
	m.memory[off+8] = 0 // clock
	binary.LittleEndian.PutUint64(m.memory[off+24:], uint64(ns))
}

// writeSubFd encodes a poll_oneoff fd_read/fd_write subscription at off.
func writeSubFd(m *Module, off int32, userdata uint64, etype byte, fd int32) {
	for i := int32(0); i < 48; i++ {
		m.memory[off+i] = 0
	}
	binary.LittleEndian.PutUint64(m.memory[off:], userdata)
	m.memory[off+8] = etype
	binary.LittleEndian.PutUint32(m.memory[off+16:], uint32(fd))
}

func TestWasi_FdDupSharesOffsetAndDefersClose(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)

	fd, errno := w.pathOpen("f.txt", 0, 0, 1<<1 /* FD_READ */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	const outOff int32 = 100
	if rc := w.Fd_dup(m, fd, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	dup := int32(binary.LittleEndian.Uint32(m.memory[outOff:]))
	if dup == fd {
		t.Fatalf("dup fd = original fd %d", fd)
	}

	// The two fds share one open descriptor: reads advance a single offset.
	readByte := func(via int32) byte {
		iovOff, bufOff, nOff := int32(200), int32(300), int32(400)
		binary.LittleEndian.PutUint32(m.memory[iovOff:], uint32(bufOff))
		binary.LittleEndian.PutUint32(m.memory[iovOff+4:], 1)
		if rc := w.Fd_read(m, via, iovOff, 1, nOff); rc != _wasiESUCCESS {
			t.Fatalf("Fd_read(%d) rc=%d", via, rc)
		}
		if n := binary.LittleEndian.Uint32(m.memory[nOff:]); n != 1 {
			t.Fatalf("read %d bytes, want 1", n)
		}
		return m.memory[bufOff]
	}
	if got := readByte(fd); got != 'a' {
		t.Fatalf("first read = %q, want 'a'", got)
	}
	if got := readByte(dup); got != 'b' {
		t.Fatalf("read via dup = %q, want 'b' (shared offset)", got)
	}

	// Closing one reference keeps the descriptor open for the other.
	if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
		t.Fatalf("close original rc=%d", rc)
	}
	if got := readByte(dup); got != 'c' {
		t.Fatalf("read after closing one ref = %q, want 'c'", got)
	}
	if rc := w.Fd_close(m, dup); rc != _wasiESUCCESS {
		t.Fatalf("close dup rc=%d", rc)
	}
	if rc := w.Fd_close(m, dup); rc != _wasiEBADF {
		t.Fatalf("double close rc=%d, want EBADF", rc)
	}
}

func TestWasi_FdDup2RedirectsAndRestoresStdio(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	var out bytes.Buffer
	w.stdout = &out

	// Save fd 1 (an alias entry: closing it must not close the stream).
	const savedOff int32 = 100
	if rc := w.Fd_dup(m, 1, savedOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup(1) rc=%d", rc)
	}
	saved := int32(binary.LittleEndian.Uint32(m.memory[savedOff:]))

	// Point fd 1 at a real file.
	logFd, errno := w.pathOpen("log.txt", 0, 0x1 /* O_CREAT */, 1<<6 /* FD_WRITE */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	if rc := w.Fd_dup2(m, logFd, 1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2(log, 1) rc=%d", rc)
	}

	writeVia1 := func(s string) {
		iovOff, bufOff, nOff := int32(200), int32(300), int32(400)
		copy(m.memory[bufOff:], s)
		binary.LittleEndian.PutUint32(m.memory[iovOff:], uint32(bufOff))
		binary.LittleEndian.PutUint32(m.memory[iovOff+4:], uint32(len(s)))
		if rc := w.Fd_write(m, 1, iovOff, 1, nOff); rc != _wasiESUCCESS {
			t.Fatalf("Fd_write rc=%d", rc)
		}
	}
	writeVia1("to-file")

	// While redirected, a spawned child's stdout resolves to the file too.
	w.mu.Lock()
	cw := w.childWriterLocked(1, w.stdout)
	w.mu.Unlock()
	if _, isBuf := cw.(*bytes.Buffer); isBuf {
		t.Fatal("childWriterLocked(1) ignored the redirection")
	}

	// Restore and close the saved alias; the stream must still work.
	if rc := w.Fd_dup2(m, saved, 1); rc != _wasiESUCCESS {
		t.Fatalf("restore rc=%d", rc)
	}
	if rc := w.Fd_close(m, saved); rc != _wasiESUCCESS {
		t.Fatalf("close saved rc=%d", rc)
	}
	writeVia1("to-stream")

	if got, err := os.ReadFile(filepath.Join(dir, "log.txt")); err != nil || string(got) != "to-file" {
		t.Fatalf("log.txt = %q, %v; want %q", got, err, "to-file")
	}
	if out.String() != "to-stream" {
		t.Fatalf("stdout = %q, want %q", out.String(), "to-stream")
	}
	if rc := w.Fd_dup2(m, 99, 1); rc != _wasiEBADF {
		t.Fatalf("Fd_dup2 from bad fd rc=%d, want EBADF", rc)
	}
}

func TestWasi_PathChmodAndFilestatMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)

	pathOff := writeCStr(m, 1000, "f.txt")
	if rc := w.Path_chmod(m, pathOff, 5, 0o460); rc != _wasiESUCCESS {
		t.Fatalf("Path_chmod rc=%d", rc)
	}
	fi, err := os.Stat(filepath.Join(dir, "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o460 {
		t.Fatalf("perm = %o, want 460", perm)
	}

	const modeOff int32 = 2000
	if rc := w.Path_filestat_mode(m, pathOff, 5, 1, modeOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_mode rc=%d", rc)
	}
	if mode := binary.LittleEndian.Uint32(m.memory[modeOff:]); mode != 0o460 {
		t.Fatalf("reported mode = %o, want 460", mode)
	}

	missOff := writeCStr(m, 3000, "missing")
	if rc := w.Path_filestat_mode(m, missOff, 7, 1, modeOff); rc >= 0 {
		t.Fatalf("stat of missing file rc=%d, want negative errno", rc)
	}

	// A backend without Chmod support reports ENOSYS.
	w.fsys = NewMemFS()
	if rc := w.Path_chmod(m, pathOff, 5, 0o600); rc != -_wasiENOSYS {
		t.Fatalf("MemFS Path_chmod rc=%d, want -ENOSYS", rc)
	}
}

func TestWasi_PollFdSubscriptionsPreemptTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen("f.txt", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}

	const subsOff, evOff, nevOff int32 = 1000, 2000, 3000
	// A one-second timeout plus a readable fd must return immediately
	// with only the fd event.
	writeSubClock(m, subsOff, 7, int64(time.Second))
	writeSubFd(m, subsOff+48, 8, 1 /* fd_read */, fd)
	start := time.Now()
	if rc := w.Poll_oneoff(m, subsOff, evOff, 2, nevOff); rc != _wasiESUCCESS {
		t.Fatalf("Poll_oneoff rc=%d", rc)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("poll with ready fd slept %v", d)
	}
	if nev := binary.LittleEndian.Uint32(m.memory[nevOff:]); nev != 1 {
		t.Fatalf("nevents = %d, want 1 (fd only)", nev)
	}
	if ud := binary.LittleEndian.Uint64(m.memory[evOff:]); ud != 8 {
		t.Fatalf("event userdata = %d, want the fd subscription's 8", ud)
	}

	// A clock-only subscription paces the call and reports the timeout.
	writeSubClock(m, subsOff, 9, int64(20*time.Millisecond))
	start = time.Now()
	if rc := w.Poll_oneoff(m, subsOff, evOff, 1, nevOff); rc != _wasiESUCCESS {
		t.Fatalf("clock-only Poll_oneoff rc=%d", rc)
	}
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Fatalf("clock-only poll returned after %v, want ~20ms", d)
	}
	if nev := binary.LittleEndian.Uint32(m.memory[nevOff:]); nev != 1 {
		t.Fatalf("clock nevents = %d, want 1", nev)
	}
	if ud := binary.LittleEndian.Uint64(m.memory[evOff:]); ud != 9 {
		t.Fatalf("clock event userdata = %d, want 9", ud)
	}
}

func TestWasi_FdDupEdgeCases(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)

	if rc := w.Fd_dup(m, 99, 100); rc != _wasiEBADF {
		t.Fatalf("Fd_dup(bad) rc=%d, want EBADF", rc)
	}
	fd, errno := w.pathOpen("f.txt", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	if rc := w.Fd_dup2(m, fd, fd); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2(fd, fd) rc=%d", rc)
	}
	// dup2 where the destination already references the same entry.
	if rc := w.Fd_dup2(m, fd, fd+50); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 rc=%d", rc)
	}
	if rc := w.Fd_dup2(m, fd, fd+50); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 onto same entry rc=%d", rc)
	}

	// Reads through a descriptor dup2'd onto fd 0 come from the file,
	// and childReaderLocked follows the same redirection.
	if rc := w.Fd_dup2(m, fd, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup2 onto 0 rc=%d", rc)
	}
	iovOff, bufOff, nOff := int32(200), int32(300), int32(400)
	binary.LittleEndian.PutUint32(m.memory[iovOff:], uint32(bufOff))
	binary.LittleEndian.PutUint32(m.memory[iovOff+4:], 3)
	if rc := w.Fd_read(m, 0, iovOff, 1, nOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_read(0) rc=%d", rc)
	}
	if got := string(m.memory[bufOff : bufOff+3]); got != "abc" {
		t.Fatalf("read via redirected fd 0 = %q", got)
	}
	w.mu.Lock()
	cr := w.childReaderLocked(0)
	crDefault := w.childReaderLocked(-1)
	w.mu.Unlock()
	if cr == w.stdin {
		t.Fatal("childReaderLocked(0) ignored the redirection")
	}
	if crDefault != w.stdin {
		t.Fatal("childReaderLocked(-1) should be the interpreter stdin")
	}

	// An alias of stderr placed on another fd writes to the stream.
	var errBuf bytes.Buffer
	w.stderr = &errBuf
	const outOff int32 = 500
	if rc := w.Fd_dup(m, 2, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup(2) rc=%d", rc)
	}
	alias := int32(binary.LittleEndian.Uint32(m.memory[outOff:]))
	copy(m.memory[bufOff:], "E")
	binary.LittleEndian.PutUint32(m.memory[iovOff+4:], 1)
	if rc := w.Fd_write(m, alias, iovOff, 1, nOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write(alias) rc=%d", rc)
	}
	if errBuf.String() != "E" {
		t.Fatalf("stderr alias wrote %q", errBuf.String())
	}

	// lstat flavor of the mode import.
	pathOff := writeCStr(m, 1000, "f.txt")
	const modeOff int32 = 1100
	if rc := w.Path_filestat_mode(m, pathOff, 5, 0, modeOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_mode(lstat) rc=%d", rc)
	}
	if mode := binary.LittleEndian.Uint32(m.memory[modeOff:]); mode != 0o644 {
		t.Fatalf("lstat mode = %o, want 644", mode)
	}
}

func TestWasi_SockGetaddrinfoNumericAndHook(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	const outOff int32 = 100

	hostOff := writeCStr(m, 1000, "1.2.3.4")
	if rc := w.Sock_getaddrinfo(m, hostOff, 7, outOff); rc != _wasiESUCCESS {
		t.Fatalf("numeric getaddrinfo rc=%d", rc)
	}
	if got := m.memory[outOff : outOff+4]; got[0] != 1 || got[1] != 2 || got[2] != 3 || got[3] != 4 {
		t.Fatalf("resolved bytes = %v", got)
	}

	if rc := w.Sock_getaddrinfo(m, hostOff, 0, outOff); rc != _wasiESUCCESS {
		t.Fatalf("empty-host getaddrinfo rc=%d", rc)
	}

	w.SetResolveHook(func(host string) bool { return false })
	if rc := w.Sock_getaddrinfo(m, hostOff, 7, outOff); rc != -_wasiEACCES {
		t.Fatalf("denied getaddrinfo rc=%d, want -EACCES", rc)
	}
}
