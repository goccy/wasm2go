package codegen

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
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

// fd_dupfd is fcntl's F_DUPFD: the duplicate gets the lowest free number
// that is at least the one asked for, and a negative one is EINVAL.
func TestWasi_FdDupfdTakesTheLowestNumberFromMin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen(m, "f.txt", 0, 0, 1<<1 /* FD_READ */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	const outOff int32 = 100
	if rc := w.Fd_dupfd(m, fd, 20, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dupfd rc=%d", rc)
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[outOff:])); got != 20 {
		t.Fatalf("Fd_dupfd(min 20) = %d, want 20", got)
	}
	if rc := w.Fd_dupfd(m, fd, 20, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dupfd rc=%d", rc)
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[outOff:])); got != 21 {
		t.Fatalf("Fd_dupfd(min 20) with 20 taken = %d, want 21", got)
	}
	if rc := w.Fd_dupfd(m, fd, -1, outOff); rc != _wasiEINVAL {
		t.Fatalf("Fd_dupfd(min -1) rc=%d, want EINVAL", rc)
	}
	if rc := w.Fd_dupfd(m, 99, 0, outOff); rc != _wasiEBADF {
		t.Fatalf("Fd_dupfd of a closed number rc=%d, want EBADF", rc)
	}
	// The numbers of descriptors end below the root's second number.
	for _, min := range []int32{wasiRootFD, math.MaxInt32} {
		if rc := w.Fd_dupfd(m, fd, min, outOff); rc != _wasiEINVAL {
			t.Fatalf("Fd_dupfd(min %#x) rc=%d, want EINVAL", min, rc)
		}
	}
	if rc := w.Fd_dupfd(m, fd, wasiRootFD-1, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dupfd(the highest number) rc=%d", rc)
	}
	if got := int32(binary.LittleEndian.Uint32(m.memory[outOff:])); got != wasiRootFD-1 {
		t.Fatalf("Fd_dupfd(the highest number) = %#x, want %#x", got, wasiRootFD-1)
	}
	refs := slotRefs(t, w, fd)
	if rc := w.Fd_dupfd(m, fd, wasiRootFD-1, outOff); rc != _wasiEMFILE {
		t.Fatalf("Fd_dupfd with no number free rc=%d, want EMFILE", rc)
	}
	if got := slotRefs(t, w, fd); got != refs {
		t.Fatalf("the refused Fd_dupfd left %d slots, want %d", got, refs)
	}
	if ft := fdFiletype(t, w, m, wasiRootFD); ft != 3 {
		t.Fatalf("the root's number has filetype %d, want directory", ft)
	}
}

// fd_dup2 and fd_renumber take a descriptor number for the destination:
// not a negative one, and not the root's second number or one above it.
func TestWasi_Dup2AndRenumberRefuseNumbersThatAreNoDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	for _, to := range []int32{-1, math.MinInt32, wasiRootFD, math.MaxInt32} {
		if rc := w.Fd_dup2(m, 1, to); rc != _wasiEBADF {
			t.Errorf("Fd_dup2(1, %#x) rc=%d, want EBADF", to, rc)
		}
		if rc := w.Fd_dup264(m, 1, to); rc != _wasiEBADF {
			t.Errorf("Fd_dup264(1, %#x) rc=%d, want EBADF", to, rc)
		}
		if rc := w.Fd_renumber(m, 1, to); rc != _wasiEBADF {
			t.Errorf("Fd_renumber(1, %#x) rc=%d, want EBADF", to, rc)
		}
		if rc := w.Fd_renumber64(m, 1, int64(to)); rc != _wasiEBADF {
			t.Errorf("Fd_renumber64(1, %#x) rc=%d, want EBADF", to, rc)
		}
	}
	if len(w.fdTable) != 3 {
		t.Errorf("the table has %d entries after the refused calls, want 3", len(w.fdTable))
	}
	if rc := fdWriteString(w, m, 1, "x"); rc != _wasiESUCCESS {
		t.Errorf("write to fd 1 after the refused calls rc=%d", rc)
	}
	if rc := w.Fd_dup2(m, 1, wasiRootFD-1); rc != _wasiESUCCESS {
		t.Errorf("Fd_dup2 onto the highest number rc=%d", rc)
	}
}

func TestWasi_FdDupSharesOffsetAndDefersClose(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)

	fd, errno := w.pathOpen(m, "f.txt", 0, 0, 1<<1 /* FD_READ */, 0)
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
	w.cfg.Stdout = &out

	// Save fd 1 (an alias entry: closing it must not close the stream).
	const savedOff int32 = 100
	if rc := w.Fd_dup(m, 1, savedOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup(1) rc=%d", rc)
	}
	saved := int32(binary.LittleEndian.Uint32(m.memory[savedOff:]))

	// Point fd 1 at a real file.
	logFd, errno := w.pathOpen(m, "log.txt", 0, 0x1 /* O_CREAT */, 1<<6 /* FD_WRITE */, 0)
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
	cw := commandStreamValue(w.commandStreamLocked(1, 2))
	w.mu.Unlock()
	if _, isBuf := cw.(*bytes.Buffer); isBuf {
		t.Fatal("commandStreamLocked(1, 2) ignored the redirection")
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

	// Every backend changes modes; one that lacks the file says so.
	w.cfg.FS = NewMemFS()
	if rc := w.Path_chmod(m, pathOff, 5, 0o600); rc != -_wasiENOENT {
		t.Fatalf("MemFS Path_chmod of a missing file rc=%d, want -ENOENT", rc)
	}
}

func TestWasi_PollFdSubscriptionsPreemptTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen(m, "f.txt", 0, 0, 1<<1, 0)
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
	w.cfg.Stdin = bytes.NewReader(nil)

	if rc := w.Fd_dup(m, 99, 100); rc != _wasiEBADF {
		t.Fatalf("Fd_dup(bad) rc=%d, want EBADF", rc)
	}
	fd, errno := w.pathOpen(m, "f.txt", 0, 0, 1<<1, 0)
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
	// and commandStreamLocked follows the same redirection.
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
	cr := commandStreamValue(w.commandStreamLocked(0, 1))
	crDefault := commandStreamValue(w.commandStreamLocked(-1, 1))
	w.mu.Unlock()
	if cr == w.cfg.Stdin {
		t.Fatal("commandStreamLocked(0, 1) ignored the redirection")
	}
	if crDefault != w.cfg.Stdin {
		t.Fatal("commandStreamLocked(-1, 1) should be the interpreter stdin")
	}

	// An alias of stderr placed on another fd writes to the stream.
	var errBuf bytes.Buffer
	w.cfg.Stderr = &errBuf
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

	// An address written in numbers is no lookup: the policy is not asked.
	var asked []string
	w.cfg.Resolve = func(host string) bool { asked = append(asked, host); return false }
	if rc := w.Sock_getaddrinfo(m, hostOff, 7, outOff); rc != _wasiESUCCESS || len(asked) != 0 {
		t.Fatalf("numeric getaddrinfo under a refusing policy rc=%d, asked %q", rc, asked)
	}
	nameOff := writeCStr(m, 1000, "blocked.invalid")
	if rc := w.Sock_getaddrinfo(m, nameOff, 15, outOff); rc != -_wasiEACCES || !slices.Equal(asked, []string{"blocked.invalid"}) {
		t.Fatalf("denied getaddrinfo rc=%d, asked %q; want -EACCES", rc, asked)
	}
}

// fixedPID is the pid argument of ownDescriptorPath for the pid pid.
func fixedPID(pid int32) func() int32 { return func() int32 { return pid } }

// /dev/stdout, /dev/fd/N, /proc/self/fd/N and /proc/PID/fd/N for the
// opener's pid are the opener's own descriptors: what is written to the
// descriptor opened under such a name goes where the guest's descriptor
// goes (a stream of the embedder's), not to the host process's.
func TestWasi_OwnDescriptorNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int32
		ok   bool
	}{
		{"dev/stdin", 0, true}, {"dev/stdout", 1, true}, {"dev/stderr", 2, true},
		{"dev/fd/7", 7, true}, {"proc/self/fd/12", 12, true}, {"proc/4242/fd/5", 5, true},
		{"dev/fd/", 0, false}, {"dev/fd/x", 0, false}, {"dev/fd/7x", 0, false}, {"dev/fd/-1", 0, false}, {"dev/null", 0, false},
		{"proc/4243/fd/5", 0, false}, {"proc/4242/fd", 0, false},
		// a number no descriptor has is a name of the guest's own, of none
		{"dev/fd/07", -1, true}, {"dev/fd/00", -1, true}, {"dev/fd/0099999999999", -1, true},
		{"dev/fd/99999999999", -1, true}, {"proc/self/fd/01", -1, true}, {"proc/4242/fd/007", -1, true},
	} {
		if n, _, ok, _ := ownDescriptorPath(tc.name, fixedPID(4242)); n != tc.n || ok != tc.ok {
			t.Errorf("ownDescriptorPath(%q) = %d, %v; want %d, %v", tc.name, n, ok, tc.n, tc.ok)
		}
	}
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.cfg.Stdout = &out
	fd, errno := w.pathOpen(m, "dev/stdout", 1, 0, 1<<6 /* FD_WRITE */, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open dev/stdout errno=%d", errno)
	}
	iovOff, bufOff, nOff := int32(200), int32(300), int32(400)
	copy(m.memory[bufOff:], "through the name\n")
	binary.LittleEndian.PutUint32(m.memory[iovOff:], uint32(bufOff))
	binary.LittleEndian.PutUint32(m.memory[iovOff+4:], uint32(len("through the name\n")))
	if rc := w.Fd_write(m, fd, iovOff, 1, nOff); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if out.String() != "through the name\n" {
		t.Fatalf("the guest's standard output got %q", out.String())
	}
	if _, errno := w.pathOpen(m, "dev/fd/9", 0, 0, 1<<1, 0); errno != _wasiENOENT {
		t.Fatalf("open dev/fd/9 of a number that is not open: errno=%d, want ENOENT", errno)
	}
	// A number in a spelling no descriptor has does not reach the host,
	// whose /dev/fd may take it for a descriptor of the host process.
	for _, name := range []string{
		"dev/fd/01", "dev/fd/00", "dev/fd/07", "dev/fd/0099999999999", "dev/fd/99999999999",
		"proc/self/fd/01", "proc/42/fd/002", "dev/fd/01/",
	} {
		if _, errno := w.pathOpen(m, name, 0, 0, 1<<6 /* FD_WRITE */, 0); errno != _wasiENOENT {
			t.Errorf("open %s errno=%d, want ENOENT", name, errno)
		}
	}
}

// /dev/fd, /proc/self/fd and /proc/PID/fd for the guest's own pid list the
// guest's descriptors, that of the directory among them: not the host
// process's. Opened for writing, such a directory is a directory.
func TestWasi_OwnDescriptorListing(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	// Enough descriptors that a number of two digits sorts before one of
	// one digit by name.
	var files []int32
	for i := range 8 {
		files = append(files, createTestFile(t, w, strconv.Itoa(i)+".txt"))
	}
	pid := w.guestProcess().IDs().PID
	for _, dir := range []string{"dev/fd", "/proc/self/fd/", "proc/" + strconv.Itoa(int(pid)) + "/fd"} {
		fd, errno := w.pathOpen(m, dir, 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open %s errno=%d", dir, errno)
		}
		w.mu.Lock()
		op := w.openLocked(fd)
		w.mu.Unlock()
		entries, err := op.readDirCached(true)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
			if e.Name() != "." && e.Name() != ".." && e.Type() != os.ModeSymlink {
				t.Errorf("%s lists %s as %v, want a symbolic link", dir, e.Name(), e.Type())
			}
		}
		want := []string{".", "..", "0", "1", "2", "3"}
		for _, n := range slices.Sorted(slices.Values(append(slices.Clone(files), fd))) {
			want = append(want, strconv.Itoa(int(n)))
		}
		if strings.Join(names, " ") != strings.Join(want, " ") {
			t.Errorf("%s lists %q, want %q", dir, names, want)
		}
		closeTestFd(t, w, m, fd)
	}
	if _, errno := w.pathOpen(m, "dev/fd", 0, 0, 1<<6 /* FD_WRITE */, 0); errno != _wasiEISDIR {
		t.Fatalf("open dev/fd for writing errno=%d, want EISDIR", errno)
	}
}

// path_filestat_get, path_filestat_ext, path_filestat_mode and path_readlink
// resolve a name of the guest's own descriptors as path_open does: followed
// it is the descriptor, as fstat describes it; not followed it is a symbolic
// link to it, whose target is the path the descriptor was opened under.
func TestWasi_OwnDescriptorNamesDescribed(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	file := createTestFile(t, w, "a.txt") // open for writing only
	name := "dev/fd/" + strconv.Itoa(int(file))
	const nameOff, outOff, out2Off int32 = 0, 1024, 2048
	off, n := putPath(m, nameOff, name)

	if rc := w.Path_filestat_get(m, wasiPreopenFD, 1, off, n, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_get(%s, follow) rc=%d", name, rc)
	}
	if rc := w.Fd_filestat_get(m, file, out2Off); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_get rc=%d", rc)
	}
	if !bytes.Equal(m.memory[outOff:outOff+64], m.memory[out2Off:out2Off+64]) {
		t.Errorf("stat of %s is not fstat of the descriptor", name)
	}
	if rc := w.Path_filestat_get(m, wasiPreopenFD, 0, off, n, outOff); rc != _wasiESUCCESS || m.memory[outOff+16] != 7 {
		t.Errorf("lstat of %s rc=%d filetype=%d, want a symbolic link (7)", name, rc, m.memory[outOff+16])
	}

	if rc := w.Path_filestat_ext(m, off, n, 1, outOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_ext(%s, follow) rc=%d", name, rc)
	}
	if rc := w.Fd_filestat_ext(m, file, out2Off); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_ext rc=%d", rc)
	}
	if !bytes.Equal(m.memory[outOff:outOff+wasiFilestatExtSize], m.memory[out2Off:out2Off+wasiFilestatExtSize]) {
		t.Errorf("path_filestat_ext of %s is not fd_filestat_ext of the descriptor", name)
	}
	if rc := w.Path_filestat_ext(m, off, n, 0, outOff); rc != _wasiESUCCESS || readU32(m.memory, int(outOff)) != unixTypeSymlink|0o300 {
		t.Errorf("lstat ext of %s rc=%d mode=%o, want a write-only link (%o)", name, rc, readU32(m.memory, int(outOff)), unixTypeSymlink|0o300)
	}
	if rc := w.Path_filestat_mode(m, off, n, 1, outOff); rc != _wasiESUCCESS || readU32(m.memory, int(outOff)) != readU32(m.memory, int(out2Off))&0o7777 {
		t.Errorf("path_filestat_mode of %s rc=%d mode=%o, want the descriptor's %o", name, rc, readU32(m.memory, int(outOff)), readU32(m.memory, int(out2Off))&0o7777)
	}
	if rc := w.Path_filestat_mode(m, off, n, 0, outOff); rc != _wasiESUCCESS || readU32(m.memory, int(outOff)) != 0o300 {
		t.Errorf("path_filestat_mode of %s not followed rc=%d mode=%o, want 300", name, rc, readU32(m.memory, int(outOff)))
	}

	readlink := func(name string) (string, int32) {
		off, n := putPath(m, nameOff, name)
		rc := w.Path_readlink(m, wasiPreopenFD, off, n, outOff, 256, out2Off)
		return string(m.memory[outOff : outOff+int32(readU32(m.memory, int(out2Off)))]), rc
	}
	if target, rc := readlink(name); rc != _wasiESUCCESS || target != "/a.txt" {
		t.Errorf("readlink %s = %q rc=%d, want /a.txt", name, target, rc)
	}
	dir, errno := w.pathOpen(m, "proc/self/fd", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open proc/self/fd errno=%d", errno)
	}
	if target, rc := readlink("dev/fd/1"); rc != _wasiESUCCESS || !strings.HasPrefix(target, "pipe:[") {
		t.Errorf("readlink dev/fd/1 of a stream the embedder gave = %q rc=%d, want pipe:[N]", target, rc)
	}
	// /dev/stdin, /dev/stdout and /dev/stderr are links to /proc/self/fd/N.
	for n, name := range []string{"dev/stdin", "dev/stdout", "dev/stderr"} {
		if target, rc := readlink(name); rc != _wasiESUCCESS || target != "/proc/self/fd/"+strconv.Itoa(n) {
			t.Errorf("readlink %s = %q rc=%d, want /proc/self/fd/%d", name, target, rc, n)
		}
	}
	if target, rc := readlink("dev/fd/3"); rc != _wasiESUCCESS || target != "/" {
		t.Errorf("readlink of the preopened root = %q rc=%d, want /", target, rc)
	}
	for _, other := range []string{"proc/self/fd", "dev/fd/" + strconv.Itoa(int(dir)) + "/"} {
		binary.LittleEndian.PutUint32(m.memory[out2Off:], 0)
		if _, rc := readlink(other); rc != _wasiEINVAL {
			t.Errorf("readlink %s rc=%d, want EINVAL", other, rc)
		}
	}
	if _, rc := readlink(name + "/"); rc != _wasiENOTDIR {
		t.Errorf("readlink %s/ rc=%d, want ENOTDIR", name, rc)
	}
	if _, rc := readlink("dev/fd/99"); rc != _wasiENOENT {
		t.Errorf("readlink of a number that is not open rc=%d, want ENOENT", rc)
	}

	// The names are resolved without an FS.
	bare := NewWASI(WASIConfig{})
	off, n = putPath(m, nameOff, "dev/stdout")
	if rc := bare.Path_filestat_ext(m, off, n, 1, outOff); rc != _wasiESUCCESS {
		t.Errorf("path_filestat_ext of dev/stdout without an FS rc=%d", rc)
	}
	off, n = putPath(m, nameOff, "proc/self/fd")
	if rc := bare.Path_filestat_mode(m, off, n, 1, outOff); rc != _wasiESUCCESS || readU32(m.memory, int(outOff)) != 0o500 {
		t.Errorf("path_filestat_mode of proc/self/fd without an FS rc=%d mode=%o, want 500", rc, readU32(m.memory, int(outOff)))
	}
}

// A descriptor's own name is a link as on Linux: path_open without the
// follow flag is ELOOP and O_CREAT|O_EXCL is EEXIST; the preopened root is
// one of the descriptors; a link leads where Linux's does and its lstat
// agrees with readlink; the made-up records belong to the Process's
// effective ids and have inode numbers of their own.
func TestWasi_OwnDescriptorNamesAreLinks(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	stdin, err := os.Create(filepath.Join(dir, "in"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil {
			t.Error(err)
		}
	})
	w.cfg.Stdin = stdin
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 42, PPID: 1, EUID: 501, EGID: 20}}
	const write = int64(1 << 6)
	if _, errno := w.pathOpen(m, "dev/stdout", 0, 0, write, 0); errno != _wasiELOOP {
		t.Errorf("open dev/stdout without the follow flag errno=%d, want ELOOP", errno)
	}
	if _, errno := w.pathOpen(m, "dev/stdout", 1, 0x1|0x4 /* O_CREAT|O_EXCL */, write, 0); errno != _wasiEEXIST {
		t.Errorf("open dev/stdout O_CREAT|O_EXCL errno=%d, want EEXIST", errno)
	}
	if _, errno := w.pathOpen(m, "dev/stdout/", 0, 0, write, 0); errno != _wasiENOTDIR {
		t.Errorf("open dev/stdout/ errno=%d, want ENOTDIR: a name that goes on follows the link", errno)
	}

	// The preopened root.
	rootFd, errno := w.pathOpen(m, "dev/fd/3", 1, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open dev/fd/3 errno=%d", errno)
	}
	if filetype := fdFiletype(t, w, m, rootFd); filetype != 3 {
		t.Errorf("dev/fd/3 has filetype %d, want a directory (3)", filetype)
	}
	const nameOff, outOff, out2Off int32 = 0, 1024, 2048
	off, n := putPath(m, nameOff, "dev/fd/3")
	if rc := w.Path_filestat_get(m, wasiPreopenFD, 1, off, n, outOff); rc != _wasiESUCCESS {
		t.Fatalf("stat dev/fd/3 rc=%d", rc)
	}
	if rc := w.Fd_filestat_get(m, wasiPreopenFD, out2Off); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_get(3) rc=%d", rc)
	}
	if !bytes.Equal(m.memory[outOff:outOff+64], m.memory[out2Off:out2Off+64]) {
		t.Errorf("stat of dev/fd/3 is not fstat of the root")
	}

	readlink := func(name string) (string, int32) {
		off, n := putPath(m, nameOff, name)
		binary.LittleEndian.PutUint32(m.memory[out2Off:], 0)
		rc := w.Path_readlink(m, wasiPreopenFD, off, n, outOff, 256, out2Off)
		return string(m.memory[outOff : outOff+int32(readU32(m.memory, int(out2Off)))]), rc
	}
	lstat := func(name string) wasiFilestat {
		off, n := putPath(m, nameOff, name)
		if rc := w.Path_filestat_get(m, wasiPreopenFD, 0, off, n, outOff); rc != _wasiESUCCESS {
			t.Fatalf("lstat %s rc=%d", name, rc)
		}
		return decodeFilestat(m.memory[outOff:])
	}
	// A standard stream that is a regular host file has no link but the
	// host's, which only the whole host filesystem has the name of; its
	// /dev/stdin is a link to /proc/self/fd/0 all the same.
	{
		if _, rc := readlink("dev/fd/0"); rc != _wasiEINVAL {
			t.Errorf("readlink dev/fd/0 of a regular file rc=%d, want EINVAL: no link", rc)
		}
		if st := lstat("dev/fd/0"); st.filetype != 4 {
			t.Errorf("lstat dev/fd/0 has filetype %d, want the regular file (4)", st.filetype)
		}
		if st := lstat("dev/stdin"); st.filetype != 7 || st.size != uint64(len("/proc/self/fd/0")) {
			t.Errorf("lstat dev/stdin = type %d size %d, want a link to /proc/self/fd/0", st.filetype, st.size)
		}
		if _, errno := w.pathOpen(m, "dev/stdin", 0, 0, 1<<1, 0); errno != _wasiELOOP {
			t.Errorf("open dev/stdin without the follow flag errno=%d, want ELOOP", errno)
		}
		fd, errno := w.pathOpen(m, "dev/fd/0", 0, 0, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Errorf("open dev/fd/0 without the follow flag errno=%d: it is no link", errno)
		} else {
			closeTestFd(t, w, m, fd)
		}
		listed, errno := w.pathOpen(m, "dev/fd", 1, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open dev/fd errno=%d", errno)
		}
		w.mu.Lock()
		op := w.openLocked(listed)
		w.mu.Unlock()
		entries, err := op.readDirCached(true)
		if err != nil {
			t.Fatal(err)
		}
		if entries[2].Name() != "0" || entries[2].Type() != 0 {
			t.Errorf("dev/fd lists %s as %v, want 0 as the regular file", entries[2].Name(), entries[2].Type())
		}
		closeTestFd(t, w, m, listed)
	}
	if runtime.GOOS == "linux" {
		whole := NewWASI(WASIConfig{FS: osFS{}, Stdin: stdin})
		want, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(stdin.Fd())))
		if err != nil {
			t.Fatal(err)
		}
		off, n := putPath(m, nameOff, "dev/fd/0")
		binary.LittleEndian.PutUint32(m.memory[out2Off:], 0)
		rc := whole.Path_readlink(m, wasiPreopenFD, off, n, outOff, 256, out2Off)
		if target := string(m.memory[outOff : outOff+int32(readU32(m.memory, int(out2Off)))]); rc != _wasiESUCCESS || target != want {
			t.Errorf("readlink dev/fd/0 on the whole host filesystem = %q rc=%d, want the host's %q", target, rc, want)
		}
		if _, errno := whole.pathOpen(m, "dev/fd/0", 0, 0, 1<<1, 0); errno != _wasiELOOP {
			t.Errorf("open dev/fd/0 without the follow flag errno=%d, want ELOOP", errno)
		}
	}
	readFd, _ := newTestPipe(t, w, m)
	if rc := w.Fd_filestat_get(m, readFd, out2Off); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_get(pipe) rc=%d", rc)
	}
	pipeIno := decodeFilestat(m.memory[out2Off:]).ino
	pipeName := "dev/fd/" + strconv.Itoa(int(readFd))
	target, rc := readlink(pipeName)
	if want := "pipe:[" + strconv.FormatUint(pipeIno, 10) + "]"; rc != _wasiESUCCESS || target != want {
		t.Errorf("readlink of a pipe = %q rc=%d, want %q", target, rc, want)
	}
	if st := lstat(pipeName); st.filetype != 7 || st.size != uint64(len(target)) {
		t.Errorf("lstat of %s = type %d size %d, want a link of size %d", pipeName, st.filetype, st.size, len(target))
	}

	ext := func(name string) (uid, gid uint32) {
		off, n := putPath(m, nameOff, name)
		if rc := w.Path_filestat_ext(m, off, n, 0, outOff); rc != _wasiESUCCESS {
			t.Fatalf("Path_filestat_ext(%s) rc=%d", name, rc)
		}
		return readU32(m.memory, int(outOff)+4), readU32(m.memory, int(outOff)+8)
	}
	for _, name := range []string{"dev/fd/1", "proc/self/fd"} {
		if uid, gid := ext(name); uid != 501 || gid != 20 {
			t.Errorf("%s belongs to %d:%d, want the Process's effective 501:20", name, uid, gid)
		}
	}
	inos := map[uint64]string{}
	for _, name := range []string{"dev/fd/0", "dev/fd/1", "dev/fd/3", "proc/self/fd"} {
		ino := lstat(name).ino
		if other, seen := inos[ino]; seen {
			t.Errorf("%s and %s have one inode number, %d", name, other, ino)
		}
		inos[ino] = name
	}
}

// The preopened root under its own-descriptor name is opened as the root
// of the FS, and a standard stream that is a closed host file is no
// descriptor: EBADF, and no entry in a listing.
func TestWasi_OwnDescriptorNamesOfTheRootAndAClosedStream(t *testing.T) {
	for _, whole := range []bool{false, true} {
		dir := t.TempDir()
		w, m := newTestStubs(t, dir)
		if whole {
			w.cfg.FS = osFS{}
		}
		fd, errno := w.pathOpen(m, "dev/fd/3", 1, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open dev/fd/3 errno=%d", errno)
		}
		closeTestFd(t, w, m, fd)

		stdin, err := os.Create(filepath.Join(dir, "in"))
		if err != nil {
			t.Fatal(err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatal(err)
		}
		w.cfg.Stdin = stdin
		off, n := putPath(m, 0, "dev/stdin")
		if rc := w.Path_filestat_get(m, wasiPreopenFD, 1, off, n, 1024); rc != _wasiEBADF {
			t.Errorf("whole=%v: stat dev/stdin of a closed file rc=%d, want EBADF", whole, rc)
		}
		off, n = putPath(m, 0, "dev/fd/0")
		if rc := w.Path_readlink(m, wasiPreopenFD, off, n, 1024, 256, 2048); rc != _wasiEBADF {
			t.Errorf("whole=%v: readlink dev/fd/0 of a closed file rc=%d, want EBADF", whole, rc)
		}
		listed, errno := w.pathOpen(m, "dev/fd", 1, 0x2, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("whole=%v: open dev/fd errno=%d", whole, errno)
		}
		w.mu.Lock()
		op := w.openLocked(listed)
		w.mu.Unlock()
		entries, err := op.readDirCached(true)
		if err != nil {
			t.Fatal(err)
		}
		if entries[2].Name() == "0" {
			t.Errorf("whole=%v: dev/fd lists the closed stdin", whole)
		}
	}
}

// A name of the guest's own descriptors is its own in any spelling: with
// repeated slashes, "." and ".." elements it does not reach the host's file
// of that name.
func TestWasi_OwnDescriptorNamesInAnySpelling(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	own := func(name string) (int32, string, bool, string) {
		t.Helper()
		clean, errno := w.guestName(name)
		if errno != _wasiESUCCESS {
			t.Fatalf("guestName(%.40q) errno=%d", name, errno)
		}
		return ownDescriptorPath(clean, w.guestPID)
	}
	for _, tc := range []struct {
		name string
		n    int32
	}{
		{"dev//fd/5", 5}, {"dev/./stdout", 1}, {"//dev/stderr", 2}, {"../dev/fd/7", 7}, {"./../.././dev/stdin", 0},
		// ".." of a listing directory takes it back
		{"proc/self/fd/../fd/1", 1},
	} {
		if n, rest, ok, _ := own(tc.name); n != tc.n || rest != "" || !ok {
			t.Errorf("ownDescriptorPath(%q) = %d, %q, %v; want %d, \"\", true", tc.name, n, rest, ok, tc.n)
		}
	}
	for name, want := range map[string]string{
		"dev//fd": "dev/fd", "dev/./fd/": "dev/fd", "../proc/self/fd": "proc/self/fd", "proc/42/fd/.": "proc/42/fd",
		"proc/self/fd/../fd": "proc/self/fd",
	} {
		if _, _, named, dir := own(name); named || dir != want {
			t.Errorf("ownDescriptorPath(%q) = %v, %q; want the directory %q", name, named, dir, want)
		}
	}
	// Any other name is neither, however deep it is and whatever it has
	// of such a name further in.
	deep := strings.Repeat("d/", 1000)
	for _, name := range []string{
		"", ".", "dev", "proc", "dev/fd/..", "dev/null", "proc/43/fd", "proc/self/fdx", "proc/self/fd/x",
		"a/dev/fd/5", "usr/dev/stdout", "home/proc/self/fd", "dev/fd0", "dev/stdoutx",
		deep + "dev/fd/5", deep + "proc/self/fd", deep + "file.txt",
	} {
		if n, rest, named, dir := own(name); named || dir != "" {
			t.Errorf("ownDescriptorPath(%.40q) = %d, %q, %v, %q; want none", name, n, rest, named, dir)
		}
	}
	// A ".." after a name the FS does not have fails.
	for _, name := range []string{"a/../dev/stdout", "dev/fd/../../dev/stdin"} {
		if _, errno := w.guestName(name); errno != _wasiENOENT {
			t.Errorf("guestName(%q) errno=%d, want ENOENT", name, errno)
		}
	}

	var out bytes.Buffer
	w.cfg.Stdout = &out
	for _, name := range []string{"dev//fd/1", "dev/./stdout", "../proc/self/fd/1"} {
		fd, errno := w.pathOpen(m, name, 1, 0, 1<<6 /* FD_WRITE */, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open %s errno=%d", name, errno)
		}
		if rc := fdWriteString(w, m, fd, name+"\n"); rc != _wasiESUCCESS {
			t.Fatalf("write to %s rc=%d", name, rc)
		}
	}
	if want := "dev//fd/1\ndev/./stdout\n../proc/self/fd/1\n"; out.String() != want {
		t.Fatalf("the guest's standard output got %q, want %q", out.String(), want)
	}
	fd, errno := w.pathOpen(m, "dev//fd/", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open dev//fd/ errno=%d", errno)
	}
	if filetype := fdFiletype(t, w, m, fd); filetype != 3 {
		t.Fatalf("dev//fd/ has filetype %d, want a directory (3)", filetype)
	}
	w.mu.Lock()
	listed := w.openLocked(fd).path
	w.mu.Unlock()
	if listed != "dev/fd" {
		t.Fatalf("the directory opened as dev//fd/ is recorded as %q, want dev/fd", listed)
	}
}

// A name that goes on after the name of one of the guest's own descriptors
// is a path from that descriptor: no such thing for a stream or a file
// (ENOTDIR), and for a directory the directory itself ("/", "/."); a name
// from the directory is not resolved (ENOTSUP).
func TestWasi_OwnDescriptorNamesThatGoOn(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "d/a.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w, m := newTestStubs(t, dir)
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	const read, write = int64(1 << 1), int64(1 << 6)
	file, errno := w.pathOpen(m, "a.txt", 0, 0, read, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open a.txt errno=%d", errno)
	}
	dirFd, errno := w.pathOpen(m, "d", 0, 0x2 /* O_DIRECTORY */, read, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open d errno=%d", errno)
	}
	fileName, dirName := "dev/fd/"+strconv.Itoa(int(file)), "dev/fd/"+strconv.Itoa(int(dirFd))
	for _, tc := range []struct {
		name   string
		rights int64
	}{
		{"dev/stdout/", write}, {"dev/fd/1/.", write}, {"dev/fd/1/../2", write}, {"dev/stdin/..", read},
		{fileName + "/", read}, {fileName + "/.", read}, {fileName + "/../0", read}, {"../proc/self/fd/" + strconv.Itoa(int(file)) + "/x", read},
	} {
		if _, errno := w.pathOpen(m, tc.name, 1, 0, tc.rights, 0); errno != _wasiENOTDIR {
			t.Errorf("open %s errno=%d, want ENOTDIR", tc.name, errno)
		}
	}
	for _, name := range []string{dirName + "/", dirName + "/.", "dev//fd/" + strconv.Itoa(int(dirFd)) + "//./"} {
		fd, errno := w.pathOpen(m, name, 0, 0, read, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open %s errno=%d", name, errno)
		}
		if filetype := fdFiletype(t, w, m, fd); filetype != 3 {
			t.Errorf("%s has filetype %d, want a directory (3)", name, filetype)
		}
	}
	for _, name := range []string{
		dirName + "/a.txt", dirName + "/../a.txt", dirName + "/../" + fileName, dirName + "/..", dirName + "/missing",
	} {
		if _, errno := w.pathOpen(m, name, 0, 0, read, 0); errno != _wasiENOTSUP {
			t.Errorf("open %s errno=%d, want ENOTSUP", name, errno)
		}
	}
}

// A descriptor opened under a name of the guest's own descriptors shares
// the open file, so it is opened for the access that one has and no other,
// and O_DIRECTORY takes a directory.
func TestWasi_OwnDescriptorNamesKeepTheAccessMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, _ := newTestStubs(t, dir)
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	const read, write = int64(1 << 1), int64(1 << 6)
	writeOnly := createTestFile(t, w, "a.txt")
	readOnly, errno := w.pathOpen(nil, "a.txt", 0, 0, read, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open a.txt for reading errno=%d", errno)
	}
	both, errno := w.pathOpen(nil, "a.txt", 0, 0, read|write, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open a.txt errno=%d", errno)
	}
	dirFd, errno := w.pathOpen(nil, "d", 0, 0x2 /* O_DIRECTORY */, read, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open d errno=%d", errno)
	}
	name := func(fd int32) string { return "dev/fd/" + strconv.Itoa(int(fd)) }
	for _, tc := range []struct {
		name   string
		oflags int32
		rights int64
		want   int32
	}{
		{"dev/stdin", 0, read, _wasiESUCCESS},
		{"dev/stdin", 0, 0, _wasiESUCCESS}, // no rights: an open for reading
		{"dev/stdin", 0, write, _wasiEACCES},
		{"dev/stdin", 0, read | write, _wasiEACCES},
		{"dev/stdout", 0, write, _wasiESUCCESS},
		{"dev/stdout", 0, read, _wasiEACCES},
		{"dev/stderr", 0, 0, _wasiEACCES},
		{name(readOnly), 0, read, _wasiESUCCESS},
		{name(readOnly), 0, write, _wasiEACCES},
		{name(writeOnly), 0, write, _wasiESUCCESS},
		{name(writeOnly), 0, read, _wasiEACCES},
		{name(writeOnly), 0, read | write, _wasiEACCES},
		{name(both), 0, read, _wasiESUCCESS},
		{name(both), 0, write, _wasiESUCCESS},
		{name(both), 0, read | write, _wasiESUCCESS},
		{name(both), 0x2 /* O_DIRECTORY */, read, _wasiENOTDIR},
		{"dev/stdout", 0x2, write, _wasiENOTDIR},
		{name(dirFd), 0x2, read, _wasiESUCCESS},
		{name(dirFd), 0, read, _wasiESUCCESS},
		{name(dirFd), 0, write, _wasiEACCES},
	} {
		if _, errno := w.pathOpen(nil, tc.name, 1, tc.oflags, tc.rights, 0); errno != tc.want {
			t.Errorf("open %s (oflags %#x, rights %#x) errno=%d, want %d", tc.name, tc.oflags, tc.rights, errno, tc.want)
		}
	}
}

// BenchmarkOwnDescriptorPath measures what the look for a name of the
// guest's own descriptors costs an open of an ordinary path.
func BenchmarkOwnDescriptorPath(b *testing.B) {
	name := "usr/local/lib/site/vendor/package/module/dev/tools/file.txt"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, named, dir := ownDescriptorPath(name, fixedPID(42)); named || dir != "" {
			b.Fatalf("%s names a descriptor of the guest's own", name)
		}
	}
}
