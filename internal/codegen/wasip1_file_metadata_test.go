package codegen

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Guest memory offsets the tests in this file use for paths and results.
const (
	metaPathOff  int32 = 0
	metaPath2Off int32 = 512
	metaOutOff   int32 = 1024
)

// skipWithoutPOSIXFiles skips a test of file owners, link counts, modes or
// locks on a platform whose host filesystem backend does not provide them.
func skipWithoutPOSIXFiles(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("the host filesystem backend has no POSIX file metadata on %s", runtime.GOOS)
	}
}

// wasiFilestat is the decoded WASI filestat structure.
type wasiFilestat struct {
	dev, ino, nlink, size uint64
	filetype              byte
	atim, mtim, ctim      uint64
}

func decodeFilestat(b []byte) wasiFilestat {
	return wasiFilestat{
		dev:      binary.LittleEndian.Uint64(b[0:]),
		ino:      binary.LittleEndian.Uint64(b[8:]),
		filetype: b[16],
		nlink:    binary.LittleEndian.Uint64(b[24:]),
		size:     binary.LittleEndian.Uint64(b[32:]),
		atim:     binary.LittleEndian.Uint64(b[40:]),
		mtim:     binary.LittleEndian.Uint64(b[48:]),
		ctim:     binary.LittleEndian.Uint64(b[56:]),
	}
}

// pathFilestat returns what Path_filestat_get reports for name.
func pathFilestat(t *testing.T, w *WasiStubs, m *Module, name string, follow bool) wasiFilestat {
	t.Helper()
	off, n := putPath(m, metaPathOff, name)
	var flags int32
	if follow {
		flags = 0x1
	}
	if rc := w.Path_filestat_get(m, 3, flags, off, n, metaOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_get(%s) rc=%d", name, rc)
	}
	return decodeFilestat(m.memory[metaOutOff:])
}

// fdFilestat returns what Fd_filestat_get reports for fd.
func fdFilestat(t *testing.T, w *WasiStubs, m *Module, fd int32) wasiFilestat {
	t.Helper()
	if rc := w.Fd_filestat_get(m, fd, metaOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_get(%d) rc=%d", fd, rc)
	}
	return decodeFilestat(m.memory[metaOutOff:])
}

// filestatExt is what Path_filestat_ext and Fd_filestat_ext report.
type filestatExt struct{ mode, uid, gid uint32 }

func pathFilestatExt(t *testing.T, w *WasiStubs, m *Module, name string) filestatExt {
	t.Helper()
	off, n := putPath(m, metaPathOff, name)
	if rc := w.Path_filestat_ext(m, off, n, 1, metaOutOff); rc != 0 {
		t.Fatalf("Path_filestat_ext(%s) rc=%d", name, rc)
	}
	return filestatExt{readU32(m.memory, int(metaOutOff)), readU32(m.memory, int(metaOutOff)+4), readU32(m.memory, int(metaOutOff)+8)}
}

func fdFilestatExt(t *testing.T, w *WasiStubs, m *Module, fd int32) filestatExt {
	t.Helper()
	if rc := w.Fd_filestat_ext(m, fd, metaOutOff); rc != 0 {
		t.Fatalf("Fd_filestat_ext(%d) rc=%d", fd, rc)
	}
	return filestatExt{readU32(m.memory, int(metaOutOff)), readU32(m.memory, int(metaOutOff)+4), readU32(m.memory, int(metaOutOff)+8)}
}

// openTestFile opens an existing file for reading and writing and returns
// the new fd: a separate open file description on every call.
func openTestFile(t *testing.T, w *WasiStubs, name string) int32 {
	t.Helper()
	fd, errno := w.pathOpen(name, 0x1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen(%s) errno=%d", name, errno)
	}
	return fd
}

// memTestStubs returns stubs whose filesystem is a fresh MemFS.
func memTestStubs(t *testing.T) (*WasiStubs, *Module, *MemFS) {
	t.Helper()
	w, m := newTestStubs(t, "/")
	fsys := NewMemFS()
	w.SetFS(fsys)
	return w, m, fsys
}

func TestWasi_FilestatReportsLinksAndIdentity(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	one := pathFilestat(t, w, m, "a", true)
	if one.nlink != 1 || one.ino == 0 || one.dev == 0 {
		t.Fatalf("single file: nlink=%d ino=%d dev=%d, want nlink 1 and a real dev/ino", one.nlink, one.ino, one.dev)
	}
	if other := pathFilestat(t, w, m, "other", true); other.ino == one.ino {
		t.Fatalf("two files share inode %d", one.ino)
	}

	oldOff, oldLen := putPath(m, metaPathOff, "a")
	newOff, newLen := putPath(m, metaPath2Off, "b")
	if rc := w.Path_link(m, 3, 0, oldOff, oldLen, 3, newOff, newLen); rc != _wasiESUCCESS {
		t.Fatalf("Path_link rc=%d", rc)
	}
	a, b := pathFilestat(t, w, m, "a", true), pathFilestat(t, w, m, "b", false)
	if a.nlink != 2 || b.nlink != 2 {
		t.Fatalf("after link: nlink a=%d b=%d, want 2 and 2", a.nlink, b.nlink)
	}
	if a.ino != b.ino || a.dev != b.dev {
		t.Fatalf("hard links differ: a=%d/%d b=%d/%d", a.dev, a.ino, b.dev, b.ino)
	}

	// An open file reports the same file as its name does, and keeps
	// reporting it while the names go away.
	fd := openTestFile(t, w, "a")
	if got := fdFilestat(t, w, m, fd); got != a {
		t.Fatalf("fd stat %+v differs from path stat %+v", got, a)
	}
	for _, name := range []string{"a", "b"} {
		off, n := putPath(m, metaPathOff, name)
		if rc := w.Path_unlink_file(m, 3, off, n); rc != _wasiESUCCESS {
			t.Fatalf("unlink %s rc=%d", name, rc)
		}
	}
	if got := fdFilestat(t, w, m, fd); got.nlink != 0 || got.ino != a.ino {
		t.Fatalf("unlinked open file: nlink=%d ino=%d, want 0 and %d", got.nlink, got.ino, a.ino)
	}
}

func TestWasi_FilestatReportsAccessAndChangeTimes(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	atime, mtime := time.Unix(1_000_000, 0), time.Unix(2_000_000, 0)
	off, n := putPath(m, metaPathOff, "f")
	if rc := w.Path_filestat_set_times(m, 3, 0x1, off, n, atime.UnixNano(), mtime.UnixNano(), 0x1|0x4); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_set_times rc=%d", rc)
	}
	st := pathFilestat(t, w, m, "f", true)
	if st.atim != uint64(atime.UnixNano()) || st.mtim != uint64(mtime.UnixNano()) {
		t.Fatalf("atim=%d mtim=%d, want %d and %d", st.atim, st.mtim, atime.UnixNano(), mtime.UnixNano())
	}
	// The status change time is when the times were set, not either of them.
	if ctime := time.Unix(0, int64(st.ctim)); ctime.Before(created.Add(-time.Minute)) {
		t.Fatalf("ctim=%v, want about %v", ctime, created)
	}

	// Setting one time leaves the other alone, through a path and an fd.
	later := time.Unix(3_000_000, 0)
	if rc := w.Path_filestat_set_times(m, 3, 0x1, off, n, 0, later.UnixNano(), 0x4); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_set_times (mtime only) rc=%d", rc)
	}
	if st := pathFilestat(t, w, m, "f", true); st.atim != uint64(atime.UnixNano()) || st.mtim != uint64(later.UnixNano()) {
		t.Fatalf("mtime only: atim=%d mtim=%d", st.atim, st.mtim)
	}
	fd := openTestFile(t, w, "f")
	earlier := time.Unix(500_000, 0)
	if rc := w.Fd_filestat_set_times(m, fd, earlier.UnixNano(), 0, 0x1); rc != _wasiESUCCESS {
		t.Fatalf("Fd_filestat_set_times (atime only) rc=%d", rc)
	}
	if st := fdFilestat(t, w, m, fd); st.atim != uint64(earlier.UnixNano()) || st.mtim != uint64(later.UnixNano()) {
		t.Fatalf("atime only: atim=%d mtim=%d", st.atim, st.mtim)
	}
}

func TestWasi_FilestatExtReportsModeAndOwner(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	hostInfo, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	hostStat, ok := osFileStat(hostInfo.Sys())
	if !ok {
		t.Fatal("the host stat result carries no POSIX metadata")
	}
	want := filestatExt{mode: 0o1640, uid: uint32(os.Getuid()), gid: hostStat.gid}
	if got := pathFilestatExt(t, w, m, "f"); got != want {
		t.Fatalf("path: %+v, want %+v", got, want)
	}
	fd := openTestFile(t, w, "f")
	if got := fdFilestatExt(t, w, m, fd); got != want {
		t.Fatalf("fd: %+v, want %+v", got, want)
	}

	// A descriptor that is not a file of the backend has nothing to report.
	if rc := w.Fd_filestat_ext(m, 1, metaOutOff); rc != -_wasiEINVAL {
		t.Errorf("stdout rc=%d, want -EINVAL", rc)
	}
	if rc := w.Fd_filestat_ext(m, 99, metaOutOff); rc != -_wasiEBADF {
		t.Errorf("closed fd rc=%d, want -EBADF", rc)
	}
}

func TestWasi_ChmodByPathAndDescriptor(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	off, n := putPath(m, metaPathOff, "f")
	if rc := w.Path_chmod(m, off, n, 0o1750); rc != 0 {
		t.Fatalf("Path_chmod rc=%d", rc)
	}
	if got := pathFilestatExt(t, w, m, "f").mode; got != 0o1750 {
		t.Fatalf("mode after Path_chmod = %o, want 1750", got)
	}
	fd := openTestFile(t, w, "f")
	if rc := w.Fd_chmod(m, fd, 0o600); rc != 0 {
		t.Fatalf("Fd_chmod rc=%d", rc)
	}
	if got := pathFilestatExt(t, w, m, "f").mode; got != 0o600 {
		t.Fatalf("mode after Fd_chmod = %o, want 600", got)
	}
	if rc := w.Fd_chmod(m, 99, 0o600); rc != -_wasiEBADF {
		t.Errorf("Fd_chmod on a closed fd rc=%d, want -EBADF", rc)
	}
}

// createWithMode creates name through Path_open_mode and returns its mode.
func createWithMode(t *testing.T, w *WasiStubs, m *Module, name string, mode int32) uint32 {
	t.Helper()
	off, n := putPath(m, metaPathOff, name)
	if rc := w.Path_open_mode(m, 0x1, off, n, 0x1 /* O_CREAT */, 1<<6 /* FD_WRITE */, 0, mode, metaOutOff); rc != 0 {
		t.Fatalf("Path_open_mode(%s, %o) rc=%d", name, mode, rc)
	}
	closeTestFd(t, w, m, int32(readU32(m.memory, int(metaOutOff))))
	return pathFilestatExt(t, w, m, name).mode
}

// mkdirWithMode creates name through Path_create_directory_mode and returns
// its mode.
func mkdirWithMode(t *testing.T, w *WasiStubs, m *Module, name string, mode int32) uint32 {
	t.Helper()
	off, n := putPath(m, metaPathOff, name)
	if rc := w.Path_create_directory_mode(m, off, n, mode); rc != 0 {
		t.Fatalf("Path_create_directory_mode(%s, %o) rc=%d", name, mode, rc)
	}
	return pathFilestatExt(t, w, m, name).mode
}

// exerciseCreationModes creates files and directories under several umasks
// and requires every one to end up with its requested mode less the umask.
func exerciseCreationModes(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	// Until the guest sets a umask, the host process's applies.
	if got, want := createWithMode(t, w, m, "inherited", 0o666), uint32(0o666&^processUmask); got != want {
		t.Errorf("file under the process umask: %o, want %o", got, want)
	}
	if prev := w.Proc_umask(m, 0o027); os.FileMode(prev) != processUmask {
		t.Errorf("first umask returned %o, want the process umask %o", prev, processUmask)
	}
	if prev := w.Proc_umask(m, 0o027); prev != 0o027 {
		t.Errorf("second umask returned %o, want 027", prev)
	}
	if got := createWithMode(t, w, m, "f640", 0o666); got != 0o640 {
		t.Errorf("file 0666 under umask 027: %o, want 640", got)
	}
	if got := createWithMode(t, w, m, "f600", 0o600); got != 0o600 {
		t.Errorf("file 0600 under umask 027: %o, want 600", got)
	}
	if got := mkdirWithMode(t, w, m, "d750", 0o777); got != 0o750 {
		t.Errorf("directory 0777 under umask 027: %o, want 750", got)
	}
	if got := mkdirWithMode(t, w, m, "d700", 0o700); got != 0o700 {
		t.Errorf("directory 0700 under umask 027: %o, want 700", got)
	}

	// path_open and path_create_directory carry no mode: they create with
	// the conventional 0666 and 0777, less the umask.
	closeTestFd(t, w, m, createTestFile(t, w, "plain"))
	if got := pathFilestatExt(t, w, m, "plain").mode; got != 0o640 {
		t.Errorf("path_open under umask 027: %o, want 640", got)
	}
	off, n := putPath(m, metaPathOff, "plaindir")
	if rc := w.Path_create_directory(m, 3, off, n); rc != _wasiESUCCESS {
		t.Fatalf("Path_create_directory rc=%d", rc)
	}
	if got := pathFilestatExt(t, w, m, "plaindir").mode; got != 0o750 {
		t.Errorf("path_create_directory under umask 027: %o, want 750", got)
	}

	// A guest umask looser than the host process's still gets the modes it
	// asks for.
	w.Proc_umask(m, 0)
	if got := createWithMode(t, w, m, "f666", 0o666); got != 0o666 {
		t.Errorf("file 0666 under umask 0: %o, want 666", got)
	}
	if got := mkdirWithMode(t, w, m, "d777", 0o777); got != 0o777 {
		t.Errorf("directory 0777 under umask 0: %o, want 777", got)
	}
	// Opening an existing file with O_CREAT leaves its mode alone.
	if got := createWithMode(t, w, m, "f600", 0o666); got != 0o600 {
		t.Errorf("existing file reopened with O_CREAT: %o, want it kept at 600", got)
	}

	// A forked instance starts with its parent's umask and then has its own.
	w.Proc_umask(m, 0o077)
	child := w.Fork()
	t.Cleanup(func() { child.CloseAll() })
	cm := newForkTestModule()
	if prev := child.Proc_umask(cm, 0o022); prev != 0o077 {
		t.Errorf("child's inherited umask = %o, want 077", prev)
	}
	if prev := w.Proc_umask(m, 0o077); prev != 0o077 {
		t.Errorf("parent's umask after the child changed its own = %o, want 077", prev)
	}
}

func TestWasi_CreationModeAppliesUmask(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	w, m := newProcTestStubs(t)
	exerciseCreationModes(t, w, m)
}

func TestWasi_CreationModeAppliesUmaskOnMemFS(t *testing.T) {
	w, m, _ := memTestStubs(t)
	exerciseCreationModes(t, w, m)
}

func TestWasi_CreateThroughDanglingSymlinkUnderLooseUmask(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	if processUmask == 0 {
		t.Skip("the process umask takes no bits out of a mode")
	}
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	w.Proc_umask(m, 0)
	off, n := putPath(m, metaPathOff, "link")
	if rc := w.Path_open_mode(m, 0x1, off, n, 0x1, 1<<6, 0, 0o666, metaOutOff); rc != 0 {
		t.Fatalf("Path_open_mode through a dangling symlink rc=%d", rc)
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); err != nil {
		t.Fatalf("the link's target was not created: %v", err)
	}
}

// flockRC applies a lock to fd without waiting and returns the import's
// result code.
func flockRC(w *WasiStubs, m *Module, fd int32, lock FileLock) int32 {
	return w.Fd_flock(m, fd, int32(lock), 0)
}

// exerciseFlock drives the flock semantics every backend has to provide,
// on stubs that already contain the file "lock".
func exerciseFlock(t *testing.T, w *WasiStubs, m *Module) {
	t.Helper()
	first := openTestFile(t, w, "lock")
	second := openTestFile(t, w, "lock")
	shared := dupTestFd(t, w, m, first)

	if rc := flockRC(w, m, first, FileLockShared); rc != 0 {
		t.Fatalf("shared lock rc=%d", rc)
	}
	// Another open of the file may share it but not take it exclusively.
	if rc := flockRC(w, m, second, FileLockShared); rc != 0 {
		t.Fatalf("second shared lock rc=%d", rc)
	}
	if rc := flockRC(w, m, second, FileLockExclusive); rc != -_wasiEAGAIN {
		t.Fatalf("exclusive lock while another open holds a shared one: rc=%d, want -EAGAIN", rc)
	}
	if rc := flockRC(w, m, second, FileUnlock); rc != 0 {
		t.Fatalf("unlock rc=%d", rc)
	}

	// A descriptor that shares the open file shares its lock: it can
	// convert it, and nobody else gets in.
	if rc := flockRC(w, m, shared, FileLockExclusive); rc != 0 {
		t.Fatalf("exclusive lock through a dup of the holder rc=%d", rc)
	}
	if rc := flockRC(w, m, second, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("shared lock while another open holds an exclusive one: rc=%d, want -EAGAIN", rc)
	}

	// So does the descriptor of a forked instance, while a file the fork
	// opens itself competes like any other.
	child := w.Fork()
	t.Cleanup(func() { child.CloseAll() })
	cm := newForkTestModule()
	if rc := flockRC(child, cm, first, FileLockExclusive); rc != 0 {
		t.Fatalf("exclusive lock through the fork's copy of the holder rc=%d", rc)
	}
	own := openTestFile(t, child, "lock")
	if rc := flockRC(child, cm, own, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("lock through the fork's own open: rc=%d, want -EAGAIN", rc)
	}

	// A waiting lock is granted when the holder unlocks, through any of
	// the descriptors that share the lock.
	granted := make(chan int32, 1)
	go func() { granted <- w.Fd_flock(newForkTestModule(), second, int32(FileLockExclusive), 1) }()
	select {
	case rc := <-granted:
		t.Fatalf("waiting lock returned %d while the lock was held", rc)
	case <-time.After(50 * time.Millisecond):
	}
	if rc := flockRC(child, cm, first, FileUnlock); rc != 0 {
		t.Fatalf("unlock through the fork rc=%d", rc)
	}
	select {
	case rc := <-granted:
		if rc != 0 {
			t.Fatalf("waiting lock rc=%d", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting lock was not granted after the unlock")
	}
	if rc := flockRC(w, m, first, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("former holder re-locking against the new one: rc=%d, want -EAGAIN", rc)
	}

	// Closing the last descriptor of an open file releases its lock;
	// closing one of several does not, wherever the others are.
	third := dupTestFd(t, w, m, second)
	closeTestFd(t, w, m, second)
	if rc := flockRC(w, m, first, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("lock after closing one of two descriptors of the holder: rc=%d, want -EAGAIN", rc)
	}
	closeTestFd(t, w, m, third)
	if rc := flockRC(w, m, first, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("lock while the fork still has a descriptor of the holder: rc=%d, want -EAGAIN", rc)
	}
	closeTestFd(t, child, cm, second)
	if rc := flockRC(w, m, first, FileLockExclusive); rc != 0 {
		t.Fatalf("lock after the holder was closed rc=%d", rc)
	}

	if rc := flockRC(w, m, 99, FileLockShared); rc != -_wasiEBADF {
		t.Errorf("lock on a closed fd rc=%d, want -EBADF", rc)
	}
	if rc := w.Fd_flock(m, first, 7, 0); rc != -_wasiEINVAL {
		t.Errorf("unknown lock kind rc=%d, want -EINVAL", rc)
	}
}

func TestWasi_FlockExcludesOtherOpens(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	w, m := newProcTestStubs(t)
	if err := os.WriteFile(filepath.Join(w.preopenDir, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	exerciseFlock(t, w, m)
}

func TestWasi_FlockExcludesOtherOpensOnMemFS(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	exerciseFlock(t, w, m)
}

func TestWasi_FlockIsVisibleToOtherProcesses(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	w, m := newProcTestStubs(t)
	p := filepath.Join(w.preopenDir, "lock")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A file opened behind the instance's back stands in for another
	// process: the lock is the operating system's, not the instance's.
	outside, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer outside.Close()
	fd := openTestFile(t, w, "lock")
	if rc := flockRC(w, m, fd, FileLockExclusive); rc != 0 {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	if err := flockOSFile(outside, FileLockShared, false); err != syscall.EAGAIN {
		t.Fatalf("outside lock while the instance holds it: %v, want EAGAIN", err)
	}
	closeTestFd(t, w, m, fd)
	if err := flockOSFile(outside, FileLockExclusive, false); err != nil {
		t.Fatalf("outside lock after the instance closed the file: %v", err)
	}
	fd = openTestFile(t, w, "lock")
	if rc := flockRC(w, m, fd, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("instance lock while the outside holds it: rc=%d, want -EAGAIN", rc)
	}
}

func TestWasi_FlockOnStandardStream(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	w, m := newProcTestStubs(t)
	// A standard stream that is not a file has no other opener: locking
	// it is a successful no-op.
	if rc := flockRC(w, m, 1, FileLockExclusive); rc != 0 {
		t.Fatalf("lock on a buffer-backed stdout rc=%d", rc)
	}
	// One that is a file of the host process is really locked.
	p := filepath.Join(w.preopenDir, "out.log")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w.SetStdout(out)
	if rc := flockRC(w, m, 1, FileLockExclusive); rc != 0 {
		t.Fatalf("lock on a file-backed stdout rc=%d", rc)
	}
	fd := openTestFile(t, w, "out.log")
	if rc := flockRC(w, m, fd, FileLockShared); rc != -_wasiEAGAIN {
		t.Fatalf("lock on the file stdout is locked on: rc=%d, want -EAGAIN", rc)
	}
}

func TestMemFS_ModesLinksAndTimes(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("f", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	off, n := putPath(m, metaPathOff, "f")
	if rc := w.Path_chmod(m, off, n, 0o600); rc != 0 {
		t.Fatalf("Path_chmod rc=%d", rc)
	}
	if got := pathFilestatExt(t, w, m, "f").mode; got != 0o600 {
		t.Fatalf("mode after Path_chmod = %o, want 600", got)
	}
	fd := openTestFile(t, w, "f")
	if rc := w.Fd_chmod(m, fd, 0o640); rc != 0 {
		t.Fatalf("Fd_chmod rc=%d", rc)
	}
	if got := fdFilestatExt(t, w, m, fd).mode; got != 0o640 {
		t.Fatalf("mode after Fd_chmod = %o, want 640", got)
	}

	mtime := time.Unix(2_000_000, 0)
	if rc := w.Path_filestat_set_times(m, 3, 0x1, off, n, 0, mtime.UnixNano(), 0x4); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_set_times rc=%d", rc)
	}
	byPath, byFd := pathFilestat(t, w, m, "f", true), fdFilestat(t, w, m, fd)
	if byPath != byFd {
		t.Fatalf("fd stat %+v differs from path stat %+v", byFd, byPath)
	}
	if byPath.mtim != uint64(mtime.UnixNano()) || byPath.nlink != 1 {
		t.Fatalf("mtim=%d nlink=%d, want %d and 1", byPath.mtim, byPath.nlink, mtime.UnixNano())
	}

	// A removed file is still there for whoever has it open, with no link
	// left; so is one that a rename replaced.
	if rc := w.Path_unlink_file(m, 3, off, n); rc != _wasiESUCCESS {
		t.Fatalf("unlink rc=%d", rc)
	}
	if got := fdFilestat(t, w, m, fd).nlink; got != 0 {
		t.Fatalf("nlink of a removed open file = %d, want 0", got)
	}
	for _, name := range []string{"old", "new"} {
		if err := fsys.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	replaced := openTestFile(t, w, "new")
	if err := fsys.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	if got := fdFilestat(t, w, m, replaced).nlink; got != 0 {
		t.Fatalf("nlink of a replaced open file = %d, want 0", got)
	}
	if got := pathFilestat(t, w, m, "new", true).nlink; got != 1 {
		t.Fatalf("nlink of the renamed file = %d, want 1", got)
	}
}
