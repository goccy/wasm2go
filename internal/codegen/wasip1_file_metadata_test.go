package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Guest memory offsets the tests in this file use for paths and results.
const (
	metaPathOff  int32 = 0
	metaPath2Off int32 = 512
	metaOutOff   int32 = 1024
)

// skipWithoutPOSIXFiles skips a test of file owners, link counts or modes
// on a platform whose host filesystem backend does not provide them.
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

// filestatExt is what Path_filestat_ext and Fd_filestat_ext report, with the
// low twelve mode bits in mode; extFileType reads the file type bits.
type filestatExt struct{ mode, uid, gid uint32 }

// extFileType returns the file type bits of the record a filestat_ext call
// left at metaOutOff.
func extFileType(m *Module) uint32 { return readU32(m.memory, int(metaOutOff)) & unixTypeMask }

func pathFilestatExt(t *testing.T, w *WasiStubs, m *Module, name string) filestatExt {
	t.Helper()
	off, n := putPath(m, metaPathOff, name)
	if rc := w.Path_filestat_ext(m, off, n, 1, metaOutOff); rc != 0 {
		t.Fatalf("Path_filestat_ext(%s) rc=%d", name, rc)
	}
	return filestatExt{readU32(m.memory, int(metaOutOff)) & 0o7777, readU32(m.memory, int(metaOutOff)+4), readU32(m.memory, int(metaOutOff)+8)}
}

func fdFilestatExt(t *testing.T, w *WasiStubs, m *Module, fd int32) filestatExt {
	t.Helper()
	if rc := w.Fd_filestat_ext(m, fd, metaOutOff); rc != 0 {
		t.Fatalf("Fd_filestat_ext(%d) rc=%d", fd, rc)
	}
	return filestatExt{readU32(m.memory, int(metaOutOff)) & 0o7777, readU32(m.memory, int(metaOutOff)+4), readU32(m.memory, int(metaOutOff)+8)}
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

// noOwnerFS is a filesystem whose Chown reports that it keeps no owners.
type noOwnerFS struct{ FS }

func (noOwnerFS) Chown(string, int, int, bool) error { return errors.ErrUnsupported }

// A file's owner is changed by path, a symbolic link's own with follow 0,
// and by descriptor. Giving a file to the user it belongs to is allowed to
// anyone; giving it away is refused unless the host process is root's, in
// which case the new owner is the file's.
func TestWasi_ChownByPathAndDescriptor(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	uid, gid := int32(os.Getuid()), int32(os.Getgid())
	off, n := putPath(m, metaPathOff, "f")
	linkOff, linkLen := putPath(m, metaPath2Off, "link")
	if rc := w.Path_chown(m, off, n, uid, -1, 1); rc != 0 {
		t.Fatalf("Path_chown to the owner rc=%d", rc)
	}
	if rc := w.Path_chown(m, linkOff, linkLen, uid, -1, 0); rc != 0 {
		t.Fatalf("Path_chown of the link itself rc=%d", rc)
	}
	fd := openTestFile(t, w, "f")
	if rc := w.Fd_chown(m, fd, uid, gid); rc != 0 {
		t.Fatalf("Fd_chown to the owner rc=%d", rc)
	}
	if uid != 0 {
		if rc := w.Path_chown(m, off, n, 0, -1, 1); rc != -_wasiEPERM {
			t.Errorf("Path_chown to root rc=%d, want -EPERM", rc)
		}
		if rc := w.Fd_chown(m, fd, 0, -1); rc != -_wasiEPERM {
			t.Errorf("Fd_chown to root rc=%d, want -EPERM", rc)
		}
	} else {
		if rc := w.Path_chown(m, off, n, 1234, 5678, 1); rc != 0 {
			t.Fatalf("Path_chown by root rc=%d", rc)
		}
		if got := pathFilestatExt(t, w, m, "f"); got.uid != 1234 || got.gid != 5678 {
			t.Errorf("owner after Path_chown = %d:%d, want 1234:5678", got.uid, got.gid)
		}
		if rc := w.Fd_chown(m, fd, 4321, -1); rc != 0 {
			t.Fatalf("Fd_chown by root rc=%d", rc)
		}
		if got := fdFilestatExt(t, w, m, fd); got.uid != 4321 || got.gid != 5678 {
			t.Errorf("owner after Fd_chown = %d:%d, want 4321:5678", got.uid, got.gid)
		}
	}

	missOff, missLen := putPath(m, metaPath2Off, "nothing")
	if rc := w.Path_chown(m, missOff, missLen, -1, -1, 1); rc != -_wasiENOENT {
		t.Errorf("Path_chown of a missing file rc=%d, want -ENOENT", rc)
	}
	if rc := w.Path_chown(m, int32(len(m.memory)), 1, -1, -1, 1); rc != -_wasiEFAULT {
		t.Errorf("Path_chown of a path outside the memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Fd_chown(m, 99, -1, -1); rc != -_wasiEBADF {
		t.Errorf("Fd_chown on a closed fd rc=%d, want -EBADF", rc)
	}
	if rc := w.Fd_chown(m, 1, -1, -1); rc != -_wasiENOSYS {
		t.Errorf("Fd_chown on a stream that is no file rc=%d, want -ENOSYS", rc)
	}
	w.SetFSAccessHook(func(string, bool) bool { return false })
	if rc := w.Path_chown(m, off, n, -1, -1, 1); rc != -_wasiEACCES {
		t.Errorf("Path_chown the access hook refuses rc=%d, want -EACCES", rc)
	}
	w.SetFSAccessHook(nil)

	// A filesystem that keeps no owners has none to change.
	w.SetFS(noOwnerFS{osFS{root: dir}})
	if rc := w.Path_chown(m, off, n, -1, -1, 1); rc != -_wasiENOSYS {
		t.Errorf("Path_chown on a filesystem without owners rc=%d, want -ENOSYS", rc)
	}
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.SetFS(mem)
	if rc := w.Path_chown(m, off, n, 0, 0, 1); rc != -_wasiENOSYS {
		t.Errorf("Path_chown in memory rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Fd_chown(m, openTestFile(t, w, "f"), 0, 0); rc != -_wasiENOSYS {
		t.Errorf("Fd_chown in memory rc=%d, want -ENOSYS", rc)
	}
}

// The calls that take a path or write a record refuse what is not in the
// guest's memory, a name that is not there, and a descriptor that is no
// file.
func TestWasi_FileMetadataErrors(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	outside := int32(len(m.memory))
	off, n := putPath(m, metaPathOff, "nothing")
	for _, tc := range []struct {
		name string
		rc   int32
		want int32
	}{
		{"Path_chmod of a path outside the memory", w.Path_chmod(m, outside, 1, 0o600), -_wasiEFAULT},
		{"Path_chmod of a missing file", w.Path_chmod(m, off, n, 0o600), -_wasiENOENT},
		{"Fd_chmod on a stream that is no file", w.Fd_chmod(m, 1, 0o600), -_wasiEINVAL},
		{"Path_filestat_ext into a record outside the memory", w.Path_filestat_ext(m, off, n, 1, outside), -_wasiEFAULT},
		{"Path_filestat_ext of a missing file", w.Path_filestat_ext(m, off, n, 1, metaOutOff), -_wasiENOENT},
		{"Path_filestat_ext of a missing file, not following", w.Path_filestat_ext(m, off, n, 0, metaOutOff), -_wasiENOENT},
		{"Fd_filestat_ext into a record outside the memory", w.Fd_filestat_ext(m, 1, outside), -_wasiEFAULT},
		{"Path_filestat_mode into a word outside the memory", w.Path_filestat_mode(m, off, n, 1, outside), -_wasiEFAULT},
		{"Fd_path with a negative capacity", w.Fd_path(m, wasiPreopenFD, metaPathOff, -1, metaOutOff), -_wasiEFAULT},
		{"Fd_path with the size outside the memory", w.Fd_path(m, wasiPreopenFD, metaPathOff, 64, outside), -_wasiEFAULT},
	} {
		if tc.rc != tc.want {
			t.Errorf("%s: rc=%d, want %d", tc.name, tc.rc, tc.want)
		}
	}
	// A descriptor whose file is closed reports the error of the call on it.
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fd := openTestFile(t, w, "f")
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if err := op.f.Close(); err != nil {
		t.Fatal(err)
	}
	if rc := w.Fd_filestat_ext(m, fd, metaOutOff); rc >= 0 {
		t.Errorf("Fd_filestat_ext of a closed file rc=%d, want a negative errno", rc)
	}
	if rc := w.Fd_chmod(m, fd, 0o600); rc >= 0 {
		t.Errorf("Fd_chmod of a closed file rc=%d, want a negative errno", rc)
	}
	if rc := w.Fd_filestat_set_times(m, fd, 0, 0, 0x4); rc == _wasiESUCCESS {
		t.Error("Fd_filestat_set_times of a closed file succeeded")
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

// A directory descriptor reports the path it was opened under, absolute in
// the guest's filesystem; other descriptors have no such name.
func TestWasi_FdPathNamesAnOpenDirectory(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(w.preopenDir, "outer", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	fdPath := func(fd, capacity int32) (string, int32) {
		rc := w.Fd_path(m, fd, metaPathOff, capacity, metaOutOff)
		if rc != 0 {
			return "", rc
		}
		return string(m.memory[metaPathOff : metaPathOff+int32(readU32(m.memory, int(metaOutOff)))]), 0
	}
	const oDirectory = 0x2
	dir, errno := w.pathOpen("outer/inner", 0x1, oDirectory, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open the directory errno=%d", errno)
	}
	if got, rc := fdPath(dir, 256); rc != 0 || got != "/outer/inner" {
		t.Fatalf("Fd_path(directory) = %q rc=%d, want /outer/inner", got, rc)
	}
	root, errno := w.pathOpen("", 0x1, oDirectory, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open the root errno=%d", errno)
	}
	if got, rc := fdPath(root, 256); rc != 0 || got != "/" {
		t.Fatalf("Fd_path(root) = %q rc=%d, want /", got, rc)
	}
	if got, rc := fdPath(wasiPreopenFD, 256); rc != 0 || got != "/" {
		t.Fatalf("Fd_path(preopen) = %q rc=%d, want /", got, rc)
	}
	// A buffer that is too small learns the size it needs.
	if _, rc := fdPath(dir, 4); rc != -_wasiERANGE || readU32(m.memory, int(metaOutOff)) != uint32(len("/outer/inner")) {
		t.Fatalf("short buffer rc=%d needed=%d, want -ERANGE and %d", rc, readU32(m.memory, int(metaOutOff)), len("/outer/inner"))
	}

	if err := os.WriteFile(filepath.Join(w.preopenDir, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := openTestFile(t, w, "file")
	if _, rc := fdPath(file, 256); rc != -_wasiENOTDIR {
		t.Fatalf("Fd_path(file) rc=%d, want -ENOTDIR", rc)
	}
	if _, rc := fdPath(1, 256); rc != -_wasiENOTDIR {
		t.Fatalf("Fd_path(stdout) rc=%d, want -ENOTDIR", rc)
	}
	if _, rc := fdPath(99, 256); rc != -_wasiEBADF {
		t.Fatalf("Fd_path(closed) rc=%d, want -EBADF", rc)
	}
}

// Every file and descriptor has its POSIX file type: WASI's own for the
// types WASI has, and the type bits of the filestat_ext record for all of
// them, a FIFO included.
func TestWasi_FileTypes(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mkfifo", filepath.Join(dir, "fifo")).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v: %s", err, out)
	}
	byPath := func(name string) (wasiType byte, posixType uint32) {
		t.Helper()
		wasiType = pathFilestat(t, w, m, name, true).filetype
		pathFilestatExt(t, w, m, name)
		return wasiType, extFileType(m)
	}
	byFd := func(fd int32) (wasiType byte, posixType uint32) {
		t.Helper()
		wasiType = fdFilestat(t, w, m, fd).filetype
		fdFilestatExt(t, w, m, fd)
		return wasiType, extFileType(m)
	}
	want := func(what string, gotWasi byte, gotPosix uint32, wantWasi byte, wantPosix uint32) {
		t.Helper()
		if gotWasi != wantWasi || gotPosix != wantPosix {
			t.Errorf("%s: wasi type %d, posix type %#o; want %d, %#o", what, gotWasi, gotPosix, wantWasi, wantPosix)
		}
	}
	wt, pt := byPath("file")
	want("a regular file", wt, pt, 4, unixTypeRegular)
	wt, pt = byPath("dir")
	want("a directory", wt, pt, 3, unixTypeDir)
	wt, pt = byPath("fifo")
	want("a FIFO", wt, pt, 0, unixTypeFIFO)

	// A character device is not a block device.
	devices, dm := newTestStubs(t, "/")
	off, n := putPath(dm, metaPathOff, "dev/null")
	if rc := devices.Path_filestat_get(dm, 3, 1, off, n, metaOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_get(/dev/null) rc=%d", rc)
	}
	wt = decodeFilestat(dm.memory[metaOutOff:]).filetype
	if rc := devices.Path_filestat_ext(dm, off, n, 1, metaOutOff); rc != 0 {
		t.Fatalf("Path_filestat_ext(/dev/null) rc=%d", rc)
	}
	want("/dev/null", wt, extFileType(dm), 2, unixTypeChar)

	// Descriptors: a pipe is a FIFO, a socket a socket.
	readFd, writeFd := newTestPipe(t, w, m)
	wt, pt = byFd(readFd)
	want("the read end of a pipe", wt, pt, 0, unixTypeFIFO)
	wt, pt = byFd(writeFd)
	want("the write end of a pipe", wt, pt, 0, unixTypeFIFO)
	sock := w.Sock_socket(m, 2, 1)
	wt, pt = byFd(sock)
	want("a socket", wt, pt, 6, unixTypeSocket)

	// A standard stream the embedder supplied is a pipe to the guest; one
	// that is a file of the host is that file.
	wt, pt = byFd(1)
	want("an embedder's stdout", wt, pt, 0, unixTypeFIFO)
	out, err := os.Create(filepath.Join(dir, "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := out.Close(); err != nil {
			t.Errorf("close out.log: %v", err)
		}
	})
	w.SetStdout(out)
	wt, pt = byFd(1)
	want("stdout redirected to a file", wt, pt, 4, unixTypeRegular)
	if got := fdFilestatExt(t, w, m, 1).uid; got != uint32(os.Getuid()) {
		t.Errorf("the owner of a file-backed stdout = %d, want %d", got, os.Getuid())
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := null.Close(); err != nil {
			t.Errorf("close the null device: %v", err)
		}
	})
	w.SetStdin(null)
	wt, pt = byFd(0)
	want("stdin from /dev/null", wt, pt, 2, unixTypeChar)
}

// The extended stat record names the block size, the blocks allocated and,
// for a special file, the device it stands for.
func TestFilestatExtBlocksAndDevice(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data"), bytes.Repeat([]byte("x"), 10000), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	record := func(name string) (blksize uint32, rdev, blocks uint64) {
		t.Helper()
		off := writeCStr(m, 1000, name)
		if rc := w.Path_filestat_ext(m, off, int32(len(name)), 1, metaOutOff); rc != 0 {
			t.Fatalf("Path_filestat_ext(%s) rc=%d", name, rc)
		}
		out := m.memory[metaOutOff:]
		return binary.LittleEndian.Uint32(out[12:]), binary.LittleEndian.Uint64(out[16:]), binary.LittleEndian.Uint64(out[24:])
	}
	blksize, rdev, blocks := record("data")
	if blksize == 0 || blocks == 0 || rdev != 0 {
		t.Fatalf("a file of 10000 bytes: block size %d, %d blocks, device %d", blksize, blocks, rdev)
	}
	// In memory a file has blocks too.
	mem := NewMemFS()
	if err := mem.WriteFile("data", make([]byte, 10000), 0o644); err != nil {
		t.Fatal(err)
	}
	w.SetFS(mem)
	if blksize, _, blocks := record("data"); blksize == 0 || blocks != 20 {
		t.Fatalf("in memory: block size %d, %d blocks; want a block size and 20 blocks", blksize, blocks)
	}
	// The null device of the host stands for a device.
	host := DefaultWASI()
	off := writeCStr(m, 1000, "dev/null")
	if rc := host.Path_filestat_ext(m, off, 8, 1, metaOutOff); rc != 0 {
		t.Skipf("the host has no /dev/null: rc=%d", rc)
	}
	if rdev := binary.LittleEndian.Uint64(m.memory[metaOutOff+16:]); rdev == 0 {
		t.Fatal("/dev/null stands for no device")
	}
}

// bareInfo is a FileInfo of the given mode that carries no POSIX metadata.
type bareInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (fi bareInfo) Mode() os.FileMode { return fi.mode }
func (bareInfo) Sys() any             { return nil }

// The mode bits and the file types of POSIX cross to os.FileMode and back,
// and a file whose FileInfo carries no POSIX metadata has one link and its
// modification time for every time.
func TestUnixModeBitsAndFileTypes(t *testing.T) {
	for _, bits := range []uint32{0, 0o644, 0o4755, 0o2750, 0o1777, 0o7777} {
		if got := unixModeBits(unixFileMode(bits)); got != bits {
			t.Errorf("mode %#o crosses to os.FileMode and back as %#o", bits, got)
		}
	}
	mtime := time.Unix(1_000_000, 0)
	plain := memFileInfo{name: "f", modTime: mtime}
	for _, tc := range []struct {
		mode      os.FileMode
		posixType uint32
		wasiType  byte
	}{
		{0, unixTypeRegular, 4},
		{os.ModeDir, unixTypeDir, 3},
		{os.ModeSymlink, unixTypeSymlink, 7},
		{os.ModeNamedPipe, unixTypeFIFO, 0},
		{os.ModeSocket, unixTypeSocket, 6},
		{os.ModeDevice | os.ModeCharDevice, unixTypeChar, 2},
		{os.ModeDevice, unixTypeBlock, 1},
	} {
		if got := unixTypeBits(tc.mode); got != tc.posixType {
			t.Errorf("unixTypeBits(%v) = %#o, want %#o", tc.mode, got, tc.posixType)
		}
		out := make([]byte, 64)
		writeFilestat(out, bareInfo{plain, tc.mode})
		st := decodeFilestat(out)
		if st.filetype != tc.wasiType {
			t.Errorf("the filestat of a file of mode %v has type %d, want %d", tc.mode, st.filetype, tc.wasiType)
		}
		if st.nlink != 1 || st.atim != uint64(mtime.UnixNano()) || st.ctim != st.atim || st.mtim != st.atim {
			t.Errorf("without POSIX metadata: nlink=%d atim=%d mtim=%d ctim=%d, want 1 and %d", st.nlink, st.atim, st.mtim, st.ctim, mtime.UnixNano())
		}
	}
}

// The record of a descriptor with no file behind it is written whole: what
// the guest's memory held there is gone.
func TestWasi_FilestatExtWithoutAFileWritesTheWholeRecord(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	for _, tc := range []struct {
		name string
		fd   int32
		mode uint32
	}{
		{"an embedder's stdout", 1, unixTypeFIFO | 0o600},
		{"a socket", w.Sock_socket(m, 2, 1), unixTypeSocket | 0o777},
	} {
		record := m.memory[metaOutOff : metaOutOff+wasiFilestatExtSize]
		for i := range record {
			record[i] = 0xa5
		}
		if rc := w.Fd_filestat_ext(m, tc.fd, metaOutOff); rc != 0 {
			t.Fatalf("%s: Fd_filestat_ext rc=%d", tc.name, rc)
		}
		want := make([]byte, wasiFilestatExtSize)
		binary.LittleEndian.PutUint32(want, tc.mode)
		if !bytes.Equal(record, want) {
			t.Errorf("%s: record % x, want % x", tc.name, record, want)
		}
	}
}

// The preopened root directory, under both of its numbers, is the
// directory "." names: its descriptor's stat is the stat of ".".
func TestWasi_RootDescriptorIsTheRootDirectory(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	byPath := pathFilestat(t, w, m, ".", true)
	if byPath.filetype != 3 {
		t.Fatalf("\".\" has type %d, want a directory's", byPath.filetype)
	}
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && (byPath.dev == 0 || byPath.ino == 0) {
		t.Fatalf("\".\" is dev %d ino %d, want a real dev/ino", byPath.dev, byPath.ino)
	}
	for _, fd := range []int32{wasiPreopenFD, wasiRootFD} {
		if got := fdFilestat(t, w, m, fd); got.dev != byPath.dev || got.ino != byPath.ino || got.filetype != byPath.filetype {
			t.Errorf("fd %d: dev %d ino %d type %d, want %d, %d and %d", fd, got.dev, got.ino, got.filetype, byPath.dev, byPath.ino, byPath.filetype)
		}
		fdFilestatExt(t, w, m, fd)
		if got := extFileType(m); got != unixTypeDir {
			t.Errorf("fd %d: posix type %#o, want a directory's", fd, got)
		}
	}
	// A root directory that is gone reports the error of its stat.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int32{wasiPreopenFD, wasiRootFD} {
		if rc := w.Fd_filestat_get(m, fd, metaOutOff); rc != _wasiENOENT {
			t.Errorf("fd %d of a removed root: Fd_filestat_get rc=%d, want ENOENT", fd, rc)
		}
		if rc := w.Fd_filestat_ext(m, fd, metaOutOff); rc != -_wasiENOENT {
			t.Errorf("fd %d of a removed root: Fd_filestat_ext rc=%d, want -ENOENT", fd, rc)
		}
	}
	// The root of a filesystem in memory is its root directory.
	w.SetFS(NewMemFS())
	if got := fdFilestat(t, w, m, wasiPreopenFD).filetype; got != 3 {
		t.Errorf("the root in memory has type %d, want a directory's", got)
	}
}
