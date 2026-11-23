package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
	fd, errno := w.pathOpen(nil, name, 0x1, 0, 1<<1|1<<6, 0)
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
	w.cfg.FS = fsys
	return w, m, fsys
}

func TestWasi_FilestatReportsLinksAndIdentity(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	// The access time is set later than now and the modification time
	// earlier than it.
	now := time.Now().Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(dir, "a"), now.Add(time.Hour), now.Add(-time.Hour)); err != nil {
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
	// The access times set are later than now.
	atime, mtime := created.Truncate(time.Second).Add(2*time.Hour), time.Unix(2_000_000, 0)
	off, n := putPath(m, metaPathOff, "f")
	if rc := w.Path_filestat_set_times(m, 3, 0x1, off, n, atime.UnixNano(), mtime.UnixNano(), 0x1|0x4); rc != _wasiESUCCESS {
		t.Fatalf("Path_filestat_set_times rc=%d", rc)
	}
	st := pathFilestat(t, w, m, "f", true)
	if st.atim != uint64(atime.UnixNano()) || st.mtim != uint64(mtime.UnixNano()) {
		t.Fatalf("atim=%d mtim=%d, want %d and %d", st.atim, st.mtim, atime.UnixNano(), mtime.UnixNano())
	}
	// The status change time is when the times were set, not either of them.
	if ctime := time.Unix(0, int64(st.ctim)); ctime.Before(created.Add(-time.Minute)) || ctime.After(created.Add(time.Minute)) {
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
	earlier := atime.Add(-time.Hour)
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

func (noOwnerFS) Chown(string, int, int) error  { return errors.ErrUnsupported }
func (noOwnerFS) Lchown(string, int, int) error { return errors.ErrUnsupported }

// A file's owner is changed by path, a symbolic link's own with follow 0,
// and by descriptor. Giving a file to the user it belongs to is allowed to
// anyone; giving it away is refused unless the host process is root's, in
// which case the new owner is the file's.
func TestWasi_ChownByPathAndDescriptor(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
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
	var seen []string
	host := w.cfg.FS
	w.cfg.FS = policyFS{FS: host, allow: func(string, bool) bool { return false }, seen: &seen}
	if rc := w.Path_chown(m, off, n, -1, -1, 1); rc != -_wasiEACCES {
		t.Errorf("Path_chown a policy refuses rc=%d, want -EACCES", rc)
	}
	w.cfg.FS = host

	// A filesystem that keeps no owners has none to change.
	w.cfg.FS = noOwnerFS{newHostFS(t, dir)}
	if rc := w.Path_chown(m, off, n, -1, -1, 1); rc != -_wasiENOSYS {
		t.Errorf("Path_chown on a filesystem without owners rc=%d, want -ENOSYS", rc)
	}
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = mem
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
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
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

// Every file of a MemFS is a file of its own: one device, an inode number
// of its own, kept across a rename and the same by name and by descriptor.
func TestMemFS_FilesHaveTheirOwnInode(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("d/a", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Mkdir("e", 0o755); err != nil {
		t.Fatal(err)
	}
	opened := openTestFile(t, w, "d/a")
	if _, errno := w.pathOpen(m, "b", 0x1, 1<<0, 1<<1|1<<6, 0); errno != _wasiESUCCESS {
		t.Fatalf("create b errno=%d", errno)
	}
	root := pathFilestat(t, w, m, ".", true)
	seen := map[uint64]string{}
	for _, name := range []string{".", "d", "d/a", "e", "b"} {
		st := pathFilestat(t, w, m, name, true)
		if st.dev == 0 || st.dev != root.dev || st.ino == 0 {
			t.Errorf("%s: dev=%d ino=%d, want dev %d (non-zero) and a non-zero ino", name, st.dev, st.ino, root.dev)
		}
		if other, ok := seen[st.ino]; ok {
			t.Errorf("%s and %s share inode %d", name, other, st.ino)
		}
		seen[st.ino] = name
	}
	before := pathFilestat(t, w, m, "d/a", true)
	if got := fdFilestat(t, w, m, opened); got != before {
		t.Fatalf("fd stat %+v differs from path stat %+v", got, before)
	}
	if err := fsys.Rename("d/a", "e/c"); err != nil {
		t.Fatal(err)
	}
	if after := pathFilestat(t, w, m, "e/c", true); after.ino != before.ino || after.dev != before.dev {
		t.Fatalf("renamed file: dev/ino %d/%d, was %d/%d", after.dev, after.ino, before.dev, before.ino)
	}
}

// direntInodes returns the d_ino fd_readdir writes for each name of the
// directory open at fd.
func direntInodes(t *testing.T, w *WasiStubs, fd int32) map[string]uint64 {
	t.Helper()
	buf := make([]byte, 4096)
	n, errno := w.fillDirents(fd, buf, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("fillDirents errno=%d", errno)
	}
	inos := map[string]uint64{}
	for off := 0; off+24 <= n; {
		end := off + 24 + int(binary.LittleEndian.Uint32(buf[off+16:]))
		inos[string(buf[off+24:end])] = binary.LittleEndian.Uint64(buf[off+8:])
		off = end
	}
	return inos
}

// fd_readdir lists every entry of a MemFS directory, "." and ".." among
// them, with the inode number its stat reports.
func TestMemFS_ReaddirInodesAreTheStatOnes(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	for _, name := range []string{"d/a", "d/sub/b"} {
		if err := fsys.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for dir, want := range map[string]map[string]string{
		"d":     {".": "d", "..": ".", "a": "d/a", "sub": "d/sub"},
		"d/sub": {".": "d/sub", "..": "d", "b": "d/sub/b"},
	} {
		fd, errno := w.pathOpen(m, dir, 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("pathOpen(%s) errno=%d", dir, errno)
		}
		got := direntInodes(t, w, fd)
		if len(got) != len(want) {
			t.Errorf("%s lists %v, want the names of %v", dir, got, want)
		}
		for name, path := range want {
			if ino := pathFilestat(t, w, m, path, true).ino; got[name] != ino {
				t.Errorf("%s/%s: d_ino %d, want %d (the inode of %s)", dir, name, got[name], ino, path)
			}
		}
		// A rewound listing lists every entry again.
		if again := direntInodes(t, w, fd); len(again) != len(got) {
			t.Errorf("%s after rewinddir lists %v, want %v", dir, again, got)
		}
	}
}

// "." and ".." of a MemFS directory are the directory open and the one
// it is in, wherever it has moved and whatever its old path names now,
// and whatever file system the stubs have since been given.
func TestMemFS_ReaddirDotsOfAMovedDirectory(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	for _, name := range []string{"a/sub/f", "b/f", "d/sub/f"} {
		if err := fsys.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	open := func(dir string) int32 {
		fd, errno := w.pathOpen(m, dir, 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("pathOpen(%s) errno=%d", dir, errno)
		}
		return fd
	}
	aSub, dSub := open("a/sub"), open("d/sub")
	if err := fsys.Rename("a/sub", "b/sub"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	ino := func(name string) uint64 { return pathFilestat(t, w, m, name, true).ino }
	want := map[int32][2]uint64{aSub: {ino("b/sub"), ino("b")}, dSub: {ino("e/sub"), ino("e")}}
	for _, setFS := range []bool{false, true} {
		if setFS {
			w.cfg.FS = NewMemFS()
		}
		for fd, dots := range want {
			if got := direntInodes(t, w, fd); got["."] != dots[0] || got[".."] != dots[1] {
				t.Errorf("fd %d (MemFS installed %v): . %d and .. %d, want %d and %d", fd, setFS, got["."], got[".."], dots[0], dots[1])
			}
		}
	}
}

// A MemFS path through a file fails with ENOTDIR, for every operation.
func TestMemFS_PathThroughAFile(t *testing.T) {
	fsys := NewMemFS()
	if err := fsys.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, statErr := fsys.Stat("f/x")
	_, openErr := fsys.OpenFile("f/x", os.O_RDONLY, 0)
	_, createErr := fsys.OpenFile("f/x", os.O_RDWR|os.O_CREATE, 0o644)
	for name, err := range map[string]error{
		"Stat":      statErr,
		"OpenFile":  openErr,
		"create":    createErr,
		"WriteFile": fsys.WriteFile("f/x", nil, 0o644),
		"MkdirAll":  fsys.MkdirAll("f/x", 0o755),
		"Mkdir":     fsys.Mkdir("f/x", 0o755),
	} {
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("%s through a file: %v, want ENOTDIR", name, err)
		}
	}
}

// statOnceFS is a MemFS whose files answer one Stat, the one Path_open
// makes, and fail every later one.
type statOnceFS struct{ *MemFS }

func (fsys statOnceFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := fsys.MemFS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &statOnceFile{File: f}, nil
}

type statOnceFile struct {
	File
	stated bool
}

func (f *statOnceFile) Stat() (os.FileInfo, error) {
	if f.stated {
		return nil, errors.New("stat failed")
	}
	f.stated = true
	return f.File.Stat()
}

// A directory whose stat fails is listed all the same, with "." and ".."
// numbered from their index.
func TestReaddir_DirectoryWhoseStatFails(t *testing.T) {
	w, _ := newTestStubs(t, t.TempDir())
	fsys := NewMemFS()
	if err := fsys.WriteFile("d/a", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = statOnceFS{fsys}
	fd, errno := w.pathOpen(nil, "d", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	got := direntInodes(t, w, fd)
	if len(got) != 3 || got["."]&(1<<63) == 0 || got[".."]&(1<<63) == 0 || got["a"] == 0 || got["a"]&(1<<63) != 0 {
		t.Errorf("listing %v, want ., .. with the top bit set and a with its inode", got)
	}
}

// The name of an open MemFS file can be asked while the file is renamed.
func TestMemFS_NameWhileRenamed(t *testing.T) {
	fsys := NewMemFS()
	if err := fsys.WriteFile("a", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := fsys.OpenFile("a", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	renamed := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			from, to := "a", "b"
			if i%2 == 1 {
				from, to = to, from
			}
			if err := fsys.Rename(from, to); err != nil {
				renamed <- err
				return
			}
		}
		renamed <- nil
	}()
	for i := 0; i < 100; i++ {
		if name := f.Name(); name != "a" && name != "b" {
			t.Fatalf("Name() = %q, want a or b", name)
		}
	}
	if err := <-renamed; err != nil {
		t.Fatal(err)
	}
}

// A seek to the start of a MemFS directory lists it again from its first
// entry; asking where the handle is does not.
func TestMemFS_SeekOfADirectory(t *testing.T) {
	fsys := NewMemFS()
	for _, name := range []string{"d/a", "d/b"} {
		if err := fsys.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := fsys.OpenFile("d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	next := func() string {
		t.Helper()
		entries, err := f.ReadDir(1)
		if err != nil {
			t.Fatal(err)
		}
		return entries[0].Name()
	}
	if got := next(); got != "a" {
		t.Fatalf("first entry %q, want a", got)
	}
	if _, err := f.Seek(0, io.SeekCurrent); err != nil {
		t.Fatal(err)
	}
	if got := next(); got != "b" {
		t.Errorf("after Seek(0, SeekCurrent): %q, want b", got)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if got := next(); got != "a" {
		t.Errorf("after Seek(0, SeekStart): %q, want a", got)
	}
}

// A MemFS directory can be read, and its entries asked about, while its
// files change.
func TestMemFS_ReadDirWhileFilesChange(t *testing.T) {
	fsys := NewMemFS()
	if err := fsys.WriteFile("d/f", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	changed := make(chan error, 1)
	defer func() {
		close(done)
		if err := <-changed; err != nil {
			t.Error(err)
		}
	}()
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				changed <- nil
				return
			default:
			}
			if err := fsys.Chmod("d/f", os.FileMode(0o600|i&1)); err != nil {
				changed <- err
				return
			}
			if err := fsys.WriteFile("d/f", []byte{byte(i)}, 0o644); err != nil {
				changed <- err
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		f, err := fsys.OpenFile("d", os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := f.ReadDir(-1)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if e.Name() != "f" || e.IsDir() || !fi.Mode().IsRegular() || fi.Size() != 1 {
				t.Fatalf("entry %s: dir=%v mode=%v size=%d, want the one-byte file f", e.Name(), e.IsDir(), fi.Mode(), fi.Size())
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// WriteFile onto an existing file writes that file: it keeps its inode and
// mode, and a descriptor of it reports the new data. It does not write
// onto a directory.
func TestMemFS_WriteFileOverAFile(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	if err := fsys.WriteFile("f", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := openTestFile(t, w, "f")
	before := pathFilestat(t, w, m, "f", true)
	if err := fsys.WriteFile("f", []byte("newer"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := pathFilestat(t, w, m, "f", true)
	if after.ino != before.ino || after.nlink != 1 || after.size != 5 {
		t.Fatalf("written file: ino=%d nlink=%d size=%d, want ino %d, nlink 1 and size 5", after.ino, after.nlink, after.size, before.ino)
	}
	if got := fdFilestat(t, w, m, fd); got != after {
		t.Fatalf("fd stat %+v differs from path stat %+v", got, after)
	}
	if got := pathFilestatExt(t, w, m, "f").mode; got != 0o600 {
		t.Fatalf("mode of the written file = %o, want 600", got)
	}

	if err := fsys.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("d", nil, 0o644); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("WriteFile onto a directory: %v, want EISDIR", err)
	}
	if got := pathFilestat(t, w, m, "d", true).filetype; got != 3 {
		t.Fatalf("d after WriteFile onto it: filetype %d, want 3 (directory)", got)
	}
}

// A MemFS renames onto an existing name as rename(2) does: a file replaces
// a file and a directory an empty directory, and anything else fails and
// leaves both names as they were. A directory does not move into itself,
// a file not under a file or to a name ending in "/", and a directory with
// something in it is not removed.
func TestMemFS_RenameOntoAnExistingName(t *testing.T) {
	w, m, fsys := memTestStubs(t)
	for _, name := range []string{"file", "full/x"} {
		if err := fsys.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"dir", "dir/sub", "empty"} {
		if err := fsys.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		from, to string
		want     int32
	}{
		{"dir", "file", _wasiENOTDIR},
		{"file", "dir", _wasiEISDIR},
		{"dir", "full", _wasiENOTEMPTY},
		{"dir", "dir/new", _wasiEINVAL},
		{"dir/sub", "dir/sub/new", _wasiEINVAL},
		{"dir", "dir/sub/new", _wasiEINVAL},
		{"file", "file/new", _wasiENOTDIR},
		{"file", "new/", _wasiENOTDIR},
		{"file/", "new", _wasiENOTDIR},
		{"file", "dir/", _wasiENOTDIR},
	} {
		if err := fsys.Rename(c.from, c.to); errnoOfError(err) != c.want {
			t.Errorf("rename %s onto %s: %v (errno %d), want errno %d", c.from, c.to, err, errnoOfError(err), c.want)
		}
	}
	if err := fsys.Rmdir("full"); errnoOfError(err) != _wasiENOTEMPTY {
		t.Errorf("rmdir full: %v (errno %d), want ENOTEMPTY", err, errnoOfError(err))
	}
	for _, name := range []string{"file", "full/x", "dir/sub", "empty"} {
		if _, err := fsys.Stat(name); err != nil {
			t.Errorf("%s after the failed renames: %v", name, err)
		}
	}

	held, errno := w.pathOpen(m, "empty", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen(empty) errno=%d", errno)
	}
	if err := fsys.Rename("dir", "empty"); err != nil {
		t.Fatalf("a directory onto an empty one: %v", err)
	}
	if _, err := fsys.Stat("empty/sub"); err != nil {
		t.Errorf("empty/sub after the rename: %v", err)
	}
	if _, err := fsys.Stat("dir"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dir after the rename: %v, want it gone", err)
	}
	if got := fdFilestat(t, w, m, held).nlink; got != 0 {
		t.Errorf("nlink of the replaced directory = %d, want 0", got)
	}
}

// A directory descriptor reports the path it was opened under, absolute in
// the guest's filesystem; other descriptors have no such name.
func TestWasi_FdPathNamesAnOpenDirectory(t *testing.T) {
	hostDir := t.TempDir()
	w, m := newTestStubs(t, hostDir)
	if err := os.MkdirAll(filepath.Join(hostDir, "outer", "inner"), 0o755); err != nil {
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
	dir, errno := w.pathOpen(m, "outer/inner", 0x1, oDirectory, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open the directory errno=%d", errno)
	}
	if got, rc := fdPath(dir, 256); rc != 0 || got != "/outer/inner" {
		t.Fatalf("Fd_path(directory) = %q rc=%d, want /outer/inner", got, rc)
	}
	root, errno := w.pathOpen(m, "", 0x1, oDirectory, 1<<1, 0)
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

	if err := os.WriteFile(filepath.Join(hostDir, "file"), []byte("x"), 0o644); err != nil {
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
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
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
	w.cfg.Stdout = out
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
	w.cfg.Stdin = null
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
	w.cfg.FS = mem
	if blksize, _, blocks := record("data"); blksize == 0 || blocks != 20 {
		t.Fatalf("in memory: block size %d, %d blocks; want a block size and 20 blocks", blksize, blocks)
	}
	// The null device of the host stands for a device.
	host := NewWASI(HostWASIConfig())
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
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
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
	// A root directory that is gone is still the directory the HostFS
	// holds open: it is stated through its descriptor.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int32{wasiPreopenFD, wasiRootFD} {
		if got := fdFilestat(t, w, m, fd); got.ino != byPath.ino || got.filetype != 3 {
			t.Errorf("fd %d of a removed root: ino %d type %d, want %d and a directory's", fd, got.ino, got.filetype, byPath.ino)
		}
		if rc := w.Fd_filestat_ext(m, fd, metaOutOff); rc != 0 {
			t.Errorf("fd %d of a removed root: Fd_filestat_ext rc=%d", fd, rc)
		}
	}
	// The root of a filesystem in memory is its root directory.
	w.cfg.FS = NewMemFS()
	if got := fdFilestat(t, w, m, wasiPreopenFD).filetype; got != 3 {
		t.Errorf("the root in memory has type %d, want a directory's", got)
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
// and requires every one to end up with its requested mode less the umask,
// and less host: the mask the filesystem itself takes out of a mode (the
// host process's umask for the host's files, none for files in memory).
func exerciseCreationModes(t *testing.T, w *WasiStubs, m *Module, host os.FileMode) {
	t.Helper()
	less := func(mode uint32) uint32 { return mode &^ uint32(host) }
	// Until the guest sets a umask, the default Process's 022 applies.
	if got, want := createWithMode(t, w, m, "inherited", 0o666), less(0o644); got != want {
		t.Errorf("file under the starting umask: %o, want %o", got, want)
	}
	if prev := w.Proc_umask(m, 0o027); prev != 0o022 {
		t.Errorf("first umask returned %o, want the starting umask 022", prev)
	}
	if prev := w.Proc_umask(m, 0o027); prev != 0o027 {
		t.Errorf("second umask returned %o, want 027", prev)
	}
	if got, want := createWithMode(t, w, m, "f640", 0o666), less(0o640); got != want {
		t.Errorf("file 0666 under umask 027: %o, want %o", got, want)
	}
	if got, want := createWithMode(t, w, m, "f600", 0o600), less(0o600); got != want {
		t.Errorf("file 0600 under umask 027: %o, want %o", got, want)
	}
	if got, want := mkdirWithMode(t, w, m, "d750", 0o777), less(0o750); got != want {
		t.Errorf("directory 0777 under umask 027: %o, want %o", got, want)
	}
	if got, want := mkdirWithMode(t, w, m, "d700", 0o700), less(0o700); got != want {
		t.Errorf("directory 0700 under umask 027: %o, want %o", got, want)
	}

	// path_open and path_create_directory carry no mode: they create with
	// the conventional 0666 and 0777, less the umask.
	closeTestFd(t, w, m, createTestFile(t, w, "plain"))
	if got, want := pathFilestatExt(t, w, m, "plain").mode, less(0o640); got != want {
		t.Errorf("path_open under umask 027: %o, want %o", got, want)
	}
	off, n := putPath(m, metaPathOff, "plaindir")
	if rc := w.Path_create_directory(m, 3, off, n); rc != _wasiESUCCESS {
		t.Fatalf("Path_create_directory rc=%d", rc)
	}
	if got, want := pathFilestatExt(t, w, m, "plaindir").mode, less(0o750); got != want {
		t.Errorf("path_create_directory under umask 027: %o, want %o", got, want)
	}

	// A guest umask looser than the mask of the filesystem does not loosen
	// a mode.
	w.Proc_umask(m, 0)
	if got, want := createWithMode(t, w, m, "f666", 0o666), less(0o666); got != want {
		t.Errorf("file 0666 under umask 0: %o, want %o", got, want)
	}
	if got, want := mkdirWithMode(t, w, m, "d777", 0o777), less(0o777); got != want {
		t.Errorf("directory 0777 under umask 0: %o, want %o", got, want)
	}
	// Opening an existing file with O_CREAT leaves its mode alone.
	if got, want := createWithMode(t, w, m, "f600", 0o666), less(0o600); got != want {
		t.Errorf("existing file reopened with O_CREAT: %o, want it kept at %o", got, want)
	}

	// A forked instance starts with its parent's umask and then has its own.
	w.Proc_umask(m, 0o077)
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
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
	exerciseCreationModes(t, w, m, hostTakesOut(t))
}

// hostTakesOut returns the mask the host's filesystem takes out of a mode
// besides the instance's umask: none where the instance's creation thread
// has the umask (creationThreads) or the runtime puts back what the host
// process's takes out (hostHasUmask without hostThreadUmask), the host
// process's elsewhere.
func hostTakesOut(t *testing.T) os.FileMode {
	if creationThreads(t) || hostHasUmask && !hostThreadUmask {
		return 0
	}
	return hostUmask(t)
}

// creationThreads reports whether an instance here gets a creation thread:
// on a system with a umask for each thread (hostThreadUmask), one that does
// not refuse unshare(2) (Docker's default seccomp profile does).
func creationThreads(t *testing.T) bool {
	t.Helper()
	if !hostThreadUmask {
		return false
	}
	if err := creationThreadsRefused(); err != nil {
		t.Logf("no creation thread: %v", err)
		return false
	}
	return true
}

func TestWasi_CreationModeAppliesUmaskOnMemFS(t *testing.T) {
	w, m, _ := memTestStubs(t)
	exerciseCreationModes(t, w, m, 0)
}

// path_open_mode and path_create_directory_mode keep the setuid, setgid and
// sticky bits of the mode; the umask takes only permission bits out. A file
// that exists is opened as it is.
func TestWasi_CreationModeKeepsSpecialBits(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	less := uint32(hostTakesOut(t) | 0o022)
	w.Proc_umask(m, 0o022)
	if got, want := mkdirWithMode(t, w, m, "sticky", 0o1777), 0o1777&^less; got != want {
		t.Errorf("directory 01777 = %o, want %o", got, want)
	}
	// The sticky bit is set on a directory its owner may not read, too.
	if got, want := mkdirWithMode(t, w, m, "unreadable", 0o1333), 0o1333&^less; got != want {
		t.Errorf("directory 01333 = %o, want %o", got, want)
	}
	if got, want := createWithMode(t, w, m, "setgid", 0o2775), 0o2775&^less; got != want {
		t.Errorf("file 02775 = %o, want %o", got, want)
	}
	if got, want := createWithMode(t, w, m, "setgid", 0o4777), 0o2775&^less; got != want {
		t.Errorf("existing file opened with 04777 = %o, want it kept at %o", got, want)
	}
	// O_CREAT of a directory that is there is EISDIR, as open(2) has it.
	off, n := putPath(m, metaPathOff, "sticky")
	if rc := w.Path_open_mode(m, 0x1, off, n, 0x1 /* O_CREAT */, 1<<1, 0, 0o2775, metaOutOff); rc != -_wasiEISDIR {
		t.Errorf("O_CREAT of a directory with 02775 rc=%d, want -EISDIR", rc)
	}
	// A refusal of a bit to this user is told from any other failure.
	if !chmodRefused(&fs.PathError{Op: "chmod", Path: "f", Err: syscall.EPERM}) || chmodRefused(fs.ErrNotExist) {
		t.Error("chmodRefused does not tell EPERM from another error")
	}
	// A symbolic link to no file: the file it leads to is created, with the
	// bits, less the host process's umask as well without a creation thread
	// (openExactly).
	if err := os.Symlink("target", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	throughLink := less
	if !creationThreads(t) {
		throughLink |= uint32(hostUmask(t))
	}
	if got, want := createWithMode(t, w, m, "dangling", 0o2775), 0o2775&^throughLink; got != want {
		t.Errorf("file 02775 through a dangling link = %o, want %o", got, want)
	}
	if got, want := pathFilestatExt(t, w, m, "target").mode, 0o2775&^throughLink; got != want {
		t.Errorf("the file the link leads to = %o, want %o", got, want)
	}
}

// hostUmask returns the file mode creation mask of the host process: from
// /proc/self/status where it has it, otherwise from the mode of a file the
// host creates with 0777.
func hostUmask(t *testing.T) os.FileMode {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, rest, found := strings.Cut("\n"+string(status), "\nUmask:"); found {
		value, _, _ := strings.Cut(rest, "\n")
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		return os.FileMode(mask)
	}
	path := filepath.Join(t.TempDir(), "host")
	if err := os.WriteFile(path, nil, 0o777); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return 0o777 &^ fi.Mode().Perm()
}

// What an instance creates on the host's filesystem has its own umask
// taken out alone where the host process has another — the root's, given
// to HostProcessChanges — looser or stricter: files, directories and FIFOs,
// those its owner may not read and those with a sticky or setgid bit too,
// of the whole host filesystem and of HostFS(dir). A file that is there
// keeps its mode.
func TestWasi_CreationModeIsTheInstancesUnderAnotherHostUmask(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	if hostThreadUmask && !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	host := hostUmask(t)
	t.Cleanup(func() {
		if _, err := hostSetUmask(host); err != nil {
			t.Error(err)
		}
	})
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.ProcessChanges = HostProcessChanges()
	w.Proc_umask(m, 0o077)
	if got := hostUmask(t); got != 0o077 {
		t.Fatalf("the host process's umask is %o, want the root's 077", got)
	}
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	cm := newForkTestModule()
	mkfifo := func(t *testing.T, w *WasiStubs, m *Module, name string, mode int32) uint32 {
		t.Helper()
		off, n := putPath(m, metaPathOff, name)
		if rc := w.Path_mkfifo(m, off, n, mode); rc != _wasiESUCCESS {
			t.Fatalf("Path_mkfifo(%s, %o) rc=%d", name, mode, rc)
		}
		return pathFilestatExt(t, w, m, name).mode
	}
	type creation struct {
		root  bool
		umask int32
		name  string
		make  func(*testing.T, *WasiStubs, *Module, string, int32) uint32
		mode  int32
		want  uint32
	}
	both := []creation{
		{true, 0o077, "root", createWithMode, 0o666, 0o600},
		{false, 0o002, "file", createWithMode, 0o666, 0o664},
		{false, 0o002, "dir", mkdirWithMode, 0o777, 0o775},
		{false, 0o002, "unreadable", mkdirWithMode, 0o333, 0o331},
		{false, 0o002, "slashed/", mkdirWithMode, 0o777, 0o775},
		{false, 0o002, "sticky", mkdirWithMode, 0o1777, 0o1775},
		{false, 0, "root", createWithMode, 0o666, 0o600},
		{false, 0o177, "strict", createWithMode, 0o666, 0o600},
	}
	for _, c := range []struct {
		fsys      FS
		dir       string
		creations []creation
	}{
		{osFS{}, hostRelative(t, t.TempDir()) + "/", append(both,
			creation{false, 0o002, "fifo", mkfifo, 0o666, 0o664},
			creation{false, 0o002, "writeonly", mkfifo, 0o222, 0o220})},
		{newHostFS(t, t.TempDir()), "", append(both,
			creation{false, 0o002, "setgid", createWithMode, 0o2775, 0o2775})},
	} {
		w.cfg.FS, child.cfg.FS = c.fsys, c.fsys
		for _, cr := range c.creations {
			in, im := child, cm
			if cr.root {
				in, im = w, m
			}
			in.Proc_umask(im, cr.umask)
			if got := cr.make(t, in, im, c.dir+cr.name, cr.mode); got != cr.want {
				t.Errorf("%T: %s %o under umask %03o, the host process's 077: %o, want %o", c.fsys, cr.name, cr.mode, cr.umask, got, cr.want)
			}
		}
	}
}

// makeExactly leaves alone what is at the name once it is no longer what
// the call made: a symbolic link put there, whose target keeps its mode,
// nothing, or a file of another kind.
func TestMakeExactlyLeavesWhatReplacedTheMadeFile(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	fsys := osFS{dir: dir}
	for name, replace := range map[string]func(path string) error{
		"link": func(path string) error {
			return errors.Join(os.Remove(path), os.Symlink(target, path))
		},
		"link/": func(path string) error {
			return errors.Join(os.Remove(path), os.Symlink(target, strings.TrimSuffix(path, "/")))
		},
		"gone": os.Remove,
		"file": func(path string) error {
			return errors.Join(os.Remove(path), os.WriteFile(path, nil, 0o600))
		},
	} {
		err := makeExactly(fsys, name, os.ModeDir, 0o777, func(name string, perm os.FileMode) error {
			if err := fsys.Mkdir(name, perm); err != nil {
				return err
			}
			return replace(fsys.join(name))
		})
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if fi, err := os.Lstat(fsys.join(name)); err == nil && fi.Mode().Type() == 0 && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: the file put at the name has mode %o, want it kept at 600", name, fi.Mode().Perm())
		}
		if err := os.RemoveAll(fsys.join(strings.TrimSuffix(name, "/"))); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("the link's target has mode %o, want it kept at 700", fi.Mode().Perm())
	}
}

// The file mode creation mask a guest sets is its instance's: the mask of
// the host process stays as it was.
func TestWasi_UmaskIsTheInstancesOwn(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	host := hostUmask(t)
	w, m := newTestStubs(t, t.TempDir())
	if prev := w.Proc_umask(m, 0o077); prev != 0o022 {
		t.Fatalf("first umask returned %o, want the starting umask 022", prev)
	}
	if got := hostUmask(t); got != host {
		t.Fatalf("host umask = %o after the guest set its own, want %o", got, host)
	}
}

// The umask the root instance's guest sets goes to the ProcessChanges as
// well; a forked instance's is its own. Each instance's files get its own
// mask.
func TestWasi_UmaskOfTheRootGoesToTheProcessChanges(t *testing.T) {
	w, m, _ := memTestStubs(t)
	changes := &recordedChanges{}
	w.cfg.ProcessChanges = changes
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	cm := newForkTestModule()
	if prev := w.Proc_umask(m, 0o077); prev != 0o022 {
		t.Fatalf("umask returned %o, want the starting umask 022", prev)
	}
	if prev := child.Proc_umask(cm, 0o002); prev != 0o022 {
		t.Fatalf("the copy's umask returned %o, want the starting umask 022", prev)
	}
	if !slices.Equal(changes.umasks, []os.FileMode{0o077}) {
		t.Fatalf("the ProcessChanges was given %o, want the root's 077 alone", changes.umasks)
	}
	if got := createWithMode(t, w, m, "root", 0o666); got != 0o600 {
		t.Errorf("file 0666 of the root under 077: %o, want 600", got)
	}
	if got := createWithMode(t, child, cm, "copy", 0o666); got != 0o664 {
		t.Errorf("file 0666 of the copy under 002: %o, want 664", got)
	}
	changes.err = errors.New("refused")
	var told []error
	w.cfg.Errors = func(op string, err error) {
		if op == "proc_umask" {
			told = append(told, err)
		}
	}
	if prev := w.Proc_umask(m, 0o027); prev != 0o077 {
		t.Fatalf("umask returned %o, want 077", prev)
	}
	if len(told) != 1 || !errors.Is(told[0], changes.err) {
		t.Fatalf("errors told: %v, want the ProcessChanges's", told)
	}
}
