package codegen

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// FSAccess is given the path cleaned as chroot(2) sees it: ".." of the
// root is the root.
func TestWasi_FSAccessSeesTheCleanedPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	var seen []string
	w.cfg.FSAccess = func(path string, write bool) bool {
		seen = append(seen, path)
		return path != "secret"
	}
	for _, tc := range []struct {
		path string
		rc   int32
		seen []string
	}{
		{"pub/../secret", _wasiEACCES, []string{"secret"}},
		{"./secret/", _wasiEACCES, []string{"secret"}},
		{"/secret", _wasiEACCES, []string{"secret"}},
		{"../secret", _wasiEACCES, []string{"secret"}},
		{"pub/../../secret", _wasiEACCES, []string{"secret"}},
		{"", _wasiESUCCESS, []string{"."}},
		// The FS is given what the hook approved: the root.
		{"..", _wasiESUCCESS, []string{"."}},
	} {
		seen = nil
		off, n := putPath(m, 128, tc.path)
		if rc := w.Path_filestat_get(m, 3, 0, off, n, 300); rc != tc.rc || !slices.Equal(seen, tc.seen) {
			t.Errorf("Path_filestat_get(%q) rc=%d, hook saw %v; want %d after %v", tc.path, rc, seen, tc.rc, tc.seen)
		}
	}
}

// pathWalkDir lays out, under a new directory: file, a/link -> ../b/sub,
// b/sub/ and b/f, so that "a/link/../f" is b/f for the system and a/f
// lexically.
func pathWalkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"a", "b/sub"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"file", "b/f"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../b/sub", filepath.Join(dir, "a", "link")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	return dir
}

// testGuestPathWalk checks, under prefix, what the FS is given. Without
// FSAccess it is the guest's path as written: the system resolves ".."
// after a symbolic link, and a trailing "/" asks for a directory. With
// FSAccess it is the cleaned path the hook approved: "a/link/../f" is a/f,
// which does not exist, and "file/" still asks for a directory.
func testGuestPathWalk(t *testing.T, w *WasiStubs, m *Module, prefix string) {
	t.Helper()
	off, n := putPath(m, 128, prefix+"a/link/../f")
	if rc := w.Path_open(m, 3, 0, off, n, 0, 1<<1, 0, 0, 300); rc != _wasiESUCCESS {
		t.Errorf("open(a/link/../f) rc=%d, want it to reach b/f", rc)
	}
	slash, slashLen := putPath(m, 512, prefix+"file/")
	if rc := w.Path_unlink_file(m, 3, slash, slashLen); rc != _wasiENOTDIR {
		t.Errorf("unlink(file/) rc=%d, want ENOTDIR", rc)
	}

	w.cfg.FSAccess = func(string, bool) bool { return true }
	defer func() { w.cfg.FSAccess = nil }()
	if rc := w.Path_open(m, 3, 0, off, n, 0, 1<<1, 0, 0, 300); rc != _wasiENOENT {
		t.Errorf("with FSAccess, open(a/link/../f) rc=%d, want ENOENT (a/f)", rc)
	}
	if rc := w.Path_unlink_file(m, 3, slash, slashLen); rc != _wasiENOTDIR {
		t.Errorf("with FSAccess, unlink(file/) rc=%d, want ENOTDIR", rc)
	}
	dot, dotLen := putPath(m, 512, prefix+"file/.")
	if rc := w.Path_unlink_file(m, 3, dot, dotLen); rc != _wasiENOTDIR {
		t.Errorf("with FSAccess, unlink(file/.) rc=%d, want ENOTDIR", rc)
	}
}

// On the whole host filesystem the guest's path is the host's: "/.." is
// "/", and paths through symbolic links resolve as the system does.
func TestWasi_WholeHostGuestPaths(t *testing.T) {
	dir := pathWalkDir(t)
	m := newGuestModule(1 << 16)
	var seen []string
	w := NewWASI(WASIConfig{FS: newHostFS(t, "/"), FSAccess: func(path string, write bool) bool {
		seen = append(seen, fmt.Sprintf("%s:%v", path, write))
		return filepath.Base(path) != "lnk"
	}})

	// stat("/..") and chdir("..") at "/" are the root.
	off, n := putPath(m, 128, "..")
	if rc := w.Path_filestat_get(m, 3, 1, off, n, 300); rc != _wasiESUCCESS || m.memory[316] != 3 {
		t.Errorf(`stat("/..") rc=%d type=%d, want the root directory`, rc, m.memory[316])
	}
	if rc := w.Path_open(m, 3, 0, off, n, 0x2, 1<<1, 0, 0, 300); rc != _wasiESUCCESS {
		t.Errorf(`open("..", O_DIRECTORY) at "/" rc=%d`, rc)
	}
	if !slices.Equal(seen, []string{".:false", ".:false"}) {
		t.Errorf("the hook saw %v, want the root twice", seen)
	}

	// symlink("../x", "lnk") at the root: the hook sees the target
	// resolved against the root, where ".." is the root.
	seen = nil
	toff, tn := putPath(m, 128, "../x")
	loff, ln := putPath(m, 256, "lnk")
	if rc := w.Path_symlink(m, toff, tn, 3, loff, ln); rc != _wasiEACCES {
		t.Errorf("symlink rc=%d, want the hook's EACCES", rc)
	}
	if !slices.Equal(seen, []string{"lnk:true", "x:false", "x:true"}) {
		t.Errorf("the hook saw %v, want the link and the target x", seen)
	}

	w.cfg.FSAccess = nil
	testGuestPathWalk(t, w, m, hostRelative(t, dir)+"/") // a prefix of raw names: not path.Join, which would fold their ".."
}

// Under HostFS of a directory, os.Root keeps every path inside it: an
// escape through "..", an absolute symbolic link or a relative one is
// EACCES; paths inside resolve as the system does.
func TestWasi_HostFSRootContainment(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := pathWalkDir(t)
	if err := os.Symlink(filepath.Join(outside, "f"), filepath.Join(dir, "abs")); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dir, filepath.Join(outside, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, filepath.Join(dir, "rel")); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	for _, name := range []string{"../f", "a/../../f", "abs", "rel"} {
		off, n := putPath(m, 128, name)
		if rc := w.Path_open(m, 3, 1, off, n, 0, 1<<1, 0, 0, 300); rc != _wasiEACCES {
			t.Errorf("open(%s) rc=%d, want EACCES", name, rc)
		}
	}
	// os.Root's refusal is EACCES.
	if _, err := w.fs().Stat("../f"); mapOSError(err) != _wasiEACCES {
		t.Errorf("the escape error %v maps to %d, want EACCES", err, mapOSError(err))
	}
	// A link the guest makes may point anywhere; the guest cannot follow
	// it out of the root.
	for _, link := range [][2]string{{"../x", "lnk"}, {"/etc/passwd", "a/lnk"}} {
		toff, tn := putPath(m, 128, link[0])
		loff, ln := putPath(m, 256, link[1])
		if rc := w.Path_symlink(m, toff, tn, 3, loff, ln); rc != _wasiESUCCESS {
			t.Errorf("symlink(%s, %s) rc=%d", link[0], link[1], rc)
		}
		if rc := w.Path_filestat_get(m, 3, 1, loff, ln, 300); rc != _wasiEACCES {
			t.Errorf("stat through %s -> %s rc=%d, want EACCES", link[1], link[0], rc)
		}
	}
	testGuestPathWalk(t, w, m, "")
}

// fd_path names a directory by its canonical path.
func TestWasi_FdPathIsCanonical(t *testing.T) {
	w, m := newTestStubs(t, pathWalkDir(t))
	fdPath := func(name, want string) {
		t.Helper()
		fd, errno := w.pathOpen(name, 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("pathOpen(%q) errno=%d", name, errno)
		}
		if rc := w.Fd_path(m, fd, 300, 64, 400); rc != _wasiESUCCESS || string(m.memory[300:300+readU32(m.memory, 400)]) != want {
			t.Errorf("Fd_path of %q rc=%d = %q, want %q", name, rc, m.memory[300:300+readU32(m.memory, 400)], want)
		}
	}
	// "." and empty components go; ".." stays, as it may follow a link.
	for name, want := range map[string]string{"": "/", ".": "/", "b/./sub//": "/b/sub", "a/link/..": "/a/link/.."} {
		fdPath(name, want)
	}
	// With FSAccess the descriptor was opened under the approved name.
	w.cfg.FSAccess = func(string, bool) bool { return true }
	fdPath("b/sub/../", "/b")
}

// The root of a HostFS of a directory is the directory os.Root holds:
// opened twice, each is an open of its own (with an offset of its own),
// and closing one leaves the FS working.
func TestWasi_HostFSRootItself(t *testing.T) {
	dir := t.TempDir()
	fsys := newHostFS(t, dir)
	a, err := fsys.OpenFile(".", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fsys.OpenFile("", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.(*os.File).Fd() == b.(*os.File).Fd() {
		t.Error("two opens of the root share a descriptor")
	}
	// Both list the whole directory, one after the other.
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []File{a, b, a} {
		list, ok, err := hostDirListing(f, false)
		if err != nil || !ok || len(list) != 3 {
			t.Errorf("listing of the root: %d names, %v, %v; want ., .. and f", len(list), ok, err)
		}
	}
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		t.Fatal(err)
	}
	if st, err := fsys.Stat(""); err != nil || !st.IsDir() {
		t.Errorf("Stat of the root after closing its opens: %v, %v", st, err)
	}
	if _, err := fsys.OpenFile(".", os.O_RDWR, 0); err == nil {
		t.Error("the root opened for writing")
	}
}

// fd_filestat_set_times sets the times by the descriptor's path, which
// FSAccess is asked about as a write, whatever the descriptor is open for:
// a read-only one and a directory one work. A pipe end has no path, and
// the root descriptor has no file: neither has the right.
func TestWasi_FdFilestatSetTimesByPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	open := func(name string, oflags int32) int32 {
		t.Helper()
		off, n := putPath(m, 128, name)
		if rc := w.Path_open(m, 3, 0, off, n, oflags, 1<<1, 0, 0, 300); rc != _wasiESUCCESS {
			t.Fatalf("Path_open(%s) rc=%d", name, rc)
		}
		return int32(readU32(m.memory, 300))
	}
	const mtime = int64(1_000_000_000_000_000_000)
	setTimes := func(fd int32) int32 { return w.Fd_filestat_set_times(m, fd, 0, mtime, 0x4) }
	const setTimesRight = uint64(1) << 23

	for name, fd := range map[string]int32{"f": open("f", 0), "d": open("d", 0x2)} {
		if rc := w.Fd_fdstat_get(m, fd, 400); rc != _wasiESUCCESS || readU64(m.memory, 408)&setTimesRight == 0 {
			t.Errorf("fdstat of read-only %s rc=%d lacks fd_filestat_set_times", name, rc)
		}
		if rc := setTimes(fd); rc != _wasiESUCCESS {
			t.Fatalf("read-only %s rc=%d", name, rc)
		}
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.ModTime().UnixNano() != mtime {
			t.Errorf("mtime of %s = %v (%v), want %d", name, st.ModTime(), err, mtime)
		}
	}
	var seen []string
	w.cfg.FSAccess = func(path string, write bool) bool {
		seen = append(seen, fmt.Sprintf("%s:%v", path, write))
		return !write
	}
	if rc := setTimes(open("f", 0)); rc != _wasiEACCES || !slices.Equal(seen, []string{"f:false", "f:true"}) {
		t.Errorf("writes denied rc=%d, hook saw %v; want EACCES after the open and f as a write", rc, seen)
	}
	w.cfg.FSAccess = nil
	r, wr := newTestPipe(t, w, m)
	for _, fd := range []int32{r, wr} {
		if rc := setTimes(fd); rc != _wasiEBADF {
			t.Errorf("pipe end %d rc=%d, want EBADF", fd, rc)
		}
	}
	if rc := setTimes(wasiPreopenFD); rc != _wasiEBADF {
		t.Errorf("root descriptor rc=%d, want EBADF", rc)
	}
	if rc := w.Fd_fdstat_get(m, wasiPreopenFD, 400); rc != _wasiESUCCESS || readU64(m.memory, 408) != wasiRootRights {
		t.Errorf("root rights rc=%d = %#x, want %#x", rc, readU64(m.memory, 408), wasiRootRights)
	}

	// A MemFS file sets its own times, once the hook allows the write.
	mem := NewMemFS()
	if err := mem.WriteFile("f", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = mem
	memFd := open("f", 0)
	w.cfg.FSAccess = func(_ string, write bool) bool { return !write }
	if rc := setTimes(memFd); rc != _wasiEACCES {
		t.Errorf("MemFS descriptor, writes denied rc=%d, want EACCES", rc)
	}
	w.cfg.FSAccess = nil
	if rc := setTimes(memFd); rc != _wasiESUCCESS {
		t.Fatalf("MemFS descriptor rc=%d", rc)
	}
	if st, err := mem.Stat("f"); err != nil || st.ModTime().UnixNano() != mtime {
		t.Errorf("MemFS mtime = %v (%v), want %d", st.ModTime(), err, mtime)
	}
}

// dup2 or renumber onto fd 3 is allowed; the preopen at 3 is then gone
// for good, in a fork too, and wasiRootFD still names the root.
func TestWasi_Dup2OntoTheRootDescriptor(t *testing.T) {
	for name, move := range map[string]func(w *WasiStubs, m *Module) int32{
		"dup2":     func(w *WasiStubs, m *Module) int32 { return w.Fd_dup2(m, 1, wasiPreopenFD) },
		"renumber": func(w *WasiStubs, m *Module) int32 { return w.Fd_renumber(m, 1, wasiPreopenFD) },
	} {
		t.Run(name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			if rc := move(w, m); rc != _wasiESUCCESS {
				t.Fatalf("rc=%d", rc)
			}
			for _, s := range []*WasiStubs{w, w.Fork()} {
				if rc := s.Fd_prestat_get(m, wasiPreopenFD, 100); rc != _wasiEBADF {
					t.Errorf("Fd_prestat_get(3) rc=%d, want EBADF", rc)
				}
				if rc := s.Fd_fdstat_get(m, wasiPreopenFD, 400); rc != _wasiESUCCESS || m.memory[400] != 2 {
					t.Errorf("fd 3 rc=%d type=%d, want the standard output", rc, m.memory[400])
				}
				off, n := putPath(m, 128, ".")
				if rc := s.Path_filestat_get(m, wasiPreopenFD, 0, off, n, 300); rc != _wasiEBADF {
					t.Errorf("a path call on fd 3 rc=%d, want EBADF", rc)
				}
				if rc := s.Path_filestat_get(m, wasiRootFD, 0, off, n, 300); rc != _wasiESUCCESS {
					t.Errorf("a path call on the root number rc=%d", rc)
				}
			}
			// Closed, 3 is a free number like any other.
			if rc := w.Fd_close(m, wasiPreopenFD); rc != _wasiESUCCESS {
				t.Fatalf("Fd_close(3) rc=%d", rc)
			}
			if rc := w.Fd_fdstat_get(m, wasiPreopenFD, 400); rc != _wasiEBADF {
				t.Errorf("Fd_fdstat_get(3) after close(3) rc=%d, want EBADF", rc)
			}
			if rc := w.Fd_dupfd(m, 0, wasiPreopenFD, 500); rc != _wasiESUCCESS || readU32(m.memory, 500) != uint32(wasiPreopenFD) {
				t.Errorf("fcntl(0, F_DUPFD, 3) rc=%d fd=%d, want 3", rc, readU32(m.memory, 500))
			}
		})
	}
}

// Every operation of a HostFS of a directory turns os.Root's refusal of
// an escape into fs.ErrPermission (EACCES), and leaves other errors as
// they are.
func TestWasi_HostFSEscapeIsPermission(t *testing.T) {
	fsys := newHostFS(t, t.TempDir())
	_, openErr := fsys.OpenFile("../x", os.O_RDONLY, 0)
	_, statErr := fsys.Stat("../x")
	_, lstatErr := fsys.Lstat("../x")
	_, readlinkErr := fsys.Readlink("../x")
	for name, err := range map[string]error{
		"OpenFile": openErr,
		"Mkdir":    fsys.Mkdir("../x", 0o755),
		"Chmod":    fsys.Chmod("../x", 0o644),
		"Chtimes":  fsys.Chtimes("../x", time.Time{}, time.Time{}),
		"Chown": fsys.(interface {
			Chown(string, int, int, bool) error
		}).Chown("../x", -1, -1, false),
		"Remove":   fsys.Remove("../x"),
		"Rename":   fsys.Rename("../x", "y"),
		"Stat":     statErr,
		"Lstat":    lstatErr,
		"Symlink":  fsys.Symlink("t", "../x"),
		"Readlink": readlinkErr,
		"Link":     fsys.Link("../x", "y"),
	} {
		if !errors.Is(err, fs.ErrPermission) || mapOSError(err) != _wasiEACCES {
			t.Errorf("%s: %v (errno %d), want EACCES", name, err, mapOSError(err))
		}
	}
	if _, err := fsys.Stat("missing"); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		t.Errorf("Stat of a missing file: %v, want not-exist only", err)
	}
}

// HostFS of a directory needs one that may be searched, as everything of
// it goes through os.Root; the whole host filesystem lists a directory
// that may be read but not searched.
func TestWasi_HostFSNeedsASearchableRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is not held to the permissions of a directory")
	}
	dir := filepath.Join(t.TempDir(), "readable")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Errorf("chmod %s: %v", dir, err)
		}
	})
	if _, err := HostFS(dir); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("HostFS of a directory that cannot be searched: %v, want a permission error", err)
	}
}
