//go:build darwin || linux

package codegen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// hostFSOf is an FS of HostFS's whose names are those under dir, and the
// prefix that names dir in it: HostFS(dir) itself ("") or the whole host
// filesystem (dir's path).
type hostFSOf struct {
	name   string
	fsys   FS
	prefix string
}

// hostFSesOf returns HostFS(dir) and HostFS("/") with dir's prefix.
func hostFSesOf(t *testing.T, dir string) []hostFSOf {
	return []hostFSOf{{"HostFS(dir)", newHostFS(t, dir), ""}, {"HostFS(/)", osFS{}, hostRelative(t, dir) + "/"}}
}

// openRoot is fsys's OpenRoot of name, closed at the end of the test.
func openRoot(t *testing.T, fsys FS, name string) FS {
	t.Helper()
	sub, err := fsys.(OpenRootFS).OpenRoot(name)
	if err != nil {
		t.Fatalf("OpenRoot(%s): %v", name, err)
	}
	t.Cleanup(func() {
		if err := sub.Close(); err != nil {
			t.Error(err)
		}
	})
	return sub
}

// OpenRoot returns a directory as an FS of its own, whose names are
// relative to it and which keeps track of it across a rename, another
// directory taking its old name: of a HostFS of a directory, of the whole
// host filesystem and of a MemFS.
func TestWasi_OpenRootFollowsTheDirectory(t *testing.T) {
	type made struct {
		fsys   FS
		prefix string
		rename func(from, to string)
	}
	for name, make := range map[string]func(t *testing.T, dir string) made{
		"HostFS(dir)": func(t *testing.T, dir string) made {
			return made{newHostFS(t, dir), "", func(from, to string) { renameUnder(t, dir, from, to) }}
		},
		"HostFS(/)": func(t *testing.T, dir string) made {
			return made{osFS{}, hostRelative(t, dir) + "/", func(from, to string) { renameUnder(t, dir, from, to) }}
		},
		"MemFS": func(t *testing.T, dir string) made {
			mem := NewMemFS()
			return made{mem, "", func(from, to string) {
				if err := mem.Rename(from, to); err != nil {
					t.Fatal(err)
				}
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := make(t, t.TempDir())
			if err := m.fsys.Mkdir(m.prefix+"d", 0o755); err != nil {
				t.Fatal(err)
			}
			sub := openRoot(t, m.fsys, m.prefix+"d")
			m.rename("d", "moved")
			if err := m.fsys.Mkdir(m.prefix+"d", 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := sub.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := m.fsys.Stat(m.prefix + "moved/x"); err != nil {
				t.Errorf("x is not in the directory the FS is of: %v", err)
			}
			if _, err := m.fsys.Stat(m.prefix + "d/x"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("x in the directory that took the old name: %v", err)
			}
			if dir, ok := sub.(hostDir); ok && dir.in == nil {
				t.Error("a HostFS of a directory's directory FS has no os.Root of the directory")
			}
			if err := sub.Mkdir("y", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := sub.Unlink("y"); !errors.Is(err, syscall.EISDIR) {
				t.Errorf("Unlink of a directory: %v, want EISDIR", err)
			}
			if err := sub.Rmdir("x"); !errors.Is(err, syscall.ENOTDIR) {
				t.Errorf("Rmdir of a file: %v, want ENOTDIR", err)
			}
			if err := errors.Join(sub.Unlink("x"), sub.Rmdir("y")); err != nil {
				t.Fatal(err)
			}
			if _, err := m.fsys.(OpenRootFS).OpenRoot(m.prefix + "moved/none"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("OpenRoot of a missing directory: %v, want not-exist", err)
			}
		})
	}
}

// renameUnder renames from to to under dir, on the host.
func renameUnder(t *testing.T, dir, from, to string) {
	t.Helper()
	if err := os.Rename(filepath.Join(dir, from), filepath.Join(dir, to)); err != nil {
		t.Fatal(err)
	}
}

// An FS of a directory of a HostFS of a directory stays inside the root,
// where a symbolic link out of the directory leads; one of the whole host
// filesystem follows a symbolic link out of the directory, as the host
// does.
func TestWasi_OpenRootOfTheHost(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "d", "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../f", filepath.Join(dir, "d", "up")); err != nil {
		t.Fatal(err)
	}
	confined := openRoot(t, newHostFS(t, dir), "d")
	if _, err := confined.Stat("out"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Stat of a link out of a HostFS(dir)'s directory: %v, want a permission error", err)
	}
	// A link out of the directory that stays inside the root leads where
	// it points.
	if fi, err := confined.Stat("up"); err != nil || fi.Size() != 1 {
		t.Errorf("Stat of a link to a file of the root beside the directory: %v, %v", fi, err)
	}
	if err := confined.Chmod("up", 0o600); err != nil {
		t.Errorf("Chmod through a link to a file of the root beside the directory: %v", err)
	}
	whole := openRoot(t, osFS{}, hostRelative(t, dir)+"/d")
	f, err := whole.OpenFile("out", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open of a link out of a directory of the whole host: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := f.Read(buf); err != nil || buf[0] != 's' {
		t.Errorf("read through the link: %q, %v", buf, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := whole.Stat("out"); err != nil || fi.Size() != 1 {
		t.Errorf("Stat through the link: %v, %v", fi, err)
	}
}

// An FS of a directory of the whole host filesystem does what the host's
// calls relative to the directory do, not what os.Root does: a rename onto
// an empty directory replaces it, and an unlink of a directory is refused
// in one call (EISDIR), after the directory was renamed too.
func TestWasi_OpenRootOfTheWholeHostIsTheHosts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"d", "d/a", "d/b", "d/sub"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sub := openRoot(t, osFS{}, hostRelative(t, dir)+"/d")
	renameUnder(t, dir, "d", "moved")
	if err := sub.Rename("a", "b"); err != nil {
		t.Errorf("rename of a directory onto an empty one: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "moved", "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a after its rename: %v", err)
	}
	if err := sub.Unlink("sub"); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("Unlink of a directory: %v, want EISDIR", err)
	}
	if err := sub.Rmdir("sub"); err != nil {
		t.Errorf("Rmdir: %v", err)
	}
}

// A HostFS of a directory's FS of one of its directories finds a name a
// symbolic link leads out of the directory with from where the directory
// is now: moved, the link leads from its new place, not from the old one,
// which another directory has taken.
func TestWasi_OpenRootFollowsALinkOutFromWhereItIs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "sib", "b", "b/sib"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sib/x", "b/sib/x"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../sib", filepath.Join(dir, "a", "lnk")); err != nil {
		t.Fatal(err)
	}
	sub := openRoot(t, newHostFS(t, dir), "a")
	renameUnder(t, dir, "a", "b/a")
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sib", filepath.Join(dir, "a", "lnk")); err != nil {
		t.Fatal(err)
	}
	if err := sub.Unlink("lnk/x"); err != nil {
		t.Fatalf("Unlink(lnk/x): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b", "sib", "x")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("b/sib/x, where the link leads from the directory now: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sib", "x")); err != nil {
		t.Errorf("sib/x, where the link led from the directory's old place: %v", err)
	}
	// A directory moved out of the root has no name of the root a link out
	// of it leads to.
	outside := t.TempDir()
	if err := os.Rename(filepath.Join(dir, "b", "a"), filepath.Join(outside, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.Stat("lnk"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Stat(lnk) of a directory moved out of the root: %v, want a permission error", err)
	}
}

// A MemFS of one of its directories whose directory was removed has no
// names, as a removed directory of the host has none.
func TestWasi_MemFSOpenRootOfARemovedDirectory(t *testing.T) {
	mem := NewMemFS()
	if err := mem.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	sub := openRoot(t, mem, "d")
	if err := mem.Rmdir("d"); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o644); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("create in a removed directory: %v, want not-exist", err)
	}
	if _, err := sub.Stat("."); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat of a removed directory: %v, want not-exist", err)
	}
}

// Lchtimes sets the times of a symbolic link itself and leaves its target's
// as they are; where the host has no call for that it refuses a link
// (ErrUnsupported) and sets a file's times. A zero time leaves that time
// as it is, as os.Chtimes has it. path_filestat_set_times without
// SYMLINK_FOLLOW is Lchtimes.
func TestWasi_LchtimesOfALink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_000_000_000, 0)
	for _, h := range hostFSesOf(t, dir) {
		err := h.fsys.Lchtimes(h.prefix+"l", mtime, mtime)
		target, terr := os.Stat(filepath.Join(dir, "f"))
		if terr != nil {
			t.Fatal(terr)
		}
		if target.ModTime().Equal(mtime) {
			t.Errorf("%s: Lchtimes of the link set its target's times", h.name)
		}
		switch runtime.GOOS {
		case "linux":
			link, lerr := os.Lstat(filepath.Join(dir, "l"))
			if err != nil || lerr != nil || !link.ModTime().Equal(mtime) {
				t.Errorf("%s: Lchtimes of the link: %v, %v; its mtime %v", h.name, err, lerr, link.ModTime())
			}
		default:
			if !errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("%s: Lchtimes of the link: %v, want ErrUnsupported", h.name, err)
			}
		}
		if err := h.fsys.Lchtimes(h.prefix+"f", mtime, mtime); err != nil {
			t.Errorf("%s: Lchtimes of a file: %v", h.name, err)
		}
		if err := h.fsys.Lchtimes(h.prefix+"f", time.Now(), time.Time{}); err != nil {
			t.Errorf("%s: Lchtimes of a file with a zero mtime: %v", h.name, err)
		}
		if fi, err := os.Stat(filepath.Join(dir, "f")); err != nil || !fi.ModTime().Equal(mtime) {
			t.Errorf("%s: mtime after Lchtimes with a zero mtime: %v, %v; want it left at %v", h.name, fi, err, mtime)
		}
		if err := os.Chtimes(filepath.Join(dir, "f"), time.Now(), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	w, m := newTestStubs(t, dir)
	off, n := putPath(m, 200, "l")
	rc := w.Path_filestat_set_times(m, 3, 0 /* no follow */, off, n, 0, mtime.UnixNano(), 0x4)
	target, err := os.Stat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if target.ModTime().Equal(mtime) {
		t.Error("path_filestat_set_times without following set the target's times")
	}
	if want := map[bool]int32{true: _wasiESUCCESS, false: _wasiENOSYS}[runtime.GOOS == "linux"]; rc != want {
		t.Errorf("path_filestat_set_times of a link without following rc=%d, want %d", rc, want)
	}
}

// A MemFS keeps no owners: Chown, Lchown and its files' Chown are
// errors.ErrUnsupported (ENOSYS to the guest).
func TestWasi_MemFSHasNoOwners(t *testing.T) {
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := mem.OpenFile("f", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"Chown": mem.Chown("f", 1, 1), "Lchown": mem.Lchown("f", 1, 1), "File.Chown": f.Chown(1, 1),
	} {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", name, err)
		}
	}
	if err := errors.Join(f.Close(), mem.Close()); err != nil {
		t.Fatal(err)
	}
	w := NewWASI(WASIConfig{FS: mem})
	m := newGuestModule(1 << 16)
	off, n := putPath(m, 200, "f")
	if rc := w.Path_chown(m, off, n, 1, 1, 1); rc != -_wasiENOSYS {
		t.Errorf("chown of a MemFS file rc=%d, want -ENOSYS", rc)
	}
}

// Lchtimes of a name with a trailing "/" whose symbolic link leads out of
// a HostFS of a directory is refused, and the directory outside keeps its
// times.
func TestWasi_LchtimesOfALinkOutWithASlash(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "dl")); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_000_000_000, 0)
	if err := newHostFS(t, dir).Lchtimes("dl/", mtime, mtime); err == nil {
		t.Error("Lchtimes of dl/ leading out of the root succeeded")
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Equal(mtime) {
		t.Error("Lchtimes of dl/ set the times of the directory outside the root")
	}
}

// OpenRoot of a directory that may be read but not searched succeeds, as
// os.Root's does: what is in it is listed, and its names are refused.
func TestWasi_OpenRootOfADirectoryWithoutSearch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "d"), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(filepath.Join(dir, "d"), 0o755); err != nil {
			t.Error(err)
		}
	})
	for _, h := range hostFSesOf(t, dir) {
		sub := openRoot(t, h.fsys, h.prefix+"d")
		if _, err := sub.Stat("f"); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s: Stat of a name in it: %v, want a permission error", h.name, err)
		}
	}
}

// "." of an FS of a directory of the whole host filesystem is the
// directory itself, as "." relative to its descriptor is: no symbolic link
// (/proc/self/fd/N is one on Linux), opened without following, no link to
// read.
func TestWasi_DotOfADirectoryOfTheWholeHost(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := openRoot(t, osFS{}, hostRelative(t, dir)+"/d")
	if fi, err := sub.Lstat("."); err != nil || !fi.IsDir() {
		t.Errorf("Lstat(.): %v, %v; want the directory", fi, err)
	}
	f, err := sub.OpenFile(".", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Errorf("open of . without following: %v", err)
	} else if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.Readlink("."); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Readlink(.): %v, want EINVAL", err)
	}
}

// Close of a HostFS of a directory's directory FS closes the os.Root of
// the directory with the directory's file.
func TestWasi_CloseOfADirectoryFSOfAHostFS(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub, err := newHostFS(t, dir).(OpenRootFS).OpenRoot("d")
	if err != nil {
		t.Fatal(err)
	}
	d := sub.(hostDir)
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.in.root.Stat("."); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("the os.Root of the directory after Close: %v, want closed", err)
	}
	if _, err := d.f.Stat(); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("the directory's file after Close: %v, want closed", err)
	}
}
