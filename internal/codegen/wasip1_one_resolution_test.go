//go:build darwin || linux

package codegen

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// swapFS is the whole host filesystem whose Lstat, once it has looked,
// calls swap with the name: the name changes between a look at it and the
// call that follows.
type swapFS struct {
	osFS
	swap  func(name string)
	swaps *int
}

func (f swapFS) Lstat(name string) (os.FileInfo, error) {
	fi, err := f.osFS.Lstat(name)
	if f.swap != nil {
		*f.swaps++
		f.swap(name)
	}
	return fi, err
}

// unlink and rmdir of the whole host filesystem are one call each: a name
// that becomes a directory after the guest looked is not looked at again,
// and the host refuses a directory to unlink and a file to rmdir.
func TestWasi_UnlinkAndRmdirAreOneCall(t *testing.T) {
	dir := t.TempDir()
	rel := hostRelative(t, dir)
	for _, name := range []string{"f", "g"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	swaps := 0
	// Were f looked at first, it would be an empty directory by the time
	// it is removed.
	fsys := swapFS{swaps: &swaps, swap: func(name string) {
		path := "/" + name
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Error(err)
		}
	}}
	w, m := newTestStubs(t, dir)
	w.cfg.FS = fsys
	call := func(what string, rc, want int32) {
		t.Helper()
		if rc != want {
			t.Errorf("%s rc=%d, want %d", what, rc, want)
		}
	}
	f, fn := putPath(m, 200, rel+"/f")
	call("unlink f", w.Path_unlink_file(m, 3, f, fn), _wasiESUCCESS)
	d, dn := putPath(m, 400, rel+"/d")
	call("unlink d", w.Path_unlink_file(m, 3, d, dn), _wasiEISDIR)
	g, gn := putPath(m, 600, rel+"/g")
	call("rmdir g", w.Path_remove_directory(m, 3, g, gn), _wasiENOTDIR)
	if swaps != 0 {
		t.Errorf("the names were looked at %d times before they were removed", swaps)
	}
	if _, err := os.Lstat(filepath.Join(dir, "f")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("f after its unlink: %v", err)
	}
	for _, name := range []string{"d", "g"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s after a refused removal: %v", name, err)
		}
	}
	call("rmdir d", w.Path_remove_directory(m, 3, d, dn), _wasiESUCCESS)
}

// A HostFS of a directory removes a name, in one call where the host has
// calls relative to a directory descriptor, and refuses the other kind of
// file.
func TestWasi_HostFSRemovesInOneCall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	fsys := newHostFS(t, dir)
	if err := fsys.Unlink("d"); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("Unlink of a directory: %v, want EISDIR", err)
	}
	if err := fsys.Rmdir("f"); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("Rmdir of a file: %v, want ENOTDIR", err)
	}
	if err := fsys.Unlink("../f"); err == nil {
		t.Error("Unlink of a name outside the root succeeded")
	}
	if err := errors.Join(fsys.Unlink("f"), fsys.Rmdir("d/")); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the directory after the removals: %v, %v", entries, err)
	}
}

// An open that does not follow a symbolic link is one call: a name that
// becomes a link after the guest looked is not followed (ELOOP).
func TestWasi_OpenWithoutFollowingIsOneCall(t *testing.T) {
	dir := t.TempDir()
	rel := hostRelative(t, dir)
	for _, name := range []string{"n", "target"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	swaps := 0
	fsys := swapFS{swaps: &swaps, swap: func(name string) {
		path := "/" + name
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("target", path); err != nil {
			t.Error(err)
		}
	}}
	w, _ := newTestStubs(t, dir)
	w.cfg.FS = fsys
	if _, errno := w.pathOpen(nil, rel+"/n", 0 /* no follow */, 0, 1<<1, 0); errno != _wasiELOOP {
		t.Errorf("open of a name that became a link errno=%d, want ELOOP", errno)
	}
	w.cfg.FS = osFS{}
	if _, errno := w.pathOpen(nil, rel+"/n", 0, 0, 1<<1, 0); errno != _wasiELOOP {
		t.Errorf("open of a link without following it errno=%d, want ELOOP", errno)
	}
	if _, errno := w.pathOpen(nil, rel+"/n", 1 /* follow */, 0, 1<<1, 0); errno != _wasiESUCCESS {
		t.Errorf("open of a link, following it, errno=%d", errno)
	}
	// An FS that wraps it passes O_NOFOLLOW on, and refuses a link alike.
	w.cfg.FS = bareFS{osFS{}}
	if _, errno := w.pathOpen(nil, rel+"/n", 0, 0, 1<<1, 0); errno != _wasiELOOP {
		t.Errorf("open of a link without following it, through a wrapper, errno=%d, want ELOOP", errno)
	}
	// A HostFS of a directory.
	w.cfg.FS = newHostFS(t, dir)
	if _, errno := w.pathOpen(nil, "n", 0, 0, 1<<1, 0); errno != _wasiELOOP {
		t.Errorf("HostFS(dir): open of a link without following it errno=%d, want ELOOP", errno)
	}
	if _, errno := w.pathOpen(nil, "target", 0, 0, 1<<1, 0); errno != _wasiESUCCESS {
		t.Errorf("HostFS(dir): open of a file without following errno=%d", errno)
	}
}

// swapRootFS is a HostFS of a directory whose Lstat, once it has looked,
// calls swap with the name.
type swapRootFS struct {
	rootFS
	swap func(name string)
}

func (f swapRootFS) Lstat(name string) (os.FileInfo, error) {
	fi, err := f.rootFS.Lstat(name)
	f.swap(name)
	return fi, err
}

// An open of a HostFS of a directory that does not follow a link at the
// end of a name opens nothing outside the root: a name with a trailing
// "/", which follows the link whatever O_NOFOLLOW says, goes through
// os.Root, also when the name became such a link after the guest looked.
func TestWasi_HostFSOpenWithoutFollowingStaysInTheRoot(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "esc")); err != nil {
		t.Fatal(err)
	}
	w, _ := newTestStubs(t, dir)
	if _, errno := w.pathOpen(nil, "esc/", 0 /* no follow */, 0x2 /* O_DIRECTORY */, 1<<1, 0); errno == _wasiESUCCESS {
		t.Error("open of esc/ opened the directory outside the root")
	}
	w.cfg.FS = swapRootFS{rootFS: newHostFS(t, dir).(rootFS), swap: func(name string) {
		if name != "d/" {
			return
		}
		if err := os.Remove(filepath.Join(dir, "d")); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "d")); err != nil {
			t.Error(err)
		}
	}}
	if _, errno := w.pathOpen(nil, "d/", 0, 0x2, 1<<1, 0); errno == _wasiESUCCESS {
		t.Error("open of d/, made a link out of the root after the look, opened the directory outside")
	}
}

// fd_filestat_set_times of a host file changes the file the descriptor is
// open on, not the file its name is given to since: through the
// descriptor on Linux, by the name the file has now on darwin.
func TestWasi_FdTimesOfTheDescriptor(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen(m, "a", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const mtime = int64(1_000_000_000_123_456_789)
	if rc := w.Fd_filestat_set_times(m, fd, 0, mtime, 0x4); rc != _wasiESUCCESS {
		t.Fatalf("rc=%d", rc)
	}
	b, err := os.Stat(filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if b.ModTime().UnixNano() != mtime {
		t.Errorf("mtime of the descriptor's file = %v, want %v", b.ModTime(), time.Unix(0, mtime))
	}
	a, err := os.Stat(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ModTime().UnixNano() == mtime {
		t.Error("the times were set on the file the name was given to")
	}
}

// fd_filestat_set_times of a host file that was removed, and whose name
// another file took since, leaves that other file as it is.
func TestWasi_FdTimesOfARemovedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "c"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen(m, "c", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if err := os.Remove(filepath.Join(dir, "c")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const mtime = int64(1_000_000_000_000_000_000)
	w.Fd_filestat_set_times(m, fd, 0, mtime, 0x4)
	c, err := os.Stat(filepath.Join(dir, "c"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ModTime().UnixNano() == mtime {
		t.Error("the times were set on the file that took the removed file's name")
	}
}

// fd_filestat_set_times of a file of a HostFS of a directory that was moved
// out of the root: through the descriptor where the host can (Linux), and
// where the times are set by the file's name (darwin) refused, the root
// having no name for it, rather than set outside the root.
func TestWasi_FdTimesOfAFileMovedOutOfTheRoot(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	fd, errno := w.pathOpen(m, "a", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(outside, "a")); err != nil {
		t.Fatal(err)
	}
	const mtime = int64(1_000_000_000_000_000_000)
	rc := w.Fd_filestat_set_times(m, fd, 0, mtime, 0x4)
	a, err := os.Stat(filepath.Join(outside, "a"))
	if err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "linux":
		if rc != _wasiESUCCESS || a.ModTime().UnixNano() != mtime {
			t.Errorf("rc=%d, mtime %v; want the descriptor's file set", rc, a.ModTime())
		}
	default:
		if rc != _wasiEACCES || a.ModTime().UnixNano() == mtime {
			t.Errorf("rc=%d, mtime %v; want EACCES and the file outside the root as it was", rc, a.ModTime())
		}
	}
}
