//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Every path call takes a directory descriptor other than the preopened
// root, and names a path relative to it; a descriptor that is no
// directory's is ENOTDIR, one that is not open EBADF.
func TestWasi_PathCallsRelativeToADirectory(t *testing.T) {
	for name, fsys := range map[string]func(t *testing.T, dir string) FS{
		"HostFS(dir)": func(t *testing.T, dir string) FS { return newHostFS(t, dir) },
		"MemFS":       func(t *testing.T, dir string) FS { return NewMemFS() },
	} {
		t.Run(name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			w.cfg.FS = fsys(t, t.TempDir())
			for _, d := range []string{"d", "e"} {
				if errno := w.pathCreateDirectory(nil, d, 0o755); errno != _wasiESUCCESS {
					t.Fatalf("mkdir %s errno=%d", d, errno)
				}
			}
			d, e := openTestDir(t, w, "d"), openTestDir(t, w, "e")
			at := int32(128)
			p := func(s string) (int32, int32) {
				off, n := putPath(m, at, s)
				at += 64
				return off, n
			}
			call := func(what string, rc, want int32) {
				t.Helper()
				if rc != want {
					t.Errorf("%s rc=%d, want %d", what, rc, want)
				}
			}
			x, xn := p("x")
			y, yn := p("y")
			sub, subn := p("sub")
			call("open d/x creating", w.Path_open(m, d, 0, x, xn, 0x1, 1<<6, 0, 0, 1000), _wasiESUCCESS)
			call("stat x from d", w.Path_filestat_get(m, d, 0, x, xn, 1100), _wasiESUCCESS)
			call("stat x from e", w.Path_filestat_get(m, e, 0, x, xn, 1100), _wasiENOENT)
			call("rename d/x to e/y", w.Path_rename(m, d, x, xn, e, y, yn), _wasiESUCCESS)
			call("mkdir e/sub", w.Path_create_directory(m, e, sub, subn), _wasiESUCCESS)
			call("set times of e/y", w.Path_filestat_set_times(m, e, 1, y, yn, 0, 0, 0x2|0x8), _wasiESUCCESS)
			call("unlink e/y", w.Path_unlink_file(m, e, y, yn), _wasiESUCCESS)
			call("rmdir e/sub", w.Path_remove_directory(m, e, sub, subn), _wasiESUCCESS)
			up, upn := p("../d")
			call("stat ../d from e", w.Path_filestat_get(m, e, 0, up, upn, 1100), _wasiESUCCESS)
			if _, err := w.fs().Stat("e/y"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("e/y after its unlink: %v", err)
			}
			file, errno := w.pathOpen(m, "f", 0, 0x1, 1<<6, 0)
			if errno != _wasiESUCCESS {
				t.Fatalf("open f errno=%d", errno)
			}
			call("stat x from a file", w.Path_filestat_get(m, file, 0, x, xn, 1100), _wasiENOTDIR)
			call("stat x from a closed descriptor", w.Path_filestat_get(m, 99, 0, x, xn, 1100), _wasiEBADF)
			// An empty name names nothing, not the directory itself; an
			// absolute one is the root's.
			empty, emptyn := p("")
			call("rmdir of an empty name from d", w.Path_remove_directory(m, d, empty, emptyn), _wasiENOENT)
			call("rename of d/x... to an empty name", w.Path_rename(m, e, up, upn, d, empty, emptyn), _wasiENOENT)
			call("stat of an empty name from d", w.Path_filestat_get(m, d, 0, empty, emptyn, 1100), _wasiENOENT)
			abs, absn := p("/e")
			call("stat of /e from d", w.Path_filestat_get(m, d, 0, abs, absn, 1100), _wasiESUCCESS)
			if _, err := w.fs().Stat("d"); err != nil {
				t.Errorf("d after the calls on an empty name: %v", err)
			}
			// A pipe has no path to go on from: d is not the root's.
			r, _ := newTestPipe(t, w, m)
			dName, dNameLen := p("d")
			call("stat d from a pipe", w.Path_filestat_get(m, r, 0, dName, dNameLen, 1100), _wasiENOTDIR)
		})
	}
}

// noRootFS is an OpenRootFS that opens no directory as an FS of its own
// (errors.ErrUnsupported); plainFS wraps an FS and is no OpenRootFS.
type noRootFS struct{ FS }
type plainFS struct{ FS }

func (noRootFS) OpenRoot(name string) (FS, error) {
	return nil, &fs.PathError{Op: "openroot", Path: name, Err: errors.ErrUnsupported}
}

// A name relative to a directory descriptor is given to the directory's FS
// (FS.OpenRoot), which the directory is found by wherever it is now:
// renamed, it still holds what is opened, made, looked at, renamed and
// removed through the descriptor. The FS of the directory is closed with
// the descriptor's last number.
func TestWasi_DirectoryDescriptorFollowsTheDirectory(t *testing.T) {
	for name, make := range map[string]func(t *testing.T, w *WasiStubs, dir string) (open string, rename func(from, to string)){
		"HostFS(/)": func(t *testing.T, w *WasiStubs, dir string) (string, func(from, to string)) {
			w.cfg.FS = osFS{}
			return hostRelative(t, dir) + "/", func(from, to string) { renameUnder(t, dir, from, to) }
		},
		"HostFS(dir)": func(t *testing.T, w *WasiStubs, dir string) (string, func(from, to string)) {
			w.cfg.FS = newHostFS(t, dir)
			return "", func(from, to string) { renameUnder(t, dir, from, to) }
		},
		"MemFS": func(t *testing.T, w *WasiStubs, dir string) (string, func(from, to string)) {
			mem := NewMemFS()
			w.cfg.FS = mem
			return "", func(from, to string) {
				if err := mem.Rename(from, to); err != nil {
					t.Fatal(err)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			w, m := newTestStubs(t, dir)
			prefix, rename := make(t, w, dir)
			if errno := w.pathCreateDirectory(nil, prefix+"d", 0o755); errno != _wasiESUCCESS {
				t.Fatalf("mkdir d errno=%d", errno)
			}
			d := openTestDir(t, w, prefix+"d")
			rename("d", "moved")
			at := int32(128)
			p := func(s string) (int32, int32) {
				off, n := putPath(m, at, s)
				at += 64
				return off, n
			}
			call := func(what string, rc, want int32) {
				t.Helper()
				if rc != want {
					t.Errorf("%s rc=%d, want %d", what, rc, want)
				}
			}
			x, xn := p("x")
			y, yn := p("y")
			sub, subn := p("sub")
			call("open x creating", w.Path_open(m, d, 0, x, xn, 0x1, 1<<6, 0, 0, 1000), _wasiESUCCESS)
			call("stat x", w.Path_filestat_get(m, d, 0, x, xn, 1100), _wasiESUCCESS)
			dot, dotn := p(".")
			call("stat . (the directory itself)", w.Path_filestat_get(m, d, 0, dot, dotn, 1100), _wasiESUCCESS)
			call("set the times of x", w.Path_filestat_set_times(m, d, 0, x, xn, 0, 0, 0x2|0x8), _wasiESUCCESS)
			call("rename x to y", w.Path_rename(m, d, x, xn, d, y, yn), _wasiESUCCESS)
			call("mkdir sub", w.Path_create_directory(m, d, sub, subn), _wasiESUCCESS)
			if _, err := w.fs().Stat(prefix + "moved/y"); err != nil {
				t.Errorf("y is not in the directory the descriptor is open on: %v", err)
			}
			if _, err := w.fs().Stat(prefix + "moved/sub"); err != nil {
				t.Errorf("sub is not in the directory the descriptor is open on: %v", err)
			}
			call("unlink y", w.Path_unlink_file(m, d, y, yn), _wasiESUCCESS)
			call("rmdir sub", w.Path_remove_directory(m, d, sub, subn), _wasiESUCCESS)
			call("unlink of the removed y", w.Path_unlink_file(m, d, y, yn), _wasiENOENT)
			// A name with ".." is found by the path the directory was opened
			// under, which leads nowhere now.
			up, upn := p("../moved")
			call("stat ../moved", w.Path_filestat_get(m, d, 0, up, upn, 1100), _wasiENOENT)
			if name == "MemFS" {
				return
			}
			target, targetn := p("x")
			l, ln := p("l")
			call("symlink l", w.Path_symlink(m, target, targetn, d, l, ln), _wasiESUCCESS)
			call("readlink l", w.Path_readlink(m, d, l, ln, 1200, 64, 1300), _wasiESUCCESS)
			// A link at the end of a name is not followed when the guest
			// says so.
			call("open of a link without following it", w.Path_open(m, d, 0, l, ln, 0x1, 1<<6, 0, 0, 1000), _wasiELOOP)
			if got, err := os.Readlink(filepath.Join(dir, "moved", "l")); err != nil || got != "x" {
				t.Errorf("l in the directory the descriptor is open on: %q, %v", got, err)
			}
		})
	}
}

// The FS of a directory a descriptor has is closed with the descriptor's
// last number; an FS that opens no directory as one of its own has the
// names found by the path the directory was opened under; a listing of the
// guest's own descriptors has none.
func TestWasi_DirectoryDescriptorFS(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	w.cfg.FS = newHostFS(t, dir)
	d := openTestDir(t, w, "d")
	w.mu.Lock()
	op := w.openLocked(d)
	w.mu.Unlock()
	root, ok := op.root.(hostDir)
	if !ok {
		t.Fatalf("the descriptor's FS is %T", op.root)
	}
	if rc := w.Fd_dup(m, d, 2000); rc != _wasiESUCCESS {
		t.Fatalf("dup rc=%d", rc)
	}
	dup := int32(binary.LittleEndian.Uint32(m.memory[2000:]))
	if rc := w.Fd_close(m, d); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	if _, err := root.f.Stat(); err != nil {
		t.Errorf("the directory's FS after one of two numbers is closed: %v", err)
	}
	if rc := w.Fd_close(m, dup); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	if _, err := root.f.Stat(); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("the directory's FS after the last number is closed: %v, want closed", err)
	}

	x, xn := putPath(m, 128, "x")
	for name, fsys := range map[string]FS{"no OpenRootFS": plainFS{newHostFS(t, dir)}, "ErrUnsupported": noRootFS{newHostFS(t, dir)}} {
		if err := os.RemoveAll(filepath.Join(dir, "moved")); err != nil {
			t.Fatal(err)
		}
		w.cfg.FS = fsys
		d = openTestDir(t, w, "d")
		if err := os.Rename(filepath.Join(dir, "d"), filepath.Join(dir, "moved")); err != nil {
			t.Fatal(err)
		}
		if rc := w.Path_open(m, d, 0, x, xn, 0x1, 1<<6, 0, 0, 1000); rc != _wasiENOENT {
			t.Errorf("%s: open by the directory's old path rc=%d, want ENOENT", name, rc)
		}
		if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if rc := w.Path_open(m, d, 0, x, xn, 0x1, 1<<6, 0, 0, 1000); rc != _wasiESUCCESS {
			t.Errorf("%s: open by the directory's path rc=%d", name, rc)
		}
		if _, err := os.Stat(filepath.Join(dir, "d", "x")); err != nil {
			t.Errorf("%s: x is not at the directory's path: %v", name, err)
		}
	}

	fdDir := openTestDir(t, w, "dev/fd")
	if rc := w.Path_open(m, fdDir, 0, x, xn, 0, 1<<1, 0, 0, 1000); rc != _wasiENOENT {
		t.Errorf("open of x from dev/fd rc=%d, want ENOENT", rc)
	}
}

// The FS of a directory of HostFS's makes the host's own calls: what it
// creates gets the kernel's umask, and its FIFO opens are the ones the host
// tells of (hostFiles); a MemFS's and a wrapper's do not.
func TestWasi_DirectoryFSOfTheHost(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	mem := NewMemFS()
	if err := mem.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	w, _ := newTestStubs(t, dir)
	for name, c := range map[string]struct {
		fsys FS
		host bool
	}{
		"HostFS(dir)": {openRoot(t, newHostFS(t, dir), "d"), true},
		"HostFS(/)":   {openRoot(t, osFS{}, hostRelative(t, dir)+"/d"), true},
		"MemFS":       {openRoot(t, mem, "d"), false},
		"a wrapper":   {plainFS{newHostFS(t, dir)}, false},
	} {
		if got := hostFiles(c.fsys); got != c.host {
			t.Errorf("%s: hostFiles = %v, want %v", name, got, c.host)
		}
		// create asks for the mode HostFS's FS is asked for, which the
		// kernel's umask takes from where the host can (hostThreadUmask),
		// and the mode less the umask for any other FS.
		asked := func(fsys FS) os.FileMode {
			var perm os.FileMode
			if err := w.create(fsys, 0o777, func(p os.FileMode, _ bool) error { perm = p; return nil }); err != nil {
				t.Fatal(err)
			}
			return perm
		}
		want := w.createMode(0o777)
		if c.host {
			want = asked(newHostFS(t, dir))
		}
		if got := asked(c.fsys); got != want {
			t.Errorf("%s: create asked for %o, want %o", name, got, want)
		}
	}
	// A FIFO opened for reading relative to a directory descriptor waits for
	// a writer as one opened by path does.
	if err := syscall.Mkfifo(filepath.Join(dir, "d", "p"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := newGuestModule(1 << 16)
	d := openTestDir(t, w, "d")
	p, pn := putPath(m, 128, "p")
	done := make(chan int32)
	go func() { done <- w.Path_open(m, d, 1, p, pn, 0, 1<<1, 0, 0, 1000) }()
	writer, err := os.OpenFile(filepath.Join(dir, "d", "p"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rc := <-done; rc != _wasiESUCCESS {
		t.Errorf("open of a FIFO for reading relative to a directory rc=%d", rc)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

// "." relative to a directory descriptor of the whole host filesystem
// without following is the directory itself, as fstatat(fd, ".",
// AT_SYMLINK_NOFOLLOW) and openat(fd, ".", O_NOFOLLOW) have it, and no
// link to read.
func TestWasi_DotOfADirectoryDescriptorOfTheWholeHost(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	w.cfg.FS = osFS{}
	d := openTestDir(t, w, hostRelative(t, dir)+"/d")
	dot, dotn := putPath(m, 128, ".")
	if rc := w.Path_filestat_get(m, d, 0, dot, dotn, 1100); rc != _wasiESUCCESS {
		t.Fatalf("stat . rc=%d", rc)
	}
	if ft := m.memory[1100+16]; ft != 3 {
		t.Errorf("stat . without following: filetype %d, want 3 (directory)", ft)
	}
	if rc := w.Path_open(m, d, 0, dot, dotn, 0x2, 1<<1, 0, 0, 1000); rc != _wasiESUCCESS {
		t.Errorf("open . O_DIRECTORY without following rc=%d", rc)
	}
	if rc := w.Path_readlink(m, d, dot, dotn, 1200, 64, 1300); rc != _wasiEINVAL {
		t.Errorf("readlink . rc=%d, want EINVAL", rc)
	}
}
