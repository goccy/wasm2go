//go:build darwin || linux

package codegen

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// wrappedFS wraps the whole host filesystem and keeps what it can do by
// implementing its optional interfaces and calling its methods.
type wrappedFS struct{ FS }

func (f wrappedFS) Chown(name string, uid, gid int, follow bool) error {
	return f.FS.(ChownFS).Chown(name, uid, gid, follow)
}
func (f wrappedFS) Mkfifo(name string, perm os.FileMode) error {
	return f.FS.(MkfifoFS).Mkfifo(name, perm)
}
func (f wrappedFS) Flock(file File, how int) error { return f.FS.(LockFS).Flock(file, how) }
func (f wrappedFS) Access(name string, mode uint32, effective bool) error {
	return f.FS.(AccessFS).Access(name, mode, effective)
}
func (f wrappedFS) HostRoot() string { return f.FS.(HostRootFS).HostRoot() }

// bareFS wraps the whole host filesystem with none of its optional
// interfaces.
type bareFS struct{ FS }

// What an FS can do is what its optional interfaces say: an FS that wraps
// the whole host filesystem and implements them works as that one does,
// one that does not has none of it.
func TestWasi_OptionalFSInterfacesOfAWrapper(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "locked"), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	rel := hostRelative(t, dir)
	for _, tc := range []struct {
		name string
		fsys FS
		can  bool
	}{{"wrapped", wrappedFS{osFS{}}, true}, {"bare", bareFS{osFS{}}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newTestStubs(t, dir)
			w.cfg.FS = tc.fsys
			want := func(what string, rc, can, cannot int32) {
				t.Helper()
				if tc.can && rc != can || !tc.can && rc != cannot {
					t.Errorf("%s rc=%d, want %d", what, rc, map[bool]int32{true: can, false: cannot}[tc.can])
				}
			}
			off, n := putPath(m, 200, rel+"/f")
			want("chown", w.Path_chown(m, off, n, -1, -1, 1), _wasiESUCCESS, -_wasiENOSYS)
			fifo, fifon := putPath(m, 400, rel+"/q-"+tc.name)
			want("mkfifo", w.Path_mkfifo(m, fifo, fifon, 0o600), _wasiESUCCESS, -_wasiENOSYS)
			fd, errno := w.pathOpen(m, rel+"/f", 0, 0, 1<<1, 0)
			if errno != _wasiESUCCESS {
				t.Fatalf("open f errno=%d", errno)
			}
			want("flock", w.Fd_flock(m, fd, flockExclusive, 0), _wasiESUCCESS, -_wasiENOSYS)
			// The isolated Process is user 0, whom the mode bits let read
			// anything; the host, asked, does not let this user read a file
			// of mode 000.
			if os.Geteuid() != 0 {
				locked, lockedn := putPath(m, 600, rel+"/locked")
				want("access", w.Path_access(m, locked, lockedn, wasiAccessRead, 0), -_wasiEACCES, _wasiESUCCESS)
			}
			sock, errno := w.unixHostPath(wasiSockAddr{family: wasiSockFamilyUnix, name: "/" + rel + "/s"}, rel+"/s")
			want("a Unix-domain socket's path", errno, _wasiESUCCESS, _wasiENOTSUP)
			if tc.can && sock != filepath.Join(dir, "s") {
				t.Errorf("the socket's host path = %q, want %q", sock, filepath.Join(dir, "s"))
			}
			if runtime.GOOS != "linux" {
				return // the host has no link of its own for a descriptor
			}
			// The link of a standard stream that is a host file is the
			// file's name in the FS; without one the file is no link.
			out, err := os.Create(filepath.Join(dir, "out-"+tc.name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := out.Close(); err != nil {
					t.Error(err)
				}
			})
			w.cfg.Stdout = out
			link, linkn := putPath(m, 700, "dev/fd/1")
			rc := w.Path_readlink(m, 3, link, linkn, 800, 200, 1000)
			want("readlink dev/fd/1", rc, _wasiESUCCESS, _wasiEINVAL)
			if got := string(m.memory[800 : 800+readU32(m.memory, 1000)]); tc.can && got != "/"+rel+"/out-"+tc.name {
				t.Errorf("readlink dev/fd/1 = %q, want the file's name", got)
			}
		})
	}
}

// chownFile is a MemFS file whose owner is changed through it: it counts
// the changes.
type chownFile struct {
	File
	changes *int
}

func (f chownFile) Chown(uid, gid int) error { *f.changes++; return nil }

// chownFilesFS is a MemFS whose files are chownFiles.
type chownFilesFS struct {
	*MemFS
	changes *int
}

func (f chownFilesFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	file, err := f.MemFS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return chownFile{file, f.changes}, nil
}

// fchown changes the owner of a file that is a ChownFile through it.
func TestWasi_FchownOfAChownFile(t *testing.T) {
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	changes := 0
	w := NewWASI(WASIConfig{FS: chownFilesFS{mem, &changes}})
	m := newGuestModule(1 << 16)
	fd, errno := w.pathOpen(m, "f", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if rc := w.Fd_chown(m, fd, 1, 2); rc != _wasiESUCCESS || changes != 1 {
		t.Errorf("Fd_chown rc=%d, %d changes; want one", rc, changes)
	}
}

// HostFS's access is the host's: for a file of a HostFS of a directory, it
// is asked through the directory os.Root holds where the system has a call
// for that, and decided by the mode bits elsewhere.
func TestWasi_HostFSAccessAsksTheHost(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the host lets user 0 read anything")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "locked"), nil, 0o000); err != nil {
		t.Fatal(err)
	}
	fsys := newHostFS(t, dir).(rootFS)
	err := fsys.Access("d/locked", uint32(wasiAccessRead), false)
	switch runtime.GOOS {
	case "linux":
		if !errors.Is(err, syscall.EACCES) {
			t.Errorf("Access of a file of mode 000: %v, want EACCES", err)
		}
		if err := fsys.Access("d/locked", 0, false); err != nil {
			t.Errorf("Access(F_OK): %v", err)
		}
		if err := fsys.Access("d/locked/", 0, false); !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("Access(F_OK) of the file as a directory: %v, want ENOTDIR", err)
		}
		if err := fsys.Access(".", uint32(wasiAccessRead|wasiAccessExec), false); err != nil {
			t.Errorf("Access of the root: %v", err)
		}
	default:
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("Access: %v, want ErrUnsupported", err)
		}
	}
	// The guest is answered alike, by the mode bits where the host is not
	// asked: the isolated Process is user 0, whom they let read anything.
	w, m := newTestStubs(t, dir)
	off, n := putPath(m, 200, "d/locked")
	want := int32(_wasiESUCCESS)
	if runtime.GOOS == "linux" {
		want = -_wasiEACCES
	}
	if rc := w.Path_access(m, off, n, wasiAccessRead, 0); rc != want {
		t.Errorf("Path_access rc=%d, want %d", rc, want)
	}
}

// access of a HostFS of a directory says nothing of a file outside it: a
// symbolic link that leads out, absolute or relative, at the root or
// deeper, to a file or to none, is refused as os.Root refuses it (EACCES).
func TestWasi_HostFSAccessStaysInTheRoot(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]string{"abs": secret, "rel": rel, "d/abs": secret, "none": filepath.Join(outside, "none"), "dl": outside}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	fsys := newHostFS(t, dir).(rootFS)
	w, m := newTestStubs(t, dir)
	for name := range links {
		if err := fsys.Access(name, 0, false); err == nil || runtime.GOOS == "linux" && !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("Access(%s, F_OK): %v, want the decision left to the mode bits", name, err)
		}
		off, n := putPath(m, 200, name)
		if rc := w.Path_access(m, off, n, 0, 0); rc != -_wasiEACCES {
			t.Errorf("Path_access(%s, F_OK) rc=%d, want -EACCES", name, rc)
		}
	}
	// A trailing "/" follows the link: os.Root refuses where it leads.
	off, n := putPath(m, 200, "dl/")
	if rc := w.Path_access(m, off, n, 0, 0); rc != -_wasiEACCES {
		t.Errorf("Path_access(dl/, F_OK) rc=%d, want -EACCES", rc)
	}
	// A directory with a trailing "/" is asked about where the host has
	// the call for it.
	if err := fsys.Access("d/", uint32(wasiAccessRead|wasiAccessExec), false); runtime.GOOS == "linux" && err != nil || runtime.GOOS != "linux" && !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Access(d/): %v", err)
	}
}

// A MemFS lets every access be made to a file it has, as its open does, and
// keeps the setuid, setgid and sticky bits Chmod sets.
func TestWasi_MemFSAccessAndModeBits(t *testing.T) {
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o000); err != nil {
		t.Fatal(err)
	}
	w := NewWASI(WASIConfig{FS: mem, Process: testProcess{ids: ProcessIDs{PID: 42, PPID: 1, UID: 1000, EUID: 1000, GID: 1000, EGID: 1000}}})
	m := newGuestModule(1 << 16)
	off, n := putPath(m, 200, "f")
	if rc := w.Path_access(m, off, n, wasiAccessRead|wasiAccessWrite, 0); rc != _wasiESUCCESS {
		t.Errorf("access(R_OK|W_OK) of a MemFS file of mode 000 rc=%d", rc)
	}
	if fd, errno := w.pathOpen(m, "f", 0, 0, 1<<1|1<<6, 0); errno != _wasiESUCCESS {
		t.Errorf("open of it for reading and writing errno=%d", errno)
	} else if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	missing, missingn := putPath(m, 300, "missing")
	if rc := w.Path_access(m, missing, missingn, 0, 0); rc != -_wasiENOENT {
		t.Errorf("access of a missing file rc=%d, want -ENOENT", rc)
	}
	if rc := w.Path_chmod(m, off, n, 0o7755); rc != _wasiESUCCESS {
		t.Fatalf("chmod rc=%d", rc)
	}
	if rc := w.Path_filestat_mode(m, off, n, 1, 400); rc != _wasiESUCCESS || readU32(m.memory, 400) != 0o7755 {
		t.Errorf("mode after chmod 7755 rc=%d = %o", rc, readU32(m.memory, 400))
	}
	fd, errno := w.pathOpen(m, "f", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if rc := w.Fd_chmod(m, fd, 0o2644); rc != _wasiESUCCESS {
		t.Fatalf("fchmod rc=%d", rc)
	}
	if rc := w.Path_filestat_mode(m, off, n, 1, 400); rc != _wasiESUCCESS || readU32(m.memory, 400) != 0o2644 {
		t.Errorf("mode after fchmod 2644 rc=%d = %o", rc, readU32(m.memory, 400))
	}
}
