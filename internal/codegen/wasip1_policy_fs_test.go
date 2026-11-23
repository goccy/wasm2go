package codegen

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// policyFS wraps an FS to keep a policy on its files, as an embedder does:
// a call on a name allow refuses fails with fs.ErrPermission (EACCES). It
// asks allow about the name, from the root, without the trailing "/" the
// FS may be given with it, and records each name it is asked about as
// "name:write". at is the name of the directory a policyFS OpenRoot
// returned is of ("" for the root).
type policyFS struct {
	FS
	allow func(name string, write bool) bool
	seen  *[]string
	at    string
}

func (p policyFS) check(name string, write bool) error {
	if p.at != "" {
		name = path.Join(p.at, name)
	}
	*p.seen = append(*p.seen, name+map[bool]string{true: ":true", false: ":false"}[write])
	if !p.allow(strings.TrimSuffix(name, "/"), write) {
		return &fs.PathError{Op: "policy", Path: name, Err: fs.ErrPermission}
	}
	return nil
}

// OpenRoot returns the directory as a policyFS of its own, which keeps the
// policy on the names from the root.
func (p policyFS) OpenRoot(name string) (FS, error) {
	if err := p.check(name, false); err != nil {
		return nil, err
	}
	inner, ok := p.FS.(OpenRootFS)
	if !ok {
		return nil, &fs.PathError{Op: "openroot", Path: name, Err: errors.ErrUnsupported}
	}
	sub, err := inner.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return policyFS{FS: sub, allow: p.allow, seen: p.seen, at: path.Join(p.at, name)}, nil
}

func (p policyFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	if err := p.check(name, flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0); err != nil {
		return nil, err
	}
	return p.FS.OpenFile(name, flag, perm)
}

func (p policyFS) Mkdir(name string, perm os.FileMode) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Mkdir(name, perm)
}

func (p policyFS) Chmod(name string, mode os.FileMode) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Chmod(name, mode)
}

func (p policyFS) Chtimes(name string, atime, mtime time.Time) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Chtimes(name, atime, mtime)
}

func (p policyFS) Lchtimes(name string, atime, mtime time.Time) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Lchtimes(name, atime, mtime)
}

func (p policyFS) Chown(name string, uid, gid int) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Chown(name, uid, gid)
}

func (p policyFS) Lchown(name string, uid, gid int) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Lchown(name, uid, gid)
}

func (p policyFS) Unlink(name string) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Unlink(name)
}

func (p policyFS) Rmdir(name string) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Rmdir(name)
}

func (p policyFS) Rename(oldName, newName string) error {
	if err := p.check(oldName, true); err != nil {
		return err
	}
	if err := p.check(newName, true); err != nil {
		return err
	}
	return p.FS.Rename(oldName, newName)
}

func (p policyFS) Link(oldName, newName string) error {
	if err := p.check(oldName, true); err != nil {
		return err
	}
	if err := p.check(newName, true); err != nil {
		return err
	}
	return p.FS.Link(oldName, newName)
}

func (p policyFS) Symlink(target, name string) error {
	if err := p.check(name, true); err != nil {
		return err
	}
	return p.FS.Symlink(target, name)
}

func (p policyFS) Stat(name string) (os.FileInfo, error) {
	if err := p.check(name, false); err != nil {
		return nil, err
	}
	return p.FS.Stat(name)
}

func (p policyFS) Lstat(name string) (os.FileInfo, error) {
	if err := p.check(name, false); err != nil {
		return nil, err
	}
	return p.FS.Lstat(name)
}

func (p policyFS) Readlink(name string) (string, error) {
	if err := p.check(name, false); err != nil {
		return "", err
	}
	return p.FS.Readlink(name)
}

// openTestDir opens name, a directory, and returns its descriptor.
func openTestDir(t *testing.T, w *WasiStubs, name string) int32 {
	t.Helper()
	fd, errno := w.pathOpen(nil, name, 1, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open %s errno=%d", name, errno)
	}
	return fd
}

// A policy on files is an FS that wraps another: every path operation goes
// through it, a refused one is EACCES and leaves the filesystem as it was,
// and it is given the names of FS's doc (".." resolved, by looking up the
// directory before it).
func TestWasi_PolicyFSGatesEveryPathOperation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	w, m := newTestStubs(t, dir)
	var seen []string
	allowWrites := func(name string) func(string, bool) bool {
		return func(n string, write bool) bool { return !write || n == name }
	}
	w.cfg.FS = policyFS{FS: w.cfg.FS, allow: allowWrites("f"), seen: &seen}
	f, fn := putPath(m, 128, "f")
	g, gn := putPath(m, 160, "g")
	d, dn := putPath(m, 192, "d")
	l, ln := putPath(m, 224, "l")
	type op struct {
		name   string
		call   func() int32
		denied int32
		last   string // the refused call's name
	}
	writes := []op{
		{"path_open creating", func() int32 { return w.Path_open(m, 3, 0, g, gn, 0x1, 1<<6, 0, 0, 300) }, _wasiEACCES, "g:true"},
		{"path_create_directory", func() int32 { return w.Path_create_directory(m, 3, g, gn) }, _wasiEACCES, "g:true"},
		{"path_unlink_file", func() int32 { return w.Path_unlink_file(m, 3, l, ln) }, _wasiEACCES, "l:true"},
		{"path_remove_directory", func() int32 { return w.Path_remove_directory(m, 3, d, dn) }, _wasiEACCES, "d:true"},
		{"path_rename", func() int32 { return w.Path_rename(m, 3, f, fn, 3, g, gn) }, _wasiEACCES, "g:true"},
		{"path_link", func() int32 { return w.Path_link(m, 3, 0, f, fn, 3, g, gn) }, _wasiEACCES, "g:true"},
		{"path_symlink", func() int32 { return w.Path_symlink(m, f, fn, 3, g, gn) }, _wasiEACCES, "g:true"},
		{"path_filestat_set_times", func() int32 { return w.Path_filestat_set_times(m, 3, 0, d, dn, 0, 0, 0x2|0x8) }, _wasiEACCES, "d:true"},
		{"path_chmod", func() int32 { return w.Path_chmod(m, d, dn, 0o700) }, -_wasiEACCES, "d:true"},
		{"path_chown", func() int32 { return w.Path_chown(m, d, dn, -1, -1, 1) }, -_wasiEACCES, "d:true"},
	}
	for _, o := range writes {
		seen = nil
		if rc := o.call(); rc != o.denied || len(seen) == 0 || seen[len(seen)-1] != o.last {
			t.Errorf("%s: rc=%d, the FS saw %v; want %d after %s", o.name, rc, seen, o.denied, o.last)
		}
	}
	for _, name := range []string{"f", "d", "l"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s after the refused writes: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "g")); !os.IsNotExist(err) {
		t.Errorf("g exists after the refused writes: %v", err)
	}
	reads := []op{
		{"path_open for reading", func() int32 { return w.Path_open(m, 3, 0, f, fn, 0, 1<<1, 0, 0, 300) }, _wasiEACCES, "f:false"},
		{"path_filestat_get", func() int32 { return w.Path_filestat_get(m, 3, 0, f, fn, 300) }, _wasiEACCES, "f:false"},
		{"path_filestat_ext", func() int32 { return w.Path_filestat_ext(m, f, fn, 0, 300) }, -_wasiEACCES, "f:false"},
		{"path_filestat_mode", func() int32 { return w.Path_filestat_mode(m, f, fn, 0, 300) }, -_wasiEACCES, "f:false"},
		{"path_readlink", func() int32 { return w.Path_readlink(m, 3, l, ln, 300, 64, 400) }, _wasiEACCES, "l:false"},
	}
	for _, o := range reads {
		if rc := o.call(); rc != _wasiESUCCESS {
			t.Errorf("%s allowed: rc=%d", o.name, rc)
		}
	}
	w.cfg.FS = policyFS{FS: w.cfg.FS.(policyFS).FS, allow: func(string, bool) bool { return false }, seen: &seen}
	for _, o := range reads {
		seen = nil
		if rc := o.call(); rc != o.denied || len(seen) == 0 || seen[len(seen)-1] != o.last {
			t.Errorf("%s: rc=%d, the FS saw %v; want %d after %s", o.name, rc, seen, o.denied, o.last)
		}
	}
	// The FS is given the name ".." resolves to, after looking up the
	// directory before it.
	if err := os.WriteFile(filepath.Join(dir, "secret"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = policyFS{FS: w.cfg.FS.(policyFS).FS, allow: func(n string, _ bool) bool { return n != "secret" }, seen: &seen}
	seen = nil
	s, sn := putPath(m, 256, "d/../secret")
	if rc := w.Path_filestat_get(m, 3, 0, s, sn, 300); rc != _wasiEACCES || len(seen) != 2 || seen[0] != "d:false" || seen[1] != "secret:false" {
		t.Errorf("stat(d/../secret) rc=%d, the FS saw %v; want EACCES after d and secret", rc, seen)
	}
	// A name relative to a directory descriptor is given to the FS of the
	// directory the policy's OpenRoot returned, which keeps the policy and
	// the directory across a rename.
	if err := os.WriteFile(filepath.Join(dir, "d", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = policyFS{FS: w.cfg.FS.(policyFS).FS, allow: func(string, bool) bool { return true }, seen: &seen}
	dfd := openTestDir(t, w, "d")
	if err := os.Rename(filepath.Join(dir, "d"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	seen = nil
	x, xn := putPath(m, 256, "x")
	if rc := w.Path_filestat_get(m, dfd, 0, x, xn, 300); rc != _wasiESUCCESS || len(seen) != 1 || seen[0] != "d/x:false" {
		t.Errorf("stat(x) from d rc=%d, the FS saw %v; want it found after d/x", rc, seen)
	}
}
