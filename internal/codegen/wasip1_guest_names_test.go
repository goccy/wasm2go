package codegen

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

// linkFS is a MemFS with the symbolic links of links (name to target),
// which it counts the lookups of.
type linkFS struct {
	*MemFS
	links   map[string]string
	lookups *int
}

func (f linkFS) Lstat(name string) (os.FileInfo, error) {
	*f.lookups++
	if _, ok := f.links[name]; ok {
		return ownNameInfo{name: path.Base(name), mode: os.ModeSymlink | 0o777}, nil
	}
	return f.MemFS.Lstat(name)
}

func (f linkFS) Readlink(name string) (string, error) {
	if target, ok := f.links[name]; ok {
		return target, nil
	}
	return f.MemFS.Readlink(name)
}

// The FS is given one name for a guest path: no empty or "." element, a
// trailing "/" for one that asks for a directory, and ".." resolved after
// the symbolic link before it, from the root for an absolute target. Only
// a name with ".." is looked up.
func TestWasi_GuestNameResolvesDotDot(t *testing.T) {
	mem := NewMemFS()
	for _, d := range []string{"a/b", "x/y"} {
		if err := mem.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{"a/rel": "../x/y", "a/abs": "/x/y", "a/dots": "./../x", "a/empty": ""}
	// c0 -> c1 -> ... -> c40 -> x: c1 is guestMaxSymlinks links from x,
	// c0 one more.
	for i := range guestMaxSymlinks + 1 {
		links["c"+strconv.Itoa(i)] = "c" + strconv.Itoa(i+1)
	}
	links["c"+strconv.Itoa(guestMaxSymlinks)] = "x"
	lookups := 0
	w := NewWASI(WASIConfig{FS: linkFS{mem, links, &lookups}})
	for raw, want := range map[string]string{
		"": ".", ".": ".", "/": ".", "..": ".", "../..": ".", "a/./b//": "a/b/", "a/b/.": "a/b/", "/a//b": "a/b",
		"a/b/../../f": "f", "a/rel/..": "x/", "a/rel/../y/": "x/y/", "a/abs/../y": "x/y", "a/dots/..": ".",
		"c1/../x/y": "x/y",
		// no ".." : nothing is looked up, the FS follows the link itself
		"c0/x": "c0/x",
	} {
		lookups = 0
		got, errno := w.guestName(raw)
		if errno != _wasiESUCCESS || got != want {
			t.Errorf("guestName(%q) = %q, %d; want %q", raw, got, errno, want)
		}
		if got := fs.ValidPath(got) || fs.ValidPath(got[:len(got)-1]); !got {
			t.Errorf("guestName(%q) is no valid path", raw)
		}
		if lookups != 0 && raw == "c0/x" {
			t.Errorf("guestName(%q) looked up %d names", raw, lookups)
		}
	}
	for raw, want := range map[string]int32{
		"f/..": _wasiENOTDIR, "none/..": _wasiENOENT, "a/empty/..": _wasiENOENT, "c0/..": _wasiELOOP,
	} {
		if got, errno := w.guestName(raw); errno != want {
			t.Errorf("guestName(%q) = %q, %d; want errno %d", raw, got, errno, want)
		}
	}
}

// HostFS of an empty root is an error, not the whole host filesystem; what
// HostFS returns can be closed as it is.
func TestWasi_HostFSOfAnEmptyRoot(t *testing.T) {
	if fsys, err := HostFS(""); err == nil {
		t.Fatalf("HostFS(\"\") = %v, want an error", fsys)
	}
	fsys, err := HostFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
}

// A MemFS name with a trailing "/" asks for a directory: a file there is
// ENOTDIR, and a file to create there EISDIR, as on a host.
func TestWasi_MemFSTrailingSlash(t *testing.T) {
	mem := NewMemFS()
	if err := mem.WriteFile("f", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	_, statErr := mem.Stat("f/")
	_, openErr := mem.OpenFile("f/", os.O_RDWR|os.O_CREATE, 0o644)
	_, createErr := mem.OpenFile("n/", os.O_RDWR|os.O_CREATE, 0o644)
	for name, err := range map[string]error{
		"Stat":         statErr,
		"OpenFile":     openErr,
		"Remove":       mem.Remove("f/"),
		"Chmod":        mem.Chmod("f/", 0o600),
		"create there": createErr,
	} {
		want := syscall.ENOTDIR
		if name == "create there" {
			want = syscall.EISDIR
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	if _, err := mem.Stat("d/"); err != nil {
		t.Errorf("Stat(d/): %v", err)
	}
	if _, err := mem.Stat("n"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("n after the open that would create it: %v", err)
	}
	w := NewWASI(WASIConfig{FS: mem})
	m := newGuestModule(1 << 16)
	off, n := putPath(m, 128, "f/")
	if rc := w.Path_unlink_file(m, 3, off, n); rc != _wasiENOTDIR {
		t.Errorf("unlink(f/) rc=%d, want ENOTDIR", rc)
	}
	if _, err := mem.Stat("f"); err != nil {
		t.Errorf("f after unlink(f/): %v", err)
	}
}

// Every path operation resolves the names of the guest's own descriptors
// itself: one that changes or asks about what the name leads to acts on the
// descriptor, one that makes, removes or renames such a name fails as on
// Linux's procfs, and none reaches the FS.
func TestWasi_OwnDescriptorNamesOfEveryPathOperation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	ids := ProcessIDs{PID: 42, PPID: 1, UID: int32(os.Getuid()), EUID: int32(os.Geteuid()), GID: int32(os.Getgid()), EGID: int32(os.Getegid())}
	w.cfg.Process = testProcess{ids: ids, umask: 0o022}
	fd, errno := w.pathOpen("f", 0, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open f errno=%d", errno)
	}
	name := "dev/fd/" + strconv.Itoa(int(fd))
	p := func(off int32, s string) (int32, int32) { return putPath(m, off, s) }
	call := func(what string, rc, want int32) {
		t.Helper()
		if rc != want {
			t.Errorf("%s rc=%d, want %d", what, rc, want)
		}
	}

	// What the name leads to: the descriptor.
	off, n := p(128, name)
	call("chmod "+name, w.Path_chmod(m, off, n, 0o600), _wasiESUCCESS)
	if st, err := os.Stat(filepath.Join(dir, "f")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode of f = %v (%v), want 0600", st.Mode(), err)
	}
	call("chown "+name, w.Path_chown(m, off, n, -1, -1, 1), _wasiESUCCESS)
	call("lchown "+name, w.Path_chown(m, off, n, -1, -1, 0), -_wasiEPERM)
	const mtime = int64(1_000_000_000_000_000_000)
	call("utimes "+name, w.Path_filestat_set_times(m, 3, 1, off, n, 0, mtime, 0x4), _wasiESUCCESS)
	if st, err := os.Stat(filepath.Join(dir, "f")); err != nil || st.ModTime().UnixNano() != mtime {
		t.Errorf("mtime of f = %v (%v), want %d", st.ModTime(), err, mtime)
	}
	call("lutimes "+name, w.Path_filestat_set_times(m, 3, 0, off, n, 0, mtime, 0x4), _wasiEPERM)
	call("access(R_OK) "+name, w.Path_access(m, off, n, wasiAccessRead, 0), _wasiESUCCESS)
	if os.Geteuid() != 0 {
		call("access(X_OK) "+name, w.Path_access(m, off, n, wasiAccessExec, 0), -_wasiEACCES)
	}
	lst, lstn := p(256, "dev/fd")
	call("chmod dev/fd", w.Path_chmod(m, lst, lstn, 0o700), -_wasiEPERM)
	call("access(R_OK) dev/fd", w.Path_access(m, lst, lstn, wasiAccessRead, 0), _wasiESUCCESS)
	if os.Geteuid() != 0 {
		call("access(W_OK) dev/fd", w.Path_access(m, lst, lstn, wasiAccessWrite, 0), -_wasiEACCES)
	}
	// The preopened root is the FS's root.
	root, rootn := p(384, "dev/fd/3")
	call("chmod dev/fd/3", w.Path_chmod(m, root, rootn, 0o700), _wasiESUCCESS)
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("mode of the root = %v (%v), want 0700", st.Mode(), err)
	}

	// Making, removing and renaming such a name.
	closed, closedn := p(512, "dev/fd/99")
	file, filen := p(640, "f")
	other, othern := p(768, "g")
	call("mkdir "+name, w.Path_create_directory_mode(m, off, n, 0o755), -_wasiEEXIST)
	call("mkdir dev/fd", w.Path_create_directory_mode(m, lst, lstn, 0o755), -_wasiEEXIST)
	call("mkdir dev/fd/99", w.Path_create_directory(m, 3, closed, closedn), _wasiENOENT)
	call("mkfifo "+name, w.Path_mkfifo(m, off, n, 0o644), -_wasiEEXIST)
	call("symlink to dev/fd/99", w.Path_symlink(m, file, filen, 3, closed, closedn), _wasiENOENT)
	call("symlink to "+name, w.Path_symlink(m, file, filen, 3, off, n), _wasiEEXIST)
	call("link f to "+name, w.Path_link(m, 3, 0, file, filen, 3, off, n), _wasiEXDEV)
	call("rename "+name+" to g", w.Path_rename(m, 3, off, n, 3, other, othern), _wasiEXDEV)
	removes := _wasiEACCES
	if os.Geteuid() == 0 {
		removes = _wasiEPERM
	}
	call("unlink "+name, w.Path_unlink_file(m, 3, off, n), removes)
	call("unlink dev/fd/99", w.Path_unlink_file(m, 3, closed, closedn), _wasiENOENT)
	call("rmdir dev/fd", w.Path_remove_directory(m, 3, lst, lstn), removes)
	stdin, stdinn := p(896, "dev/stdin")
	call("rename "+name+" to dev/stdin", w.Path_rename(m, 3, off, n, 3, stdin, stdinn), removes)
	// Between two such names a rename fails as looking either up does, a
	// link as looking up its source does, and else as making its new name.
	call("rename "+name+" to dev/fd/99", w.Path_rename(m, 3, off, n, 3, closed, closedn), _wasiENOENT)
	call("link "+name+" to dev/stdin", w.Path_link(m, 3, 0, off, n, 3, stdin, stdinn), _wasiEEXIST)
	call("link dev/fd/99 to dev/stdin", w.Path_link(m, 3, 0, closed, closedn, 3, stdin, stdinn), _wasiENOENT)
	call("link "+name+" to dev/fd/99", w.Path_link(m, 3, 0, off, n, 3, closed, closedn), _wasiENOENT)
	// A guest of effective user id 0 is not stopped by the permissions.
	ids.EUID = 0
	w.cfg.Process = testProcess{ids: ids, umask: 0o022}
	call("unlink "+name+" as root", w.Path_unlink_file(m, 3, off, n), _wasiEPERM)

	if _, err := os.Stat(filepath.Join(dir, "f")); err != nil {
		t.Errorf("f: %v", err)
	}
	for _, made := range []string{"g", "dev"} {
		if _, err := os.Lstat(filepath.Join(dir, made)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was made in the FS: %v", made, err)
		}
	}
}

// A call that changes a name refuses one whose last element is "." or ".."
// as Linux does, once what the element ends is found to be a directory;
// one that only looks at the name follows what ".." ends as a directory.
func TestWasi_ChangesOfANameThatEndsInDots(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"d/x", "e"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("d", filepath.Join(dir, "s")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	w, m := newTestStubs(t, dir)
	at := int32(128)
	p := func(name string) (int32, int32) {
		off, n := putPath(m, at, name)
		at += 64
		return off, n
	}
	call := func(what string, rc, want int32) {
		t.Helper()
		if rc != want {
			t.Errorf("%s rc=%d, want %d", what, rc, want)
		}
	}
	dDot, dDotN := p("d/.")
	dDotDot, dDotDotN := p("d/x/..")
	sDotDot, sDotDotN := p("s/x/..")
	fDot, fDotN := p("f/.")
	none, noneN := p("none/.")
	eDot, eDotN := p("e/.")
	y, yN := p("y")
	f, fN := p("f")
	call("rmdir d/.", w.Path_remove_directory(m, 3, dDot, dDotN), _wasiEINVAL)
	call("rmdir d/x/..", w.Path_remove_directory(m, 3, dDotDot, dDotDotN), _wasiENOTEMPTY)
	call("rmdir f/.", w.Path_remove_directory(m, 3, fDot, fDotN), _wasiENOTDIR)
	call("rmdir none/.", w.Path_remove_directory(m, 3, none, noneN), _wasiENOENT)
	call("unlink d/.", w.Path_unlink_file(m, 3, dDot, dDotN), _wasiEISDIR)
	call("unlink s/x/..", w.Path_unlink_file(m, 3, sDotDot, sDotDotN), _wasiEISDIR)
	call("rename e/. to y", w.Path_rename(m, 3, eDot, eDotN, 3, y, yN), _wasiEBUSY)
	call("rename f to e/.", w.Path_rename(m, 3, f, fN, 3, eDot, eDotN), _wasiEBUSY)
	call("mkdir d/.", w.Path_create_directory(m, 3, dDot, dDotN), _wasiEEXIST)
	call("mkfifo d/x/..", w.Path_mkfifo(m, dDotDot, dDotDotN, 0o644), -_wasiEEXIST)
	call("symlink to d/x/..", w.Path_symlink(m, f, fN, 3, dDotDot, dDotDotN), _wasiEEXIST)
	call("link f to d/.", w.Path_link(m, 3, 0, f, fN, 3, dDot, dDotN), _wasiEEXIST)
	call("link f to f/.", w.Path_link(m, 3, 0, f, fN, 3, fDot, fDotN), _wasiENOTDIR)
	for _, name := range []string{"d", "d/x", "e", "f", "s"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s after the refused changes: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "y")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("y after the refused rename: %v", err)
	}
	// lstat of s/x/.. is the directory s leads to, not the link s.
	if rc := w.Path_filestat_get(m, 3, 0, sDotDot, sDotDotN, 600); rc != _wasiESUCCESS || m.memory[616] != 3 {
		t.Errorf("lstat s/x/.. rc=%d type=%d, want a directory (3)", rc, m.memory[616])
	}
	// The FS is not asked to make such a name: a MemFS makes no links.
	mem := NewMemFS()
	if err := mem.MkdirAll("d", 0o755); err != nil {
		t.Fatal(err)
	}
	w.cfg.FS = mem
	call("symlink to d/. in memory", w.Path_symlink(m, f, fN, 3, dDot, dDotN), _wasiEEXIST)
	call("link f to d/. in memory", w.Path_link(m, 3, 0, f, fN, 3, dDot, dDotN), _wasiEEXIST)
}

// A zone file the guest names by a path that leads to none is the host's
// error of that.
func TestWasi_ZoneOfAPathThatLeadsToNone(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the host has no table of error numbers")
	}
	w, _ := newTestStubs(t, t.TempDir())
	if _, err := w.loadZone("/none/../zone"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("loadZone of a path through a missing directory: %v, want ENOENT", err)
	}
}
