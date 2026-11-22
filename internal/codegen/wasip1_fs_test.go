package codegen

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

// exerciseFS drives one FS backend through the full interface surface
// shared by the os and in-memory implementations.
func exerciseFS(t *testing.T, fsys FS, wantSymlinks bool) {
	t.Helper()
	if err := fsys.Mkdir("d", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	f, err := fsys.OpenFile("d/a.txt", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("OpenFile create: %v", err)
	}
	if _, err := f.Write([]byte("hello world")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := f.WriteAt([]byte("HELLO"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := f.ReadAt(buf, 6); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("ReadAt = %q, want %q", buf, "world")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	all := make([]byte, 11)
	if _, err := io.ReadFull(f, all); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(all) != "HELLO world" {
		t.Fatalf("content = %q", all)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := f.Truncate(5); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("File.Stat: %v", err)
	}
	if st.Size() != 5 {
		t.Fatalf("size after truncate = %d", st.Size())
	}
	if st.IsDir() {
		t.Fatal("file reported as dir")
	}
	_ = st.Name()
	_ = st.Mode()
	_ = st.ModTime()
	_ = st.Sys()
	if f.Name() == "" {
		t.Fatal("empty File.Name")
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := fsys.Stat("d/a.txt"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if _, err := fsys.Lstat("d/a.txt"); err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	when := time.Unix(1700000000, 0)
	type chtimer interface {
		Chtimes(name string, atime, mtime time.Time) error
	}
	if ct, ok := fsys.(chtimer); ok {
		if err := ct.Chtimes("d/a.txt", when, when); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		st2, err := fsys.Stat("d/a.txt")
		if err != nil {
			t.Fatalf("Stat after Chtimes: %v", err)
		}
		if !st2.ModTime().Equal(when) {
			t.Fatalf("mtime = %v, want %v", st2.ModTime(), when)
		}
	}
	if err := fsys.Rename("d/a.txt", "d/b.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fsys.Stat("d/a.txt"); err == nil {
		t.Fatal("old name still present after rename")
	}
	if err := fsys.Link("d/b.txt", "d/c.txt"); err == nil {
		if _, err := fsys.Stat("d/c.txt"); err != nil {
			t.Fatalf("Stat after Link: %v", err)
		}
		if err := fsys.Remove("d/c.txt"); err != nil {
			t.Fatalf("Remove link: %v", err)
		}
	}
	if wantSymlinks {
		if err := fsys.Symlink("b.txt", "d/s.txt"); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		got, err := fsys.Readlink("d/s.txt")
		if err != nil {
			t.Fatalf("Readlink: %v", err)
		}
		if got != "b.txt" {
			t.Fatalf("Readlink = %q", got)
		}
		if _, err := fsys.Lstat("d/s.txt"); err != nil {
			t.Fatalf("Lstat symlink: %v", err)
		}
		if err := fsys.Remove("d/s.txt"); err != nil {
			t.Fatalf("Remove symlink: %v", err)
		}
	} else {
		if err := fsys.Symlink("b.txt", "d/s.txt"); err == nil {
			t.Fatal("Symlink should be rejected")
		}
	}

	dir, err := fsys.OpenFile("d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile dir: %v", err)
	}
	ents, err := dir.ReadDir(-1)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(ents) != 1 || ents[0].Name() != "b.txt" {
		t.Fatalf("ReadDir = %v", ents)
	}
	if ents[0].IsDir() {
		t.Fatal("entry reported as dir")
	}
	_ = ents[0].Type()
	if _, err := ents[0].Info(); err != nil {
		t.Fatalf("DirEntry.Info: %v", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatalf("Close dir: %v", err)
	}
	if err := fsys.Remove("d/b.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := fsys.Remove("d"); err != nil {
		t.Fatalf("Remove dir: %v", err)
	}
}

func TestOSFSInterface(t *testing.T) {
	root := t.TempDir()
	exerciseFS(t, newHostFS(t, root), true)
	// The names stay inside root.
	if err := newHostFS(t, root).Mkdir("x", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "x")); err != nil {
		t.Fatalf("scoped Mkdir landed elsewhere: %v", err)
	}
}

// The whole host filesystem renames as rename(2) does: a file onto a
// directory is EISDIR, a directory onto an empty directory replaces it,
// and one onto a directory with something in it is ENOTEMPTY, 55 (or
// EEXIST, which POSIX allows too). os.Rename answers EEXIST for every one
// of them.
func TestOSFSRenameIsTheSystemCall(t *testing.T) {
	skipWithoutPOSIXFiles(t)
	root := hostRelative(t, t.TempDir())
	fsys := newHostFS(t, "/")
	for _, dir := range []string{"target", "empty", "full", "moved"} {
		if err := fsys.Mkdir(path.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"file", "full/inside"} {
		f, err := fsys.OpenFile(path.Join(root, file), os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := fsys.Rename(path.Join(root, "file"), path.Join(root, "target")); mapOSError(err) != _wasiEISDIR {
		t.Errorf("a file onto a directory: %v (errno %d), want EISDIR", err, mapOSError(err))
	}
	if err := fsys.Rename(path.Join(root, "moved"), path.Join(root, "empty")); err != nil {
		t.Errorf("a directory onto an empty directory: %v", err)
	}
	if err := fsys.Rename(path.Join(root, "target"), path.Join(root, "full")); mapOSError(err) != 55 && mapOSError(err) != _wasiEEXIST {
		t.Errorf("a directory onto a full one: %v (errno %d), want ENOTEMPTY", err, mapOSError(err))
	}
	if err := fsys.Rename(path.Join(root, "file"), path.Join(root, "renamed")); err != nil {
		t.Errorf("a file to a new name: %v", err)
	}
}

// On every host, a file renamed onto another file replaces it.
func TestOSFSRenameReplacesAFile(t *testing.T) {
	root := t.TempDir()
	fsys := newHostFS(t, root)
	for name, data := range map[string]string{"from": "new", "to": "old"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := fsys.Rename("from", "to"); err != nil {
		t.Fatalf("a file onto a file: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "to")); err != nil || string(got) != "new" {
		t.Errorf("the replaced file holds %q, err=%v; want \"new\"", got, err)
	}
	if _, err := fsys.Lstat("from"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old name after the rename: %v, want it gone", err)
	}
	if err := fsys.Rename("nothing", "to"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a rename of a missing file: %v, want a not-exist error", err)
	}
}

// On the host's own root, the guest's "." (what its C library makes of "/")
// is "/": rmdir("/") is the host's rmdir("/"), EBUSY, not rmdir("/."),
// which is EINVAL on Linux.
func TestOSFSRootIsSlash(t *testing.T) {
	for _, root := range []string{"", "/", "//", "/."} {
		fsys, ok := newHostFS(t, root).(osFS)
		if !ok {
			t.Fatalf("HostFS(%q) is not the whole host filesystem", root)
		}
		if got := fsys.join("."); got != "/" {
			t.Errorf("HostFS(%q).join(\".\") = %q, want /", root, got)
		}
		if got := fsys.join("etc"); got != "/etc" {
			t.Errorf("HostFS(%q).join(\"etc\") = %q, want /etc", root, got)
		}
	}
}

func TestMemFSInterface(t *testing.T) {
	fsys := NewMemFS()
	exerciseFS(t, fsys, false)
	if err := fsys.MkdirAll("p/q/r", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if st, err := fsys.Stat("p/q/r"); err != nil || !st.IsDir() {
		t.Fatalf("MkdirAll result: %v %v", st, err)
	}
	// Path normalization: dot and dotdot segments collapse.
	if _, err := fsys.Stat("p/./q/../q/r"); err != nil {
		t.Fatalf("normalized path: %v", err)
	}
	if _, err := fsys.Readlink("p"); err == nil {
		t.Fatal("MemFS Readlink should fail")
	}
}

// A MemFS opens a directory for reading only: an open of it for writing is
// EISDIR, as open(2)'s is.
func TestMemFSOpenDirectoryForWriting(t *testing.T) {
	fsys := NewMemFS()
	if err := fsys.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []int{os.O_WRONLY, os.O_RDWR, os.O_RDWR | os.O_CREATE} {
		if _, err := fsys.OpenFile("d", flag, 0); mapOSError(err) != _wasiEISDIR {
			t.Errorf("OpenFile(d, %#x): %v (errno %d), want EISDIR", flag, err, mapOSError(err))
		}
	}
	f, err := fsys.OpenFile("d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(d, O_RDONLY): %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewWASIKeepsConfiguredStreamsAndFS(t *testing.T) {
	var in, out, errw = &bytesReader{}, &discard{}, &discard{}
	mem := NewMemFS()
	w := NewWASI(WASIConfig{Stdin: in, Stdout: out, Stderr: errw, FS: mem})
	if w.cfg.Stdin != in || w.cfg.Stdout != out || w.cfg.Stderr != errw || w.cfg.FS != FS(mem) {
		t.Fatal("NewWASI did not install the configured streams and filesystem")
	}
}

type bytesReader struct{}

func (*bytesReader) Read(p []byte) (int, error) { return 0, io.EOF }

type discard struct{}

func (*discard) Write(p []byte) (int, error) { return len(p), nil }
