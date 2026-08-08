package codegen

import (
	"errors"
	"io"
	"os"
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
	exerciseFS(t, osFS{root: root}, true)
	// The root-scoping join must keep names inside root.
	if err := (osFS{root: root}).Mkdir("x", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "x")); err != nil {
		t.Fatalf("scoped Mkdir landed elsewhere: %v", err)
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

func TestWasiStubsSetters(t *testing.T) {
	w := &WasiStubs{}
	// Nil arguments keep the previous value; non-nil replace it.
	var in, out, errw = &bytesReader{}, &discard{}, &discard{}
	w.SetStdin(in)
	w.SetStdout(out)
	w.SetStderr(errw)
	if w.stdin != in || w.stdout != out || w.stderr != errw {
		t.Fatal("setters did not install the streams")
	}
	w.SetStdin(nil)
	w.SetStdout(nil)
	w.SetStderr(nil)
	if w.stdin != in || w.stdout != out || w.stderr != errw {
		t.Fatal("nil must keep the previous streams")
	}
	mem := NewMemFS()
	w.SetFS(mem)
	if w.fsys != FS(mem) {
		t.Fatal("SetFS did not install the backend")
	}
	w.preopenDir = "/tmp"
	w.SetFS(nil)
	if _, ok := w.fsys.(osFS); !ok {
		t.Fatal("SetFS(nil) must restore the os backend")
	}
}

type bytesReader struct{}

func (*bytesReader) Read(p []byte) (int, error) { return 0, io.EOF }

type discard struct{}

func (*discard) Write(p []byte) (int, error) { return len(p), nil }
