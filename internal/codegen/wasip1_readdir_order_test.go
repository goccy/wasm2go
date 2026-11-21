//go:build darwin || linux

package codegen

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// orderTestNames are names made in an order that is not theirs sorted.
func orderTestNames() []string {
	var names []string
	for i := 0; i < 64; i++ {
		names = append(names, fmt.Sprintf("f%02d", (i*37)%64))
	}
	return names
}

// systemOrder is the directory's names in the order the system lists them
// (ls -f, which reads them with readdir(3)).
func systemOrder(t *testing.T, dir string) []string {
	t.Helper()
	out, err := exec.Command("ls", "-f", dir).Output()
	if err != nil {
		t.Fatalf("ls -f: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

// listed is what readDirCached lists for the root of w's file system.
func listed(t *testing.T, w *WasiStubs) []string {
	t.Helper()
	fd, errno := w.pathOpen("", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	entries, err := op.readDirCached(true)
	if err != nil {
		t.Fatalf("readDirCached: %v", err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	return names
}

// A directory of the host's lists its names in the order the system gives
// them, with "." and ".." where the system puts them on linux and first on
// darwin.
func TestReaddir_HostDirectoryInTheSystemsOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range orderTestNames() {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	var want []string
	if runtime.GOOS == "darwin" {
		want = []string{"./", "../"}
	}
	for _, name := range systemOrder(t, dir) {
		if name == "." || name == ".." {
			if runtime.GOOS == "darwin" {
				continue
			}
			name += "/"
		}
		if name == "sub" {
			name += "/"
		}
		want = append(want, name)
	}
	w, _ := newTestStubs(t, dir)
	if got := listed(t, w); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("lists %q,\nwant %q", got, want)
	}
}

// A directory of the embedder's own file system (MemFS) has no order of
// its own: "." and ".." come first, then the names sorted.
func TestReaddir_MemFSDirectorySorted(t *testing.T) {
	w, _ := newTestStubs(t, t.TempDir())
	mem := NewMemFS()
	for _, name := range orderTestNames() {
		f, err := mem.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Mkdir("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	w.fsys = mem
	names := orderTestNames()
	names = append(names, "sub/")
	sort.Strings(names)
	want := append([]string{"./", "../"}, names...)
	if got := listed(t, w); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("lists %q,\nwant %q", got, want)
	}
}

// An entry of a directory of the host's has the file type of its file,
// whether the directory records the type or leaves it to the file.
func TestReaddir_HostEntryTypes(t *testing.T) {
	// A short path: the name of a Unix-domain socket has little room.
	dir, err := os.MkdirTemp("", "w2g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mkfifo", filepath.Join(dir, "fifo")).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v: %s", err, out)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close the socket: %v", err)
		}
	})
	entriesOf := func(root string) map[string]os.DirEntry {
		t.Helper()
		w, _ := newTestStubs(t, root)
		fd, errno := w.pathOpen("", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("pathOpen(%s) errno=%d", root, errno)
		}
		w.mu.Lock()
		op := w.openLocked(fd)
		w.mu.Unlock()
		entries, err := op.readDirCached(true)
		if err != nil {
			t.Fatalf("readDirCached(%s): %v", root, err)
		}
		byName := map[string]os.DirEntry{}
		for _, e := range entries {
			byName[e.Name()] = e
		}
		return byName
	}
	entries := entriesOf(dir)
	for name, want := range map[string]os.FileMode{
		".": os.ModeDir, "..": os.ModeDir, "file": 0, "dir": os.ModeDir, "link": os.ModeSymlink,
		"fifo": os.ModeNamedPipe, "sock": os.ModeSocket,
	} {
		e := entries[name]
		if e == nil {
			t.Errorf("%s is not listed", name)
			continue
		}
		if got := e.Type(); got != want {
			t.Errorf("%s: type %v, want %v", name, got, want)
		}
		if e.IsDir() != want.IsDir() {
			t.Errorf("%s: IsDir() = %v", name, e.IsDir())
		}
		// An entry whose directory does not record the type asks the file.
		unknown := &hostDirEntry{dir: dir, name: name}
		if got := unknown.Type(); got != want {
			t.Errorf("%s, type not recorded: type %v, want %v", name, got, want)
		}
	}
	if got := (&hostDirEntry{dir: dir, name: "nothing"}).Type(); got != 0 {
		t.Errorf("an entry whose file is gone: type %v, want 0", got)
	}
	if null := entriesOf("/dev")["null"]; null == nil || null.Type() != os.ModeDevice|os.ModeCharDevice {
		t.Errorf("/dev/null: entry %v, want a character device", null)
	}

	// A directory whose file is closed lists nothing.
	w, _ := newTestStubs(t, dir)
	fd, errno := w.pathOpen("", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if err := op.f.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := op.readDirCached(true); err == nil {
		t.Errorf("a closed directory lists %d entries", len(entries))
	}
}

// A directory that may be read but not searched lists its names.
func TestReaddir_DirectoryWithoutSearchPermission(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is not held to the permissions of a directory")
	}
	dir := filepath.Join(t.TempDir(), "readable")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Errorf("chmod %s: %v", dir, err)
		}
	})
	w, _ := newTestStubs(t, dir)
	var got []string
	for _, name := range listed(t, w) {
		got = append(got, strings.TrimSuffix(name, "/"))
	}
	sort.Strings(got)
	if strings.Join(got, " ") != ". .. a b" {
		t.Errorf("lists %q, want . .. a b in any order", got)
	}
}
