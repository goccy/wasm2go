//go:build darwin || linux

package codegen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
// (ls -f, which reads them with readdir(3), as perl's readdir does).
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
// them, with "." and ".." where the system puts them, as perl's readdir
// lists them; through the host's file system (an *os.File) and in the host
// process's own descriptor table alike. Before, the names were sorted,
// with "." and ".." first.
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
	for _, name := range systemOrder(t, dir) {
		if name == "." || name == ".." || name == "sub" {
			name += "/"
		}
		want = append(want, name)
	}
	for _, guest := range []struct {
		name string
		new  func(*testing.T, string) (*WasiStubs, *Module)
	}{
		{"the host's file system", newTestStubs},
		{"the host process's descriptors", newHostGuest},
	} {
		w, _ := guest.new(t, dir)
		if got := listed(t, w); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: lists %q,\nwant %q", guest.name, got, want)
		}
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
		_ = f.Close()
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
