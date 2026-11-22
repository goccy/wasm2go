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
	fd, errno := w.pathOpen(nil, "", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
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

// fd_readdir gives an entry of a directory of the host's the inode number
// the system's listing has for it on linux, and on darwin, whose listing
// is not read for one, a number that is no file's.
func TestReaddir_HostInodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, _ := newTestStubs(t, dir)
	fd, errno := w.pathOpen(nil, "", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	got := direntInodes(t, w, fd)
	for name, path := range map[string]string{".": dir, "..": filepath.Dir(dir), "a": filepath.Join(dir, "a"), "b": filepath.Join(dir, "b")} {
		if runtime.GOOS != "linux" {
			if got[name]&(1<<63) == 0 {
				t.Errorf("%s: d_ino %d, want one with the top bit set", name, got[name])
			}
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := fileStatOf(fi).ino; got[name] != want {
			t.Errorf("%s: d_ino %d, want %d", name, got[name], want)
		}
	}
}

// A directory of the host's lists its names in the order the system gives
// them, and "." and "..": where the system puts them on linux, first on
// darwin. ls -f is the system's order for every other name only (GNU ls
// may move "." and "..").
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
		switch name {
		case ".", "..":
			continue
		case "sub":
			name += "/"
		}
		want = append(want, name)
	}
	w, _ := newTestStubs(t, dir)
	all := listed(t, w)
	var got []string
	dots := 0
	for _, name := range all {
		if name == "./" || name == "../" {
			dots++
			continue
		}
		got = append(got, name)
	}
	if dots != 2 {
		t.Errorf("lists %q, want \"./\" and \"../\" once each", all)
	}
	if runtime.GOOS == "darwin" && (len(all) < 2 || all[0] != "./" || all[1] != "../") {
		t.Errorf("lists %q, want \"./\" and \"../\" first", all)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("lists %q,\nwant the other names %q", all, want)
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
	w.cfg.FS = mem
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
		fd, errno := w.pathOpen(nil, "", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
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
	dirFile, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dirFile.Close(); err != nil {
			t.Errorf("close %s: %v", dir, err)
		}
	})
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
		// An entry whose directory does not record the type asks the file:
		// by its host path in the whole host filesystem, relative to the
		// directory in a HostFS root where the system has a call for that
		// (not darwin, whose listing records every type).
		if got := (&hostDirEntry{dir: dirFile, hostPath: true, name: name}).Type(); got != want {
			t.Errorf("%s, type not recorded, whole host: type %v, want %v", name, got, want)
		}
		unknown := &hostDirEntry{dir: dirFile, name: name}
		wantUnknown := want
		if runtime.GOOS == "darwin" {
			wantUnknown = os.ModeIrregular
		}
		if got := unknown.Type(); got != wantUnknown {
			t.Errorf("%s, type not recorded: type %v, want %v", name, got, wantUnknown)
		}
	}
	// An entry whose type neither the directory nor the file tells is of
	// unknown type, in the listing fd_readdir writes too.
	gone := &hostDirEntry{dir: dirFile, name: "nothing"}
	if got := gone.Type(); got != os.ModeIrregular || gone.IsDir() {
		t.Errorf("an entry whose file is gone: type %v, IsDir() = %v; want %v and false", got, gone.IsDir(), os.ModeIrregular)
	}
	unknown, _ := newTestStubs(t, dir)
	unknownFd, errno := unknown.pathOpen(nil, "", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	unknown.mu.Lock()
	listing := unknown.openLocked(unknownFd)
	unknown.mu.Unlock()
	// A cookie other than 0 reads on in the listing the descriptor has.
	listing.mu.Lock()
	listing.dirCache = []os.DirEntry{gone, gone}
	listing.mu.Unlock()
	dirents := make([]byte, 64)
	n, errno := unknown.fillDirents(unknownFd, dirents, 1)
	if errno != _wasiESUCCESS || n != 24+len("nothing") {
		t.Fatalf("fillDirents wrote %d bytes, errno=%d; want one entry", n, errno)
	}
	if name, filetype := string(dirents[24:n]), dirents[20]; name != "nothing" || filetype != 0 {
		t.Errorf("fd_readdir lists %q with filetype %d, want \"nothing\" with 0 (unknown)", name, filetype)
	}
	if null := entriesOf("/dev")["null"]; null == nil || null.Type() != os.ModeDevice|os.ModeCharDevice {
		t.Errorf("/dev/null: entry %v, want a character device", null)
	}

	// A directory whose file is closed lists nothing.
	w, _ := newTestStubs(t, dir)
	fd, errno := w.pathOpen(nil, "", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
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
	// On the whole host filesystem: a HostFS of dir itself cannot be made
	// (os.Root searches its root).
	w := NewWASI(WASIConfig{FS: newHostFS(t, "/")})
	fd, errno := w.pathOpen(nil, hostRelative(t, dir), 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
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
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	if strings.Join(got, " ") != ". .. a b" {
		t.Errorf("lists %q, want . .. a b in any order", got)
	}
}
