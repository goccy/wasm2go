package codegen

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// pathAccess calls Path_access for the preopen-relative path.
func pathAccess(w *WasiStubs, m *Module, path string, amode, flags int32) int32 {
	const pathOff int32 = 7000
	copy(m.memory[pathOff:], path)
	return w.Path_access(m, pathOff, int32(len(path)), amode, flags)
}

// access(2) for a file of the host's filesystem is the host's answer, by the
// file's mode for the process's ids: a file of mode 0600 is readable and
// writable but cannot be run, one of mode 0400 is not writable but for uid
// 0, a directory of mode 0700 can be searched, and a missing file is not
// found. wasi-libc's own access() looked at the preopened directory's rights
// only, which every file shares: it said yes to all of them.
func TestWasi_PathAccessAsksTheHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no access(2)")
	}
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	for name, mode := range map[string]os.FileMode{"rw": 0o600, "ro": 0o400, "x": 0o700} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
			t.Fatal(err)
		}
	}
	root := os.Geteuid() == 0
	for _, c := range []struct {
		path  string
		amode int32
		flags int32
		want  int32
	}{
		{"rw", 0, 0, 0},
		{"rw", wasiAccessRead | wasiAccessWrite, 0, 0},
		{"rw", wasiAccessExec, 0, -_wasiEACCES},
		{"rw", wasiAccessExec, wasiAccessEffective, -_wasiEACCES},
		{"ro", wasiAccessRead, 0, 0},
		{"ro", wasiAccessWrite, 0, map[bool]int32{false: -_wasiEACCES, true: 0}[root]},
		{"x", wasiAccessExec | wasiAccessRead, 0, 0},
		{".", wasiAccessExec, 0, 0},
		{"missing", 0, 0, -_wasiENOENT},
		{"rw", 8, 0, -_wasiEINVAL},
		{"rw", 0, 2, -_wasiEINVAL},
	} {
		if got := pathAccess(w, m, c.path, c.amode, c.flags); got != c.want {
			t.Errorf("access(%q, %d, flags %d) = %d, want %d", c.path, c.amode, c.flags, got, c.want)
		}
	}
}

// A file of a backend that is not the host's filesystem is decided by its
// mode bits, for the ids the guest has: an isolated guest is uid 0, which
// may read and write anything and run what has an x bit.
func TestWasi_PathAccessByTheModeOfAFileElsewhere(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	mem := NewMemFS()
	w.fsys = mem
	for name, mode := range map[string]os.FileMode{"data": 0o400, "tool": 0o500} {
		f, err := mem.OpenFile(name, os.O_CREATE|os.O_WRONLY, mode)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if err := mem.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		path  string
		amode int32
		want  int32
	}{
		{"data", wasiAccessRead | wasiAccessWrite, 0},
		{"data", wasiAccessExec, -_wasiEACCES},
		{"tool", wasiAccessExec, 0},
		{"missing", wasiAccessRead, -_wasiENOENT},
	} {
		if got := pathAccess(w, m, c.path, c.amode, 0); got != c.want {
			t.Errorf("access(%q, %d) = %d, want %d", c.path, c.amode, got, c.want)
		}
	}
}

// modeAllows picks the owner's, the group's or the others' bits as access(2)
// does for a process that is not uid 0.
func TestModeAllowsPicksTheBitsOfTheCaller(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fileStat{uid: 1000, gid: 100}
	read, write := uint32(wasiAccessRead), uint32(wasiAccessWrite)
	for _, c := range []struct {
		uid, gid uint32
		groups   []uint32
		amode    uint32
		want     bool
	}{
		{1000, 1, nil, read | write, true},
		{1001, 100, nil, read, true},
		{1001, 100, nil, write, false},
		{1001, 1, []uint32{100}, read, true},
		{1001, 1, nil, read, false},
	} {
		if got := modeAllows(fi, st, c.amode, c.uid, c.gid, c.groups); got != c.want {
			t.Errorf("uid %d gid %d groups %v amode %d: %v, want %v", c.uid, c.gid, c.groups, c.amode, got, c.want)
		}
	}
}
