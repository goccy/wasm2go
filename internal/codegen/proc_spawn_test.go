package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeCStr writes s plus a NUL at off and returns off.
func writeCStr(m *Module, off int32, s string) int32 {
	copy(m.memory[off:], append([]byte(s), 0))
	return off
}

// writeArgv lays out a NULL-terminated char** for argv at off, with each
// string packed starting at strOff. Returns the argv pointer.
// Proc_spawn64 reads its strings and string arrays with 64-bit pointers.
func TestWasi_ProcSpawn64(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.cfg.FS = osFS{}
	argv := []string{"/bin/sh", "-c", "exit 3"}
	if _, err := os.Stat(argv[0]); err != nil {
		t.Skipf("%s not available", argv[0])
	}
	const argvOff, strOff, envOff, pidOff, statusOff = 2000, 3000, 4000, 4100, 4104
	at := int32(strOff)
	for i, a := range argv {
		writeCStr(m, at, a)
		binary.LittleEndian.PutUint64(m.memory[argvOff+i*8:], uint64(at))
		at += int32(len(a)) + 1
	}
	binary.LittleEndian.PutUint64(m.memory[argvOff+len(argv)*8:], 0)
	binary.LittleEndian.PutUint64(m.memory[envOff:], 0)
	if rc := w.Proc_spawn64(m, strOff, argvOff, envOff, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn64 rc=%d", rc)
	}
	pid := int32(readU32(m.memory, pidOff))
	if rc := w.Proc_wait64(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait64 rc=%d", rc)
	}
	if status := readU32(m.memory, statusOff); status != 3<<8 {
		t.Fatalf("status = %#x, want %#x", status, 3<<8)
	}
	if rc := w.Proc_spawn64(m, strOff, argvOff, envOff, -1, -1, -1, 0, 1<<40); rc != -_wasiEFAULT {
		t.Fatalf("Proc_spawn64 with the pid beyond the memory rc=%d, want -EFAULT", rc)
	}
}

func writeArgv(m *Module, off, strOff int32, argv []string) int32 {
	p := strOff
	ptrs := make([]int32, len(argv))
	for i, a := range argv {
		ptrs[i] = p
		writeCStr(m, p, a)
		p += int32(len(a)) + 1
	}
	for i, sp := range ptrs {
		binary.LittleEndian.PutUint32(m.memory[off+int32(i*4):], uint32(sp))
	}
	binary.LittleEndian.PutUint32(m.memory[off+int32(len(ptrs)*4):], 0) // NULL term
	return off
}

func TestWasi_ProcSpawnWait(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	w, m := newTestStubs(t, "/")
	var out bytes.Buffer
	w.cfg.Stdout = &out
	w.cfg.Stderr = &bytes.Buffer{}
	w.cfg.Stdin = bytes.NewReader(nil)

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "hello-proc"})
	const pidOff, statusOff int32 = 4000, 4004

	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	if pid == 0 {
		t.Fatal("pid not written")
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 0 {
		t.Errorf("exit code = %d, want 0 (status=%#x)", exit, status)
	}
	if got := out.String(); got != "hello-proc\n" {
		t.Errorf("child stdout = %q, want %q", got, "hello-proc\n")
	}
}

func TestWasi_ProcSpawnExitCode(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	w, m := newTestStubs(t, "/")
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)

	pathOff := writeCStr(m, 1000, "/bin/sh")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "exit 7"})
	const pidOff, statusOff int32 = 4000, 4004

	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 7 {
		t.Errorf("exit code = %d, want 7", exit)
	}
}

func TestWasi_ProcSpawnExecHookDenies(t *testing.T) {
	w, m := newTestStubs(t, "/")
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	var seen []ExecRequest
	w.cfg.Exec = func(req ExecRequest) bool { seen = append(seen, req); return false }

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "x"})
	envOff := writeArgv(m, 5000, 6000, []string{"LD_PRELOAD=/tmp/x.so"})
	cwdOff := writeCStr(m, 7000, "/work")
	if rc := w.Proc_spawn(m, pathOff, argvOff, envOff, -1, -1, -1, cwdOff, 4000); rc != -_wasiEACCES {
		t.Fatalf("denied spawn rc=%d, want -EACCES", rc)
	}
	want := ExecRequest{Path: "/bin/echo", Argv: []string{"/bin/echo", "x"}, Env: []string{"LD_PRELOAD=/tmp/x.so"}, Dir: "/work"}
	if len(seen) != 1 || !reflect.DeepEqual(seen[0], want) {
		t.Errorf("exec hook saw %+v, want %+v", seen, want)
	}
}

// CommandDir is asked, after Exec, where a command starts, with the host
// path of the guest's working directory: "" starts it in the host
// process's working directory, inherited without changing into it, another
// directory starts it there, and an error fails the spawn with its errno.
func TestWasi_ProcSpawnCommandDir(t *testing.T) {
	if _, err := os.Stat("/bin/pwd"); err != nil {
		t.Skip("/bin/pwd not available")
	}
	host, guest := t.TempDir(), t.TempDir()
	t.Chdir(host)
	w, m := newTestStubs(t, "/")
	var out bytes.Buffer
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &out, &bytes.Buffer{}, bytes.NewReader(nil)
	var seen []ExecRequest
	w.cfg.Exec = func(req ExecRequest) bool { seen = append(seen, req); return true }
	var asked []string
	var dir string
	var dirErr error
	w.cfg.CommandDir = func(d string) (string, error) { asked = append(asked, d); return dir, dirErr }
	pathOff := writeCStr(m, 1000, "/bin/pwd")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/pwd", "-P"})
	cwdOff := writeCStr(m, 7000, guest)
	const pidOff, statusOff int32 = 4000, 4004
	pwd := func() string {
		t.Helper()
		out.Reset()
		if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, cwdOff, pidOff); rc != _wasiESUCCESS {
			t.Fatalf("Proc_spawn rc=%d", rc)
		}
		if rc := w.Proc_wait(m, int32(binary.LittleEndian.Uint32(m.memory[pidOff:])), 0, statusOff); rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
		return strings.TrimSuffix(out.String(), "\n")
	}
	physical := func(p string) string {
		t.Helper()
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got, want := pwd(), physical(host); got != want {
		t.Errorf("command for \"\" started in %q, want the host process's %q", got, want)
	}
	if len(asked) != 1 || len(seen) != 1 || asked[0] != seen[0].Dir {
		t.Errorf("CommandDir was asked %q, Exec %+v; want it asked the Dir Exec saw", asked, seen)
	}
	dir = guest
	if got, want := pwd(), physical(guest); got != want {
		t.Errorf("command for %q started in %q, want %q", guest, got, want)
	}
	dir, dirErr = "", syscall.EPERM
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, cwdOff, pidOff); rc != -_wasiEPERM {
		t.Errorf("Proc_spawn when CommandDir fails with EPERM rc=%d, want -EPERM", rc)
	}
}

// A command started in the host process's working directory runs though
// the directory may no longer be searched: it is inherited, not changed
// into.
func TestWasi_ProcSpawnInheritsAnUnsearchableDirectory(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	if os.Geteuid() == 0 {
		t.Skip("root may search any directory")
	}
	here := t.TempDir()
	t.Chdir(here)
	if err := os.Chmod(here, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(here, 0o755); err != nil {
			t.Error(err)
		}
	})
	w, m := newTestStubs(t, "/")
	var out bytes.Buffer
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &out, &bytes.Buffer{}, bytes.NewReader(nil)
	w.cfg.CommandDir = func(string) (string, error) { return "", nil }
	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "started"})
	cwdOff := writeCStr(m, 7000, here)
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, cwdOff, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	if rc := w.Proc_wait(m, int32(binary.LittleEndian.Uint32(m.memory[pidOff:])), 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if got := out.String(); got != "started\n" {
		t.Errorf("output %q, want %q", got, "started\n")
	}
}

func TestWasi_ProcSpawnNotFound(t *testing.T) {
	w, m := newTestStubs(t, "/")
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	pathOff := writeCStr(m, 1000, "/no/such/binary-xyz")
	argvOff := writeArgv(m, 2000, 3000, []string{"/no/such/binary-xyz"})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiENOENT {
		t.Fatalf("missing binary rc=%d, want -ENOENT", rc)
	}
}

// hostRootedFS is HostFS(root) as a HostRootFS: its names are the host's
// paths under root.
type hostRootedFS struct {
	FS
	root string
}

func (r hostRootedFS) HostRoot() string { return r.root }

// newRootedSpawnStubs returns test stubs whose FS is the directory dir as
// a HostRootFS, and whose Exec hook records each request it is asked about
// in seen and refuses it when refuse is set.
func newRootedSpawnStubs(t *testing.T, dir string, refuse bool) (*WasiStubs, *Module, *[]ExecRequest) {
	t.Helper()
	w, m := newProcTestStubs(t)
	w.cfg.FS = hostRootedFS{newHostFS(t, dir), dir}
	seen := &[]ExecRequest{}
	w.cfg.Exec = func(req ExecRequest) bool { *seen = append(*seen, req); return !refuse }
	return w, m, seen
}

// spawnIn calls Proc_spawn for the command name with the argv name and the
// environment env, in the guest's working directory cwd.
func spawnIn(w *WasiStubs, m *Module, name, cwd string, env ...string) int32 {
	pathOff := writeCStr(m, 1000, name)
	argvOff := writeArgv(m, 2000, 3000, []string{name})
	envOff := writeArgv(m, 5000, 6000, env)
	cwdOff := writeCStr(m, 7000, cwd)
	return w.Proc_spawn(m, pathOff, argvOff, envOff, -1, -1, -1, cwdOff, 4000)
}

// The hook is told the host's paths of the names of the command and of the
// working directory in a HostRootFS, a relative name taken from the
// working directory and ".." resolved after the links before it, and a NULL
// environment as an empty one: the command is started from that very
// request, in that directory.
func TestWasi_ProcSpawnExecRequestOfTheHostRoot(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "work", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work", "tool"), []byte("#!/bin/sh\npwd -P\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../work/bin", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	w, m, seen := newRootedSpawnStubs(t, dir, false)
	var out bytes.Buffer
	w.cfg.Stdout = &out
	pathOff := writeCStr(m, 1000, "../link/../tool")
	argvOff := writeArgv(m, 2000, 3000, nil)
	cwdOff := writeCStr(m, 7000, "/work")
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, cwdOff, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	if rc := w.Proc_wait(m, int32(binary.LittleEndian.Uint32(m.memory[pidOff:])), 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	want := ExecRequest{Path: filepath.Join(dir, "work", "tool"), Argv: []string{"../link/../tool"}, Env: []string{}, Dir: filepath.Join(dir, "work")}
	if len(*seen) != 1 || !reflect.DeepEqual((*seen)[0], want) {
		t.Errorf("exec hook saw %+v, want %+v", *seen, want)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(dir, "work"))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != real+"\n" {
		t.Errorf("the command ran in %q, want %q", got, real+"\n")
	}

	// An empty working directory (cwdPtr 0, a zero byte) is the root of the
	// FS, not the host process's working directory.
	*seen = nil
	out.Reset()
	pathOff = writeCStr(m, 1000, "/work/tool")
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn without a working directory rc=%d", rc)
	}
	if rc := w.Proc_wait(m, int32(binary.LittleEndian.Uint32(m.memory[pidOff:])), 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if len(*seen) != 1 || (*seen)[0].Dir != dir {
		t.Errorf("exec hook saw %+v without a working directory, want the Dir %q", *seen, dir)
	}
	if real, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != real+"\n" {
		t.Errorf("the command without a working directory ran in %q, want %q", got, real+"\n")
	}
}

// A relative HostRoot is taken from the host process's working directory
// when the command is started: the hook is told absolute paths, and the
// command runs in that directory.
func TestWasi_ProcSpawnExecRequestOfARelativeHostRoot(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work", "tool"), []byte("#!/bin/sh\npwd -P\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, m, seen := newRootedSpawnStubs(t, dir, false)
	w.cfg.FS = hostRootedFS{w.cfg.FS.(hostRootedFS).FS, "."}
	t.Chdir(dir)
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w.cfg.Stdout = &out
	if rc := spawnIn(w, m, "tool", "/work", "PATH=/work"); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	if rc := w.Proc_wait(m, int32(binary.LittleEndian.Uint32(m.memory[4000:])), 0, 4004); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	want := ExecRequest{Path: filepath.Join(abs, "work", "tool"), Argv: []string{"tool"}, Env: []string{"PATH=/work"}, Dir: filepath.Join(abs, "work")}
	if len(*seen) != 1 || !reflect.DeepEqual((*seen)[0], want) {
		t.Errorf("exec hook saw %+v, want %+v", *seen, want)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(dir, "work"))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != real+"\n" {
		t.Errorf("the command ran in %q, want %q", got, real+"\n")
	}
}

// A command cannot be started from an FS that is no HostRootFS (ENOSYS):
// its names are no paths of the host's. The hook is not asked.
func TestWasi_ProcSpawnWithoutAHostRoot(t *testing.T) {
	for _, c := range []struct {
		name string
		fsys func(t *testing.T) FS
	}{
		{"HostFS of a directory", func(t *testing.T) FS { return newHostFS(t, t.TempDir()) }},
		{"MemFS", func(*testing.T) FS { return NewMemFS() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, m := newProcTestStubs(t)
			w.cfg.FS = c.fsys(t)
			hooked := false
			w.cfg.Exec = func(ExecRequest) bool { hooked = true; return true }
			if rc := spawnIn(w, m, "/bin/sh", "/"); rc != -_wasiENOSYS || hooked {
				t.Errorf("spawn rc=%d with the hook asked: %v; want -ENOSYS, not asked", rc, hooked)
			}
		})
	}
}

// A name without a "/" is looked up as musl's execvp looks it up, in the
// guest's FS: in the directories of the PATH of the environment the guest
// gives the command, the first regular file it may execute, past ones it
// may not (EACCES when there are only those) and ones that do not exist;
// an empty directory is the working directory, and without a PATH the
// directories are musl's. Any other error ends the lookup. A name with a
// "/" is not looked up. The host's PATH is not looked in.
func TestWasi_ProcSpawnLooksUpTheGuestsPath(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []struct {
		name string
		mode os.FileMode
	}{{"plain/tool", 0o644}, {"exec/tool", 0o755}, {"usr/bin/tool", 0o755}, {"file", 0o644}} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(f.name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), nil, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"plain/sub", "loop"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("tool", filepath.Join(dir, "loop", "tool")); err != nil {
		t.Fatal(err)
	}
	w, m, seen := newRootedSpawnStubs(t, dir, true)
	for _, c := range []struct {
		name, cwd string
		env       []string
		rc        int32
		path      string
	}{
		{"tool", "/", []string{"PATH=/none:/file:/plain:/exec"}, -_wasiEACCES, "exec/tool"},
		{"tool", "/", []string{"PATH=/plain"}, -_wasiEACCES, ""},
		{"sub", "/", []string{"PATH=/plain"}, -_wasiEACCES, ""},
		{"tool", "/", []string{"PATH=/none"}, -_wasiENOENT, ""},
		{"tool", "/exec", []string{"PATH="}, -_wasiEACCES, "exec/tool"},
		{"tool", "/exec", []string{"PATH=/none::/plain"}, -_wasiEACCES, "exec/tool"},
		{"tool", "/", []string{"PATH=exec"}, -_wasiEACCES, "exec/tool"},
		{"tool", "/", []string{"HOME=/"}, -_wasiEACCES, "usr/bin/tool"},
		{"tool", "/", []string{"PATH=/exec", "PATH=/plain"}, -_wasiEACCES, "exec/tool"},
		{"sh", "/", []string{"PATH=/bin:/usr/bin"}, -_wasiENOENT, ""},
		{"tool", "/", []string{"PATH=/loop:/exec"}, -_wasiELOOP, ""},
		{"plain/tool", "/", []string{"PATH=/exec"}, -_wasiEACCES, "plain/tool"},
	} {
		*seen = nil
		rc := spawnIn(w, m, c.name, c.cwd, c.env...)
		var want []string
		if c.path != "" {
			want = []string{filepath.Join(dir, c.path)}
		}
		var got []string
		for _, req := range *seen {
			got = append(got, req.Path)
		}
		if rc != c.rc || !slices.Equal(got, want) {
			t.Errorf("spawn of %q in %s with %q: rc=%d, the hook told %q; want rc=%d, %q", c.name, c.cwd, c.env, rc, got, c.rc, want)
		}
	}
	// Without an Exec policy nothing is looked up or started.
	w.cfg.Exec = nil
	if rc := spawnIn(w, m, "tool", "/", "PATH=/none"); rc != -_wasiEACCES {
		t.Errorf("spawn without an Exec policy rc=%d, want -EACCES", rc)
	}
}

// A command the host cannot start fails with the host's errno: a file that
// may be executed but is no program is ENOEXEC.
func TestWasi_ProcSpawnNotAProgram(t *testing.T) {
	const wasiENOEXEC = 45 // the runtime has no constant of its own for it
	dir := t.TempDir()
	w, m := newTestStubs(t, "/")
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	prog := filepath.Join(dir, "prog")
	if err := os.WriteFile(prog, []byte{0, 1, 2, 3}, 0o755); err != nil {
		t.Fatal(err)
	}
	pathOff := writeCStr(m, 1000, prog)
	argvOff := writeArgv(m, 2000, 3000, []string{prog})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -wasiENOEXEC {
		t.Fatalf("spawn of no program rc=%d, want -ENOEXEC", rc)
	}
}

func TestWasi_ProcWaitUnknownPID(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if rc := w.Proc_wait(m, 999999, 0, 4000); rc != -_wasiECHILD {
		t.Errorf("unknown pid rc=%d, want -ECHILD", rc)
	}
}

func TestWasi_ProcWaitWNOHANG(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	w, m := newTestStubs(t, "/")
	w.cfg.Stdout, w.cfg.Stderr, w.cfg.Stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	pathOff := writeCStr(m, 1000, "/bin/sh")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "sleep 0.3; exit 3"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	// Immediately: WNOHANG should report not-ready (EAGAIN), child still running.
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG early rc=%d, want -EAGAIN", rc)
	}
	// Block until done.
	deadline := time.Now().Add(5 * time.Second)
	for {
		rc := w.Proc_wait(m, pid, 1, statusOff)
		if rc == _wasiESUCCESS {
			break
		}
		if rc != -_wasiEAGAIN {
			t.Fatalf("WNOHANG poll rc=%d", rc)
		}
		if time.Now().After(deadline) {
			t.Fatal("child never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 3 {
		t.Errorf("exit=%d, want 3", exit)
	}
}

func TestWasi_PipeCapture(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	w, m := newTestStubs(t, "/")
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}

	const pipeOut int32 = 5000
	if rc := w.Pipe(m, pipeOut); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	readFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut:]))
	writeFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut+4:]))

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "captured-output"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, writeFd, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))

	w.mu.Lock()
	wop := w.fdTable[writeFd]
	rop := w.fdTable[readFd]
	w.mu.Unlock()
	if wop != nil && wop.f != nil {
		if err := wop.f.Close(); err != nil {
			t.Fatalf("close write end: %v", err)
		}
	}
	buf := make([]byte, 256)
	var got []byte
	for {
		n, err := rop.f.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if string(got) != "captured-output\n" {
		t.Errorf("captured = %q, want %q", string(got), "captured-output\\n")
	}
}
