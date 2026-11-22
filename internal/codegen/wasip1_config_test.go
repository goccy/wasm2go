package codegen

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The zero WASIConfig gives the guest nothing: no preopen, no file, no
// arguments, no environment, an empty stdin, discarded output, and no
// socket operation, connection, lookup or spawn. A WasiStubs built as a
// bare struct literal is the same.
func TestWasi_ZeroConfigDenies(t *testing.T) {
	for name, w := range map[string]*WasiStubs{"NewWASI": NewWASI(WASIConfig{}), "literal": {}} {
		t.Run(name, func(t *testing.T) {
			testZeroConfigDenies(t, w)
		})
	}
}

func testZeroConfigDenies(t *testing.T, w *WasiStubs) {
	m := newGuestModule(1 << 16)

	// Neither number of the root directory is open.
	if rc := w.Fd_prestat_get(m, 3, 100); rc != _wasiEBADF {
		t.Errorf("Fd_prestat_get(3) rc=%d, want EBADF", rc)
	}
	if rc := w.Fd_prestat_dir_name(m, 3, 100, 1); rc != _wasiEBADF {
		t.Errorf("Fd_prestat_dir_name(3) rc=%d, want EBADF", rc)
	}
	for _, fd := range []int32{wasiPreopenFD, wasiRootFD} {
		if rc := w.Fd_fdstat_get(m, fd, 300); rc != _wasiEBADF {
			t.Errorf("Fd_fdstat_get(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_filestat_get(m, fd, 300); rc != _wasiEBADF {
			t.Errorf("Fd_filestat_get(%d) rc=%d, want EBADF", fd, rc)
		}
		if rc := w.Fd_filestat_ext(m, fd, 300); rc != -_wasiEBADF {
			t.Errorf("Fd_filestat_ext(%d) rc=%d, want -EBADF", fd, rc)
		}
		if rc := w.Fd_path(m, fd, 300, 64, 400); rc != -_wasiEBADF {
			t.Errorf("Fd_path(%d) rc=%d, want -EBADF", fd, rc)
		}
	}
	if rc := w.Fd_close(m, wasiPreopenFD); rc != _wasiEBADF {
		t.Errorf("Fd_close(3) rc=%d, want EBADF", rc)
	}
	off, n := putPath(m, 128, "etc/passwd")
	if rc := w.Path_open(m, 3, 0, off, n, 0, 1<<1, 0, 0, 200); rc != _wasiEBADF {
		t.Errorf("Path_open in fd 3 rc=%d, want EBADF", rc)
	}
	// The path operations that name no directory reach a filesystem that
	// has no file.
	if rc := w.Path_chown(m, off, n, -1, -1, 1); rc != -_wasiENOENT {
		t.Errorf("Path_chown rc=%d, want -ENOENT", rc)
	}
	if rc := w.Path_filestat_ext(m, off, n, 1, 300); rc != -_wasiENOENT {
		t.Errorf("Path_filestat_ext rc=%d, want -ENOENT", rc)
	}

	if rc := w.Args_sizes_get(m, 0, 4); rc != _wasiESUCCESS || readU32(m.memory, 0) != 0 {
		t.Errorf("Args_sizes_get rc=%d argc=%d, want no arguments", rc, readU32(m.memory, 0))
	}
	if rc := w.Environ_sizes_get(m, 0, 4); rc != _wasiESUCCESS || readU32(m.memory, 0) != 0 {
		t.Errorf("Environ_sizes_get rc=%d envc=%d, want no environment", rc, readU32(m.memory, 0))
	}
	if got, rc := fdReadString(w, m, 0, 8); rc != _wasiESUCCESS || got != "" {
		t.Errorf("read stdin = %q rc=%d, want EOF", got, rc)
	}
	for _, fd := range []int32{1, 2} {
		if rc := fdWriteString(w, m, fd, "out"); rc != _wasiESUCCESS || readU32(m.memory, int(forkTestCountOff)) != 3 {
			t.Errorf("write fd %d rc=%d, want the output discarded", fd, rc)
		}
	}

	nameOff, nameLen := putPath(m, 512, "localhost")
	if rc := w.Sock_getaddrinfo(m, nameOff, nameLen, 600); rc != -_wasiEACCES {
		t.Errorf("Sock_getaddrinfo rc=%d, want -EACCES", rc)
	}
	// fd 3 is a free number: the first new descriptor gets it.
	sock := w.Sock_socket(m, 2, 1)
	if sock != wasiPreopenFD {
		t.Errorf("Sock_socket = %d, want 3", sock)
	}
	if rc := w.Sock_connect(m, sock, 0x0100007f, 80); rc != -_wasiEACCES {
		t.Errorf("Sock_connect rc=%d, want -EACCES", rc)
	}
	if rc := w.Sock_accept(m, sock, 0, 200); rc != _wasiEACCES {
		t.Errorf("Sock_accept rc=%d, want EACCES", rc)
	}
	if rc := w.Sock_send(m, sock, 0, 0, 0, 200); rc != _wasiEACCES {
		t.Errorf("Sock_send rc=%d, want EACCES", rc)
	}
	if rc := w.Sock_recv(m, sock, 0, 0, 0, 200, 204); rc != _wasiEACCES {
		t.Errorf("Sock_recv rc=%d, want EACCES", rc)
	}
	if rc := w.Fd_fdstat_get(m, sock, 300); rc != _wasiESUCCESS || m.memory[300] != 6 {
		t.Errorf("Fd_fdstat_get of the socket at fd 3 rc=%d type=%d, want a socket", rc, m.memory[300])
	}
	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "x"})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiEACCES {
		t.Errorf("Proc_spawn rc=%d, want -EACCES", rc)
	}

	// A fork has the same configuration: it has no preopen either.
	if rc := w.Fork().Fd_prestat_get(m, 3, 100); rc != _wasiEBADF {
		t.Errorf("Fd_prestat_get(3) of a fork rc=%d, want EBADF", rc)
	}
}

// Every operation of the filesystem of a configuration without one fails
// with fs.ErrNotExist.
func TestWasi_NoFSHasNoFile(t *testing.T) {
	var fsys noFS
	_, openErr := fsys.OpenFile("a", os.O_RDONLY, 0)
	_, statErr := fsys.Stat("a")
	_, lstatErr := fsys.Lstat("a")
	_, readlinkErr := fsys.Readlink("a")
	for name, err := range map[string]error{
		"OpenFile": openErr,
		"Mkdir":    fsys.Mkdir("a", 0o755),
		"Chmod":    fsys.Chmod("a", 0o644),
		"Chtimes":  fsys.Chtimes("a", time.Time{}, time.Time{}),
		"Chown":    fsys.Chown("a", 0, 0, true),
		"Remove":   fsys.Remove("a"),
		"Rename":   fsys.Rename("a", "b"),
		"Stat":     statErr,
		"Lstat":    lstatErr,
		"Symlink":  fsys.Symlink("a", "b"),
		"Readlink": readlinkErr,
		"Link":     fsys.Link("a", "b"),
	} {
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v, want fs.ErrNotExist", name, err)
		}
	}
}

// A nil filesystem or standard stream stands for none: noFS, an empty
// stdin, a stdout and a stderr that discard.
func TestWasi_NilConfigFields(t *testing.T) {
	w := &WasiStubs{}
	if w.stdout() != io.Discard || w.stderr() != io.Discard {
		t.Error("stdout and stderr do not discard")
	}
	if n, err := w.stdin().Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Errorf("stdin read = %d, %v; want EOF", n, err)
	}
	if _, ok := w.fs().(noFS); !ok {
		t.Errorf("FS = %#v, want noFS", w.fs())
	}
}

// NewWASI copies the arguments and the environment.
func TestWasi_NewWASICopiesArgsAndEnv(t *testing.T) {
	args, env := []string{"prog"}, []string{"A=1"}
	w := NewWASI(WASIConfig{Args: args, Env: env})
	args[0], env[0] = "changed", "B=2"
	if w.cfg.Args[0] != "prog" || w.cfg.Env[0] != "A=1" {
		t.Errorf("args %v env %v follow the caller's slices", w.cfg.Args, w.cfg.Env)
	}
}

// HostWASIConfig gives the guest what the host process has.
func TestWasi_HostWASIConfig(t *testing.T) {
	cfg := HostWASIConfig()
	if !slices.Equal(cfg.Args, os.Args) || !slices.Equal(cfg.Env, os.Environ()) {
		t.Error("args or environment are not the host process's")
	}
	if cfg.Stdin != os.Stdin || cfg.Stdout != os.Stdout || cfg.Stderr != os.Stderr {
		t.Error("stdio streams are not the host process's")
	}
	if cfg.FS != (osFS{}) {
		t.Errorf("FS = %#v, want the whole host filesystem", cfg.FS)
	}
	if cfg.FSAccess != nil {
		t.Error("FSAccess is set, want every access to FS allowed")
	}
	if cfg.LocalZone != time.Local {
		t.Errorf("LocalZone = %v, want time.Local", cfg.LocalZone)
	}
	if !cfg.NetAccess("send") || !cfg.Dial("tcp", "example.com", "192.0.2.1", 80) ||
		!cfg.Resolve("example.com") || !cfg.Exec("/bin/sh", []string{"sh"}) {
		t.Error("a hook denies")
	}

	w := NewWASI(cfg)
	m := newGuestModule(1 << 16)
	if rc := w.Fd_prestat_get(m, 3, 100); rc != _wasiESUCCESS {
		t.Errorf("Fd_prestat_get(3) rc=%d, want the root preopened", rc)
	}
	hostOff, hostLen := putPath(m, 512, "localhost")
	if rc := w.Sock_getaddrinfo(m, hostOff, hostLen, 600); rc != _wasiESUCCESS {
		t.Errorf("Sock_getaddrinfo(localhost) rc=%d, want the lookup allowed", rc)
	}
}

// The AllowAll hooks allow everything.
func TestWasi_AllowAllHooks(t *testing.T) {
	if !AllowAllNetAccess("accept") || !AllowAllDial("tcp", "", "127.0.0.1", 1) ||
		!AllowAllResolve("localhost") || !AllowAllExec("/bin/true", nil) {
		t.Error("an AllowAll hook denies")
	}
}

// FSAccess is consulted on every path operation, with each path it names
// and whether the operation writes; a denied operation leaves the
// filesystem as it was.
func TestWasi_FSAccessGatesEveryPathOperation(t *testing.T) {
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
	// Only "f" may be written.
	w.cfg.FSAccess = func(path string, write bool) bool {
		seen = append(seen, fmt.Sprintf("%s:%v", path, write))
		return !write || path == "f"
	}
	f, fn := putPath(m, 128, "f")
	g, gn := putPath(m, 160, "g")
	d, dn := putPath(m, 192, "d")
	l, ln := putPath(m, 224, "l")
	type op struct {
		name   string
		call   func() int32
		denied int32
		seen   []string
	}
	writes := []op{
		{"path_open creating", func() int32 { return w.Path_open(m, 3, 0, g, gn, 0x1, 1<<6, 0, 0, 300) }, _wasiEACCES, []string{"g:true"}},
		{"path_create_directory", func() int32 { return w.Path_create_directory(m, 3, g, gn) }, _wasiEACCES, []string{"g:true"}},
		{"path_unlink_file", func() int32 { return w.Path_unlink_file(m, 3, l, ln) }, _wasiEACCES, []string{"l:true"}},
		{"path_remove_directory", func() int32 { return w.Path_remove_directory(m, 3, d, dn) }, _wasiEACCES, []string{"d:true"}},
		{"path_rename", func() int32 { return w.Path_rename(m, 3, f, fn, 3, g, gn) }, _wasiEACCES, []string{"f:true", "g:true"}},
		{"path_link", func() int32 { return w.Path_link(m, 3, 0, f, fn, 3, g, gn) }, _wasiEACCES, []string{"f:true", "g:true"}},
		{"path_symlink", func() int32 { return w.Path_symlink(m, f, fn, 3, g, gn) }, _wasiEACCES, []string{"g:true", "f:false", "f:true"}},
		{"path_filestat_set_times", func() int32 { return w.Path_filestat_set_times(m, 3, 0, d, dn, 0, 0, 0x2|0x8) }, _wasiEACCES, []string{"d:true"}},
		{"path_chmod", func() int32 { return w.Path_chmod(m, d, dn, 0o700) }, -_wasiEACCES, []string{"d:true"}},
		{"path_chown", func() int32 { return w.Path_chown(m, d, dn, -1, -1, 1) }, -_wasiEACCES, []string{"d:true"}},
	}
	reads := []op{
		{"path_open for reading", func() int32 { return w.Path_open(m, 3, 0, f, fn, 0, 1<<1, 0, 0, 300) }, _wasiEACCES, []string{"f:false"}},
		{"path_filestat_get", func() int32 { return w.Path_filestat_get(m, 3, 0, f, fn, 300) }, _wasiEACCES, []string{"f:false"}},
		{"path_filestat_ext", func() int32 { return w.Path_filestat_ext(m, f, fn, 0, 300) }, -_wasiEACCES, []string{"f:false"}},
		{"path_filestat_mode", func() int32 { return w.Path_filestat_mode(m, f, fn, 0, 300) }, -_wasiEACCES, []string{"f:false"}},
		{"path_readlink", func() int32 { return w.Path_readlink(m, 3, l, ln, 300, 64, 400) }, _wasiEACCES, []string{"l:false"}},
	}
	for _, o := range writes {
		seen = nil
		if rc := o.call(); rc != o.denied || !slices.Equal(seen, o.seen) {
			t.Errorf("%s: rc=%d, hook saw %v; want %d after %v", o.name, rc, seen, o.denied, o.seen)
		}
	}
	for _, name := range []string{"f", "d", "l"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s after the denied writes: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "g")); !os.IsNotExist(err) {
		t.Errorf("g exists after the denied writes: %v", err)
	}
	// This hook allows the reads; one that refuses reads denies them.
	for _, o := range reads {
		if rc := o.call(); rc != _wasiESUCCESS {
			t.Errorf("%s allowed: rc=%d", o.name, rc)
		}
	}
	w.cfg.FSAccess = func(path string, write bool) bool {
		seen = append(seen, fmt.Sprintf("%s:%v", path, write))
		return write
	}
	for _, o := range reads {
		seen = nil
		if rc := o.call(); rc != o.denied || !slices.Equal(seen, o.seen) {
			t.Errorf("%s: rc=%d, hook saw %v; want %d after %v", o.name, rc, seen, o.denied, o.seen)
		}
	}
}
