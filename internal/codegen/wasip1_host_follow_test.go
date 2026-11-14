//go:build darwin || linux

package codegen

import (
	"os"
	"path/filepath"
	"testing"
)

// The host process follows the working directory and the environment of
// the guest that is it, and of no other process of the family.
func TestHostProcessFollowsDirectoryAndEnvironment(t *testing.T) {
	start, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(start)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WASI_FOLLOWED", "before")
	w := DefaultWASI()
	m := newForkTestModule()
	path := writeCStr(m, 1000, dir)
	name := writeCStr(m, 2000, "WASI_FOLLOWED")
	value := writeCStr(m, 2100, "after")

	// an isolated guest: the host process stays where it is
	if rc := w.Proc_chdir(m, path, int32(len(dir))); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir rc=%d", rc)
	}
	if rc := w.Proc_setenv(m, name, 13, value, 5, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv rc=%d", rc)
	}
	if now, _ := os.Getwd(); now != start || os.Getenv("WASI_FOLLOWED") != "before" {
		t.Fatalf("the host process followed an isolated guest: %s, %s", now, os.Getenv("WASI_FOLLOWED"))
	}

	w.SetHostProcess(true)
	defer w.SetHostProcess(false)
	// a forked process: its changes are its own
	child := w.Fork()
	defer child.CloseAll()
	if rc := child.Proc_chdir(m, path, int32(len(dir))); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir rc=%d", rc)
	}
	if rc := child.Proc_setenv(m, name, 13, value, 5, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv rc=%d", rc)
	}
	if now, _ := os.Getwd(); now != start || os.Getenv("WASI_FOLLOWED") != "before" {
		t.Fatalf("the host process followed a forked process: %s, %s", now, os.Getenv("WASI_FOLLOWED"))
	}

	if rc := w.Proc_chdir(m, path, int32(len(dir))); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir rc=%d", rc)
	}
	if rc := w.Proc_setenv(m, name, 13, value, 5, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv rc=%d", rc)
	}
	if now, _ := os.Getwd(); now != dir {
		t.Fatalf("working directory of the host process = %s, want %s", now, dir)
	}
	if got := os.Getenv("WASI_FOLLOWED"); got != "after" {
		t.Fatalf("variable in the host process = %q, want %q", got, "after")
	}
	if rc := w.Proc_setenv(m, name, 13, 0, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv (remove) rc=%d", rc)
	}
	if _, set := os.LookupEnv("WASI_FOLLOWED"); set {
		t.Fatal("the variable was not removed from the host process")
	}
}

// hostCreatedMode creates a file the way code of the host does (not through
// the guest) and returns its permission bits.
func hostCreatedMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The host process follows the file mode creation mask of the guest that is
// it, and of no other process of the family: a file that code of the host
// creates for the program (a native extension's) gets the program's mask.
func TestHostProcessFollowsUmask(t *testing.T) {
	start := processUmask()
	defer setProcessUmask(start)
	dir := t.TempDir()
	w, m := newProcTestStubs(t)

	// an isolated guest: the host process keeps its mask
	w.Proc_umask(m, 0o077)
	if got := processUmask(); got != start {
		t.Fatalf("the host process followed an isolated guest's umask: %o, want %o", got, start)
	}
	if got, want := hostCreatedMode(t, filepath.Join(dir, "isolated")), 0o666&^start; got != want {
		t.Fatalf("file the host created = %o, want %o", got, want)
	}

	w.SetHostProcess(true)
	defer w.SetHostProcess(false)
	// a forked process: its mask is its own
	child := w.Fork()
	defer child.CloseAll()
	child.Proc_umask(m, 0o007)
	if got := processUmask(); got != start {
		t.Fatalf("the host process followed a forked process's umask: %o, want %o", got, start)
	}

	if prev := w.Proc_umask(m, 0o070); os.FileMode(prev) != 0o077 {
		t.Fatalf("umask returned %o, want the guest's previous mask 077", prev)
	}
	if got := processUmask(); got != 0o070 {
		t.Fatalf("umask of the host process = %o, want 070", got)
	}
	if got := hostCreatedMode(t, filepath.Join(dir, "followed")); got != 0o606 {
		t.Fatalf("file the host created = %o, want 606", got)
	}
	// the guest's own files are created as before
	if got := os.FileMode(createWithMode(t, w, m, "guest", 0o666)); got != 0o606 {
		t.Fatalf("file the guest created = %o, want 606", got)
	}
}
