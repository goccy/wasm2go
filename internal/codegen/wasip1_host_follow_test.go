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
