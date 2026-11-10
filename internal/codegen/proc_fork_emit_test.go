package codegen_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// TestNativeWASIForkRuntime builds the bundle generated for a module that
// imports proc_fork / proc_wait / proc_wait_any / proc_kill and drives them
// from outside the generated package, the way an embedder does: a fork hook
// builds a second module instance on the forked host state.
func TestNativeWASIForkRuntime(t *testing.T) {
	mod := readFixture(t, "cg_wasi_fork.wasm")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := `package main

import (
	"errors"
	"fmt"
	"gentest/pkg"
)

func main() {
	w := pkg.DefaultWASI()
	m := pkg.NewWithWASI(w)
	fmt.Printf("no hook: fork=%d\n", m.Fork())

	fail := true
	w.SetForkHook(func(parent *pkg.Module, child *pkg.WasiStubs, pid int32, exited func(status int32)) (func(sig int32) error, error) {
		if fail {
			return nil, errors.New("refused")
		}
		childModule := pkg.NewWithWASI(child)
		return func(sig int32) error {
			go func() {
				// The child instance has no process of its own to wait
				// for (-12 is ECHILD); it then ends as if killed by sig.
				status := sig
				if childModule.WaitAny(1) != -12 || child.CloseAll() != nil {
					status = 0x7f
				}
				exited(status)
			}()
			return nil
		}, nil
	})
	fmt.Printf("failing hook: fork=%d wait_any=%d\n", m.Fork(), m.WaitAny(0))

	fail = false
	rc := m.Fork()
	pid := m.ForkedPid()
	fmt.Printf("fork=%d pid=%d\n", rc, pid)
	fmt.Printf("running: wait_any(WNOHANG)=%d wait_pid(WNOHANG)=%d\n", m.WaitAny(1), m.WaitPid(pid, 1))
	fmt.Printf("kill unknown=%d probe=%d term=%d\n", m.Kill(pid+1, 15), m.Kill(pid, 0), m.Kill(pid, 15))
	rc = m.WaitAny(0)
	fmt.Printf("wait_any=%d pid_matches=%v status=%d\n", rc, m.WaitedPid() == pid, m.WaitedStatus())
	fmt.Printf("reaped: wait_any=%d wait_pid=%d\n", m.WaitAny(0), m.WaitPid(pid, 0))

	own, exited := w.NewProc(nil)
	exited(3 << 8)
	rc = m.WaitPid(own, 0)
	fmt.Printf("embedder-run: wait_pid=%d status=%d unique=%v\n", rc, m.WaitedStatus(), own != pid)
}
`
	auxFiles := map[string][]byte{}
	for k, v := range res.AuxFiles {
		auxFiles[k] = v
	}
	for k, v := range res.Files {
		auxFiles[k] = v
	}
	out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars}, auxFiles)
	want := strings.Join([]string{
		"no hook: fork=-52\n",
		"failing hook: fork=-6 wait_any=-12\n",
		"fork=0 pid=1001\n",
		"running: wait_any(WNOHANG)=-6 wait_pid(WNOHANG)=-6\n",
		"kill unknown=-71 probe=0 term=0\n",
		"wait_any=0 pid_matches=true status=15\n",
		"reaped: wait_any=-12 wait_pid=-12\n",
		"embedder-run: wait_pid=0 status=768 unique=true\n",
	}, "")
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}

// TestNativeWASIForkMultiPackage compiles the same module in the
// multi-package layout, where the wasi runtime lives in the base package.
func TestNativeWASIForkMultiPackage(t *testing.T) {
	restore := codegen.SetMultiPackageThreshold(0)
	defer restore()
	mod := readFixture(t, "cg_wasi_fork.wasm")
	res, err := codegen.Translate(nil, mod, codegen.Options{
		Package: "wmod", OutputImportPath: "gentest/wmod",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(res.Files) == 0 {
		t.Fatal("multi-package translation produced no files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for rel, data := range res.Files {
		files[rel] = data
	}
	for rel, data := range res.Sidecars {
		files[rel] = data
	}
	for rel, data := range files {
		p := filepath.Join(dir, "wmod", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
}
