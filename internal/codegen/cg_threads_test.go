package codegen_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestThreads drives cg_threads.wasm, whose guest spawns real agents through
// wasi thread-spawn, has them bump a counter with atomics on shared memory and
// notify, and joins them with memory.atomic.wait. wazero cannot be the
// reference here (its threads support has no wasi-threads host), so the
// expectations are the wasm's own deterministic semantics.
//
// The generated program is compiled and run with the race detector, which is
// the real assertion: a wasm thread is a goroutine, so any unsynchronised
// access to the shared linear memory — above all a grow that relocated it —
// surfaces as a race, not as a flake.
func TestThreadsVisibility(t *testing.T) {
	// A plain store published by an atomic store must be visible to a
	// goroutine-agent that acquires via an atomic load — the mutex fast-path
	// pattern every C critical section relies on.
	bin := testfixture.Wasm(t, "cg_threads_visibility.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "4242" {
		t.Errorf("cross-thread plain-store visibility: got %q, want 4242", got)
	}
}

func TestThreadsMainToAgentWake(t *testing.T) {
	// The main thread notifies a parked agent — the direction a C mutex
	// handoff uses when main unlocks while an agent sleeps on the futex.
	bin := testfixture.Wasm(t, "cg_threads_wake_dir.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "7777" {
		t.Errorf("main->agent wake: got %q, want 7777", got)
	}
}

func TestThreadsMutexHandoff(t *testing.T) {
	// Two threads hammer a Drepper futex mutex 50k times each; a lost
	// waiter-bit observation wedges one side forever.
	bin := testfixture.Wasm(t, "cg_threads_mutex.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "100000" {
		t.Errorf("mutex handoff: got %q, want 100000", got)
	}
}

func TestThreadsMuslLock(t *testing.T) {
	// musl's 2-int __lock/__unlock: the unlock side reads the waiters counter
	// with a PLAIN load to decide whether to notify. Preserving wasm's
	// coherent-plain-access semantics across goroutines is what keeps
	// wasi-libc's malloc/stdio/internal locks from stranding threads.
	bin := testfixture.Wasm(t, "cg_threads_musl_lock.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	// No -race here: wasm's shared-memory model makes plain cross-agent
	// access a LEGAL race (coherent, tear-free words); Go's detector would
	// flag every such access. The assertion is completion + the exact count.
	got := runGoSnippetNoRace(t, buf.String(), main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "100000" {
		t.Errorf("musl lock handoff: got %q, want 100000", got)
	}
}

func TestThreads(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_threads.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	// The only wasi import (thread-spawn) is goroutine-backed and internal,
	// so the generated constructor takes no host parameters at all.
	m := pkg.New()
	// 8 agents, each +1 on the counter, joined through atomic wait/notify.
	fmt.Printf("joined -> %d\n", m.SpawnAndJoin(8))
	// Growing a shared memory must preserve both contents and pointers:
	// 2 pages * 65536 + 0xbeef = 131072 + 48879.
	fmt.Printf("grown -> %d\n", m.GrowShared())
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	want := "joined -> 8\ngrown -> 179951\n"
	if got != want {
		t.Errorf("output mismatch\n--want--\n%s\n--got--\n%s", want, got)
	}
	if strings.Contains(got, "DATA RACE") {
		t.Errorf("race detected:\n%s", got)
	}
}

// runGoSnippetNoRace runs the generated program without the race detector —
// for wasm whose SHARED-memory plain accesses are legal wasm races that the
// Go detector would (correctly, but unhelpfully) flag.
func runGoSnippetNoRace(t *testing.T, generated, mainSrc string, sidecars map[string][]byte, auxFiles map[string][]byte) string {
	t.Helper()
	return runGoSnippetThreads(t, generated, mainSrc, sidecars, auxFiles, false)
}

// runGoSnippetRaceDetector is runGoSnippetWithAux with -race: a wasm thread is
// a goroutine, so the detector is the assertion that the shared-memory model
// (fixed slice header, atomic memSize, relocation-free grow) actually holds.
func runGoSnippetRaceDetector(t *testing.T, generated, mainSrc string, sidecars map[string][]byte, auxFiles map[string][]byte) string {
	t.Helper()
	return runGoSnippetThreads(t, generated, mainSrc, sidecars, auxFiles, true)
}

func runGoSnippetThreads(t *testing.T, generated, mainSrc string, sidecars map[string][]byte, auxFiles map[string][]byte, race bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "gen.go"), []byte(generated), 0644); err != nil {
		t.Fatal(err)
	}
	for _, set := range []map[string][]byte{sidecars, auxFiles} {
		for name, data := range set {
			p := filepath.Join(dir, "pkg", name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}
	runArgs := []string{"run"}
	if race {
		runArgs = append(runArgs, "-race")
	}
	runArgs = append(runArgs, ".")
	cmd := exec.Command("go", runArgs...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\noutput:\n%s\ngenerated:\n%s", err, out, generated)
	}
	return string(out)
}
