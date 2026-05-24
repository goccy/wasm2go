package main

import (
	"bytes"
	"flag"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
)

// resetFlags creates a fresh flag.CommandLine so that the flags declared in
// main() can be registered again in the next call. main() uses the package-
// level flag.Bool/flag.String functions which register into flag.CommandLine.
func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

// arithWasm returns a path to a compiled arith.wasm fixture.
func arithWasm(t *testing.T) string {
	t.Helper()
	return testfixture.WasmPath(t, "arith")
}

func memoryWasm(t *testing.T) string {
	t.Helper()
	return testfixture.WasmPath(t, "memory")
}

func helloWasm(t *testing.T) string {
	t.Helper()
	return testfixture.WasmPath(t, "hello")
}

func ssaWasm(t *testing.T) string {
	t.Helper()
	return testfixture.WasmPath(t, "ssa_cf")
}

// captureStdout redirects os.Stdout to a buffer for the duration of f, then
// restores it and returns what was written.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		tmp := make([]byte, 4096)
		for {
			n, _ := r.Read(tmp)
			if n == 0 {
				break
			}
			buf.Write(tmp[:n])
		}
		done <- buf.String()
	}()

	f()
	w.Close()
	return <-done
}

// captureStderr redirects os.Stderr for the duration of f.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		tmp := make([]byte, 4096)
		for {
			n, _ := r.Read(tmp)
			if n == 0 {
				break
			}
			buf.Write(tmp[:n])
		}
		done <- buf.String()
	}()

	f()
	w.Close()
	return <-done
}

// runMain sets os.Args and calls main(). It panics (via the flag package's
// ExitOnError) or os.Exit on error paths; use runMainErr for error paths.
func runMain(t *testing.T, args ...string) {
	t.Helper()
	resetFlags()
	os.Args = append([]string{"wasm2go"}, args...)
	main()
}

// TestStdinInput tests that when -i is omitted, main reads from os.Stdin.
func TestStdinInput(t *testing.T) {
	// Open the arith.wasm file and pipe it via os.Stdin.
	f, err := os.Open(arithWasm(t))
	if err != nil {
		t.Fatalf("open wasm: %v", err)
	}
	defer f.Close()

	oldStdin := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = oldStdin }()

	out := captureStdout(t, func() {
		runMain(t, "-import", "example.com/test/pkg")
	})
	if !strings.Contains(out, "package wasm2go") {
		t.Errorf("stdin path output missing 'package wasm2go'; got:\n%s", out[:min(len(out), 300)])
	}
}

// TestTranslateToStdout tests the default path: -i FILE, output goes to stdout.
func TestTranslateToStdout(t *testing.T) {
	out := captureStdout(t, func() {
		runMain(t, "-i", arithWasm(t), "-import", "example.com/test/pkg")
	})
	if !strings.Contains(out, "package wasm2go") {
		t.Errorf("stdout missing 'package wasm2go'; got:\n%s", out[:min(len(out), 500)])
	}
	// Must be valid Go.
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "out.go", out, parser.ParseComments); err != nil {
		t.Fatalf("output is not valid Go: %v", err)
	}
}

// TestTranslateWithPkg tests the -pkg flag changes the package name.
func TestTranslateWithPkg(t *testing.T) {
	out := captureStdout(t, func() {
		runMain(t, "-i", arithWasm(t), "-pkg", "mymod", "-import", "example.com/test/mymod")
	})
	if !strings.Contains(out, "package mymod") {
		t.Errorf("stdout missing 'package mymod'")
	}
}

// TestTranslateToFile tests -i and -o flags.
func TestTranslateToFile(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "out.go")
	runMain(t, "-i", arithWasm(t), "-o", outFile, "-import", "example.com/test/pkg")

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), "package wasm2go") {
		t.Errorf("output file missing expected package declaration")
	}
}

// TestDumpFlag tests the -dump flag which prints module summary to stderr.
func TestDumpFlag(t *testing.T) {
	stderrOut := captureStderr(t, func() {
		runMain(t, "-i", arithWasm(t), "-dump")
	})
	if !strings.Contains(stderrOut, "functions:") {
		t.Errorf("-dump output missing 'functions:'; got:\n%s", stderrOut)
	}
	if !strings.Contains(stderrOut, "exports:") {
		t.Errorf("-dump output missing 'exports:'")
	}
}

// TestDumpFlagWithMemory tests -dump on a module with memory.
func TestDumpFlagWithMemory(t *testing.T) {
	out := captureStderr(t, func() {
		runMain(t, "-i", memoryWasm(t), "-dump")
	})
	if !strings.Contains(out, "memories:") {
		t.Errorf("-dump output missing 'memories:'; got:\n%s", out)
	}
	if !strings.Contains(out, "datas:") {
		t.Errorf("-dump output missing 'datas:'")
	}
}

// TestSSAOutput drives the SSA-targeted fixture and checks the output is
// valid Go. The SSA pipeline is always on; this is just a smoke test
// confirming the CLI still produces a compileable file.
func TestSSAOutput(t *testing.T) {
	out := captureStdout(t, func() {
		runMain(t, "-i", ssaWasm(t), "-import", "example.com/test/pkg")
	})
	if !strings.Contains(out, "package wasm2go") {
		t.Errorf("ssa output missing 'package wasm2go'")
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "out.go", out, parser.ParseComments); err != nil {
		t.Fatalf("ssa output is not valid Go: %v", err)
	}
}

// TestNativeWASIDefault confirms the auto-on native wasip1 emission via
// the CLI.
func TestNativeWASIDefault(t *testing.T) {
	out := captureStdout(t, func() {
		runMain(t, "-i", helloWasm(t), "-import", "example.com/test/pkg")
	})
	if !strings.Contains(out, "package wasm2go") {
		t.Errorf("native-wasi output missing package decl")
	}
}

// TestMissingImport tests that omitting -import is a fatal error.
func TestMissingImport(t *testing.T) {
	cmd := buildAndRun(t, "-i", arithWasm(t))
	if cmd.ProcessState.ExitCode() == 0 {
		t.Errorf("expected non-zero exit when -import is missing")
	}
}

// TestMissingInput tests error when input file does not exist.
func TestMissingInput(t *testing.T) {
	cmd := buildAndRun(t, "-i", "/nonexistent/file.wasm", "-import", "example.com/test/pkg")
	if cmd.ProcessState.ExitCode() == 0 {
		t.Errorf("expected non-zero exit for missing input")
	}
}

// TestBadWasm tests error on a non-wasm file.
func TestBadWasm(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(bad, []byte("not a wasm file"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := buildAndRun(t, "-i", bad, "-import", "example.com/test/pkg")
	if cmd.ProcessState.ExitCode() == 0 {
		t.Errorf("expected non-zero exit for invalid wasm")
	}
}

// TestBulkExportPrefix exercises the -bulk-export-prefix flag.
func TestBulkExportPrefix(t *testing.T) {
	bin := testfixture.WasmPath(t, "wexports")
	out := captureStdout(t, func() {
		runMain(t, "-i", bin, "-import", "example.com/test/pkg",
			"-bulk-export-prefix", "w_")
	})
	if !strings.Contains(out, "func Inv_0_0(") {
		t.Errorf("bulk-export-prefix output missing per-export Inv_ functions")
	}
}

// TestKeepDeadFuncs exercises the -keep-dead-funcs flag.
func TestKeepDeadFuncs(t *testing.T) {
	bin := testfixture.WasmPath(t, "deadfunc")
	out := captureStdout(t, func() {
		runMain(t, "-i", bin, "-import", "example.com/test/pkg", "-keep-dead-funcs")
	})
	if !strings.Contains(out, "package wasm2go") {
		t.Errorf("-keep-dead-funcs output missing package decl")
	}
}

// TestEntryExports exercises the -entry-exports flag (which replaces the
// old WASM2GO_ENTRY_EXPORTS env var). NONE means no export is a DCE
// root; only start/table/transitive call roots survive.
func TestEntryExports(t *testing.T) {
	for _, v := range []string{"add", "NONE"} {
		v := v
		t.Run(v, func(t *testing.T) {
			out := captureStdout(t, func() {
				runMain(t, "-i", arithWasm(t), "-import", "example.com/test/pkg",
					"-entry-exports", v)
			})
			if !strings.Contains(out, "package wasm2go") {
				t.Errorf("-entry-exports=%s output missing package decl", v)
			}
		})
	}
}

// buildAndRun compiles the wasm2go binary and runs it with args.
// It returns the completed exec.Cmd (with ProcessState set).
// This is used for error-path tests where fail() calls os.Exit.
func buildAndRun(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "wasm2go_test_bin")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, args...)
	_ = cmd.Run() // ignore error; we check ExitCode
	return cmd
}

// TestPrintSummaryWithStart tests the printSummary path for a module with a
// start function. We use the cli_start.wat fixture which has a start section.
func TestPrintSummaryWithStart(t *testing.T) {
	p := testfixture.WasmPath(t, "cli_start")
	out := captureStderr(t, func() {
		runMain(t, "-i", p, "-dump")
	})
	if !strings.Contains(out, "start:") {
		t.Errorf("dump output missing 'start:'; got:\n%s", out)
	}
}

// TestDumpWithElements tests a module that has an element section.
func TestDumpWithElements(t *testing.T) {
	p := testfixture.WasmPath(t, "vtable_dispatch")
	out := captureStderr(t, func() {
		runMain(t, "-i", p, "-dump")
	})
	if !strings.Contains(out, "elements:") {
		t.Errorf("dump output missing 'elements:'; got:\n%s", out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
