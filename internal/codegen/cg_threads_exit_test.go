package codegen_test

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// A thread of the guest that calls proc_exit ends the instance: the thread
// itself ends without taking the host process down, and the main thread
// unwinds with the same *WasiExitError at its next host call, or from its
// wait on the memory for the thread (join).
func TestThreadsExitEndsEveryThread(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_threads_exit.wasm")
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
	"os"

	"gentest/pkg"
)

func main() {
	run(func(m *pkg.Module) { m.Run() })
	run(func(m *pkg.Module) { m.Join() })
}

func run(call func(*pkg.Module)) {
	m := pkg.NewWithWASI(pkg.NewWASI(pkg.WASIConfig{Stdout: os.Stdout}))
	defer func() { fmt.Println("main thread ended:", recover()) }()
	call(m)
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, filesWithAux(res))
	if want := "main thread ended: wasi: proc_exit(7)\nmain thread ended: wasi: proc_exit(7)\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
}
