package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
)

// A module that imports from wasmify_posix gets the runtime's
// implementations of them by default — New takes no implementation of its
// own for that module — and they share the instance's state with
// wasi_snapshot_preview1's: a pipe made through wasmify_posix is written
// (through a dup made there) and read through wasi_snapshot_preview1.
func TestWasmifyPosixImportsAreServedByDefault(t *testing.T) {
	mod := readFixture(t, "cg_wasmify_posix.wasm")
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
	m := pkg.New()
	n := m.Roundtrip()
	fmt.Printf("roundtrip=%d data=%q\n", n, m.Memory()[300:300+max(n, 0)])
	m.Umask(0o27)
	fmt.Printf("umask=%o\n", m.Umask(0o22))
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
	want := "roundtrip=5 data=\"posix\"\numask=27\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(buf.String(), "Wasmify_posixImports") {
		t.Errorf("the translation declares an interface of its own for wasmify_posix; its imports belong to wasi_snapshot_preview1's")
	}
}

// translateImport translates a module that imports one function, of type
// () -> i32, from the module mod under name.
func translateImport(mod, name string) error {
	m := &wasm.Module{
		Types:            []wasm.FuncType{{Results: []wasm.ValType{wasm.ValI32}}},
		Imports:          []wasm.Import{{Module: mod, Name: name, Kind: wasm.ImportFunc, TypeIdx: 0}},
		NumImportedFuncs: 1,
	}
	var buf bytes.Buffer
	_, err := codegen.Translate(&buf, m, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	return err
}

// The functions of wasmify_posix are not served under
// wasi_snapshot_preview1, except the ones served there before wasmify_posix
// existed (pipe, proc_spawn, ...), and the legacy imports still served under
// wasi_snapshot_preview1 (sock_socket, ...) are not functions of
// wasmify_posix; neither are the IPv4 socket imports the runtime dropped.
func TestImportsAreServedUnderTheirModuleOnly(t *testing.T) {
	for _, c := range []struct {
		mod, name string
		ok        bool
	}{
		{"wasmify_posix", "proc_fork", true},
		{"wasmify_posix", "pipe", true},
		{"wasi_snapshot_preview1", "proc_fork", false},
		{"wasi_snapshot_preview1", "sock_open", false},
		{"wasi_snapshot_preview1", "sys_syscall", false},
		{"wasi_snapshot_preview1", "pipe", true},
		{"wasi_snapshot_preview1", "proc_spawn", true},
		{"wasi_snapshot_preview1", "sock_socket", true},
		{"wasi_snapshot_preview1", "path_filestat_mode", true},
		{"wasi_snapshot_preview1", "fd_write", true},
		{"wasmify_posix", "sock_socket", false},
		{"wasmify_posix", "fd_write", false},
		{"wasmify_posix", "sock_bind", false},
		{"wasi_snapshot_preview1", "sock_bind", true}, // not the runtime's at all: left to the embedder, as before
	} {
		err := translateImport(c.mod, c.name)
		if c.ok && err != nil {
			t.Errorf("import %s.%s: %v", c.mod, c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("import %s.%s translated; want it refused", c.mod, c.name)
		}
	}
}
