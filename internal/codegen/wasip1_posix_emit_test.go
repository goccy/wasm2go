package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
)

// A module that imports from wasip1_posix_extension gets the runtime's
// implementations of them by default — New takes no implementation of its
// own for that module — and they share the instance's state with
// wasi_snapshot_preview1's: a pipe made through wasip1_posix_extension is written
// (through a dup made there) and read through wasi_snapshot_preview1.
func TestPosixImportsAreServedByDefault(t *testing.T) {
	mod := readFixture(t, "cg_wasip1_posix.wasm")
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
	want := "roundtrip=5 data=\"posix\"\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(buf.String(), "Wasip1_posix_extensionImports") {
		t.Errorf("the translation declares an interface of its own for wasip1_posix_extension; its imports belong to wasi_snapshot_preview1's")
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

// The functions of wasip1_posix_extension are not served under
// wasi_snapshot_preview1, except the ones of wasiReleasedPosixImports (pipe,
// fd_dup2, ...); a function wasip1_posix_extension does not have is refused
// under it.
func TestImportsAreServedUnderTheirModuleOnly(t *testing.T) {
	for _, c := range []struct {
		mod, name string
		ok        bool
	}{
		{"wasip1_posix_extension", "fd_dup2", true},
		{"wasip1_posix_extension", "pipe", true},
		{"wasip1_posix_extension", "fd_closefrom", true},
		{"wasip1_posix_extension", "fd_dupfd", true},
		{"wasip1_posix_extension", "fd_cloexec", true},
		{"wasi_snapshot_preview1", "fd_closefrom", false},
		{"wasi_snapshot_preview1", "fd_dupfd", false},
		{"wasi_snapshot_preview1", "fd_cloexec", false},
		{"wasip1_posix_extension", "proc_wait_any", true},
		{"wasip1_posix_extension", "proc_ids", true},
		{"wasip1_posix_extension", "proc_umask", true},
		{"wasi_snapshot_preview1", "proc_wait_any", false},
		{"wasi_snapshot_preview1", "proc_ids", false},
		{"wasi_snapshot_preview1", "proc_umask", false},
		{"wasi_snapshot_preview1", "proc_wait", true},
		{"wasi_snapshot_preview1", "pipe", true},
		{"wasi_snapshot_preview1", "fd_dup2", true},
		{"wasi_snapshot_preview1", "sock_socket", true},
		{"wasi_snapshot_preview1", "sock_connect", true},
		{"wasi_snapshot_preview1", "sock_getaddrinfo", true},
		{"wasi_snapshot_preview1", "path_filestat_mode", true},
		{"wasi_snapshot_preview1", "fd_write", true},
		{"wasip1_posix_extension", "sock_socket", true},
		{"wasip1_posix_extension", "sock_connect", true},
		{"wasip1_posix_extension", "sock_getaddrinfo", true},
		{"wasip1_posix_extension", "path_filestat_mode", false},
		{"wasip1_posix_extension", "fd_write", false},
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

// translatedImports translates a module that imports the given functions,
// each of type () -> i32, and returns the Go source.
func translatedImports(t *testing.T, imports ...[2]string) string {
	t.Helper()
	m := &wasm.Module{Types: []wasm.FuncType{{Results: []wasm.ValType{wasm.ValI32}}}}
	for _, imp := range imports {
		m.Imports = append(m.Imports, wasm.Import{Module: imp[0], Name: imp[1], Kind: wasm.ImportFunc, TypeIdx: 0})
	}
	m.NumImportedFuncs = uint32(len(imports))
	var buf bytes.Buffer
	if _, err := codegen.Translate(&buf, m, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}); err != nil {
		t.Fatalf("translate: %v", err)
	}
	return buf.String()
}

// interfaceMethods returns how often the interface named iface declares
// method in src.
func interfaceMethods(t *testing.T, src, iface, method string) int {
	t.Helper()
	_, body, ok := strings.Cut(src, "type "+iface+" interface {")
	if !ok {
		t.Fatalf("the translation declares no interface %s", iface)
	}
	body, _, ok = strings.Cut(body, "\n}")
	if !ok {
		t.Fatalf("the interface %s does not end", iface)
	}
	return strings.Count(body, "\t"+method+"(")
}

// A function imported under both wasip1_posix_extension and wasi_snapshot_preview1
// is one method of the interface; two imports of another module whose
// names make the same method name stay two.
func TestOneMethodForAnImportOfBothWASIModules(t *testing.T) {
	src := translatedImports(t, [2]string{"wasi_snapshot_preview1", "pipe"}, [2]string{"wasip1_posix_extension", "pipe"})
	if n := interfaceMethods(t, src, "Wasi_snapshot_preview1Imports", "Pipe"); n != 1 {
		t.Errorf("pipe imported under both modules is %d methods, want 1", n)
	}
	src = translatedImports(t, [2]string{"env", "foo"}, [2]string{"env", "Foo"})
	if n := interfaceMethods(t, src, "EnvImports", "Foo"); n != 2 {
		t.Errorf("env.foo and env.Foo are %d methods, want 2", n)
	}
}
