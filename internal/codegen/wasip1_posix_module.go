package codegen

import (
	"fmt"

	"github.com/goccy/wasm2go/internal/wasm"
)

// The host imports of wasm2go's wasi runtime come in two modules:
//
//   - wasi_snapshot_preview1, WASI's own functions;
//   - wasmify_posix, POSIX functions WASI does not have: the ones of
//     wasmifyPosixImports. The guest side is wasmify's shims, which declare
//     them and build the C library's functions on them; the host side is
//     WasiStubs.
//
// One WasiStubs answers both: the two share the instance's descriptors,
// processes and signals. So a module that imports from wasmify_posix gets no
// interface or constructor parameter of its own for it: its imports become
// methods of the wasi_snapshot_preview1 interface, which DefaultWASI — or the
// embedder's implementation passed to NewWithWASI — provides.
const (
	wasiModule         = "wasi_snapshot_preview1"
	wasmifyPosixModule = "wasmify_posix"
)

// wasmifyPosixImports are the imports of wasmify_posix. A memory64 module
// binds each to its *64 method, as it does wasi_snapshot_preview1's. They
// are served under wasi_snapshot_preview1 as well.
var wasmifyPosixImports = map[string]bool{
	"fd_dup":     true,
	"fd_dup2":    true,
	"path_chmod": true,
	"pipe":       true,
	"proc_spawn": true,
	"proc_wait":  true,
}

// servingModule returns the import module whose implementation answers an
// import of mod: wasi_snapshot_preview1's for wasmify_posix (see above), the
// module itself for any other.
func servingModule(mod string) string {
	if mod == wasmifyPosixModule {
		return wasiModule
	}
	return mod
}

// servedByWASI reports whether an import of mod is answered by the wasi
// runtime: one of wasi_snapshot_preview1 or of wasmify_posix.
func servedByWASI(mod string) bool { return servingModule(mod) == wasiModule }

// importModuleError reports a function import the wasi runtime does not
// serve under the module it names: a name wasmify_posix does not have.
func importModuleError(imp wasm.Import) error {
	if imp.Kind != wasm.ImportFunc {
		return nil
	}
	switch imp.Module {
	case wasmifyPosixModule:
		if !wasmifyPosixImports[imp.Name] {
			return fmt.Errorf("import %s.%s: %s has no function %q", imp.Module, imp.Name, wasmifyPosixModule, imp.Name)
		}
	}
	return nil
}
