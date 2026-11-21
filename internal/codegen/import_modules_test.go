package codegen

import (
	"slices"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// The constructor takes the modules a wasm imports from in this order:
// wasi_snapshot_preview1 (which also serves wasip1_posix_extension), then
// env, then every other module in the order of its first import. Imports
// the code generator implements itself add no module.
func TestImportModuleOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		imports []string // module/name
		want    []string
	}{
		{
			name:    "wasi and env come first",
			imports: []string{"zeta/f", "env/f", "wasip1_posix_extension/pipe", "beta/f", "alpha/f", "wasi_snapshot_preview1/fd_write", "zeta/g"},
			want:    []string{"wasi_snapshot_preview1", "env", "zeta", "beta", "alpha"},
		},
		{
			name:    "the other modules keep their first-import order",
			imports: []string{"alpha/f", "zeta/f", "env/f", "alpha/g"},
			want:    []string{"env", "alpha", "zeta"},
		},
		{
			name:    "wasi-threads thread-spawn adds no module",
			imports: []string{"wasi/thread-spawn"},
			want:    nil,
		},
		{
			name:    "wasi thread_spawn alone adds no module",
			imports: []string{"wasi_snapshot_preview1/thread_spawn"},
			want:    nil,
		},
		{
			name:    "wasi stays first with thread_spawn and another wasi import",
			imports: []string{"env/f", "wasi_snapshot_preview1/thread_spawn", "alpha/f", "wasi_snapshot_preview1/fd_write"},
			want:    []string{"wasi_snapshot_preview1", "env", "alpha"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod := &wasm.Module{}
			for _, imp := range tc.imports {
				module, name, ok := strings.Cut(imp, "/")
				if !ok {
					t.Fatalf("import %q has no module/name form", imp)
				}
				mod.Imports = append(mod.Imports, wasm.Import{Module: module, Name: name})
			}
			tr := &translator{mod: mod}
			tr.collectImportModules()
			if !slices.Equal(tr.importedModules, tc.want) {
				t.Fatalf("imports %v: got %v, want %v", tc.imports, tr.importedModules, tc.want)
			}
		})
	}
}
