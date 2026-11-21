package codegen

import (
	"slices"
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
		modules []string
		want    []string
	}{
		{
			name:    "wasi and env come first",
			modules: []string{"zeta", "env", "wasip1_posix_extension", "beta", "alpha", "wasi_snapshot_preview1", "zeta"},
			want:    []string{"wasi_snapshot_preview1", "env", "zeta", "beta", "alpha"},
		},
		{
			name:    "the other modules keep their first-import order",
			modules: []string{"alpha", "zeta", "env", "alpha"},
			want:    []string{"env", "alpha", "zeta"},
		},
		{
			name:    "internal imports add no module",
			modules: []string{"wasi"},
			want:    nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod := &wasm.Module{}
			for _, m := range tc.modules {
				name := "f"
				if m == "wasi" {
					name = "thread-spawn"
				}
				mod.Imports = append(mod.Imports, wasm.Import{Module: m, Name: name})
			}
			tr := &translator{mod: mod}
			tr.collectImportModules()
			if !slices.Equal(tr.importedModules, tc.want) {
				t.Fatalf("modules %v: got %v, want %v", tc.modules, tr.importedModules, tc.want)
			}
		})
	}
}
