package codegen_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// TestMultiPackageBuildsAndCompiles drives several fixtures through
// the multi-package + linkname-split layout with the threshold lowered
// to 0 (forcing the partitioner to bin-pack one function per chunk)
// and runs `go build ./...` against the emitted module to catch any
// import-block / linkname-forward drift.
func TestMultiPackageBuildsAndCompiles(t *testing.T) {
	restore := codegen.SetMultiPackageThreshold(0)
	defer restore()
	for _, fx := range []string{"arith.wasm", "wexports.wasm", "cg_wasi.wasm", "cg_indirect.wasm"} {
		fx := fx
		t.Run(fx, func(t *testing.T) {
			mod := readFixture(t, fx)
			res, err := codegen.Translate(nil, mod, codegen.Options{
				Package: "wmod", OutputImportPath: "gentest/wmod",
			})
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			dir := t.TempDir()
			gomod := "module gentest\n\ngo 1.25.0\n"
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
				t.Fatal(err)
			}
			for rel, data := range res.Files {
				p := filepath.Join(dir, "wmod", rel)
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, data, 0644); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range res.Sidecars {
				if err := os.WriteFile(filepath.Join(dir, "wmod", name), data, 0644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("go", "build", "./...")
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build failed: %v\n%s", err, out)
			}
		})
	}
}

// TestMultiPackageAutoDerive exercises the auto-derive switch from
// single-file to multi-package + linkname-split output. With the
// threshold lowered to 0 (forces multi-package for any non-empty
// wasm), every supported fixture must:
//
//   - produce a Result.Files map populated with base/, p*, and the
//     main file;
//   - reference //go:linkname for cross-chunk dispatch;
//   - compile cleanly under `go build ./...`.
func TestMultiPackageAutoDerive(t *testing.T) {
	restore := codegen.SetMultiPackageThreshold(0)
	defer restore()
	for _, fx := range []string{"arith.wasm", "memory.wasm", "control.wasm", "cg_wasi.wasm", "wexports.wasm", "cg_indirect.wasm"} {
		fx := fx
		t.Run(fx, func(t *testing.T) {
			mod := readFixture(t, fx)
			res, err := codegen.Translate(nil, mod, codegen.Options{
				Package: "wmod", OutputImportPath: "gentest/wmod",
			})
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			if res.Files == nil {
				t.Fatalf("expected multi-file output; got nil Files map")
			}
			if _, ok := res.Files["base/base.go"]; !ok {
				t.Errorf("missing base/base.go in multi-file output")
			}
			if _, ok := res.Files["wmod.go"]; !ok {
				t.Errorf("missing wmod.go main file in multi-file output")
			}
			// At least one chunk file must exist.
			any := false
			for k := range res.Files {
				if strings.HasPrefix(k, "p0/") {
					any = true
					break
				}
			}
			if !any {
				t.Errorf("expected at least one p<N>/ chunk file in output")
			}
		})
	}
}
