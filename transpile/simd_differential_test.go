package transpile_test

// Differential testing for the SIMD fusion machinery. wasm2go serves
// many products, and the fusion passes rewrite generated Go across all
// of them — so beyond llama's byte-equality gate, this test pins four
// independently produced executions of the same module against each
// other:
//
//	translation with fusion  x  translation without fusion
//	    x
//	gcasm splices (GOAMD64=v2 / arm64)  x  pure Go fallback (GOAMD64=v1)
//
// The pure fallback executes the synthetic fused helpers' ordinary Go
// bodies, making it an oracle that shares no code with the splice
// synthesizers; the fusion-off translation shares no code with the
// fusion passes at all. Any divergence between the configurations is a
// bug in one of them.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

func TestGcasmSimdDifferential(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd.wasm")

	build := func(t *testing.T, fuse bool) string {
		t.Helper()
		if !fuse {
			t.Setenv("WASM2GO_NO_FUSE", "1")
		}
		m, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		res, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "simdtest/pkg"})
		if err != nil {
			t.Fatalf("translate (fuse=%v): %v", fuse, err)
		}
		dir := t.TempDir()
		w := func(rel string, data []byte) {
			p := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		w("go.mod", []byte("module simdtest\n\ngo 1.25.0\n"))
		if buf.Len() > 0 {
			w("pkg/gen.go", buf.Bytes())
		}
		for _, set := range []map[string][]byte{res.Files, res.Sidecars} {
			for name, data := range set {
				if len(data) == 0 {
					continue
				}
				w("pkg/"+name, data)
			}
		}
		w("main.go", []byte(`package main

import (
	"fmt"

	"simdtest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Intarith(-123456, 789), m.Widen(-32768, 32767), m.Memv(0), m.Shuf(0x55), m.Cmpmask(-5, 3))
}
`))
		return dir
	}

	run := func(t *testing.T, dir string, env []string) string {
		t.Helper()
		cmd := exec.Command("go", "run", ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go run %v: %v\n%s", env, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// Values verified against the wazero reference in the codegen
	// fixture test; every configuration must reproduce them.
	const want = "1646524174 2147451134 437725748 176 131342"

	for _, fuse := range []bool{true, false} {
		name := "fused"
		if !fuse {
			name = "unfused"
		}
		t.Run(name, func(t *testing.T) {
			dir := build(t, fuse)
			envs := [][]string{nil}
			if runtime.GOARCH == "amd64" {
				// v2 executes the gcasm splices, v1 the pure fallback.
				envs = [][]string{{"GOAMD64=v2"}, {"GOAMD64=v1"}}
			}
			for _, env := range envs {
				if got := run(t, dir, env); got != want {
					t.Errorf("env %v: got %q, want %q", env, got, want)
				}
			}
		})
	}
}
