package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// TestGcasmSimd runs the SIMD fixture through the FULL backend (gcasm
// emits the asm bodies), which the codegen-level fixture test does not.
func TestGcasmSimd(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd.wasm")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "simdtest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
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
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	// Values verified against the wazero reference in the codegen fixture test.
	if want := "1646524174 2147451134 437725748 176 131342"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
