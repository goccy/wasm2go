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

// TestDirectAsmLeaf runs a scalar fixture through the full backend
// with several functions opted into the direct-asm path
// (Options.DirectAsmFuncs) and verifies:
//
//   - the bundle contains asmgen-emitted bodies for the opted-in leaf
//     functions (the "// direct-asm:" marker) on both architectures;
//   - functions the direct emitter declines (helper-calling ones)
//     fall back to the listing transform without breaking the build;
//   - the generated package still computes correct values, i.e. the
//     swapped bodies are behaviorally identical to the transform's.
func TestDirectAsmLeaf(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "datest/pkg",
		// add, sub, mul64, shifts: leaf bodies the direct emitter
		// handles. rotl (fn5) routes through a rotate helper CALL and
		// must fall back per function.
		DirectAsmFuncs: []string{"fn0", "fn1", "fn2", "fn4", "fn5"},
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	var asmAll strings.Builder
	for name, data := range res.Files {
		if strings.HasSuffix(name, ".s") {
			asmAll.WriteString("=== " + name + "\n")
			asmAll.Write(data)
		}
	}
	for _, want := range []string{"// direct-asm: fn0", "// direct-asm: fn1", "// direct-asm: fn2", "// direct-asm: fn4"} {
		if got := strings.Count(asmAll.String(), want); got != 2 { // amd64 + arm64
			t.Errorf("marker %q appears %d times in the bundle, want 2 (both arches)\n%s", want, got, asmAll.String())
		}
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
	w("go.mod", []byte("module datest\n\ngo 1.25.0\n"))
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

	"datest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Add(2, 3), m.Add(2147483647, 1), m.Sub(10, 3), m.Mul64(6, 7), m.Shifts(1, 4), m.Rotl(1, 31), m.DivS(-20, 4), m.LtU(-1, 1))
}
`))
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	// Same values the asmgen driver tests pin for the arith fixture.
	if want := "5 -2147483648 7 42 1 -2147483648 -5 0"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
