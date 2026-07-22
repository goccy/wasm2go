package transpile_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestInlineBrTableJumpTreeEndToEnd reproduces the go-python Fn71
// corruption shape: a leaf callee whose body is a dense br_table gets
// inlined into a caller; gc then emits a JUMP TABLE inside the caller
// and the gcasm transform rewrites it into a compare tree
// (findJumpTables/emitJumpTree). The test executes EVERY selector
// value through the full gcasm pipeline and checks the returned
// values, so a single wrong edge in the tree fails loudly.
//
// The selector is biased (x-3) before the table and each case returns
// a distinct value, preventing gc from merging cases.
func TestInlineBrTableJumpTreeEndToEnd(t *testing.T) {
	// SPARSE table mirroring the CPython Fn71 shape that crashed: the
	// br_table's entries have HOLES (runs of default interleaved with
	// real cases) so the transform's run compression and the compare
	// tree's hole edges are exercised, not just a dense 0..N table.
	const tableLen = 55
	sparse := map[int]bool{}
	for _, v := range []int{0, 1, 2, 5, 6, 7, 8, 11, 14, 16, 17, 18, 20, 21, 22, 23, 26, 29, 32, 34, 38, 41, 44, 46, 49, 52, 54} {
		sparse[v] = true
	}
	caseVal := func(i int) int { return 1000 + i*7 }
	// Build the leaf: nested blocks + br_table; entry i br's to $b<i>
	// when sparse[i], else to the default $d. Selector = x - 3.
	var sb strings.Builder
	sb.WriteString("(module\n  (func $leaf (param $x i32) (result i32)\n")
	sb.WriteString("    (block $d\n")
	for i := tableLen - 1; i >= 0; i-- {
		if sparse[i] {
			fmt.Fprintf(&sb, "    (block $b%d\n", i)
		}
	}
	sb.WriteString("      (br_table")
	for i := 0; i < tableLen; i++ {
		if sparse[i] {
			fmt.Fprintf(&sb, " $b%d", i)
		} else {
			sb.WriteString(" $d")
		}
	}
	sb.WriteString(" $d (i32.sub (local.get $x) (i32.const 3)))\n")
	for i := 0; i < tableLen; i++ {
		if sparse[i] {
			fmt.Fprintf(&sb, "    ) (return (i32.const %d))\n", caseVal(i))
		}
	}
	sb.WriteString("    )\n    (i32.const -1))\n")
	// Caller: passes through, so the leaf inlines into it.
	sb.WriteString("  (func (export \"run\") (param $x i32) (result i32)\n")
	sb.WriteString("    (call $leaf (local.get $x))))\n")

	dir := t.TempDir()
	watPath := filepath.Join(dir, "t.wat")
	wasmPath := filepath.Join(dir, "t.wasm")
	if err := os.WriteFile(watPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("wat2wasm", "--output="+wasmPath, watPath).CombinedOutput(); err != nil {
		t.Fatalf("wat2wasm: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}

	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	restore := transpile.SetMultiPackageThreshold(1 << 30)
	defer restore()
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "jttest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module jttest\n\ngo 1.25.0\n"))
	writeFile("pkg/gen.go", buf.Bytes())
	for rel, data := range res.Files {
		writeFile("pkg/"+rel, data)
	}
	for name, data := range res.Sidecars {
		writeFile("pkg/"+name, data)
	}
	writeFile("main.go", []byte(`package main

import (
	"fmt"

	"jttest/pkg"
)

func main() {
	m := pkg.New()
	for x := int32(0); x < 70; x++ {
		fmt.Println(m.Run(x))
	}
}
`))
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) != 70 {
		t.Fatalf("expected 70 outputs, got %d:\n%s", len(lines), out)
	}
	for x := 0; x < 70; x++ {
		want := "-1"
		if sel := x - 3; sel >= 0 && sel < tableLen && sparse[sel] {
			want = fmt.Sprint(caseVal(sel))
		}
		if lines[x] != want {
			t.Errorf("run(%d) = %s, want %s", x, lines[x], want)
		}
	}
}
