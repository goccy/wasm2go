package gcasm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestGate4Bundle is the pipeline gate: run codegen.Translate, hand
// the result to Build, materialise the merged tree, and run the
// module's EXPORTS on the gcasm build (host GOARCH=amd64) against the
// pure build (same tree built with the pure guard satisfied via a
// driver that calls fnN_pure? no — exports are the public API, so the
// two VARIANTS are two separate module trees: gcasm-mode and
// pure-only) — outputs must match exactly. Also asserts Build is
// deterministic (two invocations → identical file map).
func TestGate4Bundle(t *testing.T) {
	for _, fixture := range []string{"control", "cg_brtable64", "cg_indirect", "cg_numerics", "cg_memops"} {
		t.Run(fixture, func(t *testing.T) {
			gate4(t, fixture)
		})
	}
	// The multi-package layout (base + pN chunks) exercises the
	// cross-package machinery: base imports in chunk decls, linkname
	// forwards, tail-JMP trampolines.
	t.Run("control_multipkg", func(t *testing.T) {
		defer codegen.SetMultiPackageThreshold(0)()
		gate4(t, "control")
	})
}

func gate4(t *testing.T, fixture string) {
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}

	treeIn := map[string][]byte{}
	for name, data := range res.Sidecars {
		treeIn[name] = data
	}
	for name, data := range res.Files {
		treeIn[name] = data
	}
	build := func() map[string][]byte {
		t.Helper()
		files, stats, err := Build(mod, buf.Bytes(), treeIn, "gentest/pkg", nil, nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Transformed == 0 {
			t.Fatal("nothing transformed")
		}
		return files
	}
	gcasmFiles := build()
	again := build()
	if len(gcasmFiles) != len(again) {
		t.Fatalf("Build not deterministic: %d vs %d files", len(gcasmFiles), len(again))
	}
	for k, v := range gcasmFiles {
		if !bytes.Equal(v, again[k]) {
			t.Fatalf("Build not deterministic at %s", k)
		}
	}

	// Materialise both variants.
	writeVariant := func(gcasm bool) string {
		t.Helper()
		dir := t.TempDir()
		tree := map[string][]byte{
			"go.mod": []byte("module gentest\n\ngo 1.25.0\n"),
		}
		if buf.Len() > 0 { // multi-package mode leaves the main writer empty
			tree["pkg/gen.go"] = buf.Bytes()
		}
		for name, data := range res.Sidecars {
			tree["pkg/"+name] = data
		}
		for name, data := range res.Files {
			tree["pkg/"+name] = data
		}
		if gcasm {
			for name, data := range gcasmFiles {
				if data == nil {
					delete(tree, "pkg/"+name)
					continue
				}
				tree["pkg/"+name] = data
			}
		} else {
			// Pure variant: same PureFilter path the capture uses.
			pf := map[string][]byte{}
			if buf.Len() > 0 {
				pf["gen.go"] = buf.Bytes()
			}
			for name, data := range res.Sidecars {
				pf[name] = data
			}
			for name, data := range res.Files {
				pf[name] = data
			}
			pf = PureFilter(pf)
			tree = map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
			for name, data := range pf {
				tree["pkg/"+name] = data
			}
		}
		for name, data := range tree {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	// Export-level driver: call every exported method over an input
	// sweep and print outcomes; both variants must print identically.
	var driver strings.Builder
	driver.WriteString(`package main

import (
	"fmt"
	"gentest/pkg"
)

func run(f func() int64) (val int64, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return f(), false
}

func main() {
`)
	exports := 0
	for _, exp := range mod.Exports {
		if exp.Kind != wasm.ExportFunc {
			continue
		}
		ft := mod.FuncTypeOf(exp.Index)
		if len(ft.Results) != 1 {
			continue
		}
		goName := codegen.ExportMethodName(exp.Name)
		if goName == "" {
			continue
		}
		var tuples [][]string
		switch len(ft.Params) {
		case 0:
			tuples = [][]string{{}}
		case 1:
			for _, a := range []string{"0", "1", "2", "3", "5", "42", "70", "255"} {
				tuples = append(tuples, []string{a})
			}
		default:
			for _, a := range []string{"0", "1", "3", "42"} {
				for _, b := range []string{"0", "1", "7"} {
					tup := []string{a, b}
					for len(tup) < len(ft.Params) {
						tup = append(tup, "1")
					}
					tuples = append(tuples, tup)
				}
			}
		}
		for _, tup := range tuples {
			args := ""
			for i, a := range tup {
				typ := "int32"
				switch ft.Params[i] {
				case wasm.ValI64:
					typ = "int64"
				case wasm.ValF32:
					typ = "float32"
				case wasm.ValF64:
					typ = "float64"
				}
				if i > 0 {
					args += ", "
				}
				args += fmt.Sprintf("%s(%s)", typ, a)
			}
			// Single-package mode emits methods (m.Fact(...)); the
			// multi-package layout emits package functions
			// (pkg.Fact(m, ...)).
			callArgs := args
			resExpr := fmt.Sprintf("m.%s(%s)", goName, callArgs)
			if buf.Len() == 0 {
				if callArgs != "" {
					callArgs = "m, " + callArgs
				} else {
					callArgs = "m"
				}
				resExpr = fmt.Sprintf("pkg.%s(%s)", goName, callArgs)
			}
			switch ft.Results[0] {
			case wasm.ValF32:
				resExpr = fmt.Sprintf("int64(int32(%s))", resExpr)
			case wasm.ValF64:
				resExpr = fmt.Sprintf("int64(int32(%s))", resExpr)
			default:
				resExpr = fmt.Sprintf("int64(%s)", resExpr)
			}
			fmt.Fprintf(&driver, "\t{\n\t\tm := pkg.New()\n\t\tv, p := run(func() int64 { return %s })\n\t\tfmt.Println(%q, v, p)\n\t}\n", resExpr, goName+"("+strings.Join(tup, ",")+")")
			exports++
		}
	}
	driver.WriteString("}\n")
	if exports == 0 {
		t.Skip("no drivable exports")
	}

	runVariant := func(dir string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "cmd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmd", "main.go"), []byte(driver.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("go", "run", "./cmd")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("variant run failed in %s: %v\n%s", dir, err, out)
		}
		return string(out)
	}

	gcasmOut := runVariant(writeVariant(true))
	pureOut := runVariant(writeVariant(false))
	if gcasmOut != pureOut {
		t.Fatalf("gcasm and pure variants disagree:\n--- gcasm\n%s\n--- pure\n%s", gcasmOut, pureOut)
	}
	t.Logf("gate4: %d export cases match between gcasm and pure builds", exports)
}
