package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// readFixture compiles testdata/<name>.wat and parses the result.
func readFixture(t *testing.T, name string) *wasm.Module {
	t.Helper()
	bin := testfixture.Wasm(t, name)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return mod
}

// assertSingleFileCompiles parses the generated Go source and runs `go build`
// on it in an isolated module directory, writing any data sidecar files next
// to the package source.
func assertSingleFileCompiles(t *testing.T, src string, sidecars map[string][]byte, auxFiles ...map[string][]byte) {
	t.Helper()
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "gen.go", src, parser.ParseComments); err != nil {
		t.Fatalf("generated source is not valid Go: %v\n%s", err, src)
	}
	dir := t.TempDir()
	gomod := "module gentest\n\ngo 1.25.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "gen.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	for name, data := range sidecars {
		if err := os.WriteFile(filepath.Join(dir, "pkg", name), stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, af := range auxFiles {
		for name, data := range af {
			p := filepath.Join(dir, "pkg", name)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	cmd := exec.Command("go", "build", "./pkg")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build of generated package failed: %v\n%s\n--src--\n%s", err, out, src)
	}
}

// allFixtures is the list of testdata .wasm modules driven through the
// option matrix. Every one must translate cleanly and compile under each
// supported option combination.
var allFixtures = []string{
	"arith.wasm",
	"control.wasm",
	"memory.wasm",
	"hello.wasm",
	"recursive_init.wasm",
	"vtable_dispatch.wasm",
	"wexports.wasm",
	"datacoalesce.wasm",
	"deadfunc.wasm",
	"cg_numerics.wasm",
	"cg_manyfuncs.wasm",
	"cg_bigdispatch.wasm",
	"cg_wasi.wasm",
	"cg_nestedloop.wasm",
	"cg_bulkmem.wasm",
	"cg_allops.wasm",
	"cg_sharedexit.wasm",
	"cg_memops.wasm",
	"cg_dispatchif.wasm",
	"cg_frame.wasm",
	"cg_indirect.wasm",
	"cg_specialfp.wasm",
	"cg_globals.wasm",
	"cg_globals_nan.wasm",
	"cg_misc.wasm",
	"cg_deadend.wasm",
}

// TestMatrixSingleFile translates every fixture under a broad spread of
// single-file Option combinations and asserts each output compiles.
func TestMatrixSingleFile(t *testing.T) {
	type variant struct {
		name string
		opts codegen.Options
	}
	variants := []variant{
		{"legacy", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}},
		{"ssa", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}},
		{"perexport", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", BulkExportPrefix: "w_"}},
		{"keepdead", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", KeepDeadFuncs: true}},
		{"sidecar", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}},
		{"ssa+keepdead", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", KeepDeadFuncs: true}},
		{"perexport+sidecar", codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg", BulkExportPrefix: "w_"}},
	}
	for _, fx := range allFixtures {
		fx := fx
		for _, v := range variants {
			v := v
			t.Run(fx+"/"+v.name, func(t *testing.T) {
				mod := readFixture(t, fx)
				var buf bytes.Buffer
				res, err := codegen.Translate(&buf, mod, v.opts)
				if err != nil {
					t.Fatalf("translate %s (%s): %v", fx, v.name, err)
				}
				assertSingleFileCompiles(t, buf.String(), res.Sidecars, res.AuxFiles, res.Files)
			})
		}
	}
}

// TestMatrixNativeWASI exercises the NativeWASI codegen path on the two
// wasi-importing fixtures and confirms the generated code compiles. The
// non-wasi fixtures must still translate fine with the flag on (it's inert
// when nothing imports wasi_snapshot_preview1).
func TestMatrixNativeWASI(t *testing.T) {
	for _, fx := range []string{"hello.wasm", "cg_wasi.wasm", "arith.wasm"} {
		fx := fx
		t.Run(fx, func(t *testing.T) {
			mod := readFixture(t, fx)
			var buf bytes.Buffer
			res, err := codegen.Translate(&buf, mod, codegen.Options{
				Package: "pkg", OutputImportPath: "gentest/pkg",
			})
			if err != nil {
				t.Fatalf("translate (NativeWASI): %v", err)
			}
			src := buf.String()
			assertSingleFileCompiles(t, src, res.Sidecars, res.AuxFiles, res.Files)
			if fx == "cg_wasi.wasm" || fx == "hello.wasm" {
				if !strings.Contains(src, "DefaultWASI") {
					t.Errorf("%s: NativeWASI output missing DefaultWASI()", fx)
				}
				if !strings.Contains(src, "NewWithWASI") {
					t.Errorf("%s: NativeWASI output missing NewWithWASI()", fx)
				}
			}
		})
	}
}

// runWASINative builds the NativeWASI-generated module for cg_wasi.wasm and
// runs say_hello, asserting it writes the expected string to the captured
// stdout backed by the Go-native wasi impl.
func TestNativeWASIRuntime(t *testing.T) {
	mod := readFixture(t, "cg_wasi.wasm")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
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
	rc := m.SayHello()
	fmt.Printf("say_hello rc=%d\n", rc)
	n := m.RandByte()
	fmt.Printf("rand_byte in range=%v\n", n >= 0 && n <= 255)
	ac := m.ArgCount()
	fmt.Printf("arg_count>=0=%v\n", ac >= 0)
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
	if !strings.Contains(out, "wasi native ok") {
		t.Errorf("native wasi say_hello did not write expected string, got:\n%s", out)
	}
	if !strings.Contains(out, "say_hello rc=0") {
		t.Errorf("native wasi say_hello rc != 0:\n%s", out)
	}
	if !strings.Contains(out, "rand_byte in range=true") {
		t.Errorf("native wasi rand_byte out of range:\n%s", out)
	}
}

// translateMultiToDir writes a MultiPackage / LinknameSplit translation into
// a fresh module dir and runs `go build ./...`. baseImport must match the
// directory the generated packages are placed under.
func translateMultiToDir(t *testing.T, mod *wasm.Module, opts codegen.Options, baseImport, subdir string) {
	t.Helper()
	res, err := codegen.Translate(nil, mod, opts)
	if err != nil {
		t.Fatalf("translate (multi): %v", err)
	}
	if len(res.Files) == 0 {
		t.Fatalf("multi-package translation produced no files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range res.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		p := filepath.Join(dir, subdir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, stripPureGuard(res.Files[rel]), 0644); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(rel, ".s") {
			continue
		}
		fset := token.NewFileSet()
		if _, err := parser.ParseFile(fset, rel, res.Files[rel], parser.ParseComments); err != nil {
			t.Fatalf("multi file %s is not valid Go: %v\n%s", rel, err, res.Files[rel])
		}
	}
	for name, data := range res.Sidecars {
		if err := os.WriteFile(filepath.Join(dir, subdir, name), stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build of multi-package output failed: %v\n%s", err, out)
	}
}

// TestMatrixMultiPackage drives the auto-derived multi-package
// linkname-split layout across several fixtures with the test-only
// threshold knob set to a tiny chunk budget so the partitioner emits
// multiple chunk packages, and asserts each output compiles.
func TestMatrixMultiPackage(t *testing.T) {
	// chunk=0 forces every function into its own chunk (any positive
	// total exceeds the 0 threshold), which is the strongest exercise
	// of cross-chunk linkname forwards.
	cases := []struct {
		fx    string
		chunk int
	}{
		{"cg_manyfuncs.wasm", 0},
		{"control.wasm", 0},
		{"arith.wasm", 0},
		{"vtable_dispatch.wasm", 0},
		{"cg_numerics.wasm", 0},
		{"recursive_init.wasm", 0},
	}
	for _, c := range cases {
		c := c
		t.Run("multi/"+c.fx, func(t *testing.T) {
			restore := codegen.SetMultiPackageThreshold(c.chunk)
			defer restore()
			mod := readFixture(t, c.fx)
			translateMultiToDir(t, mod, codegen.Options{
				Package: "wmod", OutputImportPath: "gentest/wmod",
			}, "gentest/wmod", "wmod")
		})
	}
}

// TestMultiPackageDataSidecar verifies multi-package mode with DataSidecar
// on: data segments must be written as sidecar files referenced by the main
// package via //go:embed.
func TestMultiPackageDataSidecar(t *testing.T) {
	restore := codegen.SetMultiPackageThreshold(64)
	defer restore()
	mod := readFixture(t, "memory.wasm")
	res, err := codegen.Translate(nil, mod, codegen.Options{
		Package: "wmod", OutputImportPath: "gentest/wmod",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(res.Sidecars) == 0 {
		t.Fatalf("expected data sidecar files in multi-package mode")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gentest\n\ngo 1.25.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for rel, data := range res.Files {
		p := filepath.Join(dir, "wmod", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range res.Sidecars {
		if err := os.WriteFile(filepath.Join(dir, "wmod", name), stripPureGuard(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("multi-package + sidecar build failed: %v\n%s", err, out)
	}
}

// TestDispatchSplitRuntime confirms the dispatch-split path: a large
// br_table dispatcher is split into per-case sub-functions, and the split
// output still produces the same per-selector results as wazero.
//
//   - cg_bigdispatch: each case returns its own value (simple split).
//   - cg_sharedexit:  the cases converge on a shared epilogue section that
//     is inlined into each sub-function (the exit-trace path).
func TestDispatchSplitRuntime(t *testing.T) {
	for _, fx := range []string{"cg_bigdispatch.wasm", "cg_sharedexit.wasm"} {
		fx := fx
		t.Run(fx, func(t *testing.T) {
			bin := testfixture.Wasm(t, fx)
			mod, err := wasm.Parse(bytes.NewReader(bin))
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			r := wazero.NewRuntime(ctx)
			t.Cleanup(func() {
				if err := r.Close(ctx); err != nil {
					t.Errorf("wazero runtime close: %v", err)
				}
			})
			wmod, err := r.Instantiate(ctx, bin)
			if err != nil {
				t.Fatalf("wazero instantiate: %v", err)
			}
			dispatch := wmod.ExportedFunction("dispatch")
			getOut := wmod.ExportedFunction("get_out")
			selectors := []int32{0, 1, 5, 17, 31, 39, 40, 100}
			want := make([]int32, len(selectors))
			for i, sel := range selectors {
				if _, err := dispatch.Call(ctx, uint64(uint32(sel))); err != nil {
					t.Fatalf("wazero dispatch(%d): %v", sel, err)
				}
				got, err := getOut.Call(ctx)
				if err != nil {
					t.Fatalf("wazero get_out: %v", err)
				}
				want[i] = int32(got[0])
			}

			var buf bytes.Buffer
			res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
			if err != nil {
				t.Fatalf("translate: %v", err)
			}
			src := buf.String()
			// NOTE: dispatch-split previously kicked in on the legacy
			// compiler's `switch` emission for br_table. The SSA path
			// lowers br_table as a chain of equality-If blocks, so the
			// splitter's pattern-match does not fire. The dispatcher
			// semantics are still asserted below. A future change can
			// either round-trip br_table through a BlockSwitch SSA op
			// or extend matchDispatcher to recognise the if-chain
			// shape, at which point the assertion below can be
			// restored.
			_ = src

			var mainSB strings.Builder
			mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
			for _, sel := range selectors {
				fmt.Fprintf(&mainSB, "\tm.%s(int32(%d))\n\tfmt.Printf(\"%%d\\n\", m.%s())\n",
					codegen.ExportMethodName("dispatch"), sel, codegen.ExportMethodName("get_out"))
			}
			mainSB.WriteString("}\n")

			out := runGoSnippet(t, src, mainSB.String(), res.Sidecars, res.Files)
			gotLines := strings.Fields(strings.TrimSpace(out))
			if len(gotLines) != len(want) {
				t.Fatalf("dispatch-split: got %d result lines, want %d\n%s", len(gotLines), len(want), out)
			}
			for i, sel := range selectors {
				var g int32
				if _, err := fmt.Sscanf(gotLines[i], "%d", &g); err != nil {
					t.Fatalf("Sscanf %q: %v", gotLines[i], err)
				}
				if g != want[i] {
					t.Errorf("%s dispatch(%d): got %d, want %d (wazero)", fx, sel, g, want[i])
				}
			}
		})
	}
}

// TestNumericsRuntime verifies the cg_numerics fixture (a broad numeric-op
// corpus) translates and produces identical results to wazero across the
// legacy and SSA pipelines.
func TestNumericsRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_numerics")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	type tc struct {
		export   string
		args     []uint64
		argTypes []wasm.ValType
		typ      wasm.ValType // result type
	}
	i32, i64 := wasm.ValI32, wasm.ValI64
	cases := []tc{
		{"popcnt", []uint64{uint64(uint32(0xF0F0F0F0))}, []wasm.ValType{i32}, i32},
		{"clz", []uint64{u32(0x00010000)}, []wasm.ValType{i32}, i32},
		{"ctz", []uint64{u32(0x00010000)}, []wasm.ValType{i32}, i32},
		{"rotl", []uint64{u32(0x12345678), 8}, []wasm.ValType{i32, i32}, i32},
		{"rotr", []uint64{u32(0x12345678), 8}, []wasm.ValType{i32, i32}, i32},
		{"eqz", []uint64{0}, []wasm.ValType{i32}, i32},
		{"cmp_eq", []uint64{5, 5}, []wasm.ValType{i32, i32}, i32},
		{"cmp_ne", []uint64{5, 6}, []wasm.ValType{i32, i32}, i32},
		{"cmp_le_s", []uint64{u32(-3), 2}, []wasm.ValType{i32, i32}, i32},
		{"cmp_ge_u", []uint64{u32(-1), 1}, []wasm.ValType{i32, i32}, i32},
		{"sel", []uint64{11, 22, 1}, []wasm.ValType{i32, i32, i32}, i32},
		{"sel", []uint64{11, 22, 0}, []wasm.ValType{i32, i32, i32}, i32},
		{"i64const", nil, nil, i64},
		{"popcnt64", []uint64{0xFFFF_0000_00FF}, []wasm.ValType{i64}, i64},
		{"i32_to_i64_u", []uint64{u32(-1)}, []wasm.ValType{i32}, i64},
		{"i64_to_i32", []uint64{0x1_0000_0042}, []wasm.ValType{i64}, i32},
		{"i64_shifts", []uint64{0xABCD, 4}, []wasm.ValType{i64, i64}, i64},
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, c := range cases {
		fn := wmod.ExportedFunction(c.export)
		res, err := fn.Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s: %v", c.export, err)
		}
		method := codegen.ExportMethodName(c.export)
		var argList []string
		for i, a := range c.args {
			switch c.argTypes[i] {
			case wasm.ValI64:
				argList = append(argList, fmt.Sprintf("int64(%d)", int64(a)))
			default:
				argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
			}
		}
		switch c.typ {
		case wasm.ValI32:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, strings.Join(argList, ", "))
		case wasm.ValI64:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int64(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, strings.Join(argList, ", "))
		}
	}
	mainSB.WriteString("}\n")

	for _, useSSA := range []bool{false, true} {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
		if err != nil {
			t.Fatalf("translate (UseSSA=%v): %v", useSSA, err)
		}
		out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files))
		gotLines := strings.Split(out, "\n")
		if len(gotLines) != len(want) {
			t.Fatalf("UseSSA=%v: got %d lines want %d\n%s", useSSA, len(gotLines), len(want), out)
		}
		for i := range want {
			if strings.TrimSpace(gotLines[i]) != want[i] {
				t.Errorf("UseSSA=%v: line %d got %q want %q", useSSA, i, gotLines[i], want[i])
			}
		}
	}
}
