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

// TestPublicAPI exercises the library entry points — Parse then
// Translate, and the Transpile convenience wrapper — the same way an
// external caller would, without touching any internal package.
func TestPublicAPI(t *testing.T) {
	bin := testfixture.Wasm(t, "wexports")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var buf bytes.Buffer
	if _, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "genwasm",
		OutputImportPath: "example.com/test/genwasm",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("Translate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "package genwasm") {
		t.Errorf("output does not look like generated Go:\n%.200s", out)
	}
	if !strings.Contains(out, "func Inv_0_0(") {
		t.Errorf("BulkExportPrefix option not honored through the public API")
	}

	// Transpile should be byte-identical to Parse+Translate for the
	// same input and options.
	var oneShot bytes.Buffer
	if _, err := transpile.Transpile(bytes.NewReader(bin), &oneShot, transpile.Options{
		Package:          "genwasm",
		OutputImportPath: "example.com/test/genwasm",
		BulkExportPrefix: "w_",
	}); err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if oneShot.String() != out {
		t.Errorf("Transpile output differs from Parse+Translate")
	}

	// A malformed input must surface as a Parse error through Transpile,
	// without invoking Translate.
	if _, err := transpile.Transpile(bytes.NewReader([]byte("not a wasm")), &bytes.Buffer{}, transpile.Options{
		Package:          "x",
		OutputImportPath: "example.com/x",
	}); err == nil {
		t.Errorf("Transpile: expected error on malformed input")
	}
}

// TestSetMultiPackageThreshold verifies the package-mode override
// flips the resulting layout. We compare two translations of the
// same wasm: one with a very high threshold (forces single-file
// Go output, no `base/`) and one with threshold=0 (forces the
// multi-package split).
func TestSetMultiPackageThresholdAPI(t *testing.T) {
	bin := testfixture.Wasm(t, "arith")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Single-file: high threshold cannot be exceeded by a small
	// fixture, so the multi-package layout must NOT trigger.
	restoreHigh := transpile.SetMultiPackageThreshold(1 << 30)
	resHigh, err := transpile.Translate(&bytes.Buffer{}, m, transpile.Options{
		Package: "x", OutputImportPath: "example.com/x",
	})
	restoreHigh()
	if err != nil {
		t.Fatalf("Translate high-threshold: %v", err)
	}
	if _, ok := resHigh.Files["base/base.go"]; ok {
		t.Errorf("high threshold should keep single-file mode but produced base/base.go")
	}

	// Threshold 0: every module exceeds and lands in multi-package mode.
	restoreZero := transpile.SetMultiPackageThreshold(0)
	resZero, err := transpile.Translate(&bytes.Buffer{}, m, transpile.Options{
		Package: "x", OutputImportPath: "example.com/x",
	})
	restoreZero()
	if err != nil {
		t.Fatalf("Translate zero-threshold: %v", err)
	}
	if _, ok := resZero.Files["base/base.go"]; !ok {
		t.Errorf("threshold=0 should trigger multi-package layout but base/base.go missing")
	}
}

// realAddWasm is a minimal module exporting add:(i32,i32)->i32 = a+b.
func realAddWasm() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
		0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
	}
}

// TestTranspileEndToEnd drives the full public pipeline — Parse then
// Translate, which runs codegen AND the gcasm backend — writes the whole
// bundle to a temp module, and builds+runs it on the host. On amd64/arm64
// the gcasm-emitted asm supplies the function bodies (the pure bodies are
// dormant), so a successful `go run` exercises the real shipped path end
// to end: codegen.Translate, gcasm.Build (capture + transform + emit),
// the purego build-tag weaving, and the assembled output itself.
func TestTranspileEndToEnd(t *testing.T) {
	m, err := transpile.Parse(bytes.NewReader(realAddWasm()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module gentest\n\ngo 1.25.0\n"))
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

	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Add(7, 35))
}
`))

	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "42" {
		t.Fatalf("Add(7,35) printed %q, want 42\n%s", got, out)
	}
}

// TestTranspileEHEndToEnd transpiles a wasm module that uses the exception-
// handling proposal (try/catch/throw — the shape clang emits for
// setjmp/longjmp) and runs the generated Go. `run` catches an exception thrown
// with operand 42 and returns it, exercising throw->panic(wasmExc),
// try/catch->defer/recover, and OpCatchArg end to end.
func TestTranspileEHEndToEnd(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_e2e")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "ehtest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module ehtest\n\ngo 1.25.0\n"))
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

	"ehtest/pkg"
)

func main() {
	fmt.Println(pkg.New().Run())
}
`))

	// Run both the default (gcasm, EH functions fall back to pure) and the
	// -tags purego build; both must catch the thrown 42.
	for _, tags := range [][]string{nil, {"-tags", "purego"}} {
		args := append([]string{"run"}, tags...)
		args = append(args, ".")
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go run %v failed: %v\n%s", tags, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "42" {
			t.Fatalf("go run %v: run() printed %q, want 42\n%s", tags, got, out)
		}
	}
}

// TestTranspileEHDelegate exercises the `delegate` EH op: run()'s inner
// `try ... delegate 0` forwards the thrown 42 to the enclosing try, whose catch
// yields 42. (rethrow is implemented too, but its E2E awaits goto-emitter EH
// support — a rethrow inside a catch handler forces the multi-block emitter,
// which cannot yet emit EH try regions.)
func TestTranspileEHDelegate(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_delegate")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "ehtest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module ehtest\n\ngo 1.25.0\n"))
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

	"ehtest/pkg"
)

func main() {
	fmt.Println(pkg.New().Run())
}
`))

	// gcasm default (EH functions fall back to pure) and -tags purego; both
	// must yield the delegated operand, 42.
	for _, tags := range [][]string{nil, {"-tags", "purego"}} {
		args := append([]string{"run"}, tags...)
		args = append(args, ".")
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go run %v failed: %v\n%s", tags, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "42" {
			t.Fatalf("go run %v: run() printed %q, want 42\n%s", tags, got, out)
		}
	}
}

// TestTranspileBrTableStructured exercises the structured emitter's br_table
// support: a 3-case (plus default) switch converging at a shared join. The
// function has no loops so it is emitted structured (a Go switch), not via the
// goto fallback. run(sel): 0→11, 1→22, 2→33, default→33.
func TestTranspileBrTableStructured(t *testing.T) {
	bin := testfixture.Wasm(t, "brtable_switch")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "brt/pkg"})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module brt\n\ngo 1.25.0\n"))
	write("pkg/gen.go", buf.Bytes())
	for rel, data := range res.Files {
		write("pkg/"+rel, data)
	}
	for name, data := range res.Sidecars {
		write("pkg/"+name, data)
	}
	write("main.go", []byte(`package main

import (
	"fmt"

	"brt/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Run(0), m.Run(1), m.Run(2), m.Run(5))
}
`))
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "11 22 33 33" {
		t.Fatalf("br_table: got %q, want %q\n%s", got, "11 22 33 33", out)
	}
}

// TestTranspileEHTrampoline exercises the recover-trampoline goto-EH path: a
// try/catch inside a multi-exit loop, which the structured emitter cannot
// handle, so the function is laid out as `for { __exc := func(){…}(); … }`.
// run(3) catches 3==x on the 3rd iteration -> 100; run(50) hits i>=10 -> 200.
func TestTranspileEHTrampoline(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_trampoline")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "eht/pkg"})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	// Confirm the trampoline layout was used (not the flat goto emitter). The
	// EH function body lands in the pure-fallback file, not the main buf.
	hasPC := strings.Contains(buf.String(), "__pc")
	for _, data := range res.Files {
		if strings.Contains(string(data), "__pc") {
			hasPC = true
		}
	}
	if !hasPC {
		t.Fatalf("expected recover-trampoline (__pc) in output; got the flat layout")
	}

	dir := t.TempDir()
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module eht\n\ngo 1.25.0\n"))
	write("pkg/gen.go", buf.Bytes())
	for rel, data := range res.Files {
		write("pkg/"+rel, data)
	}
	for name, data := range res.Sidecars {
		write("pkg/"+name, data)
	}
	write("main.go", []byte(`package main

import (
	"fmt"

	"eht/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Run(3), m.Run(50))
}
`))
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "100 200" {
		t.Fatalf("trampoline EH: got %q, want %q\n%s", got, "100 200", out)
	}
}

// TestTranspileEHMultiPackage proves EH try/catch works in MULTI-package
// output: the wasmExc type + wasm_catch helper live in `base` (exported as
// WasmExc / Wasm_catch), and the chunk package emitting the try/catch references
// them cross-package (base.WasmExc, base.Wasm_catch). The threshold override
// forces the tiny module to split so the EH function lands in a chunk. run()
// catches the thrown 42.
func TestTranspileEHMultiPackage(t *testing.T) {
	defer transpile.SetMultiPackageThreshold(0)() // force multi-package split

	bin := testfixture.Wasm(t, "eh_e2e")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "wmod",
		OutputImportPath: "ehtest/wmod",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(res.Files) == 0 {
		t.Fatalf("expected multi-package Files, got none")
	}

	dir := t.TempDir()
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module ehtest\n\ngo 1.25.0\n"))
	for rel, data := range res.Files {
		write(filepath.Join("wmod", rel), data)
	}
	for name, data := range res.Sidecars {
		write(filepath.Join("wmod", name), data)
	}
	// The exported wasm function `run` becomes the free function wmod.Run(m).
	write("main.go", []byte(`package main

import (
	"fmt"

	"ehtest/wmod"
)

func main() {
	fmt.Println(wmod.Run(wmod.New()))
}
`))

	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "42" {
		t.Fatalf("multi-package EH: run() printed %q, want 42\n%s", got, out)
	}
}

// TestTranspileSetjmpLongjmpEndToEnd is the real-world EH/SjLj test: it
// transpiles a wasm module built by clang from actual setjmp/longjmp C (via
// `-mllvm -wasm-enable-sjlj -lsetjmp`) and runs it. This exercises the whole
// exception-handling stack — the legacy EH opcodes, the __wasm_setjmp /
// __wasm_setjmp_test / __wasm_longjmp libsetjmp runtime, and the
// exception-resume loop clang emits (the catch handler branches back to the
// loop header to re-run from setjmp). run() longjmps with value 7 and returns
// 100+7 = 107. The wasm is a committed binary fixture (it cannot be rebuilt
// without a wasi-sdk clang + libsetjmp); see the .README beside it.
func TestTranspileSetjmpLongjmpEndToEnd(t *testing.T) {
	bin, err := os.ReadFile(filepath.Join("..", "testdata", "sjlj_setjmp_longjmp.wasm"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "sjtest/pkg",
	})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	dir := t.TempDir()
	writeFile := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", []byte("module sjtest\n\ngo 1.25.0\n"))
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

	"sjtest/pkg"
)

func main() {
	fmt.Println(pkg.New().Run())
}
`))

	for _, tags := range [][]string{nil, {"-tags", "purego"}} {
		args := append([]string{"run"}, tags...)
		args = append(args, ".")
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go run %v failed: %v\n%s", tags, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "107" {
			t.Fatalf("go run %v: run() printed %q, want 107 (longjmp must resume setjmp)\n%s", tags, got, out)
		}
	}
}
