package gcasm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeRecModule builds a throwaway module with the spike's recursive
// function — deep recursion exercises the regenerated stacksplit.
func writeRecModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module gcasmgate\n\ngo 1.25.0\n",
		"lib/lib.go": `package lib

//go:noinline
func Rec(n int32) int32 {
	if n <= 1 {
		return 1
	}
	var buf [64]int32
	buf[0] = n
	return Rec(n-1) + Rec(n-2) + buf[0]
}
`,
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestGate0CaptureTransformRun is the end-to-end gate: capture gc's
// compilation of Rec, transform it, assemble it into a fresh module
// with an ABI0 wrapper, run it against the pure implementation, and
// verify the transform is DETERMINISTIC (two captures → identical .s).
func TestGate0CaptureTransformRun(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture emits amd64-only asm; the harness builds and runs it on the host")
	}
	dir := writeRecModule(t)
	sig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if strings.HasSuffix(sym, ".Rec") {
			return []ArgKind{ArgI32}, true, ArgI32, "·recBody", true
		}
		return nil, false, 0, "", false
	}
	transformOnce := func() string {
		fns, _, err := Capture(dir, "gcasmgate/lib")
		if err != nil {
			t.Fatal(err)
		}
		var rec *Fn
		for _, f := range fns {
			if strings.HasSuffix(f.Name, ".Rec") {
				rec = f
			}
		}
		if rec == nil {
			t.Fatalf("Rec not captured; got %d fns", len(fns))
		}
		body, err := Transform(rec, TransformOptions{
			SymName:   "recBody",
			CalleeSig: sig,
			Params:    []ArgKind{ArgI32},
			HasResult: true,
			Result:    ArgI32,
		})
		if err != nil {
			// On toolchains where gc compiles Rec's stack array to a
			// DUFFZERO, Rec is a pure fallback in Build (not asm), so the
			// asm smoke gate does not apply. Fixtures cover the asm path.
			if errors.Is(err, errUnsupportedDuff) {
				t.Skip("Rec compiled to a DUFF pseudo-op on this toolchain; it is a pure fallback in Build")
			}
			t.Fatal(err)
		}
		return body
	}
	body := transformOnce()
	if body2 := transformOnce(); body2 != body {
		t.Fatalf("transform not deterministic:\n--- run1\n%s\n--- run2\n%s", body, body2)
	}

	// Assemble + run in a scratch module.
	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module gcasmrun\n\ngo 1.25.0\n",
		"decl.go": `package gcasmrun

func recBody(a0 int32) (r0 int32)

func Rec(n int32) int32 { return recBody(n) }

func recRef(n int32) int32 {
	if n <= 1 {
		return 1
	}
	var buf [64]int32
	buf[0] = n
	return recRef(n-1) + recRef(n-2) + buf[0]
}
`,
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package gcasmrun

import "testing"

func TestRec(t *testing.T) {
	for _, n := range []int32{1, 2, 5, 10, 20, 26} {
		if got, want := Rec(n), recRef(n); got != want {
			t.Fatalf("Rec(%d)=%d want %d", n, got, want)
		}
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-run", "TestRec", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gate0 run failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}

// TestGate0BigFrame exercises gc's LARGE-frame stack-check shape
// (frame > StackBig: MOVQ SP,R12 / SUBQ $n,R12 / JCS / CMPQ / JLS —
// the wraparound-checking variant) through capture, transform,
// assembly and a deep-recursion run.
func TestGate0BigFrame(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture emits amd64-only asm; the harness builds and runs it on the host")
	}
	dir := t.TempDir()
	libSrc := `package lib

//go:noinline
func Big(n int32) int32 {
	var buf [1024]int64
	for i := range buf {
		buf[i] = int64(n) + int64(i)
	}
	if n <= 1 {
		return int32(buf[1])
	}
	return Big(n-1) + int32(buf[n&1023]&7)
}
`
	for name, content := range map[string]string{
		"go.mod":     "module bigframe\n\ngo 1.25.0\n",
		"lib/lib.go": libSrc,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fns, _, err := Capture(dir, "bigframe/lib")
	if err != nil {
		t.Fatal(err)
	}
	var fn *Fn
	for _, f := range fns {
		if strings.HasSuffix(f.Name, ".Big") {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("Big not captured")
	}
	if fn.FrameSize < 4096 {
		t.Fatalf("fixture frame too small (%d) to trigger the large-frame check", fn.FrameSize)
	}
	body, err := Transform(fn, TransformOptions{
		SymName: "bigAsm",
		CalleeSig: func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
			if strings.HasSuffix(sym, ".Big") {
				return []ArgKind{ArgI32}, true, ArgI32, "·bigAsm", true
			}
			return nil, false, 0, "", false
		},
		Params:    []ArgKind{ArgI32},
		HasResult: true,
		Result:    ArgI32,
		ArgNames:  []string{"n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "morestack") {
		t.Fatalf("morestack tail not stripped:\n%s", body)
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod":       "module bigrun\n\ngo 1.25.0\n",
		"decl.go":      "package bigrun\n\nfunc bigAsm(n int32) (r0 int32)\n\n//go:noinline\n" + strings.ReplaceAll(strings.Replace(libSrc, "package lib\n\n//go:noinline\n", "", 1), "Big", "bigRef"),
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package bigrun

import "testing"

func TestBig(t *testing.T) {
	// 200 levels x ~8KB frame ≈ 1.6MB of stack — forces real growth
	// through the regenerated stacksplit.
	for _, n := range []int32{1, 2, 50, 200} {
		if got, want := bigAsm(n), bigRef(n); got != want {
			t.Fatalf("Big(%d)=%d want %d", n, got, want)
		}
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-run", "TestBig", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bigframe run failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}
