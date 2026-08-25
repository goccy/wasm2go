package gcasm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPerfGate quantifies the transform's cost against the SAME code
// compiled natively by gc:
//
//   - fib: call-dominated worst case. Every internal call boundary
//     pays the ABI0 marshal (register→stack stores before the CALL,
//     result load after), so this measures the ceiling of the
//     boundary tax.
//   - kern: loop-dominated best case. No internal calls — the body
//     should be byte-for-byte the gc loop, and the ratio ~1.0.
//
// The gate only asserts sanity bounds (transform not catastrophically
// slower); the measured ratios go to the log for bench-metrics.md.
func TestPerfGate(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture emits amd64-only asm; the harness builds and runs it on the host")
	}
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	dir := t.TempDir()
	libSrc := `package lib

//go:noinline
func Fib(n int32) int32 {
	if n < 2 {
		return n
	}
	return Fib(n-1) + Fib(n-2)
}

//go:noinline
func Kern(n int32, seed int32) int32 {
	acc := seed
	x := seed
	for i := int32(0); i < n; i++ {
		x = x*1103515245 + 12345
		acc ^= x
		acc = acc<<7 | int32(uint32(acc)>>25)
		if x&15 == 0 {
			acc += i
		}
	}
	return acc
}
`
	for name, content := range map[string]string{
		"go.mod":     "module perfgate\n\ngo 1.25.0\n",
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

	fns, datas, err := Capture(dir, "perfgate/lib")
	if err != nil {
		t.Fatal(err)
	}
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	pool := &ConstPool{}
	types := &TypeTable{}
	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if strings.HasSuffix(sym, ".Fib") {
			return []ArgKind{ArgI32}, true, ArgI32, "·fibAsm", true
		}
		return nil, false, 0, "", false
	}
	var asmB strings.Builder
	asmB.WriteString("#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	transform := func(suffix, sym string, params []ArgKind, names []string) {
		t.Helper()
		var fn *Fn
		for _, f := range fns {
			if strings.HasSuffix(f.Name, suffix) {
				fn = f
			}
		}
		if fn == nil {
			t.Fatalf("%s not captured", suffix)
		}
		body, err := Transform(fn, TransformOptions{
			SymName:   sym,
			CalleeSig: calleeSig,
			Params:    params,
			HasResult: true,
			Result:    ArgI32,
			ArgNames:  names,
			Datas:     dm,
			Consts:    pool,
			Types:     types,
		})
		if err != nil {
			t.Fatal(err)
		}
		asmB.WriteString(body)
		asmB.WriteString("\n")
	}
	transform(".Fib", "fibAsm", []ArgKind{ArgI32}, []string{"n"})
	transform(".Kern", "kernAsm", []ArgKind{ArgI32, ArgI32}, []string{"n", "seed"})
	asmB.WriteString(pool.Emit())
	if len(types.Names) > 0 {
		t.Fatalf("unexpected type refs: %v", types.Names)
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod":       "module perfrun\n\ngo 1.25.0\n",
		"lib.go":       strings.Replace(strings.Replace(libSrc, "package lib", "package perfrun", 1), "//go:noinline\n", "//go:noinline\n", 2),
		"decl.go":      "package perfrun\n\nfunc fibAsm(n int32) (r0 int32)\nfunc kernAsm(n int32, seed int32) (r0 int32)\n",
		"body_amd64.s": asmB.String(),
		"bench_test.go": `package perfrun

import "testing"

var sink int32

func BenchmarkFibPure(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sink = Fib(25)
	}
}
func BenchmarkFibAsm(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sink = fibAsm(25)
	}
}
func BenchmarkKernPure(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sink = Kern(1000000, 42)
	}
}
func BenchmarkKernAsm(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sink = kernAsm(1000000, 42)
	}
}
func TestParity(t *testing.T) {
	if Fib(20) != fibAsm(20) {
		t.Fatalf("fib mismatch: %d vs %d", Fib(20), fibAsm(20))
	}
	if Kern(100000, 42) != kernAsm(100000, 42) {
		t.Fatalf("kern mismatch: %d vs %d", Kern(100000, 42), kernAsm(100000, 42))
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-run", "TestParity", "-bench", ".", "-benchtime", "2s", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("perf gate failed: %v\n%s\n--- asm ---\n%s", err, out, asmB.String())
	}
	var fibPure, fibAsm, kernPure, kernAsm float64
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && strings.HasSuffix(f[len(f)-1], "ns/op") || len(f) >= 4 && f[len(f)-1] == "ns/op" {
			var v float64
			if _, err := fmt.Sscanf(f[len(f)-2], "%f", &v); err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(ln, "BenchmarkFibPure"):
				fibPure = v
			case strings.HasPrefix(ln, "BenchmarkFibAsm"):
				fibAsm = v
			case strings.HasPrefix(ln, "BenchmarkKernPure"):
				kernPure = v
			case strings.HasPrefix(ln, "BenchmarkKernAsm"):
				kernAsm = v
			}
		}
	}
	if fibPure == 0 || fibAsm == 0 || kernPure == 0 || kernAsm == 0 {
		t.Fatalf("bench parse failed:\n%s", out)
	}
	t.Logf("fib  pure=%.0fns asm=%.0fns ratio=%.3f (call-dominated: ABI0 marshal ceiling)", fibPure, fibAsm, fibAsm/fibPure)
	t.Logf("kern pure=%.0fns asm=%.0fns ratio=%.3f (loop-dominated: should be ~1.0)", kernPure, kernAsm, kernAsm/kernPure)
	if kernAsm/kernPure > 1.15 {
		t.Errorf("loop kernel ratio %.3f exceeds 1.15 — transform is damaging straight-line code", kernAsm/kernPure)
	}
	if fibAsm/fibPure > 3.0 {
		t.Errorf("fib ratio %.3f exceeds 3.0 — boundary marshal cost out of expected range", fibAsm/fibPure)
	}
}
