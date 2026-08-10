package transpile_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// TestDirectAsmSimd opts every function of the SIMD fixture into the
// direct-asm path. SIMD helper calls (OpSimdCall / OpSimdMemCall) are
// emitted as plain ABI0 CALLs of the bundle's simd_* symbols, v128
// values travel as [2]uint64 pairs in 16-byte slots, and the values
// must match the wazero-verified reference the gcasm test pins.
func TestDirectAsmSimd(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd.wasm")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var direct []string
	for i := 0; i < 32; i++ {
		direct = append(direct, fmt.Sprintf("fn%d", i))
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "dasimd/pkg",
		DirectAsmFuncs:   direct,
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var asmAll strings.Builder
	for name, data := range res.Files {
		if strings.HasSuffix(name, ".s") {
			asmAll.Write(data)
		}
	}
	if !strings.Contains(asmAll.String(), "// direct-asm: fn") {
		t.Errorf("no direct-asm bodies in the bundle; every function fell back")
	}
	// The arm64 direct-asm bodies must contain SPLICED SIMD ops
	// (inline WORD-encoded NEON), not marshalled helper CALLs — a
	// silent all-CALL body would pass the value checks while losing
	// the entire point of the splice path.
	if arm := string(res.Files["arm64.s"]); arm != "" {
		start := strings.Index(arm, "// direct-asm: fn")
		if start < 0 {
			t.Errorf("arm64.s has no direct-asm bodies")
		} else if !strings.Contains(arm[start:], "WORD $0x") {
			t.Errorf("arm64 direct-asm bodies contain no spliced NEON")
		}
		if strings.Contains(arm[start:], "CALL ·simd_") {
			// Some ops legitimately keep the CALL (no table entry);
			// log for visibility without failing.
			t.Logf("arm64 direct-asm bodies still contain some simd helper CALLs (ops without splice-table entries)")
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
	w("go.mod", []byte("module dasimd\n\ngo 1.25.0\n"))
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

	"dasimd/pkg"
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
	// Values verified against the wazero reference (see TestGcasmSimd).
	want := "1646524174 2147451134 437725748 176 131342"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// arm64 leg: the direct-asm bodies there contain SPLICED SIMD op
	// bodies (inline NEON via the gcasm tables) rather than helper
	// CALLs, so they need their own assemble + execute pass. Apple
	// Silicon runs the arm64 binary natively even when this test
	// process is x86_64 under Rosetta.
	if !canExecArm64(t) {
		t.Logf("host cannot execute arm64 binaries; arm64 leg skipped")
		return
	}
	exe := filepath.Join(dir, "driver_arm64")
	cb := exec.Command("go", "build", "-o", exe, ".")
	cb.Dir = dir
	cb.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=arm64", "CGO_ENABLED=0")
	if bout, err := cb.CombinedOutput(); err != nil {
		t.Fatalf("GOARCH=arm64 go build: %v\n%s", err, bout)
	}
	out, err = exec.Command(exe).CombinedOutput()
	if err != nil {
		t.Fatalf("arm64 driver: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("arm64: got %q, want %q", got, want)
	}
}

// canExecArm64 reports whether this darwin host can execute arm64
// binaries: native arm64, or an x86_64 test process under Rosetta 2
// (which only exists on arm64 hardware). sysctl.proc_translated is
// the OS's indicator; the parse is total — anything but a literal
// "1" means not translated.
func canExecArm64(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return false
	}
	if runtime.GOARCH == "arm64" {
		return true
	}
	out, err := exec.Command("sysctl", "-n", "sysctl.proc_translated").Output()
	return err == nil && strings.TrimSpace(string(out)) == "1"
}
