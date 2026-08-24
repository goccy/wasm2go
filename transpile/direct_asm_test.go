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

// TestDirectAsmSimdLoop is the register-coalesce-across-splices gate:
// a SIMD accumulation loop whose scalar carries (pointer, counter)
// the splice-mode coalesce keeps in the splice-safe registers. The
// direct-asm output is compared DIFFERENTIALLY against the normal
// backend across a range of trip counts, on amd64 and natively on
// arm64.
func TestDirectAsmSimdLoop(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_simd_loopsum")
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	translate := func(importPath string, direct []string) (string, map[string][]byte) {
		m2, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		res, err := transpile.Translate(&buf, m2, transpile.Options{
			Package:          importPath[strings.LastIndex(importPath, "/")+1:],
			OutputImportPath: importPath,
			DirectAsmFuncs:   direct,
		})
		if err != nil {
			t.Fatalf("translate %s: %v", importPath, err)
		}
		return buf.String(), mergeFiles(res.Files, res.Sidecars)
	}
	_ = m
	refSrc, refFiles := translate("dasl/ref", nil)
	dirSrc, dirFiles := translate("dasl/dir", []string{"fn0"})

	// The direct bundle's arm64 body must be a spliced, coalesced
	// loop: the marker proves direct-asm fired, R19 proves a carry
	// got a splice-safe register home.
	arm := string(dirFiles["arm64.s"])
	start := strings.Index(arm, "// direct-asm: fn0")
	if start < 0 {
		t.Fatalf("fn0 fell back; no direct-asm body in arm64.s")
	}
	if !strings.Contains(arm[start:], "WORD $0x") {
		t.Errorf("direct-asm fn0 contains no spliced NEON")
	}
	if !strings.Contains(arm[start:], "R19") {
		t.Errorf("direct-asm fn0 coalesced no loop carry into R19")
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
	w("go.mod", []byte("module dasl\n\ngo 1.25.0\n"))
	if refSrc != "" {
		w("ref/gen.go", []byte(refSrc))
	}
	for name, data := range refFiles {
		w("ref/"+name, data)
	}
	if dirSrc != "" {
		w("dir/gen.go", []byte(dirSrc))
	}
	for name, data := range dirFiles {
		w("dir/"+name, data)
	}
	w("main.go", []byte(`package main

import (
	"fmt"
	"os"

	"dasl/dir"
	"dasl/ref"
)

func main() {
	for n := int32(0); n <= 32; n++ {
		r := ref.New()
		d := dir.New()
		want, got := r.Loopsum(n), d.Loopsum(n)
		if want != got {
			fmt.Printf("n=%d: ref %d, direct %d\n", n, want, got)
			os.Exit(1)
		}
	}
	fmt.Println("OK")
}
`))
	run := func(env []string, label string) {
		exe := filepath.Join(dir, "driver_"+label)
		cb := exec.Command("go", "build", "-o", exe, ".")
		cb.Dir = dir
		if env != nil {
			cb.Env = append(os.Environ(), env...)
		}
		if out, err := cb.CombinedOutput(); err != nil {
			t.Fatalf("%s go build: %v\n%s", label, err, out)
		}
		out, err := exec.Command(exe).CombinedOutput()
		if err != nil {
			t.Fatalf("%s driver: %v\n%s", label, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "OK" {
			t.Fatalf("%s: %s", label, got)
		}
	}
	run(nil, "host")
	if canExecArm64(t) {
		run([]string{"GOOS=" + runtime.GOOS, "GOARCH=arm64", "CGO_ENABLED=0"}, "arm64")
	} else {
		t.Logf("host cannot execute arm64 binaries; arm64 leg skipped")
	}
}

// TestDirectAsmExc opts every function of the EH fixture into the
// direct-asm path: the branch-based exception ops (pending-flag
// check-and-branch after may-throw calls, tag dispatch, operand
// reads/writes across all four widths, catch_all rethrow) lower to
// inline MOVs against the Module's exception-state fields. The
// direct output is compared DIFFERENTIALLY against the normal
// backend, on amd64 and natively on arm64.
func TestDirectAsmExc(t *testing.T) {
	bin := testfixture.Wasm(t, "eh_direct")
	translate := func(importPath string, direct []string) (string, map[string][]byte) {
		m, err := transpile.Parse(bytes.NewReader(bin))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		res, err := transpile.Translate(&buf, m, transpile.Options{
			Package:          importPath[strings.LastIndex(importPath, "/")+1:],
			OutputImportPath: importPath,
			DirectAsmFuncs:   direct,
		})
		if err != nil {
			t.Fatalf("translate %s: %v", importPath, err)
		}
		return buf.String(), mergeFiles(res.Files, res.Sidecars)
	}
	var direct []string
	for i := 0; i < 7; i++ {
		direct = append(direct, fmt.Sprintf("fn%d", i))
	}
	refSrc, refFiles := translate("daexc/ref", nil)
	dirSrc, dirFiles := translate("daexc/dir", direct)

	// Every function must emit on both arches — a fallback here means
	// an exc op the emitters no longer cover.
	var asmAll strings.Builder
	for name, data := range dirFiles {
		if strings.HasSuffix(name, ".s") {
			asmAll.Write(data)
		}
	}
	for _, fn := range direct {
		if got := strings.Count(asmAll.String(), "// direct-asm: "+fn+"\n"); got != 2 {
			t.Errorf("marker for %s appears %d times in the bundle, want 2 (both arches)", fn, got)
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
	w("go.mod", []byte("module daexc\n\ngo 1.25.0\n"))
	if refSrc != "" {
		w("ref/gen.go", []byte(refSrc))
	}
	for name, data := range refFiles {
		w("ref/"+name, data)
	}
	if dirSrc != "" {
		w("dir/gen.go", []byte(dirSrc))
	}
	for name, data := range dirFiles {
		w("dir/"+name, data)
	}
	w("main.go", []byte(`package main

import (
	"fmt"
	"os"

	"daexc/dir"
	"daexc/ref"
)

func main() {
	r := ref.New()
	d := dir.New()
	check := func(name string, want, got int32) {
		if want != got {
			fmt.Printf("%s: ref %d, direct %d\n", name, want, got)
			os.Exit(1)
		}
	}
	for x := int32(0); x <= 4; x++ {
		check("catch_sum", r.CatchSum(x), d.CatchSum(x))
		check("reraise", r.Reraise(x), d.Reraise(x))
		check("catch_dyn", r.CatchDyn(x), d.CatchDyn(x))
	}
	check("which", r.Which(0), d.Which(0))
	check("which", r.Which(1), d.Which(1))
	// The reference itself must match the wasm semantics these
	// constants pin (throw operands across all four widths; the
	// float terms are raw bit patterns: bits(43.5f)=0x422E0000,
	// hi32(bits(44.25))=0x40462000, bits(7f)=0x40E00000,
	// hi32(bits(8.0))=0x40200000).
	for _, pin := range []struct {
		name string
		want int32
		got  int32
	}{
		{"catch_sum(0)", -1, r.CatchSum(0)},
		{"catch_sum(1)", -2106318765, r.CatchSum(1)},
		{"reraise(0)", -2, r.Reraise(0)},
		{"reraise(1)", 41, r.Reraise(1)},
		{"catch_dyn(5)", -2130706421, r.CatchDyn(5)},
		{"which(0)", 1, r.Which(0)},
		{"which(1)", 109, r.Which(1)},
	} {
		if pin.want != pin.got {
			fmt.Printf("%s: want %d, got %d\n", pin.name, pin.want, pin.got)
			os.Exit(1)
		}
	}
	fmt.Println("OK")
}
`))
	run := func(env []string, label string) {
		exe := filepath.Join(dir, "driver_"+label)
		cb := exec.Command("go", "build", "-o", exe, ".")
		cb.Dir = dir
		if env != nil {
			cb.Env = append(os.Environ(), env...)
		}
		if out, err := cb.CombinedOutput(); err != nil {
			t.Fatalf("%s go build: %v\n%s", label, err, out)
		}
		out, err := exec.Command(exe).CombinedOutput()
		if err != nil {
			t.Fatalf("%s driver: %v\n%s", label, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "OK" {
			t.Fatalf("%s: %s", label, got)
		}
	}
	run(nil, "host")
	if canExecArm64(t) {
		run([]string{"GOOS=" + runtime.GOOS, "GOARCH=arm64", "CGO_ENABLED=0"}, "arm64")
	} else {
		t.Logf("host cannot execute arm64 binaries; arm64 leg skipped")
	}
}

// mergeFiles flattens the translate outputs into one relative map.
func mergeFiles(sets ...map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for _, set := range sets {
		for name, data := range set {
			if len(data) > 0 {
				out[name] = data
			}
		}
	}
	return out
}
