package gcasm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestPerfGate pins the transform's cost against the SAME code
// compiled natively by gc, in the instructions it emits:
//
//   - fib: call-dominated worst case. Every internal call boundary
//     pays the ABI0 marshal, and nothing else may be added: the body
//     is gc's instructions plus one FP load of its parameter at entry,
//     one store per argument before and one load per result after
//     each internal CALL, and the result store before each RET.
//   - kern: loop-dominated best case. No internal calls — the loop is
//     gc's loop instruction for instruction (branch targets only
//     become pcN labels).
//
// On an amd64 host both bodies are then built and run against the pure
// functions.
func TestPerfGate(t *testing.T) {
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
	transform := func(suffix, sym string, params []ArgKind, names []string) (*Fn, string) {
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
		return fn, body
	}
	fib, fibBody := transform(".Fib", "fibAsm", []ArgKind{ArgI32}, []string{"n"})
	kern, kernBody := transform(".Kern", "kernAsm", []ArgKind{ArgI32, ArgI32}, []string{"n", "seed"})
	asmB.WriteString(pool.Emit())
	if len(types.Names) > 0 {
		t.Fatalf("unexpected type refs: %v", types.Names)
	}

	// fib: gc's instructions plus exactly the ABI0 marshal.
	fibGC, err := capturedBody(fib)
	if err != nil {
		t.Fatal(err)
	}
	want := len(fibGC) + 1 // the entry load of n
	for _, in := range fibGC {
		if m := callRe.FindStringSubmatch(in.Text); m != nil && strings.HasSuffix(m[1], ".Fib") {
			want += 2 // store of the argument, load of the result
		}
		if strings.HasPrefix(in.Text, "RET") {
			want++ // store of the result
		}
	}
	if got := len(asmInsns(strings.Split(fibBody, "\n"))); got != want {
		t.Errorf("fib: %d instructions, want %d (gc's %d plus the ABI0 marshal)\n--- asm ---\n%s", got, want, len(fibGC), fibBody)
	}

	// kern: the loop (from the backward branch's target to the branch)
	// is gc's.
	kernGC, err := capturedBody(kern)
	if err != nil {
		t.Fatal(err)
	}
	var loop []string
	var head int
	for i, in := range kernGC {
		m := branchNumRe.FindStringSubmatch(in.Text)
		if m == nil {
			continue
		}
		target, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		if target > in.Off {
			continue
		}
		head = target
		for _, l := range kernGC[:i+1] {
			if l.Off >= target {
				loop = append(loop, branchNumRe.ReplaceAllString(l.Text, "$1\tpc$2"))
			}
		}
		break
	}
	if loop == nil {
		t.Fatalf("captured Kern has no backward branch: %v", kernGC)
	}
	lines := strings.Split(kernBody, "\n")
	start := slices.Index(lines, fmt.Sprintf("pc%d:", head))
	if start < 0 {
		t.Fatalf("kern: no label pc%d\n--- asm ---\n%s", head, kernBody)
	}
	got := asmInsns(lines[start+1:])
	if got = got[:min(len(got), len(loop))]; !slices.Equal(got, loop) {
		t.Errorf("kern: the transform changed gc's loop\n got %q\nwant %q", got, loop)
	}

	if runtime.GOARCH != "amd64" {
		t.Skip("fixture emits amd64-only asm; the harness builds and runs it on the host")
	}
	run := t.TempDir()
	files := map[string]string{
		"go.mod":       "module perfrun\n\ngo 1.25.0\n",
		"lib.go":       strings.Replace(strings.Replace(libSrc, "package lib", "package perfrun", 1), "//go:noinline\n", "//go:noinline\n", 2),
		"decl.go":      "package perfrun\n\nfunc fibAsm(n int32) (r0 int32)\nfunc kernAsm(n int32, seed int32) (r0 int32)\n",
		"body_amd64.s": asmB.String(),
		"parity_test.go": `package perfrun

import "testing"

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
	cmd := exec.Command("go", "test", "-run", "TestParity", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("perf gate failed: %v\n%s\n--- asm ---\n%s", err, out, asmB.String())
	}
}

// asmInsns lists the instructions among lines of transformed asm: the
// TEXT line, NO_LOCAL_POINTERS and labels are not instructions.
func asmInsns(lines []string) []string {
	var insns []string
	for _, ln := range lines {
		ln = strings.TrimPrefix(ln, "\t")
		if ln == "" || ln == "NO_LOCAL_POINTERS" || strings.HasPrefix(ln, "TEXT ") || strings.HasSuffix(ln, ":") {
			continue
		}
		insns = append(insns, ln)
	}
	return insns
}
