package gcasm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestA64Gate0 is the arm64 end-to-end gate: capture gc's arm64
// compilation of a recursive function + a cross-function call, transform
// to ABI0 arm64 .s, assemble on GOARCH=arm64, and run vs the pure
// reference over deep recursion (real stack growth).
func TestA64Gate0(t *testing.T) {
	dir := t.TempDir()
	libSrc := `package lib

//go:noinline
func Rec(n int32) int32 {
	if n <= 1 {
		return 1
	}
	var buf [128]int64
	buf[0] = int64(n)
	return Rec(n-1) + Rec(n-2) + int32(buf[0])
}

//go:noinline
func G(a, b, c int32) int32 { return a*b + c }

//go:noinline
func F(x int32) int32 {
	r := G(x, x+1, x+2)
	return r + x
}

//go:noinline
func Med(n int32) int32 {
	var buf [900]int64 // ~7.2KB frame → SUBS + BLO wraparound guard
	for i := range buf { buf[i] = int64(n) + int64(i) }
	if n <= 1 { return int32(buf[1]) }
	return Med(n-1) + int32(buf[n&511])
}
`
	for name, content := range map[string]string{
		"go.mod":     "module a64gate\n\ngo 1.25.0\n",
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
	fns, datas, err := captureArch(dir, "a64gate/lib", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	byName := map[string]*Fn{}
	for _, f := range fns {
		byName[f.Name[strings.LastIndex(f.Name, ".")+1:]] = f
	}
	i32 := func(n int) []ArgKind {
		out := make([]ArgKind, n)
		for i := range out {
			out[i] = ArgI32
		}
		return out
	}
	sig := map[string]struct {
		params []ArgKind
		names  []string
	}{
		"Rec": {i32(1), []string{"n"}},
		"G":   {i32(3), []string{"a", "b", "c"}},
		"F":   {i32(1), []string{"x"}},
		"Med": {i32(1), []string{"n"}},
	}
	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		n := sym[strings.LastIndex(sym, ".")+1:]
		if s, ok := sig[n]; ok && strings.Contains(sym, "a64gate/lib") {
			return s.params, true, ArgI32, "·" + n, true
		}
		return nil, false, 0, "", false
	}
	var asm strings.Builder
	asm.WriteString("#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	for _, name := range []string{"Rec", "G", "F", "Med"} {
		s := sig[name]
		body, err := TransformARM64(byName[name], TransformOptions{
			SymName:   name,
			CalleeSig: calleeSig,
			Params:    s.params,
			HasResult: true,
			Result:    ArgI32,
			ArgNames:  s.names,
			Datas:     dm,
		})
		if err != nil {
			// gc may compile a stack array to DUFFZERO on some toolchains;
			// such a function is a pure fallback in Build, so this asm gate
			// does not apply to it. The fixtures cover the asm path.
			if errors.Is(err, errUnsupportedDuff) {
				t.Skipf("%s compiled to a DUFF pseudo-op on this toolchain; it is a pure fallback in Build", name)
			}
			t.Fatalf("transform %s: %v", name, err)
		}
		asm.WriteString(body)
		asm.WriteString("\n")
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module a64run\n\ngo 1.25.0\n",
		"decl.go": "//go:build arm64\n\npackage a64run\n\n" +
			"func Rec(n int32) int32\nfunc G(a, b, c int32) int32\nfunc F(x int32) int32\nfunc Med(n int32) int32\n",
		"ref.go": "package a64run\n\n" + strings.Replace(strings.Replace(libSrc, "package lib", "", 1),
			"func Rec", "func recRef", 1),
		"body_arm64.s": asm.String(),
		"run_test.go": `package a64run

import "testing"

func recRefWrap(n int32) int32 {
	if n <= 1 {
		return 1
	}
	var buf [128]int64
	buf[0] = int64(n)
	return recRefWrap(n-1) + recRefWrap(n-2) + int32(buf[0])
}

func medRefWrap(n int32) int32 {
	var buf [900]int64
	for i := range buf {
		buf[i] = int64(n) + int64(i)
	}
	if n <= 1 {
		return int32(buf[1])
	}
	return medRefWrap(n-1) + int32(buf[n&511])
}

func TestRun(t *testing.T) {
	for _, n := range []int32{1, 2, 10, 26, 30} {
		if got, want := Rec(n), recRefWrap(n); got != want {
			t.Fatalf("Rec(%d)=%d want %d", n, got, want)
		}
	}
	for _, n := range []int32{1, 2, 10, 40} {
		if got, want := Med(n), medRefWrap(n); got != want {
			t.Fatalf("Med(%d)=%d want %d", n, got, want)
		}
	}
}
`,
	}
	// The ref.go rename left a stray recRef; simplest: drop ref.go and
	// inline the reference in run_test.go (done above via recRefWrap).
	delete(files, "ref.go")
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runArm64Gate(t, run, ".", "TestRun", asm.String())
}
