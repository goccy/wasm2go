package gcasm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestA64Spill is the arm64 regression gate for ABIInternal calls that
// spill an outgoing argument to the stack (>16 integer args). gc places
// the spilled arg at a hardware `N(RSP)` slot in the low frame; the
// transform must shift that store above our ABI0 outgoing scratch so the
// call marshaller re-reads it at the right offset. Before the fix this
// read uninitialised stack (the low 32 bits of the spilled m pointer),
// faulting far outside linear memory.
func TestA64Spill(t *testing.T) {
	dir := t.TempDir()
	src := `package lib

//go:noinline
func Callee(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16 int32) int32 {
	return a0 + a16*7 + a15
}

//go:noinline
func Caller(x int32) int32 {
	return Callee(x, x+1, x+2, x+3, x+4, x+5, x+6, x+7, x+8, x+9, x+10, x+11, x+12, x+13, x+14, x+15, x+16)
}
`
	for name, content := range map[string]string{
		"go.mod":     "module a64spill\n\ngo 1.25.0\n",
		"lib/lib.go": src,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fns, datas, err := captureArch(dir, "a64spill/lib", "arm64")
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
	sig := map[string][]ArgKind{"Callee": i32(17), "Caller": i32(1)}
	names := map[string][]string{
		"Callee": {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15", "a16"},
		"Caller": {"x"},
	}
	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		n := sym[strings.LastIndex(sym, ".")+1:]
		if s, ok := sig[n]; ok && strings.Contains(sym, "a64spill/lib") {
			return s, true, ArgI32, "·" + n, true
		}
		return nil, false, 0, "", false
	}
	var asm strings.Builder
	asm.WriteString("#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	// Callee has 17 int args → it stack-assigns in ABIInternal, so it is
	// itself a pure fallback (like the real Fn24168). Only Caller is asm;
	// it calls the pure-Go Callee through the compiler's ABI0 wrapper.
	for _, name := range []string{"Caller"} {
		body, err := TransformARM64(byName[name], TransformOptions{
			SymName:   name,
			CalleeSig: calleeSig,
			Params:    sig[name],
			HasResult: true,
			Result:    ArgI32,
			ArgNames:  names[name],
			Datas:     dm,
		})
		if err != nil {
			t.Fatalf("transform %s: %v", name, err)
		}
		asm.WriteString(body)
		asm.WriteString("\n")
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module a64spillrun\n\ngo 1.25.0\n",
		"decl.go": "//go:build arm64\n\npackage a64spillrun\n\n" +
			"func Caller(x int32) int32\n",
		"callee.go": `package a64spillrun

//go:noinline
func Callee(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16 int32) int32 {
	return a0 + a16*7 + a15
}
`,
		"body_arm64.s": asm.String(),
		"run_test.go": `package a64spillrun

import "testing"

func ref(x int32) int32 {
	a := []int32{x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9, x + 10, x + 11, x + 12, x + 13, x + 14, x + 15, x + 16}
	return a[0] + a[16]*7 + a[15]
}

func TestRun(t *testing.T) {
	for _, n := range []int32{0, 1, 7, 100, -3, 1 << 20} {
		if got, want := Caller(n), ref(n); got != want {
			t.Fatalf("Caller(%d)=%d want %d", n, got, want)
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
	runArm64Gate(t, run, ".", "TestRun", asm.String())
}
