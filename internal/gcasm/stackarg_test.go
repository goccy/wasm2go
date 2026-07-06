package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStackArgCallGate executes the ABIInternal stack-argument
// marshal: a transformed caller invoking a 12-int-arg callee (which
// itself stays pure — its own params stack-assign). Gate 3a validated
// that such call sites TRANSFORM; this gate validates they RUN.
func TestStackArgCallGate(t *testing.T) {
	dir := t.TempDir()
	libSrc := `package lib

//go:noinline
func Wide(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 int32) int32 {
	return a0 + a1*2 + a2*3 + a3*5 + a4*7 + a5*11 + a6*13 + a7*17 + a8*19 + a9*23 + a10*29 + a11*31
}

//go:noinline
func Caller(x int32) int32 {
	return Wide(x, x+1, x+2, x-3, x+4, x+5, x-6, x+7, x+8, x-9, x+10, x+11)
}
`
	for name, content := range map[string]string{
		"go.mod":     "module sagate\n\ngo 1.25.0\n",
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
	fns, _, err := Capture(dir, "sagate/lib")
	if err != nil {
		t.Fatal(err)
	}
	var fn *Fn
	for _, f := range fns {
		if strings.HasSuffix(f.Name, ".Caller") {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("Caller not captured")
	}
	wideSig := make([]ArgKind, 12)
	for i := range wideSig {
		wideSig[i] = ArgI32
	}
	body, err := Transform(fn, TransformOptions{
		SymName: "callerAsm",
		CalleeSig: func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
			if strings.HasSuffix(sym, ".Wide") {
				return wideSig, true, ArgI32, "·Wide", true
			}
			return nil, false, 0, "", false
		},
		Params:    []ArgKind{ArgI32},
		HasResult: true,
		Result:    ArgI32,
		ArgNames:  []string{"x"},
	})
	if err != nil {
		t.Fatal(err)
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod":       "module sarun\n\ngo 1.25.0\n",
		"lib.go":       strings.Replace(libSrc, "package lib", "package sarun", 1) + "\nfunc callerAsm(x int32) (r0 int32)\n",
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package sarun

import "testing"

func TestStackArgs(t *testing.T) {
	for _, x := range []int32{0, 1, -7, 1000, -100000} {
		if got, want := callerAsm(x), Caller(x); got != want {
			t.Fatalf("callerAsm(%d)=%d want %d", x, got, want)
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
	cmd := exec.Command("go", "test", "-run", "TestStackArgs", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stack-arg gate failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}
