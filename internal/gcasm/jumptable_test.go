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

// dispatchSrc builds a 64-case dense switch of gotos — the shape the
// pure emitter produces for br_table and that gc lowers to a jump
// table (LEAQ fn.jumpN(SB), Rt; JMP (Rt)(Ri*8) + SRODATA of R_ADDR
// relocs into the function).
func dispatchSrc(fnName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "func %s(sel int32, v0 int32) int32 {\n\tswitch sel {\n", fnName)
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&b, "\tcase %d:\n\t\tgoto lbl_%d\n", i, i)
	}
	b.WriteString("\tdefault:\n\t\tgoto lbl_def\n\t}\nlbl_def:\n\tv0 = -1\n\tgoto done\n")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&b, "lbl_%d:\n\tv0 = v0*%d + %d\n\tgoto done\n", i, i+3, i)
	}
	b.WriteString("done:\n\treturn v0\n}\n")
	return b.String()
}

// TestJumpTableTransformRun is the jump-table gate: capture a
// function gc compiles WITH a jump table, transform it (the LEAQ+JMP
// pair must become a binary search tree over pcN labels — Plan9 asm
// cannot express label addresses in DATA), assemble, and compare
// against the pure implementation for every selector including
// out-of-range ones. Also asserts transform determinism.
func TestJumpTableTransformRun(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture emits amd64-only asm; the harness builds and runs it on the host")
	}
	dir := t.TempDir()
	src := "package lib\n\n//go:noinline\n" + dispatchSrc("Dispatch")
	for name, content := range map[string]string{
		"go.mod":     "module jtgate\n\ngo 1.25.0\n",
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

	transformOnce := func() (string, string) {
		fns, datas, err := Capture(dir, "jtgate/lib")
		if err != nil {
			t.Fatal(err)
		}
		var disp *Fn
		for _, f := range fns {
			if strings.HasSuffix(f.Name, ".Dispatch") {
				disp = f
			}
		}
		if disp == nil {
			t.Fatalf("Dispatch not captured; got %d fns", len(fns))
		}
		dm := map[string]*DataSym{}
		for _, d := range datas {
			dm[d.Name] = d
		}
		jt := &JTTable{}
		body, err := Transform(disp, TransformOptions{
			SymName:   "dispatchAsm",
			CalleeSig: func(string) ([]ArgKind, bool, ArgKind, string, bool) { return nil, false, 0, "", false },
			Params:    []ArgKind{ArgI32, ArgI32},
			HasResult: true,
			Result:    ArgI32,
			ArgNames:  []string{"sel", "v0"},
			Datas:     dm,
			JT:        jt,
		})
		if err != nil {
			t.Fatal(err)
		}
		return body + jt.EmitAsm("amd64"), jt.EmitGo("amd64")
	}
	body, jtGo := transformOnce()
	if body2, jtGo2 := transformOnce(); body2 != body || jtGo2 != jtGo {
		t.Fatalf("transform not deterministic:\n--- run1\n%s\n--- run2\n%s", body, body2)
	}
	if !strings.Contains(body, "_jt") || strings.Contains(body, ".jump") {
		t.Fatalf("jump table not rewritten to an O(1) pad:\n%s", body)
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module jtrun\n\ngo 1.25.0\n",
		"decl.go": "package jtrun\n\nimport \"unsafe\"\n\nvar _ unsafe.Pointer\n\nfunc dispatchAsm(sel int32, v0 int32) (r0 int32)\n\n//go:noinline\n" +
			dispatchSrc("dispatchRef") + "\n" + jtGo,
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package jtrun

import "testing"

func TestDispatch(t *testing.T) {
	for sel := int32(-5); sel <= 70; sel++ {
		for _, v0 := range []int32{0, 1, -7, 1 << 20} {
			if got, want := dispatchAsm(sel, v0), dispatchRef(sel, v0); got != want {
				t.Fatalf("dispatch(%d,%d)=%d want %d", sel, v0, got, want)
			}
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
	cmd := exec.Command("go", "test", "-run", "TestDispatch", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jt gate run failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}
