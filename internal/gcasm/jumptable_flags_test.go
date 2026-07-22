package gcasm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// flagDispatchSrc builds a dense switch whose selector value ALSO feeds
// a comparison right before the dispatch, and whose case bodies branch
// on the flags that comparison sets. gc keeps that compare's flags live
// ACROSS its (flag-preserving) jump-table dispatch and lets the case
// bodies consume them. The transform's compare tree clobbers flags, so
// each leaf must REPLAY the pre-dispatch compare — this fixture pins
// that: an unreplayed (or mis-detected) flag leak makes some case pick
// the wrong branch and the run-comparison below fails.
//
// Shape: `if sel < 40 { switch sel { case i: <use flags of (sel<40)> } }`
// — gc commonly emits the `CMP sel,$40 / Jcc` and reuses those flags
// inside the arms.
func flagDispatchSrc(fnName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "func %s(sel int32, v0 int32) int32 {\n", fnName)
	b.WriteString("\tc := sel < 40\n\tswitch sel {\n")
	for i := 0; i < 48; i++ {
		fmt.Fprintf(&b, "\tcase %d:\n\t\tif c {\n\t\t\tv0 = v0*%d + %d\n\t\t} else {\n\t\t\tv0 = v0 - %d\n\t\t}\n\t\tgoto done\n", i, i+3, i, i)
	}
	b.WriteString("\tdefault:\n\t\tv0 = -1\n\t}\ndone:\n\treturn v0\n}\n")
	return b.String()
}

// TestJumpTableFlagReplayRun pins the jump-table flag-replay correctness
// fix: transform a dispatch whose targets consume the pre-dispatch
// compare's flags, assemble, and check every selector against the pure
// reference. Before the fix, the flag-consumption detection had
// false-negative holes and some leaves got no replay, so the tree's
// leftover flags leaked into the arms and picked the wrong branch.
func TestJumpTableFlagReplayRun(t *testing.T) {
	// The 48-case fixture crosses the large-table fallback threshold;
	// this gate pins the compare-tree flag replay itself, so disable
	// the policy (covered by TestJumpTableFallbackPolicy and the
	// jumptable gate).
	t.Setenv("GCASM_JT_FALLBACK", "off")
	dir := t.TempDir()
	src := "package lib\n\n//go:noinline\n" + flagDispatchSrc("FDispatch")
	for name, content := range map[string]string{
		"go.mod":     "module fjtgate\n\ngo 1.25.0\n",
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

	fns, datas, err := Capture(dir, "fjtgate/lib")
	if err != nil {
		t.Fatal(err)
	}
	var disp *Fn
	for _, f := range fns {
		if strings.HasSuffix(f.Name, ".FDispatch") {
			disp = f
		}
	}
	if disp == nil {
		t.Fatalf("FDispatch not captured; got %d fns", len(fns))
	}
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	body, err := Transform(disp, TransformOptions{
		SymName:   "fdispatchAsm",
		CalleeSig: func(string) ([]ArgKind, bool, ArgKind, string, bool) { return nil, false, 0, "", false },
		Params:    []ArgKind{ArgI32, ArgI32},
		HasResult: true,
		Result:    ArgI32,
		ArgNames:  []string{"sel", "v0"},
		Datas:     dm,
	})
	if err != nil {
		// If gc chose NOT to emit a jump table (compiler-version
		// dependent), there is nothing to pin here — skip rather than
		// fail, matching the existing gate's tolerance.
		if strings.Contains(err.Error(), "jump") {
			t.Skipf("no jump table emitted for this fixture on this toolchain: %v", err)
		}
		t.Fatal(err)
	}
	if !strings.Contains(body, "jt") || strings.Contains(body, ".jump") {
		t.Skipf("gc did not emit a jump table for FDispatch on this toolchain")
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module fjtrun\n\ngo 1.25.0\n",
		"decl.go": "package fjtrun\n\nfunc fdispatchAsm(sel int32, v0 int32) (r0 int32)\n\n//go:noinline\n" +
			flagDispatchSrc("fdispatchRef"),
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package fjtrun

import "testing"

func TestFDispatch(t *testing.T) {
	for sel := int32(-5); sel <= 55; sel++ {
		for _, v0 := range []int32{0, 1, -7, 1 << 20} {
			if got, want := fdispatchAsm(sel, v0), fdispatchRef(sel, v0); got != want {
				t.Fatalf("fdispatch(%d,%d)=%d want %d", sel, v0, got, want)
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
	cmd := exec.Command("go", "test", "-run", "TestFDispatch", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jt flag-replay gate run failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}
