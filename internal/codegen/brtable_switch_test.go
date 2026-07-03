package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestBrTableEmitsSwitch pins the pure-mode br_table emission to a Go
// switch STATEMENT. The Go compiler lowers dense integer switches to
// jump tables but never reconstructs a switch from an if-else
// cascade, so the old chain-of-equality-Ifs emission cost
// O(len(cases)) compares per dispatch (CPython's eval loop: a
// 255-deep chain). The control fixture's switch3 export is a 3-case
// br_table.
func TestBrTableEmitsSwitch(t *testing.T) {
	bin := testfixture.Wasm(t, "control")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "ctl", OutputImportPath: "gentest/ctl"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var sb strings.Builder
	sb.Write(buf.Bytes())
	for _, data := range res.AuxFiles {
		sb.Write(data)
	}
	for _, data := range res.Files {
		sb.Write(data)
	}
	src := sb.String()

	// A switch with the three dispatch cases must exist...
	swRe := regexp.MustCompile(`switch [^\n]+\{`)
	if !swRe.MatchString(src) {
		t.Fatalf("no switch statement emitted for the br_table dispatcher")
	}
	if !strings.Contains(src, "case 0:") || !strings.Contains(src, "case 1:") || !strings.Contains(src, "case 2:") {
		t.Fatalf("switch missing dispatch case clauses:\n%s", clip(src))
	}
	if !strings.Contains(src, "default:") {
		t.Fatalf("switch missing default clause")
	}
}

func clip(s string) string {
	if len(s) > 4000 {
		return s[:4000] + "\n...[clipped]"
	}
	return s
}

// TestBrTable64RuntimePure diffs the pure-mode switch dispatch against
// wazero for every selector 0..70 (all 64 cases + a band of
// out-of-range values) plus the payload-carrying `pick` fallback.
func TestBrTable64RuntimePure(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_brtable64")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero close: %v", err)
		}
	})
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for sel := int32(0); sel <= 70; sel++ {
		o, err := wmod.ExportedFunction("switch64").Call(ctx, u32(sel))
		if err != nil {
			t.Fatalf("wazero switch64(%d): %v", sel, err)
		}
		want = append(want, fmt.Sprintf("%d", int32(o[0])))
		fmt.Fprintf(&mainSB, "\tfmt.Println(m.Switch64(int32(%d)))\n", sel)
	}
	for _, sel := range []int32{0, 1, 2} {
		o, err := wmod.ExportedFunction("pick").Call(ctx, u32(sel))
		if err != nil {
			t.Fatalf("wazero pick(%d): %v", sel, err)
		}
		want = append(want, fmt.Sprintf("%d", int32(o[0])))
		fmt.Fprintf(&mainSB, "\tfmt.Println(m.Pick(int32(%d)))\n", sel)
	}
	mainSB.WriteString("}\n")

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	out := strings.Fields(strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files)))
	if len(out) != len(want) {
		t.Fatalf("got %d outputs, want %d", len(out), len(want))
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("output %d: got %s want %s", i, out[i], want[i])
		}
	}
}
