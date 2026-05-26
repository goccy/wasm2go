package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// TestSSAControlFlowGoto exercises the goto-based emitMultiBlock SSA
// emission path (the fallback for CFG shapes the structured emitter
// rejects: multi-exit loops). cg_nestedloop's `multiexit` export is
// such a function. Each result is checked against wazero across both
// the legacy and the SSA pipelines.
func TestSSAControlFlowGoto(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_nestedloop")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	type tc struct {
		export string
		args   []uint64
	}
	cases := []tc{
		{"nested", []uint64{0}},
		{"nested", []uint64{1}},
		{"nested", []uint64{5}},
		{"nested", []uint64{12}},
		{"seq2", []uint64{10, 0}},
		{"seq2", []uint64{10, 3}},
		{"seq2", []uint64{0, 5}},
		{"multiexit", []uint64{20, 7}},
		{"multiexit", []uint64{20, 99}},
		{"multiexit", []uint64{0, 0}},
		{"multiexit", []uint64{5, 5}},
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, c := range cases {
		res, err := wmod.ExportedFunction(c.export).Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", c.export, c.args, err)
		}
		want = append(want, fmt.Sprintf("%s=%d", c.export, int32(res[0])))
		var argList []string
		for _, a := range c.args {
			argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
		}
		fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n",
			c.export, codegen.ExportMethodName(c.export), strings.Join(argList, ", "))
	}
	mainSB.WriteString("}\n")

	for _, useSSA := range []bool{false, true} {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
		if err != nil {
			t.Fatalf("translate (UseSSA=%v): %v", useSSA, err)
		}
		out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars))
		gotLines := strings.Split(out, "\n")
		if len(gotLines) != len(want) {
			t.Fatalf("UseSSA=%v: got %d lines want %d\n%s", useSSA, len(gotLines), len(want), out)
		}
		for i := range want {
			if strings.TrimSpace(gotLines[i]) != want[i] {
				t.Errorf("UseSSA=%v: line %d got %q want %q", useSSA, i, gotLines[i], want[i])
			}
		}
	}
}

// TestSSAControlFlowPromotionReport runs the SSA pipeline with a
// PromotionReportPath set, which triggers the Phase 4 memory-promotion
// report writer. memory.wasm exercises a spread of loads/stores so the
// memory-metrics counter is non-zero and the report is emitted; the
// report file must be created and contain JSON.
func TestSSAControlFlowPromotionReport(t *testing.T) {
	mod := readFixture(t, "memory.wasm")
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "promotion.json")
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
		PromotionReportPath: reportPath,
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("promotion report not written: %v", err)
	}
	if len(data) == 0 || data[0] != '{' {
		t.Errorf("promotion report is not JSON: %q", data)
	}
	assertSingleFileCompiles(t, buf.String(), res.Sidecars)
}
