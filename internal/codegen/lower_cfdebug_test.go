package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// TestSSAControlFlow drives the ssa_cf.wasm fixture — each export is a
// small structured-control pattern — through the full UseSSA codegen
// path and compares results against a wazero reference. This is the
// debugging harness for multi-block SSA lowering: a failure names the
// exact pattern (abs / clamp_if / count / early / sum / counteven) and
// the inputs that diverge.
func TestSSAControlFlow(t *testing.T) {
	bin := testfixture.Wasm(t, "ssa_cf")

	type probe struct {
		export string
		inputs []int32
	}
	probes := []probe{
		{"abs", []int32{-5, 0, 7, -2147483647}},
		{"clamp_if", []int32{-3, 0, 9}},
		{"count", []int32{0, 1, 5, 10}},
		{"early", []int32{3, 10, 11, 100}},
		{"sum", []int32{0, 1, 5, 10}},
		{"counteven", []int32{0, 1, 4, 9}},
		{"deadnest", []int32{0, 1, 5}},
		{"pick", []int32{-1, 0, 1, 7}},
		{"ret_nested", []int32{-3, -1, 0, 5}},
		{"deep", []int32{0, 5, 6, 100}},
		{"mul2", []int32{0, 1, 4, 10}},
		{"brblock", []int32{0, 1, 5}},
		{"fold_arith", []int32{0}},
		{"fold_cse", []int32{0, 3, 7}},
		{"fold_dead", []int32{0, 5, 41}},
	}

	// wazero reference values.
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := r.Close(ctx); err != nil {
			t.Errorf("wazero runtime close: %v", err)
		}
	})
	mod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}
	want := map[string][]int32{}
	for _, p := range probes {
		fn := mod.ExportedFunction(p.export)
		if fn == nil {
			t.Fatalf("ssa_cf.wasm: missing export %q", p.export)
		}
		for _, in := range p.inputs {
			out, err := fn.Call(ctx, uint64(uint32(in)))
			if err != nil {
				t.Fatalf("wazero %s(%d): %v", p.export, in, err)
			}
			want[p.export] = append(want[p.export], int32(out[0]))
		}
	}

	// Generate the module with UseSSA on — multi-block (control-flow)
	// functions take the SSA-emission path.
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, parsed, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	// Synthesize a main.go that prints `export(in) -> result` lines.
	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n")
	mainSB.WriteString("\tm := pkg.New()\n")
	for _, p := range probes {
		method := codegen.ExportMethodName(p.export)
		for _, in := range p.inputs {
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s(%d) -> %%d\\n\", m.%s(int32(%d)))\n",
				p.export, in, method, in)
		}
	}
	mainSB.WriteString("}\n")

	got := runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files)

	// Build the expected output block.
	var wantSB strings.Builder
	for _, p := range probes {
		for i, in := range p.inputs {
			fmt.Fprintf(&wantSB, "%s(%d) -> %d\n", p.export, in, want[p.export][i])
		}
	}
	if got != wantSB.String() {
		t.Errorf("SSA control-flow mismatch.\n--want--\n%s\n--got--\n%s\n--generated--\n%s",
			wantSB.String(), got, buf.String())
	}
}
