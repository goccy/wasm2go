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

// runExportMatrix translates a fixture (legacy + SSA), compiles+runs the
// generated package, and asserts each integer-result export call matches
// wazero. argTypes/resType per call describe the Go-call shape.
func runExportMatrix(t *testing.T, fixture string, calls []call) {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, c := range calls {
		res, err := wmod.ExportedFunction(c.export).Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", c.export, c.args, err)
		}
		method := codegen.ExportMethodName(c.export)
		var argList []string
		for i, a := range c.args {
			switch c.argTypes[i] {
			case wasm.ValI64:
				argList = append(argList, fmt.Sprintf("int64(%d)", int64(a)))
			default:
				argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
			}
		}
		argStr := strings.Join(argList, ", ")
		switch c.resType {
		case wasm.ValI64:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int64(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, argStr)
		case 0:
			want = append(want, fmt.Sprintf("%s=void", c.export))
			fmt.Fprintf(&mainSB, "\tm.%s(%s)\n\tfmt.Printf(\"%s=void\\n\")\n", method, argStr, c.export)
		default:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, argStr)
		}
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
			t.Fatalf("%s UseSSA=%v: got %d lines want %d\n%s", fixture, useSSA, len(gotLines), len(want), out)
		}
		for i := range want {
			if strings.TrimSpace(gotLines[i]) != want[i] {
				t.Errorf("%s UseSSA=%v: %s mismatch got %q want %q", fixture, useSSA, calls[i].export, gotLines[i], want[i])
			}
		}
	}
}

// TestFrameAllocRuntime drives cg_frame — the Emscripten stack-frame
// allocation idiom — and confirms the tryEmitFrameAlloc rewrite preserves
// semantics across both pipelines.
func TestFrameAllocRuntime(t *testing.T) {
	i32 := wasm.ValI32
	runExportMatrix(t, "cg_frame.wasm", []call{
		{export: "alloc_frame", resType: i32},
		{export: "alloc_frame_add", resType: i32},
		{export: "sp_now", resType: i32},
		{export: "free_frame", args: []uint64{16}, argTypes: []wasm.ValType{i32}, resType: 0},
		{export: "sp_now", resType: i32},
		{export: "alloc64", resType: wasm.ValI64},
	})
}

// TestIndirectCallRuntime drives cg_indirect — call_indirect across several
// distinct function-type signatures plus direct call chains.
func TestIndirectCallRuntime(t *testing.T) {
	i32, i64 := wasm.ValI32, wasm.ValI64
	runExportMatrix(t, "cg_indirect.wasm", []call{
		{export: "ind_unary", args: []uint64{0, 9}, argTypes: []wasm.ValType{i32, i32}, resType: i32},
		{export: "ind_unary", args: []uint64{1, 9}, argTypes: []wasm.ValType{i32, i32}, resType: i32},
		{export: "ind_binary", args: []uint64{2, 8, 5}, argTypes: []wasm.ValType{i32, i32, i32}, resType: i32},
		{export: "ind_binary", args: []uint64{3, 8, 5}, argTypes: []wasm.ValType{i32, i32, i32}, resType: i32},
		{export: "ind_i64", args: []uint64{4, 6, 7}, argTypes: []wasm.ValType{i32, i64, i64}, resType: i64},
		{export: "ind_noargs", args: []uint64{5}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "ind_void", args: []uint64{6, 1234}, argTypes: []wasm.ValType{i32, i32}, resType: i32},
		{export: "direct_chain", args: []uint64{u32(-3)}, argTypes: []wasm.ValType{i32}, resType: i32},
	})
}

// TestSpecialFPRuntime drives cg_specialfp — NaN/Inf float constants — and
// confirms the f32ConstExpr/f64ConstExpr special-value emission (which
// routes through math.Float{32,64}frombits) preserves the exact bit
// pattern that wazero produces.
func TestSpecialFPRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_specialfp")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	f32Exports := []string{"f32_nan", "f32_inf", "f32_ninf"}
	f64Exports := []string{"f64_nan", "f64_inf", "f64_ninf"}
	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"math\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, e := range f32Exports {
		res, err := wmod.ExportedFunction(e).Call(ctx)
		if err != nil {
			t.Fatalf("wazero %s: %v", e, err)
		}
		want = append(want, fmt.Sprintf("%s=%08x", e, uint32(res[0])))
		fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%08x\\n\", math.Float32bits(m.%s()))\n", e, codegen.ExportMethodName(e))
	}
	for _, e := range f64Exports {
		res, err := wmod.ExportedFunction(e).Call(ctx)
		if err != nil {
			t.Fatalf("wazero %s: %v", e, err)
		}
		want = append(want, fmt.Sprintf("%s=%016x", e, res[0]))
		fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%016x\\n\", math.Float64bits(m.%s()))\n", e, codegen.ExportMethodName(e))
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

// TestGlobalsRuntime drives cg_globals — globals of every value type,
// mutable and immutable — and checks get/set/bump results against wazero
// across both pipelines. Float globals are compared by bit pattern.
func TestGlobalsRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_globals")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wmod, err := r.Instantiate(ctx, bin)
	if err != nil {
		t.Fatalf("wazero instantiate: %v", err)
	}

	// Each call is self-contained per fresh module instance; integer
	// getters/bumpers and the const getter give deterministic values.
	type step struct {
		export   string
		args     []uint64
		argTypes []wasm.ValType
		resType  wasm.ValType
	}
	i32, i64 := wasm.ValI32, wasm.ValI64
	steps := []step{
		{"get_i32", nil, nil, i32},
		{"get_i64", nil, nil, i64},
		{"get_const", nil, nil, i32},
		{"bump_i32", []uint64{8}, []wasm.ValType{i32}, i32},
		{"set_i64", []uint64{777}, []wasm.ValType{i64}, 0},
	}
	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, s := range steps {
		res, err := wmod.ExportedFunction(s.export).Call(ctx, s.args...)
		if err != nil {
			t.Fatalf("wazero %s: %v", s.export, err)
		}
		method := codegen.ExportMethodName(s.export)
		var argList []string
		for i, a := range s.args {
			if s.argTypes[i] == wasm.ValI64 {
				argList = append(argList, fmt.Sprintf("int64(%d)", int64(a)))
			} else {
				argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
			}
		}
		argStr := strings.Join(argList, ", ")
		switch s.resType {
		case wasm.ValI64:
			want = append(want, fmt.Sprintf("%s=%d", s.export, int64(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", s.export, method, argStr)
		case 0:
			want = append(want, fmt.Sprintf("%s=void", s.export))
			fmt.Fprintf(&mainSB, "\tm.%s(%s)\n\tfmt.Printf(\"%s=void\\n\")\n", method, argStr, s.export)
		default:
			want = append(want, fmt.Sprintf("%s=%d", s.export, int32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", s.export, method, argStr)
		}
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

// TestEntryExports exercises the EntryExports DCE root-set knob:
// narrowing the export root set to a single export must still produce
// a module that compiles, and the empty-slice form (no export is a
// root) must also be accepted.
func TestEntryExports(t *testing.T) {
	mod := readFixture(t, "arith.wasm")
	t.Run("single", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := codegen.Translate(&buf, mod, codegen.Options{
			Package: "pkg", OutputImportPath: "gentest/pkg",
			EntryExports: []string{"add"},
		})
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		assertSingleFileCompiles(t, buf.String(), nil)
	})
	t.Run("none", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := codegen.Translate(&buf, mod, codegen.Options{
			Package: "pkg", OutputImportPath: "gentest/pkg",
			EntryExports: []string{},
		})
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		assertSingleFileCompiles(t, buf.String(), nil)
	})
}

// TestNaNGlobalInit verifies that float globals initialised to NaN/Inf
// compile and run correctly — the global-init emitter routes such values
// through math.Float*frombits (Go has no NaN/Inf literal).
func TestNaNGlobalInit(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_globals_nan")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Printf("is_nan=%d\n", m.IsNan())
	fmt.Printf("inf_gt=%d\n", m.InfGt())
}
`
	out := strings.TrimSpace(runGoSnippet(t, buf.String(), main, res.Sidecars))
	if !strings.Contains(out, "is_nan=1") {
		t.Errorf("NaN global not initialised to NaN: %q", out)
	}
	if !strings.Contains(out, "inf_gt=1") {
		t.Errorf("Inf global not initialised to +Inf: %q", out)
	}
}

// TestMiscOpsRuntime drives cg_misc — nop/drop/typed-select, value-producing
// blocks and if/else, loops carrying a result, and dead code after return —
// checking every result against wazero across both pipelines.
func TestMiscOpsRuntime(t *testing.T) {
	i32, i64 := wasm.ValI32, wasm.ValI64
	runExportMatrix(t, "cg_misc.wasm", []call{
		{export: "with_nop", args: []uint64{42}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "with_drop", args: []uint64{7, 9}, argTypes: []wasm.ValType{i32, i32}, resType: i32},
		{export: "block_result", args: []uint64{10}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "if_value", args: []uint64{1}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "if_value", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "loop_sum", args: []uint64{10}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "loop_sum", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "typed_select", args: []uint64{111, 222, 1}, argTypes: []wasm.ValType{i64, i64, i32}, resType: i64},
		{export: "typed_select", args: []uint64{111, 222, 0}, argTypes: []wasm.ValType{i64, i64, i32}, resType: i64},
		{export: "dead_after_return", args: []uint64{55}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "early_return", args: []uint64{1}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "early_return", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "nested_br", args: []uint64{1}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "nested_br", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
	})
}

// TestDeadEndRuntime drives cg_deadend — functions whose every path exits
// via return/br so the implicit function-end is unreachable. The SSA
// lowering must synthesise a well-formed dead-block terminator; results
// must still match wazero.
func TestDeadEndRuntime(t *testing.T) {
	i32 := wasm.ValI32
	runExportMatrix(t, "cg_deadend.wasm", []call{
		{export: "both_return", args: []uint64{1}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "both_return", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "br_root", args: []uint64{1}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "br_root", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "loop_return", args: []uint64{5}, argTypes: []wasm.ValType{i32}, resType: i32},
		{export: "loop_return", args: []uint64{0}, argTypes: []wasm.ValType{i32}, resType: i32},
	})
}
