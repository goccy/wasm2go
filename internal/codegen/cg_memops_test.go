package codegen_test

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
	"github.com/tetratelabs/wazero"
)

// TestMemoryOpsRuntime drives cg_memops — every memory load/store opcode at
// every width and sign plus memory.size/grow — through wasm2go (legacy and
// SSA) and checks every result against wazero. This is the broad coverage
// driver for handleMemoryOp and the SSA memory lowering.
func TestMemoryOpsRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_memops")
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

	i32, i64, f32, f64 := wasm.ValI32, wasm.ValI64, wasm.ValF32, wasm.ValF64
	type tc struct {
		export   string
		args     []uint64
		argTypes []wasm.ValType
		result   wasm.ValType
	}
	cases := []tc{
		{"l_i32", []uint64{0}, []wasm.ValType{i32}, i32},
		{"l_i32_8s", []uint64{0}, []wasm.ValType{i32}, i32},
		{"l_i32_8u", []uint64{15}, []wasm.ValType{i32}, i32},
		{"l_i32_16s", []uint64{2}, []wasm.ValType{i32}, i32},
		{"l_i32_16u", []uint64{2}, []wasm.ValType{i32}, i32},
		{"l_i64", []uint64{0}, []wasm.ValType{i32}, i64},
		{"l_i64_8s", []uint64{0}, []wasm.ValType{i32}, i64},
		{"l_i64_8u", []uint64{8}, []wasm.ValType{i32}, i64},
		{"l_i64_16s", []uint64{4}, []wasm.ValType{i32}, i64},
		{"l_i64_16u", []uint64{4}, []wasm.ValType{i32}, i64},
		{"l_i64_32s", []uint64{0}, []wasm.ValType{i32}, i64},
		{"l_i64_32u", []uint64{0}, []wasm.ValType{i32}, i64},
		{"l_offset", []uint64{0}, []wasm.ValType{i32}, i32},
		{"s_i32", []uint64{64, u32(-559038737)}, []wasm.ValType{i32, i32}, i32},
		{"s_i32_8", []uint64{72, 0xAB}, []wasm.ValType{i32, i32}, i32},
		{"s_i32_16", []uint64{80, 0xBEEF}, []wasm.ValType{i32, i32}, i32},
		{"s_i64", []uint64{88, 0x1122334455667788}, []wasm.ValType{i32, i64}, i64},
		{"s_i64_8", []uint64{100, 0x7F}, []wasm.ValType{i32, i64}, i64},
		{"s_i64_16", []uint64{108, 0xCAFE}, []wasm.ValType{i32, i64}, i64},
		{"s_i64_32", []uint64{116, 0xDEADBEEF}, []wasm.ValType{i32, i64}, i64},
		{"s_offset", []uint64{128, 12345}, []wasm.ValType{i32, i32}, i32},
		{"mem_size", nil, nil, i32},
		{"mem_grow", []uint64{1}, []wasm.ValType{i32}, i32},
	}
	floatCases := []tc{
		{"l_f32", []uint64{0}, []wasm.ValType{i32}, f32},
		{"l_f64", []uint64{0}, []wasm.ValType{i32}, f64},
		{"s_f32", []uint64{200, uint64(math.Float32bits(3.5))}, []wasm.ValType{i32, f32}, f32},
		{"s_f64", []uint64{208, math.Float64bits(2.71828)}, []wasm.ValType{i32, f64}, f64},
	}

	goArg := func(typ wasm.ValType, v uint64) string {
		switch typ {
		case wasm.ValI64:
			return fmt.Sprintf("int64(%d)", int64(v))
		case wasm.ValF32:
			return fmt.Sprintf("math.Float32frombits(%d)", uint32(v))
		case wasm.ValF64:
			return fmt.Sprintf("math.Float64frombits(%d)", v)
		default:
			return fmt.Sprintf("int32(%d)", int32(v))
		}
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"math\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	allCases := append(append([]tc(nil), cases...), floatCases...)
	for _, c := range allCases {
		res, err := wmod.ExportedFunction(c.export).Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", c.export, c.args, err)
		}
		method := codegen.ExportMethodName(c.export)
		var argList []string
		for i, a := range c.args {
			argList = append(argList, goArg(c.argTypes[i], a))
		}
		argStr := strings.Join(argList, ", ")
		switch c.result {
		case wasm.ValI32:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, argStr)
		case wasm.ValI64:
			want = append(want, fmt.Sprintf("%s=%d", c.export, int64(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", c.export, method, argStr)
		case wasm.ValF32:
			want = append(want, fmt.Sprintf("%s=%08x", c.export, uint32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%08x\\n\", math.Float32bits(m.%s(%s)))\n", c.export, method, argStr)
		case wasm.ValF64:
			want = append(want, fmt.Sprintf("%s=%016x", c.export, res[0]))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%016x\\n\", math.Float64bits(m.%s(%s)))\n", c.export, method, argStr)
		}
	}
	mainSB.WriteString("}\n")

	for _, useSSA := range []bool{false, true} {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
		if err != nil {
			t.Fatalf("translate (UseSSA=%v): %v", useSSA, err)
		}
		out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files))
		gotLines := strings.Split(out, "\n")
		if len(gotLines) != len(want) {
			t.Fatalf("UseSSA=%v: got %d lines want %d\n%s", useSSA, len(gotLines), len(want), out)
		}
		for i := range want {
			if strings.TrimSpace(gotLines[i]) != want[i] {
				t.Errorf("UseSSA=%v: %s mismatch: got %q want %q", useSSA, allCases[i].export, gotLines[i], want[i])
			}
		}
	}
}
