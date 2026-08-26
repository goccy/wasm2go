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

// TestAllOpsRuntime drives the cg_allops fixture — one export per numeric
// and conversion opcode family — through the wasm2go pipeline (legacy and
// SSA) and checks every result against wazero. This is the broad coverage
// driver for the legacy fncompiler numeric-op dispatch and the SSA
// numeric lowering.
func TestAllOpsRuntime(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_allops")
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

	// Argument-type and result-type metadata per export, derived from the
	// module's own type section so the generated calls are well-typed.
	exportSig := map[string]struct {
		params []wasm.ValType
		result wasm.ValType
	}{}
	for _, e := range mod.Exports {
		if e.Kind != wasm.ExportFunc {
			continue
		}
		ft := mod.FuncTypeOf(e.Index)
		var res wasm.ValType
		if len(ft.Results) > 0 {
			res = ft.Results[0]
		}
		exportSig[e.Name] = struct {
			params []wasm.ValType
			result wasm.ValType
		}{ft.Params, res}
	}

	// Per-arg sample values. Index into this by position; the same probe
	// values exercise sign handling, zero, and large magnitudes.
	i32Args := [][]uint64{
		{u32(100), u32(7)},
		{u32(-100), u32(3)},
		{u32(0x12345678), u32(5)},
	}
	i64Args := [][]uint64{
		{0x00FF_00FF_00FF_00FF, 9},
		{^uint64(9999999998), 4}, // -9999999999 as two's complement
	}
	f32Args := [][]float32{
		{3.5, 1.25},
		{-2.0, 8.0},
	}
	f64Args := [][]float64{
		{12.5, 0.25},
		{-7.5, 4.0},
	}

	goLitI := func(t wasm.ValType, v uint64) string {
		if t == wasm.ValI64 {
			return fmt.Sprintf("int64(%d)", int64(v))
		}
		return fmt.Sprintf("int32(%d)", int32(v))
	}

	type callPlan struct {
		export string
		args   []uint64 // raw wazero args
		goArgs []string // formatted Go-call args
		result wasm.ValType
	}
	var plans []callPlan

	for _, e := range mod.Exports {
		if e.Kind != wasm.ExportFunc {
			continue
		}
		sig := exportSig[e.Name]
		// Determine arg flavor from the first param (fixture exports are
		// homogeneous in param type within an export).
		allInt := true
		allF32 := len(sig.params) > 0
		allF64 := len(sig.params) > 0
		for _, p := range sig.params {
			if p == wasm.ValF32 || p == wasm.ValF64 {
				allInt = false
			}
			if p != wasm.ValF32 {
				allF32 = false
			}
			if p != wasm.ValF64 {
				allF64 = false
			}
		}
		switch {
		case len(sig.params) == 0:
			plans = append(plans, callPlan{e.Name, nil, nil, sig.result})
		case allInt:
			isI64 := sig.params[0] == wasm.ValI64
			sets := i32Args
			if isI64 {
				sets = i64Args
			}
			for _, set := range sets {
				args := append([]uint64(nil), set[:len(sig.params)]...)
				var ga []string
				for i := range sig.params {
					ga = append(ga, goLitI(sig.params[i], args[i]))
				}
				plans = append(plans, callPlan{e.Name, args, ga, sig.result})
			}
		case allF32:
			for _, set := range f32Args {
				var args []uint64
				var ga []string
				for i := range sig.params {
					args = append(args, uint64(math.Float32bits(set[i])))
					ga = append(ga, fmt.Sprintf("float32(%v)", set[i]))
				}
				plans = append(plans, callPlan{e.Name, args, ga, sig.result})
			}
		case allF64:
			for _, set := range f64Args {
				var args []uint64
				var ga []string
				for i := range sig.params {
					args = append(args, math.Float64bits(set[i]))
					ga = append(ga, fmt.Sprintf("float64(%v)", set[i]))
				}
				plans = append(plans, callPlan{e.Name, args, ga, sig.result})
			}
		}
	}

	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n")
	var want []string
	for _, p := range plans {
		res, err := wmod.ExportedFunction(p.export).Call(ctx, p.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", p.export, p.args, err)
		}
		method := codegen.ExportMethodName(p.export)
		argStr := strings.Join(p.goArgs, ", ")
		switch p.result {
		case wasm.ValI32:
			want = append(want, fmt.Sprintf("%s=%d", p.export, int32(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", p.export, method, argStr)
		case wasm.ValI64:
			want = append(want, fmt.Sprintf("%s=%d", p.export, int64(res[0])))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%d\\n\", m.%s(%s))\n", p.export, method, argStr)
		case wasm.ValF32:
			f := math.Float32frombits(uint32(res[0]))
			want = append(want, fmt.Sprintf("%s=%08x", p.export, math.Float32bits(f)))
			// Compare via bit pattern to dodge formatting drift.
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%08x\\n\", f32bits(m.%s(%s)))\n", p.export, method, argStr)
		case wasm.ValF64:
			f := math.Float64frombits(res[0])
			want = append(want, fmt.Sprintf("%s=%016x", p.export, math.Float64bits(f)))
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s=%%016x\\n\", f64bits(m.%s(%s)))\n", p.export, method, argStr)
		}
	}
	mainSB.WriteString("}\n")
	mainSB.WriteString("func f32bits(f float32) uint32 { return mathFloat32bits(f) }\n")
	mainSB.WriteString("func f64bits(f float64) uint64 { return mathFloat64bits(f) }\n")
	// Provide the bits helpers without a math import collision.
	mainHdr := strings.Replace(mainSB.String(),
		"import (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)",
		"import (\n\t\"fmt\"\n\t\"math\"\n\t\"gentest/pkg\"\n)", 1)
	mainHdr = strings.Replace(mainHdr, "mathFloat32bits", "math.Float32bits", 1)
	mainHdr = strings.Replace(mainHdr, "mathFloat64bits", "math.Float64bits", 1)

	for _, useSSA := range []bool{false, true} {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
		if err != nil {
			t.Fatalf("translate (UseSSA=%v): %v", useSSA, err)
		}
		out := strings.TrimSpace(runGoSnippet(t, buf.String(), mainHdr, res.Sidecars, filesWithAux(res)))
		gotLines := strings.Split(out, "\n")
		if len(gotLines) != len(want) {
			t.Fatalf("UseSSA=%v: got %d result lines want %d\n%s", useSSA, len(gotLines), len(want), out)
		}
		for i := range want {
			if strings.TrimSpace(gotLines[i]) != want[i] {
				t.Errorf("UseSSA=%v: %s mismatch: got %q want %q", useSSA, plans[i].export, gotLines[i], want[i])
			}
		}
	}
}
