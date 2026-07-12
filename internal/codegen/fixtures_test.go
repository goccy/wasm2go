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
	"github.com/tetratelabs/wazero/api"
)

// u32 packs a signed int32 into the low bits of a uint64 (wazero call ABI).
func u32(v int32) uint64 { return uint64(uint32(v)) }

type call struct {
	export string
	args   []uint64
	// Optional: which Go method receives this call. If empty, derived from
	// ExportMethodName(export). The Go method's args are the raw uint64 args
	// converted to int32/int64 based on argTypes.
	argTypes []wasm.ValType
	resType  wasm.ValType
}

type fixture struct {
	name  string
	calls []call
}

var fixtures = []fixture{
	{
		name: "memory.wasm",
		calls: []call{
			// data segment writes "hi\0" at offset 16.
			{export: "load_byte", args: []uint64{16}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32}, // 'h' = 104
			{export: "load_byte", args: []uint64{17}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32}, // 'i' = 105
			{export: "store_byte", args: []uint64{32, 0x42}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: 0},
			{export: "load_byte", args: []uint64{32}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "store_i32", args: []uint64{40, 0xdeadbeef}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: 0},
			{export: "load_i32", args: []uint64{40}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "sum_bytes", args: []uint64{16, 2}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32}, // 'h'+'i' = 209
			{export: "dispatch", args: []uint64{0, 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},   // double(7)=14
			{export: "dispatch", args: []uint64{1, 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},   // square(7)=49
			{export: "dispatch", args: []uint64{2, 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},   // triple(7)=21
		},
	},
	{
		name: "arith.wasm",
		calls: []call{
			{export: "add", args: []uint64{7, 35}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "add", args: []uint64{u32(-100), u32(50)}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "sub", args: []uint64{1000, 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "mul64", args: []uint64{12345, 67890}, argTypes: []wasm.ValType{wasm.ValI64, wasm.ValI64}, resType: wasm.ValI64},
			{export: "div_s", args: []uint64{100, 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "div_s", args: []uint64{u32(-100), 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "shifts", args: []uint64{0xff, 4}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "rotl", args: []uint64{0x80000001, 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "lt_s", args: []uint64{u32(-1), 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "lt_u", args: []uint64{u32(-1), 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
		},
	},
	{
		name: "control.wasm",
		calls: []call{
			{export: "fact", args: []uint64{0}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "fact", args: []uint64{1}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "fact", args: []uint64{5}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "fact", args: []uint64{10}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "gcd", args: []uint64{48, 18}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "gcd", args: []uint64{17, 13}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "max", args: []uint64{10, 20}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "max", args: []uint64{30, 7}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "max", args: []uint64{u32(-5), u32(-3)}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "switch3", args: []uint64{0}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "switch3", args: []uint64{1}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "switch3", args: []uint64{2}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "switch3", args: []uint64{3}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "switch3", args: []uint64{99}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
		},
	},
	{
		// Mirrors a C++ static-initializer pattern: recursive descent
		// through a tree where each record has {flag i8, ...,
		// child_count @20, children_ptr @24}. Verifies struct-field load
		// offsets, recursive call, looped children iteration, and
		// side-effect counter writes survive wasm2go's codegen + flush +
		// coalesce passes.
		name: "recursive_init.wasm",
		calls: []call{
			{export: "run", args: nil, argTypes: nil, resType: wasm.ValI32},
			{export: "flag_of", args: []uint64{32}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "flag_of", args: []uint64{64}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "flag_of", args: []uint64{96}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
		},
	},
	{
		// Mirrors C++ virtual-method dispatch via call_indirect through a
		// vtable stored in linear memory. Verifies that table population
		// from element segments + per-object vtable lookup + indirect call
		// all chain correctly.
		name: "vtable_dispatch.wasm",
		calls: []call{
			{export: "call_method", args: []uint64{32, 0}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "call_method", args: []uint64{32, 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "call_method", args: []uint64{48, 0}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
			{export: "call_method", args: []uint64{48, 1}, argTypes: []wasm.ValType{wasm.ValI32, wasm.ValI32}, resType: wasm.ValI32},
		},
	},
	{
		// Negative zero flowing through non-constant shapes (locals, block
		// results, phis, select, data segments, arithmetic).
		name: "cg_negzero_flows.wasm",
		calls: []call{
			{export: "via_local", resType: wasm.ValI64},
			{export: "via_block", resType: wasm.ValI64},
			{export: "via_phi", args: []uint64{1}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI64},
			{export: "via_select", args: []uint64{1}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI64},
			{export: "via_copysign_cc", resType: wasm.ValI64},
			{export: "via_copysign_cv", resType: wasm.ValI64},
			{export: "via_copysign_vc", resType: wasm.ValI64},
			{export: "via_neg_zero", resType: wasm.ValI64},
			{export: "via_load", resType: wasm.ValI64},
			{export: "via_add", resType: wasm.ValI64},
			{export: "via_mul_neg1", resType: wasm.ValI64},
		},
	},
	{
		// br_table selecting on a comparison result (SSA type bool): must
		// verify and route 0/1 correctly. Mirrors SpiderMonkey's Intl build.
		name: "cg_brtable_bool.wasm",
		calls: []call{
			{export: "pick", args: []uint64{3}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "pick", args: []uint64{5}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
			{export: "pick", args: []uint64{9}, argTypes: []wasm.ValType{wasm.ValI32}, resType: wasm.ValI32},
		},
	},
	{
		// Negative-zero float constants: Go has no -0.0 literal, so every
		// constant-emission path must go through math.Float*frombits for it.
		name: "cg_negzero.wasm",
		calls: []call{
			{export: "f64_negzero_bits", resType: wasm.ValI64},
			{export: "f32_negzero_bits", resType: wasm.ValI32},
			{export: "f64_negzero_call_bits", resType: wasm.ValI64},
			{export: "f32_negzero_call_bits", resType: wasm.ValI32},
			{export: "global_f64_negzero_bits", resType: wasm.ValI64},
			{export: "global_f32_negzero_bits", resType: wasm.ValI32},
			{export: "f64_negzero_mul1_bits", resType: wasm.ValI64},
			{export: "f64_min_negzero_bits", resType: wasm.ValI64},
			{export: "f64_nan_payload_bits", resType: wasm.ValI64},
		},
	},
}

func TestFixtures(t *testing.T) {
	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			runFixture(t, fx)
		})
	}
}

func runFixture(t *testing.T, fx fixture) {
	t.Helper()
	bin := testfixture.Wasm(t, fx.name)

	// Reference: wazero.
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
	wantLines := make([]string, 0, len(fx.calls))
	for _, c := range fx.calls {
		fn := mod.ExportedFunction(c.export)
		if fn == nil {
			t.Fatalf("missing export %q", c.export)
		}
		out, err := fn.Call(ctx, c.args...)
		if err != nil {
			t.Fatalf("wazero %s%v: %v", c.export, c.args, err)
		}
		var line string
		if c.resType == 0 {
			line = fmt.Sprintf("%s -> (void)", c.export)
		} else {
			switch c.resType {
			case wasm.ValI32:
				line = fmt.Sprintf("%s -> %d", c.export, int32(out[0]))
			case wasm.ValI64:
				line = fmt.Sprintf("%s -> %d", c.export, int64(out[0]))
			default:
				line = fmt.Sprintf("%s -> %d", c.export, out[0])
			}
		}
		wantLines = append(wantLines, line)
	}
	want := strings.Join(wantLines, "\n") + "\n"

	// Translate to Go.
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, parsed, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v\n", err)
	}

	// The SSA pipeline is always on now; the previous "regenerate with
	// UseSSA=true" path is therefore the same as the first translation.
	// Keep ssaBuf around so the comparison below still exercises a
	// second, independent compilation of the module — useful as a
	// regression guard against any non-deterministic emit path.
	var ssaBuf bytes.Buffer
	if _, err := codegen.Translate(&ssaBuf, parsed, codegen.Options{
		Package: "pkg", OutputImportPath: "gentest/pkg",
	}); err != nil {
		t.Fatalf("translate (second pass): %v\n", err)
	}

	// Synthesize a main.go that calls each export and prints results.
	var mainSB strings.Builder
	mainSB.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n")
	mainSB.WriteString("\tm := pkg.New()\n")
	for _, c := range fx.calls {
		methodName := codegen.ExportMethodName(c.export)
		var argList []string
		for i, a := range c.args {
			switch c.argTypes[i] {
			case wasm.ValI32:
				argList = append(argList, fmt.Sprintf("int32(%d)", int32(a)))
			case wasm.ValI64:
				argList = append(argList, fmt.Sprintf("int64(%d)", int64(a)))
			default:
				argList = append(argList, fmt.Sprintf("%d", a))
			}
		}
		if c.resType == 0 {
			fmt.Fprintf(&mainSB, "\tm.%s(%s)\n\tfmt.Printf(\"%s -> (void)\\n\")\n",
				methodName, strings.Join(argList, ", "), c.export)
		} else {
			fmt.Fprintf(&mainSB, "\tfmt.Printf(\"%s -> %%d\\n\", m.%s(%s))\n",
				c.export, methodName, strings.Join(argList, ", "))
		}
	}
	mainSB.WriteString("}\n")

	got := runGoSnippet(t, buf.String(), mainSB.String(), res.Sidecars, res.Files)
	if got != want {
		t.Errorf("output mismatch for %s\n--want--\n%s\n--got--\n%s\n--generated--\n%s", fx.name, want, got, buf.String())
	}

	// Run the SSA-mode regenerated source through the same test program
	// to confirm the SSA + fallback path keeps semantics intact.
	gotSSA := runGoSnippet(t, ssaBuf.String(), mainSB.String(), res.Sidecars, res.Files)
	if gotSSA != want {
		t.Errorf("UseSSA output mismatch for %s\n--want--\n%s\n--got--\n%s", fx.name, want, gotSSA)
	}
}

// silence unused import if api is dropped.
var _ = api.ValueTypeI32
