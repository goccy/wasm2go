package gcasm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// ovrModule is a module exporting `dot(i32, i64, i64) -> f32` (function
// 0, no imports) and `plain(i32)` (function 1).
func ovrModule(memory64 bool) *wasm.Module {
	return &wasm.Module{
		Types: []wasm.FuncType{
			{Params: []wasm.ValType{wasm.ValI32, wasm.ValI64, wasm.ValI64}, Results: []wasm.ValType{wasm.ValF32}},
			{Params: []wasm.ValType{wasm.ValI32}},
		},
		Functions: []wasm.Function{{TypeIdx: 0, Body: []byte{0x0b}}, {TypeIdx: 1, Body: []byte{0x0b}}},
		Memories:  []wasm.MemoryType{{Is64: memory64}},
		Exports: []wasm.Export{
			{Name: "dot", Kind: wasm.ExportFunc, Index: 0},
			{Name: "plain", Kind: wasm.ExportFunc, Index: 1},
		},
	}
}

func writeOvr(t *testing.T, dir, manifest string, bodies map[string]string) string {
	t.Helper()
	for name, text := range bodies {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(p, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const ovrGoodBody = "\tMOVW\tl0+8(FP), R1\n\tCBZW\tR1, 2(PC)\n\tB\tovr_oob\n\tFMOVS\t$0.0, F0\n\tFMOVS\tF0, r0+32(FP)\n\tRET\n"

func TestLoadAsmOverrides(t *testing.T) {
	dir := t.TempDir()
	p := writeOvr(t, dir, `{
  "version": 1,
  "memory64": true,
  "functions": [{
    "export": "dot",
    "params": ["i32", "i64", "i64"],
    "result": "f32",
    "bodies": [
      {"arch": "arm64", "feature": "neon", "frame": 0, "file": "dot_neon.s"},
      {"arch": "arm64", "feature": "i8mm", "frame": 16, "file": "dot_i8mm.s"},
      {"arch": "arm64", "feature": "fhm", "frame": 16, "file": "dot_fhm.s"},
      {"arch": "amd64", "feature": "avx2", "frame": 8, "file": "dot_avx2.s"}
    ]
  }]
}`, map[string]string{"dot_neon.s": ovrGoodBody, "dot_i8mm.s": ovrGoodBody, "dot_fhm.s": ovrGoodBody, "dot_avx2.s": "\tRET\n"})
	ovr, err := LoadAsmOverrides(p, ovrModule(true))
	if err != nil {
		t.Fatal(err)
	}
	ov := ovr.Functions["dot"]
	if ov == nil || ov.FuncIdx != 0 || ov.Result == nil || *ov.Result != wasm.ValF32 {
		t.Fatalf("function = %+v", ov)
	}
	// Bodies sorted most specific first, baseline last.
	if got := []string{ov.Bodies["arm64"][0].Feature, ov.Bodies["arm64"][1].Feature, ov.Bodies["arm64"][2].Feature}; got[0] != "fhm" || got[1] != "i8mm" || got[2] != "neon" {
		t.Fatalf("arm64 body order = %v", got)
	}
	if len(ov.Bodies["amd64"]) != 1 || ov.Bodies["amd64"][0].Frame != 8 {
		t.Fatalf("amd64 bodies = %+v", ov.Bodies["amd64"])
	}
	if offs := overrideArgOffsets(ov.Params, ov.Result); offs["l0"] != 8 || offs["l1"] != 16 || offs["l2"] != 24 || offs["r0"] != 32 {
		t.Fatalf("arg offsets = %v", offs)
	}
	if got, want := abi0ArgBytes(ovrModule(true).FuncTypeOf(0)), 36; got != want {
		t.Fatalf("abi0ArgBytes = %d, want %d", got, want)
	}
}

func TestLoadAsmOverridesRejects(t *testing.T) {
	base := func(export, params, result, bodies string) string {
		return `{"version": 1, "memory64": true, "functions": [{"export": "` + export + `", "params": ` + params + `, "result": ` + result + `, "bodies": [` + bodies + `]}]}`
	}
	neon := `{"arch": "arm64", "feature": "neon", "frame": 0, "file": "b.s"}`
	cases := []struct {
		name, manifest, body, want string
		memory64                   bool
	}{
		{"unknown export", base("nope", `["i32","i64","i64"]`, `"f32"`, neon), ovrGoodBody, "not an exported function", true},
		{"signature", base("dot", `["i32","i64"]`, `"f32"`, neon), ovrGoodBody, "does not match", true},
		{"result", base("dot", `["i32","i64","i64"]`, `null`, neon), ovrGoodBody, "does not match", true},
		{"memory64", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), ovrGoodBody, "memory64", false},
		{"feature", base("dot", `["i32","i64","i64"]`, `"f32"`, `{"arch": "arm64", "feature": "sve", "frame": 0, "file": "b.s"}`), ovrGoodBody, "unsupported feature", true},
		{"arch", base("dot", `["i32","i64","i64"]`, `"f32"`, `{"arch": "riscv64", "feature": "neon", "frame": 0, "file": "b.s"}`), ovrGoodBody, "unsupported arch", true},
		{"frame", base("dot", `["i32","i64","i64"]`, `"f32"`, `{"arch": "arm64", "feature": "neon", "frame": 12, "file": "b.s"}`), ovrGoodBody, "multiple of 8", true},
		{"duplicate body", base("dot", `["i32","i64","i64"]`, `"f32"`, neon+","+neon), ovrGoodBody, "listed twice", true},
		{"TEXT in body", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), "TEXT ·x(SB), $0-0\n\tRET\n", "TEXT directive", true},
		{"CALL in body", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), "\tCALL ·runtime·foo(SB)\n\tRET\n", "leaf", true},
		{"foreign symbol", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), "\tMOVD ·gcasmCPUDotProd(SB), R1\n\tRET\n", "only reference its own", true},
		{"reserved label", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), "ovr_x:\n\tRET\n", "reserved ovr_ prefix", true},
		{"data symbol", base("dot", `["i32","i64","i64"]`, `"f32"`, neon), "DATA ·tab+0(SB)/4, $1\nGLOBL ·tab(SB), RODATA, $4\n\tRET\n", "ovr_-prefixed", true},
		{"unknown field", `{"version": 1, "memory64": true, "extra": 1, "functions": []}`, ovrGoodBody, "unknown field", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeOvr(t, dir, c.manifest, map[string]string{"b.s": c.body})
			_, err := LoadAsmOverrides(p, ovrModule(c.memory64))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want containing %q", err, c.want)
			}
		})
	}
	// Own ovr_ data and labels are fine.
	dir := t.TempDir()
	p := writeOvr(t, dir, base("dot", `["i32","i64","i64"]`, `"f32"`, neon), map[string]string{"b.s": "DATA ·ovr_dot_c+0(SB)/4, $1\nGLOBL ·ovr_dot_c(SB), RODATA, $4\nloop:\n\tMOVD ·ovr_dot_c(SB), R1\n\tRET\n"})
	if _, err := LoadAsmOverrides(p, ovrModule(true)); err != nil {
		t.Fatal(err)
	}
}

func TestAsmOverrideTextAndStub(t *testing.T) {
	offs := &ModuleOffsets{M: 8, MemSize: 0}
	a := asmOverrideText("arm64", "Fn7ovrdotprod", "wasm_trap_simd_oob", offs, AsmOverrideBody{Arch: "arm64", Feature: "dotprod", Frame: 16, File: "x/dot.s", Asm: ovrGoodBody}, "40")
	for _, want := range []string{"TEXT ·Fn7ovrdotprod(SB), $16-40", "NO_LOCAL_POINTERS", "MOVD\t0(R0), R21", "MOVD\t(R21), R21", "MOVD\t8(R0), R20", "ovr_oob:", "CALL\t·wasm_trap_simd_oob(SB)"} {
		if !strings.Contains(a, want) {
			t.Errorf("arm64 text missing %q:\n%s", want, a)
		}
	}
	x := asmOverrideText("amd64", "Fn7ovravx2", "wasm_trap_simd_oob", offs, AsmOverrideBody{Arch: "amd64", Feature: "avx2", Frame: 0, File: "dot.s", Asm: "\tRET\n"}, "40")
	for _, want := range []string{"TEXT ·Fn7ovravx2(SB), $0-40", "MOVQ\t0(AX), R15", "MOVQ\t8(AX), R14", "ovr_oob:\n\tVZEROUPPER\n\tCALL"} {
		if !strings.Contains(x, want) {
			t.Errorf("amd64 text missing %q:\n%s", want, x)
		}
	}
	if s := asmOverrideText("amd64", "Fn7ovrsse4", "t", offs, AsmOverrideBody{Arch: "amd64", Feature: "sse4", Asm: "\tRET\n"}, "40"); strings.Contains(s, "VZEROUPPER") {
		t.Error("sse4 epilogue must not use VZEROUPPER")
	}
	stub := overrideDispatchStub("arm64", "Fn7", [][2]string{{"gcasmCPUI8MM", "Fn7ovri8mm"}, {"gcasmCPUDotProd", "Fn7ovrdotprod"}}, "Fn7generic", "40")
	want := "TEXT ·Fn7(SB), NOSPLIT, $0-40\n\tMOVBU ·gcasmCPUI8MM(SB), R27\n\tCBZ R27, 2(PC)\n\tJMP ·Fn7ovri8mm(SB)\n\tMOVBU ·gcasmCPUDotProd(SB), R27\n\tCBZ R27, 2(PC)\n\tJMP ·Fn7ovrdotprod(SB)\n\tJMP ·Fn7generic(SB)\n"
	if stub != want {
		t.Errorf("arm64 stub:\n%s\nwant:\n%s", stub, want)
	}
	xs := overrideDispatchStub("amd64", "Fn7", [][2]string{{"gcasmHasAVX2", "Fn7ovravx2"}}, "Fn7sse", "40")
	if !strings.Contains(xs, "CMPB ·gcasmHasAVX2(SB), $0\n\tJEQ 2(PC)\n\tJMP ·Fn7ovravx2(SB)\n\tJMP ·Fn7sse(SB)") {
		t.Errorf("amd64 stub:\n%s", xs)
	}
}
