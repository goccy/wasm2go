package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX64Nrc2KernelShape(t *testing.T) {
	body := x64Nrc2Kernel("Fn9nrc2fast", "gcasmFwdH_base_Wasm_trap_simd_oob", &ModuleOffsets{M: 32, MemSize: 1152}, true)
	for _, want := range []string{
		"TEXT ·Fn9nrc2fast(SB), $8-64",
		"MOVQ\t1152(AX), R15",
		"MOVQ\t32(AX), R14",
		// The four shared quant loads and the 2x2 tile collapse.
		"VMOVDQU\t(BX), Y0",
		"VPHADDD\tY2, Y1, Y1",
		"VCVTDQ2PS\tX1, X1",
		// f16 scale gather + F16C conversion + FMA accumulate.
		"VCVTPH2PS\tX2, X2",
		"VFMADD231PS\tX2, X1, X8",
		// Both result columns store through the bs stride.
		"VEXTRACTPS\t$0, X8, (R14)(R12*1)",
		"VEXTRACTPS\t$3, X8, 4(R14)(CX*1)",
		"CALL\t·gcasmFwdH_base_Wasm_trap_simd_oob(SB)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("kernel missing %q", want)
		}
	}
	if got := strings.Count(body, "VPMADDWD"); got != 8 {
		t.Errorf("VPMADDWD count = %d, want 8 (four dots, two halves each)", got)
	}
	if got := strings.Count(body, "VMOVDQU"); got != 8 {
		t.Errorf("quant loads = %d, want 8 (four per loop, AVX2 and VNNI)", got)
	}
	// The VNNI loop: entry branch on the mirror var, six VPDPBUSD per
	// block (two bias sums + four dots).
	if !strings.Contains(body, "CMPB\t·gcasmHasAVX512VNNI(SB), $0") {
		t.Error("kernel missing the VNNI entry branch")
	}
	if got := strings.Count(body, "VPDPBUSD"); got != 6 {
		t.Errorf("VPDPBUSD count = %d, want 6", got)
	}
	// Every exit clears the ymm upper state (Intel false-dep hazard).
	if got := strings.Count(body, "VZEROUPPER"); got != 2 {
		t.Errorf("VZEROUPPER count = %d, want 2 (done + trap paths)", got)
	}
	// The bounds prologue guards all six spans.
	if got := strings.Count(body, "JCS\tnrc2x64oob"); got != 6 {
		t.Errorf("bounds checks = %d, want 6", got)
	}
	// The narrow (wasm32) variant assembles the ILP32 argument layout.
	narrow := x64Nrc2Kernel("Fn9nrc2fast", "trap", &ModuleOffsets{M: 32, MemSize: 1152}, false)
	if !strings.Contains(narrow, "TEXT ·Fn9nrc2fast(SB), $8-36") || !strings.Contains(narrow, "MOVL\tl1+12(FP)") {
		t.Errorf("narrow variant lost the ILP32 layout:\n%s", narrow[:400])
	}
}

// TestX64Nrc2KernelAssembles feeds the emitted kernel through the real
// Go assembler for amd64 — the mnemonic/operand forms (VPHADDD,
// VCVTPH2PS, VFMADD231PS, VEXTRACTPS with indexed memory operands)
// must all be accepted.
func TestX64Nrc2KernelAssembles(t *testing.T) {
	dir := t.TempDir()
	body := x64Nrc2Kernel("Fn9nrc2fast", "trapstub", &ModuleOffsets{M: 32, MemSize: 1152}, true)
	asm := "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body + "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tRET\n"
	if err := os.WriteFile(filepath.Join(dir, "k_amd64.s"), []byte(asm), 0o644); err != nil {
		t.Fatal(err)
	}
	goSrc := "package main\n\nvar gcasmHasAVX512VNNI bool\n\nfunc Fn9nrc2fast(m *int64, l0 int32, l1, l2, l3, l4, l5, l6 int64)\nfunc trapstub()\nfunc main() { _ = gcasmHasAVX512VNNI; _ = Fn9nrc2fast; _ = trapstub }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module kcheck\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v2")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kernel does not assemble: %v\n%s", err, out)
	}
}
