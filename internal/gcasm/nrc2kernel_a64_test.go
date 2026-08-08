package gcasm

import (
	"strings"
	"testing"
)

func TestA64Nrc2KernelShape(t *testing.T) {
	body := a64Nrc2Kernel("Fn9nrc2fast", "gcasmFwdH_base_Wasm_trap_simd_oob", &ModuleOffsets{M: 32, MemSize: 1152})
	for _, want := range []string{
		"TEXT ·Fn9nrc2fast(SB), $16-36",
		"MOVD\t1152(R0), R21",
		"MOVD\t32(R0), R20",
		// The 2x2 tile: four SMMLA into one accumulator.
		"smmla v4.4s, v24.16b, v0.16b",
		"smmla v4.4s, v27.16b, v3.16b",
		// f16 scale conversion and the vector FMLA accumulate.
		"fcvt s5, h5",
		"fmla v30.4s, v4.4s, v17.4s",
		// Both result columns store through the bs stride.
		"MOVW\tR13, (R11)",
		"MOVW\tR13, (R15)",
		"CALL ·gcasmFwdH_base_Wasm_trap_simd_oob(SB)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("kernel missing %q", want)
		}
	}
	// Exactly four SMMLA and one FMLA per block.
	if got := strings.Count(body, "smmla v4.4s"); got != 4 {
		t.Errorf("smmla count = %d, want 4", got)
	}
	if got := strings.Count(body, "fmla v30.4s"); got != 1 {
		t.Errorf("fmla count = %d, want 1", got)
	}
	// The bounds prologue guards all six spans (x0, x1, y0, y1, s
	// column 0, s column 1).
	if got := strings.Count(body, "BLO\tnrc2oob"); got != 6 {
		t.Errorf("bounds checks = %d, want 6", got)
	}
}
