//go:build arm64 && linux

package helpers

import (
	"encoding/binary"
	"os"
)

// CPUDotProd reports FEAT_DotProd (the SDOT/UDOT instructions).
// Feature-gated splice bodies dispatch on it at runtime; the
// portable twin body runs when it is false.
var CPUDotProd = detectDotProd()

// CPUI8MM reports FEAT_I8MM (the SMMLA/UMMLA int8 matrix
// instructions). The tile kernels branch on it at entry and fall
// back to their dotprod bodies when it is false — FEAT_DotProd
// without FEAT_I8MM is common (Neoverse N1, Cortex-A76..X1, Apple
// M1), so the two are detected separately.
var CPUI8MM = detectI8MM()

func detectDotProd() bool {
	// AT_HWCAP (16), HWCAP_ASIMDDP (bit 20).
	return auxvBit(16, 20)
}

func detectI8MM() bool {
	// AT_HWCAP2 (26), HWCAP2_I8MM (bit 13).
	return auxvBit(26, 13)
}

// auxvBit reports bit `bit` of the auxiliary-vector entry `key`:
// unswappable 8-byte key/value pairs.
func auxvBit(key uint64, bit uint) bool {
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return false
	}
	for i := 0; i+16 <= len(auxv); i += 16 {
		if binary.LittleEndian.Uint64(auxv[i:]) == key {
			return binary.LittleEndian.Uint64(auxv[i+8:])&(1<<bit) != 0
		}
	}
	return false
}
