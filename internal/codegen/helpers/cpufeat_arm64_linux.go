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

func detectDotProd() bool {
	// AT_HWCAP (16), HWCAP_ASIMDDP (bit 20), from the auxiliary
	// vector: unswappable 8-byte key/value pairs.
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return false
	}
	for i := 0; i+16 <= len(auxv); i += 16 {
		if binary.LittleEndian.Uint64(auxv[i:]) == 16 {
			return binary.LittleEndian.Uint64(auxv[i+8:])&(1<<20) != 0
		}
	}
	return false
}
