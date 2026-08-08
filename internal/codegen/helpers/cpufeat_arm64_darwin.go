//go:build arm64 && darwin

package helpers

import (
	"os"
	"syscall"
)

// CPUDotProd reports FEAT_DotProd (the SDOT/UDOT instructions).
// Feature-gated splice bodies dispatch on it at runtime; the
// portable twin body runs when it is false. WASM2GO_CPU_PORTABLE
// forces the portable bodies everywhere (testing aid).
var CPUDotProd = detectDotProd()

func detectDotProd() bool {
	if os.Getenv("WASM2GO_CPU_PORTABLE") != "" {
		return false
	}
	v, err := syscall.SysctlUint32("hw.optional.arm.FEAT_DotProd")
	return err == nil && v != 0
}
