//go:build arm64 && darwin

package helpers

import "syscall"

// CPUDotProd reports FEAT_DotProd (the SDOT/UDOT instructions).
// Feature-gated splice bodies dispatch on it at runtime; the
// portable twin body runs when it is false.
var CPUDotProd = detectDotProd()

func detectDotProd() bool {
	v, err := syscall.SysctlUint32("hw.optional.arm.FEAT_DotProd")
	return err == nil && v != 0
}
