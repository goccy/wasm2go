//go:build arm64 && darwin

package helpers

import "syscall"

// CPUDotProd reports FEAT_DotProd (the SDOT/UDOT instructions).
// Feature-gated splice bodies dispatch on it at runtime; the
// portable twin body runs when it is false.
var CPUDotProd = detectDotProd()

// CPUI8MM reports FEAT_I8MM (SMMLA/UMMLA); see the linux twin for
// why it is detected apart from CPUDotProd.
var CPUI8MM = detectI8MM()

func detectDotProd() bool {
	return sysctlFeature("hw.optional.arm.FEAT_DotProd")
}

func detectI8MM() bool {
	return sysctlFeature("hw.optional.arm.FEAT_I8MM")
}

func sysctlFeature(name string) bool {
	v, err := syscall.SysctlUint32(name)
	return err == nil && v != 0
}
