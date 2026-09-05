//go:build arm64 && !darwin && !linux

package helpers

// CPUDotProd / CPUI8MM / CPUFHM: no detection story on this OS — run
// the portable bodies.
var CPUDotProd = false
var CPUI8MM = false
var CPUFHM = false
