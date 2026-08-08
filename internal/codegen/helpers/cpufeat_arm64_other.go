//go:build arm64 && !darwin && !linux

package helpers

// CPUDotProd: no detection story on this OS — run the portable
// bodies.
var CPUDotProd = false
