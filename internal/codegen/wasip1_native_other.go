//go:build !darwin && !linux

package codegen

import (
	"syscall"
)

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error; on this platform the errors are told apart
// by what package os makes of them.
func wasiErrno(e syscall.Errno) (int32, bool) { return 0, false }
