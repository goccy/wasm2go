//go:build linux && !amd64

package codegen

import "runtime"

// hostSyscallNumber returns the number the host has the guest's system call
// of the number under (HostSyscalls): the same on arm64, riscv64 and
// loong64, whose numbers are the Linux ABI's; none on any other
// architecture, of which a 32-bit one takes a 64-bit argument in two
// registers and has its calls of 64-bit times under other names, and a
// 64-bit one of numbers of its own has no table here.
func hostSyscallNumber(number int64) (uintptr, bool) {
	switch runtime.GOARCH {
	case "arm64", "riscv64", "loong64":
		return uintptr(number), true
	}
	return 0, false
}
