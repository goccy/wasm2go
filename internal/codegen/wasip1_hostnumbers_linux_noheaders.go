//go:build linux && (mips || mipsle || mips64 || mips64le)

package codegen

// Numbers of the operating system (see "the numbers of the operating
// system" in wasip1_native_posix.go). A family is a kind of number, and a
// name is the one the number has in C.

// hostNumbersFromHeaders is empty on the mips architectures, whose C headers
// number these differently from the other architectures of linux.
var hostNumbersFromHeaders = map[int32][]hostNumber{}
