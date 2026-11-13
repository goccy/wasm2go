//go:build linux && (mips || mipsle || mips64 || mips64le)

package codegen

// Numbers of the operating system for a guest that shows its program the
// host's (see "the numbers of the operating system" in
// wasip1_native_posix.go). A family is a kind of number; its id is the one
// the guest asks by, and a name is the one the number has in C. A name is
// added to its family here, for every system that has it, and to the table
// of the guest that is to translate it.

// hostNumbersFromHeaders is empty on the mips architectures, whose C headers
// number these differently from the other architectures of linux: a family
// that has no other source keeps the guest's numbers there.
var hostNumbersFromHeaders = map[int32][]hostNumber{}
