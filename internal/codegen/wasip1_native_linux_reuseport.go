//go:build linux && !(mips || mipsle || mips64 || mips64le)

package codegen

// hostSOReusePort is the name of SO_REUSEPORT, which package syscall does
// not name on every architecture of this group.
const hostSOReusePort = 15
