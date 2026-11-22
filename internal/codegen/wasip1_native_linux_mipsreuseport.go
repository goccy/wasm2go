//go:build linux && (mips || mipsle || mips64 || mips64le)

package codegen

// hostSOReusePort is the name of SO_REUSEPORT on MIPS.
const hostSOReusePort = 0x200
