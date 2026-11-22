//go:build linux && !386

package codegen

import "syscall"

// The numbers of recvmsg(2), sendmsg(2), connect(2) and getsockopt(2).
const (
	hostSysRecvmsg    = syscall.SYS_RECVMSG
	hostSysSendmsg    = syscall.SYS_SENDMSG
	hostSysConnect    = syscall.SYS_CONNECT
	hostSysGetsockopt = syscall.SYS_GETSOCKOPT
)
