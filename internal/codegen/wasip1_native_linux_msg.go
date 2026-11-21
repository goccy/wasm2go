//go:build linux && !386

package codegen

import "syscall"

// The numbers of recvmsg(2) and sendmsg(2).
const (
	hostSysRecvmsg = syscall.SYS_RECVMSG
	hostSysSendmsg = syscall.SYS_SENDMSG
)
