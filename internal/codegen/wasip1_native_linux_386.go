//go:build linux && 386

package codegen

// The numbers of recvmsg(2) and sendmsg(2), which Linux has on 386 since
// 4.3 and package syscall reaches only through socketcall(2) there.
const (
	hostSysRecvmsg = 372
	hostSysSendmsg = 370
)
