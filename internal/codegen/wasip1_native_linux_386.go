//go:build linux && 386

package codegen

// The numbers of recvmsg(2), sendmsg(2) and connect(2), which Linux has on
// 386 since 4.3 and package syscall reaches only through socketcall(2)
// there.
const (
	hostSysRecvmsg = 372
	hostSysSendmsg = 370
	hostSysConnect = 362
)
