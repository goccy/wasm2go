//go:build !linux

package codegen

import "syscall"

// System V IPC where the runtime does not reach the host's (see "System V
// IPC" in wasip1_native.go): every call fails with ENOSYS.

func hostIPCGet(kind, key int32, arg uint64, flags int32) (int32, error) {
	return -1, syscall.ENOSYS
}

func hostIPCCtl(kind, id, num, cmd int32, arg int64, buf func(n uint64) []byte) (int64, error) {
	return -1, syscall.ENOSYS
}

func hostIPCSemop(id int32, ops []byte, nops uint64) error { return syscall.ENOSYS }

func hostIPCMsgsnd(id int32, msg []byte, flags int32) error { return syscall.ENOSYS }

func hostIPCMsgrcv(id int32, msg []byte, typ int64, flags int32) (int64, error) {
	return -1, syscall.ENOSYS
}

func hostIPCShmCopy(id int32, buf []byte, pos uint64, write bool) error { return syscall.ENOSYS }
