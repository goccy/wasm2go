//go:build linux && !386 && !arm && !mips && !mipsle && !mips64 && !mips64le && !ppc64 && !ppc64le && !s390x

package codegen

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

// The System V IPC of HostIPC on Linux, on the architectures whose
// structures are the guest's: those of asm-generic on a 64-bit
// architecture, and x86-64, whose semid64_ds has a word after each time.
// The constraint names the other architectures: the gcasm capture and
// bundle drop a file whose constraint names amd64 or arm64.

// ipcStructSize is the size of the kernel's structure of the kind (struct
// msqid64_ds, semid64_ds, shmid64_ds), the guest's.
func ipcStructSize(kind IPCKind) int {
	switch kind {
	case IPCMessageQueue:
		return 120
	case IPCSemaphoreSet:
		return 88
	}
	return 112
}

// Where the guest's semid64_ds has the number of semaphores of the set
// (sem_nsems), and the size of x86-64's semid64_ds and where it has
// sem_nsems.
const (
	ipcSemNsems      = 64
	ipcSemSizeAMD64  = 104
	ipcSemNsemsAMD64 = 80
)

// ipcCall makes the system call call makes and returns its result. A call
// the host process is interrupted in (EINTR) is made again, as package os
// does (ignoringEINTR): SA_RESTART restarts none of msgsnd, msgrcv and
// semop (signal(7)).
func ipcCall(call func() (r, r2 uintptr, errno syscall.Errno)) (uintptr, error) {
	for {
		r, _, errno := call()
		switch errno {
		case 0:
			return r, nil
		case syscall.EINTR:
			continue
		}
		return 0, errno
	}
}

func (hostIPC) Get(kind IPCKind, key int32, arg uint64, flags int32) (int32, error) {
	r, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		switch kind {
		case IPCMessageQueue:
			return syscall.Syscall(syscall.SYS_MSGGET, uintptr(key), uintptr(flags), 0)
		case IPCSemaphoreSet:
			return syscall.Syscall(syscall.SYS_SEMGET, uintptr(key), uintptr(arg), uintptr(flags))
		case IPCSharedMemory:
			return syscall.Syscall(syscall.SYS_SHMGET, uintptr(key), uintptr(arg), uintptr(flags))
		}
		return 0, 0, syscall.EINVAL
	})
	if err != nil {
		return -1, err
	}
	return int32(r), nil
}

// ipcCtl makes the control call of the kind with the command and its
// argument p (an address, or nil), or value for a semctl whose argument is
// a value.
func ipcCtl(kind IPCKind, id, num, cmd int32, p unsafe.Pointer, value uintptr) (int64, error) {
	r, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		switch kind {
		case IPCMessageQueue:
			return syscall.Syscall(syscall.SYS_MSGCTL, uintptr(id), uintptr(cmd), uintptr(p))
		case IPCSemaphoreSet:
			if p == nil {
				return syscall.Syscall6(syscall.SYS_SEMCTL, uintptr(id), uintptr(num), uintptr(cmd), value, 0, 0)
			}
			return syscall.Syscall6(syscall.SYS_SEMCTL, uintptr(id), uintptr(num), uintptr(cmd), uintptr(p), 0, 0)
		case IPCSharedMemory:
			return syscall.Syscall(syscall.SYS_SHMCTL, uintptr(id), uintptr(cmd), uintptr(p))
		}
		return 0, 0, syscall.EINVAL
	})
	if err != nil {
		return -1, err
	}
	return int64(int32(r)), nil
}

// ipcStructOf returns the first n bytes of buf for a structure of the
// kernel's, of the kind; EFAULT when buf is shorter.
func ipcStructOf(buf []byte, n int) ([]byte, error) {
	if len(buf) < n {
		return nil, syscall.EFAULT
	}
	return buf[:n], nil
}

// ipcStat reads the structure of the object, in the guest's layout.
func ipcStat(kind IPCKind, id int32) ([]byte, error) {
	size := ipcStructSize(kind)
	if kind == IPCSemaphoreSet && runtime.GOARCH == "amd64" {
		size = ipcSemSizeAMD64
	}
	st := make([]byte, size)
	if _, err := ipcCtl(kind, id, 0, ipcCmdStat, unsafe.Pointer(&st[0]), 0); err != nil {
		return nil, err
	}
	if kind == IPCSemaphoreSet && runtime.GOARCH == "amd64" {
		// otime, a word, ctime, a word, nsems: the guest's has no words
		guest := make([]byte, ipcStructSize(kind))
		copy(guest, st[:56])
		copy(guest[56:64], st[64:72])
		copy(guest[ipcSemNsems:], st[ipcSemNsemsAMD64:ipcSemNsemsAMD64+8])
		st = guest
	}
	return st, nil
}

func (hostIPC) Control(kind IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error) {
	switch {
	case cmd == ipcCmdStat:
		guest, err := ipcStructOf(buf, ipcStructSize(kind))
		if err != nil {
			return -1, err
		}
		st, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		copy(guest, st)
		return 0, nil
	case cmd == ipcCmdSet:
		guest, err := ipcStructOf(buf, ipcStructSize(kind))
		if err != nil {
			return -1, err
		}
		st := guest
		if kind == IPCSemaphoreSet && runtime.GOARCH == "amd64" {
			st = make([]byte, ipcSemSizeAMD64)
			copy(st, guest[:56])
			copy(st[64:72], guest[56:64])
			copy(st[ipcSemNsemsAMD64:], guest[ipcSemNsems:ipcSemNsems+8])
		}
		return ipcCtl(kind, id, num, cmd, unsafe.Pointer(&st[0]), 0)
	case kind == IPCSemaphoreSet && (cmd == ipcCmdGetAll || cmd == ipcCmdSetAll):
		// the values of the set's semaphores, an unsigned short each, as
		// many as the set has
		st, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		nsems := binary.LittleEndian.Uint64(st[ipcSemNsems:])
		if uint64(len(buf)) < 2*nsems {
			return -1, syscall.EFAULT
		}
		return ipcCtl(kind, id, num, cmd, unsafe.Pointer(unsafe.SliceData(buf)), 0)
	case kind == IPCSemaphoreSet && cmd == ipcCmdSetVal:
		return ipcCtl(kind, id, num, cmd, nil, uintptr(int32(arg)))
	case cmd == ipcCmdRmid,
		kind == IPCSemaphoreSet && (cmd == ipcCmdGetPid || cmd == ipcCmdGetVal || cmd == ipcCmdGetNcnt || cmd == ipcCmdGetZcnt),
		kind == IPCSharedMemory && (cmd == ipcCmdShmLock || cmd == ipcCmdShmUnlock):
		return ipcCtl(kind, id, num, cmd, nil, 0)
	}
	// the commands that read or write a structure the guest has no layout
	// of (IPC_INFO, SEM_INFO, MSG_STAT, ...)
	return -1, syscall.EINVAL
}

func (hostIPC) Semop(id int32, ops []byte) error {
	_, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_SEMOP, uintptr(id), uintptr(unsafe.Pointer(unsafe.SliceData(ops))), uintptr(len(ops)/6))
	})
	return err
}

func (hostIPC) Msgsnd(id int32, msg []byte, flags int32) error {
	if len(msg) < 8 {
		return syscall.EFAULT
	}
	_, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(syscall.SYS_MSGSND, uintptr(id), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)-8), uintptr(flags), 0, 0)
	})
	return err
}

func (hostIPC) Msgrcv(id int32, msg []byte, typ int64, flags int32) (int, error) {
	if len(msg) < 8 {
		return -1, syscall.EFAULT
	}
	r, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(syscall.SYS_MSGRCV, uintptr(id), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)-8), uintptr(typ), uintptr(flags), 0)
	})
	if err != nil {
		return -1, err
	}
	return int(r), nil
}
