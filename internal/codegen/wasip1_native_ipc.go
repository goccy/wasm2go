//go:build darwin || (linux && !386 && !arm && !mips && !mipsle && !mips64 && !mips64le && !ppc64 && !ppc64le && !s390x)

package codegen

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"
)

// The System V IPC of HostIPC where the runtime reaches the host's: the
// calls, which are made alike on Linux and darwin. The system's file
// (wasip1_native_ipc_linux.go, wasip1_native_ipc_darwin.go) has what is
// its own: its structure of a kind (ipcStat, ipcHostStruct), its number of
// a command (ipcHostCommand), and the flags of msgrcv it has not
// (ipcMsgrcvUnsupported). The constraint names the architectures of Linux
// there is no file for: the gcasm capture and bundle drop a file whose
// constraint names amd64 or arm64.

// shmget's SHM_HUGETLB, the guest's (Linux's).
const ipcShmHugetlb = 0o4000

// Where the guest's semid64_ds has the number of semaphores of the set
// (sem_nsems).
const ipcSemNsems = 64

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
	if kind == IPCSharedMemory && flags&ipcShmHugetlb != 0 {
		return -1, syscall.EINVAL
	}
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

// ipcCtl makes the control call of the kind with the command (the
// guest's, ipcHostCommand) and its argument p (an address, or nil), or
// value for a semctl whose argument is a value.
func ipcCtl(kind IPCKind, id, num, cmd int32, p unsafe.Pointer, value uintptr) (int64, error) {
	cmd, ok := ipcHostCommand(kind, cmd)
	if !ok {
		return -1, syscall.EINVAL
	}
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
		st := ipcHostStruct(kind, guest)
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
	if flags&ipcMsgrcvUnsupported != 0 {
		return -1, errors.ErrUnsupported
	}
	r, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(syscall.SYS_MSGRCV, uintptr(id), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)-8), uintptr(typ), uintptr(flags), 0)
	})
	if err != nil {
		return -1, err
	}
	return int(r), nil
}
