//go:build linux

package codegen

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

// System V IPC on Linux (see "System V IPC" in wasip1_native.go). The
// guest's numbers are Linux's, so commands and flags go to the kernel as
// they are. The guest's structures are laid out as the kernel's are on a
// 64-bit architecture (asm-generic's ipc64_perm, msqid64_ds, semid64_ds and
// shmid64_ds); x86-64 has a semid64_ds of its own, with a word after each
// time, which ipcLayout says.

// The guest's commands of msgctl, semctl and shmctl that take a buffer.
const (
	ipcCmdSet    = 1
	ipcCmdStat   = 2
	ipcCmdGetAll = 13
	ipcCmdSetVal = 16
	ipcCmdSetAll = 17
)

// ipcField is a field of an IPC structure: where the guest has it, where
// the kernel has it, and its size in bytes.
type ipcField struct {
	guest, host, size int
}

// ipcLayout returns the size of the kernel's structure of the kind and its
// fields, and the size of the guest's. The permissions (struct ipc_perm,
// the first 48 bytes) are laid out alike in both: key, uid, gid, cuid,
// cgid, mode, the sequence number and two unused words.
func ipcLayout(kind int32) (hostSize, guestSize int, fields []ipcField) {
	perm := ipcField{0, 0, 48}
	switch kind {
	case ipcKindMsg:
		// stime rtime ctime cbytes qnum qbytes, lspid lrpid
		return 120, 120, []ipcField{perm, {48, 48, 48}, {96, 96, 8}}
	case ipcKindShm:
		// segsz atime dtime ctime, cpid lpid, nattch
		return 112, 112, []ipcField{perm, {48, 48, 32}, {80, 80, 8}, {88, 88, 8}}
	case ipcKindSem:
		if runtime.GOARCH == "amd64" {
			// otime, unused, ctime, unused, nsems
			return 104, 88, []ipcField{perm, {48, 48, 8}, {56, 64, 8}, {64, 80, 8}}
		}
		// otime ctime nsems
		return 88, 88, []ipcField{perm, {48, 48, 24}}
	}
	return 0, 0, nil
}

// The system calls of each kind.
var ipcCtlCall = map[int32]uintptr{ipcKindMsg: syscall.SYS_MSGCTL, ipcKindSem: syscall.SYS_SEMCTL, ipcKindShm: syscall.SYS_SHMCTL}

// hostIPCGet makes msgget, semget or shmget.
func hostIPCGet(kind, key int32, arg uint64, flags int32) (int32, error) {
	var r uintptr
	var errno syscall.Errno
	switch kind {
	case ipcKindMsg:
		r, _, errno = syscall.Syscall(syscall.SYS_MSGGET, uintptr(key), uintptr(flags), 0)
	case ipcKindSem:
		r, _, errno = syscall.Syscall(syscall.SYS_SEMGET, uintptr(key), uintptr(arg), uintptr(flags))
	case ipcKindShm:
		r, _, errno = syscall.Syscall(syscall.SYS_SHMGET, uintptr(key), uintptr(arg), uintptr(flags))
	default:
		return -1, syscall.EINVAL
	}
	if errno != 0 {
		return -1, errno
	}
	return int32(r), nil
}

// ipcCtl makes the control call of the kind with the kernel's argument arg
// (a word: a value, or an address).
func ipcCtl(kind, id, num, cmd int32, arg uintptr) (int64, error) {
	var r uintptr
	var errno syscall.Errno
	if kind == ipcKindSem {
		r, _, errno = syscall.Syscall6(syscall.SYS_SEMCTL, uintptr(id), uintptr(num), uintptr(cmd), arg, 0, 0)
	} else {
		r, _, errno = syscall.Syscall(ipcCtlCall[kind], uintptr(id), uintptr(cmd), arg)
	}
	if errno != 0 {
		return -1, errno
	}
	return int64(int32(r)), nil
}

// ipcStat reads the kernel's structure of the object into a buffer of its
// size.
func ipcStat(kind, id int32) ([]byte, error) {
	hostSize, _, _ := ipcLayout(kind)
	host := make([]byte, hostSize)
	_, err := ipcCtl(kind, id, 0, ipcCmdStat, uintptr(unsafe.Pointer(&host[0])))
	runtime.KeepAlive(host)
	return host, err
}

// hostIPCCtl makes msgctl, semctl or shmctl. buf gives the n bytes of the
// guest's buffer, or nil when they are not all in its memory.
func hostIPCCtl(kind, id, num, cmd int32, arg int64, buf func(n uint64) []byte) (int64, error) {
	if _, ok := ipcCtlCall[kind]; !ok {
		return -1, syscall.EINVAL
	}
	hostSize, guestSize, fields := ipcLayout(kind)
	switch {
	case cmd == ipcCmdStat:
		guest := buf(uint64(guestSize))
		if guest == nil {
			return -1, syscall.EFAULT
		}
		host, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		clear(guest)
		for _, f := range fields {
			copy(guest[f.guest:f.guest+f.size], host[f.host:f.host+f.size])
		}
		return 0, nil
	case cmd == ipcCmdSet:
		guest := buf(uint64(guestSize))
		if guest == nil {
			return -1, syscall.EFAULT
		}
		host := make([]byte, hostSize)
		for _, f := range fields {
			copy(host[f.host:f.host+f.size], guest[f.guest:f.guest+f.size])
		}
		r, err := ipcCtl(kind, id, num, cmd, uintptr(unsafe.Pointer(&host[0])))
		runtime.KeepAlive(host)
		return r, err
	case kind == ipcKindSem && (cmd == ipcCmdGetAll || cmd == ipcCmdSetAll):
		// the values of the set's semaphores, an unsigned short each
		host, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		nsemsAt := 64
		if runtime.GOARCH == "amd64" {
			nsemsAt = 80
		}
		nsems := binary.LittleEndian.Uint64(host[nsemsAt:])
		values := buf(2 * nsems)
		if values == nil {
			return -1, syscall.EFAULT
		}
		if nsems == 0 {
			return ipcCtl(kind, id, num, cmd, 0)
		}
		r, err := ipcCtl(kind, id, num, cmd, uintptr(unsafe.Pointer(&values[0])))
		runtime.KeepAlive(values)
		return r, err
	case kind == ipcKindSem && cmd == ipcCmdSetVal:
		return ipcCtl(kind, id, num, cmd, uintptr(int32(arg)))
	}
	// the commands with no buffer (IPC_RMID, GETVAL, GETPID, GETNCNT,
	// GETZCNT); the others, which read or write a structure the guest has
	// no layout of (IPC_INFO, SEM_INFO, MSG_STAT, ...), are refused
	switch cmd {
	case 0, 11, 12, 14, 15:
		return ipcCtl(kind, id, num, cmd, 0)
	}
	return -1, syscall.EINVAL
}

// hostIPCSemop makes semop with the guest's nops operations.
func hostIPCSemop(id int32, ops []byte, nops uint64) error {
	var p uintptr
	if len(ops) > 0 {
		p = uintptr(unsafe.Pointer(&ops[0]))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_SEMOP, uintptr(id), p, uintptr(nops))
	runtime.KeepAlive(ops)
	if errno != 0 {
		return errno
	}
	return nil
}

// hostIPCMsgsnd makes msgsnd with the guest's message (its type, then its
// bytes).
func hostIPCMsgsnd(id int32, msg []byte, flags int32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_MSGSND, uintptr(id), uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)-8), uintptr(flags), 0, 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return errno
	}
	return nil
}

// hostIPCMsgrcv makes msgrcv into the guest's buffer (the type, then room
// for the bytes) and returns the number of the message's bytes.
func hostIPCMsgrcv(id int32, msg []byte, typ int64, flags int32) (int64, error) {
	r, _, errno := syscall.Syscall6(syscall.SYS_MSGRCV, uintptr(id), uintptr(unsafe.Pointer(&msg[0])),
		uintptr(len(msg)-8), uintptr(typ), uintptr(flags), 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return -1, errno
	}
	return int64(r), nil
}

// hostIPCShmCopy copies between the segment id, from its byte pos, and buf:
// into buf, or out of it when write is set. The segment is attached to the
// host process for the copy (read-only for a read) and detached after.
func hostIPCShmCopy(id int32, buf []byte, pos uint64, write bool) error {
	host, err := ipcStat(ipcKindShm, id)
	if err != nil {
		return err
	}
	segsz := binary.LittleEndian.Uint64(host[48:])
	if pos > segsz || uint64(len(buf)) > segsz-pos {
		return syscall.EFAULT
	}
	const shmRdonly = 010000
	flags := uintptr(shmRdonly)
	if write {
		flags = 0
	}
	addr, _, errno := syscall.Syscall(syscall.SYS_SHMAT, uintptr(id), 0, flags)
	if errno != 0 {
		return errno
	}
	// the segment is memory of the process's, outside Go's heap: its bytes
	// are seen through the address the kernel gave (the bits of the word
	// read as a pointer)
	segment := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), segsz)
	if write {
		copy(segment[pos:], buf)
	} else {
		copy(buf, segment[pos:])
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_SHMDT, addr, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
