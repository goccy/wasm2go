//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

// System V IPC on a system that has it (see "System V IPC" in
// wasip1_native.go). The guest's numbers are Linux's and its structures
// Linux's 64-bit ones; the system's file of the platform (wasip1_native_
// linux.go, wasip1_native_darwin.go) says what the host's are: ipcCall
// makes a call, ipcHostLayout gives the host's structure of a kind, and
// ipcHostCommand the host's number of a command.

// The C library's calls of System V IPC, for ipcCall.
const (
	ipcOpMsgget = iota
	ipcOpSemget
	ipcOpShmget
	ipcOpMsgctl
	ipcOpSemctl
	ipcOpShmctl
	ipcOpSemop
	ipcOpMsgsnd
	ipcOpMsgrcv
	ipcOpShmat
	ipcOpShmdt
)

// The guest's commands of msgctl, semctl and shmctl.
const (
	ipcCmdRmid    = 0
	ipcCmdSet     = 1
	ipcCmdStat    = 2
	ipcCmdGetPid  = 11
	ipcCmdGetVal  = 12
	ipcCmdGetAll  = 13
	ipcCmdGetNcnt = 14
	ipcCmdGetZcnt = 15
	ipcCmdSetVal  = 16
	ipcCmdSetAll  = 17
)

// ipcField is a field of an IPC structure: where the guest has it and its
// size there, and where the host has it and its size there. A field of two
// sizes is an unsigned integer in both.
type ipcField struct {
	guest, guestSize, host, hostSize int
}

// The guest's structures (Linux's on a 64-bit architecture, as the sys/*.h
// of wasmify's shims declare them): their sizes, and the fields each kind
// has where the guest has them.
var ipcGuestSize = map[int32]int{ipcKindMsg: 120, ipcKindSem: 88, ipcKindShm: 112}

// The fields of the guest's structures that tell how big an object is:
// the number of semaphores of a set, the size of a segment.
const (
	ipcGuestSemNsems = 64
	ipcGuestShmSegsz = 48
)

// ipcHostToGuest fills the guest's structure of the kind from the host's.
func ipcHostToGuest(kind int32, host, guest []byte) {
	clear(guest)
	for _, f := range ipcHostLayout(kind).fields {
		ipcCopyField(guest[f.guest:f.guest+f.guestSize], host[f.host:f.host+f.hostSize])
	}
}

// ipcGuestToHost fills the host's structure of the kind from the guest's.
func ipcGuestToHost(kind int32, guest, host []byte) {
	clear(host)
	for _, f := range ipcHostLayout(kind).fields {
		ipcCopyField(host[f.host:f.host+f.hostSize], guest[f.guest:f.guest+f.guestSize])
	}
}

// ipcCopyField copies a field into one of the same size or, between sizes,
// as the unsigned little-endian integer it is.
func ipcCopyField(dst, src []byte) {
	if len(dst) == len(src) {
		copy(dst, src)
		return
	}
	var v uint64
	for i := len(src) - 1; i >= 0; i-- {
		v = v<<8 | uint64(src[i])
	}
	for i := range dst {
		dst[i] = byte(v)
		v >>= 8
	}
}

// ipcHostStruct is the host's structure of a kind: its size and its
// fields.
type ipcHostStruct struct {
	size   int
	fields []ipcField
}

// ipcGuestField reads the guest field at off (an unsigned integer of
// ipcHostLayout's size for it) of a host structure.
func ipcHostValue(kind int32, host []byte, guestOff int) uint64 {
	for _, f := range ipcHostLayout(kind).fields {
		if f.guest == guestOff && f.guestSize == 8 {
			v := make([]byte, 8)
			ipcCopyField(v, host[f.host:f.host+f.hostSize])
			return binary.LittleEndian.Uint64(v)
		}
	}
	return 0
}

// The control call of each kind.
var ipcCtlOp = map[int32]int{ipcKindMsg: ipcOpMsgctl, ipcKindSem: ipcOpSemctl, ipcKindShm: ipcOpShmctl}

// hostIPCGet makes msgget, semget or shmget.
func hostIPCGet(kind, key int32, arg uint64, flags int32) (int32, error) {
	var r uintptr
	var err error
	switch kind {
	case ipcKindMsg:
		r, err = ipcCall(ipcOpMsgget, uintptr(key), uintptr(flags))
	case ipcKindSem:
		r, err = ipcCall(ipcOpSemget, uintptr(key), uintptr(arg), uintptr(flags))
	case ipcKindShm:
		r, err = ipcCall(ipcOpShmget, uintptr(key), uintptr(arg), uintptr(flags))
	default:
		return -1, syscall.EINVAL
	}
	if err != nil {
		return -1, err
	}
	return int32(r), nil
}

// ipcCtl makes the control call of the kind with the host's command and
// argument (a word: a value, or an address).
func ipcCtl(kind, id, num, hostCmd int32, arg uintptr) (int64, error) {
	var r uintptr
	var err error
	if kind == ipcKindSem {
		r, err = ipcCall(ipcOpSemctl, uintptr(id), uintptr(num), uintptr(hostCmd), arg)
	} else {
		r, err = ipcCall(ipcCtlOp[kind], uintptr(id), uintptr(hostCmd), arg)
	}
	if err != nil {
		return -1, err
	}
	return int64(int32(r)), nil
}

// ipcStat reads the host's structure of the object.
func ipcStat(kind, id int32) ([]byte, error) {
	host := make([]byte, ipcHostLayout(kind).size)
	_, err := ipcCtl(kind, id, 0, ipcHostCommand(ipcCmdStat), uintptr(unsafe.Pointer(&host[0])))
	runtime.KeepAlive(host)
	return host, err
}

// hostIPCCtl makes msgctl, semctl or shmctl with the guest's command. buf
// gives the n bytes of the guest's buffer, or nil when they are not all in
// its memory.
func hostIPCCtl(kind, id, num, cmd int32, arg int64, buf func(n uint64) []byte) (int64, error) {
	if _, ok := ipcCtlOp[kind]; !ok {
		return -1, syscall.EINVAL
	}
	hostCmd := ipcHostCommand(cmd)
	switch {
	case cmd == ipcCmdStat:
		guest := buf(uint64(ipcGuestSize[kind]))
		if guest == nil {
			return -1, syscall.EFAULT
		}
		host, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		ipcHostToGuest(kind, host, guest)
		return 0, nil
	case cmd == ipcCmdSet:
		guest := buf(uint64(ipcGuestSize[kind]))
		if guest == nil {
			return -1, syscall.EFAULT
		}
		host := make([]byte, ipcHostLayout(kind).size)
		ipcGuestToHost(kind, guest, host)
		r, err := ipcCtl(kind, id, num, hostCmd, uintptr(unsafe.Pointer(&host[0])))
		runtime.KeepAlive(host)
		return r, err
	case kind == ipcKindSem && (cmd == ipcCmdGetAll || cmd == ipcCmdSetAll):
		// the values of the set's semaphores, an unsigned short each, as
		// many as the set has
		host, err := ipcStat(kind, id)
		if err != nil {
			return -1, err
		}
		nsems := ipcHostValue(kind, host, ipcGuestSemNsems)
		values := buf(2 * nsems)
		if values == nil {
			return -1, syscall.EFAULT
		}
		if nsems == 0 {
			return ipcCtl(kind, id, num, hostCmd, 0)
		}
		r, err := ipcCtl(kind, id, num, hostCmd, uintptr(unsafe.Pointer(&values[0])))
		runtime.KeepAlive(values)
		return r, err
	case kind == ipcKindSem && cmd == ipcCmdSetVal:
		return ipcCtl(kind, id, num, hostCmd, uintptr(int32(arg)))
	case cmd == ipcCmdRmid,
		kind == ipcKindSem && (cmd == ipcCmdGetPid || cmd == ipcCmdGetVal || cmd == ipcCmdGetNcnt || cmd == ipcCmdGetZcnt):
		return ipcCtl(kind, id, num, hostCmd, 0)
	}
	// the commands that read or write a structure the guest has no layout
	// of (IPC_INFO, SEM_INFO, MSG_STAT, ...)
	return -1, syscall.EINVAL
}

// ipcBlockingCall makes call, a call that can wait in the kernel (semop,
// msgsnd and msgrcv without IPC_NOWAIT), so that a signal posted to the
// guest meanwhile ends it with EINTR, as a signal ends it in a process
// (interruptibleHostCall). A call that was done before the signal came is
// kept, and the signal is noticed by the next call that waits.
func (w *WasiStubs) ipcBlockingCall(call func() error) error {
	var err error
	called, interrupted := w.interruptibleHostCall(func() { err = call() })
	if !called {
		return syscall.EINTR
	}
	if interrupted && err == nil {
		w.keepInterrupt()
	}
	return err
}

// hostIPCSemop makes semop with the guest's nops operations (struct sembuf
// is alike on every host).
func hostIPCSemop(id int32, ops []byte, nops uint64) error {
	var p uintptr
	if len(ops) > 0 {
		p = uintptr(unsafe.Pointer(&ops[0]))
	}
	_, err := ipcCall(ipcOpSemop, uintptr(id), p, uintptr(nops))
	runtime.KeepAlive(ops)
	return err
}

// hostIPCMsgsnd makes msgsnd with the guest's message (its type, a long,
// then its bytes, alike on every 64-bit host).
func hostIPCMsgsnd(id int32, msg []byte, flags int32) error {
	_, err := ipcCall(ipcOpMsgsnd, uintptr(id), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)-8), uintptr(flags))
	runtime.KeepAlive(msg)
	return err
}

// hostIPCMsgrcv makes msgrcv into the guest's buffer (the type, then room
// for the bytes) and returns the number of the message's bytes.
func hostIPCMsgrcv(id int32, msg []byte, typ int64, flags int32) (int64, error) {
	r, err := ipcCall(ipcOpMsgrcv, uintptr(id), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)-8), uintptr(typ), uintptr(flags))
	runtime.KeepAlive(msg)
	if err != nil {
		return -1, err
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
	segsz := ipcHostValue(ipcKindShm, host, ipcGuestShmSegsz)
	if pos > segsz || uint64(len(buf)) > segsz-pos {
		return syscall.EFAULT
	}
	flags := uintptr(ipcHostShmRdonly)
	if write {
		flags = 0
	}
	addr, err := ipcCall(ipcOpShmat, uintptr(id), 0, flags)
	if err != nil {
		return err
	}
	// the segment is memory of the process's, outside Go's heap: its bytes
	// are seen through the address the host gave (the bits of the word read
	// as a pointer)
	segment := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), segsz)
	if write {
		copy(segment[pos:], buf)
	} else {
		copy(buf, segment[pos:])
	}
	_, err = ipcCall(ipcOpShmdt, addr)
	return err
}
