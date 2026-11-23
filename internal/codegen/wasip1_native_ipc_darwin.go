//go:build darwin

package codegen

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

// The System V IPC of HostIPC on darwin. Its structures are the C
// library's (struct ipc_perm, semid_ds, shmid_ds and msqid_ds of the UNIX
// 03 interfaces, packed to 4 bytes), which the runtime lays out as the
// guest's; semctl's commands that read and set the values have numbers of
// their own. darwin has no SHM_LOCK and SHM_UNLOCK, and no MSG_EXCEPT and
// MSG_COPY. Its shmat attaches a segment only where nothing is mapped: the
// guest's memory would be unmapped meanwhile, where another thread's
// mapping may land, so no segment is attached over it.

// ipcField is a field of a structure of System V IPC: where the guest has
// it and its size there, and where the host has it and its size there. A
// field of two sizes is an unsigned integer in both.
type ipcField struct {
	guest, guestSize, host, hostSize int
}

// The fields of struct ipc_perm: key, uid, gid, cuid, cgid, mode and seq.
var ipcDarwinPerm = []ipcField{{0, 4, 20, 4}, {4, 4, 0, 4}, {8, 4, 4, 4}, {12, 4, 8, 4}, {16, 4, 12, 4}, {20, 4, 16, 2}, {24, 2, 18, 2}}

// ipcDarwinStruct returns the size of the C library's structure of the
// kind and its fields. Those of a message queue are stime, rtime, ctime,
// cbytes, qnum, qbytes, lspid and lrpid; of a semaphore set otime, ctime
// and nsems; of a segment segsz, atime, dtime, ctime, cpid, lpid and
// nattch.
func ipcDarwinStruct(kind IPCKind) (int, []ipcField) {
	switch kind {
	case IPCMessageQueue:
		return 116, append(ipcDarwinPerm[:len(ipcDarwinPerm):len(ipcDarwinPerm)], ipcField{48, 8, 64, 8}, ipcField{56, 8, 76, 8},
			ipcField{64, 8, 88, 8}, ipcField{72, 8, 32, 8}, ipcField{80, 8, 40, 8}, ipcField{88, 8, 48, 8}, ipcField{96, 4, 56, 4},
			ipcField{100, 4, 60, 4})
	case IPCSemaphoreSet:
		return 72, append(ipcDarwinPerm[:len(ipcDarwinPerm):len(ipcDarwinPerm)], ipcField{48, 8, 32, 8}, ipcField{56, 8, 44, 8},
			ipcField{64, 8, 28, 2})
	}
	return 76, append(ipcDarwinPerm[:len(ipcDarwinPerm):len(ipcDarwinPerm)], ipcField{48, 8, 24, 8}, ipcField{56, 8, 44, 8},
		ipcField{64, 8, 52, 8}, ipcField{72, 8, 60, 8}, ipcField{80, 4, 36, 4}, ipcField{84, 4, 32, 4}, ipcField{88, 8, 40, 2})
}

// ipcCopyFields fills dst, a structure of one layout, from src, the same
// structure of the other: the guest's from the host's when toGuest is set.
func ipcCopyFields(dst, src []byte, fields []ipcField, toGuest bool) {
	for _, f := range fields {
		dOff, dSize, sOff, sSize := f.host, f.hostSize, f.guest, f.guestSize
		if toGuest {
			dOff, dSize, sOff, sSize = f.guest, f.guestSize, f.host, f.hostSize
		}
		d, s := dst[dOff:dOff+dSize], src[sOff:sOff+sSize]
		var v uint64
		switch len(s) {
		case 2:
			v = uint64(binary.LittleEndian.Uint16(s))
		case 4:
			v = uint64(binary.LittleEndian.Uint32(s))
		default:
			v = binary.LittleEndian.Uint64(s)
		}
		switch len(d) {
		case 2:
			binary.LittleEndian.PutUint16(d, uint16(v))
		case 4:
			binary.LittleEndian.PutUint32(d, uint32(v))
		default:
			binary.LittleEndian.PutUint64(d, v)
		}
	}
}

// ipcStat reads the structure of the object, in the guest's layout.
func ipcStat(kind IPCKind, id int32) ([]byte, error) {
	size, fields := ipcDarwinStruct(kind)
	st := make([]byte, size)
	if _, err := ipcCtl(kind, id, 0, ipcCmdStat, unsafe.Pointer(&st[0]), 0); err != nil {
		return nil, err
	}
	guest := make([]byte, ipcStructSize(kind))
	ipcCopyFields(guest, st, fields, true)
	return guest, nil
}

// ipcHostStruct returns the C library's structure of the kind for the
// IPC_SET of guest, the guest's.
func ipcHostStruct(kind IPCKind, guest []byte) []byte {
	size, fields := ipcDarwinStruct(kind)
	st := make([]byte, size)
	ipcCopyFields(st, guest, fields, false)
	return st
}

// ipcHostCommand returns darwin's number of the guest's command cmd, and
// false for one it has not (shmctl's SHM_LOCK and SHM_UNLOCK).
func ipcHostCommand(kind IPCKind, cmd int32) (int32, bool) {
	switch {
	case cmd == ipcCmdRmid || cmd == ipcCmdSet || cmd == ipcCmdStat:
		return cmd, true
	case kind != IPCSemaphoreSet:
		return 0, false
	}
	switch cmd {
	case ipcCmdGetNcnt:
		return 3, true
	case ipcCmdGetPid:
		return 4, true
	case ipcCmdGetVal:
		return 5, true
	case ipcCmdGetAll:
		return 6, true
	case ipcCmdGetZcnt:
		return 7, true
	case ipcCmdSetVal:
		return 8, true
	case ipcCmdSetAll:
		return 9, true
	}
	return 0, false
}

// ipcMsgrcvUnsupported are the guest's flags of msgrcv darwin has not:
// MSG_EXCEPT and MSG_COPY, which its msgrcv would not refuse.
const ipcMsgrcvUnsupported = 0o20000 | 0o40000

// ShmAttach attaches no segment over the guest's memory here (see above).
func (hostIPC) ShmAttach(id int32, at []byte, flags int32) error { return errors.ErrUnsupported }

// ShmDetach has no segment to detach (ShmAttach).
func (hostIPC) ShmDetach(at []byte) error { return errors.ErrUnsupported }
