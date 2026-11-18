//go:build linux && (arm64 || amd64)

package codegen

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The System V IPC imports reach the host's objects, in the guest's numbers
// and structures: a semaphore set (SETVAL, semop, GETVAL, GETALL,
// IPC_STAT), a message queue (msgsnd, msgrcv) and a shared memory segment
// (shm_copy both ways, IPC_STAT), each removed at the end; a guest that is
// not the host process gets ENOSYS.
func TestIPCImportsReachTheHostsObjects(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	const idAt, resultAt, bufAt = 4096, 4104, 8192
	const ipcCreat, ipcRmid, ipcStat = 01000, 0, 2
	get := func(kind, flags int32, arg int64) int32 {
		t.Helper()
		if rc := w.Ipc_get(m, kind, 0, arg, ipcCreat|0600|flags, idAt); rc != 0 {
			t.Fatalf("ipc_get kind %d: rc %d", kind, rc)
		}
		return int32(binary.LittleEndian.Uint32(m.memory[idAt:]))
	}
	ctl := func(kind, id, num, cmd int32, arg int64) int64 {
		t.Helper()
		if rc := w.Ipc_ctl(m, kind, id, num, cmd, arg, bufAt, resultAt); rc != 0 {
			t.Fatalf("ipc_ctl kind %d cmd %d: rc %d", kind, cmd, rc)
		}
		return int64(binary.LittleEndian.Uint64(m.memory[resultAt:]))
	}

	sem := get(ipcKindSem, 0, 2)
	defer ctl(ipcKindSem, sem, 0, ipcRmid, 0)
	ctl(ipcKindSem, sem, 1, 16 /* SETVAL */, 5)
	// sem_num 1, sem_op -2, sem_flg 0
	binary.LittleEndian.PutUint16(m.memory[bufAt:], 1)
	binary.LittleEndian.PutUint16(m.memory[bufAt+2:], uint16(0xfffe))
	binary.LittleEndian.PutUint16(m.memory[bufAt+4:], 0)
	if rc := w.Ipc_semop(m, sem, bufAt, 1); rc != 0 {
		t.Fatalf("ipc_semop: rc %d", rc)
	}
	if v := ctl(ipcKindSem, sem, 1, 12 /* GETVAL */, 0); v != 3 {
		t.Errorf("GETVAL: %d, want 3", v)
	}
	ctl(ipcKindSem, sem, 0, 13 /* GETALL */, 0)
	if a, b := binary.LittleEndian.Uint16(m.memory[bufAt:]), binary.LittleEndian.Uint16(m.memory[bufAt+2:]); a != 0 || b != 3 {
		t.Errorf("GETALL: %d %d, want 0 3", a, b)
	}
	ctl(ipcKindSem, sem, 0, ipcStat, 0)
	if mode, nsems := binary.LittleEndian.Uint32(m.memory[bufAt+20:]), binary.LittleEndian.Uint64(m.memory[bufAt+64:]); mode&0777 != 0600 || nsems != 2 {
		t.Errorf("IPC_STAT of the set: mode %o nsems %d, want 600 and 2", mode&0777, nsems)
	}

	msg := get(ipcKindMsg, 0, 0)
	defer ctl(ipcKindMsg, msg, 0, ipcRmid, 0)
	binary.LittleEndian.PutUint64(m.memory[bufAt:], 7)
	copy(m.memory[bufAt+8:], "hello")
	if rc := w.Ipc_msgsnd(m, msg, bufAt, 5, 0); rc != 0 {
		t.Fatalf("ipc_msgsnd: rc %d", rc)
	}
	clear(m.memory[bufAt : bufAt+64])
	if rc := w.Ipc_msgrcv(m, msg, bufAt, 64, 0, 0, resultAt); rc != 0 {
		t.Fatalf("ipc_msgrcv: rc %d", rc)
	}
	if n, typ := binary.LittleEndian.Uint64(m.memory[resultAt:]), binary.LittleEndian.Uint64(m.memory[bufAt:]); n != 5 || typ != 7 || string(m.memory[bufAt+8:bufAt+13]) != "hello" {
		t.Errorf("ipc_msgrcv: %d bytes of type %d, %q", n, typ, m.memory[bufAt+8:bufAt+13])
	}

	shm := get(ipcKindShm, 0, 4096)
	defer ctl(ipcKindShm, shm, 0, ipcRmid, 0)
	copy(m.memory[bufAt:], "segment")
	if rc := w.Ipc_shmcopy(m, shm, bufAt, 100, 7, 1); rc != 0 {
		t.Fatalf("ipc_shmcopy write: rc %d", rc)
	}
	clear(m.memory[bufAt : bufAt+16])
	if rc := w.Ipc_shmcopy(m, shm, bufAt, 99, 9, 0); rc != 0 {
		t.Fatalf("ipc_shmcopy read: rc %d", rc)
	}
	if got := m.memory[bufAt : bufAt+9]; !bytes.Equal(got, []byte("\x00segment\x00")) {
		t.Errorf("the segment's bytes: %q", got)
	}
	if rc := w.Ipc_shmcopy(m, shm, bufAt, 4090, 7, 0); rc != -_wasiEFAULT {
		t.Errorf("a copy past the segment: rc %d, want %d", rc, -_wasiEFAULT)
	}
	ctl(ipcKindShm, shm, 0, ipcStat, 0)
	if segsz := binary.LittleEndian.Uint64(m.memory[bufAt+48:]); segsz != 4096 {
		t.Errorf("IPC_STAT of the segment: segsz %d", segsz)
	}

	sandboxed, sm := newTestStubs(t, t.TempDir())
	if rc := sandboxed.Ipc_get(sm, ipcKindSem, 0, 1, ipcCreat|0600, idAt); rc != -_wasiENOSYS {
		t.Errorf("a guest that is not the host process: rc %d, want %d", rc, -_wasiENOSYS)
	}
}
