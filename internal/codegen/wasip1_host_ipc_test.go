package codegen

import (
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"testing"
)

// hostIPCAvailable reports whether HostIPC reaches the host's objects here.
func hostIPCAvailable() bool {
	switch runtime.GOARCH {
	case "amd64", "arm64", "riscv64", "loong64":
		return runtime.GOOS == "linux"
	}
	return false
}

// The guest's flags and commands (Linux's).
const (
	guestIPCCreat   = 0o1000
	guestIPCNowait  = 0o4000
	guestIPCRmid    = 0
	guestIPCSet     = 1
	guestIPCStat    = 2
	guestIPCGetVal  = 12
	guestIPCGetAll  = 13
	guestIPCSetVal  = 16
	guestIPCSetAll  = 17
	guestIPCPrivate = 0
)

// removeAtEnd removes the object id of the kind when the test ends.
func removeAtEnd(t *testing.T, kind IPCKind, id int32) {
	t.Cleanup(func() {
		if _, err := HostIPC().Control(kind, id, 0, guestIPCRmid, 0, nil); err != nil {
			t.Error(err)
		}
	})
}

func TestHostIPC_WhereItHasNoObjects(t *testing.T) {
	if hostIPCAvailable() {
		t.Skip("HostIPC has the host's objects here")
	}
	ipc := HostIPC()
	_, getErr := ipc.Get(IPCMessageQueue, guestIPCPrivate, 0, guestIPCCreat|0o600)
	_, ctlErr := ipc.Control(IPCMessageQueue, 0, 0, 0, 0, nil)
	_, rcvErr := ipc.Msgrcv(0, nil, 0, 0)
	for i, err := range []error{getErr, ctlErr, ipc.Semop(0, nil), ipc.Msgsnd(0, nil, 0), rcvErr} {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("call %d: %v, want errors.ErrUnsupported", i, err)
		}
	}
}

func TestHostIPC_MessageQueue(t *testing.T) {
	if !hostIPCAvailable() {
		t.Skip("HostIPC has no objects here")
	}
	ipc := HostIPC()
	id, err := ipc.Get(IPCMessageQueue, guestIPCPrivate, 0, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("msgget: %v", err)
	}
	removeAtEnd(t, IPCMessageQueue, id)
	// A receive waits for the message sent after it began.
	type received struct {
		n   int
		msg []byte
		err error
	}
	done := make(chan received, 1)
	go func() {
		got := make([]byte, 8+16)
		n, err := ipc.Msgrcv(id, got, 3, 0)
		done <- received{n, got, err}
	}()
	msg := make([]byte, 8+5)
	binary.LittleEndian.PutUint64(msg, 3)
	copy(msg[8:], "hello")
	if err := ipc.Msgsnd(id, msg, 0); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.n != 5 || string(r.msg[8:8+r.n]) != "hello" || binary.LittleEndian.Uint64(r.msg) != 3 {
		t.Fatalf("msgrcv: %d %q %v", r.n, r.msg, r.err)
	}
	if err := ipc.Msgsnd(id, msg, 0); err != nil {
		t.Fatal(err)
	}
	st := make([]byte, 120)
	if _, err := ipc.Control(IPCMessageQueue, id, 0, guestIPCStat, 0, st); err != nil {
		t.Fatal(err)
	}
	if qnum := binary.LittleEndian.Uint64(st[80:]); qnum != 1 {
		t.Fatalf("msg_qnum %d, want 1", qnum)
	}
	got := make([]byte, 8+16)
	if n, err := ipc.Msgrcv(id, got, 0, guestIPCNowait); err != nil || n != 5 {
		t.Fatalf("msgrcv of the queued message: %d %v", n, err)
	}
	if _, err := ipc.Msgrcv(id, got, 0, guestIPCNowait); !errors.Is(err, syscall.ENOMSG) {
		t.Fatalf("msgrcv of an empty queue: %v, want ENOMSG", err)
	}
	if _, err := ipc.Control(IPCMessageQueue, id, 0, guestIPCStat, 0, st[:8]); !errors.Is(err, syscall.EFAULT) {
		t.Fatalf("IPC_STAT into a short buffer: %v, want EFAULT", err)
	}
	if _, err := ipc.Control(IPCMessageQueue, id, 0, 3, 0, st); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("IPC_INFO: %v, want EINVAL", err)
	}
	if err := ipc.Msgsnd(id, nil, 0); !errors.Is(err, syscall.EFAULT) {
		t.Fatalf("Msgsnd of no message: %v, want EFAULT", err)
	}
	if _, err := ipc.Msgrcv(id, nil, 0, 0); !errors.Is(err, syscall.EFAULT) {
		t.Fatalf("Msgrcv into no message: %v, want EFAULT", err)
	}
}

func TestHostIPC_SemaphoreSet(t *testing.T) {
	if !hostIPCAvailable() {
		t.Skip("HostIPC has no objects here")
	}
	ipc := HostIPC()
	id, err := ipc.Get(IPCSemaphoreSet, guestIPCPrivate, 2, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("semget: %v", err)
	}
	removeAtEnd(t, IPCSemaphoreSet, id)
	// A decrement waits for the increment made after it began.
	op := func(num uint16, delta int16, flags uint16) []byte {
		ops := make([]byte, 6)
		binary.LittleEndian.PutUint16(ops[0:], num)
		binary.LittleEndian.PutUint16(ops[2:], uint16(delta))
		binary.LittleEndian.PutUint16(ops[4:], flags)
		return ops
	}
	done := make(chan error, 1)
	go func() { done <- ipc.Semop(id, op(0, -1, 0)) }()
	if err := ipc.Semop(id, op(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the waiting decrement: %v", err)
	}
	if v, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCGetVal, 0, nil); err != nil || v != 0 {
		t.Fatalf("GETVAL %d %v, want 0", v, err)
	}
	if err := ipc.Semop(id, op(0, -1, guestIPCNowait)); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("a decrement of 0 without waiting: %v, want EAGAIN", err)
	}
	if _, err := ipc.Control(IPCSemaphoreSet, id, 1, guestIPCSetVal, 3, nil); err != nil {
		t.Fatal(err)
	}
	if err := ipc.Semop(id, op(1, -1, 0)); err != nil {
		t.Fatal(err)
	}
	if v, err := ipc.Control(IPCSemaphoreSet, id, 1, guestIPCGetVal, 0, nil); err != nil || v != 2 {
		t.Fatalf("GETVAL %d %v, want 2", v, err)
	}
	values := []byte{7, 0, 9, 0}
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCSetAll, 0, values); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCGetAll, 0, got); err != nil || string(got) != string(values) {
		t.Fatalf("GETALL %v %v, want %v", got, err, values)
	}
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCGetAll, 0, got[:2]); !errors.Is(err, syscall.EFAULT) {
		t.Fatalf("GETALL into a short buffer: %v, want EFAULT", err)
	}
	st := make([]byte, 88)
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCStat, 0, st); err != nil {
		t.Fatal(err)
	}
	if nsems := binary.LittleEndian.Uint64(st[64:]); nsems != 2 {
		t.Fatalf("sem_nsems %d, want 2", nsems)
	}
	if mode := binary.LittleEndian.Uint32(st[20:]); mode&0o777 != 0o600 {
		t.Fatalf("mode %#o, want 0600", mode)
	}
	binary.LittleEndian.PutUint32(st[20:], 0o640)
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCSet, 0, st); err != nil {
		t.Fatalf("IPC_SET: %v", err)
	}
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCStat, 0, st); err != nil {
		t.Fatal(err)
	}
	if mode := binary.LittleEndian.Uint32(st[20:]); mode&0o777 != 0o640 {
		t.Fatalf("mode after IPC_SET %#o, want 0640", mode)
	}
	if nsems := binary.LittleEndian.Uint64(st[64:]); nsems != 2 {
		t.Fatalf("sem_nsems after IPC_SET %d, want 2", nsems)
	}
}

func TestHostIPC_SharedMemory(t *testing.T) {
	if !hostIPCAvailable() {
		t.Skip("HostIPC has no objects here")
	}
	ipc := HostIPC()
	id, err := ipc.Get(IPCSharedMemory, guestIPCPrivate, 4096, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	removeAtEnd(t, IPCSharedMemory, id)
	st := make([]byte, 112)
	if _, err := ipc.Control(IPCSharedMemory, id, 0, guestIPCStat, 0, st); err != nil {
		t.Fatal(err)
	}
	if segsz := binary.LittleEndian.Uint64(st[48:]); segsz != 4096 {
		t.Fatalf("shm_segsz %d, want 4096", segsz)
	}
	// SHM_LOCK and SHM_UNLOCK reach the kernel, which may refuse a user
	// that may lock no memory.
	for _, cmd := range []int32{11, 12} {
		if _, err := ipc.Control(IPCSharedMemory, id, 0, cmd, 0, nil); err != nil && !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.ENOMEM) {
			t.Errorf("shmctl %d: %v", cmd, err)
		}
	}
}

func TestHostIPC_NoKind(t *testing.T) {
	if !hostIPCAvailable() {
		t.Skip("HostIPC has no objects here")
	}
	ipc := HostIPC()
	if _, err := ipc.Get(5, 0, 0, 0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Get of no kind: %v, want EINVAL", err)
	}
	if _, err := ipc.Control(5, 0, 0, guestIPCRmid, 0, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Control of no kind: %v, want EINVAL", err)
	}
}
