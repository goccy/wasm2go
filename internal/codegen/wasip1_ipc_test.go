package codegen

import (
	"errors"
	"slices"
	"syscall"
	"testing"
)

// Where the tests of this file keep their values in a guest's memory.
const (
	ipcOutOff int32 = 7000
	ipcBufOff int32 = 7100
	ipcMsgOff int32 = 7500
)

// fakeIPC is an IPC that records what it is asked and answers err. The
// calls that wait call wait first, when it is set.
type fakeIPC struct {
	calls []string
	bufs  [][]byte
	err   error
	wait  func()
}

func (f *fakeIPC) record(call string, buf []byte) {
	f.calls = append(f.calls, call)
	f.bufs = append(f.bufs, buf)
	if f.wait != nil && (call == "semop" || call == "msgsnd" || call == "msgrcv") {
		f.wait()
	}
}

func (f *fakeIPC) Get(kind IPCKind, key int32, arg uint64, flags int32) (int32, error) {
	f.record("get", nil)
	return int32(kind)*100 + key + int32(arg) + flags, f.err
}

func (f *fakeIPC) Control(kind IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error) {
	f.record("ctl", buf)
	return int64(id+num+cmd) + int64(arg), f.err
}

func (f *fakeIPC) Semop(id int32, ops []byte) error {
	f.record("semop", ops)
	return f.err
}

func (f *fakeIPC) Msgsnd(id int32, msg []byte, flags int32) error {
	f.record("msgsnd", msg)
	return f.err
}

func (f *fakeIPC) Msgrcv(id int32, msg []byte, typ int64, flags int32) (int, error) {
	f.record("msgrcv", msg)
	return len(msg), f.err
}

func (f *fakeIPC) ShmAttach(id int32, at []byte, flags int32) error {
	f.record("shmat", at)
	return f.err
}

func (f *fakeIPC) ShmDetach(at []byte) error {
	f.record("shmdt", at)
	return f.err
}

// ipcCalls makes every call of the IPC imports once, as a memory64 guest
// does, and returns their rcs.
func ipcCalls(w *WasiStubs, m *Module) []int32 {
	return []int32{
		w.Ipc_get64(m, int32(IPCSemaphoreSet), 1, 2, 3, int64(ipcOutOff)),
		w.Ipc_ctl64(m, int32(IPCSemaphoreSet), 1, 2, 3, 4, int64(ipcBufOff), int64(ipcOutOff)),
		w.Ipc_semop64(m, 1, int64(ipcBufOff), 2),
		w.Ipc_msgsnd64(m, 1, int64(ipcMsgOff), 16, 0),
		w.Ipc_msgrcv64(m, 1, int64(ipcMsgOff), 16, 0, 0, int64(ipcOutOff)),
	}
}

func TestIPC_WithoutOneEveryCallIsENOSYS(t *testing.T) {
	w := NewWASI(WASIConfig{})
	m := newGuestModule(1 << 16)
	for i, rc := range ipcCalls(w, m) {
		if rc != -_wasiENOSYS {
			t.Errorf("call %d without an IPC rc=%d, want -ENOSYS", i, rc)
		}
	}
}

func TestIPC_CallsReachTheIPC(t *testing.T) {
	ipc := &fakeIPC{}
	w := NewWASI(WASIConfig{IPC: ipc})
	m := newGuestModule(1 << 16)
	for i, rc := range ipcCalls(w, m) {
		if rc != _wasiESUCCESS {
			t.Errorf("call %d rc=%d", i, rc)
		}
	}
	if want := []string{"get", "ctl", "semop", "msgsnd", "msgrcv"}; !slices.Equal(ipc.calls, want) {
		t.Fatalf("calls %q, want %q", ipc.calls, want)
	}
	for i, n := range []int{0, 1<<16 - int(ipcBufOff), 12, 8 + 16, 8 + 16} {
		if len(ipc.bufs[i]) != n {
			t.Errorf("%s was given %d bytes, want %d", ipc.calls[i], len(ipc.bufs[i]), n)
		}
	}
	if got := readU64(m.memory, int(ipcOutOff)); got != 24 {
		t.Fatalf("msgrcv received %d bytes, want 24", got)
	}
	if rc := w.Ipc_ctl64(m, int32(IPCMessageQueue), 1, 2, 3, 4, 1<<40, int64(ipcOutOff)); rc != _wasiESUCCESS || ipc.bufs[len(ipc.bufs)-1] != nil {
		t.Fatalf("Ipc_ctl64 with a buffer beyond the memory rc=%d, buffer %d bytes; want none", rc, len(ipc.bufs[len(ipc.bufs)-1]))
	}
	if readU64(m.memory, int(ipcOutOff)) != 10 {
		t.Fatalf("msgctl returned %d, want 10", readU64(m.memory, int(ipcOutOff)))
	}
	// A wasm32 guest has msgget and semop, whose arguments are the same.
	if rc := w.Ipc_get(m, int32(IPCSemaphoreSet), 1, 2, 3, ipcOutOff); rc != _wasiESUCCESS || readU32(m.memory, int(ipcOutOff)) != 106 {
		t.Fatalf("Ipc_get rc=%d, id %d; want 106", rc, readU32(m.memory, int(ipcOutOff)))
	}
	if rc := w.Ipc_semop(m, 1, ipcBufOff, 2); rc != _wasiESUCCESS || len(ipc.bufs[len(ipc.bufs)-1]) != 12 {
		t.Fatalf("Ipc_semop rc=%d, %d bytes of operations; want 12", rc, len(ipc.bufs[len(ipc.bufs)-1]))
	}
}

// A wasm32 guest's commands that pass no structure reach the IPC: it can
// remove its objects, and read and set a semaphore's value.
func TestIPC_Wasm32GuestHasTheCommandsWithoutStructures(t *testing.T) {
	ipc := &fakeIPC{}
	w := NewWASI(WASIConfig{IPC: ipc})
	m := newGuestModule(1 << 16)
	for _, c := range []struct {
		kind IPCKind
		cmd  int32
	}{
		{IPCMessageQueue, ipcCmdRmid},
		{IPCSemaphoreSet, ipcCmdRmid},
		{IPCSharedMemory, ipcCmdRmid},
		{IPCSemaphoreSet, ipcCmdGetPid},
		{IPCSemaphoreSet, ipcCmdGetVal},
		{IPCSemaphoreSet, ipcCmdGetNcnt},
		{IPCSemaphoreSet, ipcCmdGetZcnt},
		{IPCSemaphoreSet, ipcCmdSetVal},
		{IPCSharedMemory, ipcCmdShmLock},
		{IPCSharedMemory, ipcCmdShmUnlock},
	} {
		if rc := w.Ipc_ctl(m, int32(c.kind), 1, 0, c.cmd, 0, ipcBufOff, ipcOutOff); rc != _wasiESUCCESS {
			t.Errorf("command %d on kind %d of a wasm32 guest rc=%d", c.cmd, c.kind, rc)
		}
	}
	if len(ipc.calls) != 10 {
		t.Fatalf("the IPC was asked %q, want 10 controls", ipc.calls)
	}
	for _, c := range []struct {
		kind IPCKind
		cmd  int32
	}{
		{IPCSemaphoreSet, ipcCmdStat},
		{IPCSemaphoreSet, ipcCmdGetAll},
		{IPCMessageQueue, ipcCmdGetVal},
		{IPCSharedMemory, ipcCmdStat},
	} {
		if rc := w.Ipc_ctl(m, int32(c.kind), 1, 0, c.cmd, 0, ipcBufOff, ipcOutOff); rc != -_wasiENOSYS {
			t.Errorf("command %d on kind %d of a wasm32 guest rc=%d, want -ENOSYS", c.cmd, c.kind, rc)
		}
	}
	if rc := w.Ipc_ctl(m, 3, 1, 0, ipcCmdStat, 0, ipcBufOff, ipcOutOff); rc != -_wasiEINVAL {
		t.Fatalf("a command on no kind of a wasm32 guest rc=%d, want -EINVAL", rc)
	}
}

// A wasm32 guest's structures are not the ones the IPC takes: the calls
// that pass one fail with ENOSYS and ask the IPC nothing.
func TestIPC_Wasm32GuestHasNoCallsOfStructures(t *testing.T) {
	ipc := &fakeIPC{}
	w := NewWASI(WASIConfig{IPC: ipc})
	m := newGuestModule(1 << 16)
	for name, rc := range map[string]int32{
		"msgctl": w.Ipc_ctl(m, int32(IPCMessageQueue), 1, 0, 2, 0, ipcBufOff, ipcOutOff),
		"msgsnd": w.Ipc_msgsnd(m, 1, ipcMsgOff, 16, 0),
		"msgrcv": w.Ipc_msgrcv(m, 1, ipcMsgOff, 16, 0, 0, ipcOutOff),
		"shmat":  w.Ipc_shmat(m, 1, 0, 1<<16, 0),
		"shmdt":  w.Ipc_shmdt(m, 0),
	} {
		if rc != -_wasiENOSYS {
			t.Errorf("%s of a wasm32 guest rc=%d, want -ENOSYS", name, rc)
		}
	}
	if len(ipc.calls) != 0 {
		t.Fatalf("the IPC was asked %q", ipc.calls)
	}
}

func TestIPC_RefusedCalls(t *testing.T) {
	ipc := &fakeIPC{}
	w := NewWASI(WASIConfig{IPC: ipc})
	m := newGuestModule(1 << 16)
	for _, c := range []struct {
		what string
		rc   int32
		want int32
	}{
		{"get of no kind", w.Ipc_get64(m, 3, 0, 0, 0, int64(ipcOutOff)), -_wasiEINVAL},
		{"ctl of no kind", w.Ipc_ctl64(m, -1, 0, 0, 0, 0, 0, int64(ipcOutOff)), -_wasiEINVAL},
		{"get beyond the memory", w.Ipc_get64(m, 0, 0, 0, 0, 1<<20), -_wasiEFAULT},
		{"ctl beyond the memory", w.Ipc_ctl64(m, 0, 0, 0, 0, 0, 0, 1<<20), -_wasiEFAULT},
		{"semop of too many", w.Ipc_semop64(m, 1, 0, -1), -_wasiE2BIG},
		{"semop beyond the memory", w.Ipc_semop64(m, 1, int64(ipcBufOff), 1<<20), -_wasiEFAULT},
		{"msgsnd of too much", w.Ipc_msgsnd64(m, 1, 0, -1, 0), -_wasiEFAULT},
		{"msgsnd beyond the memory", w.Ipc_msgsnd64(m, 1, int64(ipcMsgOff), 1<<20, 0), -_wasiEFAULT},
		{"msgrcv beyond the memory", w.Ipc_msgrcv64(m, 1, int64(ipcMsgOff), 16, 0, 0, 1<<20), -_wasiEFAULT},
	} {
		if c.rc != c.want {
			t.Errorf("%s rc=%d, want %d", c.what, c.rc, c.want)
		}
	}
	if len(ipc.calls) != 0 {
		t.Fatalf("the IPC was asked %q", ipc.calls)
	}
	for err, want := range map[error]int32{errors.ErrUnsupported: -_wasiENOSYS, syscall.EPERM: -_wasiEPERM} {
		ipc.err = err
		for i, rc := range ipcCalls(w, m) {
			if rc != want {
				t.Errorf("call %d failing with %v rc=%d, want %d", i, err, rc, want)
			}
		}
	}
}

// A guest without a registration for signals that a signal posted while a
// call waits ends is ended when the call returns.
func TestIPC_ASignalPostedWhileACallWaitsEndsTheGuestWhenItReturns(t *testing.T) {
	for name, call := range map[string]func(w *WasiStubs, m *Module) int32{
		"semop":  func(w *WasiStubs, m *Module) int32 { return w.Ipc_semop64(m, 1, int64(ipcBufOff), 1) },
		"msgsnd": func(w *WasiStubs, m *Module) int32 { return w.Ipc_msgsnd64(m, 1, int64(ipcMsgOff), 16, 0) },
		"msgrcv": func(w *WasiStubs, m *Module) int32 {
			return w.Ipc_msgrcv64(m, 1, int64(ipcMsgOff), 16, 0, 0, int64(ipcOutOff))
		},
	} {
		t.Run(name, func(t *testing.T) {
			waiting := make(chan struct{})
			release := make(chan struct{})
			ipc := &fakeIPC{wait: func() {
				close(waiting)
				<-release
			}}
			w := NewWASI(WASIConfig{IPC: ipc})
			m := newGuestModule(1 << 16)
			ended := make(chan any, 1)
			go func() {
				defer func() { ended <- recover() }()
				call(w, m)
			}()
			<-waiting
			w.PostSignal(15)
			close(release)
			r := <-ended
			if sigErr, ok := r.(*WasiSignalError); !ok || sigErr.Signal != 15 {
				t.Fatalf("the call ended with %v, want a WasiSignalError for 15", r)
			}
		})
	}
}

// A segment is attached only over a memory the runtime mapped itself, which
// no memory of this package is: shmat fails with ENOMEM and asks the IPC
// nothing. Memory that is not the guest's, or none, is refused before, as is
// a shmdt of an address no segment is attached at.
func TestIPC_ShmatOfAMemoryTheRuntimeDidNotMap(t *testing.T) {
	ipc := &fakeIPC{}
	w := NewWASI(WASIConfig{IPC: ipc})
	m := newGuestModule(1 << 16)
	for _, c := range []struct {
		what string
		rc   int32
		want int32
	}{
		{"shmat", w.Ipc_shmat64(m, 1, 0, 1<<16, 0), -_wasiENOMEM},
		{"shmat of no memory", w.Ipc_shmat64(m, 1, 0, 0, 0), -_wasiEINVAL},
		{"shmat beyond the memory", w.Ipc_shmat64(m, 1, 0, 1<<16+1, 0), -_wasiEINVAL},
		{"shmdt", w.Ipc_shmdt64(m, 0), -_wasiEINVAL},
	} {
		if c.rc != c.want {
			t.Errorf("%s rc=%d, want %d", c.what, c.rc, c.want)
		}
	}
	if len(ipc.calls) != 0 {
		t.Fatalf("the IPC was asked %q", ipc.calls)
	}
	w = NewWASI(WASIConfig{})
	if rc := w.Ipc_shmat64(m, 1, 0, 1<<16, 0); rc != -_wasiENOSYS {
		t.Fatalf("shmat without an IPC rc=%d, want -ENOSYS", rc)
	}
	if rc := w.Ipc_shmdt64(m, 0); rc != -_wasiENOSYS {
		t.Fatalf("shmdt without an IPC rc=%d, want -ENOSYS", rc)
	}
}
