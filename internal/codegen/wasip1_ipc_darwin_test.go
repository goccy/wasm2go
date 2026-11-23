package codegen

import (
	"encoding/binary"
	"errors"
	"testing"
)

// msgrcv's MSG_EXCEPT and MSG_COPY, which darwin has not, are refused, and
// no segment is attached over the guest's memory.
func TestHostIPC_WhatDarwinHasNot(t *testing.T) {
	ipc := HostIPC()
	id, err := ipc.Get(IPCMessageQueue, guestIPCPrivate, 0, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("msgget: %v", err)
	}
	removeAtEnd(t, IPCMessageQueue, id)
	msg := make([]byte, 8+1)
	binary.LittleEndian.PutUint64(msg, 1)
	if err := ipc.Msgsnd(id, msg, 0); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8+16)
	for _, flag := range []int32{0o20000, 0o40000} {
		if _, err := ipc.Msgrcv(id, got, 2, guestIPCNowait|flag); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("msgrcv with %#o: %v, want errors.ErrUnsupported", flag, err)
		}
	}
	if err := ipc.ShmAttach(0, make([]byte, 4096), 0); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ShmAttach: %v, want errors.ErrUnsupported", err)
	}
	if err := ipc.ShmDetach(make([]byte, 4096)); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ShmDetach: %v, want errors.ErrUnsupported", err)
	}
}
