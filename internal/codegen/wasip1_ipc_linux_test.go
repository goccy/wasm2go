//go:build linux && !386 && !arm && !mips && !mipsle && !mips64 && !mips64le && !ppc64 && !ppc64le && !s390x

package codegen

import (
	"errors"
	"syscall"
	"testing"
)

// IPC_SET of a semaphore set reads the guest's structure and nothing after
// it, which here is no memory.
func TestHostIPC_SemaphoreSetReadsTheGuestsStructureOnly(t *testing.T) {
	page := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(mem); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Mprotect(mem[page:], syscall.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	ipc := HostIPC()
	id, err := ipc.Get(IPCSemaphoreSet, guestIPCPrivate, 1, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("semget: %v", err)
	}
	removeAtEnd(t, IPCSemaphoreSet, id)
	st := mem[page-88 : page]
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCStat, 0, st); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Control(IPCSemaphoreSet, id, 0, guestIPCSet, 0, st); err != nil {
		t.Fatalf("IPC_SET of the structure at the end of the memory: %v", err)
	}
}

// A call the host process is interrupted in is made again; another error
// ends it.
func TestIPCCallMadeAgainOnEINTR(t *testing.T) {
	answers := []syscall.Errno{syscall.EINTR, syscall.EINTR, 0}
	made := 0
	r, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		errno := answers[made]
		made++
		return 7, 0, errno
	})
	if err != nil || r != 7 || made != 3 {
		t.Fatalf("ipcCall returned %d %v after %d calls, want 7 after 3", r, err, made)
	}
	made = 0
	answers = []syscall.Errno{syscall.EINTR, syscall.EIDRM}
	if _, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		errno := answers[made]
		made++
		return 0, 0, errno
	}); !errors.Is(err, syscall.EIDRM) || made != 2 {
		t.Fatalf("ipcCall failed with %v after %d calls, want EIDRM after 2", err, made)
	}
}
