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

// The mapping that starts at the address is accepted only at the length
// given: a segment of huge pages is mapped longer than its pages.
func TestValidateShmMapping(t *testing.T) {
	maps := []byte("7f0000000000-7f0000010000 rw-s 00000000 00:01 5                          /SYSV00000000 (deleted)\n" +
		"7f0000200000-7f0000400000 rw-s 00000000 00:10 6                          /SYSV00000000 (deleted)\n")
	if err := validateShmMapping(maps, 0x7f0000000000, 0x10000); err != nil {
		t.Fatalf("a mapping of the length: %v", err)
	}
	if err := validateShmMapping(maps, 0x7f0000200000, 0x10000); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("a mapping of huge pages, longer than the segment's pages: %v, want EINVAL", err)
	}
	if err := validateShmMapping(maps, 0x7f0000100000, 0x10000); err == nil || errors.Is(err, syscall.EINVAL) {
		t.Fatalf("no mapping at the address: %v, want an error of its own", err)
	}
	if err := validateShmMapping([]byte("garbage\n"), 0x7f0000000000, 0x10000); err == nil {
		t.Fatal("a line without its range was taken")
	}
}

// anonymousMemory maps n pages of zero memory for the test.
func anonymousMemory(t *testing.T, n int) []byte {
	t.Helper()
	mem, err := syscall.Mmap(-1, 0, n*syscall.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(mem); err != nil {
			t.Error(err)
		}
	})
	return mem
}

// A segment attached over two parts of a memory is the same bytes in both,
// stays usable after IPC_RMID until it is detached, and leaves zero memory
// where it was detached.
func TestHostIPC_ShmAttachAndDetach(t *testing.T) {
	page := syscall.Getpagesize()
	mem := anonymousMemory(t, 3)
	ipc := HostIPC()
	id, err := ipc.Get(IPCSharedMemory, guestIPCPrivate, uint64(page), guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	removed := false
	t.Cleanup(func() {
		if removed {
			return
		}
		if _, err := ipc.Control(IPCSharedMemory, id, 0, guestIPCRmid, 0, nil); err != nil {
			t.Error(err)
		}
	})
	first, second := mem[:page], mem[page:2*page]
	if err := ipc.ShmAttach(id, first, 0); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := ipc.ShmAttach(id, second, ipcShmRdonly); err != nil {
		t.Fatalf("attach read-only: %v", err)
	}
	if _, err := ipc.Control(IPCSharedMemory, id, 0, guestIPCRmid, 0, nil); err != nil {
		t.Fatal(err)
	}
	removed = true
	first[10] = 'x'
	if second[10] != 'x' {
		t.Fatalf("the second attachment has %q where the first was written, want 'x'", second[10])
	}
	for _, at := range [][]byte{first, second} {
		if err := ipc.ShmDetach(at); err != nil {
			t.Fatalf("detach: %v", err)
		}
	}
	if first[10] != 0 || second[10] != 0 {
		t.Fatalf("the detached memory has %q and %q, want zero", first[10], second[10])
	}
	first[10] = 'y'
	if second[10] != 0 {
		t.Fatal("the detached memory is shared still")
	}
	// The last detachment destroyed the removed segment.
	if _, err := ipc.Control(IPCSharedMemory, id, 0, guestIPCStat, 0, make([]byte, 112)); !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.EIDRM) {
		t.Fatalf("IPC_STAT of the removed segment after its detachments: %v, want EINVAL or EIDRM", err)
	}
}

// A segment is attached only at a page boundary, over memory as long as
// its pages, and with no flag but SHM_RDONLY.
func TestHostIPC_ShmAttachRefused(t *testing.T) {
	page := syscall.Getpagesize()
	mem := anonymousMemory(t, 3)
	ipc := HostIPC()
	id, err := ipc.Get(IPCSharedMemory, guestIPCPrivate, uint64(page)+1, guestIPCCreat|0o600)
	if err != nil {
		t.Fatalf("shmget: %v", err)
	}
	removeAtEnd(t, IPCSharedMemory, id)
	for _, c := range []struct {
		what  string
		at    []byte
		flags int32
	}{
		{"off a page boundary", mem[1 : 2*page+1], 0},
		{"over less than its pages", mem[:2*page-1], 0},
		{"with SHM_REMAP", mem[:2*page], ipcShmRemap},
	} {
		if err := ipc.ShmAttach(id, c.at, c.flags); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("attach %s: %v, want EINVAL", c.what, err)
		}
	}
}
