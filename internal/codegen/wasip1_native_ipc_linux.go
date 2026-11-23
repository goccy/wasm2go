//go:build linux && !386 && !arm && !mips && !mipsle && !mips64 && !mips64le && !ppc64 && !ppc64le && !s390x

package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// The System V IPC of HostIPC on Linux, on the architectures whose
// structures are the guest's: those of asm-generic on a 64-bit
// architecture, and x86-64, whose semid64_ds has a word after each time.
// The constraint names the other architectures: the gcasm capture and
// bundle drop a file whose constraint names amd64 or arm64.

// shmat's flags, the guest's (Linux's): SHM_RDONLY, and SHM_REMAP, which
// attaches over what is mapped there.
const (
	ipcShmRdonly = 0o10000
	ipcShmRemap  = 0o40000
)

// The size of x86-64's semid64_ds and where it has sem_nsems.
const (
	ipcSemSizeAMD64  = 104
	ipcSemNsemsAMD64 = 80
)

// ipcStat reads the structure of the object, in the guest's layout.
func ipcStat(kind IPCKind, id int32) ([]byte, error) {
	size := ipcStructSize(kind)
	if kind == IPCSemaphoreSet && runtime.GOARCH == "amd64" {
		size = ipcSemSizeAMD64
	}
	st := make([]byte, size)
	if _, err := ipcCtl(kind, id, 0, ipcCmdStat, unsafe.Pointer(&st[0]), 0); err != nil {
		return nil, err
	}
	if kind == IPCSemaphoreSet && runtime.GOARCH == "amd64" {
		// otime, a word, ctime, a word, nsems: the guest's has no words
		guest := make([]byte, ipcStructSize(kind))
		copy(guest, st[:56])
		copy(guest[56:64], st[64:72])
		copy(guest[ipcSemNsems:], st[ipcSemNsemsAMD64:ipcSemNsemsAMD64+8])
		st = guest
	}
	return st, nil
}

// ipcHostStruct returns the kernel's structure of the kind for the IPC_SET
// of guest, the guest's: guest itself, but for x86-64's semid64_ds.
func ipcHostStruct(kind IPCKind, guest []byte) []byte {
	if kind != IPCSemaphoreSet || runtime.GOARCH != "amd64" {
		return guest
	}
	st := make([]byte, ipcSemSizeAMD64)
	copy(st, guest[:56])
	copy(st[64:72], guest[56:64])
	copy(st[ipcSemNsemsAMD64:], guest[ipcSemNsems:ipcSemNsems+8])
	return st
}

// ipcHostCommand returns the kernel's number of the guest's command cmd:
// cmd itself.
func ipcHostCommand(kind IPCKind, cmd int32) (int32, bool) { return cmd, true }

// ipcMsgrcvUnsupported are the guest's flags of msgrcv the kernel has
// not: none.
const ipcMsgrcvUnsupported = 0

// ShmAttach attaches the segment over at only when the segment's mapping
// is as long as its pages: it attaches it where the kernel picks first and
// reads the length of that mapping from /proc/self/maps. A segment of huge
// pages (SHM_HUGETLB) is mapped as long as its huge pages, and the kernel
// reports that nowhere else: IPC_STAT gives the size the segment was made
// with, and its mode keeps no SHM_HUGETLB.
func (hostIPC) ShmAttach(id int32, at []byte, flags int32) error {
	if flags&^ipcShmRdonly != 0 {
		return syscall.EINVAL
	}
	st, err := ipcStat(IPCSharedMemory, id)
	if err != nil {
		return err
	}
	// The segment is mapped in whole pages, which have to be at's; shmat
	// itself refuses an address off a page boundary.
	pages, ok := ipcShmPages(binary.LittleEndian.Uint64(st[ipcShmSegsz:]), len(at))
	if !ok {
		return syscall.EINVAL
	}
	probe, err := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_SHMAT, uintptr(id), 0, uintptr(flags))
	})
	if err != nil {
		return err
	}
	maps, readErr := os.ReadFile("/proc/self/maps")
	_, detachErr := ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_SHMDT, probe, 0, 0)
	})
	if err := errors.Join(readErr, detachErr); err != nil {
		return err
	}
	if err := validateShmMapping(maps, probe, pages); err != nil {
		return err
	}
	_, err = ipcCall(func() (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_SHMAT, uintptr(id), uintptr(unsafe.Pointer(unsafe.SliceData(at))), uintptr(flags|ipcShmRemap))
	})
	return err
}

// validateShmMapping returns nil when the mapping that starts at addr in
// maps (/proc/self/maps) is length bytes long, EINVAL when it is of another
// length, and an error when maps has no mapping that starts there.
func validateShmMapping(maps []byte, addr uintptr, length uint64) error {
	for line := range strings.Lines(string(maps)) {
		span, _, _ := strings.Cut(line, " ")
		startText, endText, ok := strings.Cut(span, "-")
		if !ok {
			return fmt.Errorf("wasi: a line of /proc/self/maps without its range: %q", line)
		}
		start, err := strconv.ParseUint(startText, 16, 64)
		if err != nil {
			return err
		}
		if start != uint64(addr) {
			continue
		}
		end, err := strconv.ParseUint(endText, 16, 64)
		if err != nil {
			return err
		}
		if end-start != length {
			return syscall.EINVAL
		}
		return nil
	}
	return fmt.Errorf("wasi: no mapping at %#x in /proc/self/maps", addr)
}

// ShmDetach maps zero memory over at, which detaches the segment that is
// there in the same call and leaves no moment at which at is not mapped.
// (syscall.Mmap takes no address to map at.)
func (hostIPC) ShmDetach(at []byte) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_MMAP, uintptr(unsafe.Pointer(unsafe.SliceData(at))), uintptr(len(at)),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON|syscall.MAP_FIXED, ^uintptr(0), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
