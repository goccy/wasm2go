//go:build linux || darwin

package helpers

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// linearMemoryReserve is the address space a wasm32 linear memory occupies
// on a 64-bit host: every address a guest access can form, plus a guard. A
// load or store computes the linear-memory base plus a u32 address plus a u32
// static offset (< 8 GiB in all) and touches at most 16 bytes from there, so
// it always lands inside this range. Only the instance's own pages are
// readable and writable; every other page in the range faults, and the export
// entry points turn that fault into the out-of-bounds trap (see
// memoryAccessTrap). No access the generated code can make reaches outside
// the instance's own memory.
//
// The reservation is address space, not memory, but every instance takes
// one: a 47-bit address space holds about 16k of them, and a host that
// limits the address space (RLIMIT_AS) refuses them sooner.
const linearMemoryReserve uint64 = 8<<30 + 64<<10

// guardedLinearMemory reports whether linear memories live in a guarded
// reservation. The reservation needs a 64-bit address space; a 32-bit host
// keeps the plain heap allocation, which does not confine out-of-bounds
// accesses.
const guardedLinearMemory = unsafe.Sizeof(uintptr(0)) == 8

// newLinearMemory returns a linear memory of minBytes and the reservation
// that backs it, or — on a host without one — a heap allocation with
// capBytes capacity and a nil reservation. A reserved memory never moves and
// is readable and writable exactly up to its length: commitLinearMemory
// extends that in place as it grows.
func newLinearMemory(minBytes, capBytes uint64) (mem, reserve []byte, err error) {
	if !guardedLinearMemory {
		return make([]byte, minBytes, capBytes), nil, nil
	}
	// A shared memory is allocated at its ceiling, which a caller may set
	// past the 4 GiB a wasm32 guest can address; nothing beyond it is
	// reachable.
	minBytes = min(minBytes, 1<<32)
	size := linearMemoryReserve
	reserve, err = mmapLinearMemory(-1, int(size), syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, nil, fmt.Errorf("reserving linear memory: %w", err)
	}
	if err := commitLinearMemory(reserve, 0, minBytes); err != nil {
		return nil, nil, errors.Join(err, releaseReservation(reserve))
	}
	return reserve[:minBytes:minBytes], reserve, nil
}

// commitLinearMemory makes reserve[from:to] readable and writable. The pages
// read as zero, as freshly grown wasm memory must.
func commitLinearMemory(reserve []byte, from, to uint64) error {
	if from == to {
		return nil
	}
	if err := syscall.Mprotect(reserve[from:to], syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return fmt.Errorf("committing linear memory: %w", err)
	}
	return nil
}

// linearMappings records the length of every mapping this file made, by its
// base address: a release unmaps exactly that mapping, whatever length and
// capacity the slice it is handed has.
var linearMappings = struct {
	sync.Mutex
	length map[uintptr]int
}{length: map[uintptr]int{}}

// mmapLinearMemory is syscall.Mmap of length bytes at offset 0, recorded in
// linearMappings.
func mmapLinearMemory(fd, length, prot, flags int) ([]byte, error) {
	mem, err := syscall.Mmap(fd, 0, length, prot, flags)
	if err != nil {
		return nil, err
	}
	linearMappings.Lock()
	linearMappings.length[uintptr(unsafe.Pointer(unsafe.SliceData(mem)))] = length
	linearMappings.Unlock()
	return mem, nil
}

// releaseLinearMemory returns a linear memory from newLinearMemory or
// mapLinearMemory to the OS — the whole mapping, whatever length the slice
// has. Unmapping a mapping this package made can only fail on a slice that
// did not come from it, so a failure is a bug and panics.
func releaseLinearMemory(mem []byte) {
	if err := releaseReservation(mem); err != nil {
		panic("wasm2go: " + err.Error())
	}
}

// releaseReservation unmaps the mapping that starts at mem's base, as long
// as linearMappings recorded it.
func releaseReservation(mem []byte) error {
	base := unsafe.SliceData(mem)
	linearMappings.Lock()
	length, ok := linearMappings.length[uintptr(unsafe.Pointer(base))]
	delete(linearMappings.length, uintptr(unsafe.Pointer(base)))
	linearMappings.Unlock()
	if !ok {
		return fmt.Errorf("releasing linear memory: %p is not the start of a linear memory mapping", base)
	}
	if err := syscall.Munmap(unsafe.Slice(base, length)); err != nil {
		return fmt.Errorf("releasing linear memory: %w", err)
	}
	return nil
}

// mapLinearMemory maps length bytes of the file fd as a linear memory. With
// guard (a wasm32 memory) the file occupies the start of a guarded
// reservation like newLinearMemory's, and everything past length faults; a
// memory64, whose accesses carry their own bounds checks, maps exactly
// length bytes. flags selects MAP_PRIVATE (copy-on-write instances) or
// MAP_SHARED (in-place image builds). The returned slice is exactly length
// long and wide; release it with releaseLinearMemory.
func mapLinearMemory(fd, length, flags int, guard bool) ([]byte, error) {
	if length <= 0 {
		// Nothing could release a mapping that its slice cannot locate.
		return nil, fmt.Errorf("linear memory of %d bytes cannot be mapped", length)
	}
	if !guardedLinearMemory || !guard {
		return mmapLinearMemory(fd, length, syscall.PROT_READ|syscall.PROT_WRITE, flags)
	}
	size := linearMemoryReserve
	if uint64(length) > size {
		return nil, fmt.Errorf("linear memory of %d bytes exceeds the %d-byte reservation", length, size)
	}
	mem, err := mmapLinearMemory(fd, int(size), syscall.PROT_NONE, flags)
	if err != nil {
		return nil, err
	}
	if err := commitLinearMemory(mem, 0, uint64(length)); err != nil {
		return nil, errors.Join(err, releaseReservation(mem))
	}
	return mem[:length:length], nil
}
