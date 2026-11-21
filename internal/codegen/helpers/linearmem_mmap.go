//go:build unix && !linux && !darwin

package helpers

import "syscall"

// Unix hosts other than linux and darwin keep linear memory on the Go heap
// and map shared images without a reservation: nothing there confines an
// out-of-bounds guest access to the instance's own memory. See
// linearmem_guard.go for the guarded layout.

const linearMemoryReserve uint64 = 8<<30 + 64<<10

const guardedLinearMemory = false

func newLinearMemory(minBytes, capBytes uint64) (mem, reserve []byte, err error) {
	return make([]byte, minBytes, capBytes), nil, nil
}

func commitLinearMemory(reserve []byte, from, to uint64) error { return nil }

// releaseLinearMemory unmaps a mapping from mapLinearMemory. A failure means
// the slice did not come from there, which is a bug, so it panics.
func releaseLinearMemory(mem []byte) {
	if err := syscall.Munmap(mem[:cap(mem)]); err != nil {
		panic("wasm2go: releasing linear memory: " + err.Error())
	}
}

func mapLinearMemory(fd, length, flags int) ([]byte, error) {
	return syscall.Mmap(fd, 0, length, syscall.PROT_READ|syscall.PROT_WRITE, flags)
}
