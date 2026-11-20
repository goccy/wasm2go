//go:build !unix

package helpers

// Platforms without mmap keep linear memory on the Go heap. Nothing there
// confines an out-of-bounds guest access to the instance's own memory; see
// linearmem_guard.go for the guarded layout.

const linearMemoryReserve uint64 = 8<<30 + 64<<10

const guardedLinearMemory = false

func newLinearMemory(minBytes, capBytes uint64) (mem, reserve []byte, err error) {
	return make([]byte, minBytes, capBytes), nil, nil
}

func commitLinearMemory(reserve []byte, from, to uint64) error { return nil }

func releaseLinearMemory(mem []byte) {}
