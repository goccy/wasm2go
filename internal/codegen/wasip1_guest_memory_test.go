package codegen

import (
	"bytes"
	"sync/atomic"
	"testing"
)

// newGuestModule returns a stand-in Module whose memory is size bytes long,
// all of it the guest's (memSize is size).
func newGuestModule(size int) *Module {
	m := &Module{memory: make([]byte, size), memSize: &atomic.Uint64{}}
	m.memSize.Store(uint64(size))
	return m
}

// newSharedGuestModule returns a stand-in Module laid out as a shared
// memory is: the slice spans the memory's ceiling, of which the guest's
// memory is the first size bytes.
func newSharedGuestModule(size, ceiling int) *Module {
	m := &Module{memory: make([]byte, ceiling), memSize: &atomic.Uint64{}}
	m.memSize.Store(uint64(size))
	return m
}

// The stubs bound a guest address by the guest's memory size, not by the
// length of the memory slice: on a memory whose slice runs past memSize (a
// shared memory's spans its ceiling), a buffer at memSize is refused, a C
// string whose NUL lies past memSize is unterminated, and the signal flag
// word at memSize is not written. Once memSize grows over them they are the
// guest's.
func TestWasiGuestMemoryBoundedByMemSize(t *testing.T) {
	const size, ceiling = 1 << 16, 4 << 16
	w := &WasiStubs{}
	m := newSharedGuestModule(size, ceiling)

	if b := w.memBytes(m, size-1, 1); len(b) != 1 {
		t.Errorf("memBytes below memSize = %v, want one byte", b)
	}
	if b := w.memBytes(m, size, 1); b != nil {
		t.Errorf("memBytes at memSize = %v, want nil", b)
	}
	if b := w.memBytes(m, size-1, 2); b != nil {
		t.Errorf("memBytes across memSize = %v, want nil", b)
	}
	if rc := w.Random_get(m, size, 1); rc != _wasiEFAULT {
		t.Errorf("random_get at memSize = %d, want EFAULT", rc)
	}

	// "path" ends at memSize; the NUL after it is past the guest's memory.
	copy(m.memory[size-4:], "path")
	if s, ok := w.readCStr(m, size-4); ok {
		t.Errorf("readCStr of a string unterminated within memSize = %q, ok", s)
	}

	w.sig.flagModule, w.sig.flagAddr = m, size
	w.raiseSignalFlag()
	if !bytes.Equal(m.memory[size:size+4], make([]byte, 4)) {
		t.Errorf("the flag word past memSize was written: % x", m.memory[size:size+4])
	}

	// The guest's memory grows over all three.
	m.memSize.Store(2 * size)
	if b := w.memBytes(m, size, 1); len(b) != 1 {
		t.Errorf("memBytes at the old memSize after growth = %v, want one byte", b)
	}
	if rc := w.Random_get(m, size, 1); rc != _wasiESUCCESS {
		t.Errorf("random_get at the old memSize after growth = %d, want success", rc)
	}
	m.memory[size] = 0
	if s, ok := w.readCStr(m, size-4); !ok || s != "path" {
		t.Errorf("readCStr after growth = %q, %v, want \"path\", true", s, ok)
	}
	w.raiseSignalFlag()
	if got := m.memory[size]; got != 1 {
		t.Errorf("the flag word after growth = %d, want 1", got)
	}
}
