package wasm

import (
	"bytes"
	"runtime"
	"testing"
)

// A vector count field is bounded only by maxVectorLen (256Mi), independent of
// the section's actual payload size. A tiny module could declare a huge count
// and force the decoder to pre-allocate a large slice (make([]T, n)) before
// reading any element. Because every vec element occupies at least one byte on
// the wire, the count can never exceed the bytes remaining in the section, so
// such a module must be rejected without a large allocation.
func TestVectorCountDoS(t *testing.T) {
	// magic+version, type section (id=1) with declared payload size 4, whose
	// first bytes decode to a ~100M element count.
	data := []byte("\x00asm\x01\x00\x00\x00\x01\x04\xc4\xc4\xc40")

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := Parse(bytes.NewReader(data))
	runtime.ReadMemStats(&m1)
	mb := (m1.TotalAlloc - m0.TotalAlloc) / (1024 * 1024)

	if err == nil {
		t.Fatal("expected an error for an oversized vector count")
	}
	if mb > 16 {
		t.Fatalf("allocated %d MB parsing a 14-byte module (vector-count DoS not bounded)", mb)
	}
}
