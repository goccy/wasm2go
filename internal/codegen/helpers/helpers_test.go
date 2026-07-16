package helpers

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestMemoryGrowGeometric is the regression test for the O(n^2) startup
// stall: a C++ heap issues a long run of small memory.grow calls during
// static initialization. The old memoryGrow did make+copy of the whole
// linear memory on every call, so N grows copied O(N^2) bytes. With
// geometric backing-array growth, N grows must reallocate O(log N) times.
// newTestModule mirrors what generated New() does for a plain (non-shared)
// memory: memSize — the single source of truth for sizes and bounds since the
// shared-memory work — starts at len(memory). Hand-built Modules that skip it
// see size 0 and every helper traps.
func newTestModule(memory []byte) *Module {
	m := &Module{
		memory:  memory,
		memMu:   &sync.Mutex{},
		memSize: &atomic.Uint64{},
		threads: &threadPool{},
	}
	m.memSize.Store(uint64(len(memory)))
	return m
}

func TestMemoryGrowGeometric(t *testing.T) {
	m := newTestModule(make([]byte, 65536)) // 1 page

	reallocs := 0
	prevCap := cap(m.memory)
	const grows = 1000
	for i := 0; i < grows; i++ {
		before := uint64(len(m.memory))
		ret := memoryGrow(m, 1)
		if uint64(ret)*65536 != before {
			t.Fatalf("grow %d: prev page count %d, want %d", i, ret, before/65536)
		}
		if uint64(len(m.memory)) != before+65536 {
			t.Fatalf("grow %d: len=%d want %d", i, len(m.memory), before+65536)
		}
		if cap(m.memory) != prevCap {
			reallocs++
			prevCap = cap(m.memory)
		}
	}
	if want := (grows + 1) * 65536; len(m.memory) != want {
		t.Fatalf("final len=%d want %d", len(m.memory), want)
	}
	// 1000 one-page grows under geometric growth: ~log2(1000) ≈ 10
	// reallocations. The old O(n^2) implementation reallocated 1000×.
	if reallocs > 20 {
		t.Errorf("memoryGrow reallocated %d× for %d grows — not geometric", reallocs, grows)
	}
	t.Logf("%d one-page grows -> %d reallocations", grows, reallocs)
}

// TestMemoryGrowCorrectness checks the wasm semantics memoryGrow must
// preserve regardless of the backing-array strategy.
func TestMemoryGrowCorrectness(t *testing.T) {
	m := newTestModule(make([]byte, 65536))
	m.memory[0] = 0xAB
	m.memory[65535] = 0xCD

	if got := memoryGrow(m, 3); got != 1 {
		t.Fatalf("grow: prev pages %d, want 1", got)
	}
	if len(m.memory) != 4*65536 {
		t.Fatalf("len=%d want %d", len(m.memory), 4*65536)
	}
	if m.memory[0] != 0xAB || m.memory[65535] != 0xCD {
		t.Fatal("existing data not preserved across grow")
	}
	for i := 65536; i < 4*65536; i++ {
		if m.memory[i] != 0 {
			t.Fatalf("newly grown byte %d is %#x, want 0", i, m.memory[i])
		}
	}

	// Reslice path: write into a grown page, grow again, ensure the
	// freshly exposed pages are still zero (capacity reuse must not
	// surface stale bytes).
	m.memory[3*65536] = 0xEE
	memoryGrow(m, 2)
	for i := 4 * 65536; i < 6*65536; i++ {
		if m.memory[i] != 0 {
			t.Fatalf("reslice-exposed byte %d is %#x, want 0", i, m.memory[i])
		}
	}
	if m.memory[3*65536] != 0xEE {
		t.Fatal("data lost across reslice grow")
	}

	if got := memoryGrow(m, 0); got != 6 {
		t.Fatalf("n=0: %d, want 6", got)
	}
	if got := memoryGrow(m, -1); got != -1 {
		t.Fatalf("n<0: %d, want -1", got)
	}

	lim := newTestModule(make([]byte, 65536))
	lim.maxMem = 2 * 65536
	if got := memoryGrow(lim, 5); got != -1 {
		t.Fatalf("grow past maxMem: %d, want -1", got)
	}
	if len(lim.memory) != 65536 {
		t.Fatalf("failed grow mutated memory: len=%d", len(lim.memory))
	}
}
