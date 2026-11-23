//go:build darwin || linux

package codegen

import (
	"testing"

	"golang.org/x/sys/unix"
)

// HostMonotonicClock reads the host's clock that the Go runtime's timers
// count: a reading falls between two of the host's own, taken before and
// after it.
func TestHostMonotonicClock(t *testing.T) {
	host := func() uint64 {
		t.Helper()
		var ts unix.Timespec
		if err := unix.ClockGettime(hostMonotonicClockID, &ts); err != nil {
			t.Fatal(err)
		}
		return uint64(ts.Nano())
	}
	read := HostMonotonicClock()
	before := host()
	got := read()
	after := host()
	if got < before || got > after {
		t.Fatalf("HostMonotonicClock read %d, not within the host's %d..%d", got, before, after)
	}
}
