//go:build darwin

package codegen

import (
	"errors"
	"syscall"
	"testing"
)

// dupTo makes descriptor to a duplicate of from, closing what it was.
func dupTo(from, to int) error { return syscall.Dup2(from, to) }

// darwin makes getrandom by getentropy, 256 bytes a call, and refuses what
// Linux refuses.
func TestHostSyscalls_GetrandomOfDarwin(t *testing.T) {
	calls := HostSyscalls()
	mem := make([]byte, 1024)
	n, err := calls.Syscall(Syscall{Number: linuxSysGetrandom, Args: [6]uint64{100, 600, linuxGrndNonblock}, Pointers: 0b001, Memory: mem})
	if err != nil || n != 600 {
		t.Fatalf("getrandom of 600 bytes: %d %v", n, err)
	}
	// Each getentropy call fills a run of at most 256 bytes; a run left as
	// it was, all zeros, is one the loop did not ask for (a filled run of 88
	// bytes is all zeros with a chance of 2^-704).
	for _, run := range [][]byte{mem[100:356], mem[356:612], mem[612:700]} {
		if string(run) == string(make([]byte, len(run))) {
			t.Fatalf("getrandom left a run of %d bytes unfilled", len(run))
		}
	}
	for _, tc := range []struct {
		args     [6]uint64
		pointers uint32
		want     error
	}{
		{[6]uint64{0, 8, 0x8}, 0b001, syscall.EINVAL},
		{[6]uint64{0, 8, linuxGrndRandom | linuxGrndInsecure}, 0b001, syscall.EINVAL},
		{[6]uint64{1000, 25, 0}, 0b001, syscall.EFAULT},
		{[6]uint64{0, 8, 0}, 0, syscall.EFAULT},
	} {
		if _, err := calls.Syscall(Syscall{Number: linuxSysGetrandom, Args: tc.args, Pointers: tc.pointers, Memory: mem}); !errors.Is(err, tc.want) {
			t.Errorf("getrandom %v, pointers %#b: %v, want %v", tc.args[:3], tc.pointers, err, tc.want)
		}
	}
	if n, err := calls.Syscall(Syscall{Number: linuxSysGetrandom, Memory: mem}); err != nil || n != 0 {
		t.Fatalf("getrandom of no bytes: %d %v", n, err)
	}
}
