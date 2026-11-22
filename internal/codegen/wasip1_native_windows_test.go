package codegen

import (
	"os"
	"syscall"
	"testing"
)

func TestWasi_WindowsErrorsWithoutAName(t *testing.T) {
	for _, c := range []struct {
		err  syscall.Errno
		want int32
	}{
		{39, _wasiENOSPC},  // ERROR_HANDLE_DISK_FULL
		{112, _wasiENOSPC}, // ERROR_DISK_FULL
		{120, _wasiENOSYS}, // ERROR_CALL_NOT_IMPLEMENTED
		{131, _wasiEINVAL}, // ERROR_NEGATIVE_SEEK
		{10051, _wasiENETUNREACH},
		{10060, _wasiETIMEDOUT},
		{10061, _wasiECONNREFUSED},
		{10065, _wasiEHOSTUNREACH},
	} {
		if got := errnoOfError(&os.PathError{Op: "seek", Path: "x", Err: c.err}); got != c.want {
			t.Errorf("errnoOfError(%d) = %d, want %d", c.err, got, c.want)
		}
	}
}
