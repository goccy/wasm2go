package codegen

import (
	"fmt"
	"io/fs"
	"os/exec"
	"syscall"
	"testing"
)

func TestMapOSError(t *testing.T) {
	cases := []struct {
		err  error
		want int32
	}{
		{nil, _wasiESUCCESS},
		{fs.ErrNotExist, _wasiENOENT},
		{fs.ErrExist, _wasiEEXIST},
		{fs.ErrPermission, _wasiEACCES},
		{syscall.ENOTDIR, _wasiENOTDIR},
		{syscall.EISDIR, _wasiEISDIR},
		{syscall.EINVAL, _wasiEINVAL},
		{syscall.EBADF, _wasiEBADF},
		{syscall.EAGAIN, _wasiEAGAIN},
		{syscall.EPIPE, _wasiEPIPE},
		{fmt.Errorf("anything else"), _wasiEIO},
		// Wrapped errors must still map.
		{fmt.Errorf("open: %w", fs.ErrNotExist), _wasiENOENT},
	}
	for _, c := range cases {
		if got := mapOSError(c.err); got != c.want {
			t.Errorf("mapOSError(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestMapExecError(t *testing.T) {
	cases := []struct {
		err  error
		want int32
	}{
		{exec.ErrNotFound, _wasiENOENT},
		{fs.ErrNotExist, _wasiENOENT},
		{fs.ErrPermission, _wasiEACCES},
		{fmt.Errorf("other"), _wasiENOENT},
	}
	for _, c := range cases {
		if got := mapExecError(c.err); got != c.want {
			t.Errorf("mapExecError(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestEncodeWaitStatusNil(t *testing.T) {
	if got := encodeWaitStatus(nil); got != 0 {
		t.Fatalf("nil state = %d", got)
	}
}

func TestTotalBytesPlusNul(t *testing.T) {
	if n, ok := totalBytesPlusNul([]string{"ab", "c"}); !ok || n != 5 {
		t.Fatalf("got %d %v", n, ok)
	}
	if n, ok := totalBytesPlusNul(nil); !ok || n != 0 {
		t.Fatalf("empty: got %d %v", n, ok)
	}
	huge := string(make([]byte, 1<<20))
	ss := make([]string, 2048) // 2048 MiB + nuls > int32
	for i := range ss {
		ss[i] = huge
	}
	if _, ok := totalBytesPlusNul(ss); ok {
		t.Fatal("overflow not detected")
	}
}
