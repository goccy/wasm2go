//go:build linux

package codegen

import (
	"syscall"
	"time"
	"unsafe"
)

// fdWritable reports whether a write to the descriptor would return at
// once: there is room, or the write would fail (the reader is gone). A
// descriptor the host cannot be asked about counts as writable; the write
// then tells.
func fdWritable(fd uintptr) bool {
	// struct pollfd, with POLLOUT requested
	request := struct {
		fd      int32
		events  int16
		revents int16
	}{fd: int32(fd), events: 0x4}
	var noWait syscall.Timespec
	for {
		n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&request)), 1,
			uintptr(unsafe.Pointer(&noWait)), 0, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		return errno != 0 || n > 0
	}
}

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atim.Unix()), time.Unix(st.Ctim.Unix())
}
