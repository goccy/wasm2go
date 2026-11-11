//go:build darwin

package codegen

import (
	"syscall"
	"time"
)

// fdWritable reports whether a write to the descriptor would return at
// once: there is room, or the write would fail (the reader is gone). A
// descriptor the host cannot be asked about — one beyond what select(2)
// takes — counts as writable; the write then tells.
func fdWritable(fd uintptr) bool {
	// select(2) here reports the read end of a pipe writable. A descriptor
	// that is not open for writing refuses even a write of nothing (EBADF),
	// which is how to tell; a socket is always open both ways, and is not
	// asked this way, because writing nothing to a datagram socket sends
	// an empty datagram.
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err == nil && st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		if _, err := syscall.Write(int(fd), nil); err == syscall.EBADF {
			return false
		}
	}
	var set syscall.FdSet
	word, bit := fd/32, int32(1)<<(fd%32)
	if word >= uintptr(len(set.Bits)) {
		return true
	}
	for {
		set.Bits[word] = bit
		var noWait syscall.Timeval
		err := syscall.Select(int(fd)+1, nil, &set, nil, &noWait)
		if err == syscall.EINTR {
			continue
		}
		return err != nil || set.Bits[word]&bit != 0
	}
}

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atimespec.Unix()), time.Unix(st.Ctimespec.Unix())
}
