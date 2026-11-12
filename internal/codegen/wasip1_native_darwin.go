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

// hostPIDLimit returns the highest pid a process of the host can have
// (PID_MAX).
func hostPIDLimit() int32 { return 99999 }

// hostPriority returns the nice value of a process, a process group or a
// user of the host.
func hostPriority(which, who int) (int, error) {
	return syscall.Getpriority(which, who)
}

// setHostRESUID and setHostRESGID set the real, effective and saved ids of
// the host process. The system has no call that names the saved id: it
// follows the effective one, and only that request can be met.
func setHostRESUID(ruid, euid, suid int) error {
	if suid != -1 && suid != euid {
		return syscall.EINVAL
	}
	return syscall.Setreuid(ruid, euid)
}

func setHostRESGID(rgid, egid, sgid int) error {
	if sgid != -1 && sgid != egid {
		return syscall.EINVAL
	}
	return syscall.Setregid(rgid, egid)
}

// hostSystemName returns what uname reports: the system's name, the node's
// name, the release, the version and the machine type.
func hostSystemName() (fields [5]string, err error) {
	for i, key := range [...]string{"kern.ostype", "kern.hostname", "kern.osrelease", "kern.version", "hw.machine"} {
		if fields[i], err = syscall.Sysctl(key); err != nil {
			return fields, err
		}
	}
	return fields, nil
}
