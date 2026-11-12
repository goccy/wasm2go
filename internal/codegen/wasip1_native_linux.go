//go:build linux

package codegen

import (
	"os"
	"strconv"
	"strings"
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

// hostPIDLimit returns the highest pid a process of the host can have.
func hostPIDLimit() int32 {
	// What the kernel is built to allow at most; the limit in force
	// (kernel.pid_max) is this or less.
	limit := int32(1 << 22)
	if raw, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32); err == nil && n > 0 {
			limit = int32(n)
		}
	}
	return limit
}

// hostPriority returns the nice value of a process, a process group or a
// user of the host. The system call reports it as 20 minus the value.
func hostPriority(which, who int) (int, error) {
	raw, err := syscall.Getpriority(which, who)
	if err != nil {
		return 0, err
	}
	return 20 - raw, nil
}

// setHostRESUID and setHostRESGID set the real, effective and saved ids of
// the host process.
func setHostRESUID(ruid, euid, suid int) error { return syscall.Setresuid(ruid, euid, suid) }

func setHostRESGID(rgid, egid, sgid int) error { return syscall.Setresgid(rgid, egid, sgid) }

// hostSystemName returns what uname reports: the system's name, the node's
// name, the release, the version and the machine type.
func hostSystemName() (fields [5]string, err error) {
	var name syscall.Utsname
	if err := syscall.Uname(&name); err != nil {
		return fields, err
	}
	for i, raw := range [...][]int8{name.Sysname[:], name.Nodename[:], name.Release[:], name.Version[:], name.Machine[:]} {
		var text []byte
		for _, c := range raw {
			if c == 0 {
				break
			}
			text = append(text, byte(c))
		}
		fields[i] = string(text)
	}
	return fields, nil
}
