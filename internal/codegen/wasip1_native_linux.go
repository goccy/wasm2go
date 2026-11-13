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

// awaitHostExit waits until the host process pid has ended and returns how,
// as the POSIX wait status the guest is given (see encodeWaitStatus),
// without taking the process off the process table: it stays there, its pid
// its own, until it is waited for in earnest. ended is false when the host
// could not wait that way.
func awaitHostExit(pid int) (status int32, ended bool) {
	// waitid(P_PID, pid, &info, WEXITED|WNOWAIT, NULL); package syscall has
	// the call's number and not the call. The siginfo of a child's end
	// holds si_code at offset 8 and si_status at offset 24.
	const (
		idPID      = 1
		exited     = 4
		noWait     = 0x1000000
		codeExited = 1
	)
	var info [128]byte
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, idPID, uintptr(pid),
			uintptr(unsafe.Pointer(&info[0])), exited|noWait, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, false
		}
		break
	}
	code := *(*int32)(unsafe.Pointer(&info[8]))
	value := *(*int32)(unsafe.Pointer(&info[24]))
	if code == codeExited {
		return (value & 0xff) << 8, true
	}
	// killed by a signal, with or without a core
	if sig := guestSignalOf(syscall.Signal(value)); sig != 0 {
		return sig, true
	}
	return wasiSIGKILL, true
}

// hostMonotonic reads the host's monotonic clock (CLOCK_MONOTONIC).
func hostMonotonic() (time.Duration, bool) {
	const clockMonotonic = 1
	var ts syscall.Timespec
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0, false
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec), true
}

// defaultSignalAction gives a signal its default action in the kernel,
// behind the Go runtime's back: rt_sigaction with an action of zeros, which
// is SIG_DFL with no flags and an empty mask whatever the layout of the
// structure. Package syscall has the call's number and not the call.
func defaultSignalAction(sig syscall.Signal) error {
	var action [64]byte
	const maskSize = 8 // the kernel's signal set
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(&action[0])), 0, maskSize, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// statModTime returns the modification time of a stat result.
func statModTime(st *syscall.Stat_t) time.Time { return time.Unix(st.Mtim.Unix()) }

// hostPipeBuf is PIPE_BUF: what a pipe that reports itself writable takes
// without waiting.
const hostPipeBuf = 4096

// hostFIONREAD is the ioctl request that asks how many bytes can be read.
const hostFIONREAD = 0x541B

// hostSendFlags are the flags of every send the runtime makes for the
// guest: it does not wait in the call, and a broken connection is reported
// to the guest alone (see writeFailure), not to the host process.
const hostSendFlags = syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL

// hostPollCall is poll(2): it waits no longer than timeout, and without
// limit when timeout is negative.
func hostPollCall(fds []hostPoll, timeout time.Duration) (int, syscall.Errno) {
	var limit *syscall.Timespec
	if timeout >= 0 {
		ts := syscall.NsecToTimespec(int64(timeout))
		limit = &ts
	}
	var first *hostPoll
	if len(fds) > 0 {
		first = &fds[0]
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(first)), uintptr(len(fds)),
		uintptr(unsafe.Pointer(limit)), 0, 0, 0)
	return int(n), errno
}

// hostDup2 is dup2(2) for two different descriptors.
func hostDup2(from, to int) error {
	for {
		err := syscall.Dup3(from, to, 0)
		if err != syscall.EINTR {
			return err
		}
	}
}

// hostAccept is accept(2) with the new descriptor close-on-exec.
func hostAccept(fd int) (int, error) {
	nfd, _, err := syscall.Accept4(fd, syscall.SOCK_CLOEXEC)
	return nfd, err
}
