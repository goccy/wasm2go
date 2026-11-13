//go:build linux

package codegen

import (
	"encoding/binary"
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

// hostBeside opens a second descriptor on the pipe fd is an end of, with an
// open file of its own in non-blocking mode, for what fd is open for, and
// places it among the runtime's own descriptors. It returns -1 when it
// cannot; never says that it never will for this descriptor (the host has
// no /proc, or does not let the process open the pipe), as opposed to not
// right now (a FIFO nobody reads from yet).
func hostBeside(fd int) (beside int, never bool) {
	flags, err := descriptorFlags(fd, syscall.F_GETFL)
	if err != nil {
		return -1, false
	}
	opened, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(fd), flags&syscall.O_ACCMODE|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err != syscall.ENXIO && err != syscall.EINTR && err != syscall.EMFILE && err != syscall.ENFILE
	}
	beside, err = hostDup(opened, hostFloor())
	_ = syscall.Close(opened)
	if err != nil {
		return -1, false
	}
	return beside, false
}

// hostPipeRoom returns how much a pipe that reports itself writable takes
// without waiting, as far as the host says: PIPE_BUF.
func hostPipeRoom(fd int) int { return hostPipeBuf }

// hostFIONREAD is the ioctl request that asks how many bytes can be read.
const hostFIONREAD = 0x541B

// hostTerminal is isatty(3): a terminal answers the request for its
// settings.
func hostTerminal(fd int) bool {
	var settings syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&settings)))
	return errno == 0
}

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

// hostDescriptorPath returns the path of the file a descriptor is open on,
// where the host tells.
func hostDescriptorPath(fd int) (string, bool) {
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(path, "/") {
		return "", false
	}
	return path, true
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

// hostGenericTerminal reports whether this architecture numbers what belongs
// to a terminal — the requests, the bits of the flag words, the places of
// the control characters, the speeds — the way most architectures of linux
// do (asm-generic): the numbers the guest's own header has. The others
// (powerpc, mips) have numbers of their own; a guest is refused the
// settings of a terminal there, rather than given them under numbers that
// mean something else.
const hostGenericTerminal = syscall.TCGETS == 0x5401

// Requests about a terminal's settings that package syscall does not have
// on every architecture, as asm-generic numbers them, and the bits of
// c_cflag that hold the speed (CBAUD).
const (
	genericTCSBRK  = 0x5409
	genericTCXONC  = 0x540a
	genericTCFLSH  = 0x540b
	genericTCSBRKP = 0x5425
	genericCBAUD   = 0x100f
)

// hostTerminalRequest reports whether request is one of the terminal's:
// linux numbers those in the group of TIOCSCTTY (0x54) and, on the
// architectures that took numbers from BSD, in the groups TIOCGWINSZ and
// TCGETS are in.
func hostTerminalRequest(request uint32) bool {
	group := byte(request >> 8)
	return group == byte(syscall.TIOCSCTTY>>8&0xff) || group == byte(syscall.TIOCGWINSZ>>8&0xff) || group == byte(syscall.TCGETS>>8&0xff)
}

// hostIoctlRoom returns how large the buffer of a request has to be. The
// requests of a terminal do not say how much they read or write here; none
// reads or writes more than this.
func hostIoctlRoom(request uint32) int { return 256 }

// hostTerminalAttributes is tcgetattr(3) into the guest's record.
func hostTerminalAttributes(fd int, record []byte) error {
	if !hostGenericTerminal {
		return syscall.ENOSYS
	}
	var t syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&t))); errno != 0 {
		return errno
	}
	binary.LittleEndian.PutUint32(record[guestTermiosIflag:], t.Iflag)
	binary.LittleEndian.PutUint32(record[guestTermiosOflag:], t.Oflag)
	binary.LittleEndian.PutUint32(record[guestTermiosCflag:], t.Cflag)
	binary.LittleEndian.PutUint32(record[guestTermiosLflag:], t.Lflag)
	record[guestTermiosLine] = t.Line
	cc := record[guestTermiosCc : guestTermiosCc+guestTermiosNCCS]
	clear(cc)
	copy(cc, t.Cc[:])
	// The speed is in c_cflag; the C library keeps it in these two as
	// well.
	binary.LittleEndian.PutUint32(record[guestTermiosIspeed:], t.Cflag&genericCBAUD)
	binary.LittleEndian.PutUint32(record[guestTermiosOspeed:], t.Cflag&genericCBAUD)
	return nil
}

// setHostTerminalAttributes is tcsetattr(3) from the guest's record:
// actions is TCSANOW, TCSADRAIN or TCSAFLUSH.
func setHostTerminalAttributes(fd int, actions int32, record []byte) error {
	if !hostGenericTerminal {
		return syscall.ENOSYS
	}
	if actions < 0 || actions > 2 {
		return syscall.EINVAL
	}
	t := syscall.Termios{
		Iflag: binary.LittleEndian.Uint32(record[guestTermiosIflag:]),
		Oflag: binary.LittleEndian.Uint32(record[guestTermiosOflag:]),
		Cflag: binary.LittleEndian.Uint32(record[guestTermiosCflag:]),
		Lflag: binary.LittleEndian.Uint32(record[guestTermiosLflag:]),
		Line:  record[guestTermiosLine],
	}
	copy(t.Cc[:], record[guestTermiosCc:guestTermiosCc+guestTermiosNCCS])
	// TCSETS, TCSETSW and TCSETSF follow one another.
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS+int(actions)), uintptr(unsafe.Pointer(&t)))
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}

// hostTerminalSpeed is cfgetispeed(3) and cfgetospeed(3) on the guest's
// record: the speed is the one in c_cflag, for input as for output.
func hostTerminalSpeed(record []byte, output bool) uint32 {
	return binary.LittleEndian.Uint32(record[guestTermiosCflag:]) & genericCBAUD
}

// setHostTerminalSpeed is cfsetispeed(3) and cfsetospeed(3) on the guest's
// record. An input speed of 0 is the output's, and changes nothing.
func setHostTerminalSpeed(record []byte, output bool, speed uint32) error {
	if !hostGenericTerminal {
		return syscall.ENOSYS
	}
	if speed&^genericCBAUD != 0 {
		return syscall.EINVAL
	}
	if !output && speed == 0 {
		return nil
	}
	cflag := binary.LittleEndian.Uint32(record[guestTermiosCflag:])&^genericCBAUD | speed
	binary.LittleEndian.PutUint32(record[guestTermiosCflag:], cflag)
	binary.LittleEndian.PutUint32(record[guestTermiosIspeed:], speed)
	binary.LittleEndian.PutUint32(record[guestTermiosOspeed:], speed)
	return nil
}

// hostTerminalControl is tcdrain(3), tcflow(3), tcflush(3) and
// tcsendbreak(3), in the order of terminalDrain: arg is the action of
// tcflow, the queue of tcflush, the duration of tcsendbreak.
func hostTerminalControl(fd int, what, arg int32) error {
	if !hostGenericTerminal {
		return syscall.ENOSYS
	}
	var err error
	switch what {
	case terminalDrain:
		_, err = hostIoctlValue(fd, genericTCSBRK, 1)
	case terminalFlow:
		_, err = hostIoctlValue(fd, genericTCXONC, uintptr(arg))
	case terminalFlush:
		_, err = hostIoctlValue(fd, genericTCFLSH, uintptr(arg))
	case terminalBreak:
		if arg <= 0 {
			_, err = hostIoctlValue(fd, genericTCSBRK, 0)
		} else {
			_, err = hostIoctlValue(fd, genericTCSBRKP, uintptr(arg))
		}
	default:
		err = syscall.EINVAL
	}
	return err
}

// hostOpenTakesTerminal: a process that leads a session and has no
// controlling terminal gets the terminal it opens for one here, unless it
// opens it with O_NOCTTY.
const hostOpenTakesTerminal = true

// hostTerminalOfMaster returns the path of the terminal whose master side
// fd is; ok is false for any other descriptor. Only the master side says
// which pseudo-terminal it is (TIOCGPTN), and it is never a controlling
// terminal itself.
func hostTerminalOfMaster(fd int) (path string, ok bool) {
	const number = 0x80045430 // TIOCGPTN
	var n [4]byte
	if _, err := hostIoctlBuffer(fd, number, n[:]); err != nil {
		return "", false
	}
	return "/dev/pts/" + strconv.Itoa(int(binary.NativeEndian.Uint32(n[:]))), true
}
