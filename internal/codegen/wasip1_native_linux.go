//go:build linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

// The structures of Linux's C library for the socket addresses: the family
// is the first two bytes, in the host's byte order, the port is in network
// byte order; a Unix-domain socket has room for a name of 108 bytes.
const (
	linuxSockaddrInet4Size = 16
	linuxSockaddrInet6Size = 28
	// The size of struct sockaddr_in6 before it had the scope id
	// (SIN6_LEN_RFC2133), which the kernel still takes.
	linuxSockaddrInet6OldSize = 24
	linuxSockaddrUnixPath     = 2
	linuxSockaddrUnixSize     = linuxSockaddrUnixPath + 108
)

// hostSockaddrBytes renders a as struct sockaddr_in, sockaddr_in6 or
// sockaddr_un of the host's C library, with the length such an address
// has: the whole structure for an IP address and for a Unix-domain socket
// with a path; the family and the name for an abstract name (one that
// starts with a NUL); the family alone for a socket without a name. nil
// for a record of no family the host has.
func hostSockaddrBytes(a wasiSockAddr) []byte {
	switch a.family {
	case wasiSockFamilyIPv4:
		raw := make([]byte, linuxSockaddrInet4Size)
		binary.NativeEndian.PutUint16(raw[0:], syscall.AF_INET)
		binary.BigEndian.PutUint16(raw[2:], uint16(a.port))
		copy(raw[4:8], a.ip.To4())
		return raw
	case wasiSockFamilyIPv6:
		raw := make([]byte, linuxSockaddrInet6Size)
		binary.NativeEndian.PutUint16(raw[0:], syscall.AF_INET6)
		binary.BigEndian.PutUint16(raw[2:], uint16(a.port))
		copy(raw[8:24], a.ip.To16())
		binary.NativeEndian.PutUint32(raw[24:], a.scope)
		return raw
	case wasiSockFamilyUnix:
		if len(a.name) > linuxSockaddrUnixSize-linuxSockaddrUnixPath {
			return nil
		}
		raw := make([]byte, linuxSockaddrUnixSize)
		binary.NativeEndian.PutUint16(raw[0:], syscall.AF_UNIX)
		copy(raw[linuxSockaddrUnixPath:], a.name)
		if a.name == "" || a.name[0] == 0 {
			return raw[:linuxSockaddrUnixPath+len(a.name)]
		}
		return raw
	}
	return nil
}

// sockAddrOfHostBytes reads a struct sockaddr of the host's C library, as
// hostSockaddrBytes writes it. It reports EAFNOSUPPORT for a family the
// records have no form for, EINVAL for bytes too few for their family (as
// the kernel takes them).
func sockAddrOfHostBytes(raw []byte) (wasiSockAddr, int32) {
	if len(raw) < 2 {
		return wasiSockAddr{}, _wasiEINVAL
	}
	switch binary.NativeEndian.Uint16(raw[0:]) {
	case syscall.AF_INET:
		if len(raw) < linuxSockaddrInet4Size {
			return wasiSockAddr{}, _wasiEINVAL
		}
		return wasiSockAddr{family: wasiSockFamilyIPv4, port: int(binary.BigEndian.Uint16(raw[2:])),
			ip: append(net.IP(nil), raw[4:8]...)}, _wasiESUCCESS
	case syscall.AF_INET6:
		if len(raw) < linuxSockaddrInet6OldSize {
			return wasiSockAddr{}, _wasiEINVAL
		}
		a := wasiSockAddr{family: wasiSockFamilyIPv6, port: int(binary.BigEndian.Uint16(raw[2:])),
			ip: append(net.IP(nil), raw[8:24]...)}
		if len(raw) >= linuxSockaddrInet6Size {
			a.scope = binary.NativeEndian.Uint32(raw[24:])
		}
		return a, _wasiESUCCESS
	case syscall.AF_UNIX:
		name := raw[linuxSockaddrUnixPath:]
		if len(name) > linuxSockaddrUnixSize-linuxSockaddrUnixPath {
			name = name[:linuxSockaddrUnixSize-linuxSockaddrUnixPath]
		}
		if len(name) > 0 && name[0] != 0 {
			// a path ends at its first NUL; an abstract name is every byte
			if end := bytes.IndexByte(name, 0); end >= 0 {
				name = name[:end]
			}
		}
		return wasiSockAddr{family: wasiSockFamilyUnix, name: string(name)}, _wasiESUCCESS
	}
	return wasiSockAddr{}, _wasiEAFNOSUPPORT
}

// hostInterruptSignal is the host signal that ends a system call which the
// runtime makes for the guest and which waits in the kernel (see
// interruptibleHostCall): the last real-time signal, which neither the Go
// runtime nor the C library takes for itself, and which no signal of the
// guest is relayed as.
const hostInterruptSignal = 64

// hostKernelSigaction is struct sigaction as the kernel's rt_sigaction takes
// it on the architectures hostInterruptReady names. On those without
// SA_RESTORER the mask comes third; it is only read and written back as it
// was, so the same layout serves.
type hostKernelSigaction struct {
	handler  uintptr
	flags    uintptr
	restorer uintptr
	mask     uint64
}

const hostSARestart = 0x10000000

// hostInterruptReady reports whether hostInterruptSignal can end a system
// call; the first call makes it so.
//
// The Go runtime has its handler installed for the signal, with SA_RESTART:
// a system call it interrupts would be restarted, which is what the runtime
// wants of the signals it handles itself. For this signal it handles nothing
// (nobody asks for it, and the handler returns at once), so the flag is taken
// off its installation: the handler stays, and a system call the signal
// interrupts fails with EINTR, or returns what it has done so far. A signal
// without the runtime's handler is not used: its default action ends the
// process.
var hostInterruptReady = sync.OnceValue(func() bool {
	switch runtime.GOARCH {
	case "amd64", "arm64", "riscv64", "loong64", "ppc64", "ppc64le", "s390x":
	default:
		return false
	}
	var act hostKernelSigaction
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, hostInterruptSignal,
		0, uintptr(unsafe.Pointer(&act)), unsafe.Sizeof(act.mask), 0, 0); errno != 0 {
		return false
	}
	const sigDFL, sigIGN = 0, 1
	if act.handler == sigDFL || act.handler == sigIGN {
		return false
	}
	if act.flags&hostSARestart == 0 {
		return true
	}
	act.flags &^= hostSARestart
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, hostInterruptSignal,
		uintptr(unsafe.Pointer(&act)), 0, unsafe.Sizeof(act.mask), 0, 0)
	return errno == 0
})

// hostThreadSelf returns the thread the caller runs on (its OS thread
// locked), for interruptHostThread; ok is false where a system call cannot
// be interrupted.
func hostThreadSelf() (thread uint64, ok bool) {
	if !hostInterruptReady() {
		return 0, false
	}
	return uint64(syscall.Gettid()), true
}

// interruptHostThread sends hostInterruptSignal to the thread.
func interruptHostThread(thread uint64) {
	_ = syscall.Tgkill(syscall.Getpid(), int(thread), syscall.Signal(hostInterruptSignal))
}

// hostHostByName would look a host up as the C library's gethostbyname
// does, which the runtime has no C library to call for here: asked is
// false, and Sock_host_by_name asks the runtime's resolver.
func hostHostByName(name string) (official string, addrs [][4]byte, asked bool) {
	return "", nil, false
}

// hostAccess asks the host whether the process may make the accesses of
// amode (access's bits) to the file at path, with its effective ids or its
// real ones: faccessat(2). asked is true: the host can always say.
func hostAccess(path string, amode uint32, effective bool) (errno int32, asked bool) {
	flags := 0
	if effective {
		flags = hostATEAccess
	}
	if err := syscall.Faccessat(hostATFDCWD, path, amode, flags); err != nil {
		return mapOSError(err), true
	}
	return _wasiESUCCESS, true
}

// faccessat's AT_FDCWD and AT_EACCESS on this system.
const (
	hostATFDCWD   = -100
	hostATEAccess = 0x200
)

// kernelSigaction is struct sigaction as the kernel's rt_sigaction takes it
// on amd64 and arm64.
type kernelSigaction struct {
	handler  uintptr
	flags    uint64
	restorer uintptr
	mask     uint64
}

// hostSignalAction returns the kernel's action for the host signal.
// signalHostSelf sends the host process a signal the way perl's kill of
// its own pid has it delivered: to the thread that sends it, so that the
// handler native code installed for it (an event loop's signal watcher)
// has run by the time the call returns, as it has in a process of one
// thread. Sent to the process, any of the runtime's threads would take it,
// some time later.
func signalHostSelf(sig syscall.Signal) error {
	return syscall.Tgkill(os.Getpid(), syscall.Gettid(), sig)
}

func hostSignalAction(sig syscall.Signal) (act kernelSigaction, ok bool) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return act, false
	}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), 0,
		uintptr(unsafe.Pointer(&act)), unsafe.Sizeof(act.mask), 0, 0)
	return act, errno == 0
}

// hostSignalIgnored reports whether the host process ignores the host signal
// (its action is SIG_IGN).
func hostSignalIgnored(sig syscall.Signal) bool {
	const sigIGN = 1
	act, ok := hostSignalAction(sig)
	return ok && act.handler == sigIGN
}

// hostActionsOutside returns the actions of the host process's signals that
// code outside the runtime made its own: a handler of a native library
// (libev's, an rsignal of a module), installed after the Go runtime
// installed its own for every signal. They are told apart by the handler:
// the Go runtime has one for all the signals it takes, which is its handler
// of SIGURG (the signal it preempts goroutines with, always its own). nil
// when there are none, or where the kernel cannot be asked.
func hostActionsOutside() map[syscall.Signal]kernelSigaction {
	own, ok := hostSignalAction(syscall.SIGURG)
	const sigIGN = 1
	if !ok || own.handler <= sigIGN {
		return nil
	}
	var outside map[syscall.Signal]kernelSigaction
	for sig := syscall.Signal(1); sig < 65; sig++ {
		if sig == syscall.SIGKILL || sig == syscall.SIGSTOP {
			continue
		}
		if act, ok := hostSignalAction(sig); ok && act.handler > sigIGN && act.handler != own.handler {
			if outside == nil {
				outside = map[syscall.Signal]kernelSigaction{}
			}
			outside[sig] = act
		}
	}
	return outside
}

// takeHostSignalBack makes the Go runtime's handler the host process's
// action of the signal again when code outside the runtime made a handler of
// its own the action. os/signal cannot: the Go runtime installs its handler
// only for a signal it does not handle already, and it handles every signal
// from its start, whatever was installed over its handler since. Its action
// is the one it has for SIGURG (see hostActionsOutside).
func takeHostSignalBack(sig syscall.Signal) {
	own, ok := hostSignalAction(syscall.SIGURG)
	const sigIGN = 1
	if !ok || own.handler <= sigIGN {
		return
	}
	if act, ok := hostSignalAction(sig); !ok || act.handler <= sigIGN || act.handler == own.handler {
		return
	}
	_, _, _ = syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(&own)), 0, unsafe.Sizeof(own.mask), 0, 0)
}

// hostChildSignalTakenOutside reports whether code outside the runtime made
// a handler of its own the host process's action of SIGCHLD (see
// hostActionsOutside): libev's default loop makes one when EV loads, and
// takeHostSignalBack gives the signal back to the runtime when the guest
// sets what it does with it afterwards.
func hostChildSignalTakenOutside() bool {
	own, ok := hostSignalAction(syscall.SIGURG)
	const sigIGN = 1
	if !ok || own.handler <= sigIGN {
		return false
	}
	act, ok := hostSignalAction(syscall.SIGCHLD)
	return ok && act.handler > sigIGN && act.handler != own.handler
}

// restoreHostActionsOutside puts the actions hostActionsOutside returned
// back, after the Go runtime has installed its own handler for a signal
// again (os/signal does that when a program asks for a signal, and when it
// stops asking).
func restoreHostActionsOutside(outside map[syscall.Signal]kernelSigaction) {
	for sig, act := range outside {
		act := act
		_, _, _ = syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig),
			uintptr(unsafe.Pointer(&act)), 0, unsafe.Sizeof(act.mask), 0, 0)
	}
}

// hostRawSyscall makes the system call number with args, an argument whose
// bit is set in ptrs being the offset of a byte of mem, which the call is
// given the address of (see Sys_syscall).
func hostRawSyscall(number uintptr, args [6]uint64, ptrs uint32, mem []byte) (uintptr, error) {
	var a [6]uintptr
	for i, v := range args {
		if ptrs&(1<<i) != 0 {
			a[i] = uintptr(unsafe.Pointer(&mem[v]))
		} else {
			a[i] = uintptr(v)
		}
	}
	r, _, errno := syscall.Syscall6(number, a[0], a[1], a[2], a[3], a[4], a[5])
	runtime.KeepAlive(mem)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

// ----- System V IPC (see wasip1_native_ipc.go) ------------------------------

// The system calls of the C library's calls of System V IPC.
var ipcSyscall = [...]uintptr{
	ipcOpMsgget: syscall.SYS_MSGGET, ipcOpSemget: syscall.SYS_SEMGET, ipcOpShmget: syscall.SYS_SHMGET,
	ipcOpMsgctl: syscall.SYS_MSGCTL, ipcOpSemctl: syscall.SYS_SEMCTL, ipcOpShmctl: syscall.SYS_SHMCTL,
	ipcOpSemop: syscall.SYS_SEMOP, ipcOpMsgsnd: syscall.SYS_MSGSND, ipcOpMsgrcv: syscall.SYS_MSGRCV,
	ipcOpShmat: syscall.SYS_SHMAT, ipcOpShmdt: syscall.SYS_SHMDT,
}

// ipcCall makes the call op with the arguments (at most five).
func ipcCall(op int, args ...uintptr) (uintptr, error) {
	var a [5]uintptr
	copy(a[:], args)
	r, _, errno := syscall.Syscall6(ipcSyscall[op], a[0], a[1], a[2], a[3], a[4], 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

// ipcHostCommand is the host's number of the guest's command: Linux's are
// the guest's.
func ipcHostCommand(cmd int32) int32 { return cmd }

// shmat's SHM_RDONLY.
const ipcHostShmRdonly = 010000

// The kernel's structures of a 64-bit architecture (asm-generic's
// ipc64_perm, msqid64_ds, semid64_ds and shmid64_ds), which the guest's
// are laid out as; x86-64 has a semid64_ds of its own, with a word after
// each time.
var (
	ipcLinuxPerm = ipcField{0, 48, 0, 48}
	ipcLinuxMsg  = ipcHostStruct{120, []ipcField{ipcLinuxPerm, {48, 48, 48, 48}, {96, 8, 96, 8}}}
	ipcLinuxShm  = ipcHostStruct{112, []ipcField{ipcLinuxPerm, {48, 8, 48, 8}, {56, 24, 56, 24}, {80, 8, 80, 8}, {88, 8, 88, 8}}}
	ipcLinuxSem  = ipcHostStruct{88, []ipcField{ipcLinuxPerm, {48, 16, 48, 16}, {64, 8, 64, 8}}}
	// otime, a word, ctime, a word, nsems
	ipcLinuxSemAMD64 = ipcHostStruct{104, []ipcField{ipcLinuxPerm, {48, 8, 48, 8}, {56, 8, 64, 8}, {64, 8, 80, 8}}}
)

// ipcHostLayout is the kernel's structure of the kind.
func ipcHostLayout(kind int32) ipcHostStruct {
	switch kind {
	case ipcKindMsg:
		return ipcLinuxMsg
	case ipcKindShm:
		return ipcLinuxShm
	}
	if runtime.GOARCH == "amd64" {
		return ipcLinuxSemAMD64
	}
	return ipcLinuxSem
}
