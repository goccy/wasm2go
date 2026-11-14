//go:build darwin

package codegen

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
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

// awaitHostExit waits until a host process has ended without taking it off
// the process table, which the runtime cannot do on this platform: ended is
// false, and the process is waited for at once.
func awaitHostExit(pid int) (status int32, ended bool) { return 0, false }

// The host's monotonic clock counts from the start of the system. The
// system says when it started (kern.boottime), and the Go runtime measures
// the time since this process first asked: the reading is the one plus the
// other. systemUptime is the time the system had been up at processClock.
var (
	uptimeOnce   sync.Once
	processClock time.Time
	systemUptime time.Duration
	uptimeKnown  bool
)

// hostMonotonic reads the host's monotonic clock (CLOCK_MONOTONIC).
func hostMonotonic() (time.Duration, bool) {
	uptimeOnce.Do(func() {
		// a struct timeval: seconds and microseconds, 8 bytes each
		raw, err := syscall.Sysctl("kern.boottime")
		if err != nil || len(raw) < 12 {
			return
		}
		// Sysctl takes the value for a string and drops a trailing NUL.
		buf := make([]byte, 16)
		copy(buf, raw)
		booted := time.Unix(int64(binary.LittleEndian.Uint64(buf[0:])), int64(binary.LittleEndian.Uint32(buf[8:]))*1000)
		processClock = time.Now()
		systemUptime = processClock.Sub(booted)
		uptimeKnown = systemUptime > 0
	})
	if !uptimeKnown {
		return 0, false
	}
	return systemUptime + time.Since(processClock), true
}

// defaultSignalAction gives a signal its default action in the kernel,
// behind the Go runtime's back: sigaction with an action of zeros, which is
// SIG_DFL with no flags and an empty mask. Package syscall has the call's
// number and not the call.
func defaultSignalAction(sig syscall.Signal) error {
	var action [64]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(&action[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// statModTime returns the modification time of a stat result.
func statModTime(st *syscall.Stat_t) time.Time { return time.Unix(st.Mtimespec.Unix()) }

// hostPipeBuf is PIPE_BUF: what a pipe that reports itself writable takes
// without waiting.
const hostPipeBuf = 512

// hostBeside would open a second descriptor on a pipe with an open file of
// its own. This host has no way: opening the descriptor's name in /dev/fd
// duplicates the descriptor, open file and mode included.
func hostBeside(fd int) (beside int, never bool) { return -1, true }

// hostPipeRoom returns how much a pipe that reports itself writable takes
// without waiting. fstat of a pipe says here how large its buffer is and
// how much of it is filled; what is not filled is taken at once. When the
// answer is not within what a pipe can hold, the room is PIPE_BUF, which a
// writable pipe has for certain.
func hostPipeRoom(fd int) int {
	const largest = 64 << 10 // BIG_PIPE_SIZE
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return hostPipeBuf
	}
	room := int64(st.Blksize) - st.Size
	if room < hostPipeBuf || room > largest {
		return hostPipeBuf
	}
	return int(room)
}

// hostFIONREAD is the ioctl request that asks how many bytes can be read.
const hostFIONREAD = 0x4004667f

// hostTerminal is isatty(3), which asks the device for its type here
// (FIODTYPE): the master side of a pseudo-terminal is a terminal to it
// before it answers a request for terminal settings.
func hostTerminal(fd int) bool {
	const (
		deviceType     = 0x4004667a // FIODTYPE
		deviceTerminal = 3          // D_TTY
	)
	var kind int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), deviceType, uintptr(unsafe.Pointer(&kind)))
	return errno == 0 && kind == deviceTerminal
}

// hostSendFlags are the flags of every send the runtime makes for the
// guest: it does not wait in the call. (A broken connection raises SIGPIPE
// in the host process as well as the error; the Go runtime ignores it.)
const hostSendFlags = syscall.MSG_DONTWAIT

// hostPollCall is poll(2): it waits no longer than timeout, and without
// limit when timeout is negative.
func hostPollCall(fds []hostPoll, timeout time.Duration) (int, syscall.Errno) {
	ms := -1
	if timeout >= 0 {
		ms = int((timeout + time.Millisecond - 1) / time.Millisecond)
	}
	var first *hostPoll
	if len(fds) > 0 {
		first = &fds[0]
	}
	n, _, errno := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(first)), uintptr(len(fds)), uintptr(ms))
	return int(n), errno
}

// hostDescriptorPath returns the path of the file a descriptor is open on,
// where the host tells.
func hostDescriptorPath(fd int) (string, bool) {
	var buf [1024]byte // MAXPATHLEN
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", false
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i]), i > 0
		}
	}
	return "", false
}

// hostDup2 is dup2(2) for two different descriptors.
func hostDup2(from, to int) error {
	for {
		err := syscall.Dup2(from, to)
		if err != syscall.EINTR {
			return err
		}
	}
}

// hostAccept is accept(2) with the new descriptor close-on-exec. The call
// can wait — the connection that was there can be gone again — so it is
// made without the lock process creation takes, and the flag is set after
// it.
func hostAccept(fd int) (int, error) {
	nfd, _, err := syscall.Accept(fd)
	if err != nil {
		return -1, err
	}
	syscall.CloseOnExec(nfd)
	return nfd, nil
}

// hostTerminalRequest reports whether request is one of the terminal's:
// the requests of group 't'.
func hostTerminalRequest(request uint32) bool { return byte(request>>8) == 't' }

// hostIoctlRoom returns how large the buffer of a request has to be: the
// size the request carries in its number (IOCPARM_LEN).
func hostIoctlRoom(request uint32) int { return int(request >> 16 & 0x1fff) }

// hostTerminalAttributes is tcgetattr(3) into the guest's record. The flag
// words and the speeds are wider here than the record's; what they hold
// fits.
func hostTerminalAttributes(fd int, record []byte) error {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGETA, uintptr(unsafe.Pointer(&t))); errno != 0 {
		return errno
	}
	binary.LittleEndian.PutUint32(record[guestTermiosIflag:], uint32(t.Iflag))
	binary.LittleEndian.PutUint32(record[guestTermiosOflag:], uint32(t.Oflag))
	binary.LittleEndian.PutUint32(record[guestTermiosCflag:], uint32(t.Cflag))
	binary.LittleEndian.PutUint32(record[guestTermiosLflag:], uint32(t.Lflag))
	record[guestTermiosLine] = 0
	cc := record[guestTermiosCc : guestTermiosCc+guestTermiosNCCS]
	clear(cc)
	copy(cc, t.Cc[:])
	binary.LittleEndian.PutUint32(record[guestTermiosIspeed:], uint32(t.Ispeed))
	binary.LittleEndian.PutUint32(record[guestTermiosOspeed:], uint32(t.Ospeed))
	return nil
}

// setHostTerminalAttributes is tcsetattr(3) from the guest's record:
// actions is TCSANOW, TCSADRAIN or TCSAFLUSH, with TCSASOFT or not.
func setHostTerminalAttributes(fd int, actions int32, record []byte) error {
	const soft = 0x10 // TCSASOFT: the hardware settings stay as they are
	t := syscall.Termios{
		Iflag:  uint64(binary.LittleEndian.Uint32(record[guestTermiosIflag:])),
		Oflag:  uint64(binary.LittleEndian.Uint32(record[guestTermiosOflag:])),
		Cflag:  uint64(binary.LittleEndian.Uint32(record[guestTermiosCflag:])),
		Lflag:  uint64(binary.LittleEndian.Uint32(record[guestTermiosLflag:])),
		Ispeed: uint64(binary.LittleEndian.Uint32(record[guestTermiosIspeed:])),
		Ospeed: uint64(binary.LittleEndian.Uint32(record[guestTermiosOspeed:])),
	}
	copy(t.Cc[:], record[guestTermiosCc:guestTermiosCc+guestTermiosNCCS])
	if actions&soft != 0 {
		t.Cflag |= 0x1 // CIGNORE
	}
	var request uintptr
	switch actions &^ soft {
	case 0:
		request = syscall.TIOCSETA
	case 1:
		request = syscall.TIOCSETAW
	case 2:
		request = syscall.TIOCSETAF
	default:
		return syscall.EINVAL
	}
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&t)))
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
// record.
func hostTerminalSpeed(record []byte, output bool) uint32 {
	if output {
		return binary.LittleEndian.Uint32(record[guestTermiosOspeed:])
	}
	return binary.LittleEndian.Uint32(record[guestTermiosIspeed:])
}

// setHostTerminalSpeed is cfsetispeed(3) and cfsetospeed(3) on the guest's
// record.
func setHostTerminalSpeed(record []byte, output bool, speed uint32) error {
	if output {
		binary.LittleEndian.PutUint32(record[guestTermiosOspeed:], speed)
	} else {
		binary.LittleEndian.PutUint32(record[guestTermiosIspeed:], speed)
	}
	return nil
}

// hostTerminalControl is tcdrain(3), tcflow(3), tcflush(3) and
// tcsendbreak(3), in the order of terminalDrain: arg is the action of
// tcflow, the queue of tcflush, the duration of tcsendbreak (which this
// system does not look at).
func hostTerminalControl(fd int, what, arg int32) error {
	var err error
	switch what {
	case terminalDrain:
		_, err = hostIoctlValue(fd, syscall.TIOCDRAIN, 0)
	case terminalFlow:
		switch arg {
		case 1: // TCOOFF
			_, err = hostIoctlValue(fd, syscall.TIOCSTOP, 0)
		case 2: // TCOON
			_, err = hostIoctlValue(fd, syscall.TIOCSTART, 0)
		case 3, 4: // TCIOFF, TCION: the terminal's own STOP or START character is sent
			var record [guestTermiosSize]byte
			if err = hostTerminalAttributes(fd, record[:]); err != nil {
				break
			}
			const stop, start, disabled = 13, 12, 0xff // VSTOP, VSTART, _POSIX_VDISABLE
			c := record[guestTermiosCc+stop]
			if arg == 4 {
				c = record[guestTermiosCc+start]
			}
			if c != disabled {
				_, err = syscall.Write(fd, []byte{c})
			}
		default:
			err = syscall.EINVAL
		}
	case terminalFlush:
		var which [4]byte
		switch arg {
		case 1: // TCIFLUSH: what was received (FREAD)
			binary.NativeEndian.PutUint32(which[:], 0x1)
		case 2: // TCOFLUSH: what is to be sent (FWRITE)
			binary.NativeEndian.PutUint32(which[:], 0x2)
		case 3: // TCIOFLUSH
			binary.NativeEndian.PutUint32(which[:], 0x3)
		default:
			return syscall.EINVAL
		}
		_, err = hostIoctlBuffer(fd, syscall.TIOCFLUSH, which[:])
	case terminalBreak:
		if _, err = hostIoctlValue(fd, syscall.TIOCSBRK, 0); err != nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
		_, err = hostIoctlValue(fd, syscall.TIOCCBRK, 0)
	default:
		err = syscall.EINVAL
	}
	return err
}

// hostOpenTakesTerminal: a terminal becomes a controlling terminal by
// request only here (TIOCSCTTY), never by being opened.
const hostOpenTakesTerminal = false

// hostTerminalOfMaster returns the path of the terminal whose master side
// fd is; ok is false for any other descriptor. Only the master side says
// the name of the other (TIOCPTYGNAME), and it is never a controlling
// terminal itself.
func hostTerminalOfMaster(fd int) (path string, ok bool) {
	const name = 0x40807453 // TIOCPTYGNAME
	var buf [128]byte
	if _, err := hostIoctlBuffer(fd, name, buf[:]); err != nil {
		return "", false
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i]), i > 0
		}
	}
	return "", false
}

// The structures of the C library of darwin for the socket addresses: a
// length byte, then the family as a byte; the port is in network byte
// order; a Unix-domain socket has room for a name of 104 bytes.
const (
	darwinSockaddrInet4Size = 16
	darwinSockaddrInet6Size = 28
	darwinSockaddrUnixPath  = 2
	darwinSockaddrUnixSize  = darwinSockaddrUnixPath + 104
)

// hostSockaddrBytes renders a as struct sockaddr_in, sockaddr_in6 or
// sockaddr_un of the host's C library, with the length such an address
// has (in its length byte as well): the whole structure for an IP address
// and for a Unix-domain socket with a path, the head alone for a socket
// without a name. nil for a record of no family the host has, and for a
// name the host has no room for.
func hostSockaddrBytes(a wasiSockAddr) []byte {
	var raw []byte
	switch a.family {
	case wasiSockFamilyIPv4:
		raw = make([]byte, darwinSockaddrInet4Size)
		raw[1] = syscall.AF_INET
		binary.BigEndian.PutUint16(raw[2:], uint16(a.port))
		copy(raw[4:8], a.ip.To4())
	case wasiSockFamilyIPv6:
		raw = make([]byte, darwinSockaddrInet6Size)
		raw[1] = syscall.AF_INET6
		binary.BigEndian.PutUint16(raw[2:], uint16(a.port))
		copy(raw[8:24], a.ip.To16())
		binary.NativeEndian.PutUint32(raw[24:], a.scope)
	case wasiSockFamilyUnix:
		if len(a.name) > darwinSockaddrUnixSize-darwinSockaddrUnixPath {
			return nil
		}
		raw = make([]byte, darwinSockaddrUnixSize)
		raw[1] = syscall.AF_UNIX
		copy(raw[darwinSockaddrUnixPath:], a.name)
		if a.name == "" {
			raw = raw[:darwinSockaddrUnixPath]
		}
	default:
		return nil
	}
	raw[0] = byte(len(raw))
	return raw
}

// sockAddrOfHostBytes reads a struct sockaddr of the host's C library, as
// hostSockaddrBytes writes it (the length byte is not relied on: programs
// pack addresses without one). It reports EAFNOSUPPORT for a family the
// records have no form for, EINVAL for bytes too few for their family.
func sockAddrOfHostBytes(raw []byte) (wasiSockAddr, int32) {
	if len(raw) < 2 {
		return wasiSockAddr{}, _wasiEINVAL
	}
	switch raw[1] {
	case syscall.AF_INET:
		if len(raw) < darwinSockaddrInet4Size {
			return wasiSockAddr{}, _wasiEINVAL
		}
		return wasiSockAddr{family: wasiSockFamilyIPv4, port: int(binary.BigEndian.Uint16(raw[2:])),
			ip: append(net.IP(nil), raw[4:8]...)}, _wasiESUCCESS
	case syscall.AF_INET6:
		if len(raw) < darwinSockaddrInet6Size {
			return wasiSockAddr{}, _wasiEINVAL
		}
		return wasiSockAddr{family: wasiSockFamilyIPv6, port: int(binary.BigEndian.Uint16(raw[2:])),
			ip: append(net.IP(nil), raw[8:24]...), scope: binary.NativeEndian.Uint32(raw[24:])}, _wasiESUCCESS
	case syscall.AF_UNIX:
		name := raw[darwinSockaddrUnixPath:]
		if len(name) > darwinSockaddrUnixSize-darwinSockaddrUnixPath {
			name = name[:darwinSockaddrUnixSize-darwinSockaddrUnixPath]
		}
		if end := bytes.IndexByte(name, 0); end >= 0 {
			name = name[:end]
		}
		return wasiSockAddr{family: wasiSockFamilyUnix, name: string(name)}, _wasiESUCCESS
	}
	return wasiSockAddr{}, _wasiEAFNOSUPPORT
}

// hostInterruptSignal is the host signal that ends a system call which the
// runtime makes for the guest and which waits in the kernel (see
// interruptibleHostCall): SIGINFO, which the Go runtime does not take for
// itself and which no signal of the guest is relayed as (the guest's signals
// are Linux's, which has no SIGINFO).
const hostInterruptSignal = 29

// The C library's functions that send a signal to one thread and change a
// signal's installation: the system has no system call for the first that
// the Go runtime lets a program make, so they are called as the syscall
// package calls the C library, through a trampoline of the assembly file
// beside this one.
//
//go:cgo_import_dynamic libc_pthread_self pthread_self "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_kill pthread_kill "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sigaction sigaction "/usr/lib/libSystem.B.dylib"

// The addresses of the trampolines (defined in the assembly file).
var hostLibcPthreadSelf, hostLibcPthreadKill, hostLibcSigaction uintptr

// hostLibcCall calls the C library's function at fn with three arguments,
// as the syscall package does.
//
//go:linkname hostLibcCall syscall.syscall
func hostLibcCall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// hostSigaction is struct sigaction as the C library's sigaction takes it.
type hostSigaction struct {
	handler uintptr
	mask    uint32
	flags   int32
}

const hostSARestart = 0x0002

// hostInterruptReady reports whether hostInterruptSignal can end a system
// call; the first call makes it so.
//
// The Go runtime has its handler installed for the signal, with SA_RESTART:
// a system call it interrupts would be restarted, which is what the runtime
// wants of the signals it handles itself. For this signal it handles nothing
// (nobody asks for it, and the handler returns at once), so the flag is taken
// off its installation: the handler stays, and a system call the signal
// interrupts fails with EINTR, or returns what it has done so far. A signal
// without the runtime's handler is not used: its default action is not to
// interrupt.
var hostInterruptReady = sync.OnceValue(func() bool {
	var act hostSigaction
	if rc, _, _ := hostLibcCall(hostLibcSigaction, hostInterruptSignal, 0, uintptr(unsafe.Pointer(&act))); int32(rc) != 0 {
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
	rc, _, _ := hostLibcCall(hostLibcSigaction, hostInterruptSignal, uintptr(unsafe.Pointer(&act)), 0)
	return int32(rc) == 0
})

// hostThreadSelf returns the thread the caller runs on (its OS thread
// locked), for interruptHostThread; ok is false where a system call cannot
// be interrupted.
func hostThreadSelf() (thread uint64, ok bool) {
	if !hostInterruptReady() {
		return 0, false
	}
	self, _, _ := hostLibcCall(hostLibcPthreadSelf, 0, 0, 0)
	return uint64(self), true
}

// interruptHostThread sends hostInterruptSignal to the thread.
func interruptHostThread(thread uint64) {
	hostLibcCall(hostLibcPthreadKill, uintptr(thread), hostInterruptSignal, 0)
}

// The C library's gethostbyname2, called as the functions above are: what
// perl's gethostbyname calls on this system. It answers in storage of its
// own, which the next call reuses, hence the lock.
//
//go:cgo_import_dynamic libc_gethostbyname2 gethostbyname2 "/usr/lib/libSystem.B.dylib"

var hostLibcGethostbyname2 uintptr

var hostHostByNameMu sync.Mutex

// hostHostent is struct hostent.
type hostHostent struct {
	name     *byte
	aliases  **byte
	addrtype int32
	length   int32
	addrList **byte
}

// hostHostByName looks the host name up as the C library's gethostbyname
// does — gethostbyname2(name, AF_INET) — and returns its official name and
// IPv4 addresses (none when it has none, or the name has no entry). asked
// is true: the runtime can ask on this system. Unlike the C library's
// getaddrinfo, which the runtime's resolver calls here, it leaves no socket
// to the system open behind (getaddrinfo's sorting of the addresses opens
// one, and keeps it).
func hostHostByName(name string) (official string, addrs [][4]byte, asked bool) {
	cname := append([]byte(name), 0)
	const afInet = 2
	hostHostByNameMu.Lock()
	defer hostHostByNameMu.Unlock()
	r, _, _ := hostLibcCall(hostLibcGethostbyname2, uintptr(unsafe.Pointer(&cname[0])), afInet, 0)
	runtime.KeepAlive(cname)
	if r == 0 {
		return "", nil, true
	}
	// The entry is the C library's memory, which the Go collector does not
	// manage: it is read here, under the lock, and copied. (The address is
	// taken as the pointer it is, not converted from a number.)
	ent := *(**hostHostent)(unsafe.Pointer(&r))
	if ent.addrtype != afInet || ent.length != 4 {
		return "", nil, true
	}
	if ent.name != nil {
		official = unsafe.String(ent.name, cStringLen(ent.name))
		official = strings.Clone(official)
	}
	if ent.addrList != nil {
		// The C library packs the entry: its address list need not be
		// aligned as a Go pointer must be (darwin's lies 2 bytes past a
		// pointer boundary), so the list is read as numbers, each address
		// then taken as the pointer it is.
		list := unsafe.Pointer(ent.addrList)
		for i := uintptr(0); ; i++ {
			a := *(*uintptr)(unsafe.Add(list, i*unsafe.Sizeof(uintptr(0))))
			if a == 0 {
				break
			}
			addrs = append(addrs, *(*[4]byte)(*(*unsafe.Pointer)(unsafe.Pointer(&a))))
		}
	}
	return official, addrs, true
}

// cStringLen returns the length of the NUL-terminated string at p.
func cStringLen(p *byte) int {
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return n
}
