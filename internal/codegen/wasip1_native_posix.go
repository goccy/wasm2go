//go:build darwin || linux

package codegen

import (
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// processUmask is the file mode creation mask of the host process. The only
// way to read it is to set it, so it is read once, while the program is
// still initializing its packages and nothing creates files concurrently.
var processUmask = readProcessUmask()

func readProcessUmask() os.FileMode {
	mask := syscall.Umask(0)
	syscall.Umask(mask)
	return os.FileMode(mask) & 0o777
}

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned.
func osFileStat(sys any) (fileStat, bool) {
	st, ok := sys.(*syscall.Stat_t)
	if !ok {
		return fileStat{}, false
	}
	atime, ctime := statTimes(st)
	return fileStat{
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint64(st.Nlink),
		uid:   st.Uid,
		gid:   st.Gid,
		atime: atime,
		ctime: ctime,
		// the widths of these differ from host to host
		rdev:    uint64(st.Rdev),
		blksize: uint32(st.Blksize),
		blocks:  uint64(st.Blocks),
	}, true
}

// flockOSFile applies flock(2) to a file of the host process. The descriptor
// is borrowed through SyscallConn rather than taken with Fd, which would
// switch a pipe or terminal to blocking mode for good.
func flockOSFile(f *os.File, lock FileLock, wait bool) error {
	how := syscall.LOCK_UN
	switch lock {
	case FileLockShared:
		how = syscall.LOCK_SH
	case FileLockExclusive:
		how = syscall.LOCK_EX
	}
	if lock != FileUnlock && !wait {
		how |= syscall.LOCK_NB
	}
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		for {
			lockErr = syscall.Flock(int(fd), how)
			if lockErr != syscall.EINTR {
				return
			}
		}
	}); err != nil {
		return err
	}
	return lockErr
}

// hostSignals maps the guest's signal numbers to the host's signals; see
// hostSignalOf.
var hostSignals = map[int32]syscall.Signal{
	wasiSIGHUP:    syscall.SIGHUP,
	wasiSIGINT:    syscall.SIGINT,
	wasiSIGQUIT:   syscall.SIGQUIT,
	wasiSIGILL:    syscall.SIGILL,
	wasiSIGTRAP:   syscall.SIGTRAP,
	wasiSIGABRT:   syscall.SIGABRT,
	wasiSIGBUS:    syscall.SIGBUS,
	wasiSIGFPE:    syscall.SIGFPE,
	wasiSIGKILL:   syscall.SIGKILL,
	wasiSIGUSR1:   syscall.SIGUSR1,
	wasiSIGSEGV:   syscall.SIGSEGV,
	wasiSIGUSR2:   syscall.SIGUSR2,
	wasiSIGPIPE:   syscall.SIGPIPE,
	wasiSIGALRM:   syscall.SIGALRM,
	wasiSIGTERM:   syscall.SIGTERM,
	wasiSIGCHLD:   syscall.SIGCHLD,
	wasiSIGCONT:   syscall.SIGCONT,
	wasiSIGSTOP:   syscall.SIGSTOP,
	wasiSIGTSTP:   syscall.SIGTSTP,
	wasiSIGTTIN:   syscall.SIGTTIN,
	wasiSIGTTOU:   syscall.SIGTTOU,
	wasiSIGURG:    syscall.SIGURG,
	wasiSIGXCPU:   syscall.SIGXCPU,
	wasiSIGXFSZ:   syscall.SIGXFSZ,
	wasiSIGVTALRM: syscall.SIGVTALRM,
	wasiSIGPROF:   syscall.SIGPROF,
	wasiSIGWINCH:  syscall.SIGWINCH,
	wasiSIGIO:     syscall.SIGIO,
	wasiSIGSYS:    syscall.SIGSYS,
}

// hostSignalOf returns the host's signal for a guest signal number. Number
// 0, the existence probe of kill, is the same everywhere. known is false for
// a signal this host does not have.
func hostSignalOf(sig int32) (hostSig syscall.Signal, known bool) {
	if sig == 0 {
		return 0, true
	}
	hostSig, known = hostSignals[sig]
	return hostSig, known
}

// guestSignalOf returns the guest's number for a host signal, or 0 when the
// guest has none for it.
func guestSignalOf(hostSig syscall.Signal) int32 {
	for sig, candidate := range hostSignals {
		if candidate == hostSig {
			return sig
		}
	}
	return 0
}

// signalHostProcess sends a signal to a process of the host.
func signalHostProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// hostProcessGroup returns the process group of a process of the host, 0
// naming the host process itself.
func hostProcessGroup(pid int) (int, error) {
	return syscall.Getpgid(pid)
}

// setHostProcessGroup moves a process of the host — 0 names the host
// process itself — into a process group, 0 standing for a group of its own.
func setHostProcessGroup(pid, pgid int) error {
	return syscall.Setpgid(pid, pgid)
}

// newHostSession makes the host process the leader of a new session.
func newHostSession() (sid int, err error) {
	return syscall.Setsid()
}

// hostProcessTimes returns the CPU time of the host process — user, then
// system — and of the children it has waited for.
func hostProcessTimes() (times [4]time.Duration, err error) {
	var self, children syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &self); err != nil {
		return times, err
	}
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &children); err != nil {
		return times, err
	}
	return [4]time.Duration{
		time.Duration(self.Utime.Nano()), time.Duration(self.Stime.Nano()),
		time.Duration(children.Utime.Nano()), time.Duration(children.Stime.Nano()),
	}, nil
}

// setHostPriority sets the nice value of processes of the host.
func setHostPriority(which, who, nice int) error {
	return syscall.Setpriority(which, who, nice)
}

// makeHostFIFO creates a FIFO in the host filesystem.
func makeHostFIFO(path string, perm os.FileMode) error {
	return syscall.Mkfifo(path, uint32(perm.Perm()))
}

// setHostIDs changes the user or group ids of the host process; see
// Proc_setids for the requests.
//
// The ids are per thread to the kernel of some hosts, and the Go runtime
// changes them on every thread of the process — which it refuses to do, by
// panicking, in a program that is linked with a C runtime it does not
// control. The change is then one this process cannot make
// (errors.ErrUnsupported).
func setHostIDs(request int32, a, b, c int) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.ErrUnsupported
		}
	}()
	switch request {
	case wasiSetUID:
		return syscall.Setuid(a)
	case wasiSetEUID:
		return syscall.Seteuid(a)
	case wasiSetREUID:
		return syscall.Setreuid(a, b)
	case wasiSetRESUID:
		return setHostRESUID(a, b, c)
	case wasiSetGID:
		return syscall.Setgid(a)
	case wasiSetEGID:
		return syscall.Setegid(a)
	case wasiSetREGID:
		return syscall.Setregid(a, b)
	case wasiSetRESGID:
		return setHostRESGID(a, b, c)
	}
	return syscall.EINVAL
}

// setHostGroups sets the supplementary groups of the host process, with the
// limitation setHostIDs has.
func setHostGroups(gids []int) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.ErrUnsupported
		}
	}()
	return syscall.Setgroups(gids)
}

// hostInputNow says that the host can read, receive and accept on a
// descriptor without waiting in the call: see readRaw, receiveRaw and
// acceptRaw.
const hostInputNow = true

// descriptorWaits reports whether a call on the descriptor waits when there
// is nothing for it: it is not in non-blocking mode, which the descriptors
// the runtime polls are. Such a descriptor cannot be asked what is there.
func descriptorWaits(fd uintptr) bool {
	flags, err := descriptorFlags(int(fd), syscall.F_GETFL)
	return err != nil || flags&syscall.O_NONBLOCK == 0
}

// readRaw reads from a descriptor that does not wait, once. again reports
// that nothing is there right now; otherwise n bytes were read (none at the
// end of input), or err says why not.
func readRaw(fd uintptr, p []byte) (n int, again bool, err error) {
	for {
		n, err = syscall.Read(int(fd), p)
		if err == syscall.EINTR {
			continue
		}
		if n < 0 {
			n = 0
		}
		if err == syscall.EAGAIN {
			return 0, true, nil
		}
		return n, false, err
	}
}

// receiveRaw receives one datagram from a socket that does not wait, into
// p, with the address it came from as package net names it (nil when the
// sender has none). again reports that no datagram is there right now.
func receiveRaw(fd uintptr, p []byte) (n int, from net.Addr, again bool, err error) {
	for {
		var sender syscall.Sockaddr
		n, sender, err = syscall.Recvfrom(int(fd), p, 0)
		if err == syscall.EINTR {
			continue
		}
		if n < 0 {
			n = 0
		}
		if err == syscall.EAGAIN {
			return 0, nil, true, nil
		}
		switch a := sender.(type) {
		case *syscall.SockaddrInet4:
			from = &net.UDPAddr{IP: net.IP(a.Addr[:]).To4(), Port: a.Port}
		case *syscall.SockaddrInet6:
			zone := ""
			if a.ZoneId != 0 {
				zone = strconv.FormatUint(uint64(a.ZoneId), 10)
				if ifc, ierr := net.InterfaceByIndex(int(a.ZoneId)); ierr == nil {
					zone = ifc.Name
				}
			}
			from = &net.UDPAddr{IP: net.IP(a.Addr[:]), Port: a.Port, Zone: zone}
		case *syscall.SockaddrUnix:
			if a.Name != "" {
				from = &net.UnixAddr{Name: a.Name, Net: "unixgram"}
			}
		}
		return n, from, false, err
	}
}

// acceptRaw accepts one connection from a listening socket that does not
// wait. again reports that no connection is there right now.
func acceptRaw(fd uintptr) (conn net.Conn, again bool, err error) {
	for {
		nfd, _, aerr := syscall.Accept(int(fd))
		switch aerr {
		case nil:
		case syscall.EINTR:
			continue
		case syscall.EAGAIN, syscall.ECONNABORTED:
			// one that was taken back before it was accepted is not there
			return nil, true, nil
		default:
			return nil, false, os.NewSyscallError("accept", aerr)
		}
		syscall.CloseOnExec(nfd)
		// The connection of package net is made on a duplicate, which it
		// puts in the mode it needs.
		file := os.NewFile(uintptr(nfd), "")
		conn, err = net.FileConn(file)
		_ = file.Close()
		return conn, false, err
	}
}

// peerFailure returns the errno getpeername(2) fails with on the host's
// socket, and 0 when the socket has a peer: ENOTCONN, or EINVAL where the
// host says that of a socket that was shut down. Any other failure is not
// about the peer and counts as none.
func peerFailure(fd uintptr) int32 {
	switch _, err := syscall.Getpeername(int(fd)); err {
	case syscall.ENOTCONN:
		return _wasiENOTCONN
	case syscall.EINVAL:
		return _wasiEINVAL
	}
	return _wasiESUCCESS
}

// hostStreamWrites says that the host can write to a stream without waiting
// in the write, and ask whether one has room: see writeRaw and fdWritable.
const hostStreamWrites = true

// writeRaw writes p to a descriptor the runtime polls (and so keeps in
// non-blocking mode) once. again reports that the descriptor takes nothing
// right now; otherwise n bytes were taken, or err says why not.
func writeRaw(fd uintptr, p []byte) (n int, again bool, err error) {
	for {
		n, err = syscall.Write(int(fd), p)
		if err == syscall.EINTR {
			continue
		}
		if n < 0 {
			n = 0
		}
		if err == syscall.EAGAIN {
			return 0, true, nil
		}
		return n, false, err
	}
}

// socketPair creates a pair of connected Unix-domain sockets: stream
// sockets, or datagram sockets with dgram.
func socketPair(dgram bool) (a, b net.Conn, err error) {
	typ := syscall.SOCK_STREAM
	if dgram {
		typ = syscall.SOCK_DGRAM
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ, 0)
	if err != nil {
		return nil, nil, err
	}
	conns := [2]net.Conn{}
	for i, fd := range fds {
		syscall.CloseOnExec(fd)
		f := os.NewFile(uintptr(fd), "socketpair")
		// FileConn works on a duplicate; the original is done with either way.
		conn, connErr := net.FileConn(f)
		err = errors.Join(err, connErr, f.Close())
		conns[i] = conn
	}
	if err != nil {
		for _, conn := range conns {
			if conn != nil {
				err = errors.Join(err, conn.Close())
			}
		}
		return nil, nil, err
	}
	return conns[0], conns[1], nil
}

// unboundUnixDatagram creates a Unix-domain datagram socket that has no
// name: package net makes none without binding or connecting it.
func unboundUnixDatagram() (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "unixgram")
	// FileConn works on a duplicate; the original is done with either way.
	conn, err := net.FileConn(f)
	if err = errors.Join(err, f.Close()); err != nil {
		if conn != nil {
			err = errors.Join(err, conn.Close())
		}
		return nil, err
	}
	return conn, nil
}

// setIPv6Only makes the IPv6 socket fd take IPv6 traffic only, or IPv4
// traffic as well (IPV6_V6ONLY).
func setIPv6Only(fd uintptr, only bool) error {
	value := 0
	if only {
		value = 1
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, value)
}

// inheritedOnce lets one instance adopt the descriptors the process was
// started with (AdoptInheritedDescriptors): they exist once.
var inheritedOnce sync.Once

// descriptorFlags returns what fcntl(fd, get) reports: the descriptor flags
// for F_GETFD, the status flags for F_GETFL.
func descriptorFlags(fd int, get int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(get), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

// inheritedDescriptors returns the descriptors above the standard three
// that the process was started with, in ascending order: the open ones that
// are not close-on-exec. A descriptor that reaches a program through exec
// is not, and every descriptor this process opens itself is — the Go
// runtime and library see to that.
func inheritedDescriptors() []int {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return nil
	}
	var fds []int
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		// The descriptor the directory was read through is listed too: it
		// is closed by now, or close-on-exec.
		if flags, err := descriptorFlags(fd, syscall.F_GETFD); err != nil || flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		fds = append(fds, fd)
	}
	sort.Ints(fds)
	return fds
}

// adoptHostDescriptor makes an entry of the guest's descriptor table out of
// a descriptor the process inherited, which the entry takes over. A socket
// becomes the connection or the listening socket it is — the network API
// works on a duplicate, and the inherited number is closed; anything else
// is the file under its number, open for what the descriptor is open for.
// nil when the descriptor cannot be used.
func adoptHostDescriptor(fd int) *wasiOpen {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil
	}
	syscall.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "/dev/fd/"+strconv.Itoa(fd))
	if st.Mode&syscall.S_IFMT == syscall.S_IFSOCK {
		defer file.Close()
		op := &wasiOpen{isSocket: true}
		typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil {
			return nil
		}
		op.dgram = typ == syscall.SOCK_DGRAM
		if _, err := syscall.Getpeername(fd); err == nil || op.dgram {
			conn, err := net.FileConn(file)
			if err != nil {
				return nil
			}
			op.conn = conn
		} else {
			// A stream socket without a peer is held as a bound socket is:
			// through a listener, which accepts once the socket listens
			// and gives its address up to a connect. Whether it listens
			// already the host says where it can (SO_ACCEPTCONN); where it
			// cannot, the socket counts as listening, and an accept on one
			// that is not fails as the host fails it.
			l, err := net.FileListener(file)
			if err != nil {
				return nil
			}
			if unix, isUnix := l.(*net.UnixListener); isUnix {
				unix.SetUnlinkOnClose(false)
			}
			accepting, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
			op.listener = l
			op.sock = &wasiSocket{listening: err != nil || accepting != 0}
		}
		op.family = op.socketFamily()
		return op
	}
	op := &wasiOpen{f: file, isDir: st.Mode&syscall.S_IFMT == syscall.S_IFDIR}
	if flags, err := descriptorFlags(fd, syscall.F_GETFL); err == nil {
		switch flags & syscall.O_ACCMODE {
		case syscall.O_RDONLY:
			op.noWrite = true
		case syscall.O_WRONLY:
			op.noRead = true
		}
	}
	return op
}

// sendToOnConnected sends the datagram p to an address on the connected
// datagram socket conn with the host's sendto, which package net does not
// offer for a socket it knows to be connected. ipv6 says that the socket is
// an IPv6 one, which names an IPv4 destination by its mapped address.
func sendToOnConnected(conn net.Conn, p []byte, to net.Addr, ipv6 bool) (int, error) {
	var sa syscall.Sockaddr
	switch addr := to.(type) {
	case *net.UDPAddr:
		v4 := addr.IP.To4()
		if v4 != nil && !ipv6 {
			in := &syscall.SockaddrInet4{Port: addr.Port}
			copy(in.Addr[:], v4)
			sa = in
		} else {
			in := &syscall.SockaddrInet6{Port: addr.Port, ZoneId: scopeOfZone(addr.Zone)}
			copy(in.Addr[:], addr.IP.To16())
			sa = in
		}
	case *net.UnixAddr:
		sa = &syscall.SockaddrUnix{Name: addr.Name}
	default:
		return 0, errors.ErrUnsupported
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.ErrUnsupported
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var failed error
	err = rc.Write(func(fd uintptr) bool {
		failed = syscall.Sendto(int(fd), p, 0, sa)
		return failed != syscall.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	if failed != nil {
		return 0, failed
	}
	return len(p), nil
}
