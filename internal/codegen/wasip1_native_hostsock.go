//go:build darwin || linux

package codegen

import (
	"net"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// hostNumberFamilySocketOption is the family of the socket option numbers
// (SO_...) in the tables of the host's numbers.
const hostNumberFamilySocketOption int32 = 9

// The sockets of a guest whose descriptors are the host process's (see
// wasip1_native_hostfd.go): a socket is the host's socket from the moment
// it is made, under the host's number, and what it is bound to, connected
// to, listening for and set to is what the kernel says. The imports keep
// what they are for every guest — the network policy is asked first, and
// addresses cross in the records the guest's libc and the host agree on.

// hostAddressFamily returns the host's AF_ number of a socket family.
func hostAddressFamily(family int32) (int, bool) {
	switch family {
	case wasiSockFamilyIPv4:
		return syscall.AF_INET, true
	case wasiSockFamilyIPv6:
		return syscall.AF_INET6, true
	case wasiSockFamilyUnix:
		return syscall.AF_UNIX, true
	}
	return 0, false
}

// newHostSockets makes the entries of the sockets of the family and type
// the host makes in one call: one socket, or a connected pair.
func newHostSockets(family, typ int32, pair bool) ([]*wasiOpen, error) {
	domain, known := hostAddressFamily(family)
	if !known {
		return nil, syscall.EAFNOSUPPORT
	}
	kind := syscall.SOCK_STREAM
	if typ == wasiSockTypeDgram {
		kind = syscall.SOCK_DGRAM
	}
	var fds []int
	syscall.ForkLock.RLock()
	var err error
	if pair {
		var two [2]int
		if two, err = syscall.Socketpair(domain, kind, 0); err == nil {
			fds = two[:]
		}
	} else {
		var one int
		if one, err = syscall.Socket(domain, kind, 0); err == nil {
			fds = []int{one}
		}
	}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	ops := make([]*wasiOpen, len(fds))
	for i, fd := range fds {
		ops[i] = &wasiOpen{
			f:        newHostFile(fd, syscall.S_IFSOCK, ""),
			isSocket: true,
			dgram:    typ == wasiSockTypeDgram,
			family:   family,
		}
	}
	return ops, nil
}

// openHostSockets makes a socket of the host, or a connected pair, and
// enters it in the instance's table. It returns the guest's numbers, or an
// errno.
func (w *WasiStubs) openHostSockets(family, typ int32, pair bool) ([]int32, int32) {
	ops, err := newHostSockets(family, typ, pair)
	if err != nil {
		return nil, mapOSError(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fds := make([]int32, 0, len(ops))
	for _, op := range ops {
		fd, err := w.addHostFDLocked(op)
		if err != nil {
			for _, made := range ops {
				_ = made.f.Close()
			}
			for _, entered := range fds {
				delete(w.fdsLocked(), entered)
			}
			return nil, mapOSError(err)
		}
		fds = append(fds, fd)
	}
	return fds, _wasiESUCCESS
}

// hostSockaddr returns the address a as the host's sockaddr; unixPath is
// the path of the host's a Unix-domain address names.
func (a wasiSockAddr) hostSockaddr(unixPath string) syscall.Sockaddr {
	switch a.family {
	case wasiSockFamilyIPv6:
		sa := &syscall.SockaddrInet6{Port: a.port, ZoneId: a.scope}
		copy(sa.Addr[:], a.ip.To16())
		return sa
	case wasiSockFamilyUnix:
		return &syscall.SockaddrUnix{Name: unixPath}
	}
	sa := &syscall.SockaddrInet4{Port: a.port}
	copy(sa.Addr[:], a.ip.To4())
	return sa
}

// hostNetAddr returns a sockaddr of the host's as package net names the
// address, which is how the records for the guest are written; nil for no
// address, and for a Unix-domain socket that has no name. dgram says
// whether the socket is a datagram socket.
func hostNetAddr(sa syscall.Sockaddr, dgram bool) net.Addr {
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		ip := net.IP(append([]byte(nil), a.Addr[:]...))
		if dgram {
			return &net.UDPAddr{IP: ip, Port: a.Port}
		}
		return &net.TCPAddr{IP: ip, Port: a.Port}
	case *syscall.SockaddrInet6:
		zone := ""
		if a.ZoneId != 0 {
			zone = strconv.FormatUint(uint64(a.ZoneId), 10)
			if ifc, err := net.InterfaceByIndex(int(a.ZoneId)); err == nil {
				zone = ifc.Name
			}
		}
		ip := net.IP(append([]byte(nil), a.Addr[:]...))
		if dgram {
			return &net.UDPAddr{IP: ip, Port: a.Port, Zone: zone}
		}
		return &net.TCPAddr{IP: ip, Port: a.Port, Zone: zone}
	case *syscall.SockaddrUnix:
		if a.Name == "" {
			return nil
		}
		network := "unix"
		if dgram {
			network = "unixgram"
		}
		return &net.UnixAddr{Name: a.Name, Net: network}
	}
	return nil
}

// holdSocket is hold for a call on a socket: it returns the descriptor of a
// socket entry of the host's, to be released after the call, or the errno
// of an entry that is no socket, or is gone.
func (h *hostFile) holdSocket() (int, int32) {
	if !h.socket() {
		return -1, _wasiENOTSOCK
	}
	fd, err := h.hold()
	if err != nil {
		return -1, _wasiEBADF
	}
	return fd, _wasiESUCCESS
}

// bindHost is bind(2) for a socket of the host's: the socket gets the local
// address a, whose path of the host's is unixPath for a Unix-domain one.
func (w *WasiStubs) bindHost(op *wasiOpen, h *hostFile, a wasiSockAddr, unixPath string) int32 {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return errno
	}
	defer h.release()
	if err := syscall.Bind(fd, a.hostSockaddr(unixPath)); err != nil {
		return mapOSError(err)
	}
	if a.family == wasiSockFamilyUnix {
		op.mu.Lock()
		op.socketLocked().unixLocal = a.name
		op.mu.Unlock()
	}
	return _wasiESUCCESS
}

// listenHost is listen(2) for a socket of the host's.
func (w *WasiStubs) listenHost(op *wasiOpen, h *hostFile, backlog int32) int32 {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return errno
	}
	defer h.release()
	if backlog < 0 {
		backlog = 0
	}
	if err := syscall.Listen(fd, int(backlog)); err != nil {
		return mapOSError(err)
	}
	op.mu.Lock()
	op.socketLocked().listening = true
	op.mu.Unlock()
	return _wasiESUCCESS
}

// hostListening reports whether the socket fd of the entry listens. The
// host says where it can (SO_ACCEPTCONN); where it cannot, the entry knows
// of the listen that was made through it, and of a socket that came from
// outside the guest it knows that the host could not say: such a socket
// counts as listening, and an accept on it waits.
func (op *wasiOpen) hostListening(fd int) bool {
	if accepting, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN); err == nil {
		return accepting != 0
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.sock != nil && op.sock.listening
}

// acceptHost is accept(2) for a listening socket of the host's: it takes
// the next connection and returns its entry. A socket in non-blocking mode
// reports EAGAIN when none is waiting; otherwise the call waits, no longer
// than the socket's receive timeout, and a signal posted to the guest ends
// the wait with EINTR.
func (w *WasiStubs) acceptHost(op *wasiOpen, h *hostFile) (*wasiOpen, int32) {
	asked := false
	var until time.Time
	for {
		fd, errno := h.holdSocket()
		if errno != _wasiESUCCESS {
			return nil, errno
		}
		// Whoever finds a connection waiting takes it: see hostCallTurn.
		hostCallTurn(fd).Lock()
		nfd, err := -1, error(syscall.EAGAIN)
		if hostReadyNow(fd, hostPollIn) != 0 {
			nfd, err = hostAccept(fd)
		}
		hostCallTurn(fd).Unlock()
		nonblocking, listening := false, true
		if err == syscall.EAGAIN {
			if flags, ferr := descriptorFlags(fd, syscall.F_GETFL); ferr == nil {
				nonblocking = flags&syscall.O_NONBLOCK != 0
			}
			if !nonblocking && !asked {
				asked = true
				// A socket that does not listen never has a connection.
				listening = op.hostListening(fd)
				if limit := hostSocketTimeout(fd, syscall.SO_RCVTIMEO); limit > 0 {
					until = time.Now().Add(limit)
				}
			}
		}
		h.release()
		switch err {
		case nil:
			accepted := &wasiOpen{
				f:        newHostFile(nfd, syscall.S_IFSOCK, ""),
				isSocket: true,
				family:   op.family,
			}
			op.mu.Lock()
			if op.sock != nil && op.sock.unixLocal != "" {
				// the local name of the connection is the listener's
				accepted.sock = &wasiSocket{unixLocal: op.sock.unixLocal}
			}
			op.mu.Unlock()
			return accepted, _wasiESUCCESS
		case syscall.EINTR, syscall.ECONNABORTED:
			continue
		case syscall.EAGAIN:
		default:
			return nil, mapOSError(err)
		}
		if nonblocking {
			return nil, _wasiEAGAIN
		}
		if !listening {
			return nil, _wasiEINVAL
		}
		wait := [1]hostPoll{{fd: int32(fd), events: hostPollIn}}
		if errno := w.awaitHost(wait[:], until); errno != _wasiESUCCESS {
			return nil, errno
		}
	}
}

// hostConnectRetry is how long a blocking connect waits before it asks
// again for a connection the host could not take yet (a Unix-domain socket
// whose listener has no room).
const hostConnectRetry = 2 * time.Millisecond

// connectHost is connect(2) for a socket of the host's. A datagram socket
// takes its peer at once. A stream socket in non-blocking mode reports
// EINPROGRESS unless the connection is made at once, becomes writable when
// the attempt has ended, and SO_ERROR then tells how. One in blocking mode
// waits for the connection: the attempt is started without waiting — the
// open file is in non-blocking mode for the length of that one call — and
// waited for in poll, so that a signal posted to the guest ends the wait
// with EINTR, and the socket's send timeout with EINPROGRESS; the attempt
// goes on either way, and another connect while it does is EALREADY.
func (w *WasiStubs) connectHost(op *wasiOpen, h *hostFile, sa syscall.Sockaddr) int32 {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return errno
	}
	blocking := true
	if flags, err := descriptorFlags(fd, syscall.F_GETFL); err == nil {
		blocking = flags&syscall.O_NONBLOCK == 0
	}
	if op.dgram || !blocking {
		defer h.release()
		for {
			err := syscall.Connect(fd, sa)
			if err != syscall.EINTR {
				return mapOSError(err)
			}
		}
	}
	var until time.Time
	if limit := hostSocketTimeout(fd, syscall.SO_SNDTIMEO); limit > 0 {
		until = time.Now().Add(limit)
	}
	h.release()
	for {
		fd, errno := h.holdSocket()
		if errno != _wasiESUCCESS {
			return errno
		}
		hostCallTurn(fd).Lock()
		err := syscall.SetNonblock(fd, true)
		if err == nil {
			err = syscall.Connect(fd, sa)
			_ = syscall.SetNonblock(fd, false)
		}
		hostCallTurn(fd).Unlock()
		h.release()
		switch err {
		case nil:
			return _wasiESUCCESS
		case syscall.EALREADY:
			// An attempt a signal took the wait from is still under way.
			return _wasiEALREADY
		case syscall.EINPROGRESS, syscall.EINTR:
			wait := [1]hostPoll{{fd: int32(fd), events: hostPollOut}}
			switch errno := w.awaitHost(wait[:], until); errno {
			case _wasiESUCCESS:
			case _wasiEAGAIN:
				return _wasiEINPROGRESS
			default:
				return errno
			}
			if fd, errno = h.holdSocket(); errno != _wasiESUCCESS {
				return errno
			}
			failure, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			h.release()
			if err != nil {
				return mapOSError(err)
			}
			if failure != 0 {
				return mapOSError(syscall.Errno(failure))
			}
			return _wasiESUCCESS
		case syscall.EAGAIN:
			// No room at the listener yet: a blocking connect waits for it.
			retry := time.Now().Add(hostConnectRetry)
			if !until.IsZero() && until.Before(retry) {
				return _wasiEINPROGRESS
			}
			if errno := w.awaitHost(nil, retry); errno != _wasiEAGAIN {
				return errno
			}
		default:
			return mapOSError(err)
		}
	}
}

// shutdownHost is shutdown(2) for a socket of the host's; how has bit 0x1
// for the receiving and 0x2 for the sending side.
func (w *WasiStubs) shutdownHost(h *hostFile, how int32) int32 {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return errno
	}
	defer h.release()
	var side int
	switch how & 0x3 {
	case 0x1:
		side = syscall.SHUT_RD
	case 0x2:
		side = syscall.SHUT_WR
	case 0x3:
		side = syscall.SHUT_RDWR
	default:
		return _wasiEINVAL
	}
	return mapOSError(syscall.Shutdown(fd, side))
}

// hostSocketName returns the local name of a socket of the host's, or the
// name of its peer, as package net names an address.
func (op *wasiOpen) hostSocketName(h *hostFile, peer bool) (net.Addr, int32) {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return nil, errno
	}
	defer h.release()
	var sa syscall.Sockaddr
	var err error
	if peer {
		sa, err = syscall.Getpeername(fd)
	} else {
		sa, err = syscall.Getsockname(fd)
	}
	if err != nil {
		return nil, mapOSError(err)
	}
	addr := hostNetAddr(sa, op.dgram)
	if addr == nil && op.family == wasiSockFamilyUnix {
		// A Unix-domain socket without a name still has an address of its
		// family.
		addr = &net.UnixAddr{}
	}
	return addr, _wasiESUCCESS
}

// timeoutHost reads a socket's receive or send timeout, and sets it when
// set is true: SO_RCVTIMEO and SO_SNDTIMEO of the host's socket.
func (w *WasiStubs) timeoutHost(h *hostFile, which int32, set bool, nanos int64) (old time.Duration, errno int32) {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return 0, errno
	}
	defer h.release()
	option := syscall.SO_RCVTIMEO
	if which == wasiSockTimeoutSend {
		option = syscall.SO_SNDTIMEO
	}
	old = hostSocketTimeout(fd, option)
	if set {
		tv := syscall.NsecToTimeval(nanos)
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, option, &tv); err != nil {
			return old, mapOSError(err)
		}
	}
	return old, _wasiESUCCESS
}

// hostSocketOption returns the level and the name of a socket option of
// the host's for an option the guest's shim names (wasiSockOpt...); ok is
// false for one the host has no option for.
func hostSocketOption(option int32) (level, name int, ok bool) {
	switch option {
	case wasiSockOptReuseAddr:
		return syscall.SOL_SOCKET, syscall.SO_REUSEADDR, true
	case wasiSockOptReusePort:
		// package syscall does not have the number on every host
		for _, number := range hostNumberTable(hostNumberFamilySocketOption) {
			if number.name == "SO_REUSEPORT" {
				return syscall.SOL_SOCKET, int(number.value), true
			}
		}
		return 0, 0, false
	case wasiSockOptKeepAlive:
		return syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, true
	case wasiSockOptNoDelay:
		return syscall.IPPROTO_TCP, syscall.TCP_NODELAY, true
	case wasiSockOptRcvBuf:
		return syscall.SOL_SOCKET, syscall.SO_RCVBUF, true
	case wasiSockOptSndBuf:
		return syscall.SOL_SOCKET, syscall.SO_SNDBUF, true
	case wasiSockOptLinger:
		return syscall.SOL_SOCKET, syscall.SO_LINGER, true
	case wasiSockOptError:
		return syscall.SOL_SOCKET, syscall.SO_ERROR, true
	case wasiSockOptType:
		return syscall.SOL_SOCKET, syscall.SO_TYPE, true
	case wasiSockOptAccepting:
		return syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN, true
	case wasiSockOptV6Only:
		return syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, true
	}
	return 0, 0, false
}

// setoptHost is setsockopt(2) for a socket of the host's and one of the
// options the guest's shim names. Linger takes seconds, or -1 for off.
func (w *WasiStubs) setoptHost(op *wasiOpen, h *hostFile, option, value int32) int32 {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return errno
	}
	defer h.release()
	level, name, known := hostSocketOption(option)
	switch {
	case !known, option == wasiSockOptError, option == wasiSockOptType, option == wasiSockOptAccepting:
		return _wasiENOPROTOOPT
	case option == wasiSockOptV6Only && op.family != wasiSockFamilyIPv6:
		return _wasiENOPROTOOPT
	case option == wasiSockOptLinger:
		linger := syscall.Linger{}
		if value >= 0 {
			linger.Onoff, linger.Linger = 1, value
		}
		return mapOSError(syscall.SetsockoptLinger(fd, level, name, &linger))
	}
	return mapOSError(syscall.SetsockoptInt(fd, level, name, int(value)))
}

// getoptHost is getsockopt(2) for a socket of the host's and one of the
// options the guest's shim names, in the values the shim knows them by:
// SO_ERROR as a wasi errno, SO_TYPE as wasiSockType..., linger as seconds
// or -1 for off, any other switch as 0 or 1.
func (w *WasiStubs) getoptHost(op *wasiOpen, h *hostFile, option int32) (value, errno int32) {
	fd, errno := h.holdSocket()
	if errno != _wasiESUCCESS {
		return 0, errno
	}
	defer h.release()
	level, name, known := hostSocketOption(option)
	if !known || (option == wasiSockOptV6Only && op.family != wasiSockFamilyIPv6) {
		return 0, _wasiENOPROTOOPT
	}
	if option == wasiSockOptLinger {
		var linger syscall.Linger
		size := uint32(unsafe.Sizeof(linger))
		if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name),
			uintptr(unsafe.Pointer(&linger)), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
			return 0, mapOSError(errno)
		}
		if linger.Onoff == 0 {
			return -1, _wasiESUCCESS
		}
		return linger.Linger, _wasiESUCCESS
	}
	if option == wasiSockOptAccepting {
		if op.hostListening(fd) {
			return 1, _wasiESUCCESS
		}
		return 0, _wasiESUCCESS
	}
	got, err := syscall.GetsockoptInt(fd, level, name)
	if err != nil {
		return 0, mapOSError(err)
	}
	switch option {
	case wasiSockOptError:
		if got != 0 {
			return mapOSError(syscall.Errno(got)), _wasiESUCCESS
		}
		return 0, _wasiESUCCESS
	case wasiSockOptType:
		if got == syscall.SOCK_DGRAM {
			return wasiSockTypeDgram, _wasiESUCCESS
		}
		return wasiSockTypeStream, _wasiESUCCESS
	case wasiSockOptRcvBuf, wasiSockOptSndBuf:
		return int32(got), _wasiESUCCESS
	}
	if got != 0 {
		return 1, _wasiESUCCESS
	}
	return 0, _wasiESUCCESS
}

// receiveFromHost is recvfrom(2) for a socket of the host's: one receive
// into buf with the flags of a receive (wasiMsg...), and the name of who
// sent it — the sender of a datagram, the peer of a stream socket — or nil
// when there is none to give.
func (w *WasiStubs) receiveFromHost(op *wasiOpen, h *hostFile, buf []byte, flags int32) (uint64, net.Addr, int32) {
	if !h.socket() {
		return 0, nil, _wasiENOTSOCK
	}
	n, from, errno := w.receiveHost(h, [][]byte{buf}, flags)
	if errno != _wasiESUCCESS {
		return 0, nil, errno
	}
	if !op.dgram {
		if fd, errno := h.holdSocket(); errno == _wasiESUCCESS {
			if peer, err := syscall.Getpeername(fd); err == nil {
				from = peer
			}
			h.release()
		}
	}
	return n, hostNetAddr(from, op.dgram), _wasiESUCCESS
}
