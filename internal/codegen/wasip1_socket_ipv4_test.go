package codegen

import (
	"encoding/binary"
	"net"
)

// IPv4 conveniences for the socket tests, through the imports of every
// family: an address as it sits in sockaddr_in.sin_addr (ipBE, the low byte
// is the first octet) and a port, and a socket name read back as
// readSockName reads it (family, ipBE, port, three little-endian u32).

// ipv4RecordOff is scratch memory for the address records the helpers pass.
const ipv4RecordOff int32 = 23000

// ipv4OfBE returns the dotted form of an IPv4 address as it sits in s_addr.
func ipv4OfBE(ipBE int32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(ipBE))
	return net.IP(b[:]).String()
}

// putSockNameIPv4 writes at off the name readSockName reads, from the
// address record at recOff.
func putSockNameIPv4(m *Module, recOff, off int32) {
	r := readSockRecord(m, recOff)
	var ip uint32
	if v4 := net.ParseIP(r.ip).To4(); v4 != nil {
		ip = binary.LittleEndian.Uint32(v4)
	}
	binary.LittleEndian.PutUint32(m.memory[off:], r.family)
	binary.LittleEndian.PutUint32(m.memory[off+4:], ip)
	binary.LittleEndian.PutUint32(m.memory[off+8:], r.port)
}

// sockBindIPv4 binds fd to ipBE:port with sock_bind_addr.
func sockBindIPv4(w *WasiStubs, m *Module, fd, ipBE, port int32) int32 {
	putIPAddr(m, ipv4RecordOff, ipv4OfBE(ipBE), port)
	return w.Sock_bind_addr(m, fd, ipv4RecordOff, 0, 0)
}

// sockNameIPv4 writes at off the name of fd's own address, or of its peer's,
// with sock_name.
func sockNameIPv4(w *WasiStubs, m *Module, fd int32, peer bool, off int32) int32 {
	var which int32
	if peer {
		which = 1
	}
	if rc := w.Sock_name(m, fd, which, ipv4RecordOff); rc != _wasiESUCCESS {
		return rc
	}
	putSockNameIPv4(m, ipv4RecordOff, off)
	return _wasiESUCCESS
}

// sockSendtoIPv4 is sendto with sock_sendto_addr, to ipBE:port when hasAddr
// is set and to the socket's peer otherwise.
func sockSendtoIPv4(w *WasiStubs, m *Module, fd, bufPtr, bufLen, flags, hasAddr, ipBE, port, sentPtr int32) int32 {
	var addr int32
	if hasAddr != 0 {
		putIPAddr(m, ipv4RecordOff, ipv4OfBE(ipBE), port)
		addr = ipv4RecordOff
	}
	return w.Sock_sendto_addr(m, fd, bufPtr, bufLen, flags, addr, 0, 0, sentPtr)
}

// sockRecvfromIPv4 is recvfrom with sock_recvfrom_addr; the sender's name
// goes to namePtr as readSockName reads it.
func sockRecvfromIPv4(w *WasiStubs, m *Module, fd, bufPtr, bufLen, flags, namePtr, receivedPtr int32) int32 {
	rc := w.Sock_recvfrom_addr(m, fd, bufPtr, bufLen, flags, ipv4RecordOff, receivedPtr)
	if rc == _wasiESUCCESS {
		putSockNameIPv4(m, ipv4RecordOff, namePtr)
	}
	return rc
}

// sockPairStream makes a pair of connected Unix-domain stream sockets with
// sock_socketpair and writes their fds at fdsOutPtr.
func sockPairStream(w *WasiStubs, m *Module, fdsOutPtr int32) int32 {
	return w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, fdsOutPtr)
}
