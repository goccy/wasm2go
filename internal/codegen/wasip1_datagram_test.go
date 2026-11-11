package codegen

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Datagram (UDP) sockets: bind, sendto and recvfrom between two sockets of
// one instance, connected sockets, readiness, and the policy hooks.

const (
	dgBufOff  int32 = 21000
	dgLenOff  int32 = 21600
	dgNameOff int32 = 21700
)

func newDatagramSocket(t *testing.T, w *WasiStubs, m *Module) int32 {
	t.Helper()
	fd := w.Sock_socket(m, 2, wasiSockTypeDgram)
	if fd < 0 {
		t.Fatalf("Sock_socket(datagram) = %d", fd)
	}
	return fd
}

func sendTo(w *WasiStubs, m *Module, fd int32, s string, ipBE uint32, port int32) (sent uint32, rc int32) {
	copy(m.memory[dgBufOff:], s)
	rc = w.Sock_sendto(m, fd, dgBufOff, int32(len(s)), 0, 1, int32(ipBE), port, dgLenOff)
	return readU32(m.memory, int(dgLenOff)), rc
}

func recvFrom(w *WasiStubs, m *Module, fd, capacity int32) (data string, from sockName, rc int32) {
	rc = w.Sock_recvfrom(m, fd, dgBufOff, capacity, 0, dgNameOff, dgLenOff)
	if rc != 0 {
		return "", sockName{}, rc
	}
	n := int32(readU32(m.memory, int(dgLenOff)))
	from = sockName{
		family: binary.LittleEndian.Uint32(m.memory[dgNameOff:]),
		ip:     binary.LittleEndian.Uint32(m.memory[dgNameOff+4:]),
		port:   binary.LittleEndian.Uint32(m.memory[dgNameOff+8:]),
	}
	return string(m.memory[dgBufOff : dgBufOff+n]), from, 0
}

func TestDatagram_SendToAndReceiveFrom(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetNetAccessHook(func(string) bool { return true })
	server := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, server, int32(loopbackBE), 0); rc != 0 {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	serverName := localName(t, w, m, server)
	if serverName.family != wasiSockFamilyIPv4 || serverName.ip != uint32(loopbackBE) || serverName.port == 0 {
		t.Fatalf("the bound socket's name = %+v", serverName)
	}
	if rc := w.Sock_getpeername(m, server, sockValueOff); rc != -_wasiENOTCONN {
		t.Fatalf("getpeername of an unconnected datagram socket rc=%d, want -ENOTCONN", rc)
	}

	// An unbound socket sends from an address the host picks.
	client := newDatagramSocket(t, w, m)
	if sent, rc := sendTo(w, m, client, "first", uint32(loopbackBE), int32(serverName.port)); rc != 0 || sent != 5 {
		t.Fatalf("sendto: %d bytes rc=%d", sent, rc)
	}
	if sent, rc := sendTo(w, m, client, "second datagram", uint32(loopbackBE), int32(serverName.port)); rc != 0 || sent != 15 {
		t.Fatalf("sendto: %d bytes rc=%d", sent, rc)
	}
	clientName := localName(t, w, m, client)
	if clientName.port == 0 {
		t.Fatalf("the sending socket has no port: %+v", clientName)
	}

	// Each receive takes one datagram and names its sender; a datagram
	// larger than the buffer is cut, and the rest of it is gone.
	got, from, rc := recvFrom(w, m, server, 64)
	if rc != 0 || got != "first" || from.port != clientName.port || from.ip != uint32(loopbackBE) {
		t.Fatalf("recvfrom = %q from %+v rc=%d", got, from, rc)
	}
	if got, _, rc := recvFrom(w, m, server, 6); rc != 0 || got != "second" {
		t.Fatalf("recvfrom into a short buffer = %q rc=%d, want %q", got, rc, "second")
	}

	// The server answers the sender.
	if _, rc := sendTo(w, m, server, "reply", from.ip, int32(from.port)); rc != 0 {
		t.Fatalf("reply rc=%d", rc)
	}
	if got, from, rc := recvFrom(w, m, client, 64); rc != 0 || got != "reply" || from.port != serverName.port {
		t.Fatalf("the client received %q from %+v rc=%d", got, from, rc)
	}

	// A datagram socket takes no connections.
	if rc := w.Sock_listen(m, server, 5); rc != -_wasiENOTSUP {
		t.Fatalf("listen on a datagram socket rc=%d, want -ENOTSUP", rc)
	}
	if ft := fdFiletype(t, w, m, server); ft != 5 {
		t.Fatalf("filetype of a datagram socket = %d, want 5", ft)
	}
	if rc := w.Sock_getopt(m, server, wasiSockOptType, sockValueOff); rc != 0 || int32(readU32(m.memory, int(sockValueOff))) != wasiSockTypeDgram {
		t.Fatalf("SO_TYPE rc=%d value=%d", rc, readU32(m.memory, int(sockValueOff)))
	}
}

func TestDatagram_ConnectedSocketSendsAndReceives(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetNetAccessHook(func(string) bool { return true })
	server := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, server, int32(loopbackBE), 0); rc != 0 {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	port := int32(localName(t, w, m, server).port)

	client := newDatagramSocket(t, w, m)
	if rc := w.Sock_connect(m, client, int32(loopbackBE), port); rc != 0 {
		t.Fatalf("Sock_connect rc=%d", rc)
	}
	if rc := w.Sock_getpeername(m, client, sockValueOff); rc != 0 || readSockName(m).port != uint32(port) {
		t.Fatalf("getpeername rc=%d name=%+v", rc, readSockName(m))
	}
	// send and write on a connected socket: one datagram each
	if rc := sockSend(w, m, client, "by send"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if rc := fdWriteString(w, m, client, "by write"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if _, rc := sendTo(w, m, client, "x", uint32(loopbackBE), port); rc != -_wasiEISCONN {
		t.Fatalf("sendto with an address on a connected socket rc=%d, want -EISCONN", rc)
	}
	got, from, rc := recvFrom(w, m, server, 64)
	if rc != 0 || got != "by send" {
		t.Fatalf("first datagram = %q rc=%d", got, rc)
	}
	if got, _, rc := recvFrom(w, m, server, 64); rc != 0 || got != "by write" {
		t.Fatalf("second datagram = %q rc=%d", got, rc)
	}
	// recv and read on the connected socket take what the peer sends back
	if _, rc := sendTo(w, m, server, "one", from.ip, int32(from.port)); rc != 0 {
		t.Fatalf("reply rc=%d", rc)
	}
	if _, rc := sendTo(w, m, server, "two", from.ip, int32(from.port)); rc != 0 {
		t.Fatalf("reply rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, client); rc != _wasiESUCCESS || got != "one" {
		t.Fatalf("Sock_recv = %q rc=%d", got, rc)
	}
	if got, rc := fdReadString(w, m, client, 64); rc != _wasiESUCCESS || got != "two" {
		t.Fatalf("Fd_read = %q rc=%d", got, rc)
	}
	// An unconnected socket has nobody to send to without an address.
	lonely := newDatagramSocket(t, w, m)
	if rc := sockSend(w, m, lonely, "x"); rc != _wasiENOTCONN {
		t.Fatalf("send on an unconnected datagram socket rc=%d, want ENOTCONN", rc)
	}
}

func TestDatagram_ReadinessNonBlockingAndSignals(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.SetNetAccessHook(func(string) bool { return true })
	server := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, server, int32(loopbackBE), 0); rc != 0 {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	port := int32(localName(t, w, m, server).port)
	client := newDatagramSocket(t, w, m)

	// Nothing to receive: a poll runs into its timeout, a non-blocking
	// receive is EAGAIN, a blocking one is ended by a signal.
	writeSubClock(m, pollSubsOff, 1, int64(40*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, server)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	postSoon(w, wasiSIGUSR1)
	if _, _, rc := recvFrom(w, m, server, 64); rc != -_wasiEINTR {
		t.Fatalf("blocking recvfrom with a signal rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	if rc := w.Fd_fdstat_set_flags(m, server, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if _, _, rc := recvFrom(w, m, server, 64); rc != -_wasiEAGAIN {
		t.Fatalf("non-blocking recvfrom rc=%d, want -EAGAIN", rc)
	}

	// A datagram makes the socket readable, and the poll does not eat it.
	if _, rc := sendTo(w, m, client, "ping", uint32(loopbackBE), port); rc != 0 {
		t.Fatalf("sendto rc=%d", rc)
	}
	writeSubClock(m, pollSubsOff, 1, int64(10*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1, server)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if got, from, rc := recvFrom(w, m, server, 64); rc != 0 || got != "ping" || from.port == 0 {
		t.Fatalf("after the poll recvfrom = %q from %+v rc=%d", got, from, rc)
	}
	// It is writable.
	if ok, rc := pollWritable(w, m, client, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("a datagram socket polled writable=%v rc=%d", ok, rc)
	}
}

func TestDatagram_IsSubjectToTheNetworkPolicy(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.SetNetAccessHook(func(op string) bool { return op != "listen" })
	sock := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, sock, int32(loopbackBE), 0); rc != -_wasiEACCES {
		t.Fatalf("bind without the listen permission rc=%d, want -EACCES", rc)
	}
	var asked []string
	w.SetDialHook(func(network, host, ip string, port int) bool {
		asked = append(asked, network+" "+net.JoinHostPort(ip, "x"))
		return false
	})
	if _, rc := sendTo(w, m, sock, "x", uint32(loopbackBE), 9); rc != -_wasiEACCES {
		t.Fatalf("sendto against the dial policy rc=%d, want -EACCES", rc)
	}
	if rc := w.Sock_connect(m, sock, int32(loopbackBE), 9); rc != -_wasiEACCES {
		t.Fatalf("connect against the dial policy rc=%d, want -EACCES", rc)
	}
	if len(asked) != 2 || asked[0] != "udp 127.0.0.1:x" || asked[1] != "udp 127.0.0.1:x" {
		t.Fatalf("the dial hook was asked %q", asked)
	}
	if fd := w.Sock_socket(m, 2, 3); fd != -_wasiEPROTONOSUPPORT {
		t.Fatalf("a socket of an unknown type = %d, want -EPROTONOSUPPORT", fd)
	}
}
