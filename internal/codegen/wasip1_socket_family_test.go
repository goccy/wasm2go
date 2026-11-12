package codegen

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Scratch offsets of the tests of sockets by address record.
const (
	addrOff  int32 = 14000
	addr2Off int32 = 14200
	pathOff  int32 = 14400
	fdsOff   int32 = 14600
	manyOff  int32 = 15000
)

// sockRecord is an address record as the tests read it back.
type sockRecord struct {
	family uint32
	port   uint32
	ip     string
	scope  uint32
	name   string
}

func readSockRecord(m *Module, off int32) sockRecord {
	rec := m.memory[off : off+wasiSockAddrSize]
	r := sockRecord{
		family: binary.LittleEndian.Uint32(rec[0:]),
		port:   binary.LittleEndian.Uint32(rec[4:]),
		scope:  binary.LittleEndian.Uint32(rec[24:]),
	}
	switch r.family {
	case wasiSockFamilyIPv4:
		r.ip = net.IP(rec[8:12]).String()
	case wasiSockFamilyIPv6:
		r.ip = net.IP(rec[8:24]).String()
	case wasiSockFamilyUnix:
		r.name = string(rec[32 : 32+binary.LittleEndian.Uint32(rec[28:])])
	}
	return r
}

// putIPAddr writes the address record of ip:port at off.
func putIPAddr(m *Module, off int32, ip string, port int32) {
	rec := m.memory[off : off+wasiSockAddrSize]
	for i := range rec {
		rec[i] = 0
	}
	parsed := net.ParseIP(ip)
	if v4 := parsed.To4(); v4 != nil {
		binary.LittleEndian.PutUint32(rec[0:], wasiSockFamilyIPv4)
		copy(rec[8:], v4)
	} else {
		binary.LittleEndian.PutUint32(rec[0:], wasiSockFamilyIPv6)
		copy(rec[8:], parsed.To16())
	}
	binary.LittleEndian.PutUint32(rec[4:], uint32(port))
}

// putUnixAddr writes the address record of the Unix-domain name at off, and
// the same as a path under the preopened root at pathOff; it returns the
// length of that path.
func putUnixAddr(m *Module, off int32, name string) int32 {
	rec := m.memory[off : off+wasiSockAddrSize]
	for i := range rec {
		rec[i] = 0
	}
	binary.LittleEndian.PutUint32(rec[0:], wasiSockFamilyUnix)
	binary.LittleEndian.PutUint32(rec[28:], uint32(len(name)))
	copy(rec[32:], name)
	// The guest of these tests has the root as its working directory.
	return int32(copy(m.memory[pathOff:], name))
}

func nameOf(t *testing.T, w *WasiStubs, m *Module, fd, peer int32) sockRecord {
	t.Helper()
	if rc := w.Sock_name(m, fd, peer, addr2Off); rc != _wasiESUCCESS {
		t.Fatalf("Sock_name(%d, peer %d) rc=%d", fd, peer, rc)
	}
	return readSockRecord(m, addr2Off)
}

// newSocketFamilyStubs is newProcTestStubs with a root whose path is short:
// the name of a Unix-domain socket has little room.
func newSocketFamilyStubs(t *testing.T) (*WasiStubs, *Module, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "w2g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	w, m := newTestStubs(t, root)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	return w, m, root
}

func skipWithoutUnixSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the tests of Unix-domain sockets run on darwin and linux")
	}
}

// A named Unix-domain stream socket: bind makes the socket file, a client
// connects to it by name, both ends know the names, and closing the
// listener leaves the file, as close(2) does.
func TestSocketFamily_UnixStream(t *testing.T) {
	skipWithoutUnixSockets(t)
	w, m, root := newSocketFamilyStubs(t)
	server := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if got := nameOf(t, w, m, server, 0); got.family != wasiSockFamilyUnix || got.name != "" {
		t.Fatalf("name of an unbound socket = %+v", got)
	}
	if rc := w.Sock_listen(m, server, 5); rc != -_wasiEINVAL {
		t.Fatalf("listen on an unbound socket rc=%d, want -EINVAL", rc)
	}
	n := putUnixAddr(m, addrOff, "srv.sock")
	if rc := w.Sock_bind_addr(m, server, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr rc=%d", rc)
	}
	if fi, err := os.Stat(filepath.Join(root, "srv.sock")); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("bind made no socket file: %v", err)
	}
	other := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_bind_addr(m, other, addrOff, pathOff, n); rc != -_wasiEADDRINUSE {
		t.Fatalf("second bind of the name rc=%d, want -EADDRINUSE", rc)
	}
	if rc := w.Sock_listen(m, server, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	if got := nameOf(t, w, m, server, 0); got.name != "srv.sock" {
		t.Fatalf("name of the listener = %+v", got)
	}

	client := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_connect_addr(m, client, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect_addr rc=%d", rc)
	}
	if got := nameOf(t, w, m, client, 1); got.name != "srv.sock" {
		t.Fatalf("peer of the client = %+v", got)
	}
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	if got := nameOf(t, w, m, conn, 0); got.name != "srv.sock" {
		t.Fatalf("local name of the accepted connection = %+v", got)
	}
	if got := nameOf(t, w, m, conn, 1); got.family != wasiSockFamilyUnix || got.name != "" {
		t.Fatalf("peer of the accepted connection = %+v, want a socket without a name", got)
	}
	if rc := sockSend(w, m, client, "to the server"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, conn); rc != _wasiESUCCESS || got != "to the server" {
		t.Fatalf("server received %q rc=%d", got, rc)
	}

	// Nobody listens at a name that is not there, and a socket of another
	// family does not take the address.
	n2 := putUnixAddr(m, addr2Off, "nobody.sock")
	stray := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_connect_addr(m, stray, addr2Off, pathOff, n2); rc != -_wasiENOENT {
		t.Fatalf("connect to a missing name rc=%d, want -ENOENT", rc)
	}
	inet := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	n = putUnixAddr(m, addrOff, "srv.sock")
	if rc := w.Sock_connect_addr(m, inet, addrOff, pathOff, n); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("connect of an IPv4 socket to a Unix name rc=%d, want -EAFNOSUPPORT", rc)
	}

	if rc := w.Fd_close(m, server); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	if _, err := os.Stat(filepath.Join(root, "srv.sock")); err != nil {
		t.Fatalf("closing the listener removed the socket file: %v", err)
	}
	late := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_connect_addr(m, late, addrOff, pathOff, n); rc != -_wasiECONNREFUSED {
		t.Fatalf("connect to a name nobody listens at rc=%d, want -ECONNREFUSED", rc)
	}
}

// Unix-domain datagram sockets: a bound one receives from a named and from
// an unnamed sender and knows which; a connected one sends without an
// address.
func TestSocketFamily_UnixDatagram(t *testing.T) {
	skipWithoutUnixSockets(t)
	w, m, _ := newSocketFamilyStubs(t)
	server := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeDgram)
	n := putUnixAddr(m, addrOff, "dg.sock")
	if rc := w.Sock_bind_addr(m, server, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr rc=%d", rc)
	}

	send := func(fd int32, s string, to bool) int32 {
		copy(m.memory[sockBufOff:], s)
		target := int32(0)
		if to {
			target = addrOff
		}
		return w.Sock_sendto_addr(m, fd, sockBufOff, int32(len(s)), 0, target, pathOff, n, sockLenOff)
	}
	recv := func(fd int32) (string, sockRecord) {
		t.Helper()
		if rc := w.Sock_recvfrom_addr(m, fd, sockBufOff, 64, 0, addr2Off, sockLenOff); rc != _wasiESUCCESS {
			t.Fatalf("Sock_recvfrom_addr rc=%d", rc)
		}
		return string(m.memory[sockBufOff : sockBufOff+int32(readU32(m.memory, int(sockLenOff)))]), readSockRecord(m, addr2Off)
	}

	anonymous := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeDgram)
	if rc := send(anonymous, "no return address", true); rc != _wasiESUCCESS {
		t.Fatalf("Sock_sendto_addr rc=%d", rc)
	}
	if data, from := recv(server); data != "no return address" || from.family != 0 {
		t.Fatalf("received %q from %+v, want a sender without a name", data, from)
	}

	named := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeDgram)
	n = putUnixAddr(m, addrOff, "client.sock")
	if rc := w.Sock_bind_addr(m, named, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr rc=%d", rc)
	}
	n = putUnixAddr(m, addrOff, "dg.sock")
	if rc := w.Sock_connect_addr(m, named, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect_addr rc=%d", rc)
	}
	if rc := send(named, "with a return address", false); rc != _wasiESUCCESS {
		t.Fatalf("send on the connected socket rc=%d", rc)
	}
	data, from := recv(server)
	if data != "with a return address" || from.family != wasiSockFamilyUnix || from.name != "/client.sock" {
		t.Fatalf("received %q from %+v", data, from)
	}
	// The answer goes to the name the datagram came from.
	n = putUnixAddr(m, addrOff, "client.sock")
	if rc := send(server, "answer", true); rc != _wasiESUCCESS {
		t.Fatalf("answer rc=%d", rc)
	}
	if data, _ := recv(named); data != "answer" {
		t.Fatalf("the client received %q", data)
	}
}

// socketpair makes pairs of Unix-domain stream and datagram sockets, and
// refuses the families that have none.
func TestSocketFamily_Pairs(t *testing.T) {
	skipWithoutUnixSockets(t)
	w, m, _ := newSocketFamilyStubs(t)
	if rc := w.Sock_socketpair(m, wasiSockFamilyIPv4, wasiSockTypeStream, fdsOff); rc != -_wasiENOTSUP {
		t.Fatalf("pair of IPv4 sockets rc=%d, want -ENOTSUP", rc)
	}
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, 5, fdsOff); rc != -_wasiEPROTONOSUPPORT {
		t.Fatalf("pair of an unknown type rc=%d, want -EPROTONOSUPPORT", rc)
	}
	for _, typ := range []int32{wasiSockTypeStream, wasiSockTypeDgram} {
		if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, typ, fdsOff); rc != _wasiESUCCESS {
			t.Fatalf("Sock_socketpair(type %d) rc=%d", typ, rc)
		}
		a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
		if rc := w.Sock_getopt(m, a, wasiSockOptType, sockValueOff); rc != _wasiESUCCESS || int32(readU32(m.memory, int(sockValueOff))) != typ {
			t.Fatalf("SO_TYPE of a pair end = %d rc=%d, want %d", readU32(m.memory, int(sockValueOff)), rc, typ)
		}
		for _, msg := range []string{"first", "second"} {
			if rc := sockSend(w, m, a, msg); rc != _wasiESUCCESS {
				t.Fatalf("type %d: Sock_send rc=%d", typ, rc)
			}
		}
		got, rc := sockRecv(w, m, b)
		want := "firstsecond"
		if typ == wasiSockTypeDgram {
			want = "first" // a datagram at a time
		}
		if rc != _wasiESUCCESS || got != want {
			t.Fatalf("type %d: b received %q rc=%d, want %q", typ, got, rc, want)
		}
		if got := nameOf(t, w, m, a, 1); got.family != wasiSockFamilyUnix {
			t.Fatalf("type %d: peer of a pair end = %+v", typ, got)
		}
	}
}

func skipWithoutIPv6(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("this machine has no IPv6 loopback: %v", err)
	}
	l.Close()
}

// IPv6 sockets: stream and datagram, with their names; IPV6_V6ONLY decides
// whether a socket bound to every address takes IPv4 connections too.
func TestSocketFamily_IPv6(t *testing.T) {
	skipWithoutIPv6(t)
	w, m, _ := newSocketFamilyStubs(t)
	server := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeStream)
	if got := nameOf(t, w, m, server, 0); got.family != wasiSockFamilyIPv6 || got.ip != "::" {
		t.Fatalf("name of an unbound socket = %+v", got)
	}
	putIPAddr(m, addrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, server, addrOff, 0, 0); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("bind of an IPv6 socket to an IPv4 address rc=%d, want -EAFNOSUPPORT", rc)
	}
	putIPAddr(m, addrOff, "::1", 0)
	if rc := w.Sock_bind_addr(m, server, addrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr rc=%d", rc)
	}
	if rc := w.Sock_listen(m, server, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	bound := nameOf(t, w, m, server, 0)
	if bound.family != wasiSockFamilyIPv6 || bound.ip != "::1" || bound.port == 0 {
		t.Fatalf("name of the listener = %+v", bound)
	}
	client := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeStream)
	putIPAddr(m, addrOff, "::1", int32(bound.port))
	if rc := w.Sock_connect_addr(m, client, addrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect_addr rc=%d", rc)
	}
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	if peer, local := nameOf(t, w, m, conn, 1), nameOf(t, w, m, client, 0); peer != local || peer.ip != "::1" {
		t.Fatalf("the connection came from %+v, the client is at %+v", peer, local)
	}
	if rc := sockSend(w, m, client, "over IPv6"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, conn); rc != _wasiESUCCESS || got != "over IPv6" {
		t.Fatalf("server received %q rc=%d", got, rc)
	}

	// Datagrams.
	receiver := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeDgram)
	putIPAddr(m, addrOff, "::1", 0)
	if rc := w.Sock_bind_addr(m, receiver, addrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("bind of a datagram socket rc=%d", rc)
	}
	at := nameOf(t, w, m, receiver, 0)
	sender := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeDgram)
	putIPAddr(m, addrOff, "::1", int32(at.port))
	copy(m.memory[sockBufOff:], "datagram")
	if rc := w.Sock_sendto_addr(m, sender, sockBufOff, 8, 0, addrOff, 0, 0, sockLenOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_sendto_addr rc=%d", rc)
	}
	if rc := w.Sock_recvfrom_addr(m, receiver, sockBufOff, 64, 0, addr2Off, sockLenOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_recvfrom_addr rc=%d", rc)
	}
	if from, sent := readSockRecord(m, addr2Off), nameOf(t, w, m, sender, 0); from.ip != "::1" || from.port != sent.port {
		t.Fatalf("the datagram came from %+v, the sender is at %+v", from, sent)
	}

	// IPV6_V6ONLY.
	for _, only := range []int32{1, 0} {
		l := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeStream)
		if rc := w.Sock_setopt(m, l, wasiSockOptV6Only, only); rc != _wasiESUCCESS {
			t.Fatalf("set IPV6_V6ONLY rc=%d", rc)
		}
		putIPAddr(m, addrOff, "::", 0)
		if rc := w.Sock_bind_addr(m, l, addrOff, 0, 0); rc != _wasiESUCCESS {
			t.Fatalf("bind to every address rc=%d", rc)
		}
		if rc := w.Sock_listen(m, l, 5); rc != _wasiESUCCESS {
			t.Fatalf("Sock_listen rc=%d", rc)
		}
		if rc := w.Sock_getopt(m, l, wasiSockOptV6Only, sockValueOff); rc != _wasiESUCCESS || int32(readU32(m.memory, int(sockValueOff))) != only {
			t.Fatalf("IPV6_V6ONLY reads %d rc=%d, want %d", readU32(m.memory, int(sockValueOff)), rc, only)
		}
		port := int32(nameOf(t, w, m, l, 0).port)
		v4 := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
		putIPAddr(m, addrOff, "127.0.0.1", port)
		rc := w.Sock_connect_addr(m, v4, addrOff, 0, 0)
		if only == 1 && rc != -_wasiECONNREFUSED {
			t.Fatalf("IPv4 connect to an IPv6-only listener rc=%d, want -ECONNREFUSED", rc)
		}
		if only == 0 {
			if rc != _wasiESUCCESS {
				t.Fatalf("IPv4 connect to a listener of both families rc=%d", rc)
			}
			conn, rc := acceptOn(w, m, l)
			if rc != _wasiESUCCESS {
				t.Fatalf("Sock_accept rc=%d", rc)
			}
			if peer := nameOf(t, w, m, conn, 1); peer.family != wasiSockFamilyIPv6 || peer.ip != "127.0.0.1" {
				// net.IP prints an IPv4-mapped address as the IPv4 one
				t.Fatalf("peer of the IPv4 connection on the IPv6 socket = %+v", peer)
			}
		}
		w.Fd_close(m, v4)
		w.Fd_close(m, l)
	}
}

// A connect on a non-blocking socket does not wait: it reports EINPROGRESS
// (or is done at once), the socket polls writable when the attempt has
// ended, and SO_ERROR then tells how it ended, once.
func TestSocketFamily_NonBlockingConnect(t *testing.T) {
	w, m, _ := newSocketFamilyStubs(t)
	// A listener of the host whose backlog nobody empties still completes
	// connections; a port nobody listens on refuses them.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := int32(l.Addr().(*net.TCPAddr).Port)

	client := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Fd_fdstat_set_flags(m, client, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	putIPAddr(m, addrOff, "127.0.0.1", port)
	rc := w.Sock_connect_addr(m, client, addrOff, 0, 0)
	if rc != _wasiESUCCESS && rc != -_wasiEINPROGRESS {
		t.Fatalf("non-blocking connect rc=%d, want 0 or -EINPROGRESS", rc)
	}
	writeSubClock(m, pollSubsOff, 1, int64(5*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 2 /* fd_write */, client)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if rc := w.Sock_getopt(m, client, wasiSockOptError, sockValueOff); rc != _wasiESUCCESS || readU32(m.memory, int(sockValueOff)) != 0 {
		t.Fatalf("SO_ERROR after a connect that succeeded = %d rc=%d", readU32(m.memory, int(sockValueOff)), rc)
	}
	if rc := w.Sock_connect_addr(m, client, addrOff, 0, 0); rc != -_wasiEISCONN {
		t.Fatalf("connect of a connected socket rc=%d, want -EISCONN", rc)
	}
	if got := nameOf(t, w, m, client, 1); got.port != uint32(port) {
		t.Fatalf("peer of the connected socket = %+v", got)
	}

	// Refused: the port of a listener that is gone.
	gone, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := int32(gone.Addr().(*net.TCPAddr).Port)
	gone.Close()
	second := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	w.Fd_fdstat_set_flags(m, second, wasiFdflagNonblock)
	putIPAddr(m, addrOff, "127.0.0.1", refused)
	rc = w.Sock_connect_addr(m, second, addrOff, 0, 0)
	if rc == -_wasiEINPROGRESS {
		writeSubClock(m, pollSubsOff, 1, int64(5*time.Second))
		writeSubFd(m, pollSubsOff+48, 2, 2, second)
		wantUserdata(t, pollUserdata(t, w, m, 2), 2)
		if rc := w.Sock_getopt(m, second, wasiSockOptError, sockValueOff); rc != _wasiESUCCESS || int32(readU32(m.memory, int(sockValueOff))) != _wasiECONNREFUSED {
			t.Fatalf("SO_ERROR after a refused connect = %d rc=%d, want ECONNREFUSED", readU32(m.memory, int(sockValueOff)), rc)
		}
		if rc := w.Sock_getopt(m, second, wasiSockOptError, sockValueOff); rc != _wasiESUCCESS || readU32(m.memory, int(sockValueOff)) != 0 {
			t.Fatalf("SO_ERROR read again = %d rc=%d, want 0", readU32(m.memory, int(sockValueOff)), rc)
		}
	} else if rc != -_wasiECONNREFUSED {
		t.Fatalf("connect to a port nobody listens on rc=%d", rc)
	}
}

// A blocking connect that waits is ended by a signal posted to the guest,
// and by the socket's send timeout.
func TestSocketFamily_BlockingConnectIsInterruptible(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("needs an address that does not answer")
	}
	w, m, _ := newSocketFamilyStubs(t)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d, want 0 (new)", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGALRM), 0, 0)
	// An address reserved for documentation: nothing answers, nothing
	// refuses.
	putIPAddr(m, addrOff, "192.0.2.1", 9)
	fd := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	go func() {
		time.Sleep(50 * time.Millisecond)
		w.PostSignal(wasiSIGALRM)
	}()
	start := time.Now()
	rc := w.Sock_connect_addr(m, fd, addrOff, 0, 0)
	if rc == -_wasiENETUNREACH {
		t.Skip("this machine has no route to try")
	}
	if rc != -_wasiEINTR || time.Since(start) > 5*time.Second {
		t.Fatalf("connect rc=%d after %v, want -EINTR at once", rc, time.Since(start))
	}
	if rc := w.Sock_connect_addr(m, fd, addrOff, 0, 0); rc != -_wasiEALREADY {
		t.Fatalf("connect while the attempt goes on rc=%d, want -EALREADY", rc)
	}

	timed := w.Sock_open(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Sock_timeout(m, timed, wasiSockTimeoutSend, 1, int64(80*time.Millisecond), sockValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_timeout rc=%d", rc)
	}
	start = time.Now()
	if rc := w.Sock_connect_addr(m, timed, addrOff, 0, 0); rc != -_wasiEINPROGRESS || time.Since(start) > 5*time.Second {
		t.Fatalf("connect with a send timeout rc=%d after %v, want -EINPROGRESS", rc, time.Since(start))
	}
	w.Fd_close(m, fd)
	w.Fd_close(m, timed)
}

// Sock_resolve gives the addresses of a name of the family asked for, and
// converts an address written in numbers without a lookup.
func TestSocketFamily_Resolve(t *testing.T) {
	w, m, _ := newSocketFamilyStubs(t)
	asked := false
	w.SetResolveHook(func(host string) bool { asked = true; return host == "localhost" })
	resolve := func(node string, family int32) ([]sockRecord, int32) {
		copy(m.memory[sockBufOff:], node)
		rc := w.Sock_resolve(m, sockBufOff, int32(len(node)), family, manyOff, 8, sockLenOff)
		if rc != _wasiESUCCESS {
			return nil, rc
		}
		var out []sockRecord
		for i := int32(0); i < int32(readU32(m.memory, int(sockLenOff))); i++ {
			out = append(out, readSockRecord(m, manyOff+i*wasiSockAddrSize))
		}
		return out, rc
	}
	got, rc := resolve("127.0.0.1", 0)
	if rc != _wasiESUCCESS || len(got) != 1 || got[0].family != wasiSockFamilyIPv4 || got[0].ip != "127.0.0.1" {
		t.Fatalf("resolve of an IPv4 address = %+v rc=%d", got, rc)
	}
	got, rc = resolve("::1", wasiSockFamilyIPv6)
	if rc != _wasiESUCCESS || len(got) != 1 || got[0].family != wasiSockFamilyIPv6 || got[0].ip != "::1" {
		t.Fatalf("resolve of an IPv6 address = %+v rc=%d", got, rc)
	}
	if _, rc := resolve("::1", wasiSockFamilyIPv4); rc != -_wasiENOENT {
		t.Fatalf("an IPv6 address asked for as IPv4 rc=%d, want -ENOENT", rc)
	}
	if asked {
		t.Fatal("the lookup policy was asked about an address written in numbers")
	}
	got, rc = resolve("localhost", wasiSockFamilyIPv4)
	if rc != _wasiESUCCESS || len(got) == 0 || got[0].ip != "127.0.0.1" {
		t.Fatalf("resolve of localhost = %+v rc=%d", got, rc)
	}
	if _, rc := resolve("refused.example", 0); rc != -_wasiEACCES {
		t.Fatalf("resolve of a name the policy refuses rc=%d, want -EACCES", rc)
	}
}

// The policies are asked about sockets of every family as about IPv4 ones.
func TestSocketFamily_Policies(t *testing.T) {
	skipWithoutUnixSockets(t)
	w, m, _ := newSocketFamilyStubs(t)
	type dial struct {
		network, ip string
		port        int
	}
	var dials []dial
	allow := false
	w.SetDialHook(func(network, host, ip string, port int) bool {
		dials = append(dials, dial{network, ip, port})
		return allow
	})
	n := putUnixAddr(m, addrOff, "p.sock")
	server := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	w.SetNetAccessHook(func(op string) bool { return op != "listen" })
	if rc := w.Sock_bind_addr(m, server, addrOff, pathOff, n); rc != -_wasiEACCES {
		t.Fatalf("bind with listening refused rc=%d, want -EACCES", rc)
	}
	w.SetNetAccessHook(nil)
	if rc := w.Sock_bind_addr(m, server, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr rc=%d", rc)
	}
	w.Sock_listen(m, server, 1)
	client := w.Sock_open(m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_connect_addr(m, client, addrOff, pathOff, n); rc != -_wasiEACCES {
		t.Fatalf("connect with dialing refused rc=%d, want -EACCES", rc)
	}
	six := w.Sock_open(m, wasiSockFamilyIPv6, wasiSockTypeStream)
	putIPAddr(m, addr2Off, "::1", 9)
	if rc := w.Sock_connect_addr(m, six, addr2Off, 0, 0); rc != -_wasiEACCES {
		t.Fatalf("IPv6 connect with dialing refused rc=%d, want -EACCES", rc)
	}
	want := []dial{{"unix", "/p.sock", 0}, {"tcp", "::1", 9}}
	if len(dials) != len(want) || dials[0] != want[0] || dials[1] != want[1] {
		t.Fatalf("the dial policy was asked %+v, want %+v", dials, want)
	}
	allow = true
	if rc := w.Sock_connect_addr(m, client, addrOff, pathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("connect with dialing allowed rc=%d", rc)
	}
}
