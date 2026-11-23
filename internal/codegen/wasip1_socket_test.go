//go:build darwin || linux

package codegen

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Scratch offsets of the socket tests.
const (
	sockValueOff int32 = 13000
	sockIovOff   int32 = 13040
	sockLenOff   int32 = 13060
	sockFlagsOff int32 = 13064
	sockBufOff   int32 = 13100
	sockAddrOff  int32 = 14000
	sockAddr2Off int32 = 14200
	sockPathOff  int32 = 14400
	sockFdsOff   int32 = 14600
	sockManyOff  int32 = 15000
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
	r := sockRecord{family: binary.LittleEndian.Uint32(rec[0:]), port: binary.LittleEndian.Uint32(rec[4:])}
	switch int32(r.family) {
	case wasiSockFamilyIPv4:
		r.ip = net.IP(rec[8:12]).String()
	case wasiSockFamilyIPv6:
		r.ip = net.IP(rec[8:24]).String()
		r.scope = binary.LittleEndian.Uint32(rec[24:])
	case wasiSockFamilyUnix:
		r.name = string(rec[32 : 32+binary.LittleEndian.Uint32(rec[28:])])
	}
	return r
}

// putIPAddr writes the address record of ip:port at off.
func putIPAddr(m *Module, off int32, ip string, port int32) {
	rec := m.memory[off : off+wasiSockAddrSize]
	clear(rec)
	parsed := net.ParseIP(ip)
	if v4 := parsed.To4(); v4 != nil {
		binary.LittleEndian.PutUint32(rec[0:], uint32(wasiSockFamilyIPv4))
		copy(rec[8:], v4)
	} else {
		binary.LittleEndian.PutUint32(rec[0:], uint32(wasiSockFamilyIPv6))
		copy(rec[8:], parsed.To16())
	}
	binary.LittleEndian.PutUint32(rec[4:], uint32(port))
}

// putUnixAddr writes the address record of the Unix-domain socket at the
// host path at off, and the same path under the preopened root, the whole
// host filesystem, at sockPathOff; it returns the length of that path.
func putUnixAddr(m *Module, off int32, path string) int32 {
	rec := m.memory[off : off+wasiSockAddrSize]
	clear(rec)
	binary.LittleEndian.PutUint32(rec[0:], uint32(wasiSockFamilyUnix))
	binary.LittleEndian.PutUint32(rec[28:], uint32(len(path)))
	copy(rec[32:], path)
	return int32(copy(m.memory[sockPathOff:], strings.TrimPrefix(path, "/")))
}

func nameOf(t *testing.T, w *WasiStubs, m *Module, fd, peer int32) sockRecord {
	t.Helper()
	if rc := w.Sock_name(m, fd, peer, sockAddr2Off); rc != _wasiESUCCESS {
		t.Fatalf("Sock_name(%d, peer %d) rc=%d", fd, peer, rc)
	}
	return readSockRecord(m, sockAddr2Off)
}

func acceptOn(w *WasiStubs, m *Module, fd int32) (conn int32, rc int32) {
	rc = w.Sock_accept(m, fd, 0, sockValueOff)
	return int32(readU32(m.memory, int(sockValueOff))), rc
}

func sockSend(w *WasiStubs, m *Module, fd int32, s string) int32 {
	copy(m.memory[sockBufOff:], s)
	makeIovec(m, sockIovOff, sockBufOff, int32(len(s)))
	return w.Sock_send(m, fd, sockIovOff, 1, 0, sockLenOff)
}

func sockRecv(w *WasiStubs, m *Module, fd int32) (string, int32) {
	makeIovec(m, sockIovOff, sockBufOff, 64)
	rc := w.Sock_recv(m, fd, sockIovOff, 1, 0, sockLenOff, sockFlagsOff)
	if rc != _wasiESUCCESS {
		return "", rc
	}
	n := readU32(m.memory, int(sockLenOff))
	return string(m.memory[sockBufOff : sockBufOff+int32(n)]), rc
}

// recvFrom is Sock_recvfrom_addr into the scratch buffer, the sender's
// record at sockAddr2Off.
func recvFrom(w *WasiStubs, m *Module, fd, size, flags int32) (string, sockRecord, int32) {
	rc := w.Sock_recvfrom_addr(m, fd, sockBufOff, size, flags, sockAddr2Off, sockLenOff)
	if rc != _wasiESUCCESS {
		return "", sockRecord{}, rc
	}
	n := readU32(m.memory, int(sockLenOff))
	return string(m.memory[sockBufOff : sockBufOff+int32(n)]), readSockRecord(m, sockAddr2Off), rc
}

// sendTo is Sock_sendto_addr of s, to the record at sockAddrOff (with the
// path of n bytes at sockPathOff) when to is set.
func sendTo(w *WasiStubs, m *Module, fd int32, s string, to bool, n int32) int32 {
	copy(m.memory[sockBufOff:], s)
	target := int32(0)
	if to {
		target = sockAddrOff
	}
	return w.Sock_sendto_addr(m, fd, sockBufOff, int32(len(s)), 0, target, sockPathOff, n, sockLenOff)
}

// newSocketStubs is newProcTestStubs with the whole host filesystem, which
// Unix-domain sockets live in, every local address allowed, and a directory
// whose path is short: the name of a Unix-domain socket has little room.
func newSocketStubs(t *testing.T) (*WasiStubs, *Module, string) {
	t.Helper()
	skipWithoutRawSockets(t)
	dir, err := os.MkdirTemp("/tmp", "w2g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
	w, m := newProcTestStubs(t)
	closeAllAtCleanup(t, w)
	w.cfg.FS = osFS{}
	w.cfg.Listen = AllowAllListen
	return w, m, dir
}

func skipWithoutRawSockets(t *testing.T) {
	t.Helper()
	if !hostOpensSockets {
		t.Skip("the runtime makes no sockets of the host's here")
	}
}

// openSocket is Sock_open that must succeed.
func openSocket(t *testing.T, w *WasiStubs, m *Module, family, typ int32) int32 {
	t.Helper()
	fd := w.Sock_open(m, family, typ)
	if fd < 0 {
		t.Fatalf("Sock_open(%d, %d) rc=%d", family, typ, fd)
	}
	return fd
}

// newIPListener is a stream socket bound to 127.0.0.1 at a port the host
// picks, listening; it returns the fd and the port.
func newIPListener(t *testing.T, w *WasiStubs, m *Module) (fd, port int32) {
	t.Helper()
	fd = openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	if rc := w.Sock_listen(m, fd, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	return fd, int32(nameOf(t, w, m, fd, 0).port)
}

// connectTo is a stream socket connected to 127.0.0.1:port.
func connectTo(t *testing.T, w *WasiStubs, m *Module, port int32) int32 {
	t.Helper()
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect_addr rc=%d", rc)
	}
	return fd
}

// hostNonblocking reports whether the host socket of fd's open file
// description is in non-blocking mode.
func hostNonblocking(t *testing.T, w *WasiStubs, fd int32) bool {
	t.Helper()
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	var flags int
	var err error
	if errno := w.socketCall("test", op.hostSocket(), func(fd int) { flags, err = descriptorFlags(fd, syscall.F_GETFL) }); errno != _wasiESUCCESS || err != nil {
		t.Fatalf("F_GETFL errno=%d err=%v", errno, err)
	}
	return flags&syscall.O_NONBLOCK != 0
}

func TestSocket_OpenRefuses(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	if rc := w.Sock_open(m, 9, wasiSockTypeStream); rc != -_wasiEAFNOSUPPORT {
		t.Errorf("Sock_open of an unknown family rc=%d, want -EAFNOSUPPORT", rc)
	}
	if rc := w.Sock_open(m, wasiSockFamilyIPv4, 9); rc != -_wasiEINVAL {
		t.Errorf("Sock_open of an unknown type rc=%d, want -EINVAL", rc)
	}
	if rc := w.Sock_listen(m, 3, 1); rc != -_wasiENOTSOCK {
		t.Errorf("Sock_listen of the preopened root rc=%d, want -ENOTSOCK", rc)
	}
	if rc := w.Sock_listen(m, 99, 1); rc != -_wasiEBADF {
		t.Errorf("Sock_listen of a closed fd rc=%d, want -EBADF", rc)
	}
}

// A TCP server and client: bind, listen, connect, accept, and the
// transfers of every import, with the names the host gives.
func TestSocket_ServerAndClient(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	server, port := newIPListener(t, w, m)
	client := connectTo(t, w, m, port)
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	if got := nameOf(t, w, m, client, 1); got.ip != "127.0.0.1" || got.port != uint32(port) {
		t.Fatalf("peer of the client %+v", got)
	}
	if rc := sockSend(w, m, client, "ping"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, conn); rc != _wasiESUCCESS || got != "ping" {
		t.Fatalf("Sock_recv = %q rc=%d", got, rc)
	}
	if rc := fdWriteString(w, m, conn, "pong"); rc != _wasiESUCCESS {
		t.Fatalf("fd_write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, client, 16); rc != _wasiESUCCESS || got != "pong" {
		t.Fatalf("fd_read = %q rc=%d", got, rc)
	}
	if rc := sendTo(w, m, client, "x", false, 0); rc != _wasiESUCCESS {
		t.Fatalf("sendto rc=%d", rc)
	}
	if got, from, rc := recvFrom(w, m, conn, 8, 0); rc != _wasiESUCCESS || got != "x" || from.family != 0 {
		t.Fatalf("recvfrom of a stream socket = %q from %+v rc=%d", got, from, rc)
	}
	for _, fd := range []int32{server, client, conn} {
		if rc := w.Fd_fdstat_get(m, fd, sockValueOff); rc != _wasiESUCCESS || m.memory[sockValueOff] != 6 {
			t.Fatalf("fdstat of fd %d: rc=%d filetype=%d, want a stream socket (6)", fd, rc, m.memory[sockValueOff])
		}
	}
	// The host says what a socket without a connection is.
	other := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Sock_name(m, other, 1, sockAddr2Off); rc != -_wasiENOTCONN {
		t.Fatalf("peer of an unconnected socket rc=%d, want -ENOTCONN", rc)
	}
	// Shutting down the client's writing ends the connection's input.
	if rc := w.Sock_shutdown(m, client, 2); rc != _wasiESUCCESS {
		t.Fatalf("Sock_shutdown rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, conn, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read after the peer's shutdown = %q rc=%d, want the end of input", got, rc)
	}
}

// The Listen and Dial policies are asked before a socket takes an address
// others reach it at, and before it connects.
func TestSocket_Policies(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	var listened []string
	w.cfg.Listen = func(network, address string) bool {
		listened = append(listened, network+" "+address)
		return false
	}
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEACCES {
		t.Fatalf("refused bind rc=%d, want -EACCES", rc)
	}
	if rc := w.Sock_listen(m, fd, 1); rc != -_wasiEACCES {
		t.Fatalf("refused listen of an unbound socket rc=%d, want -EACCES", rc)
	}
	udp := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 9)
	if rc := sendTo(w, m, udp, "x", true, 0); rc != -_wasiEACCES {
		t.Fatalf("refused first send of an unbound datagram socket rc=%d, want -EACCES", rc)
	}
	want := []string{"tcp 127.0.0.1:0", "tcp 0.0.0.0:0", "udp 0.0.0.0:0"}
	if strings.Join(listened, ",") != strings.Join(want, ",") {
		t.Fatalf("Listen was asked %v, want %v", listened, want)
	}
	// Once allowed, a socket is not asked about again.
	w.cfg.Listen = func(network, address string) bool {
		listened = append(listened, network+" "+address)
		return true
	}
	listened = nil
	for range 2 {
		if rc := sendTo(w, m, udp, "x", true, 0); rc != _wasiESUCCESS {
			t.Fatalf("allowed send rc=%d", rc)
		}
	}
	if len(listened) != 1 {
		t.Fatalf("Listen was asked %v, want once", listened)
	}
	var dialed []string
	w.cfg.Dial = func(network, host, ip string, port int) bool {
		dialed = append(dialed, network+" "+ip)
		return false
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", 9)
	if rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEACCES {
		t.Fatalf("refused connect rc=%d, want -EACCES", rc)
	}
	if rc := sendTo(w, m, udp, "x", true, 0); rc != -_wasiEACCES {
		t.Fatalf("refused send rc=%d, want -EACCES", rc)
	}
	if len(dialed) != 2 {
		t.Fatalf("Dial was asked %v, want twice", dialed)
	}
}

// A datagram socket sends to addresses and to its peer; a receive names
// the sender; sends of nothing send an empty datagram, a write of nothing
// none.
func TestSocket_Datagrams(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	receiver := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, receiver, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	port := int32(nameOf(t, w, m, receiver, 0).port)
	sender := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := sendTo(w, m, sender, "one", true, 0); rc != _wasiESUCCESS {
		t.Fatalf("sendto rc=%d", rc)
	}
	got, from, rc := recvFrom(w, m, receiver, 64, 0)
	if rc != _wasiESUCCESS || got != "one" || from.port != nameOf(t, w, m, sender, 0).port {
		t.Fatalf("recvfrom = %q from %+v rc=%d", got, from, rc)
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := w.Sock_connect_addr(m, sender, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("connect rc=%d", rc)
	}
	if rc := sockSend(w, m, sender, ""); rc != _wasiESUCCESS {
		t.Fatalf("send of nothing rc=%d", rc)
	}
	if rc := fdWriteString(w, m, sender, ""); rc != _wasiESUCCESS {
		t.Fatalf("write of nothing rc=%d", rc)
	}
	if rc := sockSend(w, m, sender, "two"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	for _, want := range []string{"", "two"} {
		if got, rc := sockRecv(w, m, receiver); rc != _wasiESUCCESS || got != want {
			t.Fatalf("recv = %q rc=%d, want %q", got, rc, want)
		}
	}
	if rc := w.Fd_fdstat_get(m, sender, sockValueOff); rc != _wasiESUCCESS || m.memory[sockValueOff] != 5 {
		t.Fatalf("fdstat filetype=%d rc=%d, want a datagram socket (5)", m.memory[sockValueOff], rc)
	}
	// A receive that asks for no address writes none.
	if rc := sockSend(w, m, sender, "three"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	if rc := w.Sock_recvfrom_addr(m, receiver, sockBufOff, 64, 0, 0, sockLenOff); rc != _wasiESUCCESS || readU32(m.memory, int(sockLenOff)) != 5 {
		t.Fatalf("recvfrom without an address rc=%d count=%d", rc, readU32(m.memory, int(sockLenOff)))
	}
}

// The guest's O_NONBLOCK is the entry's: a call that does not wait reports
// EAGAIN. The host's open file description is in non-blocking mode
// whatever the guest's is.
func TestSocket_NonBlocking(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	server, port := newIPListener(t, w, m)
	if !hostNonblocking(t, w, server) {
		t.Fatal("a new socket's host socket is in blocking mode")
	}
	if rc := w.Fd_fdstat_set_flags(m, server, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if rc := w.Fd_fdstat_get(m, server, sockValueOff); rc != _wasiESUCCESS || binary.LittleEndian.Uint16(m.memory[sockValueOff+2:])&uint16(wasiFdflagNonblock) == 0 {
		t.Fatalf("fdstat rc=%d: the socket does not report O_NONBLOCK", rc)
	}
	if _, rc := acceptOn(w, m, server); rc != _wasiEAGAIN {
		t.Fatalf("accept with none waiting rc=%d, want EAGAIN", rc)
	}
	client := connectTo(t, w, m, port)
	// The connection is there once poll says so.
	writeSubFd(m, pollSubsOff, 7, 1, server)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	if !hostNonblocking(t, w, conn) {
		t.Fatal("an accepted connection's host socket is in blocking mode")
	}
	if rc := w.Fd_fdstat_get(m, conn, sockValueOff); rc != _wasiESUCCESS || binary.LittleEndian.Uint16(m.memory[sockValueOff+2:])&uint16(wasiFdflagNonblock) != 0 {
		t.Fatalf("fdstat rc=%d: a connection accepted with no flags reports O_NONBLOCK", rc)
	}
	if rc := w.Fd_fdstat_set_flags(m, client, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if _, rc := sockRecv(w, m, client); rc != _wasiEAGAIN {
		t.Fatalf("recv with nothing there rc=%d, want EAGAIN", rc)
	}
	// MSG_DONTWAIT keeps a blocking socket's call from waiting.
	if rc := w.Sock_recvfrom_addr(m, conn, sockBufOff, 8, wasiMsgDontWait, 0, sockLenOff); rc != -_wasiEAGAIN {
		t.Fatalf("recvfrom with MSG_DONTWAIT rc=%d, want -EAGAIN", rc)
	}
	if rc := w.Sock_accept(m, server, wasiFdflagNonblock, sockValueOff); rc != _wasiEAGAIN {
		t.Fatalf("accept rc=%d, want EAGAIN", rc)
	}
	if rc := w.Fd_fdstat_set_flags(m, server, 0); rc != _wasiESUCCESS || !hostNonblocking(t, w, server) {
		t.Fatalf("clear O_NONBLOCK rc=%d: the host socket left non-blocking mode", rc)
	}
}

// A signal posted to the guest ends a blocking accept and a blocking
// receive with EINTR; a close of the socket ends them with EBADF.
func TestSocket_WaitsEnd(t *testing.T) {
	skipWithoutRawSockets(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.cfg.FS = osFS{}
	w.cfg.Listen = AllowAllListen
	server, port := newIPListener(t, w, m)
	postWhenBlocked(w, wasiSIGUSR1)
	if _, rc := acceptOn(w, m, server); rc != _wasiEINTR {
		t.Fatalf("accept ended by a signal rc=%d, want EINTR", rc)
	}
	client := connectTo(t, w, m, port)
	if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if _, rc := sockRecv(w, m, client); rc != _wasiEINTR {
		t.Fatalf("recv ended by a signal rc=%d, want EINTR", rc)
	}
	closed := whenBlocked(w, func() {
		if rc := w.Fd_close(newForkTestModule(), server); rc != _wasiESUCCESS {
			t.Errorf("Fd_close rc=%d", rc)
		}
	})
	if _, rc := acceptOn(w, m, server); rc != _wasiEBADF {
		t.Fatalf("accept ended by a close rc=%d, want EBADF", rc)
	}
	<-closed
}

// Unix-domain sockets have paths of the whole host filesystem only, and
// keep the names the guest gave them.
func TestSocket_UnixPaths(t *testing.T) {
	w, m, dir := newSocketStubs(t)
	path := filepath.Join(dir, "srv")
	server := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
	n := putUnixAddr(m, sockAddrOff, path)
	w.cfg.FS = newHostFS(t, dir)
	if rc := w.Sock_bind_addr(m, server, sockAddrOff, sockPathOff, n); rc != -_wasiENOTSUP {
		t.Fatalf("bind under HostFS(dir) rc=%d, want -ENOTSUP", rc)
	}
	w.cfg.FS = osFS{}
	if rc := w.Sock_bind_addr(m, server, sockAddrOff, sockPathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	if rc := w.Sock_listen(m, server, 1); rc != _wasiESUCCESS {
		t.Fatalf("listen rc=%d", rc)
	}
	client := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
	if rc := w.Sock_connect_addr(m, client, sockAddrOff, sockPathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("connect rc=%d", rc)
	}
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	for _, c := range []struct {
		fd, peer int32
	}{{server, 0}, {client, 1}, {conn, 0}} {
		if got := nameOf(t, w, m, c.fd, c.peer); got.name != path {
			t.Fatalf("name of fd %d (peer %d) = %+v, want %s", c.fd, c.peer, got, path)
		}
	}
}

// A datagram from a Unix-domain socket without a name comes from an
// address of no family, as Linux reports it.
func TestSocket_UnixDatagramFromNoName(t *testing.T) {
	w, m, dir := newSocketStubs(t)
	receiver := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeDgram)
	n := putUnixAddr(m, sockAddrOff, filepath.Join(dir, "dg"))
	if rc := w.Sock_bind_addr(m, receiver, sockAddrOff, sockPathOff, n); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	sender := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeDgram)
	if rc := sendTo(w, m, sender, "x", true, n); rc != _wasiESUCCESS {
		t.Fatalf("sendto rc=%d", rc)
	}
	if got, from, rc := recvFrom(w, m, receiver, 64, 0); rc != _wasiESUCCESS || got != "x" || from != (sockRecord{}) {
		t.Fatalf("recvfrom = %q from %+v rc=%d, want \"x\" from no family", got, from, rc)
	}
}

// Two connected sockets of a pair; datagrams keep their boundaries.
func TestSocket_Pairs(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	// An IP family has no pairs (EOPNOTSUPP), as socketpair(2) has it.
	for _, family := range []int32{wasiSockFamilyIPv4, wasiSockFamilyIPv6} {
		if rc := w.Sock_socketpair(m, family, wasiSockTypeStream, sockFdsOff); rc != -_wasiENOTSUP {
			t.Fatalf("pair of family %d rc=%d, want -ENOTSUP", family, rc)
		}
	}
	if rc := w.Sock_socketpair(m, 99, wasiSockTypeStream, sockFdsOff); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("pair of family 99 rc=%d, want -EAFNOSUPPORT", rc)
	}
	for _, typ := range []int32{wasiSockTypeStream, wasiSockTypeDgram} {
		if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, typ, sockFdsOff); rc != _wasiESUCCESS {
			t.Fatalf("Sock_socketpair(%d) rc=%d", typ, rc)
		}
		a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
		if rc := sockSend(w, m, a, "hi"); rc != _wasiESUCCESS {
			t.Fatalf("send rc=%d", rc)
		}
		if got, rc := sockRecv(w, m, b); rc != _wasiESUCCESS || got != "hi" {
			t.Fatalf("recv = %q rc=%d", got, rc)
		}
	}
}

// A write or send on a socket of the host's whose peer is gone raises
// SIGPIPE with EPIPE, as the kernel does; a send with MSG_NOSIGNAL
// (wasiMsgNoSignal) gets EPIPE alone.
func TestSocket_BrokenConnectionRaisesSIGPIPE(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGPIPE), 0, 0)
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	if rc := w.Fd_close(m, b); rc != _wasiESUCCESS {
		t.Fatalf("close of the peer rc=%d", rc)
	}
	copy(m.memory[sockBufOff:], "x")
	makeIovec(m, sockIovOff, sockBufOff, 1)
	for _, c := range []struct {
		name   string
		signal bool
		call   func() int32
	}{
		{"Fd_write", true, func() int32 { return w.Fd_write(m, a, sockIovOff, 1, sockLenOff) }},
		{"Sock_send", true, func() int32 { return w.Sock_send(m, a, sockIovOff, 1, 0, sockLenOff) }},
		{"Sock_send with MSG_NOSIGNAL", false, func() int32 { return w.Sock_send(m, a, sockIovOff, 1, wasiMsgNoSignal, sockLenOff) }},
		{"Sock_sendto_addr", true, func() int32 { return -w.Sock_sendto_addr(m, a, sockBufOff, 1, 0, 0, 0, 0, sockLenOff) }},
		{"Sock_sendto_addr with MSG_NOSIGNAL", false, func() int32 {
			return -w.Sock_sendto_addr(m, a, sockBufOff, 1, wasiMsgNoSignal, 0, 0, 0, sockLenOff)
		}},
	} {
		if rc := c.call(); rc != _wasiEPIPE {
			t.Fatalf("%s: rc=%d, want EPIPE", c.name, rc)
		}
		want := uint64(0)
		if c.signal {
			want = signalMask(wasiSIGPIPE)
		}
		if got := takeSignals(t, w, m); got != want {
			t.Fatalf("%s: pending signals %#x, want %#x", c.name, got, want)
		}
	}
}

// A socket is ready in poll_oneoff as poll(2) says.
func TestSocket_Poll(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	writeSubFd(m, pollSubsOff, 7, 2, a) // writable at once
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	writeSubFd(m, pollSubsOff, 8, 1, b)
	polled := make(chan []uint64, 1)
	go func() { polled <- pollUserdata(t, w, m, 1) }()
	awaitBlockedCalls(w, 1)
	if rc := sockSend(w, newForkTestModule(), a, "x"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	wantUserdata(t, <-polled, 8)
}

// Two numbers of one descriptor in one poll: closing one leaves the
// descriptor open and the poll waiting, as on Linux. When input ends the
// wait, the closed number's event carries EBADF, and the other's reports
// the input.
func TestWasi_PollOfTwoNumbersOfOneDescriptor(t *testing.T) {
	if !hostPolls {
		t.Skip("the host has no poll(2)")
	}
	w, m := newProcTestStubs(t)
	closeAllAtCleanup(t, w)
	readFd, writeFd := newTestPipe(t, w, m)
	const dupOut int32 = 5100
	if rc := w.Fd_dup(m, readFd, dupOut); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup rc=%d", rc)
	}
	dup := int32(readU32(m.memory, int(dupOut)))
	writeSubFd(m, pollSubsOff, 7, 1, readFd)
	writeSubFd(m, pollSubsOff+48, 8, 1, dup)
	polled := make(chan []uint64, 1)
	go func() { polled <- pollUserdata(t, w, m, 2) }()
	awaitBlockedCalls(w, 1)
	if rc := w.Fd_close(newForkTestModule(), readFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	// The poll still waits: its wake is registered and was not written to.
	w.mu.Lock()
	op := w.openLocked(dup)
	w.mu.Unlock()
	op.mu.Lock()
	waiters := slices.Collect(maps.Keys(op.waiters))
	op.mu.Unlock()
	if len(waiters) != 1 || woken(t, waiters[0]) {
		t.Fatalf("the close of one number woke the poll (%d waits registered)", len(waiters))
	}
	select {
	case got := <-polled:
		t.Fatalf("the poll returned %v after the close of one number", got)
	default:
	}
	if rc := fdWriteString(w, newForkTestModule(), writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	wantUserdata(t, <-polled, 7, 8)
	for i, want := range []int32{_wasiEBADF, _wasiESUCCESS} {
		if errno := binary.LittleEndian.Uint16(m.memory[pollEvOff+int32(i)*32+8:]); errno != uint16(want) {
			t.Fatalf("event %d errno %d, want %d", i, errno, want)
		}
	}
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
}

// The *64 twins serve a memory64 guest as the imports do a wasm32 one.
func TestSocket_Mem64Twins(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := w.Sock_open64(m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if fd < 0 {
		t.Fatalf("Sock_open64 rc=%d", fd)
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr64(m, fd, int64(sockAddrOff), 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind_addr64 rc=%d", rc)
	}
	if rc := w.Sock_listen64(m, fd, 1); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen64 rc=%d", rc)
	}
	if rc := w.Sock_name64(m, fd, 0, int64(sockAddr2Off)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_name64 rc=%d", rc)
	}
	port := int32(readSockRecord(m, sockAddr2Off).port)
	client := w.Sock_socket64(m, 2, 1)
	if rc := w.Sock_connect64(m, client, 0x0100007f, port); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect64 rc=%d", rc)
	}
	if rc := w.Sock_accept64(m, int64(fd), 0, int64(sockValueOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept64 rc=%d", rc)
	}
	conn := int32(readU32(m.memory, int(sockValueOff)))
	// A memory64 iovec is a u64 pointer and a u64 length.
	copy(m.memory[sockBufOff:], "ok")
	binary.LittleEndian.PutUint64(m.memory[sockIovOff:], uint64(sockBufOff))
	binary.LittleEndian.PutUint64(m.memory[sockIovOff+8:], 2)
	if rc := w.Sock_send64(m, int64(client), int64(sockIovOff), 1, 0, int64(sockLenOff)); rc != _wasiESUCCESS || readU64(m.memory, int(sockLenOff)) != 2 {
		t.Fatalf("Sock_send64 rc=%d count=%d", rc, readU64(m.memory, int(sockLenOff)))
	}
	binary.LittleEndian.PutUint64(m.memory[sockIovOff+8:], 64)
	if rc := w.Sock_recv64(m, int64(conn), int64(sockIovOff), 1, 0, int64(sockLenOff), int64(sockFlagsOff)); rc != _wasiESUCCESS || readU64(m.memory, int(sockLenOff)) != 2 {
		t.Fatalf("Sock_recv64 rc=%d count=%d", rc, readU64(m.memory, int(sockLenOff)))
	}
	if rc := w.Sock_sendto_addr64(m, conn, int64(sockBufOff), 2, 0, 0, 0, 0, int64(sockLenOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_sendto_addr64 rc=%d", rc)
	}
	if rc := w.Sock_recvfrom_addr64(m, client, int64(sockBufOff), 64, 0, int64(sockAddr2Off), int64(sockLenOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_recvfrom_addr64 rc=%d", rc)
	}
	if rc := w.Sock_shutdown64(m, int64(client), 3); rc != _wasiESUCCESS {
		t.Fatalf("Sock_shutdown64 rc=%d", rc)
	}
	if rc := w.Sock_socketpair64(m, wasiSockFamilyUnix, wasiSockTypeStream, int64(sockFdsOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair64 rc=%d", rc)
	}
	other := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := w.Sock_connect_addr64(m, other, int64(sockAddrOff), 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect_addr64 rc=%d", rc)
	}
}

// A blocking guest's connection that the host has not made when
// connect(2) returns is waited for as Go's package net waits: until the
// socket is writable, then SO_ERROR and the peer say how it ended.
func TestSocket_ConnectNotMadeAtOnce(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	_, port := newIPListener(t, w, m)
	dead, deadPort := newIPListener(t, w, m)
	if rc := w.Fd_close(m, dead); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	for _, c := range []struct {
		port int32
		want int32
	}{{port, _wasiESUCCESS}, {deadPort, -_wasiECONNREFUSED}} {
		fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
		putIPAddr(m, sockAddrOff, "127.0.0.1", c.port)
		if rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc != c.want {
			t.Fatalf("connect to port %d rc=%d, want %d", c.port, rc, c.want)
		}
	}
	// A non-blocking guest's connect that is not made at once is
	// EINPROGRESS; one made at once is 0.
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEINPROGRESS && rc != _wasiESUCCESS {
		t.Fatalf("non-blocking connect rc=%d, want -EINPROGRESS or 0", rc)
	}
}

// A datagram socket's association dissolves with AF_UNSPEC, after the
// Listen policy is asked about the port the host bound it at.
func TestSocket_DatagramDisconnect(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	receiver := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, receiver, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	port := int32(nameOf(t, w, m, receiver, 0).port)
	sender := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	if rc := w.Sock_connect_addr(m, sender, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("connect rc=%d", rc)
	}
	bound := nameOf(t, w, m, sender, 0).port
	var asked []string
	w.cfg.Listen = func(network, address string) bool {
		asked = append(asked, network+" "+address)
		return false
	}
	clear(m.memory[sockAddrOff : sockAddrOff+wasiSockAddrSize])
	if rc := w.Sock_connect_addr(m, sender, sockAddrOff, 0, 0); rc != -_wasiEACCES {
		t.Fatalf("refused AF_UNSPEC rc=%d, want -EACCES", rc)
	}
	if len(asked) != 1 || !strings.HasSuffix(asked[0], ":"+strconv.Itoa(int(bound))) {
		t.Fatalf("Listen was asked %v, want the bound port %d", asked, bound)
	}
}

// Receives that look (MSG_PEEK) and that wait for all (MSG_WAITALL).
func TestSocket_ReceiveFlags(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	if rc := sockSend(w, m, a, "abcd"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	if got, _, rc := recvFrom(w, m, b, 8, wasiMsgPeek); rc != _wasiESUCCESS || got != "abcd" {
		t.Fatalf("peek = %q rc=%d", got, rc)
	}
	type received struct {
		got string
		rc  int32
	}
	waited := make(chan received, 1)
	go func() {
		rc := w.Sock_recvfrom_addr(m, b, sockBufOff, 6, wasiMsgWaitAll, 0, sockLenOff)
		waited <- received{string(m.memory[sockBufOff : sockBufOff+int32(readU32(m.memory, int(sockLenOff)))]), rc}
	}()
	awaitBlockedCalls(w, 1)
	if rc := sockSend(w, newForkTestModule(), a, "ef"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	if r := <-waited; r.rc != _wasiESUCCESS || r.got != "abcdef" {
		t.Fatalf("MSG_WAITALL received %q rc=%d, want abcdef", r.got, r.rc)
	}
}

// Records and requests the runtime refuses before the host is asked, and
// an address the host refuses.
func TestSocket_Refusals(t *testing.T) {
	w, m, dir := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyUnix, wasiSockTypeStream)
	rec := m.memory[sockAddrOff : sockAddrOff+wasiSockAddrSize]
	clear(rec)
	binary.LittleEndian.PutUint32(rec[0:], 9)
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEAFNOSUPPORT {
		t.Errorf("bind to a record of an unknown family rc=%d, want -EAFNOSUPPORT", rc)
	}
	binary.LittleEndian.PutUint32(rec[0:], uint32(wasiSockFamilyUnix))
	binary.LittleEndian.PutUint32(rec[28:], wasiSockAddrNameMax+1)
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEINVAL {
		t.Errorf("bind to a name too long rc=%d, want -EINVAL", rc)
	}
	binary.LittleEndian.PutUint32(rec[28:], 0)
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEINVAL {
		t.Errorf("bind to no name rc=%d, want -EINVAL", rc)
	}
	if rc := w.Sock_bind_addr(m, fd, 1<<30, 0, 0); rc != -_wasiEFAULT {
		t.Errorf("bind to a record out of memory rc=%d, want -EFAULT", rc)
	}
	n := putUnixAddr(m, sockAddrOff, filepath.Join(dir, "x"))
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 1<<30, n); rc != -_wasiEFAULT {
		t.Errorf("bind with a path out of memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_connect_addr(m, fd, 1<<30, 0, 0); rc != -_wasiEFAULT {
		t.Errorf("connect to a record out of memory rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, 9, sockFdsOff); rc != -_wasiEINVAL {
		t.Errorf("pair of an unknown type rc=%d, want -EINVAL", rc)
	}
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, 1<<30); rc != -_wasiEFAULT {
		t.Errorf("pair into memory out of range rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_sendto_addr(m, fd, 1<<30, 4, 0, 0, 0, 0, sockLenOff); rc != -_wasiEFAULT {
		t.Errorf("sendto from memory out of range rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_recvfrom_addr(m, fd, sockBufOff, 4, 0, 1<<30, sockLenOff); rc != -_wasiEFAULT {
		t.Errorf("recvfrom into an address out of memory rc=%d, want -EFAULT", rc)
	}
	// A connection of package net's takes none of the socket imports.
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close the peer: %v", err)
		}
	})
	w.mu.Lock()
	conn := addTestFD(w, &wasiOpen{conn: local})
	w.mu.Unlock()
	if rc := w.Sock_name(m, conn, 0, sockAddr2Off); rc != -_wasiENOTSUP {
		t.Errorf("Sock_name of a connection of package net's rc=%d, want -ENOTSUP", rc)
	}
	// The address is the host's to take or refuse on a Unix-domain stream
	// socket: Linux refuses it, darwin ignores it.
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	pair := int32(readU32(m.memory, int(sockFdsOff)))
	n = putUnixAddr(m, sockAddrOff, filepath.Join(dir, "x"))
	want := map[string]int32{"linux": -_wasiEISCONN, "darwin": _wasiESUCCESS}[runtime.GOOS]
	if rc := sendTo(w, m, pair, "x", true, n); rc != want {
		t.Errorf("sendto with an address of a connected Unix-domain stream socket rc=%d, want %d", rc, want)
	}
}

// The legacy connect of a socket without a socket of the host's dials as
// package net does.
func TestSocket_LegacyDial(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	_, port := newIPListener(t, w, m)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{isSocket: true})
	w.mu.Unlock()
	if rc := w.Sock_connect(m, fd, 0x0100007f, port); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect rc=%d", rc)
	}
	if rc := sockSend(w, m, fd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
}

// A close of the socket ends a blocking receive or send that waits for it
// with EBADF.
func TestSocket_CloseEndsTransfers(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	receiver := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_bind_addr(m, receiver, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("bind rc=%d", rc)
	}
	closed := whenBlocked(w, func() {
		if rc := w.Fd_close(newForkTestModule(), receiver); rc != _wasiESUCCESS {
			t.Errorf("Fd_close rc=%d", rc)
		}
	})
	if _, _, rc := recvFrom(w, m, receiver, 64, 0); rc != -_wasiEBADF {
		t.Fatalf("recvfrom ended by a close rc=%d, want -EBADF", rc)
	}
	<-closed
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a := int32(readU32(m.memory, int(sockFdsOff)))
	fillNonBlocking(t, w, m, a)
	if rc := w.Fd_fdstat_set_flags(m, a, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	closed = whenBlocked(w, func() {
		if rc := w.Fd_close(newForkTestModule(), a); rc != _wasiESUCCESS {
			t.Errorf("Fd_close rc=%d", rc)
		}
	})
	if rc := sendTo(w, m, a, "x", false, 0); rc != -_wasiEBADF {
		t.Fatalf("sendto ended by a close rc=%d, want -EBADF", rc)
	}
	<-closed
}

// accept(2) of a socket that does not listen fails at once with the host's
// errno, whether it blocks or not.
func TestSocket_AcceptOfASocketThatDoesNotListen(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if _, rc := acceptOn(w, m, fd); rc != _wasiEINVAL {
		t.Fatalf("blocking accept of a socket that does not listen rc=%d, want EINVAL", rc)
	}
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if _, rc := acceptOn(w, m, fd); rc != _wasiEINVAL {
		t.Fatalf("non-blocking accept of a socket that does not listen rc=%d, want EINVAL", rc)
	}
}

// A record of family 0 is no address: a bind of it is EINVAL, and a send
// to it goes to the peer, without asking a policy.
func TestSocket_RecordsOfNoFamily(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	asked := 0
	w.cfg.Listen = func(network, address string) bool { asked++; return true }
	w.cfg.Dial = func(network, host, ip string, port int) bool { asked++; return true }
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	clear(m.memory[sockAddrOff : sockAddrOff+wasiSockAddrSize])
	if rc := w.Sock_bind_addr(m, fd, sockAddrOff, 0, 0); rc != -_wasiEINVAL {
		t.Fatalf("bind to a record of family 0 rc=%d, want -EINVAL", rc)
	}
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeDgram, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	if rc := sendTo(w, m, a, "peer", true, 0); rc != _wasiESUCCESS {
		t.Fatalf("send to a record of family 0 rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, b); rc != _wasiESUCCESS || got != "peer" {
		t.Fatalf("the peer received %q rc=%d", got, rc)
	}
	if asked != 0 {
		t.Fatalf("a policy was asked %d times", asked)
	}
}

// A blocking MSG_PEEK|MSG_WAITALL waits in poll(2) until something has
// arrived, a signal ending the wait with EINTR, and then looks at what
// has.
func TestSocket_PeekForAllLooksOnceSomethingHasArrived(t *testing.T) {
	skipWithoutRawSockets(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.cfg.FS = osFS{}
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Sock_recvfrom_addr(m, a, sockBufOff, 8, wasiMsgPeek|wasiMsgWaitAll, 0, sockLenOff); rc != -_wasiEINTR {
		t.Fatalf("receive ended by a signal rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	if rc := sockSend(w, m, b, "ab"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	if got, _, rc := recvFrom(w, m, a, 8, wasiMsgPeek|wasiMsgWaitAll); rc != _wasiESUCCESS || got != "ab" {
		t.Fatalf("peek for all = %q rc=%d, want ab", got, rc)
	}
	if got, rc := sockRecv(w, m, a); rc != _wasiESUCCESS || got != "ab" {
		t.Fatalf("receive after the peek = %q rc=%d, want ab", got, rc)
	}
}

// Blocking accepts that share a listener, as forked copies of a guest
// share one, each take a connection: none of them changes the mode of the
// host socket under another.
func TestSocket_AcceptsThatShareAListener(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	server, port := newIPListener(t, w, m)
	const accepts = 2
	results := make(chan int32, accepts)
	for i := range int32(accepts) {
		go func() { results <- w.Sock_accept(m, server, 0, sockFdsOff+8*i) }()
	}
	awaitBlockedCalls(w, accepts)
	for range accepts {
		connectTo(t, w, m, port)
	}
	for range accepts {
		if rc := <-results; rc != _wasiESUCCESS {
			t.Fatalf("accept rc=%d", rc)
		}
	}
	if !hostNonblocking(t, w, server) {
		t.Fatal("the listener's host socket left non-blocking mode")
	}
}

// Sock_resolve gives the addresses of a name of the family asked for, and
// converts an address written in numbers without a lookup.
func TestSocket_Resolve(t *testing.T) {
	w, m := newProcTestStubs(t)
	var asked []string
	w.cfg.Resolve = func(host string) bool {
		asked = append(asked, host)
		return host == "localhost"
	}
	resolve := func(node string, family, limit int32) ([]sockRecord, int32) {
		copy(m.memory[sockBufOff:], node)
		rc := w.Sock_resolve(m, sockBufOff, int32(len(node)), family, sockManyOff, limit, sockLenOff)
		if rc != _wasiESUCCESS {
			return nil, rc
		}
		var out []sockRecord
		for i := range int32(readU32(m.memory, int(sockLenOff))) {
			out = append(out, readSockRecord(m, sockManyOff+i*wasiSockAddrSize))
		}
		return out, rc
	}
	got, rc := resolve("127.0.0.1", 0, 8)
	if rc != _wasiESUCCESS || len(got) != 1 || got[0].family != uint32(wasiSockFamilyIPv4) || got[0].ip != "127.0.0.1" {
		t.Fatalf("resolve of an IPv4 address = %+v rc=%d", got, rc)
	}
	got, rc = resolve("fe80::1%7", wasiSockFamilyIPv6, 8)
	if rc != _wasiESUCCESS || len(got) != 1 || got[0].ip != "fe80::1" || got[0].scope != 7 {
		t.Fatalf("resolve of an IPv6 address with a zone = %+v rc=%d", got, rc)
	}
	if _, rc := resolve("::1", wasiSockFamilyIPv4, 8); rc != -_wasiENOENT {
		t.Fatalf("an IPv6 address asked for as IPv4 rc=%d, want -ENOENT", rc)
	}
	if _, rc := resolve("::1", 0, 0); rc != -_wasiENOENT {
		t.Fatalf("resolve with room for none rc=%d, want -ENOENT", rc)
	}
	if _, rc := resolve("fe80::1%no-such-interface", 0, 8); rc == _wasiESUCCESS {
		t.Fatal("resolve of a zone that is no interface succeeded")
	}
	if len(asked) != 0 {
		t.Fatalf("the lookup policy was asked %q about addresses written in numbers", asked)
	}
	got, rc = resolve("localhost", wasiSockFamilyIPv4, 8)
	if rc != _wasiESUCCESS || len(got) == 0 || got[0].ip != "127.0.0.1" {
		t.Fatalf("resolve of localhost = %+v rc=%d", got, rc)
	}
	if !w.hosts.names["127.0.0.1"]["localhost"] {
		t.Fatalf("127.0.0.1 is remembered as %v, want localhost", w.hosts.names["127.0.0.1"])
	}
	if _, rc := resolve("refused.example", 0, 8); rc != -_wasiEACCES {
		t.Fatalf("resolve of a name the policy refuses rc=%d, want -EACCES", rc)
	}
	if _, rc := resolve("localhost", 9, 8); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("resolve of an unknown family rc=%d, want -EAFNOSUPPORT", rc)
	}
	if rc := w.Sock_resolve(m, sockBufOff, 4, 0, sockManyOff, -1, sockLenOff); rc != -_wasiEFAULT {
		t.Fatalf("resolve with a negative room rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_resolve(m, sockBufOff, 9, 0, 1<<20, 8, sockLenOff); rc != -_wasiEFAULT {
		t.Fatalf("resolve into memory that is not there rc=%d, want -EFAULT", rc)
	}
	copy(m.memory[sockBufOff:], "127.0.0.1")
	if rc := w.Sock_resolve64(m, int64(sockBufOff), 9, 0, int64(sockManyOff), 1, int64(sockLenOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_resolve64 rc=%d", rc)
	}
}

func TestSocket_HostByName(t *testing.T) {
	w, m := newProcTestStubs(t)
	var asked []string
	w.cfg.Resolve = func(host string) bool {
		asked = append(asked, host)
		return host == "localhost"
	}
	lookup := func(name string, room int32) (addrs []string, official string, rc int32) {
		copy(m.memory[sockBufOff:], name)
		rc = w.Sock_host_by_name(m, sockBufOff, int32(len(name)), sockManyOff, room, sockLenOff)
		if rc != _wasiESUCCESS {
			return nil, "", rc
		}
		rec := m.memory[sockManyOff : sockManyOff+int32(readU32(m.memory, int(sockLenOff)))]
		count := binary.LittleEndian.Uint32(rec)
		for i := range count {
			addrs = append(addrs, net.IP(rec[4+4*i:8+4*i]).String())
		}
		return addrs, string(rec[4+4*count:]), rc
	}
	if addrs, official, rc := lookup("127.0.0.1", 64); rc != _wasiESUCCESS || len(addrs) != 1 || addrs[0] != "127.0.0.1" || official != "127.0.0.1" {
		t.Fatalf("lookup of an address = %q %q rc=%d", addrs, official, rc)
	}
	if _, _, rc := lookup("::1", 64); rc != -_wasiENOENT {
		t.Fatalf("lookup of an IPv6 address rc=%d, want -ENOENT", rc)
	}
	if len(asked) != 0 {
		t.Fatalf("the lookup policy was asked %q about addresses written in numbers", asked)
	}
	if addrs, official, rc := lookup("localhost", 64); rc != _wasiESUCCESS || len(addrs) == 0 || official != "localhost" {
		t.Fatalf("lookup of localhost = %q %q rc=%d", addrs, official, rc)
	}
	if _, _, rc := lookup("localhost", 2); rc != -_wasiERANGE {
		t.Fatalf("lookup into a buffer too small rc=%d, want -ERANGE", rc)
	}
	if _, _, rc := lookup("refused.example", 64); rc != -_wasiEACCES {
		t.Fatalf("lookup the policy refuses rc=%d, want -EACCES", rc)
	}
	if rc := w.Sock_host_by_name(m, 1<<20, 4, sockManyOff, 64, sockLenOff); rc != -_wasiEFAULT {
		t.Fatalf("lookup of a name outside memory rc=%d, want -EFAULT", rc)
	}
	copy(m.memory[sockBufOff:], "127.0.0.1")
	if rc := w.Sock_host_by_name64(m, int64(sockBufOff), 9, int64(sockManyOff), 64, int64(sockLenOff)); rc != _wasiESUCCESS {
		t.Fatalf("Sock_host_by_name64 rc=%d", rc)
	}
}

func TestSocket_ReverseAddr(t *testing.T) {
	w, m := newProcTestStubs(t)
	var asked []string
	w.cfg.Resolve = func(host string) bool {
		asked = append(asked, host)
		return false
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", 0)
	if rc := w.Sock_reverse_addr(m, sockAddrOff, sockManyOff, 256, sockLenOff); rc != -_wasiEACCES {
		t.Fatalf("reverse lookup the policy refuses rc=%d, want -EACCES", rc)
	}
	if len(asked) != 1 || asked[0] != "127.0.0.1" {
		t.Fatalf("the lookup policy was asked %q", asked)
	}
	w.cfg.Resolve = AllowAllResolve
	switch rc := w.Sock_reverse_addr64(m, int64(sockAddrOff), int64(sockManyOff), 256, int64(sockLenOff)); rc {
	case _wasiESUCCESS:
		if name := string(m.memory[sockManyOff : sockManyOff+int32(readU32(m.memory, int(sockLenOff)))]); name == "" || strings.HasSuffix(name, ".") {
			t.Fatalf("reverse lookup of 127.0.0.1 = %q", name)
		}
	case -_wasiENOENT:
		// this machine knows no name of it
	default:
		t.Fatalf("reverse lookup of 127.0.0.1 rc=%d", rc)
	}
	putUnixAddr(m, sockAddrOff, "/x")
	if rc := w.Sock_reverse_addr(m, sockAddrOff, sockManyOff, 256, sockLenOff); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("reverse lookup of a Unix-domain address rc=%d, want -EAFNOSUPPORT", rc)
	}
	if rc := w.Sock_reverse_addr(m, 1<<20, sockManyOff, 256, sockLenOff); rc != -_wasiEFAULT {
		t.Fatalf("reverse lookup of a record outside memory rc=%d, want -EFAULT", rc)
	}
}

// Sock_getaddrinfo looks a name up as Sock_resolve does: its first IPv4
// address, remembered for the Dial policy.
func TestSocket_GetaddrinfoLooksUp(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.cfg.Resolve = AllowAllResolve
	copy(m.memory[sockBufOff:], "localhost")
	if rc := w.Sock_getaddrinfo64(m, int64(sockBufOff), 9, int64(sockValueOff)); rc != _wasiESUCCESS {
		t.Fatalf("getaddrinfo of localhost rc=%d", rc)
	}
	if got := net.IP(m.memory[sockValueOff : sockValueOff+4]).String(); got != "127.0.0.1" || !w.hosts.names[got]["localhost"] {
		t.Fatalf("getaddrinfo of localhost = %s, remembered as %v", got, w.hosts.names[got])
	}
	copy(m.memory[sockBufOff:], "::1")
	if rc := w.Sock_getaddrinfo(m, sockBufOff, 3, sockValueOff); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("getaddrinfo of an IPv6 address rc=%d, want -EAFNOSUPPORT", rc)
	}
	copy(m.memory[sockBufOff:], "::ffff:10.0.0.1")
	if rc := w.Sock_getaddrinfo(m, sockBufOff, 15, sockValueOff); rc != _wasiESUCCESS || net.IP(m.memory[sockValueOff:sockValueOff+4]).String() != "10.0.0.1" {
		t.Fatalf("getaddrinfo of an IPv4-mapped address rc=%d", rc)
	}
	if rc := w.Sock_getaddrinfo(m, sockBufOff, 15, 1<<20); rc != -_wasiEFAULT {
		t.Fatalf("getaddrinfo into memory that is not there rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_getaddrinfo(m, 1<<20, 15, sockValueOff); rc != -_wasiEFAULT {
		t.Fatalf("getaddrinfo of a name outside memory rc=%d, want -EFAULT", rc)
	}
}

// A signal ends a lookup with EINTR: one posted before it starts it, and
// one posted while it waits for the resolver, which cancels it. A lookup
// that ends well after all leaves the signal to the next call that waits.
func TestSocket_LookupIsInterruptible(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.cfg.Resolve = AllowAllResolve
	w.PostSignal(wasiSIGUSR1)
	copy(m.memory[sockBufOff:], "localhost")
	if rc := w.Sock_resolve(m, sockBufOff, 9, 0, sockManyOff, 8, sockLenOff); rc != -_wasiEINTR {
		t.Fatalf("resolve with a signal waiting rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	postWhenBlocked(w, wasiSIGUSR1)
	if errno := w.lookupInterruptibly(m, "sock_resolve", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}); errno != _wasiEINTR {
		t.Fatalf("lookup cancelled by a signal errno=%d, want EINTR", errno)
	}
	takeSignals(t, w, m)
	postWhenBlocked(w, wasiSIGUSR1)
	if errno := w.lookupInterruptibly(m, "sock_resolve", func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}); errno != _wasiESUCCESS {
		t.Fatalf("lookup that went through errno=%d", errno)
	}
	notFound := func(context.Context) error { return &net.DNSError{IsNotFound: true} }
	if errno := w.lookupInterruptibly(m, "sock_resolve", notFound); errno != _wasiEINTR {
		t.Fatalf("lookup after one that went through a signal errno=%d, want EINTR", errno)
	}
	takeSignals(t, w, m)
	if errno := w.lookupInterruptibly(m, "sock_resolve", notFound); errno != _wasiENOENT {
		t.Fatalf("lookup of no name errno=%d, want ENOENT", errno)
	}
}

func TestSocket_LookupErrno(t *testing.T) {
	w := &WasiStubs{}
	for _, c := range []struct {
		err  error
		want int32
	}{
		{&net.DNSError{IsNotFound: true}, _wasiENOENT},
		{&net.DNSError{IsTimeout: true}, _wasiEAGAIN},
		{&net.DNSError{IsTemporary: true}, _wasiEAGAIN},
		{&net.DNSError{}, _wasiEIO},
		{&net.AddrError{Err: "no suitable address found", Addr: "h"}, _wasiENOENT},
		{errors.ErrUnsupported, _wasiENOSYS},
	} {
		if got := w.lookupErrno("sock_resolve", c.err); got != c.want {
			t.Errorf("lookupErrno(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// A failure to make or accept a socket is an error of the system call that
// failed, wrapped once.
func TestSocket_MakingErrorsNameTheirCall(t *testing.T) {
	skipWithoutRawSockets(t)
	once := func(err error, calls ...string) {
		t.Helper()
		var se *os.SyscallError
		if !errors.As(err, &se) || !slices.Contains(calls, se.Syscall) {
			t.Fatalf("error %v: want an error of %v", err, calls)
		}
		if inner := (*os.SyscallError)(nil); errors.As(se.Err, &inner) {
			t.Fatalf("error %v is wrapped twice", err)
		}
	}
	w := &WasiStubs{}
	_, err := hostSocketFD(-1, syscall.SOCK_STREAM)
	once(err, "socket")
	_, err = hostSocketPairFDs(-1)
	once(err, "socketpair")
	host, err := openHostSocket(wasiSockFamilyIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if errno := w.socketCall("test", host, func(fd int) { _, _, err = hostAccept(fd) }); errno != _wasiESUCCESS {
		t.Fatalf("socketCall errno=%d", errno)
	}
	once(err, "accept", "accept4")
}

// An address written in numbers is no lookup: it is not remembered as a
// host name, and the name an earlier lookup gave the address stays the one
// the Dial policy is told of a connect to it.
func TestSocket_LiteralsAreNoHostNames(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	w.cfg.Resolve = AllowAllResolve
	_, port := newIPListener(t, w, m)
	var hosts []string
	w.cfg.Dial = func(network, host, ip string, p int) bool {
		hosts = append(hosts, host)
		return true
	}
	connect := func() {
		t.Helper()
		fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
		putIPAddr(m, sockAddrOff, "127.0.0.1", port)
		if rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc != _wasiESUCCESS {
			t.Fatalf("connect rc=%d", rc)
		}
	}
	copy(m.memory[sockBufOff:], "127.0.0.1")
	if rc := w.Sock_getaddrinfo(m, sockBufOff, 9, sockValueOff); rc != _wasiESUCCESS {
		t.Fatalf("getaddrinfo of an address rc=%d", rc)
	}
	if rc := w.Sock_resolve(m, sockBufOff, 9, 0, sockManyOff, 8, sockLenOff); rc != _wasiESUCCESS {
		t.Fatalf("resolve of an address rc=%d", rc)
	}
	connect()
	copy(m.memory[sockBufOff:], "localhost")
	if rc := w.Sock_resolve(m, sockBufOff, 9, wasiSockFamilyIPv4, sockManyOff, 8, sockLenOff); rc != _wasiESUCCESS {
		t.Fatalf("resolve of localhost rc=%d", rc)
	}
	copy(m.memory[sockBufOff:], "127.0.0.1")
	if rc := w.Sock_host_by_name(m, sockBufOff, 9, sockManyOff, 64, sockLenOff); rc != _wasiESUCCESS {
		t.Fatalf("host by name of an address rc=%d", rc)
	}
	connect()
	if !slices.Equal(hosts, []string{"", "localhost"}) {
		t.Fatalf("Dial was told of hosts %q, want none, then localhost", hosts)
	}
}

// An address that lookups gave for several names is dialed when the Dial
// policy allows any of them, whichever was looked up last: the policy is
// asked with each name in sorted order until one allows.
func TestSocket_DialAsksEveryNameOfAnAddress(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	_, port := newIPListener(t, w, m)
	w.recordResolvedHost("127.0.0.1", "c.example")
	w.recordResolvedHost("127.0.0.1", "a.example")
	w.recordResolvedHost("127.0.0.1", "b.example")
	var hosts []string
	allowed := "a.example"
	w.cfg.Dial = func(network, host, ip string, p int) bool {
		hosts = append(hosts, host)
		return host == allowed
	}
	connect := func() int32 {
		fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
		putIPAddr(m, sockAddrOff, "127.0.0.1", port)
		return w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0)
	}
	if rc := connect(); rc != _wasiESUCCESS {
		t.Fatalf("connect to an address of an allowed name rc=%d", rc)
	}
	if !slices.Equal(hosts, []string{"a.example"}) {
		t.Fatalf("Dial was told %q, want a.example alone", hosts)
	}
	hosts, allowed = nil, "b.example"
	if rc := connect(); rc != _wasiESUCCESS {
		t.Fatalf("connect to an address of an allowed name rc=%d", rc)
	}
	if !slices.Equal(hosts, []string{"a.example", "b.example"}) {
		t.Fatalf("Dial was told %q, want a.example, then b.example", hosts)
	}
	hosts, allowed = nil, "other.example"
	if rc := connect(); rc != -_wasiEACCES {
		t.Fatalf("connect to an address of no allowed name rc=%d, want -EACCES", rc)
	}
	if !slices.Equal(hosts, []string{"a.example", "b.example", "c.example"}) {
		t.Fatalf("Dial was told %q, want every name in order", hosts)
	}
}

// A zone of digits is an interface's index, and one too large for it is
// an error; any other zone names an interface.
func TestSocket_ScopeOfZone(t *testing.T) {
	if scope, err := scopeOfZone("7"); err != nil || scope != 7 {
		t.Fatalf("scopeOfZone(7) = %d, %v", scope, err)
	}
	if _, err := scopeOfZone("99999999999"); !errors.Is(err, strconv.ErrRange) {
		t.Fatalf("scopeOfZone of an index too large: %v, want ErrRange", err)
	}
	if _, err := scopeOfZone("no-such-interface"); err == nil {
		t.Fatal("scopeOfZone of no interface succeeded")
	}
}
