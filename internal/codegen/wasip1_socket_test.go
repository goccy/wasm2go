package codegen

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"
)

// Scratch offsets of the socket tests.
const (
	sockNameOff  int32 = 13000
	sockValueOff int32 = 13020
	sockIovOff   int32 = 13040
	sockLenOff   int32 = 13060
	sockFlagsOff int32 = 13064
	sockBufOff   int32 = 13100
)

// loopbackBE is 127.0.0.1 as it sits in sockaddr_in.sin_addr.
const loopbackBE int32 = 0x0100007f

type sockName struct{ family, ip, port uint32 }

func readSockName(m *Module) sockName {
	return sockName{
		family: readU32(m.memory, int(sockNameOff)),
		ip:     readU32(m.memory, int(sockNameOff)+4),
		port:   readU32(m.memory, int(sockNameOff)+8),
	}
}

// localName returns getsockname of fd.
func localName(t *testing.T, w *WasiStubs, m *Module, fd int32) sockName {
	t.Helper()
	if rc := w.Sock_getsockname(m, fd, sockNameOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_getsockname(%d) rc=%d", fd, rc)
	}
	return readSockName(m)
}

// newListener is socket + bind(127.0.0.1:0) + listen; it returns the fd and
// the port the host picked.
func newListener(t *testing.T, w *WasiStubs, m *Module) (fd int32, port int32) {
	t.Helper()
	fd = w.Sock_socket(m, 0, 0)
	if rc := w.Sock_bind(m, fd, loopbackBE, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	if rc := w.Sock_listen(m, fd, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	return fd, int32(localName(t, w, m, fd).port)
}

// dialLoopback is socket + connect to 127.0.0.1:port.
func dialLoopback(t *testing.T, w *WasiStubs, m *Module, port int32) int32 {
	t.Helper()
	fd := w.Sock_socket(m, 0, 0)
	if rc := w.Sock_connect(m, fd, loopbackBE, port); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect rc=%d", rc)
	}
	return fd
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

func TestSocket_ServerAndClientInOneInstance(t *testing.T) {
	w, m := newProcTestStubs(t)
	server := w.Sock_socket(m, 0, 0)

	// A new socket has the unspecified address and no peer.
	if got := localName(t, w, m, server); got != (sockName{family: wasiSockFamilyIPv4}) {
		t.Fatalf("name of an unbound socket = %+v", got)
	}
	if rc := w.Sock_getpeername(m, server, sockNameOff); rc != -_wasiENOTCONN {
		t.Fatalf("Sock_getpeername of an unconnected socket rc=%d, want -ENOTCONN", rc)
	}

	if rc := w.Sock_bind(m, server, loopbackBE, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	bound := localName(t, w, m, server)
	if bound.family != wasiSockFamilyIPv4 || bound.ip != uint32(loopbackBE) || bound.port == 0 {
		t.Fatalf("bound name = %+v, want 127.0.0.1 and a port", bound)
	}
	if rc := w.Sock_bind(m, server, loopbackBE, 0); rc != -_wasiEINVAL {
		t.Fatalf("second bind rc=%d, want -EINVAL", rc)
	}
	// Bound is not listening.
	if _, rc := acceptOn(w, m, server); rc != _wasiEINVAL {
		t.Fatalf("accept before listen rc=%d, want EINVAL", rc)
	}
	if rc := w.Sock_listen(m, server, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}

	// The port is taken.
	other := w.Sock_socket(m, 0, 0)
	if rc := w.Sock_bind(m, other, loopbackBE, int32(bound.port)); rc != -_wasiEADDRINUSE {
		t.Fatalf("bind of a port in use rc=%d, want -EADDRINUSE", rc)
	}

	client := dialLoopback(t, w, m, int32(bound.port))
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	// Each end names the other.
	clientLocal := localName(t, w, m, client)
	if rc := w.Sock_getpeername(m, conn, sockNameOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_getpeername rc=%d", rc)
	}
	if peer := readSockName(m); peer != clientLocal {
		t.Fatalf("peer of the accepted socket = %+v, client is %+v", peer, clientLocal)
	}
	if rc := w.Sock_getpeername(m, client, sockNameOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_getpeername rc=%d", rc)
	}
	if peer := readSockName(m); peer != bound {
		t.Fatalf("peer of the client = %+v, server is %+v", peer, bound)
	}

	if rc := sockSend(w, m, client, "ping"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, conn); rc != _wasiESUCCESS || got != "ping" {
		t.Fatalf("server received %q rc=%d", got, rc)
	}
	if rc := sockSend(w, m, conn, "pong"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, client); rc != _wasiESUCCESS || got != "pong" {
		t.Fatalf("client received %q rc=%d", got, rc)
	}

	// Every one of them is a socket to fstat.
	for _, fd := range []int32{server, client, conn, other} {
		if rc := w.Fd_fdstat_get(m, fd, sockNameOff); rc != _wasiESUCCESS || m.memory[sockNameOff] != 6 {
			t.Fatalf("fdstat of fd %d: rc=%d filetype=%d, want a stream socket (6)", fd, rc, m.memory[sockNameOff])
		}
	}
}

func TestSocket_ListenWithoutBindPicksAPort(t *testing.T) {
	w, m := newProcTestStubs(t)
	server := w.Sock_socket(m, 0, 0)
	if rc := w.Sock_listen(m, server, 1); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	port := int32(localName(t, w, m, server).port)
	if port == 0 {
		t.Fatal("no port")
	}
	dialLoopback(t, w, m, port)
	if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
}

func TestSocket_ListeningIsSubjectToTheNetworkPolicy(t *testing.T) {
	w, m := newProcTestStubs(t)
	var asked []string
	w.SetNetAccessHook(func(op string) bool {
		asked = append(asked, op)
		return op != "listen"
	})
	fd := w.Sock_socket(m, 0, 0)
	if rc := w.Sock_bind(m, fd, loopbackBE, 0); rc != -_wasiEACCES {
		t.Fatalf("Sock_bind rc=%d, want -EACCES", rc)
	}
	if rc := w.Sock_listen(m, fd, 1); rc != -_wasiEACCES {
		t.Fatalf("Sock_listen rc=%d, want -EACCES", rc)
	}
	if len(asked) != 2 || asked[0] != "listen" || asked[1] != "listen" {
		t.Fatalf("policy was asked %q", asked)
	}
	if got := localName(t, w, m, fd); got.port != 0 {
		t.Fatalf("a refused socket has port %d", got.port)
	}
}

func TestSocket_PollReportsAListenerOnlyWithAConnectionWaiting(t *testing.T) {
	w, m := newProcTestStubs(t)
	server, port := newListener(t, w, m)

	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, server)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1) // the timeout
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll on an idle listener returned after %v", d)
	}

	// Without a timeout it waits for the connection.
	go func() {
		time.Sleep(30 * time.Millisecond)
		cw, cm := w, newForkTestModule()
		fd := cw.Sock_socket(cm, 0, 0)
		cw.Sock_connect(cm, fd, loopbackBE, port)
	}()
	writeSubFd(m, pollSubsOff, 2, 1, server)
	wantUserdata(t, pollUserdata(t, w, m, 1), 2)
	// Still ready when asked again, and the accept gets that connection.
	writeSubClock(m, pollSubsOff, 1, int64(5*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1, server)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	// And idle again.
	writeSubClock(m, pollSubsOff, 1, int64(30*time.Millisecond))
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
}

func TestSocket_NonBlockingAcceptAndRead(t *testing.T) {
	w, m := newProcTestStubs(t)
	server, port := newListener(t, w, m)
	if rc := w.Fd_fdstat_set_flags(m, server, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	if _, rc := acceptOn(w, m, server); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking accept without a connection rc=%d, want EAGAIN", rc)
	}
	client := dialLoopback(t, w, m, port)
	// The connection is on its way through the host's stack.
	var conn int32
	deadline := time.Now().Add(10 * time.Second)
	for {
		var rc int32
		if conn, rc = acceptOn(w, m, server); rc == _wasiESUCCESS {
			break
		} else if rc != _wasiEAGAIN || time.Now().After(deadline) {
			t.Fatalf("non-blocking accept rc=%d", rc)
		}
		runtime.Gosched()
	}

	if rc := w.Fd_fdstat_set_flags(m, conn, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	if _, rc := sockRecv(w, m, conn); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking recv without input rc=%d, want EAGAIN", rc)
	}
	if _, rc := fdReadString(w, m, conn, 16); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking read without input rc=%d, want EAGAIN", rc)
	}
	if rc := sockSend(w, m, client, "data"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		got, rc := sockRecv(w, m, conn)
		if rc == _wasiESUCCESS {
			if got != "data" {
				t.Fatalf("received %q", got)
			}
			break
		}
		if rc != _wasiEAGAIN || time.Now().After(deadline) {
			t.Fatalf("non-blocking recv rc=%d", rc)
		}
		runtime.Gosched()
	}
	// End of input is not "try again".
	if rc := w.Fd_close(m, client); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		got, rc := sockRecv(w, m, conn)
		if rc == _wasiESUCCESS {
			if got != "" {
				t.Fatalf("received %q at end of input", got)
			}
			break
		}
		if rc != _wasiEAGAIN || time.Now().After(deadline) {
			t.Fatalf("non-blocking recv at end of input rc=%d", rc)
		}
		runtime.Gosched()
	}
}

func TestSocket_SignalInterruptsAccept(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGALRM)
	server, port := newListener(t, w, m)
	postSoon(w, wasiSIGALRM)
	if _, rc := acceptOn(w, m, server); rc != _wasiEINTR {
		t.Fatalf("accept rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	// The interruption left the listener as it was.
	dialLoopback(t, w, m, port)
	if _, rc := acceptOn(w, m, server); rc != _wasiESUCCESS {
		t.Fatalf("accept after the interruption rc=%d", rc)
	}
}

func TestSocket_ForkedInstanceAcceptsOnTheSharedListener(t *testing.T) {
	w, m := newProcTestStubs(t)
	server, port := newListener(t, w, m)
	child := w.Fork()
	defer child.CloseAll()
	cm := newForkTestModule()

	accepted := make(chan int32, 1)
	go func() {
		conn, rc := acceptOn(child, cm, server)
		if rc != _wasiESUCCESS {
			conn = -rc
		}
		accepted <- conn
	}()
	client := dialLoopback(t, w, m, port)
	conn := <-accepted
	if conn < 0 {
		t.Fatalf("the child's accept failed: errno %d", -conn)
	}
	if rc := sockSend(w, m, client, "to the child"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(child, cm, conn); rc != _wasiESUCCESS || got != "to the child" {
		t.Fatalf("the child received %q rc=%d", got, rc)
	}
	// The parent closing its listener leaves the child's open.
	if rc := w.Fd_close(m, server); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	dialLoopback(t, w, m, port)
	if _, rc := acceptOn(child, cm, server); rc != _wasiESUCCESS {
		t.Fatalf("accept in the child after the parent closed rc=%d", rc)
	}
}

func TestSocket_BoundSocketConnectsFromItsAddress(t *testing.T) {
	w, m := newProcTestStubs(t)
	server, port := newListener(t, w, m)
	client := w.Sock_socket(m, 0, 0)
	if rc := w.Sock_bind(m, client, loopbackBE, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	bound := localName(t, w, m, client)
	if rc := w.Sock_connect(m, client, loopbackBE, port); rc != _wasiESUCCESS {
		t.Fatalf("Sock_connect rc=%d", rc)
	}
	conn, rc := acceptOn(w, m, server)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	if rc := w.Sock_getpeername(m, conn, sockNameOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_getpeername rc=%d", rc)
	}
	if peer := readSockName(m); peer != bound {
		t.Fatalf("the connection came from %+v, the client was bound to %+v", peer, bound)
	}
}

func TestSocket_Options(t *testing.T) {
	w, m := newProcTestStubs(t)
	fd := w.Sock_socket(m, 0, 0)
	get := func(option int32) (int32, int32) {
		rc := w.Sock_getopt(m, fd, option, sockValueOff)
		return int32(binary.LittleEndian.Uint32(m.memory[sockValueOff:])), rc
	}
	for option, initial := range map[int32]int32{
		wasiSockOptReuseAddr: 0, wasiSockOptKeepAlive: 0, wasiSockOptNoDelay: 0,
		wasiSockOptLinger: -1, wasiSockOptError: 0, wasiSockOptType: 1,
	} {
		if v, rc := get(option); rc != _wasiESUCCESS || v != initial {
			t.Errorf("option %d = %d rc=%d, want %d", option, v, rc, initial)
		}
	}
	for option, value := range map[int32]int32{
		wasiSockOptReuseAddr: 1, wasiSockOptReusePort: 1, wasiSockOptKeepAlive: 1,
		wasiSockOptNoDelay: 1, wasiSockOptRcvBuf: 65536, wasiSockOptSndBuf: 32768, wasiSockOptLinger: 3,
	} {
		if rc := w.Sock_setopt(m, fd, option, value); rc != _wasiESUCCESS {
			t.Errorf("set option %d rc=%d", option, rc)
		}
		if v, rc := get(option); rc != _wasiESUCCESS || v != value {
			t.Errorf("option %d reads back %d rc=%d, want %d", option, v, rc, value)
		}
	}
	for _, option := range []int32{wasiSockOptError, wasiSockOptType, 0, 99} {
		if rc := w.Sock_setopt(m, fd, option, 1); rc != -_wasiENOPROTOOPT {
			t.Errorf("set option %d rc=%d, want -ENOPROTOOPT", option, rc)
		}
	}
	if _, rc := get(99); rc != -_wasiENOPROTOOPT {
		t.Errorf("get of an unknown option rc=%d, want -ENOPROTOOPT", rc)
	}

	// On a live connection the host applies what it can.
	_, port := newListener(t, w, m)
	client := dialLoopback(t, w, m, port)
	for _, option := range []int32{wasiSockOptKeepAlive, wasiSockOptNoDelay, wasiSockOptRcvBuf, wasiSockOptSndBuf, wasiSockOptLinger} {
		if rc := w.Sock_setopt(m, client, option, 1); rc != _wasiESUCCESS {
			t.Errorf("set option %d on a connection rc=%d", option, rc)
		}
	}
	// Not a socket at all.
	readFd, _ := newTestPipe(t, w, m)
	if rc := w.Sock_setopt(m, readFd, wasiSockOptKeepAlive, 1); rc != -_wasiENOTSOCK {
		t.Errorf("set option on a pipe rc=%d, want -ENOTSOCK", rc)
	}
}

func TestSocket_Pair(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("socket pairs are made on darwin and linux only")
	}
	w, m := newProcTestStubs(t)
	const fdsOff int32 = 13200
	if rc := w.Sock_pair(m, fdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_pair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
	if rc := sockSend(w, m, a, "a to b"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, b); rc != _wasiESUCCESS || got != "a to b" {
		t.Fatalf("b received %q rc=%d", got, rc)
	}
	// Plain reads and writes work on it as well, in the other direction.
	if rc := fdWriteString(w, m, b, "b to a"); rc != _wasiESUCCESS {
		t.Fatalf("Fd_write rc=%d", rc)
	}
	if got, rc := fdReadString(w, m, a, 16); rc != _wasiESUCCESS || got != "b to a" {
		t.Fatalf("a read %q rc=%d", got, rc)
	}
	if got := localName(t, w, m, a); got.family != wasiSockFamilyUnix {
		t.Fatalf("family of a socket pair end = %d, want unix", got.family)
	}
	// Closing one end is end of input on the other.
	if rc := w.Fd_close(m, a); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	if got, rc := sockRecv(w, m, b); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("after close b received %q rc=%d", got, rc)
	}
}
