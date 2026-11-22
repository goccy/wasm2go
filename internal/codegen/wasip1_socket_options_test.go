//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"math"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// _wasiENOPROTOOPT is WASI's ENOPROTOOPT, which the guest sees for an
// option a socket has not.
const _wasiENOPROTOOPT int32 = 50

// getOpt is Sock_getopt into the scratch value.
func getOpt(w *WasiStubs, m *Module, fd, option int32) (int32, int32) {
	rc := w.Sock_getopt(m, fd, option, sockValueOff)
	return int32(readU32(m.memory, int(sockValueOff))), rc
}

// socketTimeout is Sock_timeout of the timeout which of fd, set to d when
// set; it returns the timeout before the call.
func socketTimeout(t *testing.T, w *WasiStubs, m *Module, fd, which int32, set bool, d time.Duration) time.Duration {
	t.Helper()
	setting := int32(0)
	if set {
		setting = 1
	}
	if rc := w.Sock_timeout(m, fd, which, setting, int64(d), sockValueOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_timeout(%d, which %d) rc=%d", fd, which, rc)
	}
	return time.Duration(binary.LittleEndian.Uint64(m.memory[sockValueOff:]))
}

// An option is the host socket's: what the guest sets is what the host
// gives back, linger in seconds or -1 for off, and the type and the
// listening state as the host knows them.
func TestSocket_Options(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	for _, option := range []int32{wasiSockOptReuseAddr, wasiSockOptReusePort, wasiSockOptKeepAlive, wasiSockOptNoDelay} {
		if v, rc := getOpt(w, m, fd, option); rc != _wasiESUCCESS || v != 0 {
			t.Fatalf("option %d of a new socket = %d rc=%d, want off", option, v, rc)
		}
		if rc := w.Sock_setopt(m, fd, option, 1); rc != _wasiESUCCESS {
			t.Fatalf("set option %d rc=%d", option, rc)
		}
		if v, rc := getOpt(w, m, fd, option); rc != _wasiESUCCESS || v == 0 {
			t.Fatalf("option %d after setting it = %d rc=%d, want on", option, v, rc)
		}
	}
	if rc := w.Sock_setopt(m, fd, wasiSockOptRcvBuf, 1<<16); rc != _wasiESUCCESS {
		t.Fatalf("set SO_RCVBUF rc=%d", rc)
	}
	if v, rc := getOpt(w, m, fd, wasiSockOptRcvBuf); rc != _wasiESUCCESS || v < 1<<16 {
		t.Fatalf("SO_RCVBUF = %d rc=%d, want at least what was set", v, rc)
	}
	if v, rc := getOpt(w, m, fd, wasiSockOptSndBuf); rc != _wasiESUCCESS || v <= 0 {
		t.Fatalf("SO_SNDBUF = %d rc=%d", v, rc)
	}
	if v, rc := getOpt(w, m, fd, wasiSockOptLinger); rc != _wasiESUCCESS || v != -1 {
		t.Fatalf("linger of a new socket = %d rc=%d, want -1 (off)", v, rc)
	}
	for _, linger := range []int32{5, 0, -1} {
		if rc := w.Sock_setopt(m, fd, wasiSockOptLinger, linger); rc != _wasiESUCCESS {
			t.Fatalf("set linger %d rc=%d", linger, rc)
		}
		if v, rc := getOpt(w, m, fd, wasiSockOptLinger); rc != _wasiESUCCESS || v != linger {
			t.Fatalf("linger = %d rc=%d, want %d", v, rc, linger)
		}
	}
	if v, rc := getOpt(w, m, fd, wasiSockOptType); rc != _wasiESUCCESS || v != wasiSockTypeStream {
		t.Fatalf("SO_TYPE of a stream socket = %d rc=%d", v, rc)
	}
	dgram := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeDgram)
	if v, rc := getOpt(w, m, dgram, wasiSockOptType); rc != _wasiESUCCESS || v != wasiSockTypeDgram {
		t.Fatalf("SO_TYPE of a datagram socket = %d rc=%d", v, rc)
	}
	if rc := w.Sock_setopt(m, dgram, wasiSockOptBroadcast, 1); rc != _wasiESUCCESS {
		t.Fatalf("set SO_BROADCAST rc=%d", rc)
	}
	if v, rc := getOpt(w, m, dgram, wasiSockOptBroadcast); rc != _wasiESUCCESS || v == 0 {
		t.Fatalf("SO_BROADCAST = %d rc=%d, want on", v, rc)
	}
	v6 := openSocket(t, w, m, wasiSockFamilyIPv6, wasiSockTypeStream)
	if rc := w.Sock_setopt(m, v6, wasiSockOptV6Only, 1); rc != _wasiESUCCESS {
		t.Fatalf("set IPV6_V6ONLY rc=%d", rc)
	}
	if v, rc := getOpt(w, m, v6, wasiSockOptV6Only); rc != _wasiESUCCESS || v == 0 {
		t.Fatalf("IPV6_V6ONLY = %d rc=%d, want on", v, rc)
	}
	listener, _ := newIPListener(t, w, m)
	accepting := map[string]struct{ listener, other, rc int32 }{
		"linux":  {1, 0, _wasiESUCCESS},
		"darwin": {0, 0, -_wasiENOPROTOOPT}, // darwin's getsockopt has no SO_ACCEPTCONN
	}[runtime.GOOS]
	if v, rc := getOpt(w, m, listener, wasiSockOptAccepting); rc != accepting.rc || rc == _wasiESUCCESS && v != accepting.listener {
		t.Fatalf("SO_ACCEPTCONN of a listener = %d rc=%d, want %d rc=%d", v, rc, accepting.listener, accepting.rc)
	}
	if v, rc := getOpt(w, m, fd, wasiSockOptAccepting); rc != accepting.rc || rc == _wasiESUCCESS && v != accepting.other {
		t.Fatalf("SO_ACCEPTCONN of a socket that does not listen = %d rc=%d", v, rc)
	}
	if runtime.GOOS == "linux" {
		if rc := w.Sock_setopt(m, listener, wasiSockOptDefer, 5); rc != _wasiESUCCESS {
			t.Fatalf("set TCP_DEFER_ACCEPT rc=%d", rc)
		}
		if v, rc := getOpt(w, m, listener, wasiSockOptDefer); rc != _wasiESUCCESS || v == 0 {
			t.Fatalf("TCP_DEFER_ACCEPT = %d rc=%d, want some seconds", v, rc)
		}
	}
	if rc := w.Sock_setopt64(m, fd, wasiSockOptKeepAlive, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_setopt64 rc=%d", rc)
	}
	if rc := w.Sock_getopt64(m, fd, wasiSockOptKeepAlive, int64(sockValueOff)); rc != _wasiESUCCESS || readU32(m.memory, int(sockValueOff)) != 0 {
		t.Fatalf("Sock_getopt64 rc=%d value %d, want off", rc, readU32(m.memory, int(sockValueOff)))
	}
}

// SO_ERROR is the failure of a connection the host made after the connect
// that started it returned, once, as the guest's errno.
func TestSocket_OptionError(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	dead, port := newIPListener(t, w, m)
	if rc := w.Fd_close(m, dead); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	putIPAddr(m, sockAddrOff, "127.0.0.1", port)
	switch rc := w.Sock_connect_addr(m, fd, sockAddrOff, 0, 0); rc {
	case -_wasiECONNREFUSED:
		// refused within the connect: SO_ERROR has nothing left
		if v, rc := getOpt(w, m, fd, wasiSockOptError); rc != _wasiESUCCESS || v != 0 {
			t.Fatalf("SO_ERROR after a refused connect = %d rc=%d, want 0", v, rc)
		}
	case -_wasiEINPROGRESS:
		writeSubFd(m, pollSubsOff, 7, 1, fd)
		wantUserdata(t, pollUserdata(t, w, m, 1), 7)
		if v, rc := getOpt(w, m, fd, wasiSockOptError); rc != _wasiESUCCESS || v != _wasiECONNREFUSED {
			t.Fatalf("SO_ERROR of the refused connection = %d rc=%d, want ECONNREFUSED", v, rc)
		}
		if v, rc := getOpt(w, m, fd, wasiSockOptError); rc != _wasiESUCCESS || v != 0 {
			t.Fatalf("SO_ERROR read again = %d rc=%d, want 0", v, rc)
		}
	default:
		t.Fatalf("non-blocking connect to a closed port rc=%d", rc)
	}
}

// Options the runtime or the host refuses.
func TestSocket_OptionRefusals(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	for _, option := range []int32{0, 14, math.MaxInt32} {
		if rc := w.Sock_setopt(m, fd, option, 1); rc != -_wasiENOPROTOOPT {
			t.Errorf("set unknown option %d rc=%d, want -ENOPROTOOPT", option, rc)
		}
		if _, rc := getOpt(w, m, fd, option); rc != -_wasiENOPROTOOPT {
			t.Errorf("get unknown option %d rc=%d, want -ENOPROTOOPT", option, rc)
		}
	}
	for _, option := range []int32{wasiSockOptError, wasiSockOptType, wasiSockOptAccepting} {
		if rc := w.Sock_setopt(m, fd, option, 1); rc != -_wasiENOPROTOOPT {
			t.Errorf("set read-only option %d rc=%d, want -ENOPROTOOPT", option, rc)
		}
	}
	if runtime.GOOS == "darwin" {
		if rc := w.Sock_setopt(m, fd, wasiSockOptDefer, 1); rc != -_wasiENOPROTOOPT {
			t.Errorf("set TCP_DEFER_ACCEPT on darwin rc=%d, want -ENOPROTOOPT", rc)
		}
	}
	if rc := w.Sock_setopt(m, 999, wasiSockOptReuseAddr, 1); rc != -_wasiEBADF {
		t.Errorf("set on no descriptor rc=%d, want -EBADF", rc)
	}
	if rc := w.Sock_setopt(m, wasiPreopenFD, wasiSockOptReuseAddr, 1); rc != -_wasiENOTSOCK {
		t.Errorf("set on a directory rc=%d, want -ENOTSOCK", rc)
	}
	if rc := w.Sock_getopt(m, fd, wasiSockOptReuseAddr, 1<<20); rc != -_wasiEFAULT {
		t.Errorf("get into memory that is not there rc=%d, want -EFAULT", rc)
	}
	if _, rc := getOpt(w, m, 999, wasiSockOptReuseAddr); rc != -_wasiEBADF {
		t.Errorf("get on no descriptor rc=%d, want -EBADF", rc)
	}
}

// The timeouts are the host socket's: read back, inherited by a connection
// the socket accepts, and refused when malformed.
func TestSocket_TimeoutValues(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	listener, port := newIPListener(t, w, m)
	for _, which := range []int32{wasiSockTimeoutReceive, wasiSockTimeoutSend} {
		if old := socketTimeout(t, w, m, listener, which, true, 3*time.Second); old != 0 {
			t.Fatalf("timeout %d of a new socket = %v, want none", which, old)
		}
		if got := socketTimeout(t, w, m, listener, which, false, 0); got < 3*time.Second {
			t.Fatalf("timeout %d = %v, want at least 3s", which, got)
		}
	}
	connectTo(t, w, m, port)
	conn, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	// Linux gives the connection the listener's timeouts; darwin does not.
	inherits := map[string]bool{"linux": true, "darwin": false}[runtime.GOOS]
	if got := socketTimeout(t, w, m, conn, wasiSockTimeoutReceive, false, 0); (got >= 3*time.Second) != inherits {
		t.Fatalf("receive timeout of an accepted connection = %v; the listener's expected: %v", got, inherits)
	}
	// A time a microsecond short of whole seconds is rounded up to them.
	socketTimeout(t, w, m, conn, wasiSockTimeoutSend, true, 2*time.Second-time.Nanosecond)
	if got := socketTimeout(t, w, m, conn, wasiSockTimeoutSend, false, 0); got < 2*time.Second || got > 3*time.Second {
		t.Fatalf("send timeout after setting 1.999999999s = %v, want about 2s", got)
	}
	// A time too far off to count is the farthest the timeval holds.
	socketTimeout(t, w, m, conn, wasiSockTimeoutSend, true, math.MaxInt64)
	if farthest := socketTimeout(t, w, m, conn, wasiSockTimeoutSend, true, 0); farthest < math.MaxInt32*time.Second {
		t.Fatalf("send timeout after setting the farthest = %v, want at least %v", farthest, math.MaxInt32*time.Second)
	}
	if got := socketTimeout(t, w, m, conn, wasiSockTimeoutSend, false, 0); got != 0 {
		t.Fatalf("send timeout after clearing it = %v, want none", got)
	}
	for _, c := range []struct {
		which int32
		nanos int64
	}{{0, 0}, {3, 0}, {wasiSockTimeoutReceive, -1}} {
		if rc := w.Sock_timeout(m, conn, c.which, 1, c.nanos, sockValueOff); rc != -_wasiEINVAL {
			t.Errorf("Sock_timeout(which %d, %d) rc=%d, want -EINVAL", c.which, c.nanos, rc)
		}
	}
	if rc := w.Sock_timeout(m, conn, wasiSockTimeoutReceive, 0, 0, 1<<20); rc != -_wasiEFAULT {
		t.Errorf("Sock_timeout into memory that is not there rc=%d, want -EFAULT", rc)
	}
	if rc := w.Sock_timeout(m, 999, wasiSockTimeoutReceive, 0, 0, sockValueOff); rc != -_wasiEBADF {
		t.Errorf("Sock_timeout of no descriptor rc=%d, want -EBADF", rc)
	}
	if rc := w.Sock_timeout64(m, conn, wasiSockTimeoutReceive, 0, 0, int64(sockValueOff)); rc != _wasiESUCCESS {
		t.Errorf("Sock_timeout64 rc=%d", rc)
	}
}

// A blocking receive, accept or send waits no longer than its timeout,
// counted from its first wait: it gives up with EAGAIN, and a receive that
// waits for all reports what it has.
func TestSocket_TimeoutsEndWaits(t *testing.T) {
	const timeout = 20 * time.Millisecond
	w, m, _ := newSocketStubs(t)
	waitsAbout := func(what string, call func() int32, want int32) {
		t.Helper()
		start := time.Now()
		if rc := call(); rc != want {
			t.Fatalf("%s rc=%d, want %d", what, rc, want)
		}
		if waited := time.Since(start); waited < timeout {
			t.Fatalf("%s gave up after %v, before its timeout %v", what, waited, timeout)
		}
	}
	listener, _ := newIPListener(t, w, m)
	socketTimeout(t, w, m, listener, wasiSockTimeoutReceive, true, timeout)
	waitsAbout("accept", func() int32 { _, rc := acceptOn(w, m, listener); return rc }, _wasiEAGAIN)

	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	socketTimeout(t, w, m, a, wasiSockTimeoutReceive, true, timeout)
	waitsAbout("recv", func() int32 { _, rc := sockRecv(w, m, a); return rc }, _wasiEAGAIN)
	if rc := sockSend(w, m, b, "ab"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	waitsAbout("recv for all", func() int32 {
		return w.Sock_recvfrom_addr(m, a, sockBufOff, 8, wasiMsgWaitAll, 0, sockLenOff)
	}, _wasiESUCCESS)
	if n := readU32(m.memory, int(sockLenOff)); n != 2 {
		t.Fatalf("recv for all that timed out got %d bytes, want the 2 there", n)
	}

	fillNonBlocking(t, w, m, b)
	if rc := w.Fd_fdstat_set_flags(m, b, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	socketTimeout(t, w, m, b, wasiSockTimeoutSend, true, timeout)
	waitsAbout("send", func() int32 { return sockSend(w, m, b, "more") }, _wasiEAGAIN)
}

// A timeout is set in microseconds rounded up, and one longer than the
// host's timeval holds is the longest it holds: the host is given a time of
// at least the one asked for.
func TestSocket_TimeoutsSetOnTheHost(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	for _, d := range []time.Duration{time.Nanosecond, 2*time.Second - time.Nanosecond, math.MaxInt64} {
		var tv syscall.Timeval
		var failed error
		if errno := w.socketCall("test", op.hostSocket(), func(fd int) {
			if failed = setHostSocketTimeout(fd, false, d); failed == nil {
				failed = hostGetsockopt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, unsafe.Pointer(&tv), unsafe.Sizeof(tv))
			}
		}); errno != _wasiESUCCESS || failed != nil {
			t.Fatalf("set %v: errno=%d err=%v", d, errno, failed)
		}
		if tv.Nano() < min(int64(d), math.MaxInt32*int64(time.Second)) {
			t.Fatalf("set %v: the host has %v, less than asked for", d, time.Duration(tv.Nano()))
		}
	}
}

// Linger is in seconds on every host.
func TestSocket_LingerInSeconds(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	fd := openSocket(t, w, m, wasiSockFamilyIPv4, wasiSockTypeStream)
	if rc := w.Sock_setopt(m, fd, wasiSockOptLinger, 3); rc != _wasiESUCCESS {
		t.Fatalf("set linger rc=%d", rc)
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	var linger syscall.Linger
	var failed error
	if errno := w.socketCall("test", op.hostSocket(), func(fd int) {
		failed = hostGetsockopt(fd, syscall.SOL_SOCKET, hostSOLinger, unsafe.Pointer(&linger), unsafe.Sizeof(linger))
	}); errno != _wasiESUCCESS || failed != nil {
		t.Fatalf("getsockopt errno=%d err=%v", errno, failed)
	}
	if linger.Onoff == 0 || linger.Linger != 3 {
		t.Fatalf("the host's linger in seconds = %+v, want on for 3", linger)
	}
}
