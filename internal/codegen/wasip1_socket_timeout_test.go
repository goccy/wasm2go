package codegen

import (
	"encoding/binary"
	"testing"
	"time"
)

// SO_ACCEPTCONN, and the receive and send timeouts of a socket.

func TestSocket_AcceptingOption(t *testing.T) {
	w, m := newProcTestStubs(t)
	accepting := func(fd int32) int32 {
		if rc := w.Sock_getopt(m, fd, wasiSockOptAccepting, sockValueOff); rc != _wasiESUCCESS {
			t.Fatalf("Sock_getopt rc=%d", rc)
		}
		return int32(binary.LittleEndian.Uint32(m.memory[sockValueOff:]))
	}
	fd := w.Sock_socket(m, 2, wasiSockTypeStream)
	if got := accepting(fd); got != 0 {
		t.Errorf("a new socket accepts: %d", got)
	}
	if rc := w.Sock_bind(m, fd, loopbackBE, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	if got := accepting(fd); got != 0 {
		t.Errorf("a bound socket accepts: %d", got)
	}
	if rc := w.Sock_listen(m, fd, 5); rc != _wasiESUCCESS {
		t.Fatalf("Sock_listen rc=%d", rc)
	}
	if got := accepting(fd); got != 1 {
		t.Errorf("a listening socket does not accept: %d", got)
	}
	client := dialLoopback(t, w, m, int32(localName(t, w, m, fd).port))
	if got := accepting(client); got != 0 {
		t.Errorf("a connected socket accepts: %d", got)
	}
	if rc := w.Sock_setopt(m, fd, wasiSockOptAccepting, 0); rc != -_wasiENOPROTOOPT {
		t.Errorf("setting the option rc=%d, want -ENOPROTOOPT", rc)
	}
}

func TestSocket_Timeouts(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	const oldOff int32 = 13300
	timeout := func(fd, which, set int32, d time.Duration) (time.Duration, int32) {
		rc := w.Sock_timeout(m, fd, which, set, int64(d), oldOff)
		return time.Duration(binary.LittleEndian.Uint64(m.memory[oldOff:])), rc
	}
	listener, port := newListener(t, w, m)
	client := dialLoopback(t, w, m, port)
	server, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}

	if old, rc := timeout(server, wasiSockTimeoutReceive, 0, 0); rc != 0 || old != 0 {
		t.Fatalf("initial receive timeout = %v rc=%d, want none", old, rc)
	}
	if _, rc := timeout(server, wasiSockTimeoutReceive, 1, 60*time.Millisecond); rc != 0 {
		t.Fatalf("Sock_timeout rc=%d", rc)
	}
	if old, rc := timeout(server, wasiSockTimeoutReceive, 0, 0); rc != 0 || old != 60*time.Millisecond {
		t.Fatalf("receive timeout reads back %v rc=%d", old, rc)
	}
	if old, _ := timeout(server, wasiSockTimeoutSend, 0, 0); old != 0 {
		t.Fatalf("send timeout = %v, want none", old)
	}
	if _, rc := timeout(server, 3, 1, time.Second); rc != -_wasiEINVAL {
		t.Errorf("unknown timeout rc=%d, want -EINVAL", rc)
	}
	if _, rc := timeout(server, wasiSockTimeoutReceive, 1, -1); rc != -_wasiEINVAL {
		t.Errorf("negative timeout rc=%d, want -EINVAL", rc)
	}
	readFd, _ := newTestPipe(t, w, m)
	if _, rc := timeout(readFd, wasiSockTimeoutReceive, 0, 0); rc != -_wasiENOTSOCK {
		t.Errorf("timeout of a pipe rc=%d, want -ENOTSOCK", rc)
	}

	// A receive gives up when the time is over.
	start := time.Now()
	if _, rc := sockRecv(w, m, server); rc != _wasiEAGAIN {
		t.Fatalf("recv on an idle socket with a timeout rc=%d, want EAGAIN", rc)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the receive waited %v, its timeout is 60ms", waited)
	}
	if _, rc := fdReadString(w, m, server, 16); rc != _wasiEAGAIN {
		t.Fatalf("read on an idle socket with a timeout rc=%d, want EAGAIN", rc)
	}
	// Input that arrives in time is received.
	go func() {
		time.Sleep(10 * time.Millisecond)
		sockSend(w, newForkTestModule(), client, "in time")
	}()
	if got, rc := sockRecv(w, m, server); rc != _wasiESUCCESS || got != "in time" {
		t.Fatalf("recv = %q rc=%d", got, rc)
	}
	// A signal still ends the wait first.
	if _, rc := timeout(server, wasiSockTimeoutReceive, 1, 30*time.Second); rc != 0 {
		t.Fatalf("Sock_timeout rc=%d", rc)
	}
	postSoon(w, wasiSIGUSR1)
	if _, rc := sockRecv(w, m, server); rc != _wasiEINTR {
		t.Fatalf("recv interrupted by a signal rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)

	// An accept has the listener's receive timeout.
	if _, rc := timeout(listener, wasiSockTimeoutReceive, 1, 60*time.Millisecond); rc != 0 {
		t.Fatalf("Sock_timeout rc=%d", rc)
	}
	start = time.Now()
	if _, rc := acceptOn(w, m, listener); rc != _wasiEAGAIN {
		t.Fatalf("accept with a timeout and nobody connecting rc=%d, want EAGAIN", rc)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the accept waited %v, its timeout is 60ms", waited)
	}
	dialLoopback(t, w, m, port)
	if _, rc := acceptOn(w, m, listener); rc != _wasiESUCCESS {
		t.Fatalf("accept with a timeout and a connection waiting rc=%d", rc)
	}
}
