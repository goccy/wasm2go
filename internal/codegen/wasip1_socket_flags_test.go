package codegen

import (
	"testing"
	"time"
)

// The flags of send and recv.

// recvFlags is one recvfrom with flags; it returns the bytes and the errno
// (positive).
func recvFlags(w *WasiStubs, m *Module, fd, capacity, flags int32) (string, int32) {
	rc := w.Sock_recvfrom(m, fd, dgBufOff, capacity, flags, dgNameOff, dgLenOff)
	if rc != 0 {
		return "", -rc
	}
	n := int32(readU32(m.memory, int(dgLenOff)))
	return string(m.memory[dgBufOff : dgBufOff+n]), 0
}

func sendFlags(w *WasiStubs, m *Module, fd int32, s string, flags int32) int32 {
	copy(m.memory[dgBufOff:], s)
	return -w.Sock_sendto(m, fd, dgBufOff, int32(len(s)), flags, 0, 0, 0, dgLenOff)
}

// connectedPair returns the two ends of a TCP connection over loopback.
func connectedPair(t *testing.T, w *WasiStubs, m *Module) (client, server int32) {
	t.Helper()
	listener, port := newListener(t, w, m)
	client = dialLoopback(t, w, m, port)
	server, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("accept rc=%d", rc)
	}
	return client, server
}

func TestSocket_ReceiveFlags(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	client, server := connectedPair(t, w, m)

	// Not waiting, on a socket that otherwise blocks.
	if _, errno := recvFlags(w, m, server, 16, wasiMsgDontWait); errno != _wasiEAGAIN {
		t.Fatalf("recv without waiting, nothing there: errno %d, want EAGAIN", errno)
	}
	if _, errno := recvFlags(w, m, server, 16, wasiMsgDontWait|wasiMsgPeek); errno != _wasiEAGAIN {
		t.Fatalf("peek without waiting, nothing there: errno %d, want EAGAIN", errno)
	}

	// Looking leaves the input in place, as often as it is looked at.
	if rc := sockSend(w, m, client, "hello"); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	for i := 0; i < 2; i++ {
		if got, errno := recvFlags(w, m, server, 16, wasiMsgPeek); errno != 0 || got != "hello" {
			t.Fatalf("peek %d = %q errno %d, want %q", i, got, errno, "hello")
		}
	}
	if got, errno := recvFlags(w, m, server, 3, wasiMsgPeek); errno != 0 || got != "hel" {
		t.Fatalf("short peek = %q errno %d, want %q", got, errno, "hel")
	}
	// The standard receive has the same flag.
	makeIovec(m, sockIovOff, sockBufOff, 64)
	if rc := w.Sock_recv(m, server, sockIovOff, 1, wasiMsgPeek, sockLenOff, sockFlagsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_recv with RECV_PEEK rc=%d", rc)
	}
	if n := readU32(m.memory, int(sockLenOff)); string(m.memory[sockBufOff:sockBufOff+int32(n)]) != "hello" {
		t.Fatalf("Sock_recv with RECV_PEEK took %d bytes", n)
	}
	if got, errno := recvFlags(w, m, server, 2, 0); errno != 0 || got != "he" {
		t.Fatalf("recv = %q errno %d, want %q", got, errno, "he")
	}
	if got, errno := recvFlags(w, m, server, 16, 0); errno != 0 || got != "llo" {
		t.Fatalf("recv of the rest = %q errno %d, want %q", got, errno, "llo")
	}

	// A peek waits for input like a receive, and a signal ends the wait.
	postSoon(w, wasiSIGUSR1)
	if _, errno := recvFlags(w, m, server, 16, wasiMsgPeek); errno != _wasiEINTR {
		t.Fatalf("peek of an idle socket: errno %d, want EINTR", errno)
	}
	takeSignals(t, w, m)

	// Waiting for all of it gathers what arrives in pieces.
	go func() {
		cm := newForkTestModule()
		sockSend(w, cm, client, "ab")
		time.Sleep(50 * time.Millisecond)
		sockSend(w, cm, client, "cdef")
	}()
	if got, errno := recvFlags(w, m, server, 4, wasiMsgWaitAll); errno != 0 || got != "abcd" {
		t.Fatalf("recv of all 4 = %q errno %d, want %q", got, errno, "abcd")
	}
	// ... and returns short at the end of input.
	if rc := w.Sock_shutdown(m, client, 2); rc != _wasiESUCCESS {
		t.Fatalf("Sock_shutdown rc=%d", rc)
	}
	if got, errno := recvFlags(w, m, server, 8, wasiMsgWaitAll); errno != 0 || got != "ef" {
		t.Fatalf("recv of all 8 before the end of input = %q errno %d, want %q", got, errno, "ef")
	}
	if got, errno := recvFlags(w, m, server, 8, wasiMsgPeek); errno != 0 || got != "" {
		t.Fatalf("peek at the end of input = %q errno %d, want nothing", got, errno)
	}
}

func TestDatagram_PeekLeavesTheDatagram(t *testing.T) {
	w, m := newProcTestStubs(t)
	receiver := newDatagramSocket(t, w, m)
	if rc := w.Sock_bind(m, receiver, loopbackBE, 0); rc != _wasiESUCCESS {
		t.Fatalf("Sock_bind rc=%d", rc)
	}
	port := int32(localName(t, w, m, receiver).port)
	sender := newDatagramSocket(t, w, m)
	if _, errno := recvFlags(w, m, receiver, 16, wasiMsgDontWait); errno != _wasiEAGAIN {
		t.Fatalf("recv without waiting, nothing there: errno %d, want EAGAIN", errno)
	}
	if _, rc := sendTo(w, m, sender, "datagram", uint32(loopbackBE), port); rc != 0 {
		t.Fatalf("Sock_sendto rc=%d", rc)
	}
	for i := 0; i < 2; i++ {
		if got, errno := recvFlags(w, m, receiver, 16, wasiMsgPeek); errno != 0 || got != "datagram" {
			t.Fatalf("peek %d = %q errno %d", i, got, errno)
		}
	}
	if got, errno := recvFlags(w, m, receiver, 16, 0); errno != 0 || got != "datagram" {
		t.Fatalf("recv = %q errno %d", got, errno)
	}
	if _, errno := recvFlags(w, m, receiver, 16, wasiMsgDontWait); errno != _wasiEAGAIN {
		t.Fatalf("recv after the datagram was taken: errno %d, want EAGAIN", errno)
	}
}

func TestSocket_SendFlags(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGPIPE)
	client, server := connectedPair(t, w, m)
	if errno := sendFlags(w, m, client, "ok", wasiMsgNoSignal|wasiMsgDontWait); errno != 0 {
		t.Fatalf("send errno %d", errno)
	}
	if got, errno := recvFlags(w, m, server, 16, 0); errno != 0 || got != "ok" {
		t.Fatalf("recv = %q errno %d", got, errno)
	}
	// The peer is gone: a send that asked for no signal gets EPIPE alone.
	if rc := w.Fd_close(m, server); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	var errno int32
	for i := 0; i < 100 && errno == 0; i++ {
		errno = sendFlags(w, m, client, "into the void", wasiMsgNoSignal)
		time.Sleep(5 * time.Millisecond)
	}
	if errno != _wasiEPIPE && errno != _wasiECONNRESET {
		t.Fatalf("send to a closed peer: errno %d, want EPIPE", errno)
	}
	if got := takeSignals(t, w, m); got&wasiSignalBit(wasiSIGPIPE) != 0 {
		t.Fatalf("a send without signal posted SIGPIPE (pending %#x)", got)
	}
	// Without the flag the signal comes with it.
	errno = 0
	for i := 0; i < 100 && errno != _wasiEPIPE; i++ {
		errno = sendFlags(w, m, client, "into the void", 0)
		time.Sleep(5 * time.Millisecond)
	}
	if errno != _wasiEPIPE {
		t.Fatalf("send to a closed peer: errno %d, want EPIPE", errno)
	}
	if got := takeSignals(t, w, m); got&wasiSignalBit(wasiSIGPIPE) == 0 {
		t.Fatalf("a plain send to a closed peer posted no SIGPIPE (pending %#x)", got)
	}
}
