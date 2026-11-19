package codegen

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// sockRecvAsync runs Sock_recv on fd on another goroutine with two iovecs of
// the given lengths and delivers what it received.
func sockRecvAsync(w *WasiStubs, fd int32, len0, len1 int32) <-chan string {
	res := make(chan string, 1)
	go func() {
		m := newForkTestModule()
		const iov, buf0, buf1, lenOut, flagsOut = 100, 200, 300, 400, 410
		binary.LittleEndian.PutUint32(m.memory[iov:], buf0)
		binary.LittleEndian.PutUint32(m.memory[iov+4:], uint32(len0))
		binary.LittleEndian.PutUint32(m.memory[iov+8:], buf1)
		binary.LittleEndian.PutUint32(m.memory[iov+12:], uint32(len1))
		if rc := w.Sock_recv(m, fd, iov, 2, 0, lenOut, flagsOut); rc != _wasiESUCCESS {
			res <- "error"
			return
		}
		n := int32(binary.LittleEndian.Uint32(m.memory[lenOut:]))
		got := append([]byte(nil), m.memory[buf0:buf0+min(n, len0)]...)
		if n > len0 {
			got = append(got, m.memory[buf1:buf1+n-len0]...)
		}
		res <- string(got)
	}()
	return res
}

// newSocketPair registers one end of an in-memory connection as a socket fd
// of w and returns the fd and the other end.
func newSocketPair(t *testing.T, w *WasiStubs) (int32, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	w.mu.Lock()
	fd := w.addFDLocked(&wasiOpen{conn: a, isSocket: true})
	w.mu.Unlock()
	return fd, b
}

func wantRecv(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("Sock_recv received %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Sock_recv did not return; want %q", want)
	}
}

// Input a poll probe took out of a socket reaches a recv whose first iovec is
// empty: the probed input fills the iovecs in order, as a read of the stream
// does. Before, the empty first iovec took a zero-byte share of it and the
// recv returned 0, which reads as end of input.
func TestWasi_SockRecvDeliversProbedInputPastAnEmptyIovec(t *testing.T) {
	w, m := newProcTestStubs(t)
	fd, peer := newSocketPair(t, w)
	go peer.Write([]byte("HELLO"))
	writeSubFd(m, pollSubsOff, 1, 1 /* fd_read */, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 1)
	wantRecv(t, sockRecvAsync(w, fd, 0, 16), "HELLO")
}

// A recv into two iovecs returns what one read of the connection delivered
// when it is short of the first iovec, as readv does, instead of going on to
// wait for more input for the second.
func TestWasi_SockRecvReturnsAShortRead(t *testing.T) {
	w, _ := newProcTestStubs(t)
	fd, peer := newSocketPair(t, w)
	got := sockRecvAsync(w, fd, 16, 16)
	if _, err := peer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	wantRecv(t, got, "abc")
}
