//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// poll_oneoff tells the guest that the peer of a descriptor it reads has
// hung up — eventrwflags' fd_readwrite_hangup, which the guest's poll()
// reports as POLLHUP — and not before: a pipe whose writer is still there
// is readable without it, one whose writers have all closed it carries it
// with whatever input is left.

// pollHangup polls fd for reading and reports whether the poll reported it,
// and with the hang-up flag.
func pollHangup(t *testing.T, w *WasiStubs, m *Module, fd int32) (reported, hangup bool) {
	t.Helper()
	writeSubClock(m, pollSubsOff, 1, int64(2*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, fd)
	got := pollUserdata(t, w, m, 2)
	if len(got) != 1 || got[0] != 2 {
		return false, false
	}
	// the event's fd_readwrite.flags (offset 24); bit 0 is
	// fd_readwrite_hangup in the WASI ABI
	return true, binary.LittleEndian.Uint16(m.memory[pollEvOff+24:])&1 != 0
}

func wantHangup(t *testing.T, w *WasiStubs, m *Module, fd int32, want bool) {
	t.Helper()
	reported, hangup := pollHangup(t, w, m, fd)
	if !reported {
		t.Fatalf("descriptor %d was not reported readable", fd)
	}
	if hangup != want {
		t.Fatalf("descriptor %d: hang-up flag %v, want %v", fd, hangup, want)
	}
}

// A pipe of the runtime's own (a stream it probes).
func TestWasi_PollReportsThatAPipeWasHungUpOn(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	wantHangup(t, w, m, readFd, false)
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	wantHangup(t, w, m, readFd, true)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read after the hang-up = %q rc=%d, want the input left", got, rc)
	}
	wantHangup(t, w, m, readFd, true)
}

// A connection of the runtime's own whose peer has closed it: the host
// says whether that is a hang-up (an AF_UNIX stream's is).
func TestWasi_PollReportsThatAConnectionWasHungUpOn(t *testing.T) {
	w, m := newProcTestStubs(t)
	// A directory of its own with a short name: the socket's path must fit
	// in sun_path.
	dir, err := os.MkdirTemp("", "hup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	peer, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	w.cfg.Stdin = conn
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	wantHangup(t, w, m, 0, false)
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	wantHangup(t, w, m, 0, true)
}

// A socket of the host's the runtime made, whose peer has closed it: the
// host says whether that is a hang-up (an AF_UNIX stream's is).
func TestWasi_PollReportsThatASocketPeerHungUp(t *testing.T) {
	w, m, _ := newSocketStubs(t)
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(sockFdsOff))), int32(readU32(m.memory, int(sockFdsOff)+4))
	if rc := sockSend(w, m, b, "x"); rc != _wasiESUCCESS {
		t.Fatalf("send rc=%d", rc)
	}
	wantHangup(t, w, m, a, false)
	if got, rc := sockRecv(w, m, a); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("recv = %q rc=%d", got, rc)
	}
	if rc := w.Fd_close(m, b); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	wantHangup(t, w, m, a, true)
}
