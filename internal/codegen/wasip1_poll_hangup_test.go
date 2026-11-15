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
	if got, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read after the hang-up = %q rc=%d, want the input left", got, rc)
	}
	wantHangup(t, w, m, readFd, true)
}

// A descriptor of the host process (the guest is the host process).
func TestHostDescriptors_PollReportsThatAPipeWasHungUpOn(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	wantHangup(t, w, m, readFd, false)
	if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	wantHangup(t, w, m, readFd, true)
}

// pollEvent polls fd for one event of etype (1 fd_read, 2 fd_write) and
// reports whether it was reported, and its errno and hang-up flag.
func pollEvent(t *testing.T, w *WasiStubs, m *Module, fd int32, etype byte) (reported bool, errno uint16, hangup bool) {
	t.Helper()
	writeSubClock(m, pollSubsOff, 1, int64(2*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, etype, fd)
	got := pollUserdata(t, w, m, 2)
	if len(got) != 1 || got[0] != 2 {
		return false, 0, false
	}
	// the event's errno (offset 8) and fd_readwrite.flags (offset 24)
	return true, binary.LittleEndian.Uint16(m.memory[pollEvOff+8:]), binary.LittleEndian.Uint16(m.memory[pollEvOff+24:])&1 != 0
}

// A socket of the host process whose peer is gone is writable, as the
// host's select(2) has it (Linux's poll reports POLLOUT with POLLHUP,
// darwin's POLLHUP alone): the subscription for writing is reported
// without an error and without the hang-up, which the guest's C library
// would take as the end of writability — wasi-libc's select() then reports
// the descriptor in no set and returns 0 at once, and an event loop waiting
// for a connect to end spins. The subscription for reading carries the
// hang-up.
func TestHostDescriptors_PollReportsASocketWhosePeerIsGoneWritable(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	const fdsOff int32 = 6000
	if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, wasiSockTypeStream, fdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
	if rc := w.Fd_close(m, b); rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	reported, errno, hangup := pollEvent(t, w, m, a, 2)
	if !reported || errno != 0 || hangup {
		t.Fatalf("for writing: reported %v errno %d hang-up %v, want reported, errno 0, no hang-up", reported, errno, hangup)
	}
	reported, errno, hangup = pollEvent(t, w, m, a, 1)
	if !reported || errno != 0 || !hangup {
		t.Fatalf("for reading: reported %v errno %d hang-up %v, want reported, errno 0, hang-up", reported, errno, hangup)
	}
}

// A connection of the runtime's own whose peer has closed it: the host
// says whether that is a hang-up (an AF_UNIX stream's is).
func TestWasi_PollReportsThatAConnectionWasHungUpOn(t *testing.T) {
	w, m := newProcTestStubs(t)
	dir, err := os.MkdirTemp("", "hup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	peer, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	w.stdin = conn
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	wantHangup(t, w, m, 0, false)
	if got, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	_ = peer.Close()
	wantHangup(t, w, m, 0, true)
}
