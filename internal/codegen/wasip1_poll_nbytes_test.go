//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// The event for reading of a descriptor that has input carries the number
// of bytes it holds (fd_readwrite.nbytes), which the guest's
// ioctl(FIONREAD) reads off a poll_oneoff of a subscription for reading
// beside a clock of no time.

// pollReadEvent waits until fd is readable, then polls it as the guest's
// ioctl(FIONREAD) does and returns its event's errno, byte count and flags.
func pollReadEvent(t *testing.T, w *WasiStubs, m *Module, fd int32) (errno uint16, nbytes uint64, flags uint16) {
	t.Helper()
	writeSubClock(m, pollSubsOff, 1, int64(waitLimit))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, fd)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	writeSubFd(m, pollSubsOff, 0, 1 /* fd_read */, fd)
	writeSubClock(m, pollSubsOff+48, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 2), 0)
	return binary.LittleEndian.Uint16(m.memory[pollEvOff+8:]),
		binary.LittleEndian.Uint64(m.memory[pollEvOff+16:]),
		binary.LittleEndian.Uint16(m.memory[pollEvOff+24:])
}

// wantPollCounts fails the test unless the event for reading of fd counts
// want bytes.
func wantPollCounts(t *testing.T, w *WasiStubs, m *Module, fd int32, want uint64) {
	t.Helper()
	errno, got, _ := pollReadEvent(t, w, m, fd)
	if errno != 0 {
		t.Fatalf("the event of fd %d carries errno %d", fd, errno)
	}
	if got != want {
		t.Fatalf("the event of fd %d counts %d bytes, want %d", fd, got, want)
	}
}

// wantWritten writes s to fd through fd_write.
func wantWritten(t *testing.T, w *WasiStubs, m *Module, fd int32, s string) {
	t.Helper()
	if rc := fdWriteString(w, m, fd, s); rc != _wasiESUCCESS {
		t.Fatalf("write to fd %d rc=%d", fd, rc)
	}
}

// A pipe of the runtime's own.
func TestWasi_PollCountsTheBytesOfAPipe(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr := newTestPipe(t, w, m)
	wantWritten(t, w, m, wr, "hello")
	wantPollCounts(t, w, m, r, 5)
}

// A pipe of the host's that the runtime shares with others.
func TestWasi_PollCountsTheBytesOfAHostPipe(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r)
	closeAtEnd(t, wr)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{f: r, noWrite: true})
	w.mu.Unlock()
	write(t, wr, "hello")
	wantPollCounts(t, w, m, fd, 5)
}

// A FIFO is counted by the host where poll(2) waits for it; on darwin,
// where poll(2) does not report the end of a FIFO (hostPollReportsFIFOEnd),
// what the FIFO's reader holds is counted.
func TestWasi_PollCountsTheBytesOfAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Skipf("no FIFO: %v", err)
	}
	w, m := newTestStubs(t, dir)
	writer := make(chan *os.File, 1)
	go func() {
		f, err := os.OpenFile(filepath.Join(dir, "fifo"), os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
		}
		writer <- f
	}()
	fd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("pathOpen errno=%d", errno)
	}
	wf := <-writer
	if wf == nil {
		t.FailNow()
	}
	closeAtEnd(t, wf)
	write(t, wf, "hello")
	wantPollCounts(t, w, m, fd, 5)
}

// A datagram socket counts as the host's FIONREAD does: the next datagram
// on linux, every datagram of the receive buffer with its address on
// darwin.
func TestWasi_PollCountsTheBytesOfASocketPair(t *testing.T) {
	for _, typ := range []int32{wasiSockTypeStream, wasiSockTypeDgram} {
		t.Run(map[int32]string{wasiSockTypeStream: "Stream", wasiSockTypeDgram: "Datagram"}[typ], func(t *testing.T) {
			w, m := newProcTestStubs(t)
			if rc := w.Sock_socketpair(m, wasiSockFamilyUnix, typ, 5000); rc != _wasiESUCCESS {
				t.Fatalf("Sock_socketpair rc=%d", rc)
			}
			a, b := int32(readU32(m.memory, 5000)), int32(readU32(m.memory, 5004))
			wantWritten(t, w, m, a, "hello")
			wantWritten(t, w, m, a, "abc")
			want := uint64(8)
			if typ == wasiSockTypeDgram {
				want = 5
				if runtime.GOOS == "darwin" {
					if want = hostCount(t, w, b); want <= 8 {
						t.Fatalf("darwin counts %d bytes of two datagrams of 8 bytes and their addresses", want)
					}
				}
			}
			wantPollCounts(t, w, m, b, want)
		})
	}
}

// hostCount returns the bytes the host's FIONREAD counts of the descriptor
// behind the guest's fd.
func hostCount(t *testing.T, w *WasiStubs, fd int32) uint64 {
	t.Helper()
	w.mu.Lock()
	conn := w.entryHostConnLocked(w.openLocked(fd))
	w.mu.Unlock()
	var n int
	if err := withHostDescriptor(conn, func(fd uintptr) error {
		var err error
		n, err = hostReadable(fd)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return uint64(n)
}

// A descriptor the host has no count of is ready as poll(2) says, and its
// event counts no bytes and carries no error: /dev/null (ENOTTY on linux,
// ENODEV on darwin), a terminal whose master is closed (EIO on linux),
// which keeps its hang-up.
func TestWasi_PollOfWhatTheHostDoesNotCount(t *testing.T) {
	stubs := func(t *testing.T, stdin *os.File) (*WasiStubs, *Module) {
		w, m := newProcTestStubs(t)
		w.cfg.Stdin = stdin
		w.cfg.Errors = func(op string, err error) { t.Errorf("%s: %v", op, err) }
		return w, m
	}
	t.Run("DevNull", func(t *testing.T) {
		null, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		closeAtEnd(t, null)
		w, m := stubs(t, null)
		if errno, n, _ := pollReadEvent(t, w, m, 0); errno != 0 || n != 0 {
			t.Fatalf("the event of %s carries errno %d and counts %d bytes", os.DevNull, errno, n)
		}
	})
	t.Run("HungUpTerminal", func(t *testing.T) {
		master, slave := openTestPty(t)
		w, m := stubs(t, slave)
		if err := master.Close(); err != nil {
			t.Fatal(err)
		}
		errno, n, flags := pollReadEvent(t, w, m, 0)
		if errno != 0 || n != 0 || flags&wasiEventHangup == 0 {
			t.Fatalf("the event of a terminal whose master is closed carries errno %d, counts %d bytes, flags %#x; want a hang-up", errno, n, flags)
		}
	})
}
