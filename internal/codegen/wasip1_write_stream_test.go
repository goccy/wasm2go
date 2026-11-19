package codegen

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"
)

// Writing to streams whose write can block (pipes, sockets): poll_oneoff
// reports them writable only while they have room, and a write honours
// O_NONBLOCK, is ended by a signal, and reports its failure.

const (
	wsIovOff   int32 = 20000
	wsCountOff int32 = 20016
	wsBufOff   int32 = 20032
	wsChunk    int32 = 16384
)

func skipWithoutStreamWrites(t *testing.T) {
	t.Helper()
	if !hostStreamWrites {
		t.Skipf("the runtime cannot write to a stream without waiting on %s", runtime.GOOS)
	}
}

// writeChunk writes one chunk of wsChunk bytes to fd and returns the count
// and the errno.
func writeChunk(w *WasiStubs, m *Module, fd int32) (uint32, int32) {
	makeIovec(m, wsIovOff, wsBufOff, wsChunk)
	binary.LittleEndian.PutUint32(m.memory[wsCountOff:], 0xdeadbeef)
	rc := w.Fd_write(m, fd, wsIovOff, 1, wsCountOff)
	return readU32(m.memory, int(wsCountOff)), rc
}

// fillNonBlocking sets O_NONBLOCK on fd and writes until the stream takes
// no more; it returns the bytes written.
func fillNonBlocking(t *testing.T, w *WasiStubs, m *Module, fd int32) uint64 {
	t.Helper()
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	var total uint64
	for i := 0; i < 1<<16; i++ {
		n, rc := writeChunk(w, m, fd)
		if rc == _wasiEAGAIN {
			if n != 0 {
				t.Fatalf("EAGAIN with a count of %d", n)
			}
			return total
		}
		if rc != _wasiESUCCESS {
			t.Fatalf("non-blocking write rc=%d after %d bytes", rc, total)
		}
		if n == 0 || n > uint32(wsChunk) {
			t.Fatalf("non-blocking write reported %d bytes of %d", n, wsChunk)
		}
		total += uint64(n)
	}
	t.Fatalf("the stream took %d bytes and never filled up", total)
	return 0
}

// pollWritable polls fd for writing with the given timeout (negative: none)
// and reports whether it came back writable; rc is Poll_oneoff's result.
func pollWritable(w *WasiStubs, m *Module, fd int32, timeout time.Duration) (writable bool, rc int32) {
	nsubs := int32(1)
	writeSubFd(m, pollSubsOff, 9, 2 /* fd_write */, fd)
	if timeout >= 0 {
		writeSubClock(m, pollSubsOff+48, 1, int64(timeout))
		nsubs = 2
	}
	rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, nsubs, pollNevOff)
	if rc != _wasiESUCCESS {
		return false, rc
	}
	n := int32(binary.LittleEndian.Uint32(m.memory[pollNevOff:]))
	for i := int32(0); i < n; i++ {
		if binary.LittleEndian.Uint64(m.memory[pollEvOff+i*32:]) == 9 {
			return true, rc
		}
	}
	return false, rc
}

func TestWasi_PipeIsWritableOnlyWhileItHasRoom(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)

	if ok, rc := pollWritable(w, m, writeFd, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("an empty pipe polled writable=%v rc=%d, want writable", ok, rc)
	}
	// The read end is never writable: the poll runs into its timeout.
	start := time.Now()
	if ok, rc := pollWritable(w, m, readFd, 60*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("the read end polled writable=%v rc=%d", ok, rc)
	}
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll on the read end returned after %v, before its timeout", d)
	}

	written := fillNonBlocking(t, w, m, writeFd)
	if written == 0 {
		t.Fatal("nothing fitted into an empty pipe")
	}
	if ok, rc := pollWritable(w, m, writeFd, 60*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("a full pipe polled writable=%v rc=%d", ok, rc)
	}

	// A reader that drains the pipe makes it writable again, and ends a
	// poll that was waiting for exactly that.
	go func() {
		time.Sleep(50 * time.Millisecond)
		buf := make([]byte, 1<<16)
		w.mu.Lock()
		src, _ := w.fdSrcLocked(readFd)
		w.mu.Unlock()
		for left := written; left > 0; {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			left -= uint64(n)
		}
	}()
	if ok, rc := pollWritable(w, m, writeFd, 20*time.Second); !ok || rc != _wasiESUCCESS {
		t.Fatalf("after the reader drained it the pipe polled writable=%v rc=%d", ok, rc)
	}
	if n, rc := writeChunk(w, m, writeFd); rc != _wasiESUCCESS || n == 0 {
		t.Fatalf("write after draining: %d bytes rc=%d", n, rc)
	}
}

func TestWasi_BlockingWriteWaitsForRoomAndIsEndedByASignal(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	written := fillNonBlocking(t, w, m, writeFd)
	if rc := w.Fd_fdstat_set_flags(m, writeFd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}

	// Nothing fits: the write waits, and a signal ends it with EINTR.
	postSoon(w, wasiSIGUSR1)
	start := time.Now()
	if n, rc := writeChunk(w, m, writeFd); rc != _wasiEINTR || n != 0 {
		t.Fatalf("blocking write into a full pipe: %d bytes rc=%d, want EINTR", n, rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the interrupted write returned after %v", d)
	}
	takeSignals(t, w, m)

	// With a reader the same write completes.
	done := make(chan uint64, 1)
	go func() {
		buf := make([]byte, 1<<16)
		w.mu.Lock()
		src, _ := w.fdSrcLocked(readFd)
		w.mu.Unlock()
		var got uint64
		for got < written+uint64(wsChunk) {
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			got += uint64(n)
		}
		done <- got
	}()
	if n, rc := writeChunk(w, m, writeFd); rc != _wasiESUCCESS || n != uint32(wsChunk) {
		t.Fatalf("blocking write with a reader: %d bytes rc=%d, want all %d", n, rc, wsChunk)
	}
	select {
	case got := <-done:
		if got != written+uint64(wsChunk) {
			t.Fatalf("the reader got %d bytes, want %d", got, written+uint64(wsChunk))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the reader never saw the data")
	}
}

func TestWasi_WriteToAClosedPipeIsEPIPEAndPostsSIGPIPE(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newSignalGuest(t, wasiSIGPIPE)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
		t.Fatalf("close the read end rc=%d", rc)
	}
	// poll(2) reports such a pipe writable: the write returns at once.
	if ok, rc := pollWritable(w, m, writeFd, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("a pipe without a reader polled writable=%v rc=%d", ok, rc)
	}
	if n, rc := writeChunk(w, m, writeFd); rc != _wasiEPIPE || n != 0 {
		t.Fatalf("write without a reader: %d bytes rc=%d, want EPIPE", n, rc)
	}
	if got, want := takeSignals(t, w, m), signalMask(wasiSIGPIPE); got != want {
		t.Fatalf("taken = %#x, want SIGPIPE", got)
	}
	// A guest that ignores SIGPIPE gets the errno alone.
	setDispositions(t, w, m, 0, wasiDefaultIgnoredSignals|signalMask(wasiSIGPIPE), 0)
	if n, rc := writeChunk(w, m, writeFd); rc != _wasiEPIPE || n != 0 {
		t.Fatalf("write with SIGPIPE ignored: %d bytes rc=%d, want EPIPE", n, rc)
	}
	if got := takeSignals(t, w, m); got != 0 {
		t.Fatalf("taken = %#x with SIGPIPE ignored", got)
	}
}

func TestWasi_WriteReportsItsFailure(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	// Writing to the read end of a pipe transfers nothing and says why.
	if n, rc := writeChunk(w, m, readFd); rc != _wasiEBADF || n != 0 {
		t.Fatalf("write to a read end: %d bytes rc=%d, want EBADF", n, rc)
	}
}

func TestSocket_ListenerIsNeverWritableAndPollWaitsForASignal(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	w.SetNetAccessHook(func(string) bool { return true })
	listener, port := newListener(t, w, m)
	if ok, rc := pollWritable(w, m, listener, 40*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("a listener polled writable=%v rc=%d", ok, rc)
	}
	// With nothing that can become ready and no timeout, only a signal
	// ends the poll.
	postSoon(w, wasiSIGUSR1)
	start := time.Now()
	if ok, rc := pollWritable(w, m, listener, -1); ok || rc != _wasiEINTR {
		t.Fatalf("poll without timeout on a listener: writable=%v rc=%d, want EINTR", ok, rc)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the poll returned after %v", d)
	}
	takeSignals(t, w, m)

	// A connection is writable, on both ends.
	client := dialLoopback(t, w, m, port)
	server, rc := acceptOn(w, m, listener)
	if rc != _wasiESUCCESS {
		t.Fatalf("Sock_accept rc=%d", rc)
	}
	for name, fd := range map[string]int32{"client": client, "server": server} {
		if ok, rc := pollWritable(w, m, fd, 0); !ok || rc != _wasiESUCCESS {
			t.Fatalf("the %s end polled writable=%v rc=%d, want writable", name, ok, rc)
		}
	}
	// An unconnected socket: a write fails at once, so it does not wait.
	fresh := w.Sock_socket(m, 2, 1)
	if ok, rc := pollWritable(w, m, fresh, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("an unconnected socket polled writable=%v rc=%d", ok, rc)
	}
	if rc := sockSend(w, m, fresh, "x"); rc != _wasiENOTCONN {
		t.Fatalf("send on an unconnected socket rc=%d, want ENOTCONN", rc)
	}
}

func TestSocket_NonBlockingSendTakesWhatFits(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	const fdsOff int32 = 13200
	if rc := sockPairStream(w, m, fdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_pair rc=%d", rc)
	}
	a, b := int32(readU32(m.memory, int(fdsOff))), int32(readU32(m.memory, int(fdsOff)+4))
	if rc := w.Fd_fdstat_set_flags(m, a, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	var total uint64
	filled := false
	for i := 0; i < 1<<16 && !filled; i++ {
		makeIovec(m, wsIovOff, wsBufOff, wsChunk)
		rc := w.Sock_send(m, a, wsIovOff, 1, 0, wsCountOff)
		switch rc {
		case _wasiESUCCESS:
			total += uint64(readU32(m.memory, int(wsCountOff)))
		case _wasiEAGAIN:
			filled = true
		default:
			t.Fatalf("non-blocking send rc=%d after %d bytes", rc, total)
		}
	}
	if !filled || total == 0 {
		t.Fatalf("the socket took %d bytes, filled=%v", total, filled)
	}
	if ok, rc := pollWritable(w, m, a, 40*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("a full socket polled writable=%v rc=%d", ok, rc)
	}
	// The peer going away makes the next send fail, not hang.
	if rc := w.Fd_close(m, b); rc != _wasiESUCCESS {
		t.Fatalf("close the peer rc=%d", rc)
	}
	makeIovec(m, wsIovOff, wsBufOff, wsChunk)
	if rc := w.Sock_send(m, a, wsIovOff, 1, 0, wsCountOff); rc != _wasiEPIPE && rc != _wasiECONNRESET {
		t.Fatalf("send to a closed peer rc=%d, want EPIPE or ECONNRESET", rc)
	}
}
