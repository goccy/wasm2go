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
func writeChunk(t *testing.T, w *WasiStubs, m *Module, fd int32) (n uint32, rc int32) {
	t.Helper()
	makeIovec(m, wsIovOff, wsBufOff, wsChunk)
	binary.LittleEndian.PutUint32(m.memory[wsCountOff:], 0xdeadbeef)
	returnsWithin(t, "Fd_write", func() { rc = w.Fd_write(m, fd, wsIovOff, 1, wsCountOff) })
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
		n, rc := writeChunk(t, w, m, fd)
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
func pollWritable(t *testing.T, w *WasiStubs, m *Module, fd int32, timeout time.Duration) (writable bool, rc int32) {
	t.Helper()
	nsubs := int32(1)
	writeSubFd(m, pollSubsOff, 9, 2 /* fd_write */, fd)
	if timeout >= 0 {
		writeSubClock(m, pollSubsOff+48, 1, int64(timeout))
		nsubs = 2
	}
	returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, nsubs, pollNevOff) })
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

// drainSoon reads n bytes from fd's stream on another goroutine, once the
// caller has had time to block, and delivers how many it got.
func drainSoon(t *testing.T, w *WasiStubs, fd int32, n uint64) <-chan uint64 {
	w.mu.Lock()
	src, _ := w.fdSrcLocked(fd)
	w.mu.Unlock()
	done := make(chan uint64, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		buf := make([]byte, 1<<16)
		var got uint64
		for got < n {
			c, err := src.Read(buf)
			got += uint64(c)
			if err != nil {
				t.Errorf("draining the stream: %v after %d bytes", err, got)
				break
			}
		}
		done <- got
	}()
	return done
}

func TestWasi_PipeIsWritableOnlyWhileItHasRoom(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)

	if ok, rc := pollWritable(t, w, m, writeFd, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("an empty pipe polled writable=%v rc=%d, want writable", ok, rc)
	}
	// The read end is never writable: the poll runs into its timeout.
	start := time.Now()
	if ok, rc := pollWritable(t, w, m, readFd, 60*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("the read end polled writable=%v rc=%d", ok, rc)
	}
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll on the read end returned after %v, before its timeout", d)
	}

	written := fillNonBlocking(t, w, m, writeFd)
	if written == 0 {
		t.Fatal("nothing fitted into an empty pipe")
	}
	if ok, rc := pollWritable(t, w, m, writeFd, 60*time.Millisecond); ok || rc != _wasiESUCCESS {
		t.Fatalf("a full pipe polled writable=%v rc=%d", ok, rc)
	}

	// A reader that drains the pipe makes it writable again, and ends a
	// poll that was waiting for exactly that.
	drained := drainSoon(t, w, readFd, written)
	if ok, rc := pollWritable(t, w, m, writeFd, waitLimit/2); !ok || rc != _wasiESUCCESS {
		t.Fatalf("after the reader drained it the pipe polled writable=%v rc=%d", ok, rc)
	}
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiESUCCESS || n == 0 {
		t.Fatalf("write after draining: %d bytes rc=%d", n, rc)
	}
	select {
	case <-drained:
	case <-time.After(waitLimit):
		t.Fatal("the reader never drained the pipe")
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
	postWhenBlocked(w, wasiSIGUSR1)
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiEINTR || n != 0 {
		t.Fatalf("blocking write into a full pipe: %d bytes rc=%d, want EINTR", n, rc)
	}
	takeSignals(t, w, m)

	// With a reader the same write completes.
	drained := drainSoon(t, w, readFd, written+uint64(wsChunk))
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiESUCCESS || n != uint32(wsChunk) {
		t.Fatalf("blocking write with a reader: %d bytes rc=%d, want all %d", n, rc, wsChunk)
	}
	select {
	case got := <-drained:
		if got != written+uint64(wsChunk) {
			t.Fatalf("the reader got %d bytes, want %d", got, written+uint64(wsChunk))
		}
	case <-time.After(waitLimit):
		t.Fatal("the reader never saw the data")
	}
}

func TestWasi_WriteToAClosedPipeIsEPIPE(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
		t.Fatalf("close the read end rc=%d", rc)
	}
	// poll(2) reports such a pipe writable: the write returns at once.
	if ok, rc := pollWritable(t, w, m, writeFd, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("a pipe without a reader polled writable=%v rc=%d", ok, rc)
	}
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiEPIPE || n != 0 {
		t.Fatalf("write without a reader: %d bytes rc=%d, want EPIPE", n, rc)
	}
	// Linux's poll(2) reports the write end in error (POLLERR) as well,
	// which a subscription for reading of it asks about.
	if runtime.GOOS != "linux" {
		return
	}
	writeSubFd(m, pollSubsOff, 7, 1 /* fd_read */, writeFd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if errno := binary.LittleEndian.Uint16(m.memory[pollEvOff+8:]); errno != uint16(_wasiEPIPE) {
		t.Fatalf("the event for reading the write end has errno %d, want EPIPE", errno)
	}
}

func TestWasi_WriteReportsItsFailure(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	// Writing to the read end of a pipe transfers nothing and says why.
	if n, rc := writeChunk(t, w, m, readFd); rc != _wasiEBADF || n != 0 {
		t.Fatalf("write to a read end: %d bytes rc=%d, want EBADF", n, rc)
	}
}
