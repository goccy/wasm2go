//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Descriptors of the host's are waited for in poll(2): nothing is taken off
// them to learn whether they are ready, and the wait is ended by a signal
// even on a descriptor that takes no deadline (a terminal, a pipe in
// blocking mode).

// Offsets in a test module's memory for the reads with several buffers.
const (
	hostIovOff   int32 = 30000
	hostCountOff int32 = 30064
	hostBufOff   int32 = 30100
)

// closeAtEnd closes f when the test ends, unless the test has closed it.
func closeAtEnd(t *testing.T, f *os.File) {
	t.Cleanup(func() {
		if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
}

// blockingPipe returns a pipe in blocking mode whose ends take no deadline,
// as a terminal or a pipe a process inherits (os.Stdin) do. (os.Pipe makes
// its ends non-blocking, and they take deadlines.)
func blockingPipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	r, w = os.NewFile(uintptr(p[0]), "r"), os.NewFile(uintptr(p[1]), "w")
	closeAtEnd(t, r)
	closeAtEnd(t, w)
	if err := r.SetReadDeadline(time.Time{}); !errors.Is(err, os.ErrNoDeadline) {
		t.Fatalf("the read end of a blocking pipe took a deadline: %v", err)
	}
	return r, w
}

// write writes s to f, failing the test when it cannot.
func write(t *testing.T, f *os.File, s string) {
	t.Helper()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// fdReadv reads fd through one Fd_read into buffers of the given sizes and
// returns what they got, in order.
func fdReadv(t *testing.T, w *WasiStubs, m *Module, fd int32, sizes ...int32) (got string, rc int32) {
	t.Helper()
	off := hostBufOff
	for i, size := range sizes {
		makeIovec(m, hostIovOff+int32(i)*8, off, size)
		off += size
	}
	returnsWithin(t, "Fd_read", func() { rc = w.Fd_read(m, fd, hostIovOff, int32(len(sizes)), hostCountOff) })
	n := int32(readU32(m.memory, int(hostCountOff)))
	if rc != _wasiESUCCESS {
		return "", rc
	}
	return string(m.memory[hostBufOff : hostBufOff+n]), rc
}

// wantInputAwaited polls fd for reading: with nothing there the poll waits
// out its timeout, and once feed has written to the stream fd is reported
// and reads what was written.
func wantInputAwaited(t *testing.T, w *WasiStubs, m *Module, fd int32, feed func(string)) {
	t.Helper()
	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, fd)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll of a stream with no input returned after %v, before its timeout", d)
	}
	feed("x\n")
	writeSubClock(m, pollSubsOff, 1, int64(waitLimit))
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "x\n" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "x\n")
	}
}

func TestWasi_PollWaitsForInputOnAStreamThatTakesNoDeadline(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr := blockingPipe(t)
	w.cfg.Stdin = r
	wantInputAwaited(t, w, m, 0, func(s string) { write(t, wr, s) })
}

func TestWasi_PollWaitsForInputOnATerminal(t *testing.T) {
	master, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	wantInputAwaited(t, w, m, 0, func(s string) { write(t, master, s) })
}

// The input of a pipe the host shares with others (a process it spawned)
// stays in the pipe until the guest reads it, and a read takes no more than
// the guest asked for.
func TestWasi_PollTakesNothingOffAHostPipe(t *testing.T) {
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
	hostRead := func() string {
		t.Helper()
		if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := r.Read(buf)
		if err != nil {
			t.Fatalf("the host's read of the pipe: %v", err)
		}
		return string(buf[:n])
	}

	write(t, wr, "hello")
	writeSubFd(m, pollSubsOff, 7, 1, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got := hostRead(); got != "hello" {
		t.Fatalf("the host read %q after the poll, want %q", got, "hello")
	}

	write(t, wr, "hello")
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if got, rc := readWithin(t, w, m, fd, 2); rc != _wasiESUCCESS || got != "he" {
		t.Fatalf("non-blocking read = %q rc=%d", got, rc)
	}
	if got := hostRead(); got != "llo" {
		t.Fatalf("the host read %q after the guest's read, want %q", got, "llo")
	}
}

// udpPair returns a connected pair of UDP sockets, the first entered in the
// guest's table.
func udpPair(t *testing.T, w *WasiStubs) (fd int32, peer *net.UDPConn) {
	t.Helper()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err = net.DialUDP("udp", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	})
	// Datagrams larger than the host's default bound (9 KiB on darwin).
	if err := peer.SetWriteBuffer(1 << 16); err != nil {
		t.Fatal(err)
	}
	if err := local.SetReadBuffer(1 << 18); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	fd = addTestFD(w, &wasiOpen{conn: local})
	w.mu.Unlock()
	return fd, peer
}

// A datagram is one message to every read: one that a read takes a part of
// has its rest dropped, not left for the next read, and a read takes all of
// a large one, in as many buffers as it gives.
func TestWasi_DatagramsKeepTheirBoundaries(t *testing.T) {
	w, m := newProcTestStubs(t)
	fd, peer := udpPair(t, w)
	for _, d := range []string{"aaaa", "bb"} {
		if _, err := peer.Write([]byte(d)); err != nil {
			t.Fatal(err)
		}
	}
	writeSubFd(m, pollSubsOff, 7, 1, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, fd, 2); rc != _wasiESUCCESS || got != "aa" {
		t.Fatalf("read of a part of a datagram = %q rc=%d", got, rc)
	}
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "bb" {
		t.Fatalf("read after it = %q rc=%d, want the next datagram", got, rc)
	}

	large := strings.Repeat("d", 40000)
	if _, err := peer.Write([]byte(large)); err != nil {
		t.Fatal(err)
	}
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := fdReadv(t, w, newGuestModule(1<<17), fd, 4, 30000, 20000); rc != _wasiESUCCESS || got != large {
		t.Fatalf("read of a %d-byte datagram got %d bytes rc=%d", len(large), len(got), rc)
	}
}

// A read into several buffers returns once one has input, as readv(2) does
// on a stream: it does not wait for more to fill the next.
func TestWasi_ReadOfAStreamStopsAtTheInputThere(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "abcd"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadv(t, w, m, readFd, 4, 16); rc != _wasiESUCCESS || got != "abcd" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	if rc := fdWriteString(w, m, writeFd, "abcdef"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if got, rc := fdReadv(t, w, m, readFd, 4, 16); rc != _wasiESUCCESS || got != "abcdef" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

// poll(2) reports POLLERR on the write end of a pipe whose reader closes it
// while the poll waits (Linux reports it; darwin does not).
func TestWasi_PollNoticesTheReaderGoingWhileItWaits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("%s's poll(2) reports no error on a pipe whose reader is gone", runtime.GOOS)
	}
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	go func() {
		time.Sleep(50 * time.Millisecond)
		if rc := w.Fd_close(newForkTestModule(), readFd); rc != _wasiESUCCESS {
			t.Errorf("close of the read end rc=%d", rc)
		}
	}()
	writeSubClock(m, pollSubsOff, 1, int64(waitLimit/2))
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, writeFd)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if d := time.Since(start); d > waitLimit/4 {
		t.Fatalf("the reader's going was noticed after %v", d)
	}
	if errno := binary.LittleEndian.Uint16(m.memory[pollEvOff+8:]); errno != uint16(_wasiEPIPE) {
		t.Fatalf("the event has errno %d, want EPIPE", errno)
	}
}

// A listening socket is readable once a connection waits to be accepted.
func TestWasi_PollWaitsForAConnectionToAccept(t *testing.T) {
	w, m := newProcTestStubs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{listener: ln})
	w.mu.Unlock()
	t.Cleanup(func() {
		if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
			t.Errorf("close of the listener rc=%d", rc)
		}
	})
	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1, fd)
	start := time.Now()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("poll of a listener with no connection returned after %v", d)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	writeSubClock(m, pollSubsOff, 1, int64(waitLimit))
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
}

// A signal ends a read waiting on a descriptor that takes no deadline.
func TestSignal_InterruptsAReadOfAStreamThatTakesNoDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(t *testing.T) (r, w *os.File)
	}{
		{"pipe", blockingPipe},
		{"terminal", func(t *testing.T) (r, w *os.File) {
			master, slave := openTestPty(t)
			return slave, master
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, wr := tc.open(t)
			w, m := newSignalGuest(t, wasiSIGUSR1)
			w.cfg.Stdin = r
			postWhenBlocked(w, wasiSIGUSR1)
			if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiEINTR {
				t.Fatalf("interrupted read = %q rc=%d, want EINTR", got, rc)
			}
			takeSignals(t, w, m)
			write(t, wr, "x\n")
			if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "x\n" {
				t.Fatalf("read after the signal = %q rc=%d", got, rc)
			}
		})
	}
}

// A write to a descriptor that takes no deadline takes all it is given in
// one write(2); one that does not wait reports EAGAIN when there is no room.
func TestWasi_WriteToAStreamThatTakesNoDeadline(t *testing.T) {
	r, wr := blockingPipe(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdout = wr
	// Fill the pipe from the host's side.
	if err := syscall.SetNonblock(int(wr.Fd()), true); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := syscall.Write(int(wr.Fd()), make([]byte, 4096)); err == syscall.EAGAIN {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.SetNonblock(int(wr.Fd()), false); err != nil {
		t.Fatal(err)
	}
	if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if n, rc := writeChunk(t, w, m, 1); rc != _wasiEAGAIN || n != 0 {
		t.Fatalf("non-blocking write to a full pipe: %d bytes rc=%d, want EAGAIN", n, rc)
	}
	if rc := w.Fd_fdstat_set_flags(m, 1, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	go func() {
		buf := make([]byte, 1<<16)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	}()
	if n, rc := writeChunk(t, w, m, 1); rc != _wasiESUCCESS || n != uint32(wsChunk) {
		t.Fatalf("write with a reader: %d bytes rc=%d", n, rc)
	}
}

// A large write to a descriptor in blocking mode is written whole, in
// steps that do not wait in the kernel, however little room the pipe has
// at a time (a signal meanwhile ends it with what it wrote:
// TestWasi_AWriteToABlockingPipeTakesASignal).
func TestWasi_LargeWriteToABlockingPipeIsWrittenWhole(t *testing.T) {
	const size = 10 << 20
	r, wr := blockingPipe(t)
	w, _ := newProcTestStubs(t)
	m := newGuestModule(size + 4096)
	w.cfg.Stdout = wr
	drained := make(chan int64, 1)
	go func() {
		n, err := io.Copy(io.Discard, r)
		if err != nil {
			t.Error(err)
		}
		drained <- n
	}()
	makeIovec(m, 0, 4096, size)
	var rc int32
	returnsWithin(t, "Fd_write", func() { rc = w.Fd_write(m, 1, 0, 1, 16) })
	if n := readU32(m.memory, 16); rc != _wasiESUCCESS || n != size {
		t.Fatalf("write of %d bytes: %d rc=%d", size, n, rc)
	}
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}
	if n := <-drained; n != size {
		t.Fatalf("the reader got %d bytes", n)
	}
}

// fdIdentity is what a descriptor of the process refers to.
type fdIdentity struct{ dev, ino uint64 }

// openFDs returns the descriptors the process has open, each with what it
// refers to, so that newFDs counts the ones opened since. A count of them
// would not do: a file an earlier test left to its finalizer may be closed
// in between.
func openFDs(t *testing.T) map[int]fdIdentity {
	t.Helper()
	// The names only: os.ReadDir also stats an entry whose type darwin does
	// not report, which fails for a descriptor closed meanwhile.
	dir, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	names, err := dir.Readdirnames(-1)
	if err := errors.Join(err, dir.Close()); err != nil {
		t.Fatal(err)
	}
	fds := make(map[int]fdIdentity, len(names))
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			t.Fatal(err)
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			if errors.Is(err, syscall.EBADF) {
				// Closed since it was listed: the descriptor /dev/fd was read
				// through, or a file an earlier test left to its finalizer.
				continue
			}
			t.Fatal(err)
		}
		fds[fd] = fdIdentity{uint64(st.Dev), st.Ino}
	}
	return fds
}

// newFDs returns how many of the descriptors open now (openFDs) were not
// open before, or refer to another file than they did.
func newFDs(t *testing.T, before map[int]fdIdentity) int {
	t.Helper()
	n := 0
	for fd, id := range openFDs(t) {
		if was, ok := before[fd]; !ok || was != id {
			n++
		}
	}
	return n
}

// Polls waiting for many descriptors, one after another, open none of their
// own after the first has made the instance's wake pipe.
func TestWasi_PollOfManyPipesOpensNoDescriptors(t *testing.T) {
	w, m := newProcTestStubs(t)
	const pipes = 200
	reads := make([]int32, pipes)
	for i := range reads {
		reads[i], _ = newTestPipe(t, w, m)
	}
	poll := func(d time.Duration) {
		t.Helper()
		subs := newGuestModule(1 << 16)
		writeSubClock(subs, 0, 1, int64(d))
		for i, fd := range reads {
			writeSubFd(subs, int32(i+1)*48, uint64(i+2), 1, fd)
		}
		var rc int32
		returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(subs, 0, 20000, pipes+1, 30000) })
		if rc != _wasiESUCCESS {
			t.Fatalf("Poll_oneoff rc=%d", rc)
		}
	}
	poll(10 * time.Millisecond)
	before := openFDs(t)
	for range 3 {
		during := make(chan int, 1)
		go func() {
			time.Sleep(50 * time.Millisecond)
			during <- newFDs(t, before)
		}()
		poll(100 * time.Millisecond)
		if n := <-during; n != 0 {
			t.Fatalf("%d descriptors were opened while the poll waited", n)
		}
	}
	if n := newFDs(t, before); n != 0 {
		t.Fatalf("%d descriptors are open after the polls that were not before", n)
	}
}

// The buffers of one send to a datagram socket are one datagram.
func TestWasi_SendOfBuffersIsOneDatagram(t *testing.T) {
	w, m := newProcTestStubs(t)
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*net.UDPConn{rx, conn} {
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: conn})
	w.mu.Unlock()
	copy(m.memory[hostBufOff:], "abcd")
	makeIovec(m, hostIovOff, hostBufOff, 2)
	makeIovec(m, hostIovOff+8, hostBufOff+2, 2)
	if rc := w.Sock_send(m, fd, hostIovOff, 2, 0, hostCountOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_send rc=%d", rc)
	}
	if err := rx.SetReadDeadline(time.Now().Add(waitLimit)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := rx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "abcd" {
		t.Fatalf("the peer received %q, want one datagram %q", got, "abcd")
	}
}

// A FIFO opened by its name reports the end of its input once its writer
// has closed it.
func TestWasi_PollSeesTheEndOfAFIFO(t *testing.T) {
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
	write(t, wf, "x")
	if err := wf.Close(); err != nil {
		t.Fatal(err)
	}
	writeSubFd(m, pollSubsOff, 7, 1, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "" {
		t.Fatalf("read at the end = %q rc=%d, want zero bytes", got, rc)
	}
}

// A timeout longer than poll(2) takes in milliseconds (an int) is waited
// for: poll(2) is not handed a number that wraps to no wait at all.
func TestWasi_PollWaitsLongerThanAnIntOfMilliseconds(t *testing.T) {
	r, wr := blockingPipe(t)
	go func() {
		time.Sleep(200 * time.Millisecond)
		write(t, wr, "x")
	}()
	set := []hostPoll{{fd: int32(r.Fd()), events: hostPollIn}}
	start := time.Now()
	var n int
	var errno syscall.Errno
	returnsWithin(t, "poll", func() {
		for {
			// The Go runtime's own signals interrupt the call.
			if n, errno = hostPollCall(set, time.Duration(1<<32)*time.Millisecond); errno != syscall.EINTR {
				return
			}
		}
	})
	if errno != 0 || n != 1 {
		t.Fatalf("poll = %d, %v", n, errno)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("poll returned after %v, before the input", d)
	}
}

// A terminal whose master is closed is hung up on: polling it for input
// returns.
func TestWasi_PollReportsATerminalWhoseMasterIsClosed(t *testing.T) {
	master, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	if err := master.Close(); err != nil {
		t.Fatal(err)
	}
	writeSubClock(m, pollSubsOff, 1, int64(waitLimit/2))
	writeSubFd(m, pollSubsOff+48, 2, 1, 0)
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
}

// Asking whether a pipe whose reader is gone has room raises no SIGPIPE.
func TestWasi_PollForRoomRaisesNoSIGPIPE(t *testing.T) {
	skipWithoutStreamWrites(t)
	raised := make(chan os.Signal, 1)
	signal.Notify(raised, syscall.SIGPIPE)
	defer signal.Stop(raised)
	if err := syscall.Kill(os.Getpid(), syscall.SIGPIPE); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raised:
	case <-time.After(time.Second):
		t.Skip("SIGPIPE does not reach this process: it was started with SIGPIPE ignored")
	}
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
		t.Fatalf("close the read end rc=%d", rc)
	}
	if ok, rc := pollWritable(t, w, m, writeFd, 0); !ok || rc != _wasiESUCCESS {
		t.Fatalf("a pipe without a reader polled writable=%v rc=%d", ok, rc)
	}
	select {
	case sig := <-raised:
		t.Fatalf("the poll raised %v", sig)
	case <-time.After(100 * time.Millisecond):
	}
}

// A terminal open for reading only has no room for the guest, although
// poll(2) reports room in it.
func TestWasi_PollReportsNoRoomInATerminalOpenForReading(t *testing.T) {
	_, slave := openTestPty(t)
	fd, err := syscall.Open(slave.Name(), syscall.O_RDONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	readOnly := os.NewFile(uintptr(fd), slave.Name())
	closeAtEnd(t, readOnly)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = readOnly
	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 2 /* fd_write */, 0)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
}

// sock_send writes the stream as fd_write does: O_NONBLOCK makes it report
// EAGAIN when there is no room, and a failure that sent nothing is its
// errno.
func TestWasi_SendIsAWriteOfTheStream(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	ignoreSIGPIPE(t, w, m)
	local, remote := unixConnPair(t)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: local})
	w.mu.Unlock()
	if rc := w.Fd_fdstat_set_flags(m, fd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	send := func() (n uint32, rc int32) {
		makeIovec(m, wsIovOff, wsBufOff, wsChunk)
		returnsWithin(t, "Sock_send", func() { rc = w.Sock_send(m, fd, wsIovOff, 1, 0, wsCountOff) })
		return readU32(m.memory, int(wsCountOff)), rc
	}
	for i := 0; ; i++ {
		_, rc := send()
		if rc == _wasiEAGAIN {
			break
		}
		if rc != _wasiESUCCESS || i > 1<<12 {
			t.Fatalf("send %d rc=%d", i, rc)
		}
	}
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	if _, rc := send(); rc != _wasiEPIPE && rc != 15 /* ECONNRESET */ {
		t.Fatalf("send to a closed peer rc=%d, want EPIPE or ECONNRESET", rc)
	}
}

// unixConnPair returns the two ends of a connected AF_UNIX stream.
func unixConnPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]net.Conn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "socketpair")
		conn, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		conns[i] = conn
		t.Cleanup(func() {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		})
	}
	return conns[0], conns[1]
}

// A non-blocking read of a descriptor in blocking mode (a pipe, a socket
// a process inherits) reports EAGAIN when nothing is there, and takes what
// is.
func TestWasi_NonBlockingReadOfAStreamThatTakesNoDeadline(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	sockR, sockW := os.NewFile(uintptr(fds[0]), "socket"), os.NewFile(uintptr(fds[1]), "socket")
	closeAtEnd(t, sockR)
	closeAtEnd(t, sockW)
	pipeR, pipeW := blockingPipe(t)
	for _, tc := range []struct {
		name string
		r, w *os.File
	}{{"pipe", pipeR, pipeW}, {"socket", sockR, sockW}} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newProcTestStubs(t)
			w.cfg.Stdin = tc.r
			if rc := w.Fd_fdstat_set_flags(m, 0, wasiFdflagNonblock); rc != _wasiESUCCESS {
				t.Fatalf("set O_NONBLOCK rc=%d", rc)
			}
			if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiEAGAIN {
				t.Fatalf("read of nothing = %q rc=%d, want EAGAIN", got, rc)
			}
			write(t, tc.w, "x")
			if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "x" {
				t.Fatalf("read = %q rc=%d", got, rc)
			}
		})
	}
}

// A poll of a descriptor of the host's beside a stream that is not one
// waits for both: either ends the wait.
func TestWasi_PollWaitsForAHostPipeBesideAnotherStream(t *testing.T) {
	w, m := newProcTestStubs(t)
	local, remote := net.Pipe()
	for _, c := range []net.Conn{local, remote} {
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	w.cfg.Stdin = local
	readFd, writeFd := newTestPipe(t, w, m)
	writeSubFd(m, pollSubsOff, 1, 1, 0)
	writeSubFd(m, pollSubsOff+48, 2, 1, readFd)
	writeSoon(t, w, writeFd, "x")
	wantUserdata(t, pollUserdata(t, w, m, 2), 2)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read of the pipe = %q rc=%d", got, rc)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		if _, err := remote.Write([]byte("y")); err != nil {
			t.Error(err)
		}
	}()
	wantUserdata(t, pollUserdata(t, w, m, 2), 1)
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "y" {
		t.Fatalf("read of the other stream = %q rc=%d", got, rc)
	}
}

// addHostFile enters f, open for reading only, in the guest's table.
func addHostFile(w *WasiStubs, f *os.File) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return addTestFD(w, &wasiOpen{f: f, noWrite: true})
}

// waiter is a blocking call of the guest's: wait makes it and returns its
// errno, feed gives it what ends it without a signal.
type waiter struct {
	wait func() int32
	feed func()
}

// readWaiter is a read of fd by a thread of its own (signalWaiter), which
// feed feeds.
func readWaiter(t *testing.T, w *WasiStubs, fd int32, feed func()) waiter {
	m := signalWaiter(t, w)
	return waiter{
		wait: func() int32 {
			_, rc := fdReadString(w, m, fd, 16)
			return rc
		},
		feed: feed,
	}
}

// A signal ends one of the waits in progress of the threads that take it,
// each with a wake of its own: the other call of the instance's goes on
// waiting, whatever it waits in.
func TestSignal_EndsOneOfTheWaits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		waiters func(t *testing.T, w *WasiStubs) []waiter
	}{
		{"reads in poll(2)", func(t *testing.T, w *WasiStubs) []waiter {
			aR, aW := blockingPipe(t)
			bR, bW := blockingPipe(t)
			return []waiter{
				readWaiter(t, w, addHostFile(w, aR), func() { write(t, aW, "x") }),
				readWaiter(t, w, addHostFile(w, bR), func() { write(t, bW, "x") }),
			}
		}},
		{"reads with a deadline", func(t *testing.T, w *WasiStubs) []waiter {
			m := newForkTestModule()
			aR, aW := newTestPipe(t, w, m)
			bR, bW := newTestPipe(t, w, m)
			feed := func(fd int32) func() {
				return func() {
					if rc := fdWriteString(w, newForkTestModule(), fd, "x"); rc != _wasiESUCCESS {
						t.Errorf("write rc=%d", rc)
					}
				}
			}
			return []waiter{readWaiter(t, w, aR, feed(aW)), readWaiter(t, w, bR, feed(bW))}
		}},
		{"a poll and a read", func(t *testing.T, w *WasiStubs) []waiter {
			m := newForkTestModule()
			aR, aW := newTestPipe(t, w, m)
			bR, bW := newTestPipe(t, w, m)
			feed := func(fd int32) func() {
				return func() {
					if rc := fdWriteString(w, newForkTestModule(), fd, "x"); rc != _wasiESUCCESS {
						t.Errorf("write rc=%d", rc)
					}
				}
			}
			pm := signalWaiter(t, w)
			writeSubFd(pm, pollSubsOff, 7, 1, aR)
			return []waiter{
				{wait: func() int32 { return w.Poll_oneoff(pm, pollSubsOff, pollEvOff, 1, pollNevOff) }, feed: feed(aW)},
				readWaiter(t, w, bR, feed(bW)),
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newSignalGuest(t, wasiSIGUSR1)
			// The thread that registered first blocks the signal: it
			// goes to a thread that waits.
			setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, signalMask(wasiSIGUSR1))
			waiters := tc.waiters(t, w)
			results := make([]chan int32, len(waiters))
			for i, wt := range waiters {
				results[i] = make(chan int32, 1)
				go func() { results[i] <- wt.wait() }()
			}
			awaitBlockedCalls(w, 2)
			w.PostSignal(wasiSIGUSR1)
			var other int
			select {
			case rc := <-results[0]:
				if rc != _wasiEINTR {
					t.Fatalf("a call rc=%d, want EINTR", rc)
				}
				other = 1
			case rc := <-results[1]:
				if rc != _wasiEINTR {
					t.Fatalf("a call rc=%d, want EINTR", rc)
				}
				other = 0
			case <-time.After(waitLimit):
				t.Fatal("no call has returned after the signal")
			}
			awaitBlockedCalls(w, 1)
			waiters[other].feed()
			select {
			case rc := <-results[other]:
				if rc != _wasiESUCCESS {
					t.Fatalf("the other call rc=%d", rc)
				}
			case <-time.After(waitLimit):
				t.Fatal("the other call has not returned")
			}
		})
	}
}

// A signal that ends a guest which has not registered for signals ends a
// blocking call of its: the call is unwound (terminate), and leaves the
// stream as it found it — no turn held, no deadline set, no wake pipe kept.
func TestSignal_EndsTheBlockingCallsOfAnUnregisteredGuest(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(w *WasiStubs, fd int32)
	}{
		{"read", func(w *WasiStubs, fd int32) { fdReadString(w, newForkTestModule(), fd, 16) }},
		{"poll", func(w *WasiStubs, fd int32) {
			m := newForkTestModule()
			writeSubFd(m, pollSubsOff, 7, 1, fd)
			w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newProcTestStubs(t)
			readFd, writeFd := newTestPipe(t, w, m)
			child := w.Fork()
			t.Cleanup(func() {
				if err := child.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			before := openFDs(t)
			postWhenBlocked(w, wasiSIGKILL)
			var sigErr *WasiSignalError
			returnsWithin(t, tc.name, func() { sigErr = signalErrorOf(func() { tc.call(w, readFd) }) })
			if sigErr == nil || sigErr.Signal != wasiSIGKILL {
				t.Fatalf("the call ended with %v, want a WasiSignalError for SIGKILL", sigErr)
			}
			if tc.name == "poll" {
				// The wake pipe went back to the pool.
				if n := newFDs(t, before); n != 2 {
					t.Fatalf("%d descriptors are open that were not before the poll, want the wake pipe's 2", n)
				}
			}
			if rc := fdWriteString(child, newForkTestModule(), writeFd, "x"); rc != _wasiESUCCESS {
				t.Fatalf("write rc=%d", rc)
			}
			if got, rc := readWithin(t, child, newForkTestModule(), readFd, 16); rc != _wasiESUCCESS || got != "x" {
				t.Fatalf("the read after the guest ended = %q rc=%d", got, rc)
			}
		})
	}
}

// A connection the host closes while poll_oneoff waits for it closes at
// once.
func TestWasi_CloseOfAConnectionAPollWaitsFor(t *testing.T) {
	w, m := newProcTestStubs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	}()
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: conn})
	w.mu.Unlock()
	writeSubClock(m, pollSubsOff, 1, int64(2*time.Second))
	writeSubFd(m, pollSubsOff+48, 2, 1, fd)
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		w.Poll_oneoff(m, pollSubsOff, pollEvOff, 2, pollNevOff)
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close took %v while the poll waited", d)
	}
	<-polled
}

// A write that does not wait to a full descriptor in blocking mode takes no
// more than there is room for, without waiting: a pipe what the host
// reports room for (hostPipeWriteNow), or no more than PIPE_BUF once
// poll(2) reports room, a socket what it takes without waiting.
func TestWasi_NonBlockingWriteToAFullStreamThatTakesNoDeadline(t *testing.T) {
	const size = 64 << 10
	m := newGuestModule(size + 4096)
	makeIovec(m, 0, 4096, size)
	write64K := func(t *testing.T, w *WasiStubs) (n uint32, rc int32) {
		t.Helper()
		returnsWithin(t, "Fd_write", func() { rc = w.Fd_write(m, 1, 0, 1, 16) })
		return readU32(m.memory, 16), rc
	}
	t.Run("pipe", func(t *testing.T) {
		r, wr := blockingPipe(t)
		w, _ := newProcTestStubs(t)
		w.cfg.Stdout = wr
		fd := int(wr.Fd())
		if err := syscall.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := syscall.Write(fd, make([]byte, 4096)); err == syscall.EAGAIN {
				break
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if err := syscall.SetNonblock(fd, false); err != nil {
			t.Fatal(err)
		}
		// Some room, less than the write: what was read, and less than a
		// chunk of the fill besides.
		const room = 16<<10 + 4096
		if _, err := io.ReadFull(r, make([]byte, 16<<10)); err != nil {
			t.Fatal(err)
		}
		if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
			t.Fatalf("set O_NONBLOCK rc=%d", rc)
		}
		if n, rc := write64K(t, w); rc == _wasiESUCCESS && (n == 0 || n >= room) || rc != _wasiESUCCESS && rc != _wasiEAGAIN {
			t.Fatalf("write = %d bytes rc=%d", n, rc)
		}
	})
	t.Run("socket", func(t *testing.T) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		a, b := os.NewFile(uintptr(fds[0]), "socket"), os.NewFile(uintptr(fds[1]), "socket")
		closeAtEnd(t, a)
		closeAtEnd(t, b)
		w, _ := newProcTestStubs(t)
		w.cfg.Stdout = a
		if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
			t.Fatalf("set O_NONBLOCK rc=%d", rc)
		}
		for i := 0; ; i++ {
			n, rc := write64K(t, w)
			if rc == _wasiEAGAIN {
				break
			}
			if rc != _wasiESUCCESS || n == 0 || i > 1<<10 {
				t.Fatalf("write %d = %d bytes rc=%d", i, n, rc)
			}
		}
	})
}

// A datagram read without waiting from a socket in blocking mode fills the
// buffers it is given; a stream the runtime reads through its own Read is
// read once, into all of them.
func TestWasi_DatagramReadIntoSeveralBuffers(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "socket"), os.NewFile(uintptr(fds[1]), "socket")
	closeAtEnd(t, a)
	closeAtEnd(t, b)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = a
	if rc := w.Fd_fdstat_set_flags(m, 0, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	datagram := strings.Repeat("d", 1000)
	write(t, b, datagram)
	if got, rc := fdReadv(t, w, m, 0, 8, 1500); rc != _wasiESUCCESS || got != datagram {
		t.Fatalf("read of a datagram got %d bytes rc=%d, want %d", len(got), rc, len(datagram))
	}

	w, m = newProcTestStubs(t)
	w.cfg.Stdin = &endThenInput{steps: []string{"abcdef"}}
	if got, rc := fdReadv(t, w, m, 0, 2, 16); rc != _wasiESUCCESS || got != "abcdef" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "abcdef")
	}
}

// upperConn is a connection of the embedder's own over one of package net's:
// what it reads and writes is in capitals.
type upperConn struct{ *net.TCPConn }

func (c upperConn) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	copy(p, bytes.ToUpper(p[:n]))
	return n, err
}

func (c upperConn) Write(p []byte) (int, error) { return c.TCPConn.Write(bytes.ToUpper(p)) }

// A connection that wraps one of package net's is read and written through
// its own Read and Write.
func TestWasi_WrapperConnectionIsReadThroughItsRead(t *testing.T) {
	w, m := newProcTestStubs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{ln, conn, peer} {
		t.Cleanup(func() {
			if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		})
	}
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{conn: upperConn{conn.(*net.TCPConn)}})
	w.mu.Unlock()
	if _, err := peer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	writeSubFd(m, pollSubsOff, 7, 1, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "ABC" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "ABC")
	}
	if rc := fdWriteString(w, m, fd, "xyz"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if err := peer.SetReadDeadline(time.Now().Add(waitLimit)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "XYZ" {
		t.Fatalf("the peer received %q, want %q", got, "XYZ")
	}
}

// A read into a buffer larger than a call takes (darwin refuses more than
// INT_MAX bytes) is a short read, not a failure.
func TestWasi_ReadIntoAHugeBuffer(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("a 32-bit host has no 3 GiB of address space to give")
	}
	size := int64(3) << 30
	big, err := syscall.Mmap(-1, 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Skipf("no 3 GiB of address space: %v", err)
	}
	defer func() {
		if err := syscall.Munmap(big); err != nil {
			t.Error(err)
		}
	}()
	iov, _ := hostIovecs([][]byte{big[:1<<29], big[1<<29 : 2<<29], big[2<<29:]})
	total := 0
	for _, v := range iov {
		total += int(v.Len)
	}
	if total > math.MaxInt32 {
		t.Fatalf("the iovecs take %d bytes", total)
	}
	r, wr := blockingPipe(t)
	write(t, wr, "abc")
	n, again, err := readvRaw(r.Fd(), [][]byte{big})
	if err != nil || again || n != 3 || string(big[:3]) != "abc" {
		t.Fatalf("readv = %d, %v, %v", n, again, err)
	}
}

// One datagram takes no more buffers than one call does (EINVAL); a
// blocking write to a stream takes them all, in as many calls as it needs.
func TestWasi_SendOfMoreBuffersThanOneCallTakes(t *testing.T) {
	const iovOff, bufOff, count = 40000, 50000, 1025
	w, m := newProcTestStubs(t)
	for i := int32(0); i < count; i++ {
		makeIovec(m, iovOff+i*8, bufOff+i, 1)
	}
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	local, remote := unixConnPair(t)
	for _, c := range []io.Closer{rx, conn} {
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	w.mu.Lock()
	dgram, stream := addTestFD(w, &wasiOpen{conn: conn}), addTestFD(w, &wasiOpen{conn: local})
	w.mu.Unlock()
	if rc := w.Sock_send(m, dgram, iovOff, count, 0, hostCountOff); rc != _wasiEINVAL {
		t.Fatalf("send of a datagram in %d buffers rc=%d, want EINVAL", count, rc)
	}
	go func() {
		// It ends when the test closes the stream.
		if _, err := io.Copy(io.Discard, remote); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	if rc := w.Sock_send(m, stream, iovOff, count, 0, hostCountOff); rc != _wasiESUCCESS {
		t.Fatalf("send to a stream rc=%d", rc)
	}
	if n := readU32(m.memory, int(hostCountOff)); n != count {
		t.Fatalf("the stream took %d bytes, want %d", n, count)
	}
}

// What poll(2) reports of a descriptor it cannot ask about (POLLNVAL) is no
// failure of it: a subscription for its failure is ready on POLLERR or
// POLLHUP only.
func TestWasi_PollNvalIsNoFailure(t *testing.T) {
	const notOpen = 1 << 20 // beyond any descriptor the process has
	ready := []bool{false}
	if err := hostWaitReady([]uintptr{notOpen}, []int{hostWantFailure}, ready, nil, time.Now().Add(50*time.Millisecond), -1); err != nil {
		t.Fatal(err)
	}
	if ready[0] {
		t.Fatal("POLLNVAL made a subscription for failure ready")
	}
	if err := hostWaitReady([]uintptr{notOpen}, []int{hostWantInput}, ready, nil, time.Now(), -1); err != nil {
		t.Fatal(err)
	}
	if !ready[0] {
		t.Fatal("POLLNVAL did not make a subscription for input ready")
	}
}

// A write that does not wait to a datagram socket in blocking mode sends the
// datagram whole.
func TestWasi_NonBlockingWriteOfADatagramIsWhole(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "socket"), os.NewFile(uintptr(fds[1]), "socket")
	closeAtEnd(t, a)
	closeAtEnd(t, b)
	w, m := newProcTestStubs(t)
	w.cfg.Stdout = a
	if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	datagram := strings.Repeat("d", 1500)
	if rc := fdWriteString(w, m, 1, datagram); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	buf := make([]byte, 4096)
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(datagram) {
		t.Fatalf("the peer received a datagram of %d bytes, want %d", n, len(datagram))
	}
}

// A call that has to wait while the process has no descriptor left for its
// wake pipe reports EMFILE.
func TestWasi_WaitWithNoDescriptorLeftIsEMFILE(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, _ := newTestPipe(t, w, m)
	r, _ := blockingPipe(t)
	fd := addHostFile(w, r)
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	// The lowest number free now is the limit: no descriptor can be made.
	free, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(free); err != nil {
		t.Fatal(err)
	}
	low := limit
	low.Cur = uint64(free)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Skipf("the limit of descriptors cannot be lowered: %v", err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Error(err)
		}
	}()
	writeSubClock(m, pollSubsOff, 1, int64(60*time.Millisecond))
	writeSubFd(m, pollSubsOff+48, 2, 1, readFd)
	var rc int32
	returnsWithin(t, "Poll_oneoff", func() { rc = w.Poll_oneoff(m, pollSubsOff, pollEvOff, 2, pollNevOff) })
	if rc != _wasiEMFILE {
		t.Fatalf("poll rc=%d, want EMFILE", rc)
	}
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiEMFILE {
		t.Fatalf("read = %q rc=%d, want EMFILE", got, rc)
	}
}

// A stream the runtime reads through its own Read is read into no buffer of
// the size of the guest's.
func TestWasi_ReadIntoLargeBuffersAllocatesLittle(t *testing.T) {
	const size, reads = 8 << 20, 8
	w, _ := newProcTestStubs(t)
	m := newGuestModule(size + 1<<20)
	steps := make([]string, reads)
	for i := range steps {
		steps[i] = "abcdef"
	}
	w.cfg.Stdin = &endThenInput{steps: steps}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range reads {
		if got, rc := fdReadv(t, w, m, 0, 4, size); rc != _wasiESUCCESS || got != "abcdef" {
			t.Fatalf("read = %q rc=%d", got, rc)
		}
	}
	runtime.ReadMemStats(&after)
	// Allocations of other goroutines meanwhile count too: the bound is far
	// below the size of the guest's buffer, far above a read's own.
	if n := (after.TotalAlloc - before.TotalAlloc) / reads; n > 1<<20 {
		t.Fatalf("a read allocated %d bytes", n)
	}
}

// The guest closing a descriptor that poll_oneoff waits for ends the wait,
// and the event for it carries EBADF.
func TestWasi_CloseEndsAPollThatWaits(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	writeSubFd(m, pollSubsOff, 7, 1, readFd)
	polled := make(chan int32, 1)
	go func() { polled <- w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff) }()
	time.Sleep(50 * time.Millisecond)
	var rc int32
	returnsWithin(t, "Fd_close", func() { rc = w.Fd_close(newForkTestModule(), readFd) })
	if rc != _wasiESUCCESS {
		t.Fatalf("close rc=%d", rc)
	}
	select {
	case rc := <-polled:
		if rc != _wasiESUCCESS {
			t.Fatalf("poll rc=%d", rc)
		}
	case <-time.After(waitLimit):
		t.Fatal("the poll has not returned after its descriptor was closed")
	}
	if n := readU32(m.memory, int(pollNevOff)); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
	if ud, errno := readU64(m.memory, int(pollEvOff)), binary.LittleEndian.Uint16(m.memory[pollEvOff+8:]); ud != 7 || errno != uint16(_wasiEBADF) {
		t.Fatalf("event %d errno %d, want 7 with EBADF", ud, errno)
	}
}

// A write that does not wait to a terminal in blocking mode takes no more
// than PIPE_BUF once poll(2) reports room: it does not wait for the rest.
func TestWasi_NonBlockingWriteToATerminalIsShort(t *testing.T) {
	_, slave := openTestPty(t)
	w, _ := newProcTestStubs(t)
	m := newGuestModule(1 << 17)
	w.cfg.Stdout = slave
	if rc := w.Fd_fdstat_set_flags(m, 1, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	makeIovec(m, 0, 4096, 64<<10)
	var rc int32
	returnsWithin(t, "Fd_write", func() { rc = w.Fd_write(m, 1, 0, 1, 16) })
	if n := readU32(m.memory, 16); rc != _wasiEAGAIN && (rc != _wasiESUCCESS || n == 0 || n > hostPipeBuf) {
		t.Fatalf("write = %d bytes rc=%d", n, rc)
	}
}
