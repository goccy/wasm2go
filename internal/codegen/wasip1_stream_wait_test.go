//go:build darwin || linux

package codegen

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The waits of reads and writes of descriptors of the host's: each is a
// wait in poll(2) that a signal, a close or input a command left ends; a
// turn is held only around the attempts that could wait in the kernel, and
// by the writes that wait.

// entryOf returns the entry behind fd.
func entryOf(t *testing.T, w *WasiStubs, fd int32) *wasiOpen {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	if op == nil {
		t.Fatalf("fd %d is not open", fd)
	}
	return op
}

// openFileFlags returns the flags (F_GETFL) of the open file description
// of the host file behind fd.
func openFileFlags(t *testing.T, w *WasiStubs, fd int32) int {
	t.Helper()
	file, isFile := entryOf(t, w, fd).f.(*os.File)
	if !isFile {
		t.Fatalf("fd %d is no file of the host", fd)
	}
	var flags int
	if err := withHostDescriptor(file, func(d uintptr) error {
		var err error
		flags, err = descriptorFlags(int(d), syscall.F_GETFL)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return flags
}

// blockedOrDone reports whether w's guest blocked (awaitBlockedCalls)
// before done delivered a result, which it returns otherwise.
func blockedOrDone[T any](t *testing.T, w *WasiStubs, done <-chan T) (blocked bool, result T) {
	t.Helper()
	waiting := make(chan struct{})
	go func() {
		awaitBlockedCalls(w, 1)
		close(waiting)
	}()
	select {
	case result = <-done:
		return false, result
	case <-waiting:
		return true, result
	case <-time.After(waitLimit):
		t.Fatalf("the call neither blocked nor returned within %v", waitLimit)
	}
	return false, result
}

// within returns what done delivers, failing the test after waitLimit.
func within[T any](t *testing.T, what string, done <-chan T) T {
	t.Helper()
	select {
	case v := <-done:
		return v
	case <-time.After(waitLimit):
		t.Fatalf("%s has not returned after %v", what, waitLimit)
	}
	var zero T
	return zero
}

type readOutcome struct {
	got string
	rc  int32
}

// readAsync reads up to 16 bytes from fd on another goroutine, as the
// guest's thread m, which a signal reaches once it has registered.
func readAsync(w *WasiStubs, m *Module, fd int32) <-chan readOutcome {
	done := make(chan readOutcome, 1)
	go func() {
		got, rc := fdReadString(w, m, fd, 16)
		done <- readOutcome{got, rc}
	}()
	return done
}

// makeFIFO makes a FIFO named fifo in dir, or skips the test.
func makeFIFO(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFO: %v", err)
	}
	return path
}

// A FIFO opened without waiting keeps the open file description Linux gave
// it in non-blocking mode, whatever the guest's O_NONBLOCK says later: the
// Go runtime polls it, and its blocking read and write wait in poll(2),
// which a signal ends.
func TestWasi_AFIFOOpenedWithoutWaitingStaysNonBlockingOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Go runtime polls FIFOs on Linux only")
	}
	dir := t.TempDir()
	path := makeFIFO(t, dir)
	w, m := newSignalGuestIn(t, dir)
	closeAllAtCleanup(t, w)

	fd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<1, wasiFdflagNonblock)
	if errno != _wasiESUCCESS {
		t.Fatalf("open for reading errno=%d", errno)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, writer)
	if rc := w.Fd_fdstat_set_flags(m, fd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	if openFileFlags(t, w, fd)&syscall.O_NONBLOCK == 0 {
		t.Fatal("the FIFO's open file description is in blocking mode")
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiEINTR {
		t.Fatalf("blocking read of an empty FIFO = %q rc=%d, want EINTR", got, rc)
	}
	takeSignals(t, w, m)
	write(t, writer, "x")
	if got, rc := readWithin(t, w, m, fd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "x")
	}

	// The end for writing: a write into the full FIFO waits, and a signal
	// ends it.
	reader, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, reader)
	wfd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<6, wasiFdflagNonblock)
	if errno != _wasiESUCCESS {
		t.Fatalf("open for writing errno=%d", errno)
	}
	if openFileFlags(t, w, wfd)&syscall.O_NONBLOCK == 0 {
		t.Fatal("the FIFO's open file description for writing is in blocking mode")
	}
	if fillNonBlocking(t, w, m, wfd) == 0 {
		t.Fatal("nothing fitted into an empty FIFO")
	}
	if rc := w.Fd_fdstat_set_flags(m, wfd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if n, rc := writeChunk(t, w, m, wfd); rc != _wasiEINTR || n != 0 {
		t.Fatalf("blocking write into a full FIFO: %d bytes rc=%d, want EINTR", n, rc)
	}
	takeSignals(t, w, m)
}

// On darwin the Go runtime does not poll a FIFO: one opened without
// waiting is put in blocking mode, so that its reads wait for input and
// end with the end of it, the close of the last writer.
func TestWasi_AFIFOOpenedWithoutWaitingWaitsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the Go runtime polls FIFOs here")
	}
	dir := t.TempDir()
	path := makeFIFO(t, dir)
	w, m := newTestStubs(t, dir)
	closeAllAtCleanup(t, w)
	fd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<1, wasiFdflagNonblock)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	if openFileFlags(t, w, fd)&syscall.O_NONBLOCK != 0 {
		t.Fatal("the FIFO's open file description is in non-blocking mode")
	}
	if rc := w.Fd_fdstat_set_flags(m, fd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, writer)
	read := readAsync(w, newForkTestModule(), fd)
	write(t, writer, "x")
	if r := within(t, "fd_read", read); r.rc != _wasiESUCCESS || r.got != "x" {
		t.Fatalf("read = %q rc=%d, want %q", r.got, r.rc, "x")
	}
	read = readAsync(w, newForkTestModule(), fd)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if r := within(t, "fd_read", read); r.rc != _wasiESUCCESS || r.got != "" {
		t.Fatalf("read after the writer closed = %q rc=%d, want zero bytes", r.got, r.rc)
	}
}

// A write that does not wait takes what the stream has room for while a
// write that waits holds the turn at its output.
func TestWasi_AWriteThatDoesNotWaitTakesNoTurn(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	turn := entryOf(t, w, writeFd).outputTurn()
	turn <- struct{}{} // a write that waits for room holds it
	if rc := w.Fd_fdstat_set_flags(m, writeFd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	var rc int32
	returnsWithin(t, "fd_write", func() { rc = fdWriteString(w, m, writeFd, "x") })
	<-turn
	if rc != _wasiESUCCESS {
		t.Fatalf("write that does not wait beside a holder of the turn rc=%d, want success", rc)
	}
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
}

// A write that waits takes the turn at the stream's output before it
// writes anything, so that it does not run into the middle of another
// write that waits.
func TestWasi_AWriteThatWaitsTakesTheTurnFirst(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	turn := entryOf(t, w, writeFd).outputTurn()
	// A write that went through comes back as the wait is seen: the rounds
	// let the select see both.
	for round := 0; round < 20; round++ {
		turn <- struct{}{} // another write that waits is under way
		wrote := make(chan int32, 1)
		go func() { wrote <- fdWriteString(w, newForkTestModule(), writeFd, "late") }()
		if blocked, rc := blockedOrDone(t, w, wrote); !blocked {
			t.Fatalf("round %d: the write went through (rc=%d) while another held the turn", round, rc)
		}
		<-turn
		if rc := within(t, "fd_write", wrote); rc != _wasiESUCCESS {
			t.Fatalf("round %d: write rc=%d", round, rc)
		}
		if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "late" {
			t.Fatalf("round %d: read = %q rc=%d", round, got, rc)
		}
	}
}

// A write that waits to a descriptor that can wait in the kernel (an
// inherited pipe in blocking mode) takes the turn at its output first too:
// its one writev(2) does not run into another write's.
func TestWasi_AWriteThatCanBlockInTheKernelTakesTheTurnFirst(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, _ := newProcTestStubs(t)
	r, wr := blockingPipe(t)
	w.cfg.Stdout = wr
	turn := entryOf(t, w, 1).outputTurn()
	turn <- struct{}{} // another write that waits is under way
	wrote := make(chan int32, 1)
	go func() { wrote <- fdWriteString(w, newForkTestModule(), 1, "late") }()
	if blocked, rc := blockedOrDone(t, w, wrote); !blocked {
		t.Fatalf("the write went through (rc=%d) while another held the turn", rc)
	}
	<-turn
	if rc := within(t, "fd_write", wrote); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	buf := make([]byte, 16)
	if n, err := r.Read(buf); err != nil || string(buf[:n]) != "late" {
		t.Fatalf("the pipe got %q, %v", buf[:n], err)
	}
}

// A read and a write that wait for their turn at a stream closed meanwhile
// find it closed: EBADF, which is no failure of the runtime's.
func TestWasi_ACallWaitingForItsTurnAtAClosedStreamIsEBADF(t *testing.T) {
	w, m := newProcTestStubs(t)
	w.cfg.Errors = func(op string, err error) { t.Errorf("%s: %v", op, err) }
	readFd, writeFd := newTestPipe(t, w, m)
	t.Run("Read", func(t *testing.T) {
		turn := entryOf(t, w, readFd).inputTurn()
		turn <- struct{}{} // another reader is looking
		read := readAsync(w, newForkTestModule(), readFd)
		if blocked, res := blockedOrDone(t, w, read); !blocked {
			t.Fatalf("the read went through (%q rc=%d) while another reader held the turn", res.got, res.rc)
		}
		if rc := w.Fd_close(m, readFd); rc != _wasiESUCCESS {
			t.Fatalf("close rc=%d", rc)
		}
		<-turn
		if res := within(t, "fd_read", read); res.rc != _wasiEBADF {
			t.Fatalf("read = %q rc=%d, want EBADF", res.got, res.rc)
		}
	})
	t.Run("Write", func(t *testing.T) {
		skipWithoutStreamWrites(t)
		turn := entryOf(t, w, writeFd).outputTurn()
		turn <- struct{}{} // another write that waits is under way
		wrote := make(chan int32, 1)
		go func() { wrote <- fdWriteString(w, newForkTestModule(), writeFd, "x") }()
		if blocked, rc := blockedOrDone(t, w, wrote); !blocked {
			t.Fatalf("the write went through (rc=%d) while another held the turn", rc)
		}
		if rc := w.Fd_close(m, writeFd); rc != _wasiESUCCESS {
			t.Fatalf("close rc=%d", rc)
		}
		<-turn
		if rc := within(t, "fd_write", wrote); rc != _wasiEBADF {
			t.Fatalf("write rc=%d, want EBADF", rc)
		}
	})
}

// Two readers of one pipe wait together, one in the Go runtime's poller
// with the turn at the input and the other for the turn: input reaches
// one, and the other waits on, for its signal.
func TestWasi_TheReadersOfAPipeWaitTogether(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	instances, modules := sharedWaiters(t, w, 2)
	reads := make([]<-chan readOutcome, len(instances))
	for i, inst := range instances {
		reads[i] = readAsync(inst, modules[i], readFd)
		awaitBlockedCalls(inst, 1)
	}
	if rc := fdWriteString(w, m, writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	var first readOutcome
	other := -1
	select {
	case first = <-reads[0]:
		other = 1
	case first = <-reads[1]:
		other = 0
	case <-time.After(waitLimit):
		t.Fatal("no reader got the input")
	}
	if first.rc != _wasiESUCCESS || first.got != "x" {
		t.Fatalf("read = %q rc=%d", first.got, first.rc)
	}
	instances[other].PostSignal(wasiSIGTERM)
	if r := within(t, "the other read", reads[other]); r.rc != _wasiEINTR {
		t.Fatalf("the other read = %q rc=%d, want EINTR", r.got, r.rc)
	}
}

// A descriptor whose read can wait in the kernel (an inherited pipe in
// blocking mode) is read only by the holder of the turn at its input, once
// poll(2) has found input: two readers poll(2) woke together do not both
// read, which would leave one waiting in readv(2) where no signal reaches
// it.
func TestWasi_TheReadersOfADescriptorThatCanBlockTakeTurns(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	r, wr := blockingPipe(t)
	w.cfg.Stdin = r
	turn := entryOf(t, w, 0).inputTurn()
	turn <- struct{}{} // another reader is looking
	write(t, wr, "x")
	read := readAsync(w, m, 0)
	if blocked, res := blockedOrDone(t, w, read); !blocked {
		t.Fatalf("the read went through (%q rc=%d) while another reader held the turn", res.got, res.rc)
	}
	// The holder of the turn takes the input.
	if n, err := r.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("read of the holder = %d, %v", n, err)
	}
	<-turn
	// The read finds nothing and waits, which its signal ends.
	w.PostSignal(wasiSIGUSR1)
	if res := within(t, "fd_read", read); res.rc != _wasiEINTR {
		t.Fatalf("read = %q rc=%d, want EINTR", res.got, res.rc)
	}
}

// A read that does not wait of a descriptor that can wait in the kernel
// does not wait for the turn another reader holds either: EAGAIN.
func TestWasi_AReadThatDoesNotWaitTakesNoBusyTurn(t *testing.T) {
	w, m := newProcTestStubs(t)
	r, wr := blockingPipe(t)
	w.cfg.Stdin = r
	turn := entryOf(t, w, 0).inputTurn()
	turn <- struct{}{} // another reader is looking
	write(t, wr, "x")
	if rc := w.Fd_fdstat_set_flags(m, 0, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("set O_NONBLOCK rc=%d", rc)
	}
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiEAGAIN {
		t.Fatalf("read that does not wait beside a holder of the turn = %q rc=%d, want EAGAIN", got, rc)
	}
	<-turn
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read with the turn free = %q rc=%d, want %q", got, rc, "x")
	}
}

// A reader of a descriptor that can wait in the kernel, woken by input that
// a sibling reads first, looks again before it reads: it waits on, and its
// signal ends the wait.
func TestWasi_AReaderWokenByInputASiblingTookLooksAgain(t *testing.T) {
	w, _ := newProcTestStubs(t)
	r, wr := blockingPipe(t)
	w.cfg.Stdin = r
	instances, modules := sharedWaiters(t, w, 1)
	woken := instances[0]
	// The reader waits in poll(2) for input.
	read := readAsync(woken, modules[0], 0)
	awaitBlockedCalls(woken, 1)
	op := entryOf(t, w, 0)
	turn := op.inputTurn()
	turn <- struct{}{} // the sibling holds the turn
	write(t, wr, "x")
	// The reader's wait has ended (its wake pipe is back in the pool) and
	// it waits for the turn.
	waits := func(pooled int) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				woken.mu.Lock()
				n := len(woken.wakes)
				woken.mu.Unlock()
				woken.sig.mu.Lock()
				blocked := blockedCallsLocked(woken)
				woken.sig.mu.Unlock()
				if n == pooled && blocked == 1 {
					return
				}
				runtime.Gosched()
			}
		}()
		return done
	}
	within(t, "the reader's wait for the turn", waits(1))
	// The sibling reads the input and gives the turn back.
	buf := make([]byte, 16)
	if n, rc := w.readNow("fd_read", op, r, [][]byte{buf}); rc != _wasiESUCCESS || string(buf[:n]) != "x" {
		t.Fatalf("the sibling's read = %q rc=%d, want %q", buf[:n], rc, "x")
	}
	<-turn
	// The reader looks, finds nothing and waits in poll(2) again (it has
	// taken its wake pipe out of the pool), instead of reading.
	within(t, "the reader's second wait", waits(0))
	woken.PostSignal(wasiSIGTERM)
	if res := within(t, "the woken read", read); res.rc != _wasiEINTR {
		t.Fatalf("the woken read = %q rc=%d, want EINTR", res.got, res.rc)
	}
}

// Input a command left of a descriptor (giveAhead) ends the waits for its
// input: a read, a poll, a receive.
func TestWasi_InputACommandLeftEndsTheWaits(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	op := entryOf(t, w, readFd)

	read := readAsync(w, newForkTestModule(), readFd)
	awaitBlockedCalls(w, 1)
	if err := op.giveAhead([]byte("left")); err != nil {
		t.Fatal(err)
	}
	if r := within(t, "fd_read", read); r.rc != _wasiESUCCESS || r.got != "left" {
		t.Fatalf("read = %q rc=%d, want %q", r.got, r.rc, "left")
	}

	pm := newForkTestModule()
	writeSubFd(pm, pollSubsOff, 7, 1 /* fd_read */, readFd)
	polled := make(chan int32, 1)
	go func() { polled <- w.Poll_oneoff(pm, pollSubsOff, pollEvOff, 1, pollNevOff) }()
	awaitBlockedCalls(w, 1)
	if err := op.giveAhead([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if rc := within(t, "poll_oneoff", polled); rc != _wasiESUCCESS {
		t.Fatalf("Poll_oneoff rc=%d", rc)
	}
	if n, ud, nbytes := readU32(pm.memory, int(pollNevOff)), readU64(pm.memory, int(pollEvOff)), readU64(pm.memory, int(pollEvOff)+16); n != 1 || ud != 7 || nbytes != 4 {
		t.Fatalf("poll reported %d events, userdata %d, nbytes %d; want the read with 4 bytes", n, ud, nbytes)
	}
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiESUCCESS || got != "more" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}

	sw, sm, _ := newSocketStubs(t)
	if rc := sw.Sock_socketpair(sm, wasiSockFamilyUnix, wasiSockTypeStream, sockFdsOff); rc != _wasiESUCCESS {
		t.Fatalf("Sock_socketpair rc=%d", rc)
	}
	b := int32(readU32(sm.memory, int(sockFdsOff)+4))
	received := make(chan readOutcome, 1)
	go func() {
		got, rc := sockRecv(sw, sm, b)
		received <- readOutcome{got, rc}
	}()
	awaitBlockedCalls(sw, 1)
	if err := entryOf(t, sw, b).giveAhead([]byte("left")); err != nil {
		t.Fatal(err)
	}
	if r := within(t, "sock_recv", received); r.rc != _wasiESUCCESS || r.got != "left" {
		t.Fatalf("recv = %q rc=%d, want %q", r.got, r.rc, "left")
	}
}

// replacingConn is a stream of the embedder's whose descriptor number the
// embedder gives another file (dup2) right after the runtime has borrowed
// it the first time.
type replacingConn struct {
	f       *os.File
	replace func()
	once    sync.Once
}

func (c *replacingConn) SyscallConn() (syscall.RawConn, error) {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	return replacingRawConn{RawConn: rc, c: c}, nil
}

type replacingRawConn struct {
	syscall.RawConn
	c *replacingConn
}

func (rc replacingRawConn) Control(f func(fd uintptr)) error {
	err := rc.RawConn.Control(f)
	rc.c.once.Do(rc.c.replace)
	return err
}

// A stream of the embedder's is waited for on a duplicate of its
// descriptor: a number the embedder gives another file meanwhile does not
// make the wait ask about that file.
func TestWasi_AStreamOfTheEmbeddersIsWaitedForOnADuplicate(t *testing.T) {
	var old, other [2]int
	for _, p := range []*[2]int{&old, &other} {
		if err := syscall.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
	}
	oldR := os.NewFile(uintptr(old[0]), "old")
	closeAtEnd(t, oldR)
	for _, fd := range []int{old[1], other[0], other[1]} {
		t.Cleanup(func() {
			if err := hostCloseFD(fd); err != nil {
				t.Error(err)
			}
		})
	}
	// The file that gets the number has input; the stream does not.
	if _, err := syscall.Write(other[1], []byte("x")); err != nil {
		t.Fatal(err)
	}
	conn := &replacingConn{f: oldR, replace: func() {
		if err := dupTo(other[0], old[0]); err != nil {
			t.Error(err)
		}
	}}
	wakeR, wakeW, err := hostWakePipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(hostCloseFD(wakeR), hostCloseFD(wakeW)); err != nil {
			t.Error(err)
		}
	})
	if err := hostWakeWrite(wakeW); err != nil {
		t.Fatal(err)
	}
	set := []hostWaitFD{{stream: conn, want: hostWantInput, op: &wasiOpen{stdio: 1}}}
	returnsWithin(t, "the wait", func() { err = waitHostReady(set, time.Time{}, &wasiWake{r: wakeR, w: wakeW}) })
	if err != nil {
		t.Fatal(err)
	}
	if set[0].ready {
		t.Fatal("the wait for the embedder's stream found the input of the file that got its number")
	}
}

// A write that waits and is ended by a signal after it wrote something
// reports the count, and the next call that waits reports the signal.
func TestWasi_AnInterruptedWriteReportsWhatItWrote(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, writeFd := newTestPipe(t, w, m)
	fillNonBlocking(t, w, m, writeFd)
	if rc := w.Fd_fdstat_set_flags(m, writeFd, 0); rc != _wasiESUCCESS {
		t.Fatalf("clear O_NONBLOCK rc=%d", rc)
	}
	// Room for part of the next write.
	if got, rc := readWithin(t, w, newForkTestModule(), readFd, 4096); rc != _wasiESUCCESS || len(got) == 0 {
		t.Fatalf("read to make room = %d bytes rc=%d", len(got), rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if n, rc := writeChunk(t, w, m, writeFd); rc != _wasiESUCCESS || n == 0 || n >= uint32(wsChunk) {
		t.Fatalf("interrupted write: %d bytes rc=%d, want part of %d", n, rc, wsChunk)
	}
	if rc := sleepPoll(t, w, m, time.Hour); rc != _wasiEINTR {
		t.Fatalf("the next call that waits rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
}

// A command given an entry's open file description itself shares it: the
// entry is no longer waited for in the Go runtime's poller.
func TestWasi_ACommandSharingADescriptionMarksTheEntry(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, _ := newTestPipe(t, w, m)
	op := entryOf(t, w, readFd)
	f := op.f.(*os.File)
	if !w.netpolled(op, f) {
		t.Fatal("the read end of a pipe of the runtime's is not waited for in the Go runtime's poller")
	}
	// The guest's O_NONBLOCK is the description's: the command gets it.
	var c commandSetup
	if err := c.add(0, &commandStream{host: f, nonblock: true, op: op}, nil, func(err error) {
		if err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if c.conns[0] != syscall.Conn(f) {
		t.Fatalf("the command's stdin is %v, want the entry's file", c.conns[0])
	}
	if w.netpolled(op, f) {
		t.Fatal("an entry whose description a command shares is still waited for in the Go runtime's poller")
	}
}

// The read of an entry whose description a command shares asks the
// description's mode at every attempt: one the command put in blocking
// mode is waited for in poll(2), which a signal ends.
func TestWasi_ASharedDescriptionPutInBlockingModeTakesASignal(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	readFd, _ := newTestPipe(t, w, m)
	op := entryOf(t, w, readFd)
	op.shared.Store(true)
	if err := setHostNonblock(op.f, false); err != nil {
		t.Fatal(err)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if got, rc := readWithin(t, w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("read = %q rc=%d, want EINTR", got, rc)
	}
	takeSignals(t, w, m)
}

// A standard stream of the embedder's that the Go runtime polls is waited
// for in its poller, with a deadline on the embedder's file, whoever else
// holds it: a signal ends the wait, and the deadline does not outlive it.
func TestWasi_AnEmbeddersPolledStreamWaitsInTheGoRuntimesPoller(t *testing.T) {
	w, m := newSignalGuest(t, wasiSIGUSR1)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r)
	closeAtEnd(t, wr)
	w.cfg.Stdin = r
	op := entryOf(t, w, 0)
	op.shared.Store(true) // given to a command as well
	if !w.netpolled(op, r) {
		t.Fatal("the embedder's pipe is not waited for in the Go runtime's poller")
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if got, rc := readWithin(t, w, m, 0, 16); rc != _wasiEINTR {
		t.Fatalf("read = %q rc=%d, want EINTR", got, rc)
	}
	takeSignals(t, w, m)
	read := readAsync(w, newForkTestModule(), 0)
	awaitBlockedCalls(w, 1)
	write(t, wr, "x")
	if res := within(t, "fd_read", read); res.rc != _wasiESUCCESS || res.got != "x" {
		t.Fatalf("read = %q rc=%d, want %q", res.got, res.rc, "x")
	}
}

// A write that waits to a pipe in blocking mode (one the process
// inherited) is made in steps that do not wait in the kernel
// (writesInSteps): a signal ends its wait for room, with EINTR when it
// wrote nothing and the count otherwise.
func TestWasi_AWriteToABlockingPipeTakesASignal(t *testing.T) {
	skipWithoutStreamWrites(t)
	w, m := newSignalGuest(t, wasiSIGUSR1)
	r, wr := blockingPipe(t)
	w.cfg.Stdout = wr
	fillBlockingPipe(t, wr)
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := fdWriteString(w, m, 1, "x"); rc != _wasiEINTR {
		t.Fatalf("write to a full blocking pipe with a signal rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
	if _, err := r.Read(make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if n, rc := writeChunk(t, w, m, 1); rc != _wasiESUCCESS || n == 0 || n >= uint32(wsChunk) {
		t.Fatalf("interrupted write: %d bytes rc=%d, want part of %d", n, rc, wsChunk)
	}
	if rc := sleepPoll(t, w, m, time.Hour); rc != _wasiEINTR {
		t.Fatalf("the next call that waits rc=%d, want EINTR", rc)
	}
	takeSignals(t, w, m)
}

// A write that does not wait to a pipe in blocking mode takes nothing from
// a full pipe, from one with room the room the host has, more than
// PIPE_BUF, in one call, and fails once the reader is gone
// (hostPipeWriteNow).
func TestHostPipeWriteNowTakesTheRoom(t *testing.T) {
	r, wr := blockingPipe(t)
	fillBlockingPipe(t, wr)
	rc, err := wr.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	write := func(size int) (int, bool) {
		t.Helper()
		var n int
		var again, done bool
		var writeErr error
		if err := rc.Control(func(fd uintptr) {
			n, again, done, writeErr = hostPipeWriteNow(fd, [][]byte{make([]byte, size)})
		}); err != nil || writeErr != nil {
			t.Fatal(err, writeErr)
		}
		if !done {
			if hostTellsPipeRoom() {
				t.Fatal("the host tells the room in a pipe, and the write did not use it")
			}
			t.Skip("the host does not tell the room in a pipe")
		}
		return n, again
	}
	if n, again := write(1); !again || n != 0 {
		t.Fatalf("write to a full pipe = %d, again %v; want nothing, again", n, again)
	}
	if _, err := io.ReadFull(r, make([]byte, 4*hostPipeBuf)); err != nil {
		t.Fatal(err)
	}
	if n, again := write(1 << 20); again || n <= hostPipeBuf {
		t.Fatalf("write to a pipe with room = %d, again %v; want more than PIPE_BUF (%d)", n, again, hostPipeBuf)
	}
	// a full pipe whose reader is gone fails the write at once
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	var writeErr error
	if err := rc.Control(func(fd uintptr) {
		_, _, _, writeErr = hostPipeWriteNow(fd, [][]byte{make([]byte, 1)})
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(writeErr, syscall.EPIPE) {
		t.Fatalf("write to a pipe without a reader: %v, want EPIPE", writeErr)
	}
}

// fillBlockingPipe fills the pipe whose write end in blocking mode is wr,
// in non-blocking mode for the fill only.
func fillBlockingPipe(t *testing.T, wr *os.File) {
	t.Helper()
	rc, err := wr.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fillErr error
	if err := rc.Control(func(fd uintptr) {
		if fillErr = syscall.SetNonblock(int(fd), true); fillErr != nil {
			return
		}
		for {
			if _, err := syscall.Write(int(fd), []byte{0}); err != nil {
				if !errors.Is(err, syscall.EAGAIN) {
					fillErr = err
				}
				break
			}
		}
		fillErr = errors.Join(fillErr, syscall.SetNonblock(int(fd), false))
	}); err != nil || fillErr != nil {
		t.Fatal(err, fillErr)
	}
}

// The reader of a descriptor whose open file description is put in
// non-blocking mode after a Read is asked for keeps nothing of the EAGAIN
// the Read finds: it is no input and no end.
func TestStreamReaderKeepsNoEAGAIN(t *testing.T) {
	fds := make([]int, 2)
	if err := syscall.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	// Made in blocking mode, the file is one the Go runtime does not poll.
	in, out := os.NewFile(uintptr(fds[0]), "in"), os.NewFile(uintptr(fds[1]), "out")
	closeAtEnd(t, in)
	closeAtEnd(t, out)
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	r := newStreamReader(in, func(err error) {
		if err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(r.stop)
	wk := newChannelWake()
	r.addWaiter(wk)
	r.request()
	within(t, "the reader's Read", wk.ch)
	if n, err, ok := r.take([][]byte{make([]byte, 4)}); ok {
		t.Fatalf("the reader keeps %d bytes, %v", n, err)
	}
}

// A poll of a FIFO read through its reader ends with input the reader
// does not take: its Read asked for by the poll ended with nothing, as one
// does when the description is put in non-blocking mode meanwhile.
func TestWasi_PollOfAFIFOWhoseReadEndedWithNothing(t *testing.T) {
	if hostPollReportsFIFOEnd {
		t.Skip("a FIFO is waited for in poll(2) here")
	}
	dir := t.TempDir()
	path := makeFIFO(t, dir)
	w, m := newTestStubs(t, dir)
	closeAllAtCleanup(t, w)
	fd, errno := w.pathOpen(m, "fifo", 0, 0, 1<<1, wasiFdflagNonblock)
	if errno != _wasiESUCCESS {
		t.Fatalf("open errno=%d", errno)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, writer)
	// A reader whose goroutine is taken as started: the Read the poll asks
	// for is the test's to end.
	op := entryOf(t, w, fd)
	r := newStreamReader(op.f.(*os.File), func(err error) {
		if err != nil {
			t.Error(err)
		}
	})
	r.started = true
	op.mu.Lock()
	op.reader = r
	op.mu.Unlock()
	written := make(chan error, 1)
	whenBlocked(w, func() {
		r.mu.Lock()
		r.reading = false
		err := r.wakeLocked()
		r.mu.Unlock()
		_, werr := writer.WriteString("q")
		written <- errors.Join(err, werr)
	})
	writeSubFd(m, pollSubsOff, 7, 1, fd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 7)
	if err := within(t, "the write", written); err != nil {
		t.Fatal(err)
	}
}
