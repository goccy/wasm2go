//go:build darwin || linux

package codegen

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// newSignalGuestIn returns host state whose FS is HostFS(dir), with a guest
// that has registered for signals and handles SIGUSR1.
func newSignalGuestIn(t *testing.T, dir string) (*WasiStubs, *Module) {
	t.Helper()
	w, m := newTestStubs(t, dir)
	if rc := w.Proc_signal_register(m, sigFlagOff); rc != 0 {
		t.Fatalf("Proc_signal_register rc=%d", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
	return w, m
}

func TestPathMkfifoOnTheHost(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	name, nameLen := putPath(m, 900, "q")
	if rc := w.Path_mkfifo(m, name, nameLen, 0o600); rc != -_wasiENOSYS {
		t.Fatalf("Path_mkfifo under a HostFS root rc=%d, want -ENOSYS", rc)
	}
	w.cfg.FS = osFS{}
	path, pathLen := putPath(m, 1000, hostRelative(t, filepath.Join(dir, "queue")))
	if rc := w.Path_mkfifo(m, path, pathLen, 0o600); rc != _wasiESUCCESS {
		t.Fatalf("Path_mkfifo rc=%d", rc)
	}
	fi, err := os.Stat(filepath.Join(dir, "queue"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("made %v, want a FIFO of mode 600", fi.Mode())
	}
	if rc := w.Path_mkfifo(m, path, pathLen, 0o600); rc != -_wasiEEXIST {
		t.Fatalf("a second FIFO of the name rc=%d, want -EEXIST", rc)
	}
}

// An open of one end of a FIFO waits for the other; one that a signal
// interrupts leaves no end of the FIFO open behind, so the next open of
// the other end waits for a peer as the first did.
func TestOpenOfAFIFO(t *testing.T) {
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	fifo := filepath.Join(dir, "queue")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	path, pathLen := putPath(m, 1000, "queue")
	const rightsRead, rightsWrite, fdOut = 1 << 1, 1 << 6, 200
	for round := 0; round < 5; round++ {
		postWhenBlocked(w, wasiSIGUSR1)
		if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsRead, 0, 0, fdOut); rc != _wasiEINTR {
			t.Fatalf("round %d: open for reading rc=%d, want EINTR", round, rc)
		}
		takeSignals(t, w, m)
		// No reader is left: a writer that does not wait is refused.
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			t.Fatalf("round %d: the FIFO still has a reader after the interrupted open for reading (close: %v)", round, f.Close())
		} else if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("round %d: open for writing without waiting: %v, want ENXIO", round, err)
		}

		postWhenBlocked(w, wasiSIGUSR1)
		if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsWrite, 0, 0, fdOut); rc != _wasiEINTR {
			t.Fatalf("round %d: open for writing rc=%d, want EINTR", round, rc)
		}
		takeSignals(t, w, m)
		// No writer is left: a reader finds the end of input.
		reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, readErr := syscall.Read(int(reader.Fd()), make([]byte, 1))
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if n != 0 || readErr != nil {
			t.Fatalf("round %d: read after the interrupted open for writing = %d, %v: the FIFO still has a writer", round, n, readErr)
		}
	}
	w.mu.Lock()
	open := len(w.fdsLocked())
	w.mu.Unlock()
	if open != 3 {
		t.Fatalf("%d descriptors are open after the interrupted opens, want the standard three", open)
	}

	// With a peer the open is done.
	peer := whenBlocked(w, func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := f.WriteString("x"); err != nil {
			t.Error(err)
		}
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsRead, 0, 0, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("open for reading with a writer rc=%d", rc)
	}
	<-peer
	if got, rc := fdReadString(w, m, int32(readU32(m.memory, fdOut)), 4); rc != _wasiESUCCESS || got != "x" {
		t.Fatalf("read = %q rc=%d", got, rc)
	}
	// An open for reading and writing does not wait.
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsRead|rightsWrite, 0, 0, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("open for reading and writing rc=%d", rc)
	}
}

// When the other end cannot be opened to make an interrupted open return,
// the open is left to return when someone opens the FIFO, and what it
// opened is closed then.
func TestOpenOfAFIFOThatCannotBeUnblocked(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the superuser opens a FIFO of mode 200 for reading")
	}
	dir := t.TempDir()
	w, m := newSignalGuestIn(t, dir)
	fifo := filepath.Join(dir, "queue")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	path, pathLen := putPath(m, 1000, "queue")
	// The open for writing waits; then the FIFO can no longer be opened
	// for reading and writing.
	whenBlocked(w, func() {
		if err := os.Chmod(fifo, 0o200); err != nil {
			t.Error(err)
		}
		w.PostSignal(wasiSIGUSR1)
	})
	var told []string
	w.cfg.Errors = func(op string, err error) { told = append(told, op) }
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, 1<<6, 0, 0, 200); rc != _wasiEINTR {
		t.Fatalf("open for writing rc=%d, want EINTR", rc)
	}
	if len(told) != 1 || told[0] != "path_open" {
		t.Fatalf("Errors was told %q, want the failed open of path_open", told)
	}
	if err := os.Chmod(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// A reader lets the open return; its end is closed, so the reader
	// finds the end of input once it is.
	reader, err := os.OpenFile(fifo, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, reader)
	if n, err := reader.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("read = %d, %v; want the end of input", n, err)
	}
}

// When the name of a FIFO whose open waits names another file than the one
// the open was asked for (the name was given to another file meanwhile),
// the open is not made to return through it: the guest is told EINTR at
// once, and Errors why. The open is left to return when someone opens the
// FIFO it waits for.
func TestOpenOfAFIFOWhoseNameMoved(t *testing.T) {
	dir := t.TempDir()
	w, _ := newSignalGuestIn(t, dir)
	fifo := filepath.Join(dir, "queue")
	other := filepath.Join(dir, "other")
	for _, name := range []string{fifo, other} {
		if err := syscall.Mkfifo(name, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The open is asked for the FIFO now called other, and finds the name
	// queue: the FIFO the open waits for is not the one at the name.
	asked, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	var told []string
	w.cfg.Errors = func(op string, err error) { told = append(told, op) }
	postWhenBlocked(w, wasiSIGUSR1)
	if _, errno := w.openFIFO(w.fs().OpenFile, "queue", asked, os.O_RDONLY, 0); errno != _wasiEINTR {
		t.Fatalf("open for reading errno=%d, want EINTR", errno)
	}
	if len(told) != 1 || told[0] != "path_open" {
		t.Fatalf("Errors was told %q, want the open of another file", told)
	}
	// An end of queue that stays open until the test ends lets the waiting
	// open return, whenever it gets as far as opening; what it opened is
	// closed then.
	end, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, end)
}

// A close of a descriptor does not wait for a flock of it that waits: the
// wait is made on a duplicate of the descriptor.
func TestCloseDuringAWaitingFlock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newSignalGuestIn(t, dir)
	holder := openTestFile(t, w, "lock")
	waiter := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, holder, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	closed := make(chan int32, 1)
	whenBlocked(w, func() { closed <- w.Fd_close(newForkTestModule(), waiter) })
	waited := make(chan int32, 1)
	go func() { waited <- w.Fd_flock(m, waiter, 2, 1) }()
	select {
	case rc := <-closed:
		if rc != _wasiESUCCESS {
			t.Fatalf("close during the wait rc=%d", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the close waited for the flock")
	}
	if rc := w.Fd_flock(newForkTestModule(), holder, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("unlock rc=%d", rc)
	}
	// The flock took its duplicate before the close, or found the
	// descriptor closed.
	if rc := <-waited; rc != _wasiESUCCESS && rc != -_wasiEBADF {
		t.Fatalf("the waiting flock rc=%d, want 0 or -EBADF", rc)
	}
}

// opendir of a FIFO is ENOTDIR at once, without waiting for a peer.
func TestOpenOfAFIFOAsADirectory(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := syscall.Mkfifo(filepath.Join(dir, "queue"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, pathLen := putPath(m, 1000, "queue")
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0x2 /* O_DIRECTORY */, 1<<1, 0, 0, 200); rc != _wasiENOTDIR {
		t.Fatalf("open of a FIFO as a directory rc=%d, want ENOTDIR", rc)
	}
}

// flock of a file of a HostFS root is the host's: it excludes an open of
// the file outside the instance.
func TestFlockOnTheHost(t *testing.T) {
	dir := t.TempDir()
	w, m := newProcTestStubs(t)
	w.cfg.FS = newHostFS(t, dir)
	p := filepath.Join(dir, "lock")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	exerciseFlock(t, w, m)
	outside, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, outside)
	fd := openTestFile(t, w, "lock")
	if rc := w.Fd_flock(m, fd, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("exclusive lock rc=%d", rc)
	}
	if err := flockOSFile(outside, flockShared|flockNonblock); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("outside lock while the instance holds it: %v, want EAGAIN", err)
	}
	if err := (rootFS{}).Flock(&memFile{}, flockShared); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("rootFS.Flock of a file not of the host: %v, want EBADF", err)
	}
	if err := (osFS{}).Flock(&memFile{}, flockShared); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("osFS.Flock of a file not of the host: %v, want EBADF", err)
	}

	// A standard stream that is a file of the host is locked on the host.
	out, err := os.Create(filepath.Join(dir, "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, out)
	w.cfg.Stdout = out
	if rc := w.Fd_flock(m, 1, 2, 0); rc != _wasiESUCCESS {
		t.Fatalf("lock of a file-backed stdout rc=%d", rc)
	}
	logFd := openTestFile(t, w, "out.log")
	if rc := w.Fd_flock(m, logFd, 1, 0); rc != -_wasiEAGAIN {
		t.Fatalf("lock of the file stdout is locked on rc=%d, want -EAGAIN", rc)
	}
}

// On Linux the record locks are the open file description's: two
// instances of one host process exclude each other, and closing another
// descriptor of the file keeps the lock. Elsewhere they are the process's.
func TestFdLockOfTwoInstancesOfAProcess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w1, m1 := newTestStubs(t, dir)
	w2, m2 := newTestStubs(t, dir)
	fd1, fd2 := openTestFile(t, w1, "f"), openTestFile(t, w2, "f")
	const lockOff = 200
	putRecordLock(m1, lockOff, 1)
	if rc := w1.Fd_lock(m1, fd1, recordLockSet, lockOff); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK of the first instance rc=%d", rc)
	}
	closeTestFd(t, w1, m1, openTestFile(t, w1, "f"))
	putRecordLock(m2, lockOff, 1)
	rc := w2.Fd_lock(m2, fd2, recordLockSet, lockOff)
	if runtime.GOOS == "linux" && rc != -_wasiEAGAIN {
		t.Fatalf("F_SETLK of the second instance rc=%d, want -EAGAIN", rc)
	}
	if runtime.GOOS != "linux" && rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK of the second instance rc=%d, want the process's own lock", rc)
	}
}

// The range of a lock to wait for is made one from the start of the file.
func TestAbsoluteRecordLock(t *testing.T) {
	w := &WasiStubs{}
	f, err := os.Create(filepath.Join(t.TempDir(), "f"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		whence int32
		start  int64
	}{{0, 1}, {1, 3}, {2, 7}} {
		lk := recordLock{typ: 1, whence: c.whence, start: 1, len: 1}
		if errno := w.absoluteRecordLock(f, &lk); errno != _wasiESUCCESS || lk.whence != 0 || lk.start != c.start {
			t.Fatalf("whence %d: errno %d lock %+v, want start %d from SEEK_SET", c.whence, errno, lk, c.start)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	lk := recordLock{whence: 1}
	if errno := w.absoluteRecordLock(f, &lk); errno != _wasiEBADF {
		t.Fatalf("SEEK_CUR of a closed file errno %d, want EBADF", errno)
	}
	lk = recordLock{whence: 2}
	if errno := w.absoluteRecordLock(f, &lk); errno != _wasiEBADF {
		t.Fatalf("SEEK_END of a closed file errno %d, want EBADF", errno)
	}
}

// A FIFO opened with O_NONBLOCK is opened without waiting for the other
// end: for reading at once, for writing refused with ENXIO while nobody
// reads.
func TestOpenOfAFIFOWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := syscall.Mkfifo(filepath.Join(dir, "queue"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, pathLen := putPath(m, 1000, "queue")
	const rightsRead, rightsWrite, nonblock, fdOut = 1 << 1, 1 << 6, 0x4, 200
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsWrite, 0, nonblock, fdOut); rc != _wasiENXIO {
		t.Fatalf("open for writing without waiting, nobody reading: rc=%d, want ENXIO", rc)
	}
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsRead, 0, nonblock, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("open for reading without waiting rc=%d", rc)
	}
	if rc := w.Path_open(m, 3, 1, path, pathLen, 0, rightsWrite, 0, nonblock, fdOut); rc != _wasiESUCCESS {
		t.Fatalf("open for writing without waiting, somebody reading: rc=%d", rc)
	}
	// The host's descriptor waits: the guest's NONBLOCK is its fdflags.
	w.mu.Lock()
	op := w.openLocked(int32(readU32(m.memory, fdOut)))
	w.mu.Unlock()
	if err := withHostDescriptor(op.f.(*os.File), func(fd uintptr) error {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if errno != 0 {
			return errno
		}
		if flags&syscall.O_NONBLOCK != 0 {
			return errors.New("the host descriptor is O_NONBLOCK")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := setHostNonblock(&memFile{}, false); err != nil {
		t.Fatalf("setHostNonblock of a file not of the host: %v", err)
	}
}

// putRecordLock writes a recordLock of the whole file at off.
func putRecordLock(m *Module, off int, typ int32) {
	clear(m.memory[off : off+32])
	binary.LittleEndian.PutUint32(m.memory[off:], uint32(typ))
}

// lockHolder runs as a process of its own (TestMain's helper) that takes a
// write lock of the whole file at the path in WASM2GO_LOCK_FILE, says so
// on its stdout, and holds it until its stdin ends.
func lockHolder(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	lk := recordLock{typ: 1}
	if err := hostRecordLock(f, recordLockSet, &lk); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := os.Stdin.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// fd_lock takes record locks of the host: F_GETLK reports none in the way
// of this process's own lock and the lock of another process that is;
// F_SETLKW waits for that one until a signal ends the wait, and the lock
// it takes later is removed before the descriptor takes one again.
func TestFdLockTakesRecordLocks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newSignalGuestIn(t, dir)
	fd := openTestFile(t, w, "f")
	const lockOff = 200
	putRecordLock(m, lockOff, 1)
	if rc := w.Fd_lock(m, fd, recordLockSet, lockOff); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK write lock rc=%d", rc)
	}
	if rc := w.Fd_lock(m, fd, recordLockGet, lockOff); rc != _wasiESUCCESS || readU32(m.memory, lockOff) != 2 {
		t.Fatalf("F_GETLK of this process's own lock rc=%d type %d, want F_UNLCK (2)", rc, readU32(m.memory, lockOff))
	}
	putRecordLock(m, lockOff, 2)
	if rc := w.Fd_lock(m, fd, recordLockWait, lockOff); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW unlock rc=%d", rc)
	}

	holder := exec.Command(os.Args[0], "-test.run=^$")
	holder.Env = append(os.Environ(), "WASM2GO_LOCK_FILE="+p)
	release, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	said, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := release.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
		if err := holder.Wait(); err != nil {
			t.Errorf("the lock holder: %v", err)
		}
	})
	if line, err := bufio.NewReader(said).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("the lock holder said %q, %v", line, err)
	}
	// The holder's lock is one of an open file description on Linux,
	// whose pid is -1, and one of its process elsewhere.
	wantPID := int32(holder.Process.Pid)
	if runtime.GOOS == "linux" {
		wantPID = -1
	}
	putRecordLock(m, lockOff, 0)
	if rc := w.Fd_lock(m, fd, recordLockGet, lockOff); rc != _wasiESUCCESS || readU32(m.memory, lockOff) != 1 || int32(readU32(m.memory, lockOff+24)) != wantPID {
		t.Fatalf("F_GETLK beside the holder rc=%d type %d pid %d, want F_WRLCK of %d", rc, readU32(m.memory, lockOff), int32(readU32(m.memory, lockOff+24)), wantPID)
	}
	putRecordLock(m, lockOff, 0)
	if rc := w.Fd_lock(m, fd, recordLockSet, lockOff); rc != -_wasiEAGAIN && rc != -_wasiEACCES {
		t.Fatalf("F_SETLK beside the holder rc=%d, want -EAGAIN or -EACCES", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := w.Fd_lock(m, fd, recordLockWait, lockOff); rc != -_wasiEINTR {
		t.Fatalf("F_SETLKW beside the holder rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	if rc := w.Fd_lock(m, fd, recordLockSet, lockOff); rc != -_wasiEAGAIN {
		t.Fatalf("F_SETLK beside the interrupted F_SETLKW rc=%d, want -EAGAIN", rc)
	}
	released := whenBlocked(w, func() {
		if err := release.Close(); err != nil {
			t.Error(err)
		}
	})
	if rc := w.Fd_lock(m, fd, recordLockWait, lockOff); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW after the holder let go rc=%d", rc)
	}
	<-released
}

func TestMain(m *testing.M) {
	if path := os.Getenv("WASM2GO_LOCK_FILE"); path != "" {
		if err := lockHolder(path); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// On Linux the nice value of the host process is set for every thread it
// has, and read from its main thread.
func TestHostPriorityOfEveryThread(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel keeps a nice value for each thread on Linux")
	}
	p := HostProcessUmask(0o022)
	nice, err := p.Priority(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if nice >= 19 {
		t.Skipf("the nice value is %d already", nice)
	}
	if err := HostProcessChanges().SetPriority(0, 0, nice+1); err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := syscall.Getpriority(0, tid)
		if errors.Is(err, syscall.ESRCH) {
			continue // the thread ended meanwhile
		}
		if err != nil {
			t.Fatal(err)
		}
		if 20-raw != int(nice)+1 {
			t.Fatalf("thread %d has the nice value %d, want %d", tid, 20-raw, nice+1)
		}
	}
	if got, err := p.Priority(0, 0); err != nil || got != nice+1 {
		t.Fatalf("Priority = %d, %v; want %d", got, err, nice+1)
	}
}

// The host's logger keeps one connection for a facility, made for the
// ident used last.
func TestHostSyslogConnections(t *testing.T) {
	l, err := HostSyslog()
	if err != nil {
		t.Skipf("no syslog daemon to connect to: %v", err)
	}
	for _, ident := range []string{"wasm2go-test", "wasm2go-other"} {
		if err := l.Log(SyslogMessage{Severity: 7, Facility: 1, Ident: ident, Message: "a debug message of a test"}); err != nil {
			t.Fatal(err)
		}
	}
	host := l.(*hostSyslogger)
	host.mu.Lock()
	n, ident := len(host.writers), host.writers[1].ident
	host.mu.Unlock()
	if n != 1 || ident != "wasm2go-other" {
		t.Fatalf("%d connections, facility 1's for %q; want one for wasm2go-other", n, ident)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
