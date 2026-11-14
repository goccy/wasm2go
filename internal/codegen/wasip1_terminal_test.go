//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Offsets in the test module's memory.
const (
	ttyRecordOff int32 = 6000 // struct termios of the guest
	ttyResultOff int32 = 6100 // what an ioctl returned
	ttyBufferOff int32 = 6200 // the argument of an ioctl (256 bytes and more)
	ttyOutOff    int32 = 6800
)

// ioctlValue makes a request with a number for an argument and returns the
// import's result.
func ioctlValue(w *WasiStubs, m *Module, fd int32, request uint32, value int32) int32 {
	return w.Fd_ioctl(m, fd, int32(request), 0, value, 0, ttyResultOff)
}

// ioctlBuffer makes a request with a buffer of 256 bytes holding arg, and
// returns the import's result and the buffer afterwards.
func ioctlBuffer(w *WasiStubs, m *Module, fd int32, request uint32, arg []byte) (int32, []byte) {
	buf := m.memory[ttyBufferOff : ttyBufferOff+256]
	clear(buf)
	copy(buf, arg)
	rc := w.Fd_ioctl(m, fd, int32(request), 1, ttyBufferOff, 256, ttyResultOff)
	return rc, buf
}

// openTestTerminal opens a pseudo-terminal through the guest: the
// descriptor of its master side, and the path of the terminal. The requests
// that make the terminal usable are the guest's own (Fd_ioctl).
func openTestTerminal(t *testing.T, w *WasiStubs, m *Module) (master int32, path string) {
	t.Helper()
	master, errno := w.pathOpen("dev/ptmx", 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Skipf("no pseudo-terminal to open (errno %d)", errno)
	}
	switch runtime.GOOS {
	case "linux":
		const unlock, number = 0x40045431, 0x80045430 // TIOCSPTLCK, TIOCGPTN
		if rc, _ := ioctlBuffer(w, m, master, unlock, []byte{0, 0, 0, 0}); rc != _wasiESUCCESS {
			t.Fatalf("TIOCSPTLCK rc=%d", rc)
		}
		rc, buf := ioctlBuffer(w, m, master, number, nil)
		if rc != _wasiESUCCESS {
			t.Fatalf("TIOCGPTN rc=%d", rc)
		}
		path = "/dev/pts/" + strconv.Itoa(int(binary.NativeEndian.Uint32(buf)))
	case "darwin":
		const grant, unlock, name = 0x20007454, 0x20007452, 0x40807453 // TIOCPTYGRANT, TIOCPTYUNLK, TIOCPTYGNAME
		if rc := ioctlValue(w, m, master, grant, 0); rc != _wasiESUCCESS {
			t.Fatalf("TIOCPTYGRANT rc=%d", rc)
		}
		if rc := ioctlValue(w, m, master, unlock, 0); rc != _wasiESUCCESS {
			t.Fatalf("TIOCPTYUNLK rc=%d", rc)
		}
		rc, buf := ioctlBuffer(w, m, master, name, nil)
		if rc != _wasiESUCCESS {
			t.Fatalf("TIOCPTYGNAME rc=%d", rc)
		}
		path = string(buf[:strings.IndexByte(string(buf), 0)])
	}
	return master, path
}

// openTerminal opens the terminal at path for reading and writing.
func openTerminal(t *testing.T, w *WasiStubs, path string) int32 {
	t.Helper()
	fd, errno := w.pathOpen(strings.TrimPrefix(path, "/"), 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open %s errno=%d", path, errno)
	}
	return fd
}

// terminalDevice returns the device a descriptor of the guest's is open on.
func terminalDevice(t *testing.T, w *WasiStubs, fd int32) uint64 {
	t.Helper()
	host, ok := w.HostDescriptor(fd)
	if !ok {
		t.Fatalf("descriptor %d has no descriptor of the host", fd)
	}
	device, ok := hostTerminalIdentity(int(host))
	if !ok {
		t.Fatalf("descriptor %d is no character device", fd)
	}
	return device
}

// The window size set through one side of a pseudo-terminal is read through
// the other: the requests reach the host with the guest's memory for their
// argument.
func TestTerminal_RequestsReadAndWriteTheGuestsMemory(t *testing.T) {
	w, m := newHostGuest(t, "/")
	master, path := openTestTerminal(t, w, m)
	slave := openTerminal(t, w, path)

	size := make([]byte, 8) // struct winsize: rows, columns, two sizes in pixels
	binary.NativeEndian.PutUint16(size[0:], 37)
	binary.NativeEndian.PutUint16(size[2:], 111)
	if rc, _ := ioctlBuffer(w, m, master, syscall.TIOCSWINSZ, size); rc != _wasiESUCCESS {
		t.Fatalf("TIOCSWINSZ rc=%d", rc)
	}
	rc, got := ioctlBuffer(w, m, slave, syscall.TIOCGWINSZ, nil)
	if rc != _wasiESUCCESS {
		t.Fatalf("TIOCGWINSZ rc=%d", rc)
	}
	if rows, columns := binary.NativeEndian.Uint16(got[0:]), binary.NativeEndian.Uint16(got[2:]); rows != 37 || columns != 111 {
		t.Fatalf("the window is %d by %d, want 37 by 111", rows, columns)
	}
	if returned := int32(readU32(m.memory, int(ttyResultOff))); returned != 0 {
		t.Fatalf("the request returned %d, want 0", returned)
	}

	// A buffer smaller than the request takes is refused, and so is
	// memory that is not the guest's.
	if rc := w.Fd_ioctl(m, slave, int32(syscall.TIOCGWINSZ), 1, ttyBufferOff, 4, ttyResultOff); rc != -_wasiEINVAL {
		t.Fatalf("a buffer of 4 bytes rc=%d, want -EINVAL", rc)
	}
	if rc := w.Fd_ioctl(m, slave, int32(syscall.TIOCGWINSZ), 1, int32(len(m.memory)-8), 256, ttyResultOff); rc != -_wasiEFAULT {
		t.Fatalf("a buffer beyond the memory rc=%d, want -EFAULT", rc)
	}
}

func TestTerminal_RequestsThatAreNotATerminals(t *testing.T) {
	dir := t.TempDir()
	w, m := newHostGuest(t, dir)
	file := createTestFile(t, w, "plain.txt")
	// A request of another group is not passed on.
	const socketRequest = 0x8912 // SIOCGIFCONF on linux: its argument holds a pointer
	if rc, _ := ioctlBuffer(w, m, file, socketRequest, nil); rc != -_wasiEINVAL {
		t.Fatalf("a request of another group rc=%d, want -EINVAL", rc)
	}
	// A terminal's request on a file is the host's to refuse.
	if rc, _ := ioctlBuffer(w, m, file, syscall.TIOCGWINSZ, nil); rc != -_wasiENOTTY {
		t.Fatalf("TIOCGWINSZ on a file rc=%d, want -ENOTTY", rc)
	}
	if rc := w.Tty_getattr(m, file, ttyRecordOff); rc != -_wasiENOTTY {
		t.Fatalf("Tty_getattr on a file rc=%d, want -ENOTTY", rc)
	}
	// a number beyond what a process may have open
	if rc := w.Tty_getattr(m, 1<<30, ttyRecordOff); rc != -_wasiEBADF {
		t.Fatalf("Tty_getattr on no descriptor rc=%d, want -EBADF", rc)
	}

	// A guest with descriptors of its own has no terminal of the host's.
	if hostSuite {
		return
	}
	own, om := newProcTestStubs(t)
	fd := createTestFile(t, own, "plain.txt")
	if rc := own.Tty_getattr(om, fd, ttyRecordOff); rc != -_wasiENOTTY {
		t.Fatalf("Tty_getattr of a guest with its own descriptors rc=%d, want -ENOTTY", rc)
	}
	if rc, _ := ioctlBuffer(own, om, fd, syscall.TIOCGWINSZ, nil); rc != -_wasiENOTTY {
		t.Fatalf("TIOCGWINSZ of a guest with its own descriptors rc=%d, want -ENOTTY", rc)
	}
}

// The settings of a terminal come and go as the guest's struct termios:
// what is set is what is read back, and it is the terminal's (echo, which
// both systems number 0x8 among the local flags, is seen at work).
func TestTerminal_SettingsAreTheTerminals(t *testing.T) {
	w, m := newHostGuest(t, "/")
	master, path := openTestTerminal(t, w, m)
	slave := openTerminal(t, w, path)
	const echo = 0x8
	lflag := func() uint32 {
		t.Helper()
		if rc := w.Tty_getattr(m, slave, ttyRecordOff); rc != _wasiESUCCESS {
			t.Fatalf("Tty_getattr rc=%d", rc)
		}
		return readU32(m.memory, int(ttyRecordOff)+guestTermiosLflag)
	}
	setEcho := func(on bool) {
		t.Helper()
		flags := lflag() &^ echo
		if on {
			flags |= echo
		}
		binary.LittleEndian.PutUint32(m.memory[int(ttyRecordOff)+guestTermiosLflag:], flags)
		if rc := w.Tty_setattr(m, slave, 0 /* TCSANOW */, ttyRecordOff); rc != _wasiESUCCESS {
			t.Fatalf("Tty_setattr rc=%d", rc)
		}
	}
	// What is typed at the master comes back from it when the terminal
	// echoes, and does not when it does not.
	echoed := func() bool {
		t.Helper()
		if rc := fdWriteString(w, m, master, "x\n"); rc != _wasiESUCCESS {
			t.Fatalf("write to the master rc=%d", rc)
		}
		if got, rc := fdReadString(w, m, slave, 16); rc != _wasiESUCCESS || got != "x\n" {
			t.Fatalf("read from the terminal = %q, rc=%d", got, rc)
		}
		host, _ := w.HostDescriptor(master)
		return hostReadyNow(int(host), hostPollIn)&hostPollIn != 0
	}
	setEcho(true)
	if lflag()&echo == 0 {
		t.Fatal("echo is off after it was turned on")
	}
	if !echoed() {
		t.Fatal("nothing came back from a terminal that echoes")
	}
	if got, rc := fdReadString(w, m, master, 16); rc != _wasiESUCCESS || !strings.HasPrefix(got, "x") {
		t.Fatalf("the echo = %q, rc=%d", got, rc)
	}
	setEcho(false)
	if lflag()&echo != 0 {
		t.Fatal("echo is on after it was turned off")
	}
	if echoed() {
		t.Fatal("a terminal that does not echo sent something back")
	}

	// The speed is where the host keeps it: set, it is what is read.
	if rc := w.Tty_getattr(m, slave, ttyRecordOff); rc != _wasiESUCCESS {
		t.Fatalf("Tty_getattr rc=%d", rc)
	}
	if rc := w.Tty_speed(m, ttyRecordOff, 1, 0, 0, ttyOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Tty_speed(get) rc=%d", rc)
	}
	was := readU32(m.memory, int(ttyOutOff))
	const b1200 = 9 // B1200 on linux; a speed like any other on darwin
	speed := uint32(b1200)
	if runtime.GOOS == "darwin" {
		speed = 1200
	}
	for output := int32(0); output <= 1; output++ {
		if rc := w.Tty_speed(m, ttyRecordOff, output, 1, int32(speed), ttyOutOff); rc != _wasiESUCCESS {
			t.Fatalf("Tty_speed(set, output %d) rc=%d", output, rc)
		}
		if got := readU32(m.memory, int(ttyOutOff)); got != was && output == 0 {
			t.Fatalf("the speed before the change was reported as %d, want %d", got, was)
		}
		if rc := w.Tty_speed(m, ttyRecordOff, output, 0, 0, ttyOutOff); rc != _wasiESUCCESS {
			t.Fatalf("Tty_speed(get, output %d) rc=%d", output, rc)
		}
		if got := readU32(m.memory, int(ttyOutOff)); got != speed {
			t.Fatalf("the speed (output %d) is %d after it was set to %d", output, got, speed)
		}
	}
	if rc := w.Tty_setattr(m, slave, 0, ttyRecordOff); rc != _wasiESUCCESS {
		t.Fatalf("Tty_setattr with the new speed rc=%d", rc)
	}
	if rc := w.Tty_control(m, slave, terminalFlush, int32(syscall.TCIFLUSH)); rc != _wasiESUCCESS {
		t.Fatalf("Tty_control(flush) rc=%d", rc)
	}
	if rc := w.Tty_control(m, slave, 99, 0); rc != -_wasiEINVAL {
		t.Fatalf("Tty_control of an unknown kind rc=%d, want -EINVAL", rc)
	}
}

// A process forked within the runtime that starts a session and takes a
// terminal for its controlling terminal has that terminal as /dev/tty; the
// process it was forked from keeps its own.
func TestTerminal_AForkedProcessHasItsOwnControllingTerminal(t *testing.T) {
	w, m := newHostGuest(t, "/")
	master, path := openTestTerminal(t, w, m)
	slave := openTerminal(t, w, path)
	child := forkProcess(t, w)
	defer child.wasi.CloseAll()
	cm := newForkTestModule()

	// Not before it leads a session.
	if rc := ioctlValue(child.wasi, cm, slave, syscall.TIOCSCTTY, 0); rc != -_wasiEPERM {
		t.Fatalf("TIOCSCTTY before setsid rc=%d, want -EPERM", rc)
	}
	if rc := child.wasi.Proc_setsid(cm, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	// A new session has no controlling terminal.
	if _, errno := child.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0); errno != _wasiENXIO {
		t.Fatalf("open /dev/tty in a new session errno=%d, want ENXIO", errno)
	}
	file := createTestFile(t, child.wasi, strings.TrimPrefix(t.TempDir(), "/")+"/plain.txt")
	if rc := ioctlValue(child.wasi, cm, file, syscall.TIOCSCTTY, 0); rc != -_wasiENOTTY {
		t.Fatalf("TIOCSCTTY on a file rc=%d, want -ENOTTY", rc)
	}
	// Asked of the master side, it is the terminal that is taken.
	if rc := ioctlValue(child.wasi, cm, master, syscall.TIOCSCTTY, 0); rc != _wasiESUCCESS {
		t.Fatalf("TIOCSCTTY rc=%d", rc)
	}
	tty, errno := child.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open /dev/tty errno=%d", errno)
	}
	if got, want := terminalDevice(t, child.wasi, tty), terminalDevice(t, w, slave); got != want {
		t.Fatalf("/dev/tty of the process is device %#x, want the terminal it took (%#x)", got, want)
	}
	// Asked for again, it is the one the process has; another is refused.
	if rc := ioctlValue(child.wasi, cm, slave, syscall.TIOCSCTTY, 0); rc != _wasiESUCCESS {
		t.Fatalf("TIOCSCTTY of the terminal the process has rc=%d", rc)
	}
	_, otherPath := openTestTerminal(t, w, m)
	other := openTerminal(t, child.wasi, otherPath)
	if rc := ioctlValue(child.wasi, cm, other, syscall.TIOCSCTTY, 0); rc != -_wasiEPERM {
		t.Fatalf("TIOCSCTTY of another terminal rc=%d, want -EPERM", rc)
	}
	// A process forked from it has the same terminal, and leads nothing.
	grandchild := forkProcess(t, child.wasi)
	defer grandchild.wasi.CloseAll()
	gtty, errno := grandchild.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open /dev/tty in the process forked from it errno=%d", errno)
	}
	if got, want := terminalDevice(t, grandchild.wasi, gtty), terminalDevice(t, w, slave); got != want {
		t.Fatalf("/dev/tty of that process is device %#x, want %#x", got, want)
	}
	if rc := ioctlValue(grandchild.wasi, cm, slave, syscall.TIOCSCTTY, 0); rc != -_wasiEPERM {
		t.Fatalf("TIOCSCTTY of a process that leads no session rc=%d, want -EPERM", rc)
	}
	// The first process's is untouched: the runtime kept all of it.
	w.mu.Lock()
	own := w.terminal
	w.mu.Unlock()
	if own != nil {
		t.Fatalf("the first process's controlling terminal became %q", *own)
	}
	// Given up, there is none.
	if rc := ioctlValue(child.wasi, cm, tty, syscall.TIOCNOTTY, 0); rc != _wasiESUCCESS {
		t.Fatalf("TIOCNOTTY rc=%d", rc)
	}
	if _, errno := child.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0); errno != _wasiENXIO {
		t.Fatalf("open /dev/tty after TIOCNOTTY errno=%d, want ENXIO", errno)
	}

	// Where the host gives a session leader the terminal it opens, the
	// runtime does: the master side never, the terminal itself when the
	// process has none.
	if !hostOpenTakesTerminal {
		return
	}
	if _, errno := child.wasi.pathOpen("dev/ptmx", 1, 0, 1<<1|1<<6, 0); errno != _wasiESUCCESS {
		t.Fatalf("open /dev/ptmx errno=%d", errno)
	}
	if _, errno := child.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0); errno != _wasiENXIO {
		t.Fatalf("open /dev/tty after opening a master side errno=%d, want ENXIO", errno)
	}
	openTerminal(t, child.wasi, otherPath)
	tty, errno = child.wasi.pathOpen("dev/tty", 1, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open /dev/tty after opening a terminal errno=%d", errno)
	}
	if got, want := terminalDevice(t, child.wasi, tty), terminalDevice(t, child.wasi, other); got != want {
		t.Fatalf("/dev/tty is device %#x, want the terminal the process opened (%#x)", got, want)
	}
}

// The command such a process becomes leads a session of the host's, with
// the terminal for its controlling terminal: what it writes to /dev/tty
// comes out of the master.
func TestTerminal_TheCommandAProcessBecomesTakesItsTerminal(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	w, m := newHostGuest(t, "/")
	master, path := openTestTerminal(t, w, m)
	slave := openTerminal(t, w, path)
	child := forkProcess(t, w)
	defer child.wasi.CloseAll()
	cm := newForkTestModule()
	if rc := child.wasi.Proc_setsid(cm, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setsid rc=%d", rc)
	}
	if rc := ioctlValue(child.wasi, cm, slave, syscall.TIOCSCTTY, 0); rc != _wasiESUCCESS {
		t.Fatalf("TIOCSCTTY rc=%d", rc)
	}
	const statusOff int32 = 4100
	start := func(becomes bool, script string) (pid int32) {
		t.Helper()
		if becomes {
			if rc := child.wasi.Proc_exec_next(cm, 1); rc != _wasiESUCCESS {
				t.Fatalf("Proc_exec_next rc=%d", rc)
			}
		}
		argv := []string{"/bin/sh", "-c", script}
		pathOff := writeCStr(cm, 1000, argv[0])
		argvOff := writeArgv(cm, 2000, 3000, argv)
		const pidOff int32 = 4000
		if rc := child.wasi.Proc_spawn(cm, pathOff, argvOff, 0, slave, slave, slave, 0, pidOff); rc != _wasiESUCCESS {
			t.Fatalf("Proc_spawn rc=%d", rc)
		}
		return int32(readU32(cm.memory, int(pidOff)))
	}
	// What arrives at the master until it has want, or the time is up: it
	// is read before the command is waited for, because a terminal that
	// still holds output keeps the process that closes it waiting on some
	// systems. A line and its end can come in reads of their own.
	fromMaster := func(want string, wait time.Duration) string {
		t.Helper()
		host, _ := w.HostDescriptor(master)
		until := time.Now().Add(wait)
		got := ""
		for !strings.Contains(got, want) {
			set := []hostPoll{{fd: int32(host), events: hostPollIn}}
			hostPollUntil(set, until)
			if set[0].revents&hostPollIn == 0 {
				break
			}
			more, rc := fdReadString(w, m, master, 64)
			if rc != _wasiESUCCESS {
				break
			}
			got += more
		}
		return got
	}
	ended := func(pid int32) int32 {
		t.Helper()
		if rc := child.wasi.Proc_wait(cm, pid, 0, statusOff); rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
		return int32(readU32(cm.memory, int(statusOff)))
	}
	// A child like any other is started as before: it writes to its output.
	pid := start(false, "echo done")
	if got := fromMaster("done", 10*time.Second); !strings.Contains(got, "done") {
		t.Fatalf("a child command: the master has %q, want what it wrote to its output", got)
	}
	if status := ended(pid); status != 0 {
		t.Fatalf("the child command ended with status %#x", status)
	}
	// Said and taken back, the next command is a child like any other.
	if rc := child.wasi.Proc_exec_next(cm, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_exec_next rc=%d", rc)
	}
	if rc := child.wasi.Proc_exec_next(cm, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_exec_next(0) rc=%d", rc)
	}
	child.wasi.mu.Lock()
	said := child.wasi.execNext
	child.wasi.mu.Unlock()
	if said {
		t.Fatal("the next command is still the one the process becomes after that was taken back")
	}
	pid = start(true, "echo became > /dev/tty")
	if got := fromMaster("became", 10*time.Second); !strings.Contains(got, "became") {
		t.Fatalf("the master has %q, want what the command wrote to /dev/tty", got)
	}
	if status := ended(pid); status != 0 {
		t.Fatalf("the command the process became ended with status %#x", status)
	}
}
