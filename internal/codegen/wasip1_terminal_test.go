//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// termiosOff is where the tests put the record a request of a terminal
// takes in the guest's memory.
const termiosOff = 2048

// guestIoctl makes the guest's request of a terminal of fd, with arg.
func guestIoctl(w *WasiStubs, m *Module, fd int32, request uint32, arg int32) int32 {
	return w.Fd_ioctl(m, fd, int32(request), arg)
}

// guestTermiosAt returns the struct termios2 at termiosOff.
func guestTermiosAt(m *Module) linuxTermios {
	var t linuxTermios
	t.decode(m.memory[termiosOff : termiosOff+44])
	return t
}

// putGuestTermios writes t at termiosOff as a struct termios2.
func putGuestTermios(m *Module, t linuxTermios) {
	t.encode(m.memory[termiosOff : termiosOff+44])
}

// hostIoctlOf makes a request of f with the host's number.
func hostIoctlOf(t *testing.T, f *os.File, request uint32, arg unsafe.Pointer) {
	t.Helper()
	if err := withHostDescriptor(f, func(fd uintptr) error {
		_, err := hostIoctlPointer(int(fd), request, arg)
		return err
	}); err != nil {
		t.Fatalf("ioctl %#x: %v", request, err)
	}
}

// hostSettings returns the settings of the terminal f, as the host has
// them.
func hostSettings(t *testing.T, f *os.File) syscall.Termios {
	t.Helper()
	var h syscall.Termios
	hostIoctlOf(t, f, hostGetSettings, unsafe.Pointer(&h))
	return h
}

// waitInput waits for f to have input.
func waitInput(t *testing.T, f *os.File) {
	t.Helper()
	if err := withHostDescriptor(f, func(fd uintptr) error {
		return hostWaitReady([]uintptr{fd}, []int{hostWantInput}, make([]bool, 1), time.Time{}, -1)
	}); err != nil {
		t.Fatal(err)
	}
}

// readByte reads one byte of f.
func readByte(t *testing.T, f *os.File) byte {
	t.Helper()
	var b [1]byte
	if _, err := f.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return b[0]
}

// The guest reads a terminal's settings in Linux's numbers: the flags at
// Linux's bits, the control characters at Linux's places with a disabled
// one 0, and the speed in c_cflag and in the speeds of struct termios2.
func TestFdIoctlReadsTheSettingsInLinuxNumbers(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave

	h := hostSettings(t, slave)
	h.Lflag = h.Lflag&^syscall.ICANON | syscall.ECHO | syscall.ISIG
	h.Iflag |= syscall.IXON | syscall.ICRNL
	h.Oflag = h.Oflag&^hostTabMask | syscall.OPOST | syscall.ONLCR | hostTab3
	h.Cflag = h.Cflag&^syscall.CLOCAL | syscall.CSTOPB
	h.Cc[syscall.VMIN], h.Cc[syscall.VTIME] = 1, 255
	h.Cc[syscall.VINTR], h.Cc[syscall.VSTOP] = 0x03, hostDisabledChar
	setHostOutputSpeed(&h, 9600)
	hostIoctlOf(t, slave, hostSetSettings, unsafe.Pointer(&h))

	for _, request := range []uint32{linuxTCGETS, linuxTCGETS2} {
		for i := range 44 {
			m.memory[termiosOff+i] = 0xa5
		}
		if rc := guestIoctl(w, m, 0, request, termiosOff); rc != _wasiESUCCESS {
			t.Fatalf("ioctl %#x rc=%d", request, rc)
		}
		g := guestTermiosAt(m)
		const (
			isig, icanon, echo   = 0x1, 0x2, 0x8
			icrnl, ixon          = 0x100, 0x400
			opost, onlcr, tab3   = 0x1, 0x4, 0x1800
			cstopb, clocal       = 0x40, 0x800
			cbaud, b9600         = 0x100f, 0xd
			vintr, vtime, vmin   = 0, 5, 6
			vstop                = 9
			wantL                = isig | echo
			wantI                = icrnl | ixon
			wantO                = opost | onlcr | tab3
			wantC                = cstopb | b9600
			wantCMask            = cstopb | clocal | cbaud
			wantLMask, wantIMask = isig | icanon | echo, icrnl | ixon
		)
		switch {
		case g.Lflag&wantLMask != wantL, g.Iflag&wantIMask != wantI, g.Oflag&wantO != wantO, g.Cflag&wantCMask != wantC:
			t.Fatalf("ioctl %#x: flags i%#x o%#x c%#x l%#x", request, g.Iflag, g.Oflag, g.Cflag, g.Lflag)
		case g.Cc[vmin] != 1 || g.Cc[vtime] != 255 || g.Cc[vintr] != 0x03 || g.Cc[vstop] != 0:
			t.Fatalf("ioctl %#x: c_cc %v", request, g.Cc)
		}
		if request == linuxTCGETS2 && g.Ospeed != 9600 {
			t.Fatalf("TCGETS2: c_ospeed %d, want 9600", g.Ospeed)
		}
		if past := m.memory[termiosOff+36 : termiosOff+44]; request == linuxTCGETS && !bytes.Equal(past, bytes.Repeat([]byte{0xa5}, 8)) {
			t.Fatalf("TCGETS wrote past struct termios: % x", past)
		}
	}
}

// The guest sets a terminal's settings in Linux's numbers, now or after
// the output has drained (and the input is flushed).
func TestFdIoctlSetsTheSettingsFromLinuxNumbers(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.mu.Lock()
	fd := w.addFDLocked(&wasiOpen{f: slave})
	w.mu.Unlock()

	for _, request := range []uint32{linuxTCSETS, linuxTCSETSW, linuxTCSETSF} {
		if rc := guestIoctl(w, m, fd, linuxTCGETS, termiosOff); rc != _wasiESUCCESS {
			t.Fatalf("TCGETS rc=%d", rc)
		}
		g := guestTermiosAt(m)
		const (
			icanon, echo, ixoff = 0x2, 0x8, 0x1000
			tabdly, tab1        = 0x1800, 0x800
			cstopb, clocal      = 0x40, 0x800
			cbaud, b19200       = 0x100f, 0xe
			veof, vtime, vmin   = 4, 5, 6
			vstop, vsusp        = 9, 10
		)
		g.Lflag &^= echo | icanon
		g.Iflag |= ixoff
		g.Oflag = g.Oflag&^tabdly | tab1
		g.Cflag = g.Cflag&^(cstopb|cbaud) | clocal | b19200
		g.Cc[vmin], g.Cc[vtime], g.Cc[veof], g.Cc[vstop], g.Cc[vsusp] = 0, 5, 0x05, 0x13, 0
		putGuestTermios(m, g)
		if rc := guestIoctl(w, m, fd, request, termiosOff); rc != _wasiESUCCESS {
			t.Fatalf("ioctl %#x rc=%d", request, rc)
		}
		h := hostSettings(t, slave)
		switch {
		case h.Lflag&syscall.ICANON != 0, h.Lflag&syscall.ECHO != 0, h.Iflag&syscall.IXOFF == 0:
			t.Fatalf("ioctl %#x: host flags i%#x l%#x", request, h.Iflag, h.Lflag)
		case h.Oflag&hostTabMask != hostTab1, h.Cflag&syscall.CLOCAL == 0, h.Cflag&syscall.CSTOPB != 0, hostOutputSpeed(&h) != 19200:
			t.Fatalf("ioctl %#x: host c_oflag %#x c_cflag %#x", request, h.Oflag, h.Cflag)
		case h.Cc[syscall.VMIN] != 0, h.Cc[syscall.VTIME] != 5, h.Cc[syscall.VEOF] != 0x05, h.Cc[syscall.VSTOP] != 0x13, h.Cc[syscall.VSUSP] != hostDisabledChar:
			t.Fatalf("ioctl %#x: host c_cc %v", request, h.Cc)
		}
		// The next request changes the settings back from the host's.
		h.Lflag |= syscall.ECHO | syscall.ICANON
		hostIoctlOf(t, slave, hostSetSettings, unsafe.Pointer(&h))
	}
}

// A speed with no code of c_cflag is BOTHER there and exact in the speeds
// of struct termios2, which set it; set with struct termios, BOTHER keeps
// the speed the terminal has.
func TestFdIoctlSpeedsOfTermios2(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	const cbaud, bother, b9600 = 0x100f, 0x1000, 0xd

	if rc := guestIoctl(w, m, 0, linuxTCGETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCGETS2 rc=%d", rc)
	}
	g := guestTermiosAt(m)
	g.Cflag = g.Cflag&^(cbaud|cbaud<<16) | bother | bother<<16
	g.Ispeed, g.Ospeed = 23456, 12345
	putGuestTermios(m, g)
	if rc := guestIoctl(w, m, 0, linuxTCSETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCSETS2 rc=%d", rc)
	}
	clear(m.memory[termiosOff : termiosOff+44])
	if rc := guestIoctl(w, m, 0, linuxTCGETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCGETS2 rc=%d", rc)
	}
	if g := guestTermiosAt(m); g.Cflag&(cbaud|cbaud<<16) != bother|bother<<16 || g.Ospeed != 12345 || g.Ispeed != 23456 {
		t.Fatalf("after TCSETS2 of 12345 and 23456: c_cflag %#x, speeds %d %d", g.Cflag, g.Ispeed, g.Ospeed)
	}

	// TCSETS with BOTHER, and speeds of 9600 it does not carry.
	g.Ispeed, g.Ospeed = 9600, 9600
	putGuestTermios(m, g)
	if rc := guestIoctl(w, m, 0, linuxTCSETS, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCSETS rc=%d", rc)
	}
	clear(m.memory[termiosOff : termiosOff+44])
	if rc := guestIoctl(w, m, 0, linuxTCGETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCGETS2 rc=%d", rc)
	}
	if g := guestTermiosAt(m); g.Cflag&cbaud != bother || g.Ospeed != 12345 || g.Ispeed != 23456 {
		t.Fatalf("after TCSETS of BOTHER: c_cflag %#x, speeds %d %d, want 23456 12345", g.Cflag, g.Ispeed, g.Ospeed)
	}

	// A speed of a code, and the same input speed (CIBAUD of B0).
	g.Cflag = g.Cflag&^(cbaud|cbaud<<16) | b9600
	putGuestTermios(m, g)
	if rc := guestIoctl(w, m, 0, linuxTCSETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCSETS2 rc=%d", rc)
	}
	clear(m.memory[termiosOff : termiosOff+44])
	if rc := guestIoctl(w, m, 0, linuxTCGETS2, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCGETS2 rc=%d", rc)
	}
	if g := guestTermiosAt(m); g.Cflag&(cbaud|cbaud<<16) != b9600 || g.Ospeed != 9600 || g.Ispeed != 9600 {
		t.Fatalf("after TCSETS2 of B9600: c_cflag %#x, speeds %d %d", g.Cflag, g.Ispeed, g.Ospeed)
	}
}

// The window size goes both ways as struct winsize.
func TestFdIoctlWindowSize(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave

	for i, v := range []uint16{24, 80, 640, 480} {
		binary.LittleEndian.PutUint16(m.memory[termiosOff+2*i:], v)
	}
	if rc := guestIoctl(w, m, 0, linuxTIOCSWINSZ, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TIOCSWINSZ rc=%d", rc)
	}
	var host [4]uint16
	hostIoctlOf(t, slave, syscall.TIOCGWINSZ, unsafe.Pointer(&host))
	if host != [4]uint16{24, 80, 640, 480} {
		t.Fatalf("the host's window size %v", host)
	}
	host = [4]uint16{30, 100, 800, 600}
	hostIoctlOf(t, slave, syscall.TIOCSWINSZ, unsafe.Pointer(&host))
	clear(m.memory[termiosOff : termiosOff+8])
	if rc := guestIoctl(w, m, 0, linuxTIOCGWINSZ, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TIOCGWINSZ rc=%d", rc)
	}
	for i, v := range host {
		if got := binary.LittleEndian.Uint16(m.memory[termiosOff+2*i:]); got != v {
			t.Fatalf("struct winsize field %d is %d, want %d", i, got, v)
		}
	}
	// A memory64 guest's address keeps its 64 bits.
	if rc := w.Fd_ioctl64(m, 0, linuxTIOCGWINSZ, 1<<32|termiosOff); rc != -_wasiEFAULT {
		t.Fatalf("TIOCGWINSZ at 1<<32|%d rc=%d, want -EFAULT", termiosOff, rc)
	}
}

// TCFLSH discards the input the terminal has received.
func TestFdIoctlFlushesInput(t *testing.T) {
	master, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave

	write(t, master, "abc\n")
	waitInput(t, slave)
	if rc := guestIoctl(w, m, 0, linuxTCFLSH, 0); rc != _wasiESUCCESS { // TCIFLUSH
		t.Fatalf("TCFLSH rc=%d", rc)
	}
	var queued int32
	hostIoctlOf(t, slave, hostInputQueued, unsafe.Pointer(&queued))
	if queued != 0 {
		t.Fatalf("%d bytes are queued after TCFLSH", queued)
	}
	for _, queue := range []int32{1, 2} { // TCOFLUSH, TCIOFLUSH
		if rc := guestIoctl(w, m, 0, linuxTCFLSH, queue); rc != _wasiESUCCESS {
			t.Fatalf("TCFLSH %d rc=%d", queue, rc)
		}
	}
	if rc := guestIoctl(w, m, 0, linuxTCFLSH, 3); rc != -_wasiEINVAL {
		t.Fatalf("TCFLSH of no queue rc=%d, want -EINVAL", rc)
	}
}

// TCXONC stops and restarts the output, which the master side sees in
// packet mode, and sends the STOP and the START character.
func TestFdIoctlFlow(t *testing.T) {
	master, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave

	h := hostSettings(t, slave)
	h.Cc[syscall.VSTOP], h.Cc[syscall.VSTART] = 0x13, 0x11
	hostIoctlOf(t, slave, hostSetSettings, unsafe.Pointer(&h))
	for _, tc := range []struct {
		action int32
		want   byte
	}{{2, 0x13}, {3, 0x11}} { // TCIOFF, TCION
		if rc := guestIoctl(w, m, 0, linuxTCXONC, tc.action); rc != _wasiESUCCESS {
			t.Fatalf("TCXONC %d rc=%d", tc.action, rc)
		}
		if got := readByte(t, master); got != tc.want {
			t.Fatalf("TCXONC %d sent %#x, want %#x", tc.action, got, tc.want)
		}
	}

	packet := int32(1)
	hostIoctlOf(t, master, syscall.TIOCPKT, unsafe.Pointer(&packet))
	const stop, start = 0x04, 0x08 // TIOCPKT_STOP, TIOCPKT_START
	for _, tc := range []struct {
		action int32
		want   byte
	}{{0, stop}, {1, start}} { // TCOOFF, TCOON
		if rc := guestIoctl(w, m, 0, linuxTCXONC, tc.action); rc != _wasiESUCCESS {
			t.Fatalf("TCXONC %d rc=%d", tc.action, rc)
		}
		if got := readByte(t, master); got&tc.want == 0 {
			t.Fatalf("TCXONC %d: the master read the packet %#x, want %#x", tc.action, got, tc.want)
		}
	}
	if rc := guestIoctl(w, m, 0, linuxTCXONC, 4); rc != -_wasiEINVAL {
		t.Fatalf("TCXONC of no action rc=%d, want -EINVAL", rc)
	}
}

// TCSBRK sends a break with 0 and waits for the output to drain
// otherwise; TIOCEXCL and TIOCNXCL set and clear exclusive use; TIOCOUTQ
// is the host's count.
func TestFdIoctlLine(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave

	for _, duration := range []int32{0, 1} {
		if rc := guestIoctl(w, m, 0, linuxTCSBRK, duration); rc != _wasiESUCCESS {
			t.Fatalf("TCSBRK %d rc=%d", duration, rc)
		}
	}
	for _, tc := range []struct {
		request uint32
		want    bool
	}{{linuxTIOCEXCL, true}, {linuxTIOCNXCL, false}} {
		if rc := guestIoctl(w, m, 0, tc.request, 0); rc != _wasiESUCCESS {
			t.Fatalf("ioctl %#x rc=%d", tc.request, rc)
		}
		if exclusive, known := terminalExclusive(t, slave); known && exclusive != tc.want {
			t.Fatalf("ioctl %#x: exclusive use is %v", tc.request, exclusive)
		}
	}
	var queued int32
	hostIoctlOf(t, slave, syscall.TIOCOUTQ, unsafe.Pointer(&queued))
	binary.LittleEndian.PutUint32(m.memory[termiosOff:], 0xffffffff)
	if rc := guestIoctl(w, m, 0, linuxTIOCOUTQ, termiosOff); rc != _wasiESUCCESS || int32(readU32(m.memory, termiosOff)) != queued {
		t.Fatalf("TIOCOUTQ rc=%d count %d, want %d", rc, int32(readU32(m.memory, termiosOff)), queued)
	}
}

// What the guest is refused: EBADF for no descriptor; ENOTTY for a request
// that is no terminal's and, before its memory is looked at, for a
// descriptor that is no terminal; EFAULT for a record out of the memory;
// ENOSYS for the changes of the foreground process group and the
// controlling terminal; ENOTTY for the foreground process group and the
// session of an instance without a Process.
func TestFdIoctlRefusals(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	r, _ := blockingPipe(t)
	w.mu.Lock()
	pipe := w.addFDLocked(&wasiOpen{f: r, noWrite: true})
	w.mu.Unlock()
	outside := int32(len(m.memory))

	for _, tc := range []struct {
		name    string
		fd      int32
		request uint32
		arg     int32
		want    int32
	}{
		{"no descriptor", 99, linuxTCGETS, termiosOff, -_wasiEBADF},
		{"FIONREAD", 0, 0x541b, termiosOff, -_wasiENOTTY},
		{"a pipe", pipe, linuxTCGETS, termiosOff, -_wasiENOTTY},
		{"a pipe with a record out of the memory", pipe, linuxTCGETS, outside, -_wasiENOTTY},
		{"a standard stream that is no file", 1, linuxTIOCGWINSZ, termiosOff, -_wasiENOTTY},
		{"a record out of the memory", 0, linuxTCGETS, outside, -_wasiEFAULT},
		{"TIOCSPGRP", 0, linuxTIOCSPGRP, termiosOff, -_wasiENOSYS},
		{"TIOCSCTTY", 0, linuxTIOCSCTTY, 0, -_wasiENOSYS},
		{"TIOCNOTTY", 0, linuxTIOCNOTTY, 0, -_wasiENOSYS},
		{"TIOCGPGRP without a Process", 0, linuxTIOCGPGRP, termiosOff, -_wasiENOTTY},
		{"TIOCGSID without a Process", 0, linuxTIOCGSID, termiosOff, -_wasiENOTTY},
	} {
		if rc := guestIoctl(w, m, tc.fd, tc.request, tc.arg); rc != tc.want {
			t.Errorf("%s: rc=%d, want %d", tc.name, rc, tc.want)
		}
	}
	// A terminal that is not the host process's controlling terminal tells
	// an instance with a Process neither.
	w.cfg.Process = HostProcessUmask(0o022)
	for _, request := range []uint32{linuxTIOCGPGRP, linuxTIOCGSID} {
		if rc := guestIoctl(w, m, 0, request, termiosOff); rc != -_wasiENOTTY {
			t.Errorf("ioctl %#x of no controlling terminal rc=%d, want -ENOTTY", request, rc)
		}
	}
}

// Of the controlling terminal of the host process, an instance with a
// Process reads the foreground process group and the session, which are
// the host process's; one without is refused them. The host process is a
// process of its own that leads a session with the terminal
// (TestFdIoctlInTheSessionLeader).
func TestFdIoctlOfTheControllingTerminal(t *testing.T) {
	if os.Getenv("WASM2GO_TERMINAL_SESSION") != "" {
		t.Skip("this is the session leader")
	}
	openTestPty(t) // skips the test where there is none
	leader := exec.Command(os.Args[0], "-test.run=^TestFdIoctlInTheSessionLeader$")
	leader.Env = append(os.Environ(), "WASM2GO_TERMINAL_SESSION=1")
	if out, err := leader.CombinedOutput(); err != nil {
		t.Fatalf("the session leader: %v: %s", err, out)
	}
}

// TestFdIoctlInTheSessionLeader is the process of
// TestFdIoctlOfTheControllingTerminal: it leads a session of its own with a
// pseudo-terminal for its controlling terminal.
func TestFdIoctlInTheSessionLeader(t *testing.T) {
	if os.Getenv("WASM2GO_TERMINAL_SESSION") == "" {
		t.Skip("run by TestFdIoctlOfTheControllingTerminal")
	}
	// The terminal hangs up on its controlling process when the test
	// closes its master side.
	signal.Ignore(syscall.SIGHUP)
	_, slave := openTestPty(t)
	if _, err := syscall.Setsid(); err != nil {
		t.Fatal(err)
	}
	if err := withHostDescriptor(slave, func(fd uintptr) error {
		_, err := hostIoctlValue(int(fd), syscall.TIOCSCTTY, 0)
		return err
	}); err != nil {
		t.Fatalf("TIOCSCTTY: %v", err)
	}
	sid := hostSession(t)
	for _, process := range []Process{HostProcessUmask(0o022), nil} {
		w, m := newProcTestStubs(t)
		w.cfg.Stdin, w.cfg.Process = slave, process
		for _, tc := range []struct {
			request uint32
			want    int
		}{{linuxTIOCGPGRP, syscall.Getpgrp()}, {linuxTIOCGSID, sid}} {
			rc := guestIoctl(w, m, 0, tc.request, termiosOff)
			got := int(int32(readU32(m.memory, termiosOff)))
			switch {
			case process == nil && rc != -_wasiENOTTY:
				t.Errorf("ioctl %#x without a Process rc=%d, want -ENOTTY", tc.request, rc)
			case process != nil && (rc != _wasiESUCCESS || got != tc.want):
				t.Errorf("ioctl %#x rc=%d, %d; want %d", tc.request, rc, got, tc.want)
			}
		}
	}
}
