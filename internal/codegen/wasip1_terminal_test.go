//go:build darwin || linux

package codegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	fd := addTestFD(w, &wasiOpen{f: slave})
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

// hostNumberFamilyIoctl is the family of the requests of ioctl.
const hostNumberFamilyIoctl int32 = 21

// terminalRequestsByName holds the requests of a terminal fd_ioctl takes
// that package syscall names on every architecture of linux, at their
// names, in Linux's (asm-generic) numbers.
var terminalRequestsByName = map[string]uint32{
	"TCGETS": linuxTCGETS, "TCSETS": linuxTCSETS,
	"TIOCEXCL": linuxTIOCEXCL, "TIOCNXCL": linuxTIOCNXCL,
	"TIOCSCTTY": linuxTIOCSCTTY, "TIOCNOTTY": linuxTIOCNOTTY,
	"TIOCGPGRP": linuxTIOCGPGRP, "TIOCSPGRP": linuxTIOCSPGRP,
	"TIOCOUTQ": linuxTIOCOUTQ, "TIOCGSID": linuxTIOCGSID,
	"TIOCGWINSZ": linuxTIOCGWINSZ, "TIOCSWINSZ": linuxTIOCSWINSZ,
	"TIOCGPTN": linuxTIOCGPTN, "TIOCSPTLCK": linuxTIOCSPTLCK,
}

// The host's numbering has those of the requests of a terminal fd_ioctl
// takes that the host's C names, and the host's TIOCGWINSZ is, by its
// name, the request fd_ioctl takes for the window size.
func TestHostNumberingOfTerminalRequests(t *testing.T) {
	want := slices.Sorted(maps.Keys(terminalRequestsByName))
	if runtime.GOOS == "darwin" {
		// darwin's C has no TCGETS, TCSETS, TIOCGSID, TIOCGPTN or TIOCSPTLCK.
		want = []string{"TIOCEXCL", "TIOCGPGRP", "TIOCGWINSZ", "TIOCNOTTY", "TIOCNXCL", "TIOCOUTQ", "TIOCSCTTY", "TIOCSPGRP", "TIOCSWINSZ"}
	}
	var got []string
	nameOf := make(map[int64]string)
	for _, n := range hostNumberTable(hostNumberFamilyIoctl) {
		if _, ok := terminalRequestsByName[n.name]; ok {
			got = append(got, n.name)
			nameOf[n.value] = n.name
		}
	}
	if slices.Sort(got); !slices.Equal(got, want) {
		t.Fatalf("the requests of a terminal %v, want %v", got, want)
	}
	name := nameOf[syscall.TIOCGWINSZ]
	if name != "TIOCGWINSZ" {
		t.Fatalf("the host's TIOCGWINSZ (%#x) is named %q", syscall.TIOCGWINSZ, name)
	}

	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	host := [4]uint16{30, 100, 800, 600}
	hostIoctlOf(t, slave, syscall.TIOCSWINSZ, unsafe.Pointer(&host))
	if rc := guestIoctl(w, m, 0, terminalRequestsByName[name], termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("%s rc=%d", name, rc)
	}
	for i, v := range host {
		if got := binary.LittleEndian.Uint16(m.memory[termiosOff+2*i:]); got != v {
			t.Fatalf("struct winsize field %d is %d, want %d", i, got, v)
		}
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
	pipe := addTestFD(w, &wasiOpen{f: r, noWrite: true})
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
		{"TIOCSPGRP without a Process", 0, linuxTIOCSPGRP, termiosOff, -_wasiENOTTY},
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
	for _, request := range []uint32{linuxTIOCGPGRP, linuxTIOCSPGRP, linuxTIOCGSID} {
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

// fdstatOf returns the filetype and the rights fd_fdstat_get reports for fd.
func fdstatOf(t *testing.T, w *WasiStubs, m *Module, fd int32) (filetype byte, base, inheriting uint64) {
	t.Helper()
	const out int32 = 5200
	if rc := w.Fd_fdstat_get(m, fd, out); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_get(%d) rc=%d", fd, rc)
	}
	return m.memory[out], binary.LittleEndian.Uint64(m.memory[out+8:]), binary.LittleEndian.Uint64(m.memory[out+16:])
}

// A terminal is a character device that cannot be sought on, as wasi-libc's
// isatty tells one: a standard stream, a file of Files and a file path_open
// opened that are a terminal of the host have no FD_SEEK and FD_TELL. A
// pipe and a regular file keep them.
func TestFdstatOfATerminalHasNoSeek(t *testing.T) {
	const seekTell = wasiRightFdSeek | wasiRightFdTell
	_, slave := openTestPty(t)
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r)
	closeAtEnd(t, wr)
	given, err := os.OpenFile(slave.Name(), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, m := newProcTestStubs(t)
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = slave, slave, wr
	w.cfg.Files = map[int32]*os.File{7: given}
	closeAllAtCleanup(t, w)

	for _, fd := range []int32{0, 1, 7} {
		filetype, base, inheriting := fdstatOf(t, w, m, fd)
		if filetype != 2 || base&seekTell != 0 || inheriting != ^uint64(0) {
			t.Errorf("fdstat of the terminal at %d: filetype %d rights %#x %#x, want 2 without FD_SEEK and FD_TELL", fd, filetype, base, inheriting)
		}
	}
	if filetype, base, _ := fdstatOf(t, w, m, 2); filetype != 2 || base&seekTell != seekTell {
		t.Errorf("fdstat of a pipe: filetype %d rights %#x, want 2 with FD_SEEK and FD_TELL", filetype, base)
	}
	file := createTestFile(t, w, "a.txt")
	if filetype, base, _ := fdstatOf(t, w, m, file); filetype != 4 || base&seekTell != seekTell {
		t.Errorf("fdstat of a regular file: filetype %d rights %#x, want 4 with FD_SEEK and FD_TELL", filetype, base)
	}

	w.cfg.FS = osFS{}
	tty, errno := w.pathOpen(m, slave.Name()[1:], 0, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open %s errno=%d", slave.Name(), errno)
	}
	if filetype, base, _ := fdstatOf(t, w, m, tty); filetype != 2 || base&seekTell != 0 {
		t.Errorf("fdstat of %s path_open opened: filetype %d rights %#x, want 2 without FD_SEEK and FD_TELL", slave.Name(), filetype, base)
	}
	closeTestFd(t, w, m, tty)
}

// A standard stream that is a closed host file is a stream to
// fd_fdstat_get, which succeeds: its read or write reports the failure.
func TestFdstatOfAClosedStream(t *testing.T) {
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(r.Close(), wr.Close()); err != nil {
		t.Fatal(err)
	}
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = r
	closeAllAtCleanup(t, w)
	if filetype, _, _ := fdstatOf(t, w, m, 0); filetype != 2 {
		t.Errorf("fdstat of a closed stream: filetype %d, want 2", filetype)
	}
}

// hostTerminalEnv holds the name of the terminal that is the standard
// input of the process runOnATerminal starts.
const hostTerminalEnv = "WASM2GO_HOST_TERMINAL"

// runOnATerminal runs the test named test in a process of its own, with the
// slave of a pseudo-terminal as its standard input, and fails unless it
// passes there.
func runOnATerminal(t *testing.T, test string) {
	t.Helper()
	if os.Getenv(hostTerminalEnv) != "" {
		t.Skip("this is the process of the tests")
	}
	_, slave := openTestPty(t)
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), hostTerminalEnv+"="+slave.Name())
	cmd.Stdin = slave
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the process of the tests: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: "+test)) {
		t.Fatalf("the process of the tests ran no test:\n%s", out)
	}
}

// TestFdstatWithoutAFreeDescriptor runs
// TestFdstatWithoutAFreeDescriptorInAProcess on a terminal.
func TestFdstatWithoutAFreeDescriptor(t *testing.T) {
	runOnATerminal(t, "TestFdstatWithoutAFreeDescriptorInAProcess")
}

// fd_fdstat_get takes no descriptor of the host's: it succeeds for a
// terminal and a regular file while the process has no number free.
func TestFdstatWithoutAFreeDescriptorInAProcess(t *testing.T) {
	if os.Getenv(hostTerminalEnv) == "" {
		t.Skip("run by TestFdstatWithoutAFreeDescriptor")
	}
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = os.Stdin
	closeAllAtCleanup(t, w)
	file := createTestFile(t, w, "a.txt")

	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	low := limit
	low.Cur = 256
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Error(err)
		}
	})
	var fill []int
	t.Cleanup(func() {
		for _, fd := range fill {
			if err := syscall.Close(fd); err != nil {
				t.Error(err)
			}
		}
	})
	for {
		fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if errors.Is(err, syscall.EMFILE) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		fill = append(fill, fd)
	}

	for fd, want := range map[int32]byte{0: 2, file: 4} {
		const out int32 = 5200
		if rc := w.Fd_fdstat_get(m, fd, out); rc != _wasiESUCCESS || m.memory[out] != want {
			t.Errorf("Fd_fdstat_get(%d) without a free descriptor rc=%d filetype %d, want filetype %d", fd, rc, m.memory[out], want)
		}
	}
}

// TestHostDescriptorsOnATerminal runs
// TestHostDescriptorsOnATerminalInAProcess on a terminal.
func TestHostDescriptorsOnATerminal(t *testing.T) {
	runOnATerminal(t, "TestHostDescriptorsOnATerminalInAProcess")
}

// The standard input an instance whose descriptors are the host's takes
// over (takeStandardLocked) is a terminal to the guest when it is the
// host's, and on the whole host filesystem its link leads to the
// terminal's name.
func TestHostDescriptorsOnATerminalInAProcess(t *testing.T) {
	name := os.Getenv(hostTerminalEnv)
	if name == "" {
		t.Skip("run by TestHostDescriptorsOnATerminal")
	}
	w, m := newHostNumberedStubs(t, nil, os.Stdin)
	w.mu.Lock()
	op := w.openLocked(0)
	w.mu.Unlock()
	if op == nil || op.stdio != 0 {
		t.Fatal("fd 0 is not the host's standard input")
	}
	if filetype, base, _ := fdstatOf(t, w, m, 0); filetype != 2 || base&(wasiRightFdSeek|wasiRightFdTell) != 0 {
		t.Errorf("fdstat of the terminal at 0: filetype %d rights %#x, want 2 without FD_SEEK and FD_TELL", filetype, base)
	}
	w.cfg.FS = osFS{}
	if target, rc := guestReadlink(w, m, "dev/fd/0"); rc != _wasiESUCCESS || target != name {
		t.Errorf("readlink dev/fd/0 of the terminal = %q rc=%d, want %q", target, rc, name)
	}
}

// guestReadlink is the guest's readlink of name.
func guestReadlink(w *WasiStubs, m *Module, name string) (string, int32) {
	const nameOff, outOff, sizeOff int32 = 0, 1024, 2048
	off, n := putPath(m, nameOff, name)
	binary.LittleEndian.PutUint32(m.memory[sizeOff:], 0)
	rc := w.Path_readlink(m, wasiPreopenFD, off, n, outOff, 256, sizeOff)
	return string(m.memory[outOff : outOff+int32(readU32(m.memory, int(sizeOff)))]), rc
}

// On the whole host filesystem the link of a standard stream that is a
// terminal leads to the terminal's name, as ttyname reads it; that of a
// regular file of Files to the host's link for it (none on darwin); that of
// a file path_open opened to the path it was opened under.
func TestLinkOfATerminalIsItsName(t *testing.T) {
	_, slave := openTestPty(t)
	given, err := os.Create(filepath.Join(t.TempDir(), "given"))
	if err != nil {
		t.Fatal(err)
	}
	hostPath, err := filepath.EvalSymlinks(given.Name())
	if err != nil {
		t.Fatal(err)
	}
	w, m := newProcTestStubs(t)
	w.cfg.FS = osFS{}
	w.cfg.Stdin = slave
	w.cfg.Files = map[int32]*os.File{7: given}
	closeAllAtCleanup(t, w)
	for _, name := range []string{"dev/fd/0", "proc/self/fd/0"} {
		if target, rc := guestReadlink(w, m, name); rc != _wasiESUCCESS || target != slave.Name() {
			t.Errorf("readlink %s of a terminal = %q rc=%d, want %q", name, target, rc, slave.Name())
		}
	}
	target, rc := guestReadlink(w, m, "proc/self/fd/7")
	switch runtime.GOOS {
	case "linux":
		if rc != _wasiESUCCESS || target != hostPath {
			t.Errorf("readlink proc/self/fd/7 of a regular file of Files = %q rc=%d, want %q", target, rc, hostPath)
		}
	case "darwin":
		if rc != _wasiEINVAL {
			t.Errorf("readlink proc/self/fd/7 of a regular file of Files = %q rc=%d, want EINVAL: no link", target, rc)
		}
	}
	path := filepath.Join(t.TempDir(), "a.txt")
	file, errno := w.pathOpen(m, path[1:], 0, 0x1 /* O_CREAT */, 1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open %s errno=%d", path, errno)
	}
	name := "dev/fd/" + strconv.Itoa(int(file))
	if target, rc := guestReadlink(w, m, name); rc != _wasiESUCCESS || target != path {
		t.Errorf("readlink %s of a regular file = %q rc=%d, want %q", name, target, rc, path)
	}
	closeTestFd(t, w, m, file)
}
