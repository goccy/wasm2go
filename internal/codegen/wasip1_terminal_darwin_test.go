package codegen

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// The field of the delays after a tab of c_oflag (TABDLY) and two of its
// values, TAB1 and TAB3.
const hostTabMask, hostTab1, hostTab3 = 0xc04, 0x400, 0x4

// The host's requests for the settings of a terminal and for the count of
// its input (FIONREAD), and the value of a disabled control character.
const (
	hostGetSettings       = syscall.TIOCGETA
	hostSetSettings       = syscall.TIOCSETA
	hostInputQueued       = 0x4004667f
	hostDisabledChar byte = 0xff
)

// hostOutputSpeed returns the output speed of h.
func hostOutputSpeed(h *syscall.Termios) uint64 { return h.Ospeed }

// setHostOutputSpeed sets the output speed of h, and the input speed with
// it.
func setHostOutputSpeed(h *syscall.Termios, speed uint64) { h.Ispeed, h.Ospeed = speed, speed }

// terminalExclusive: darwin has no request that tells whether a terminal is
// in exclusive use.
func terminalExclusive(t *testing.T, f *os.File) (exclusive, known bool) { return false, false }

// hostSession returns the session of the process.
func hostSession(t *testing.T) int {
	t.Helper()
	sid, err := syscall.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// The bits of the host's flags that the guest has no name for, and its
// control characters the guest has no place for, stay as the terminal has
// them when the guest sets the settings.
func TestFdIoctlKeepsWhatTheGuestHasNoNameFor(t *testing.T) {
	_, slave := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.cfg.Stdin = slave
	const noKernInfo, altWerase = 0x02000000, 0x200 // NOKERNINFO, ALTWERASE

	h := hostSettings(t, slave)
	h.Lflag |= noKernInfo | altWerase
	h.Cc[syscall.VSTATUS] = 0x14
	hostIoctlOf(t, slave, hostSetSettings, unsafe.Pointer(&h))
	if rc := guestIoctl(w, m, 0, linuxTCGETS, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCGETS rc=%d", rc)
	}
	g := guestTermiosAt(m)
	g.Lflag &^= 0x8 // ECHO
	putGuestTermios(m, g)
	if rc := guestIoctl(w, m, 0, linuxTCSETS, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TCSETS rc=%d", rc)
	}
	h = hostSettings(t, slave)
	if h.Lflag&(noKernInfo|altWerase) != noKernInfo|altWerase || h.Lflag&syscall.ECHO != 0 || h.Cc[syscall.VSTATUS] != 0x14 {
		t.Fatalf("host c_lflag %#x, VSTATUS %#x", h.Lflag, h.Cc[syscall.VSTATUS])
	}
}

// A pseudo-terminal of darwin has no number that names its slave side as
// /dev/pts/N, and no lock of Linux's.
func TestFdIoctlPseudoTerminalMaster(t *testing.T) {
	master, _ := openTestPty(t)
	w, m := newProcTestStubs(t)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{f: master})
	w.mu.Unlock()
	for _, request := range []uint32{linuxTIOCGPTN, linuxTIOCSPTLCK} {
		if rc := guestIoctl(w, m, fd, request, termiosOff); rc != -_wasiENOTTY {
			t.Fatalf("ioctl %#x of the master rc=%d, want -ENOTTY", request, rc)
		}
	}
}

// The guest makes a pseudo-terminal usable with darwin's requests of its
// master side (grantpt, unlockpt, ptsname): the slave side opens at the
// name TIOCPTYGNAME writes, and is a terminal.
func TestFdIoctlPseudoTerminalMasterOfDarwin(t *testing.T) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	closeAtEnd(t, ptmx)
	w, m := newProcTestStubs(t)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{f: ptmx})
	w.mu.Unlock()
	for _, request := range []uint32{darwinTIOCPTYGRANT, darwinTIOCPTYUNLK} {
		if rc := guestIoctl(w, m, fd, request, 0); rc != _wasiESUCCESS {
			t.Fatalf("ioctl %#x rc=%d", request, rc)
		}
	}
	if rc := guestIoctl(w, m, fd, darwinTIOCPTYGNAME, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TIOCPTYGNAME rc=%d", rc)
	}
	field := m.memory[termiosOff : termiosOff+darwinPtyNameSize]
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		t.Fatalf("TIOCPTYGNAME wrote no string: %q", field)
	}
	name := string(field[:end])
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	closeAtEnd(t, slave)
	if terminal, err := hostFileTerminal(slave); err != nil || !terminal {
		t.Fatalf("%s is a terminal: %v, %v", name, terminal, err)
	}
}
