package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// The field of the delays after a tab of c_oflag (TABDLY) and two of its
// values, TAB1 and TAB3.
const hostTabMask, hostTab1, hostTab3 = 0x1800, 0x800, 0x1800

// The host's requests for the settings of a terminal and for the count of
// its input, and the value of a disabled control character.
const (
	hostGetSettings       = syscall.TCGETS
	hostSetSettings       = syscall.TCSETS
	hostInputQueued       = syscall.TIOCINQ
	hostDisabledChar byte = 0
)

// The codes of c_cflag of the speeds the tests use (CBAUD).
var hostSpeedCodes = map[uint64]uint32{9600: syscall.B9600, 19200: syscall.B19200}

// hostOutputSpeed returns the output speed of h, 0 for one of no code the
// tests use.
func hostOutputSpeed(h *syscall.Termios) uint64 {
	for speed, code := range hostSpeedCodes {
		if h.Cflag&0x100f == code {
			return speed
		}
	}
	return 0
}

// setHostOutputSpeed sets the output speed of h, and the input speed with
// it.
func setHostOutputSpeed(h *syscall.Termios, speed uint64) {
	h.Cflag = h.Cflag&^(0x100f|0x100f<<16) | hostSpeedCodes[speed]
}

// terminalExclusive reports whether f is in exclusive use (TIOCGEXCL).
func terminalExclusive(t *testing.T, f *os.File) (exclusive, known bool) {
	t.Helper()
	var on int32
	hostIoctlOf(t, f, 0x80045440, unsafe.Pointer(&on)) // TIOCGEXCL
	return on != 0, true
}

// hostSession returns the session of the process (getsid(2), which package
// syscall does not have here).
func hostSession(t *testing.T) int {
	t.Helper()
	sid, _, errno := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	return int(sid)
}

// The master side of a pseudo-terminal tells its number (TIOCGPTN), whose
// /dev/pts name the slave side has, and opens the slave side to an open of
// that name when it is unlocked (TIOCSPTLCK).
func TestFdIoctlPseudoTerminalMaster(t *testing.T) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	closeAtEnd(t, ptmx)
	w, m := newProcTestStubs(t)
	w.mu.Lock()
	fd := addTestFD(w, &wasiOpen{f: ptmx})
	w.mu.Unlock()

	if rc := guestIoctl(w, m, fd, linuxTIOCGPTN, termiosOff); rc != _wasiESUCCESS {
		t.Fatalf("TIOCGPTN rc=%d", rc)
	}
	name := fmt.Sprintf("/dev/pts/%d", readU32(m.memory, termiosOff))
	for _, lock := range []uint32{1, 0} {
		binary.LittleEndian.PutUint32(m.memory[termiosOff:], lock)
		if rc := guestIoctl(w, m, fd, linuxTIOCSPTLCK, termiosOff); rc != _wasiESUCCESS {
			t.Fatalf("TIOCSPTLCK %d rc=%d", lock, rc)
		}
		slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
		if lock == 1 {
			if !errors.Is(err, syscall.EIO) {
				t.Fatalf("open %s locked: %v, want EIO", name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("open %s unlocked: %v", name, err)
		}
		closeAtEnd(t, slave)
	}
}

// On a host that numbers the requests of a terminal as asm-generic does,
// the host's numbering gives each the number fd_ioctl takes.
func TestHostNumberingOfTerminalRequestsIsLinuxs(t *testing.T) {
	if !hostGenericTerminal {
		t.Skip("this host numbers the requests of a terminal otherwise than asm-generic")
	}
	for _, n := range hostNumberTable(hostNumberFamilyIoctl) {
		if want, ok := terminalRequestsByName[n.name]; ok && n.value != int64(want) {
			t.Errorf("%s = %#x, want %#x", n.name, n.value, want)
		}
	}
}
