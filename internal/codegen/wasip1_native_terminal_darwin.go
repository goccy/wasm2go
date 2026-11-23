//go:build darwin

package codegen

// The requests of a terminal on darwin (see "terminals" in
// wasip1_native.go): each request of the guest becomes the request of
// darwin that does what it does, and struct termios is moved between the
// guest's numbers and darwin's by the tables below. darwin's numbers are
// those of its sys/termios.h, sys/ttycom.h and sys/filio.h.

import (
	"slices"
	"syscall"
	"time"
	"unsafe"
)

// hostTerminal is isatty(3) of the open descriptor fd, which asks the
// device for its type here (FIODTYPE): the master side of a pseudo-terminal
// is a terminal to it before it answers a request for terminal settings. A
// device refuses the request when it has no type to tell (ENOTTY,
// EOPNOTSUPP, ENXIO or ENODEV, as its driver answers what it does not
// know), which is no terminal.
func hostTerminal(fd int) bool {
	const (
		deviceType     = 0x4004667a // FIODTYPE
		deviceTerminal = 3          // D_TTY
	)
	var kind int32
	_, err := hostIoctlPointer(fd, deviceType, unsafe.Pointer(&kind))
	return err == nil && kind == deviceTerminal
}

// terminalFlag is one value of a field of a flag word of struct termios,
// in the guest's numbers and in the host's (QEMU's bitmask_transtbl): the
// guest's bits under guestMask are guestBits where the host's under
// hostMask are hostBits. A flag of one bit has it for mask and bits.
type terminalFlag struct {
	guestMask, guestBits uint32
	hostMask, hostBits   uint64
}

// The values of the fields of the flag words that both numberings have. A
// bit the guest has and the host has not (IUCLC, OLCUC, CMSPAR, XCASE) is
// none of the host's; the bits of the host the guest has no name for
// (ONOEOT, the flow controls of the modem lines, ALTWERASE, NOKERNINFO) are
// kept as the terminal has them when the guest sets the settings.
var (
	hostInputFlags = []terminalFlag{
		{0x1, 0x1, 0x1, 0x1},             // IGNBRK
		{0x2, 0x2, 0x2, 0x2},             // BRKINT
		{0x4, 0x4, 0x4, 0x4},             // IGNPAR
		{0x8, 0x8, 0x8, 0x8},             // PARMRK
		{0x10, 0x10, 0x10, 0x10},         // INPCK
		{0x20, 0x20, 0x20, 0x20},         // ISTRIP
		{0x40, 0x40, 0x40, 0x40},         // INLCR
		{0x80, 0x80, 0x80, 0x80},         // IGNCR
		{0x100, 0x100, 0x100, 0x100},     // ICRNL
		{0x400, 0x400, 0x200, 0x200},     // IXON
		{0x800, 0x800, 0x800, 0x800},     // IXANY
		{0x1000, 0x1000, 0x400, 0x400},   // IXOFF
		{0x2000, 0x2000, 0x2000, 0x2000}, // IMAXBEL
		{0x4000, 0x4000, 0x4000, 0x4000}, // IUTF8
	}
	hostOutputFlags = []terminalFlag{
		{0x1, 0x1, 0x1, 0x1},               // OPOST
		{0x4, 0x4, 0x2, 0x2},               // ONLCR
		{0x8, 0x8, 0x10, 0x10},             // OCRNL
		{0x10, 0x10, 0x20, 0x20},           // ONOCR
		{0x20, 0x20, 0x40, 0x40},           // ONLRET
		{0x40, 0x40, 0x80, 0x80},           // OFILL
		{0x80, 0x80, 0x20000, 0x20000},     // OFDEL
		{0x100, 0x0, 0x300, 0x0},           // NLDLY: NL0
		{0x100, 0x100, 0x300, 0x100},       // NL1
		{0x600, 0x0, 0x3000, 0x0},          // CRDLY: CR0
		{0x600, 0x200, 0x3000, 0x1000},     // CR1
		{0x600, 0x400, 0x3000, 0x2000},     // CR2
		{0x600, 0x600, 0x3000, 0x3000},     // CR3
		{0x1800, 0x0, 0xc04, 0x0},          // TABDLY: TAB0
		{0x1800, 0x800, 0xc04, 0x400},      // TAB1
		{0x1800, 0x1000, 0xc04, 0x800},     // TAB2
		{0x1800, 0x1800, 0xc04, 0x4},       // TAB3, which is OXTABS here
		{0x2000, 0x2000, 0x8000, 0x8000},   // BSDLY: BS1
		{0x4000, 0x4000, 0x10000, 0x10000}, // VTDLY: VT1
		{0x8000, 0x8000, 0x4000, 0x4000},   // FFDLY: FF1
	}
	hostControlFlags = []terminalFlag{
		{0x30, 0x0, 0x300, 0x0},                    // CSIZE: CS5
		{0x30, 0x10, 0x300, 0x100},                 // CS6
		{0x30, 0x20, 0x300, 0x200},                 // CS7
		{0x30, 0x30, 0x300, 0x300},                 // CS8
		{0x40, 0x40, 0x400, 0x400},                 // CSTOPB
		{0x80, 0x80, 0x800, 0x800},                 // CREAD
		{0x100, 0x100, 0x1000, 0x1000},             // PARENB
		{0x200, 0x200, 0x2000, 0x2000},             // PARODD
		{0x400, 0x400, 0x4000, 0x4000},             // HUPCL
		{0x800, 0x800, 0x8000, 0x8000},             // CLOCAL
		{0x80000000, 0x80000000, 0x30000, 0x30000}, // CRTSCTS: CCTS_OFLOW|CRTS_IFLOW
	}
	hostLocalFlags = []terminalFlag{
		{0x1, 0x1, 0x80, 0x80},                   // ISIG
		{0x2, 0x2, 0x100, 0x100},                 // ICANON
		{0x8, 0x8, 0x8, 0x8},                     // ECHO
		{0x10, 0x10, 0x2, 0x2},                   // ECHOE
		{0x20, 0x20, 0x4, 0x4},                   // ECHOK
		{0x40, 0x40, 0x10, 0x10},                 // ECHONL
		{0x80, 0x80, 0x80000000, 0x80000000},     // NOFLSH
		{0x100, 0x100, 0x400000, 0x400000},       // TOSTOP
		{0x200, 0x200, 0x40, 0x40},               // ECHOCTL
		{0x400, 0x400, 0x20, 0x20},               // ECHOPRT
		{0x800, 0x800, 0x1, 0x1},                 // ECHOKE
		{0x1000, 0x1000, 0x800000, 0x800000},     // FLUSHO
		{0x4000, 0x4000, 0x20000000, 0x20000000}, // PENDIN
		{0x8000, 0x8000, 0x400, 0x400},           // IEXTEN
		{0x10000, 0x10000, 0x800, 0x800},         // EXTPROC
	}
)

// hostControlChars holds, at the guest's place of each control character
// of c_cc, the host's place of it: VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME,
// VMIN, VSWTC, VSTART, VSTOP, VSUSP, VEOL, VREPRINT, VDISCARD, VWERASE,
// VLNEXT, VEOL2, and two places the guest does not use. VSWTC, which the
// host has not, and the places not used are -1.
var hostControlChars = [linuxNCCS]int{8, 9, 3, 5, 0, 17, 16, -1, 12, 13, 10, 1, 6, 15, 4, 14, 2, -1, -1}

// The places of c_cc that hold numbers rather than characters, the host's
// VTIME and VMIN, and the value of a character that is disabled, the
// host's _POSIX_VDISABLE (the guest's is 0).
const (
	hostVTIME         = 17
	hostVMIN          = 16
	hostVDISABLE byte = 0xff
)

// The guest's bits of c_cflag that hold the output speed (CBAUD) and the
// input speed (CIBAUD, the same bits IBSHIFT up), and the speed whose
// number is the one of struct termios2 (BOTHER).
const (
	linuxCBAUD   = 0x100f
	linuxIBSHIFT = 16
	linuxBOTHER  = 0x1000
)

// linuxSpeeds are the guest's speeds of c_cflag (CBAUD) and the speeds in
// bits per second they stand for, which are the host's speeds.
var linuxSpeeds = []struct {
	code  uint32
	speed uint64
}{
	{0x0, 0}, {0x1, 50}, {0x2, 75}, {0x3, 110}, {0x4, 134}, {0x5, 150},
	{0x6, 200}, {0x7, 300}, {0x8, 600}, {0x9, 1200}, {0xa, 1800},
	{0xb, 2400}, {0xc, 4800}, {0xd, 9600}, {0xe, 19200}, {0xf, 38400},
	{0x1001, 57600}, {0x1002, 115200}, {0x1003, 230400}, {0x1004, 460800},
	{0x1005, 500000}, {0x1006, 576000}, {0x1007, 921600},
	{0x1008, 1000000}, {0x1009, 1152000}, {0x100a, 1500000},
	{0x100b, 2000000}, {0x100c, 2500000}, {0x100d, 3000000},
	{0x100e, 3500000}, {0x100f, 4000000},
}

// linuxSpeedCode returns the guest's code of speed (linuxSpeeds), BOTHER
// for one that has none.
func linuxSpeedCode(speed uint64) uint32 {
	i := slices.IndexFunc(linuxSpeeds, func(s struct {
		code  uint32
		speed uint64
	}) bool {
		return s.speed == speed
	})
	if i < 0 {
		return linuxBOTHER
	}
	return linuxSpeeds[i].code
}

// linuxSpeedOf returns the speed of the guest's code (linuxSpeeds), and
// whether it stands for one: BOTHER, the speed of struct termios2, does
// not.
func linuxSpeedOf(code uint32) (uint64, bool) {
	i := slices.IndexFunc(linuxSpeeds, func(s struct {
		code  uint32
		speed uint64
	}) bool {
		return s.code == code
	})
	if i < 0 {
		return 0, false
	}
	return linuxSpeeds[i].speed, true
}

// guestFlags returns the guest's flag word of the host's flags.
func guestFlags(table []terminalFlag, flags uint64) uint32 {
	var guest uint32
	for _, f := range table {
		if flags&f.hostMask == f.hostBits {
			guest |= f.guestBits
		}
	}
	return guest
}

// hostFlags returns the host's flags with the fields of table set as the
// guest's flag word has them, and the host's other bits as they are.
func hostFlags(table []terminalFlag, flags uint64, guest uint32) uint64 {
	for _, f := range table {
		flags &^= f.hostMask
	}
	for _, f := range table {
		if guest&f.guestMask == f.guestBits {
			flags |= f.hostBits
		}
	}
	return flags
}

// guestTermios returns the host's settings h in the guest's numbers. The
// output speed is in c_cflag (CBAUD), BOTHER when it has no code there,
// and so is the input speed when it differs (CIBAUD); both are in the
// speeds of struct termios2. There is no line discipline to tell (c_line
// is N_TTY, 0).
func guestTermios(h *syscall.Termios) linuxTermios {
	t := linuxTermios{
		Iflag:  guestFlags(hostInputFlags, h.Iflag),
		Oflag:  guestFlags(hostOutputFlags, h.Oflag),
		Cflag:  guestFlags(hostControlFlags, h.Cflag) | linuxSpeedCode(h.Ospeed),
		Lflag:  guestFlags(hostLocalFlags, h.Lflag),
		Ispeed: uint32(h.Ispeed),
		Ospeed: uint32(h.Ospeed),
	}
	if h.Ispeed != h.Ospeed {
		t.Cflag |= linuxSpeedCode(h.Ispeed) << linuxIBSHIFT
	}
	for guest, host := range hostControlChars {
		if host < 0 {
			continue
		}
		c := h.Cc[host]
		if c == hostVDISABLE && host != hostVTIME && host != hostVMIN {
			c = 0
		}
		t.Cc[guest] = c
	}
	return t
}

// setHostTermios changes the host's settings h to the guest's t. The
// speeds of struct termios2 are taken for BOTHER when exact is set (a
// request of termios2); otherwise BOTHER keeps the speed the terminal has,
// as the kernel keeps the speeds of a struct termios, which has none. An
// input speed of B0 is the output speed.
func setHostTermios(h *syscall.Termios, t *linuxTermios, exact bool) {
	h.Iflag = hostFlags(hostInputFlags, h.Iflag, t.Iflag)
	h.Oflag = hostFlags(hostOutputFlags, h.Oflag, t.Oflag)
	h.Cflag = hostFlags(hostControlFlags, h.Cflag, t.Cflag)
	h.Lflag = hostFlags(hostLocalFlags, h.Lflag, t.Lflag)
	if speed, ok := linuxSpeedOf(t.Cflag & linuxCBAUD); ok {
		h.Ospeed = speed
	} else if exact {
		h.Ospeed = uint64(t.Ospeed)
	}
	if code := t.Cflag >> linuxIBSHIFT & linuxCBAUD; code == 0 {
		h.Ispeed = h.Ospeed
	} else if speed, ok := linuxSpeedOf(code); ok {
		h.Ispeed = speed
	} else if exact {
		h.Ispeed = uint64(t.Ispeed)
	}
	for guest, host := range hostControlChars {
		if host < 0 {
			continue
		}
		c := t.Cc[guest]
		if c == 0 && host != hostVTIME && host != hostVMIN {
			c = hostVDISABLE
		}
		h.Cc[host] = c
	}
}

// hostTerminalIoctl makes the guest's request of the terminal fd, with
// arg, as the request of the host that does what it does.
func hostTerminalIoctl(fd int, request uint32, arg *terminalArg) (int, error) {
	switch request {
	case linuxTCGETS, linuxTCGETS2:
		var h syscall.Termios
		if _, err := hostIoctlPointer(fd, syscall.TIOCGETA, unsafe.Pointer(&h)); err != nil {
			return 0, err
		}
		arg.termios = guestTermios(&h)
		return 0, nil
	case linuxTCSETS, linuxTCSETS2:
		return hostTerminalSettings(fd, syscall.TIOCSETA, arg)
	case linuxTCSETSW, linuxTCSETSW2:
		return hostTerminalSettings(fd, syscall.TIOCSETAW, arg)
	case linuxTCSETSF, linuxTCSETSF2:
		return hostTerminalSettings(fd, syscall.TIOCSETAF, arg)
	case linuxTCSBRK:
		return 0, hostTerminalBreak(fd, arg.value)
	case linuxTCXONC:
		return 0, hostTerminalFlow(fd, arg.value)
	case linuxTCFLSH:
		return 0, hostTerminalFlush(fd, arg.value)
	case linuxTIOCEXCL:
		return hostIoctlValue(fd, syscall.TIOCEXCL, 0)
	case linuxTIOCNXCL:
		return hostIoctlValue(fd, syscall.TIOCNXCL, 0)
	case linuxTIOCOUTQ:
		return hostIoctlPointer(fd, syscall.TIOCOUTQ, unsafe.Pointer(&arg.value))
	case linuxTIOCGPGRP:
		return hostIoctlPointer(fd, syscall.TIOCGPGRP, unsafe.Pointer(&arg.value))
	case linuxTIOCGSID:
		return 0, hostTerminalSession(fd, &arg.value)
	case linuxTIOCGWINSZ:
		// struct winsize is the same here.
		return hostIoctlPointer(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&arg.winsize))
	case linuxTIOCSWINSZ:
		return hostIoctlPointer(fd, syscall.TIOCSWINSZ, unsafe.Pointer(&arg.winsize))
	case darwinTIOCPTYGRANT, darwinTIOCPTYUNLK:
		return hostIoctlValue(fd, request, 0)
	case darwinTIOCPTYGNAME:
		return hostIoctlPointer(fd, request, unsafe.Pointer(&arg.name))
	}
	// The name of a pseudo-terminal's slave side is no /dev/pts/N here,
	// which is all TIOCGPTN can tell.
	return 0, syscall.ENOTTY
}

// hostTerminalSettings sets the settings of the terminal fd to arg's with
// the host's request set (TIOCSETA, TIOCSETAW or TIOCSETAF), from the
// settings it has (setHostTermios).
func hostTerminalSettings(fd int, set uint32, arg *terminalArg) (int, error) {
	var h syscall.Termios
	if _, err := hostIoctlPointer(fd, syscall.TIOCGETA, unsafe.Pointer(&h)); err != nil {
		return 0, err
	}
	setHostTermios(&h, &arg.termios, arg.what == terminalTakesTermios2)
	return hostIoctlPointer(fd, set, unsafe.Pointer(&h))
}

// hostTerminalFlush is TCFLSH: the queues are named as open(2)'s FREAD and
// FWRITE here.
func hostTerminalFlush(fd int, queue int32) error {
	const read, write = 0x1, 0x2
	var which int32
	switch queue {
	case 0: // TCIFLUSH
		which = read
	case 1: // TCOFLUSH
		which = write
	case 2: // TCIOFLUSH
		which = read | write
	default:
		return syscall.EINVAL
	}
	_, err := hostIoctlPointer(fd, syscall.TIOCFLUSH, unsafe.Pointer(&which))
	return err
}

// hostTerminalBreak is TCSBRK: with duration 0 a break, for 0.4 seconds as
// the C library's tcsendbreak makes it (FreeBSD lib/libc/gen/termios.c);
// otherwise tcdrain.
func hostTerminalBreak(fd int, duration int32) error {
	if duration != 0 {
		_, err := hostIoctlValue(fd, syscall.TIOCDRAIN, 0)
		return err
	}
	if _, err := hostIoctlValue(fd, syscall.TIOCSBRK, 0); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	_, err := hostIoctlValue(fd, syscall.TIOCCBRK, 0)
	return err
}

// hostTerminalFlow is TCXONC: TCOOFF and TCOON stop and restart the
// output; TCIOFF and TCION send the terminal's STOP and START character,
// unless it is disabled, as the C library's tcflow does.
func hostTerminalFlow(fd int, action int32) error {
	switch action {
	case 0: // TCOOFF
		_, err := hostIoctlValue(fd, syscall.TIOCSTOP, 0)
		return err
	case 1: // TCOON
		_, err := hostIoctlValue(fd, syscall.TIOCSTART, 0)
		return err
	case 2, 3: // TCIOFF, TCION
		var h syscall.Termios
		if _, err := hostIoctlPointer(fd, syscall.TIOCGETA, unsafe.Pointer(&h)); err != nil {
			return err
		}
		c := h.Cc[syscall.VSTOP]
		if action == 3 {
			c = h.Cc[syscall.VSTART]
		}
		if c == hostVDISABLE {
			return nil
		}
		for {
			_, err := syscall.Write(fd, []byte{c})
			if err != syscall.EINTR {
				return err
			}
		}
	}
	return syscall.EINVAL
}

// hostTerminalSession is TIOCGSID, which darwin has no request for: a
// terminal is the process's controlling terminal when it tells the process
// its foreground process group (TIOCGPGRP, which is ENOTTY for any other
// terminal, as TIOCGSID is on Linux), and its session is the process's.
func hostTerminalSession(fd int, sid *int32) error {
	var pgrp int32
	if _, err := hostIoctlPointer(fd, syscall.TIOCGPGRP, unsafe.Pointer(&pgrp)); err != nil {
		return err
	}
	s, err := syscall.Getsid(0)
	*sid = int32(s)
	return err
}
