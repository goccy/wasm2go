//go:build linux

package codegen

// The requests of a terminal on linux (see "terminals" in wasip1_native.go).

import (
	"syscall"
	"unsafe"
)

// hostGenericTerminal reports whether this architecture numbers the
// requests of a terminal and lays out what they take as asm-generic does,
// as the guest does. The others (mips, powerpc) have numbers and layouts of
// their own, under which the guest's would mean something else, so no
// descriptor is a terminal to the guest there (hostTerminal).
const hostGenericTerminal = syscall.TCGETS == linuxTCGETS

// hostTerminal is isatty(3) of the open descriptor fd: a terminal answers
// the request for its settings.
func hostTerminal(fd int) bool {
	if !hostGenericTerminal {
		return false
	}
	var settings linuxTermios
	_, err := hostIoctlPointer(fd, linuxTCGETS, unsafe.Pointer(&settings))
	return err == nil
}

// hostTerminalIoctl makes the request of the terminal fd with arg. The
// host's numbers and layouts are the guest's here (hostGenericTerminal):
// the request is made as it is, with the int or the record it takes.
// darwin's requests of a pseudo-terminal are none of Linux's.
func hostTerminalIoctl(fd int, request uint32, arg *terminalArg) (int, error) {
	switch request {
	case darwinTIOCPTYGRANT, darwinTIOCPTYUNLK, darwinTIOCPTYGNAME:
		return 0, syscall.ENOTTY
	}
	switch arg.what {
	case terminalTakesValue:
		return hostIoctlValue(fd, request, uintptr(arg.value))
	case terminalTakesInt:
		return hostIoctlPointer(fd, request, unsafe.Pointer(&arg.value))
	case terminalTakesTermios, terminalTakesTermios2:
		return hostIoctlPointer(fd, request, unsafe.Pointer(&arg.termios))
	case terminalTakesWinsize:
		return hostIoctlPointer(fd, request, unsafe.Pointer(&arg.winsize))
	}
	return hostIoctlValue(fd, request, 0)
}
