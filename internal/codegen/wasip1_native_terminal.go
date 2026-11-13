//go:build darwin || linux

package codegen

// Terminals, for a guest whose descriptors are the host process's: the
// settings of a terminal (struct termios), the requests a program makes of
// one with ioctl, and the controlling terminal.
//
// The numbers in all of it are the host's: the bits of the flag words, the
// places of the control characters, the speeds, the requests. A guest that
// is the host process shows its program the host's numbers (the termios
// family of the number tables), and what it hands on is what the program
// made of them; the record below carries them between the two as they are.
// A guest with descriptors of its own has no terminal of the host's among
// them.

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// The record of a terminal's settings in the guest's memory: struct termios
// of the guest's C library, by field. The flag words and the speeds are 32
// bits there, and there is room for 32 control characters; the host's fit
// on every system this file is built for.
const (
	guestTermiosIflag  = 0
	guestTermiosOflag  = 4
	guestTermiosCflag  = 8
	guestTermiosLflag  = 12
	guestTermiosLine   = 16
	guestTermiosCc     = 17
	guestTermiosNCCS   = 32
	guestTermiosIspeed = 52
	guestTermiosOspeed = 56
	guestTermiosSize   = 60
)

// hostIoctlBuffer is ioctl(2) with a buffer for the request to read and
// write; it returns what the call returned.
func hostIoctlBuffer(fd int, request uint32, buf []byte) (int, error) {
	if len(buf) == 0 {
		return -1, syscall.EFAULT
	}
	for {
		r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(&buf[0])))
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return -1, errno
		}
		return int(r), nil
	}
}

// hostIoctlValue is ioctl(2) with a number for an argument.
func hostIoctlValue(fd int, request uint32, value uintptr) (int, error) {
	for {
		r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), value)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return -1, errno
		}
		return int(r), nil
	}
}

// hostTerminalGroup is tcgetpgrp(3): the process group in the foreground of
// the terminal.
func hostTerminalGroup(fd int) (int, error) {
	var pgrp [4]byte
	if _, err := hostIoctlBuffer(fd, syscall.TIOCGPGRP, pgrp[:]); err != nil {
		return -1, err
	}
	return int(int32(binary.NativeEndian.Uint32(pgrp[:]))), nil
}

// setHostTerminalGroup is tcsetpgrp(3).
func setHostTerminalGroup(fd, pgrp int) error {
	var buf [4]byte
	binary.NativeEndian.PutUint32(buf[:], uint32(int32(pgrp)))
	_, err := hostIoctlBuffer(fd, syscall.TIOCSPGRP, buf[:])
	return err
}

// The two requests about the controlling terminal that a process forked
// within the runtime cannot make of the host: see controlTerminal.
const (
	hostTakeTerminal  = syscall.TIOCSCTTY
	hostLeaveTerminal = syscall.TIOCNOTTY
)

// hostTerminalIdentity returns what tells the terminal descriptor fd is
// open on from another: the device it is (st_rdev). ok is false for a
// descriptor that is no character device.
func hostTerminalIdentity(fd int) (device uint64, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFCHR {
		return 0, false
	}
	return uint64(st.Rdev), true
}

// commandTerminal returns what a command needs to be started as the leader
// of a session with the terminal at path for its controlling terminal:
// the attributes for the host, with the number of one of the command's own
// descriptors that is open on that terminal. files are the command's
// descriptors in order, nil for one it does not get. Without a path, or
// when none of the descriptors is open on the terminal, the command leads
// its session without a controlling terminal: there is no descriptor to
// take one through.
func commandTerminal(path string, files []any) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setsid: true}
	if path == "" {
		return attr
	}
	var want syscall.Stat_t
	if err := syscall.Stat(path, &want); err != nil {
		return attr
	}
	for number, file := range files {
		f, isFile := file.(interface{ Fd() uintptr })
		if !isFile || f == nil {
			continue
		}
		if device, ok := hostTerminalIdentity(int(f.Fd())); ok && device == uint64(want.Rdev) {
			attr.Setctty, attr.Ctty = true, number
			break
		}
	}
	return attr
}

// heldHostDescriptor returns the descriptor of the host process that fd of
// the guest is, held for a call of the host's on it: the caller releases h.
// A descriptor that is not the host's is no terminal of the host's
// (ENOTTY).
func (w *WasiStubs) heldHostDescriptor(fd int32) (h *hostFile, number int, errno int32) {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return nil, -1, _wasiEBADF
	}
	if h = op.host(); h == nil {
		return nil, -1, _wasiENOTTY
	}
	number, err := h.hold()
	if err != nil {
		return nil, -1, _wasiEBADF
	}
	return h, number, _wasiESUCCESS
}

// Tty_getattr is a NON-STANDARD host import (name "tty_getattr") backing
// tcgetattr: the settings of the terminal fd are written at recordPtr, as
// struct termios of the guest's C library, in the host's numbers. Returns 0
// or a negative errno: ENOTTY for a descriptor that is no terminal.
func (w *WasiStubs) Tty_getattr(m *Module, fd, recordPtr int32) int32 {
	record := w.memSlice(m, recordPtr, guestTermiosSize)
	if record == nil {
		return -_wasiEFAULT
	}
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if err := hostTerminalAttributes(number, record); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Tty_name is a NON-STANDARD host import (name "tty_name") backing ttyname:
// the path of the terminal fd is written at bufPtr, which holds bufLen
// bytes, and its length at lenPtr (u32) — also when it does not fit, which
// is -ERANGE. Returns 0 or a negative errno: ENOTTY for a descriptor that is
// no terminal, ENODEV for a terminal the host has no name for.
func (w *WasiStubs) Tty_name(m *Module, fd, bufPtr, bufLen, lenPtr int32) int32 {
	buf := w.memSlice(m, bufPtr, bufLen)
	length := w.memSlice(m, lenPtr, 4)
	if buf == nil || length == nil {
		return -_wasiEFAULT
	}
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if !hostTerminal(number) {
		return -_wasiENOTTY
	}
	path, ok := hostDescriptorPath(number)
	if !ok {
		return -_wasiENODEV
	}
	binary.LittleEndian.PutUint32(length, uint32(len(path)))
	if len(path) > len(buf) {
		return -_wasiERANGE
	}
	copy(buf, path)
	return _wasiESUCCESS
}

// Tty_setattr is a NON-STANDARD host import (name "tty_setattr") backing
// tcsetattr: the terminal fd gets the settings at recordPtr, at the time
// actions says (the host's TCSANOW, TCSADRAIN or TCSAFLUSH). Returns 0 or a
// negative errno.
func (w *WasiStubs) Tty_setattr(m *Module, fd, actions, recordPtr int32) int32 {
	record := w.memSlice(m, recordPtr, guestTermiosSize)
	if record == nil {
		return -_wasiEFAULT
	}
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if err := setHostTerminalAttributes(number, actions, record); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Tty_speed is a NON-STANDARD host import (name "tty_speed") backing
// cfgetispeed, cfgetospeed, cfsetispeed and cfsetospeed: where the speed of
// a terminal is kept in its settings is the host's own. The input speed
// (output 0) or the output speed of the settings at recordPtr is written at
// outPtr (u32) as it was; with set non-zero it then becomes speed. Returns
// 0 or a negative errno: EINVAL for a speed the host has no such number
// for.
func (w *WasiStubs) Tty_speed(m *Module, recordPtr, output, set, speed, outPtr int32) int32 {
	record := w.memSlice(m, recordPtr, guestTermiosSize)
	out := w.memSlice(m, outPtr, 4)
	if record == nil || out == nil {
		return -_wasiEFAULT
	}
	binary.LittleEndian.PutUint32(out, hostTerminalSpeed(record, output != 0))
	if set != 0 {
		if err := setHostTerminalSpeed(record, output != 0, uint32(speed)); err != nil {
			return -mapOSError(err)
		}
	}
	return _wasiESUCCESS
}

// Tty_control is a NON-STANDARD host import (name "tty_control") backing
// tcdrain, tcflow, tcflush and tcsendbreak (what 0, 1, 2, 3): arg is the
// action of tcflow and the queue of tcflush in the host's numbers, and the
// duration of tcsendbreak. Returns 0 or a negative errno.
func (w *WasiStubs) Tty_control(m *Module, fd, what, arg int32) int32 {
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if err := hostTerminalControl(number, what, arg); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Tty_pgrp is a NON-STANDARD host import (name "tty_pgrp") backing
// tcgetpgrp and tcsetpgrp: the process group in the foreground of the
// terminal fd is written at outPtr (u32); with set non-zero it then becomes
// pgrp. Returns 0 or a negative errno. A process forked within the runtime
// is refused (ENOSYS): the groups of such processes are the runtime's, and
// a terminal's foreground group is a group of the host.
func (w *WasiStubs) Tty_pgrp(m *Module, fd, set, pgrp, outPtr int32) int32 {
	out := w.memSlice(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if w.forked {
		return -_wasiENOSYS
	}
	group, err := hostTerminalGroup(number)
	if err != nil {
		return -mapOSError(err)
	}
	binary.LittleEndian.PutUint32(out, uint32(int32(group)))
	if set != 0 {
		if err := setHostTerminalGroup(number, int(pgrp)); err != nil {
			return -mapOSError(err)
		}
	}
	return _wasiESUCCESS
}

// Fd_ioctl is a NON-STANDARD host import (name "fd_ioctl") backing ioctl
// for the requests of a terminal (window size, controlling terminal, modem
// lines, ...), which the guest's C library does not answer. request is the
// host's number. The argument is a number (buffer 0: arg is it) or memory
// the request reads and writes (buffer non-zero: argLen bytes at arg, at
// least what the request takes); what a request reads and writes there is
// in the host's layout. What the call returned is written at resultPtr
// (i32). Returns 0 or a negative errno: EINVAL for a request that is not
// one of a terminal's, ENOTTY for a descriptor that is not the host's.
//
// The memory is the guest's, so a request whose argument holds pointers
// cannot be passed on; no request of a terminal's does.
func (w *WasiStubs) Fd_ioctl(m *Module, fd, request, buffer, arg, argLen, resultPtr int32) int32 {
	result := w.memSlice(m, resultPtr, 4)
	if result == nil {
		return -_wasiEFAULT
	}
	req := uint32(request)
	if !hostTerminalRequest(req) {
		return -_wasiEINVAL
	}
	h, number, errno := w.heldHostDescriptor(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	defer h.release()
	if w.forked && (req == hostTakeTerminal || req == hostLeaveTerminal) {
		if errno := w.controlTerminal(number, req == hostTakeTerminal); errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(result, 0)
		return _wasiESUCCESS
	}
	var returned int
	var err error
	if buffer != 0 {
		buf := w.memSlice(m, arg, argLen)
		if buf == nil {
			return -_wasiEFAULT
		}
		if len(buf) < hostIoctlRoom(req) {
			return -_wasiEINVAL
		}
		returned, err = hostIoctlBuffer(number, req, buf)
	} else {
		returned, err = hostIoctlValue(number, req, uintptr(int(arg)))
	}
	if err != nil {
		return -mapOSError(err)
	}
	binary.LittleEndian.PutUint32(result, uint32(int32(returned)))
	return _wasiESUCCESS
}

// controlTerminal is TIOCSCTTY (take) and TIOCNOTTY for a process forked
// within the runtime. The host keeps one controlling terminal for the
// whole host process, so such a process cannot change its own there
// without changing everyone's; the runtime keeps it instead (see
// WasiStubs.terminal): the process opens it as /dev/tty, and a command it
// becomes (exec) is started with it for real. Returns a wasi errno: ENOTTY
// for a descriptor that is no terminal, EPERM for a process that does not
// lead a session or has a controlling terminal already.
func (w *WasiStubs) controlTerminal(fd int, take bool) int32 {
	if !hostTerminal(fd) {
		return _wasiENOTTY
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !take {
		none := ""
		w.terminal = &none
		return _wasiESUCCESS
	}
	// Asked of the master side of a pseudo-terminal, it is the terminal
	// that is taken.
	path, ok := hostTerminalOfMaster(fd)
	if !ok {
		path, ok = hostDescriptorPath(fd)
	}
	if !ok {
		return _wasiENOTTY
	}
	if !w.sessionLeader || w.terminal == nil || (*w.terminal != "" && *w.terminal != path) {
		return _wasiEPERM
	}
	w.terminal = &path
	return _wasiESUCCESS
}

// hostOpenNoTerminal is the flag of open(2) that keeps a terminal from
// becoming the controlling terminal of the process that opens it.
const hostOpenNoTerminal = syscall.O_NOCTTY

// takeOpenedTerminalLocked gives a forked process the terminal it has just
// opened for its controlling terminal, where the host does that for a
// process of its own: one that leads a session and has none yet. (The
// host was asked not to: see pathOpenMode.) Caller holds w.mu.
func (w *WasiStubs) takeOpenedTerminalLocked(op *wasiOpen) {
	if !hostOpenTakesTerminal || !w.forked || !w.sessionLeader || w.terminal == nil || *w.terminal != "" {
		return
	}
	h := op.host()
	if h == nil || !h.terminal() {
		return
	}
	fd, err := h.hold()
	if err != nil {
		return
	}
	defer h.release()
	if _, master := hostTerminalOfMaster(fd); master {
		return
	}
	if path, ok := hostDescriptorPath(fd); ok {
		w.terminal = &path
	}
}
