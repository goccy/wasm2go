//go:build darwin

package codegen

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atimespec.Unix()), time.Unix(st.Ctimespec.Unix())
}

// hostSignalByNumber returns the host's signal for a guest signal number
// the table of hostSignals does not name: on this system, none.
func hostSignalByNumber(sig int32) (hostSig syscall.Signal, known bool) {
	return 0, false
}

// lstatAt would describe name in the directory open as dir; package
// syscall has no call relative to a directory descriptor on this system,
// and a path of the host is not looked up instead. osFileDirents records
// the type of every name, so the listing never asks.
func lstatAt(dir *os.File, name string) (os.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstatat", Path: name, Err: errors.ErrUnsupported}
}

// chmodRefused reports whether err is chmod(2)'s refusal of a mode bit to
// this user or this file: EPERM, or EFTYPE for a sticky bit of a file that
// is no directory.
func chmodRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EFTYPE)
}

// hostFDLink reports that the host has no link for descriptor fd of the
// host process: /dev/fd/N of this system is no link.
func hostFDLink(fd uintptr) (string, bool, error) { return "", false, nil }

// readHostUmask returns the file mode creation mask of the host process,
// which this system has no way to read without changing it:
// errors.ErrUnsupported.
func readHostUmask() (os.FileMode, error) {
	return 0, fmt.Errorf("the umask of the host process cannot be read without changing it: %w", errors.ErrUnsupported)
}

// osFileDirents returns the names in the directory open as d: "." and
// "..", then the names in the order the system gives them, which ReadDir
// keeps. ReadDir reads through the descriptor itself, so a directory that
// may be read but not searched lists; syscall.ReadDirent opens "." in the
// directory on this system.
func osFileDirents(d *os.File) ([]hostName, error) {
	if _, err := d.Seek(0, 0); err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]hostName, 0, len(entries)+2)
	names = append(names, hostName{name: ".", typ: syscall.DT_DIR}, hostName{name: "..", typ: syscall.DT_DIR})
	for _, e := range entries {
		// The values of d_type are the file type bits of a mode, shifted.
		names = append(names, hostName{name: e.Name(), typ: uint8(unixTypeBits(e.Type()) >> 12)})
	}
	return names, nil
}

// hostPollReportsFIFOEnd says that poll(2) here reports neither POLLIN nor
// POLLHUP on a FIFO with a name whose last writer has closed it: a read of
// one finds its end.
const hostPollReportsFIFOEnd = false

// hostSendsWithoutWaiting says that a send to a socket here waits for room
// in a socket in blocking mode whatever MSG_DONTWAIT says (an AF_UNIX
// stream's does).
const hostSendsWithoutWaiting = false

// hostPipeBuf is PIPE_BUF: a pipe that poll(2) reports writable takes that
// much without waiting.
const hostPipeBuf = 512

// The numbers of recvmsg(2) and sendmsg(2).
const (
	hostSysRecvmsg = syscall.SYS_RECVMSG
	hostSysSendmsg = syscall.SYS_SENDMSG
)

// hostWakePipe makes a pipe whose ends do not wait and are closed on exec:
// a wait in poll(2) watches its read end, and a byte written to the other
// end (hostWakeWrite) ends the wait. (os.Pipe hands the ends to the
// poller of the Go runtime, whose Write waits when the pipe is full.)
func hostWakePipe() (r, w int, err error) {
	var p [2]int
	syscall.ForkLock.RLock()
	err = syscall.Pipe(p[:])
	if err == nil {
		syscall.CloseOnExec(p[0])
		syscall.CloseOnExec(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, -1, os.NewSyscallError("pipe", err)
	}
	for _, fd := range p {
		if err := syscall.SetNonblock(fd, true); err != nil {
			return -1, -1, errors.Join(os.NewSyscallError("fcntl", err), hostCloseFD(p[0]), hostCloseFD(p[1]))
		}
	}
	return p[0], p[1], nil
}

// hostPollCall is poll(2): it waits no longer than timeout, and without
// limit when timeout is negative.
func hostPollCall(fds []hostPoll, timeout time.Duration) (int, syscall.Errno) {
	ms := -1
	if timeout >= 0 {
		// poll(2) takes an int of milliseconds; a longer wait ends early,
		// and the caller waits again.
		ms = int(min((timeout+time.Millisecond-1)/time.Millisecond, math.MaxInt32))
	}
	var first *hostPoll
	if len(fds) > 0 {
		first = &fds[0]
	}
	n, _, errno := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(first)), uintptr(len(fds)), uintptr(ms))
	return int(n), errno
}
