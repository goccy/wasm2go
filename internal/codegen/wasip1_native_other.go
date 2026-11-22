//go:build !darwin && !linux

package codegen

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

// hostSetUmask: this platform has no umask(2) the runtime can set.
func hostSetUmask(mask os.FileMode) (os.FileMode, error) { return 0, errors.ErrUnsupported }

// hostThreadUmask says that no thread here has a umask of its own.
const hostThreadUmask = false

// hostOnMainThread: no creation thread is made here.
func hostOnMainThread() bool { return false }

// hostUnshareFS: no thread here has file system attributes of its own.
func hostUnshareFS() error { return errors.ErrUnsupported }

// withHostTerminal: no file is a terminal of the host's here.
func withHostTerminal(f *os.File, use func(fd int) error) error { return syscall.ENOTTY }

// hostTerminalIoctl: no request of a terminal is made here
// (withHostTerminal).
func hostTerminalIoctl(fd int, request uint32, arg *terminalArg) (int, error) {
	return 0, syscall.ENOTTY
}

// hostSetThreadUmask: this platform has no umask.
func hostSetThreadUmask(mask os.FileMode) {}

// hostProcessTimes returns the CPU time of the host process and of its
// children, which the runtime cannot read on this platform.
func hostProcessTimes() (ProcessTimes, error) {
	return ProcessTimes{}, errors.ErrUnsupported
}

// chmodRefused reports whether err is the system's refusal of a mode bit
// to this user, EPERM.
func chmodRefused(err error) bool { return errors.Is(err, syscall.EPERM) }

// hostFDLink reports that the host has no link for descriptor fd of the
// host process: this platform names none.
func hostFDLink(fd uintptr) (string, bool, error) { return "", false, nil }

// readHostUmask returns the file mode creation mask of the host process,
// which this platform has no way to read without changing it:
// errors.ErrUnsupported.
func readHostUmask() (os.FileMode, error) {
	return 0, fmt.Errorf("the umask of the host process cannot be read without changing it: %w", errors.ErrUnsupported)
}

// clearHostNonblock would make the descriptor of f one that waits; no open
// of this platform is given O_NONBLOCK (hostONonblock).
func clearHostNonblock(f File) error { return nil }

// hostONonblock is the open flag of the host that opens a file without
// waiting. This platform's opens wait as they will: the syscall package of
// some (js, wasip1) has no such flag.
const hostONonblock = 0

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned. This platform's carries none the runtime knows how to
// read.
func osFileStat(sys any) (fileStat, bool) {
	return fileStat{}, false
}

// hostRename renames a file as os.Rename does on this platform: onto an
// existing file, it replaces the file.
func hostRename(from, to string) error { return os.Rename(from, to) }

// hostSignalOf returns the host's signal for a guest signal number. The
// runtime does not know this platform's signals, so only number 0, the
// existence probe of kill, has one.
func hostSignalOf(sig int32) (hostSig syscall.Signal, known bool) {
	return 0, sig == 0
}

// guestSignalOf returns the guest's number for a host signal, or 0 when the
// guest has none for it — always, on this platform.
func guestSignalOf(hostSig syscall.Signal) int32 {
	return 0
}

// descriptorWaits reports whether a call on the descriptor waits when there
// is nothing for it, which the runtime cannot tell on this platform.
func descriptorWaits(fd uintptr) bool { return true }

// readvRaw would read with readv(2), which the runtime cannot do on this
// platform.
func readvRaw(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// recvNow would receive from a socket without waiting, which the runtime
// cannot do on this platform.
func recvNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// sendNow would send to a socket without waiting, which the runtime cannot
// do on this platform.
func sendNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// hostSendsWithoutWaiting says nothing on this platform, which cannot send
// without waiting.
const hostSendsWithoutWaiting = false

// hostStreamSendLowat would ask a socket for its low-water mark, which the
// runtime cannot do on this platform.
func hostStreamSendLowat(fd uintptr) (int, error) { return 0, errors.ErrUnsupported }

// hostPipeBuf is PIPE_BUF as POSIX bounds it from below.
const hostPipeBuf = 512

// hostStreamWrites says whether the host can write to a stream without
// waiting in the write. The runtime does not know how on this platform, so
// writes go through the stream's own Write and wait there.
const hostStreamWrites = false

// writevRaw would write with writev(2), which the runtime cannot do on
// this platform.
func writevRaw(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// openForWriting reports whether the descriptor is open for writing, which
// the runtime cannot ask on this platform; the write tells.
func openForWriting(fd uintptr) bool { return true }

// hostPolls says that the runtime cannot wait for a descriptor in poll(2) on
// this platform: a readiness probe reads the stream instead.
const hostPolls = false

// hostPollReportsFIFOEnd says nothing on this platform, which has no
// poll(2).
const hostPollReportsFIFOEnd = false

// hostWaitReady would wait in poll(2) for descriptors to be ready, which
// the runtime cannot do on this platform.
func hostWaitReady(fds []uintptr, wants []int, ready []bool, until time.Time, wake int) error {
	return errors.ErrUnsupported
}

// hostWakePipe would make the pipe a wait in poll(2) watches, which the
// runtime cannot do on this platform.
func hostWakePipe() (r, w int, err error) { return -1, -1, errors.ErrUnsupported }

// hostWakeWrite would write to a wake pipe, which this platform has none of.
func hostWakeWrite(w int) error { return errors.ErrUnsupported }

// hostWakeDrain would read a wake pipe empty, which this platform has none
// of.
func hostWakeDrain(r int) error { return errors.ErrUnsupported }

// hostCloseFD would close a descriptor of the runtime's own, which this
// platform has none of.
func hostCloseFD(fd int) error { return errors.ErrUnsupported }

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error; on this platform the errors are told apart
// by what package os makes of them, except a few of windows.
func wasiErrno(e syscall.Errno) (int32, bool) {
	if runtime.GOOS != "windows" {
		return 0, false
	}
	// The numbers of windows' errors that package syscall does not name.
	switch e {
	case 39, 112: // ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL
		return _wasiENOSPC, true
	case 120: // ERROR_CALL_NOT_IMPLEMENTED
		return _wasiENOSYS, true
	case 131: // ERROR_NEGATIVE_SEEK
		return _wasiEINVAL, true
	case 10051: // WSAENETUNREACH
		return _wasiENETUNREACH, true
	case 10060: // WSAETIMEDOUT
		return _wasiETIMEDOUT, true
	case 10061: // WSAECONNREFUSED
		return _wasiECONNREFUSED, true
	case 10065: // WSAEHOSTUNREACH
		return _wasiEHOSTUNREACH, true
	}
	return 0, false
}

// hostHungUp would ask the host whether a descriptor of its own has been
// hung up on, which the runtime cannot do on this platform.
func hostHungUp(fd uintptr) bool { return false }

// hostDirListing lists a directory of the host's file system (an *os.File,
// which HostFS opens) in the order the system gives its names, which Go's
// ReadDir keeps. ReadDir leaves "." and ".." out, and they come first. ok
// is false for a directory of another file system. hostPath (the directory
// is of the whole host filesystem) changes nothing here: dotEntry states
// "." and ".." by their host paths either way.
func hostDirListing(f File, hostPath bool) ([]os.DirEntry, bool, error) {
	d, isHost := f.(*os.File)
	if !isHost {
		return nil, false, nil
	}
	if _, err := d.Seek(0, 0); err != nil {
		return nil, true, err
	}
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, true, err
	}
	out := make([]os.DirEntry, 0, len(entries)+2)
	out = append(out, dotEntry(d.Name(), "."), dotEntry(d.Name(), ".."))
	return append(out, entries...), true, nil
}

// hostPriority and setHostPriority read and set the nice value of processes
// of the host, which the runtime cannot do on this platform.
func hostPriority(which, who int) (int, error) { return 0, errors.ErrUnsupported }

func setHostPriority(which, who, nice int) error { return errors.ErrUnsupported }

// setHostIDs changes the user or group ids of the host process, which this
// platform does not have.
func setHostIDs(change IDChange) error { return errors.ErrUnsupported }

// setHostGroups sets the supplementary groups of the host process, which
// this platform does not have.
func setHostGroups(gids []int) error { return errors.ErrUnsupported }

// makeHostFIFO creates a FIFO in the host filesystem, which this platform
// does not have.
func makeHostFIFO(path string, perm os.FileMode) error { return errors.ErrUnsupported }

// hostUname returns what uname reports, which the runtime cannot ask on this
// platform.
func hostUname() (Uname, error) { return Uname{}, errors.ErrUnsupported }

// hostAccess would ask the host about an access to a file, which the
// runtime cannot do on this platform: asked is false, and Path_access
// decides by the file's mode bits.
func hostAccess(path string, amode uint32, effective bool) (errno int32, asked bool) {
	return 0, false
}

// flockOSFile would apply flock(2) to a file of the host process, which the
// runtime cannot do on this platform.
func flockOSFile(f *os.File, how int) error { return errors.ErrUnsupported }

// hostRecordLock would take a record lock of a file of the host process,
// which the runtime cannot do on this platform.
func hostRecordLock(f *os.File, cmd int32, lk *recordLock) error { return errors.ErrUnsupported }

// newHostSyslog would return the host's system logger, which package
// log/syslog does not have on this platform.
func newHostSyslog() (Syslogger, error) { return nil, errors.ErrUnsupported }

// hostOpensSockets says that the runtime makes no sockets of the host's on
// this platform: the socket imports are ENOTSUP, and the legacy ones serve
// connections of package net's.
const hostOpensSockets = false

// hostAbstractSockets says that Unix-domain sockets have no abstract names
// here.
const hostAbstractSockets = false

// The calls on a socket of the host's, which the runtime makes none of on
// this platform.

func openHostSocket(family int32, dgram bool) (*os.File, error) { return nil, errors.ErrUnsupported }

func hostSocketPair(dgram bool) (a, b *os.File, err error) { return nil, nil, errors.ErrUnsupported }

func hostBind(fd int, a wasiSockAddr, hostPath string) error { return errors.ErrUnsupported }

func hostListen(fd, backlog int) error { return errors.ErrUnsupported }

func hostAccept(fd int) (conn int, again bool, err error) { return -1, false, errors.ErrUnsupported }

func hostConnect(fd int, a wasiSockAddr, hostPath string) error { return errors.ErrUnsupported }

func hostConnectDone(fd int) (again bool, err error) { return false, errors.ErrUnsupported }

func hostSocketName(fd int, peer bool) (wasiSockAddr, error) {
	return wasiSockAddr{}, errors.ErrUnsupported
}

func hostReceive(fd int, bufs [][]byte, peek bool) (n int, truncated, again bool, err error) {
	return 0, false, false, errors.ErrUnsupported
}

func hostReceiveFrom(fd int, buf []byte, peek bool) (n int, from wasiSockAddr, again bool, err error) {
	return 0, wasiSockAddr{}, false, errors.ErrUnsupported
}

func hostSend(fd int, bufs [][]byte, to *wasiSockAddr, hostPath string) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

func hostShutdown(fd int, how int32) error { return errors.ErrUnsupported }

func setHostSockOpt(fd int, option, value int32) error { return errors.ErrUnsupported }

func getHostSockOpt(fd int, option int32) (int32, error) { return 0, errors.ErrUnsupported }

func hostSocketTimeout(fd int, send bool) (time.Duration, error) { return 0, errors.ErrUnsupported }

func setHostSocketTimeout(fd int, send bool, d time.Duration) error { return errors.ErrUnsupported }

// hostSyscall: this platform has no system calls of the Linux ABI
// (HostSyscalls).
func hostSyscall(number int64, args [6]uint64, ptrs uint32, mem []byte) (int64, error) {
	return 0, errors.ErrUnsupported
}
