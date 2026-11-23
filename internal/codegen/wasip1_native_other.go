//go:build !darwin && !linux

package codegen

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"sync"
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

// openFIFOWatched reports that this platform opens no FIFO by waiting for
// an open of the other end: the caller opens it another way.
func (w *WasiStubs) openFIFOWatched(m *Module, openFile func(name string, flag int, perm os.FileMode) (File, error), name string, flag int, perm os.FileMode) (File, int32, bool) {
	return nil, _wasiESUCCESS, false
}

// readHostUmask returns the file mode creation mask of the host process,
// which this platform has no way to read without changing it:
// errors.ErrUnsupported.
func readHostUmask() (os.FileMode, error) {
	return 0, fmt.Errorf("the umask of the host process cannot be read without changing it: %w", errors.ErrUnsupported)
}

// setHostNonblock would set the O_NONBLOCK of f's descriptor; no open of
// this platform is given O_NONBLOCK (hostONonblock).
func setHostNonblock(f File, nonblock bool) error { return nil }

// hostONonblock is the open flag of the host that opens a file without
// waiting. This platform's opens wait as they will: the syscall package of
// some (js, wasip1) has no such flag.
const hostONonblock = 0

// hostONofollow is O_NOFOLLOW, which this platform has none of: the
// runtime asks Lstat before an open that does not follow.
const hostONofollow = 0

// Unlink and Rmdir remove a file and an empty directory of the host's after
// Lstat finds the name is that kind (lstatRemove): this platform has no
// call that removes one kind only.
func (o osFS) Unlink(name string) error { return lstatRemove(os.Lstat, os.Remove, o.join(name), false) }
func (o osFS) Rmdir(name string) error  { return lstatRemove(os.Lstat, os.Remove, o.join(name), true) }

// The calls of rootFS relative to a directory, for a platform without
// them: as darwin's.
func (r rootFS) unlinkAt(name string) error {
	return lstatRemove(r.root.Lstat, r.root.Remove, name, false)
}
func (r rootFS) rmdirAt(name string) error {
	return lstatRemove(r.root.Lstat, r.root.Remove, name, true)
}
func (r rootFS) lchtimesAt(name string, atime, mtime time.Time) error {
	return lstatChtimes(r.root.Lstat, r.root.Chtimes, name, atime, mtime)
}
func (r rootFS) openNoFollow(name string, flag int, perm os.FileMode) (File, error) {
	return lstatOpen(r.root.Lstat, r.OpenFile, name, flag, perm)
}

// hostLchtimes sets the times of the file at path, which is no symbolic
// link (lstatChtimes).
func hostLchtimes(path string, atime, mtime time.Time) error {
	return lstatChtimes(os.Lstat, os.Chtimes, path, atime, mtime)
}

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

// hostMayBlock reports whether a call on the descriptor can wait in the
// kernel when there is nothing for it, which the runtime cannot tell on this
// platform.
func hostMayBlock(fd uintptr) bool { return true }

// duplicateDescriptor would duplicate the descriptor of f, which the runtime
// cannot do on this platform.
func duplicateDescriptor(f syscall.Conn) (int, error) { return -1, errors.ErrUnsupported }

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

// hostErrnoOf would return the host's error number of a wasi errno; this
// platform has no table of them.
func hostErrnoOf(n int32) error {
	return fmt.Errorf("wasi errno %d, which this host has no number of", n)
}

// hostNumberTable returns no numbers: the runtime has no table of this
// host's.
func hostNumberTable(family int32) []hostNumber { return nil }

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
// is false for a directory of another file system. dotEntry states "." and
// ".." by their host paths.
func hostDirListing(f File) ([]os.DirEntry, bool, error) {
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
func hostAccess(path string, amode uint32, effective bool) (asked bool, err error) {
	return false, nil
}

// rootAccess would ask the host about an access to a file of r, which the
// runtime cannot do on this platform: errors.ErrUnsupported.
func rootAccess(r *os.Root, name string, amode uint32, effective bool) error {
	return errors.ErrUnsupported
}

// hostDirOpen is the open of a directory an FS of it holds (the file of a
// hostDir, a rootFS's at).
const hostDirOpen = os.O_RDONLY

// hostDirAt and hostFDName would tell where a directory, or a file, open is
// now, which the runtime cannot learn on this platform:
// errors.ErrUnsupported (osFS.OpenRoot is, and a HostFS of a directory's
// FS of one of its directories has none either).
func hostDirAt(f *os.File) (string, error) { return "", errors.ErrUnsupported }
func hostFDName(f *os.File) (string, error) {
	return "", &fs.PathError{Op: "fdname", Path: f.Name(), Err: errors.ErrUnsupported}
}

// hostFutimens would set the times of the file open as f through its
// descriptor, which the runtime cannot do on this platform:
// errors.ErrUnsupported, and the times are set by the file's name.
func hostFutimens(FS, *os.File, time.Time, time.Time) error { return errors.ErrUnsupported }

// flockOSFile would apply flock(2) to a file of the host process, which the
// runtime cannot do on this platform.
func flockOSFile(f *os.File, how int) error { return errors.ErrUnsupported }

// hostRecordLocks says that the system has no record locks of the host:
// fd_lock fails with ENOTSUP.
const hostRecordLocks = false

// The host's side of the record lock table, which fd_lock does not use on
// this platform (hostRecordLocks).
func (file *lockedFile) hostLockLocked(via *os.File, cmd int32, lk *recordLock) error {
	return errors.ErrUnsupported
}
func (file *lockedFile) prepareHostLocked(f *os.File, regular, read, write, forWrite bool) (passed, err error) {
	return nil, errors.ErrUnsupported
}
func (file *lockedFile) closeHostLocked() error                         { return nil }
func (file *lockedFile) waitDescriptorLocked() (int, error)             { return -1, errors.ErrUnsupported }
func hostWaitRecordLock(waitFD int, via *os.File, lk *recordLock) error { return errors.ErrUnsupported }

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

// startCommand starts the command path with argv and env in dir (the host
// process's directory when it is empty), its standard streams those of
// streams, with os/exec: a file or socket of the host is the command's as
// it is, and os/exec copies any other stream, to the instance's stdout and
// stderr under the family's output lock (familyStreams). Its wait waits for
// the copies, as Cmd.Wait does.
func (w *WasiStubs) startCommand(op, path string, argv, env []string, dir string, job hostJob, streams *[3]commandStream, share *familyStreams) (*hostCommand, error) {
	cmd := &exec.Cmd{Path: path, Args: argv, Env: env, Dir: dir}
	if s := streams[0]; s.host != nil {
		cmd.Stdin = s.host.(io.Reader)
	} else if s.reader != nil {
		cmd.Stdin = s.reader
	}
	out := [2]*io.Writer{&cmd.Stdout, &cmd.Stderr}
	for i, s := range streams[1:] {
		switch {
		case s.host != nil:
			*out[i] = s.host.(io.Writer)
		case s.writer != nil && s.stdio >= 2:
			*out[i] = lockedWriter{&share.output, s.writer}
		case s.writer != nil:
			*out[i] = s.writer
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &hostCommand{process: cmd.Process, wait: func() int32 {
		err := cmd.Wait()
		return w.waitStatusOf(cmd.ProcessState, err)
	}}, nil
}

// lockedWriter writes to w under mu.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// This platform has no process groups or sessions the runtime can change
// or put a command in: every command is in the host process's.
func hostGetpgid(pid int32) (int32, error)         { return 0, errors.ErrUnsupported }
func hostSetpgid(pid, pgid int32) error            { return errors.ErrUnsupported }
func hostSetsid() (int32, error)                   { return 0, errors.ErrUnsupported }
func hostJobAttr(job hostJob) *syscall.SysProcAttr { return nil }
func killHostGroup(pgid int, sig int32) error      { return errors.ErrUnsupported }
func hostWaitExited(pid int) (int32, error)        { return 0, errors.ErrUnsupported }

const hostJobControl = false

// Nor has it a terminal of the host's for the guest (fd_ioctl).
func hostProcessGroup() int                { return 0 }
func hostForeground(fd int) (int, error)   { return 0, syscall.ENOTTY }
func hostSetForeground(fd, pgid int) error { return syscall.ENOTTY }
func dupHostFD(fd uintptr) (int, error)    { return -1, errors.ErrUnsupported }

// commandProcess is a command of the host's the runtime started: package
// os's process here.
type commandProcess = os.Process

// ---- descriptors of the host process ---------------------------------------

// hostDescriptorsSupported says that no instance's descriptors are the host
// process's here (WASIConfig.HostDescriptors has no effect).
const hostDescriptorsSupported = false

// startHostNumbers: there is nothing to record here.
func startHostNumbers(files map[int32]*os.File) error { return nil }

// hostIdentity: no descriptor is taken in from outside the guest here.
type hostIdentity struct{}

// makeRuntimeDescriptors runs make: no guest takes a descriptor in here.
func makeRuntimeDescriptors(make func() error) error { return make() }

// runtimeFloor is 0: the runtime's descriptors are where the host puts
// them.
func runtimeFloor() int { return 0 }

// runtimeFile is make: the runtime's descriptors are where the host puts
// them.
func runtimeFile(make func() (*os.File, error)) (*os.File, error) { return make() }

// runtimePipe is os.Pipe.
func runtimePipe() (r, wr *os.File, err error) { return os.Pipe() }

// keepRuntimeFile: the runtime's descriptors are where the host puts them.
func keepRuntimeFile(f *os.File) (*os.File, error) { return f, nil }

// keepRuntimeOpened: the runtime's descriptors are where the host puts them.
func keepRuntimeOpened(f File) (File, error) { return f, nil }

// currentLocked: every slot is what it was made for here.
func (w *WasiStubs) currentLocked(fd int32) bool { return true }

// keepRuntimeFD: the runtime's descriptors are where the host puts them.
func keepRuntimeFD(fd int) (int, error) { return fd, nil }

// hostSlotLocked: no instance's descriptors are the host's here.
func (w *WasiStubs) hostSlotLocked(op *wasiOpen, min int32) (int32, error) {
	return -1, errors.ErrUnsupported
}

// placeHostSlotLocked: no instance's descriptors are the host's here.
func (w *WasiStubs) placeHostSlotLocked(to int32, src *wasiOpen) error {
	return errors.ErrUnsupported
}

// placeFileLocked: no instance's descriptors are the host's here.
func (w *WasiStubs) placeFileLocked(fd int32, f *os.File) error {
	return errors.Join(errors.ErrUnsupported, f.Close())
}

// hostSlotHeld: no slot has a descriptor of the host's here.
func (w *WasiStubs) hostSlotHeld(fd int32) bool { return false }

// releaseHostSlotLocked: no slot has a descriptor of the host's here.
func (w *WasiStubs) releaseHostSlotLocked(fd int32) error { return nil }

// leaveStandardNumbersLocked: no slot has a descriptor of the host's here.
func (w *WasiStubs) leaveStandardNumbersLocked() {}

// adoptHostLocked: no instance's descriptors are the host's here.
func (w *WasiStubs) adoptHostLocked(fd int32) *wasiOpen { return nil }

// takeStandardLocked: no instance's descriptors are the host's here.
func (w *WasiStubs) takeStandardLocked(fd int32) bool { return false }

// fileEntry returns the entry of f, a file of the configuration's Files,
// which it takes over: f itself, a directory or a regular file as its Stat
// says. On failure f is closed.
func fileEntry(f *os.File) (*wasiOpen, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return &wasiOpen{f: f, isDir: st.IsDir(), regular: st.Mode().IsRegular()}, nil
}
