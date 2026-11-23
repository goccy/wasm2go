//go:build darwin

package codegen

import (
	"bytes"
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

// hostThreadUmask says that no thread here has a umask of its own: the
// umask is the process's.
const hostThreadUmask = false

// hostOnMainThread: no creation thread is made here.
func hostOnMainThread() bool { return false }

// hostUnshareFS: no thread here has file system attributes of its own.
func hostUnshareFS() error { return errors.ErrUnsupported }

// chmodRefused reports whether err is chmod(2)'s refusal of a mode bit to
// this user or this file: EPERM, or EFTYPE for a sticky bit of a file that
// is no directory.
func chmodRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EFTYPE)
}

// hostFDLink returns the target of the host's link for descriptor fd of
// the host process, and whether the host has one: /dev/fd/N of this system
// is no link, so a character device (a terminal) has the name fcntl
// F_GETPATH gives it, and any other file none.
func hostFDLink(fd uintptr) (string, bool, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(fd), &st); err != nil {
		return "", false, os.NewSyscallError("fstat", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return "", false, nil
	}
	name, errno := hostDescriptorPath(fd)
	if errno != 0 {
		return "", false, os.NewSyscallError("fcntl", errno)
	}
	return name, true, nil
}

// hostReopen would open descriptor fd again as a new open file
// description, which this system has no way to (no /proc/self/fd).
func hostReopen(fd uintptr, flags int) (int, error) { return -1, errors.ErrUnsupported }

// hostReopensTerminal: no terminal is opened again here (hostReopen).
func hostReopensTerminal(fd uintptr) (bool, error) { return false, nil }

// openFIFOWatched reports that this system opens no FIFO by waiting for an
// open of the other end, having no inotify: the caller opens it another
// way.
func (w *WasiStubs) openFIFOWatched(m *Module, openFile func(name string, flag int, perm os.FileMode) (File, error), name string, flag int, perm os.FileMode) (File, int32, bool) {
	return nil, _wasiESUCCESS, false
}

// hostFIONREAD is FIONREAD, _IOR('f', 127, int): package syscall names it
// for no darwin architecture.
const hostFIONREAD = 0x4004667f

// hostReadable returns the number of bytes that can be read from fd, a
// pipe, without waiting (FIONREAD).
func hostReadable(fd uintptr) (int, error) {
	var n int32
	err := hostIoctl(fd, hostFIONREAD, unsafe.Pointer(&n))
	return int(n), err
}

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

// hostWritesWithoutWaiting says that a write that waits to a descriptor in
// blocking mode is not made in steps here (writeHostStream): darwin has no
// write that does not wait in one call on such a descriptor, so the write is
// one writev(2), which waits in the kernel, and a signal does not end it.
const hostWritesWithoutWaiting = false

// hostPipeWriteNow: darwin does not tell how to write to a pipe without
// waiting whatever its mode.
func hostPipeWriteNow(fd uintptr, bufs [][]byte) (n int, again, done bool, err error) {
	return 0, false, false, nil
}

// The numbers of recvmsg(2) and sendmsg(2).
const (
	hostSysRecvmsg = syscall.SYS_RECVMSG
	hostSysSendmsg = syscall.SYS_SENDMSG
	hostSysConnect = syscall.SYS_CONNECT

	hostSysGetsockopt = syscall.SYS_GETSOCKOPT
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

// hostDupTo makes descriptor to a close-on-exec duplicate of fd in one step
// (dup2), closing what to was open on. darwin has no dup3: the mark is set
// under syscall.ForkLock, before a command can be started with to open.
func hostDupTo(fd, to int) error {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	if err := syscall.Dup2(fd, to); err != nil {
		return os.NewSyscallError("dup2", err)
	}
	syscall.CloseOnExec(to)
	return nil
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

// hostPriority and setHostPriority read and set the nice value of a
// process, a process group or a user of the host.
func hostPriority(which, who int) (int, error) {
	return syscall.Getpriority(which, who)
}

func setHostPriority(which, who, nice int) error {
	return syscall.Setpriority(which, who, nice)
}

// setHostRESUID and setHostRESGID set the real, effective and saved ids of
// the host process. The system has no call that names the saved id: it
// follows the effective one, and only that request can be met.
func setHostRESUID(ruid, euid, suid int) error {
	if suid != -1 && suid != euid {
		return syscall.EINVAL
	}
	return syscall.Setreuid(ruid, euid)
}

func setHostRESGID(rgid, egid, sgid int) error {
	if sgid != -1 && sgid != egid {
		return syscall.EINVAL
	}
	return syscall.Setregid(rgid, egid)
}

// hostUname returns what uname(3) reports, from the sysctl values it reads.
func hostUname() (Uname, error) {
	var fields [5]string
	for i, key := range [...]string{"kern.ostype", "kern.hostname", "kern.osrelease", "kern.version", "hw.machine"} {
		value, err := syscall.Sysctl(key)
		if err != nil {
			return Uname{}, err
		}
		fields[i] = value
	}
	return Uname{Sysname: fields[0], Nodename: fields[1], Release: fields[2], Version: fields[3], Machine: fields[4]}, nil
}

// hostAccess asks the host whether the process may make the accesses of
// amode (access's bits) to the file at path, with its effective ids or its
// real ones: access(2), which asks with the real ones. Package syscall has
// no faccessat on this system, so a question with the effective ids is
// asked only of a process whose effective ids are its real ones; for any
// other, asked is false.
func hostAccess(path string, amode uint32, effective bool) (asked bool, err error) {
	if effective && (os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid()) {
		return false, nil
	}
	return true, syscall.Access(path, amode)
}

// rootAccess would be hostAccess for name in r; package syscall has no
// call relative to a directory descriptor on this system, and a path of
// the host is not looked up instead: errors.ErrUnsupported. For the same
// reason a rootFS here removes, opens without following and sets the times
// of a link after a look at the name (unlinkAt, rmdirAt, openNoFollow,
// lchtimesAt).
func rootAccess(r *os.Root, name string, amode uint32, effective bool) error {
	return errors.ErrUnsupported
}

// unlinkAt and rmdirAt remove a file and an empty directory of r, after
// Lstat finds the name is that kind (lstatRemove): package syscall has no
// unlinkat here.
func (r rootFS) unlinkAt(name string) error {
	return lstatRemove(r.root.Lstat, r.root.Remove, name, false)
}
func (r rootFS) rmdirAt(name string) error {
	return lstatRemove(r.root.Lstat, r.root.Remove, name, true)
}

// lchtimesAt sets the times of name of r, which is no symbolic link
// (lstatChtimes): package syscall has no utimensat here.
func (r rootFS) lchtimesAt(name string, atime, mtime time.Time) error {
	return lstatChtimes(r.root.Lstat, r.root.Chtimes, name, atime, mtime)
}

// openNoFollow opens name of r, which is no symbolic link (lstatOpen):
// package syscall has no openat here.
func (r rootFS) openNoFollow(name string, flag int, perm os.FileMode) (File, error) {
	return lstatOpen(r.root.Lstat, r.OpenFile, name, flag, perm)
}

// hostLchtimes sets the times of the file at path, which is no symbolic
// link (lstatChtimes): package syscall has no lutimes here.
func hostLchtimes(path string, atime, mtime time.Time) error {
	return lstatChtimes(os.Lstat, os.Chtimes, path, atime, mtime)
}

// hostFutimens sets the times of the file open as f by the name it has now
// in fsys (hostFDName): package syscall has no call through a descriptor
// with times in nanoseconds here. Of the whole host filesystem that is the
// host's name; of a HostFS of a directory the root's name for it, through
// os.Root, which refuses a file that is no longer in the root
// (rootRelName); of any other FS errors.ErrUnsupported, and the times are
// set by the name the descriptor was opened under. A file that has no
// name now (removed) is ENOENT.
func hostFutimens(fsys FS, f *os.File, atime, mtime time.Time) error {
	switch fsys := fsys.(type) {
	case osFS:
		name, err := hostFDName(f)
		if err != nil {
			return err
		}
		return os.Chtimes(name, atime, mtime)
	case rootFS:
		name, err := rootRelName(fsys, f)
		if err != nil {
			return err
		}
		return fsys.Chtimes(name, atime, mtime)
	}
	return errors.ErrUnsupported
}

// hostDirOpen is the open of a directory an FS of it holds (osDir, the
// file of a hostDir, a rootFS's at).
const hostDirOpen = syscall.O_RDONLY | syscall.O_DIRECTORY

// hostDirAt returns "" for the directory open as f, once it finds where
// the directory is (hostFDName): darwin has no path that leads to a
// directory wherever it is, so its name is asked for on every call.
func hostDirAt(f *os.File) (string, error) {
	_, err := hostFDName(f)
	return "", err
}

// hostMaxPathLen is MAXPATHLEN of <sys/param.h>, the most F_GETPATH writes.
const hostMaxPathLen = 1024

// hostFDName returns the name the file open as f has now (fcntl F_GETPATH),
// once a Stat of it finds that file there (sameFileAt).
func hostFDName(f *os.File) (string, error) {
	var (
		name  string
		errno syscall.Errno
	)
	if !hostDescriptor(f, func(fd uintptr) { name, errno = hostDescriptorPath(fd) }) {
		return "", &fs.PathError{Op: "fcntl", Path: f.Name(), Err: errors.ErrUnsupported}
	}
	if errno != 0 {
		return "", &fs.PathError{Op: "fcntl", Path: f.Name(), Err: errno}
	}
	return name, sameFileAt(f, name)
}

// hostDescriptorPath returns the name of the file open as descriptor fd of
// the host process (fcntl F_GETPATH).
func hostDescriptorPath(fd uintptr) (string, syscall.Errno) {
	var buf [hostMaxPathLen]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", errno
	}
	end := bytes.IndexByte(buf[:], 0)
	if end < 0 {
		return "", syscall.ENAMETOOLONG
	}
	return string(buf[:end]), 0
}

// hostRecordLockCommands are the commands of hostRecordLock, at recordLockGet,
// recordLockSet and recordLockWait: fcntl's F_GETLK, F_SETLK and F_SETLKW,
// whose locks are the process's.
var hostRecordLockCommands = [...]int{recordLockGet: syscall.F_GETLK, recordLockSet: syscall.F_SETLK, recordLockWait: syscall.F_SETLKW}

// hostRecordLocksOfDescription says that the record locks of
// hostRecordLockCommands are the process's, not the open file
// description's.
const hostRecordLocksOfDescription = false

// hostAbstractSockets says that Unix-domain sockets here have no abstract
// names.
const hostAbstractSockets = false

// hostSOLinger is the name of SO_LINGER_SEC, the SO_LINGER whose time is
// in seconds (darwin's SO_LINGER counts in clock ticks).
const hostSOLinger = syscall.SO_LINGER_SEC

// hostSOReusePort is the name of SO_REUSEPORT.
const hostSOReusePort = syscall.SO_REUSEPORT

// hostTCPDeferAccept is the name of TCP_DEFER_ACCEPT, which darwin has not
// (-1).
const hostTCPDeferAccept = -1

// hostSocketFD makes a socket of the host's, closed on exec under
// syscall.ForkLock and in non-blocking mode, as Go's package net makes one
// where socket(2) takes no such flags (sysSocket).
func hostSocketFD(domain, typ int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := syscall.Socket(domain, typ, 0)
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
	return fd, socketFDMade(fd)
}

// hostSocketPairFDs makes two connected Unix-domain sockets of the type, as
// hostSocketFD makes a socket.
func hostSocketPairFDs(typ int) ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ, 0)
	if err != nil {
		return fds, os.NewSyscallError("socketpair", err)
	}
	if err := socketFDMade(fds[0]); err != nil {
		return fds, errors.Join(err, hostCloseFD(fds[1]))
	}
	if err := socketFDMade(fds[1]); err != nil {
		return fds, errors.Join(err, hostCloseFD(fds[0]))
	}
	return fds, nil
}

// hostAcceptFD accepts a connection on socket fd, closed on exec under
// syscall.ForkLock and in non-blocking mode, as Go's package net accepts
// where accept(2) takes no such flags (accept).
func hostAcceptFD(fd int) (int, error) {
	// An accept on a description in blocking mode may wait in the host:
	// it is not made under syscall.ForkLock, which every command start
	// waits for, and a command started meanwhile may inherit the
	// connection until socketFDMade marks it close-on-exec.
	blocking, err := descriptorBlocks(fd)
	if err != nil {
		return -1, err
	}
	if !blocking {
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
	}
	conn, _, err := syscall.Accept(fd)
	if err != nil {
		return -1, os.NewSyscallError("accept", err)
	}
	return conn, socketFDMade(conn)
}

// blockThreadSignal blocks sig on the calling thread (__pthread_sigmask,
// which pthread_sigmask(3) calls: Darwin's sigprocmask(2) changes the mask
// of every thread) and returns what puts the thread's mask back.
func blockThreadSignal(sig syscall.Signal) (restore func() error, err error) {
	const sigBlock, sigSetmask = 1, 3
	set, old := uint32(1)<<(sig-1), uint32(0)
	if _, _, errno := syscall.RawSyscall(syscall.SYS___PTHREAD_SIGMASK, sigBlock, uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&old))); errno != 0 {
		return nil, os.NewSyscallError("pthread_sigmask", errno)
	}
	return func() error {
		if _, _, errno := syscall.RawSyscall(syscall.SYS___PTHREAD_SIGMASK, sigSetmask, uintptr(unsafe.Pointer(&old)), 0); errno != 0 {
			return os.NewSyscallError("pthread_sigmask", errno)
		}
		return nil
	}, nil
}

// hostSiginfo is Darwin's siginfo_t (waitid(2)): si_signo, si_errno,
// si_code, si_pid, si_uid and si_status, within its 104 bytes.
type hostSiginfo struct {
	signo, errno, code, pid, uid, status int32
	_                                    [104 - 24]byte
}

// socketFDMade sets the socket fd, made by the caller, closed on exec and
// in non-blocking mode; on a failure it closes fd.
func socketFDMade(fd int) error {
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		return errors.Join(os.NewSyscallError("fcntl", err), hostCloseFD(fd))
	}
	return nil
}

// hostSyscall makes the guest's system call of the number (HostSyscalls),
// of the two whose arguments darwin's calls take as the Linux ABI gives
// them: gettimeofday(2), whose third argument of darwin's (where to store
// mach_absolute_time) is null, and getrandom(2), made by getentropy(2)
// (hostGetrandom). Every other call fails with ENOSYS.
func hostSyscall(number int64, args [6]uint64, ptrs uint32, mem []byte) (int64, error) {
	switch number {
	case linuxSysGettimeofday:
		return hostRawSyscall(syscall.SYS_GETTIMEOFDAY, [6]uint64{args[0], args[1]}, ptrs&0b11, mem)
	case linuxSysGetrandom:
		return hostGetrandom(args, ptrs, mem)
	}
	return 0, syscall.ENOSYS
}

// The flags of getrandom(2), Linux's (include/uapi/linux/random.h), which
// darwin has no constants of.
const (
	linuxGrndNonblock = 0x1
	linuxGrndRandom   = 0x2
	linuxGrndInsecure = 0x4
)

// darwin's getentropy(2) (bsd/kern/syscalls.master), and the most bytes it
// gives a call (its manual page), which package syscall has no constants
// of.
const (
	hostSysGetentropy = 500
	hostGetentropyMax = 256
)

// hostGetrandom makes Linux's getrandom(buf, buflen, flags) by darwin's
// getentropy(2), which does not block once the system has booted, so every
// flag Linux takes asks for what it gives. As Linux does, it fails with
// EINVAL for any other flag and for GRND_RANDOM with GRND_INSECURE, and
// returns buflen; EFAULT for a buffer not all in the guest's memory.
func hostGetrandom(args [6]uint64, ptrs uint32, mem []byte) (int64, error) {
	buf, n, flags := args[0], args[1], args[2]
	if flags&^(linuxGrndNonblock|linuxGrndRandom|linuxGrndInsecure) != 0 ||
		flags&(linuxGrndRandom|linuxGrndInsecure) == linuxGrndRandom|linuxGrndInsecure {
		return 0, syscall.EINVAL
	}
	if n == 0 {
		return 0, nil
	}
	if ptrs&1 == 0 || buf > uint64(len(mem)) || n > uint64(len(mem))-buf {
		return 0, syscall.EFAULT
	}
	for done := uint64(0); done < n; {
		chunk := min(n-done, hostGetentropyMax)
		if _, err := hostRawSyscall(hostSysGetentropy, [6]uint64{buf + done, chunk}, 0b1, mem); err != nil {
			return 0, err
		}
		done += chunk
	}
	return int64(n), nil
}
