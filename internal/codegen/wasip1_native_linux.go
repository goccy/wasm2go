//go:build linux

package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atim.Unix()), time.Unix(st.Ctim.Unix())
}

// hostSignalByNumber returns the host's signal for a guest signal number
// the table of hostSignals does not name: Linux numbers its signals as the
// guest does, so SIGSTKFLT (16), SIGPWR (30) and the real-time signals (32
// to 64) are the host's signals of the same numbers.
func hostSignalByNumber(sig int32) (hostSig syscall.Signal, known bool) {
	return syscall.Signal(sig), sig == 16 || sig == 30 || sig >= 32 && sig <= 64
}

// hostPollReportsFIFOEnd says that poll(2) here reports POLLHUP on a FIFO
// whose last writer has closed it.
const hostPollReportsFIFOEnd = true

// hostSendsWithoutWaiting says that a send to a socket with MSG_DONTWAIT
// does not wait for room.
const hostSendsWithoutWaiting = true

// hostPipeBuf is PIPE_BUF: a pipe that poll(2) reports writable takes that
// much without waiting.
const hostPipeBuf = 4096

// hostWakePipe makes a pipe whose ends do not wait and are closed on exec:
// a wait in poll(2) watches its read end, and a byte written to the other
// end (hostWakeWrite) ends the wait.
func hostWakePipe() (r, w int, err error) {
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return -1, -1, os.NewSyscallError("pipe2", err)
	}
	return p[0], p[1], nil
}

// hostPollCall is poll(2): it waits no longer than timeout, and without
// limit when timeout is negative.
func hostPollCall(fds []hostPoll, timeout time.Duration) (int, syscall.Errno) {
	var limit *syscall.Timespec
	if timeout >= 0 {
		ts := syscall.NsecToTimespec(int64(timeout))
		limit = &ts
	}
	var first *hostPoll
	if len(fds) > 0 {
		first = &fds[0]
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(first)), uintptr(len(fds)),
		uintptr(unsafe.Pointer(limit)), 0, 0, 0)
	return int(n), errno
}

// openPath is O_PATH, which has this number on every linux GOARCH while
// package syscall names it on some of them only.
const openPath = 0x200000

// lstatAt describes name in the directory open as dir, without following
// a symbolic link: through a descriptor opened relative to dir (O_PATH),
// so no path of the host is looked up.
func lstatAt(dir *os.File, name string) (os.FileInfo, error) {
	rc, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var openErr error
	if err := rc.Control(func(dirFd uintptr) {
		fd, openErr = syscall.Openat(int(dirFd), name, openPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: openErr}
	}
	f := os.NewFile(uintptr(fd), name)
	fi, err := f.Stat()
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	return fi, nil
}

// hostThreadUmask says that a thread here can have a umask of its own
// (creationThread).
const hostThreadUmask = true

// hostOnMainThread reports whether the calling thread is the main thread
// of the process, whose thread id is the process id: the thread the
// runtime cannot discard. In a program built with -buildmode=c-archive or
// c-shared the main thread is the host program's, which the runtime
// reaches only through a call the host program makes on it; it is the
// thread checked all the same.
func hostOnMainThread() bool { return syscall.Gettid() == syscall.Getpid() }

// hostUnshareFS gives the calling thread file system attributes of its
// own: unshare(2) with CLONE_FS.
func hostUnshareFS() error {
	if err := syscall.Unshare(syscall.CLONE_FS); err != nil {
		return os.NewSyscallError("unshare", err)
	}
	return nil
}

// chmodRefused reports whether err is chmod(2)'s refusal of a mode bit to
// this user, EPERM: a setgid bit of a group the user is not in.
func chmodRefused(err error) bool { return errors.Is(err, syscall.EPERM) }

// hostFDLink returns the target of the host's link for descriptor fd of
// the host process, /proc/self/fd/fd, and whether the host has one: a
// system without /proc has none.
func hostFDLink(fd uintptr) (string, bool, error) {
	target, err := os.Readlink(hostFDPath(fd))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return target, true, nil
}

// hostFDPath returns the name of descriptor fd of the host process in
// /proc: /proc/self/fd/fd.
func hostFDPath(fd uintptr) string { return "/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10) }

// hostReopen opens descriptor fd of the host process again with flags,
// through /proc/self/fd/fd: a new open file description of the same file
// (close-on-exec). A system without /proc gives fs.ErrNotExist.
func hostReopen(fd uintptr, flags int) (int, error) {
	path := hostFDPath(fd)
	reopened, err := syscall.Open(path, flags|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return reopened, nil
}

// hostReopensTerminal reports whether fd is a terminal a command is given
// an open file description of its own of (commandFile): one that is not
// the master of a pseudo-terminal, whose open makes a new pseudo-terminal
// (TIOCGPTN answers only on a master). An ioctl that fails otherwise than
// for a descriptor of another kind returns its error.
func hostReopensTerminal(fd uintptr) (bool, error) {
	var termios syscall.Termios
	if err := hostIoctl(fd, syscall.TCGETS, unsafe.Pointer(&termios)); err != nil {
		return false, unlessOtherKind(err)
	}
	var n uint32
	if err := hostIoctl(fd, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		return true, unlessOtherKind(err)
	}
	return false, nil
}

// unlessOtherKind returns err of an ioctl, but nil for its refusal by a
// descriptor of another kind than the request is for (ENOTTY, EINVAL).
func unlessOtherKind(err error) error {
	if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EINVAL) {
		return nil
	}
	return err
}

// hostReadable returns the number of bytes that can be read from fd, a
// pipe, without waiting (FIONREAD).
func hostReadable(fd uintptr) (int, error) {
	var n int32
	err := hostIoctl(fd, syscall.TIOCINQ, unsafe.Pointer(&n))
	return int(n), err
}

// readHostUmask returns the file mode creation mask of the host process,
// from /proc/thread-self/status.
func readHostUmask() (os.FileMode, error) {
	// The calling thread's, which no creation thread is: its goroutine
	// runs on none. A kernel before 3.17 has no /proc/thread-self; the
	// main thread's (/proc/self) is then read, which none is either.
	mask, err := statusUmask("/proc/thread-self/status")
	if errors.Is(err, fs.ErrNotExist) {
		return statusUmask("/proc/self/status")
	}
	return mask, err
}

// statusUmask returns the umask the "Umask:" line of the process status file
// at path gives (Linux 4.7 and later). A status without that line is one of
// a system that has no way to read the umask without changing it:
// errors.ErrUnsupported.
func statusUmask(path string) (os.FileMode, error) {
	status, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	_, rest, found := strings.Cut("\n"+string(status), "\nUmask:")
	if !found {
		return 0, fmt.Errorf("%s has no umask: %w", path, errors.ErrUnsupported)
	}
	value, _, _ := strings.Cut(rest, "\n")
	mask, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("the umask in %s: %w", path, err)
	}
	return os.FileMode(mask).Perm(), nil
}

// osFileDirents reads the names in the directory open as d, in the order
// the system gives them, "." and ".." where it has them.
func osFileDirents(d *os.File) (names []hostName, err error) {
	rc, err := d.SyscallConn()
	if err != nil {
		return nil, err
	}
	if readErr := rc.Read(func(fd uintptr) bool {
		names, err = readHostDirents(int(fd))
		return true
	}); readErr != nil {
		return nil, readErr
	}
	return names, err
}

// readHostDirents reads the names in the directory open as fd from its
// beginning, in the order the system gives them, "." and ".." where it
// has them.
func readHostDirents(fd int) ([]hostName, error) {
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return nil, os.NewSyscallError("lseek", err)
	}
	var entry syscall.Dirent
	const (
		reclenAt = unsafe.Offsetof(entry.Reclen)
		typeAt   = unsafe.Offsetof(entry.Type)
		nameAt   = unsafe.Offsetof(entry.Name)
	)
	var out []hostName
	buf := make([]byte, 32<<10)
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("getdents", err)
		}
		if n <= 0 {
			return out, nil
		}
		for rest := buf[:n]; len(rest) > int(nameAt); {
			reclen := int(binary.NativeEndian.Uint16(rest[reclenAt:]))
			if reclen <= int(nameAt) || reclen > len(rest) {
				break
			}
			rec := rest[:reclen]
			rest = rest[reclen:]
			ino := binary.NativeEndian.Uint64(rec)
			if ino == 0 {
				continue
			}
			name := rec[nameAt:]
			for i, c := range name {
				if c == 0 {
					name = name[:i]
					break
				}
			}
			out = append(out, hostName{name: string(name), typ: rec[typeAt], ino: ino})
		}
	}
}

// hostPriority returns the nice value of a process, a process group or a
// user of the host. The system call reports it as 20 minus the value. The
// host process's own (PRIO_PROCESS, 0) is its main thread's: the kernel
// keeps a nice value for each thread, and 0 names the calling one.
func hostPriority(which, who int) (int, error) {
	if which == hostPrioProcess && who == 0 {
		who = os.Getpid()
	}
	raw, err := syscall.Getpriority(which, who)
	if err != nil {
		return 0, err
	}
	return 20 - raw, nil
}

// setHostRESUID and setHostRESGID set the real, effective and saved ids of
// the host process.
func setHostRESUID(ruid, euid, suid int) error { return syscall.Setresuid(ruid, euid, suid) }

func setHostRESGID(rgid, egid, sgid int) error { return syscall.Setresgid(rgid, egid, sgid) }

// hostUname returns what uname(2) reports.
func hostUname() (Uname, error) {
	var name syscall.Utsname
	if err := syscall.Uname(&name); err != nil {
		return Uname{}, err
	}
	return Uname{
		Sysname:  utsnameField(name.Sysname[:]),
		Nodename: utsnameField(name.Nodename[:]),
		Release:  utsnameField(name.Release[:]),
		Version:  utsnameField(name.Version[:]),
		Machine:  utsnameField(name.Machine[:]),
	}, nil
}

// utsnameField returns a field of a Utsname, a NUL-terminated string in
// bytes that are signed on some architectures and unsigned on others.
func utsnameField[T int8 | uint8](raw []T) string {
	text := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		text = append(text, byte(c))
	}
	return string(text)
}

// hostAccess asks the host whether the process may make the accesses of
// amode (access's bits) to the file at path, with its effective ids or its
// real ones: faccessat(2). asked is true: the host can always say.
func hostAccess(path string, amode uint32, effective bool) (asked bool, err error) {
	// faccessat's AT_FDCWD and AT_EACCESS on this system
	const atFDCWD, atEAccess = -100, 0x200
	flags := 0
	if effective {
		flags = atEAccess
	}
	return true, syscall.Faccessat(atFDCWD, path, amode, flags)
}

// hostRecordLockCommands are the commands of hostRecordLock, at recordLockGet,
// recordLockSet and recordLockWait: those of the locks of an open file
// description, F_OFD_GETLK, F_OFD_SETLK and F_OFD_SETLKW (Linux 3.15), the
// same on every architecture; package syscall does not name them.
var hostRecordLockCommands = [...]int{recordLockGet: 36, recordLockSet: 37, recordLockWait: 38}

// hostRecordLocksOfDescription says that the record locks of
// hostRecordLockCommands are the open file description's.
const hostRecordLocksOfDescription = true

// hostPrioProcess is PRIO_PROCESS.
const hostPrioProcess = 0

// setHostPriority sets the nice value of processes of the host. The kernel
// keeps one for each thread, so the host process's own (PRIO_PROCESS, 0)
// is set for every thread it has (/proc/self/task); a thread that ends
// meanwhile (ESRCH) is skipped.
func setHostPriority(which, who, nice int) error {
	if which != hostPrioProcess || who != 0 {
		return syscall.Setpriority(which, who, nice)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			return fmt.Errorf("the thread /proc/self/task/%s: %w", task.Name(), err)
		}
		if err := syscall.Setpriority(which, tid, nice); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
	}
	return nil
}

// hostAbstractSockets says that Unix-domain sockets here have abstract
// names (a leading NUL), which are no files.
const hostAbstractSockets = true

// hostSOLinger is the name of SO_LINGER, whose time is in seconds.
const hostSOLinger = syscall.SO_LINGER

// hostTCPDeferAccept is the name of TCP_DEFER_ACCEPT.
const hostTCPDeferAccept = syscall.TCP_DEFER_ACCEPT

// hostSocketFD makes a socket of the host's, in non-blocking mode and
// closed on exec at once, as Go's package net makes one (sysSocket).
func hostSocketFD(domain, typ int) (int, error) {
	fd, err := syscall.Socket(domain, typ|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	return fd, os.NewSyscallError("socket", err)
}

// hostSocketPairFDs makes two connected Unix-domain sockets of the type, as
// hostSocketFD makes a socket.
func hostSocketPairFDs(typ int) ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	return fds, os.NewSyscallError("socketpair", err)
}

// hostAcceptFD accepts a connection on socket fd, in non-blocking mode and
// closed on exec at once (accept4(2), as Go's package net accepts).
func hostAcceptFD(fd int) (int, error) {
	conn, _, err := syscall.Accept4(fd, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
	return conn, os.NewSyscallError("accept4", err)
}

// hostSyscall makes the guest's system call of the number (HostSyscalls) as
// the host's call of its name (hostSyscallNumber).
func hostSyscall(number int64, args [6]uint64, ptrs uint32, mem []byte) (int64, error) {
	n, ok := hostSyscallNumber(number)
	if !ok {
		return 0, syscall.ENOSYS
	}
	return hostRawSyscall(n, args, ptrs, mem)
}

// openFIFOWatched opens the FIFO name, of a filesystem of the host's, for
// reading with flag the way a blocking open(2) does (fs/pipe.c fifo_open),
// and reports whether it did so here (watched): not where /proc or inotify
// is missing, which is known before the FIFO is opened, and the caller
// opens it another way. The open is made without waiting
// (O_NONBLOCK), which makes it a reader at once, as a waiting reader is:
// a writer's open that waits for one returns. The call then waits until
// the FIFO has had a writer since (awaitFIFOWriter); a signal posted to
// the guest meanwhile ends the wait with EINTR and closes the reader,
// which a writer that came takes for a reader gone, as for an open(2)
// that a signal interrupts. No other end of the FIFO is opened.
func (w *WasiStubs) openFIFOWatched(openFile func(name string, flag int, perm os.FileMode) (File, error), name string, flag int, perm os.FileMode) (File, int32, bool) {
	// Known before the FIFO is opened: an open made and closed again would
	// show.
	if _, err := os.Stat("/proc/self/fd"); errors.Is(err, fs.ErrNotExist) {
		return nil, _wasiESUCCESS, false
	} else if err != nil {
		return nil, w.guestErrno("path_open", err), true
	}
	fw, err := newFIFOWatch()
	if err != nil {
		// No inotify instance (the user's limit of them, a kernel without
		// inotify): the open is made the way that needs none, which it can
		// still be, as nothing of the FIFO's is opened yet. Errors is told
		// why.
		w.reportError("path_open", err)
		return nil, _wasiESUCCESS, false
	}
	f, err := openFile(name, flag|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, w.guestErrno("path_open", errors.Join(err, fw.Close())), true
	}
	ended := false
	defer func() {
		if !ended {
			// Unwound by terminate: the guest is ending.
			w.reportError("path_open", errors.Join(fw.Close(), f.Close()))
		}
	}()
	opened, err := w.awaitFIFOWriter(fw, f)
	ended = true
	err = errors.Join(err, fw.Close())
	if err == nil && opened {
		return f, _wasiESUCCESS, true
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, w.guestErrno("path_open", err), true
	}
	return nil, _wasiEINTR, true
}

// awaitFIFOWriter waits until f, the read end of a FIFO opened without
// waiting, has had a writer since it was opened, as a blocking open of it
// for reading waits (fs/pipe.c wait_for_partner), and reports whether it
// has: not when a signal posted to the guest ended the wait first. A
// writer that comes and goes ends the wait as well; a read then finds the
// end of input. f that is no FIFO, another file the name was given to
// after it was looked up, is what open(2) opens: there is nothing to wait
// for.
//
// The wait is for an open of the FIFO (inotify IN_OPEN, on the inode
// /proc/self/fd names, so no name is looked up again) and for f to be
// readable, after which the call looks whether a writer has come
// (fifoWatch.hasWriter). The events are read before each look, so that one
// after it ends the next wait; a writer that came before the watch was set
// is found by the first look, and one a look missed (another reader took
// the input tee(2) was to find) by f's input or hang-up.
func (w *WasiStubs) awaitFIFOWriter(fw *fifoWatch, f File) (bool, error) {
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if st.Mode()&os.ModeNamedPipe == 0 {
		return true, nil
	}
	if err := fw.watch(f); err != nil {
		return false, err
	}
	interrupted := false
	for {
		if err := fw.drain(); err != nil {
			return false, err
		}
		found, err := fw.hasWriter(f)
		switch {
		case err != nil:
			return false, err
		case found:
			if interrupted {
				// The open is done after all: the next call that waits
				// reports the signal.
				w.keepInterrupt()
			}
			return true, nil
		case interrupted:
			return false, nil
		}
		set := []hostWaitFD{{stream: fw.events, want: hostWantInput}, {stream: f, want: hostWantInput}}
		if interrupted, err = w.waitHostInterruptibly("path_open", set, time.Time{}); err != nil {
			return false, err
		}
	}
}

// spliceFNonblock is SPLICE_F_NONBLOCK (include/uapi/linux/splice.h), which
// package syscall does not name.
const spliceFNonblock = 0x02

// fifoWatch is what awaitFIFOWriter waits and looks with: an inotify
// instance (events, whose descriptor is fd) that watches a FIFO for opens,
// and a pipe of the runtime's (tee) that a look copies a byte of the FIFO
// into.
type fifoWatch struct {
	events *os.File
	fd     int
	tee    [2]int
}

// newFIFOWatch makes a fifoWatch, which watches nothing yet.
func newFIFOWatch() (*fifoWatch, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return nil, os.NewSyscallError("inotify_init1", err)
	}
	fw := &fifoWatch{events: os.NewFile(uintptr(fd), "inotify"), fd: fd}
	if err := syscall.Pipe2(fw.tee[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		return nil, errors.Join(os.NewSyscallError("pipe2", err), fw.events.Close())
	}
	return fw, nil
}

// Close closes what the watch is made of.
func (fw *fifoWatch) Close() error {
	return errors.Join(fw.events.Close(), hostCloseFD(fw.tee[0]), hostCloseFD(fw.tee[1]))
}

// watch watches the FIFO f, a file of the host's, for opens.
func (fw *fifoWatch) watch(f File) error {
	var err error
	if !hostDescriptor(f, func(fd uintptr) { _, err = syscall.InotifyAddWatch(fw.fd, hostFDPath(fd), syscall.IN_OPEN) }) {
		return fmt.Errorf("%s has no descriptor of the host's", f.Name())
	}
	return os.NewSyscallError("inotify_add_watch", err)
}

// drain reads the events of the watch that are there.
func (fw *fifoWatch) drain() error {
	// Room for one event at least, as inotify(7) asks of a read.
	buf := make([]byte, syscall.SizeofInotifyEvent+syscall.NAME_MAX+1)
	for {
		_, err := syscall.Read(fw.fd, buf)
		switch {
		case err == nil, errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EAGAIN):
			return nil
		}
		return os.NewSyscallError("read", err)
	}
}

// hasWriter reports whether f, the read end of a FIFO the runtime opened
// without waiting, has had a writer since it was opened: one is there now,
// or came and went. tee(2) of a byte that does not wait tells of one that
// is there (gVisor's nonblockingPipeHasWriter): EAGAIN is a FIFO that is
// empty and has a writer, a byte one that has input, which a writer put
// there; nothing is taken out of the FIFO. Of a FIFO that is empty and has
// no writer, poll(2) tells of one that came and went: POLLHUP is set when
// no writer is there and one has opened the FIFO since the read end was
// opened, or was there then (fs/pipe.c pipe_poll compares the count of
// writers' opens with the one fifo_open kept for a reader that does not
// wait), and input when one has come since the tee. The input tee found is
// not asked about again: another reader may take it before poll(2), while
// the writer that put it there stays and opens nothing more.
func (fw *fifoWatch) hasWriter(f File) (bool, error) {
	var n int64
	var err error
	if !hostDescriptor(f, func(fd uintptr) {
		for {
			if n, err = syscall.Tee(int(fd), fw.tee[1], 1, spliceFNonblock); !errors.Is(err, syscall.EINTR) {
				return
			}
		}
	}) {
		return false, fmt.Errorf("%s has no descriptor of the host's", f.Name())
	}
	switch {
	case errors.Is(err, syscall.EAGAIN), err == nil && n > 0:
		return true, nil
	case err != nil:
		return false, os.NewSyscallError("tee", err)
	}
	set := []hostWaitFD{{stream: f, want: hostWantInput}}
	if err := waitHostReady(set, time.Now(), -1); err != nil {
		return false, err
	}
	return set[0].ready, nil
}

// hostSiginfo is Linux's siginfo_t of a child (waitid(2)): si_signo,
// si_errno and si_code, then, in the union, aligned as a pointer is,
// si_pid, si_uid and si_status, and room for the rest of its 128 bytes.
type hostSiginfo struct {
	signo, errno, code int32
	_                  [unsafe.Sizeof(uintptr(0))/4 - 1]int32
	pid, uid, status   int32
	_                  [128 - 24]byte
}
