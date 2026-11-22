//go:build darwin || linux

package codegen

import (
	"errors"
	"fmt"
	"io/fs"
	"log/syslog"
	"math"
	"net"
	"os"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned.
func osFileStat(sys any) (fileStat, bool) {
	st, ok := sys.(*syscall.Stat_t)
	if !ok {
		return fileStat{}, false
	}
	atime, ctime := statTimes(st)
	return fileStat{
		dev:   uint64(st.Dev),
		ino:   uint64(st.Ino),
		nlink: uint64(st.Nlink),
		uid:   st.Uid,
		gid:   st.Gid,
		atime: atime,
		ctime: ctime,
		// the widths of these differ from host to host
		rdev:    uint64(st.Rdev),
		blksize: uint32(st.Blksize),
		blocks:  uint64(st.Blocks),
	}, true
}

// hostRename is rename(2): a file renamed onto a directory fails with
// EISDIR, and a directory renamed onto an empty one replaces it. os.Rename
// refuses every rename onto a directory with EEXIST, which no system call
// does.
func hostRename(from, to string) error {
	for {
		err := syscall.Rename(from, to)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
		}
		return nil
	}
}

// hostSignals maps the guest's signal numbers to the host's signals; see
// hostSignalOf.
var hostSignals = map[int32]syscall.Signal{
	wasiSIGHUP:    syscall.SIGHUP,
	wasiSIGINT:    syscall.SIGINT,
	wasiSIGQUIT:   syscall.SIGQUIT,
	wasiSIGILL:    syscall.SIGILL,
	wasiSIGTRAP:   syscall.SIGTRAP,
	wasiSIGABRT:   syscall.SIGABRT,
	wasiSIGBUS:    syscall.SIGBUS,
	wasiSIGFPE:    syscall.SIGFPE,
	wasiSIGKILL:   syscall.SIGKILL,
	wasiSIGUSR1:   syscall.SIGUSR1,
	wasiSIGSEGV:   syscall.SIGSEGV,
	wasiSIGUSR2:   syscall.SIGUSR2,
	wasiSIGPIPE:   syscall.SIGPIPE,
	wasiSIGALRM:   syscall.SIGALRM,
	wasiSIGTERM:   syscall.SIGTERM,
	wasiSIGCHLD:   syscall.SIGCHLD,
	wasiSIGCONT:   syscall.SIGCONT,
	wasiSIGSTOP:   syscall.SIGSTOP,
	wasiSIGTSTP:   syscall.SIGTSTP,
	wasiSIGTTIN:   syscall.SIGTTIN,
	wasiSIGTTOU:   syscall.SIGTTOU,
	wasiSIGURG:    syscall.SIGURG,
	wasiSIGXCPU:   syscall.SIGXCPU,
	wasiSIGXFSZ:   syscall.SIGXFSZ,
	wasiSIGVTALRM: syscall.SIGVTALRM,
	wasiSIGPROF:   syscall.SIGPROF,
	wasiSIGWINCH:  syscall.SIGWINCH,
	wasiSIGIO:     syscall.SIGIO,
	wasiSIGSYS:    syscall.SIGSYS,
}

// hostSignalOf returns the host's signal for a guest signal number. Number
// 0, the existence probe of kill, is the same everywhere. known is false for
// a signal this host does not have. A number the table does not name may still
// be a signal of the host (hostSignalByNumber).
func hostSignalOf(sig int32) (hostSig syscall.Signal, known bool) {
	if sig == 0 {
		return 0, true
	}
	if hostSig, known = hostSignals[sig]; known {
		return hostSig, true
	}
	return hostSignalByNumber(sig)
}

// guestSignalOf returns the guest's number for a host signal, or 0 when the
// guest has none for it.
func guestSignalOf(hostSig syscall.Signal) int32 {
	for sig, candidate := range hostSignals {
		if candidate == hostSig {
			return sig
		}
	}
	return 0
}

// hostSetUmask sets the umask of the host process to the permission bits of
// mask (umask(2)) and returns the previous one.
func hostSetUmask(mask os.FileMode) (os.FileMode, error) {
	s := &hostUmaskState
	s.read.Do(func() {})
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := os.FileMode(syscall.Umask(int(mask.Perm()))).Perm()
	s.known, s.mask = true, mask.Perm()
	return prev, nil
}

// hostSetThreadUmask sets the umask of a creation thread (umask(2) on it,
// whose file system attributes are its own).
func hostSetThreadUmask(mask os.FileMode) { syscall.Umask(int(mask.Perm())) }

// hostProcessTimes returns the CPU time of the host process — user, then
// system — and of the children it has waited for.
func hostProcessTimes() (ProcessTimes, error) {
	var self, children syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &self); err != nil {
		return ProcessTimes{}, err
	}
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &children); err != nil {
		return ProcessTimes{}, err
	}
	return ProcessTimes{
		User:           time.Duration(self.Utime.Nano()),
		System:         time.Duration(self.Stime.Nano()),
		ChildrenUser:   time.Duration(children.Utime.Nano()),
		ChildrenSystem: time.Duration(children.Stime.Nano()),
	}, nil
}

// descriptorWaits reports whether a call on the descriptor waits when there
// is nothing for it: it is not in non-blocking mode, which the descriptors
// the runtime polls are. Such a descriptor cannot be asked what is there.
func descriptorWaits(fd uintptr) bool {
	flags, err := descriptorFlags(int(fd), syscall.F_GETFL)
	return err != nil || flags&syscall.O_NONBLOCK == 0
}

// hostIovecs returns the iovecs of the buffers of bufs that have room: no
// more than IOV_MAX (1024) of them, and no more than INT_MAX bytes in all,
// more than darwin's readv(2) and writev(2) take (EINVAL), so that a call
// given more moves fewer bytes, as a short read or write does. tooMany reports that bufs has more buffers
// with room than one call takes.
func hostIovecs(bufs [][]byte) (iov []syscall.Iovec, tooMany bool) {
	left := math.MaxInt32
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		if len(iov) == 1024 {
			return iov, true
		}
		if left > 0 {
			v := syscall.Iovec{Base: &buf[0]}
			v.SetLen(min(len(buf), left))
			iov, left = append(iov, v), left-min(len(buf), left)
		}
	}
	return iov, false
}

// writeIovecs is hostIovecs for a write to fd. A datagram socket refuses
// more buffers than one call takes (EINVAL): a datagram is not split into
// two. A descriptor that is no socket (ENOTSOCK) takes a short write.
func writeIovecs(fd uintptr, bufs [][]byte) ([]syscall.Iovec, error) {
	iov, tooMany := hostIovecs(bufs)
	if tooMany {
		typ, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		switch {
		case err == syscall.ENOTSOCK:
		case err != nil:
			return nil, os.NewSyscallError("getsockopt", err)
		case typ != syscall.SOCK_STREAM:
			return nil, syscall.EINVAL
		}
	}
	return iov, nil
}

// hostStreamSendLowat returns the low-water mark of socket fd for sending
// (SO_SNDLOWAT), which a stream socket that poll(2) reports writable has
// room for, or 0 for a socket of another type, which takes a datagram whole.
func hostStreamSendLowat(fd uintptr) (int, error) {
	typ, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	if typ != syscall.SOCK_STREAM {
		return 0, nil
	}
	lowat, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDLOWAT)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	return lowat, nil
}

// hostIO makes the system call that call makes once, again on EINTR. again
// reports that a descriptor in non-blocking mode has nothing or no room
// right now; otherwise n bytes were moved (none at the end of input), or err
// says why not.
func hostIO(call func() (uintptr, syscall.Errno)) (n int, again bool, err error) {
	for {
		r, errno := call()
		switch errno {
		case 0:
			return int(r), false, nil
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
			return 0, true, nil
		}
		return 0, false, errno
	}
}

// readvRaw reads from fd into bufs with one readv(2): see hostIO. (Package
// syscall has no Readv.)
func readvRaw(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, _ := hostIovecs(bufs)
	if len(iov) == 0 {
		return 0, false, nil
	}
	return hostIO(func() (uintptr, syscall.Errno) {
		r, _, errno := syscall.Syscall(syscall.SYS_READV, fd, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		runtime.KeepAlive(iov)
		return r, errno
	})
}

// writevRaw writes bufs to fd with one writev(2): see hostIO. (Package
// syscall has no Writev.)
func writevRaw(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, err := writeIovecs(fd, bufs)
	if err != nil || len(iov) == 0 {
		return 0, false, err
	}
	return hostIO(func() (uintptr, syscall.Errno) {
		r, _, errno := syscall.Syscall(syscall.SYS_WRITEV, fd, uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
		runtime.KeepAlive(iov)
		return r, errno
	})
}

// messageIO makes system call trap, recvmsg(2) or sendmsg(2)
// (hostSysRecvmsg, hostSysSendmsg), on socket fd over iov once, with flags
// (MSG_*): see hostIO. msgFlags are the flags the host gives back (a
// receive's MSG_TRUNC). (syscall.Recvmsg and SendmsgN take one buffer, not
// the guest's iovecs.)
func messageIO(trap, fd uintptr, iov []syscall.Iovec, flags int) (n int, msgFlags int32, again bool, err error) {
	var h syscall.Msghdr
	if len(iov) > 0 {
		h.Iov = &iov[0]
		for range iov {
			h.Iovlen++ // its type differs from host to host
		}
	}
	n, again, err = hostIO(func() (uintptr, syscall.Errno) {
		r, _, errno := syscall.Syscall(trap, fd, uintptr(unsafe.Pointer(&h)), uintptr(flags))
		runtime.KeepAlive(&h)
		runtime.KeepAlive(iov)
		return r, errno
	})
	return n, h.Flags, again, err
}

// recvNow receives into bufs from socket fd without waiting.
func recvNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, _ := hostIovecs(bufs)
	n, _, again, err = messageIO(hostSysRecvmsg, fd, iov, syscall.MSG_DONTWAIT)
	return n, again, err
}

// sendNow sends bufs to socket fd without waiting.
func sendNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, err := writeIovecs(fd, bufs)
	if err != nil {
		return 0, false, err
	}
	n, _, again, err = messageIO(hostSysSendmsg, fd, iov, syscall.MSG_DONTWAIT)
	return n, again, err
}

// hostCloseFD closes a descriptor of the runtime's own.
func hostCloseFD(fd int) error {
	if err := syscall.Close(fd); err != nil {
		return os.NewSyscallError("close", err)
	}
	return nil
}

// hostStreamWrites says that the host can write to a stream without waiting
// in the write, and wait for one to have room: see writevRaw and
// hostWaitReady.
const hostStreamWrites = true

// openForWriting reports whether the descriptor is open for writing. One the
// host cannot be asked about counts as open; the write then tells.
func openForWriting(fd uintptr) bool {
	flags, err := descriptorFlags(int(fd), syscall.F_GETFL)
	if err != nil {
		return true
	}
	return flags&syscall.O_ACCMODE != syscall.O_RDONLY
}

// descriptorFlags returns what fcntl(fd, get) reports: the descriptor flags
// for F_GETFD, the status flags for F_GETFL.
func descriptorFlags(fd int, get int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(get), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

// ---- the numbers of the operating system ---------------------------------
//
// The host's numbers and wasi's differ: every number has a name in C,
// and the two sides meet by that name. The tables are in the
// wasip1_hostnumbers_* files, one family of numbers after another.

// hostNumber is a number of the operating system under its name in C.
type hostNumber struct {
	name  string
	value int64
}

// hostNumberFamilyErrno is the family of the error numbers.
const hostNumberFamilyErrno int32 = 1

// hostNumberTables returns the numbers of every family: those package
// syscall has, then those taken from the system's headers.
var hostNumberTables = sync.OnceValue(func() map[int32][]hostNumber {
	tables := make(map[int32][]hostNumber, len(hostNumbers))
	for family, numbers := range hostNumbers {
		tables[family] = append(tables[family], numbers...)
	}
	for family, numbers := range hostNumbersFromHeaders {
		tables[family] = append(tables[family], numbers...)
	}
	return tables
})

// hostNumberTable returns the numbers of a family, in the order of its
// table; none for a family the host has no table of.
func hostNumberTable(family int32) []hostNumber {
	return hostNumberTables()[family]
}

// wasiErrnoNames holds the name of every wasi errno, at its number.
var wasiErrnoNames = [...]string{
	1: "E2BIG", 2: "EACCES", 3: "EADDRINUSE", 4: "EADDRNOTAVAIL", 5: "EAFNOSUPPORT",
	6: "EAGAIN", 7: "EALREADY", 8: "EBADF", 9: "EBADMSG", 10: "EBUSY",
	11: "ECANCELED", 12: "ECHILD", 13: "ECONNABORTED", 14: "ECONNREFUSED", 15: "ECONNRESET",
	16: "EDEADLK", 17: "EDESTADDRREQ", 18: "EDOM", 19: "EDQUOT", 20: "EEXIST",
	21: "EFAULT", 22: "EFBIG", 23: "EHOSTUNREACH", 24: "EIDRM", 25: "EILSEQ",
	26: "EINPROGRESS", 27: "EINTR", 28: "EINVAL", 29: "EIO", 30: "EISCONN",
	31: "EISDIR", 32: "ELOOP", 33: "EMFILE", 34: "EMLINK", 35: "EMSGSIZE",
	36: "EMULTIHOP", 37: "ENAMETOOLONG", 38: "ENETDOWN", 39: "ENETRESET", 40: "ENETUNREACH",
	41: "ENFILE", 42: "ENOBUFS", 43: "ENODEV", 44: "ENOENT", 45: "ENOEXEC",
	46: "ENOLCK", 47: "ENOLINK", 48: "ENOMEM", 49: "ENOMSG", 50: "ENOPROTOOPT",
	51: "ENOSPC", 52: "ENOSYS", 53: "ENOTCONN", 54: "ENOTDIR", 55: "ENOTEMPTY",
	56: "ENOTRECOVERABLE", 57: "ENOTSOCK", 58: "ENOTSUP", 59: "ENOTTY", 60: "ENXIO",
	61: "EOVERFLOW", 62: "EOWNERDEAD", 63: "EPERM", 64: "EPIPE", 65: "EPROTO",
	66: "EPROTONOSUPPORT", 67: "EPROTOTYPE", 68: "ERANGE", 69: "EROFS", 70: "ESPIPE",
	71: "ESRCH", 72: "ESTALE", 73: "ETIMEDOUT", 74: "ETXTBSY", 75: "EXDEV",
	76: "ENOTCAPABLE",
}

// wasiErrnoOfHost maps the host's error numbers to wasi's: the two that
// have the same name. Two names of the host for one number (EAGAIN and
// EWOULDBLOCK, ENOTSUP and EOPNOTSUPP on linux) are one error in wasi too.
var wasiErrnoOfHost = sync.OnceValue(func() map[syscall.Errno]int32 {
	host := make(map[string]int64)
	for _, n := range hostNumberTable(hostNumberFamilyErrno) {
		host[n.name] = n.value
	}
	byHost := make(map[syscall.Errno]int32)
	for wasi, name := range wasiErrnoNames {
		if value, ok := host[name]; ok && name != "" {
			byHost[syscall.Errno(value)] = int32(wasi)
		}
	}
	for alias, wasi := range map[string]int32{"EWOULDBLOCK": _wasiEAGAIN, "EOPNOTSUPP": _wasiENOTSUP} {
		if value, ok := host[alias]; ok {
			if _, known := byHost[syscall.Errno(value)]; !known {
				byHost[syscall.Errno(value)] = wasi
			}
		}
	}
	return byHost
})

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error.
func wasiErrno(e syscall.Errno) (int32, bool) {
	n, ok := wasiErrnoOfHost()[e]
	return n, ok
}

// setHostIDs makes a change of the user or group ids of the host process.
func setHostIDs(change IDChange) error {
	a, b, c := int(change.IDs[0]), int(change.IDs[1]), int(change.IDs[2])
	switch change.Call {
	case IDSetuid:
		return syscall.Setuid(a)
	case IDSeteuid:
		return syscall.Seteuid(a)
	case IDSetreuid:
		return syscall.Setreuid(a, b)
	case IDSetresuid:
		return setHostRESUID(a, b, c)
	case IDSetgid:
		return syscall.Setgid(a)
	case IDSetegid:
		return syscall.Setegid(a)
	case IDSetregid:
		return syscall.Setregid(a, b)
	case IDSetresgid:
		return setHostRESGID(a, b, c)
	}
	return syscall.EINVAL
}

// setHostGroups sets the supplementary groups of the host process.
func setHostGroups(gids []int) error { return syscall.Setgroups(gids) }

// makeHostFIFO creates a FIFO in the host filesystem.
func makeHostFIFO(path string, perm os.FileMode) error {
	return syscall.Mkfifo(path, uint32(perm.Perm()))
}

// withHostDescriptor calls use with the descriptor of f. The descriptor is
// borrowed through SyscallConn rather than taken with Fd, which would
// switch a pipe or terminal to blocking mode for good.
func withHostDescriptor(f *os.File, use func(fd uintptr) error) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var useErr error
	if err := conn.Control(func(fd uintptr) { useErr = use(fd) }); err != nil {
		// Control fails only for a file that is being closed, with an
		// error of its own that is not fs.ErrClosed.
		return fmt.Errorf("%w: %w", fs.ErrClosed, err)
	}
	return useErr
}

// withDuplicateDescriptor calls use with a duplicate of the descriptor of
// f, made close-on-exec while f's descriptor is borrowed and closed when
// use returns: a call of use that waits holds no reference to f, whose
// Close would wait for it.
func withDuplicateDescriptor(f *os.File, use func(fd uintptr) error) error {
	var dup int
	if err := withHostDescriptor(f, func(fd uintptr) error {
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()
		var err error
		if dup, err = syscall.Dup(int(fd)); err != nil {
			return err
		}
		syscall.CloseOnExec(dup)
		return nil
	}); err != nil {
		return err
	}
	return errors.Join(use(uintptr(dup)), syscall.Close(dup))
}

// flockOSFile applies flock(2) with how (LockFS.Flock's) to a file of the
// host process. A lock that may have to be waited for is taken through a
// duplicate of the descriptor (withDuplicateDescriptor), which shares the
// open file description the lock belongs to. A call the delivery of a
// signal to the host process interrupts (EINTR) is made again.
func flockOSFile(f *os.File, how int) error {
	on := withHostDescriptor
	if how&(syscall.LOCK_NB|syscall.LOCK_UN) == 0 {
		on = withDuplicateDescriptor
	}
	return on(f, func(fd uintptr) error {
		for {
			if err := syscall.Flock(int(fd), how); !errors.Is(err, syscall.EINTR) {
				return err
			}
		}
	})
}

// hostRecordLock is fcntl(2) F_GETLK (recordLockGet, which writes the lock
// in the way back into lk), F_SETLK (recordLockSet) or F_SETLKW
// (recordLockWait) on the descriptor of f, by the commands
// hostRecordLockCommands names. Where the locks are the open file
// description's (hostRecordLocksOfDescription), a lock that may have to be
// waited for is taken through a duplicate of the descriptor
// (withDuplicateDescriptor); where they are the process's, closing the
// duplicate would release them, and the wait holds f's descriptor. A call
// the delivery of a signal to the host process interrupts (EINTR) is made
// again.
func hostRecordLock(f *os.File, cmd int32, lk *recordLock) error {
	types := [3]int16{syscall.F_RDLCK, syscall.F_WRLCK, syscall.F_UNLCK}
	fl := syscall.Flock_t{Type: types[lk.typ], Whence: int16(lk.whence), Start: lk.start, Len: lk.len}
	op := hostRecordLockCommands[cmd]
	on := withHostDescriptor
	if cmd == recordLockWait && hostRecordLocksOfDescription {
		on = withDuplicateDescriptor
	}
	err := on(f, func(fd uintptr) error {
		for {
			if err := syscall.FcntlFlock(fd, op, &fl); !errors.Is(err, syscall.EINTR) {
				return err
			}
		}
	})
	if err != nil || cmd != recordLockGet {
		return err
	}
	for i, t := range types {
		if fl.Type == t {
			lk.typ = int32(i)
		}
	}
	lk.whence, lk.start, lk.len, lk.pid = int32(fl.Whence), fl.Start, fl.Len, int32(fl.Pid)
	return nil
}

// hostSyslogger is the Syslogger HostSyslog returns: at most one connection
// of package log/syslog for each facility, made for the ident it was last
// used with. Its lock is held across every write, so a connection Close
// has closed is never written to (package log/syslog would open it again).
type hostSyslogger struct {
	mu      sync.Mutex
	writers map[int32]*hostSyslogWriter
}

// hostSyslogWriter is a connection of a hostSyslogger and the ident it was
// made for.
type hostSyslogWriter struct {
	writer *syslog.Writer
	ident  string
}

// syslogFacilityUser is the facility LOG_USER, syslog(3)'s default.
const syslogFacilityUser int32 = 1

// newHostSyslog returns the host's system logger (see HostSyslog).
func newHostSyslog() (Syslogger, error) {
	l := &hostSyslogger{writers: map[int32]*hostSyslogWriter{}}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.writerLocked("", syslogFacilityUser); err != nil {
		return nil, err
	}
	return l, nil
}

// writerLocked returns the connection for facility made for ident. One
// made for another ident is closed and replaced. Caller holds l.mu.
func (l *hostSyslogger) writerLocked(ident string, facility int32) (*syslog.Writer, error) {
	if facility < 0 || facility > 23 {
		return nil, syscall.EINVAL
	}
	if wr := l.writers[facility]; wr != nil {
		if wr.ident == ident {
			return wr.writer, nil
		}
		delete(l.writers, facility)
		if err := wr.writer.Close(); err != nil {
			return nil, err
		}
	}
	wr, err := syslog.New(syslog.Priority(facility<<3)|syslog.LOG_INFO, ident)
	if err != nil {
		return nil, err
	}
	l.writers[facility] = &hostSyslogWriter{writer: wr, ident: ident}
	return wr, nil
}

func (l *hostSyslogger) Open(ident string, options, facility int32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.writerLocked(ident, facility)
	return err
}

func (l *hostSyslogger) Log(msg SyslogMessage) error {
	if msg.Severity < 0 || msg.Severity > 7 {
		return syscall.EINVAL
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	wr, err := l.writerLocked(msg.Ident, msg.Facility)
	if err != nil {
		return err
	}
	return [...]func(string) error{wr.Emerg, wr.Alert, wr.Crit, wr.Err, wr.Warning, wr.Notice, wr.Info, wr.Debug}[msg.Severity](msg.Message)
}

// Close closes every connection; a message logged later connects again.
func (l *hostSyslogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	for facility, wr := range l.writers {
		err = errors.Join(err, wr.writer.Close())
		delete(l.writers, facility)
	}
	return err
}

// clearHostNonblock makes the descriptor of f, a file of the host, one
// that waits (clears O_NONBLOCK). A File of another backend is left as it
// is.
func clearHostNonblock(f File) error {
	file, isHost := f.(*os.File)
	if !isHost {
		return nil
	}
	return withHostDescriptor(file, func(fd uintptr) error { return syscall.SetNonblock(int(fd), false) })
}

// hostONonblock is the open flag of the host that opens a file without
// waiting (a FIFO nobody writes to, or reads from).
const hostONonblock = syscall.O_NONBLOCK

// ----- sockets ----------------------------------------------------------------

// hostOpensSockets says that the runtime makes sockets of the host's.
const hostOpensSockets = true

// hostDomain is the host's address family of a guest's (wasiSockFamily*).
func hostDomain(family int32) int {
	switch family {
	case wasiSockFamilyIPv6:
		return syscall.AF_INET6
	case wasiSockFamilyUnix:
		return syscall.AF_UNIX
	}
	return syscall.AF_INET
}

// hostSocketType is the host's socket type of a datagram socket (dgram) or a
// stream one.
func hostSocketType(dgram bool) int {
	if dgram {
		return syscall.SOCK_DGRAM
	}
	return syscall.SOCK_STREAM
}

// openHostSocket makes a socket of the host's of the family and type, in
// non-blocking mode and closed on exec (hostSocketFD).
func openHostSocket(family int32, dgram bool) (*os.File, error) {
	fd, err := hostSocketFD(hostDomain(family), hostSocketType(dgram))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "socket"), nil
}

// hostSocketPair makes two connected Unix-domain sockets of the host's of
// the type, in non-blocking mode and closed on exec (hostSocketPairFDs).
func hostSocketPair(dgram bool) (a, b *os.File, err error) {
	fds, err := hostSocketPairFDs(hostSocketType(dgram))
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "socket"), os.NewFile(uintptr(fds[1]), "socket"), nil
}

// hostSockaddr is the host's address of the guest's a; hostPath is the
// host's name of a Unix-domain one (unixHostPath).
func hostSockaddr(a wasiSockAddr, hostPath string) syscall.Sockaddr {
	switch a.family {
	case wasiSockFamilyIPv4:
		sa := &syscall.SockaddrInet4{Port: a.port}
		copy(sa.Addr[:], a.ip.To4())
		return sa
	case wasiSockFamilyIPv6:
		sa := &syscall.SockaddrInet6{Port: a.port, ZoneId: a.scope}
		copy(sa.Addr[:], a.ip.To16())
		return sa
	}
	return &syscall.SockaddrUnix{Name: hostPath}
}

// guestSockAddr is the guest's address of the host's sa: of family 0 for
// none.
func guestSockAddr(sa syscall.Sockaddr) wasiSockAddr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return wasiSockAddr{family: wasiSockFamilyIPv4, ip: append(net.IP(nil), sa.Addr[:]...), port: sa.Port}
	case *syscall.SockaddrInet6:
		return wasiSockAddr{family: wasiSockFamilyIPv6, ip: append(net.IP(nil), sa.Addr[:]...), port: sa.Port, scope: sa.ZoneId}
	case *syscall.SockaddrUnix:
		return wasiSockAddr{family: wasiSockFamilyUnix, name: unixGuestName(sa.Name)}
	}
	return wasiSockAddr{}
}

// hostBind binds socket fd to a (bind(2)).
func hostBind(fd int, a wasiSockAddr, hostPath string) error {
	return os.NewSyscallError("bind", syscall.Bind(fd, hostSockaddr(a, hostPath)))
}

// hostListen makes socket fd listen (listen(2)).
func hostListen(fd, backlog int) error {
	return os.NewSyscallError("listen", syscall.Listen(fd, backlog))
}

// hostAccept accepts a connection on socket fd (accept(2)) without
// waiting, as hostAcceptFD makes it; again reports that none is waiting. A
// connection that was aborted before it was accepted is none, as Go's
// internal/poll has it.
func hostAccept(fd int) (conn int, again bool, err error) {
	for {
		conn, err := hostAcceptFD(fd)
		switch {
		case err == nil:
			return conn, false, nil
		case errors.Is(err, syscall.EINTR), errors.Is(err, syscall.ECONNABORTED):
			continue
		case errors.Is(err, syscall.EAGAIN):
			return -1, true, nil
		}
		return -1, false, err
	}
}

// hostConnect starts connecting socket fd to a (connect(2)), which does not
// wait: EINPROGRESS for a connection that is not made at once. For a of
// family 0 it gives the host AF_UNSPEC, which package syscall has no
// address of.
func hostConnect(fd int, a wasiSockAddr, hostPath string) error {
	if a.family != 0 {
		return os.NewSyscallError("connect", syscall.Connect(fd, hostSockaddr(a, hostPath)))
	}
	unspec := syscall.RawSockaddr{Family: syscall.AF_UNSPEC}
	_, _, errno := syscall.Syscall(hostSysConnect, uintptr(fd), uintptr(unsafe.Pointer(&unspec)), unsafe.Sizeof(unspec))
	if errno != 0 {
		return os.NewSyscallError("connect", errno)
	}
	return nil
}

// hostConnectDone reports whether the connection socket fd started has
// ended (again: not yet), and how: as Go's package net finds out (netFD's
// connect), SO_ERROR gives the failure, and with none, getpeername tells a
// connection made from one still under way.
func hostConnectDone(fd int) (again bool, err error) {
	failure, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return false, os.NewSyscallError("getsockopt", err)
	}
	switch e := syscall.Errno(failure); e {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		return true, nil
	case 0:
		// woken without the connection made (Go's issues 14548, 19289)
		switch _, err := syscall.Getpeername(fd); err {
		case nil:
			return false, nil
		case syscall.ENOTCONN:
			return true, nil
		default:
			return false, os.NewSyscallError("getpeername", err)
		}
	default:
		return false, os.NewSyscallError("connect", e)
	}
}

// hostSocketName returns the name of socket fd, or of its peer
// (getsockname(2), getpeername(2)).
func hostSocketName(fd int, peer bool) (wasiSockAddr, error) {
	if peer {
		sa, err := syscall.Getpeername(fd)
		return guestSockAddr(sa), os.NewSyscallError("getpeername", err)
	}
	sa, err := syscall.Getsockname(fd)
	return guestSockAddr(sa), os.NewSyscallError("getsockname", err)
}

// hostReceive receives into bufs from socket fd once, without waiting
// (recvmsg(2)); peek leaves what it receives there (MSG_PEEK). truncated
// reports a datagram cut to the buffers; see hostIO for the rest.
func hostReceive(fd int, bufs [][]byte, peek bool) (n int, truncated, again bool, err error) {
	flags := syscall.MSG_DONTWAIT
	if peek {
		flags |= syscall.MSG_PEEK
	}
	iov, _ := hostIovecs(bufs)
	n, msgFlags, again, err := messageIO(hostSysRecvmsg, uintptr(fd), iov, flags)
	return n, msgFlags&syscall.MSG_TRUNC != 0, again, os.NewSyscallError("recvmsg", err)
}

// hostReceiveFrom receives into buf from socket fd once, without waiting,
// and returns the sender (recvmsg(2)); peek leaves what it receives there.
// See hostIO for the rest.
func hostReceiveFrom(fd int, buf []byte, peek bool) (n int, from wasiSockAddr, again bool, err error) {
	flags := syscall.MSG_DONTWAIT
	if peek {
		flags |= syscall.MSG_PEEK
	}
	var sa syscall.Sockaddr
	n, again, err = hostIO(func() (uintptr, syscall.Errno) {
		k, _, _, got, err := syscall.Recvmsg(fd, buf, nil, flags)
		sa = got
		return uintptr(k), errnoOf(err)
	})
	return n, guestSockAddr(sa), again, os.NewSyscallError("recvmsg", err)
}

// hostSend sends bufs on socket fd once, without waiting (sendmsg(2)): to
// the address to, with hostPath the host's name of a Unix-domain one, or,
// for to nil, to the socket's peer. See hostIO for the rest.
func hostSend(fd int, bufs [][]byte, to *wasiSockAddr, hostPath string) (n int, again bool, err error) {
	if to == nil && firstBuffer(bufs) != nil {
		n, again, err = sendNow(uintptr(fd), bufs)
		return n, again, os.NewSyscallError("sendmsg", err)
	}
	// A send to an address, or of nothing (one empty iovec: darwin
	// refuses none)
	var sa syscall.Sockaddr
	if to != nil {
		sa = hostSockaddr(*to, hostPath)
	}
	buf := slices.Concat(bufs...)
	n, again, err = hostIO(func() (uintptr, syscall.Errno) {
		k, err := syscall.SendmsgN(fd, buf, nil, sa, syscall.MSG_DONTWAIT)
		return uintptr(k), errnoOf(err)
	})
	return n, again, os.NewSyscallError("sendmsg", err)
}

// errnoOf is the error number err of a call of package syscall is, which
// returns no other: 0 for none.
func errnoOf(err error) syscall.Errno {
	var errno syscall.Errno
	errors.As(err, &errno)
	return errno
}

// hostShutdown shuts the halves how (1 reading, 2 writing) of socket fd
// down (shutdown(2)).
func hostShutdown(fd int, how int32) error {
	halves := syscall.SHUT_RDWR
	switch how {
	case 0x1:
		halves = syscall.SHUT_RD
	case 0x2:
		halves = syscall.SHUT_WR
	}
	return os.NewSyscallError("shutdown", syscall.Shutdown(fd, halves))
}
