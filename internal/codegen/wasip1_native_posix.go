//go:build darwin || linux

package codegen

import (
	"math"
	"os"
	"runtime"
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
// (hostSysRecvmsg, hostSysSendmsg), on socket fd over iov once, without
// waiting (MSG_DONTWAIT): see hostIO. (syscall.Recvmsg and SendmsgN take
// one buffer, not the guest's iovecs.)
func messageIO(trap, fd uintptr, iov []syscall.Iovec) (n int, again bool, err error) {
	var h syscall.Msghdr
	if len(iov) > 0 {
		h.Iov = &iov[0]
		for range iov {
			h.Iovlen++ // its type differs from host to host
		}
	}
	return hostIO(func() (uintptr, syscall.Errno) {
		r, _, errno := syscall.Syscall(trap, fd, uintptr(unsafe.Pointer(&h)), syscall.MSG_DONTWAIT)
		runtime.KeepAlive(&h)
		runtime.KeepAlive(iov)
		return r, errno
	})
}

// recvNow receives into bufs from socket fd without waiting.
func recvNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, _ := hostIovecs(bufs)
	return messageIO(hostSysRecvmsg, fd, iov)
}

// sendNow sends bufs to socket fd without waiting.
func sendNow(fd uintptr, bufs [][]byte) (n int, again bool, err error) {
	iov, err := writeIovecs(fd, bufs)
	if err != nil {
		return 0, false, err
	}
	return messageIO(hostSysSendmsg, fd, iov)
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

// hostONonblock is the open flag of the host that opens a file without
// waiting (a FIFO nobody writes to, or reads from).
const hostONonblock = syscall.O_NONBLOCK
