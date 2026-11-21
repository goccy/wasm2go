//go:build darwin || linux

package codegen

import (
	"os"
	"sync"
	"syscall"
	"time"
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
