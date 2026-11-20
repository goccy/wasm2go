//go:build linux

package codegen

// Numbers of the operating system (see "the numbers of the operating
// system" in wasip1_native_posix.go). A family is a kind of number, and a
// name is the one the number has in C.

import "syscall"

// hostNumbers holds the numbers of linux that package syscall has on every
// architecture, by family and name.
var hostNumbers = map[int32][]hostNumber{
	1: { // errno
		{"E2BIG", int64(syscall.E2BIG)},
		{"EACCES", int64(syscall.EACCES)},
		{"EADDRINUSE", int64(syscall.EADDRINUSE)},
		{"EADDRNOTAVAIL", int64(syscall.EADDRNOTAVAIL)},
		{"EAFNOSUPPORT", int64(syscall.EAFNOSUPPORT)},
		{"EAGAIN", int64(syscall.EAGAIN)},
		{"EALREADY", int64(syscall.EALREADY)},
		{"EBADF", int64(syscall.EBADF)},
		{"EBADMSG", int64(syscall.EBADMSG)},
		{"EBUSY", int64(syscall.EBUSY)},
		{"ECANCELED", int64(syscall.ECANCELED)},
		{"ECHILD", int64(syscall.ECHILD)},
		{"ECONNABORTED", int64(syscall.ECONNABORTED)},
		{"ECONNREFUSED", int64(syscall.ECONNREFUSED)},
		{"ECONNRESET", int64(syscall.ECONNRESET)},
		{"EDEADLK", int64(syscall.EDEADLK)},
		{"EDESTADDRREQ", int64(syscall.EDESTADDRREQ)},
		{"EDOM", int64(syscall.EDOM)},
		{"EDQUOT", int64(syscall.EDQUOT)},
		{"EEXIST", int64(syscall.EEXIST)},
		{"EFAULT", int64(syscall.EFAULT)},
		{"EFBIG", int64(syscall.EFBIG)},
		{"EHOSTUNREACH", int64(syscall.EHOSTUNREACH)},
		{"EIDRM", int64(syscall.EIDRM)},
		{"EILSEQ", int64(syscall.EILSEQ)},
		{"EINPROGRESS", int64(syscall.EINPROGRESS)},
		{"EINTR", int64(syscall.EINTR)},
		{"EINVAL", int64(syscall.EINVAL)},
		{"EIO", int64(syscall.EIO)},
		{"EISCONN", int64(syscall.EISCONN)},
		{"EISDIR", int64(syscall.EISDIR)},
		{"ELOOP", int64(syscall.ELOOP)},
		{"EMFILE", int64(syscall.EMFILE)},
		{"EMLINK", int64(syscall.EMLINK)},
		{"EMSGSIZE", int64(syscall.EMSGSIZE)},
		{"EMULTIHOP", int64(syscall.EMULTIHOP)},
		{"ENAMETOOLONG", int64(syscall.ENAMETOOLONG)},
		{"ENETDOWN", int64(syscall.ENETDOWN)},
		{"ENETRESET", int64(syscall.ENETRESET)},
		{"ENETUNREACH", int64(syscall.ENETUNREACH)},
		{"ENFILE", int64(syscall.ENFILE)},
		{"ENOBUFS", int64(syscall.ENOBUFS)},
		{"ENODEV", int64(syscall.ENODEV)},
		{"ENOENT", int64(syscall.ENOENT)},
		{"ENOEXEC", int64(syscall.ENOEXEC)},
		{"ENOLCK", int64(syscall.ENOLCK)},
		{"ENOLINK", int64(syscall.ENOLINK)},
		{"ENOMEM", int64(syscall.ENOMEM)},
		{"ENOMSG", int64(syscall.ENOMSG)},
		{"ENOPROTOOPT", int64(syscall.ENOPROTOOPT)},
		{"ENOSPC", int64(syscall.ENOSPC)},
		{"ENOSYS", int64(syscall.ENOSYS)},
		{"ENOTCONN", int64(syscall.ENOTCONN)},
		{"ENOTDIR", int64(syscall.ENOTDIR)},
		{"ENOTEMPTY", int64(syscall.ENOTEMPTY)},
		{"ENOTRECOVERABLE", int64(syscall.ENOTRECOVERABLE)},
		{"ENOTSOCK", int64(syscall.ENOTSOCK)},
		{"ENOTSUP", int64(syscall.ENOTSUP)},
		{"ENOTTY", int64(syscall.ENOTTY)},
		{"ENXIO", int64(syscall.ENXIO)},
		{"EOVERFLOW", int64(syscall.EOVERFLOW)},
		{"EOWNERDEAD", int64(syscall.EOWNERDEAD)},
		{"EPERM", int64(syscall.EPERM)},
		{"EPIPE", int64(syscall.EPIPE)},
		{"EPROTO", int64(syscall.EPROTO)},
		{"EPROTONOSUPPORT", int64(syscall.EPROTONOSUPPORT)},
		{"EPROTOTYPE", int64(syscall.EPROTOTYPE)},
		{"ERANGE", int64(syscall.ERANGE)},
		{"EROFS", int64(syscall.EROFS)},
		{"ESPIPE", int64(syscall.ESPIPE)},
		{"ESRCH", int64(syscall.ESRCH)},
		{"ESTALE", int64(syscall.ESTALE)},
		{"ETIMEDOUT", int64(syscall.ETIMEDOUT)},
		{"ETXTBSY", int64(syscall.ETXTBSY)},
		{"EXDEV", int64(syscall.EXDEV)},
		{"EOPNOTSUPP", int64(syscall.EOPNOTSUPP)},
		{"EWOULDBLOCK", int64(syscall.EWOULDBLOCK)},
	},
}

// hostNumbersFromHeaders holds the numbers of linux that package syscall
// lacks: none.
var hostNumbersFromHeaders = map[int32][]hostNumber{}
