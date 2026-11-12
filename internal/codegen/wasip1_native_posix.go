//go:build darwin || linux

package codegen

import (
	"errors"
	"net"
	"os"
	"syscall"
)

// processUmask is the file mode creation mask of the host process. The only
// way to read it is to set it, so it is read once, while the program is
// still initializing its packages and nothing creates files concurrently.
var processUmask = readProcessUmask()

func readProcessUmask() os.FileMode {
	mask := syscall.Umask(0)
	syscall.Umask(mask)
	return os.FileMode(mask) & 0o777
}

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
	}, true
}

// flockOSFile applies flock(2) to a file of the host process. The descriptor
// is borrowed through SyscallConn rather than taken with Fd, which would
// switch a pipe or terminal to blocking mode for good.
func flockOSFile(f *os.File, lock FileLock, wait bool) error {
	how := syscall.LOCK_UN
	switch lock {
	case FileLockShared:
		how = syscall.LOCK_SH
	case FileLockExclusive:
		how = syscall.LOCK_EX
	}
	if lock != FileUnlock && !wait {
		how |= syscall.LOCK_NB
	}
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) {
		for {
			lockErr = syscall.Flock(int(fd), how)
			if lockErr != syscall.EINTR {
				return
			}
		}
	}); err != nil {
		return err
	}
	return lockErr
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
// a signal this host does not have.
func hostSignalOf(sig int32) (hostSig syscall.Signal, known bool) {
	if sig == 0 {
		return 0, true
	}
	hostSig, known = hostSignals[sig]
	return hostSig, known
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

// signalHostProcess sends a signal to a process of the host.
func signalHostProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// hostProcessGroup returns the process group of a process of the host, 0
// naming the host process itself.
func hostProcessGroup(pid int) (int, error) {
	return syscall.Getpgid(pid)
}

// setHostProcessGroup moves a process of the host — 0 names the host
// process itself — into a process group, 0 standing for a group of its own.
func setHostProcessGroup(pid, pgid int) error {
	return syscall.Setpgid(pid, pgid)
}

// newHostSession makes the host process the leader of a new session.
func newHostSession() (sid int, err error) {
	return syscall.Setsid()
}

// hostStreamWrites says that the host can write to a stream without waiting
// in the write, and ask whether one has room: see writeRaw and fdWritable.
const hostStreamWrites = true

// writeRaw writes p to a descriptor the runtime polls (and so keeps in
// non-blocking mode) once. again reports that the descriptor takes nothing
// right now; otherwise n bytes were taken, or err says why not.
func writeRaw(fd uintptr, p []byte) (n int, again bool, err error) {
	for {
		n, err = syscall.Write(int(fd), p)
		if err == syscall.EINTR {
			continue
		}
		if n < 0 {
			n = 0
		}
		if err == syscall.EAGAIN {
			return 0, true, nil
		}
		return n, false, err
	}
}

// socketPair creates a pair of connected Unix-domain stream sockets.
func socketPair() (a, b net.Conn, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	conns := [2]net.Conn{}
	for i, fd := range fds {
		syscall.CloseOnExec(fd)
		f := os.NewFile(uintptr(fd), "socketpair")
		// FileConn works on a duplicate; the original is done with either way.
		conn, connErr := net.FileConn(f)
		err = errors.Join(err, connErr, f.Close())
		conns[i] = conn
	}
	if err != nil {
		for _, conn := range conns {
			if conn != nil {
				err = errors.Join(err, conn.Close())
			}
		}
		return nil, nil, err
	}
	return conns[0], conns[1], nil
}
