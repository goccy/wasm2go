//go:build darwin || linux

package codegen

import (
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
