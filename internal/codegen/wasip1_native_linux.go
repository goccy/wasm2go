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
	target, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return target, true, nil
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
func hostAccess(path string, amode uint32, effective bool) (errno int32, asked bool) {
	// faccessat's AT_FDCWD and AT_EACCESS on this system
	const atFDCWD, atEAccess = -100, 0x200
	flags := 0
	if effective {
		flags = atEAccess
	}
	if err := syscall.Faccessat(atFDCWD, path, amode, flags); err != nil {
		return mapOSError(err), true
	}
	return _wasiESUCCESS, true
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
