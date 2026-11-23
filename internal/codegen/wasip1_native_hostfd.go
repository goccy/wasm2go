//go:build darwin || linux

package codegen

import (
	"os"
	"syscall"
	"time"
)

// The events of poll(2), which have the same bits on every host this file
// is built for.
const (
	hostPollIn  int16 = 0x1
	hostPollOut int16 = 0x4
	hostPollErr int16 = 0x8
	hostPollHup int16 = 0x10
)

// hostPoll is struct pollfd.
type hostPoll struct {
	fd      int32
	events  int16
	revents int16
}

// hostName is one name of a directory with the file type the directory
// records for it, and its inode number where the directory records that
// too (0 where it does not).
type hostName struct {
	name string
	typ  uint8
	ino  uint64
}

// hostDirListing lists a directory of the host's in the order the system
// gives its names, with "." and ".." where osFileDirents has them: a
// directory opened through the host's file system (an *os.File, which HostFS
// opens). ok is false for a directory of another file system.
func hostDirListing(f File) (list []os.DirEntry, ok bool, err error) {
	var dir *os.File
	var names []hostName
	switch d := f.(type) {
	case *os.File:
		names, err = osFileDirents(d)
		dir = d
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	list = make([]os.DirEntry, 0, len(names))
	for _, entry := range names {
		list = append(list, &hostDirEntry{dir: dir, name: entry.name, typ: entry.typ, ino: entry.ino})
	}
	return list, true, nil
}

// hostDirEntry is an entry of a directory of the host's, open as dir.
type hostDirEntry struct {
	dir  *os.File
	name string
	typ  uint8  // d_type
	ino  uint64 // d_ino, 0 where the directory does not record it
}

func (e *hostDirEntry) inode() uint64 { return e.ino }

func (e *hostDirEntry) Name() string { return e.name }
func (e *hostDirEntry) IsDir() bool  { return e.Type().IsDir() }
func (e *hostDirEntry) Type() os.FileMode {
	// The values of d_type are the file type bits of a mode, shifted.
	switch uint32(e.typ) << 12 {
	case syscall.S_IFDIR:
		return os.ModeDir
	case syscall.S_IFLNK:
		return os.ModeSymlink
	case syscall.S_IFIFO:
		return os.ModeNamedPipe
	case syscall.S_IFSOCK:
		return os.ModeSocket
	case syscall.S_IFCHR:
		return os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFBLK:
		return os.ModeDevice
	case syscall.S_IFREG:
		return 0
	}
	// The directory does not say (DT_UNKNOWN): the file does. A file that
	// cannot be asked leaves the type unknown. Type has no error to return,
	// and the listing goes on: the name is listed, and the guest stats it.
	fi, err := e.Info()
	if err != nil {
		return os.ModeIrregular
	}
	return fi.Mode().Type()
}

// Info describes the entry's file through the directory's descriptor
// (lstatAt): no path of the host is looked up, so a directory of a HostFS
// root says nothing of a file outside it.
func (e *hostDirEntry) Info() (os.FileInfo, error) {
	return lstatAt(e.dir, e.name)
}

// hostHungUp asks the host whether a descriptor of its own has been hung up
// on (POLLHUP).
func hostHungUp(fd uintptr) bool {
	return hostReadyNow(int(fd), hostPollIn)&hostPollHup != 0
}

// hostReadyNow reports which of events descriptor fd has right now.
func hostReadyNow(fd int, events int16) int16 {
	set := [1]hostPoll{{fd: int32(fd), events: events}}
	for {
		_, errno := hostPollCall(set[:], 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			// The host cannot say: the call on the descriptor will.
			return events
		}
		return set[0].revents
	}
}

// hostPolls says that the host can wait for its descriptors in poll(2): see
// hostWaitReady.
const hostPolls = true

// hostWaitReady asks poll(2) about descriptors fds, each for what wants
// says (hostWant...), and records in ready which are: at once when until
// has passed, otherwise waiting until one is, until passes (the zero time
// is no limit) or wake (-1 for none) is readable. Whatever poll(2) reports
// of a descriptor asked about input or room makes it ready, and the call on
// it tells what it was: input or room, the end of input or a hang-up
// (POLLHUP), an error (POLLERR), or a device poll(2) does not support
// (POLLNVAL, which darwin reports of /dev/null, and poll(2) of a number
// closed meanwhile). One asked about failure is ready on POLLERR or POLLHUP
// only. hungUp, when not nil, records which of the ready ones poll(2)
// reported hung up on (POLLHUP).
func hostWaitReady(fds []uintptr, wants []int, ready, hungUp []bool, until time.Time, wake int) error {
	set := make([]hostPoll, len(fds), len(fds)+1)
	for i, fd := range fds {
		set[i] = hostPoll{fd: int32(fd), events: hostPollIn}
		switch wants[i] {
		case hostWantRoom:
			set[i].events = hostPollOut
		case hostWantFailure:
			set[i].events = 0
		}
	}
	if wake >= 0 {
		set = append(set, hostPoll{fd: int32(wake), events: hostPollIn})
	}
	for {
		timeout := time.Duration(-1)
		if !until.IsZero() {
			timeout = max(time.Until(until), 0)
		}
		_, errno := hostPollCall(set, timeout)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return os.NewSyscallError("poll", errno)
		}
		found := false
		for i := range fds {
			if wants[i] == hostWantFailure && set[i].revents&(hostPollErr|hostPollHup) == 0 && set[i].revents != 0 {
				// It would be reported at once again: not watched any more.
				set[i].fd = -1
			} else if set[i].revents != 0 {
				ready[i], found = true, true
				if hungUp != nil {
					hungUp[i] = set[i].revents&hostPollHup != 0
				}
			}
		}
		if found || wake >= 0 && set[len(fds)].revents != 0 || timeout == 0 || !until.IsZero() && !time.Now().Before(until) {
			return nil
		}
	}
}

// hostWakeWrite writes a byte to the write end of a wake pipe. A full pipe
// is readable already.
func hostWakeWrite(w int) error {
	for {
		_, err := syscall.Write(w, []byte{0})
		switch err {
		case syscall.EINTR:
			continue
		case nil, syscall.EAGAIN:
			return nil
		}
		return os.NewSyscallError("write", err)
	}
}

// hostWakeDrain reads a wake pipe empty.
func hostWakeDrain(r int) error {
	var buf [64]byte
	for {
		n, err := syscall.Read(r, buf[:])
		switch {
		case err == syscall.EINTR || err == nil && n == len(buf):
			continue
		case err == nil, err == syscall.EAGAIN:
			return nil
		}
		return os.NewSyscallError("read", err)
	}
}
