//go:build !darwin && !linux

package codegen

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// hostProcessTimes returns the CPU time of the host process and of its
// children, which the runtime cannot read on this platform.
func hostProcessTimes() (ProcessTimes, error) {
	return ProcessTimes{}, errors.ErrUnsupported
}

// chmodRefused reports whether err is the system's refusal of a mode bit
// to this user, EPERM.
func chmodRefused(err error) bool { return errors.Is(err, syscall.EPERM) }

// hostFDLink reports that the host has no link for descriptor fd of the
// host process: this platform names none.
func hostFDLink(fd uintptr) (string, bool, error) { return "", false, nil }

// readHostUmask returns the file mode creation mask of the host process,
// which this platform has no way to read without changing it:
// errors.ErrUnsupported.
func readHostUmask() (os.FileMode, error) {
	return 0, fmt.Errorf("the umask of the host process cannot be read without changing it: %w", errors.ErrUnsupported)
}

// hostONonblock is the open flag of the host that opens a file without
// waiting. This platform's opens wait as they will: the syscall package of
// some (js, wasip1) has no such flag.
const hostONonblock = 0

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned. This platform's carries none the runtime knows how to
// read.
func osFileStat(sys any) (fileStat, bool) {
	return fileStat{}, false
}

// hostRename renames a file as os.Rename does on this platform: onto an
// existing file, it replaces the file.
func hostRename(from, to string) error { return os.Rename(from, to) }

// hostSignalOf returns the host's signal for a guest signal number. The
// runtime does not know this platform's signals, so only number 0, the
// existence probe of kill, has one.
func hostSignalOf(sig int32) (hostSig syscall.Signal, known bool) {
	return 0, sig == 0
}

// guestSignalOf returns the guest's number for a host signal, or 0 when the
// guest has none for it — always, on this platform.
func guestSignalOf(hostSig syscall.Signal) int32 {
	return 0
}

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error; on this platform the errors are told apart
// by what package os makes of them, except a few of windows.
func wasiErrno(e syscall.Errno) (int32, bool) {
	if runtime.GOOS != "windows" {
		return 0, false
	}
	// The numbers of windows' errors that package syscall does not name.
	switch e {
	case 39, 112: // ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL
		return _wasiENOSPC, true
	case 120: // ERROR_CALL_NOT_IMPLEMENTED
		return _wasiENOSYS, true
	case 131: // ERROR_NEGATIVE_SEEK
		return _wasiEINVAL, true
	case 10051: // WSAENETUNREACH
		return _wasiENETUNREACH, true
	case 10060: // WSAETIMEDOUT
		return _wasiETIMEDOUT, true
	case 10061: // WSAECONNREFUSED
		return _wasiECONNREFUSED, true
	case 10065: // WSAEHOSTUNREACH
		return _wasiEHOSTUNREACH, true
	}
	return 0, false
}

// hostDirListing lists a directory of the host's file system (an *os.File,
// which HostFS opens) in the order the system gives its names, which Go's
// ReadDir keeps. ReadDir leaves "." and ".." out, and they come first. ok
// is false for a directory of another file system. hostPath (the directory
// is of the whole host filesystem) changes nothing here: dotEntry states
// "." and ".." by their host paths either way.
func hostDirListing(f File, hostPath bool) ([]os.DirEntry, bool, error) {
	d, isHost := f.(*os.File)
	if !isHost {
		return nil, false, nil
	}
	if _, err := d.Seek(0, 0); err != nil {
		return nil, true, err
	}
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, true, err
	}
	out := make([]os.DirEntry, 0, len(entries)+2)
	out = append(out, dotEntry(d.Name(), "."), dotEntry(d.Name(), ".."))
	return append(out, entries...), true, nil
}
