//go:build !darwin && !linux

package codegen

import (
	"os"
	"runtime"
	"syscall"
)

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned. This platform's carries none the runtime knows how to
// read.
func osFileStat(sys any) (fileStat, bool) {
	return fileStat{}, false
}

// hostRename renames a file as os.Rename does on this platform: onto an
// existing file, it replaces the file.
func hostRename(from, to string) error { return os.Rename(from, to) }

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
// which osFS opens) in the order the system gives its names, which Go's
// ReadDir keeps. ReadDir leaves "." and ".." out, and they come first. ok
// is false for a directory of another file system.
func hostDirListing(f File) ([]os.DirEntry, bool, error) {
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
