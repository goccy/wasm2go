//go:build !darwin && !linux

package codegen

import (
	"os"
	"syscall"
)

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned. This platform's carries none the runtime knows how to
// read.
func osFileStat(sys any) (fileStat, bool) {
	return fileStat{}, false
}

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error; on this platform the errors are told apart
// by what package os makes of them.
func wasiErrno(e syscall.Errno) (int32, bool) { return 0, false }

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
