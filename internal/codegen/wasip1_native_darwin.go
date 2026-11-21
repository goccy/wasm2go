//go:build darwin

package codegen

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atimespec.Unix()), time.Unix(st.Ctimespec.Unix())
}

// lstatAt would describe name in the directory open as dir; package
// syscall has no call relative to a directory descriptor on this system,
// and a path of the host is not looked up instead. osFileDirents records
// the type of every name, so the listing never asks.
func lstatAt(dir *os.File, name string) (os.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstatat", Path: name, Err: errors.ErrUnsupported}
}

// chmodRefused reports whether err is chmod(2)'s refusal of a mode bit to
// this user or this file: EPERM, or EFTYPE for a sticky bit of a file that
// is no directory.
func chmodRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EFTYPE)
}

// hostFDLink reports that the host has no link for descriptor fd of the
// host process: /dev/fd/N of this system is no link.
func hostFDLink(fd uintptr) (string, bool, error) { return "", false, nil }

// readHostUmask returns the file mode creation mask of the host process,
// which this system has no way to read without changing it:
// errors.ErrUnsupported.
func readHostUmask() (os.FileMode, error) {
	return 0, fmt.Errorf("the umask of the host process cannot be read without changing it: %w", errors.ErrUnsupported)
}

// osFileDirents returns the names in the directory open as d: "." and
// "..", then the names in the order the system gives them, which ReadDir
// keeps. ReadDir reads through the descriptor itself, so a directory that
// may be read but not searched lists; syscall.ReadDirent opens "." in the
// directory on this system.
func osFileDirents(d *os.File) ([]hostName, error) {
	if _, err := d.Seek(0, 0); err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]hostName, 0, len(entries)+2)
	names = append(names, hostName{name: ".", typ: syscall.DT_DIR}, hostName{name: "..", typ: syscall.DT_DIR})
	for _, e := range entries {
		// The values of d_type are the file type bits of a mode, shifted.
		names = append(names, hostName{name: e.Name(), typ: uint8(unixTypeBits(e.Type()) >> 12)})
	}
	return names, nil
}
