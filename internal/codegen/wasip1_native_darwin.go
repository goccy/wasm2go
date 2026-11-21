//go:build darwin

package codegen

import (
	"os"
	"syscall"
	"time"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atimespec.Unix()), time.Unix(st.Ctimespec.Unix())
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
