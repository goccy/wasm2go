//go:build !darwin && !linux

package codegen

import (
	"errors"
	"os"
)

// processUmask is the file mode creation mask of the host process. This
// platform has none the runtime can read, so none is applied.
var processUmask os.FileMode

// osFileStat reads the POSIX metadata out of the Sys value of a FileInfo the
// os package returned. This platform's carries none the runtime knows how to
// read.
func osFileStat(sys any) (fileStat, bool) {
	return fileStat{}, false
}

// flockOSFile applies flock(2) to a file of the host process, which this
// platform does not offer.
func flockOSFile(f *os.File, lock FileLock, wait bool) error {
	return errors.ErrUnsupported
}
