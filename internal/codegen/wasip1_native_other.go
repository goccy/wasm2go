//go:build !darwin && !linux

package codegen

import (
	"errors"
	"net"
	"os"
	"syscall"
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

// signalHostProcess sends a signal to a process of the host, which the
// runtime cannot do on this platform.
func signalHostProcess(pid int, sig syscall.Signal) error {
	return errors.ErrUnsupported
}

// socketPair creates a pair of connected stream sockets, which the runtime
// cannot do on this platform.
func socketPair() (a, b net.Conn, err error) {
	return nil, nil, errors.ErrUnsupported
}
