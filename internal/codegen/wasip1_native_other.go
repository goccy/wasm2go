//go:build !darwin && !linux

package codegen

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
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

// defaultSignalAction gives a signal its default action in the kernel,
// which the runtime cannot do on this platform.
func defaultSignalAction(sig syscall.Signal) error { return errors.ErrUnsupported }

// signalHostProcess sends a signal to a process of the host, which the
// runtime cannot do on this platform.
func signalHostProcess(pid int, sig syscall.Signal) error {
	return errors.ErrUnsupported
}

// hostProcessGroup returns the process group of a process of the host,
// which this platform does not have.
func hostProcessGroup(pid int) (int, error) {
	return 0, errors.ErrUnsupported
}

// setHostProcessGroup moves a process of the host into a process group,
// which this platform does not have.
func setHostProcessGroup(pid, pgid int) error {
	return errors.ErrUnsupported
}

// newHostSession makes the host process the leader of a new session, which
// this platform does not have.
func newHostSession() (sid int, err error) {
	return 0, errors.ErrUnsupported
}

// hostPIDLimit returns the highest pid a process of the host can have, or 0
// when the runtime does not know this platform's.
func hostPIDLimit() int32 { return 0 }

// hostProcessTimes returns the CPU time of the host process and of its
// children, which the runtime cannot read on this platform.
func hostProcessTimes() (times [4]time.Duration, err error) {
	return times, errors.ErrUnsupported
}

// hostPriority and setHostPriority read and set the nice value of processes
// of the host, which this platform does not have.
func hostPriority(which, who int) (int, error) { return 0, errors.ErrUnsupported }

func setHostPriority(which, who, nice int) error { return errors.ErrUnsupported }

// makeHostFIFO creates a FIFO in the host filesystem, which this platform
// does not have.
func makeHostFIFO(path string, perm os.FileMode) error { return errors.ErrUnsupported }

// setHostIDs changes the user or group ids of the host process, which this
// platform does not have.
func setHostIDs(request int32, a, b, c int) error { return errors.ErrUnsupported }

// setHostGroups sets the supplementary groups of the host process, which
// this platform does not have.
func setHostGroups(gids []int) error { return errors.ErrUnsupported }

// hostSystemName returns what uname reports, which the runtime cannot ask
// on this platform.
func hostSystemName() (fields [5]string, err error) {
	return fields, errors.ErrUnsupported
}

// hostInputNow says whether the host can read, receive and accept on a
// descriptor without waiting in the call. The runtime does not know how on
// this platform: a readiness probe bounds the call by a deadline instead.
const hostInputNow = false

// descriptorWaits reports whether a call on the descriptor waits when there
// is nothing for it, which the runtime cannot tell on this platform.
func descriptorWaits(fd uintptr) bool { return true }

// readRaw reads from a descriptor without waiting, which the runtime cannot
// do on this platform.
func readRaw(fd uintptr, p []byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// receiveRaw receives a datagram without waiting, which the runtime cannot
// do on this platform.
func receiveRaw(fd uintptr, p []byte) (n int, from net.Addr, again bool, err error) {
	return 0, nil, false, errors.ErrUnsupported
}

// acceptRaw accepts a connection without waiting, which the runtime cannot
// do on this platform.
func acceptRaw(fd uintptr) (conn net.Conn, again bool, err error) {
	return nil, false, errors.ErrUnsupported
}

// peerFailure returns the errno getpeername fails with on the host's
// socket, which the runtime does not ask on this platform: the connection
// counts as having its peer.
func peerFailure(fd uintptr) int32 { return _wasiESUCCESS }

// hostStreamWrites says whether the host can write to a stream without
// waiting in the write. The runtime does not know how on this platform, so
// writes go through the stream's own Write and wait there.
const hostStreamWrites = false

// writeRaw writes to a descriptor without waiting, which the runtime cannot
// do on this platform.
func writeRaw(fd uintptr, p []byte) (n int, again bool, err error) {
	return 0, false, errors.ErrUnsupported
}

// fdWritable reports whether a write to the descriptor would return at
// once. The runtime cannot ask on this platform; the write tells.
func fdWritable(fd uintptr) bool { return true }

// socketPair creates a pair of connected sockets, which the runtime cannot
// do on this platform.
func socketPair(dgram bool) (a, b net.Conn, err error) {
	return nil, nil, errors.ErrUnsupported
}

// unboundUnixDatagram creates a Unix-domain datagram socket that has no
// name, which the runtime cannot do on this platform.
func unboundUnixDatagram() (net.Conn, error) {
	return nil, errors.ErrUnsupported
}

// setIPv6Only makes an IPv6 socket take IPv6 traffic only, or IPv4 traffic
// as well. The runtime cannot say on this platform: the socket stays as the
// network API made it.
func setIPv6Only(fd uintptr, only bool) error { return nil }

// inheritedOnce lets one instance adopt the descriptors the process was
// started with (AdoptInheritedDescriptors): they exist once.
var inheritedOnce sync.Once

// inheritedDescriptors returns the descriptors above the standard three
// that the process was started with. The runtime cannot tell on this
// platform: none.
func inheritedDescriptors() []int { return nil }

// adoptHostDescriptor makes an entry of the guest's descriptor table out of
// a descriptor the process inherited, which the runtime cannot do on this
// platform.
func adoptHostDescriptor(fd int) *wasiOpen { return nil }

// sendToOnConnected sends a datagram to an address on a connected datagram
// socket, which the runtime cannot do on this platform: the socket is
// connected.
func sendToOnConnected(conn net.Conn, p []byte, to net.Addr, ipv6 bool) (int, error) {
	return 0, syscall.EISCONN
}

// awaitHostExit waits until a host process has ended without taking it off
// the process table, which the runtime cannot do on this platform: ended is
// false, and the process is waited for at once.
func awaitHostExit(pid int) (status int32, ended bool) { return 0, false }

// hostMonotonic reads the host's monotonic clock, which the runtime cannot
// do on this platform: the guest's clock counts from the start of the
// instance.
func hostMonotonic() (time.Duration, bool) { return 0, false }
