//go:build !darwin && !linux

package codegen

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
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

// hostNumber is a number of the operating system under its name in C.
type hostNumber struct {
	name  string
	value int64
}

// hostNumberTable returns the numbers of a family of the host's numbers:
// none on this platform, where a guest keeps the numbers of its C library.
func hostNumberTable(family int32) []hostNumber { return nil }

// wasiErrno returns the wasi errno of an error number of the host, and
// whether wasi has that error; on this platform the errors are told apart
// by what package os makes of them.
func wasiErrno(e syscall.Errno) (int32, bool) { return 0, false }

// hostErrnoKnown reports whether the host's error numbers are known by
// name on this platform: they are not.
func hostErrnoKnown() bool { return false }

// The descriptor layer of a guest that is the host process — the guest's
// descriptors being the host's, number for number — does not exist on this
// platform: such a guest has descriptors of its own, as every guest has.
// What follows is what the rest of the runtime names of that layer.

// hostFile would be a descriptor of the host process as the file of an
// entry; no entry has one here.
type hostFile struct {
	File
	fd atomic.Int32
}

func (h *hostFile) waits() bool               { return false }
func (h *hostFile) terminal() bool            { return false }
func (h *hostFile) nonblocking() bool         { return false }
func (h *hostFile) fdflags() int32            { return 0 }
func (h *hostFile) setFdflags(int32) error    { return errors.ErrUnsupported }
func (h *hostFile) filetype(dgram bool) byte  { return 0 }
func (h *hostFile) flock(lock FileLock) error { return errors.ErrUnsupported }
func (h *hostFile) pending() uint64           { return 0 }
func (h *hostFile) childFile() *os.File       { return nil }

// host returns the descriptor of the host process the entry is: none.
func (op *wasiOpen) host() *hostFile { return nil }

func (op *wasiOpen) leaveStandard() {}

// hostWaker would end a wait in the host's poll.
type hostWaker struct{}

// hostStandard would be the standard descriptors of the host process an
// instance took over.
type hostStandard struct{}

func (w *WasiStubs) restoreStandardLocked() {}

func (w *WasiStubs) leavesStandardLocked() bool { return true }

// hostPollSet would be the descriptors of the host one poll_oneoff asks
// about; it stays empty.
type hostPollSet struct{}

func (s *hostPollSet) add(sub int, h *hostFile, read bool) bool             { return false }
func (s *hostPollSet) empty() bool                                          { return true }
func (s *hostPollSet) look()                                                {}
func (s *hostPollSet) ready(mark func(sub int)) bool                        { return false }
func (s *hostPollSet) await(w *WasiStubs, until time.Time) int32            { return _wasiENOSYS }
func (s *hostPollSet) awaitStoppable(until time.Time, stop <-chan struct{}) {}

// KeepRuntimeDescriptorsHigh keeps the Go runtime's own descriptors above
// the numbers a program's descriptors get, where the guest's descriptors
// can be the host's: not on this platform.
func KeepRuntimeDescriptorsHigh() {}

func (w *WasiStubs) hostDescriptorsLocked() bool                     { return false }
func (w *WasiStubs) hostStandardLocked(stdio int8) *wasiOpen         { return &wasiOpen{stdio: stdio} }
func (w *WasiStubs) freeNumberLocked() int32                         { return 0 }
func (w *WasiStubs) hostOpenLocked(fd int32, op *wasiOpen) *wasiOpen { return op }
func (h *hostFile) madeOutside() bool                                { return false }
func (h *hostFile) current() bool                                    { return false }
func (w *WasiStubs) inheritableOutsideLocked() []*hostFile           { return nil }
func (h *hostFile) closeOnExec(set, value bool) (bool, error)        { return false, errors.ErrUnsupported }
func (w *WasiStubs) closeHostWakerLocked()                           {}
func (w *WasiStubs) addHostFDLocked(op *wasiOpen) (int32, error)     { return -1, errors.ErrUnsupported }
func (w *WasiStubs) dupHostLocked(op *wasiOpen) (int32, error)       { return -1, errors.ErrUnsupported }
func (w *WasiStubs) dup2HostLocked(src *wasiOpen, to int32) error {
	return errors.ErrUnsupported
}
func (w *WasiStubs) readHost(h *hostFile, bufs [][]byte) (uint64, int32) { return 0, _wasiENOSYS }
func (w *WasiStubs) writeHost(op *wasiOpen, h *hostFile, bufs [][]byte) (uint64, int32) {
	return 0, _wasiENOSYS
}

// OpenDescriptor would open a file as a descriptor of the host process.
func (o osFS) OpenDescriptor(name string, flag int, perm os.FileMode) (File, error) {
	return nil, errors.ErrUnsupported
}

func hostPipe() (r, wr *wasiOpen, err error) { return nil, nil, errors.ErrUnsupported }

func inheritedHostDescriptor(fd int) *wasiOpen { return nil }

func (h *hostFile) socket() bool { return false }

func (w *WasiStubs) openHostSockets(family, typ int32, pair bool) ([]int32, int32) {
	return nil, _wasiENOSYS
}
func (w *WasiStubs) bindHost(op *wasiOpen, h *hostFile, a wasiSockAddr, unixPath string) int32 {
	return _wasiENOSYS
}
func (w *WasiStubs) listenHost(op *wasiOpen, h *hostFile, backlog int32) int32 {
	return _wasiENOSYS
}
func (w *WasiStubs) acceptHost(op *wasiOpen, h *hostFile) (*wasiOpen, int32) {
	return nil, _wasiENOSYS
}
func (w *WasiStubs) connectHost(op *wasiOpen, h *hostFile, sa syscall.Sockaddr) int32 {
	return _wasiENOSYS
}
func (w *WasiStubs) shutdownHost(h *hostFile, how int32) int32 { return _wasiENOSYS }
func (op *wasiOpen) hostSocketName(h *hostFile, peer bool) (net.Addr, int32) {
	return nil, _wasiENOSYS
}
func (w *WasiStubs) timeoutHost(h *hostFile, which int32, set bool, nanos int64) (time.Duration, int32) {
	return 0, _wasiENOSYS
}
func (w *WasiStubs) setoptHost(op *wasiOpen, h *hostFile, option, value int32) int32 {
	return _wasiENOSYS
}
func (w *WasiStubs) getoptHost(op *wasiOpen, h *hostFile, option int32) (value, errno int32) {
	return 0, _wasiENOSYS
}
func (w *WasiStubs) receiveHost(h *hostFile, bufs [][]byte, flags int32) (uint64, syscall.Sockaddr, int32) {
	return 0, nil, _wasiENOSYS
}
func (w *WasiStubs) receiveFromHost(op *wasiOpen, h *hostFile, buf []byte, flags int32) (uint64, net.Addr, int32) {
	return 0, nil, _wasiENOSYS
}
func (w *WasiStubs) sendHost(op *wasiOpen, h *hostFile, bufs [][]byte, to syscall.Sockaddr, flags int32) (uint64, int32) {
	return 0, _wasiENOSYS
}
func (a wasiSockAddr) hostSockaddr(unixPath string) syscall.Sockaddr { return nil }
