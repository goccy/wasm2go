//go:build darwin || linux

package codegen

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
)

// This file is the descriptor layer of an instance whose descriptors are
// the host process's (WASIConfig.HostDescriptors). Its table keeps the
// entries it has everywhere else; what it adds is a descriptor of the host
// for every slot: slot N holds host descriptor N, open on the entry's open
// file description (or on hostPlaceholder for an entry without one), which
// the instance closes when it clears the slot. The entries' own
// descriptors, and every other descriptor the runtime makes for itself, are
// at hostDescriptorFloor or above, out of the guest's numbers.

// hostDescriptorsSupported says that an instance's descriptors can be the
// host process's.
const hostDescriptorsSupported = true

// hostDescriptorFloor is the lowest number of a descriptor the runtime makes
// for itself once an instance of the process has the host's descriptors,
// and one more than the highest number of the guest's: FD_SETSIZE, so that
// every number of the guest's can be given to select(2).
const hostDescriptorFloor = 1024

// hostTable is what the runtime knows of the descriptor table of the host
// process, which every instance in it shares.
var hostTable struct {
	// active is set once an instance whose descriptors are the host's is
	// made (startHostNumbers): from then on the runtime keeps the
	// descriptors it makes at hostDescriptorFloor or above.
	active atomic.Bool
	// making is held for reading while the runtime makes descriptors for
	// itself, from their making until they are at hostDescriptorFloor or
	// above (makeRuntimeDescriptors), and while a command is started
	// (startCommand), as package syscall makes descriptors for it under
	// numbers the runtime cannot move; and for writing while a guest takes in
	// a descriptor that is nobody's (adoptHostLocked), which must not be one
	// of those. It is taken after a WasiStubs' mu, never before, and no
	// WasiStubs' mu is taken under the read lock.
	making sync.RWMutex
	// mu guards the fields below and makes the placements of the guests'
	// descriptors (hostSlotLocked, placeHostSlotLocked) one at a time. It is
	// taken after a WasiStubs' mu and making; under it the runtime makes
	// system calls only.
	mu sync.Mutex
	// started records that the descriptors the process had then were
	// recorded (startHostNumbers).
	started bool
	// adoptable is set when they were: without the record, no descriptor
	// is taken in by its number.
	adoptable bool
	// held maps a slot descriptor to the instance whose slot it is.
	held map[int]*WasiStubs
	// reserved holds the descriptors the process had open when its first
	// instance with the host's descriptors was made, but for those given in
	// the Files of such instances, with what each was open on: the
	// process's own, which no guest gets at (reservedLocked).
	reserved map[int]hostIdentity
	// standard holds, for 0, 1 and 2, the instances whose slot there has the
	// process's standard descriptor (takeStandardLocked, or a placement onto
	// it): it is theirs together, as it is every thread's of a process. Each
	// may put a file there (placeHostSlotLocked), and the last to clear its
	// slot closes it (releaseHostSlotLocked).
	standard [3]map[*WasiStubs]bool
	// files holds, by number, the files of Files that were given at the
	// number they are open under: the slot's descriptor is the file's, and
	// it is closed through the file (releaseHostSlotLocked), which is not
	// left to close it again when it is collected.
	files map[int]*os.File
	// placeholder is the descriptor a slot of an entry without a descriptor
	// of the host's holds a duplicate of (hostPlaceholder); 0 before it is
	// made, as it is never at 0.
	placeholder int
}

// startHostNumbers makes the runtime keep its descriptors out of the
// guests' numbers, and records, the first time, the descriptors the process
// has open as its own (hostTable.reserved); the descriptors of files, which
// are given to the guest, are not. A failure to record them leaves every
// descriptor of the process out of the guests' reach, and is returned.
func startHostNumbers(files map[int32]*os.File) error {
	hostTable.active.Store(true)
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	given := map[int]bool{}
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := withHostDescriptor(f, func(fd uintptr) error {
			given[int(fd)] = true
			return nil
		}); err != nil {
			hostTable.started = true
			return err
		}
	}
	if hostTable.started {
		for fd := range given {
			delete(hostTable.reserved, fd)
		}
		return nil
	}
	hostTable.started = true
	// The Go runtime makes the descriptors of its poller on the first file
	// it polls: they are made now, to be the process's own below.
	r, wr, err := os.Pipe()
	if err != nil {
		return err
	}
	if err := errors.Join(r.Close(), wr.Close()); err != nil {
		return err
	}
	open, err := openHostDescriptors()
	if err != nil {
		return err
	}
	hostTable.reserved = map[int]hostIdentity{}
	for _, fd := range open {
		if id, ok := hostIdentityOf(fd); ok && !given[fd] {
			hostTable.reserved[fd] = id
		}
	}
	hostTable.adoptable = true
	return nil
}

// hostIdentity is what fstat tells of the file a descriptor is open on:
// its device, inode and type.
type hostIdentity struct {
	dev, ino uint64
	mode     uint32
}

// hostIdentityOf returns the identity of what fd is open on; ok is false
// when it is not open.
func hostIdentityOf(fd int) (id hostIdentity, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return id, false
	}
	return hostIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), mode: uint32(st.Mode) & syscall.S_IFMT}, true
}

// reservedLocked reports whether fd is one of the process's own descriptors
// (hostTable.reserved): open on what it was open on when it was recorded.
// One that is closed, or open on another file, is the process's no longer,
// and is forgotten: its owner closed it, and the number was given to
// something else since. (A file the host gives the identity of one closed
// before, a new pipe on darwin say, is taken for the old one.) Caller holds
// hostTable.mu.
func reservedLocked(fd int) bool {
	id, ok := hostTable.reserved[fd]
	if !ok {
		return false
	}
	if now, open := hostIdentityOf(fd); open && now == id {
		return true
	}
	delete(hostTable.reserved, fd)
	return false
}

// openHostDescriptors returns the descriptors the host process has open:
// the names of /dev/fd that are still open once the directory is read (the
// one the reading itself used is not).
func openHostDescriptors() ([]int, error) {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return nil, err
	}
	var open []int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			return nil, fmt.Errorf("/dev/fd: %w", err)
		}
		if _, err := descriptorFlags(fd, syscall.F_GETFD); err == nil {
			open = append(open, fd)
		}
	}
	return open, nil
}

// runtimeFloor is the lowest number for a descriptor the runtime makes for
// itself: hostDescriptorFloor once an instance has the host's descriptors,
// 0 before.
func runtimeFloor() int {
	if hostTable.active.Load() {
		return hostDescriptorFloor
	}
	return 0
}

// dupFrom returns a close-on-exec duplicate of fd under the lowest free
// number that is at least min (fcntl's F_DUPFD_CLOEXEC). A min the process
// may not have a descriptor at (EINVAL) has no number free: EMFILE.
func dupFrom(fd, min int) (int, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, uintptr(min))
	if errno == syscall.EINVAL && min > 0 {
		errno = syscall.EMFILE
	}
	if errno != 0 {
		return -1, os.NewSyscallError("fcntl", errno)
	}
	return int(r), nil
}

// descriptorBlocks reports whether fd's description is in blocking mode.
func descriptorBlocks(fd int) (bool, error) {
	flags, err := descriptorFlags(fd, syscall.F_GETFL)
	if err != nil {
		return false, os.NewSyscallError("fcntl", err)
	}
	return flags&syscall.O_NONBLOCK == 0, nil
}

// makeRuntimeDescriptors runs make, which makes descriptors for the runtime
// and moves them to runtimeFloor or above (keepRuntimeFD, keepRuntimeFile),
// with hostTable.making held for reading: no guest takes one in while it is
// under a number of the guests' (adoptHostLocked). Caller holds no
// WasiStubs' mu, and make takes none.
func makeRuntimeDescriptors(make func() error) error {
	hostTable.making.RLock()
	defer hostTable.making.RUnlock()
	return make()
}

// keepRuntimeFD returns fd, a descriptor the runtime made for itself, at
// runtimeFloor or above: a duplicate there, fd being closed, once an
// instance has the host's descriptors. On failure fd is closed.
func keepRuntimeFD(fd int) (int, error) {
	if !hostTable.active.Load() || fd >= hostDescriptorFloor {
		return fd, nil
	}
	moved, err := dupFrom(fd, hostDescriptorFloor)
	return moved, errors.Join(err, hostCloseFD(fd))
}

// keepRuntimeFile is keepRuntimeFD for a file: a file of the duplicate,
// under f's name, f being closed. The open file description is f's, and
// so is its mode, which decides whether package os polls the new file as
// it polled f (os.NewFile). On failure f is closed.
func keepRuntimeFile(f *os.File) (*os.File, error) {
	if !hostTable.active.Load() {
		return f, nil
	}
	return moveFile(f, nil)
}

// guestFile is keepRuntimeFile for f, a file of the host's the runtime made
// or opened for the guest. Where the guest's descriptors are the host's
// (hostFamily), the guest's mode is the open file description's, which code
// outside the guest shares: the description is put in it, non-blocking when
// nonblock asks, and package os is given the descriptor anew, as it polls
// one only in non-blocking mode (os.NewFile), so that the Go runtime's
// poller has the descriptor only in the mode it takes. On failure f is
// closed.
func (w *WasiStubs) guestFile(f *os.File, nonblock bool) (*os.File, error) {
	if !w.hostFamily() {
		return keepRuntimeFile(f)
	}
	return moveFile(f, func(fd int) error {
		return os.NewSyscallError("fcntl", syscall.SetNonblock(fd, nonblock))
	})
}

// acceptedMode puts conn, a connection accepted for the guest, in the
// guest's mode, fdflags', where the guest's mode is the description's
// (hostFamily); elsewhere it is left non-blocking, as accept made it.
func (w *WasiStubs) acceptedMode(conn int, fdflags int32) error {
	if !w.hostFamily() {
		return nil
	}
	return os.NewSyscallError("fcntl", syscall.SetNonblock(conn, fdflags&wasiFdflagNonblock != 0))
}

// guestOpened is guestFile for a file a FS opened for the guest: a file of
// the host's is moved and put in the guest's mode, any other is f itself.
func (w *WasiStubs) guestOpened(f File, nonblock bool) (File, error) {
	if file, ok := f.(*os.File); ok {
		return w.guestFile(file, nonblock)
	}
	return f, nil
}

// moveFile returns a file of a duplicate of f's descriptor at runtimeFloor
// or above, under f's name, f being closed, or f itself when its descriptor
// is there already. setMode, when it is not nil, is run on the descriptor
// first, and the file is then always one of a duplicate. On failure f is
// closed.
func moveFile(f *os.File, setMode func(fd int) error) (*os.File, error) {
	moved := -1
	err := withHostDescriptor(f, func(fd uintptr) error {
		if setMode != nil {
			if err := setMode(int(fd)); err != nil {
				return err
			}
		} else if fd >= hostDescriptorFloor {
			return nil // moved already
		}
		var err error
		moved, err = dupFrom(int(fd), hostDescriptorFloor)
		return err
	})
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if moved < 0 {
		return f, nil
	}
	nf := os.NewFile(uintptr(moved), f.Name())
	if err := f.Close(); err != nil {
		return nil, errors.Join(err, nf.Close())
	}
	return nf, nil
}

// runtimeFile returns the file make makes for the runtime's own use, moved
// to runtimeFloor or above (keepRuntimeFile), made as the runtime makes its
// own descriptors (makeRuntimeDescriptors): so are the files of the memory
// images of the package this runtime is emitted in (makeImageFile), whose
// descriptors no guest may get at by number. A nil file make returns
// without an error is returned as it is. Caller holds no WasiStubs' mu.
func runtimeFile(make func() (*os.File, error)) (*os.File, error) {
	var f *os.File
	err := makeRuntimeDescriptors(func() error {
		var err error
		if f, err = make(); err != nil || f == nil {
			return err
		}
		f, err = keepRuntimeFile(f)
		return err
	})
	return f, err
}

// keepRuntimeOpened is keepRuntimeFile for a file a FS opened: a file of
// the host's is moved, any other is f itself.
func keepRuntimeOpened(f File) (File, error) {
	if file, ok := f.(*os.File); ok {
		return keepRuntimeFile(file)
	}
	return f, nil
}

// hostPlaceholder returns the descriptor the slot of an entry without one
// of the host's holds a duplicate of: the read end of a pipe whose write
// end is closed, made on first use. Caller holds hostTable.mu.
func hostPlaceholder() (int, error) {
	if hostTable.placeholder != 0 {
		return hostTable.placeholder, nil
	}
	r, wr, err := hostWakePipe()
	if err != nil {
		return -1, err
	}
	if err := hostCloseFD(wr); err != nil {
		return -1, errors.Join(err, hostCloseFD(r))
	}
	if r, err = keepRuntimeFD(r); err != nil {
		return -1, err
	}
	hostTable.placeholder = r
	return r, nil
}

// withSlotSourceLocked calls use with the descriptor a slot of op is a
// duplicate of: op's file or socket of the host (entryHostConnLocked), or
// the placeholder. Caller holds w.mu and hostTable.mu.
func (w *WasiStubs) withSlotSourceLocked(op *wasiOpen, use func(fd int) error) error {
	if conn := w.entryHostConnLocked(op); conn != nil {
		return withHostDescriptor(conn, func(fd uintptr) error { return use(int(fd)) })
	}
	fd, err := hostPlaceholder()
	if err != nil {
		return err
	}
	return use(fd)
}

// hostSlotLocked makes the host's descriptor for a new slot of op, under
// the lowest number the host has free that is at least min, and returns the
// number: EMFILE when that is not below hostDescriptorFloor. A standard
// number the guest's file gets is shared as the process's standard
// descriptor (shareStandardLocked). A number the host gives that is a slot
// of w's already — a standard stream of the guest's own whose number the
// process closed (see placeHostSlotLocked) — stays that slot's: its
// descriptor is made the placeholder's, and the next number is taken.
// Caller holds w.mu.
func (w *WasiStubs) hostSlotLocked(op *wasiOpen, min int32) (int32, error) {
	fds := w.fdsLocked() // set up before hostTable.mu is taken (takeStandardLocked)
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	for {
		fd := -1
		if err := w.withSlotSourceLocked(op, func(src int) error {
			var err error
			fd, err = dupFrom(src, int(min))
			return err
		}); err != nil {
			return -1, err
		}
		if fd >= hostDescriptorFloor {
			return -1, errors.Join(syscall.EMFILE, hostCloseFD(fd))
		}
		if fds[int32(fd)] == nil && fd <= 2 && w.entryHostConnLocked(op) != nil {
			w.shareStandardLocked(int32(fd))
			return int32(fd), nil
		}
		w.holdLocked(fd)
		if fds[int32(fd)] == nil {
			return int32(fd), nil
		}
		if err := w.withSlotSourceLocked(nil, func(src int) error { return hostDupTo(src, fd) }); err != nil {
			return -1, err
		}
		min = int32(fd) + 1
	}
}

// shareStandardLocked records w's slot fd (0, 1 or 2) as one that has the
// process's standard descriptor fd (hostTable.standard). Caller holds
// hostTable.mu.
func (w *WasiStubs) shareStandardLocked(fd int32) {
	if hostTable.standard[fd] == nil {
		hostTable.standard[fd] = map[*WasiStubs]bool{}
	}
	hostTable.standard[fd][w] = true
	delete(hostTable.reserved, int(fd))
}

// hostSlotHeld reports whether w's slot fd has the host's descriptor fd.
func (w *WasiStubs) hostSlotHeld(fd int32) bool {
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	return hostTable.held[int(fd)] == w || fd <= 2 && hostTable.standard[fd][w]
}

// holdLocked records fd as the slot descriptor of a slot of w. Caller holds
// hostTable.mu.
func (w *WasiStubs) holdLocked(fd int) {
	if hostTable.held == nil {
		hostTable.held = map[int]*WasiStubs{}
	}
	hostTable.held[fd] = w
}

// placeHostSlotLocked makes the host's descriptor to the descriptor of a
// slot of src, for a dup2 or renumber onto to: in one step (hostDupTo), so
// that a descriptor of w's there is replaced rather than closed first, and a
// descriptor of the process's that is nobody's is closed, as dup2(2) closes
// it. A standard number of the guest's own (ownStandard) whose number w
// does not hold is left as it is: the slot is the guest's alone. A file put
// at any other standard number
// is the process's descriptor there, which w shares from then on with the
// instances that have it (hostTable.standard). EBADF for a number not below
// hostDescriptorFloor, which no guest has; EBUSY for one that is another
// instance's or the process's own (as Linux's dup2 fails in a race with
// open). Caller holds w.mu.
func (w *WasiStubs) placeHostSlotLocked(to int32, src *wasiOpen) error {
	if to < 0 || to >= hostDescriptorFloor {
		return syscall.EBADF
	}
	// A number w has no descriptor at may be one the runtime is making
	// (hostTable.making), which the placement would close.
	hostTable.mu.Lock()
	owned := hostTable.held[int(to)] == w || to <= 2 && hostTable.standard[to][w]
	hostTable.mu.Unlock()
	if !owned {
		hostTable.making.Lock()
		defer hostTable.making.Unlock()
	}
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	if to <= 2 && w.ownStandard[to] && hostTable.held[int(to)] != w {
		return nil
	}
	if owner, held := hostTable.held[int(to)]; held && owner != w || reservedLocked(int(to)) {
		return syscall.EBUSY
	}
	if err := w.withSlotSourceLocked(src, func(fd int) error { return hostDupTo(fd, int(to)) }); err != nil {
		return err
	}
	if to <= 2 && w.entryHostConnLocked(src) != nil {
		delete(hostTable.held, int(to))
		w.shareStandardLocked(to)
		return nil
	}
	w.holdLocked(int(to))
	return nil
}

// releaseHostSlotLocked closes the host's descriptor of w's slot fd, when
// it has one (closeHostSlotLocked). A standard descriptor of the process's
// that other instances share stays open; the last to let it go closes it.
// One taken in from outside the guest that the host no longer has under the
// number (currentLocked) is not closed: it is not the slot's any more. It
// is closed under hostTable.mu: the number is free only once no placement
// can be told it is still someone's. Caller holds w.mu.
func (w *WasiStubs) releaseHostSlotLocked(fd int32) error {
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	if made, adopted := w.adopted[fd]; adopted {
		delete(w.adopted, fd)
		if now, open := hostIdentityOf(int(fd)); !open || now != made {
			delete(hostTable.held, int(fd))
			return nil
		}
	}
	if fd <= 2 && hostTable.standard[fd][w] {
		delete(hostTable.standard[fd], w)
		if len(hostTable.standard[fd]) > 0 {
			return nil
		}
		return closeHostSlotLocked(int(fd))
	}
	if hostTable.held[int(fd)] != w {
		return nil
	}
	delete(hostTable.held, int(fd))
	return closeHostSlotLocked(int(fd))
}

// closeHostSlotLocked closes the slot descriptor fd: through the file of
// Files it is (hostTable.files), or by its number. Caller holds
// hostTable.mu.
func closeHostSlotLocked(fd int) error {
	if f := hostTable.files[fd]; f != nil {
		delete(hostTable.files, fd)
		return f.Close()
	}
	return hostCloseFD(fd)
}

// leaveStandardNumbersLocked gives up w's share of the process's standard
// descriptors without closing them: at the end of the instance they stay
// the process's. One of the placeholder's is closed with its slot. Caller
// holds w.mu.
func (w *WasiStubs) leaveStandardNumbersLocked() {
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	for fd := range hostTable.standard {
		delete(hostTable.standard[fd], w)
	}
}

// adoptHostLocked makes descriptor fd of the host process, which w has no
// slot for, w's slot fd and returns its entry: when fd is open, below
// hostDescriptorFloor, and nobody's — no instance's slot, not one the
// process had when it started having the host's descriptors (reserved),
// not one the runtime is making (hostTable.making). Code outside the guest
// made it, native code say. The entry has a duplicate of its own
// (hostDescriptorEntry), and the descriptor keeps its mode; the guest's
// close closes fd. What fd is open on is recorded: code outside the guest
// may close it without the guest, and the slot is checked against it on
// every use (currentLocked). A standard number is the process's or the
// guest's own, never taken in. A failure is told Errors once w.mu is let go
// (reportLater), and the guest finds fd closed. Caller holds w.mu.
func (w *WasiStubs) adoptHostLocked(fd int32) *wasiOpen {
	if fd <= 2 || fd >= hostDescriptorFloor {
		return nil
	}
	hostTable.making.Lock()
	defer hostTable.making.Unlock()
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	if !hostTable.adoptable || hostTable.held[int(fd)] != nil || reservedLocked(int(fd)) {
		return nil
	}
	made, open := hostIdentityOf(int(fd))
	if !open {
		return nil
	}
	op, err := hostDescriptorEntry(int(fd), "/dev/fd/"+strconv.Itoa(int(fd)), false)
	if err != nil {
		w.reportLater("host_descriptors", err)
		return nil
	}
	w.holdLocked(int(fd))
	w.setSlotLocked(fd, op)
	if w.adopted == nil {
		w.adopted = map[int32]hostIdentity{}
	}
	w.adopted[fd] = made
	return op
}

// hostCloseOnExec reports whether the host's descriptor fd is not passed
// on to a command: it is close-on-exec, or not open.
func hostCloseOnExec(fd int) bool {
	flags, err := descriptorFlags(fd, syscall.F_GETFD)
	return err != nil || flags&syscall.FD_CLOEXEC != 0
}

// hostCloseOnExecMark returns the close-on-exec mark of the host's
// descriptor fd (1 for close-on-exec), as F_GETFD gives it, and with set
// sets it to value (F_SETFD).
func hostCloseOnExecMark(fd int, set, value bool) (uint32, error) {
	flags, err := descriptorFlags(fd, syscall.F_GETFD)
	if err != nil {
		return 0, os.NewSyscallError("fcntl", err)
	}
	old := uint32(flags & syscall.FD_CLOEXEC)
	if set {
		flags &^= syscall.FD_CLOEXEC
		if value {
			flags |= syscall.FD_CLOEXEC
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, uintptr(flags)); errno != 0 {
			return 0, os.NewSyscallError("fcntl", errno)
		}
	}
	return old, nil
}

// inheritedOutside returns the descriptors of the host process that a
// command of w's inherits besides its slots (inheritedLocked), where
// w's descriptors are the host's: the open ones below hostDescriptorFloor
// that are not close-on-exec and are w's to have (adoptHostLocked), as
// exec(2) passes the descriptors code outside the guest made. A failure to
// list them is told Errors, and none is passed.
func (w *WasiStubs) inheritedOutside() []commandDescriptor {
	if !w.hostNumbered() {
		return nil
	}
	open, err := openHostDescriptors()
	if err != nil {
		w.reportError("proc_spawn", err)
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	var out []commandDescriptor
	for _, fd := range open {
		if fd <= 2 || fd >= hostDescriptorFloor {
			continue
		}
		n := int32(fd)
		if w.fdTable[n] != nil || hostTable.held[fd] != nil || reservedLocked(fd) {
			continue
		}
		if hostCloseOnExec(fd) {
			continue
		}
		out = append(out, commandDescriptor{at: n})
	}
	return out
}

// currentLocked reports whether w's slot fd, which has an entry, is still
// what the host has under the number: always for a descriptor the runtime
// made or was given, and for one taken in from outside the guest
// (adoptHostLocked) while the host has the same file there. One that code
// outside the guest closed, its number given to something else or not, is
// dropped from the table without closing anything of the host's under the
// number; its entry is closed once w.mu is let go. Caller holds w.mu.
func (w *WasiStubs) currentLocked(fd int32) bool {
	made, adopted := w.adopted[fd]
	if !adopted {
		return true
	}
	if now, open := hostIdentityOf(int(fd)); open && now == made {
		return true
	}
	hostTable.mu.Lock()
	delete(hostTable.held, int(fd))
	hostTable.mu.Unlock()
	delete(w.adopted, fd)
	w.replaceSlotLocked("host_descriptors", fd, nil)
	return false
}

// takeStandardLocked sets up slot fd (0, 1 or 2) of an instance whose
// descriptors are the host's when the standard stream there is the host's
// file under that number (os.Stdin, os.Stdout, os.Stderr): the slot holds
// an entry of its own of the descriptor (hostDescriptorEntry), which keeps
// its mode, and shares the process's descriptor fd (shareStandardLocked).
// It reports whether it did; a stream that is no such file, or whose number
// another instance holds a descriptor of its own at, stays the instance's
// stream, at a number of the guest's own (ownStandard), and a failure is
// told Errors once w.mu is let go (reportLater). Caller holds w.mu.
func (w *WasiStubs) takeStandardLocked(fd int32) bool {
	f, ok := [...]any{w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr}[fd].(*os.File)
	if !ok || f == nil {
		return false
	}
	at := -1
	if err := withHostDescriptor(f, func(d uintptr) error {
		at = int(d)
		return nil
	}); err != nil || at != int(fd) {
		w.reportLater("host_descriptors", err)
		return false
	}
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	if hostTable.held[at] != nil {
		// another instance's descriptor, not the stream's
		return false
	}
	op, err := hostDescriptorEntry(at, f.Name(), false)
	if err != nil {
		w.reportLater("host_descriptors", err)
		return false
	}
	w.shareStandardLocked(fd)
	w.setSlotLocked(fd, op)
	return true
}

// fileEntry returns the entry of f, a file of the configuration's Files,
// which it takes over: an entry of a duplicate of its descriptor
// (hostDescriptorEntry), a socket put in non-blocking mode when nonblock
// asks, f being closed. On failure f is closed.
func fileEntry(f *os.File, nonblock bool) (*wasiOpen, error) {
	var op *wasiOpen
	err := withHostDescriptor(f, func(fd uintptr) error {
		var err error
		op, err = hostDescriptorEntry(int(fd), f.Name(), nonblock)
		return err
	})
	if err = errors.Join(err, f.Close()); err != nil {
		if op != nil {
			err = errors.Join(err, closeWasiOpen(op))
		}
		return nil, err
	}
	return op, nil
}

// placeFileLocked enters f, a file of the configuration's Files, at fd in
// an instance whose descriptors are the host's: an entry of a duplicate of
// its descriptor, with the host's descriptor fd the slot's
// (placeHostSlotLocked). A file at fd itself is the slot's descriptor, and
// is closed with it (hostTable.files); any other is closed, as the
// instance took it over. A file at a standard number is the process's
// descriptor there, whatever the instance's stream was (ownStandard). On
// failure f is closed. Caller holds w.mu.
func (w *WasiStubs) placeFileLocked(fd int32, f *os.File) error {
	if fd <= 2 {
		w.ownStandard[fd] = false
	}
	at := -1
	var op *wasiOpen
	if err := withHostDescriptor(f, func(d uintptr) error {
		at = int(d)
		var err error
		// The guest's mode is the description's here (hostFamily).
		op, err = hostDescriptorEntry(at, f.Name(), false)
		return err
	}); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := w.placeHostSlotLocked(fd, op); err != nil {
		return errors.Join(fmt.Errorf("descriptor %d: %w", fd, err), closeWasiOpen(op), f.Close())
	}
	var err error
	if at == int(fd) {
		hostTable.mu.Lock()
		if hostTable.files == nil {
			hostTable.files = map[int]*os.File{}
		}
		hostTable.files[at] = f
		hostTable.mu.Unlock()
	} else {
		err = f.Close()
	}
	w.replaceSlotLocked("files", fd, op)
	return err
}

// hostDescriptorEntry returns an entry of descriptor fd of the host, which
// it leaves open: of a close-on-exec duplicate at runtimeFloor or above,
// named name. A socket is a socket entry, of the family getsockname tells
// and the type SO_TYPE tells, reachable at its address as it is bound
// already, its open file description put in non-blocking mode when nonblock
// asks (a socket of Files where the guest's mode is not the description's,
// as net.FileConn does); any other is a file entry open for what F_GETFL
// says. Its O_APPEND and O_NONBLOCK are the guest's flags.
func hostDescriptorEntry(fd int, name string, nonblock bool) (*wasiOpen, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, os.NewSyscallError("fstat", err)
	}
	flags, err := descriptorFlags(fd, syscall.F_GETFL)
	if err != nil {
		return nil, os.NewSyscallError("fcntl", err)
	}
	dup, err := dupFrom(fd, runtimeFloor())
	if err != nil {
		return nil, err
	}
	var fdflags int32
	if flags&syscall.O_APPEND != 0 {
		fdflags |= 0x1
	}
	socket := st.Mode&syscall.S_IFMT == syscall.S_IFSOCK
	if flags&syscall.O_NONBLOCK != 0 || nonblock && socket {
		fdflags |= 0x4
	}
	if socket {
		op, err := hostSocketEntry(dup, nonblock)
		if err != nil {
			return nil, errors.Join(err, hostCloseFD(dup))
		}
		op.fdflags = fdflags
		return op, nil
	}
	mode := st.Mode & syscall.S_IFMT
	return &wasiOpen{
		f:       os.NewFile(uintptr(dup), name),
		isDir:   mode == syscall.S_IFDIR,
		regular: mode == syscall.S_IFREG,
		fdflags: fdflags,
		noRead:  flags&syscall.O_ACCMODE == syscall.O_WRONLY,
		noWrite: flags&syscall.O_ACCMODE == syscall.O_RDONLY,
	}, nil
}

// hostSocketEntry returns the socket entry of fd, a socket of the host's
// the entry takes over (see hostDescriptorEntry).
func hostSocketEntry(fd int, nonblock bool) (*wasiOpen, error) {
	if nonblock {
		if err := syscall.SetNonblock(fd, true); err != nil {
			return nil, os.NewSyscallError("fcntl", err)
		}
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, os.NewSyscallError("getsockname", err)
	}
	var family int32
	switch sa.(type) {
	case *syscall.SockaddrInet4:
		family = wasiSockFamilyIPv4
	case *syscall.SockaddrInet6:
		family = wasiSockFamilyIPv6
	case *syscall.SockaddrUnix:
		family = wasiSockFamilyUnix
	default:
		return nil, syscall.EAFNOSUPPORT
	}
	typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return nil, os.NewSyscallError("getsockopt", err)
	}
	if typ != syscall.SOCK_STREAM && typ != syscall.SOCK_DGRAM {
		return nil, syscall.EPROTOTYPE
	}
	return &wasiOpen{isSocket: true, family: family, dgram: typ == syscall.SOCK_DGRAM, sock: &wasiSocket{
		host:      os.NewFile(uintptr(fd), "socket"),
		reachable: true,
	}}, nil
}
