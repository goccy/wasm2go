//go:build darwin || linux

package codegen

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// This file is the descriptor layer of a guest that is the host process
// (SetHostProcess). Such a guest has the host process's descriptors as its
// own: descriptor N of the guest is descriptor N of the host, in both
// directions. A number the guest hands to code that runs outside it (a
// native library) names the same open file there, and a descriptor such
// code made is the guest's under its number.
//
// An entry of the guest's table is then a hostFile: nothing but the number,
// and every operation is the host's system call on it. What the kernel
// keeps for a descriptor is kept nowhere else — the blocking mode the guest
// set is the mode of the open file, a socket's options and timeouts are the
// socket's — so that code outside the guest finds what the guest left, and
// the guest finds what that code left.
//
// The runtime never switches a descriptor to non-blocking mode for its own
// waiting. A call of the guest's that has to wait waits in poll(2), together
// with the pipe a signal posted to the guest writes to (hostWaker), and
// makes the call once the descriptor is ready.

// The events of poll(2), which have the same bits on every host this file
// is built for.
const (
	hostPollIn   int16 = 0x1
	hostPollPri  int16 = 0x2
	hostPollOut  int16 = 0x4
	hostPollErr  int16 = 0x8
	hostPollHup  int16 = 0x10
	hostPollNval int16 = 0x20
)

// hostPoll is struct pollfd.
type hostPoll struct {
	fd      int32
	events  int16
	revents int16
}

// hostTable is what the runtime knows about the descriptor table of the
// host process, which is one for every guest in it.
var hostTable struct {
	mu sync.Mutex
	// open maps a descriptor to the entry of a guest's table that is it:
	// the descriptors guests opened, were started with, or took over from
	// code outside them. An entry can be in the tables of several
	// instances (Fork); a descriptor that is in none of the table of the
	// instance that asks, and is here, is another process's.
	open map[int]*wasiOpen
	// reserved holds the descriptors below floor that the runtime has for
	// itself: the ones the Go runtime made its poller and its signal
	// delivery with. No guest gets at them by number.
	reserved map[int]struct{}
	// floor is the lowest number the runtime gives a descriptor of its
	// own that it can place (see hostFloor). From there up every number is
	// the runtime's.
	floor int
}

// hostCallTurn is held while a descriptor is asked whether a call on it
// would wait and, if not, while the call is made: of all the guests in the
// process that wait for the same pipe or listening socket, the one that
// finds it ready is the one that reads or accepts, and no other gets in
// between and is left waiting inside the host's call, where no signal
// reaches it.
var hostCallTurn sync.Mutex

// hostFloor returns the lowest number for a descriptor the runtime makes
// for itself: well above what a program's own descriptors reach, so that
// the lowest free number is the same for the guest as for the host.
func hostFloor() int {
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	if hostTable.floor == 0 {
		floor := 1 << 16
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err == nil && limit.Cur/2 < uint64(floor) {
			floor = int(limit.Cur / 2)
		}
		if floor < 3 {
			floor = 3
		}
		hostTable.floor = floor
	}
	return hostTable.floor
}

// hostReserve records that fd is a descriptor of the runtime's own.
func hostReserve(fd int) {
	hostTable.mu.Lock()
	if hostTable.reserved == nil {
		hostTable.reserved = map[int]struct{}{}
	}
	hostTable.reserved[fd] = struct{}{}
	hostTable.mu.Unlock()
}

// hostLowRange is how many of the lowest descriptor numbers are kept free
// of the Go runtime's poller: see KeepRuntimeDescriptorsHigh.
const hostLowRange = 64

var keepRuntimeHigh sync.Once

// KeepRuntimeDescriptorsHigh makes the Go runtime create the descriptors of
// its network poller now, above the low numbers, and records them as the
// runtime's. A guest that is the host process gets the numbers the host
// gives out, lowest free first, and a program expects its first descriptor
// to be 3: the poller, which the runtime otherwise makes when it first
// needs it, would take that number.
//
// It has an effect the first time it is called, and the earlier that is
// the better — an embedder whose program is the host process calls it while
// its packages are initialized. Where the poller exists already, its
// descriptors stay where they are, and are recorded as the runtime's all
// the same. SetHostProcess calls it too.
func KeepRuntimeDescriptorsHigh() {
	keepRuntimeHigh.Do(func() {
		// What is open now, is not a standard stream and is not passed on
		// to commands is the runtime's or the embedder's own.
		for _, fd := range openDescriptors() {
			if flags, err := descriptorFlags(fd, syscall.F_GETFD); err == nil && fd > 2 && flags&syscall.FD_CLOEXEC != 0 {
				hostReserve(fd)
			}
		}
		// Fill the low numbers, have the poller made, and free them again.
		var plugs []int
		defer func() {
			for _, fd := range plugs {
				_ = syscall.Close(fd)
			}
		}()
		syscall.ForkLock.RLock()
		null, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			syscall.ForkLock.RUnlock()
			return
		}
		plugs = append(plugs, null)
		for null < hostLowRange {
			fd, err := hostDup(null, 0)
			if err != nil {
				break
			}
			if fd >= hostLowRange {
				_ = syscall.Close(fd)
				break
			}
			plugs = append(plugs, fd)
		}
		syscall.ForkLock.RUnlock()
		before := openDescriptors()
		// A pipe of package os is a descriptor the poller watches.
		if r, wr, err := os.Pipe(); err == nil {
			_ = r.Close()
			_ = wr.Close()
		}
		// Where the runtime hands signals to package os/signal through a
		// pipe, it makes the pipe when a signal is first asked for. One
		// that is ignored unless a program handles it serves.
		asked := make(chan os.Signal, 1)
		signal.Notify(asked, syscall.SIGWINCH)
		signal.Stop(asked)
		known := map[int]bool{}
		for _, fd := range before {
			known[fd] = true
		}
		for _, fd := range openDescriptors() {
			if !known[fd] {
				hostReserve(fd)
			}
		}
	})
}

// openDescriptors returns the descriptors of the host process that are
// open, in ascending order. The names in /dev/fd are read and nothing is
// asked about them: not every descriptor has a file there that can be
// looked at (the queue of the runtime's poller has none on some hosts).
func openDescriptors() []int {
	var fds []int
	dir, err := syscall.Open("/dev/fd", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer syscall.Close(dir)
	listing := &hostFile{}
	listing.fd.Store(int32(dir))
	names, err := listing.names()
	if err != nil {
		return nil
	}
	for _, entry := range names {
		fd := 0
		digits := len(entry.name) > 0
		for _, c := range entry.name {
			if c < '0' || c > '9' {
				digits = false
				break
			}
			fd = fd*10 + int(c-'0')
		}
		if !digits || fd == dir {
			continue
		}
		fds = append(fds, fd)
	}
	sort.Ints(fds)
	return fds
}

// hostFile is a descriptor of the host process as the file of an entry of
// the guest's table.
type hostFile struct {
	// fd is the descriptor, and -1 once the entry has closed it or it is
	// known to be gone (closed by code outside the guest, its number given
	// to something else).
	fd atomic.Int32
	// kind is the file type (the S_IFMT bits of its mode) the descriptor
	// had when the entry was made. Immutable.
	kind uint32
	// path is the path of the host's the descriptor was opened under, for
	// a file or directory the guest opened by name. Immutable.
	path string
	// closing keeps the descriptor from being closed while a call of the
	// host's is made on it: whoever makes one holds it for reading (hold),
	// and Close takes it for writing. An instance's descriptors can be
	// closed from outside the guest while the guest is still running
	// (CloseDescriptors), and the number of a closed descriptor is the
	// next one the host gives out — to another process of the family,
	// perhaps, whose file a call under the old number would then reach.
	// Waiting for a descriptor is not a call on it and is done without.
	closing sync.RWMutex
}

// newHostFile returns the file for descriptor fd of the given type.
func newHostFile(fd int, kind uint32, path string) *hostFile {
	h := &hostFile{kind: kind & syscall.S_IFMT, path: path}
	h.fd.Store(int32(fd))
	return h
}

// hold returns the descriptor for a call of the host's on it, or an error
// when it is gone, and keeps it open until release is called: see closing.
func (h *hostFile) hold() (int, error) {
	h.closing.RLock()
	fd := int(h.fd.Load())
	if fd < 0 {
		h.closing.RUnlock()
		return -1, syscall.EBADF
	}
	return fd, nil
}

// release ends what hold began.
func (h *hostFile) release() { h.closing.RUnlock() }

// number returns the descriptor, or an error when it is gone: for waiting
// on it, and for telling which descriptor the entry is. A call of the
// host's on it takes hold instead.
func (h *hostFile) number() (int, error) {
	fd := int(h.fd.Load())
	if fd < 0 {
		return -1, syscall.EBADF
	}
	return fd, nil
}

// waits reports whether a read or write of the descriptor can wait: it is a
// pipe, a socket or a character device (a terminal), and not a file,
// directory or block device, whose reads and writes return at once.
func (h *hostFile) waits() bool {
	switch h.kind {
	case syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFCHR:
		return true
	}
	return false
}

// socket reports whether the descriptor is a socket.
func (h *hostFile) socket() bool { return h.kind == syscall.S_IFSOCK }

func (h *hostFile) Name() string { return h.path }

func (h *hostFile) Read(p []byte) (int, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	for {
		n, err := syscall.Read(fd, p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, os.NewSyscallError("read", err)
		}
		if n == 0 && len(p) > 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (h *hostFile) ReadAt(p []byte, off int64) (int, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	total := 0
	for total < len(p) {
		n, err := syscall.Pread(fd, p[total:], off+int64(total))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, os.NewSyscallError("pread", err)
		}
		if n == 0 {
			return total, io.EOF
		}
		total += n
	}
	return total, nil
}

func (h *hostFile) Write(p []byte) (int, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	total := 0
	for total < len(p) {
		n, err := syscall.Write(fd, p[total:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, os.NewSyscallError("write", err)
		}
		total += n
	}
	return total, nil
}

func (h *hostFile) WriteAt(p []byte, off int64) (int, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	total := 0
	for total < len(p) {
		n, err := syscall.Pwrite(fd, p[total:], off+int64(total))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, os.NewSyscallError("pwrite", err)
		}
		total += n
	}
	return total, nil
}

func (h *hostFile) Seek(offset int64, whence int) (int64, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	n, err := syscall.Seek(fd, offset, whence)
	if err != nil {
		return 0, os.NewSyscallError("lseek", err)
	}
	return n, nil
}

// Close closes the descriptor and takes it off the host's table.
func (h *hostFile) Close() error {
	h.closing.Lock()
	defer h.closing.Unlock()
	fd := int(h.fd.Swap(-1))
	if fd < 0 {
		return nil
	}
	hostForget(fd, h)
	if err := syscall.Close(fd); err != nil && err != syscall.EINTR {
		return os.NewSyscallError("close", err)
	}
	return nil
}

// leave ends the entry's hold on the descriptor without closing it: the
// descriptor stays the host process's.
func (h *hostFile) leave() {
	h.closing.Lock()
	defer h.closing.Unlock()
	if fd := int(h.fd.Swap(-1)); fd >= 0 {
		hostForget(fd, h)
	}
}

// hostForget takes the entry whose file is h off the host's table, where it
// was known under fd.
func hostForget(fd int, h *hostFile) {
	hostTable.mu.Lock()
	if op := hostTable.open[fd]; op != nil && op.f == File(h) {
		delete(hostTable.open, fd)
	}
	hostTable.mu.Unlock()
}

func (h *hostFile) Stat() (os.FileInfo, error) {
	fd, err := h.hold()
	if err != nil {
		return nil, err
	}
	defer h.release()
	info := &hostFileInfo{name: h.path}
	for {
		err := syscall.Fstat(fd, &info.st)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("fstat", err)
		}
		return info, nil
	}
}

func (h *hostFile) Sync() error {
	fd, err := h.hold()
	if err != nil {
		return err
	}
	defer h.release()
	for {
		err := syscall.Fsync(fd)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return os.NewSyscallError("fsync", err)
		}
		return nil
	}
}

func (h *hostFile) Truncate(size int64) error {
	fd, err := h.hold()
	if err != nil {
		return err
	}
	defer h.release()
	for {
		err := syscall.Ftruncate(fd, size)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return os.NewSyscallError("ftruncate", err)
		}
		return nil
	}
}

func (h *hostFile) Chmod(mode os.FileMode) error {
	fd, err := h.hold()
	if err != nil {
		return err
	}
	defer h.release()
	for {
		err := syscall.Fchmod(fd, unixModeBits(mode))
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return os.NewSyscallError("fchmod", err)
		}
		return nil
	}
}

// hostName is one name of a directory with the file type the directory
// records for it.
type hostName struct {
	name string
	typ  uint8
}

// names reads the names in the directory from its beginning, without "."
// and "..".
func (h *hostFile) names() ([]hostName, error) {
	fd, err := h.hold()
	if err != nil {
		return nil, err
	}
	defer h.release()
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return nil, os.NewSyscallError("lseek", err)
	}
	var entry syscall.Dirent
	const (
		reclenAt = unsafe.Offsetof(entry.Reclen)
		typeAt   = unsafe.Offsetof(entry.Type)
		nameAt   = unsafe.Offsetof(entry.Name)
	)
	var out []hostName
	buf := make([]byte, 32<<10)
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("getdents", err)
		}
		if n <= 0 {
			return out, nil
		}
		for rest := buf[:n]; len(rest) > int(nameAt); {
			reclen := int(uint16(rest[reclenAt]) | uint16(rest[reclenAt+1])<<8)
			if reclen <= int(nameAt) || reclen > len(rest) {
				break
			}
			rec := rest[:reclen]
			rest = rest[reclen:]
			ino := uint64(0)
			for i := 7; i >= 0; i-- {
				ino = ino<<8 | uint64(rec[i])
			}
			if ino == 0 {
				continue
			}
			name := rec[nameAt:]
			for i, c := range name {
				if c == 0 {
					name = name[:i]
					break
				}
			}
			if s := string(name); s != "." && s != ".." {
				out = append(out, hostName{name: s, typ: rec[typeAt]})
			}
		}
	}
}

// ReadDir reads the whole directory, whatever n is: the one caller asks
// for all of it.
func (h *hostFile) ReadDir(n int) ([]os.DirEntry, error) {
	names, err := h.names()
	if err != nil {
		return nil, err
	}
	out := make([]os.DirEntry, 0, len(names))
	for _, entry := range names {
		out = append(out, &hostDirEntry{dir: h.path, name: entry.name, typ: entry.typ})
	}
	return out, nil
}

// hostDirEntry is an entry of a directory read through a hostFile.
type hostDirEntry struct {
	dir, name string
	typ       uint8 // d_type
}

func (e *hostDirEntry) Name() string { return e.name }
func (e *hostDirEntry) IsDir() bool  { return e.Type().IsDir() }
func (e *hostDirEntry) Type() os.FileMode {
	// The values of d_type are the file type bits of a mode, shifted.
	switch uint32(e.typ) << 12 {
	case syscall.S_IFDIR:
		return os.ModeDir
	case syscall.S_IFLNK:
		return os.ModeSymlink
	case syscall.S_IFIFO:
		return os.ModeNamedPipe
	case syscall.S_IFSOCK:
		return os.ModeSocket
	case syscall.S_IFCHR:
		return os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFBLK:
		return os.ModeDevice
	case syscall.S_IFREG:
		return 0
	}
	// The directory does not say (DT_UNKNOWN): the file does.
	if fi, err := e.Info(); err == nil {
		return fi.Mode().Type()
	}
	return 0
}
func (e *hostDirEntry) Info() (os.FileInfo, error) { return os.Lstat(e.dir + "/" + e.name) }

// hostFileInfo describes a descriptor by its fstat result.
type hostFileInfo struct {
	name string
	st   syscall.Stat_t
}

func (fi *hostFileInfo) Name() string       { return fi.name }
func (fi *hostFileInfo) Size() int64        { return fi.st.Size }
func (fi *hostFileInfo) ModTime() time.Time { return statModTime(&fi.st) }
func (fi *hostFileInfo) IsDir() bool        { return uint32(fi.st.Mode)&syscall.S_IFMT == syscall.S_IFDIR }
func (fi *hostFileInfo) Sys() any           { return &fi.st }
func (fi *hostFileInfo) Mode() os.FileMode {
	mode := unixFileMode(uint32(fi.st.Mode))
	switch uint32(fi.st.Mode) & syscall.S_IFMT {
	case syscall.S_IFDIR:
		mode |= os.ModeDir
	case syscall.S_IFLNK:
		mode |= os.ModeSymlink
	case syscall.S_IFIFO:
		mode |= os.ModeNamedPipe
	case syscall.S_IFSOCK:
		mode |= os.ModeSocket
	case syscall.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFBLK:
		mode |= os.ModeDevice
	}
	return mode
}

// statusFlags returns the file status flags of the descriptor (F_GETFL).
func (h *hostFile) statusFlags() (int, error) {
	fd, err := h.hold()
	if err != nil {
		return 0, err
	}
	defer h.release()
	return descriptorFlags(fd, syscall.F_GETFL)
}

// nonblocking reports whether the open file is in non-blocking mode.
func (h *hostFile) nonblocking() bool {
	flags, err := h.statusFlags()
	return err == nil && flags&syscall.O_NONBLOCK != 0
}

// fdflags returns the status flags as the fdflags of WASI: 0x1 APPEND,
// 0x4 NONBLOCK, 0x10 SYNC.
func (h *hostFile) fdflags() int32 {
	flags, err := h.statusFlags()
	if err != nil {
		return 0
	}
	var out int32
	if flags&syscall.O_APPEND != 0 {
		out |= 0x1
	}
	if flags&syscall.O_NONBLOCK != 0 {
		out |= wasiFdflagNonblock
	}
	if flags&syscall.O_SYNC != 0 {
		out |= 0x10
	}
	return out
}

// setFdflags sets the status flags the fdflags of WASI name, and clears
// the ones they leave out.
func (h *hostFile) setFdflags(fdflags int32) error {
	fd, err := h.hold()
	if err != nil {
		return err
	}
	defer h.release()
	flags, err := descriptorFlags(fd, syscall.F_GETFL)
	if err != nil {
		return err
	}
	flags &^= syscall.O_APPEND | syscall.O_NONBLOCK | syscall.O_SYNC
	if fdflags&0x1 != 0 {
		flags |= syscall.O_APPEND
	}
	if fdflags&wasiFdflagNonblock != 0 {
		flags |= syscall.O_NONBLOCK
	}
	if fdflags&(0x2|0x8|0x10) != 0 {
		flags |= syscall.O_SYNC
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFL, uintptr(flags)); errno != 0 {
		return errno
	}
	return nil
}

// host returns the descriptor of the host process the entry is, or nil for
// an entry that is something else: a file of another filesystem backend, a
// stream or a connection the embedder supplied.
func (op *wasiOpen) host() *hostFile {
	if op == nil {
		return nil
	}
	h, _ := op.f.(*hostFile)
	return h
}

// leaveStandard gives up the entry's hold on a standard descriptor of the
// host process (0, 1 or 2) without closing it, when no other table slot
// refers to the entry: see endWasiOpen.
func (op *wasiOpen) leaveStandard() {
	h := op.host()
	if h == nil {
		return
	}
	if fd := h.fd.Load(); fd < 0 || fd > 2 {
		return
	}
	op.mu.Lock()
	last := op.refs == 0
	op.mu.Unlock()
	if last {
		h.leave()
	}
}

// filetype returns the WASI file type of the descriptor: 1 block device,
// 2 character device, 3 directory, 4 regular file, 5 datagram socket,
// 6 stream socket. WASI has none for a pipe, which is reported as a
// regular file here and gets its type from the filestat_ext record.
func (h *hostFile) filetype(dgram bool) byte {
	switch h.kind {
	case syscall.S_IFBLK:
		return 1
	case syscall.S_IFCHR:
		return 2
	case syscall.S_IFDIR:
		return 3
	case syscall.S_IFSOCK:
		if dgram {
			return 5
		}
		return 6
	}
	return 4
}

// inheritedHostDescriptor makes the entry for a descriptor the process was
// started with. It is close-on-exec from here on, like every descriptor the
// runtime holds: whether a command the guest starts gets it is the guest's
// to say (Fd_cloexec), and it does unless the guest says otherwise.
func inheritedHostDescriptor(fd int) *wasiOpen {
	op, err := newHostOpen(fd, "")
	if err != nil {
		return nil
	}
	if op.isSocket {
		// A socket is taken over through the host's network API.
		return nil
	}
	syscall.CloseOnExec(fd)
	return op
}

// hostPollSet is the descriptors of the host process one poll_oneoff asks
// about, with the subscription each belongs to.
type hostPollSet struct {
	subs []int
	read []bool
	fds  []hostPoll
}

// add enters the descriptor of h for subscription sub, for reading or for
// writing. It reports false when the descriptor is gone.
func (s *hostPollSet) add(sub int, h *hostFile, read bool) bool {
	fd, err := h.number()
	if err != nil {
		return false
	}
	s.subs = append(s.subs, sub)
	s.read = append(s.read, read)
	s.fds = append(s.fds, hostPoll{fd: int32(fd), events: hostPollRequest(read)})
	return true
}

func (s *hostPollSet) empty() bool { return len(s.fds) == 0 }

// look asks the host which of the descriptors are ready right now.
func (s *hostPollSet) look() { hostPollUntil(s.fds, time.Now()) }

// ready calls mark with the subscription of every descriptor the last poll
// found ready, and reports whether there was one.
func (s *hostPollSet) ready(mark func(sub int)) bool {
	any := false
	for i, p := range s.fds {
		if hostPollReady(s.read[i], p.revents) {
			mark(s.subs[i])
			any = true
		}
	}
	return any
}

// await waits for one of the descriptors, as awaitHost does.
func (s *hostPollSet) await(w *WasiStubs, until time.Time) int32 {
	return w.awaitHost(s.fds, until)
}

// awaitStoppable waits for one of the descriptors until the time until, or
// until stop is closed.
func (s *hostPollSet) awaitStoppable(until time.Time, stop <-chan struct{}) {
	hostPollStoppable(s.fds, until, stop)
}

// hostDup duplicates fd onto the lowest free number that is at least min,
// close-on-exec like every descriptor the runtime holds.
func hostDup(fd, min int) (int, error) {
	for {
		nfd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, uintptr(min))
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return -1, errno
		}
		return int(nfd), nil
	}
}

// newHostOpen makes the entry for descriptor fd of the host process, which
// it finds out about by asking the host: what kind of file it is, what it
// is open for, and for a socket its type and family. path is the path it
// was opened under, if it was opened by name.
func newHostOpen(fd int, path string) (*wasiOpen, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	h := newHostFile(fd, uint32(st.Mode), path)
	op := &wasiOpen{f: h, isDir: h.kind == syscall.S_IFDIR}
	if h.socket() {
		op.isSocket = true
		if typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err == nil {
			op.dgram = typ == syscall.SOCK_DGRAM
		}
		op.family = wasiSockFamilyIPv4
		if sa, err := syscall.Getsockname(fd); err == nil {
			switch sa.(type) {
			case *syscall.SockaddrInet6:
				op.family = wasiSockFamilyIPv6
			case *syscall.SockaddrUnix:
				op.family = wasiSockFamilyUnix
			}
		}
		return op, nil
	}
	if flags, err := descriptorFlags(fd, syscall.F_GETFL); err == nil {
		switch flags & syscall.O_ACCMODE {
		case syscall.O_RDONLY:
			op.noWrite = true
		case syscall.O_WRONLY:
			op.noRead = true
		}
	}
	return op, nil
}

// hostDescriptorsOn reports whether the instance's descriptors are the host
// process's. Caller holds w.mu.
func (w *WasiStubs) hostDescriptorsLocked() bool { return w.hostProcess }

// hostStandardLocked returns the entry for the standard stream stdio
// (1 stdin, 2 stdout, 3 stderr) of an instance whose descriptors are the
// host's: the host process's own descriptor when the instance's stream is
// that one — a file of the host whose descriptor is 0, 1 or 2 respectively
// — which it shares with whoever else has it, and otherwise the entry that
// names the instance's stream. Caller holds w.mu.
func (w *WasiStubs) hostStandardLocked(stdio int8) *wasiOpen {
	var stream any
	switch stdio {
	case 1:
		stream = w.stdin
	case 2:
		stream = w.stdout
	case 3:
		stream = w.stderr
	}
	fd := int(stdio) - 1
	own := false
	if file, isFile := stream.(*os.File); isFile {
		hostDescriptor(file, func(number uintptr) { own = int(number) == fd })
	}
	if own {
		hostTable.mu.Lock()
		shared := hostTable.open[fd]
		hostTable.mu.Unlock()
		if shared != nil && shared.host() != nil {
			w.keepStandardLocked(fd)
			shared.addRef()
			return shared
		}
		if op, err := newHostOpen(fd, ""); err == nil {
			w.keepStandardLocked(fd)
			hostEnter(fd, op)
			return op
		}
	}
	return &wasiOpen{stdio: stdio}
}

// keepStandardLocked keeps a duplicate of standard descriptor fd of the
// host process (0, 1 or 2) as it is before the guest has it, for
// restoreStandardLocked to put back. Caller holds w.mu.
func (w *WasiStubs) keepStandardLocked(fd int) {
	if w.standard == nil {
		w.standard = &hostStandard{kept: [3]int{-1, -1, -1}}
	}
	if kept, err := hostDup(fd, hostFloor()); err == nil {
		w.standard.kept[fd] = kept
	}
}

// restoreStandardLocked gives the host process its standard descriptors
// back as they were when the instance took them: whatever the guest left
// under 0, 1 and 2 — a file it redirected a stream to, nothing after a
// close — is replaced. The program is over; the process it ran in goes on,
// and reports, or runs the next program, through them. Caller holds w.mu.
func (w *WasiStubs) restoreStandardLocked() {
	if w.standard == nil || w.forked {
		// A forked process has its parent's record of them, to know which
		// are the family's; they are the first process's to give back.
		return
	}
	syscall.ForkLock.RLock()
	for fd, kept := range w.standard.kept {
		if kept < 0 {
			continue
		}
		_ = hostDup2(kept, fd)
		_ = syscall.Close(kept)
	}
	syscall.ForkLock.RUnlock()
	w.standard = nil
}

// hostStandard is the standard descriptors of the host process an instance
// took over: duplicates of 0, 1 and 2 as they were, -1 for one it did not
// take. The processes forked from the instance share the record; it does
// not change once the instance's table is set up.
type hostStandard struct {
	kept [3]int
}

// hostEnter records op as the entry that is descriptor fd. An entry that
// was known under the number is gone: the host gives a number out again
// only once the descriptor that had it is closed, so that one was closed
// by code outside the guest.
func hostEnter(fd int, op *wasiOpen) {
	hostTable.mu.Lock()
	if hostTable.open == nil {
		hostTable.open = map[int]*wasiOpen{}
	}
	if old := hostTable.open[fd]; old != nil && old != op {
		if h := old.host(); h != nil {
			h.fd.CompareAndSwap(int32(fd), -1)
		}
	}
	hostTable.open[fd] = op
	hostTable.mu.Unlock()
}

// hostOwner returns the entry that is descriptor fd, if a guest has one,
// and whether the number is one of the runtime's own.
func hostOwner(fd int) (op *wasiOpen, reserved bool) {
	hostTable.mu.Lock()
	defer hostTable.mu.Unlock()
	_, reserved = hostTable.reserved[fd]
	return hostTable.open[fd], reserved
}

// addHostFDLocked enters op, a new entry that is a descriptor of the host
// process, in the instance's table and returns the number the guest knows
// it by: the descriptor's own. Only when the instance has something else
// under that number — a stream of the embedder's, a descriptor it got
// under a number of the host's that another process holds — is the
// descriptor moved to a number that is free for both. Caller holds w.mu.
func (w *WasiStubs) addHostFDLocked(op *wasiOpen) (int32, error) {
	h := op.host()
	fd, err := h.number()
	if err != nil {
		return -1, err
	}
	fds := w.fdsLocked()
	if in := fds[int32(fd)]; in != nil {
		if at := in.host(); at != nil && int(at.fd.Load()) == fd {
			// The instance's entry for this very number: it was closed
			// behind the runtime's back, or the host could not have given
			// the number out again.
			at.fd.CompareAndSwap(int32(fd), -1)
			_ = closeWasiOpen(in)
			delete(fds, int32(fd))
		} else {
			var passed []int
			moved := -1
			for from := fd + 1; ; {
				nfd, err := hostDup(fd, from)
				if err != nil {
					break
				}
				if fds[int32(nfd)] == nil {
					moved = nfd
					break
				}
				passed = append(passed, nfd)
				from = nfd + 1
			}
			for _, nfd := range passed {
				_ = syscall.Close(nfd)
			}
			if moved < 0 {
				return -1, syscall.EMFILE
			}
			_ = syscall.Close(fd)
			h.fd.Store(int32(moved))
			fd = moved
		}
	}
	if fd <= 2 {
		// A standard descriptor is the host process's as well, and code
		// outside the guest that starts a command counts on handing it on.
		hostKeepOnExec(fd)
	}
	hostEnter(fd, op)
	fds[int32(fd)] = op
	delete(w.cloexec, int32(fd))
	return int32(fd), nil
}

// hostKeepOnExec clears the close-on-exec flag of a descriptor.
func hostKeepOnExec(fd int) {
	if flags, err := descriptorFlags(fd, syscall.F_GETFD); err == nil && flags&syscall.FD_CLOEXEC != 0 {
		_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, uintptr(flags&^syscall.FD_CLOEXEC))
	}
}

// hostNumberFreeLocked reports whether the instance can have a descriptor
// of its own under the host's number fd. It cannot when another guest's
// entry is that descriptor; when the number is the runtime's — one the
// runtime recorded as its own, or any number from hostFloor up, which is
// where the runtime puts what it opens for itself; and when it is a
// standard descriptor of the host process that the instance was not given:
// an instance whose standard output is a stream of the embedder's has
// nothing to do with descriptor 1 of the process. Caller holds w.mu.
func (w *WasiStubs) hostNumberFreeLocked(fd int) bool {
	if fd >= hostFloor() {
		return false
	}
	if fd <= 2 && (w.standard == nil || w.standard.kept[fd] < 0) {
		return false
	}
	owner, reserved := hostOwner(fd)
	return owner == nil && !reserved
}

// freeNumberLocked returns the lowest number that is free in the instance's
// table and is no open descriptor of the host process: the number for an
// entry that is not a descriptor of the host (a stream of the embedder's, a
// file of another filesystem backend). Caller holds w.mu.
func (w *WasiStubs) freeNumberLocked() int32 {
	fds := w.fdsLocked()
	for fd := int32(0); ; fd++ {
		if _, used := fds[fd]; used {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(int(fd), &st); err == nil {
			continue
		}
		return fd
	}
}

// dupHostLocked is dup(2) for an entry that is a descriptor of the host:
// the duplicate is a descriptor of its own that shares the open file, under
// the number the host gives it. Caller holds w.mu.
func (w *WasiStubs) dupHostLocked(op *wasiOpen) (int32, error) {
	fd, err := op.host().hold()
	if err != nil {
		return -1, err
	}
	nfd, err := hostDup(fd, 0)
	op.host().release()
	if err != nil {
		return -1, err
	}
	return w.addHostFDLocked(op.hostCopy(nfd))
}

// hostCopy returns the entry for nfd, a duplicate of the descriptor op is.
func (op *wasiOpen) hostCopy(nfd int) *wasiOpen {
	h := op.host()
	dup := &wasiOpen{
		f:        newHostFile(nfd, h.kind, h.path),
		isDir:    op.isDir,
		isSocket: op.isSocket,
		noRead:   op.noRead,
		noWrite:  op.noWrite,
		dgram:    op.dgram,
		family:   op.family,
		path:     op.path,
	}
	op.mu.Lock()
	if op.sock != nil {
		dup.sock = &wasiSocket{unixLocal: op.sock.unixLocal, unixPeer: op.sock.unixPeer}
	}
	op.mu.Unlock()
	return dup
}

// dup2HostLocked is dup2(2) for a source that is a descriptor of the host:
// the guest's number to becomes a duplicate of it, after whatever the
// instance had there is closed. The duplicate is the host's descriptor of
// that number whenever the number is the instance's to use. It is not when
// another process of the family still has its own file there — a forked
// process that reopens a standard stream leaves its parent's alone — when
// the number is one of the runtime's, and when it is a standard descriptor
// of the process that the instance was not given (hostNumberFreeLocked):
// the duplicate is then a descriptor above the range programs use, which
// only this instance's table connects with the number. Caller holds w.mu.
func (w *WasiStubs) dup2HostLocked(src *wasiOpen, to int32) error {
	fd, err := src.host().hold()
	if err != nil {
		return err
	}
	defer src.host().release()
	fds := w.fdsLocked()
	var closeErr error
	if dst := fds[to]; dst != nil {
		closeErr = closeWasiOpen(dst)
		delete(fds, to)
	}
	var nfd int
	if w.hostNumberFreeLocked(int(to)) {
		syscall.ForkLock.RLock()
		err = hostDup2(fd, int(to))
		if err == nil && to > 2 {
			syscall.CloseOnExec(int(to))
		}
		syscall.ForkLock.RUnlock()
		nfd = int(to)
	} else {
		nfd, err = hostDup(fd, hostFloor())
	}
	if err != nil {
		return err
	}
	dup := src.hostCopy(nfd)
	hostEnter(nfd, dup)
	fds[to] = dup
	delete(w.cloexec, to)
	return closeErr
}

// hostWaker is the pipe a signal posted to the guest writes to, to end the
// poll(2) a waiting call of the guest's is in. Both ends are descriptors of
// the runtime's own, above the range programs use (hostFloor).
type hostWaker struct {
	r, w int
}

// hostWakerLocked returns the instance's waker, making it on first use.
// Caller holds w.mu.
func (w *WasiStubs) hostWakerLocked() (*hostWaker, error) {
	if w.waker != nil {
		return w.waker, nil
	}
	var p [2]int
	syscall.ForkLock.RLock()
	err := syscall.Pipe(p[:])
	var ends [2]int
	if err == nil {
		for i, fd := range p {
			if ends[i], err = hostDup(fd, hostFloor()); err != nil {
				if i == 1 {
					_ = syscall.Close(ends[0])
				}
				break
			}
		}
		_ = syscall.Close(p[0])
		_ = syscall.Close(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	for _, fd := range ends {
		_ = syscall.SetNonblock(fd, true)
	}
	w.waker = &hostWaker{r: ends[0], w: ends[1]}
	return w.waker, nil
}

// closeHostWakerLocked closes the instance's waker. Caller holds w.mu.
func (w *WasiStubs) closeHostWakerLocked() {
	if w.waker == nil {
		return
	}
	_ = syscall.Close(w.waker.r)
	_ = syscall.Close(w.waker.w)
	w.waker = nil
}

// hostPollUntil is poll(2) on fds until the time until (the zero time is no
// limit): it returns when one of them has an event, or when the time is up.
func hostPollUntil(fds []hostPoll, until time.Time) {
	for {
		timeout := time.Duration(-1)
		if !until.IsZero() {
			if timeout = time.Until(until); timeout < 0 {
				timeout = 0
			}
		}
		_, errno := hostPollCall(fds, timeout)
		if errno == syscall.EINTR {
			continue
		}
		return
	}
}

// hostReadyNow reports which of events descriptor fd has right now.
func hostReadyNow(fd int, events int16) int16 {
	set := [1]hostPoll{{fd: int32(fd), events: events}}
	for {
		_, errno := hostPollCall(set[:], 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			// The host cannot say: the call on the descriptor will.
			return events
		}
		return set[0].revents
	}
}

// awaitHost waits in poll(2) until one of fds has an event, for a call of
// the guest's that has to wait. It returns 0 when one has (the events are
// in fds), EAGAIN when the time until was up first (the zero time is no
// limit), and EINTR when a signal was posted to the guest first.
func (w *WasiStubs) awaitHost(fds []hostPoll, until time.Time) int32 {
	w.mu.Lock()
	waker, err := w.hostWakerLocked()
	w.mu.Unlock()
	if err != nil {
		return mapOSError(err)
	}
	if !w.beginBlocking(func() { _, _ = syscall.Write(waker.w, []byte{0}) }) {
		return _wasiEINTR
	}
	set := make([]hostPoll, len(fds)+1)
	copy(set, fds)
	set[len(fds)] = hostPoll{fd: int32(waker.r), events: hostPollIn}
	hostPollUntil(set, until)
	copy(fds, set)
	interrupted := w.endBlocking()
	if interrupted {
		var drain [16]byte
		_, _ = syscall.Read(waker.r, drain[:])
	}
	for _, p := range fds {
		if p.revents != 0 {
			if interrupted {
				// The call is made after all; the signal is still to be
				// noticed.
				w.keepInterrupt()
			}
			return _wasiESUCCESS
		}
	}
	if interrupted {
		return _wasiEINTR
	}
	return _wasiEAGAIN
}

// The MSG_ flags of the host for the flags of one send or receive.
func hostMsgFlags(flags int32) int {
	out := 0
	if flags&wasiMsgPeek != 0 {
		out |= syscall.MSG_PEEK
	}
	return out
}

// scatter copies data into bufs in order and returns how much fitted.
func scatter(bufs [][]byte, data []byte) uint64 {
	var total uint64
	for _, buf := range bufs {
		c := copy(buf, data)
		data = data[c:]
		total += uint64(c)
		if len(data) == 0 {
			break
		}
	}
	return total
}

// vecBuffer returns the buffer one read into bufs is made into: the first
// of them when there is one, and otherwise a buffer of their total size,
// which the caller scatters.
func vecBuffer(bufs [][]byte) (buf []byte, whole bool) {
	switch len(bufs) {
	case 0:
		return nil, true
	case 1:
		return bufs[0], true
	}
	total := 0
	for _, b := range bufs {
		total += len(b)
	}
	return make([]byte, total), false
}

// receiveNow makes one read or receive on the descriptor without waiting.
// again reports that nothing is there right now; otherwise n bytes were
// taken (none at the end of input) and from is where a datagram came from,
// or errno says why not.
func (h *hostFile) receiveNow(bufs [][]byte, flags int32) (n uint64, from syscall.Sockaddr, again bool, errno int32) {
	fd, err := h.hold()
	if err != nil {
		return 0, nil, false, _wasiEBADF
	}
	defer h.release()
	buf, whole := vecBuffer(bufs)
	var got int
	for {
		if h.socket() {
			got, from, err = syscall.Recvfrom(fd, buf, hostMsgFlags(flags)|syscall.MSG_DONTWAIT)
		} else {
			hostCallTurn.Lock()
			if hostReadyNow(fd, hostPollIn) != 0 {
				got, err = syscall.Read(fd, buf)
			} else if mode, ferr := descriptorFlags(fd, syscall.F_GETFL); ferr == nil && mode&syscall.O_NONBLOCK != 0 {
				// In non-blocking mode the read does not wait, and says
				// itself what is there: nothing, or the end of input where
				// the host does not report that as something to read (a
				// FIFO nobody has opened for writing since).
				got, err = syscall.Read(fd, buf)
			} else {
				got, err = 0, syscall.EAGAIN
			}
			hostCallTurn.Unlock()
		}
		if err != syscall.EINTR {
			break
		}
	}
	if err == syscall.EAGAIN {
		return 0, nil, true, _wasiESUCCESS
	}
	if err != nil {
		return 0, nil, false, mapOSError(err)
	}
	if got < 0 {
		got = 0
	}
	if whole {
		return uint64(got), from, false, _wasiESUCCESS
	}
	return scatter(bufs, buf[:got]), from, false, _wasiESUCCESS
}

// receiveHost is one read or receive of the guest's on a descriptor of the
// host that can wait, with the flags of a receive (wasiMsg...). A descriptor
// in non-blocking mode, or a receive that does not wait, reports EAGAIN when
// nothing is there. Otherwise the call waits — no longer than the socket's
// receive timeout — and a signal posted to the guest meanwhile ends it with
// EINTR.
func (w *WasiStubs) receiveHost(h *hostFile, bufs [][]byte, flags int32) (uint64, syscall.Sockaddr, int32) {
	var total uint64
	var until time.Time
	for {
		n, from, again, errno := h.receiveNow(bufs, flags)
		if errno != _wasiESUCCESS {
			if total > 0 {
				return total, from, _wasiESUCCESS
			}
			return 0, nil, errno
		}
		if !again {
			total += n
			if flags&wasiMsgWaitAll == 0 || flags&wasiMsgPeek != 0 || n == 0 {
				return total, from, _wasiESUCCESS
			}
			// Drop what is filled; go on when room is left.
			for len(bufs) > 0 && n >= uint64(len(bufs[0])) {
				n -= uint64(len(bufs[0]))
				bufs = bufs[1:]
			}
			if len(bufs) == 0 {
				return total, from, _wasiESUCCESS
			}
			bufs[0] = bufs[0][n:]
			continue
		}
		if flags&wasiMsgDontWait != 0 || h.nonblocking() {
			if total > 0 {
				return total, nil, _wasiESUCCESS
			}
			return 0, nil, _wasiEAGAIN
		}
		fd, err := h.hold()
		if err != nil {
			return total, nil, _wasiEBADF
		}
		if until.IsZero() && h.socket() {
			if limit := hostSocketTimeout(fd, syscall.SO_RCVTIMEO); limit > 0 {
				until = time.Now().Add(limit)
			}
		}
		h.release()
		wait := [1]hostPoll{{fd: int32(fd), events: hostPollIn}}
		if errno := w.awaitHost(wait[:], until); errno != _wasiESUCCESS {
			if total > 0 {
				return total, nil, _wasiESUCCESS
			}
			return 0, nil, errno
		}
	}
}

// readHost is fd_read for an entry that is a descriptor of the host.
func (w *WasiStubs) readHost(h *hostFile, bufs [][]byte) (uint64, int32) {
	if !h.waits() {
		n, err := readVecFailure(h, bufs)
		if n == 0 && err != nil && !errors.Is(err, io.EOF) {
			return 0, mapOSError(err)
		}
		return n, _wasiESUCCESS
	}
	n, _, errno := w.receiveHost(h, bufs, 0)
	return n, errno
}

// hostWriteChunk is how much is written at a time to a pipe or terminal in
// blocking mode: what the host takes without waiting once it reports the
// descriptor writable (PIPE_BUF).
const hostWriteChunk = hostPipeBuf

// sendNow writes or sends p to the descriptor without waiting, at address
// to when there is one. again reports that the descriptor takes nothing
// right now; otherwise n bytes were taken, or err says why not. blocking
// says that the open file is in blocking mode, where a write of more than
// the host takes at once would wait.
func (h *hostFile) sendNow(p []byte, to syscall.Sockaddr, blocking bool) (n int, again bool, err error) {
	fd, err := h.hold()
	if err != nil {
		return 0, false, err
	}
	defer h.release()
	for {
		if h.socket() {
			n, err = syscall.SendmsgN(fd, p, nil, to, hostSendFlags)
		} else if !blocking {
			// In non-blocking mode the write does not wait, and takes
			// what the host has room for.
			n, err = syscall.Write(fd, p)
		} else {
			hostCallTurn.Lock()
			if hostReadyNow(fd, hostPollOut) == 0 {
				hostCallTurn.Unlock()
				return 0, true, nil
			}
			chunk := p
			if len(chunk) > hostWriteChunk {
				chunk = chunk[:hostWriteChunk]
			}
			n, err = syscall.Write(fd, chunk)
			hostCallTurn.Unlock()
		}
		if err != syscall.EINTR {
			break
		}
	}
	if n < 0 {
		n = 0
	}
	if err == syscall.EAGAIN {
		return 0, true, nil
	}
	return n, false, err
}

// sendHost is one write or send of the guest's on a descriptor of the host
// that can wait, with the flags of a send (wasiMsg...), to the address to
// when there is one. A descriptor in non-blocking mode, or a send that does
// not wait, takes what there is room for right now and reports EAGAIN when
// that is nothing. Otherwise the call waits until everything is written —
// for room no longer than the socket's send timeout; a signal posted to the
// guest meanwhile ends the wait, with EINTR when nothing was written yet
// and the count otherwise.
func (w *WasiStubs) sendHost(op *wasiOpen, h *hostFile, bufs [][]byte, to syscall.Sockaddr, flags int32) (uint64, int32) {
	if op.dgram && len(bufs) != 1 {
		// One write is one datagram, however many pieces it comes in.
		var whole []byte
		for _, buf := range bufs {
			whole = append(whole, buf...)
		}
		bufs = [][]byte{whole}
	}
	nonblocking := flags&wasiMsgDontWait != 0 || h.nonblocking()
	var total uint64
	var until time.Time
	for i := 0; i < len(bufs); {
		buf := bufs[i]
		if len(buf) == 0 && !op.dgram {
			i++
			continue
		}
		n, again, err := h.sendNow(buf, to, !nonblocking)
		if err != nil {
			if total > 0 {
				return total, _wasiESUCCESS
			}
			return 0, w.writeFailure(err, flags)
		}
		total += uint64(n)
		if !again {
			if bufs[i] = buf[n:]; len(bufs[i]) == 0 || op.dgram {
				i++
			}
			continue
		}
		if nonblocking {
			if total > 0 {
				return total, _wasiESUCCESS
			}
			return 0, _wasiEAGAIN
		}
		fd, err := h.hold()
		if err != nil {
			return total, _wasiEBADF
		}
		if until.IsZero() && h.socket() {
			if limit := hostSocketTimeout(fd, syscall.SO_SNDTIMEO); limit > 0 {
				until = time.Now().Add(limit)
			}
		}
		h.release()
		wait := [1]hostPoll{{fd: int32(fd), events: hostPollOut}}
		if errno := w.awaitHost(wait[:], until); errno != _wasiESUCCESS {
			if total > 0 {
				return total, _wasiESUCCESS
			}
			return 0, errno
		}
	}
	return total, _wasiESUCCESS
}

// writeHost is fd_write for an entry that is a descriptor of the host.
func (w *WasiStubs) writeHost(op *wasiOpen, h *hostFile, bufs [][]byte) (uint64, int32) {
	if !h.waits() {
		n, err := writeVec(h, bufs)
		if n == 0 && err != nil {
			return 0, w.writeFailure(err, 0)
		}
		return n, _wasiESUCCESS
	}
	return w.sendHost(op, h, bufs, nil, 0)
}

// hostSocketTimeout returns a socket's receive or send timeout (option is
// SO_RCVTIMEO or SO_SNDTIMEO); 0 is no limit.
func hostSocketTimeout(fd int, option int) time.Duration {
	var tv syscall.Timeval
	size := uint32(unsafe.Sizeof(tv))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, uintptr(option),
		uintptr(unsafe.Pointer(&tv)), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
		return 0
	}
	return time.Duration(tv.Nano())
}

// hostPending returns how many bytes can be read from the descriptor right
// now, as far as the host tells (FIONREAD).
func (h *hostFile) pending() uint64 {
	fd, err := h.hold()
	if err != nil {
		return 0
	}
	defer h.release()
	var n int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), hostFIONREAD, uintptr(unsafe.Pointer(&n))); errno != 0 || n < 0 {
		return 0
	}
	return uint64(n)
}

// hostEvents are the events of poll(2) that make a descriptor ready for
// reading and for writing, as poll_oneoff reports it: a descriptor that
// was hung up on, or is in error, is ready for the call that finds out.
const (
	hostReadable = hostPollIn | hostPollPri | hostPollHup | hostPollErr | hostPollNval
	hostWritable = hostPollOut | hostPollHup | hostPollErr | hostPollNval
)

// hostPollEvents returns the poll(2) request for a subscription of
// poll_oneoff and tells from the answer whether the descriptor is ready.
func hostPollRequest(read bool) int16 {
	if read {
		return hostPollIn | hostPollPri
	}
	return hostPollOut
}

func hostPollReady(read bool, revents int16) bool {
	if read {
		return revents&hostReadable != 0
	}
	return revents&hostWritable != 0
}

// hostPollStoppable is poll(2) on fds that ends when stop is closed, too:
// for a poll_oneoff that waits for descriptors of the host together with
// streams of the embedder's, which are waited for on goroutines.
func hostPollStoppable(fds []hostPoll, until time.Time, stop <-chan struct{}) {
	if stop == nil {
		hostPollUntil(fds, until)
		return
	}
	var p [2]int
	syscall.ForkLock.RLock()
	err := syscall.Pipe(p[:])
	if err == nil {
		syscall.CloseOnExec(p[0])
		syscall.CloseOnExec(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-stop:
			_, _ = syscall.Write(p[1], []byte{0})
		case <-done:
		}
	}()
	set := make([]hostPoll, len(fds)+1)
	copy(set, fds)
	set[len(fds)] = hostPoll{fd: int32(p[0]), events: hostPollIn}
	hostPollUntil(set, until)
	copy(fds, set)
	close(done)
	<-stopped
	_ = syscall.Close(p[0])
	_ = syscall.Close(p[1])
}

// hostChildFile returns the descriptor as a file package os/exec can hand
// to a command: a duplicate, which the caller closes once the command has
// started.
func (h *hostFile) childFile() *os.File {
	fd, err := h.hold()
	if err != nil {
		return nil
	}
	defer h.release()
	dup, err := hostDup(fd, hostFloor())
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(dup), h.path)
}

// OpenDescriptor opens a file of the host filesystem as a descriptor of the
// host process, the way OpenFile opens one as a file of package os: flag
// and perm are open(2)'s, and a file the call creates gets exactly perm.
// The file it returns is nothing but the descriptor: every operation on it
// is the host's on that number, and the descriptor is in the mode the flags
// ask for. It is what a guest whose descriptors are the host process's
// (SetHostProcess) opens its files through; a backend that wraps this one
// passes the method on for the files that are this backend's, and reports
// errors.ErrUnsupported for a name it serves itself.
func (o osFS) OpenDescriptor(name string, flag int, perm os.FileMode) (File, error) {
	path := o.join(name)
	mode := unixModeBits(perm)
	open := func(flag int) (int, error) {
		for {
			fd, err := syscall.Open(path, flag|syscall.O_CLOEXEC, mode)
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				return -1, &os.PathError{Op: "open", Path: path, Err: err}
			}
			return fd, nil
		}
	}
	made := func(fd int) (File, error) {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			_ = syscall.Close(fd)
			return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
		}
		return newHostFile(fd, uint32(st.Mode), path), nil
	}
	if flag&os.O_CREATE != 0 && perm&processUmask != 0 {
		// See osFS.OpenFile.
		for i := 0; i < osCreateAttempts; i++ {
			fd, err := open(flag | os.O_EXCL)
			if err == nil {
				if err := syscall.Fchmod(fd, mode); err != nil {
					_ = syscall.Close(fd)
					return nil, &os.PathError{Op: "fchmod", Path: path, Err: err}
				}
				return made(fd)
			}
			if flag&os.O_EXCL != 0 || !errors.Is(err, syscall.EEXIST) {
				return nil, err
			}
			fd, err = open(flag &^ os.O_CREATE)
			if err == nil {
				return made(fd)
			}
			if !errors.Is(err, syscall.ENOENT) {
				return nil, err
			}
		}
	}
	fd, err := open(flag)
	if err != nil {
		return nil, err
	}
	return made(fd)
}

// flockHost applies flock(2) to a descriptor of the host, without waiting.
func (h *hostFile) flock(lock FileLock) error {
	fd, err := h.hold()
	if err != nil {
		return err
	}
	defer h.release()
	how := syscall.LOCK_UN
	switch lock {
	case FileLockShared:
		how = syscall.LOCK_SH | syscall.LOCK_NB
	case FileLockExclusive:
		how = syscall.LOCK_EX | syscall.LOCK_NB
	}
	for {
		err := syscall.Flock(fd, how)
		if err != syscall.EINTR {
			return err
		}
	}
}

// hostPipe makes a pipe of the host and returns the entries of its two
// ends.
func hostPipe() (r, wr *wasiOpen, err error) {
	var p [2]int
	syscall.ForkLock.RLock()
	err = syscall.Pipe(p[:])
	if err == nil {
		syscall.CloseOnExec(p[0])
		syscall.CloseOnExec(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	r = &wasiOpen{f: newHostFile(p[0], syscall.S_IFIFO, ""), noWrite: true}
	wr = &wasiOpen{f: newHostFile(p[1], syscall.S_IFIFO, ""), noRead: true}
	return r, wr, nil
}
