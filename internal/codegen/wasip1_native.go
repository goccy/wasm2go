// Package codegen — wasip1_native.go owns the default wasi_snapshot_preview1
// host implementation that gets woven into the translated output.
//
// Design notes:
//
//   - The struct WasiStubs holds all the runtime-side state (fd table, args,
//     env, monotonic start) so the wasm runtime's Module type stays free of
//     host-specific fields.
//   - DefaultWASI() returns *WasiStubs wired to os.Stdin/Stdout/Stderr,
//     os.Args, os.Environ() and time.Now() — drop-in replacement for the
//     wazero wasi_snapshot_preview1 interceptor.
//   - Memory access uses m.memory (lowercase) at template time. In
//     multi-package mode, capitalizeModuleFieldRefs rewrites it to
//     m.Memory so the impl works in base/ too.
//   - Method signatures must match what t.importMethodName produces from
//     the wasm import names. We use the same MangleID + capitalize chain
//     by emitting the exact wasi function names ("Environ_get" etc).
//   - Bodies favour clarity over micro-optimisation.
//
// Security model: WasiStubs is a faithful Go-syscall passthrough for the
// translated module. There is no sandbox, no path-traversal refuse logic,
// and no allow-list — the translated module has the same filesystem,
// clock, environment, and stdio access as the host Go process that links
// it in. Out-of-range linear-memory accesses are reported back to the
// guest as EFAULT (rather than being allowed to panic the host) because
// wasm itself traps on OOB; that's the only "refusal" the stubs perform.
// Callers that need a tighter sandbox should pass their own
// Wasi_snapshot_preview1Imports implementation via NewWithWASI.
//
// File layout: this file is real, compilable Go and is also //go:embed-ed
// so the same code that the codegen test suite exercises is the code that
// gets written into generated output. Everything goes through the Go
// stdlib (os, time, syscall, net), so no third-party dependencies are
// needed. The few operations the stdlib only offers per platform — reading
// the owner, link count and times out of a stat result, flock, the process
// umask — live in the wasip1_native_<platform>.go companions, which are
// emitted next to the generated output with their build constraints.
package codegen

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Module is the minimal in-package proxy for the generated module type.
// In production, codegen emits a separate Module struct into the user's
// output package; this in-package Module exists so the WasiStubs methods
// below are real, compilable Go (and therefore directly testable). The
// embedded-source path strips the package + import header at emit time
// and lets the generated Module shadow this one. It has the generated
// Module's fields the stubs read: the memory slice and memSize, the size
// the guest sees (see guestMemory).
type Module struct {
	memory  []byte
	memSize *atomic.Uint64
}

// accessMemory is the in-package stand-in for the runtime helper of the same
// name, which runs f over the module's memory under the lock memory.grow
// takes. The generated output has the real one; this one is not emitted.
func accessMemory(m *Module, f func(mem []byte)) { f(m.memory) }

// WasiExitError is the sentinel that the recover layer of SafeInvokeExport
// promotes Proc_exit() panics into, so a wasm-level exit doesn't kill the
// host process and the caller can read the exit code instead.
type WasiExitError struct{ Code int32 }

func (e *WasiExitError) Error() string {
	return "wasi: proc_exit(" + itoa32(e.Code) + ")"
}

// itoa32 is a tiny dependency-free strconv replacement so this file
// doesn't drag in fmt for its sole error path.
func itoa32(v int32) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		v = -v
		neg = true
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// FS is the read/write filesystem backend the WASI host opens files through.
// It abstracts the default os-backed filesystem so an embedder can supply an
// alternative — an in-memory FS, an overlay, a read-only bundle, ... — and
// have every guest path operation (open, stat, mkdir, readdir, write, ...)
// routed to it. It is a write-capable superset of io/fs.FS.
//
// Names are GUEST paths relative to the preopen root: slash-separated, with no
// leading slash (e.g. "encodings/__init__.py", or "" for the root). Methods
// should return the standard fs errors (fs.ErrNotExist, fs.ErrExist,
// fs.ErrPermission) so the host maps them to the right wasi errno.
type FS interface {
	// OpenFile mirrors os.OpenFile: flag is O_RDONLY/O_WRONLY/O_RDWR optionally
	// OR'd with O_CREATE/O_EXCL/O_TRUNC/O_APPEND. The returned File must
	// support the operations the mode implies. perm is the mode a file this
	// call creates ends up with: the guest's umask is already applied to it,
	// so a backend on a real filesystem must not let its own process umask
	// narrow it further.
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	// Mkdir creates a directory whose mode is perm, exactly as for OpenFile.
	Mkdir(name string, perm os.FileMode) error
	// Chmod sets the permission bits of name, and its setuid, setgid and
	// sticky bits from the corresponding os.FileMode flags.
	Chmod(name string, mode os.FileMode) error
	// Chtimes sets the access and modification times of name.
	Chtimes(name string, atime, mtime time.Time) error
	// Flock applies or releases an advisory lock on f, a file this FS
	// opened, with the semantics of flock(2): the lock belongs to the open
	// file, so everything that shares f shares the lock, while another open
	// of the same file — by anyone — competes for it. A shared lock excludes
	// exclusive ones; an exclusive lock excludes every other. With wait
	// false, a lock that cannot be granted at once fails with
	// syscall.EAGAIN; with wait true the call blocks until it is granted.
	// Closing f releases the lock.
	Flock(f File, lock FileLock, wait bool) error
	Remove(name string) error
	Rename(oldName, newName string) error
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Symlink(oldName, newName string) error
	Readlink(name string) (string, error)
	Link(oldName, newName string) error
}

// File is an open file handle returned by FS.OpenFile. *os.File satisfies it,
// so the default os backend needs no wrapper.
type File interface {
	Read(p []byte) (int, error)
	ReadAt(p []byte, off int64) (int, error)
	Write(p []byte) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Seek(offset int64, whence int) (int64, error)
	Close() error
	Stat() (os.FileInfo, error)
	ReadDir(n int) ([]os.DirEntry, error)
	Sync() error
	Truncate(size int64) error
	// Chmod sets the mode of the open file, as FS.Chmod does by name.
	Chmod(mode os.FileMode) error
	Name() string
}

// FileLock is the kind of advisory lock FS.Flock applies.
type FileLock int

const (
	// FileUnlock releases the lock held through the open file.
	FileUnlock FileLock = iota
	// FileLockShared is a lock any number of open files can hold together.
	FileLockShared
	// FileLockExclusive is a lock a single open file holds alone.
	FileLockExclusive
)

// fileStat is what POSIX stat reports about a file beyond os.FileInfo. A
// backend's FileInfo carries it as its Sys value: the in-memory backend as a
// *fileStat, a backend on the host filesystem as whatever the os package
// provides, which fileStatOf reads through the platform companion.
type fileStat struct {
	dev, ino, nlink uint64
	uid, gid        uint32
	atime, ctime    time.Time
	// rdev is the device a character or block special file stands for,
	// blksize the preferred block size for I/O on the file (0: the backend
	// names none) and blocks the number of 512-byte blocks allocated to it.
	rdev    uint64
	blksize uint32
	blocks  uint64
}

// fileStatOf returns the POSIX metadata of the file fi describes. A FileInfo
// that carries none describes a file with a single link, owned by uid and gid
// 0, whose three times are its modification time.
func fileStatOf(fi os.FileInfo) fileStat {
	if st, ok := fi.Sys().(*fileStat); ok {
		return *st
	}
	if st, ok := osFileStat(fi.Sys()); ok {
		return st
	}
	return fileStat{nlink: 1, atime: fi.ModTime(), ctime: fi.ModTime()}
}

// unixFileMode converts the permission and setuid/setgid/sticky bits of a
// POSIX mode_t into an os.FileMode.
func unixFileMode(bits uint32) os.FileMode {
	mode := os.FileMode(bits & 0o777)
	if bits&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if bits&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if bits&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// The file type bits of a POSIX mode_t, with the values every Unix gives
// them. They cross to the guest in a filestat_ext record, whose shim turns
// them into its libc's own constants.
const (
	unixTypeMask    uint32 = 0o170000
	unixTypeFIFO    uint32 = 0o010000
	unixTypeChar    uint32 = 0o020000
	unixTypeDir     uint32 = 0o040000
	unixTypeBlock   uint32 = 0o060000
	unixTypeRegular uint32 = 0o100000
	unixTypeSymlink uint32 = 0o120000
	unixTypeSocket  uint32 = 0o140000
)

// unixTypeBits returns the file type bits of the POSIX mode_t of a file
// whose mode is mode. A character device has os.ModeDevice set as well, so
// it is told apart from a block device first.
func unixTypeBits(mode os.FileMode) uint32 {
	switch {
	case mode.IsDir():
		return unixTypeDir
	case mode&os.ModeSymlink != 0:
		return unixTypeSymlink
	case mode&os.ModeNamedPipe != 0:
		return unixTypeFIFO
	case mode&os.ModeSocket != 0:
		return unixTypeSocket
	case mode&os.ModeCharDevice != 0:
		return unixTypeChar
	case mode&os.ModeDevice != 0:
		return unixTypeBlock
	}
	return unixTypeRegular
}

// unixModeBits is the inverse of unixFileMode: the low twelve bits of the
// POSIX mode_t of a file whose mode is mode.
func unixModeBits(mode os.FileMode) uint32 {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

// osFS is the default FS backend: a thin pass-through to the host filesystem,
// scoped to root (the preopen directory). root "" or "/" means no rewriting.
type osFS struct{ root string }

// NewOSFS returns the FS backend of the host filesystem scoped to root: root
// becomes the guest's root directory. An empty root or "/" is the host's own
// root. It is the backend a WasiStubs uses until SetFS replaces it.
func NewOSFS(root string) FS { return osFS{root: root} }

func (o osFS) join(name string) string {
	if o.root == "" || o.root == "/" {
		// "." is the root itself, which the guest's C library names so: a
		// call on "/" is the host's call on "/" (rmdir of it is EBUSY;
		// of "/." it would be EINVAL).
		if name == "." {
			return "/"
		}
		return "/" + name
	}
	return filepath.Join(o.root, name)
}

// osCreateAttempts bounds how often osFS.OpenFile alternates between
// creating a file and opening the one that is in the way.
const osCreateAttempts = 4

func (o osFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	path := o.join(name)
	if flag&os.O_CREATE != 0 && perm&processUmask() != 0 {
		// The process umask would take bits out of perm. A mode can only
		// be put right on a file this call created, and only an exclusive
		// create tells a new file from an existing one.
		for i := 0; i < osCreateAttempts; i++ {
			f, err := os.OpenFile(path, flag|os.O_EXCL, perm)
			if err == nil {
				if err := f.Chmod(perm); err != nil {
					return nil, errors.Join(err, f.Close())
				}
				return f, nil
			}
			if flag&os.O_EXCL != 0 || !errors.Is(err, fs.ErrExist) {
				return nil, err
			}
			f, err = os.OpenFile(path, flag&^os.O_CREATE, perm)
			if err == nil {
				return f, nil
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			// The name exists and yet cannot be opened: the file went away
			// in between, or the name is a symbolic link to nothing.
		}
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (o osFS) Mkdir(name string, perm os.FileMode) error {
	path := o.join(name)
	if err := os.Mkdir(path, perm); err != nil {
		return err
	}
	if perm&processUmask() == 0 {
		return nil
	}
	// Give back the bits the process umask took, keeping what the parent
	// directory passed down (a setgid bit).
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return os.Chmod(path, fi.Mode()|perm)
}
func (o osFS) Chmod(name string, mode os.FileMode) error { return os.Chmod(o.join(name), mode) }
func (o osFS) Flock(f File, lock FileLock, wait bool) error {
	of, ok := f.(*os.File)
	if !ok {
		return syscall.EBADF
	}
	return flockOSFile(of, lock, wait)
}
func (o osFS) Remove(name string) error               { return os.Remove(o.join(name)) }
func (o osFS) Stat(name string) (os.FileInfo, error)  { return os.Stat(o.join(name)) }
func (o osFS) Lstat(name string) (os.FileInfo, error) { return os.Lstat(o.join(name)) }
func (o osFS) Symlink(target, name string) error      { return os.Symlink(target, o.join(name)) }
func (o osFS) Readlink(name string) (string, error)   { return os.Readlink(o.join(name)) }
func (o osFS) Link(a, b string) error                 { return os.Link(o.join(a), o.join(b)) }

// Rename is rename(2): a file renamed onto a directory fails with EISDIR,
// and a directory renamed onto an empty one replaces it. os.Rename refuses
// every rename onto a directory with EEXIST, which no system call does.
func (o osFS) Rename(a, b string) error {
	from, to := o.join(a), o.join(b)
	for {
		err := syscall.Rename(from, to)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
		}
		return nil
	}
}

// MemFS is an in-memory read/write FS. Each value is an independent tree, so
// two interpreters given separate MemFS values cannot observe each other's
// files (full per-interpreter filesystem isolation, no disk). Build one with
// NewMemFS. Safe for concurrent use.
type MemFS struct {
	mu   sync.Mutex
	root *memNode
	// lockReleased wakes the Flock calls waiting for a lock whenever one
	// is released or downgraded. Created by the first waiter; guarded by mu.
	lockReleased *sync.Cond
}

// NewMemFS returns an empty in-memory filesystem with a root directory.
func NewMemFS() *MemFS {
	return &MemFS{root: &memNode{dir: true, mode: os.ModeDir | 0o755, modTime: time.Unix(0, 0), children: map[string]*memNode{}}}
}

// memNode is a file or directory in a MemFS tree.
type memNode struct {
	name     string
	dir      bool
	mode     os.FileMode
	modTime  time.Time
	data     []byte
	children map[string]*memNode
	// unlinked is set once the node has no name in the tree any more (it
	// was removed or replaced), which only its open files can still see:
	// their stat reports a link count of zero.
	unlinked bool
	// locks holds the advisory lock of every open file that has one on
	// this node (see MemFS.Flock).
	locks map[*memFile]FileLock
}

func memSplit(name string) []string {
	name = strings.Trim(name, "/")
	if name == "" {
		return nil
	}
	raw := strings.Split(name, "/")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		switch p {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, p)
		}
	}
	return out
}

// lookup resolves name to a node. Caller holds fsys.mu.
func (fsys *MemFS) lookup(name string) (*memNode, error) {
	n := fsys.root
	for _, part := range memSplit(name) {
		if !n.dir {
			return nil, fs.ErrNotExist
		}
		c, ok := n.children[part]
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = c
	}
	return n, nil
}

// lookupParent resolves the parent dir of name. Caller holds fsys.mu.
func (fsys *MemFS) lookupParent(name string) (*memNode, string, error) {
	parts := memSplit(name)
	if len(parts) == 0 {
		return nil, "", fs.ErrInvalid
	}
	n := fsys.root
	for _, part := range parts[:len(parts)-1] {
		c, ok := n.children[part]
		if !ok || !c.dir {
			return nil, "", fs.ErrNotExist
		}
		n = c
	}
	return n, parts[len(parts)-1], nil
}

func (fsys *MemFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	node, err := fsys.lookup(name)
	if err != nil {
		if flag&os.O_CREATE == 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		parent, base, perr := fsys.lookupParent(name)
		if perr != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: perr}
		}
		node = &memNode{name: base, mode: perm & 0o777, modTime: time.Now()}
		parent.children[base] = node
	} else {
		if flag&os.O_EXCL != 0 && flag&os.O_CREATE != 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrExist}
		}
		if flag&os.O_TRUNC != 0 && !node.dir {
			node.data = node.data[:0]
			node.modTime = time.Now()
		}
	}
	f := &memFile{fsys: fsys, node: node}
	if flag&os.O_APPEND != 0 {
		f.off = int64(len(node.data))
	}
	return f, nil
}

func (fsys *MemFS) Mkdir(name string, perm os.FileMode) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	parent, base, err := fsys.lookupParent(name)
	if err != nil {
		return &fs.PathError{Op: "mkdir", Path: name, Err: err}
	}
	if _, ok := parent.children[base]; ok {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
	}
	parent.children[base] = &memNode{name: base, dir: true, mode: os.ModeDir | (perm & 0o777), modTime: time.Now(), children: map[string]*memNode{}}
	return nil
}

func (fsys *MemFS) Remove(name string) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	parent, base, err := fsys.lookupParent(name)
	if err != nil {
		return &fs.PathError{Op: "remove", Path: name, Err: err}
	}
	n, ok := parent.children[base]
	if !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	if n.dir && len(n.children) > 0 {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	delete(parent.children, base)
	n.unlinked = true
	return nil
}

func (fsys *MemFS) Rename(oldName, newName string) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	op, ob, err := fsys.lookupParent(oldName)
	if err != nil {
		return &fs.PathError{Op: "rename", Path: oldName, Err: err}
	}
	node, ok := op.children[ob]
	if !ok {
		return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
	}
	np, nb, err := fsys.lookupParent(newName)
	if err != nil {
		return &fs.PathError{Op: "rename", Path: newName, Err: err}
	}
	delete(op.children, ob)
	node.name = nb
	if replaced, ok := np.children[nb]; ok && replaced != node {
		replaced.unlinked = true
	}
	np.children[nb] = node
	return nil
}

func (fsys *MemFS) Stat(name string) (os.FileInfo, error) {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n, err := fsys.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return n.info(), nil
}

func (fsys *MemFS) Lstat(name string) (os.FileInfo, error) { return fsys.Stat(name) }

// memfs has no symlinks/hardlinks.
func (fsys *MemFS) Symlink(_, _ string) error { return fs.ErrPermission }
func (fsys *MemFS) Link(_, _ string) error    { return fs.ErrPermission }
func (fsys *MemFS) Readlink(name string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
}

// Chmod sets the permission bits of name; a MemFS keeps no other mode bits.
func (fsys *MemFS) Chmod(name string, mode os.FileMode) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n, err := fsys.lookup(name)
	if err != nil {
		return &fs.PathError{Op: "chmod", Path: name, Err: err}
	}
	n.mode = n.mode&^0o777 | mode&0o777
	return nil
}

// Flock implements FS.Flock for the files of this MemFS.
func (fsys *MemFS) Flock(f File, lock FileLock, wait bool) error {
	mf, ok := f.(*memFile)
	if !ok || mf.fsys != fsys {
		return syscall.EBADF
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	node := mf.node
	if lock == FileUnlock {
		mf.unlockLocked()
		return nil
	}
	for node.lockConflicts(mf, lock) {
		if !wait {
			return syscall.EAGAIN
		}
		if fsys.lockReleased == nil {
			fsys.lockReleased = sync.NewCond(&fsys.mu)
		}
		fsys.lockReleased.Wait()
	}
	if node.locks == nil {
		node.locks = map[*memFile]FileLock{}
	}
	downgraded := node.locks[mf] == FileLockExclusive && lock == FileLockShared
	node.locks[mf] = lock
	if downgraded && fsys.lockReleased != nil {
		fsys.lockReleased.Broadcast()
	}
	return nil
}

// lockConflicts reports whether an open file other than f holds a lock on n
// that rules out f taking lock. Caller holds the MemFS lock.
func (n *memNode) lockConflicts(f *memFile, lock FileLock) bool {
	for holder, held := range n.locks {
		if holder != f && (lock == FileLockExclusive || held == FileLockExclusive) {
			return true
		}
	}
	return false
}

// unlockLocked releases the lock f holds, if any, and wakes the waiters.
// Caller holds the MemFS lock.
func (f *memFile) unlockLocked() {
	if _, held := f.node.locks[f]; !held {
		return
	}
	delete(f.node.locks, f)
	if f.fsys.lockReleased != nil {
		f.fsys.lockReleased.Broadcast()
	}
}

// Chtimes sets the modification time of name, the only time a MemFS keeps.
func (fsys *MemFS) Chtimes(name string, _ time.Time, mtime time.Time) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n, err := fsys.lookup(name)
	if err != nil {
		return &fs.PathError{Op: "chtimes", Path: name, Err: err}
	}
	n.modTime = mtime
	return nil
}

// MkdirAll creates name and any missing parents. Exposed so embedders can
// populate the FS (e.g. unpack a stdlib bundle) before handing it to a module.
func (fsys *MemFS) MkdirAll(name string, perm os.FileMode) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n := fsys.root
	for _, part := range memSplit(name) {
		c, ok := n.children[part]
		if !ok {
			c = &memNode{name: part, dir: true, mode: os.ModeDir | (perm & 0o777), modTime: time.Now(), children: map[string]*memNode{}}
			n.children[part] = c
		} else if !c.dir {
			return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
		}
		n = c
	}
	return nil
}

// WriteFile creates (or overwrites) a file with data, making parent dirs as
// needed. Exposed for pre-populating the FS.
func (fsys *MemFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	if parts := memSplit(name); len(parts) > 1 {
		if err := fsys.MkdirAll(strings.Join(parts[:len(parts)-1], "/"), 0o755); err != nil {
			return err
		}
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	parent, base, err := fsys.lookupParent(name)
	if err != nil {
		return &fs.PathError{Op: "writefile", Path: name, Err: err}
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	if replaced, ok := parent.children[base]; ok {
		replaced.unlinked = true
	}
	parent.children[base] = &memNode{name: base, mode: perm & 0o777, modTime: time.Now(), data: cp}
	return nil
}

func (n *memNode) info() os.FileInfo {
	fi := memFileInfo{name: n.name, size: int64(len(n.data)), mode: n.mode & 0o777, modTime: n.modTime, unlinked: n.unlinked}
	if n.dir {
		fi.size = 0
		fi.mode |= os.ModeDir
	}
	return fi
}

type memFileInfo struct {
	name     string
	size     int64
	mode     os.FileMode
	modTime  time.Time
	unlinked bool
}

func (fi memFileInfo) Name() string       { return fi.name }
func (fi memFileInfo) Size() int64        { return fi.size }
func (fi memFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi memFileInfo) ModTime() time.Time { return fi.modTime }
func (fi memFileInfo) IsDir() bool        { return fi.mode.IsDir() }

// Sys reports the file's POSIX metadata: a MemFS has no hard links, so a
// file has one link until it is removed, and it keeps no owner and no times
// other than the modification time.
func (fi memFileInfo) Sys() any {
	st := &fileStat{nlink: 1, atime: fi.modTime, ctime: fi.modTime,
		blksize: memBlockSize, blocks: uint64(fi.size+511) / 512}
	if fi.unlinked {
		st.nlink = 0
	}
	return st
}

// memBlockSize is the block size an in-memory file reports for I/O.
const memBlockSize = 4096

type memDirEntry struct{ n *memNode }

func (e memDirEntry) Name() string { return e.n.name }
func (e memDirEntry) IsDir() bool  { return e.n.dir }
func (e memDirEntry) Type() os.FileMode {
	if e.n.dir {
		return os.ModeDir
	}
	return 0
}
func (e memDirEntry) Info() (os.FileInfo, error) { return e.n.info(), nil }

// memFile is an open handle into a MemFS node.
type memFile struct {
	fsys   *MemFS
	node   *memNode
	off    int64
	dirOff int
}

func (f *memFile) Name() string { return f.node.name }
func (f *memFile) Sync() error  { return nil }

// Close releases the lock the file holds, if any.
func (f *memFile) Close() error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.unlockLocked()
	return nil
}

// Chmod sets the permission bits of the open file.
func (f *memFile) Chmod(mode os.FileMode) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.node.mode = f.node.mode&^0o777 | mode&0o777
	return nil
}

func (f *memFile) Stat() (os.FileInfo, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return f.node.info(), nil
}

func (f *memFile) Read(p []byte) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.node.dir {
		return 0, &fs.PathError{Op: "read", Path: f.node.name, Err: fs.ErrInvalid}
	}
	if f.off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// writeAt grows node.data as needed and writes p at off. Caller holds the lock.
func (f *memFile) writeAt(p []byte, off int64) int {
	end := off + int64(len(p))
	if end > int64(len(f.node.data)) {
		grown := make([]byte, end)
		copy(grown, f.node.data)
		f.node.data = grown
	}
	copy(f.node.data[off:], p)
	f.node.modTime = time.Now()
	return len(p)
}

func (f *memFile) Write(p []byte) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	n := f.writeAt(p, f.off)
	f.off += int64(n)
	return n, nil
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return f.writeAt(p, off), nil
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	switch whence {
	case io.SeekStart:
		f.off = offset
	case io.SeekCurrent:
		f.off += offset
	case io.SeekEnd:
		f.off = int64(len(f.node.data)) + offset
	}
	return f.off, nil
}

func (f *memFile) Truncate(size int64) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if size <= int64(len(f.node.data)) {
		f.node.data = f.node.data[:size]
	} else {
		grown := make([]byte, size)
		copy(grown, f.node.data)
		f.node.data = grown
	}
	f.node.modTime = time.Now()
	return nil
}

func (f *memFile) ReadDir(n int) ([]os.DirEntry, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if !f.node.dir {
		return nil, &fs.PathError{Op: "readdir", Path: f.node.name, Err: fs.ErrInvalid}
	}
	names := make([]string, 0, len(f.node.children))
	for name := range f.node.children {
		names = append(names, name)
	}
	sort.Strings(names)
	if f.dirOff >= len(names) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	end := len(names)
	if n > 0 && f.dirOff+n < end {
		end = f.dirOff + n
	}
	out := make([]os.DirEntry, 0, end-f.dirOff)
	for _, name := range names[f.dirOff:end] {
		out = append(out, memDirEntry{f.node.children[name]})
	}
	f.dirOff = end
	return out, nil
}

// wasiOpen is one entry in WasiStubs' fd table. An entry for a standard
// stream carries no file: its stdio field names which of the WasiStubs
// streams it reads or writes. The conn arm carries a net.Conn for sockets
// opened via Sock_accept.
//
// An entry can be referenced from several table slots (dup/dup2) and, after
// Fork, from the tables of several WasiStubs that each have their own lock.
// The fields that change after the entry is created (conn, fdflags, dirCache,
// refs) are therefore guarded by the entry's own mu; the others are immutable.
// mu is a leaf lock: it may be taken while a WasiStubs.mu is held, never the
// other way round, and it is never held across blocking I/O.
type wasiOpen struct {
	mu       sync.Mutex
	f        File
	conn     net.Conn     // guarded by mu; read it through netConn
	listener net.Listener // guarded by mu; read it through netListener
	isDir    bool
	isSocket bool // created by Sock_socket, may not yet have a conn
	// noRead and noWrite record the access mode the descriptor was opened
	// with: a file opened for writing only cannot be read, the read end of
	// a pipe cannot be written. Both false is a descriptor open both ways
	// (a socket). They say nothing for a standard stream (stdio != 0),
	// whose direction is its own; see access. Immutable.
	noRead, noWrite bool
	// dgram marks a datagram socket (UDP), as Sock_socket was asked for
	// one: it decides how the socket binds, connects, sends and receives
	// from before it has anything to tell by. Immutable.
	dgram bool
	// family is the address family of a socket (wasiSockFamily*), as it
	// was made: it decides what the socket binds and connects to from
	// before it has an address to tell by. 0 for an entry that is no
	// socket, and for a connection or listener the embedder handed in (see
	// socketFamily). Immutable.
	family   int32
	path     string        // guest path relative to the preopen root
	fdflags  int32         // last fdflags set via Path_open or Fd_fdstat_set_flags; guarded by mu
	dirCache []os.DirEntry // guarded by mu
	// stdio marks an entry that refers to a standard stream of the
	// instance (1/2/3 = the configured stdin/stdout/stderr; 0 = not one).
	// The stream is looked up on every use, so SetStdin/SetStdout/SetStderr
	// take effect for the entry and all its dups. Fds 0/1/2 start out with
	// such entries; closing one never touches the stream itself.
	stdio int8
	// refs counts EXTRA table slots sharing this entry (dup/dup2 in one
	// instance, plus every slot of a forked instance): closeWasiOpen only
	// closes the descriptor when it reaches zero. Guarded by mu.
	refs int32
	// ahead is input a readiness probe took out of the stream: the only
	// portable way to learn that a pipe or socket is readable is to read
	// it (see pollReady). Reads of this descriptor drain ahead before
	// they touch the stream. aheadEnd is the end of input a probe ran into
	// (io.EOF or a read failure), reported once ahead is drained. Both
	// guarded by mu.
	ahead    []byte
	aheadEnd error
	// turn is the turn at this descriptor's input and outTurn the turn at
	// its output; see inputTurn. Made on first use; guarded by mu.
	turn    chan struct{}
	outTurn chan struct{}
	// sock is the state of a socket beyond its connection or listener;
	// see wasiSocket. Guarded by mu; use it through socketLocked.
	sock *wasiSocket
	// blocks caches whether f is a stream, whose reads and writes can block
	// (see fileIsStream): 0 not determined yet, 1 it is, 2 it is not.
	// Finding out takes a system call, and every read and write needs to
	// know. Guarded by mu.
	blocks int8
}

// deadlineReader is a stream whose blocking read can be bounded: a pipe, a
// socket, a terminal. Regular files are not (they never block), and say so
// by refusing the deadline.
type deadlineReader interface {
	Read(p []byte) (int, error)
	SetReadDeadline(t time.Time) error
}

// pollProbeGrace bounds a probe that must not wait: long enough for the
// read to be attempted, which is all a "what is ready right now" poll needs.
const pollProbeGrace = 200 * time.Microsecond

// takeAhead serves a read from the input a readiness probe already took. ok
// is false when there is none and the read must go to the stream.
func (op *wasiOpen) takeAhead(bufs [][]byte) (n uint64, ok bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if len(op.ahead) == 0 {
		// A probe that hit end of input leaves a zero-byte read behind.
		return 0, op.aheadEnd != nil
	}
	for _, buf := range bufs {
		c := copy(buf, op.ahead)
		op.ahead = op.ahead[c:]
		n += uint64(c)
		if len(op.ahead) == 0 {
			op.ahead = nil
			break
		}
	}
	return n, true
}

// aheadReady reports whether a read would return without blocking because
// of probed input, and how many bytes are waiting.
func (op *wasiOpen) aheadReady() (ready bool, pending int) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return len(op.ahead) > 0 || op.aheadEnd != nil, len(op.ahead)
}

// inputTurn returns the channel that holds the turn at this descriptor's
// input: whoever has put a value in it has the turn, and gives it back by
// taking the value out (takeInputTurn, passInputTurn).
//
// A descriptor can be shared — by the slots of one instance (dup) and by the
// instances of a fork family, each on a goroutine of its own. Reading a
// stream, accepting from a listener and receiving a datagram all wait inside
// a call of the host's that admits one caller at a time and queues the
// others where nothing can call them back: a deadline ends the wait of the
// one caller inside, not of the queue, and the caller it ends need not be
// the one it was meant for. A guest queued that way could not be reached by
// a signal.
//
// So the waiting is done in turns. Whoever is about to read, accept or
// receive on a descriptor takes its turn first, in a select that a signal or
// a timeout can end, and only the holder of the turn enters the host's call
// and sets the deadline that bounds it. The turn also keeps what probes
// take off the descriptor (ahead, the accepted connections, the datagram) in
// the order it arrived.
func (op *wasiOpen) inputTurn() chan struct{} {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.turn == nil {
		op.turn = make(chan struct{}, 1)
	}
	return op.turn
}

// outputTurn returns the channel that holds the turn at this descriptor's
// output. Writing to a stream that is full waits inside a call of the host's
// as reading an empty one does, with the same queue behind the one caller
// it admits; writers and the probes that ask whether a write would wait
// therefore take turns the way readers do (inputTurn). The two directions
// have a turn each: a process waiting for input on a socket does not keep
// another from writing to it.
func (op *wasiOpen) outputTurn() chan struct{} {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.outTurn == nil {
		op.outTurn = make(chan struct{}, 1)
	}
	return op.outTurn
}

// takeInputTurn waits for the turn at the descriptor's input and reports
// whether it got it: not when until passed first (the zero time is no
// limit), nor when stop was closed first.
func (op *wasiOpen) takeInputTurn(until time.Time, stop <-chan struct{}) bool {
	return takeTurn(op.inputTurn(), until, stop)
}

// takeOutputTurn is takeInputTurn for the descriptor's output.
func (op *wasiOpen) takeOutputTurn(until time.Time, stop <-chan struct{}) bool {
	return takeTurn(op.outputTurn(), until, stop)
}

// passOutputTurn gives the turn at the descriptor's output back.
func (op *wasiOpen) passOutputTurn() { <-op.outputTurn() }

// takeTurn waits for a turn and reports whether it got it: not when until
// passed first (the zero time is no limit), nor when stop was closed first.
func takeTurn(turn chan struct{}, until time.Time, stop <-chan struct{}) bool {
	select {
	case turn <- struct{}{}:
		return true
	default:
	}
	var expired <-chan time.Time
	if !until.IsZero() {
		timer := time.NewTimer(time.Until(until))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case turn <- struct{}{}:
		return true
	case <-stop:
	case <-expired:
	}
	return false
}

// passInputTurn gives the turn back.
func (op *wasiOpen) passInputTurn() { <-op.inputTurn() }

// probeInput is a readiness probe of the descriptor's input. It waits — no
// longer than until (the zero time is no limit), and not after stop is
// closed — first for the turn and then in attempt, which makes one read,
// accept or receive and keeps what it got on the entry. kept reports whether
// something is kept there, in which case the descriptor is ready.
// setDeadline bounds the host call attempt makes.
//
// Before it waits, the probe looks: look makes the same read, accept or
// receive without waiting and reports whether it could (the host has a way,
// and the descriptor is one that can be asked). What is there right now is
// found that way whatever time the probe has — a deadline cannot say it: one
// that has passed by the time the host's call is entered ends the call
// before it has asked, and a probe that may not wait would report input that
// is there as missing whenever it was not scheduled in time. A probe with no
// more time than pollProbeGrace was only to look, and does not wait once it
// has.
//
// refused is true when the stream takes no deadline: nothing was attempted
// then, and the caller decides what an unbounded read is worth to it.
func (op *wasiOpen) probeInput(setDeadline func(time.Time) error, until time.Time, stop <-chan struct{}, kept func() bool, look func() bool, attempt func()) (ready, refused bool) {
	if kept() {
		return true, false
	}
	if !op.takeInputTurn(until, stop) {
		return kept(), false
	}
	defer op.passInputTurn()
	// Whoever had the turn before may have found something.
	if kept() {
		return true, false
	}
	if look() {
		if kept() {
			return true, false
		}
		if !until.IsZero() && time.Until(until) <= pollProbeGrace {
			return false, false
		}
	}
	if err := setDeadline(until); err != nil {
		return false, true
	}
	if stop == nil {
		attempt()
	} else {
		// stop ends the attempt in progress. The goroutine is gone before
		// the deadline is cleared below, so no deadline is left behind.
		attempted, watched := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(watched)
			select {
			case <-stop:
				_ = setDeadline(time.Now())
			case <-attempted:
			}
		}()
		attempt()
		close(attempted)
		<-watched
	}
	_ = setDeadline(time.Time{})
	return kept(), false
}

// probeRead reads src once, as probeInput describes, and keeps what arrives
// in ahead. It reports whether the descriptor is now readable.
func (op *wasiOpen) probeRead(src deadlineReader, until time.Time, stop <-chan struct{}) (ready, refused bool) {
	kept := func() bool {
		ready, _ := op.aheadReady()
		return ready
	}
	look := func() bool {
		buf := make([]byte, 32<<10)
		n, again, err, looked := readNow(src, buf)
		if !looked || again {
			return looked
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		op.ahead = append(op.ahead, buf[:n]...)
		switch {
		case err != nil:
			op.aheadEnd = os.NewSyscallError("read", err)
		case n == 0:
			op.aheadEnd = io.EOF
		}
		return true
	}
	return op.probeInput(src.SetReadDeadline, until, stop, kept, look, func() {
		buf := make([]byte, 32<<10)
		n, err := src.Read(buf)
		op.mu.Lock()
		defer op.mu.Unlock()
		op.ahead = append(op.ahead, buf[:n]...)
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			op.aheadEnd = err
		}
	})
}

// hostDescriptor runs use on the descriptor of the host behind stream — a
// file, connection or listener of the host's — and reports whether it did:
// not when stream is no such thing, or is closed.
func hostDescriptor(stream any, use func(fd uintptr)) bool {
	conn, ok := stream.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	return rc.Control(use) == nil
}

// readNow reads from src once without waiting. looked is false when that
// cannot be done: the host has no way (hostInputNow), or src is not a
// descriptor of the host's that returns from a read with nothing to read.
// Otherwise again says that nothing is there right now, and n and err are
// the read's: no bytes and no error is the end of input.
func readNow(src any, p []byte) (n int, again bool, err error, looked bool) {
	if !hostInputNow {
		return 0, false, nil, false
	}
	asked := hostDescriptor(src, func(fd uintptr) {
		if descriptorWaits(fd) {
			return
		}
		n, again, err = readRaw(fd, p)
		looked = true
	})
	return n, again, err, asked && looked
}

// readBlocks reports whether a read of src, the stream behind this entry,
// can block waiting for input — a pipe, a socket, a terminal — in which
// case it is a deadlineReader whose deadline bounds the wait. A regular
// file is not such a stream although *os.File has the method: its reads
// return at once, and must never be reported as interrupted.
func (op *wasiOpen) readBlocks(src io.Reader) (deadlineReader, bool) {
	stream, bounded := src.(deadlineReader)
	if !bounded {
		return nil, false
	}
	file, isFile := src.(*os.File)
	if !isFile {
		return stream, true
	}
	return stream, op.fileIsStream(file)
}

// fileIsStream reports whether file, the host file behind this entry, is a
// stream — a pipe, a socket, a terminal — whose reads and writes can block,
// and not a regular file, whose never do.
func (op *wasiOpen) fileIsStream(file *os.File) bool {
	const streamModes = os.ModeNamedPipe | os.ModeSocket | os.ModeCharDevice
	if op.stdio != 0 {
		// The instance stream can be replaced at any time: not cached.
		fi, err := file.Stat()
		return err == nil && fi.Mode()&streamModes != 0
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.blocks == 0 {
		op.blocks = 2
		if fi, err := file.Stat(); err == nil && fi.Mode()&streamModes != 0 {
			op.blocks = 1
		}
	}
	return op.blocks == 1
}

// streamWriter is a stream the host can write to without waiting in the
// write itself, and whose wait for room it can bound: a pipe or a socket
// the runtime polls.
type streamWriter interface {
	SetWriteDeadline(t time.Time) error
	SyscallConn() (syscall.RawConn, error)
}

// writeBlocks is readBlocks for writing: it reports whether a write to dst,
// the stream behind this entry, can block waiting for room, in which case
// dst is a streamWriter. A regular file is not such a stream, and neither is
// anything on a host where the runtime cannot write without waiting.
func (op *wasiOpen) writeBlocks(dst io.Writer) (streamWriter, bool) {
	if !hostStreamWrites {
		return nil, false
	}
	stream, bounded := dst.(streamWriter)
	if !bounded {
		return nil, false
	}
	file, isFile := dst.(*os.File)
	if !isFile {
		return stream, true
	}
	return stream, op.fileIsStream(file)
}

// access reports whether the descriptor is open for reading and for
// writing: what open(2) was asked for, the direction of a pipe end, of a
// standard stream.
func (op *wasiOpen) access() (read, write bool) {
	switch op.stdio {
	case 1:
		return true, false
	case 2, 3:
		return false, true
	}
	return !op.noRead, !op.noWrite
}

// plainFile reports whether the entry is a file or directory of the
// filesystem, as opposed to a stream (a pipe, a terminal, a socket): reads
// and writes of it never wait, and poll reports it ready whatever it is
// open for.
func (op *wasiOpen) plainFile() bool {
	if op.f == nil || op.stdio != 0 {
		return false
	}
	if h := op.host(); h != nil {
		return !h.waits()
	}
	file, isHostFile := op.f.(*os.File)
	return !isHostFile || !op.fileIsStream(file)
}

// netConn returns the connection attached to a socket entry, or nil.
func (op *wasiOpen) netConn() net.Conn {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.conn
}

// addRef records one more table slot referring to op.
func (op *wasiOpen) addRef() {
	op.mu.Lock()
	op.refs++
	op.mu.Unlock()
}

// WasiStubs is the default Go-native implementation of wasi_snapshot_preview1.
// State is owned per-Module via NewWithWASI / DefaultWASI.
type WasiStubs struct {
	mu sync.Mutex

	// stdin/stdout/stderr are the instance's standard streams, which guest
	// fds 0/1/2 refer to until the guest closes or replaces them (see
	// fdsLocked). They default to the host
	// os.Std* (DefaultWASI) but can be redirected to any io.Reader/io.Writer
	// (an in-process buffer, pipe, ...) via SetStdin/SetStdout/SetStderr, so an
	// embedder can feed input and capture/stream output without touching the
	// host process stdio.
	stdin          io.Reader
	stdout, stderr io.Writer
	// fdTable maps every open guest fd, 0/1/2 included, to its entry. Use
	// it through fdsLocked: nil means the table has not been set up yet,
	// which is how a WasiStubs built as a bare struct literal starts.
	fdTable   map[int32]*wasiOpen
	args, env []string
	monoStart time.Time
	// preopenDir is the host directory mapped to wasi preopen fd 3.
	// Defaults to "/" (i.e. no rewriting) — the legacy behaviour. Tests
	// can set this via SetPreopenDir to scope filesystem ops to a
	// temporary directory.
	preopenDir string
	// fsHook, when non-nil, is consulted before every filesystem access
	// (Path_open, Path_create_directory, Path_unlink_file). It receives
	// the guest-supplied path (relative to the preopen, e.g. "a.txt" or
	// "sub/a.txt") and whether the access is a write. Returning false
	// denies the operation, which surfaces to the guest as EACCES. This
	// is the host-controlled whitelist hook: the policy itself lives in
	// the embedding application, OUTSIDE the generated runtime.
	fsHook func(path string, write bool) bool
	// netHook, when non-nil, is consulted before every socket operation
	// (Sock_accept, Sock_recv, Sock_send). op is "accept"/"recv"/"send".
	// Returning false denies the operation (EACCES). The same
	// host-controlled-whitelist intent as fsHook, for the network surface.
	netHook func(op string) bool
	// dialHook, when non-nil, is consulted before an OUTBOUND connect
	// (Sock_connect) with the resolved network ("tcp"), the HOST the guest
	// resolved to reach this address (from the preceding Sock_getaddrinfo, or ""
	// if the guest dialed a literal IP), the dotted-quad IP, and the port.
	// Returning false denies the connection (EACCES). Passing the host lets the
	// policy match host+port jointly, which a port-scoped rule needs — the IP
	// alone cannot be tied back to the rule that authorized the name.
	dialHook func(network, host, ip string, port int) bool
	// resolveHook, when non-nil, is consulted before a name lookup
	// (Sock_getaddrinfo) with the requested host. Returning false denies the
	// resolution (the guest sees a gaierror). This is the hostname-level
	// whitelist control point (e.g. block "example.com" by name).
	resolveHook func(host string) bool
	// resolvedHosts maps a resolved dotted-quad IP back to the host name the
	// guest looked it up under (populated by Sock_getaddrinfo, read by
	// Sock_connect), so the dial hook can be given the host. Guarded by mu.
	resolvedHosts map[string]string
	// fsys is the filesystem backend every guest path operation is routed
	// through. Defaults to an osFS scoped to preopenDir (the host filesystem);
	// SetFS swaps in an alternative (e.g. an in-memory FS) so each module can
	// see a private, arbitrary filesystem.
	fsys FS
	// procs tracks the processes this instance may wait for — host
	// processes spawned via Proc_spawn and embedder-run processes registered
	// via NewProc / Proc_fork — keyed by the pid handed back to the guest.
	procs map[int32]*wasiProc
	// pids allocates the pid tokens (kept distinct from real OS pids — the
	// guest only ever sees these tokens). It is created on first use and
	// shared with every instance derived through Fork, so a token is unique
	// across a whole fork family.
	pids *wasiPIDs
	// procFinished is closed, and dropped so the next waiter makes a fresh
	// one, whenever a process in procs finishes. Proc_wait_any blocks on it
	// instead of polling. Guarded by mu.
	procFinished chan struct{}
	// forkHook, when non-nil, is the embedder's implementation of fork,
	// called by Proc_fork. See SetForkHook.
	forkHook func(parent *Module, child *WasiStubs, pid int32, exited func(status int32)) (kill func(sig int32) error, err error)
	// execHook, when non-nil, gates every Proc_spawn with the resolved
	// executable path and argv; returning false denies the spawn (EACCES).
	// This is the outbound-process whitelist control point — the analogue of
	// dialHook for sockets. Spawning runs a HOST binary, so a sandbox that
	// enables host processes should always install this.
	execHook func(path string, argv []string) bool
	// umask is the guest's file mode creation mask once it has set one
	// (Proc_umask); nil means the host process's own mask applies. It is
	// per instance because every instance is a process of its own to the
	// guest, and the host process's mask is shared by all of them. Use it
	// through createMode. Guarded by mu.
	umask *os.FileMode
	// hostProcess records that the guest program is the host process (see
	// SetHostProcess). Guarded by mu.
	hostProcess bool
	// hostIDs, when non-nil, is the embedder's way of changing the ids of
	// the host process; see SetHostIDs. Guarded by mu.
	hostIDs HostIDs
	// localZone is the time zone of a guest that names none; see
	// SetLocalZone. nil is UTC. Guarded by mu.
	localZone *time.Location
	// syslogger, when non-nil, is the system logger the guest's syslog(3)
	// delivers to; see SetSyslogger. Guarded by mu.
	syslogger Syslogger
	// forked marks host state made by Fork: the instance it backs is a
	// process of its own, never the host process, whatever hostProcess
	// says about the identity it inherited. Immutable.
	forked bool
	// parent is the host state of the process that forked this one, and pid
	// the pid token this one was forked under (Proc_fork); both are zero
	// for the first process of a family. They are what getpid and getppid
	// of a forked process answer from: the parent's pid for as long as the
	// parent exists, 1 afterwards. Set before the process runs.
	parent *WasiStubs
	pid    int32
	// ended records that the instance is gone (CloseAll). Guarded by mu.
	ended bool
	// pgid is the process group of the instance. 0 stands for the group
	// the first process of a family starts in: the host process's own
	// group when the guest is the host process, and a group of its own
	// otherwise. A forked process always has a number here, its parent's
	// group at the time of the fork until it changes it. Guarded by mu.
	pgid int32
	// sessionLeader records that a forked process started a session of
	// its own (setsid), and terminal is the controlling terminal of a
	// forked process when that is not the host process's: the path of the
	// terminal it took (TIOCSCTTY), or the empty string for none (after
	// setsid or TIOCNOTTY). nil stands for the host process's. The host
	// keeps one session and one controlling terminal for the whole host
	// process, so these cannot be the host's to keep; a forked process
	// starts with its parent's terminal. Guarded by mu.
	sessionLeader bool
	terminal      *string
	// execNext records that the next command the process starts is the
	// one it becomes (Proc_exec_next). Guarded by mu.
	execNext bool
	// execing records that the process has become the command it started
	// (from its start until Proc_exec has waited for it). A signal to the
	// process's group reaches the command as a member of the group
	// (killGroup), and is not posted to the process as well, which would
	// pass it on to the command a second time (Proc_exec). Guarded by mu.
	execing bool
	// cloexec holds the descriptor numbers the guest has marked
	// close-on-exec (Fd_cloexec). A number that is given to a new
	// descriptor starts unmarked. Guarded by mu.
	cloexec map[int32]bool
	// sig is the signal state; see wasiSignals. Guarded by mu.
	sig wasiSignals
	// waker is what ends the wait of a call of the guest's that waits for
	// descriptors of the host process, when a signal is posted (see
	// awaitHost): nothing else reaches a wait inside the host's poll. Made
	// on first use, nil until then and on a host without such waits.
	// Guarded by mu.
	waker *hostWaker
	// standard is which standard descriptors of the host process the
	// instance has as its own (see takeStandardLocked): what the guest does
	// to descriptors 0, 1 and 2 it does to the process's. nil for an
	// instance that took none; a forked instance has its parent's. Guarded
	// by mu.
	standard *hostStandard
}

// wasiProc is a process the guest can wait for: a host process spawned by
// Proc_spawn (cmd != nil), or a process the embedder runs itself, registered
// through NewProc / Proc_fork (cmd == nil). Whoever runs the process publishes
// the encoded POSIX status and closes done, so Proc_wait can support both the
// blocking (options 0) and non-blocking (WNOHANG) forms without holding the
// WasiStubs lock across the child's lifetime.
type wasiProc struct {
	cmd    *exec.Cmd
	done   chan struct{}
	status int32 // POSIX wait status, valid once done is closed
	// kill delivers a signal to an embedder-run process (Proc_kill). nil
	// when the embedder gave none. It is set before the process is entered
	// in the family's table (wasiPIDs.enter) and not changed afterwards.
	kill func(sig int32) error
	// inst is the host state of a process that is a guest instance of the
	// family (Proc_fork, and the first process of an isolated family): the
	// process group it is in is found there. nil for any other process.
	// Set before the process is entered in the family's table.
	inst *WasiStubs
	// reap takes a host process (cmd) off the host's process table, once:
	// when the guest has waited for it, or when nobody is left who could.
	// Until then the process, though it has ended, keeps its pid — the
	// host gives the number to no other process, so the status the guest
	// has not collected yet cannot be mistaken for another command's.
	reap sync.Once
}

// release lets the host forget a host process that has ended: see
// wasiProc.reap. Every caller has seen the process end (done is closed),
// so the wait returns at once — a command whose streams the runtime copies
// was waited for when it ended, and one whose streams are the host's has
// nothing more to wait for — and it is made before release returns. A
// guest's wait for a child thus returns with the child off the host's
// process table, as the host's own wait does; that is also when the host
// adds the child's CPU time to the times of the children of the process
// (getrusage RUSAGE_CHILDREN), which a guest reads next (times, after
// system).
func (proc *wasiProc) release() {
	if proc.cmd == nil {
		return
	}
	proc.reap.Do(func() { _ = waitCommand(proc.cmd) })
}

// wasiPIDs hands out pid tokens and knows the processes of a fork family by
// them. One is shared by every WasiStubs of the family, each of which has
// its own lock, hence the separate mutex.
type wasiPIDs struct {
	mu sync.Mutex
	// first is the first token of the family and next the one handed out
	// next. first is immutable.
	first, next int32
	// procs holds every process of the family that exists: from the moment
	// it can be signalled until it has been waited for, or has finished
	// with nobody left to wait for it. An instance waits only for the
	// processes in its own table (WasiStubs.procs), but it may signal any
	// process whose pid it knows — a sibling, its parent's parent, a
	// grandchild — and only its own children are in its own table.
	procs map[int32]*wasiProc
	// groups holds, for a process group of the family, the process groups
	// of the host that commands lead for it: a process that leads its group
	// or its session within the runtime and execs a command has the command
	// lead a group of the host. A signal to the family's group goes to each
	// for as long as the host has it, which is while a process is left in
	// it — after the command has ended and the process it replaced has been
	// waited for, as a signal to a group reaches every member until there
	// is none (Proc::Simple kills the shell of `sh -c` and then its group).
	// The host gives the number of such a group to no other process while
	// the group exists.
	groups map[int32][]int
}

// addGroup records that the host's process group hostPgid is one of the
// family's group pgid.
func (p *wasiPIDs) addGroup(pgid int32, hostPgid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.groups == nil {
		p.groups = map[int32][]int{}
	}
	p.groups[pgid] = append(p.groups[pgid], hostPgid)
}

// hostGroups returns the host's process groups recorded for the family's
// group pgid, or for every group of the family when all is set.
func (p *wasiPIDs) hostGroups(pgid int32, all bool) []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !all {
		return append([]int(nil), p.groups[pgid]...)
	}
	var hosts []int
	for _, g := range p.groups {
		hosts = append(hosts, g...)
	}
	return hosts
}

// dropGroup forgets a process group the host no longer has.
func (p *wasiPIDs) dropGroup(hostPgid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for pgid, g := range p.groups {
		for i, h := range g {
			if h == hostPgid {
				g = append(g[:i], g[i+1:]...)
				break
			}
		}
		if len(g) == 0 {
			delete(p.groups, pgid)
		} else {
			p.groups[pgid] = g
		}
	}
}

// enter makes proc reachable by pid for every instance of the family.
func (p *wasiPIDs) enter(pid int32, proc *wasiProc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.procs == nil {
		p.procs = map[int32]*wasiProc{}
	}
	p.procs[pid] = proc
}

// leave forgets the process known by pid.
func (p *wasiPIDs) leave(pid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.procs, pid)
}

// find returns the process of the family known by pid, or nil.
func (p *wasiPIDs) find(pid int32) *wasiProc {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.procs[pid]
}

// alloc returns the next unused pid token.
func (p *wasiPIDs) alloc() int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	pid := p.next
	p.next++
	return pid
}

// allocated reports whether pid is a token this allocator has handed out.
func (p *wasiPIDs) allocated(pid int32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return pid >= p.first && pid < p.next
}

// wasiFirstPID is the first pid token a fresh instance hands out, unless the
// guest is the host process (see pidsLocked).
const wasiFirstPID int32 = 1000

// DefaultWASI returns a WasiStubs configured for typical CLI use: real
// stdio, os.Args, os.Environ(), wall + monotonic clocks. Consumers who
// want a sandboxed setup should construct their own WasiStubs (or any
// Wasi_snapshot_preview1Imports implementation) and pass it to
// NewWithWASI.
func DefaultWASI() *WasiStubs {
	return &WasiStubs{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		args:       os.Args,
		env:        os.Environ(),
		monoStart:  time.Now(),
		preopenDir: "/",
		fsys:       osFS{root: "/"},
		procs:      map[int32]*wasiProc{},
	}
}

// SetPreopenDir scopes the default (os-backed) filesystem to a host directory.
// Empty string restores the default ("/"), i.e. no rewriting. Tests use this
// to run filesystem syscalls against t.TempDir(). Has no effect once SetFS has
// installed a non-os backend.
func (w *WasiStubs) SetPreopenDir(dir string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if dir == "" {
		dir = "/"
	}
	w.preopenDir = dir
	w.fsys = osFS{root: dir}
}

// SetFS installs a custom filesystem backend. Every guest path operation
// (open, stat, mkdir, readdir, read, write, ...) is then routed to fsys, so a
// caller can give a module a private, arbitrary filesystem — for example an
// in-memory FS so writes never touch disk and are invisible to other modules.
// Pass nil to restore the default os-backed filesystem.
func (w *WasiStubs) SetFS(fsys FS) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if fsys == nil {
		fsys = osFS{root: w.preopenDir}
	}
	w.fsys = fsys
}

// SetFSAccessHook installs a host-controlled filesystem access policy.
// hook is called with the guest path (relative to the preopen) and a
// write flag before each open/create/unlink; returning false denies the
// operation (the guest sees EACCES). Pass nil to clear the policy
// (unrestricted, the default). The hook runs without w.mu held, so it
// may itself call back into the host freely.
func (w *WasiStubs) SetFSAccessHook(hook func(path string, write bool) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fsHook = hook
}

// SetNetAccessHook installs a host-controlled network access policy.
// hook is called with the operation name before each socket operation;
// returning false denies it (EACCES). The operations are "listen" (taking a
// local address to accept connections on: Sock_bind, Sock_listen), "accept",
// "recv" and "send". Pass nil to clear (unrestricted, the default).
//
// NOTE: WASI preview1 has no outbound connect or name resolution, so a
// guest cannot initiate connections regardless of this hook; it governs
// the accept/recv/send surface that preview1 does expose (host-preopened
// listening sockets). Full outbound control requires a host connect
// import, which this runtime does not yet provide.
func (w *WasiStubs) SetNetAccessHook(hook func(op string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.netHook = hook
}

// SetDialHook installs a host-controlled OUTBOUND-connection policy. hook is
// called with ("tcp", host, dotted-quad-IP, port) before each Sock_connect,
// where host is the name the guest resolved to reach the IP (from the preceding
// Sock_getaddrinfo) or "" for a literal-IP dial; returning false denies the
// connection (the guest sees a connect EACCES). Pass nil to clear (all outbound
// allowed, the default once outbound is wired).
func (w *WasiStubs) SetDialHook(hook func(network, host, ip string, port int) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dialHook = hook
}

// SetResolveHook installs a host-controlled name-resolution policy. hook is
// called with the host being resolved (Sock_getaddrinfo) before the lookup;
// returning false denies it (the guest sees a name-resolution error). Pass nil
// to clear (all lookups allowed). This is where a hostname whitelist such as
// "block example.com" is enforced.
func (w *WasiStubs) SetResolveHook(hook func(host string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.resolveHook = hook
}

// SetExecHook installs the process-spawn whitelist consulted by Proc_spawn
// with the executable path and full argv. Returning false denies the spawn
// (the guest's posix_spawn sees EACCES). Spawning runs a HOST binary, so a
// sandbox enabling host processes should always set this.
func (w *WasiStubs) SetExecHook(hook func(path string, argv []string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.execHook = hook
}

// SetForkHook installs the embedder's implementation of fork, called by
// Proc_fork. Without a hook Proc_fork reports ENOSYS. Pass nil to clear.
//
// The hook runs synchronously inside the guest's proc_fork call, on the
// guest's goroutine and without w.mu held, so the guest is stopped while it
// runs: this is where the embedder snapshots the guest (parent is the calling
// module) into a new module instance. Its arguments are
//
//   - child: the host state for that new instance (see Fork). It becomes the
//     embedder's to own; call child.CloseAll once the child has finished.
//   - pid: the token the parent's guest will know the child by.
//   - exited: to be called with the child's POSIX wait status when it ends —
//     (code&0xff)<<8 for a normal exit, the signal number in the low 7 bits
//     for a death by signal. It may be called from any goroutine; only its
//     first call has an effect.
//
// The hook returns the function Proc_kill uses to deliver a signal to the
// child (nil when the child cannot be signalled; see NewProc for how it is
// called), or an error when the child could not be created. On an error the
// hook must not have started the child: Proc_fork then releases child's
// descriptors, forgets pid and reports EAGAIN.
func (w *WasiStubs) SetForkHook(hook func(parent *Module, child *WasiStubs, pid int32, exited func(status int32)) (kill func(sig int32) error, err error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.forkHook = hook
}

// Fork returns the host state for a forked copy of the guest, with fork(2)
// semantics:
//
//   - the configuration is the same: stdio streams, args, environment,
//     filesystem backend, clock origin, every hook and the identity
//     (SetHostProcess);
//   - the fd table has the same fd numbers — an fd closed in w, fd 0, 1 or
//     2 included, is closed in the result — and each slot refers to the SAME
//     open descriptor as the corresponding slot of w, so the two instances
//     share the file offset, and the underlying file, connection or listener
//     is closed only when the last slot referring to it, in any instance, is
//     closed;
//   - the process table is empty: a child does not inherit its parent's
//     children. Pid tokens stay unique across w, the result and everything
//     later forked from either;
//   - no signal is pending and no interval timer is set, and the guest has not
//     registered for signals: the copy of the guest that runs on the result
//     registers and reports its dispositions (the ones it inherited) itself.
//
// The result is independent of w from then on (its own lock, its own fd
// numbering) and is meant to back a second module instance running on
// another goroutine. Release its descriptors with CloseAll when that instance
// is done.
func (w *WasiStubs) Fork() *WasiStubs {
	w.mu.Lock()
	defer w.mu.Unlock()
	child := &WasiStubs{
		stdin:       w.stdin,
		stdout:      w.stdout,
		stderr:      w.stderr,
		fdTable:     make(map[int32]*wasiOpen, len(w.fdsLocked())),
		args:        w.args,
		env:         w.env,
		monoStart:   w.monoStart,
		preopenDir:  w.preopenDir,
		fsHook:      w.fsHook,
		netHook:     w.netHook,
		dialHook:    w.dialHook,
		resolveHook: w.resolveHook,
		fsys:        w.fsys,
		procs:       map[int32]*wasiProc{},
		pids:        w.pidsLocked(),
		execHook:    w.execHook,
		forkHook:    w.forkHook,
		syslogger:   w.syslogger,
		localZone:   w.localZone,
		hostProcess: w.hostProcess,
		hostIDs:     w.hostIDs,
		forked:      true,
		parent:      w,
		pgid:        w.groupLocked(),
		standard:    w.standard,
		terminal:    w.terminal,
	}
	if len(w.cloexec) > 0 {
		child.cloexec = make(map[int32]bool, len(w.cloexec))
		for fd := range w.cloexec {
			child.cloexec[fd] = true
		}
	}
	if w.umask != nil {
		mask := *w.umask
		child.umask = &mask
	}
	if w.resolvedHosts != nil {
		child.resolvedHosts = make(map[string]string, len(w.resolvedHosts))
		for ip, host := range w.resolvedHosts {
			child.resolvedHosts[ip] = host
		}
	}
	for fd, op := range w.fdsLocked() {
		op.addRef()
		child.fdTable[fd] = op
	}
	if !w.forked && !w.hostProcess {
		// The first process of an isolated family has a pid its
		// descendants know (getppid), and they may signal it. (The pid of
		// a guest that is the host process is the host's: a signal to it
		// goes through the host, see killOutside.)
		pids := w.pidsLocked()
		if pids.find(wasiIsolatedPID) == nil {
			pids.enter(wasiIsolatedPID, &wasiProc{
				done: make(chan struct{}),
				kill: func(sig int32) error {
					w.PostSignal(sig)
					return nil
				},
				inst: w,
			})
		}
	}
	return child
}

// CloseAll closes every fd of this instance, as if the guest had called
// fd_close on each: a descriptor shared with another slot or another instance
// (dup, Fork) stays open until its last reference goes. It lets an embedder
// dispose of the host state of a finished instance, typically a forked child.
// It also ends signal delivery to the instance — the interval timer is disarmed, and
// PostSignal drops what it is given from here on — so the guest's memory
// can be released afterwards.
// Calling it again is a no-op. The close errors are joined.
func (w *WasiStubs) CloseAll() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ended = true
	w.detachSignalsLocked()
	var err error
	leave := w.leavesStandardLocked()
	for fd, op := range w.fdsLocked() {
		err = errors.Join(err, endWasiOpen(op, leave))
		delete(w.fdsLocked(), fd)
	}
	w.closeHostWakerLocked()
	w.endStandardLocked()
	// Nobody is left to wait for this instance's processes: the finished
	// ones are gone, and the running ones go when they finish (finishProc
	// finds them missing from the table).
	for pid, proc := range w.procs {
		select {
		case <-proc.done:
			proc.release()
			w.pidsLocked().leave(pid)
		default:
		}
		delete(w.procs, pid)
	}
	return err
}

// KillCommands ends the commands this instance started and has not waited
// for (the host processes of Proc_spawn): each one still running is killed,
// as by SIGKILL, and the call returns when all of them have ended and the
// host has taken them off its process table. They stay in the instance's
// process table with the status they ended with.
//
// A command with a standard stream that the runtime copies (one that is not
// a file of the host) is killed and not waited for: it has ended for the
// guest only when its streams are at their end, which a process it started
// and left behind can hold off for as long as it likes. The host takes it
// off its process table as soon as it is dead all the same.
//
// It is for an embedder that ends an instance without letting it run on —
// one it has posted SIGKILL to — and may be called while the guest is still
// running on another goroutine.
func (w *WasiStubs) KillCommands() {
	w.mu.Lock()
	var commands []*wasiProc
	for _, proc := range w.procs {
		if proc.cmd != nil {
			commands = append(commands, proc)
		}
	}
	w.mu.Unlock()
	for _, proc := range commands {
		select {
		case <-proc.done:
		default:
			// A command that has just ended cannot be killed: nothing to
			// report.
			_ = proc.cmd.Process.Kill()
		}
	}
	for _, proc := range commands {
		cmd := proc.cmd
		if !hostStream(cmd.Stdin) || !hostStream(cmd.Stdout) || !hostStream(cmd.Stderr) {
			continue
		}
		<-proc.done
		proc.reap.Do(func() { _ = waitCommand(cmd) })
	}
}

// CloseDescriptors closes every fd of this instance, each as fd_close
// would, and nothing else: the instance stays what it is to the processes
// of its family and keeps receiving signals. It is for an embedder that
// has killed an instance whose guest may still be running on another
// goroutine; the guest finds every descriptor closed. CloseAll is still to
// be called once the guest is no longer running. The close errors are
// joined.
func (w *WasiStubs) CloseDescriptors() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	leave := w.leavesStandardLocked()
	for fd, op := range w.fdsLocked() {
		err = errors.Join(err, endWasiOpen(op, leave))
		delete(w.fdsLocked(), fd)
	}
	return err
}

// Fd_closefrom is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_closefrom") backing closefrom(): it closes every fd numbered
// lowFd or higher, each as fd_close would. A guest emulating exec needs it:
// the process it started has its own descriptors, and the fds this instance
// still holds — close-on-exec ones included — must go, or a peer waiting for
// end-of-file on one of them waits for as long as the command runs. Returns
// 0, or a positive errno for the first close that failed (every fd in range
// is closed regardless).
func (w *WasiStubs) Fd_closefrom(m *Module, lowFd int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	for fd, op := range w.fdsLocked() {
		if fd < lowFd {
			continue
		}
		err = errors.Join(err, closeWasiOpen(op))
		delete(w.fdsLocked(), fd)
	}
	if err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_closefrom64 is Fd_closefrom for a memory64 guest.
func (w *WasiStubs) Fd_closefrom64(m *Module, lowFd int32) int32 {
	return w.Fd_closefrom(m, lowFd)
}

// wasiPreopenFD is the fd of the preopened root directory. It is not a
// table entry and is never handed out for a new descriptor — except to a
// guest whose descriptors are the host process's, for which 3 is a number
// like any other (see rootNumberLocked).
const wasiPreopenFD int32 = 3

// wasiRootFD is a second number of the preopened root directory, which a
// guest's libc can resolve its paths against instead of wasiPreopenFD: one
// that no descriptor ever has, so that the root directory is in nobody's
// way. A libc finds the preopened directory under wasiPreopenFD (that is
// where WASI has it start looking); one that knows this number names the
// root by it from then on, in the path calls and where it asks what the
// directory may be opened for (fd_fdstat_get), and leaves 3 alone.
const wasiRootFD int32 = 0x7ffffff0

// rootDirFD reports whether fd, the directory descriptor of a path call,
// names the preopened root directory.
func rootDirFD(fd int32) bool { return fd == wasiPreopenFD || fd == wasiRootFD }

// fdsLocked returns the fd table. On first use it sets the table up with
// fds 0, 1 and 2 referring to the instance's stdin, stdout and stderr; from
// then on those are ordinary slots that the guest can close, dup and reuse.
// Caller holds w.mu.
func (w *WasiStubs) fdsLocked() map[int32]*wasiOpen {
	if w.fdTable == nil {
		if w.hostDescriptorsLocked() {
			// The standard descriptors of the host process, where the
			// instance's streams are those.
			w.fdTable = map[int32]*wasiOpen{}
			for stdio := int8(1); stdio <= 3; stdio++ {
				w.fdTable[int32(stdio)-1] = w.hostStandardLocked(stdio)
			}
			return w.fdTable
		}
		w.fdTable = map[int32]*wasiOpen{
			0: {stdio: 1},
			1: {stdio: 2},
			2: {stdio: 3},
		}
	}
	return w.fdTable
}

// openLocked returns the entry the guest knows as descriptor fd, or nil
// when it has none. A guest whose descriptors are the host process's has
// every descriptor of the process that is nobody else's: one it did not
// open itself — code outside the guest did, a native library — becomes an
// entry of its table when it is first used (hostOpenLocked). Caller holds
// w.mu.
func (w *WasiStubs) openLocked(fd int32) *wasiOpen {
	op := w.fdsLocked()[fd]
	if w.hostDescriptorsLocked() {
		return w.hostOpenLocked(fd, op)
	}
	return op
}

// rootNumberLocked reports whether fd, a number the instance has no entry
// for, is the preopened root directory to a call that asks about the
// descriptor itself (fd_fdstat_get, fd_filestat_get). wasiRootFD always is.
// wasiPreopenFD is for a guest with descriptors of its own; for a guest
// whose descriptors are the host process's, 3 is a number like any other —
// free for the host to give out, and not open until it does. Caller holds
// w.mu.
func (w *WasiStubs) rootNumberLocked(fd int32) bool {
	return fd == wasiRootFD || (fd == wasiPreopenFD && !w.hostDescriptorsLocked())
}

// addFDLocked stores op under the lowest fd number not in use, as POSIX
// requires of open, pipe, dup, socket and accept, and returns that number.
// In an instance whose descriptors are the host process's, a number the
// host has in use is not free either: the entry is not a descriptor of the
// host (those come in through addHostFDLocked, under their own numbers) and
// must not be mistaken for one. Caller holds w.mu.
func (w *WasiStubs) addFDLocked(op *wasiOpen) int32 {
	return w.addFDFromLocked(op, 0)
}

// addFDFromLocked enters op under the lowest free number that is at least
// min (fcntl's F_DUPFD).
func (w *WasiStubs) addFDFromLocked(op *wasiOpen, min int32) int32 {
	fds := w.fdsLocked()
	fd := min
	if w.hostDescriptorsLocked() {
		fd = w.freeNumberLocked(min)
	} else {
		for {
			if _, used := fds[fd]; !used && fd != wasiPreopenFD {
				break
			}
			fd++
		}
	}
	fds[fd] = op
	delete(w.cloexec, fd)
	return fd
}

// pidsLocked returns the pid allocator, creating it on first use. Caller
// holds w.mu.
func (w *WasiStubs) pidsLocked() *wasiPIDs {
	if w.pids == nil {
		first := wasiFirstPID
		if w.hostProcess {
			// The guest sees the host's processes by their own pids — the
			// commands it starts among them — so the tokens of the family
			// are numbers no host process ever has.
			if limit := hostPIDLimit(); limit >= first {
				first = limit + 1
			}
		}
		w.pids = &wasiPIDs{first: first, next: first}
	}
	return w.pids
}

// addProcLocked registers proc under a fresh pid token, as a process this
// instance waits for. The family does not know it yet: see enterProcLocked.
// Caller holds w.mu.
func (w *WasiStubs) addProcLocked(proc *wasiProc) int32 {
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	pid := w.pidsLocked().alloc()
	w.procs[pid] = proc
	return pid
}

// enterProcLocked makes the process registered under pid known to the whole
// fork family, once everything Proc_kill needs of it is in place. Caller
// holds w.mu.
func (w *WasiStubs) enterProcLocked(pid int32) {
	w.pidsLocked().enter(pid, w.procs[pid])
}

// dropProcLocked removes a process from this instance's table and from the
// family's: it has been waited for, or it never ran. Caller holds w.mu.
func (w *WasiStubs) dropProcLocked(pid int32) {
	if proc := w.procs[pid]; proc != nil {
		proc.release()
	}
	delete(w.procs, pid)
	w.pidsLocked().leave(pid)
}

// finishProc publishes the wait status of proc and wakes every waiter.
// It must be called exactly once per process.
func (w *WasiStubs) finishProc(proc *wasiProc, status int32) {
	proc.status = status
	close(proc.done)
	// Proc_wait_any scans the table and picks up procFinished under one hold
	// of w.mu, so a finish is either seen by its scan or closes the channel
	// it then blocks on.
	w.mu.Lock()
	if w.procFinished != nil {
		close(w.procFinished)
		w.procFinished = nil
	}
	// A process whose parent instance is gone (CloseAll emptied the table)
	// has nobody to wait for it: it does not stay behind as a zombie. Nor
	// does the child of a process that ignores SIGCHLD.
	if w.sig.reapsChildren() {
		w.reapFinishedLocked()
	}
	waitedFor := false
	for _, pr := range w.procs {
		if pr == proc {
			waitedFor = true
			break
		}
	}
	if !waitedFor {
		proc.release()
		pids := w.pidsLocked()
		pids.mu.Lock()
		for pid, pr := range pids.procs {
			if pr == proc {
				delete(pids.procs, pid)
				break
			}
		}
		pids.mu.Unlock()
	}
	w.mu.Unlock()
	// The parent is told, as the kernel tells a process whose child ended.
	w.PostSignal(wasiSIGCHLD)
}

// reapFinishedLocked forgets every process of this instance that has ended:
// what happens to the children of a process that ignores SIGCHLD. Caller
// holds w.mu.
func (w *WasiStubs) reapFinishedLocked() {
	for pid, proc := range w.procs {
		select {
		case <-proc.done:
			w.dropProcLocked(pid)
		default:
		}
	}
}

// NewProc registers a process that the embedder runs itself (not a host
// process started by Proc_spawn) so the guest can wait for it and signal it
// like any other child. It returns the pid token to hand to the guest, and
// exited, which the embedder calls with the POSIX wait status when the
// process ends: (code&0xff)<<8 for a normal exit, the signal number in the
// low 7 bits for a death by signal. exited may be called from any goroutine;
// only its first call has an effect.
//
// kill, when non-nil, is called by Proc_kill to deliver a signal. It is not
// called for signal 0, nor when the process is already known to have
// finished, and it runs without w.mu held, possibly while exited is being
// called on another goroutine. With a nil kill the process cannot be
// signalled.
func (w *WasiStubs) NewProc(kill func(sig int32) error) (pid int32, exited func(status int32)) {
	proc := &wasiProc{done: make(chan struct{}), kill: kill}
	w.mu.Lock()
	pid = w.addProcLocked(proc)
	w.enterProcLocked(pid)
	w.mu.Unlock()
	return pid, w.procExitFunc(proc)
}

// procExitFunc returns the function that reports the end of an embedder-run
// process.
func (w *WasiStubs) procExitFunc(proc *wasiProc) func(status int32) {
	var once sync.Once
	return func(status int32) {
		once.Do(func() { w.finishProc(proc, status) })
	}
}

// readCStr reads a NUL-terminated C string at ptr from linear memory. A nil
// ptr (0) yields "". ok is false on an out-of-bounds or unterminated read:
// a string whose NUL is not within the guest's memory (guestMemory).
func (w *WasiStubs) readCStr(m *Module, ptr uint64) (s string, ok bool) {
	if ptr == 0 {
		return "", true
	}
	mem := w.guestMemory(m)
	if ptr > uint64(len(mem)) {
		return "", false
	}
	rest := mem[ptr:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			return string(rest[:i]), true
		}
	}
	return "", false
}

// readCStrArray reads a NULL-terminated array of C-string pointers (a char**)
// at ptr, whose entries are the guest's pointers (abi). A nil ptr (0) yields
// a nil slice. ok is false on a bad read.
func (w *WasiStubs) readCStrArray(m *Module, abi wasiABI, ptr uint64) (out []string, ok bool) {
	if ptr == 0 {
		return nil, true
	}
	for off := ptr; ; off += abi.wordSize() {
		b := w.memBytes(m, off, abi.wordSize())
		if b == nil {
			return nil, false
		}
		p := abi.word(b)
		if p == 0 {
			break
		}
		s, sok := w.readCStr(m, p)
		if !sok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// Proc_spawn is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "proc_spawn") backing the bridge's posix_spawn(). It spawns a HOST
// process: path is the executable, argv/envp are NUL-terminated char** in
// linear memory. stdinFd/stdoutFd/stderrFd name the guest fds the child gets
// as its fds 0/1/2 (see childReaderLocked); a negative one stands for the
// instance's own stream. Every other descriptor of the guest that is not
// marked close-on-exec (Fd_cloexec) is the child's too, under the same
// number, when the host can hand it over (see inheritedFilesLocked). The
// pid the guest knows the command by is written at pidOutPtr: the command's
// own pid when the guest is the host process, a pid token otherwise.
// Returns 0 or a negative errno.
func (w *WasiStubs) Proc_spawn(m *Module, pathPtr, argvPtr, envpPtr, stdinFd, stdoutFd, stderrFd, cwdPtr, pidOutPtr int32) int32 {
	return w.procSpawn(m, wasiABI32, zext(pathPtr), zext(argvPtr), zext(envpPtr), stdinFd, stdoutFd, stderrFd, zext(cwdPtr), zext(pidOutPtr))
}

// Proc_spawn64 is Proc_spawn for a memory64 guest.
func (w *WasiStubs) Proc_spawn64(m *Module, pathPtr, argvPtr, envpPtr int64, stdinFd, stdoutFd, stderrFd int32, cwdPtr, pidOutPtr int64) int32 {
	return w.procSpawn(m, wasiABI64, uint64(pathPtr), uint64(argvPtr), uint64(envpPtr), stdinFd, stdoutFd, stderrFd, uint64(cwdPtr), uint64(pidOutPtr))
}

// procSpawn is the body of Proc_spawn and Proc_spawn64.
func (w *WasiStubs) procSpawn(m *Module, abi wasiABI, pathPtr, argvPtr, envpPtr uint64, stdinFd, stdoutFd, stderrFd int32, cwdPtr, pidOutPtr uint64) int32 {
	path, ok := w.readCStr(m, pathPtr)
	if !ok || path == "" {
		return -_wasiEINVAL
	}
	argv, ok := w.readCStrArray(m, abi, argvPtr)
	if !ok {
		return -_wasiEFAULT
	}
	env, ok := w.readCStrArray(m, abi, envpPtr)
	if !ok {
		return -_wasiEFAULT
	}
	// The guest's working directory lives in its libc (WASI has no chdir
	// syscall), so the bridge passes it explicitly; the child must start
	// there, not in the host process's cwd.
	cwd, ok := w.readCStr(m, cwdPtr)
	if !ok {
		return -_wasiEFAULT
	}
	out := w.memBytes(m, pidOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}

	w.mu.Lock()
	if w.sig.killPending() {
		// A process that has been killed starts nothing more.
		w.mu.Unlock()
		return -_wasiEINTR
	}
	hook := w.execHook
	// A command the process becomes takes the session the process leads,
	// and its terminal (see Proc_exec_next).
	leads, terminal := w.execNext && w.sessionLeader, ""
	if leads && w.terminal != nil {
		terminal = *w.terminal
	}
	// So does one that leads its process group within the runtime (setpgrp
	// before exec): the command leads a group of its own, which a signal to
	// the process group reaches with every process the command starts.
	leadsGroup := w.execNext && !leads && w.forked && w.groupLocked() == w.processIDLocked()
	// A command that cannot be started does not take the process's place:
	// the next one started does, as the next candidate of a search of PATH
	// (posix_spawnp tries each).
	becomes := w.execNext
	w.execNext = false
	started := false
	defer func() {
		if becomes && !started {
			w.mu.Lock()
			w.execNext = true
			w.mu.Unlock()
		}
	}()
	inherited, borrowed := w.inheritedFilesLocked()
	cin := w.childReaderLocked(stdinFd)
	cout := w.childWriterLocked(stdoutFd, w.stdout)
	cerr := w.childWriterLocked(stderrFd, w.stderr)
	// A standard descriptor the guest has closed is closed in the command,
	// as a child that execs has it (`cmd <&-`).
	var closed [3]bool
	for i, fd := range [3]int32{stdinFd, stdoutFd, stderrFd} {
		closed[i] = fd >= 0 && w.openLocked(fd) == nil
	}
	// A descriptor of the host process is handed over as it is, whatever
	// it is open for: as a duplicate, closed once the command has its own.
	if file, host := w.hostChildFileLocked(stdinFd); host {
		cin = nil
		if file != nil {
			cin, borrowed = file, append(borrowed, file)
		}
	}
	if file, host := w.hostChildFileLocked(stdoutFd); host {
		cout = nil
		if file != nil {
			cout, borrowed = file, append(borrowed, file)
		}
	}
	if file, host := w.hostChildFileLocked(stderrFd); host {
		cerr = nil
		if file != nil {
			cerr, borrowed = file, append(borrowed, file)
		}
	}
	hostPID := w.hostProcess
	// The host process follows every change of directory of the first
	// process of the family (Proc_chdir): its directory is that process's.
	inProcessDir := w.hostProcess && !w.forked
	w.mu.Unlock()
	// The duplicates made for the child are this process's to close, once
	// the child has its own.
	defer func() {
		for _, file := range borrowed {
			_ = file.Close()
		}
	}()
	if hook != nil && !hook(path, argv) {
		return -_wasiEACCES
	}

	// path is a path, as posix_spawn's is: one without a slash names a file
	// in the working directory. Looking a bare name up on PATH is
	// posix_spawnp's job, and the PATH that counts is the guest's, so the
	// guest's libc does it. (exec.Command would search the host process's.)
	cmd := &exec.Cmd{Path: path}
	if len(argv) > 0 {
		cmd.Args = argv
	} else {
		cmd.Args = []string{path}
	}
	// A command started in the directory of the host process inherits
	// it, as a child of fork and exec does: it is not changed into, which
	// would fail for a directory the user may no longer search (EACCES),
	// where the process can stay. The first process of the family is
	// always there; a forked one is while it has not changed directory.
	if cwd != "" && !inProcessDir && !processDirIs(cwd) {
		cmd.Dir = cwd
	}
	// Sandbox: the child sees ONLY the guest-provided environment; a nil
	// (NULL envp) must NOT fall through to the host process environment.
	cmd.Env = env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	// stdin/stdout/stderr are whatever the guest's fds refer to: the
	// instance streams, a file, a guest pipe end, or nothing for a closed
	// fd. A pipe end's dynamic type is *os.File, so Go's exec passes the
	// fd straight to the child; capture works by the guest reading the pipe's
	// other end via Fd_read.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = cin, cout, cerr
	cmd.ExtraFiles = inherited
	if leads {
		files := []any{cin, cout, cerr}
		for _, file := range inherited {
			files = append(files, file)
		}
		cmd.SysProcAttr = commandTerminal(terminal, files)
	} else if leadsGroup {
		cmd.SysProcAttr = commandGroup()
	}
	if err := startCommand(cmd, closed); err != nil {
		return -mapExecError(err)
	}
	started = true

	proc := &wasiProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		// The command's end is learnt without taking the command off the
		// host's process table where the host can tell that way: the pid
		// stays the command's until the guest has waited (wasiProc.reap).
		// That is for a command whose pid the guest knows as the host's,
		// and whose streams are the host's own: one whose streams the
		// runtime copies has ended for the guest when they are copied,
		// which the wait in earnest sees to.
		var status int32
		ended := false
		if hostPID && hostStream(cin) && hostStream(cout) && hostStream(cerr) {
			status, ended = awaitHostExit(cmd.Process.Pid)
		}
		if !ended {
			proc.reap.Do(func() {
				werr := waitCommand(cmd)
				status = encodeWaitStatus(cmd.ProcessState)
				// A non-zero exit or signal surfaces as *exec.ExitError
				// and is the normal path (status already encoded from
				// ProcessState above). Any OTHER error means the wait
				// itself failed; report a 127 exit.
				var exitErr *exec.ExitError
				if werr != nil && !errors.As(werr, &exitErr) {
					status = int32(127) << 8
				}
			})
		}
		w.finishProc(proc, status)
	}()

	w.mu.Lock()
	if becomes {
		w.execing = true
	}
	var pid int32
	if hostPID {
		// The pid is the host's to give. It gives the number to no other
		// process before the guest has waited for this one, where the
		// command stays on the host's process table until then
		// (awaitHostExit); elsewhere a number given again names the new
		// command from here on.
		pid = int32(cmd.Process.Pid)
		if w.procs == nil {
			w.procs = map[int32]*wasiProc{}
		}
		w.procs[pid] = proc
	} else {
		pid = w.addProcLocked(proc)
	}
	w.enterProcLocked(pid)
	if attr := cmd.SysProcAttr; attr != nil && commandLeadsGroup(attr) {
		// The command leads a group of the host for the process's group
		// within the runtime (see wasiPIDs.groups).
		if pids, group := w.pidsLocked(), w.groupLocked(); pids.allocated(group) {
			pids.addGroup(group, cmd.Process.Pid)
		}
	}
	killed := w.sig.killPending()
	w.mu.Unlock()
	if killed {
		// SIGKILL was posted while the command was being started, and
		// whoever posted it may have looked for this instance's commands
		// (KillCommands) before this one was among them.
		_ = cmd.Process.Kill()
	}

	binary.LittleEndian.PutUint32(out, uint32(pid))
	return _wasiESUCCESS
}

// hostStream reports whether a standard stream handed to a command is one
// the command gets as it is — a file of the host, or none — and not one
// the runtime copies to or from while the command runs.
func hostStream(stream any) bool {
	if stream == nil {
		return true
	}
	_, isFile := stream.(*os.File)
	return isFile
}

// wasiInheritedFDLimit bounds the descriptor numbers a command inherits
// beyond its standard streams.
const wasiInheritedFDLimit int32 = 1024

// inheritedFilesLocked returns what a command started now inherits besides
// its standard streams, in the form os/exec takes it: entry i is the
// command's descriptor 3+i, nil for a number the command does not get. A
// descriptor is inherited when the guest has not marked it close-on-exec and
// the host process holds it as a file, a pipe end or a socket; one that
// exists only inside this runtime (a file of an in-memory filesystem) has
// nothing a command could be given. borrowed are the duplicates made for
// the purpose, which the caller closes once the command has started. Caller
// holds w.mu.
func (w *WasiStubs) inheritedFilesLocked() (files, borrowed []*os.File) {
	for fd, op := range w.fdsLocked() {
		if fd < 3 || fd >= wasiInheritedFDLimit || w.cloexec[fd] {
			continue
		}
		if h := op.host(); h.madeOutside() {
			// The flag is the host's own (Fd_cloexec), and so is whether
			// the descriptor is still what the entry was made for.
			if marked, err := h.closeOnExec(false, false); err != nil || marked || !h.current() {
				continue
			}
		}
		var file *os.File
		switch {
		case op.host() != nil:
			if file = op.host().childFile(); file != nil {
				borrowed = append(borrowed, file)
			}
		case op.stdio != 0:
			stream := [...]any{w.stdin, w.stdout, w.stderr}[op.stdio-1]
			file, _ = stream.(*os.File)
		case op.f != nil:
			file, _ = op.f.(*os.File)
		default:
			var socket interface{ File() (*os.File, error) }
			if conn := op.netConn(); conn != nil {
				socket, _ = conn.(interface{ File() (*os.File, error) })
			} else if l, _ := op.netListener(); l != nil {
				socket, _ = l.(interface{ File() (*os.File, error) })
			}
			if socket != nil {
				if dup, err := socket.File(); err == nil {
					file = dup
					borrowed = append(borrowed, dup)
				}
			}
		}
		if file == nil {
			continue
		}
		for int32(len(files)) <= fd-3 {
			files = append(files, nil)
		}
		files[fd-3] = file
	}
	if w.hostDescriptorsLocked() {
		// What code outside the guest left open for a command to inherit
		// is part of what the guest has, and so of what the command gets.
		for _, fd := range w.inheritableOutsideLocked() {
			file := fd.childFile()
			if file == nil {
				continue
			}
			borrowed = append(borrowed, file)
			at := fd.fd.Load() - 3
			for int32(len(files)) <= at {
				files = append(files, nil)
			}
			files[at] = file
		}
	}
	return files, borrowed
}

// Fd_cloexec is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_cloexec") backing fcntl's F_GETFD and F_SETFD: the close-on-exec
// flag of a descriptor, which decides whether a command the guest starts
// inherits it (Proc_spawn). The flag as it was is written at oldPtr (u32, 0
// or 1); with set non-zero it then becomes value. It belongs to the
// descriptor number, not to the open file: a duplicate starts without it.
// Returns 0 or a negative errno.
func (w *WasiStubs) Fd_cloexec(m *Module, fd, set, value, oldPtr int32) int32 {
	return w.fdCloexec(m, fd, set, value, zext(oldPtr))
}

// Fd_cloexec64 is Fd_cloexec for a memory64 guest.
func (w *WasiStubs) Fd_cloexec64(m *Module, fd, set, value int32, oldPtr int64) int32 {
	return w.fdCloexec(m, fd, set, value, uint64(oldPtr))
}

// fdCloexec is the body of Fd_cloexec and Fd_cloexec64.
func (w *WasiStubs) fdCloexec(m *Module, fd, set, value int32, oldPtr uint64) int32 {
	out := w.memBytes(m, oldPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	if op == nil {
		return -_wasiEBADF
	}
	if h := op.host(); h.madeOutside() {
		// The flag of a descriptor that code outside the guest made is
		// the host's own: that code set it, and reads it.
		was, err := h.closeOnExec(set != 0, value != 0)
		if err != nil {
			return -mapOSError(err)
		}
		old := uint32(0)
		if was {
			old = 1
		}
		binary.LittleEndian.PutUint32(out, old)
		return _wasiESUCCESS
	}
	old := uint32(0)
	if w.cloexec[fd] {
		old = 1
	}
	binary.LittleEndian.PutUint32(out, old)
	if set != 0 {
		if value != 0 {
			if w.cloexec == nil {
				w.cloexec = map[int32]bool{}
			}
			w.cloexec[fd] = true
		} else {
			delete(w.cloexec, fd)
		}
	}
	return _wasiESUCCESS
}

// childReaderLocked resolves the stdin of a spawned process. A negative fd
// asks for the instance's stdin. Any other fd is resolved through the fd
// table like a read of it: the standard stream, file, pipe end or
// connection it refers to, and nil — no stream, which os/exec turns into
// the null device — when the fd is closed or cannot be read. Caller holds
// w.mu.
func (w *WasiStubs) childReaderLocked(fd int32) io.Reader {
	if fd < 0 {
		return w.stdin
	}
	src, _ := w.fdSrcLocked(fd)
	return src
}

// hostChildFileLocked returns what a command gets for the guest's fd when
// that is a descriptor of the host process (host is true): a duplicate of
// it for package os/exec to hand over, which the caller closes, or nil when
// the descriptor is gone. Caller holds w.mu.
func (w *WasiStubs) hostChildFileLocked(fd int32) (file *os.File, host bool) {
	if fd < 0 {
		return nil, false
	}
	h := w.openLocked(fd).host()
	if h == nil {
		return nil, false
	}
	return h.childFile(), true
}

// childWriterLocked is the stdout/stderr counterpart of childReaderLocked;
// inherited is the instance stream a negative fd asks for.
func (w *WasiStubs) childWriterLocked(fd int32, inherited io.Writer) io.Writer {
	if fd < 0 {
		return inherited
	}
	dst, _ := w.fdDstLocked(fd)
	return dst
}

// Pipe is a NON-STANDARD host import (module wasi_snapshot_preview1, name
// "pipe") backing the bridge's pipe()/pipe2(). It creates a host OS pipe and
// registers both ends as guest fds, writing [readFd, writeFd] (two i32) at
// fdsOutPtr. The guest reads the read end via Fd_read; the write end is given
// to a child as its stdout/stderr via Proc_spawn, so subprocess.run can
// capture output. Returns 0 or a negative errno.
func (w *WasiStubs) Pipe(m *Module, fdsOutPtr int32) int32 {
	return w.pipe(m, zext(fdsOutPtr))
}

// Pipe64 is Pipe for a memory64 guest.
func (w *WasiStubs) Pipe64(m *Module, fdsOutPtr int64) int32 {
	return w.pipe(m, uint64(fdsOutPtr))
}

// pipe is the body of Pipe and Pipe64.
func (w *WasiStubs) pipe(m *Module, fdsOutPtr uint64) int32 {
	out := w.memBytes(m, fdsOutPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	host := w.hostDescriptorsLocked()
	w.mu.Unlock()
	var rfd, wfd int32
	if host {
		rop, wop, err := hostPipe()
		if err != nil {
			return -mapOSError(err)
		}
		w.mu.Lock()
		rfd, err = w.addHostFDLocked(rop)
		if err == nil {
			wfd, err = w.addHostFDLocked(wop)
		}
		w.mu.Unlock()
		if err != nil {
			return -mapOSError(errors.Join(err, closeWasiOpen(rop), closeWasiOpen(wop)))
		}
	} else {
		r, wr, err := os.Pipe()
		if err != nil {
			return -mapOSError(err)
		}
		w.mu.Lock()
		rfd = w.addFDLocked(&wasiOpen{f: r, noWrite: true})
		wfd = w.addFDLocked(&wasiOpen{f: wr, noRead: true})
		w.mu.Unlock()
	}
	binary.LittleEndian.PutUint32(out[0:], uint32(rfd))
	binary.LittleEndian.PutUint32(out[4:], uint32(wfd))
	return _wasiESUCCESS
}

// Proc_wait is a NON-STANDARD host import (name "proc_wait") backing the
// bridge's waitpid(). It waits for the process token pid and writes the POSIX
// wait status at statusOutPtr. options is the waitpid() options mask; bit 0
// (WNOHANG) makes it return without blocking when the child is still running
// (the guest sees the documented "0 means no child ready" result, signalled
// by writing pid 0 — encoded by returning EAGAIN). Returns 0, or a negative
// errno: ECHILD for an unknown pid — and, when the guest ignores SIGCHLD,
// once the process has finished — EINTR when a signal was posted to the
// guest before the process finished.
func (w *WasiStubs) Proc_wait(m *Module, pid, options, statusOutPtr int32) int32 {
	return w.procWait(m, pid, options, zext(statusOutPtr))
}

// Proc_wait64 is Proc_wait for a memory64 guest.
func (w *WasiStubs) Proc_wait64(m *Module, pid, options int32, statusOutPtr int64) int32 {
	return w.procWait(m, pid, options, uint64(statusOutPtr))
}

// procWait is the body of Proc_wait and Proc_wait64.
func (w *WasiStubs) procWait(m *Module, pid, options int32, statusOutPtr uint64) int32 {
	out := w.memBytes(m, statusOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	proc := w.procs[pid]
	if proc == nil && w.hostProcess {
		proc = w.adoptHostChildLocked(pid)
	}
	w.mu.Unlock()
	if proc == nil {
		return -_wasiECHILD
	}
	const wnohang = 1
	if options&wnohang != 0 {
		select {
		case <-proc.done:
		default:
			// Child still running; non-blocking caller gets EAGAIN.
			return -_wasiEAGAIN
		}
	} else if !w.awaitInterruptibly(proc.done) {
		return -_wasiEINTR
	}
	w.mu.Lock()
	w.dropProcLocked(pid)
	reaped := w.sig.reapsChildren()
	w.mu.Unlock()
	if reaped {
		// The child of a process that ignores SIGCHLD left no status.
		return -_wasiECHILD
	}
	binary.LittleEndian.PutUint32(out, uint32(proc.status))
	return _wasiESUCCESS
}

// adoptHostChildLocked makes a child of the host process that the runtime
// did not start a process of this instance, so that the guest that is the
// host process waits for it as perl waits for any child of its process:
// native code starts such children for it (a module's C that calls
// posix_spawn, or vfork and exec — Proc::FastSpawn — and returns the pid).
// It returns nil when pid is no such child: a process of the family (a
// sibling's command, which this instance does not wait for, as one process
// does not wait for another's children), or no child of the host process.
// A child that has ended is reaped by the asking; one that has not is
// waited for, and reaped, by a goroutine, and its status is collected as a
// spawned command's is. Only the guest's wait for that pid finds it: wait()
// (Proc_wait_any) does not look for children the runtime does not know.
// Caller holds w.mu.
func (w *WasiStubs) adoptHostChildLocked(pid int32) *wasiProc {
	if pid <= 0 || w.pidsLocked().find(pid) != nil {
		return nil
	}
	status, child, ended := hostChildState(int(pid))
	if !child {
		return nil
	}
	proc := &wasiProc{done: make(chan struct{})}
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	w.procs[pid] = proc
	if ended {
		proc.status = status
		close(proc.done)
		return proc
	}
	go func() { w.finishProc(proc, hostAwaitChild(int(pid))) }()
	return proc
}

// Proc_wait_any is a NON-STANDARD host import (name "proc_wait_any") backing
// the bridge's wait() / waitpid(-1): it waits for ANY process of this
// instance — spawned by Proc_spawn or run by the embedder (NewProc,
// Proc_fork) — to finish, removes it from the process table, and writes its
// pid token at pidOutPtr and its POSIX wait status at statusOutPtr. When
// several have finished, the one with the lowest pid is reported. options is
// the waitpid() options mask; with bit 0 (WNOHANG) the call does not block.
// Returns 0, or a negative errno: ECHILD when the instance has no process at
// all, EAGAIN when WNOHANG is set and none of them has finished yet, EINTR
// when a signal was posted to the guest before one finished.
func (w *WasiStubs) Proc_wait_any(m *Module, options, pidOutPtr, statusOutPtr int32) int32 {
	return w.procWaitAny(m, options, zext(pidOutPtr), zext(statusOutPtr))
}

// Proc_wait_any64 is Proc_wait_any for a memory64 guest.
func (w *WasiStubs) Proc_wait_any64(m *Module, options int32, pidOutPtr, statusOutPtr int64) int32 {
	return w.procWaitAny(m, options, uint64(pidOutPtr), uint64(statusOutPtr))
}

// procWaitAny is the body of Proc_wait_any and Proc_wait_any64.
func (w *WasiStubs) procWaitAny(m *Module, options int32, pidOutPtr, statusOutPtr uint64) int32 {
	pidOut := w.memBytes(m, pidOutPtr, 4)
	statusOut := w.memBytes(m, statusOutPtr, 4)
	if pidOut == nil || statusOut == nil {
		return -_wasiEFAULT
	}
	const wnohang = 1
	for {
		w.mu.Lock()
		if w.sig.reapsChildren() {
			w.reapFinishedLocked()
		}
		if len(w.procs) == 0 {
			w.mu.Unlock()
			return -_wasiECHILD
		}
		var (
			pid  int32
			proc *wasiProc
		)
		for p, pr := range w.procs {
			select {
			case <-pr.done:
				if proc == nil || p < pid {
					pid, proc = p, pr
				}
			default:
			}
		}
		if proc != nil {
			w.dropProcLocked(pid)
			w.mu.Unlock()
			binary.LittleEndian.PutUint32(pidOut, uint32(pid))
			binary.LittleEndian.PutUint32(statusOut, uint32(proc.status))
			return _wasiESUCCESS
		}
		if options&wnohang != 0 {
			w.mu.Unlock()
			return -_wasiEAGAIN
		}
		// Taken under the same hold of w.mu as the scan above: a process
		// that finishes from here on closes exactly this channel.
		if w.procFinished == nil {
			w.procFinished = make(chan struct{})
		}
		finished := w.procFinished
		w.mu.Unlock()
		if !w.awaitInterruptibly(finished) {
			return -_wasiEINTR
		}
	}
}

// Proc_exec is a NON-STANDARD host import (name "proc_exec") backing the
// guest's exec. A guest cannot replace its process image, so it starts the
// command (Proc_spawn), gives up its descriptors, and calls this to wait for
// the command — pid — in the command's name: from here on the instance IS
// the command to everyone else, and every signal posted to the instance
// (PostSignal: Proc_kill from another process of the family, a relayed
// signal of the host process, the instance's own timer) is sent on to the
// command instead of being held for a guest that no longer runs. The guest's
// own dispositions do not apply to the command, so none is dropped as
// ignored or held back as blocked; what a signal does is the command's
// business.
//
// The call returns when the command has ended, with its POSIX wait status at
// statusOutPtr (the process is then reaped), or a negative errno: ECHILD
// when pid is not a process of this instance, EINVAL when it is not a host
// process.
func (w *WasiStubs) Proc_exec(m *Module, pid, statusOutPtr int32) int32 {
	return w.procExec(m, pid, zext(statusOutPtr))
}

// Proc_exec64 is Proc_exec for a memory64 guest.
func (w *WasiStubs) Proc_exec64(m *Module, pid int32, statusOutPtr int64) int32 {
	return w.procExec(m, pid, uint64(statusOutPtr))
}

// procExec is the body of Proc_exec and Proc_exec64.
func (w *WasiStubs) procExec(m *Module, pid int32, statusOutPtr uint64) int32 {
	out := w.memBytes(m, statusOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	proc := w.procs[pid]
	if proc != nil && proc.cmd != nil {
		// Every signal posted is one to pass on. Of the host process's own
		// signals, the ones that would end a process are caught for that;
		// the others (a terminal's job control, the runtime's own use of
		// SIGURG) are not this instance's to repeat.
		w.sig.handled, w.sig.ignored, w.sig.blocked = ^wasiDefaultIgnoredSignals, 0, 0
		w.syncHostSignalsLocked()
	}
	w.mu.Unlock()
	if proc == nil {
		return -_wasiECHILD
	}
	if proc.cmd == nil {
		return -_wasiEINVAL
	}
	for {
		// The signals posted so far, the ones that arrived before the
		// command was the process included.
		w.mu.Lock()
		pending := w.sig.pending
		w.sig.pending = 0
		w.sig.interrupt = false
		w.mu.Unlock()
		for sig := int32(1); sig <= 64; sig++ {
			if pending&wasiSignalBit(sig) == 0 {
				continue
			}
			if hostSig, known := hostSignalOf(sig); known {
				// A command that has just ended cannot take it: nothing
				// to report.
				_ = proc.cmd.Process.Signal(hostSig)
			}
		}
		if w.awaitInterruptibly(proc.done) {
			break
		}
	}
	w.mu.Lock()
	w.dropProcLocked(pid)
	w.execing = false
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(proc.status))
	return _wasiESUCCESS
}

// becameCommand reports whether the process has become the command it
// started (execing).
func (w *WasiStubs) becameCommand() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.execing
}

// awaitInterruptibly blocks the guest until done is closed. It reports false
// when a signal posted to the guest ended the wait first; the caller then
// returns EINTR. An event that has already happened is never reported as
// interrupted.
func (w *WasiStubs) awaitInterruptibly(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
	}
	posted := make(chan struct{})
	if !w.beginBlocking(func() { close(posted) }) {
		return false
	}
	select {
	case <-done:
	case <-posted:
	}
	w.endBlocking()
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// Proc_fork is a NON-STANDARD host import (name "proc_fork") backing the
// bridge's fork(). The fork itself is the embedder's: Proc_fork prepares the
// child's host state (Fork) and its pid token, then calls the hook installed
// with SetForkHook, which snapshots the stopped guest into a new module
// instance and starts it. The hook has returned before Proc_fork does. On
// success the child's pid token is written at pidOutPtr — only then, so a
// snapshot taken by the hook does not contain it; making the child's own
// fork() return 0 is the embedder's job. The child is then a process of this
// instance: Proc_wait / Proc_wait_any reap it, Proc_kill signals it.
//
// Returns 0, or a negative errno: ENOSYS when no hook is installed, EAGAIN
// when the hook failed (the child's descriptors are released and the pid is
// forgotten).
func (w *WasiStubs) Proc_fork(m *Module, pidOutPtr int32) int32 {
	return w.procFork(m, zext(pidOutPtr))
}

// Proc_fork64 is Proc_fork for a memory64 guest.
func (w *WasiStubs) Proc_fork64(m *Module, pidOutPtr int64) int32 {
	return w.procFork(m, uint64(pidOutPtr))
}

// procFork is the body of Proc_fork and Proc_fork64.
func (w *WasiStubs) procFork(m *Module, pidOutPtr uint64) int32 {
	out := w.memBytes(m, pidOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	hook := w.forkHook
	w.mu.Unlock()
	if hook == nil {
		return -_wasiENOSYS
	}
	child := w.Fork()
	proc := &wasiProc{done: make(chan struct{}), inst: child}
	w.mu.Lock()
	pid := w.addProcLocked(proc)
	w.mu.Unlock()
	// Nothing runs on child yet.
	child.pid = pid
	kill, err := hook(m, child, pid, w.procExitFunc(proc))
	if err != nil {
		// The child never ran, so every descriptor it holds is one it
		// shares with w: this drops the references and normally closes
		// nothing.
		closeErr := child.CloseAll()
		w.mu.Lock()
		w.dropProcLocked(pid)
		w.mu.Unlock()
		if closeErr != nil {
			return -mapOSError(closeErr)
		}
		return -_wasiEAGAIN
	}
	w.mu.Lock()
	proc.kill = kill
	w.enterProcLocked(pid)
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(pid))
	return _wasiESUCCESS
}

// Proc_kill is a NON-STANDARD host import (name "proc_kill") backing the
// bridge's kill() for a process other than the caller. sig is the guest's
// signal number (Linux numbering, which is wasi-libc's); 0 only probes that
// the process exists.
//
//   - A host process (Proc_spawn) receives the signal through the OS, under
//     the number the host has for that signal.
//
//   - An embedder-run process (NewProc, Proc_fork) receives it through the
//     kill function the embedder registered. Without one the process exists
//     but cannot be signalled, which is reported as EPERM.
//
//   - A process that has finished but has not been waited for yet is a
//     zombie: as with kill(2), signalling it succeeds and does nothing.
//
//   - The process need not be the caller's child: any process of the fork
//     family is reached by its pid — a sibling, the parent of a pseudo-process
//     that is itself a fork child, a grandchild. (Waiting stays limited to
//     the caller's own children.)
//
//   - A pid that is no process of the family names a process of the host
//     when the guest is the host process (SetHostProcess), and nothing
//     otherwise; see killOutside.
//
//   - A pid of 0 or less names a process group; see killGroup.
//
// Returns 0, or a negative errno: ESRCH for an unknown pid, EINVAL for a
// negative signal number or one the host has no signal for, EPERM when the
// signal could not be delivered.
func (w *WasiStubs) Proc_kill(m *Module, pid, sig int32) int32 {
	if sig < 0 {
		return -_wasiEINVAL
	}
	if pid <= 0 {
		return w.killGroup(pid, sig)
	}
	w.mu.Lock()
	proc := w.pidsLocked().find(pid)
	w.mu.Unlock()
	if proc == nil {
		return w.killOutside(pid, sig)
	}
	kill := proc.kill
	select {
	case <-proc.done:
		return _wasiESUCCESS
	default:
	}
	if proc.cmd != nil {
		hostSig, known := hostSignalOf(sig)
		if !known {
			return -_wasiEINVAL
		}
		// Signal 0 is passed through as well: the OS answers the probe.
		err := proc.cmd.Process.Signal(hostSig)
		switch {
		case err == nil, errors.Is(err, os.ErrProcessDone):
			// ErrProcessDone: it finished after the probe of done above.
			return _wasiESUCCESS
		case errors.Is(err, syscall.EINVAL):
			return -_wasiEINVAL
		default:
			return -_wasiEPERM
		}
	}
	if sig == 0 {
		return _wasiESUCCESS
	}
	if kill == nil || kill(sig) != nil {
		return -_wasiEPERM
	}
	return _wasiESUCCESS
}

// Proc_kill64 is Proc_kill for a memory64 guest.
func (w *WasiStubs) Proc_kill64(m *Module, pid, sig int32) int32 {
	return w.Proc_kill(m, pid, sig)
}

// killOutside signals a process that is not one of the fork family's. Only
// a guest that is the host process can reach any: pid is then a process id
// of the host, unless it is a pid token of this fork family — the token of a
// process that is gone never names a host process, whatever the host uses
// the same number for.
func (w *WasiStubs) killOutside(pid, sig int32) int32 {
	w.mu.Lock()
	host := w.hostProcess
	token := w.pidsLocked().allocated(pid)
	w.mu.Unlock()
	if !host || token || pid <= 0 {
		return -_wasiESRCH
	}
	hostSig, known := hostSignalOf(sig)
	if !known {
		return -_wasiEINVAL
	}
	if int(pid) == os.Getpid() && w.firstOfFamily().takeAsHostProcess(sig) {
		return _wasiESUCCESS
	}
	var err error
	if int(pid) == os.Getpid() {
		err = signalHostSelf(hostSig)
	} else {
		err = signalHostProcess(int(pid), hostSig)
	}
	switch {
	case err == nil:
		return _wasiESUCCESS
	case errors.Is(err, syscall.ESRCH), errors.Is(err, errors.ErrUnsupported):
		return -_wasiESRCH
	case errors.Is(err, syscall.EINVAL):
		return -_wasiEINVAL
	default:
		return -_wasiEPERM
	}
}

// firstOfFamily returns the host state of the first process of the fork
// family: the one that was not forked.
func (w *WasiStubs) firstOfFamily() *WasiStubs {
	for w.parent != nil {
		w = w.parent
	}
	return w
}

// takeAsHostProcess is given a signal that a process of the fork family
// sends to the pid of the host process, which is the pid of this guest. It
// reports whether the signal has been dealt with here: one that the host
// process would only hand on to the guest (see syncHostSignalsLocked) is
// posted to the guest, and one the host process ignores for the guest is
// dropped — at once, as kill(2) has a signal pending for its target by the
// time it returns. The host's own route for such a signal ends at the same
// place, but some time after the sender has gone on: a parent could be told
// that its child had ended before it got the signal the child had sent it
// first.
//
// Any other signal is for the host process to act on (it ends or stops the
// process), and is not dealt with here; nor is any signal once the guest is
// gone or before it has registered.
func (w *WasiStubs) takeAsHostProcess(sig int32) bool {
	if hostSig, known := hostSignalOf(sig); known {
		if _, outside := hostActionsOutside()[hostSig]; outside {
			// Code outside the guest made its own handler the process's
			// action for the signal (an event loop's signal watcher):
			// the process takes it, as it would from anyone.
			return false
		}
	}
	bit := wasiSignalBit(sig)
	uncatchable := wasiSignalBit(wasiSIGKILL) | wasiSignalBit(wasiSIGSTOP)
	w.mu.Lock()
	s := &w.sig
	mine := w.hostProcess && !w.forked && !w.ended && s.flagModule != nil && bit&^uncatchable != 0
	// A signal the guest blocks stays pending for it, whatever its action
	// is, until the guest unblocks it.
	posted := mine && (s.handled|(wasiSignalsHeldByRuntime|s.blocked)&^s.ignored)&bit != 0
	dropped := mine && s.hostIgnored&bit != 0
	w.mu.Unlock()
	if posted {
		w.PostSignal(sig)
	}
	return posted || dropped
}

// encodeWaitStatus turns a Go ProcessState into a POSIX wait status int (the
// raw value os.waitstatus_to_exitcode decodes): a normal exit N becomes
// (N&0xff)<<8 (WIFEXITED); a signal becomes the low-7-bits signal number
// (WIFSIGNALED), in the guest's numbering.
func encodeWaitStatus(st *os.ProcessState) int32 {
	if st == nil {
		return 0
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok {
		return encodeHostWaitStatus(ws)
	}
	code := st.ExitCode()
	if code < 0 {
		code = 127
	}
	return int32(code&0xff) << 8
}

// encodeHostWaitStatus is encodeWaitStatus for the host's wait status of a
// process.
func encodeHostWaitStatus(ws syscall.WaitStatus) int32 {
	if ws.Signaled() {
		if sig := guestSignalOf(ws.Signal()); sig != 0 {
			return sig
		}
		// A signal the guest has no number for: all that can be said is
		// that a signal ended the process, and SIGKILL says the least
		// about which.
		return wasiSIGKILL
	}
	return int32(ws.ExitStatus()&0xff) << 8
}

// mapExecError maps an exec.Command Start() failure to a wasi errno. The
// guest tells the failures apart as execvp does: a file that is not a program
// (ENOEXEC) is handed to the shell, a path through something that is not a
// directory (ENOTDIR) moves a PATH search on.
func mapExecError(err error) int32 {
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return _wasiENOENT
	case errors.Is(err, fs.ErrPermission):
		return _wasiEACCES
	case errors.Is(err, syscall.ENOEXEC):
		return _wasiENOEXEC
	case errors.Is(err, syscall.ENOTDIR):
		return _wasiENOTDIR
	default:
		return _wasiENOENT
	}
}

// Sock_getaddrinfo is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_getaddrinfo") backing the bridge's getaddrinfo(). It reads the
// host string at (nodePtr,nodeLen), consults the resolve whitelist, resolves it
// to an IPv4 address via Go's resolver (numeric IPs pass through), and writes
// the 4-byte network-order address at outPtr. Returns 0 on success or a
// negative POSIX-ish errno (the bridge maps it to an EAI_* code).
func (w *WasiStubs) Sock_getaddrinfo(m *Module, nodePtr, nodeLen, outPtr int32) int32 {
	return w.sockGetaddrinfo(m, zext(nodePtr), nodeLen, zext(outPtr))
}

// Sock_getaddrinfo64 is Sock_getaddrinfo for a memory64 guest.
func (w *WasiStubs) Sock_getaddrinfo64(m *Module, nodePtr int64, nodeLen int32, outPtr int64) int32 {
	return w.sockGetaddrinfo(m, uint64(nodePtr), nodeLen, uint64(outPtr))
}

// sockGetaddrinfo is the body of Sock_getaddrinfo and Sock_getaddrinfo64.
func (w *WasiStubs) sockGetaddrinfo(m *Module, nodePtr uint64, nodeLen int32, outPtr uint64) int32 {
	host := ""
	if nodeLen > 0 {
		b := w.memBytes(m, nodePtr, zext(nodeLen))
		if b == nil {
			return -_wasiEFAULT
		}
		host = string(b)
	}
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	if host == "" {
		binary.LittleEndian.PutUint32(out, 0) // INADDR_ANY
		return _wasiESUCCESS
	}
	w.mu.Lock()
	hook := w.resolveHook
	w.mu.Unlock()
	if hook != nil && !hook(host) {
		return -_wasiEACCES
	}
	// Numeric IPv4 fast path (avoids a resolver call and works offline).
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out[0], out[1], out[2], out[3] = v4[0], v4[1], v4[2], v4[3]
			w.recordResolvedHost(v4.String(), host)
			return _wasiESUCCESS
		}
		return -_wasiEAFNOSUPPORT // this import gives IPv4 addresses; see Sock_resolve
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return -_wasiENOENT
	}
	v4 := ips[0].To4()
	if v4 == nil {
		return -_wasiEAFNOSUPPORT
	}
	out[0], out[1], out[2], out[3] = v4[0], v4[1], v4[2], v4[3]
	w.recordResolvedHost(v4.String(), host)
	return _wasiESUCCESS
}

// recordResolvedHost remembers that host resolved to the address ip (as
// wasiSockAddr.ipText renders it), so a later connect to that address can
// hand the dial hook the host name it was looked up under.
func (w *WasiStubs) recordResolvedHost(ip, host string) {
	w.mu.Lock()
	if w.resolvedHosts == nil {
		w.resolvedHosts = make(map[string]string)
	}
	w.resolvedHosts[ip] = host
	w.mu.Unlock()
}

// SetEnv overrides the environment the guest sees via environ_get /
// environ_sizes_get. By default DefaultWASI leaks the host process
// os.Environ(); a sandboxed embedding should call SetEnv with an
// explicit (possibly empty) slice of "KEY=VALUE" strings.
func (w *WasiStubs) SetEnv(env []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.env = append([]string(nil), env...)
}

// SetArgs overrides os.Args as seen by the guest (argv). Mirrors SetEnv.
func (w *WasiStubs) SetArgs(args []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.args = append([]string(nil), args...)
}

// SetStdin redirects the instance's stdin to r: guest fd 0 and its dups,
// for as long as the guest has not closed or replaced them. A nil r leaves
// the current source.
// Use this to feed input() / sys.stdin from an in-process io.Reader instead
// of the host process stdin.
func (w *WasiStubs) SetStdin(r io.Reader) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r != nil {
		w.stdin = r
	}
}

// SetStdout redirects the instance's stdout to wr: guest fd 1 and its dups,
// for as long as the guest has not closed or replaced them. A nil wr leaves
// the current sink.
func (w *WasiStubs) SetStdout(wr io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if wr != nil {
		w.stdout = wr
	}
}

// SetStderr redirects the instance's stderr to wr: guest fd 2 and its dups,
// for as long as the guest has not closed or replaced them. A nil wr leaves
// the current sink.
func (w *WasiStubs) SetStderr(wr io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if wr != nil {
		w.stderr = wr
	}
}

// checkFS consults the FS policy hook (if any). Returns true when the
// access is permitted. Callers must NOT hold w.mu.
func (w *WasiStubs) checkFS(path string, write bool) bool {
	w.mu.Lock()
	hook := w.fsHook
	w.mu.Unlock()
	if hook == nil {
		return true
	}
	return hook(path, write)
}

// checkNet consults the network policy hook (if any). Returns true when
// the operation is permitted. Callers must NOT hold w.mu.
func (w *WasiStubs) checkNet(op string) bool {
	w.mu.Lock()
	hook := w.netHook
	w.mu.Unlock()
	if hook == nil {
		return true
	}
	return hook(op)
}

// guestMemory returns the guest's linear memory as the guest sees it: the
// first memory.size bytes (memSize) of the module's memory slice. Every
// bound the stubs put on a guest address comes from here, so that an
// address at or past memory.size is refused as wasm refuses it. For a
// shared memory the slice spans the memory's whole ceiling from the start
// and only memSize says how much of it the guest may touch; another agent
// may grow the memory at any moment, which raises memSize and leaves the
// slice and its backing array as they are, so a view taken here stays
// valid. Any other memory's slice is memory.size long.
func (w *WasiStubs) guestMemory(m *Module) []byte {
	return m.memory[:m.memSize.Load()]
}

// memBytes returns the n bytes of guest memory at off, m.memory[off :
// off+n], or nil when any of them lies outside the guest's memory
// (guestMemory; the wasi function should then return EFAULT / EINVAL).
// off and n are the guest's address and size at full width: a wasm32
// guest's zero-extended (zext), a memory64 guest's as they are. No sum of
// them wraps around, so a guest address with bits above the memory's size
// set never aliases memory below it. Callers must hold any locks they need
// on the wasm side; WasiStubs.mu is independent.
func (w *WasiStubs) memBytes(m *Module, off, n uint64) []byte {
	mem := w.guestMemory(m)
	size := uint64(len(mem))
	if off > size || n > size-off {
		return nil
	}
	return mem[off : off+n]
}

// memSlice is memBytes for the i32 address and size of a binding that
// only a wasm32 guest has.
func (w *WasiStubs) memSlice(m *Module, off, n int32) []byte {
	return w.memBytes(m, zext(off), zext(n))
}

// zext widens a wasm32 guest's i32 that stands for an address or a size,
// both unsigned there, to the full width the bindings shared with a
// memory64 guest take.
func zext(v int32) uint64 { return uint64(uint32(v)) }

// wasiABI is the width in bytes of a pointer and of __wasi_size_t in the
// guest's C library: 4 for a wasm32 module, 8 for a memory64 one (LP64).
// The records whose layout depends on it — iovecs, the argv and environ
// tables, prestat, the size a call writes back — are read and written
// through it. A binding knows it by which of its two methods was called:
// the wasm32 one passes wasiABI32, its *64 twin wasiABI64.
type wasiABI uint64

const (
	wasiABI32 wasiABI = 4
	wasiABI64 wasiABI = 8
)

// wordSize is the size of a pointer or __wasi_size_t.
func (a wasiABI) wordSize() uint64 { return uint64(a) }

// word reads the pointer or __wasi_size_t at the start of b.
func (a wasiABI) word(b []byte) uint64 {
	if a == wasiABI32 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

// putWord writes v as a pointer or __wasi_size_t at the start of b.
func (a wasiABI) putWord(b []byte, v uint64) {
	if a == wasiABI32 {
		binary.LittleEndian.PutUint32(b, uint32(v))
		return
	}
	binary.LittleEndian.PutUint64(b, v)
}

// errno values used below (subset; see wasi-libc errno.h).
const (
	_wasiESUCCESS        int32 = 0
	_wasiE2BIG           int32 = 1
	_wasiEACCES          int32 = 2
	_wasiEADDRINUSE      int32 = 3
	_wasiEADDRNOTAVAIL   int32 = 4
	_wasiEAFNOSUPPORT    int32 = 5
	_wasiEAGAIN          int32 = 6
	_wasiEALREADY        int32 = 7
	_wasiEINPROGRESS     int32 = 26
	_wasiENAMETOOLONG    int32 = 37
	_wasiEBADF           int32 = 8
	_wasiECHILD          int32 = 12
	_wasiECONNREFUSED    int32 = 14
	_wasiECONNRESET      int32 = 15
	_wasiENETUNREACH     int32 = 40
	_wasiENOPROTOOPT     int32 = 50
	_wasiENOTCONN        int32 = 53
	_wasiETIMEDOUT       int32 = 73
	_wasiEISCONN         int32 = 30
	_wasiEBUSY           int32 = 10
	_wasiEEXIST          int32 = 20
	_wasiEFAULT          int32 = 21
	_wasiEINTR           int32 = 27
	_wasiEINVAL          int32 = 28
	_wasiEIO             int32 = 29
	_wasiEISDIR          int32 = 31
	_wasiENODEV          int32 = 43
	_wasiENOENT          int32 = 44
	_wasiENOEXEC         int32 = 45
	_wasiENOTDIR         int32 = 54
	_wasiENOTSOCK        int32 = 57
	_wasiENOTSUP         int32 = 58
	_wasiENOTTY          int32 = 59
	_wasiENOSYS          int32 = 52
	_wasiENXIO           int32 = 60
	_wasiEPERM           int32 = 63
	_wasiEPIPE           int32 = 64
	_wasiEPROTONOSUPPORT int32 = 66
	_wasiERANGE          int32 = 68
	_wasiESRCH           int32 = 71
)

// wasiErrnoHostOnly marks an errno the guest is given as an error number of
// the host's that wasi has no number for (EHOSTDOWN, ENOTBLK, ENODATA): the
// number is in the bits below the mark. No wasi errno has the bit (they end
// at 76), and the marked value fits the 16 bits of a wasi errno. A guest
// that shows its program the host's numbers shows the number; any other
// guest treats a marked errno as EIO, which is what such an error was
// reported as before.
const wasiErrnoHostOnly int32 = 0x4000

// wasiHostOnlyErrno returns the marked errno for an error number of the
// host's that wasi has none for; ok is false for a number that cannot be
// carried, and where the host's errors are not told apart by number at all
// (no table of them: see wasiErrno).
func wasiHostOnlyErrno(number syscall.Errno) (errno int32, ok bool) {
	if !hostErrnoKnown() || number <= 0 || int64(number) >= int64(wasiErrnoHostOnly) {
		return 0, false
	}
	return wasiErrnoHostOnly | int32(number), true
}

// mapOSError turns an os/filesystem error into a wasi errno. Used by the
// path-based syscalls so any os.PathError surfaces as the appropriate
// guest-visible code instead of a coarse EIO.
func mapOSError(err error) int32 {
	if err == nil {
		return _wasiESUCCESS
	}
	// The error number of the system call that failed says exactly which
	// error it is; what follows tells only the kinds package os knows
	// apart.
	var number syscall.Errno
	if errors.As(err, &number) {
		if wasi, ok := wasiErrno(number); ok {
			return wasi
		}
		if hostOnly, ok := wasiHostOnlyErrno(number); ok {
			return hostOnly
		}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return _wasiENOENT
	case errors.Is(err, fs.ErrExist):
		return _wasiEEXIST
	case errors.Is(err, syscall.EPERM):
		// before fs.ErrPermission, which stands for EACCES as well
		return _wasiEPERM
	case errors.Is(err, fs.ErrPermission):
		return _wasiEACCES
	case errors.Is(err, syscall.ESRCH):
		return _wasiESRCH
	case errors.Is(err, syscall.ENOTDIR):
		return _wasiENOTDIR
	case errors.Is(err, syscall.EISDIR):
		return _wasiEISDIR
	case errors.Is(err, syscall.EINVAL):
		return _wasiEINVAL
	case errors.Is(err, syscall.EBADF):
		return _wasiEBADF
	case errors.Is(err, syscall.EAGAIN):
		return _wasiEAGAIN
	case errors.Is(err, syscall.EPIPE):
		return _wasiEPIPE
	case errors.Is(err, syscall.ENXIO):
		return _wasiENXIO
	case errors.Is(err, errors.ErrUnsupported):
		return _wasiENOTSUP
	}
	return _wasiEIO
}

// totalBytes sums len(s)+1 over s in a uint64 and reports whether the
// total fits in an int32 (i.e. is representable as a wasm-side i32
// length). Callers route the result through memBytes and an OOB on a
// pathologically long arg list surfaces as EFAULT to the guest rather
// than a host-side panic via a wrapped-int32 length.
func totalBytesPlusNul(ss []string) (int32, bool) {
	var total uint64
	for _, s := range ss {
		total += uint64(len(s)) + 1
		if total > 0x7fffffff {
			return 0, false
		}
	}
	return int32(total), true
}

func (w *WasiStubs) Args_get(m *Module, argv, argvBuf int32) int32 {
	return w.argsGet(m, wasiABI32, zext(argv), zext(argvBuf))
}

// Args_get64 is Args_get for a memory64 guest.
func (w *WasiStubs) Args_get64(m *Module, argv, argvBuf int64) int32 {
	return w.argsGet(m, wasiABI64, uint64(argv), uint64(argvBuf))
}

// argsGet is the body of Args_get and Args_get64.
func (w *WasiStubs) argsGet(m *Module, abi wasiABI, argv, argvBuf uint64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.putStrVec(m, abi, argv, argvBuf, w.args)
}

func (w *WasiStubs) Args_sizes_get(m *Module, argcPtr, argvBufLenPtr int32) int32 {
	return w.argsSizesGet(m, wasiABI32, zext(argcPtr), zext(argvBufLenPtr))
}

// Args_sizes_get64 is Args_sizes_get for a memory64 guest.
func (w *WasiStubs) Args_sizes_get64(m *Module, argcPtr, argvBufLenPtr int64) int32 {
	return w.argsSizesGet(m, wasiABI64, uint64(argcPtr), uint64(argvBufLenPtr))
}

// argsSizesGet is the body of Args_sizes_get and Args_sizes_get64.
func (w *WasiStubs) argsSizesGet(m *Module, abi wasiABI, argcPtr, argvBufLenPtr uint64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.putStrVecSizes(m, abi, argcPtr, argvBufLenPtr, w.args)
}

func (w *WasiStubs) Environ_get(m *Module, envv, envBuf int32) int32 {
	return w.environGet(m, wasiABI32, zext(envv), zext(envBuf))
}

// Environ_get64 is Environ_get for a memory64 guest.
func (w *WasiStubs) Environ_get64(m *Module, envv, envBuf int64) int32 {
	return w.environGet(m, wasiABI64, uint64(envv), uint64(envBuf))
}

// environGet is the body of Environ_get and Environ_get64.
func (w *WasiStubs) environGet(m *Module, abi wasiABI, envv, envBuf uint64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.putStrVec(m, abi, envv, envBuf, w.env)
}

func (w *WasiStubs) Environ_sizes_get(m *Module, envcPtr, envBufLenPtr int32) int32 {
	return w.environSizesGet(m, wasiABI32, zext(envcPtr), zext(envBufLenPtr))
}

// Environ_sizes_get64 is Environ_sizes_get for a memory64 guest.
func (w *WasiStubs) Environ_sizes_get64(m *Module, envcPtr, envBufLenPtr int64) int32 {
	return w.environSizesGet(m, wasiABI64, uint64(envcPtr), uint64(envBufLenPtr))
}

// environSizesGet is the body of Environ_sizes_get and Environ_sizes_get64.
func (w *WasiStubs) environSizesGet(m *Module, abi wasiABI, envcPtr, envBufLenPtr uint64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.putStrVecSizes(m, abi, envcPtr, envBufLenPtr, w.env)
}

// putStrVec writes ss the way args_get and environ_get hand a list of
// strings to the guest: a char* table of len(ss) guest pointers at vec,
// and the NUL-terminated strings they point to packed at buf. Every
// window is validated before anything is written.
func (w *WasiStubs) putStrVec(m *Module, abi wasiABI, vec, buf uint64, ss []string) int32 {
	// The table is len(ss) words; multiply in uint64 so a pathological
	// count cannot wrap.
	vecBytes := uint64(len(ss)) * abi.wordSize()
	if vecBytes > 0x7fffffff {
		return _wasiEFAULT
	}
	vecSlice := w.memBytes(m, vec, vecBytes)
	if vecSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(ss)
	if !ok {
		return _wasiEFAULT
	}
	bufSlice := w.memBytes(m, buf, uint64(total))
	if bufSlice == nil {
		return _wasiEFAULT
	}
	bufOff := uint64(0)
	for i, s := range ss {
		abi.putWord(vecSlice[uint64(i)*abi.wordSize():], buf+bufOff)
		n := copy(bufSlice[bufOff:], s)
		if n < len(s) {
			return _wasiEFAULT
		}
		bufOff += uint64(n)
		bufSlice[bufOff] = 0
		bufOff++
	}
	return _wasiESUCCESS
}

// putStrVecSizes writes what args_sizes_get and environ_sizes_get report
// about ss: its length at countPtr and the bytes its strings take with
// their NULs at bufLenPtr, both __wasi_size_t.
func (w *WasiStubs) putStrVecSizes(m *Module, abi wasiABI, countPtr, bufLenPtr uint64, ss []string) int32 {
	countSlice := w.memBytes(m, countPtr, abi.wordSize())
	bufLenSlice := w.memBytes(m, bufLenPtr, abi.wordSize())
	if countSlice == nil || bufLenSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(ss)
	if !ok {
		return _wasiEFAULT
	}
	abi.putWord(countSlice, uint64(len(ss)))
	abi.putWord(bufLenSlice, uint64(total))
	return _wasiESUCCESS
}

func (w *WasiStubs) Clock_res_get(m *Module, clockID, resPtr int32) int32 {
	return w.clockResGet(m, clockID, zext(resPtr))
}

// Clock_res_get64 is Clock_res_get for a memory64 guest.
func (w *WasiStubs) Clock_res_get64(m *Module, clockID, resPtr int64) int32 {
	return w.clockResGet(m, int32(clockID), uint64(resPtr))
}

// clockResGet is the body of Clock_res_get and Clock_res_get64.
func (w *WasiStubs) clockResGet(m *Module, clockID int32, resPtr uint64) int32 {
	// Report 1ns resolution for both realtime and monotonic — Go's
	// time.Now() resolution is OS-dependent but always claims ns
	// precision in its API.
	out := w.memBytes(m, resPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint64(out, 1)
	return _wasiESUCCESS
}

func (w *WasiStubs) Clock_time_get(m *Module, clockID int32, precision int64, timePtr int32) int32 {
	return w.clockTimeGet(m, clockID, precision, zext(timePtr))
}

// Clock_time_get64 is Clock_time_get for a memory64 guest.
func (w *WasiStubs) Clock_time_get64(m *Module, clockID, precision, timePtr int64) int32 {
	return w.clockTimeGet(m, int32(clockID), precision, uint64(timePtr))
}

// clockTimeGet is the body of Clock_time_get and Clock_time_get64.
func (w *WasiStubs) clockTimeGet(m *Module, clockID int32, precision int64, timePtr uint64) int32 {
	out := w.memBytes(m, timePtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	nanos, errno := w.clockNanos(clockID)
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint64(out, nanos)
	return _wasiESUCCESS
}

// clockNanos reads the clock clock_time_get reports for clockID.
func (w *WasiStubs) clockNanos(clockID int32) (uint64, int32) {
	switch clockID {
	case 0: // CLOCK_REALTIME
		return uint64(time.Now().UnixNano()), _wasiESUCCESS
	case 1: // CLOCK_MONOTONIC
		// A guest that is the host process reads the host's clock, as
		// every process of the host does: it counts from the start of the
		// system, and programs take its readings for large numbers. An
		// isolated guest's clock counts from the start of the instance.
		w.mu.Lock()
		host := w.hostProcess
		nanos := uint64(time.Since(w.monoStart).Nanoseconds())
		w.mu.Unlock()
		if host {
			if reading, known := hostMonotonic(); known {
				return uint64(reading.Nanoseconds()), _wasiESUCCESS
			}
		}
		return nanos, _wasiESUCCESS
	default:
		return 0, _wasiEINVAL
	}
}

// closeWasiOpen releases every underlying handle held by op and
// joins any Close errors so callers can map them to a wasi errno
// instead of silently dropping the failure.
func closeWasiOpen(op *wasiOpen) error {
	op.mu.Lock()
	if op.refs > 0 {
		// another table slot, of this instance (dup/dup2) or of a forked
		// one, still references this descriptor
		op.refs--
		op.mu.Unlock()
		return nil
	}
	conn, listener := op.conn, op.listener
	var accepted []net.Conn
	if op.sock != nil {
		accepted, op.sock.accepted = op.sock.accepted, nil
		if op.sock.dial != nil {
			// The attempt ends, and closes what it may have connected.
			op.sock.dial.cancel()
		}
	}
	op.mu.Unlock()
	var err error
	if op.f != nil {
		err = errors.Join(err, op.f.Close())
	}
	if conn != nil {
		err = errors.Join(err, conn.Close())
	}
	if listener != nil {
		err = errors.Join(err, listener.Close())
	}
	// connections a readiness probe accepted and nobody took
	for _, c := range accepted {
		err = errors.Join(err, c.Close())
	}
	return err
}

// endWasiOpen is closeWasiOpen for an instance that ends, as opposed to a
// guest that closes a descriptor: with leaveStandard, the standard
// descriptors of the host process stay open when the last instance that
// has them goes. The host process is still there, and reports through
// them.
func endWasiOpen(op *wasiOpen, leaveStandard bool) error {
	if leaveStandard {
		op.leaveStandard()
	}
	return closeWasiOpen(op)
}

func (w *WasiStubs) Fd_close(m *Module, fd int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	if op == nil {
		return _wasiEBADF
	}
	closeErr := closeWasiOpen(op)
	delete(w.fdsLocked(), fd)
	if closeErr != nil {
		return mapOSError(closeErr)
	}
	return _wasiESUCCESS
}

// Fd_close64 is Fd_close for a memory64 guest.
func (w *WasiStubs) Fd_close64(m *Module, fd int64) int32 {
	return w.Fd_close(m, int32(fd))
}

func (w *WasiStubs) Fd_fdstat_get(m *Module, fd, ptr int32) int32 {
	return w.fdFdstatGet(m, fd, zext(ptr))
}

// Fd_fdstat_get64 is Fd_fdstat_get for a memory64 guest.
func (w *WasiStubs) Fd_fdstat_get64(m *Module, fd, ptr int64) int32 {
	return w.fdFdstatGet(m, int32(fd), uint64(ptr))
}

// fdFdstatGet is the body of Fd_fdstat_get and Fd_fdstat_get64.
func (w *WasiStubs) fdFdstatGet(m *Module, fd int32, ptr uint64) int32 {
	// fdstat is 24 bytes wide (filetype u8 + flags u16 + rights base/inherit u64+u64).
	out := w.memBytes(m, ptr, 24)
	if out == nil {
		return _wasiEFAULT
	}
	return w.fdstatFill(fd, out)
}

// fdstatFill writes the 24-byte fdstat for fd into out (the struct holds
// no pointers, so its layout is the same for every guest).
func (w *WasiStubs) fdstatFill(fd int32, out []byte) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var ftype byte = 4 // regular file
	var fdflags uint16
	// Every right is granted (the host process is the trust boundary),
	// except that the rights to read and to write say what the descriptor
	// is open for: it is how libc answers fcntl(F_GETFL).
	rights := ^uint64(0)
	if op := w.openLocked(fd); op != nil {
		if read, write := op.access(); !read {
			rights &^= wasiRightFdRead | wasiRightFdReaddir
		} else if !write {
			rights &^= wasiRightFdWrite
		}
		op.mu.Lock()
		if h := op.host(); h != nil {
			ftype = h.filetype(op.dgram)
			if h.terminal() {
				// What tells a terminal from another character device to
				// a libc that has only this record to go by: it cannot be
				// sought on.
				rights &^= wasiRightFdSeek | wasiRightFdTell
			}
		} else if op.stdio != 0 {
			ftype = 2 // a standard stream is a character device
		} else if op.isDir {
			ftype = 3
		} else if op.dgram {
			ftype = 5 // socket_dgram
		} else if op.conn != nil || op.listener != nil || op.isSocket {
			ftype = 6 // socket_stream
		}
		fdflags = uint16(op.fdflags)
		op.mu.Unlock()
		if h := op.host(); h != nil {
			fdflags = uint16(h.fdflags())
		}
	} else if w.rootNumberLocked(fd) {
		ftype = 3 // preopen "/"
	} else {
		return _wasiEBADF
	}
	out[0] = ftype
	out[1] = 0
	binary.LittleEndian.PutUint16(out[2:], fdflags)
	binary.LittleEndian.PutUint64(out[8:], rights)
	binary.LittleEndian.PutUint64(out[16:], ^uint64(0))
	return _wasiESUCCESS
}

// The rights of fd_fdstat_get that tell what a descriptor is open for.
const (
	wasiRightFdRead    uint64 = 1 << 1
	wasiRightFdSeek    uint64 = 1 << 2
	wasiRightFdTell    uint64 = 1 << 5
	wasiRightFdWrite   uint64 = 1 << 6
	wasiRightFdReaddir uint64 = 1 << 14
)

// Fd_fdstat_set_flags maps WASI fdflags to OS file-status flags via the
// per-platform Fcntl wrapper. The flags are also cached on the wasiOpen
// so a subsequent Fd_fdstat_get reflects what the guest set. Standard
// streams store the requested flags but otherwise no-op; sockets/listeners take
// only the cache update because Go's net layer manages blocking mode
// internally.
func (w *WasiStubs) Fd_fdstat_set_flags(m *Module, fd, flags int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return _wasiEBADF
	}
	if h := op.host(); h != nil {
		// The flags are those of the host's open file.
		return mapOSError(h.setFdflags(flags))
	}
	op.mu.Lock()
	op.fdflags = flags
	op.mu.Unlock()
	// Go's stdlib does not expose a portable equivalent of fcntl
	// F_SETFL; treat the call as accepted-but-no-op so wasi-libc
	// callers (which typically set NONBLOCK before a poll loop) still
	// progress without surfacing a spurious error.
	_ = op
	_ = flags
	return _wasiESUCCESS
}

// Fd_fdstat_set_flags64 is Fd_fdstat_set_flags for a memory64 guest.
func (w *WasiStubs) Fd_fdstat_set_flags64(m *Module, fd, flags int64) int32 {
	return w.Fd_fdstat_set_flags(m, int32(fd), int32(flags))
}

// Fd_fdstat_set_rights stores the requested rights on the wasiOpen but
// does not enforce them — the host process is the trust boundary. WASI
// programs that succeed with maximal rights (per Fd_fdstat_get) get the
// same ESUCCESS here.
func (w *WasiStubs) Fd_fdstat_set_rights(m *Module, fd int32, rightsBase, rightsInherit int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.openLocked(fd) == nil {
		return _wasiEBADF
	}
	return _wasiESUCCESS
}

// Fd_fdstat_set_rights64 is Fd_fdstat_set_rights for a memory64 guest.
func (w *WasiStubs) Fd_fdstat_set_rights64(m *Module, fd, rightsBase, rightsInherit int64) int32 {
	return w.Fd_fdstat_set_rights(m, int32(fd), rightsBase, rightsInherit)
}

func (w *WasiStubs) Fd_filestat_get(m *Module, fd, ptr int32) int32 {
	return w.fdFilestatGet(m, fd, zext(ptr))
}

// Fd_filestat_get64 is Fd_filestat_get for a memory64 guest.
func (w *WasiStubs) Fd_filestat_get64(m *Module, fd, ptr int64) int32 {
	return w.fdFilestatGet(m, int32(fd), uint64(ptr))
}

// fdFilestatGet is the body of Fd_filestat_get and Fd_filestat_get64.
func (w *WasiStubs) fdFilestatGet(m *Module, fd int32, ptr uint64) int32 {
	// filestat is 64 bytes wide.
	out := w.memBytes(m, ptr, 64)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	root := op == nil && w.rootNumberLocked(fd)
	w.mu.Unlock()
	if op == nil && !root {
		return _wasiEBADF
	}
	if op == nil || op.f == nil {
		if fi := w.streamFileInfo(op); fi != nil {
			// A standard stream that is a file of the host is that
			// file: a terminal, a pipe, a regular file it was
			// redirected to.
			writeFilestat(out, fi)
			return _wasiESUCCESS
		}
		// Synthesise a minimal stat for the preopen, a socket, or a
		// standard stream the embedder supplied.
		for i := range out {
			out[i] = 0
		}
		// The preopen is a directory (3) and a socket a stream socket
		// (6). An embedder's stream is a pipe to the guest, which WASI
		// has no file type for: it stays "unknown" (0) here, and
		// Fd_filestat_ext names it.
		switch {
		case op == nil:
			out[16] = 3
		case op.dgram:
			out[16] = 5
		case op.isSocket || op.netConn() != nil:
			out[16] = 6
		}
		return _wasiESUCCESS
	}
	st, err := op.f.Stat()
	if err != nil {
		return mapOSError(err)
	}
	writeFilestat(out, st)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_filestat_set_size(m *Module, fd int32, size int64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	if err := op.f.Truncate(size); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_filestat_set_size64 is Fd_filestat_set_size for a memory64 guest.
func (w *WasiStubs) Fd_filestat_set_size64(m *Module, fd, size int64) int32 {
	return w.Fd_filestat_set_size(m, int32(fd), size)
}

func (w *WasiStubs) Fd_filestat_set_times(m *Module, fd int32, atim, mtim int64, fstFlags int32) int32 {
	// fstFlags: 0x1 ATIME, 0x2 ATIME_NOW, 0x4 MTIME, 0x8 MTIME_NOW.
	// atim/mtim are wasi `timestamp` (u64 nanoseconds) — a single i64 each
	// at the wasm ABI, matching the import signature the transpiler derives.
	w.mu.Lock()
	op := w.openLocked(fd)
	fsys := w.fsys
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	var current os.FileInfo
	if filetimesNeedCurrent(fstFlags) {
		st, err := op.f.Stat()
		if err != nil {
			return mapOSError(err)
		}
		current = st
	}
	atime, mtime := resolveFiletimes(uint64(atim), uint64(mtim), fstFlags, current)
	if err := fsys.Chtimes(op.path, atime, mtime); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_filestat_set_times64 is Fd_filestat_set_times for a memory64 guest.
func (w *WasiStubs) Fd_filestat_set_times64(m *Module, fd, atim, mtim, fstFlags int64) int32 {
	return w.Fd_filestat_set_times(m, int32(fd), atim, mtim, int32(fstFlags))
}

// combine64 reconstructs an unsigned 64-bit time value from a pair of
// 32-bit args. WASI signature uses two i32s for the nanosecond timestamp
// in fd_filestat_set_times.
func combine64(hi, lo int32) uint64 {
	return (uint64(uint32(hi)) << 32) | uint64(uint32(lo))
}

// filetimesNeedCurrent reports whether a fstFlags bitmask leaves the access
// or the modification time as it is (neither its explicit nor its "now" bit
// is set), so that the file's current times have to be read first.
func filetimesNeedCurrent(fstFlags int32) bool {
	return fstFlags&(0x1|0x2) == 0 || fstFlags&(0x4|0x8) == 0
}

// resolveFiletimes decides the (atime, mtime) pair to apply given a
// fstFlags bitmask. Bits 0x2 (ATIME_NOW) and 0x8 (MTIME_NOW) override the
// explicit values with time.Now(). A time whose bits are both unset keeps
// its value from current, the file's stat, which the caller supplies
// whenever filetimesNeedCurrent says one is needed.
func resolveFiletimes(atimNs, mtimNs uint64, fstFlags int32, current os.FileInfo) (time.Time, time.Time) {
	now := time.Now()
	var atime, mtime time.Time
	if current != nil {
		atime = fileStatOf(current).atime
		mtime = current.ModTime()
	}
	if fstFlags&0x1 != 0 {
		atime = time.Unix(0, int64(atimNs))
	}
	if fstFlags&0x2 != 0 {
		atime = now
	}
	if fstFlags&0x4 != 0 {
		mtime = time.Unix(0, int64(mtimNs))
	}
	if fstFlags&0x8 != 0 {
		mtime = now
	}
	return atime, mtime
}

func (w *WasiStubs) Fd_prestat_get(m *Module, fd, ptr int32) int32 {
	return w.fdPrestatGet(m, wasiABI32, fd, zext(ptr))
}

// Fd_prestat_get64 is Fd_prestat_get for a memory64 guest.
func (w *WasiStubs) Fd_prestat_get64(m *Module, fd, ptr int64) int32 {
	return w.fdPrestatGet(m, wasiABI64, int32(fd), uint64(ptr))
}

// fdPrestatGet is the body of Fd_prestat_get and Fd_prestat_get64.
func (w *WasiStubs) fdPrestatGet(m *Module, abi wasiABI, fd int32, ptr uint64) int32 {
	// Only fd 3 is reserved as the preopen "/" directory. Returning EBADF
	// for everything else is the wasi-libc convention used to terminate
	// the directory-enumeration loop in __wasilibc_register_preopened_fd.
	if fd != 3 {
		return _wasiEBADF
	}
	// prestat is a u8 tag, padding, then the name's length as a
	// __wasi_size_t aligned to its size: 8 bytes for a wasm32 guest (the
	// length a u32 at 4), 16 for a memory64 one (a u64 at 8).
	out := w.memBytes(m, ptr, 2*abi.wordSize())
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = 0 // preopen tag = directory
	abi.putWord(out[abi.wordSize():], 1)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_prestat_dir_name(m *Module, fd, buf, buflen int32) int32 {
	return w.fdPrestatDirName(m, fd, zext(buf), int64(buflen))
}

// Fd_prestat_dir_name64 is Fd_prestat_dir_name for a memory64 guest.
func (w *WasiStubs) Fd_prestat_dir_name64(m *Module, fd, buf, buflen int64) int32 {
	return w.fdPrestatDirName(m, int32(fd), uint64(buf), buflen)
}

// fdPrestatDirName is the body of Fd_prestat_dir_name and
// Fd_prestat_dir_name64.
func (w *WasiStubs) fdPrestatDirName(m *Module, fd int32, buf uint64, buflen int64) int32 {
	if fd != 3 {
		return _wasiEBADF
	}
	if buflen < 1 {
		return _wasiESUCCESS
	}
	out := w.memBytes(m, buf, uint64(buflen))
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = '/'
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_read(m *Module, fd, iovs, iovsLen, nreadPtr int32) int32 {
	return w.fdRead(m, wasiABI32, fd, zext(iovs), zext(iovsLen), zext(nreadPtr))
}

// Fd_read64 is Fd_read for a memory64 guest.
func (w *WasiStubs) Fd_read64(m *Module, fd, iovs, iovsLen, nreadPtr int64) int32 {
	return w.fdRead(m, wasiABI64, int32(fd), uint64(iovs), uint64(iovsLen), uint64(nreadPtr))
}

// fdRead is the body of Fd_read and Fd_read64.
func (w *WasiStubs) fdRead(m *Module, abi wasiABI, fd int32, iovs, iovsLen, nreadPtr uint64) int32 {
	w.mu.Lock()
	src, op := w.fdSrcLocked(fd)
	w.mu.Unlock()
	if src == nil {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nread is a __wasi_size_t.
	nreadSlice := w.memBytes(m, nreadPtr, abi.wordSize())
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	var n uint64
	served := false
	if h := op.host(); h != nil {
		var errno int32
		if n, errno = w.readHost(h, bufs); errno != _wasiESUCCESS {
			return errno
		}
		served = true
	} else if dg, isDatagram := src.(datagramSocket); isDatagram && op != nil && op.dgram {
		var errno int32
		if n, _, errno = w.receiveDatagram(op, dg, bufs, 0); errno != _wasiESUCCESS {
			return errno
		}
		served = true
	} else if op != nil {
		n, served = op.takeAhead(bufs)
	}
	if !served {
		if stream, blocks := op.readBlocks(src); blocks {
			var errno int32
			if n, errno = w.readStream(op, stream, bufs); errno != _wasiESUCCESS {
				return errno
			}
		} else {
			n = readVec(src, bufs)
		}
	}
	abi.putWord(nreadSlice, n)
	return _wasiESUCCESS
}

// iovecSlices resolves a ciovec/iovec array (iovsLen entries at iovs of a
// guest pointer and a __wasi_size_t each: {u32 ptr, u32 len} for a wasm32
// guest, {u64 ptr, u64 len} for a memory64 one) into the backing memory
// windows. Every entry is validated before any I/O happens, so a bad iovec
// faults the whole call instead of after a partial transfer.
func (w *WasiStubs) iovecSlices(m *Module, abi wasiABI, iovs, iovsLen uint64) ([][]byte, bool) {
	// The array may take up to 2 GiB; bound the count before multiplying
	// so that a pathological iovsLen cannot wrap.
	stride := 2 * abi.wordSize()
	if iovsLen > 0x7fffffff/stride {
		return nil, false
	}
	iovecs := w.memBytes(m, iovs, iovsLen*stride)
	if iovecs == nil {
		return nil, false
	}
	bufs := make([][]byte, 0, iovsLen)
	for i := uint64(0); i < iovsLen; i++ {
		entry := iovecs[i*stride:]
		buf := w.memBytes(m, abi.word(entry), abi.word(entry[abi.wordSize():]))
		if buf == nil {
			return nil, false
		}
		bufs = append(bufs, buf)
	}
	return bufs, true
}

// readVec fills bufs from src in order, stopping at the first error
// (EOF included) or short read; returns the bytes read. Shared by the
// wasm32 and wasm64 fd_read bindings — only the iovec layout differs.
func readVec(src io.Reader, bufs [][]byte) uint64 {
	total, _ := readVecFailure(src, bufs)
	return total
}

// readVecFailure is readVec that also returns the error that ended the
// read, if one did.
func readVecFailure(src io.Reader, bufs [][]byte) (uint64, error) {
	var failure error
	var total uint64
	for _, buf := range bufs {
		n, err := src.Read(buf)
		// A read deadline on a stream is only ever set by a readiness
		// probe, possibly of another instance sharing the descriptor
		// (pollReady); it is not this read's and is cleared as soon as
		// that probe ends.
		for n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			runtime.Gosched()
			n, err = src.Read(buf)
		}
		total += uint64(n)
		if err != nil || n < len(buf) {
			failure = err
			break
		}
	}
	return total, failure
}

// writeVec drains bufs into dst in order, stopping at the first failed
// write; returns the bytes written and that failure. Shared like readVec.
func writeVec(dst io.Writer, bufs [][]byte) (uint64, error) {
	var total uint64
	for _, buf := range bufs {
		n, err := dst.Write(buf)
		total += uint64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// writeFd writes bufs to dst, the destination of the entry op, the way
// write(2) does: a stream takes what it has room for (see writeStream),
// anything else takes all of it. A write that transferred nothing reports
// why (see writeFailure); one that transferred something reports the count,
// and the failure meets the guest's next write.
func (w *WasiStubs) writeFd(op *wasiOpen, dst io.Writer, bufs [][]byte) (uint64, int32) {
	return w.sendFd(op, dst, bufs, 0)
}

// The flags of one send or receive on a socket: what the MSG_ flags of
// send(2) and recv(2) ask for, in the host's own numbering (libc's numbers
// differ from libc to libc). The first two are the bits WASI's sock_recv
// has for them.
const (
	wasiMsgPeek     int32 = 1 // receive: what is received stays where it is
	wasiMsgWaitAll  int32 = 2 // receive: wait until the buffer is full
	wasiMsgDontWait int32 = 4 // this call does not wait, whatever O_NONBLOCK says
	wasiMsgNoSignal int32 = 8 // send: a broken connection is EPIPE without SIGPIPE
)

// sendFd is writeFd for one send on a socket, with its flags (wasiMsg...).
func (w *WasiStubs) sendFd(op *wasiOpen, dst io.Writer, bufs [][]byte, flags int32) (uint64, int32) {
	if op.dgram && len(bufs) > 1 {
		// One write is one datagram, however many pieces it comes in.
		var whole []byte
		for _, buf := range bufs {
			whole = append(whole, buf...)
		}
		bufs = [][]byte{whole}
	}
	if stream, blocks := op.writeBlocks(dst); blocks {
		return w.writeStream(op, stream, bufs, flags)
	}
	n, err := writeVec(dst, bufs)
	if n == 0 && err != nil {
		return 0, w.writeFailure(err, flags)
	}
	return n, _wasiESUCCESS
}

// writeFailure turns a failed write into its errno. Writing to a pipe or
// socket nobody reads from any more is EPIPE, and POSIX has the kernel send
// the writer SIGPIPE as well: it is posted to the guest, whose disposition
// decides — the default ends it, as it ends a process writing into a closed
// pipe. A send that asked for no signal (wasiMsgNoSignal in flags) gets the
// errno alone.
//
// A process that ignores SIGPIPE gets the errno alone too. Code outside the
// guest may have made that the action of the host process (a network
// library ignores SIGPIPE when it is loaded, so that a reset peer is an
// error of the write), and the guest, which is that process, does not die
// of it then.
func (w *WasiStubs) writeFailure(err error, flags int32) int32 {
	errno := mapNetError(err)
	if errno == _wasiEPIPE && flags&wasiMsgNoSignal == 0 && !w.processIgnores(wasiSIGPIPE) {
		w.PostSignal(wasiSIGPIPE)
	}
	return errno
}

// writeStream writes bufs to a stream whose write can block, as the guest
// asked for it. A non-blocking descriptor (O_NONBLOCK) takes what there is
// room for right now and reports EAGAIN when that is nothing. A blocking one
// waits until everything is written; a signal posted to the guest meanwhile
// ends the wait, with EINTR when nothing was written yet and the count
// otherwise. flags are those of a send (wasiMsg...): one that does not wait
// is non-blocking whatever the descriptor says.
func (w *WasiStubs) writeStream(op *wasiOpen, dst streamWriter, bufs [][]byte, flags int32) (uint64, int32) {
	n, errno := w.writeStreamOnce(op, dst, bufs, flags)
	if errno == _wasiEINTR {
		// A signal interrupts a write that has to wait. What there is room
		// for is written all the same, as write(2) takes it from a process
		// with a signal pending — whether the signal was posted before the
		// call or while it was on its way.
		if n, errno := w.writeStreamOnce(op, dst, bufs, flags|wasiMsgDontWait); errno != _wasiEAGAIN {
			w.keepInterrupt()
			return n, errno
		}
	}
	return n, errno
}

// writeStreamOnce is writeStream without the second look of an interrupted
// write.
func (w *WasiStubs) writeStreamOnce(op *wasiOpen, dst streamWriter, bufs [][]byte, flags int32) (uint64, int32) {
	rc, err := dst.SyscallConn()
	if err != nil {
		return 0, w.writeFailure(err, flags)
	}
	nonblocking := op.nonblocking() || flags&wasiMsgDontWait != 0
	// A socket's send timeout bounds the wait, for the turn and for room.
	var until time.Time
	if _, limit := op.timeouts(); !nonblocking && limit > 0 {
		until = time.Now().Add(limit)
	}
	// Only the holder of the turn at the stream's output enters the host's
	// write and sets the deadline that bounds it.
	if nonblocking {
		// Long enough for a writer that is not waiting to be done; one that
		// waits for room has found the stream full.
		if !op.takeOutputTurn(time.Now().Add(pollProbeGrace), nil) {
			return 0, _wasiEAGAIN
		}
	} else if held, interrupted := w.awaitOutputTurn(op, until); !held {
		if interrupted {
			return 0, _wasiEINTR
		}
		return 0, _wasiEAGAIN // the send timeout
	}
	defer op.passOutputTurn()
	if !nonblocking && !w.beginBlocking(func() { _ = dst.SetWriteDeadline(time.Now()) }) {
		return 0, _wasiEINTR
	}
	if !until.IsZero() {
		_ = dst.SetWriteDeadline(until)
	}
	var total uint64
	var failure error
	full, cutShort, timedOut := false, false, false
write:
	for _, buf := range bufs {
		for len(buf) > 0 {
			var n int
			var again bool
			var writeErr error
			waitErr := rc.Write(func(fd uintptr) bool {
				n, again, writeErr = writeRaw(fd, buf)
				// A blocking write waits for room and tries again.
				return nonblocking || !again
			})
			if errors.Is(waitErr, os.ErrDeadlineExceeded) {
				if !nonblocking && w.interruptDue() {
					cutShort = true
					break write
				}
				if !until.IsZero() && !time.Now().Before(until) {
					timedOut = true
					break write
				}
				// Only the holder of the turn sets a deadline, so this one
				// is not the stream's any more: it was left behind.
				_ = dst.SetWriteDeadline(until)
				continue
			}
			if waitErr != nil {
				failure = waitErr
				break write
			}
			total += uint64(n)
			buf = buf[n:]
			if again {
				full = true
				break write
			}
			if writeErr != nil {
				failure = writeErr
				break write
			}
		}
	}
	if (!nonblocking && w.endBlocking()) || !until.IsZero() {
		// The deadline of wake, or of the send timeout, must not outlive
		// this write.
		_ = dst.SetWriteDeadline(time.Time{})
	}
	switch {
	case total > 0:
		return total, _wasiESUCCESS
	case failure != nil:
		return 0, w.writeFailure(failure, flags)
	case cutShort:
		return 0, _wasiEINTR
	case full, timedOut:
		return 0, _wasiEAGAIN
	}
	return 0, _wasiESUCCESS
}

// The ways poll_oneoff learns whether a descriptor can be written.
const (
	pollWriteReady = iota // a write returns at once, with data taken or an error
	pollWriteNever        // nothing will ever make it writable
	pollWriteProbe        // the host has to be asked, and waited on
)

// writeReadiness decides how poll_oneoff treats a subscription for writing
// to the entry op, whose destination is dst (see fdDstLocked); stdin is the
// instance's standard input. When the host has to be asked, stream is what
// to ask about.
//
// A socket that listens, or is bound and not connected, never becomes
// writable. The instance's standard input is writable when it is a host
// stream open both ways, as a terminal is; a descriptor with nothing to
// write to is never writable, except an unconnected socket, where a write
// fails at once. Regular files and destinations the host cannot ask about
// count as writable, as they always did.
func (op *wasiOpen) writeReadiness(dst io.Writer, stdin io.Reader) (stream streamWriter, how int) {
	if op.stdio == 1 {
		dst, _ = stdin.(io.Writer)
	}
	if l, _ := op.netListener(); l != nil && op.netConn() == nil {
		return nil, pollWriteNever
	}
	if dst == nil {
		if op.isSocket {
			return nil, pollWriteReady
		}
		return nil, pollWriteNever
	}
	stream, blocks := op.writeBlocks(dst)
	if !blocks {
		return nil, pollWriteReady
	}
	return stream, pollWriteProbe
}

// probeWritable waits — no longer than the write deadline the caller has
// set — until a write to dst would not block, and reports whether it would
// not. Nothing is written. A descriptor a write would fail on at once (the
// reader of the pipe is gone) counts as writable, as it does for poll(2).
func probeWritable(dst streamWriter) bool {
	rc, err := dst.SyscallConn()
	if err != nil {
		return true // closed under us: the write reports it
	}
	// What is true right now does not depend on the deadline: a deadline
	// that has passed by the time this runs must not hide a stream that
	// has room.
	writable := false
	if err := rc.Control(func(fd uintptr) { writable = fdWritable(fd) }); err != nil || writable {
		return true
	}
	err = rc.Write(func(fd uintptr) bool {
		writable = fdWritable(fd)
		return writable
	})
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return writable
}

// probeWritableUntil is probeWritable bounded for a poll: it waits no longer
// than until (the zero time is no limit), and not after stop is closed —
// first for the turn at the output of op, whose stream dst is, then for
// room. A stream that takes no deadline cannot be asked, and counts as
// writable.
func (op *wasiOpen) probeWritableUntil(dst streamWriter, until time.Time, stop <-chan struct{}) bool {
	if !op.takeOutputTurn(until, stop) {
		// Whoever holds the turn is waiting for room: there is none.
		return false
	}
	defer op.passOutputTurn()
	if err := dst.SetWriteDeadline(until); err != nil {
		return true
	}
	probed, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-stop:
			_ = dst.SetWriteDeadline(time.Now())
		case <-probed:
		}
	}()
	writable := probeWritable(dst)
	close(probed)
	<-watched
	// Leave no deadline behind: later writes to the stream must block.
	_ = dst.SetWriteDeadline(time.Time{})
	return writable
}

// fdSrcLocked returns the io.Reader for fd and (when applicable) the
// wasiOpen it came from, or nil if fd is invalid. Caller must hold w.mu.
func (w *WasiStubs) fdSrcLocked(fd int32) (io.Reader, *wasiOpen) {
	// The table decides what an fd is, fd 0 included: an entry for the
	// instance's stdin reads from the stream configured right now.
	op := w.openLocked(fd)
	if op == nil {
		return nil, nil
	}
	if op.noRead {
		// not open for reading: there is nothing to read from
		return nil, op
	}
	if op.stdio == 1 {
		return w.stdin, op
	}
	if op.f != nil {
		return op.f, op
	}
	if conn := op.netConn(); conn != nil {
		return conn, op
	}
	return nil, op
}

// fdDstLocked returns the io.Writer for fd or nil if fd is invalid.
// Caller must hold w.mu.
func (w *WasiStubs) fdDstLocked(fd int32) (io.Writer, *wasiOpen) {
	op := w.openLocked(fd)
	if op == nil {
		return nil, nil
	}
	if op.noWrite {
		// not open for writing: there is nothing to write to
		return nil, op
	}
	switch op.stdio {
	case 2:
		return w.stdout, op
	case 3:
		return w.stderr, op
	}
	if op.f != nil {
		return op.f, op
	}
	if conn := op.netConn(); conn != nil {
		return conn, op
	}
	return nil, op
}

func (w *WasiStubs) Fd_pread(m *Module, fd, iovs, iovsLen int32, offset int64, nreadPtr int32) int32 {
	return w.fdPread(m, wasiABI32, fd, zext(iovs), zext(iovsLen), offset, zext(nreadPtr))
}

// Fd_pread64 is Fd_pread for a memory64 guest.
func (w *WasiStubs) Fd_pread64(m *Module, fd, iovs, iovsLen, offset, nreadPtr int64) int32 {
	return w.fdPread(m, wasiABI64, int32(fd), uint64(iovs), uint64(iovsLen), offset, uint64(nreadPtr))
}

// fdPread is the body of Fd_pread and Fd_pread64: it reads into the
// buffers of the iovecs from offset in the file, and stops at the end of
// the file, at an error or at a short read.
func (w *WasiStubs) fdPread(m *Module, abi wasiABI, fd int32, iovs, iovsLen uint64, offset int64, nreadPtr uint64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil || op.noRead {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nread is a __wasi_size_t.
	nreadSlice := w.memBytes(m, nreadPtr, abi.wordSize())
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	var total uint64
	curOff := offset
	for _, buf := range bufs {
		n, err := op.f.ReadAt(buf, curOff)
		total += uint64(n)
		curOff += int64(n)
		if err != nil || n < len(buf) {
			break
		}
	}
	abi.putWord(nreadSlice, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_pwrite(m *Module, fd, iovs, iovsLen int32, offset int64, nwrittenPtr int32) int32 {
	return w.fdPwrite(m, wasiABI32, fd, zext(iovs), zext(iovsLen), offset, zext(nwrittenPtr))
}

// Fd_pwrite64 is Fd_pwrite for a memory64 guest.
func (w *WasiStubs) Fd_pwrite64(m *Module, fd, iovs, iovsLen, offset, nwrittenPtr int64) int32 {
	return w.fdPwrite(m, wasiABI64, int32(fd), uint64(iovs), uint64(iovsLen), offset, uint64(nwrittenPtr))
}

// fdPwrite is the body of Fd_pwrite and Fd_pwrite64: it writes the
// buffers of the iovecs from offset in the file, and stops at an error.
func (w *WasiStubs) fdPwrite(m *Module, abi wasiABI, fd int32, iovs, iovsLen uint64, offset int64, nwrittenPtr uint64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil || op.noWrite {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nwritten is a __wasi_size_t.
	nwSlice := w.memBytes(m, nwrittenPtr, abi.wordSize())
	if !ok || nwSlice == nil {
		return _wasiEFAULT
	}
	var total uint64
	curOff := offset
	for _, buf := range bufs {
		n, err := op.f.WriteAt(buf, curOff)
		total += uint64(n)
		curOff += int64(n)
		if err != nil {
			break
		}
	}
	abi.putWord(nwSlice, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_seek(m *Module, fd int32, offset int64, whence, newOffPtr int32) int32 {
	return w.fdSeek(m, fd, offset, whence, zext(newOffPtr))
}

// Fd_seek64 is Fd_seek for a memory64 guest.
func (w *WasiStubs) Fd_seek64(m *Module, fd, offset, whence, newOffPtr int64) int32 {
	return w.fdSeek(m, int32(fd), offset, int32(whence), uint64(newOffPtr))
}

// fdSeek is the body of Fd_seek and Fd_seek64.
func (w *WasiStubs) fdSeek(m *Module, fd int32, offset int64, whence int32, newOffPtr uint64) int32 {
	out := w.memBytes(m, newOffPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	n, err := op.f.Seek(offset, int(whence))
	if err != nil {
		return _wasiEINVAL
	}
	binary.LittleEndian.PutUint64(out, uint64(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_tell(m *Module, fd, offsetPtr int32) int32 {
	return w.fdTell(m, fd, zext(offsetPtr))
}

// Fd_tell64 is Fd_tell for a memory64 guest.
func (w *WasiStubs) Fd_tell64(m *Module, fd, offsetPtr int64) int32 {
	return w.fdTell(m, int32(fd), uint64(offsetPtr))
}

// fdTell is the body of Fd_tell and Fd_tell64.
func (w *WasiStubs) fdTell(m *Module, fd int32, offsetPtr uint64) int32 {
	out := w.memBytes(m, offsetPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	n, err := op.f.Seek(0, 1) // SEEK_CUR
	if err != nil {
		return _wasiEIO
	}
	binary.LittleEndian.PutUint64(out, uint64(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_write(m *Module, fd, iovs, iovsLen, nwrittenPtr int32) int32 {
	return w.fdWrite(m, wasiABI32, fd, zext(iovs), zext(iovsLen), zext(nwrittenPtr))
}

// Fd_write64 is Fd_write for a memory64 guest.
func (w *WasiStubs) Fd_write64(m *Module, fd, iovs, iovsLen, nwrittenPtr int64) int32 {
	return w.fdWrite(m, wasiABI64, int32(fd), uint64(iovs), uint64(iovsLen), uint64(nwrittenPtr))
}

// fdWrite is the body of Fd_write and Fd_write64.
func (w *WasiStubs) fdWrite(m *Module, abi wasiABI, fd int32, iovs, iovsLen, nwrittenPtr uint64) int32 {
	w.mu.Lock()
	dst, op := w.fdDstLocked(fd)
	w.mu.Unlock()
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nwritten is a __wasi_size_t.
	nwrittenSlice := w.memBytes(m, nwrittenPtr, abi.wordSize())
	if !ok || nwrittenSlice == nil {
		return _wasiEFAULT
	}
	if dst == nil {
		abi.putWord(nwrittenSlice, 0)
		return _wasiEBADF
	}
	var n uint64
	var errno int32
	if h := op.host(); h != nil {
		n, errno = w.writeHost(op, h, bufs)
	} else {
		n, errno = w.writeFd(op, dst, bufs)
	}
	abi.putWord(nwrittenSlice, n)
	return errno
}

func (w *WasiStubs) Fd_sync(m *Module, fd int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	if err := op.f.Sync(); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_sync64 is Fd_sync for a memory64 guest.
func (w *WasiStubs) Fd_sync64(m *Module, fd int64) int32 {
	return w.Fd_sync(m, int32(fd))
}

func (w *WasiStubs) Fd_datasync(m *Module, fd int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	// fdatasync skips metadata; the portable Sync() is a strict
	// superset (also flushes metadata) and satisfies the wasi spec.
	if err := op.f.Sync(); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_datasync64 is Fd_datasync for a memory64 guest.
func (w *WasiStubs) Fd_datasync64(m *Module, fd int64) int32 {
	return w.Fd_datasync(m, int32(fd))
}

func (w *WasiStubs) Fd_advise(m *Module, fd int32, offset, length int64, advice int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	// posix_fadvise is a hint; the spec lets implementations no-op it.
	_, _, _ = offset, length, advice
	return _wasiESUCCESS
}

// Fd_advise64 is Fd_advise for a memory64 guest.
func (w *WasiStubs) Fd_advise64(m *Module, fd, offset, length, advice int64) int32 {
	return w.Fd_advise(m, int32(fd), offset, length, int32(advice))
}

func (w *WasiStubs) Fd_allocate(m *Module, fd int32, offset, length int64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	// fallocate "reserves" space; the portable equivalent is Truncate
	// to offset+length so the file is at least the requested size.
	if err := op.f.Truncate(offset + length); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_allocate64 is Fd_allocate for a memory64 guest.
func (w *WasiStubs) Fd_allocate64(m *Module, fd, offset, length int64) int32 {
	return w.Fd_allocate(m, int32(fd), offset, length)
}

// Path_chmod is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "path_chmod") backing a bridge-provided chmod(): WASI preview1 has
// no way to change file modes. The path at (pathPtr,pathLen) is
// preopen-relative, like path_open's. Returns 0 or a negative errno.
func (w *WasiStubs) Path_chmod(m *Module, pathPtr, pathLen, mode int32) int32 {
	return w.pathChmod(m, zext(pathPtr), pathLen, mode)
}

// Path_chmod64 is Path_chmod for a memory64 guest.
func (w *WasiStubs) Path_chmod64(m *Module, pathPtr int64, pathLen, mode int32) int32 {
	return w.pathChmod(m, uint64(pathPtr), pathLen, mode)
}

// pathChmod is the body of Path_chmod and Path_chmod64.
func (w *WasiStubs) pathChmod(m *Module, pathPtr uint64, pathLen, mode int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if err := fsys.Chmod(string(pathSlice), unixFileMode(uint32(mode))); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_chmod is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_chmod") backing a bridge-provided fchmod(). Returns 0 or a
// negative errno.
func (w *WasiStubs) Fd_chmod(m *Module, fd, mode int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if op.f == nil {
		return -_wasiEINVAL
	}
	if err := op.f.Chmod(unixFileMode(uint32(mode))); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_chmod64 is Fd_chmod for a memory64 guest.
func (w *WasiStubs) Fd_chmod64(m *Module, fd, mode int32) int32 {
	return w.Fd_chmod(m, fd, mode)
}

// Path_access is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "path_access") backing access() and faccessat(): whether the program
// may read, write or run a file, or find it at all. WASI preview1 has no
// call that says so: wasi-libc's faccessat looks at the rights of the
// preopened directory alone, which every file under it shares, and never at
// X_OK, so a file of mode 0600 was runnable and one of mode 0400 writable.
// The path at (pathPtr,pathLen) is preopen-relative, like path_open's; amode
// is access's (F_OK 0, or any of X_OK 1, W_OK 2, R_OK 4); flags bit 0
// (wasiAccessEffective) asks with the effective ids instead of the real ones,
// as AT_EACCESS does.
//
// A file of the host's filesystem is asked about with the host's own check
// (faccessat(2)), which also knows access control lists and read-only
// mounts; a file of another backend by its mode bits and owner, for the ids
// the guest has (Proc_ids). Returns 0, or a negative errno: EACCES when the
// access is refused, ENOENT and the like when the file cannot be found,
// EINVAL for an amode or flags it does not know.
func (w *WasiStubs) Path_access(m *Module, pathPtr, pathLen, amode, flags int32) int32 {
	return w.pathAccess(m, zext(pathPtr), pathLen, amode, flags)
}

// Path_access64 is Path_access for a memory64 guest.
func (w *WasiStubs) Path_access64(m *Module, pathPtr int64, pathLen, amode, flags int32) int32 {
	return w.pathAccess(m, uint64(pathPtr), pathLen, amode, flags)
}

// pathAccess is the body of Path_access and Path_access64.
func (w *WasiStubs) pathAccess(m *Module, pathPtr uint64, pathLen, amode, flags int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	if amode&^(wasiAccessRead|wasiAccessWrite|wasiAccessExec) != 0 || flags&^wasiAccessEffective != 0 {
		return -_wasiEINVAL
	}
	path := string(pathSlice)
	if !w.checkFS(path, false) {
		return -_wasiEACCES
	}
	effective := flags&wasiAccessEffective != 0
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if located, can := fsys.(interface {
		HostPath(name string) (string, error)
	}); can {
		if host, err := located.HostPath(path); err == nil {
			if errno, asked := hostAccess(host, uint32(amode), effective); asked {
				return -errno
			}
		} else if !errors.Is(err, errors.ErrUnsupported) {
			return -mapOSError(err)
		}
	}
	fi, err := fsys.Stat(path)
	if err != nil {
		return -mapOSError(err)
	}
	if amode == 0 {
		return _wasiESUCCESS
	}
	uid, gid := w.accessIDs(effective)
	if !modeAllows(fi, fileStatOf(fi), uint32(amode), uid, gid, w.accessGroups()) {
		return -_wasiEACCES
	}
	return _wasiESUCCESS
}

// The bits of Path_access's amode (access's R_OK, W_OK, X_OK) and flags.
const (
	wasiAccessExec      int32 = 1
	wasiAccessWrite     int32 = 2
	wasiAccessRead      int32 = 4
	wasiAccessEffective int32 = 1
)

// accessIDs returns the user and group id the guest asks Path_access with:
// its real ones, or its effective ones (Proc_ids reports both).
func (w *WasiStubs) accessIDs(effective bool) (uid, gid uint32) {
	if !w.hostIdentity() {
		return 0, 0
	}
	if effective {
		return uint32(os.Geteuid()), uint32(os.Getegid())
	}
	return uint32(os.Getuid()), uint32(os.Getgid())
}

// accessGroups returns the supplementary groups of the guest: the host
// process's when the guest has its identity, none otherwise.
func (w *WasiStubs) accessGroups() []uint32 {
	if !w.hostIdentity() {
		return nil
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil
	}
	out := make([]uint32, len(groups))
	for i, g := range groups {
		out[i] = uint32(g)
	}
	return out
}

// modeAllows reports whether a process of user uid and group gid (with the
// supplementary groups) may make the accesses of amode to the file fi
// describes, by its mode bits, as access(2) decides without access control
// lists: the owner's bits for its owner, the group's for a member of its
// group, the others' for the rest; uid 0 may read and write anything, and
// run what has any x bit, or search any directory.
func modeAllows(fi os.FileInfo, st fileStat, amode, uid, gid uint32, groups []uint32) bool {
	perm := uint32(fi.Mode().Perm())
	if uid == 0 {
		return amode&uint32(wasiAccessExec) == 0 || fi.IsDir() || perm&0o111 != 0
	}
	shift := uint32(0)
	member := st.gid == gid
	for _, g := range groups {
		member = member || g == st.gid
	}
	switch {
	case st.uid == uid:
		shift = 6
	case member:
		shift = 3
	}
	return (perm>>shift)&amode == amode
}

// Proc_umask is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "proc_umask") backing a bridge-provided umask(): it sets the
// instance's file mode creation mask and returns the previous one. The
// mask applies to every file and directory the instance creates from then
// on, and a forked instance starts with its parent's (see Fork).
//
// When the guest is the host process (SetHostProcess) the host process
// follows, as it does the working directory (Proc_chdir): code of the host
// that runs for the program (a native extension creating a file) creates
// with the mask the program set. A forked process's mask stays its own.
func (w *WasiStubs) Proc_umask(m *Module, mask int32) int32 {
	next := os.FileMode(uint32(mask) & 0o777)
	w.mu.Lock()
	defer w.mu.Unlock()
	prev := processUmask()
	if w.umask != nil {
		prev = *w.umask
	}
	w.umask = &next
	if w.hostProcess && !w.forked {
		setProcessUmask(next)
	}
	return int32(prev)
}

// Proc_umask64 is Proc_umask for a memory64 guest.
func (w *WasiStubs) Proc_umask64(m *Module, mask int32) int32 {
	return w.Proc_umask(m, mask)
}

// createMode returns the mode a file or directory the guest creates with
// the requested mode gets: the instance's umask taken out of it.
func (w *WasiStubs) createMode(requested os.FileMode) os.FileMode {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.umask != nil {
		return requested &^ *w.umask
	}
	return requested &^ processUmask()
}

// Path_open_mode is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "path_open_mode") backing a bridge-provided
// open(): path_open cannot carry the mode argument of open(2), so every
// file it creates gets the default 0666. This one takes the same arguments
// for a preopen-relative path, plus that mode, and writes the new fd at
// openedFdPtr. Returns 0 or a negative errno.
func (w *WasiStubs) Path_open_mode(m *Module, dirflags, pathPtr, pathLen, oflags int32, fsRightsBase int64, fdflags, mode, openedFdPtr int32) int32 {
	return w.openGuestPathMode(m, dirflags, zext(pathPtr), pathLen, oflags, fsRightsBase, fdflags, mode, zext(openedFdPtr))
}

// Path_open_mode64 is Path_open_mode for a memory64 guest.
func (w *WasiStubs) Path_open_mode64(m *Module, dirflags int32, pathPtr int64, pathLen, oflags int32, fsRightsBase int64, fdflags, mode int32, openedFdPtr int64) int32 {
	return w.openGuestPathMode(m, dirflags, uint64(pathPtr), pathLen, oflags, fsRightsBase, fdflags, mode, uint64(openedFdPtr))
}

// openGuestPathMode is the body of Path_open_mode and Path_open_mode64.
func (w *WasiStubs) openGuestPathMode(m *Module, dirflags int32, pathPtr uint64, pathLen, oflags int32, fsRightsBase int64, fdflags, mode int32, openedFdPtr uint64) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	outSlice := w.memBytes(m, openedFdPtr, 4)
	if pathSlice == nil || outSlice == nil {
		return -_wasiEFAULT
	}
	fd, errno := w.pathOpenMode(string(pathSlice), dirflags, oflags, fsRightsBase, fdflags, os.FileMode(uint32(mode)&0o777))
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(outSlice, uint32(fd))
	return _wasiESUCCESS
}

// Path_create_directory_mode is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "path_create_directory_mode") backing a
// bridge-provided mkdir(): path_create_directory cannot carry the mode
// argument of mkdir(2). The path is preopen-relative. Returns 0 or a
// negative errno.
func (w *WasiStubs) Path_create_directory_mode(m *Module, pathPtr, pathLen, mode int32) int32 {
	return w.pathCreateDirectoryMode(m, zext(pathPtr), pathLen, mode)
}

// Path_create_directory_mode64 is Path_create_directory_mode for a memory64 guest.
func (w *WasiStubs) Path_create_directory_mode64(m *Module, pathPtr int64, pathLen, mode int32) int32 {
	return w.pathCreateDirectoryMode(m, uint64(pathPtr), pathLen, mode)
}

// pathCreateDirectoryMode is the body of Path_create_directory_mode and
// Path_create_directory_mode64.
func (w *WasiStubs) pathCreateDirectoryMode(m *Module, pathPtr uint64, pathLen, mode int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	return -w.pathCreateDirectory(string(pathSlice), os.FileMode(uint32(mode)&0o777))
}

// pathCreateDirectory creates the directory rel with the requested mode,
// less the instance's umask, and returns a wasi errno.
func (w *WasiStubs) pathCreateDirectory(rel string, mode os.FileMode) int32 {
	if !w.checkFS(rel, true) {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if err := fsys.Mkdir(rel, w.createMode(mode)); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_flock is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_flock") backing a bridge-provided flock(). lock is 0 to unlock,
// 1 for a shared and 2 for an exclusive lock; wait is non-zero when the
// call may block until the lock is granted, and otherwise a lock held
// elsewhere makes it fail with EAGAIN. The lock belongs to the open
// descriptor: every fd that shares it (dup, fork) shares the lock, and the
// lock goes when the last of them is closed. Returns 0 or a negative errno;
// a waiting call ends with EINTR when a signal is posted to the guest.
func (w *WasiStubs) Fd_flock(m *Module, fd, lock, wait int32) int32 {
	var kind FileLock
	switch lock {
	case 0:
		kind = FileUnlock
	case 1:
		kind = FileLockShared
	case 2:
		kind = FileLockExclusive
	default:
		return -_wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	fsys := w.fsys
	var stream any
	if op != nil {
		switch op.stdio {
		case 1:
			stream = w.stdin
		case 2:
			stream = w.stdout
		case 3:
			stream = w.stderr
		}
	}
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	var try func() error
	switch {
	case op.host() != nil:
		try = func() error { return op.host().flock(kind) }
	case op.f != nil:
		try = func() error { return fsys.Flock(op.f, kind, false) }
	case op.stdio != 0:
		// A standard stream is outside the FS backend. One that is a file
		// of the host process is locked as such; any other (a buffer, a
		// pipe to the embedder) has no other opener to exclude.
		f, ok := stream.(*os.File)
		if !ok {
			return _wasiESUCCESS
		}
		try = func() error { return flockOSFile(f, kind, false) }
	default:
		return -_wasiEINVAL
	}
	// A lock held elsewhere is waited for by trying again, at growing
	// intervals: a blocked lock request cannot be withdrawn, and the wait
	// has to end when a signal is posted to the guest.
	retry := flockRetryMin
	for {
		err := try()
		if err == nil {
			return _wasiESUCCESS
		}
		if wait == 0 || kind == FileUnlock || !errors.Is(err, syscall.EAGAIN) {
			return -mapOSError(err)
		}
		posted := make(chan struct{})
		if !w.beginBlocking(func() { close(posted) }) {
			return -_wasiEINTR
		}
		timer := time.NewTimer(retry)
		select {
		case <-timer.C:
		case <-posted:
			timer.Stop()
		}
		if w.endBlocking() {
			return -_wasiEINTR
		}
		if retry *= 2; retry > flockRetryMax {
			retry = flockRetryMax
		}
	}
}

// Fd_flock64 is Fd_flock for a memory64 guest.
func (w *WasiStubs) Fd_flock64(m *Module, fd, lock, wait int32) int32 {
	return w.Fd_flock(m, fd, lock, wait)
}

// recordLock is a POSIX record lock as Fd_lock passes it: the record at
// its lockPtr, 32 bytes, little-endian.
//
//	i32 type    0 F_RDLCK, 1 F_WRLCK, 2 F_UNLCK
//	i32 whence  0 SEEK_SET, 1 SEEK_CUR, 2 SEEK_END
//	i64 start
//	i64 len     0: to the end of the file, however long it grows
//	i32 pid     F_GETLK: the process that holds the lock in the way
//	i32 (pad)
type recordLock struct {
	typ, whence int32
	start, len  int64
	pid         int32
}

// The commands of Fd_lock.
const (
	recordLockGet  int32 = 0 // F_GETLK
	recordLockSet  int32 = 1 // F_SETLK
	recordLockWait int32 = 2 // F_SETLKW
)

// Fd_lock is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_lock") backing fcntl's F_GETLK, F_SETLK and F_SETLKW: a POSIX
// record lock of a file, by the host's fcntl(2). cmd is recordLockGet,
// recordLockSet or recordLockWait, and lockPtr the lock (recordLock).
// recordLockGet writes back the lock that would be in the way of the one
// asked about, or that one with type F_UNLCK when none would. A lock held
// elsewhere is waited for (recordLockWait) by trying again, as Fd_flock
// does, until a signal is posted to the guest (EINTR). Returns 0 or a
// negative errno: EAGAIN or EACCES for a lock held elsewhere, ENOTSUP for a
// descriptor with no file of the host behind it (a stream of the
// embedder's, a file of an in-memory filesystem), which has no other
// process to exclude.
func (w *WasiStubs) Fd_lock(m *Module, fd, cmd, lockPtr int32) int32 {
	return w.fdLock(m, fd, cmd, zext(lockPtr))
}

// Fd_lock64 is Fd_lock for a memory64 guest.
func (w *WasiStubs) Fd_lock64(m *Module, fd, cmd int32, lockPtr int64) int32 {
	return w.fdLock(m, fd, cmd, uint64(lockPtr))
}

// fdLock is the body of Fd_lock and Fd_lock64.
func (w *WasiStubs) fdLock(m *Module, fd, cmd int32, lockPtr uint64) int32 {
	rec := w.memBytes(m, lockPtr, 32)
	if rec == nil {
		return -_wasiEFAULT
	}
	lk := recordLock{
		typ:    int32(binary.LittleEndian.Uint32(rec[0:])),
		whence: int32(binary.LittleEndian.Uint32(rec[4:])),
		start:  int64(binary.LittleEndian.Uint64(rec[8:])),
		len:    int64(binary.LittleEndian.Uint64(rec[16:])),
	}
	if cmd < recordLockGet || cmd > recordLockWait || lk.typ < 0 || lk.typ > 2 || lk.whence < 0 || lk.whence > 2 {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	var file func(use func(fd uintptr) error) error
	switch {
	case op.host() != nil:
		file = op.host().withNumber
	default:
		f, ok := op.f.(*os.File)
		if !ok {
			return -_wasiENOTSUP
		}
		file = func(use func(fd uintptr) error) error {
			rc, err := f.SyscallConn()
			if err != nil {
				return err
			}
			var useErr error
			if err := rc.Control(func(fd uintptr) { useErr = use(fd) }); err != nil {
				return err
			}
			return useErr
		}
	}
	if cmd == recordLockGet {
		err := file(func(fd uintptr) error { return hostRecordLock(fd, recordLockGet, &lk) })
		if err != nil {
			return -mapOSError(err)
		}
		binary.LittleEndian.PutUint32(rec[0:], uint32(lk.typ))
		binary.LittleEndian.PutUint32(rec[4:], uint32(lk.whence))
		binary.LittleEndian.PutUint64(rec[8:], uint64(lk.start))
		binary.LittleEndian.PutUint64(rec[16:], uint64(lk.len))
		binary.LittleEndian.PutUint32(rec[24:], uint32(lk.pid))
		return _wasiESUCCESS
	}
	// A blocked lock request cannot be withdrawn, and the wait has to end
	// when a signal is posted to the guest: a lock held elsewhere is waited
	// for by trying again, at growing intervals.
	retry := flockRetryMin
	for {
		err := file(func(fd uintptr) error { return hostRecordLock(fd, recordLockSet, &lk) })
		if err == nil {
			return _wasiESUCCESS
		}
		if cmd != recordLockWait || lk.typ == 2 || !(errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES)) {
			return -mapOSError(err)
		}
		posted := make(chan struct{})
		if !w.beginBlocking(func() { close(posted) }) {
			return -_wasiEINTR
		}
		timer := time.NewTimer(retry)
		select {
		case <-timer.C:
		case <-posted:
			timer.Stop()
		}
		if w.endBlocking() {
			return -_wasiEINTR
		}
		if retry *= 2; retry > flockRetryMax {
			retry = flockRetryMax
		}
	}
}

// The interval at which a waiting Fd_flock tries again: it starts at the
// minimum and doubles up to the maximum.
const (
	flockRetryMin = 500 * time.Microsecond
	flockRetryMax = 20 * time.Millisecond
)

// Path_filestat_ext is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "path_filestat_ext") backing a
// bridge-provided stat/lstat: WASI's filestat carries neither permission
// bits nor an owner, and its file types have no FIFO, so the bridge merges
// them in from here. The path is preopen-relative; follow selects stat vs
// lstat semantics. Writes three little-endian u32 at outPtr — the POSIX
// mode (the file type bits, unixType*, and the low twelve mode bits), the
// uid, the gid — and returns 0 or a negative errno.
func (w *WasiStubs) Path_filestat_ext(m *Module, pathPtr, pathLen, follow, outPtr int32) int32 {
	return w.pathFilestatExt(m, zext(pathPtr), pathLen, follow, zext(outPtr))
}

// Path_filestat_ext64 is Path_filestat_ext for a memory64 guest.
func (w *WasiStubs) Path_filestat_ext64(m *Module, pathPtr int64, pathLen, follow int32, outPtr int64) int32 {
	return w.pathFilestatExt(m, uint64(pathPtr), pathLen, follow, uint64(outPtr))
}

// pathFilestatExt is the body of Path_filestat_ext and Path_filestat_ext64.
func (w *WasiStubs) pathFilestatExt(m *Module, pathPtr uint64, pathLen, follow int32, outPtr uint64) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	out := w.memBytes(m, outPtr, wasiFilestatExtSize)
	if pathSlice == nil || out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	var fi os.FileInfo
	var err error
	if follow != 0 {
		fi, err = fsys.Stat(string(pathSlice))
	} else {
		fi, err = fsys.Lstat(string(pathSlice))
	}
	if err != nil {
		return -mapOSError(err)
	}
	writeFilestatExt(out, fi)
	return _wasiESUCCESS
}

// Fd_filestat_ext is Path_filestat_ext for an open descriptor (module
// wasi_snapshot_preview1, name "fd_filestat_ext"), backing a
// bridge-provided fstat. A descriptor that is not a file of the FS backend
// is described as what it is to the guest: a standard stream that is a
// file of the host as that file (a terminal, a pipe, a regular file), a
// stream the embedder supplied as a pipe, a socket as a socket. The last
// two have no file behind them; they belong to the guest's own user (see
// SetHostProcess).
func (w *WasiStubs) Fd_filestat_ext(m *Module, fd, outPtr int32) int32 {
	return w.fdFilestatExt(m, fd, zext(outPtr))
}

// Fd_filestat_ext64 is Fd_filestat_ext for a memory64 guest.
func (w *WasiStubs) Fd_filestat_ext64(m *Module, fd int32, outPtr int64) int32 {
	return w.fdFilestatExt(m, fd, uint64(outPtr))
}

// fdFilestatExt is the body of Fd_filestat_ext and Fd_filestat_ext64.
func (w *WasiStubs) fdFilestatExt(m *Module, fd int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, wasiFilestatExtSize)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	fi := w.streamFileInfo(op)
	if fi == nil && op.f != nil {
		var err error
		if fi, err = op.f.Stat(); err != nil {
			return -mapOSError(err)
		}
	}
	if fi != nil {
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
	}
	mode := unixTypeFIFO | 0o600
	if op.isSocket || op.netConn() != nil {
		mode = unixTypeSocket | 0o777
	}
	var uid, gid uint32
	if w.hostIdentity() {
		uid, gid = uint32(os.Getuid()), uint32(os.Getgid())
	}
	binary.LittleEndian.PutUint32(out[0:], mode)
	binary.LittleEndian.PutUint32(out[4:], uid)
	binary.LittleEndian.PutUint32(out[8:], gid)
	return _wasiESUCCESS
}

// streamFileInfo describes the host file behind an entry that refers to a
// standard stream of the instance, or returns nil when the entry is not a
// standard stream or the stream is not a file of the host (an embedder's
// reader or writer).
func (w *WasiStubs) streamFileInfo(op *wasiOpen) os.FileInfo {
	if op == nil || op.stdio == 0 {
		return nil
	}
	w.mu.Lock()
	var stream any
	switch op.stdio {
	case 1:
		stream = w.stdin
	case 2:
		stream = w.stdout
	case 3:
		stream = w.stderr
	}
	w.mu.Unlock()
	file, isFile := stream.(*os.File)
	if !isFile {
		return nil
	}
	fi, err := file.Stat()
	if err != nil {
		return nil
	}
	return fi
}

// HostDescriptor returns the descriptor of the host process behind the
// guest's descriptor fd, for code of the embedder that runs outside the
// guest and has to hand a descriptor to the host's system calls. ok is false
// when fd is not open or has no host descriptor: a file of an in-memory
// filesystem, a standard stream the embedder supplied as a reader or
// writer, a socket that is not connected, bound or listening yet.
//
// For a guest whose descriptors are the host process's (SetHostProcess) the
// answer is fd itself: the number means the same on both sides, and the
// descriptor is in the blocking mode the guest set. The one exception is a
// descriptor the instance holds under a number that is another's for the
// process — its own file where another process of the family still has
// one, or in place of a standard descriptor it was not given: that one has
// no number outside the guest, and ok is false.
//
// For any other guest the guest's numbers mean nothing outside it, and the
// descriptor returned stays the runtime's: it is valid until the guest
// closes fd, it must not be closed, and it is in whatever blocking mode the
// Go runtime keeps it in (non-blocking for sockets and pipes), not the mode
// the guest asked for.
func (w *WasiStubs) HostDescriptor(fd int32) (hostFd uintptr, ok bool) {
	w.mu.Lock()
	op := w.openLocked(fd)
	var stream any
	if op != nil {
		switch op.stdio {
		case 1:
			stream = w.stdin
		case 2:
			stream = w.stdout
		case 3:
			stream = w.stderr
		default:
			if op.f != nil {
				stream = op.f
			}
		}
	}
	w.mu.Unlock()
	if op == nil {
		return 0, false
	}
	if h := op.host(); h != nil {
		// The guest's number is the host's, except where the instance has
		// its own file under a number another process still uses: that one
		// has no number outside the guest.
		if number := h.fd.Load(); number == fd {
			return uintptr(number), true
		}
		return 0, false
	}
	if stream == nil {
		if conn := op.netConn(); conn != nil {
			stream = conn
		} else if l, _ := op.netListener(); l != nil {
			stream = l
		}
	}
	raw, hasDescriptor := stream.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !hasDescriptor {
		return 0, false
	}
	rc, err := raw.SyscallConn()
	if err != nil {
		return 0, false
	}
	if err := rc.Control(func(d uintptr) { hostFd = d }); err != nil {
		return 0, false
	}
	return hostFd, true
}

// Fd_path is a NON-STANDARD host import (module wasi_snapshot_preview1, name
// "fd_path") backing fchdir(): a guest's libc keeps the working directory
// as a path, so a directory that is known only by its descriptor has to be
// named before it can become the working directory. The call hands back the
// path fd was opened under, absolute in the guest's filesystem ("/" is the
// preopen root), through writeWasiRecord. It is the name the directory had
// when it was opened: a caller that needs the directory itself compares
// what the name leads to now with fstat's answer.
//
// Returns 0, or a negative errno: EBADF, ENOTDIR for a descriptor that is
// not a directory's, ERANGE when the buffer is too small.
func (w *WasiStubs) Fd_path(m *Module, fd, bufPtr, bufLen, neededPtr int32) int32 {
	return w.fdPath(m, fd, zext(bufPtr), bufLen, zext(neededPtr))
}

// Fd_path64 is Fd_path for a memory64 guest.
func (w *WasiStubs) Fd_path64(m *Module, fd int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.fdPath(m, fd, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// fdPath is the body of Fd_path and Fd_path64.
func (w *WasiStubs) fdPath(m *Module, fd int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	root := op == nil && w.rootNumberLocked(fd)
	w.mu.Unlock()
	if op == nil && !root {
		return -_wasiEBADF
	}
	path := "/"
	if op != nil {
		if !op.isDir {
			return -_wasiENOTDIR
		}
		path += op.path
	}
	return w.writeWasiRecord(m, []byte(path), bufPtr, bufLen, neededPtr)
}

// wasiFilestatExtSize is the size of the record Path_filestat_ext and
// Fd_filestat_ext write: u32 mode, uid, gid and block size, then u64 device
// of a special file and number of 512-byte blocks.
const wasiFilestatExtSize = 32

// writeFilestatExt writes what Path_filestat_ext and Fd_filestat_ext
// report about the file fi describes.
func writeFilestatExt(out []byte, fi os.FileInfo) {
	st := fileStatOf(fi)
	binary.LittleEndian.PutUint32(out[0:], unixTypeBits(fi.Mode())|unixModeBits(fi.Mode()))
	binary.LittleEndian.PutUint32(out[4:], st.uid)
	binary.LittleEndian.PutUint32(out[8:], st.gid)
	binary.LittleEndian.PutUint32(out[12:], st.blksize)
	binary.LittleEndian.PutUint64(out[16:], st.rdev)
	binary.LittleEndian.PutUint64(out[24:], st.blocks)
}

// Path_filestat_mode is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "path_filestat_mode") backing a
// bridge-provided stat/lstat: WASI's filestat carries no permission
// bits, so the bridge merges the real mode in from here. The path is
// preopen-relative; follow selects stat vs lstat semantics. Writes the
// unix permission bits at modeOutPtr; returns 0 or a negative errno.
func (w *WasiStubs) Path_filestat_mode(m *Module, pathPtr, pathLen, follow, modeOutPtr int32) int32 {
	return w.pathFilestatMode(m, zext(pathPtr), pathLen, follow, zext(modeOutPtr))
}

// Path_filestat_mode64 is Path_filestat_mode for a memory64 guest.
func (w *WasiStubs) Path_filestat_mode64(m *Module, pathPtr int64, pathLen, follow int32, modeOutPtr int64) int32 {
	return w.pathFilestatMode(m, uint64(pathPtr), pathLen, follow, uint64(modeOutPtr))
}

// pathFilestatMode is the body of Path_filestat_mode and Path_filestat_mode64.
func (w *WasiStubs) pathFilestatMode(m *Module, pathPtr uint64, pathLen, follow int32, modeOutPtr uint64) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	out := w.memBytes(m, modeOutPtr, 4)
	if pathSlice == nil || out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	var fi os.FileInfo
	var err error
	if follow != 0 {
		fi, err = fsys.Stat(string(pathSlice))
	} else {
		fi, err = fsys.Lstat(string(pathSlice))
	}
	if err != nil {
		return -mapOSError(err)
	}
	binary.LittleEndian.PutUint32(out, unixModeBits(fi.Mode()))
	return _wasiESUCCESS
}

// Fd_dup is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dup") backing the bridge's dup(): the new fd shares the same
// open descriptor (offset included), and the underlying file closes only
// when the last sharing fd does. Writes the new fd at outPtr.
func (w *WasiStubs) Fd_dup(m *Module, fd, outPtr int32) int32 {
	return w.fdDup(m, fd, zext(outPtr))
}

// Fd_dup64 is Fd_dup for a memory64 guest.
func (w *WasiStubs) Fd_dup64(m *Module, fd int32, outPtr int64) int32 {
	return w.fdDup(m, fd, uint64(outPtr))
}

// fdDup is the body of Fd_dup and Fd_dup64.
func (w *WasiStubs) fdDup(m *Module, fd int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	if op == nil {
		return _wasiEBADF
	}
	return w.dupLocked(op, 0, out)
}

// dupLocked enters a duplicate of op under the lowest free number that is
// at least min, and writes the number at out. Caller holds w.mu.
func (w *WasiStubs) dupLocked(op *wasiOpen, min int32, out []byte) int32 {
	if op.host() != nil {
		nfd, err := w.dupHostLocked(op, int(min))
		if err != nil {
			return mapOSError(err)
		}
		binary.LittleEndian.PutUint32(out, uint32(nfd))
		return _wasiESUCCESS
	}
	nfd := w.addFDFromLocked(op, min)
	op.addRef()
	binary.LittleEndian.PutUint32(out, uint32(nfd))
	return _wasiESUCCESS
}

// Fd_dupfd is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dupfd") backing fcntl's F_DUPFD: fd_dup, under the lowest free
// number that is at least min. EINVAL for a negative min.
func (w *WasiStubs) Fd_dupfd(m *Module, fd, min, outPtr int32) int32 {
	return w.fdDupfd(m, fd, min, zext(outPtr))
}

// Fd_dupfd64 is Fd_dupfd for a memory64 guest.
func (w *WasiStubs) Fd_dupfd64(m *Module, fd, min int32, outPtr int64) int32 {
	return w.fdDupfd(m, fd, min, uint64(outPtr))
}

// fdDupfd is the body of Fd_dupfd and Fd_dupfd64.
func (w *WasiStubs) fdDupfd(m *Module, fd, min int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	if min < 0 {
		return _wasiEINVAL
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	if op == nil {
		return _wasiEBADF
	}
	return w.dupLocked(op, min, out)
}

// Fd_dup2 is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dup2") backing the bridge's dup2(): to becomes another
// reference to from's descriptor, closing whatever to previously held.
func (w *WasiStubs) Fd_dup2(m *Module, from, to int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := w.openLocked(from)
	if src == nil {
		return _wasiEBADF
	}
	if from == to {
		return _wasiESUCCESS
	}
	if src.host() != nil {
		return mapOSError(w.dup2HostLocked(src, to))
	}
	var closeErr error
	if dst := w.fdsLocked()[to]; dst != nil {
		if dst == src {
			return _wasiESUCCESS
		}
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	delete(w.cloexec, to)
	src.addRef()
	if closeErr != nil {
		return mapOSError(closeErr)
	}
	return _wasiESUCCESS
}

// Fd_dup264 is Fd_dup2 for a memory64 guest.
func (w *WasiStubs) Fd_dup264(m *Module, from, to int32) int32 {
	return w.Fd_dup2(m, from, to)
}

func (w *WasiStubs) Fd_renumber(m *Module, from, to int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if from == to {
		// Renumbering an fd onto itself is a no-op. We must NOT close
		// the entry at "to" here — that would destroy the live fd the
		// caller is trying to keep.
		if w.openLocked(from) != nil {
			return _wasiESUCCESS
		}
		return _wasiEBADF
	}
	src := w.openLocked(from)
	if src == nil {
		return _wasiEBADF
	}
	if src.host() != nil {
		// The number is the host's: the descriptor is duplicated onto the
		// new one and closed under the old.
		if err := w.dup2HostLocked(src, to); err != nil {
			return mapOSError(err)
		}
		delete(w.fdsLocked(), from)
		return mapOSError(closeWasiOpen(src))
	}
	var closeErr error
	if dst, ok2 := w.fdsLocked()[to]; ok2 {
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	delete(w.cloexec, to)
	delete(w.fdsLocked(), from)
	if closeErr != nil {
		return mapOSError(closeErr)
	}
	return _wasiESUCCESS
}

// Fd_renumber64 is Fd_renumber for a memory64 guest.
func (w *WasiStubs) Fd_renumber64(m *Module, from, to int64) int32 {
	return w.Fd_renumber(m, int32(from), int32(to))
}

// readDirCached lazily caches the directory listing on first
// Fd_readdir, so paged reads (cookie-driven) walk the same snapshot.
// With rewind the snapshot is taken afresh. The returned slice is never
// modified afterwards, so it stays valid after a later rewind.
func (op *wasiOpen) readDirCached(rewind bool) ([]os.DirEntry, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if rewind {
		op.dirCache = nil
	}
	if op.dirCache != nil {
		return op.dirCache, nil
	}
	if op.f == nil {
		return nil, syscall.EBADF
	}
	if _, err := op.f.Seek(0, 0); err != nil {
		return nil, err
	}
	entries, err := op.f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	// WASI expects "." and ".." as the first two entries; synthesise
	// them so they receive cookies 1 and 2 respectively.
	out := make([]os.DirEntry, 0, len(entries)+2)
	out = append(out, dotEntry(op.path, "."), dotEntry(op.path, ".."))
	out = append(out, entries...)
	// Sort the real entries for deterministic Fd_readdir output. The
	// "." and ".." entries stay at the front.
	sort.SliceStable(out[2:], func(i, j int) bool {
		return out[2+i].Name() < out[2+j].Name()
	})
	op.dirCache = out
	return out, nil
}

// dotEntry produces a synthetic os.DirEntry for "." and "..". Its
// Info() returns the stat of the parent directory (good enough for
// guest-side d_type detection).
func dotEntry(parent, name string) os.DirEntry {
	return &dotDirEntry{name: name, parent: parent}
}

type dotDirEntry struct {
	name, parent string
}

func (d *dotDirEntry) Name() string { return d.name }
func (d *dotDirEntry) IsDir() bool  { return true }
func (d *dotDirEntry) Type() os.FileMode {
	return os.ModeDir
}
func (d *dotDirEntry) Info() (os.FileInfo, error) {
	if d.name == "." {
		return os.Stat(d.parent)
	}
	return os.Stat(filepath.Dir(d.parent))
}

func (w *WasiStubs) Fd_readdir(m *Module, fd, buf, buflen int32, cookie int64, bufusedPtr int32) int32 {
	return w.fdReaddir(m, wasiABI32, fd, zext(buf), zext(buflen), cookie, zext(bufusedPtr))
}

// Fd_readdir64 is Fd_readdir for a memory64 guest.
func (w *WasiStubs) Fd_readdir64(m *Module, fd, buf, buflen, cookie, bufusedPtr int64) int32 {
	return w.fdReaddir(m, wasiABI64, int32(fd), uint64(buf), uint64(buflen), cookie, uint64(bufusedPtr))
}

// fdReaddir is the body of Fd_readdir and Fd_readdir64.
func (w *WasiStubs) fdReaddir(m *Module, abi wasiABI, fd int32, buf, buflen uint64, cookie int64, bufusedPtr uint64) int32 {
	bufSlice := w.memBytes(m, buf, buflen)
	// bufused is a __wasi_size_t; the dirents themselves are the same
	// for every guest (u64s and a u32).
	bufusedSlice := w.memBytes(m, bufusedPtr, abi.wordSize())
	if bufSlice == nil || bufusedSlice == nil {
		return _wasiEFAULT
	}
	written, errno := w.fillDirents(fd, bufSlice, cookie)
	if errno != _wasiESUCCESS {
		return errno
	}
	abi.putWord(bufusedSlice, uint64(written))
	return _wasiESUCCESS
}

// fillDirents packs the dirents of fd_readdir into bufSlice starting at
// the cookie'th entry and returns the byte count used.
func (w *WasiStubs) fillDirents(fd int32, bufSlice []byte, cookie int64) (int, int32) {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.f == nil || !op.isDir {
		return 0, _wasiEBADF
	}
	// cookie == 0 is the wasi-libc rewinddir signal — invalidate any
	// snapshot so a fresh Readdir picks up entries created or removed
	// since the previous call.
	entries, err := op.readDirCached(cookie == 0)
	if err != nil {
		return 0, mapOSError(err)
	}
	startIdx := int(cookie)
	if startIdx < 0 {
		startIdx = 0
	}
	written := 0
	for i := startIdx; i < len(entries); i++ {
		e := entries[i]
		nameBytes := []byte(e.Name())
		// dirent header: d_next u64 + d_ino u64 + d_namlen u32 + d_type u8 + 3 pad = 24 bytes.
		const headerLen = 24
		// os.FileInfo does not expose inode portably; report 0.
		var dtype byte = 4 // regular file
		if e.IsDir() {
			dtype = 3
		} else if e.Type()&os.ModeSymlink != 0 {
			dtype = 7
		} else if e.Type()&os.ModeNamedPipe != 0 {
			dtype = 6
		} else if e.Type()&os.ModeSocket != 0 {
			dtype = 6
		}
		// Assemble the fixed header, then copy header+name into the buffer.
		// When a record does not fully fit we copy as much as fits so that
		// bufused == buflen, which is the wasi-libc signal for "more entries
		// available; call again with the last returned cookie". We must NOT
		// zero-fill the leftover: a zeroed dirent (d_namlen=0, d_next=0) is
		// misread by wasi-libc as end-of-directory and silently truncates the
		// listing (e.g. makes a guest's importer miss standard-library packages).
		var hdr [headerLen]byte
		binary.LittleEndian.PutUint64(hdr[0:], uint64(i+1)) // d_next (cookie)
		// d_ino MUST be non-zero: wasi-libc's readdir treats a dirent with
		// d_ino == 0 as a deleted/empty slot and SKIPS it, which would make
		// the whole listing appear empty (e.g. a guest's importer then fails
		// to load any standard-library module). os.FileInfo has no
		// portable inode, so synthesize a stable non-zero id from the entry
		// index.
		binary.LittleEndian.PutUint64(hdr[8:], uint64(i)+1) // d_ino (nonzero)
		binary.LittleEndian.PutUint32(hdr[16:], uint32(len(nameBytes)))
		hdr[20] = dtype
		n := copy(bufSlice[written:], hdr[:])
		written += n
		if n < len(hdr) {
			written = len(bufSlice)
			break
		}
		n = copy(bufSlice[written:], nameBytes)
		written += n
		if n < len(nameBytes) {
			written = len(bufSlice)
			break
		}
	}
	return written, _wasiESUCCESS
}

// Path_open opens a wasm-supplied path and registers it in the fd
// table. The path is resolved against the host filesystem with the same
// rights the host Go process has — wasm2go's default WASI is a thin
// passthrough, not a sandbox. The dirFd == 3 special case keeps the
// "preopen /" convention that wasi-libc requires for its directory
// enumeration, but the path itself is opened verbatim (joined to "/")
// using os.OpenFile. Callers that need a sandbox should provide their
// own Wasi_snapshot_preview1Imports implementation via NewWithWASI.
func (w *WasiStubs) Path_open(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags, openedFdPtr int32) int32 {
	return w.openGuestPath(m, dirFd, dirflags, zext(pathPtr), zext(pathLen), oflags, fsRightsBase, fsRightsInherit, fdflags, zext(openedFdPtr))
}

// Path_open64 is Path_open for a memory64 guest.
func (w *WasiStubs) Path_open64(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags, fsRightsBase, fsRightsInherit, fdflags, openedFdPtr int64) int32 {
	return w.openGuestPath(m, int32(dirFd), int32(dirflags), uint64(pathPtr), uint64(pathLen), int32(oflags), fsRightsBase, fsRightsInherit, int32(fdflags), uint64(openedFdPtr))
}

// openGuestPath is the body of Path_open and Path_open64.
func (w *WasiStubs) openGuestPath(m *Module, dirFd, dirflags int32, pathPtr, pathLen uint64, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags int32, openedFdPtr uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	outSlice := w.memBytes(m, openedFdPtr, 4)
	if pathSlice == nil || outSlice == nil {
		return _wasiEFAULT
	}
	fd, errno := w.pathOpen(string(pathSlice), dirflags, oflags, fsRightsBase, fdflags)
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint32(outSlice, uint32(fd))
	return _wasiESUCCESS
}

// wasiDefaultFileMode and wasiDefaultDirMode are the modes path_open and
// path_create_directory request for what they create, as open(2) and
// mkdir(2) callers conventionally do: neither import has a mode argument.
// The instance's umask is taken out of them like out of any other.
const (
	wasiDefaultFileMode os.FileMode = 0o666
	wasiDefaultDirMode  os.FileMode = 0o777
)

// pathOpen is the layout-independent body of path_open: it resolves and
// opens rel, registers the fd, and returns it. Callers own reading the
// path and writing the opened fd at their ABI's pointer width.
func (w *WasiStubs) pathOpen(rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32) (int32, int32) {
	return w.pathOpenMode(rel, dirflags, oflags, fsRightsBase, fdflags, wasiDefaultFileMode)
}

// ownDescriptorName returns the descriptor a path names that stands for a
// descriptor of the process that opens it: /dev/stdin, /dev/stdout,
// /dev/stderr (0, 1, 2), /dev/fd/N, /proc/self/fd/N and /proc/PID/fd/N for
// the process's own pid. The names are the system's (rel is relative to
// the root, as the guest's C library gives it).
func ownDescriptorName(rel string, pid int32) (int32, bool) {
	rel = strings.TrimPrefix(rel, "/")
	switch rel {
	case "dev/stdin":
		return 0, true
	case "dev/stdout":
		return 1, true
	case "dev/stderr":
		return 2, true
	}
	for _, dir := range ownDescriptorDirs(pid) {
		if num, ok := strings.CutPrefix(rel, dir+"/"); ok {
			n, err := strconv.ParseUint(num, 10, 31)
			if err != nil || strconv.FormatUint(n, 10) != num {
				return 0, false
			}
			return int32(n), true
		}
	}
	return 0, false
}

// ownDescriptorDirs returns the directories that list the descriptors of
// the process that reads them, relative to the root: /dev/fd, /proc/self/fd
// and /proc/PID/fd for the process's own pid.
func ownDescriptorDirs(pid int32) []string {
	return []string{"dev/fd", "proc/self/fd", "proc/" + strconv.Itoa(int(pid)) + "/fd"}
}

// ownDescriptorDir reports whether rel names a directory of
// ownDescriptorDirs.
func ownDescriptorDir(rel string, pid int32) bool {
	rel = strings.TrimSuffix(strings.TrimPrefix(rel, "/"), "/")
	for _, dir := range ownDescriptorDirs(pid) {
		if rel == dir {
			return true
		}
	}
	return false
}

// descriptorListing is what a directory of ownDescriptorDirs is to the
// guest: an entry for each of its open descriptors, named by the number,
// as they were when it opened the directory. The host would list the host
// process's, which are the runtime's and the other processes' of the family
// as well, and has nothing under the pid of a forked process.
type descriptorListing struct {
	name    string
	numbers []int32
}

func (d *descriptorListing) Read(p []byte) (int, error)              { return 0, syscall.EISDIR }
func (d *descriptorListing) ReadAt(p []byte, off int64) (int, error) { return 0, syscall.EISDIR }
func (d *descriptorListing) Write(p []byte) (int, error)             { return 0, syscall.EBADF }
func (d *descriptorListing) WriteAt(p []byte, off int64) (int, error) {
	return 0, syscall.EBADF
}
func (d *descriptorListing) Seek(offset int64, whence int) (int64, error) { return 0, nil }
func (d *descriptorListing) Close() error                                 { return nil }
func (d *descriptorListing) Stat() (os.FileInfo, error) {
	return memFileInfo{name: d.name, mode: os.ModeDir | 0o500}, nil
}
func (d *descriptorListing) Sync() error                  { return nil }
func (d *descriptorListing) Truncate(size int64) error    { return syscall.EISDIR }
func (d *descriptorListing) Chmod(mode os.FileMode) error { return syscall.EPERM }
func (d *descriptorListing) Name() string                 { return d.name }

// ReadDir returns every entry, whatever n is: the runtime reads a directory
// whole (readDirCached).
func (d *descriptorListing) ReadDir(n int) ([]os.DirEntry, error) {
	entries := make([]os.DirEntry, 0, len(d.numbers))
	for _, fd := range d.numbers {
		entries = append(entries, memDirEntry{&memNode{name: strconv.Itoa(int(fd)), mode: 0o700}})
	}
	return entries, nil
}

// ownDescriptorsLocked returns the numbers of the guest's open descriptors
// in order: the entries of its table, and the descriptors of the host
// process that are the guest's although its table does not have them yet
// (outsideDescriptorsLocked). The numbers of the root directory are the
// runtime's (rootNumberLocked). Caller holds w.mu.
func (w *WasiStubs) ownDescriptorsLocked() []int32 {
	var fds []int32
	for fd, op := range w.fdsLocked() {
		if w.rootNumberLocked(fd) {
			continue
		}
		if h := op.host(); h.madeOutside() && !h.current() {
			// code outside the guest closed it (hostOpenLocked)
			continue
		}
		fds = append(fds, fd)
	}
	fds = append(fds, w.outsideDescriptorsLocked()...)
	sort.Slice(fds, func(i, j int) bool { return fds[i] < fds[j] })
	return fds
}

// pathOpenMode is pathOpen with the mode of open(2): a file the call
// creates gets mode, less the instance's umask.
func (w *WasiStubs) pathOpenMode(rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32, mode os.FileMode) (int32, int32) {
	w.mu.Lock()
	if w.terminal != nil && w.hostDescriptorsLocked() && strings.TrimPrefix(rel, "/") == "dev/tty" {
		// /dev/tty is the controlling terminal of whoever opens it. That
		// of a forked process which changed its own is the runtime's to
		// name: the host would open the host process's.
		if *w.terminal == "" {
			w.mu.Unlock()
			return -1, _wasiENXIO
		}
		rel = strings.TrimPrefix(*w.terminal, "/")
	}
	if ownDescriptorDir(rel, w.processIDLocked()) {
		// The guest's own descriptors, as a directory: one that is
		// opened for writing is a directory still.
		defer w.mu.Unlock()
		if oflags&(0x1|0x8) != 0 || fsRightsBase&(1<<6) != 0 { // O_CREAT, O_TRUNC; FD_WRITE
			return -1, _wasiEISDIR
		}
		listing := &descriptorListing{name: filepath.Base(strings.TrimSuffix(rel, "/"))}
		op := &wasiOpen{f: listing, isDir: true, path: rel, noWrite: true}
		fd := w.addFDLocked(op)
		listing.numbers = w.ownDescriptorsLocked()
		return fd, _wasiESUCCESS
	}
	if n, named := ownDescriptorName(rel, w.processIDLocked()); named {
		// The opener's own descriptor: the host would open the host
		// process's (a forked process's standard output is not the host
		// process's, nor is a stream of the embedder's). The new
		// descriptor shares the open file, as /dev/fd/N does on darwin
		// and the BSDs; a number that is not open is no such file.
		defer w.mu.Unlock()
		op := w.openLocked(n)
		if op == nil {
			return -1, _wasiENOENT
		}
		var out [4]byte
		if errno := w.dupLocked(op, 0, out[:]); errno != _wasiESUCCESS {
			return -1, errno
		}
		return int32(binary.LittleEndian.Uint32(out[:])), _wasiESUCCESS
	}
	forked := w.forked
	fsys := w.fsys
	// A file of the host filesystem is opened as a descriptor of the host
	// process when those are the guest's. A backend that has no such file
	// under the name (errors.ErrUnsupported) opens it its own way.
	openFile := fsys.OpenFile
	hostFS, onHost := fsys.(interface {
		OpenDescriptor(name string, flag int, perm os.FileMode) (File, error)
	})
	if onHost = onHost && w.hostDescriptorsLocked(); onHost {
		openFile = func(name string, flag int, perm os.FileMode) (File, error) {
			f, err := hostFS.OpenDescriptor(name, flag, perm)
			if errors.Is(err, errors.ErrUnsupported) {
				return fsys.OpenFile(name, flag&^hostONonblock, perm)
			}
			return f, err
		}
	}
	w.mu.Unlock()

	// Decode rights into access mode. WASI rights bits: 0=FD_DATASYNC,
	// 1=FD_READ, 6=FD_WRITE. We treat absent rights as the closest fit.
	canRead := fsRightsBase&(1<<1) != 0
	canWrite := fsRightsBase&(1<<6) != 0
	var flag int
	switch {
	case canRead && canWrite:
		flag = os.O_RDWR
	case canWrite && !canRead:
		flag = os.O_WRONLY
	default:
		flag = os.O_RDONLY
	}

	// oflags: 0x1=O_CREAT, 0x2=O_DIRECTORY, 0x4=O_EXCL, 0x8=O_TRUNC.
	if oflags&0x1 != 0 {
		flag |= os.O_CREATE
	}
	if oflags&0x4 != 0 {
		flag |= os.O_EXCL
	}
	if oflags&0x8 != 0 {
		flag |= os.O_TRUNC
	}

	// fdflags: 0x1 APPEND, 0x2 DSYNC, 0x4 NONBLOCK, 0x8 RSYNC, 0x10 SYNC.
	if fdflags&0x1 != 0 {
		flag |= os.O_APPEND
	}
	if fdflags&(0x2|0x8|0x10) != 0 {
		flag |= os.O_SYNC
	}
	// NONBLOCK (0x4) doesn't translate directly via os.OpenFile; we
	// store it on the wasiOpen so Fd_fdstat_get reflects it.
	if forked {
		// Where the open of a terminal can make it the controlling
		// terminal of the process, the process would be the host
		// process: a forked process's is the runtime's to keep (see
		// takeOpenedTerminalLocked).
		flag |= hostOpenNoTerminal
	}

	// Consult the host filesystem policy before touching the disk. An
	// open counts as a write when it requests write access or asks to
	// create/truncate the target.
	writeAccess := flag&(os.O_WRONLY|os.O_RDWR) != 0 || flag&(os.O_CREATE|os.O_TRUNC) != 0
	if !w.checkFS(rel, writeAccess) {
		return -1, _wasiEACCES
	}

	requireDir := oflags&0x2 != 0
	noFollow := dirflags&0x1 == 0

	if requireDir {
		// os.OpenFile on a directory tolerates O_RDONLY only on POSIX.
		flag = os.O_RDONLY
	}

	// When the guest opted out of symlink-follow, refuse the open
	// up-front if Lstat says the target is a symlink. There is a
	// TOCTOU window between this check and OpenFile, but Go's
	// stdlib does not expose a portable O_NOFOLLOW; this Lstat
	// pre-check gives the right answer for the documented attack
	// model (an existing symlink at the path) without dragging in
	// platform-specific syscall constants.
	if noFollow {
		if li, lerr := fsys.Lstat(rel); lerr == nil && (li.Mode()&os.ModeSymlink) != 0 {
			return -1, _wasiENOENT
		}
	}
	var f File
	var err error
	isFIFO := false
	if fi, serr := fsys.Stat(rel); serr == nil {
		isFIFO = fi.Mode()&os.ModeNamedPipe != 0
	}
	switch {
	case isFIFO && fdflags&wasiFdflagNonblock == 0 && flag&os.O_RDWR == 0:
		var errno int32
		if f, errno = w.openFIFO(openFile, rel, flag, w.createMode(mode)); errno != _wasiESUCCESS {
			return -1, errno
		}
	case (isFIFO || onHost) && fdflags&wasiFdflagNonblock != 0:
		// An open that does not wait is the host's own: a reader gets the
		// FIFO whether or not anyone writes to it, a writer is refused
		// (ENXIO) while nobody reads. A descriptor of the host's is in the
		// mode it was opened in, whatever it is.
		if f, err = openFile(rel, flag|hostONonblock, w.createMode(mode)); err != nil {
			return -1, mapOSError(err)
		}
	default:
		if f, err = openFile(rel, flag, w.createMode(mode)); err != nil {
			return -1, mapOSError(err)
		}
	}
	st, statErr := f.Stat()
	if statErr != nil {
		return -1, mapOSError(errors.Join(statErr, f.Close()))
	}
	isDir := st.IsDir()
	if requireDir && !isDir {
		if cerr := f.Close(); cerr != nil {
			return -1, mapOSError(cerr)
		}
		return -1, _wasiENOTDIR
	}
	op := &wasiOpen{
		f: f, isDir: isDir, path: rel, fdflags: fdflags,
		noRead:  flag&os.O_WRONLY != 0,
		noWrite: flag&(os.O_WRONLY|os.O_RDWR) == 0,
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if op.host() != nil {
		fd, err := w.addHostFDLocked(op)
		if err != nil {
			return -1, mapOSError(errors.Join(err, f.Close()))
		}
		w.takeOpenedTerminalLocked(op)
		return fd, _wasiESUCCESS
	}
	return w.addFDLocked(op), _wasiESUCCESS
}

// openFIFO opens a FIFO for reading or for writing the way a blocking
// open(2) does: it waits until the other end is open too, and a signal
// posted to the guest ends the wait with EINTR. The host's open cannot be
// called off, so it is made to return: the other end is opened for a
// moment without waiting, and what the two calls opened is closed again
// before the guest is told — an open that was interrupted leaves no end of
// the FIFO open behind, which the next open of the other end would take for
// a peer.
func (w *WasiStubs) openFIFO(openFile func(name string, flag int, perm os.FileMode) (File, error), rel string, flag int, perm os.FileMode) (File, int32) {
	posted := make(chan struct{})
	if !w.beginBlocking(func() { close(posted) }) {
		return nil, _wasiEINTR
	}
	type opened struct {
		f   File
		err error
	}
	result := make(chan opened, 1)
	go func() {
		f, err := openFile(rel, flag, perm)
		result <- opened{f, err}
	}()
	select {
	case r := <-result:
		w.endBlocking()
		if r.err != nil {
			return nil, mapOSError(r.err)
		}
		return r.f, _wasiESUCCESS
	case <-posted:
	}
	w.endBlocking()
	other := os.O_WRONLY
	if flag&os.O_WRONLY != 0 {
		other = os.O_RDONLY
	}
	for {
		end, endErr := openFile(rel, other|hostONonblock, 0)
		if endErr == nil {
			// The other end is open: the host's open returns, now or as
			// soon as it gets as far as looking for it.
			r := <-result
			_ = end.Close()
			if r.err == nil {
				_ = r.f.Close()
			}
			return nil, _wasiEINTR
		}
		// The other end is not to be had. A writer's end is refused
		// (ENXIO) for as long as the host's open for reading has not got
		// as far as waiting, which it will: the attempt is repeated. Any
		// other failure stays (the FIFO is gone from its name): the open
		// is left where it is until someone else opens the FIFO, and is
		// given up then.
		retry := errors.Is(endErr, syscall.ENXIO)
		var again <-chan time.Time
		if retry {
			again = time.After(fifoUnblockRetry)
		} else {
			closed := make(chan time.Time)
			close(closed)
			again = closed
		}
		select {
		case r := <-result:
			if r.err != nil {
				return nil, _wasiEINTR
			}
			// It returned by itself: a peer opened the FIFO meanwhile, and
			// the open is done. The signal is still to be noticed.
			w.keepInterrupt()
			return r.f, _wasiESUCCESS
		case <-again:
		}
		if !retry {
			go func() {
				if r := <-result; r.err == nil {
					_ = r.f.Close()
				}
			}()
			return nil, _wasiEINTR
		}
	}
}

// fifoUnblockRetry is how long openFIFO waits before it tries again to open
// the other end of a FIFO whose open it has to make return.
const fifoUnblockRetry = time.Millisecond

func (w *WasiStubs) Path_create_directory(m *Module, dirFd, pathPtr, pathLen int32) int32 {
	return w.pathCreateDirectoryAt(m, dirFd, zext(pathPtr), zext(pathLen))
}

// Path_create_directory64 is Path_create_directory for a memory64 guest.
func (w *WasiStubs) Path_create_directory64(m *Module, dirFd, pathPtr, pathLen int64) int32 {
	return w.pathCreateDirectoryAt(m, int32(dirFd), uint64(pathPtr), uint64(pathLen))
}

// pathCreateDirectoryAt is the body of Path_create_directory and
// Path_create_directory64: the directory at the path, relative to the
// preopened directory dirFd, with the default mode.
func (w *WasiStubs) pathCreateDirectoryAt(m *Module, dirFd int32, pathPtr, pathLen uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	return w.pathCreateDirectory(string(pathSlice), wasiDefaultDirMode)
}

func (w *WasiStubs) Path_unlink_file(m *Module, dirFd, pathPtr, pathLen int32) int32 {
	return w.pathUnlinkFile(m, dirFd, zext(pathPtr), zext(pathLen))
}

// Path_unlink_file64 is Path_unlink_file for a memory64 guest.
func (w *WasiStubs) Path_unlink_file64(m *Module, dirFd, pathPtr, pathLen int64) int32 {
	return w.pathUnlinkFile(m, int32(dirFd), uint64(pathPtr), uint64(pathLen))
}

// pathUnlinkFile is the body of Path_unlink_file and Path_unlink_file64.
func (w *WasiStubs) pathUnlinkFile(m *Module, dirFd int32, pathPtr, pathLen uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	if !w.checkFS(string(pathSlice), true) {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	rel := string(pathSlice)
	st, err := fsys.Lstat(rel)
	if err != nil {
		return mapOSError(err)
	}
	if st.IsDir() {
		return _wasiEISDIR
	}
	if err := fsys.Remove(rel); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_remove_directory(m *Module, dirFd, pathPtr, pathLen int32) int32 {
	return w.pathRemoveDirectory(m, dirFd, zext(pathPtr), zext(pathLen))
}

// Path_remove_directory64 is Path_remove_directory for a memory64 guest.
func (w *WasiStubs) Path_remove_directory64(m *Module, dirFd, pathPtr, pathLen int64) int32 {
	return w.pathRemoveDirectory(m, int32(dirFd), uint64(pathPtr), uint64(pathLen))
}

// pathRemoveDirectory is the body of Path_remove_directory and
// Path_remove_directory64.
func (w *WasiStubs) pathRemoveDirectory(m *Module, dirFd int32, pathPtr, pathLen uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	rel := string(pathSlice)
	st, err := fsys.Lstat(rel)
	if err != nil {
		return mapOSError(err)
	}
	if !st.IsDir() {
		return _wasiENOTDIR
	}
	if err := fsys.Remove(rel); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_rename(m *Module, oldFd, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen int32) int32 {
	return w.pathRename(m, oldFd, zext(oldPathPtr), zext(oldPathLen), newFd, zext(newPathPtr), zext(newPathLen))
}

// Path_rename64 is Path_rename for a memory64 guest.
func (w *WasiStubs) Path_rename64(m *Module, oldFd, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen int64) int32 {
	return w.pathRename(m, int32(oldFd), uint64(oldPathPtr), uint64(oldPathLen), int32(newFd), uint64(newPathPtr), uint64(newPathLen))
}

// pathRename is the body of Path_rename and Path_rename64.
func (w *WasiStubs) pathRename(m *Module, oldFd int32, oldPathPtr, oldPathLen uint64, newFd int32, newPathPtr, newPathLen uint64) int32 {
	if !rootDirFD(oldFd) || !rootDirFD(newFd) {
		return _wasiEBADF
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if err := fsys.Rename(string(oldSlice), string(newSlice)); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_filestat_get(m *Module, dirFd, flags, pathPtr, pathLen, outPtr int32) int32 {
	return w.pathFilestatGet(m, dirFd, flags, zext(pathPtr), zext(pathLen), zext(outPtr))
}

// Path_filestat_get64 is Path_filestat_get for a memory64 guest.
func (w *WasiStubs) Path_filestat_get64(m *Module, dirFd, flags, pathPtr, pathLen, outPtr int64) int32 {
	return w.pathFilestatGet(m, int32(dirFd), int32(flags), uint64(pathPtr), uint64(pathLen), uint64(outPtr))
}

// pathFilestatGet is the body of Path_filestat_get and Path_filestat_get64.
func (w *WasiStubs) pathFilestatGet(m *Module, dirFd, flags int32, pathPtr, pathLen, outPtr uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	out := w.memBytes(m, outPtr, 64)
	if pathSlice == nil || out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	rel := string(pathSlice)
	var st os.FileInfo
	var err error
	if flags&0x1 != 0 {
		st, err = fsys.Stat(rel)
	} else {
		st, err = fsys.Lstat(rel)
	}
	if err != nil {
		return mapOSError(err)
	}
	writeFilestat(out, st)
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_filestat_set_times(m *Module, dirFd, flags, pathPtr, pathLen int32, atim, mtim int64, fstFlags int32) int32 {
	return w.pathFilestatSetTimes(m, dirFd, flags, zext(pathPtr), zext(pathLen), atim, mtim, fstFlags)
}

// Path_filestat_set_times64 is Path_filestat_set_times for a memory64 guest.
func (w *WasiStubs) Path_filestat_set_times64(m *Module, dirFd, flags, pathPtr, pathLen, atim, mtim, fstFlags int64) int32 {
	return w.pathFilestatSetTimes(m, int32(dirFd), int32(flags), uint64(pathPtr), uint64(pathLen), atim, mtim, int32(fstFlags))
}

// pathFilestatSetTimes is the body of Path_filestat_set_times and
// Path_filestat_set_times64.
func (w *WasiStubs) pathFilestatSetTimes(m *Module, dirFd, flags int32, pathPtr, pathLen uint64, atim, mtim int64, fstFlags int32) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	rel := string(pathSlice)
	follow := flags&0x1 != 0
	var st os.FileInfo
	var statErr error
	if follow {
		st, statErr = fsys.Stat(rel)
	} else {
		st, statErr = fsys.Lstat(rel)
	}
	if statErr != nil {
		return mapOSError(statErr)
	}
	atime, mtime := resolveFiletimes(uint64(atim), uint64(mtim), fstFlags, st)
	if err := fsys.Chtimes(rel, atime, mtime); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (o osFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(o.join(name), atime, mtime)
}

func (w *WasiStubs) Path_link(m *Module, oldFd, oldFlags, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen int32) int32 {
	return w.pathLink(m, oldFd, oldFlags, zext(oldPathPtr), zext(oldPathLen), newFd, zext(newPathPtr), zext(newPathLen))
}

// Path_link64 is Path_link for a memory64 guest.
func (w *WasiStubs) Path_link64(m *Module, oldFd, oldFlags, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen int64) int32 {
	return w.pathLink(m, int32(oldFd), int32(oldFlags), uint64(oldPathPtr), uint64(oldPathLen), int32(newFd), uint64(newPathPtr), uint64(newPathLen))
}

// pathLink is the body of Path_link and Path_link64.
func (w *WasiStubs) pathLink(m *Module, oldFd, oldFlags int32, oldPathPtr, oldPathLen uint64, newFd int32, newPathPtr, newPathLen uint64) int32 {
	if !rootDirFD(oldFd) || !rootDirFD(newFd) {
		return _wasiEBADF
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if err := fsys.Link(string(oldSlice), string(newSlice)); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_symlink(m *Module, targetPtr, targetLen, dirFd, linkPathPtr, linkPathLen int32) int32 {
	return w.pathSymlink(m, zext(targetPtr), zext(targetLen), dirFd, zext(linkPathPtr), zext(linkPathLen))
}

// Path_symlink64 is Path_symlink for a memory64 guest.
func (w *WasiStubs) Path_symlink64(m *Module, targetPtr, targetLen, dirFd, linkPathPtr, linkPathLen int64) int32 {
	return w.pathSymlink(m, uint64(targetPtr), uint64(targetLen), int32(dirFd), uint64(linkPathPtr), uint64(linkPathLen))
}

// pathSymlink is the body of Path_symlink and Path_symlink64.
func (w *WasiStubs) pathSymlink(m *Module, targetPtr, targetLen uint64, dirFd int32, linkPathPtr, linkPathLen uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	targetSlice := w.memBytes(m, targetPtr, targetLen)
	linkSlice := w.memBytes(m, linkPathPtr, linkPathLen)
	if targetSlice == nil || linkSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if err := fsys.Symlink(string(targetSlice), string(linkSlice)); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_readlink(m *Module, dirFd, pathPtr, pathLen, buf, buflen, bufusedPtr int32) int32 {
	return w.pathReadlink(m, wasiABI32, dirFd, zext(pathPtr), zext(pathLen), zext(buf), zext(buflen), zext(bufusedPtr))
}

// Path_readlink64 is Path_readlink for a memory64 guest.
func (w *WasiStubs) Path_readlink64(m *Module, dirFd, pathPtr, pathLen, buf, buflen, bufusedPtr int64) int32 {
	return w.pathReadlink(m, wasiABI64, int32(dirFd), uint64(pathPtr), uint64(pathLen), uint64(buf), uint64(buflen), uint64(bufusedPtr))
}

// pathReadlink is the body of Path_readlink and Path_readlink64.
func (w *WasiStubs) pathReadlink(m *Module, abi wasiABI, dirFd int32, pathPtr, pathLen, buf, buflen, bufusedPtr uint64) int32 {
	if !rootDirFD(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	bufSlice := w.memBytes(m, buf, buflen)
	// bufused is a __wasi_size_t.
	bufused := w.memBytes(m, bufusedPtr, abi.wordSize())
	if pathSlice == nil || bufSlice == nil || bufused == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	target, err := fsys.Readlink(string(pathSlice))
	if err != nil {
		return mapOSError(err)
	}
	n := copy(bufSlice, target)
	abi.putWord(bufused, uint64(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Random_get(m *Module, buf, bufLen int32) int32 {
	return w.randomGet(m, zext(buf), zext(bufLen))
}

// Random_get64 is Random_get for a memory64 guest.
func (w *WasiStubs) Random_get64(m *Module, buf, bufLen int64) int32 {
	return w.randomGet(m, uint64(buf), uint64(bufLen))
}

// randomGet is the body of Random_get and Random_get64.
func (w *WasiStubs) randomGet(m *Module, buf, bufLen uint64) int32 {
	slice := w.memBytes(m, buf, bufLen)
	if slice == nil {
		return _wasiEFAULT
	}
	_, err := rand.Read(slice)
	if err != nil {
		return _wasiEIO
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Sched_yield(m *Module) int32 {
	runtime.Gosched()
	return _wasiESUCCESS
}

// Sched_yield64 is Sched_yield for a memory64 guest.
func (w *WasiStubs) Sched_yield64(m *Module) int32 {
	return w.Sched_yield(m)
}

// Poll_oneoff decodes the WASI subscription_u records and reproduces the
// requested events.
//
// Each subscription is 48 bytes:
//
//	u64 userdata
//	u8  eventtype  (0=clock, 1=fd_read, 2=fd_write)
//	... per-type payload starting at offset 16
//
// For clock subscriptions, payload at offset 16 is: u32 clock_id, u64
// timeout, u64 precision, u16 sub_clock_flags (bit0=ABSTIME). We sleep
// for `timeout` ns (relative timer) or the diff to `timeout` (absolute
// timer). For fd_read / fd_write subscriptions, payload at offset 16 is
// a u32 fd; we call into the platform Poll helper to wait for
// readiness.
//
// Each emitted event is 32 bytes: u64 userdata, u16 errno, u16
// eventtype, u64 fd_readwrite_nbytes (filled for fd events), u16
// flags, then 6 bytes of padding.
func (w *WasiStubs) Poll_oneoff(m *Module, inPtr, outPtr, nsubs, neventsPtr int32) int32 {
	return w.pollOneoff(m, wasiABI32, zext(inPtr), zext(outPtr), zext(nsubs), zext(neventsPtr))
}

// Poll_oneoff64 is Poll_oneoff for a memory64 guest.
func (w *WasiStubs) Poll_oneoff64(m *Module, inPtr, outPtr, nsubs, neventsPtr int64) int32 {
	return w.pollOneoff(m, wasiABI64, uint64(inPtr), uint64(outPtr), uint64(nsubs), uint64(neventsPtr))
}

// pollOneoff is the body of Poll_oneoff and Poll_oneoff64.
func (w *WasiStubs) pollOneoff(m *Module, abi wasiABI, inPtr, outPtr, nsubs, neventsPtr uint64) int32 {
	// The subscriptions (48 bytes each) and the events (32 bytes each)
	// are the same for every guest; only nevents is a __wasi_size_t. The
	// arrays may take up to 2 GiB: bound the count before multiplying so
	// that a pathological nsubs cannot wrap.
	if nsubs > 0x7fffffff/48 {
		return _wasiEFAULT
	}
	subs := w.memBytes(m, inPtr, nsubs*48)
	events := w.memBytes(m, outPtr, nsubs*32)
	nev := w.memBytes(m, neventsPtr, abi.wordSize())
	if subs == nil || events == nil || nev == nil {
		return _wasiEFAULT
	}

	type pollItem struct {
		userdata uint64
		etype    byte
		fd       int32
		isRead   bool
	}
	var minClockNs int64 = -1
	var clockEvents []pollItem
	var fdEvents []pollItem
	for i := uint64(0); i < nsubs; i++ {
		base := i * 48
		userdata := binary.LittleEndian.Uint64(subs[base:])
		etype := subs[base+8]
		switch etype {
		case 0: // clock
			timeout := int64(binary.LittleEndian.Uint64(subs[base+24:]))
			flags := binary.LittleEndian.Uint16(subs[base+40:])
			ns := timeout
			if flags&0x1 != 0 {
				// Absolute timeout in nanoseconds since the clock epoch.
				// We approximate by treating it as relative — the guest
				// program's wall time will see the right elapsed
				// duration even if the absolute value is past.
				ns = timeout - time.Now().UnixNano()
				if ns < 0 {
					ns = 0
				}
			}
			if minClockNs < 0 || ns < minClockNs {
				minClockNs = ns
			}
			clockEvents = append(clockEvents, pollItem{userdata: userdata, etype: 0})
		case 1, 2: // fd_read / fd_write
			fd := int32(binary.LittleEndian.Uint32(subs[base+16:]))
			fdEvents = append(fdEvents, pollItem{userdata: userdata, etype: etype, fd: fd, isRead: etype == 1})
		default:
			// Unknown event type — write an EINVAL-tagged event below.
			clockEvents = append(clockEvents, pollItem{userdata: userdata, etype: etype})
		}
	}

	// Decide which fd subscriptions are ready. A descriptor whose read or
	// write cannot block — a regular file, a stream this host cannot probe
	// — is ready at once, as it always was. A stream whose read CAN block
	// (pipe, socket, terminal) is ready only when input is actually there:
	// reporting it ready regardless sends a guest multiplexing two pipes
	// into a blocking read of the idle one while the busy one fills up and
	// its writer stalls. Likewise a stream is writable only while it has
	// room, and a listener or the read end of a pipe never is: an event
	// loop told otherwise spins, or writes into a full pipe and stalls.
	type probeKey struct {
		op    *wasiOpen
		write bool
	}
	ready := make([]bool, len(fdEvents))
	errnos := make([]int32, len(fdEvents))
	ops := make([]*wasiOpen, len(fdEvents))
	// The stream behind a subscription for reading that can be hung up on,
	// asked about when its event is reported (streamHungUp); a socket
	// that is connecting finds its stream then. Descriptors of the host
	// process are answered by the host's poll instead.
	hangStreams := make([]any, len(fdEvents))
	connecting := make([]bool, len(fdEvents))
	// The descriptors of the host process among them are asked about
	// together, in one poll(2).
	var hostSet hostPollSet
	var probes []pollProbe
	probeOf := map[probeKey]int{}
	probeIndex := make([]int, len(fdEvents))
	anyReady := false
	for i, ev := range fdEvents {
		probeIndex[i] = -1
		w.mu.Lock()
		src, op := w.fdSrcLocked(ev.fd)
		dst, _ := w.fdDstLocked(ev.fd)
		stdin := w.stdin
		w.mu.Unlock()
		ops[i] = op
		if op == nil {
			errnos[i] = _wasiEBADF
			ready[i], anyReady = true, true
			continue
		}
		// A stream that is not open in the direction asked about never
		// becomes ready in it: the write end of a pipe has no input. A plain
		// file is ready either way, and the read or write reports what it
		// is open for.
		if readable, writable := op.access(); (ev.isRead && !readable) || (!ev.isRead && !writable && op.stdio == 0) {
			if op.plainFile() {
				ready[i], anyReady = true, true
				continue
			}
			// A stream open only for writing is never readable, but
			// poll(2) reports what happens to it whether asked or not:
			// POLLERR once nobody reads it any more (the reader of a pipe
			// has closed it). The guest asks about that with a
			// subscription for reading, having asked for neither.
			if ev.isRead && writable {
				if h := op.host(); h != nil {
					if !hostSet.addErrors(i, h) {
						errnos[i] = _wasiEBADF
						ready[i], anyReady = true, true
					}
				} else if dst != nil && streamFailed(dst) {
					errnos[i] = _wasiEPIPE
					ready[i], anyReady = true, true
				}
			}
			continue
		}
		if h := op.host(); h != nil {
			if !hostSet.add(i, h, ev.isRead) {
				errnos[i] = _wasiEBADF
				ready[i], anyReady = true, true
			}
			continue
		}
		if d := op.dialing(); d != nil {
			// A socket that is connecting becomes writable when the
			// attempt has ended, either way, and readable when it has
			// failed or when the connection it made has input.
			connecting[i] = ev.isRead
			key := probeKey{op: op, write: !ev.isRead}
			if at, seen := probeOf[key]; seen {
				probeIndex[i] = at
				continue
			}
			probeOf[key] = len(probes)
			probeIndex[i] = len(probes)
			forInput := ev.isRead
			probes = append(probes, pollProbe{
				op: op,
				probe: func(until time.Time, stop <-chan struct{}) bool {
					if !awaitDial(d, until, stop) {
						return false
					}
					stream, connected := op.netConn().(deadlineReader)
					if !forInput || !connected {
						return true
					}
					ready, refused := op.probeRead(stream, until, stop)
					return ready || refused
				},
			})
			continue
		}
		if !ev.isRead {
			stream, how := op.writeReadiness(dst, stdin)
			switch how {
			case pollWriteReady:
				ready[i], anyReady = true, true
			case pollWriteProbe:
				key := probeKey{op: op, write: true}
				if at, seen := probeOf[key]; seen {
					probeIndex[i] = at
					continue
				}
				probeOf[key] = len(probes)
				probeIndex[i] = len(probes)
				probes = append(probes, pollProbe{
					op: op,
					probe: func(until time.Time, stop <-chan struct{}) bool {
						return op.probeWritableUntil(stream, until, stop)
					},
				})
			}
			continue
		}
		// A listening socket is readable when a connection is waiting.
		if l, listening := op.netListener(); listening {
			if bounded, canBound := l.(deadlineListener); canBound {
				if op.acceptedReady() {
					ready[i], anyReady = true, true
					continue
				}
				if at, seen := probeOf[probeKey{op: op}]; seen {
					probeIndex[i] = at
					continue
				}
				probeOf[probeKey{op: op}] = len(probes)
				probeIndex[i] = len(probes)
				probes = append(probes, pollProbe{
					op: op,
					probe: func(until time.Time, stop <-chan struct{}) bool {
						return op.probeAccept(bounded, until, stop)
					},
				})
				continue
			}
		}
		if dg, isDatagram := src.(datagramSocket); isDatagram && op.dgram {
			if op.datagramReady() {
				ready[i], anyReady = true, true
				continue
			}
			if at, seen := probeOf[probeKey{op: op}]; seen {
				probeIndex[i] = at
				continue
			}
			probeOf[probeKey{op: op}] = len(probes)
			probeIndex[i] = len(probes)
			probes = append(probes, pollProbe{
				op: op,
				probe: func(until time.Time, stop <-chan struct{}) bool {
					return op.probeDatagram(dg, until, stop)
				},
			})
			continue
		}
		stream, blocks := op.readBlocks(src)
		if !blocks {
			ready[i], anyReady = true, true
			continue
		}
		hangStreams[i] = stream
		if pending, _ := op.aheadReady(); pending {
			ready[i], anyReady = true, true
			continue
		}
		if at, seen := probeOf[probeKey{op: op}]; seen {
			probeIndex[i] = at
			continue
		}
		probeOf[probeKey{op: op}] = len(probes)
		probeIndex[i] = len(probes)
		probes = append(probes, pollProbe{
			op: op,
			probe: func(until time.Time, stop <-chan struct{}) bool {
				// A stream that takes no deadline cannot be asked: it
				// counts as readable, and the read finds out.
				ready, refused := op.probeRead(stream, until, stop)
				return ready || refused
			},
		})
	}

	// The call blocks the guest when nothing is ready yet and there is
	// something to wait for; a signal posted meanwhile ends the wait. With
	// descriptors that can never become ready and no timeout, a signal is
	// all there is to wait for, as for poll(2).
	hostWaited := false
	markHost := func(sub int) { ready[sub], anyReady = true, true }
	if !hostSet.empty() {
		hostSet.look()
		hostSet.ready(markHost)
		switch {
		case anyReady || minClockNs == 0:
		case len(probes) == 0:
			// Nothing but descriptors of the host to wait for: the wait is
			// the host's poll, which a signal posted to the guest ends.
			var until time.Time
			if minClockNs > 0 {
				until = time.Now().Add(time.Duration(minClockNs))
			}
			errno := hostSet.await(w, until)
			hostSet.ready(markHost)
			if errno == _wasiEINTR {
				return _wasiEINTR
			}
			hostWaited = true
		default:
			// They are waited for next to the streams that are probed.
			probes = append(probes, pollProbe{
				probe: func(until time.Time, stop <-chan struct{}) bool {
					hostSet.awaitStoppable(until, stop)
					return hostSet.ready(func(int) {})
				},
			})
		}
	}
	onlySignal := !anyReady && !hostWaited && len(probes) == 0 && minClockNs < 0 && len(fdEvents) > 0
	var posted chan struct{}
	if !anyReady && !hostWaited && (len(probes) > 0 || minClockNs > 0 || onlySignal) {
		posted = make(chan struct{})
		if !w.beginBlocking(func() { close(posted) }) {
			return _wasiEINTR
		}
	}
	if len(probes) > 0 {
		// How long the probes may wait: not at all when something is
		// ready already, until the timeout when there is one, otherwise
		// until input arrives.
		var deadline time.Time
		switch {
		case anyReady:
			deadline = time.Now().Add(pollProbeGrace)
		case minClockNs >= 0:
			wait := time.Duration(minClockNs)
			if wait < pollProbeGrace {
				wait = pollProbeGrace
			}
			deadline = time.Now().Add(wait)
		}
		pollReady(probes, deadline, posted)
		for i := range fdEvents {
			if at := probeIndex[i]; at >= 0 && probes[at].ready {
				ready[i], anyReady = true, true
			}
		}
		hostSet.ready(markHost)
	} else if minClockNs > 0 && !anyReady && !hostWaited {
		// The clock paces the call only when nothing else can end it.
		timer := time.NewTimer(time.Duration(minClockNs))
		select {
		case <-timer.C:
		case <-posted:
			timer.Stop()
		}
	} else if onlySignal {
		<-posted
	}
	if posted != nil && w.endBlocking() && !anyReady {
		return _wasiEINTR
	}

	written := int32(0)
	for _, ev := range clockEvents {
		// A poll returns its ready fds without also claiming that the
		// timeout expired.
		if ev.etype == 0 && anyReady {
			continue
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, 0, 0, 0)
		written += 32
	}
	for i, ev := range fdEvents {
		if !ready[i] {
			continue
		}
		// A stream open only for writing that is in error is ready for
		// the call that finds out, and the event of the subscription for
		// reading that asked about it says so (EPIPE), as poll(2) reports
		// POLLERR: a write to it fails at once. The event for writing
		// carries no error: the guest's select would leave the descriptor
		// out of its sets.
		if errnos[i] == 0 && hostSet.errorsOnly(i) && hostSet.failed(i) {
			errnos[i] = _wasiEPIPE
		}
		// The hang-up goes with events for reading only. The guest's C
		// library takes it on an event for writing as the end of
		// writability (POLLHUP contradicts POLLWRNORM), and its select()
		// then puts the descriptor in no set, while the host's select(2)
		// reports a socket whose peer is gone writable, a connect that
		// failed among them: the write, or SO_ERROR, tells what happened.
		var flags uint16
		if errnos[i] == 0 && ev.isRead {
			if hostSet.hungUp(i) {
				flags = wasiEventHangup
			} else if stream := hangStreams[i]; stream != nil && streamHungUp(stream) {
				flags = wasiEventHangup
			} else if connecting[i] {
				if stream := ops[i].netConn(); stream != nil && streamHungUp(stream) {
					flags = wasiEventHangup
				}
			}
		}
		var nbytes uint64
		if op := ops[i]; op != nil && ev.isRead && errnos[i] == 0 {
			if h := op.host(); h != nil && h.waits() {
				nbytes = h.pending()
			} else if _, pending := op.aheadReady(); pending > 0 {
				nbytes = uint64(pending)
			} else if op.f != nil && probeIndex[i] < 0 {
				// Regular file: pass through the bytes left to read
				// (best-effort; the read itself reports the real state).
				if st, err := op.f.Stat(); err == nil {
					if cur, err := op.f.Seek(0, 1); err == nil && st.Size() > cur {
						nbytes = uint64(st.Size() - cur)
					}
				}
			}
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, uint16(errnos[i]), nbytes, flags)
		written += 32
	}

	abi.putWord(nev, uint64(written/32))
	return _wasiESUCCESS
}

// wasiEventHangup is eventrwflags' fd_readwrite_hangup: the peer of the
// descriptor has hung up. The guest's poll() reports it as POLLHUP. It is
// set on events for reading only (see Poll_oneoff).
const wasiEventHangup uint16 = 1

// streamFailed reports whether a stream is in error, as poll(2) tells it
// with POLLERR: the reader of a pipe has closed it. Only the host can tell,
// for a stream that is a descriptor of its own.
func streamFailed(stream any) bool {
	var failed bool
	hostDescriptor(stream, func(fd uintptr) { failed = hostFailed(fd) })
	return failed
}

// streamHungUp reports whether a stream has been hung up on, as poll(2)
// tells it with POLLHUP: the writers of a pipe have all closed it, a
// connection is shut down both ways. Only the host can tell, for a stream
// that is a descriptor of its own; of any other stream it is not known, and
// the guest finds the end of its input by reading it.
func streamHungUp(stream any) bool {
	var hup bool
	hostDescriptor(stream, func(fd uintptr) { hup, _ = hostHungUp(fd) })
	return hup
}

// pollProbe is one descriptor poll_oneoff has to probe for readiness: a
// stream, for input or for room to write, or a listening socket, for a
// connection. probe waits for it — no longer than until (the zero time is
// no limit), and not after stop is closed — and reports whether the
// descriptor is ready; what it took off the descriptor to find out stays
// with the descriptor's entry.
type pollProbe struct {
	op    *wasiOpen
	probe func(until time.Time, stop <-chan struct{}) bool
	ready bool
}

// pollReady waits until one of the probed descriptors is ready, or until
// deadline — the zero time means no limit — and records which are. For
// input the readiness test is a read: whatever arrives is kept on the
// descriptor and handed to the guest's next read of it. For output the host
// is asked, and nothing is written.
//
// cancel, when non-nil, ends the wait early once it is closed.
func pollReady(probes []pollProbe, deadline time.Time, cancel <-chan struct{}) {
	if len(probes) == 1 && cancel == nil {
		probes[0].ready = probes[0].probe(deadline, nil)
		return
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	hit := make(chan struct{}, len(probes))
	for i := range probes {
		wg.Add(1)
		go func(pr *pollProbe) {
			defer wg.Done()
			if pr.ready = pr.probe(deadline, stop); pr.ready {
				hit <- struct{}{}
			}
		}(&probes[i])
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-hit:
		// One is ready: stop waiting on the rest, once they have had the
		// time a probe needs to find what is ready right now — a poll
		// reports every descriptor that is ready, not the first. Their
		// probes then end at once, keeping whatever they had received.
		grace := time.NewTimer(pollProbeGrace)
		select {
		case <-done:
		case <-cancel:
		case <-grace.C:
		}
		grace.Stop()
	case <-cancel:
	case <-done:
	}
	close(stop)
	<-done
}

func writeEvent(dst []byte, userdata uint64, etype byte, errno uint16, nbytes uint64, flags uint16) {
	for i := range dst {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint64(dst[0:], userdata)
	binary.LittleEndian.PutUint16(dst[8:], errno)
	binary.LittleEndian.PutUint16(dst[10:], uint16(etype))
	binary.LittleEndian.PutUint64(dst[16:], nbytes)
	binary.LittleEndian.PutUint16(dst[24:], flags)
}

func (w *WasiStubs) Proc_exit(m *Module, code int32) {
	// Panic so SafeInvokeExport's recover catches it and surfaces a
	// *WasiExitError instead of killing the host process.
	panic(&WasiExitError{Code: code})
}

// Proc_exit64 is Proc_exit for a memory64 guest.
func (w *WasiStubs) Proc_exit64(m *Module, code int64) {
	w.Proc_exit(m, int32(code))
}

func (w *WasiStubs) Proc_raise(m *Module, sig int32) int32 {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return mapOSError(err)
	}
	hostSig, known := hostSignalOf(sig)
	if !known {
		return _wasiEINVAL
	}
	if err := p.Signal(hostSig); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Proc_raise64 is Proc_raise for a memory64 guest. The wasi-libc that
// memory64 guests are built with declares no proc_raise: this takes the
// one argument of the standard import widened to an i64, as that C
// library widens every argument of the standard imports.
func (w *WasiStubs) Proc_raise64(m *Module, sig int64) int32 {
	return w.Proc_raise(m, int32(sig))
}

// Sock_socket is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_socket") that backs a libc socket() call wrapped via
// -Wl,--wrap=socket in the guest. WASI preview1 has no way to create an
// outbound socket; this gives the guest a host-managed fd whose connection is
// established later by Sock_connect. The socket is an IPv4 one; typ is its
// type by the host's numbering (wasiSockType*: a libc's SOCK_* numbers
// differ from libc to libc): a stream socket (TCP) or a datagram socket
// (UDP). Returns the new fd, or a negative errno: EPROTONOSUPPORT for
// another type.
func (w *WasiStubs) Sock_socket(m *Module, domain, typ int32) int32 {
	// The bridge's socket() shim has already validated the family against the
	// guest's AF_INET before calling us, so we do not re-check domain here
	// (the guest's AF_INET numeric value need not match the host's).
	_ = domain
	if typ != wasiSockTypeStream && typ != wasiSockTypeDgram {
		return -_wasiEPROTONOSUPPORT
	}
	return w.openSocket(wasiSockFamilyIPv4, typ)
}

// Sock_socket64 is Sock_socket for a memory64 guest.
func (w *WasiStubs) Sock_socket64(m *Module, domain, typ int32) int32 {
	return w.Sock_socket(m, domain, typ)
}

// openSocket makes a socket of the family and type and returns its fd, or
// a negative errno. A guest whose descriptors are the host process's gets
// a socket of the host's at once; any other gets an entry that has a host
// socket as soon as it needs one.
func (w *WasiStubs) openSocket(family, typ int32) int32 {
	w.mu.Lock()
	host := w.hostDescriptorsLocked()
	w.mu.Unlock()
	if host {
		fds, errno := w.openHostSockets(family, typ, false)
		if errno != _wasiESUCCESS {
			return -errno
		}
		return fds[0]
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(&wasiOpen{isSocket: true, dgram: typ == wasiSockTypeDgram, family: family})
}

// The socket types of Sock_socket and of the SO_TYPE option.
const (
	wasiSockTypeStream int32 = 1
	wasiSockTypeDgram  int32 = 2
)

// Sock_connect is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_connect") backing a libc connect() wrapped via
// -Wl,--wrap=connect. ipBE carries the IPv4 address in network byte order
// exactly as it sat in sockaddr_in.sin_addr.s_addr (so the low byte is the
// first octet); port is host byte order. It consults the dial whitelist,
// dials via Go's net, and attaches the resulting conn to the socket fd so the
// existing Sock_send / Sock_recv / Fd_close paths drive it. Returns 0 or a
// negative errno; see connectStream for what a blocking and a non-blocking
// socket do. Sock_connect_addr is the same for an address of any family.
func (w *WasiStubs) Sock_connect(m *Module, fd, ipBE, port int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || !op.isSocket {
		return -_wasiENOTSOCK
	}
	return -w.connectSocket(op, ipv4SockAddr(ipBE, port), "")
}

// Sock_connect64 is Sock_connect for a memory64 guest.
func (w *WasiStubs) Sock_connect64(m *Module, fd, ipBE, port int32) int32 {
	return w.Sock_connect(m, fd, ipBE, port)
}

// Sock_accept accepts the next incoming TCP/Unix connection on the
// listener associated with fd, registers it as a new socket entry (with
// flags as its fdflags), and writes the new fd at fdOutPtr. It waits for a
// connection unless the listening socket is non-blocking, in which case it
// reports EAGAIN when none is there. Returns 0 or an errno: ENOTSOCK if fd
// isn't a listener, EINVAL for a socket the guest has bound but not
// called listen on, EINTR when a signal is posted to the guest while it
// waits.
func (w *WasiStubs) Sock_accept(m *Module, fd, flags, fdOutPtr int32) int32 {
	return w.sockAccept(m, fd, flags, zext(fdOutPtr))
}

// Sock_accept64 is Sock_accept for a memory64 guest.
func (w *WasiStubs) Sock_accept64(m *Module, fd, flags, fdOutPtr int64) int32 {
	return w.sockAccept(m, int32(fd), int32(flags), uint64(fdOutPtr))
}

// sockAccept is the body of Sock_accept and Sock_accept64.
func (w *WasiStubs) sockAccept(m *Module, fd, flags int32, fdOutPtr uint64) int32 {
	if !w.checkNet("accept") {
		return _wasiEACCES
	}
	out := w.memBytes(m, fdOutPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		// as Sock_recv and Sock_send report a descriptor that is not open
		return _wasiENOTSOCK
	}
	if op.dgram {
		return _wasiENOTSUP // EOPNOTSUPP: a datagram socket takes no connections
	}
	if h := op.host(); h != nil {
		accepted, errno := w.acceptHost(op, h)
		if errno != _wasiESUCCESS {
			return errno
		}
		if flags&wasiFdflagNonblock != 0 {
			_ = accepted.host().setFdflags(flags)
		}
		w.mu.Lock()
		newFD, err := w.addHostFDLocked(accepted)
		w.mu.Unlock()
		if err != nil {
			return mapOSError(errors.Join(err, accepted.f.Close()))
		}
		binary.LittleEndian.PutUint32(out, uint32(newFD))
		return _wasiESUCCESS
	}
	l, listening := op.netListener()
	if l == nil {
		if op.isSocket {
			return _wasiEINVAL
		}
		return _wasiENOTSOCK
	}
	if op.isSocket && !listening {
		return _wasiEINVAL
	}
	// What a readiness probe already accepted comes first.
	conn, err, taken := op.takeAccepted()
	if !taken {
		bounded, canBound := l.(deadlineListener)
		switch {
		case !canBound:
			conn, err = l.Accept()
		case op.nonblocking():
			// Long enough for the accept to be attempted, as for a
			// readiness probe.
			if !op.probeAccept(bounded, time.Now().Add(pollProbeGrace), nil) {
				return _wasiEAGAIN
			}
			if conn, err, taken = op.takeAccepted(); !taken {
				// another process sharing the listener took it first
				return _wasiEAGAIN
			}
		default:
			if limit, _ := op.timeouts(); limit > 0 {
				errno := w.awaitWithin(limit, func(until time.Time, stop <-chan struct{}) bool {
					return op.probeAccept(bounded, until, stop)
				})
				if errno != _wasiESUCCESS {
					return errno
				}
				if conn, err, taken = op.takeAccepted(); !taken {
					// another process sharing the listener took it first
					return _wasiEAGAIN
				}
				break
			}
			var interrupted bool
			if conn, err, interrupted = w.acceptInterruptibly(op, bounded); interrupted {
				return _wasiEINTR
			}
		}
	}
	if err != nil {
		return mapNetError(err)
	}
	accepted := &wasiOpen{conn: conn, isSocket: true, fdflags: flags, family: op.socketFamily()}
	op.mu.Lock()
	if op.sock != nil && op.sock.unixLocal != "" {
		// the local name of the connection is the listener's
		accepted.sock = &wasiSocket{unixLocal: op.sock.unixLocal}
	}
	op.mu.Unlock()
	w.mu.Lock()
	newFD := w.addFDLocked(accepted)
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(newFD))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_recv(m *Module, fd, riData, riDataLen, riFlags, roDataLenPtr, roFlagsPtr int32) int32 {
	return w.sockRecv(m, wasiABI32, fd, zext(riData), zext(riDataLen), riFlags, zext(roDataLenPtr), zext(roFlagsPtr))
}

// Sock_recv64 is Sock_recv for a memory64 guest.
func (w *WasiStubs) Sock_recv64(m *Module, fd, riData, riDataLen, riFlags, roDataLenPtr, roFlagsPtr int64) int32 {
	return w.sockRecv(m, wasiABI64, int32(fd), uint64(riData), uint64(riDataLen), int32(riFlags), uint64(roDataLenPtr), uint64(roFlagsPtr))
}

// sockRecv is the body of Sock_recv and Sock_recv64.
func (w *WasiStubs) sockRecv(m *Module, abi wasiABI, fd int32, riData, riDataLen uint64, riFlags int32, roDataLenPtr, roFlagsPtr uint64) int32 {
	if !w.checkNet("recv") {
		return _wasiEACCES
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	var conn net.Conn
	if op != nil {
		conn = op.netConn()
	}
	if conn == nil && op.host() == nil {
		return _wasiENOTSOCK
	}
	bufs, ok := w.iovecSlices(m, abi, riData, riDataLen)
	// ro_datalen is a __wasi_size_t.
	lenOut := w.memBytes(m, roDataLenPtr, abi.wordSize())
	// ro_flags is a __wasi_roflags_t — a 16-bit value. wasi-libc packs it
	// immediately before ro_datalen (only 2 bytes apart), so writing 4 bytes
	// here would clobber the low half of ro_datalen and make recv() report 0
	// bytes received even when data arrived.
	flagsOut := w.memBytes(m, roFlagsPtr, 2)
	if !ok || lenOut == nil || flagsOut == nil {
		return _wasiEFAULT
	}
	// ri_flags has two bits, RECV_PEEK and RECV_WAITALL: wasiMsgPeek and
	// wasiMsgWaitAll.
	flags := riFlags & (wasiMsgPeek | wasiMsgWaitAll)
	if h := op.host(); h != nil {
		if !h.socket() {
			return _wasiENOTSOCK
		}
		n, _, errno := w.receiveHost(h, bufs, flags)
		if errno != _wasiESUCCESS {
			return errno
		}
		binary.LittleEndian.PutUint16(flagsOut, 0)
		abi.putWord(lenOut, uint64(n))
		return _wasiESUCCESS
	}
	if dg, isDatagram := conn.(datagramSocket); isDatagram && op.dgram {
		n, _, errno := w.receiveDatagram(op, dg, bufs, flags)
		if errno != _wasiESUCCESS {
			return errno
		}
		binary.LittleEndian.PutUint16(flagsOut, 0)
		abi.putWord(lenOut, uint64(n))
		return _wasiESUCCESS
	}
	got, errno := w.receiveStream(op, conn, bufs, flags)
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint16(flagsOut, 0)
	abi.putWord(lenOut, uint64(got))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_send(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int32) int32 {
	return w.sockSend(m, wasiABI32, fd, zext(siData), zext(siDataLen), siFlags, zext(soDataLenPtr))
}

// Sock_send64 is Sock_send for a memory64 guest.
func (w *WasiStubs) Sock_send64(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int64) int32 {
	return w.sockSend(m, wasiABI64, int32(fd), uint64(siData), uint64(siDataLen), int32(siFlags), uint64(soDataLenPtr))
}

// sockSend is the body of Sock_send and Sock_send64.
func (w *WasiStubs) sockSend(m *Module, abi wasiABI, fd int32, siData, siDataLen uint64, siFlags int32, soDataLenPtr uint64) int32 {
	if !w.checkNet("send") {
		return _wasiEACCES
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	var conn net.Conn
	if op != nil {
		conn = op.netConn()
	}
	h := op.host()
	if conn == nil && h == nil {
		if op != nil && op.isSocket {
			return _wasiENOTCONN
		}
		return _wasiENOTSOCK
	}
	bufs, ok := w.iovecSlices(m, abi, siData, siDataLen)
	// so_datalen is a __wasi_size_t.
	lenOut := w.memBytes(m, soDataLenPtr, abi.wordSize())
	if !ok || lenOut == nil {
		return _wasiEFAULT
	}
	if h != nil {
		if !h.socket() {
			return _wasiENOTSOCK
		}
		n, errno := w.sendHost(op, h, bufs, nil, 0)
		abi.putWord(lenOut, uint64(n))
		return errno
	}
	// WASI defines no flags for a send; siFlags is always 0.
	n, errno := w.writeFd(op, conn, bufs)
	abi.putWord(lenOut, uint64(n))
	return errno
}

func (w *WasiStubs) Sock_shutdown(m *Module, fd, how int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if h := op.host(); h != nil {
		return w.shutdownHost(h, how)
	}
	var conn net.Conn
	if op != nil {
		conn = op.netConn()
	}
	if conn == nil {
		return _wasiENOTSOCK
	}
	type shutdowner interface {
		CloseRead() error
		CloseWrite() error
	}
	sh, ok := conn.(shutdowner)
	if !ok && op.dgram {
		// There is no connection to shut down, and the socket stays open.
		return _wasiESUCCESS
	}
	if !ok {
		// Generic conn: just close it. Surface a failure via the wasi
		// errno so the guest can see write-on-broken-socket failures.
		if err := conn.Close(); err != nil {
			return mapOSError(err)
		}
		return _wasiESUCCESS
	}
	var shErr error
	if how&0x1 != 0 {
		shErr = errors.Join(shErr, sh.CloseRead())
	}
	if how&0x2 != 0 {
		shErr = errors.Join(shErr, sh.CloseWrite())
	}
	if shErr != nil {
		return mapNetError(shErr)
	}
	return _wasiESUCCESS
}

// Sock_shutdown64 is Sock_shutdown for a memory64 guest.
func (w *WasiStubs) Sock_shutdown64(m *Module, fd, how int64) int32 {
	return w.Sock_shutdown(m, int32(fd), int32(how))
}

// writeFilestat populates the 64-byte WASI filestat structure from a
// backend's os.FileInfo. The device, inode, link count and the access and
// status-change times are the POSIX metadata fileStatOf finds in it.
func writeFilestat(out []byte, st os.FileInfo) {
	posix := fileStatOf(st)
	binary.LittleEndian.PutUint64(out[0:], posix.dev)
	binary.LittleEndian.PutUint64(out[8:], posix.ino)
	// WASI's file types: 1 block device, 2 character device, 3 directory,
	// 4 regular file, 6 stream socket, 7 symbolic link. There is none for
	// a FIFO, which is therefore "unknown" (0) here — not a socket — and
	// gets its type from the filestat_ext record.
	var ftype byte = 4
	switch unixTypeBits(st.Mode()) {
	case unixTypeDir:
		ftype = 3
	case unixTypeSymlink:
		ftype = 7
	case unixTypeFIFO:
		ftype = 0
	case unixTypeSocket:
		ftype = 6
	case unixTypeChar:
		ftype = 2
	case unixTypeBlock:
		ftype = 1
	}
	out[16] = ftype
	binary.LittleEndian.PutUint64(out[24:], posix.nlink)
	binary.LittleEndian.PutUint64(out[32:], uint64(st.Size()))
	binary.LittleEndian.PutUint64(out[40:], uint64(posix.atime.UnixNano()))
	binary.LittleEndian.PutUint64(out[48:], uint64(st.ModTime().UnixNano()))
	binary.LittleEndian.PutUint64(out[56:], uint64(posix.ctime.UnixNano()))
}

// The guest's signal numbers are Linux's, which is what wasi-libc's
// <signal.h> defines. A host has its own (SIGUSR1 is 10 here and 30 on
// macOS), so a number never crosses to or from the host OS as it is:
// hostSignalOf and guestSignalOf translate it by the signal's identity.
const (
	wasiSIGHUP    int32 = 1
	wasiSIGINT    int32 = 2
	wasiSIGQUIT   int32 = 3
	wasiSIGILL    int32 = 4
	wasiSIGTRAP   int32 = 5
	wasiSIGABRT   int32 = 6
	wasiSIGBUS    int32 = 7
	wasiSIGFPE    int32 = 8
	wasiSIGKILL   int32 = 9
	wasiSIGUSR1   int32 = 10
	wasiSIGSEGV   int32 = 11
	wasiSIGUSR2   int32 = 12
	wasiSIGPIPE   int32 = 13
	wasiSIGALRM   int32 = 14
	wasiSIGTERM   int32 = 15
	wasiSIGCHLD   int32 = 17
	wasiSIGCONT   int32 = 18
	wasiSIGSTOP   int32 = 19
	wasiSIGTSTP   int32 = 20
	wasiSIGTTIN   int32 = 21
	wasiSIGTTOU   int32 = 22
	wasiSIGURG    int32 = 23
	wasiSIGXCPU   int32 = 24
	wasiSIGXFSZ   int32 = 25
	wasiSIGVTALRM int32 = 26
	wasiSIGPROF   int32 = 27
	wasiSIGWINCH  int32 = 28
	wasiSIGIO     int32 = 29
	wasiSIGSYS    int32 = 31
)

// ----- process identity -------------------------------------------------------

// SetHostProcess declares that the guest program IS the host process, the
// way a command-line tool built around one instance is. With it
//
//   - the process and parent process ids, the user and group ids and the
//     user and group databases the guest sees are the host's (Proc_ids,
//     Proc_groups, Proc_user_by_id, ...);
//   - a signal the host process receives and the guest handles is posted to
//     the guest (see PostSignal), and a signal the guest ignores is ignored
//     by the host process;
//   - Proc_kill reaches host processes that are not processes of this
//     instance;
//   - on Linux and macOS the guest's descriptors are the host process's:
//     descriptor N of the guest is descriptor N of the process, a new one
//     gets the lowest number the process has free, the blocking mode is the
//     open file's, and a descriptor that code outside the guest opened is
//     the guest's to use under its number (wasip1_native_hostfd.go). Every
//     descriptor of the process is within the guest's reach that way,
//     except those of another instance, those the runtime holds for itself
//     — what was open and close-on-exec when the first instance became the
//     host process, and every number from 1024 up (hostFloor) —
//     and the standard descriptors when the instance's streams are not
//     those: an embedder that keeps descriptors of its own while such a
//     guest runs opens them before, or duplicates them to 1024 or above.
//     What the guest does to the standard descriptors it was given it does
//     to the process's, for good: one it closed stays closed and one it
//     redirected stays redirected when the instance ends (CloseAll).
//
// Without it (the default) the guest is an isolated process of its own:
// pid 42, parent 1, user and group 0, empty user and group databases, no
// way to signal anything but its own processes, and descriptors of its own
// that are not the host's.
//
// An instance derived through Fork keeps the identity — the same user, the
// same databases, the same reach of Proc_kill, the same descriptors — but
// is not the host process: signals the host process receives go to the
// instance SetHostProcess was called on.
func (w *WasiStubs) SetHostProcess(on bool) {
	if on {
		KeepRuntimeDescriptorsHigh()
		forwardSIGPIPEToIgnore()
	}
	w.mu.Lock()
	w.hostProcess = on
	w.mu.Unlock()
	w.syncHostSignals()
}

// AdoptInheritedDescriptors gives the instance the descriptors above the
// standard three that the host process was started with, under their
// numbers: a program started as `prog 5<file` finds descriptor 5 open, as
// it would as a process of its own. It is for the instance that is the
// host process (SetHostProcess). The descriptors become the guest's: files,
// pipes and terminals as they are, sockets as the sockets they are
// (connected, bound or listening), and they are closed when the guest
// closes them. They are the process's, so one instance gets them: the first
// that asks, and a later call does nothing.
//
// For a guest with descriptors of its own, the number of the preopened root
// (3) is not the guest's to use: a descriptor inherited under that number
// is left alone, out of the guest's reach. A guest whose descriptors are
// the host process's has it like the others.
func (w *WasiStubs) AdoptInheritedDescriptors() {
	inheritedOnce.Do(func() {
		for _, fd := range inheritedDescriptors() {
			w.mu.Lock()
			host := w.hostDescriptorsLocked()
			w.mu.Unlock()
			if host {
				// The descriptor is the guest's as it is, under its number.
				if op := inheritedHostDescriptor(fd); op != nil {
					w.mu.Lock()
					_, _ = w.addHostFDLocked(op)
					w.mu.Unlock()
					continue
				}
			} else if int32(fd) == wasiPreopenFD {
				continue
			}
			op := adoptHostDescriptor(fd)
			if op == nil {
				continue
			}
			w.mu.Lock()
			if _, used := w.fdsLocked()[int32(fd)]; used {
				w.mu.Unlock()
				_ = closeWasiOpen(op)
				continue
			}
			w.fdsLocked()[int32(fd)] = op
			w.mu.Unlock()
		}
	})
}

// hostIdentity reports whether the guest sees the host's identity.
func (w *WasiStubs) hostIdentity() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hostProcess
}

// The identity an isolated guest has: the values wasi-libc's own emulation
// reports.
const (
	wasiIsolatedPID  = 42
	wasiIsolatedPPID = 1
)

// Proc_ids is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "proc_ids") backing getpid, getppid and the getuid family. It writes
// six little-endian u32 at outPtr: pid, ppid, uid, euid, gid, egid. A
// process made by Proc_fork has the pid it was forked under, and for a
// parent the process that forked it until that one is gone, then 1. Returns
// 0 or a negative errno.
func (w *WasiStubs) Proc_ids(m *Module, outPtr int32) int32 {
	return w.procIDs(m, zext(outPtr))
}

// Proc_ids64 is Proc_ids for a memory64 guest.
func (w *WasiStubs) Proc_ids64(m *Module, outPtr int64) int32 {
	return w.procIDs(m, uint64(outPtr))
}

// procIDs is the body of Proc_ids and Proc_ids64.
func (w *WasiStubs) procIDs(m *Module, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 24)
	if out == nil {
		return -_wasiEFAULT
	}
	ids := [6]uint32{wasiIsolatedPID, wasiIsolatedPPID, 0, 0, 0, 0}
	if w.hostIdentity() {
		ids = [6]uint32{
			uint32(os.Getpid()), uint32(os.Getppid()),
			uint32(os.Getuid()), uint32(os.Geteuid()),
			uint32(os.Getgid()), uint32(os.Getegid()),
		}
	}
	if w.pid != 0 {
		// A forked process: the token it was forked under, and the process
		// that forked it for as long as that one exists. An orphan is
		// adopted by process 1, as on Unix.
		ids[0], ids[1] = uint32(w.pid), 1
		if pid, alive := w.parent.processID(); alive {
			ids[1] = uint32(pid)
		}
	}
	for i, id := range ids {
		binary.LittleEndian.PutUint32(out[i*4:], id)
	}
	return _wasiESUCCESS
}

// processIDLocked returns the pid the guest of this instance has. Caller
// holds w.mu.
func (w *WasiStubs) processIDLocked() int32 {
	switch {
	case w.pid != 0:
		return w.pid
	case w.hostProcess && !w.forked:
		return int32(os.Getpid())
	default:
		return wasiIsolatedPID
	}
}

// processID returns the pid the guest of this instance has, and whether the
// instance still exists.
func (w *WasiStubs) processID() (pid int32, alive bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.processIDLocked(), !w.ended
}

// ----- what the host process is and does ---------------------------------------

// Proc_times is a NON-STANDARD host import (name "proc_times") backing
// times(2): four little-endian u64 of nanoseconds are written at outPtr —
// the user and system CPU time of the process, then those of the children
// it has waited for. Every process of a fork family is part of one host
// process, whose times these are. Returns 0, or a negative errno: ENOSYS on
// a host that does not account for them.
func (w *WasiStubs) Proc_times(m *Module, outPtr int32) int32 {
	return w.procTimes(m, zext(outPtr))
}

// Proc_times64 is Proc_times for a memory64 guest.
func (w *WasiStubs) Proc_times64(m *Module, outPtr int64) int32 {
	return w.procTimes(m, uint64(outPtr))
}

// procTimes is the body of Proc_times and Proc_times64.
func (w *WasiStubs) procTimes(m *Module, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 32)
	if out == nil {
		return -_wasiEFAULT
	}
	times, err := hostProcessTimes()
	if err != nil {
		return -_wasiENOSYS
	}
	for i, d := range times {
		binary.LittleEndian.PutUint64(out[i*8:], uint64(d))
	}
	return _wasiESUCCESS
}

// Proc_priority is a NON-STANDARD host import (name "proc_priority")
// backing getpriority, setpriority and nice for a guest that is the host
// process. which is PRIO_PROCESS (0), PRIO_PGRP (1) or PRIO_USER (2) and
// who the id it applies to, 0 for the caller's own; a process of the fork
// family is the host process. With set non-zero the nice value becomes
// value; the nice value then in effect is written at outPtr (i32). Returns
// 0, or a negative errno: ENOSYS for a guest that is not the host process,
// which has no priority to speak of.
func (w *WasiStubs) Proc_priority(m *Module, which, who, set, value, outPtr int32) int32 {
	return w.procPriority(m, which, who, set, value, zext(outPtr))
}

// Proc_priority64 is Proc_priority for a memory64 guest.
func (w *WasiStubs) Proc_priority64(m *Module, which, who, set, value int32, outPtr int64) int32 {
	return w.procPriority(m, which, who, set, value, uint64(outPtr))
}

// procPriority is the body of Proc_priority and Proc_priority64.
func (w *WasiStubs) procPriority(m *Module, which, who, set, value int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	host := w.hostProcess
	self := w.processIDLocked()
	token := w.pidsLocked().allocated(who)
	w.mu.Unlock()
	if !host {
		return -_wasiENOSYS
	}
	if which == 0 && (who == self || token) {
		who = 0
	}
	if set != 0 {
		if err := setHostPriority(int(which), int(who), int(value)); err != nil {
			return -mapOSError(err)
		}
	}
	nice, err := hostPriority(int(which), int(who))
	if err != nil {
		return -mapOSError(err)
	}
	binary.LittleEndian.PutUint32(out, uint32(int32(nice)))
	return _wasiESUCCESS
}

// Path_mkfifo is a NON-STANDARD host import (name "path_mkfifo") backing
// mkfifo: it creates a FIFO at the preopen-relative path with the given
// permission bits, less the instance's umask. Returns 0, or a negative
// errno: ENOSYS when the filesystem of the instance has no FIFOs.
func (w *WasiStubs) Path_mkfifo(m *Module, pathPtr, pathLen, mode int32) int32 {
	return w.pathMkfifo(m, zext(pathPtr), pathLen, mode)
}

// Path_mkfifo64 is Path_mkfifo for a memory64 guest.
func (w *WasiStubs) Path_mkfifo64(m *Module, pathPtr int64, pathLen, mode int32) int32 {
	return w.pathMkfifo(m, uint64(pathPtr), pathLen, mode)
}

// pathMkfifo is the body of Path_mkfifo and Path_mkfifo64.
func (w *WasiStubs) pathMkfifo(m *Module, pathPtr uint64, pathLen, mode int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	path := string(pathSlice)
	if !w.checkFS(path, true) {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	maker, can := fsys.(interface {
		Mkfifo(name string, perm os.FileMode) error
	})
	if !can {
		return -_wasiENOSYS
	}
	if err := maker.Mkfifo(path, w.createMode(unixFileMode(uint32(mode)).Perm())); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return -_wasiENOSYS
		}
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Mkfifo creates a FIFO in the host filesystem.
func (o osFS) Mkfifo(name string, perm os.FileMode) error {
	return makeHostFIFO(o.join(name), perm)
}

// Chown changes the owner and group of a file of the host filesystem; -1
// leaves an id as it is. With follow false a symbolic link itself is
// changed, not the file it names.
func (o osFS) Chown(name string, uid, gid int, follow bool) error {
	if follow {
		return os.Chown(o.join(name), uid, gid)
	}
	return os.Lchown(o.join(name), uid, gid)
}

// Path_chown is a NON-STANDARD host import (name "path_chown") backing
// chown and lchown (follow 0) for the preopen-relative path; an id of -1
// is left as it is. Returns 0, or a negative errno: ENOSYS when the
// filesystem of the instance keeps no owners.
func (w *WasiStubs) Path_chown(m *Module, pathPtr, pathLen, uid, gid, follow int32) int32 {
	return w.pathChown(m, zext(pathPtr), pathLen, uid, gid, follow)
}

// Path_chown64 is Path_chown for a memory64 guest.
func (w *WasiStubs) Path_chown64(m *Module, pathPtr int64, pathLen, uid, gid, follow int32) int32 {
	return w.pathChown(m, uint64(pathPtr), pathLen, uid, gid, follow)
}

// pathChown is the body of Path_chown and Path_chown64.
func (w *WasiStubs) pathChown(m *Module, pathPtr uint64, pathLen, uid, gid, follow int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	path := string(pathSlice)
	if !w.checkFS(path, true) {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	owner, can := fsys.(interface {
		Chown(name string, uid, gid int, follow bool) error
	})
	if !can {
		return -_wasiENOSYS
	}
	if err := owner.Chown(path, int(uid), int(gid), follow != 0); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return -_wasiENOSYS
		}
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_chown is a NON-STANDARD host import (name "fd_chown") backing fchown.
// Returns 0, or a negative errno: ENOSYS for a descriptor that is not a
// file of the host.
func (w *WasiStubs) Fd_chown(m *Module, fd, uid, gid int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	file, isHostFile := op.f.(*os.File)
	if !isHostFile {
		return -_wasiENOSYS
	}
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_chown64 is Fd_chown for a memory64 guest.
func (w *WasiStubs) Fd_chown64(m *Module, fd, uid, gid int32) int32 {
	return w.Fd_chown(m, fd, uid, gid)
}

// The requests of Proc_setids.
const (
	wasiSetUID    int32 = iota // setuid(a)
	wasiSetEUID                // seteuid(a)
	wasiSetREUID               // setreuid(a, b)
	wasiSetRESUID              // setresuid(a, b, c)
	wasiSetGID                 // setgid(a)
	wasiSetEGID                // setegid(a)
	wasiSetREGID               // setregid(a, b)
	wasiSetRESGID              // setresgid(a, b, c)
)

// HostIDs changes the user and group ids of the host process: the calls of
// the setuid and setgid families, with their arguments (-1 for an id to
// leave alone) and their errors (a syscall.Errno), and setgroups. An
// embedder gives one (SetHostIDs) when its process changes its ids by
// other means than the Go runtime's — a process linked with a C library
// has to go through that library, which keeps the threads of the process
// in step.
//
// The error of a call that failed is the error number it failed with
// (the C library's errno, read on the thread that made the call), which
// the guest is given as the wasi errno of the same meaning. An error that
// carries no number — a syscall.Errno of 0, as a foreign-function call
// that does not collect errno reports — tells the guest nothing but that
// the call failed: it gets EIO.
type HostIDs interface {
	Setuid(uid int) error
	Seteuid(euid int) error
	Setreuid(ruid, euid int) error
	Setresuid(ruid, euid, suid int) error
	Setgid(gid int) error
	Setegid(egid int) error
	Setregid(rgid, egid int) error
	Setresgid(rgid, egid, sgid int) error
	Setgroups(gids []int) error
}

// SetHostIDs makes ids the way the guest's setuid and setgid families and
// setgroups change the ids of the host process (see HostIDs); nil is the
// runtime's own way, the default. It matters for a guest that is the host
// process (SetHostProcess) only: no other guest changes ids.
func (w *WasiStubs) SetHostIDs(ids HostIDs) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hostIDs = ids
}

// changeHostIDs is setHostIDs by the embedder's means when it gave some.
func (w *WasiStubs) changeHostIDs(request int32, a, b, c int) error {
	w.mu.Lock()
	ids := w.hostIDs
	w.mu.Unlock()
	if ids == nil {
		return setHostIDs(request, a, b, c)
	}
	switch request {
	case wasiSetUID:
		return ids.Setuid(a)
	case wasiSetEUID:
		return ids.Seteuid(a)
	case wasiSetREUID:
		return ids.Setreuid(a, b)
	case wasiSetRESUID:
		return ids.Setresuid(a, b, c)
	case wasiSetGID:
		return ids.Setgid(a)
	case wasiSetEGID:
		return ids.Setegid(a)
	case wasiSetREGID:
		return ids.Setregid(a, b)
	case wasiSetRESGID:
		return ids.Setresgid(a, b, c)
	}
	return syscall.EINVAL
}

// Proc_setids is a NON-STANDARD host import (name "proc_setids") backing
// the setuid and setgid families for a guest that is the host process:
// request names the call (wasiSetUID ...) and a, b, c are its arguments, -1
// for an id to leave alone. The ids are the host process's, so every
// process of the fork family changes with it. Returns 0, or a negative
// errno: ENOSYS for a guest that is not the host process.
func (w *WasiStubs) Proc_setids(m *Module, request, a, b, c int32) int32 {
	if !w.hostIdentity() {
		return -_wasiENOSYS
	}
	if err := w.changeHostIDs(request, int(a), int(b), int(c)); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return -_wasiENOSYS
		}
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Proc_setids64 is Proc_setids for a memory64 guest.
func (w *WasiStubs) Proc_setids64(m *Module, request, a, b, c int32) int32 {
	return w.Proc_setids(m, request, a, b, c)
}

// Proc_setgroups is a NON-STANDARD host import (name "proc_setgroups")
// backing setgroups for a guest that is the host process: count u32 group
// ids at listPtr become the supplementary groups. Returns 0, or a negative
// errno: ENOSYS for a guest that is not the host process.
func (w *WasiStubs) Proc_setgroups(m *Module, listPtr, count int32) int32 {
	return w.procSetgroups(m, zext(listPtr), count)
}

// Proc_setgroups64 is Proc_setgroups for a memory64 guest.
func (w *WasiStubs) Proc_setgroups64(m *Module, listPtr int64, count int32) int32 {
	return w.procSetgroups(m, uint64(listPtr), count)
}

// procSetgroups is the body of Proc_setgroups and Proc_setgroups64.
func (w *WasiStubs) procSetgroups(m *Module, listPtr uint64, count int32) int32 {
	if count < 0 || count > 65536 {
		return -_wasiEINVAL
	}
	list := w.memBytes(m, listPtr, zext(count*4))
	if list == nil && count > 0 {
		return -_wasiEFAULT
	}
	if !w.hostIdentity() {
		return -_wasiENOSYS
	}
	gids := make([]int, count)
	for i := range gids {
		gids[i] = int(binary.LittleEndian.Uint32(list[i*4:]))
	}
	w.mu.Lock()
	ids := w.hostIDs
	w.mu.Unlock()
	var err error
	if ids != nil {
		err = ids.Setgroups(gids)
	} else {
		err = setHostGroups(gids)
	}
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return -_wasiENOSYS
		}
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Proc_uname is a NON-STANDARD host import (name "proc_uname") backing
// uname and gethostname for a guest that is the host process. The record
// (writeWasiRecord) is five strings: the system's name, the node's name on
// the network, the release, the version and the machine type. Returns 0, or
// a negative errno: ENOSYS for a guest that is not the host process — it is
// a system of its own — and on a host that cannot say.
func (w *WasiStubs) Proc_uname(m *Module, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUname(m, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_uname64 is Proc_uname for a memory64 guest.
func (w *WasiStubs) Proc_uname64(m *Module, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUname(m, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUname is the body of Proc_uname and Proc_uname64.
func (w *WasiStubs) procUname(m *Module, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if !w.hostIdentity() {
		return -_wasiENOSYS
	}
	fields, err := hostSystemName()
	if err != nil {
		return -_wasiENOSYS
	}
	var rec []byte
	for _, field := range fields {
		rec = appendWasiString(rec, field)
	}
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Proc_chdir is a NON-STANDARD host import (name "proc_chdir"). The working
// directory of a guest is kept by its libc; the guest reports every change
// here, and when it is the host process the host process follows — code of
// the host that runs for the program (a native extension, a library it
// loads) then finds the directory the program is in. path is absolute.
//
// The processes of a fork family share the one host process, which has one
// working directory: it is the first process's. A forked process's change
// stays its own.
//
// Returns 0 or a negative errno.
func (w *WasiStubs) Proc_chdir(m *Module, pathPtr, pathLen int32) int32 {
	return w.procChdir(m, zext(pathPtr), pathLen)
}

// Proc_chdir64 is Proc_chdir for a memory64 guest.
func (w *WasiStubs) Proc_chdir64(m *Module, pathPtr int64, pathLen int32) int32 {
	return w.procChdir(m, uint64(pathPtr), pathLen)
}

// procChdir is the body of Proc_chdir and Proc_chdir64.
func (w *WasiStubs) procChdir(m *Module, pathPtr uint64, pathLen int32) int32 {
	path := w.memBytes(m, pathPtr, zext(pathLen))
	if path == nil {
		return -_wasiEFAULT
	}
	if !w.isHostProcess() {
		return _wasiESUCCESS
	}
	if err := os.Chdir(string(path)); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Proc_setenv is a NON-STANDARD host import (name "proc_setenv"), the
// counterpart of Proc_chdir for the environment: the guest reports every
// variable it sets (hasValue non-zero) or removes, and when it is the host
// process the host process's environment follows. A forked process's
// change stays its own. Returns 0 or a negative errno.
func (w *WasiStubs) Proc_setenv(m *Module, namePtr, nameLen, valuePtr, valueLen, hasValue int32) int32 {
	return w.procSetenv(m, zext(namePtr), nameLen, zext(valuePtr), valueLen, hasValue)
}

// Proc_setenv64 is Proc_setenv for a memory64 guest.
func (w *WasiStubs) Proc_setenv64(m *Module, namePtr int64, nameLen int32, valuePtr int64, valueLen, hasValue int32) int32 {
	return w.procSetenv(m, uint64(namePtr), nameLen, uint64(valuePtr), valueLen, hasValue)
}

// procSetenv is the body of Proc_setenv and Proc_setenv64.
func (w *WasiStubs) procSetenv(m *Module, namePtr uint64, nameLen int32, valuePtr uint64, valueLen, hasValue int32) int32 {
	name := w.memBytes(m, namePtr, zext(nameLen))
	value := w.memBytes(m, valuePtr, zext(valueLen))
	if name == nil || (value == nil && hasValue != 0) {
		return -_wasiEFAULT
	}
	if !w.isHostProcess() {
		return _wasiESUCCESS
	}
	var err error
	if hasValue != 0 {
		err = os.Setenv(string(name), string(value))
	} else {
		err = os.Unsetenv(string(name))
	}
	if err != nil {
		return -_wasiEINVAL
	}
	return _wasiESUCCESS
}

// ----- network databases -------------------------------------------------------

// wasiService is one entry of the services database.
type wasiService struct {
	name    string
	aliases []string
	port    int
	proto   string
}

// hostServicesFile is the services database of a Unix host, services(5):
// one service per line — its name, port/protocol, and aliases — with
// comments from a # to the end of the line.
const hostServicesFile = "/etc/services"

// findHostService returns the first entry of the host's services database
// that match accepts. The file is read anew for every lookup: lookups are
// rare, and the file is the host's to change.
func findHostService(match func(wasiService) bool) (found wasiService, ok bool) {
	raw, err := os.ReadFile(hostServicesFile)
	if err != nil {
		return found, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if at := strings.IndexByte(line, '#'); at >= 0 {
			line = line[:at]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		portText, proto, isPair := strings.Cut(fields[1], "/")
		port, err := strconv.Atoi(portText)
		if !isPair || err != nil {
			continue
		}
		entry := wasiService{name: fields[0], aliases: fields[2:], port: port, proto: proto}
		if match(entry) {
			return entry, true
		}
	}
	return found, false
}

// Sock_service is a NON-STANDARD host import (name "sock_service") backing
// getservbyname and getservbyport for a guest that is the host process: the
// service called name (by its name or an alias) when byPort is 0, or the
// service on port otherwise, for the protocol proto when that is not
// empty. The record (writeWasiRecord) is the port (u32), the name, the
// protocol, the number of aliases (u32) and the aliases, strings as
// appendWasiString writes them. Returns 0, or a negative errno: ENOENT when
// there is no such service — as for every guest that is not the host
// process, which has no services database.
func (w *WasiStubs) Sock_service(m *Module, namePtr, nameLen, port, byPort, protoPtr, protoLen, bufPtr, bufLen, neededPtr int32) int32 {
	return w.sockService(m, zext(namePtr), nameLen, port, byPort, zext(protoPtr), protoLen, zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_service64 is Sock_service for a memory64 guest.
func (w *WasiStubs) Sock_service64(m *Module, namePtr int64, nameLen, port, byPort int32, protoPtr int64, protoLen int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.sockService(m, uint64(namePtr), nameLen, port, byPort, uint64(protoPtr), protoLen, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// sockService is the body of Sock_service and Sock_service64.
func (w *WasiStubs) sockService(m *Module, namePtr uint64, nameLen, port, byPort int32, protoPtr uint64, protoLen int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	nameBytes := w.memBytes(m, namePtr, zext(nameLen))
	protoBytes := w.memBytes(m, protoPtr, zext(protoLen))
	if nameBytes == nil || protoBytes == nil {
		return -_wasiEFAULT
	}
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	name, proto := string(nameBytes), string(protoBytes)
	entry, ok := findHostService(func(s wasiService) bool {
		if proto != "" && s.proto != proto {
			return false
		}
		if byPort != 0 {
			return s.port == int(port)
		}
		if s.name == name {
			return true
		}
		for _, alias := range s.aliases {
			if alias == name {
				return true
			}
		}
		return false
	})
	if !ok {
		return -_wasiENOENT
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(entry.port))
	rec = appendWasiString(rec, entry.name)
	rec = appendWasiString(rec, entry.proto)
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(entry.aliases)))
	for _, alias := range entry.aliases {
		rec = appendWasiString(rec, alias)
	}
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Sock_reverse is a NON-STANDARD host import (name "sock_reverse") backing
// gethostbyaddr and getnameinfo: the name of the host that has the IPv4
// address ipBE (as it sits in s_addr), as the host's resolver knows it. The
// record (writeWasiRecord) is the name, without a length prefix. The lookup
// is subject to the resolve hook, which is asked about the address in
// dotted form. Returns 0, or a negative errno: ENOENT when the address has
// no name, EACCES when the hook refuses.
func (w *WasiStubs) Sock_reverse(m *Module, ipBE, bufPtr, bufLen, neededPtr int32) int32 {
	return w.reverseLookup(m, socketIPv4(ipBE), zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_reverse64 is Sock_reverse for a memory64 guest.
func (w *WasiStubs) Sock_reverse64(m *Module, ipBE int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.reverseLookup(m, socketIPv4(ipBE), uint64(bufPtr), bufLen, uint64(neededPtr))
}

// reverseLookup is Sock_reverse for the IP address ip, of either family,
// written in numbers.
func (w *WasiStubs) reverseLookup(m *Module, ip string, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	w.mu.Lock()
	hook := w.resolveHook
	w.mu.Unlock()
	if hook != nil && !hook(ip) {
		return -_wasiEACCES
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return -_wasiENOENT
	}
	// The resolver answers with a fully qualified name, which ends in the
	// root's dot; a host's name is written without it.
	name := strings.TrimSuffix(names[0], ".")
	return w.writeWasiRecord(m, []byte(name), bufPtr, bufLen, neededPtr)
}

// Sock_host_by_name is a NON-STANDARD host import (name
// "sock_host_by_name") backing gethostbyname(): the IPv4 addresses of the
// host named at (nodePtr, nodeLen), and its official name, as the host's
// gethostbyname finds them where the runtime can call it (darwin: the C
// library's gethostbyname2, which is what perl calls there), and as the
// runtime's resolver finds them otherwise (the official name is then the
// name asked about). It is an import of its own, and not Sock_resolve's
// lookup of IPv4 addresses, because the two lookups differ on a host where
// getaddrinfo does more than gethostbyname: darwin's sorts the addresses it
// finds, for which it opens, and keeps, a socket to the system that
// gethostbyname never opens; a program that only called gethostbyname
// would leave it to every command it starts.
//
// The record (writeWasiRecord) is the number of addresses (u32), the
// addresses (4 bytes each, as they sit in s_addr), then the official name.
// An address written in numbers is converted, not looked up, and the lookup
// policy (SetResolveHook) is not asked about it. Returns 0, or a negative
// errno: ENOENT when the name has no IPv4 address, EACCES when the policy
// refuses.
func (w *WasiStubs) Sock_host_by_name(m *Module, nodePtr, nodeLen, bufPtr, bufLen, neededPtr int32) int32 {
	return w.sockHostByName(m, zext(nodePtr), nodeLen, zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_host_by_name64 is Sock_host_by_name for a memory64 guest.
func (w *WasiStubs) Sock_host_by_name64(m *Module, nodePtr int64, nodeLen int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.sockHostByName(m, uint64(nodePtr), nodeLen, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// sockHostByName is the body of Sock_host_by_name and Sock_host_by_name64.
func (w *WasiStubs) sockHostByName(m *Module, nodePtr uint64, nodeLen int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	node := w.memBytes(m, nodePtr, zext(nodeLen))
	if node == nil && nodeLen != 0 {
		return -_wasiEFAULT
	}
	name := string(node)
	official := name
	var addrs [][4]byte
	if ip := net.ParseIP(name); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return -_wasiENOENT
		}
		addrs = append(addrs, [4]byte(v4))
	} else {
		w.mu.Lock()
		hook := w.resolveHook
		w.mu.Unlock()
		if hook != nil && !hook(name) {
			return -_wasiEACCES
		}
		var asked bool
		official, addrs, asked = hostHostByName(name)
		if !asked {
			official = name
			found, err := net.DefaultResolver.LookupIPAddr(context.Background(), name)
			if err != nil {
				return -_wasiENOENT
			}
			for _, addr := range found {
				if v4 := addr.IP.To4(); v4 != nil {
					addrs = append(addrs, [4]byte(v4))
				}
			}
		}
	}
	if len(addrs) == 0 {
		return -_wasiENOENT
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(len(addrs)))
	for _, a := range addrs {
		rec = append(rec, a[:]...)
	}
	rec = append(rec, official...)
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// ----- process groups ---------------------------------------------------------
//
// The processes of a fork family are goroutines of one host process, so the
// host knows nothing of the groups they form: the family keeps them. A
// forked process starts in its parent's group and may start one of its own
// (setpgid, setsid), whose id is its pid token. The first process of the
// family is in the host process's real group when the guest is the host
// process — what it does to its group it does to the host process — and in
// a group of its own (its pid) otherwise.

// groupLocked returns the process group of the instance. Caller holds w.mu.
func (w *WasiStubs) groupLocked() int32 {
	if w.pgid != 0 {
		return w.pgid
	}
	if w.hostProcess && !w.forked {
		if pgid, err := hostProcessGroup(0); err == nil {
			return int32(pgid)
		}
	}
	return w.processIDLocked()
}

// group returns the process group of the instance.
func (w *WasiStubs) group() int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.groupLocked()
}

// Host_numbering is a NON-STANDARD host import (name "host_numbering"): it
// tells the guest whose numbers its program sees. 0: the numbers of the
// guest's own C library. 1: the host operating system's, which the guest
// obtains with host_number_at; so for a guest that is the host process
// (SetHostProcess) and for the processes it forks.
func (w *WasiStubs) Host_numbering(m *Module) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hostProcess {
		return 1
	}
	return 0
}

// Host_numbering64 is Host_numbering for a memory64 guest.
func (w *WasiStubs) Host_numbering64(m *Module) int32 {
	return w.Host_numbering(m)
}

// Host_number_at is a NON-STANDARD host import (name "host_number_at"): the
// index-th number of a family of the host operating system's numbers. The
// families are numbered as in the wasip1_hostnumbers_* tables (1 is the
// error numbers). The name the number has in C is written at namePtr (at
// most nameCap bytes, no terminator) and its length at nameLenPtr (u32);
// the number at valuePtr (i64). Returns 0, or a negative errno: ENOENT
// past the last number of the family (at index 0: the host has no table of
// it), ERANGE for a name longer than nameCap.
func (w *WasiStubs) Host_number_at(m *Module, family, index, namePtr, nameCap, nameLenPtr, valuePtr int32) int32 {
	return w.hostNumberAt(m, family, index, zext(namePtr), nameCap, zext(nameLenPtr), zext(valuePtr))
}

// Host_number_at64 is Host_number_at for a memory64 guest.
func (w *WasiStubs) Host_number_at64(m *Module, family, index int32, namePtr int64, nameCap int32, nameLenPtr, valuePtr int64) int32 {
	return w.hostNumberAt(m, family, index, uint64(namePtr), nameCap, uint64(nameLenPtr), uint64(valuePtr))
}

// hostNumberAt is the body of Host_number_at and Host_number_at64.
func (w *WasiStubs) hostNumberAt(m *Module, family, index int32, namePtr uint64, nameCap int32, nameLenPtr, valuePtr uint64) int32 {
	table := hostNumberTable(family)
	if index < 0 || int(index) >= len(table) {
		return -_wasiENOENT
	}
	number := table[index]
	if int64(len(number.name)) > int64(nameCap) {
		return -_wasiERANGE
	}
	name := w.memBytes(m, namePtr, uint64(len(number.name)))
	nameLen := w.memBytes(m, nameLenPtr, 4)
	value := w.memBytes(m, valuePtr, 8)
	if name == nil || nameLen == nil || value == nil {
		return -_wasiEFAULT
	}
	copy(name, number.name)
	binary.LittleEndian.PutUint32(nameLen, uint32(len(number.name)))
	binary.LittleEndian.PutUint64(value, uint64(number.value))
	return 0
}

// isHostProcess reports whether the instance is the host process itself:
// its group and session are then the host process's.
func (w *WasiStubs) isHostProcess() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hostProcess && !w.forked
}

// familyProcs returns the processes of the family that exist.
func (w *WasiStubs) familyProcs() []*wasiProc {
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	pids.mu.Lock()
	defer pids.mu.Unlock()
	procs := make([]*wasiProc, 0, len(pids.procs))
	for _, proc := range pids.procs {
		procs = append(procs, proc)
	}
	return procs
}

// groupExists reports whether some process of the family is in group pgid.
func (w *WasiStubs) groupExists(pgid int32) bool {
	for _, proc := range w.familyProcs() {
		if proc.inst != nil && proc.inst.group() == pgid {
			return true
		}
	}
	return false
}

// Proc_getpgid is a NON-STANDARD host import (name "proc_getpgid") backing
// getpgid and getpgrp. pid 0 names the caller; otherwise it names a process
// of the fork family, or, for a guest that is the host process, a process
// of the host. The group is written at outPtr (u32). Returns 0, or a
// negative errno: ESRCH for a pid that names no such process.
func (w *WasiStubs) Proc_getpgid(m *Module, pid, outPtr int32) int32 {
	return w.procGetpgid(m, pid, zext(outPtr))
}

// Proc_getpgid64 is Proc_getpgid for a memory64 guest.
func (w *WasiStubs) Proc_getpgid64(m *Module, pid int32, outPtr int64) int32 {
	return w.procGetpgid(m, pid, uint64(outPtr))
}

// procGetpgid is the body of Proc_getpgid and Proc_getpgid64.
func (w *WasiStubs) procGetpgid(m *Module, pid int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	self := w.processIDLocked()
	pids := w.pidsLocked()
	host := w.hostProcess
	w.mu.Unlock()
	var pgid int32
	switch proc := pids.find(pid); {
	case pid == 0 || pid == self:
		pgid = w.group()
	case pid < 0:
		return -_wasiESRCH
	case proc != nil && proc.inst != nil:
		pgid = proc.inst.group()
	case proc != nil && proc.cmd != nil:
		real, err := hostProcessGroup(proc.cmd.Process.Pid)
		if err != nil {
			return -_wasiESRCH
		}
		pgid = int32(real)
	case proc == nil && host && !pids.allocated(pid):
		real, err := hostProcessGroup(int(pid))
		if err != nil {
			return -_wasiESRCH
		}
		pgid = int32(real)
	default:
		return -_wasiESRCH
	}
	binary.LittleEndian.PutUint32(out, uint32(pgid))
	return _wasiESUCCESS
}

// Proc_setpgid is a NON-STANDARD host import (name "proc_setpgid") backing
// setpgid: the process pid — 0 for the caller, or one of the caller's
// children — joins the group pgid, 0 standing for a group of its own.
// Returns 0, or a negative errno: ESRCH for a pid that is neither the
// caller nor a child of it, EINVAL for a negative number, EPERM for a group
// that does not exist.
func (w *WasiStubs) Proc_setpgid(m *Module, pid, pgid int32) int32 {
	if pgid < 0 || pid < 0 {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	self := w.processIDLocked()
	child := w.procs[pid]
	w.mu.Unlock()
	target := w
	if pid != 0 && pid != self {
		if child == nil {
			return -_wasiESRCH
		}
		if child.cmd != nil {
			// A command the guest started: a process of the host, whose
			// group is the host's to keep. It gets a group of its own, or
			// joins a real one.
			real := 0
			if pgid != 0 && pgid != pid {
				real = int(pgid)
			}
			if err := setHostProcessGroup(child.cmd.Process.Pid, real); err != nil {
				return -mapOSError(err)
			}
			return _wasiESUCCESS
		}
		if child.inst == nil {
			return -_wasiESRCH
		}
		target = child.inst
		self = pid
	}
	if target.isHostProcess() {
		if err := setHostProcessGroup(0, int(pgid)); err != nil {
			return -mapOSError(err)
		}
		return _wasiESUCCESS
	}
	if pgid == 0 {
		pgid = self
	}
	if pgid != self && !w.groupExists(pgid) {
		return -_wasiEPERM
	}
	target.mu.Lock()
	target.pgid = pgid
	target.mu.Unlock()
	return _wasiESUCCESS
}

// Proc_setpgid64 is Proc_setpgid for a memory64 guest.
func (w *WasiStubs) Proc_setpgid64(m *Module, pid, pgid int32) int32 {
	return w.Proc_setpgid(m, pid, pgid)
}

// Proc_setsid is a NON-STANDARD host import (name "proc_setsid") backing
// setsid: the caller starts a session, and in it a process group, of its
// own; their id, the caller's pid, is written at outPtr (u32). A guest that
// is the host process does this to the host process. Returns 0, or a
// negative errno: EPERM when the caller already leads a process group.
func (w *WasiStubs) Proc_setsid(m *Module, outPtr int32) int32 {
	return w.procSetsid(m, zext(outPtr))
}

// Proc_setsid64 is Proc_setsid for a memory64 guest.
func (w *WasiStubs) Proc_setsid64(m *Module, outPtr int64) int32 {
	return w.procSetsid(m, uint64(outPtr))
}

// procSetsid is the body of Proc_setsid and Proc_setsid64.
func (w *WasiStubs) procSetsid(m *Module, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	if w.isHostProcess() {
		sid, err := newHostSession()
		if err != nil {
			return -mapOSError(err)
		}
		binary.LittleEndian.PutUint32(out, uint32(sid))
		return _wasiESUCCESS
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	self := w.processIDLocked()
	if w.groupLocked() == self {
		return -_wasiEPERM
	}
	w.pgid = self
	// A new session has no controlling terminal.
	none := ""
	w.sessionLeader, w.terminal = true, &none
	binary.LittleEndian.PutUint32(out, uint32(self))
	return _wasiESUCCESS
}

// Proc_exec_next is a NON-STANDARD host import (name "proc_exec_next"): with
// on non-zero the guest says that the next command it starts (Proc_spawn) is
// the one it becomes, as exec does (Proc_exec follows); with on zero it
// takes that back, when the command could not be started before the host
// was asked. What the process made of its session within the runtime is
// the command's for real: a process that leads a session of its own is
// replaced by a command that leads one, with the terminal the process took
// for its controlling terminal. A command started for any other reason is a
// child like any other.
func (w *WasiStubs) Proc_exec_next(m *Module, on int32) int32 {
	w.mu.Lock()
	w.execNext = on != 0
	w.mu.Unlock()
	return _wasiESUCCESS
}

// Proc_exec_next64 is Proc_exec_next for a memory64 guest.
func (w *WasiStubs) Proc_exec_next64(m *Module, on int32) int32 {
	return w.Proc_exec_next(m, on)
}

// killGroup signals every process of a group, for Proc_kill: pid 0 names
// the caller's group, -1 every process of the family but the caller, and
// any other negative number the group of that id.
//
// The members that are guest instances of the family are signalled one by
// one, the caller included when it is one of them. A group of the host —
// the one the host process is in, or any other real one — is signalled
// through the OS as well when the guest is the host process: that reaches
// the host process itself (and so the first process of the family) and the
// commands the family started. In a group the family formed, the commands
// its members started are signalled with them, and so are the groups of
// the host that commands lead for it, for as long as the host has them
// (wasiPIDs.groups): what the command of a process that led the group
// started is in one, also once the command and that process are gone.
//
// Returns 0, or a negative errno: ESRCH when the group has no process,
// EINVAL for a signal the host does not have.
func (w *WasiStubs) killGroup(pid, sig int32) int32 {
	w.mu.Lock()
	pids := w.pidsLocked()
	host := w.hostProcess
	first := !w.forked
	w.mu.Unlock()
	everyone := pid == -1
	pgid := -pid
	if pid == 0 {
		pgid = w.group()
	}
	real := host && !everyone && !pids.allocated(pgid)
	hostSig, known := hostSignalOf(sig)
	if !known && real {
		return -_wasiEINVAL
	}
	reached := false
	// The first process of a family is in the family's table only when it
	// is isolated and has forked, so the caller is looked at on its own.
	callerIsMember := !everyone && w.group() == pgid
	for _, proc := range w.familyProcs() {
		inst := proc.inst
		if inst == nil || inst == w {
			continue
		}
		select {
		case <-proc.done:
			continue
		default:
		}
		if !everyone && inst.group() != pgid {
			continue
		}
		reached = true
		if sig == 0 {
			continue
		}
		// A member that has become a command (exec) takes the signal as
		// that command, which the commands of the group are signalled
		// for below; posted to the member, it would reach the command
		// twice.
		if proc.kill != nil && !inst.becameCommand() {
			_ = proc.kill(sig)
		}
		if !real && known {
			inst.signalCommands(hostSig)
		}
	}
	if callerIsMember {
		reached = true
		switch {
		case sig == 0:
		case real && first:
			// The host process itself: signalled through the OS below.
		case real:
			w.PostSignal(sig)
		default:
			w.PostSignal(sig)
			if known {
				w.signalCommands(hostSig)
			}
		}
	}
	if !real && known {
		for _, host := range pids.hostGroups(pgid, everyone) {
			switch err := signalHostProcess(-host, hostSig); {
			case err == nil:
				reached = true
			case errors.Is(err, syscall.ESRCH):
				pids.dropGroup(host)
			}
		}
	}
	if real {
		if err := signalHostProcess(-int(pgid), hostSig); err == nil {
			reached = true
		}
	}
	if !reached {
		return -_wasiESRCH
	}
	return _wasiESUCCESS
}

// processDirIs reports whether dir is the working directory of the host
// process, as getcwd(2) names it: os.Getwd looks at ".", which a directory
// that cannot be searched refuses. A name with a symbolic link in it is
// not the name getcwd gives, and is taken for another directory.
func processDirIs(dir string) bool {
	wd, err := syscall.Getwd()
	return err == nil && wd == dir
}

// signalCommands sends a signal to the running commands this instance
// started, but for one that leads a process group of the host: that group
// is the instance's group's, which killGroup signals as one
// (wasiPIDs.groups).
func (w *WasiStubs) signalCommands(sig syscall.Signal) {
	w.mu.Lock()
	var cmds []*exec.Cmd
	for _, proc := range w.procs {
		if proc.cmd == nil {
			continue
		}
		select {
		case <-proc.done:
		default:
			cmds = append(cmds, proc.cmd)
		}
	}
	w.mu.Unlock()
	for _, cmd := range cmds {
		if attr := cmd.SysProcAttr; attr != nil && commandLeadsGroup(attr) {
			continue
		}
		_ = cmd.Process.Signal(sig)
	}
}

// Proc_groups is a NON-STANDARD host import (name "proc_groups") backing
// getgroups. It writes the number of supplementary group ids at countPtr
// and, when capacity (a count of u32 slots at bufPtr) is enough for all of
// them, the ids themselves. Returns 0, or a negative errno: ERANGE when
// capacity is non-zero and too small (the count is still written).
func (w *WasiStubs) Proc_groups(m *Module, bufPtr, capacity, countPtr int32) int32 {
	return w.procGroups(m, zext(bufPtr), capacity, zext(countPtr))
}

// Proc_groups64 is Proc_groups for a memory64 guest.
func (w *WasiStubs) Proc_groups64(m *Module, bufPtr int64, capacity int32, countPtr int64) int32 {
	return w.procGroups(m, uint64(bufPtr), capacity, uint64(countPtr))
}

// procGroups is the body of Proc_groups and Proc_groups64.
func (w *WasiStubs) procGroups(m *Module, bufPtr uint64, capacity int32, countPtr uint64) int32 {
	countOut := w.memBytes(m, countPtr, 4)
	if countOut == nil || capacity < 0 {
		return -_wasiEFAULT
	}
	var groups []int
	if w.hostIdentity() {
		var err error
		if groups, err = os.Getgroups(); err != nil {
			return -mapOSError(err)
		}
	}
	binary.LittleEndian.PutUint32(countOut, uint32(len(groups)))
	if capacity == 0 {
		return _wasiESUCCESS
	}
	if int(capacity) < len(groups) {
		return -_wasiERANGE
	}
	buf := w.memBytes(m, bufPtr, uint64(len(groups))*4)
	if buf == nil {
		return -_wasiEFAULT
	}
	for i, gid := range groups {
		binary.LittleEndian.PutUint32(buf[i*4:], uint32(gid))
	}
	return _wasiESUCCESS
}

// appendWasiString appends s as a little-endian u32 length followed by its
// bytes: the form every string in a record handed to the guest takes.
func appendWasiString(rec []byte, s string) []byte {
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(s)))
	return append(rec, s...)
}

// writeWasiRecord hands a variable-length record to the guest: its size is
// written at neededPtr, and the record at bufPtr when bufLen bytes are
// enough for it. Returns 0, or a negative errno: ERANGE when the buffer is
// too small — the guest then calls again with one of the size it was told.
func (w *WasiStubs) writeWasiRecord(m *Module, rec []byte, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	needed := w.memBytes(m, neededPtr, 4)
	if needed == nil || bufLen < 0 {
		return -_wasiEFAULT
	}
	binary.LittleEndian.PutUint32(needed, uint32(len(rec)))
	if int(bufLen) < len(rec) {
		return -_wasiERANGE
	}
	buf := w.memBytes(m, bufPtr, uint64(len(rec)))
	if buf == nil {
		return -_wasiEFAULT
	}
	copy(buf, rec)
	return _wasiESUCCESS
}

// userRecord encodes an entry of the user database: u32 uid, u32 gid, then
// the login name, the real name, the home directory and the shell as
// strings (appendWasiString). The shell is always empty: the host's user
// lookup (os/user) does not report one. ok is false when the entry's ids are
// not numbers, as on a host whose user ids are not POSIX ones.
func userRecord(u *user.User) (rec []byte, ok bool) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, false
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, false
	}
	rec = binary.LittleEndian.AppendUint32(rec, uint32(uid))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(gid))
	rec = appendWasiString(rec, u.Username)
	rec = appendWasiString(rec, u.Name)
	rec = appendWasiString(rec, u.HomeDir)
	rec = appendWasiString(rec, "")
	return rec, true
}

// writeUser answers a user lookup: the record of u, or ENOENT when the
// lookup found no such user (err != nil) or the instance has no user
// database.
func (w *WasiStubs) writeUser(m *Module, u *user.User, err error, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if err != nil {
		return -_wasiENOENT
	}
	rec, ok := userRecord(u)
	if !ok {
		return -_wasiENOENT
	}
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Proc_user_by_id is a NON-STANDARD host import (name "proc_user_by_id")
// backing getpwuid. It looks uid up in the host's user database and hands
// back its record (userRecord, through writeWasiRecord). Returns 0, or a
// negative errno: ENOENT when there is no such user — always, for an
// instance that is not the host process — and ERANGE when the buffer is too
// small.
func (w *WasiStubs) Proc_user_by_id(m *Module, uid, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUserByID(m, uid, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_user_by_id64 is Proc_user_by_id for a memory64 guest.
func (w *WasiStubs) Proc_user_by_id64(m *Module, uid int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUserByID(m, uid, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUserByID is the body of Proc_user_by_id and Proc_user_by_id64.
func (w *WasiStubs) procUserByID(m *Module, uid int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uint32(uid)), 10))
	return w.writeUser(m, u, err, bufPtr, bufLen, neededPtr)
}

// Proc_user_by_name is a NON-STANDARD host import (name "proc_user_by_name")
// backing getpwnam: Proc_user_by_id for the login name at (namePtr,
// nameLen).
func (w *WasiStubs) Proc_user_by_name(m *Module, namePtr, nameLen, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUserByName(m, zext(namePtr), nameLen, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_user_by_name64 is Proc_user_by_name for a memory64 guest.
func (w *WasiStubs) Proc_user_by_name64(m *Module, namePtr int64, nameLen int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUserByName(m, uint64(namePtr), nameLen, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUserByName is the body of Proc_user_by_name and Proc_user_by_name64.
func (w *WasiStubs) procUserByName(m *Module, namePtr uint64, nameLen int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	name := w.memBytes(m, namePtr, zext(nameLen))
	if name == nil {
		return -_wasiEFAULT
	}
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	u, err := user.Lookup(string(name))
	return w.writeUser(m, u, err, bufPtr, bufLen, neededPtr)
}

// hostDatabaseEntries returns the entries of a database file of the host
// in the files' format (passwd(5), group(5)): one entry a line, its fields
// separated by colons; a line that is empty, a comment, or an entry of the
// NIS compatibility syntax (+ or - first) is none. The fields of an entry
// whose ids (fields idFields) are not numbers are left out too.
func hostDatabaseEntries(path string, minFields int, idFields ...int) [][]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < minFields {
			continue
		}
		numeric := true
		for _, i := range idFields {
			if _, err := strconv.ParseUint(fields[i], 10, 32); err != nil {
				numeric = false
			}
		}
		if numeric {
			entries = append(entries, fields)
		}
	}
	return entries
}

// Proc_user_at is a NON-STANDARD host import (name "proc_user_at") backing
// getpwent: the index-th entry of the host's user database, the file
// /etc/passwd (the source os/user reads as well), as Proc_user_by_id hands
// an entry back, with its shell. Returns 0, or a negative errno: ENOENT past
// the last entry — at once, for an instance that is not the host process —
// and ERANGE when the buffer is too small.
func (w *WasiStubs) Proc_user_at(m *Module, index, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUserAt(m, index, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_user_at64 is Proc_user_at for a memory64 guest.
func (w *WasiStubs) Proc_user_at64(m *Module, index int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUserAt(m, index, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUserAt is the body of Proc_user_at and Proc_user_at64.
func (w *WasiStubs) procUserAt(m *Module, index int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	// name:password:uid:gid:gecos:home:shell
	entries := hostDatabaseEntries("/etc/passwd", 7, 2, 3)
	if index < 0 || int(index) >= len(entries) {
		return -_wasiENOENT
	}
	e := entries[index]
	uid, _ := strconv.ParseUint(e[2], 10, 32)
	gid, _ := strconv.ParseUint(e[3], 10, 32)
	rec := binary.LittleEndian.AppendUint32(nil, uint32(uid))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(gid))
	rec = appendWasiString(rec, e[0])
	rec = appendWasiString(rec, e[4])
	rec = appendWasiString(rec, e[5])
	rec = appendWasiString(rec, e[6])
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Proc_group_at is a NON-STANDARD host import (name "proc_group_at")
// backing getgrent: the index-th entry of the host's group database, the
// file /etc/group, as Proc_group_by_id hands an entry back. See
// Proc_user_at.
func (w *WasiStubs) Proc_group_at(m *Module, index, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procGroupAt(m, index, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_group_at64 is Proc_group_at for a memory64 guest.
func (w *WasiStubs) Proc_group_at64(m *Module, index int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procGroupAt(m, index, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procGroupAt is the body of Proc_group_at and Proc_group_at64.
func (w *WasiStubs) procGroupAt(m *Module, index int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	// name:password:gid:members
	entries := hostDatabaseEntries("/etc/group", 3, 2)
	if index < 0 || int(index) >= len(entries) {
		return -_wasiENOENT
	}
	e := entries[index]
	gid, _ := strconv.ParseUint(e[2], 10, 32)
	rec := binary.LittleEndian.AppendUint32(nil, uint32(gid))
	rec = appendWasiString(rec, e[0])
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// writeGroup answers a group lookup with the group's record: u32 gid, then
// the group name as a string (appendWasiString). The host's group lookup
// (os/user) does not report a group's members, so the record carries none.
func (w *WasiStubs) writeGroup(m *Module, g *user.Group, err error, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if err != nil {
		return -_wasiENOENT
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return -_wasiENOENT
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(gid))
	rec = appendWasiString(rec, g.Name)
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Proc_group_by_id is a NON-STANDARD host import (name "proc_group_by_id")
// backing getgrgid; see Proc_user_by_id and writeGroup.
func (w *WasiStubs) Proc_group_by_id(m *Module, gid, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procGroupByID(m, gid, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_group_by_id64 is Proc_group_by_id for a memory64 guest.
func (w *WasiStubs) Proc_group_by_id64(m *Module, gid int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procGroupByID(m, gid, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procGroupByID is the body of Proc_group_by_id and Proc_group_by_id64.
func (w *WasiStubs) procGroupByID(m *Module, gid int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(uint32(gid)), 10))
	return w.writeGroup(m, g, err, bufPtr, bufLen, neededPtr)
}

// Proc_group_by_name is a NON-STANDARD host import (name
// "proc_group_by_name") backing getgrnam; see Proc_user_by_name and
// writeGroup.
func (w *WasiStubs) Proc_group_by_name(m *Module, namePtr, nameLen, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procGroupByName(m, zext(namePtr), nameLen, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_group_by_name64 is Proc_group_by_name for a memory64 guest.
func (w *WasiStubs) Proc_group_by_name64(m *Module, namePtr int64, nameLen int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procGroupByName(m, uint64(namePtr), nameLen, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procGroupByName is the body of Proc_group_by_name and Proc_group_by_name64.
func (w *WasiStubs) procGroupByName(m *Module, namePtr uint64, nameLen int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	name := w.memBytes(m, namePtr, zext(nameLen))
	if name == nil {
		return -_wasiEFAULT
	}
	if !w.hostIdentity() {
		return -_wasiENOENT
	}
	g, err := user.LookupGroup(string(name))
	return w.writeGroup(m, g, err, bufPtr, bufLen, neededPtr)
}

// ----- time zones -------------------------------------------------------------
//
// A guest's libc knows one time zone, UTC, and has no zone database. The
// rules of a zone are the host's to know: the guest names the zone it wants
// (the value of its TZ variable) and a moment, and Clock_zone answers what
// holds in that zone at that moment — the offset from UTC, whether daylight
// saving time is in effect, and the abbreviations in use.

// SetLocalZone sets the time zone a guest is in when it names none (TZ is
// not set): the embedder's choice, typically time.Local for a guest that
// stands for the host process. nil, the default, is UTC.
func (w *WasiStubs) SetLocalZone(loc *time.Location) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.localZone = loc
}

// wasiZoneMoment is what holds in a time zone at one moment.
type wasiZoneMoment struct {
	offset int    // seconds east of UTC
	dst    bool   // daylight saving time is in effect
	name   string // the abbreviation in use
	// other is the offset under the opposite daylight-saving state at the
	// nearest change, and equal to offset in a zone that has none.
	other int
	// stdOffset and stdName describe the zone's standard time around the
	// moment; dstName is the abbreviation of its daylight saving time, ""
	// when the zone has none there.
	stdOffset        int
	stdName, dstName string
}

// posixZoneRule is one date of a POSIX TZ string on which daylight saving
// time starts or ends: Mm.w.d, Jn or n, with the time of day in seconds.
type posixZoneRule struct {
	kind         byte // 'M', 'J', or 'N' for the plain day number
	month, week  int  // 'M': month 1..12, week 1..5 (5: the last)
	day          int  // 'M': weekday 0..6 from Sunday; 'J': 1..365; 'N': 0..365
	secondsOfDay int
}

// posixZone is a time zone given as a POSIX TZ string, such as "JST-9" or
// "EST5EDT,M3.2.0,M11.1.0".
type posixZone struct {
	stdName, dstName string // dstName "": no daylight saving time
	stdOffset        int    // seconds east of UTC
	dstOffset        int
	dstStart, dstEnd posixZoneRule
}

// posixZoneScanner reads a POSIX TZ string left to right.
type posixZoneScanner struct {
	s  string
	ok bool
}

func (p *posixZoneScanner) peek() byte {
	if len(p.s) == 0 {
		return 0
	}
	return p.s[0]
}

func (p *posixZoneScanner) take(c byte) bool {
	if p.peek() != c {
		return false
	}
	p.s = p.s[1:]
	return true
}

// name reads a zone abbreviation: three or more letters, or anything
// between angle brackets.
func (p *posixZoneScanner) name() string {
	if p.take('<') {
		end := strings.IndexByte(p.s, '>')
		if end < 1 {
			p.ok = false
			return ""
		}
		name := p.s[:end]
		p.s = p.s[end+1:]
		return name
	}
	n := 0
	for n < len(p.s) && (p.s[n] >= 'A' && p.s[n] <= 'Z' || p.s[n] >= 'a' && p.s[n] <= 'z') {
		n++
	}
	if n < 3 {
		p.ok = false
		return ""
	}
	name := p.s[:n]
	p.s = p.s[n:]
	return name
}

// number reads an unsigned decimal number of at most max.
func (p *posixZoneScanner) number(max int) int {
	n, digits := 0, 0
	for len(p.s) > 0 && p.s[0] >= '0' && p.s[0] <= '9' && digits < 4 {
		n = n*10 + int(p.s[0]-'0')
		p.s = p.s[1:]
		digits++
	}
	if digits == 0 || n > max {
		p.ok = false
	}
	return n
}

// clock reads [+-]hh[:mm[:ss]] as seconds.
func (p *posixZoneScanner) clock(maxHours int) int {
	sign := 1
	if p.take('-') {
		sign = -1
	} else {
		p.take('+')
	}
	seconds := p.number(maxHours) * 3600
	if p.take(':') {
		seconds += p.number(59) * 60
		if p.take(':') {
			seconds += p.number(59)
		}
	}
	return sign * seconds
}

// rule reads one transition date with its optional time of day.
func (p *posixZoneScanner) rule() posixZoneRule {
	r := posixZoneRule{kind: 'N', secondsOfDay: 2 * 3600}
	switch {
	case p.take('M'):
		r.kind = 'M'
		r.month = p.number(12)
		if !p.take('.') {
			p.ok = false
		}
		r.week = p.number(5)
		if !p.take('.') {
			p.ok = false
		}
		r.day = p.number(6)
		if r.month < 1 || r.week < 1 {
			p.ok = false
		}
	case p.take('J'):
		r.kind = 'J'
		if r.day = p.number(365); r.day < 1 {
			p.ok = false
		}
	default:
		r.day = p.number(365)
	}
	if p.take('/') {
		r.secondsOfDay = p.clock(167)
	}
	return r
}

// parsePosixZone reads a POSIX TZ string: std offset [dst [offset]
// [,start[/time],end[/time]]]. An offset is what is added to local time to
// get UTC, so a zone east of Greenwich has a negative one. Daylight saving
// time is one hour ahead of standard time unless it has an offset of its
// own, and follows the rules of the United States unless the string has
// rules. ok is false for anything that is not such a string.
func parsePosixZone(tz string) (zone *posixZone, ok bool) {
	p := &posixZoneScanner{s: tz, ok: true}
	z := &posixZone{}
	z.stdName = p.name()
	if !p.ok {
		return nil, false
	}
	z.stdOffset = -p.clock(24)
	if !p.ok {
		return nil, false
	}
	if len(p.s) == 0 {
		return z, true
	}
	z.dstName = p.name()
	z.dstOffset = z.stdOffset + 3600
	if c := p.peek(); p.ok && c != ',' && c != 0 {
		z.dstOffset = -p.clock(24)
	}
	z.dstStart = posixZoneRule{kind: 'M', month: 3, week: 2, secondsOfDay: 2 * 3600}
	z.dstEnd = posixZoneRule{kind: 'M', month: 11, week: 1, secondsOfDay: 2 * 3600}
	if p.take(',') {
		z.dstStart = p.rule()
		if !p.take(',') {
			p.ok = false
		}
		z.dstEnd = p.rule()
	}
	if !p.ok || len(p.s) != 0 {
		return nil, false
	}
	return z, true
}

// localSeconds returns the rule's moment in the given year as seconds since
// the epoch on a clock that is not adjusted for any zone.
func (r posixZoneRule) localSeconds(year int) int64 {
	var day time.Time
	switch r.kind {
	case 'M':
		first := time.Date(year, time.Month(r.month), 1, 0, 0, 0, 0, time.UTC)
		offset := (r.day - int(first.Weekday()) + 7) % 7
		day = first.AddDate(0, 0, offset+7*(r.week-1))
		if day.Month() != first.Month() {
			// week 5 is the last such weekday of the month
			day = day.AddDate(0, 0, -7)
		}
	case 'J':
		// days 1..365, February 29 never counted
		day = time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, r.day-1)
		leap := year%4 == 0 && (year%100 != 0 || year%400 == 0)
		if leap && r.day >= 60 {
			day = day.AddDate(0, 0, 1)
		}
	default:
		day = time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, r.day)
	}
	return day.Unix() + int64(r.secondsOfDay)
}

// inDST reports whether daylight saving time is in effect at utc (seconds
// since the epoch).
func (z *posixZone) inDST(utc int64) bool {
	if z.dstName == "" {
		return false
	}
	year := time.Unix(utc+int64(z.stdOffset), 0).UTC().Year()
	start := z.dstStart.localSeconds(year) - int64(z.stdOffset)
	end := z.dstEnd.localSeconds(year) - int64(z.dstOffset)
	if start < end {
		return utc >= start && utc < end
	}
	// the southern hemisphere: summer spans the turn of the year
	return utc >= start || utc < end
}

// moment answers for a POSIX zone. With local set, t is a reading of the
// zone's own clock rather than seconds since the epoch.
func (z *posixZone) moment(t int64, local bool) wasiZoneMoment {
	zm := wasiZoneMoment{stdOffset: z.stdOffset, stdName: z.stdName, dstName: z.dstName}
	dst := false
	if local {
		// A reading that exists under both states, or under neither, is
		// taken as standard time.
		dst = z.inDST(t-int64(z.dstOffset)) && z.inDST(t-int64(z.stdOffset))
	} else {
		dst = z.inDST(t)
	}
	zm.offset, zm.name, zm.other = z.stdOffset, z.stdName, z.stdOffset
	if z.dstName != "" {
		zm.other = z.dstOffset
	}
	if dst {
		zm.dst, zm.offset, zm.name, zm.other = true, z.dstOffset, z.dstName, z.stdOffset
	}
	return zm
}

// locationMoment answers for a zone of the host's zone database (or a fixed
// one). With local set, t is a reading of the zone's own clock.
func locationMoment(loc *time.Location, t int64, local bool) wasiZoneMoment {
	at := time.Unix(t, 0).In(loc)
	if local {
		u := time.Unix(t, 0).UTC()
		at = time.Date(u.Year(), u.Month(), u.Day(), u.Hour(), u.Minute(), u.Second(), 0, loc)
	}
	var zm wasiZoneMoment
	zm.name, zm.offset = at.Zone()
	zm.dst = at.IsDST()
	zm.other, zm.stdOffset, zm.stdName = zm.offset, zm.offset, zm.name
	// The period next to this one, later or else earlier, shows the other
	// daylight-saving state when the zone has one at this time: a change
	// more than a year away is history, or not decided yet.
	start, end := at.ZoneBounds()
	var neighbours []time.Time
	if !end.IsZero() {
		neighbours = append(neighbours, end)
	}
	if !start.IsZero() {
		neighbours = append(neighbours, start.Add(-time.Second))
	}
	for _, n := range neighbours {
		n = n.In(loc)
		if apart := n.Sub(at); n.IsDST() == zm.dst || apart > 366*24*time.Hour || apart < -366*24*time.Hour {
			continue
		}
		name, offset := n.Zone()
		zm.other = offset
		if zm.dst {
			zm.stdName, zm.stdOffset, zm.dstName = name, offset, zm.name
		} else {
			zm.dstName = name
		}
		return zm
	}
	if zm.dst {
		zm.dstName = zm.name
	}
	return zm
}

// zoneMoment resolves the zone a guest named and answers for it. No name
// (TZ not set) is the embedder's local zone, UTC by default. A name is
// looked up in the host's zone database first — ":Europe/Paris" and
// "Europe/Paris" alike — and read as a POSIX TZ string otherwise; a name
// that is neither is UTC, as it is for a C library.
func (w *WasiStubs) zoneMoment(tz string, named bool, t int64, local bool) wasiZoneMoment {
	if !named {
		w.mu.Lock()
		loc := w.localZone
		w.mu.Unlock()
		if loc == nil {
			loc = time.UTC
		}
		return locationMoment(loc, t, local)
	}
	tz = strings.TrimPrefix(tz, ":")
	if tz == "" {
		return locationMoment(time.UTC, t, local)
	}
	if loc, err := time.LoadLocation(tz); err == nil && tz != "Local" {
		return locationMoment(loc, t, local)
	}
	if zone, ok := parsePosixZone(tz); ok {
		return zone.moment(t, local)
	}
	return locationMoment(time.UTC, t, local)
}

// wasiZoneNameSize is the space a zone abbreviation has in the record
// Clock_zone writes, its terminating NUL included.
const wasiZoneNameSize = 16

// Clock_zone is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "clock_zone") backing the time zone side of a guest's libc
// (localtime, mktime, strftime's %z and %Z, tzset). (tzPtr, tzLen) is the
// zone the guest names — the value of its TZ variable — when hasTZ is
// non-zero; see zoneMoment for what a name means. t is seconds since the
// epoch, or with local non-zero a reading of the zone's own clock counted
// the same way (what mktime starts from).
//
// It writes a 64-byte record at outPtr: four little-endian i32 — the offset
// from UTC in seconds east, 1 when daylight saving time is in effect, the
// offset under the opposite daylight-saving state, the offset of standard
// time — and three NUL-terminated abbreviations of wasiZoneNameSize bytes
// each: the one in use, standard time's, and daylight saving time's (empty
// when the zone has none). Returns 0 or a negative errno.
func (w *WasiStubs) Clock_zone(m *Module, tzPtr, tzLen, hasTZ int32, t int64, local, outPtr int32) int32 {
	return w.clockZone(m, zext(tzPtr), tzLen, hasTZ, t, local, zext(outPtr))
}

// Clock_zone64 is Clock_zone for a memory64 guest.
func (w *WasiStubs) Clock_zone64(m *Module, tzPtr int64, tzLen, hasTZ int32, t int64, local int32, outPtr int64) int32 {
	return w.clockZone(m, uint64(tzPtr), tzLen, hasTZ, t, local, uint64(outPtr))
}

// clockZone is the body of Clock_zone and Clock_zone64.
func (w *WasiStubs) clockZone(m *Module, tzPtr uint64, tzLen, hasTZ int32, t int64, local int32, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 16+3*wasiZoneNameSize)
	var tz []byte
	if hasTZ != 0 {
		tz = w.memBytes(m, tzPtr, zext(tzLen))
		if tz == nil && tzLen != 0 {
			return -_wasiEFAULT
		}
	}
	if out == nil {
		return -_wasiEFAULT
	}
	zm := w.zoneMoment(string(tz), hasTZ != 0, t, local != 0)
	for i := range out {
		out[i] = 0
	}
	binary.LittleEndian.PutUint32(out[0:], uint32(int32(zm.offset)))
	if zm.dst {
		binary.LittleEndian.PutUint32(out[4:], 1)
	}
	binary.LittleEndian.PutUint32(out[8:], uint32(int32(zm.other)))
	binary.LittleEndian.PutUint32(out[12:], uint32(int32(zm.stdOffset)))
	for i, name := range []string{zm.name, zm.stdName, zm.dstName} {
		if len(name) > wasiZoneNameSize-1 {
			name = name[:wasiZoneNameSize-1]
		}
		copy(out[16+i*wasiZoneNameSize:], name)
	}
	return _wasiESUCCESS
}

// ----- the system logger ------------------------------------------------------

// Syslogger is a system logger as a guest's syslog(3) uses it. The embedder
// supplies one with SetSyslogger; without one the guest has no system
// logger, and its openlog and syslog fail.
//
// An instance and the instances forked from it share the Syslogger, each
// calling it from its own goroutine.
type Syslogger interface {
	// Open is the guest's openlog: it reports whether messages from ident
	// can be delivered. options and facility are as in SyslogMessage.
	Open(ident string, options, facility int32) error
	// Log delivers one message.
	Log(msg SyslogMessage) error
	// Close is the guest's closelog.
	Close() error
}

// SyslogMessage is one message a guest logs, as syslog(3) takes it apart.
type SyslogMessage struct {
	// Severity is the level, 0 (emergency) to 7 (debug).
	Severity int32
	// Facility is the facility's number, 0 (kernel) to 23 (local7): the
	// value syslog.h shifts left by three.
	Facility int32
	// Options are the openlog option flags: SyslogOptPID and the rest.
	Options int32
	// Ident is the tag openlog set, "" when the guest set none.
	Ident string
	// Message is the message text.
	Message string
}

// The openlog option flags in SyslogMessage.Options and Syslogger.Open,
// with the values the guest's shim passes (Linux's).
const (
	SyslogOptPID    int32 = 0x01 // LOG_PID: log the process id with each message
	SyslogOptCons   int32 = 0x02 // LOG_CONS: write to the console when the logger fails
	SyslogOptNDelay int32 = 0x08 // LOG_NDELAY: connect at openlog
	SyslogOptPerror int32 = 0x20 // LOG_PERROR: the guest also writes the message to its stderr
)

// SetSyslogger gives the guest a system logger (nil takes it away).
func (w *WasiStubs) SetSyslogger(l Syslogger) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syslogger = l
}

// syslogResult turns the outcome of a Syslogger call into the result of a
// syslog import.
func syslogResult(err error) int32 {
	if err == nil {
		return _wasiESUCCESS
	}
	if errno := mapNetError(err); errno != _wasiEIO {
		return -errno
	}
	return -_wasiEIO
}

// Proc_syslog_open is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "proc_syslog_open") backing openlog(): the
// guest is about to log as (identPtr, identLen) with the given option flags
// (SyslogOpt*) and default facility number. Returns 0 when the embedder's
// Syslogger accepts, or a negative errno: ENOSYS when the instance has no
// system logger, otherwise what the logger reported.
func (w *WasiStubs) Proc_syslog_open(m *Module, identPtr, identLen, options, facility int32) int32 {
	return w.procSyslogOpen(m, zext(identPtr), identLen, options, facility)
}

// Proc_syslog_open64 is Proc_syslog_open for a memory64 guest.
func (w *WasiStubs) Proc_syslog_open64(m *Module, identPtr int64, identLen, options, facility int32) int32 {
	return w.procSyslogOpen(m, uint64(identPtr), identLen, options, facility)
}

// procSyslogOpen is the body of Proc_syslog_open and Proc_syslog_open64.
func (w *WasiStubs) procSyslogOpen(m *Module, identPtr uint64, identLen, options, facility int32) int32 {
	ident := w.memBytes(m, identPtr, zext(identLen))
	if ident == nil && identLen != 0 {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	l := w.syslogger
	w.mu.Unlock()
	if l == nil {
		return -_wasiENOSYS
	}
	return syslogResult(l.Open(string(ident), options, facility))
}

// Proc_syslog is a NON-STANDARD host import (name "proc_syslog") backing
// syslog(): one message, as the values syslog(3) works with — the severity
// (0..7), the facility number (0..23), the option flags and ident of the
// guest's openlog, and the message text. Returns 0 once the embedder's
// Syslogger has taken the message, or a negative errno: ENOSYS when the
// instance has no system logger, EINVAL for a severity or facility out of
// range, otherwise what the logger reported.
func (w *WasiStubs) Proc_syslog(m *Module, severity, facility, options, identPtr, identLen, msgPtr, msgLen int32) int32 {
	return w.procSyslog(m, severity, facility, options, zext(identPtr), identLen, zext(msgPtr), msgLen)
}

// Proc_syslog64 is Proc_syslog for a memory64 guest.
func (w *WasiStubs) Proc_syslog64(m *Module, severity, facility, options int32, identPtr int64, identLen int32, msgPtr int64, msgLen int32) int32 {
	return w.procSyslog(m, severity, facility, options, uint64(identPtr), identLen, uint64(msgPtr), msgLen)
}

// procSyslog is the body of Proc_syslog and Proc_syslog64.
func (w *WasiStubs) procSyslog(m *Module, severity, facility, options int32, identPtr uint64, identLen int32, msgPtr uint64, msgLen int32) int32 {
	ident := w.memBytes(m, identPtr, zext(identLen))
	text := w.memBytes(m, msgPtr, zext(msgLen))
	if (ident == nil && identLen != 0) || (text == nil && msgLen != 0) {
		return -_wasiEFAULT
	}
	if severity < 0 || severity > 7 || facility < 0 || facility > 23 {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	l := w.syslogger
	w.mu.Unlock()
	if l == nil {
		return -_wasiENOSYS
	}
	return syslogResult(l.Log(SyslogMessage{
		Severity: severity,
		Facility: facility,
		Options:  options,
		Ident:    string(ident),
		Message:  string(text),
	}))
}

// Proc_syslog_close is a NON-STANDARD host import (name "proc_syslog_close")
// backing closelog(). Returns 0, or a negative errno as Proc_syslog_open.
func (w *WasiStubs) Proc_syslog_close(m *Module) int32 {
	w.mu.Lock()
	l := w.syslogger
	w.mu.Unlock()
	if l == nil {
		return -_wasiENOSYS
	}
	return syslogResult(l.Close())
}

// Proc_syslog_close64 is Proc_syslog_close for a memory64 guest.
func (w *WasiStubs) Proc_syslog_close64(m *Module) int32 {
	return w.Proc_syslog_close(m)
}

// ----- signals ----------------------------------------------------------------
//
// A guest cannot be interrupted: it is ordinary code on a goroutine. A
// signal is therefore delivered the way an interpreter with deferred signal
// handling takes one from its own C-level handler: the host records the
// signal and raises a flag word in the guest's memory, the guest notices the
// flag at its next safe point and takes the recorded signals
// (Proc_signal_take), and a blocking host call the guest is waiting in ends
// early with EINTR so that the safe point comes.
//
// What a signal does — run a handler, be ignored, end the process — is the
// guest's business: it owns the dispositions and tells the host about them
// (Proc_signal_dispositions) only so that the host can drop a signal nobody
// would notice instead of interrupting a blocking call for it.
//
// Signal sets cross the boundary as 64-bit masks in which signal n is bit
// n-1.

// WasiSignalError is the panic value of a guest that ended by a signal
// (Proc_terminate), the counterpart of WasiExitError: the recover layer of
// SafeInvokeExport hands it to the caller as an error, which then knows the
// instance is gone and which signal ended it. Signal is the guest's number
// for the signal (Linux numbering).
type WasiSignalError struct{ Signal int32 }

func (e *WasiSignalError) Error() string {
	return "wasi: terminated by signal " + itoa32(e.Signal)
}

// wasiSignals is the signal state of one instance. All of it is guarded by
// the owning WasiStubs.mu.
type wasiSignals struct {
	// flagModule and flagAddr locate the guest's flag word, once the guest
	// has registered it (Proc_signal_register). Until then there is no one
	// to deliver a signal to, and PostSignal drops what it is given. The
	// address is a guest address at full width, which a memory64 guest's
	// may need; the flag word itself is a 32-bit int.
	flagModule *Module
	flagAddr   uint64
	// handled, ignored and blocked are the dispositions the guest reported:
	// the signals it has a handler for, the ones it ignores explicitly
	// (SIG_IGN), and its signal mask. A signal in neither of the first two
	// has its default action; see discards.
	handled, ignored, blocked uint64
	// pending holds the posted signals the guest has not taken yet.
	pending uint64
	// interrupt records that a signal was posted and no blocking call has
	// reported it yet: the next one (or the one in progress) ends with
	// EINTR, once — as a system call does for one delivered signal.
	interrupt bool
	// wake ends the blocking call in progress early. Set by beginBlocking,
	// called (once) by PostSignal.
	wake func()
	// outside interrupts the code outside the guest that the guest is
	// running at the moment, if any (SetOutsideInterrupt): the host learns
	// of such code only from the one who runs it, and only that one knows
	// how to interrupt it.
	outside func()
	// timer is the running real-time interval timer (setitimer's
	// ITIMER_REAL, which alarm and ualarm set as well), timerAt the time it
	// fires next, and timerEvery the interval at which it fires again after
	// that: 0 for a timer that fires once.
	timer      *time.Timer
	timerAt    time.Time
	timerEvery time.Duration
	// relay receives the host process's signals that the guest handles,
	// relayed is the set it is subscribed to, and hostIgnored the set the
	// host process ignores on the guest's behalf. See syncHostSignalsLocked.
	relay       chan os.Signal
	relayed     uint64
	hostIgnored uint64
}

// discards returns the signals that have no effect on the guest: the ones it
// ignores, and the ones left at a default action that is to do nothing.
func (s *wasiSignals) discards() uint64 {
	return s.ignored | wasiDefaultIgnoredSignals&^s.handled
}

// killPending reports whether SIGKILL has been posted and the guest has
// not taken it yet: the guest is on its way to its end.
func (s *wasiSignals) killPending() bool {
	return s.pending&wasiSignalBit(wasiSIGKILL) != 0
}

// reapsChildren reports whether the guest ignores SIGCHLD explicitly. As
// POSIX has it, a child of such a process leaves nothing to wait for when
// it ends, and a wait reports ECHILD once no child is left running.
func (s *wasiSignals) reapsChildren() bool {
	return s.ignored&wasiSignalBit(wasiSIGCHLD) != 0
}

// wasiSignalBit returns the mask bit of a signal number, or 0 for a number
// that is not a signal's.
func wasiSignalBit(sig int32) uint64 {
	if sig < 1 || sig > 64 {
		return 0
	}
	return uint64(1) << uint(sig-1)
}

// The signals whose default action is to do nothing to the process (the
// stop signals among them: stopping has no meaning for a guest).
const wasiDefaultIgnoredSignals = uint64(1)<<(17-1) | // SIGCHLD
	uint64(1)<<(18-1) | // SIGCONT
	uint64(1)<<(19-1) | // SIGSTOP
	uint64(1)<<(20-1) | // SIGTSTP
	uint64(1)<<(21-1) | // SIGTTIN
	uint64(1)<<(22-1) | // SIGTTOU
	uint64(1)<<(23-1) | // SIGURG
	uint64(1)<<(28-1) // SIGWINCH

// The signals whose default action is to end the process, but which a Go
// program that has not asked for them takes otherwise: the Go runtime
// catches them and carries on, or, for SIGQUIT and SIGABRT, prints its
// goroutines and exits with status 2 instead of dying of the signal.
// (SIGHUP, SIGINT and SIGTERM end a Go program as they end any process; the
// signals of a fault, SIGPROF and SIGPIPE have a meaning of their own to the
// runtime and are left to it unless the guest handles them.)
const wasiSignalsHeldByRuntime = uint64(1)<<(3-1) | // SIGQUIT
	uint64(1)<<(6-1) | // SIGABRT
	uint64(1)<<(10-1) | // SIGUSR1
	uint64(1)<<(12-1) | // SIGUSR2
	uint64(1)<<(14-1) | // SIGALRM
	uint64(1)<<(24-1) | // SIGXCPU
	uint64(1)<<(25-1) | // SIGXFSZ
	uint64(1)<<(26-1) | // SIGVTALRM
	uint64(1)<<(29-1) // SIGIO

// PostSignal delivers a signal to the guest, as kill(2) does to a process.
// sig is the guest's number for it (Linux numbering). It may be called from
// any goroutine, at any time.
//
// The signal is dropped when the guest ignores it (explicitly or because
// that is the signal's default action), and when no guest has registered for
// signals. Otherwise it is recorded for the guest to take. Unless the guest
// has the signal blocked, its flag word is raised, and the blocking call it
// is waiting in — or the next one it makes before taking the signal — ends
// with EINTR.
//
// The host state of a forked instance (Fork) is the exception to the
// registration rule: the guest it is for exists from the moment of the fork
// and registers as soon as it runs, so a signal posted in between — a parent
// that kills its child right after forking it — is kept for it.
func (w *WasiStubs) PostSignal(sig int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.postSignalLocked(sig)
}

// postSignalLocked is PostSignal for a caller that holds w.mu.
func (w *WasiStubs) postSignalLocked(sig int32) {
	bit := wasiSignalBit(sig)
	if bit == 0 {
		return
	}
	s := &w.sig
	if s.flagModule == nil {
		if w.forked {
			s.pending |= bit
		}
		return
	}
	if s.discards()&bit != 0 {
		return
	}
	s.pending |= bit
	if s.blocked&bit != 0 {
		return
	}
	w.raiseSignalFlagLocked()
	s.interrupt = true
	if wake := s.wake; wake != nil {
		s.wake = nil
		wake()
	} else if s.outside != nil {
		// The guest is in code outside it: the signal interrupts that
		// code where it stands — a system call it is waiting in ends with
		// EINTR — and is noticed when the code has returned, as a signal
		// delivered while a process runs a library's code is. It has
		// interrupted the call in progress: the guest's own blocking
		// calls that follow do not end by it.
		s.interrupt = false
		s.outside()
	}
}

// SetOutsideInterrupt registers interrupt as what a signal posted for the
// guest does while the guest runs code outside it: code the host runs for
// the guest on its goroutine that has not returned yet — a native library
// the guest called, say, which may be waiting in a system call. A signal
// interrupts a process's system call wherever the process is; the guest's
// own blocking calls are ended by the host, code outside the guest by
// interrupt, which ends a system call that code is waiting in (or does
// nothing when it is in none). PostSignal calls it, from another goroutine
// and with the signal state locked, for each signal it posts that the guest
// neither blocks nor discards while no blocking call of the guest's own is
// waiting. nil registers nothing.
//
// It returns what was registered before, for the caller to put back when
// the code returns: such code can call back into the guest, which can run
// code outside it again. Once SetOutsideInterrupt has returned, an
// interrupt that was replaced is not called any more.
func (w *WasiStubs) SetOutsideInterrupt(interrupt func()) (previous func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	previous, w.sig.outside = w.sig.outside, interrupt
	return previous
}

// raiseSignalFlagLocked stores 1 in the guest's flag word. The guest runs on
// another goroutine and may be growing its memory, hence accessMemory: the
// word is looked up in the guest's memory (memBytes) under the lock growth
// takes. Caller holds w.mu.
func (w *WasiStubs) raiseSignalFlagLocked() {
	flagModule, addr := w.sig.flagModule, w.sig.flagAddr
	accessMemory(flagModule, func([]byte) {
		if b := w.memBytes(flagModule, addr, 4); b != nil {
			binary.LittleEndian.PutUint32(b, 1)
		}
	})
}

// beginBlocking is called by a host call that is about to block the guest.
// It reports false when the call must not block at all because a posted
// signal is waiting to be noticed: the call then returns EINTR. Otherwise
// wake is registered: PostSignal calls it, once, from another goroutine and
// with w.mu held, to end the wait. Every beginBlocking that returned true is
// followed by endBlocking.
//
// SIGKILL is noticed by ending: until the guest has taken it, no call of
// its blocks, however many it makes on the way to the point where it takes
// its signals.
func (w *WasiStubs) beginBlocking(wake func()) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fireDueTimerLocked()
	if w.sig.interrupt || w.sig.killPending() {
		w.sig.interrupt = false
		return false
	}
	w.sig.wake = wake
	return true
}

// endBlocking ends what beginBlocking started and reports whether a signal
// was posted in between, in which case wake has run.
func (w *WasiStubs) endBlocking() (interrupted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sig.wake = nil
	w.fireDueTimerLocked()
	interrupted = w.sig.interrupt || w.sig.killPending()
	w.sig.interrupt = false
	return interrupted
}

// keepInterrupt is called when a call that a signal had interrupted was
// carried out after all, because it did not have to wait. The guest has not
// noticed the signal yet, and nothing has told it: the next call that has
// to wait is interrupted, as the one that was let through would have been.
func (w *WasiStubs) keepInterrupt() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sig.pending&^w.sig.blocked != 0 {
		w.sig.interrupt = true
	}
}

// interruptDue reports whether a signal was posted since the blocking call
// in progress began.
func (w *WasiStubs) interruptDue() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sig.interrupt
}

// Proc_signal_register is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "proc_signal_register"). The guest names the
// 32-bit word in its memory that the host sets to 1 whenever a signal is
// waiting to be taken. A guest calls it whenever it may be running in a
// module instance the host has not seen yet (a snapshot or fork copy of the
// one that registered), so it is cheap: it returns 1 when this module and
// address are already registered, and 0 when the registration is new — the
// guest then reports its dispositions, which the host does not know either.
func (w *WasiStubs) Proc_signal_register(m *Module, flagPtr int32) int32 {
	return w.procSignalRegister(m, zext(flagPtr))
}

// Proc_signal_register64 is Proc_signal_register for a memory64 guest.
func (w *WasiStubs) Proc_signal_register64(m *Module, flagPtr int64) int32 {
	return w.procSignalRegister(m, uint64(flagPtr))
}

// procSignalRegister is the body of Proc_signal_register and
// Proc_signal_register64.
func (w *WasiStubs) procSignalRegister(m *Module, flagPtr uint64) int32 {
	if w.memBytes(m, flagPtr, 4) == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := &w.sig
	if s.flagModule == m && s.flagAddr == flagPtr {
		return 1
	}
	s.flagModule, s.flagAddr = m, flagPtr
	return 0
}

// Proc_signal_dispositions is a NON-STANDARD host import (name
// "proc_signal_dispositions"). The guest reports, as signal masks, the
// signals it has a handler for, the signals it ignores explicitly (SIG_IGN)
// and the signals it has blocked, every time one of the three changes. A
// pending signal that now has no effect is discarded, as sigaction(2) does.
// Ignoring SIGCHLD also gives up the children that have ended and were not
// waited for (see wasiSignals.reapsChildren). Returns 0.
func (w *WasiStubs) Proc_signal_dispositions(m *Module, handled, ignored, blocked int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := &w.sig
	s.handled, s.ignored, s.blocked = uint64(handled), uint64(ignored), uint64(blocked)
	s.pending &^= s.discards()
	if s.reapsChildren() {
		w.reapFinishedLocked()
	}
	if s.flagModule != nil && s.pending&^s.blocked != 0 {
		// Deliverable now: unblocked while pending, or posted to a forked
		// guest before it had registered.
		w.raiseSignalFlagLocked()
	}
	w.syncHostSignalsLocked()
	return _wasiESUCCESS
}

// Proc_signal_dispositions64 is Proc_signal_dispositions for a memory64 guest.
func (w *WasiStubs) Proc_signal_dispositions64(m *Module, handled, ignored, blocked int64) int32 {
	return w.Proc_signal_dispositions(m, handled, ignored, blocked)
}

// Proc_signal_take is a NON-STANDARD host import (name "proc_signal_take").
// It writes the mask of posted signals (u64) at maskPtr and forgets them:
// from here on they are the guest's to deliver, or to hold while blocked.
// Returns 0 or a negative errno.
func (w *WasiStubs) Proc_signal_take(m *Module, maskPtr int32) int32 {
	return w.procSignalTake(m, zext(maskPtr))
}

// Proc_signal_take64 is Proc_signal_take for a memory64 guest.
func (w *WasiStubs) Proc_signal_take64(m *Module, maskPtr int64) int32 {
	return w.procSignalTake(m, uint64(maskPtr))
}

// procSignalTake is the body of Proc_signal_take and Proc_signal_take64.
func (w *WasiStubs) procSignalTake(m *Module, maskPtr uint64) int32 {
	out := w.memBytes(m, maskPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	taken := w.sig.pending
	w.sig.pending = 0
	// The guest is at a safe point and has the signals: there is nothing
	// left to interrupt a blocking call for.
	w.sig.interrupt = false
	w.mu.Unlock()
	binary.LittleEndian.PutUint64(out, taken)
	return _wasiESUCCESS
}

// What Tty_control does, by number.
const (
	terminalDrain int32 = iota
	terminalFlow
	terminalFlush
	terminalBreak
)

// Proc_itimer is a NON-STANDARD host import (name "proc_itimer"): the
// instance's real-time interval timer, which backs setitimer(ITIMER_REAL),
// getitimer, alarm and ualarm.
//
// The state of the timer before the call is written at oldPtr as two
// little-endian u64 of nanoseconds: the time until it fires next (0 when it
// is not set) and the interval at which it fires again after that (0 for a
// timer that fires once). When set is non-zero the timer is then replaced:
// SIGALRM is posted to the guest value nanoseconds from now, and every
// interval nanoseconds after that when interval is not 0; a value of 0 only
// disarms the timer. With set 0 the call only reports.
//
// Returns 0, or a negative errno: EINVAL for a negative time.
func (w *WasiStubs) Proc_itimer(m *Module, set int32, value, interval int64, oldPtr int32) int32 {
	return w.procItimer(m, set, value, interval, zext(oldPtr))
}

// Proc_itimer64 is Proc_itimer for a memory64 guest.
func (w *WasiStubs) Proc_itimer64(m *Module, set int32, value, interval, oldPtr int64) int32 {
	return w.procItimer(m, set, value, interval, uint64(oldPtr))
}

// procItimer is the body of Proc_itimer and Proc_itimer64.
func (w *WasiStubs) procItimer(m *Module, set int32, value, interval int64, oldPtr uint64) int32 {
	out := w.memBytes(m, oldPtr, 16)
	if out == nil {
		return -_wasiEFAULT
	}
	if set != 0 && (value < 0 || interval < 0) {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	left, every := w.timerStateLocked()
	if set != 0 {
		w.stopTimerLocked()
		if value > 0 {
			w.startTimerLocked(time.Duration(value), time.Duration(interval))
		}
	}
	w.mu.Unlock()
	binary.LittleEndian.PutUint64(out[0:], uint64(left))
	binary.LittleEndian.PutUint64(out[8:], uint64(every))
	return _wasiESUCCESS
}

// timerStateLocked returns the time until the interval timer fires next and
// its reload interval; both are 0 when no timer is set. Caller holds w.mu.
func (w *WasiStubs) timerStateLocked() (left, every time.Duration) {
	s := &w.sig
	if s.timer == nil {
		return 0, 0
	}
	left = time.Until(s.timerAt)
	if left <= 0 {
		// It is about to fire; a set timer never reports that it is not.
		left = 1
	}
	return left, s.timerEvery
}

// startTimerLocked sets the interval timer: it fires after value, and then
// every every when that is not 0. Each firing posts SIGALRM. Firings the
// host was late for are not made up one by one — the signal would only be
// pending once anyway. Caller holds w.mu and has stopped any earlier timer.
func (w *WasiStubs) startTimerLocked(value, every time.Duration) {
	// The moment is taken before the host's timer is set, so that the
	// host's timer never runs ahead of it.
	at := time.Now().Add(value)
	var timer *time.Timer
	timer = time.AfterFunc(value, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.sig.timer == timer {
			w.fireDueTimerLocked()
		}
	})
	w.sig.timer, w.sig.timerAt, w.sig.timerEvery = timer, at, every
}

// fireDueTimerLocked makes the firing of the interval timer whose time has
// come: SIGALRM is posted, and the timer is set for its next firing or is
// over. The host's own timer does this when it runs, which is some time
// after the moment it was set for; a blocking call of the guest's does it
// when it begins and when it ends, so that the guest sees the two in the
// order of their times — a wait that ended by a timeout later than the
// timer's time ends after the signal was posted, as it does when a kernel
// keeps both (alarm(1); sleep(1) finds its handler run when sleep is over).
// Caller holds w.mu.
func (w *WasiStubs) fireDueTimerLocked() {
	s := &w.sig
	if s.timer == nil {
		return
	}
	now := time.Now()
	if s.timerAt.After(now) {
		return
	}
	if s.timerEvery > 0 {
		next := s.timerAt.Add(s.timerEvery)
		if !next.After(now) {
			next = now.Add(s.timerEvery)
		}
		s.timerAt = next
		s.timer.Reset(next.Sub(now))
	} else {
		s.timer.Stop()
		s.timer = nil
	}
	if w.hostProcess && !w.forked {
		if hostSig, known := hostSignalOf(wasiSIGALRM); known {
			if _, outside := hostActionsOutside()[hostSig]; outside {
				// Code outside the guest made its own handler the
				// process's action for SIGALRM (an event loop's signal
				// watcher, as libev's): the alarm is the process's, and
				// goes to that handler, as the kernel's alarm does. The
				// guest takes it from there if the handler passes it on.
				_ = signalHostSelf(hostSig)
				return
			}
		}
	}
	w.postSignalLocked(wasiSIGALRM)
}

// stopTimerLocked disarms the interval timer, if one is set. Caller holds
// w.mu.
func (w *WasiStubs) stopTimerLocked() {
	s := &w.sig
	if s.timer == nil {
		return
	}
	s.timer.Stop()
	s.timer, s.timerEvery = nil, 0
}

// Proc_signal_ignored is a NON-STANDARD host import (name
// "proc_signal_ignored"): 1 when the host process ignores the guest's
// signal sig by an action the runtime did not set, 0 otherwise. A guest that
// is the host process, or a pseudo-process forked from it, shares its
// signal actions with code outside the guest: a native library sets a signal
// to SIG_IGN with the host's sigaction (a network client ignores SIGPIPE),
// and the guest's C library reports and keeps that action, as the action of
// the process, where its own is the default one (sigaction(2) shows the
// action of the process, whoever set it). Any other guest, and a host the
// runtime cannot ask, gets 0.
func (w *WasiStubs) Proc_signal_ignored(m *Module, sig int32) int32 {
	if w.processIgnores(sig) {
		return 1
	}
	return 0
}

// Proc_signal_ignored64 is Proc_signal_ignored for a memory64 guest.
func (w *WasiStubs) Proc_signal_ignored64(m *Module, sig int32) int32 {
	return w.Proc_signal_ignored(m, sig)
}

// processIgnores reports whether the guest is the host process (or a
// pseudo-process forked from it) and that process ignores the guest's
// signal sig by an action the runtime did not set for the guest.
func (w *WasiStubs) processIgnores(sig int32) bool {
	bit := wasiSignalBit(sig)
	w.mu.Lock()
	mine := w.hostProcess && bit != 0 && w.sig.hostIgnored&bit == 0
	w.mu.Unlock()
	if !mine {
		return false
	}
	hostSig, known := hostSignalOf(sig)
	return known && hostSignalIgnored(hostSig)
}

// Proc_terminate is a NON-STANDARD host import (name "proc_terminate"): the
// guest ends by signal sig, the default action of a signal it neither
// handles nor ignores. It does not return; like Proc_exit it unwinds the
// guest with a panic, whose value is a *WasiSignalError.
func (w *WasiStubs) Proc_terminate(m *Module, sig int32) {
	panic(&WasiSignalError{Signal: sig})
}

// Proc_terminate64 is Proc_terminate for a memory64 guest.
func (w *WasiStubs) Proc_terminate64(m *Module, sig int32) {
	w.Proc_terminate(m, sig)
}

// detachSignalsLocked ends signal delivery to this instance: nothing may
// touch the guest's memory once it is being torn down. Caller holds w.mu.
func (w *WasiStubs) detachSignalsLocked() {
	w.stopTimerLocked()
	s := &w.sig
	s.flagModule, s.flagAddr = nil, 0
	s.handled, s.ignored, s.blocked, s.pending = 0, 0, 0, 0
	s.interrupt = false
	w.syncHostSignalsLocked()
}

// restoreHostSignal gives a signal the host process ignores (signal.Ignore)
// the action it has in a Go program that never touched it. Package signal
// has no way back from Ignore: Reset leaves the signal ignored — for the
// process, and for every command it starts from then on, which inherits
// the ignoring. A subscription that is taken and dropped again puts the
// runtime's handler back, over the ignoring, for every signal but SIGHUP
// and SIGINT: those two the runtime leaves ignored when it finds them so
// (it respects an ignoring the process may have inherited). For those two
// the kernel is told first that the signal has its default action
// (defaultSignalAction), and the runtime then does what it did when the
// program started.
//
// No other signal goes through its default action on the way: the process
// can get the signal at any moment, and for some the default action ends
// it — SIGPIPE comes at every write of the process (another process of the
// family, the runtime, a library) into a closed pipe.
func restoreHostSignal(sig syscall.Signal) {
	if sig == syscall.SIGHUP || sig == syscall.SIGINT {
		if err := defaultSignalAction(sig); err != nil {
			signal.Reset(sig)
			return
		}
	}
	taken := make(chan os.Signal, 1)
	signal.Notify(taken, sig)
	signal.Stop(taken)
}

// syncHostSignals is syncHostSignalsLocked for a caller without w.mu.
func (w *WasiStubs) syncHostSignals() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncHostSignalsLocked()
}

// syncHostSignalsLocked makes the host process's own signal handling follow
// the guest's dispositions when the guest is the host process
// (SetHostProcess) — and undoes all of it when it is not, or no longer:
//
//   - a signal the guest handles is caught and posted to the guest;
//   - a signal the guest ignores explicitly is ignored by the host process;
//   - any other signal is to do to the host process what it would do to the
//     program. The Go runtime sees to that for some signals and not for
//     others (wasiSignalsHeldByRuntime); the latter are caught and posted to
//     the guest as well, whose default action then ends the guest by that
//     signal (Proc_terminate), for the embedder to end the process likewise.
//
// SIGCHLD is not caught: the host posts it itself when a process of the
// instance finishes, and the host process's own SIGCHLD reports the same
// event (or one the guest has no part in). Signals the host does not have,
// and SIGKILL and SIGSTOP, which cannot be caught, are skipped.
//
// Caller holds w.mu.
func (w *WasiStubs) syncHostSignalsLocked() {
	s := &w.sig
	var relay, ignore uint64
	if w.hostProcess && !w.forked && s.flagModule != nil {
		uncatchable := wasiSignalBit(wasiSIGKILL) | wasiSignalBit(wasiSIGSTOP)
		relay = (s.handled | wasiSignalsHeldByRuntime&^s.ignored) &^ (uncatchable | wasiSignalBit(wasiSIGCHLD))
		ignore = s.ignored &^ (uncatchable | wasiDefaultIgnoredSignals)
	}
	// os/signal installs the Go runtime's handler again for a signal it is
	// asked for, and when it stops being asked for one. A handler that code
	// outside the guest made the process's action (libev's, for its signal
	// watchers) is put back afterwards, unless the guest changed what it
	// does with that very signal now: the last to set an action has it, as
	// in a process of its own.
	if outside := hostActionsOutside(); outside != nil {
		changed := (relay ^ s.relayed) | (ignore ^ s.hostIgnored)
		for hostSig := range outside {
			if sig := guestSignalOf(hostSig); sig != 0 && changed&wasiSignalBit(sig) != 0 {
				delete(outside, hostSig)
			}
		}
		defer restoreHostActionsOutside(outside)
	}
	// Ignoring or resetting a signal undoes a subscription to it, so this
	// comes before the subscription is brought up to date.
	if changed := ignore ^ s.hostIgnored; changed != 0 {
		for sig := int32(1); sig <= 64; sig++ {
			bit := wasiSignalBit(sig)
			hostSig, known := hostSignalOf(sig)
			if changed&bit == 0 || !known {
				continue
			}
			if ignore&bit != 0 {
				signal.Ignore(hostSig)
			} else {
				restoreHostSignal(hostSig)
			}
		}
		s.hostIgnored = ignore
	}
	if relay == s.relayed {
		return
	}
	// The new subscription is in place before the old one is dropped, so a
	// signal that stays handled is caught throughout.
	var relayTo chan os.Signal
	var sigs []os.Signal
	for sig := int32(1); sig <= 64; sig++ {
		if hostSig, known := hostSignalOf(sig); known && relay&wasiSignalBit(sig) != 0 {
			sigs = append(sigs, hostSig)
		}
	}
	if len(sigs) > 0 {
		relayTo = make(chan os.Signal, 64)
		signal.Notify(relayTo, sigs...)
		go w.relayHostSignals(relayTo)
	}
	if s.relay != nil {
		signal.Stop(s.relay)
		close(s.relay)
	}
	s.relay, s.relayed = relayTo, relay
}

// relayHostSignals posts the host process's signals arriving on from to the
// guest, until from is closed.
//
// SIGPIPE is the exception. The host process's SIGPIPE is the report of a
// write that failed with EPIPE, and the guest's writes post the signal
// themselves, at the write, where a process gets it (writeFailure). The
// host's copy of the same event arrives later, on this goroutine, when the
// guest may already have another disposition for the signal; so it is
// dropped here. It is still caught while the guest handles SIGPIPE, which
// keeps the Go runtime from ending the process over it.
func (w *WasiStubs) relayHostSignals(from <-chan os.Signal) {
	for received := range from {
		hostSig, ok := received.(syscall.Signal)
		if !ok {
			continue
		}
		if sig := guestSignalOf(hostSig); sig != 0 && sig != wasiSIGPIPE {
			w.PostSignal(sig)
		}
	}
}

// readStream reads from a stream whose read can block, as the guest asked
// for it: a non-blocking descriptor (O_NONBLOCK) reports EAGAIN when no
// input is there, a blocking one waits and reports EINTR when a signal is
// posted to the guest meanwhile.
func (w *WasiStubs) readStream(op *wasiOpen, src deadlineReader, bufs [][]byte) (uint64, int32) {
	return w.readStreamAs(op, src, bufs, op.nonblocking())
}

// readStreamAs is readStream with the blocking mode given by the caller: a
// receive may ask not to wait on a descriptor that otherwise does.
func (w *WasiStubs) readStreamAs(op *wasiOpen, src deadlineReader, bufs [][]byte, nonblocking bool) (uint64, int32) {
	if !nonblocking {
		var n uint64
		errno := _wasiESUCCESS
		if limit, _ := op.timeouts(); limit > 0 {
			n, errno = w.readWithin(op, src, bufs, limit)
		} else if got, interrupted := w.readInterruptibly(op, src, bufs); interrupted {
			errno = _wasiEINTR
		} else {
			n = got
		}
		if errno == _wasiEINTR {
			// A signal interrupts a read that has to wait. Input that is
			// there is read all the same, as read(2) returns it to a
			// process with a signal pending — whether the signal was
			// posted before the call or while it was on its way.
			if ready, refused := op.probeRead(src, time.Now().Add(pollProbeGrace), nil); ready && !refused {
				if got, served := op.takeAhead(bufs); served {
					w.keepInterrupt()
					return got, _wasiESUCCESS
				}
			}
		}
		return n, errno
	}
	// The probe is the non-blocking read: it waits just long enough for
	// the read to be attempted and keeps what arrives.
	ready, refused := op.probeRead(src, time.Now().Add(pollProbeGrace), nil)
	if refused {
		// A stream whose read cannot be bounded: all there is is the read.
		// One the host itself opened without waiting (a FIFO the guest
		// opened with O_NONBLOCK, where the host does not poll FIFOs) says
		// that nothing is there.
		n, err := readVecFailure(src, bufs)
		if n == 0 && errors.Is(err, syscall.EAGAIN) {
			return 0, _wasiEAGAIN
		}
		return n, _wasiESUCCESS
	}
	if !ready {
		return 0, _wasiEAGAIN
	}
	n, _ := op.takeAhead(bufs)
	return n, _wasiESUCCESS
}

// awaitWithin runs probe — a readiness probe of op's input, see probeInput —
// for a blocking call that gives up after limit (the socket's receive
// timeout). It returns 0 when the descriptor is ready, EAGAIN when the time
// ran out, EINTR when a signal was posted to the guest first.
func (w *WasiStubs) awaitWithin(limit time.Duration, probe func(until time.Time, stop <-chan struct{}) bool) int32 {
	posted := make(chan struct{})
	if !w.beginBlocking(func() { close(posted) }) {
		return _wasiEINTR
	}
	ready := probe(time.Now().Add(limit), posted)
	interrupted := w.endBlocking()
	switch {
	case ready:
		return _wasiESUCCESS
	case interrupted:
		return _wasiEINTR
	}
	return _wasiEAGAIN
}

// readWithin is the blocking read of a socket with a receive timeout.
func (w *WasiStubs) readWithin(op *wasiOpen, src deadlineReader, bufs [][]byte, limit time.Duration) (uint64, int32) {
	errno := w.awaitWithin(limit, func(until time.Time, stop <-chan struct{}) bool {
		ready, _ := op.probeRead(src, until, stop)
		return ready
	})
	if errno != _wasiESUCCESS {
		return 0, errno
	}
	n, served := op.takeAhead(bufs)
	if !served {
		// another process sharing the socket took the input first
		return 0, _wasiEAGAIN
	}
	return n, _wasiESUCCESS
}

// awaitAhead waits until input of the stream src is kept on op (ahead, or
// the end of input), without taking any of it: what a receive that only
// looks needs. It returns 0, EAGAIN when nothing is there and the call does
// not wait, or EINTR when a signal was posted to the guest first.
func (w *WasiStubs) awaitAhead(op *wasiOpen, src deadlineReader, nonblocking bool) int32 {
	for {
		if ready, _ := op.aheadReady(); ready {
			return _wasiESUCCESS
		}
		if nonblocking {
			if ready, _ := op.probeRead(src, time.Now().Add(pollProbeGrace), nil); !ready {
				return _wasiEAGAIN
			}
			return _wasiESUCCESS
		}
		posted := make(chan struct{})
		if !w.beginBlocking(func() { close(posted) }) {
			return _wasiEINTR
		}
		ready, refused := op.probeRead(src, time.Time{}, posted)
		interrupted := w.endBlocking()
		switch {
		case ready:
			return _wasiESUCCESS
		case interrupted:
			return _wasiEINTR
		case refused:
			// A stream whose read cannot be bounded cannot be looked at
			// without reading it.
			return _wasiENOTSUP
		}
	}
}

// peekAhead copies the input kept on op into bufs without taking it.
func (op *wasiOpen) peekAhead(bufs [][]byte) (n uint64) {
	op.mu.Lock()
	defer op.mu.Unlock()
	rest := op.ahead
	for _, buf := range bufs {
		c := copy(buf, rest)
		rest = rest[c:]
		n += uint64(c)
	}
	return n
}

// receiveStream is one receive on a connected stream socket, with its flags
// (wasiMsg...): input a probe already took comes first; a receive that only
// looks leaves everything in place; one that waits for all of it returns
// short only at the end of input or when a signal ends the wait.
func (w *WasiStubs) receiveStream(op *wasiOpen, conn net.Conn, bufs [][]byte, flags int32) (uint64, int32) {
	nonblocking := op.nonblocking() || flags&wasiMsgDontWait != 0
	if flags&wasiMsgPeek != 0 {
		if errno := w.awaitAhead(op, conn, nonblocking); errno != _wasiESUCCESS {
			return 0, errno
		}
		return op.peekAhead(bufs), _wasiESUCCESS
	}
	var total uint64
	for {
		n, served := op.takeAhead(bufs)
		if !served {
			var errno int32
			if n, errno = w.readStreamAs(op, conn, bufs, nonblocking); errno != _wasiESUCCESS {
				if total > 0 {
					return total, _wasiESUCCESS
				}
				return 0, errno
			}
		}
		total += n
		if flags&wasiMsgWaitAll == 0 || n == 0 || nonblocking {
			return total, _wasiESUCCESS
		}
		// Drop what is filled; go on when room is left.
		for len(bufs) > 0 && n >= uint64(len(bufs[0])) {
			n -= uint64(len(bufs[0]))
			bufs = bufs[1:]
		}
		if len(bufs) == 0 {
			return total, _wasiESUCCESS
		}
		bufs[0] = bufs[0][n:]
	}
}

// awaitOutputTurn takes the turn at op's output for a blocking write of the
// guest's, waiting no longer than until (the zero time is no limit). held is
// false when the turn was not taken: because a signal posted to the guest
// ended the wait (interrupted, to be reported as EINTR), or because the time
// was up.
func (w *WasiStubs) awaitOutputTurn(op *wasiOpen, until time.Time) (held, interrupted bool) {
	posted := make(chan struct{})
	if !w.beginBlocking(func() { close(posted) }) {
		return false, true
	}
	held = op.takeOutputTurn(until, posted)
	if w.endBlocking() {
		if held {
			op.passOutputTurn()
		}
		return false, true
	}
	return held, false
}

// awaitInputTurn takes the turn at op's input for a blocking call of the
// guest's. It reports false when a signal posted to the guest ended the wait
// first: the call is then to be reported as EINTR, and the turn is not held.
func (w *WasiStubs) awaitInputTurn(op *wasiOpen) bool {
	posted := make(chan struct{})
	if !w.beginBlocking(func() { close(posted) }) {
		return false
	}
	held := op.takeInputTurn(time.Time{}, posted)
	if w.endBlocking() {
		if held {
			op.passInputTurn()
		}
		return false
	}
	return held
}

// readInterruptibly is readVec for a stream whose read can block (a pipe, a
// socket, a terminal): a signal posted while the read waits — for its turn
// at the stream, or for input — ends it. interrupted is true when that
// happened before any byte arrived, and the read is to be reported as EINTR.
func (w *WasiStubs) readInterruptibly(op *wasiOpen, src deadlineReader, bufs [][]byte) (total uint64, interrupted bool) {
	if !w.awaitInputTurn(op) {
		return 0, true
	}
	defer op.passInputTurn()
	// Whoever had the turn before may have left input behind.
	if n, served := op.takeAhead(bufs); served {
		return n, false
	}
	if !w.beginBlocking(func() { _ = src.SetReadDeadline(time.Now()) }) {
		return 0, true
	}
	cutShort := false
read:
	for _, buf := range bufs {
		n, err := src.Read(buf)
		for n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			if w.interruptDue() {
				cutShort = true
				break read
			}
			// Only the holder of the turn sets a deadline, so this one is
			// not the stream's any more: it was left behind.
			_ = src.SetReadDeadline(time.Time{})
			n, err = src.Read(buf)
		}
		total += uint64(n)
		if err != nil || n < len(buf) {
			break
		}
	}
	if w.endBlocking() {
		// wake has set a deadline, which must not outlive this read.
		_ = src.SetReadDeadline(time.Time{})
	}
	return total, cutShort && total == 0
}

// ----- listening sockets, socket names and options ----------------------------

// wasiSocket is what a socket entry (wasiOpen.isSocket) carries besides its
// connection or listener. Guarded by the entry's mu.
type wasiSocket struct {
	// listening is set by Sock_listen: bind alone does not make a socket
	// accept connections.
	listening bool
	// accepted holds connections a readiness probe took off the listener:
	// the only portable way to learn that a listener has a connection
	// waiting is to accept it (see probeAccept). Sock_accept hands these
	// out first. acceptErr is a failure a probe ran into, reported by the
	// next Sock_accept.
	accepted  []net.Conn
	acceptErr error
	// options holds the option values the guest set (Sock_setopt), so that
	// they read back as set whatever the host could do with them.
	options map[int32]int32
	// datagram is a datagram a readiness probe took off a datagram socket,
	// with the address it came from (see probeDatagram): the next receive
	// hands it out whole. hasDatagram tells an empty datagram from none,
	// and datagramErr is a failure a probe ran into instead.
	datagram     []byte
	datagramFrom net.Addr
	datagramErr  error
	hasDatagram  bool
	// unixLocal and unixPeer are the names of a Unix-domain socket and of
	// the socket it is connected to as the guest gave them to bind and
	// connect: the host knows the sockets by other paths (its own, under
	// the preopened root), and getsockname and getpeername answer with the
	// guest's. Empty while the socket has none.
	unixLocal, unixPeer string
	// dial is the connection attempt of a stream socket that is under way
	// (see connectStream); nil when there is none.
	dial *wasiDial
	// failure is the errno of a connection attempt that failed after the
	// connect that started it had returned: SO_ERROR, or the next connect,
	// reports it once.
	failure int32
	// receiveTimeout and sendTimeout are the socket's SO_RCVTIMEO and
	// SO_SNDTIMEO (Sock_timeout): how long a blocking receive or accept, or
	// a blocking send, waits before it gives up with EAGAIN. 0 is no limit.
	receiveTimeout, sendTimeout time.Duration
}

// deadlineListener is a listener whose blocking accept can be bounded, as
// the TCP and Unix listeners of package net can.
type deadlineListener interface {
	net.Listener
	SetDeadline(t time.Time) error
}

// socketLocked returns the socket state of op, creating it on first use.
// Caller holds op.mu.
func (op *wasiOpen) socketLocked() *wasiSocket {
	if op.sock == nil {
		op.sock = &wasiSocket{}
	}
	return op.sock
}

// netListener returns the listener attached to a socket entry and whether
// the guest has called listen on it.
func (op *wasiOpen) netListener() (l net.Listener, listening bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.listener, op.sock != nil && op.sock.listening
}

// takeAccepted returns a connection a readiness probe accepted, or the
// failure one ran into; ok is false when there is neither.
func (op *wasiOpen) takeAccepted() (conn net.Conn, err error, ok bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	s := op.sock
	if s == nil {
		return nil, nil, false
	}
	if len(s.accepted) > 0 {
		conn = s.accepted[0]
		s.accepted = s.accepted[1:]
		return conn, nil, true
	}
	if s.acceptErr != nil {
		err, s.acceptErr = s.acceptErr, nil
		return nil, err, true
	}
	return nil, nil, false
}

// acceptedReady reports whether an accept would return without blocking
// because of what a probe already took.
func (op *wasiOpen) acceptedReady() bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.sock != nil && (len(op.sock.accepted) > 0 || op.sock.acceptErr != nil)
}

// probeAccept accepts once from l, as probeInput describes, and keeps a
// connection that arrives for the next Sock_accept. It reports whether the
// listener is now ready for an accept.
func (op *wasiOpen) probeAccept(l deadlineListener, until time.Time, stop <-chan struct{}) bool {
	look := func() bool {
		if !hostInputNow {
			return false
		}
		var conn net.Conn
		var again, looked bool
		var err error
		asked := hostDescriptor(l, func(fd uintptr) {
			if descriptorWaits(fd) {
				return
			}
			conn, again, err = acceptRaw(fd)
			looked = true
		})
		if !asked || !looked || again {
			return asked && looked
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		s := op.socketLocked()
		if err != nil {
			s.acceptErr = err
		} else {
			s.accepted = append(s.accepted, conn)
		}
		return true
	}
	ready, _ := op.probeInput(l.SetDeadline, until, stop, op.acceptedReady, look, func() {
		conn, err := l.Accept()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		s := op.socketLocked()
		if err != nil {
			s.acceptErr = err
		} else {
			s.accepted = append(s.accepted, conn)
		}
	})
	return ready
}

// mapNetError turns a failure of package net into a wasi errno.
func mapNetError(err error) int32 {
	switch {
	case err == nil:
		return _wasiESUCCESS
	case errors.Is(err, syscall.EADDRINUSE):
		return _wasiEADDRINUSE
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return _wasiEADDRNOTAVAIL
	case errors.Is(err, syscall.ECONNREFUSED):
		return _wasiECONNREFUSED
	case errors.Is(err, syscall.ECONNRESET):
		return _wasiECONNRESET
	case errors.Is(err, syscall.ENOTCONN):
		return _wasiENOTCONN
	case errors.Is(err, syscall.EISCONN):
		return _wasiEISCONN
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded):
		return _wasiETIMEDOUT
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return _wasiENETUNREACH
	case errors.Is(err, net.ErrClosed):
		return _wasiEBADF
	}
	return mapOSError(err)
}

// socketIPv4 renders the address of a sock_bind / sock_connect call: ipBE
// holds the four octets as they sat in sockaddr_in.sin_addr (the low byte is
// the first octet).
func socketIPv4(ipBE int32) string {
	u := uint32(ipBE)
	return fmt.Sprintf("%d.%d.%d.%d", u&0xff, (u>>8)&0xff, (u>>16)&0xff, (u>>24)&0xff)
}

// ipv4SockAddr is the address of a sock_bind / sock_connect call as a
// socket address: ipBE as socketIPv4 describes it, port in host byte order.
func ipv4SockAddr(ipBE, port int32) wasiSockAddr {
	u := uint32(ipBE)
	return wasiSockAddr{
		family: wasiSockFamilyIPv4,
		ip:     net.IP{byte(u), byte(u >> 8), byte(u >> 16), byte(u >> 24)},
		port:   int(uint16(port)),
	}
}

// Sock_bind is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_bind") backing bind() for an IPv4 stream socket: the socket
// gets the local address ipBE:port (ipBE as in Sock_connect; port in host
// byte order, 0 for one the host picks). The host's network API binds and
// listens in one step, so the address is taken — and connections to it
// queue — from here on; the guest's accept still needs its listen (see
// Sock_listen). Subject to the network policy's "listen" operation. Returns
// 0, or a negative errno: EADDRINUSE, EADDRNOTAVAIL, EACCES, EINVAL for a
// socket that is already bound or connected. Sock_bind_addr is the same for
// an address of any family.
func (w *WasiStubs) Sock_bind(m *Module, fd, ipBE, port int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket {
		return -_wasiENOTSOCK
	}
	return -w.bindSocket(op, ipv4SockAddr(ipBE, port), "")
}

// Sock_bind64 is Sock_bind for a memory64 guest.
func (w *WasiStubs) Sock_bind64(m *Module, fd, ipBE, port int32) int32 {
	return w.Sock_bind(m, fd, ipBE, port)
}

// attachListener makes l the listener of a socket entry, unless the entry
// got one or a connection in the meantime (a forked instance shares it); l
// is then closed and the call reports EINVAL. listening marks the socket as
// listening as well.
func (op *wasiOpen) attachListener(l net.Listener, listening bool) int32 {
	op.mu.Lock()
	if op.listener != nil || op.conn != nil {
		op.mu.Unlock()
		if err := l.Close(); err != nil {
			return mapNetError(err)
		}
		return _wasiEINVAL
	}
	op.listener = l
	if listening {
		op.socketLocked().listening = true
	}
	op.mu.Unlock()
	return _wasiESUCCESS
}

// Sock_listen is a NON-STANDARD host import (name "sock_listen") backing
// listen(): the socket accepts connections from here on. A socket of an IP
// family that was not bound listens on a port the host picks, on every
// address, as listen(2) has it; a Unix-domain socket has to be bound
// (EINVAL). backlog is accepted and left to the host. Returns 0 or a
// negative errno.
func (w *WasiStubs) Sock_listen(m *Module, fd, backlog int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket {
		return -_wasiENOTSOCK
	}
	if op.dgram {
		return -_wasiENOTSUP // EOPNOTSUPP
	}
	if h := op.host(); h != nil {
		if !w.checkNet("listen") {
			return -_wasiEACCES
		}
		return -w.listenHost(op, h, backlog)
	}
	if op.netConn() != nil {
		return -_wasiEINVAL
	}
	if op.dialing() != nil {
		return -_wasiEINVAL
	}
	if l, _ := op.netListener(); l == nil {
		if op.family == wasiSockFamilyUnix {
			return -_wasiEINVAL
		}
		l, errno := w.listenIP(op, op.unspecifiedAddr())
		if errno != _wasiESUCCESS {
			return -errno
		}
		return -op.attachListener(l, true)
	}
	op.mu.Lock()
	op.socketLocked().listening = true
	op.mu.Unlock()
	return _wasiESUCCESS
}

// Sock_listen64 is Sock_listen for a memory64 guest.
func (w *WasiStubs) Sock_listen64(m *Module, fd, backlog int32) int32 {
	return w.Sock_listen(m, fd, backlog)
}

// The address families of a socket and of a socket name: the host's own
// numbering (a libc's AF_* numbers differ from libc to libc).
const (
	wasiSockFamilyIPv4 = 1
	wasiSockFamilyUnix = 2
	wasiSockFamilyIPv6 = 3
)

// writeSockName writes a socket name at outPtr as three little-endian u32:
// the family (wasiSockFamily*), the IPv4 address with its first octet in the
// low byte, and the port. A name that is not an IPv4 one has only a family.
func (w *WasiStubs) writeSockName(m *Module, addr net.Addr, outPtr uint64) int32 {
	out := w.memBytes(m, outPtr, 12)
	if out == nil {
		return -_wasiEFAULT
	}
	var family, ip, port uint32
	switch a := addr.(type) {
	case *net.TCPAddr:
		family = wasiSockFamilyIPv4
		if v4 := a.IP.To4(); v4 != nil {
			ip = binary.LittleEndian.Uint32(v4)
		}
		port = uint32(a.Port)
	case *net.UDPAddr:
		family = wasiSockFamilyIPv4
		if v4 := a.IP.To4(); v4 != nil {
			ip = binary.LittleEndian.Uint32(v4)
		}
		port = uint32(a.Port)
	case *net.UnixAddr:
		family = wasiSockFamilyUnix
	case nil:
		// a socket that is not bound yet: the unspecified address
		family = wasiSockFamilyIPv4
	default:
		return -_wasiENOTSUP
	}
	binary.LittleEndian.PutUint32(out[0:], family)
	binary.LittleEndian.PutUint32(out[4:], ip)
	binary.LittleEndian.PutUint32(out[8:], port)
	return _wasiESUCCESS
}

// Sock_getsockname is a NON-STANDARD host import (name "sock_getsockname")
// backing getsockname(): the local name of the socket (see writeSockName) —
// the address it listens on, the local end of its connection, or the
// unspecified address while it has neither. Returns 0 or a negative errno.
func (w *WasiStubs) Sock_getsockname(m *Module, fd, outPtr int32) int32 {
	return w.sockGetsockname(m, fd, zext(outPtr))
}

// Sock_getsockname64 is Sock_getsockname for a memory64 guest.
func (w *WasiStubs) Sock_getsockname64(m *Module, fd int32, outPtr int64) int32 {
	return w.sockGetsockname(m, fd, uint64(outPtr))
}

// sockGetsockname is the body of Sock_getsockname and Sock_getsockname64.
func (w *WasiStubs) sockGetsockname(m *Module, fd int32, outPtr uint64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if h := op.host(); h != nil {
		addr, errno := op.hostSocketName(h, false)
		if errno != _wasiESUCCESS {
			return -errno
		}
		return w.writeSockName(m, addr, outPtr)
	}
	if conn := op.netConn(); conn != nil {
		return w.writeSockName(m, conn.LocalAddr(), outPtr)
	}
	if l, _ := op.netListener(); l != nil {
		return w.writeSockName(m, l.Addr(), outPtr)
	}
	if !op.isSocket {
		return -_wasiENOTSOCK
	}
	return w.writeSockName(m, nil, outPtr)
}

// Sock_getpeername is a NON-STANDARD host import (name "sock_getpeername")
// backing getpeername(): the name of the socket's peer (see writeSockName).
// Returns 0, or a negative errno: ENOTCONN for a socket without a
// connection.
func (w *WasiStubs) Sock_getpeername(m *Module, fd, outPtr int32) int32 {
	return w.sockGetpeername(m, fd, zext(outPtr))
}

// Sock_getpeername64 is Sock_getpeername for a memory64 guest.
func (w *WasiStubs) Sock_getpeername64(m *Module, fd int32, outPtr int64) int32 {
	return w.sockGetpeername(m, fd, uint64(outPtr))
}

// sockGetpeername is the body of Sock_getpeername and Sock_getpeername64.
func (w *WasiStubs) sockGetpeername(m *Module, fd int32, outPtr uint64) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if h := op.host(); h != nil {
		addr, errno := op.hostSocketName(h, true)
		if errno != _wasiESUCCESS {
			return -errno
		}
		return w.writeSockName(m, addr, outPtr)
	}
	conn := op.netConn()
	if conn == nil {
		if l, _ := op.netListener(); l == nil && !op.isSocket {
			return -_wasiENOTSOCK
		}
		return -_wasiENOTCONN
	}
	peer := conn.RemoteAddr()
	if peer == nil {
		// a datagram socket that is bound and not connected
		return -_wasiENOTCONN
	}
	if errno := op.peerLost(conn); errno != _wasiESUCCESS {
		return -errno
	}
	return w.writeSockName(m, peer, outPtr)
}

// peerLost asks the host whether the stream connection conn of op still has
// its peer, and returns 0 while it has. A connection that is over — closed
// by the peer and shut down or reset on this side — has none: getpeername
// fails from then on (ENOTCONN on Linux), and that is how a program learns
// it (IO::Socket's connected, in a loop that receives for as long as the
// socket is connected). The address package net remembers for the
// connection does not tell.
func (op *wasiOpen) peerLost(conn net.Conn) int32 {
	if op.dgram {
		return _wasiESUCCESS
	}
	errno := _wasiESUCCESS
	hostDescriptor(conn, func(fd uintptr) { errno = peerFailure(fd) })
	return errno
}

// The socket options the host knows, as the guest's shim names them to
// Sock_setopt / Sock_getopt (the numbers libc gives the options differ from
// libc to libc, so they are not used on this boundary).
const (
	wasiSockOptReuseAddr int32 = 1  // SO_REUSEADDR
	wasiSockOptReusePort int32 = 2  // SO_REUSEPORT
	wasiSockOptKeepAlive int32 = 3  // SO_KEEPALIVE
	wasiSockOptNoDelay   int32 = 4  // TCP_NODELAY
	wasiSockOptRcvBuf    int32 = 5  // SO_RCVBUF
	wasiSockOptSndBuf    int32 = 6  // SO_SNDBUF
	wasiSockOptLinger    int32 = 7  // SO_LINGER: seconds, or -1 for off
	wasiSockOptError     int32 = 8  // SO_ERROR (read only)
	wasiSockOptType      int32 = 9  // SO_TYPE (read only): wasiSockTypeStream or wasiSockTypeDgram
	wasiSockOptAccepting int32 = 10 // SO_ACCEPTCONN (read only): 1 for a listening socket
	wasiSockOptV6Only    int32 = 11 // IPV6_V6ONLY: takes effect when the socket is bound or connected
	wasiSockOptBroadcast int32 = 12 // SO_BROADCAST
	wasiSockOptDefer     int32 = 13 // TCP_DEFER_ACCEPT: seconds
)

// The two timeouts of a socket, as Sock_timeout names them.
const (
	wasiSockTimeoutReceive int32 = 1 // SO_RCVTIMEO
	wasiSockTimeoutSend    int32 = 2 // SO_SNDTIMEO
)

// timeouts returns the socket's receive and send timeouts; 0 is no limit.
func (op *wasiOpen) timeouts() (receive, send time.Duration) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.sock == nil {
		return 0, 0
	}
	return op.sock.receiveTimeout, op.sock.sendTimeout
}

// Sock_timeout is a NON-STANDARD host import (name "sock_timeout") backing
// SO_RCVTIMEO and SO_SNDTIMEO. which names the timeout (1 receive, 2 send).
// The timeout before the call is written at oldPtr in nanoseconds (i64; 0 is
// no limit); when set is non-zero it is then replaced by nanos. A blocking
// receive or accept, or a blocking send, that has waited that long gives up
// with EAGAIN. Returns 0, or a negative errno: EINVAL for another which or a
// negative time.
func (w *WasiStubs) Sock_timeout(m *Module, fd, which, set int32, nanos int64, oldPtr int32) int32 {
	return w.sockTimeout(m, fd, which, set, nanos, zext(oldPtr))
}

// Sock_timeout64 is Sock_timeout for a memory64 guest.
func (w *WasiStubs) Sock_timeout64(m *Module, fd, which, set int32, nanos, oldPtr int64) int32 {
	return w.sockTimeout(m, fd, which, set, nanos, uint64(oldPtr))
}

// sockTimeout is the body of Sock_timeout and Sock_timeout64.
func (w *WasiStubs) sockTimeout(m *Module, fd, which, set int32, nanos int64, oldPtr uint64) int32 {
	out := w.memBytes(m, oldPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		return -_wasiENOTSOCK
	}
	if (which != wasiSockTimeoutReceive && which != wasiSockTimeoutSend) || (set != 0 && nanos < 0) {
		return -_wasiEINVAL
	}
	if h := op.host(); h != nil {
		old, errno := w.timeoutHost(h, which, set != 0, nanos)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint64(out, uint64(old))
		return _wasiESUCCESS
	}
	op.mu.Lock()
	sock := op.socketLocked()
	timeout := &sock.receiveTimeout
	if which == wasiSockTimeoutSend {
		timeout = &sock.sendTimeout
	}
	old := *timeout
	if set != 0 {
		*timeout = time.Duration(nanos)
	}
	op.mu.Unlock()
	binary.LittleEndian.PutUint64(out, uint64(old))
	return _wasiESUCCESS
}

// Sock_setopt is a NON-STANDARD host import (name "sock_setopt") backing
// setsockopt() for the options above. The value is remembered and reads back
// through Sock_getopt. What the host can act on is applied to the socket's
// connection when it has one: keep-alive, no-delay, the buffer sizes and
// linger. Address reuse is how the host binds every listener anyway. Returns
// 0, or a negative errno: ENOPROTOOPT for an option that is unknown or read
// only.
func (w *WasiStubs) Sock_setopt(m *Module, fd, option, value int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		return -_wasiENOTSOCK
	}
	if h := op.host(); h != nil {
		return -w.setoptHost(op, h, option, value)
	}
	var err error
	tcp, _ := op.netConn().(*net.TCPConn)
	switch option {
	case wasiSockOptReuseAddr, wasiSockOptReusePort, wasiSockOptBroadcast, wasiSockOptDefer:
		// remembered: the host's socket is made with the defaults
	case wasiSockOptV6Only:
		if op.family != wasiSockFamilyIPv6 {
			return -_wasiENOPROTOOPT
		}
		if l, _ := op.netListener(); l != nil || op.netConn() != nil {
			// the host's socket exists and is bound: too late
			return -_wasiEINVAL
		}
	case wasiSockOptKeepAlive:
		if tcp != nil {
			err = tcp.SetKeepAlive(value != 0)
		}
	case wasiSockOptNoDelay:
		if tcp != nil {
			err = tcp.SetNoDelay(value != 0)
		}
	case wasiSockOptRcvBuf:
		if tcp != nil {
			err = tcp.SetReadBuffer(int(value))
		}
	case wasiSockOptSndBuf:
		if tcp != nil {
			err = tcp.SetWriteBuffer(int(value))
		}
	case wasiSockOptLinger:
		if tcp != nil {
			err = tcp.SetLinger(int(value))
		}
	default:
		return -_wasiENOPROTOOPT
	}
	if err != nil {
		return -mapNetError(err)
	}
	op.mu.Lock()
	s := op.socketLocked()
	if s.options == nil {
		s.options = map[int32]int32{}
	}
	s.options[option] = value
	op.mu.Unlock()
	return _wasiESUCCESS
}

// Sock_setopt64 is Sock_setopt for a memory64 guest.
func (w *WasiStubs) Sock_setopt64(m *Module, fd, option, value int32) int32 {
	return w.Sock_setopt(m, fd, option, value)
}

// Sock_getopt is a NON-STANDARD host import (name "sock_getopt") backing
// getsockopt(): it writes the option's value (i32) at valuePtr — what the
// guest set, or the option's initial value: 0, and -1 (off) for linger.
// SO_ERROR is the errno of a connection attempt that failed after the
// connect that started it had returned, once, and 0 otherwise: every other
// failed operation reports its error itself.
// SO_ACCEPTCONN is 1 for a socket that listens. Returns
// 0, or a negative errno: ENOPROTOOPT for an unknown option.
func (w *WasiStubs) Sock_getopt(m *Module, fd, option, valuePtr int32) int32 {
	return w.sockGetopt(m, fd, option, zext(valuePtr))
}

// Sock_getopt64 is Sock_getopt for a memory64 guest.
func (w *WasiStubs) Sock_getopt64(m *Module, fd, option int32, valuePtr int64) int32 {
	return w.sockGetopt(m, fd, option, uint64(valuePtr))
}

// sockGetopt is the body of Sock_getopt and Sock_getopt64.
func (w *WasiStubs) sockGetopt(m *Module, fd, option int32, valuePtr uint64) int32 {
	out := w.memBytes(m, valuePtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		return -_wasiENOTSOCK
	}
	if h := op.host(); h != nil {
		value, errno := w.getoptHost(op, h, option)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(value))
		return _wasiESUCCESS
	}
	var value int32
	switch option {
	case wasiSockOptError:
		value = op.takeFailure()
	case wasiSockOptAccepting:
		if _, listening := op.netListener(); listening {
			value = 1
		}
	case wasiSockOptType:
		value = wasiSockTypeStream
		if op.dgram {
			value = wasiSockTypeDgram
		}
	case wasiSockOptReuseAddr, wasiSockOptReusePort, wasiSockOptKeepAlive, wasiSockOptNoDelay,
		wasiSockOptRcvBuf, wasiSockOptSndBuf, wasiSockOptLinger, wasiSockOptV6Only,
		wasiSockOptBroadcast, wasiSockOptDefer:
		if option == wasiSockOptV6Only && op.family != wasiSockFamilyIPv6 {
			return -_wasiENOPROTOOPT
		}
		if option == wasiSockOptLinger {
			value = -1
		}
		op.mu.Lock()
		if op.sock != nil {
			if set, ok := op.sock.options[option]; ok {
				value = set
			}
		}
		op.mu.Unlock()
	default:
		return -_wasiENOPROTOOPT
	}
	binary.LittleEndian.PutUint32(out, uint32(value))
	return _wasiESUCCESS
}

// Sock_pair is a NON-STANDARD host import (name "sock_pair") backing
// socketpair(AF_UNIX, SOCK_STREAM): it creates a pair of connected stream
// sockets and writes their two fds (i32 each) at fdsOutPtr. Returns 0 or a
// negative errno (ENOTSUP on a host without socket pairs).
func (w *WasiStubs) Sock_pair(m *Module, fdsOutPtr int32) int32 {
	return w.sockPair(m, zext(fdsOutPtr))
}

// Sock_pair64 is Sock_pair for a memory64 guest.
func (w *WasiStubs) Sock_pair64(m *Module, fdsOutPtr int64) int32 {
	return w.sockPair(m, uint64(fdsOutPtr))
}

// sockPair is the body of Sock_pair and Sock_pair64.
func (w *WasiStubs) sockPair(m *Module, fdsOutPtr uint64) int32 {
	out := w.memBytes(m, fdsOutPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	afd, bfd, errno := w.openSocketPair(false)
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(out[0:], uint32(afd))
	binary.LittleEndian.PutUint32(out[4:], uint32(bfd))
	return _wasiESUCCESS
}

// openSocketPair makes a pair of connected Unix-domain sockets, of stream
// or of datagram sockets, and returns their fds, or an errno.
func (w *WasiStubs) openSocketPair(dgram bool) (afd, bfd, errno int32) {
	w.mu.Lock()
	host := w.hostDescriptorsLocked()
	w.mu.Unlock()
	if host {
		typ := wasiSockTypeStream
		if dgram {
			typ = wasiSockTypeDgram
		}
		fds, errno := w.openHostSockets(wasiSockFamilyUnix, typ, true)
		if errno != _wasiESUCCESS {
			return -1, -1, errno
		}
		return fds[0], fds[1], _wasiESUCCESS
	}
	a, b, err := socketPair(dgram)
	if err != nil {
		return -1, -1, mapNetError(err)
	}
	w.mu.Lock()
	afd = w.addFDLocked(&wasiOpen{conn: a, isSocket: true, dgram: dgram, family: wasiSockFamilyUnix})
	bfd = w.addFDLocked(&wasiOpen{conn: b, isSocket: true, dgram: dgram, family: wasiSockFamilyUnix})
	w.mu.Unlock()
	return afd, bfd, _wasiESUCCESS
}

// ----- datagram sockets -------------------------------------------------------
//
// A datagram socket (Sock_socket or Sock_open with wasiSockTypeDgram) is a
// UDP socket of the host, or a Unix-domain datagram socket. It has one as
// soon as it needs one: when it is bound, when it is connected, or when it
// first sends. Its datagrams keep their boundaries: one send is one
// datagram, and one receive takes one, cut to the buffer.

// datagramSocket is a datagram socket of the host: a UDP socket or a
// Unix-domain one.
type datagramSocket interface {
	net.Conn
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, addr net.Addr) (int, error)
}

// listenDatagram makes the host socket of the datagram socket op, bound to
// local (nil: no name for a Unix-domain socket, and any address with a port
// the host picks otherwise).
func (op *wasiOpen) listenDatagram(local net.Addr) (net.Conn, error) {
	if op.family == wasiSockFamilyUnix {
		if at, _ := local.(*net.UnixAddr); at != nil {
			return net.ListenUnixgram("unixgram", at)
		}
		return unboundUnixDatagram()
	}
	network, address := "udp4", ":0"
	if op.family == wasiSockFamilyIPv6 {
		network = "udp6"
	}
	if at, _ := local.(*net.UDPAddr); at != nil {
		address = at.String()
	}
	lc := net.ListenConfig{Control: op.socketControl()}
	pc, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	conn, isConn := pc.(net.Conn)
	if !isConn {
		return nil, errors.Join(errors.ErrUnsupported, pc.Close())
	}
	return conn, nil
}

// attachDatagramConn gives a datagram socket its host socket, bound to
// local (see listenDatagram). It reports 0, or the errno of the failure —
// EINVAL when the socket got one in the meantime (a forked instance shares
// it).
func (op *wasiOpen) attachDatagramConn(local net.Addr) int32 {
	conn, err := op.listenDatagram(local)
	if err != nil {
		return mapNetError(err)
	}
	op.mu.Lock()
	if op.conn != nil {
		op.mu.Unlock()
		if cerr := conn.Close(); cerr != nil {
			return mapNetError(cerr)
		}
		return _wasiEINVAL
	}
	op.conn = conn
	op.mu.Unlock()
	return _wasiESUCCESS
}

// connectDatagram connects a datagram socket: from now on it sends to peer
// and receives only from there. The caller has asked the dial policy. A
// socket that is bound keeps its local address, and one that is connected
// already is connected anew: the host's sockets cannot change their peer,
// so the socket is replaced by one at the same local address. It reports an
// errno.
func (w *WasiStubs) connectDatagram(op *wasiOpen, peer net.Addr) int32 {
	op.mu.Lock()
	old := op.conn
	op.mu.Unlock()
	var local net.Addr
	if old != nil {
		local = old.LocalAddr()
		if cerr := old.Close(); cerr != nil {
			return mapNetError(cerr)
		}
	}
	var conn net.Conn
	var err error
	switch to := peer.(type) {
	case *net.UnixAddr:
		from, _ := local.(*net.UnixAddr)
		if from != nil && from.Name == "" {
			from = nil // the socket had no name
		}
		if from != nil && from.Name[0] != '@' {
			// the name is taken anew by the socket that replaces the old
			err = os.Remove(from.Name)
		}
		if err == nil {
			conn, err = net.DialUnix("unixgram", from, to)
		}
	case *net.UDPAddr:
		network := "udp4"
		if op.family == wasiSockFamilyIPv6 && to.IP.To4() == nil {
			network = "udp6"
		}
		from, _ := local.(*net.UDPAddr)
		dialer := net.Dialer{Control: op.socketControl()}
		if from != nil {
			dialer.LocalAddr = from
		}
		conn, err = dialer.Dial(network, to.String())
	default:
		err = errors.ErrUnsupported
	}
	if err != nil {
		op.mu.Lock()
		if op.conn == old {
			op.conn = nil
		}
		op.mu.Unlock()
		return mapNetError(err)
	}
	op.mu.Lock()
	if op.conn != old {
		// A forked instance sharing the socket connected it meanwhile.
		op.mu.Unlock()
		if cerr := conn.Close(); cerr != nil {
			return mapNetError(cerr)
		}
		return _wasiEINVAL
	}
	op.conn = conn
	op.mu.Unlock()
	return _wasiESUCCESS
}

// datagramConn returns the host socket of a datagram socket entry, giving
// it one when it has none yet — at an address the host picks, or without a
// name in the Unix domain: what sending from an unbound socket does.
func (op *wasiOpen) datagramConn() (datagramSocket, int32) {
	if conn, ok := op.netConn().(datagramSocket); ok {
		return conn, _wasiESUCCESS
	}
	if errno := op.attachDatagramConn(nil); errno != _wasiESUCCESS && errno != _wasiEINVAL {
		return nil, errno
	}
	conn, ok := op.netConn().(datagramSocket)
	if !ok {
		return nil, _wasiEBADF
	}
	return conn, _wasiESUCCESS
}

// datagramReady reports whether a receive would return at once because of
// what a probe already took.
func (op *wasiOpen) datagramReady() bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.sock != nil && (op.sock.hasDatagram || op.sock.datagramErr != nil)
}

// takeDatagram hands out the datagram a probe took, or the failure one ran
// into; ok is false when there is neither. With keep the datagram stays
// where it is, for a receive that only looks.
func (op *wasiOpen) takeDatagram(keep bool) (data []byte, from net.Addr, err error, ok bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	s := op.sock
	if s == nil {
		return nil, nil, nil, false
	}
	if s.hasDatagram {
		data, from = s.datagram, s.datagramFrom
		if !keep {
			s.datagram, s.datagramFrom, s.hasDatagram = nil, nil, false
		}
		return data, from, nil, true
	}
	if s.datagramErr != nil {
		err, s.datagramErr = s.datagramErr, nil
		return nil, nil, err, true
	}
	return nil, nil, nil, false
}

// keepDatagram receives one datagram from conn and keeps it, with its
// sender, for the next receive; a receive that ran into the deadline keeps
// nothing. The caller has the turn at op's input. Only receiving tells that
// a datagram is there, as only reading tells for a stream.
func (op *wasiOpen) keepDatagram(conn datagramSocket) {
	buf := make([]byte, op.datagramRoom())
	n, from, err := conn.ReadFrom(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	s := op.socketLocked()
	if err != nil {
		s.datagramErr = err
	} else {
		s.datagram, s.datagramFrom, s.hasDatagram = buf[:n], from, true
	}
}

// probeDatagram receives one datagram from conn, as probeInput describes,
// and reports whether the socket is now ready for a receive.
func (op *wasiOpen) probeDatagram(conn datagramSocket, until time.Time, stop <-chan struct{}) bool {
	look := func() bool {
		if !hostInputNow {
			return false
		}
		buf := make([]byte, op.datagramRoom())
		var n int
		var from net.Addr
		var again, looked bool
		var err error
		asked := hostDescriptor(conn, func(fd uintptr) {
			if descriptorWaits(fd) {
				return
			}
			n, from, again, err = receiveRaw(fd, buf)
			looked = true
		})
		if !asked || !looked || again {
			return asked && looked
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		s := op.socketLocked()
		if err != nil {
			s.datagramErr = os.NewSyscallError("recvfrom", err)
		} else {
			s.datagram, s.datagramFrom, s.hasDatagram = buf[:n], from, true
		}
		return true
	}
	ready, _ := op.probeInput(conn.SetReadDeadline, until, stop, op.datagramReady, look, func() { op.keepDatagram(conn) })
	return ready
}

// datagramRoom is the size of the buffer a datagram of the socket is
// received into: no datagram is larger.
func (op *wasiOpen) datagramRoom() int {
	if op.family == wasiSockFamilyUnix {
		return 1 << 18 // a Unix-domain one, with the usual send buffers
	}
	return 1 << 16 // UDP
}

// receiveDatagram takes one datagram off a datagram socket into bufs — what
// does not fit is dropped, as recv does — and returns its size as received
// and its sender. A non-blocking socket reports EAGAIN when none is there; a
// blocking one waits, and reports EINTR when a signal is posted to the guest
// meanwhile. flags are the receive's (wasiMsgPeek, wasiMsgDontWait).
func (w *WasiStubs) receiveDatagram(op *wasiOpen, conn datagramSocket, bufs [][]byte, flags int32) (uint64, net.Addr, int32) {
	keep := flags&wasiMsgPeek != 0
	data, from, err, taken := op.takeDatagram(keep)
	if !taken && (op.nonblocking() || flags&wasiMsgDontWait != 0) {
		// Long enough for the receive to be attempted, as for a readiness
		// probe.
		if !op.probeDatagram(conn, time.Now().Add(pollProbeGrace), nil) {
			return 0, nil, _wasiEAGAIN
		}
		if data, from, err, taken = op.takeDatagram(keep); !taken {
			// another process sharing the socket took it first
			return 0, nil, _wasiEAGAIN
		}
	}
	if limit, _ := op.timeouts(); !taken && limit > 0 {
		errno := w.awaitWithin(limit, func(until time.Time, stop <-chan struct{}) bool {
			return op.probeDatagram(conn, until, stop)
		})
		if errno != _wasiESUCCESS {
			return 0, nil, errno
		}
		if data, from, err, taken = op.takeDatagram(keep); !taken {
			// another process sharing the socket took it first
			return 0, nil, _wasiEAGAIN
		}
	}
	for !taken {
		if !w.awaitInputTurn(op) {
			return 0, nil, _wasiEINTR
		}
		// Whoever had the turn before may have left a datagram behind.
		interrupted := false
		if !op.datagramReady() {
			if w.beginBlocking(func() { _ = conn.SetReadDeadline(time.Now()) }) {
				for {
					op.keepDatagram(conn)
					if op.datagramReady() {
						break
					}
					if w.interruptDue() {
						interrupted = true
						break
					}
					// Only the holder of the turn sets a deadline, so this
					// one was left behind.
					_ = conn.SetReadDeadline(time.Time{})
				}
				if w.endBlocking() {
					// wake has set a deadline, which must not outlive this
					// receive.
					_ = conn.SetReadDeadline(time.Time{})
				}
			} else {
				interrupted = true
			}
		}
		op.passInputTurn()
		if data, from, err, taken = op.takeDatagram(keep); !taken && interrupted {
			return 0, nil, _wasiEINTR
		}
	}
	if err != nil {
		return 0, nil, mapNetError(err)
	}
	var n uint64
	for _, buf := range bufs {
		c := copy(buf, data)
		data = data[c:]
		n += uint64(c)
	}
	return n, from, _wasiESUCCESS
}

// Sock_sendto is a NON-STANDARD host import (name "sock_sendto") backing
// sendto(): it sends the bytes at (bufPtr, bufLen) on the socket fd and
// writes the count sent (u32) at sentPtr. With hasAddr set, a datagram
// socket sends the datagram to ipBE:port (as in Sock_connect), which is
// subject to the dial policy with the network "udp"; a socket that has no
// local address yet gets one the host picks. Without an address — and on a
// stream socket, where an address means nothing — it is a send to the
// socket's peer. flags are the send's (wasiMsgDontWait, wasiMsgNoSignal).
// Returns 0, or a negative errno: ENOTCONN (EDESTADDRREQ's place) for no
// address on an unconnected datagram socket, and for an address on a
// connected one what the host's sendto says (see sendDatagram).
func (w *WasiStubs) Sock_sendto(m *Module, fd, bufPtr, bufLen, flags, hasAddr, ipBE, port, sentPtr int32) int32 {
	return w.sockSendto(m, fd, zext(bufPtr), bufLen, flags, hasAddr, ipBE, port, zext(sentPtr))
}

// Sock_sendto64 is Sock_sendto for a memory64 guest.
func (w *WasiStubs) Sock_sendto64(m *Module, fd int32, bufPtr int64, bufLen, flags, hasAddr, ipBE, port int32, sentPtr int64) int32 {
	return w.sockSendto(m, fd, uint64(bufPtr), bufLen, flags, hasAddr, ipBE, port, uint64(sentPtr))
}

// sockSendto is the body of Sock_sendto and Sock_sendto64.
func (w *WasiStubs) sockSendto(m *Module, fd int32, bufPtr uint64, bufLen, flags, hasAddr, ipBE, port int32, sentPtr uint64) int32 {
	if !w.checkNet("send") {
		return -_wasiEACCES
	}
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, sentPtr, 4)
	if (buf == nil && bufLen != 0) || out == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	hook := w.dialHook
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		return -_wasiENOTSOCK
	}
	h := op.host()
	if !op.dgram || hasAddr == 0 {
		if h != nil {
			n, errno := w.sendHost(op, h, [][]byte{buf}, nil, flags)
			binary.LittleEndian.PutUint32(out, uint32(n))
			return -errno
		}
		conn := op.netConn()
		if conn == nil || (op.dgram && conn.RemoteAddr() == nil) {
			return -_wasiENOTCONN
		}
		n, errno := w.sendFd(op, conn, [][]byte{buf}, flags)
		binary.LittleEndian.PutUint32(out, uint32(n))
		return -errno
	}
	ip := socketIPv4(ipBE)
	p := int(uint16(port))
	w.mu.Lock()
	host := w.resolvedHosts[ip]
	w.mu.Unlock()
	if hook != nil && !hook("udp", host, ip, p) {
		return -_wasiEACCES
	}
	if h != nil {
		n, errno := w.sendHost(op, h, [][]byte{buf}, ipv4SockAddr(ipBE, port).hostSockaddr(""), flags)
		binary.LittleEndian.PutUint32(out, uint32(n))
		return -errno
	}
	conn, errno := op.datagramConn()
	if errno != _wasiESUCCESS {
		return -errno
	}
	n, err := sendDatagram(op, conn, buf, &net.UDPAddr{IP: net.ParseIP(ip), Port: p})
	if err != nil {
		return -w.writeFailure(err, flags)
	}
	binary.LittleEndian.PutUint32(out, uint32(n))
	return _wasiESUCCESS
}

// Sock_recvfrom is a NON-STANDARD host import (name "sock_recvfrom") backing
// recvfrom(): it receives into (bufPtr, bufLen), writes the count received
// (u32) at receivedPtr and the sender's name at namePtr (see writeSockName;
// a name of family 0 when there is none to give). A datagram socket hands
// over one datagram, cut to the buffer, and names who sent it; a stream
// socket receives like Sock_recv and names its peer. flags are the
// receive's (wasiMsgPeek, wasiMsgWaitAll, wasiMsgDontWait). Returns 0, or a
// negative errno: EAGAIN on a non-blocking socket with nothing to receive,
// EINTR when a signal is posted to the guest while it waits.
func (w *WasiStubs) Sock_recvfrom(m *Module, fd, bufPtr, bufLen, flags, namePtr, receivedPtr int32) int32 {
	return w.sockRecvfrom(m, fd, zext(bufPtr), bufLen, flags, zext(namePtr), zext(receivedPtr))
}

// Sock_recvfrom64 is Sock_recvfrom for a memory64 guest.
func (w *WasiStubs) Sock_recvfrom64(m *Module, fd int32, bufPtr int64, bufLen, flags int32, namePtr, receivedPtr int64) int32 {
	return w.sockRecvfrom(m, fd, uint64(bufPtr), bufLen, flags, uint64(namePtr), uint64(receivedPtr))
}

// sockRecvfrom is the body of Sock_recvfrom and Sock_recvfrom64.
func (w *WasiStubs) sockRecvfrom(m *Module, fd int32, bufPtr uint64, bufLen, flags int32, namePtr, receivedPtr uint64) int32 {
	if !w.checkNet("recv") {
		return -_wasiEACCES
	}
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, receivedPtr, 4)
	name := w.memBytes(m, namePtr, 12)
	if (buf == nil && bufLen != 0) || out == nil || name == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		return -_wasiENOTSOCK
	}
	for i := range name {
		name[i] = 0
	}
	if h := op.host(); h != nil {
		n, from, errno := w.receiveFromHost(op, h, buf, flags)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
		if from != nil {
			if rc := w.writeSockName(m, from, namePtr); rc != -_wasiENOTSUP {
				return rc
			}
		}
		return _wasiESUCCESS
	}
	if op.dgram {
		conn, errno := op.datagramConn()
		if errno != _wasiESUCCESS {
			return -errno
		}
		n, from, errno := w.receiveDatagram(op, conn, [][]byte{buf}, flags)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
		if from != nil {
			return w.writeSockName(m, from, namePtr)
		}
		return _wasiESUCCESS
	}
	conn := op.netConn()
	if conn == nil {
		return -_wasiENOTCONN
	}
	n, errno := w.receiveStream(op, conn, [][]byte{buf}, flags)
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(out, uint32(n))
	if peer := conn.RemoteAddr(); peer != nil {
		if rc := w.writeSockName(m, peer, namePtr); rc != -_wasiENOTSUP {
			return rc
		}
	}
	return _wasiESUCCESS
}

// wasiFdflagNonblock is the O_NONBLOCK bit of the fdflags (fd_fdstat_set_flags).
const wasiFdflagNonblock int32 = 0x4

// nonblocking reports whether the guest has set O_NONBLOCK on the entry.
func (op *wasiOpen) nonblocking() bool {
	if h := op.host(); h != nil {
		return h.nonblocking()
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.fdflags&wasiFdflagNonblock != 0
}

// acceptInterruptibly accepts from l, the listener of op, for a blocking
// socket: a signal posted to the guest while the accept waits — for its turn
// at the listener, or for a connection — ends it, and interrupted is then
// true.
func (w *WasiStubs) acceptInterruptibly(op *wasiOpen, l deadlineListener) (conn net.Conn, err error, interrupted bool) {
	if conn, err, interrupted = w.acceptWaiting(op, l); !interrupted {
		return conn, err, false
	}
	// A signal interrupts an accept that has to wait. A connection that is
	// there is accepted all the same, as accept(2) hands it to a process
	// with a signal pending — whether the signal was posted before the
	// call or while it was on its way.
	if op.probeAccept(l, time.Now().Add(pollProbeGrace), nil) {
		if conn, err, taken := op.takeAccepted(); taken {
			w.keepInterrupt()
			return conn, err, false
		}
	}
	return nil, nil, true
}

// acceptWaiting is acceptInterruptibly without the second look of an
// interrupted accept.
func (w *WasiStubs) acceptWaiting(op *wasiOpen, l deadlineListener) (conn net.Conn, err error, interrupted bool) {
	if !w.awaitInputTurn(op) {
		return nil, nil, true
	}
	defer op.passInputTurn()
	// Whoever had the turn before may have accepted a connection that
	// nobody has taken.
	if conn, err, taken := op.takeAccepted(); taken {
		return conn, err, false
	}
	if !w.beginBlocking(func() { _ = l.SetDeadline(time.Now()) }) {
		return nil, nil, true
	}
	for {
		conn, err = l.Accept()
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if w.interruptDue() {
			interrupted = true
			break
		}
		// Only the holder of the turn sets a deadline, so this one is not
		// the listener's any more: it was left behind.
		_ = l.SetDeadline(time.Time{})
	}
	if w.endBlocking() {
		// wake has set a deadline, which must not outlive this accept.
		_ = l.SetDeadline(time.Time{})
	}
	if conn != nil {
		interrupted = false
	}
	return conn, err, interrupted
}

// ----- sockets of every family ------------------------------------------------
//
// The imports of this section name a socket address by a record in the
// guest's memory, whatever its family: IPv4, IPv6 or Unix-domain. The
// record is wasiSockAddrSize bytes, little-endian:
//
//	offset  0  u32       family (wasiSockFamily*; 0 where there is no address)
//	offset  4  u32       port, in host byte order (IP families)
//	offset  8  [16]byte  address: 4 bytes for IPv4, 16 for IPv6
//	offset 24  u32       scope id (IPv6)
//	offset 28  u32       length of the name (Unix)
//	offset 32  [108]byte name, as the guest gave it (Unix)
//
// The name of a Unix-domain socket is a path of the guest's, relative to
// its working directory, which the host does not know: where an import
// takes an address that may be one, it also takes the path as the
// filesystem imports do, relative to the preopened root.
const (
	wasiSockAddrSize    = 140
	wasiSockAddrNameMax = 108
)

// wasiSockAddr is a socket address read from the guest.
type wasiSockAddr struct {
	family int32
	ip     net.IP // 4 bytes for IPv4, 16 for IPv6
	port   int
	scope  uint32
	name   string // of a Unix-domain socket, as the guest gave it
}

// readSockAddr reads the address record at ptr. It reports an errno:
// EFAULT, EAFNOSUPPORT for a family the host has no sockets of, EINVAL for
// a record that is not well formed.
func (w *WasiStubs) readSockAddr(m *Module, ptr uint64) (wasiSockAddr, int32) {
	rec := w.memBytes(m, ptr, wasiSockAddrSize)
	if rec == nil {
		return wasiSockAddr{}, _wasiEFAULT
	}
	a := wasiSockAddr{
		family: int32(binary.LittleEndian.Uint32(rec[0:])),
		port:   int(uint16(binary.LittleEndian.Uint32(rec[4:]))),
		scope:  binary.LittleEndian.Uint32(rec[24:]),
	}
	switch a.family {
	case wasiSockFamilyIPv4:
		a.ip = append(net.IP(nil), rec[8:12]...)
	case wasiSockFamilyIPv6:
		a.ip = append(net.IP(nil), rec[8:24]...)
	case wasiSockFamilyUnix:
		n := binary.LittleEndian.Uint32(rec[28:])
		if n > wasiSockAddrNameMax {
			return a, _wasiEINVAL
		}
		a.name = string(rec[32 : 32+n])
	default:
		return a, _wasiEAFNOSUPPORT
	}
	return a, _wasiESUCCESS
}

// zone returns the zone of an IPv6 address as package net names it: the
// name of the interface whose index the scope id is.
func (a wasiSockAddr) zone() string {
	if a.scope == 0 || a.family != wasiSockFamilyIPv6 {
		return ""
	}
	if ifc, err := net.InterfaceByIndex(int(a.scope)); err == nil {
		return ifc.Name
	}
	return strconv.FormatUint(uint64(a.scope), 10)
}

// scopeOfZone is the inverse of wasiSockAddr.zone.
func scopeOfZone(zone string) uint32 {
	if zone == "" {
		return 0
	}
	if ifc, err := net.InterfaceByName(zone); err == nil {
		return uint32(ifc.Index)
	}
	n, err := strconv.ParseUint(zone, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// ipText renders the IP address, with its zone: what the dial policy is
// asked about, and what resolved host names are remembered under.
func (a wasiSockAddr) ipText() string {
	if zone := a.zone(); zone != "" {
		return a.ip.String() + "%" + zone
	}
	return a.ip.String()
}

// hostPort renders an IP address and port for package net.
func (a wasiSockAddr) hostPort() string {
	return net.JoinHostPort(a.ipText(), strconv.Itoa(a.port))
}

// writeSockAddr writes addr at ptr as an address record. family is the
// family of the socket the address is one of: an IPv6 socket names an IPv4
// peer by its IPv4-mapped address, and a socket without an address has the
// unspecified one of its family. unixName is the name of a Unix-domain
// address as the guest knows it. Returns 0 or a negative errno.
func (w *WasiStubs) writeSockAddr(m *Module, ptr uint64, family int32, addr net.Addr, unixName string) int32 {
	rec := w.memBytes(m, ptr, wasiSockAddrSize)
	if rec == nil {
		return -_wasiEFAULT
	}
	for i := range rec {
		rec[i] = 0
	}
	var ip net.IP
	var port int
	var zone string
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a != nil {
			ip, port, zone = a.IP, a.Port, a.Zone
		}
	case *net.UDPAddr:
		if a != nil {
			ip, port, zone = a.IP, a.Port, a.Zone
		}
	case *net.UnixAddr:
		family = wasiSockFamilyUnix
	case nil:
	default:
		return -_wasiENOTSUP
	}
	if family == wasiSockFamilyUnix {
		if len(unixName) > wasiSockAddrNameMax {
			return -_wasiENAMETOOLONG
		}
		binary.LittleEndian.PutUint32(rec[0:], wasiSockFamilyUnix)
		binary.LittleEndian.PutUint32(rec[28:], uint32(len(unixName)))
		copy(rec[32:], unixName)
		return _wasiESUCCESS
	}
	v4 := ip.To4()
	if family == 0 {
		family = wasiSockFamilyIPv4
		if ip != nil && v4 == nil {
			family = wasiSockFamilyIPv6
		}
	}
	binary.LittleEndian.PutUint32(rec[0:], uint32(family))
	binary.LittleEndian.PutUint32(rec[4:], uint32(port))
	if family == wasiSockFamilyIPv6 {
		if ip != nil {
			copy(rec[8:24], ip.To16())
		}
		binary.LittleEndian.PutUint32(rec[24:], scopeOfZone(zone))
	} else if v4 != nil {
		copy(rec[8:12], v4)
	}
	return _wasiESUCCESS
}

// writeSockAddrRecord writes a into rec as an address record.
func writeSockAddrRecord(rec []byte, a wasiSockAddr) {
	for i := range rec {
		rec[i] = 0
	}
	binary.LittleEndian.PutUint32(rec[0:], uint32(a.family))
	switch a.family {
	case wasiSockFamilyUnix:
		binary.LittleEndian.PutUint32(rec[28:], uint32(len(a.name)))
		copy(rec[32:32+wasiSockAddrNameMax], a.name)
	case wasiSockFamilyIPv6:
		binary.LittleEndian.PutUint32(rec[4:], uint32(a.port))
		copy(rec[8:24], a.ip.To16())
		binary.LittleEndian.PutUint32(rec[24:], a.scope)
	case wasiSockFamilyIPv4:
		binary.LittleEndian.PutUint32(rec[4:], uint32(a.port))
		copy(rec[8:12], a.ip.To4())
	}
}

// Sock_addr_to_host is a NON-STANDARD host import (name
// "sock_addr_to_host"): the address of the record at recordPtr as the
// host's C library has it in a struct sockaddr — the bytes a native library
// of the host's makes and takes, and so the packed addresses a guest that
// is the host process shows its program. The bytes are written at outPtr,
// which has room for outCap, and their number at outLenPtr (u32). Returns 0
// or a negative errno: EAFNOSUPPORT for a record of no family the host has,
// ERANGE where the room is too small.
func (w *WasiStubs) Sock_addr_to_host(m *Module, recordPtr, outPtr, outCap, outLenPtr int32) int32 {
	return w.sockAddrToHost(m, zext(recordPtr), zext(outPtr), outCap, zext(outLenPtr))
}

// Sock_addr_to_host64 is Sock_addr_to_host for a memory64 guest.
func (w *WasiStubs) Sock_addr_to_host64(m *Module, recordPtr, outPtr int64, outCap int32, outLenPtr int64) int32 {
	return w.sockAddrToHost(m, uint64(recordPtr), uint64(outPtr), outCap, uint64(outLenPtr))
}

// sockAddrToHost is the body of Sock_addr_to_host and Sock_addr_to_host64.
func (w *WasiStubs) sockAddrToHost(m *Module, recordPtr, outPtr uint64, outCap int32, outLenPtr uint64) int32 {
	a, errno := w.readSockAddr(m, recordPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	raw := hostSockaddrBytes(a)
	if raw == nil {
		return -_wasiEAFNOSUPPORT
	}
	if outCap < 0 || len(raw) > int(outCap) {
		return -_wasiERANGE
	}
	out := w.memBytes(m, outPtr, uint64(len(raw)))
	lenOut := w.memBytes(m, outLenPtr, 4)
	if out == nil || lenOut == nil {
		return -_wasiEFAULT
	}
	copy(out, raw)
	binary.LittleEndian.PutUint32(lenOut, uint32(len(raw)))
	return _wasiESUCCESS
}

// Sock_addr_from_host is a NON-STANDARD host import (name
// "sock_addr_from_host"), the reverse of Sock_addr_to_host: the struct
// sockaddr of the host's C library in the inLen bytes at inPtr, as an
// address record at recordPtr. Returns 0 or a negative errno: EAFNOSUPPORT
// for a family the records have no form for (the bytes are no address of
// the guest's then), EINVAL for bytes too few for their family.
func (w *WasiStubs) Sock_addr_from_host(m *Module, inPtr, inLen, recordPtr int32) int32 {
	return w.sockAddrFromHost(m, zext(inPtr), inLen, zext(recordPtr))
}

// Sock_addr_from_host64 is Sock_addr_from_host for a memory64 guest.
func (w *WasiStubs) Sock_addr_from_host64(m *Module, inPtr int64, inLen int32, recordPtr int64) int32 {
	return w.sockAddrFromHost(m, uint64(inPtr), inLen, uint64(recordPtr))
}

// sockAddrFromHost is the body of Sock_addr_from_host and
// Sock_addr_from_host64.
func (w *WasiStubs) sockAddrFromHost(m *Module, inPtr uint64, inLen int32, recordPtr uint64) int32 {
	in := w.memBytes(m, inPtr, zext(inLen))
	rec := w.memBytes(m, recordPtr, wasiSockAddrSize)
	if in == nil || rec == nil || inLen < 0 {
		return -_wasiEFAULT
	}
	a, errno := sockAddrOfHostBytes(in)
	if errno != _wasiESUCCESS {
		return -errno
	}
	writeSockAddrRecord(rec, a)
	return _wasiESUCCESS
}

// socketFamily returns the address family of a socket entry: the one it was
// made with, or, for a connection or a listener the embedder handed in, the
// family of its address.
func (op *wasiOpen) socketFamily() int32 {
	if op.family != 0 {
		return op.family
	}
	var addr net.Addr
	if conn := op.netConn(); conn != nil {
		addr = conn.LocalAddr()
	} else if l, _ := op.netListener(); l != nil {
		addr = l.Addr()
	}
	switch a := addr.(type) {
	case *net.UnixAddr:
		return wasiSockFamilyUnix
	case *net.TCPAddr:
		if a != nil && a.IP != nil && a.IP.To4() == nil {
			return wasiSockFamilyIPv6
		}
	case *net.UDPAddr:
		if a != nil && a.IP != nil && a.IP.To4() == nil {
			return wasiSockFamilyIPv6
		}
	}
	return wasiSockFamilyIPv4
}

// option returns the value the guest set a socket option to (Sock_setopt),
// or 0.
func (op *wasiOpen) option(option int32) int32 {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.sock == nil {
		return 0
	}
	return op.sock.options[option]
}

// socketControl returns what has to be done to a host socket made for op
// between its creation and its binding or connecting: an IPv6 socket takes
// IPv4 traffic as well or not as the guest's IPV6_V6ONLY says, where the
// host's own choice would be the network API's.
func (op *wasiOpen) socketControl() func(network, address string, c syscall.RawConn) error {
	if op.family != wasiSockFamilyIPv6 {
		return nil
	}
	only := op.option(wasiSockOptV6Only) != 0
	return func(_, _ string, c syscall.RawConn) error {
		var failed error
		if err := c.Control(func(fd uintptr) { failed = setIPv6Only(fd, only) }); err != nil {
			return err
		}
		return failed
	}
}

// unixHostPath returns where the Unix-domain socket the guest names lives
// for the host: name is the socket's name as the guest gave it and path the
// same as a path relative to the preopened root. An abstract name (Linux:
// one that starts with a NUL) is no file, and is the host's as it is. The
// filesystem policy is asked about a path, for writing — binding creates
// the file, and connecting or sending to it takes write access. It reports
// an errno: ENOTSUP when the filesystem of the instance is not one sockets
// can live in.
func (w *WasiStubs) unixHostPath(name, path string) (string, int32) {
	if name == "" {
		return "", _wasiEINVAL
	}
	if name[0] == 0 {
		return "@" + name[1:], _wasiESUCCESS
	}
	if !w.checkFS(path, true) {
		return "", _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	located, can := fsys.(interface {
		HostPath(name string) (string, error)
	})
	if !can {
		return "", _wasiENOTSUP
	}
	host, err := located.HostPath(path)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return "", _wasiENOTSUP
		}
		return "", mapOSError(err)
	}
	return host, _wasiESUCCESS
}

// unixGuestName returns the name the guest knows a Unix-domain address of
// the host by: the path under the preopened root for a socket file that is
// there, and the address itself otherwise. An address without a name has
// none.
func (w *WasiStubs) unixGuestName(addr net.Addr) string {
	a, _ := addr.(*net.UnixAddr)
	// The host's network API writes the leading NUL of an abstract name
	// as '@', and so a socket without a name as "@" alone on Linux.
	if a == nil || a.Name == "" || a.Name == "@" {
		return ""
	}
	if a.Name[0] == '@' {
		return "\x00" + a.Name[1:]
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	if named, can := fsys.(interface {
		HostName(path string) (string, bool)
	}); can {
		if name, known := named.HostName(a.Name); known {
			return "/" + name
		}
	}
	return a.Name
}

// HostPath returns the path in the host's filesystem of the file known as
// name: where a Unix-domain socket of that name is bound and found.
func (o osFS) HostPath(name string) (string, error) { return o.join(name), nil }

// HostName returns the name of the file at a path of the host's
// filesystem, and whether the path is under the root.
func (o osFS) HostName(path string) (string, bool) {
	if o.root == "" || o.root == "/" {
		return strings.TrimPrefix(path, "/"), filepath.IsAbs(path)
	}
	rel, err := filepath.Rel(o.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// readSockPath reads the path that accompanies an address record (see the
// head of this section); ok is false when it is not readable.
func (w *WasiStubs) readSockPath(m *Module, ptr uint64, n int32) (path string, ok bool) {
	if n == 0 {
		return "", true
	}
	b := w.memBytes(m, ptr, zext(n))
	if b == nil {
		return "", false
	}
	return string(b), true
}

// socketEntry returns the socket entry behind fd, or the errno of a
// descriptor that is not open (EBADF) or not a socket (ENOTSOCK).
func (w *WasiStubs) socketEntry(fd int32) (*wasiOpen, int32) {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return nil, _wasiEBADF
	}
	if !op.isSocket && op.netConn() == nil {
		if l, _ := op.netListener(); l == nil {
			return nil, _wasiENOTSOCK
		}
	}
	return op, _wasiESUCCESS
}

// Sock_open is a NON-STANDARD host import (name "sock_open") backing
// socket(): it makes a socket of the family (wasiSockFamily*) and type
// (wasiSockType*) and returns its fd, or a negative errno: EAFNOSUPPORT,
// EPROTONOSUPPORT.
func (w *WasiStubs) Sock_open(m *Module, family, typ int32) int32 {
	switch family {
	case wasiSockFamilyIPv4, wasiSockFamilyIPv6, wasiSockFamilyUnix:
	default:
		return -_wasiEAFNOSUPPORT
	}
	if typ != wasiSockTypeStream && typ != wasiSockTypeDgram {
		return -_wasiEPROTONOSUPPORT
	}
	return w.openSocket(family, typ)
}

// Sock_open64 is Sock_open for a memory64 guest.
func (w *WasiStubs) Sock_open64(m *Module, family, typ int32) int32 {
	return w.Sock_open(m, family, typ)
}

// listenIP opens the listening socket behind a bound guest socket of an IP
// family, after asking the network policy: listening is the "listen"
// operation of the hook installed with SetNetAccessHook.
func (w *WasiStubs) listenIP(op *wasiOpen, a wasiSockAddr) (net.Listener, int32) {
	if !w.checkNet("listen") {
		return nil, _wasiEACCES
	}
	network := "tcp4"
	if op.family == wasiSockFamilyIPv6 {
		network = "tcp6"
	}
	lc := net.ListenConfig{Control: op.socketControl()}
	l, err := lc.Listen(context.Background(), network, a.hostPort())
	if err != nil {
		return nil, mapNetError(err)
	}
	return l, _wasiESUCCESS
}

// unspecifiedAddr is the address a socket of op's family listens on or
// sends from when the guest named none: every address, a port the host
// picks.
func (op *wasiOpen) unspecifiedAddr() wasiSockAddr {
	if op.family == wasiSockFamilyIPv6 {
		return wasiSockAddr{family: wasiSockFamilyIPv6, ip: net.IPv6unspecified}
	}
	return wasiSockAddr{family: wasiSockFamilyIPv4, ip: net.IPv4zero.To4()}
}

// bindSocket gives the socket op the local address a; path is the address
// as a path under the preopened root when it is a Unix-domain one. The
// host's network API binds and listens in one step, so a stream socket's
// address takes connections from here on; the guest's accept still needs
// its listen (Sock_listen). A Unix-domain socket's file stays when the
// socket is closed, as bind(2) leaves it. It reports an errno.
func (w *WasiStubs) bindSocket(op *wasiOpen, a wasiSockAddr, path string) int32 {
	if a.family != op.family {
		return _wasiEAFNOSUPPORT
	}
	if h := op.host(); h != nil {
		// Having a local address is being a server on the host's network.
		if !w.checkNet("listen") {
			return _wasiEACCES
		}
		host := ""
		if a.family == wasiSockFamilyUnix {
			var errno int32
			if host, errno = w.unixHostPath(a.name, path); errno != _wasiESUCCESS {
				return errno
			}
		}
		return w.bindHost(op, h, a, host)
	}
	if l, _ := op.netListener(); l != nil || op.netConn() != nil {
		return _wasiEINVAL
	}
	if a.family != wasiSockFamilyUnix {
		if op.dgram {
			// Receiving datagrams at a local address is being a server on
			// the host's network, like listening.
			if !w.checkNet("listen") {
				return _wasiEACCES
			}
			return op.attachDatagramConn(&net.UDPAddr{IP: a.ip, Port: a.port, Zone: a.zone()})
		}
		l, errno := w.listenIP(op, a)
		if errno != _wasiESUCCESS {
			return errno
		}
		return op.attachListener(l, false)
	}
	if !w.checkNet("listen") {
		return _wasiEACCES
	}
	host, errno := w.unixHostPath(a.name, path)
	if errno != _wasiESUCCESS {
		return errno
	}
	if op.dgram {
		if errno := op.attachDatagramConn(&net.UnixAddr{Name: host, Net: "unixgram"}); errno != _wasiESUCCESS {
			return errno
		}
	} else {
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: host, Net: "unix"})
		if err != nil {
			return mapNetError(err)
		}
		l.SetUnlinkOnClose(false)
		if errno := op.attachListener(l, false); errno != _wasiESUCCESS {
			return errno
		}
	}
	op.mu.Lock()
	op.socketLocked().unixLocal = a.name
	op.mu.Unlock()
	return _wasiESUCCESS
}

// Sock_bind_addr is a NON-STANDARD host import (name "sock_bind_addr")
// backing bind() for a socket of any family: the socket gets the local
// address in the record at addrPtr, with the path at (pathPtr, pathLen) for
// a Unix-domain one (see the head of this section). Subject to the network
// policy's "listen" operation. Returns 0 or a negative errno: EADDRINUSE,
// EADDRNOTAVAIL, EACCES, EAFNOSUPPORT for an address of another family than
// the socket's, EINVAL for a socket that is already bound or connected.
func (w *WasiStubs) Sock_bind_addr(m *Module, fd, addrPtr, pathPtr, pathLen int32) int32 {
	return w.sockBindAddr(m, fd, zext(addrPtr), zext(pathPtr), pathLen)
}

// Sock_bind_addr64 is Sock_bind_addr for a memory64 guest.
func (w *WasiStubs) Sock_bind_addr64(m *Module, fd int32, addrPtr, pathPtr int64, pathLen int32) int32 {
	return w.sockBindAddr(m, fd, uint64(addrPtr), uint64(pathPtr), pathLen)
}

// sockBindAddr is the body of Sock_bind_addr and Sock_bind_addr64.
func (w *WasiStubs) sockBindAddr(m *Module, fd int32, addrPtr, pathPtr uint64, pathLen int32) int32 {
	a, errno := w.readSockAddr(m, addrPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	path, ok := w.readSockPath(m, pathPtr, pathLen)
	if !ok {
		return -_wasiEFAULT
	}
	op, errno := w.socketEntry(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	return -w.bindSocket(op, a, path)
}

// wasiDial is a connection attempt of a stream socket that has not ended
// yet. done is closed when it has; errno is then its outcome.
type wasiDial struct {
	done   chan struct{}
	cancel context.CancelFunc
	errno  int32
}

// dialing returns the connection attempt of op that is under way, or nil.
func (op *wasiOpen) dialing() *wasiDial {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.sock == nil {
		return nil
	}
	return op.sock.dial
}

// takeFailure returns the errno of a connection attempt that failed after
// the call that started it had returned, once: what SO_ERROR reads.
func (op *wasiOpen) takeFailure() int32 {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.sock == nil {
		return 0
	}
	errno := op.sock.failure
	op.sock.failure = 0
	return errno
}

// awaitDial waits until the connection attempt d has ended, no longer than
// until (the zero time is no limit) and not after stop is closed, and
// reports whether it has.
func awaitDial(d *wasiDial, until time.Time, stop <-chan struct{}) bool {
	var expired <-chan time.Time
	if !until.IsZero() {
		timer := time.NewTimer(time.Until(until))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-d.done:
		return true
	case <-expired:
	case <-stop:
	}
	select {
	case <-d.done:
		return true
	default:
		return false
	}
}

// connectStream connects the stream socket op to address on network, from
// the local address the socket is bound to when it is (local; unlink is
// then the socket file to remove first, for a Unix-domain socket). The
// connection is made in the background. A blocking socket waits for it: a
// signal posted to the guest ends the wait with EINTR and the socket's send
// timeout with EINPROGRESS, and the attempt goes on either way. A
// non-blocking socket reports EINPROGRESS unless the attempt ends at once;
// the socket polls writable when it has ended, and SO_ERROR then tells how.
// While an attempt is under way another connect is EALREADY. It reports an
// errno.
func (w *WasiStubs) connectStream(op *wasiOpen, network, address string, local net.Addr, unlink string) int32 {
	nonblocking := op.nonblocking()
	posted := make(chan struct{})
	if !nonblocking && !w.beginBlocking(func() { close(posted) }) {
		return _wasiEINTR
	}
	end := func(errno int32) int32 {
		if !nonblocking && w.endBlocking() && errno == _wasiEINPROGRESS {
			return _wasiEINTR
		}
		return errno
	}
	op.mu.Lock()
	s := op.socketLocked()
	switch {
	case s.dial != nil:
		op.mu.Unlock()
		return end(_wasiEALREADY)
	case op.conn != nil:
		op.mu.Unlock()
		return end(_wasiEISCONN)
	case s.failure != 0:
		// An attempt failed since the last connect: this one reports it.
		errno := s.failure
		s.failure = 0
		op.mu.Unlock()
		return end(errno)
	case s.listening:
		op.mu.Unlock()
		return end(_wasiEINVAL)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &wasiDial{done: make(chan struct{}), cancel: cancel}
	s.dial = d
	// A socket that was bound and now connects: the connection leaves from
	// the bound address, which the listener holding it gives up.
	bound := op.listener
	op.listener = nil
	op.mu.Unlock()

	go func() {
		defer cancel()
		var conn net.Conn
		var err error
		if bound != nil {
			err = bound.Close()
			if err == nil && unlink != "" {
				err = os.Remove(unlink)
			}
		}
		if err == nil {
			dialer := net.Dialer{LocalAddr: local, Control: op.socketControl()}
			conn, err = dialer.DialContext(ctx, network, address)
		}
		op.mu.Lock()
		s := op.socketLocked()
		s.dial = nil
		switch {
		case err != nil:
			// A failure the host cannot name is a connection nobody took.
			if d.errno = mapNetError(err); d.errno == _wasiEIO {
				d.errno = _wasiECONNREFUSED
			}
			s.failure = d.errno
		case ctx.Err() != nil:
			// The socket was closed meanwhile.
			d.errno = _wasiEBADF
		default:
			op.conn = conn
			conn = nil
		}
		op.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		close(d.done)
	}()

	var until time.Time
	if nonblocking {
		// Long enough for a connection that needs no waiting for: to a
		// socket of this machine.
		until = time.Now().Add(pollProbeGrace)
	} else if _, limit := op.timeouts(); limit > 0 {
		until = time.Now().Add(limit)
	}
	if !awaitDial(d, until, posted) {
		return end(_wasiEINPROGRESS)
	}
	if d.errno != _wasiESUCCESS {
		// reported here, not left for SO_ERROR
		op.takeFailure()
	}
	return end(d.errno)
}

// connectSocket connects the socket op to the address a; path is the
// address as a path under the preopened root when it is a Unix-domain one.
// The destination is subject to the dial policy, which is asked with the
// network "tcp", "udp", "unix" or "unixgram" — for a Unix-domain socket
// with the socket's path as the address and port 0. It reports an errno.
func (w *WasiStubs) connectSocket(op *wasiOpen, a wasiSockAddr, path string) int32 {
	if a.family != op.family {
		return _wasiEAFNOSUPPORT
	}
	w.mu.Lock()
	hook := w.dialHook
	w.mu.Unlock()
	if a.family == wasiSockFamilyUnix {
		network := "unix"
		if op.dgram {
			network = "unixgram"
		}
		if hook != nil && !hook(network, "", "/"+path, 0) {
			return _wasiEACCES
		}
		host, errno := w.unixHostPath(a.name, path)
		if errno != _wasiESUCCESS {
			return errno
		}
		peer := &net.UnixAddr{Name: host, Net: network}
		if h := op.host(); h != nil {
			errno = w.connectHost(op, h, a.hostSockaddr(host))
		} else if op.dgram {
			errno = w.connectDatagram(op, peer)
		} else {
			var local net.Addr
			var unlink string
			if l, _ := op.netListener(); l != nil {
				local = l.Addr()
				if at, _ := local.(*net.UnixAddr); at != nil && at.Name != "" && at.Name[0] != '@' {
					unlink = at.Name
				}
			}
			errno = w.connectStream(op, network, host, local, unlink)
		}
		if errno == _wasiESUCCESS || errno == _wasiEINPROGRESS || errno == _wasiEINTR {
			op.mu.Lock()
			op.socketLocked().unixPeer = a.name
			op.mu.Unlock()
		}
		return errno
	}
	ip := a.ipText()
	w.mu.Lock()
	host := w.resolvedHosts[ip] // "" for a literal-IP dial with no preceding lookup
	w.mu.Unlock()
	if op.dgram {
		if hook != nil && !hook("udp", host, ip, a.port) {
			return _wasiEACCES
		}
		if h := op.host(); h != nil {
			return w.connectHost(op, h, a.hostSockaddr(""))
		}
		return w.connectDatagram(op, &net.UDPAddr{IP: a.ip, Port: a.port, Zone: a.zone()})
	}
	if hook != nil && !hook("tcp", host, ip, a.port) {
		return _wasiEACCES
	}
	if h := op.host(); h != nil {
		return w.connectHost(op, h, a.hostSockaddr(""))
	}
	network := "tcp4"
	if a.family == wasiSockFamilyIPv6 && a.ip.To4() == nil {
		network = "tcp6"
	}
	var local net.Addr
	if l, _ := op.netListener(); l != nil {
		local = l.Addr()
	}
	return w.connectStream(op, network, a.hostPort(), local, "")
}

// Sock_connect_addr is a NON-STANDARD host import (name
// "sock_connect_addr") backing connect() for a socket of any family: the
// address is the record at addrPtr, with the path at (pathPtr, pathLen)
// for a Unix-domain one (see the head of this section). See connectSocket
// and connectStream for the policy and for what a blocking and a
// non-blocking socket do. Returns 0 or a negative errno.
func (w *WasiStubs) Sock_connect_addr(m *Module, fd, addrPtr, pathPtr, pathLen int32) int32 {
	return w.sockConnectAddr(m, fd, zext(addrPtr), zext(pathPtr), pathLen)
}

// Sock_connect_addr64 is Sock_connect_addr for a memory64 guest.
func (w *WasiStubs) Sock_connect_addr64(m *Module, fd int32, addrPtr, pathPtr int64, pathLen int32) int32 {
	return w.sockConnectAddr(m, fd, uint64(addrPtr), uint64(pathPtr), pathLen)
}

// sockConnectAddr is the body of Sock_connect_addr and Sock_connect_addr64.
func (w *WasiStubs) sockConnectAddr(m *Module, fd int32, addrPtr, pathPtr uint64, pathLen int32) int32 {
	a, errno := w.readSockAddr(m, addrPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	path, ok := w.readSockPath(m, pathPtr, pathLen)
	if !ok {
		return -_wasiEFAULT
	}
	op, errno := w.socketEntry(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if !op.isSocket {
		return -_wasiEISCONN
	}
	return -w.connectSocket(op, a, path)
}

// Sock_name is a NON-STANDARD host import (name "sock_name") backing
// getsockname() (peer 0) and getpeername() (peer non-zero) for a socket of
// any family: it writes the name as an address record at addrPtr. The
// local name of a socket that has none yet is the unspecified address of
// its family, or a Unix-domain address without a name. Returns 0, or a
// negative errno: ENOTCONN for the peer of a socket without a connection.
func (w *WasiStubs) Sock_name(m *Module, fd, peer, addrPtr int32) int32 {
	return w.sockName(m, fd, peer, zext(addrPtr))
}

// Sock_name64 is Sock_name for a memory64 guest.
func (w *WasiStubs) Sock_name64(m *Module, fd, peer int32, addrPtr int64) int32 {
	return w.sockName(m, fd, peer, uint64(addrPtr))
}

// sockName is the body of Sock_name and Sock_name64.
func (w *WasiStubs) sockName(m *Module, fd, peer int32, addrPtr uint64) int32 {
	op, errno := w.socketEntry(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	family := op.socketFamily()
	op.mu.Lock()
	var local, remote string
	if op.sock != nil {
		local, remote = op.sock.unixLocal, op.sock.unixPeer
	}
	op.mu.Unlock()
	if h := op.host(); h != nil {
		addr, errno := op.hostSocketName(h, peer != 0)
		if errno != _wasiESUCCESS {
			return -errno
		}
		name := local
		if peer != 0 {
			name = remote
		}
		if family == wasiSockFamilyUnix && name == "" {
			name = w.unixGuestName(addr)
		}
		return w.writeSockAddr(m, addrPtr, family, addr, name)
	}
	conn := op.netConn()
	if peer != 0 {
		if conn == nil || conn.RemoteAddr() == nil {
			// no connection, or a datagram socket that is not connected
			return -_wasiENOTCONN
		}
		if errno := op.peerLost(conn); errno != _wasiESUCCESS {
			return -errno
		}
		addr := conn.RemoteAddr()
		if family == wasiSockFamilyUnix && remote == "" {
			remote = w.unixGuestName(addr)
		}
		return w.writeSockAddr(m, addrPtr, family, addr, remote)
	}
	var addr net.Addr
	if conn != nil {
		addr = conn.LocalAddr()
	} else if l, _ := op.netListener(); l != nil {
		addr = l.Addr()
	}
	if family == wasiSockFamilyUnix && local == "" {
		local = w.unixGuestName(addr)
	}
	return w.writeSockAddr(m, addrPtr, family, addr, local)
}

// Sock_sendto_addr is a NON-STANDARD host import (name "sock_sendto_addr")
// backing sendto() for a socket of any family: Sock_sendto with the
// destination as an address record at addrPtr (0 for none), and its path
// at (pathPtr, pathLen) for a Unix-domain one. A datagram to an address is
// subject to the dial policy, as connecting to it is. Returns 0 or a
// negative errno.
func (w *WasiStubs) Sock_sendto_addr(m *Module, fd, bufPtr, bufLen, flags, addrPtr, pathPtr, pathLen, sentPtr int32) int32 {
	return w.sockSendtoAddr(m, fd, zext(bufPtr), bufLen, flags, zext(addrPtr), zext(pathPtr), pathLen, zext(sentPtr))
}

// Sock_sendto_addr64 is Sock_sendto_addr for a memory64 guest.
func (w *WasiStubs) Sock_sendto_addr64(m *Module, fd int32, bufPtr int64, bufLen, flags int32, addrPtr, pathPtr int64, pathLen int32, sentPtr int64) int32 {
	return w.sockSendtoAddr(m, fd, uint64(bufPtr), bufLen, flags, uint64(addrPtr), uint64(pathPtr), pathLen, uint64(sentPtr))
}

// sockSendtoAddr is the body of Sock_sendto_addr and Sock_sendto_addr64.
func (w *WasiStubs) sockSendtoAddr(m *Module, fd int32, bufPtr uint64, bufLen, flags int32, addrPtr, pathPtr uint64, pathLen int32, sentPtr uint64) int32 {
	if !w.checkNet("send") {
		return -_wasiEACCES
	}
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, sentPtr, 4)
	if (buf == nil && bufLen != 0) || out == nil {
		return -_wasiEFAULT
	}
	op, errno := w.socketEntry(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	h := op.host()
	if !op.dgram || addrPtr == 0 {
		if h != nil {
			n, errno := w.sendHost(op, h, [][]byte{buf}, nil, flags)
			binary.LittleEndian.PutUint32(out, uint32(n))
			return -errno
		}
		conn := op.netConn()
		if conn == nil || (op.dgram && conn.RemoteAddr() == nil) {
			return -_wasiENOTCONN
		}
		n, errno := w.sendFd(op, conn, [][]byte{buf}, flags)
		binary.LittleEndian.PutUint32(out, uint32(n))
		return -errno
	}
	a, errno := w.readSockAddr(m, addrPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	path, ok := w.readSockPath(m, pathPtr, pathLen)
	if !ok {
		return -_wasiEFAULT
	}
	if a.family != op.family {
		return -_wasiEAFNOSUPPORT
	}
	var conn datagramSocket
	if h == nil {
		if conn, errno = op.datagramConn(); errno != _wasiESUCCESS {
			return -errno
		}
	}
	w.mu.Lock()
	hook := w.dialHook
	w.mu.Unlock()
	var to net.Addr
	if a.family == wasiSockFamilyUnix {
		if hook != nil && !hook("unixgram", "", "/"+path, 0) {
			return -_wasiEACCES
		}
		host, errno := w.unixHostPath(a.name, path)
		if errno != _wasiESUCCESS {
			return -errno
		}
		if h != nil {
			n, errno := w.sendHost(op, h, [][]byte{buf}, a.hostSockaddr(host), flags)
			binary.LittleEndian.PutUint32(out, uint32(n))
			return -errno
		}
		to = &net.UnixAddr{Name: host, Net: "unixgram"}
	} else {
		ip := a.ipText()
		w.mu.Lock()
		host := w.resolvedHosts[ip]
		w.mu.Unlock()
		if hook != nil && !hook("udp", host, ip, a.port) {
			return -_wasiEACCES
		}
		if h != nil {
			n, errno := w.sendHost(op, h, [][]byte{buf}, a.hostSockaddr(""), flags)
			binary.LittleEndian.PutUint32(out, uint32(n))
			return -errno
		}
		to = &net.UDPAddr{IP: a.ip, Port: a.port, Zone: a.zone()}
	}
	n, err := sendDatagram(op, conn, buf, to)
	if err != nil {
		return -w.writeFailure(err, flags)
	}
	binary.LittleEndian.PutUint32(out, uint32(n))
	return _wasiESUCCESS
}

// sendDatagram sends one datagram to an address on the datagram socket
// conn of op. What an address means on a socket that is connected is the
// host's sendto to say, and it is asked: Linux sends the datagram to the
// address, the BSDs refuse it (EISCONN).
func sendDatagram(op *wasiOpen, conn datagramSocket, buf []byte, to net.Addr) (int, error) {
	if conn.RemoteAddr() == nil {
		return conn.WriteTo(buf, to)
	}
	return sendToOnConnected(conn, buf, to, op.family == wasiSockFamilyIPv6)
}

// Sock_recvfrom_addr is a NON-STANDARD host import (name
// "sock_recvfrom_addr") backing recvfrom() for a socket of any family:
// Sock_recvfrom with the sender's name written as an address record at
// addrPtr — of family 0 when there is none to give, as for a datagram from
// a Unix-domain socket that has no name. Returns 0 or a negative errno.
func (w *WasiStubs) Sock_recvfrom_addr(m *Module, fd, bufPtr, bufLen, flags, addrPtr, receivedPtr int32) int32 {
	return w.sockRecvfromAddr(m, fd, zext(bufPtr), bufLen, flags, zext(addrPtr), zext(receivedPtr))
}

// Sock_recvfrom_addr64 is Sock_recvfrom_addr for a memory64 guest.
func (w *WasiStubs) Sock_recvfrom_addr64(m *Module, fd int32, bufPtr int64, bufLen, flags int32, addrPtr, receivedPtr int64) int32 {
	return w.sockRecvfromAddr(m, fd, uint64(bufPtr), bufLen, flags, uint64(addrPtr), uint64(receivedPtr))
}

// sockRecvfromAddr is the body of Sock_recvfrom_addr and Sock_recvfrom_addr64.
func (w *WasiStubs) sockRecvfromAddr(m *Module, fd int32, bufPtr uint64, bufLen, flags int32, addrPtr, receivedPtr uint64) int32 {
	if !w.checkNet("recv") {
		return -_wasiEACCES
	}
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, receivedPtr, 4)
	name := w.memBytes(m, addrPtr, wasiSockAddrSize)
	if (buf == nil && bufLen != 0) || out == nil || name == nil {
		return -_wasiEFAULT
	}
	op, errno := w.socketEntry(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	for i := range name {
		name[i] = 0
	}
	family := op.socketFamily()
	var from net.Addr
	if h := op.host(); h != nil {
		var n uint64
		if n, from, errno = w.receiveFromHost(op, h, buf, flags); errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
	} else if op.dgram {
		conn, errno := op.datagramConn()
		if errno != _wasiESUCCESS {
			return -errno
		}
		var n uint64
		if n, from, errno = w.receiveDatagram(op, conn, [][]byte{buf}, flags); errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
	} else {
		conn := op.netConn()
		if conn == nil {
			return -_wasiENOTCONN
		}
		n, errno := w.receiveStream(op, conn, [][]byte{buf}, flags)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
		from = conn.RemoteAddr()
	}
	var unixName string
	if family == wasiSockFamilyUnix {
		if unixName = w.unixGuestName(from); unixName == "" {
			return _wasiESUCCESS
		}
	} else if from == nil {
		return _wasiESUCCESS
	}
	if rc := w.writeSockAddr(m, addrPtr, family, from, unixName); rc != -_wasiENOTSUP {
		return rc
	}
	return _wasiESUCCESS
}

// Sock_socketpair is a NON-STANDARD host import (name "sock_socketpair")
// backing socketpair(): it makes two connected sockets of the family and
// type and writes their fds (i32 each) at fdsOutPtr. Pairs exist in the
// Unix domain, of stream and of datagram sockets. Returns 0, or a negative
// errno: ENOTSUP (EOPNOTSUPP) for another family, as socketpair(2) has it,
// and on a host without socket pairs; EPROTONOSUPPORT for another type.
func (w *WasiStubs) Sock_socketpair(m *Module, family, typ, fdsOutPtr int32) int32 {
	return w.sockSocketpair(m, family, typ, zext(fdsOutPtr))
}

// Sock_socketpair64 is Sock_socketpair for a memory64 guest.
func (w *WasiStubs) Sock_socketpair64(m *Module, family, typ int32, fdsOutPtr int64) int32 {
	return w.sockSocketpair(m, family, typ, uint64(fdsOutPtr))
}

// sockSocketpair is the body of Sock_socketpair and Sock_socketpair64.
func (w *WasiStubs) sockSocketpair(m *Module, family, typ int32, fdsOutPtr uint64) int32 {
	out := w.memBytes(m, fdsOutPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	switch family {
	case wasiSockFamilyUnix:
	case wasiSockFamilyIPv4, wasiSockFamilyIPv6:
		return -_wasiENOTSUP
	default:
		return -_wasiEAFNOSUPPORT
	}
	if typ != wasiSockTypeStream && typ != wasiSockTypeDgram {
		return -_wasiEPROTONOSUPPORT
	}
	afd, bfd, errno := w.openSocketPair(typ == wasiSockTypeDgram)
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(out[0:], uint32(afd))
	binary.LittleEndian.PutUint32(out[4:], uint32(bfd))
	return _wasiESUCCESS
}

// Sock_resolve is a NON-STANDARD host import (name "sock_resolve") backing
// getaddrinfo(): it resolves the host name at (nodePtr, nodeLen) to its
// addresses of family (wasiSockFamilyIPv4, wasiSockFamilyIPv6, or 0 for
// both) and writes them as address records at outPtr, at most max of them,
// IPv4 addresses first; their number goes to countPtr (u32). An address
// written in numbers is converted, not looked up, and the lookup policy
// (SetResolveHook) is not asked about it. Returns 0, or a negative errno:
// ENOENT when the name has no address of the family, EACCES when the
// policy refuses.
func (w *WasiStubs) Sock_resolve(m *Module, nodePtr, nodeLen, family, outPtr, max, countPtr int32) int32 {
	return w.sockResolve(m, zext(nodePtr), nodeLen, family, zext(outPtr), max, zext(countPtr))
}

// Sock_resolve64 is Sock_resolve for a memory64 guest.
func (w *WasiStubs) Sock_resolve64(m *Module, nodePtr int64, nodeLen, family int32, outPtr int64, max int32, countPtr int64) int32 {
	return w.sockResolve(m, uint64(nodePtr), nodeLen, family, uint64(outPtr), max, uint64(countPtr))
}

// sockResolve is the body of Sock_resolve and Sock_resolve64.
func (w *WasiStubs) sockResolve(m *Module, nodePtr uint64, nodeLen, family int32, outPtr uint64, max int32, countPtr uint64) int32 {
	node := w.memBytes(m, nodePtr, zext(nodeLen))
	count := w.memBytes(m, countPtr, 4)
	if (node == nil && nodeLen != 0) || count == nil || max < 0 {
		return -_wasiEFAULT
	}
	if family != 0 && family != wasiSockFamilyIPv4 && family != wasiSockFamilyIPv6 {
		return -_wasiEAFNOSUPPORT
	}
	host := string(node)
	var found []net.IPAddr
	looked := false
	literal, zone, _ := strings.Cut(host, "%")
	if ip := net.ParseIP(literal); ip != nil {
		found = []net.IPAddr{{IP: ip, Zone: zone}}
	} else {
		looked = true
		w.mu.Lock()
		hook := w.resolveHook
		w.mu.Unlock()
		if hook != nil && !hook(host) {
			return -_wasiEACCES
		}
		var err error
		if found, err = net.DefaultResolver.LookupIPAddr(context.Background(), host); err != nil {
			return -_wasiENOENT
		}
	}
	var n int32
	for _, want := range []int32{wasiSockFamilyIPv4, wasiSockFamilyIPv6} {
		if family != 0 && family != want {
			continue
		}
		for _, addr := range found {
			if (addr.IP.To4() != nil) != (want == wasiSockFamilyIPv4) || n >= max {
				continue
			}
			rc := w.writeSockAddr(m, outPtr+uint64(n)*wasiSockAddrSize, want, &net.TCPAddr{IP: addr.IP, Zone: addr.Zone}, "")
			if rc != _wasiESUCCESS {
				return rc
			}
			if looked {
				text := addr.IP.String()
				if addr.Zone != "" {
					text += "%" + addr.Zone
				}
				w.recordResolvedHost(text, host)
			}
			n++
		}
	}
	if n == 0 {
		return -_wasiENOENT
	}
	binary.LittleEndian.PutUint32(count, uint32(n))
	return _wasiESUCCESS
}

// Sock_reverse_addr is a NON-STANDARD host import (name
// "sock_reverse_addr") backing gethostbyaddr and getnameinfo: Sock_reverse
// for the IP address in the address record at addrPtr, of either family.
func (w *WasiStubs) Sock_reverse_addr(m *Module, addrPtr, bufPtr, bufLen, neededPtr int32) int32 {
	return w.sockReverseAddr(m, zext(addrPtr), zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_reverse_addr64 is Sock_reverse_addr for a memory64 guest.
func (w *WasiStubs) Sock_reverse_addr64(m *Module, addrPtr, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.sockReverseAddr(m, uint64(addrPtr), uint64(bufPtr), bufLen, uint64(neededPtr))
}

// sockReverseAddr is the body of Sock_reverse_addr and Sock_reverse_addr64.
func (w *WasiStubs) sockReverseAddr(m *Module, addrPtr, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	a, errno := w.readSockAddr(m, addrPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if a.family == wasiSockFamilyUnix {
		return -_wasiEAFNOSUPPORT
	}
	return w.reverseLookup(m, a.ip.String(), bufPtr, bufLen, neededPtr)
}

// ─────────────────────────────────────────────────────────────────────
// Codegen plumbing — the rest of the file weaves the live WasiStubs
// implementation into translated output.
// ─────────────────────────────────────────────────────────────────────

//go:embed wasip1_native.go
var wasip1NativeRaw []byte

// emitWasip1Native parses the embedded template, strips package + import
// scaffolding, and returns decls + the set of stdlib imports the
// generated impl needs. The caller is expected to merge those imports
// into the file the decls land in (base/ in multi-package mode, the
// single output file in single-package mode).
//
// In multi-package mode (currentChunk == chunkBase) the field references like
// m.memory get rewritten to m.Memory by capitalizeModuleFieldRefs,
// matching how helpers are handled.
//
// The per-platform companions (wasip1_native_unix.go, _windows.go) are
// not parsed into the main file's decls — they go out as separate
// sidecar files so their //go:build constraints stick.
func (t *translator) emitWasip1Native() ([]ast.Decl, []string, error) {
	if !t.wasmImportsWasi() {
		return nil, nil, nil
	}
	src, err := codegenStripForEmit(wasip1NativeRaw, codegenStripOpts{
		// Only the names listed here survive into emitted output.
		// Anything else (codegen-only helpers, the in-package Module
		// stand-in, the embed vars, this very function, etc.) is
		// stripped.
		keepTypeNames: map[string]bool{
			"WasiExitError":     true,
			"WasiSignalError":   true,
			"HostIDs":           true,
			"Syslogger":         true,
			"wasiZoneMoment":    true,
			"posixZoneRule":     true,
			"posixZone":         true,
			"posixZoneScanner":  true,
			"SyslogMessage":     true,
			"wasiSocket":        true,
			"wasiSockAddr":      true,
			"wasiDial":          true,
			"datagramSocket":    true,
			"wasiService":       true,
			"deadlineListener":  true,
			"wasiSignals":       true,
			"wasiOpen":          true,
			"wasiProc":          true,
			"wasiPIDs":          true,
			"deadlineReader":    true,
			"streamWriter":      true,
			"pollProbe":         true,
			"recordLock":        true,
			"WasiStubs":         true,
			"wasiABI":           true,
			"dotDirEntry":       true,
			"descriptorListing": true,
			"FS":                true,
			"File":              true,
			"osFS":              true,
			"FileLock":          true,
			"fileStat":          true,
			"MemFS":             true,
			"memFile":           true,
			"memNode":           true,
			"memFileInfo":       true,
			"memDirEntry":       true,
		},
		keepFuncNames: map[string]bool{
			"itoa32":                    true,
			"rootDirFD":                 true,
			"DefaultWASI":               true,
			"SetPreopenDir":             true,
			"NewMemFS":                  true,
			"NewOSFS":                   true,
			"fileStatOf":                true,
			"unixFileMode":              true,
			"unixModeBits":              true,
			"unixTypeBits":              true,
			"filetimesNeedCurrent":      true,
			"writeFilestatExt":          true,
			"memSplit":                  true,
			"memSlice":                  true,
			"mapOSError":                true,
			"wasiHostOnlyErrno":         true,
			"mapExecError":              true,
			"encodeWaitStatus":          true,
			"encodeHostWaitStatus":      true,
			"totalBytesPlusNul":         true,
			"zext":                      true,
			"readVec":                   true,
			"readVecFailure":            true,
			"hostDescriptor":            true,
			"streamHungUp":              true,
			"streamFailed":              true,
			"ownDescriptorName":         true,
			"processDirIs":              true,
			"ownDescriptorDirs":         true,
			"ownDescriptorDir":          true,
			"modeAllows":                true,
			"restoreHostSignal":         true,
			"readNow":                   true,
			"appendWasiString":          true,
			"wasiSignalBit":             true,
			"syslogResult":              true,
			"parsePosixZone":            true,
			"locationMoment":            true,
			"mapNetError":               true,
			"socketIPv4":                true,
			"ipv4SockAddr":              true,
			"scopeOfZone":               true,
			"writeSockAddrRecord":       true,
			"awaitDial":                 true,
			"sendDatagram":              true,
			"userRecord":                true,
			"hostDatabaseEntries":       true,
			"pollReady":                 true,
			"probeWritable":             true,
			"takeTurn":                  true,
			"findHostService":           true,
			"writeVec":                  true,
			"Args_get":                  true,
			"Args_sizes_get":            true,
			"Environ_get":               true,
			"Environ_sizes_get":         true,
			"Clock_res_get":             true,
			"Clock_time_get":            true,
			"closeWasiOpen":             true,
			"endWasiOpen":               true,
			"hostStream":                true,
			"release":                   true,
			"openFIFO":                  true,
			"changeHostIDs":             true,
			"SetHostIDs":                true,
			"AdoptInheritedDescriptors": true,
			"Fd_close":                  true,
			"Fd_fdstat_get":             true,
			"Fd_fdstat_set_flags":       true,
			"Fd_fdstat_set_rights":      true,
			"Fd_filestat_get":           true,
			"Fd_filestat_set_size":      true,
			"Fd_filestat_set_times":     true,
			"combine64":                 true,
			"resolveFiletimes":          true,
			"Fd_prestat_get":            true,
			"Fd_prestat_dir_name":       true,
			"Fd_read":                   true,
			"fdSrcLocked":               true,
			"fdDstLocked":               true,
			"Fd_pread":                  true,
			"Fd_pwrite":                 true,
			"Fd_seek":                   true,
			"Fd_tell":                   true,
			"Fd_write":                  true,
			"Fd_sync":                   true,
			"Fd_datasync":               true,
			"Fd_advise":                 true,
			"Fd_allocate":               true,
			"Fd_renumber":               true,
			"readDirCached":             true,
			"dotEntry":                  true,
			"Name":                      true,
			"IsDir":                     true,
			"Type":                      true,
			"Info":                      true,
			"Fd_readdir":                true,
			"Path_open":                 true,
			"Path_create_directory":     true,
			"Path_unlink_file":          true,
			"Path_remove_directory":     true,
			"Path_rename":               true,
			"Path_filestat_get":         true,
			"Path_filestat_set_times":   true,
			"osLstatOrStat":             true,
			"Path_link":                 true,
			"Path_symlink":              true,
			"Path_readlink":             true,
			"Random_get":                true,
			"Sched_yield":               true,
			"Poll_oneoff":               true,
			"writeEvent":                true,
			"Proc_exit":                 true,
			"Proc_raise":                true,
			"Sock_accept":               true,
			"Sock_recv":                 true,
			"Sock_send":                 true,
			"Sock_shutdown":             true,
			"writeFilestat":             true,
			"Error":                     true,
		},
		keepVarNames: map[string]bool{},
		keepConstAll: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("strip wasi template: %w", err)
	}
	f, err := parser.ParseFile(t.fset, "wasip1native.go", src, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parse wasi template: %w", err)
	}

	multi := t.multiPackage

	var decls []ast.Decl
	for _, d := range f.Decls {
		switch dd := d.(type) {
		case *ast.GenDecl:
			if dd.Tok.String() == "import" {
				continue
			}
			if multi {
				// In multi-pkg mode helper file goes into base/, where
				// the lowercase Module fields are exported (Memory etc).
				dd2 := *dd
				dd2.Specs = rewriteValueSpecsSelfRefs(dd2.Specs)
				decls = append(decls, &dd2)
			} else {
				decls = append(decls, dd)
			}
		case *ast.FuncDecl:
			fn := *dd
			if multi {
				// base/ exports the Module fields and the runtime helpers.
				fn.Body = rewriteHelperBody(fn.Body, map[string]bool{"accessMemory": true})
			}
			decls = append(decls, &fn)
		}
	}

	imports := []string{
		"context",
		"crypto/rand",
		"encoding/binary",
		"errors",
		"fmt",
		"io",
		"io/fs",
		"net",
		"os",
		"os/exec",
		"os/signal",
		"os/user",
		"path/filepath",
		"runtime",
		"sort",
		"strconv",
		"strings",
		"sync",
		"syscall",
		"time",
	}

	return decls, imports, nil
}

// The per-platform companions of this file, embedded as they are compiled
// into this package.
var (
	//go:embed wasip1_native_posix.go
	wasip1NativePosixRaw []byte
	//go:embed wasip1_native_linux.go
	wasip1NativeLinuxRaw []byte
	//go:embed wasip1_native_darwin.go
	wasip1NativeDarwinRaw []byte
	//go:embed wasip1_native_darwin_arm64.s
	wasip1NativeDarwinARM64Raw []byte
	//go:embed wasip1_native_darwin_amd64.s
	wasip1NativeDarwinAMD64Raw []byte
	//go:embed wasip1_native_other.go
	wasip1NativeOtherRaw []byte
	//go:embed wasip1_native_hostfd.go
	wasip1NativeHostFDRaw []byte
	//go:embed wasip1_native_hostsock.go
	wasip1NativeHostSockRaw []byte
	//go:embed wasip1_native_terminal.go
	wasip1NativeTerminalRaw []byte
	//go:embed wasip1_hostnumbers_linux.go
	wasip1HostNumbersLinuxRaw []byte
	//go:embed wasip1_hostnumbers_linux_headers.go
	wasip1HostNumbersLinuxHeadersRaw []byte
	//go:embed wasip1_hostnumbers_linux_noheaders.go
	wasip1HostNumbersLinuxNoHeadersRaw []byte
	//go:embed wasip1_hostnumbers_darwin.go
	wasip1HostNumbersDarwinRaw []byte
)

// emitWasip1Platform returns the per-platform companions of the native wasi
// implementation — output filename → Go source for package pkg (or, for an
// assembly file, the file as it is) — or nil when the module does not import
// wasi. They are written out as separate files, next to the one that holds
// the emitWasip1Native declarations, because their build constraints have to
// stay attached to them.
func (t *translator) emitWasip1Platform(pkg string) map[string][]byte {
	if !t.wasmImportsWasi() {
		return nil
	}
	out := map[string][]byte{}
	for name, raw := range map[string][]byte{
		"wasip1_native_posix.go":  wasip1NativePosixRaw,
		"wasip1_native_linux.go":  wasip1NativeLinuxRaw,
		"wasip1_native_darwin.go": wasip1NativeDarwinRaw,
		// the C library's trampolines of the darwin file
		"wasip1_native_darwin_arm64.s": wasip1NativeDarwinARM64Raw,
		"wasip1_native_darwin_amd64.s": wasip1NativeDarwinAMD64Raw,
		"wasip1_native_other.go":       wasip1NativeOtherRaw,
		"wasip1_native_hostfd.go":      wasip1NativeHostFDRaw,
		"wasip1_native_hostsock.go":    wasip1NativeHostSockRaw,
		"wasip1_native_terminal.go":    wasip1NativeTerminalRaw,

		"wasip1_hostnumbers_linux.go":           wasip1HostNumbersLinuxRaw,
		"wasip1_hostnumbers_linux_headers.go":   wasip1HostNumbersLinuxHeadersRaw,
		"wasip1_hostnumbers_linux_noheaders.go": wasip1HostNumbersLinuxNoHeadersRaw,
		"wasip1_hostnumbers_darwin.go":          wasip1HostNumbersDarwinRaw,
	} {
		out[name] = bytes.Replace(raw, []byte("\npackage codegen\n"), []byte("\npackage "+pkg+"\n"), 1)
	}
	return out
}

// codegenStripOpts is the allow-list flavour of strip: any top-level
// decl whose name isn't listed is removed from the embedded source
// before it is spliced into the generated output. Const blocks survive
// wholesale (the wasi errno constants are all part of the runtime
// surface).
type codegenStripOpts struct {
	keepTypeNames map[string]bool
	keepFuncNames map[string]bool
	keepVarNames  map[string]bool
	keepConstAll  bool
}

// codegenStripForEmit returns the embedded source with codegen-only
// types/funcs/vars removed (only entries listed in opts survive). It
// also rewrites the package declaration to wasip1native so downstream
// parser-level operations don't see the codegen package name.
func codegenStripForEmit(raw []byte, opts codegenStripOpts) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", raw, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	f.Name = &ast.Ident{Name: "wasip1native"}
	kept := f.Decls[:0]
	for _, d := range f.Decls {
		switch dd := d.(type) {
		case *ast.GenDecl:
			switch dd.Tok.String() {
			case "import":
				continue
			case "const":
				if opts.keepConstAll {
					kept = append(kept, dd)
				}
			case "type":
				specs := dd.Specs[:0]
				for _, sp := range dd.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok {
						specs = append(specs, sp)
						continue
					}
					if opts.keepTypeNames[ts.Name.Name] {
						specs = append(specs, sp)
					}
				}
				if len(specs) == 0 {
					continue
				}
				dd.Specs = specs
				kept = append(kept, dd)
			case "var":
				specs := dd.Specs[:0]
				for _, sp := range dd.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						specs = append(specs, sp)
						continue
					}
					keep := false
					for _, n := range vs.Names {
						if opts.keepVarNames[n.Name] {
							keep = true
							break
						}
					}
					if keep {
						specs = append(specs, sp)
					}
				}
				if len(specs) == 0 {
					continue
				}
				dd.Specs = specs
				dd.Doc = nil // strip //go:embed
				kept = append(kept, dd)
			}
		case *ast.FuncDecl:
			// Functions are kept iff their name is in the allow-list,
			// OR they are a method whose receiver type is in the
			// allow-list (which catches all methods on the kept
			// WasiStubs / wasiOpen / dotDirEntry).
			recvType := ""
			if dd.Recv != nil && len(dd.Recv.List) > 0 {
				recvType = receiverTypeName(dd.Recv.List[0].Type)
			}
			if opts.keepFuncNames[dd.Name.Name] {
				kept = append(kept, dd)
				continue
			}
			if recvType != "" && opts.keepTypeNames[recvType] {
				kept = append(kept, dd)
				continue
			}
		}
	}
	f.Decls = kept
	// Drop the package-level comment groups so the emitted output has
	// a clean header.
	f.Comments = nil
	var buf []byte
	out := &codegenWriter{buf: &buf}
	if err := printAST(out, fset, f); err != nil {
		return nil, err
	}
	return buf, nil
}

// receiverTypeName returns the underlying type identifier of a method
// receiver expression. For "*Foo" it returns "Foo"; for "Foo" it
// returns "Foo". Used by the strip logic to drop entire receiver
// families (e.g. every method on *translator) by name.
func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.Ident:
		return e.Name
	}
	return ""
}

// codegenWriter is a tiny io.Writer that appends to a *[]byte. Kept
// local to avoid pulling bytes.Buffer into this file just for emission.
type codegenWriter struct{ buf *[]byte }

func (w *codegenWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

func printAST(w io.Writer, fset *token.FileSet, f *ast.File) error {
	return format.Node(w, fset, f)
}

// rewriteValueSpecsSelfRefs is a stub for symmetry with the FuncDecl
// path. Currently the template's package-scope vars/consts don't
// reference m.<field>, so this is a pass-through. Kept so future
// template additions don't break the multi-pkg rewrite path.
func rewriteValueSpecsSelfRefs(specs []ast.Spec) []ast.Spec { return specs }

// wasmImportsWasi reports whether the wasm module imports
// wasi_snapshot_preview1.
func (t *translator) wasmImportsWasi() bool {
	for _, mod := range t.importedModules {
		if mod == "wasi_snapshot_preview1" {
			return true
		}
	}
	return false
}

// ----- wasm64-wasip1 (widened ABI) ------------------------------------------
//
// A memory64 module's wasi imports arrive widened (see the wasm2go
// wasi-libc port's __wasi_abi_t): every argument of a standard import is a
// pointer-width i64, every pointer of a non-standard one an i64, and the
// WASI structs that hold pointers or sizes (iovecs, the argv and environ
// tables, prestat, the sizes a call writes back) use the LP64 layout.
// Codegen binds such a module's imports to the methods named <Name>64
// (importMethodName); a wasm32 module binds the ones without the suffix.
//
// The two methods of an import are thin wrappers over one body, which
// takes the guest's addresses as uint64 — a wasm32 guest's zero-extended
// (zext), a memory64 guest's as they are, never truncated — and, where a
// record's layout depends on the guest's pointer width, a wasiABI. A *64
// method therefore does exactly what its wasm32 twin does but for the
// widths. Most of them sit next to that twin; those of the terminal
// imports, whose bodies are per platform (wasip1_native_terminal.go,
// wasip1_native_other.go), follow.

// Tty_getattr is a NON-STANDARD host import (name "tty_getattr") backing
// tcgetattr: the settings of the terminal fd are written at recordPtr, as
// struct termios of the guest's C library, in the host's numbers. Returns 0
// or a negative errno: ENOTTY for a descriptor that is no terminal.
func (w *WasiStubs) Tty_getattr(m *Module, fd, recordPtr int32) int32 {
	return w.ttyGetattr(m, fd, zext(recordPtr))
}

// Tty_getattr64 is Tty_getattr for a memory64 guest.
func (w *WasiStubs) Tty_getattr64(m *Module, fd int32, recordPtr int64) int32 {
	return w.ttyGetattr(m, fd, uint64(recordPtr))
}

// Tty_name is a NON-STANDARD host import (name "tty_name") backing ttyname:
// the path of the terminal fd is written at bufPtr, which holds bufLen
// bytes, and its length at lenPtr (u32) — also when it does not fit, which
// is -ERANGE. Returns 0 or a negative errno: ENOTTY for a descriptor that is
// no terminal, ENODEV for a terminal the host has no name for.
func (w *WasiStubs) Tty_name(m *Module, fd, bufPtr, bufLen, lenPtr int32) int32 {
	return w.ttyName(m, fd, zext(bufPtr), bufLen, zext(lenPtr))
}

// Tty_name64 is Tty_name for a memory64 guest.
func (w *WasiStubs) Tty_name64(m *Module, fd int32, bufPtr int64, bufLen int32, lenPtr int64) int32 {
	return w.ttyName(m, fd, uint64(bufPtr), bufLen, uint64(lenPtr))
}

// Tty_setattr is a NON-STANDARD host import (name "tty_setattr") backing
// tcsetattr: the terminal fd gets the settings at recordPtr, at the time
// actions says (the host's TCSANOW, TCSADRAIN or TCSAFLUSH). Returns 0 or a
// negative errno.
func (w *WasiStubs) Tty_setattr(m *Module, fd, actions, recordPtr int32) int32 {
	return w.ttySetattr(m, fd, actions, zext(recordPtr))
}

// Tty_setattr64 is Tty_setattr for a memory64 guest.
func (w *WasiStubs) Tty_setattr64(m *Module, fd, actions int32, recordPtr int64) int32 {
	return w.ttySetattr(m, fd, actions, uint64(recordPtr))
}

// Tty_speed is a NON-STANDARD host import (name "tty_speed") backing
// cfgetispeed, cfgetospeed, cfsetispeed and cfsetospeed: where the speed of
// a terminal is kept in its settings is the host's own. The input speed
// (output 0) or the output speed of the settings at recordPtr is written at
// outPtr (u32) as it was; with set non-zero it then becomes speed. Returns
// 0 or a negative errno: EINVAL for a speed the host has no such number
// for.
func (w *WasiStubs) Tty_speed(m *Module, recordPtr, output, set, speed, outPtr int32) int32 {
	return w.ttySpeed(m, zext(recordPtr), output, set, speed, zext(outPtr))
}

// Tty_speed64 is Tty_speed for a memory64 guest.
func (w *WasiStubs) Tty_speed64(m *Module, recordPtr int64, output, set, speed int32, outPtr int64) int32 {
	return w.ttySpeed(m, uint64(recordPtr), output, set, speed, uint64(outPtr))
}

// Tty_control64 is Tty_control for a memory64 guest.
func (w *WasiStubs) Tty_control64(m *Module, fd, what, arg int32) int32 {
	return w.Tty_control(m, fd, what, arg)
}

// Tty_pgrp is a NON-STANDARD host import (name "tty_pgrp") backing
// tcgetpgrp and tcsetpgrp: the process group in the foreground of the
// terminal fd is written at outPtr (u32); with set non-zero it then becomes
// pgrp. Returns 0 or a negative errno. A process forked within the runtime
// is refused (ENOSYS): the groups of such processes are the runtime's, and
// a terminal's foreground group is a group of the host.
func (w *WasiStubs) Tty_pgrp(m *Module, fd, set, pgrp, outPtr int32) int32 {
	return w.ttyPgrp(m, fd, set, pgrp, zext(outPtr))
}

// Tty_pgrp64 is Tty_pgrp for a memory64 guest.
func (w *WasiStubs) Tty_pgrp64(m *Module, fd, set, pgrp int32, outPtr int64) int32 {
	return w.ttyPgrp(m, fd, set, pgrp, uint64(outPtr))
}

// Fd_ioctl is a NON-STANDARD host import (name "fd_ioctl") backing ioctl
// for the requests of a terminal (window size, controlling terminal, modem
// lines, ...), which the guest's C library does not answer. request is the
// host's number. The argument is a number (buffer 0: arg is it) or memory
// the request reads and writes (buffer non-zero: argLen bytes at arg, at
// least what the request takes); what a request reads and writes there is
// in the host's layout. What the call returned is written at resultPtr
// (i32). Returns 0 or a negative errno: EINVAL for a request that is not
// one of a terminal's, ENOTTY for a descriptor that is not the host's.
//
// The memory is the guest's, so a request whose argument holds pointers
// cannot be passed on; no request of a terminal's does.
func (w *WasiStubs) Fd_ioctl(m *Module, fd, request, buffer, arg, argLen, resultPtr int32) int32 {
	return w.fdIoctl(m, fd, request, buffer, zext(arg), uintptr(int(arg)), argLen, zext(resultPtr))
}

// Fd_ioctl64 is Fd_ioctl for a memory64 guest, whose argument keeps all
// of its 64 bits as an address and as a number.
func (w *WasiStubs) Fd_ioctl64(m *Module, fd, request, buffer int32, arg int64, argLen int32, resultPtr int64) int32 {
	return w.fdIoctl(m, fd, request, buffer, uint64(arg), uintptr(arg), argLen, uint64(resultPtr))
}
