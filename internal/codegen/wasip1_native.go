// Package codegen — wasip1_native.go owns the default wasi_snapshot_preview1
// host implementation that gets woven into the translated output.
//
// Design notes:
//
//   - The struct WasiStubs holds all the runtime-side state (fd table, args,
//     env, monotonic start) so the wasm runtime's Module type stays free of
//     host-specific fields.
//   - NewWASI(cfg) returns *WasiStubs built from a WASIConfig;
//     HostWASIConfig() is the configuration wired to os.Stdin/Stdout/Stderr,
//     os.Args, os.Environ() and the host filesystem.
//   - Memory access uses m.memory (lowercase) at template time. In
//     multi-package mode, capitalizeModuleFieldRefs rewrites it to
//     m.Memory so the impl works in base/ too.
//   - Method signatures must match what t.importMethodName produces from
//     the wasm import names. We use the same MangleID + capitalize chain
//     by emitting the exact wasi function names ("Environ_get" etc).
//   - Bodies favour clarity over micro-optimisation.
//
// Security model: the guest has what its WASIConfig gives it and nothing
// else (see WASIConfig). HostFS("/") is the whole host filesystem, a
// Go-syscall passthrough; HostFS(dir) keeps every path inside dir through
// os.Root. FSAccess is a policy on path names, and the hooks are the only
// allow-lists. Out-of-range linear-memory accesses are reported back to the
// guest as EFAULT (rather than being allowed to panic the host) because
// wasm itself traps on OOB.
//
// File layout: this file is real, compilable Go and is also //go:embed-ed
// so the same code that the codegen test suite exercises is the code that
// gets written into generated output. Everything goes through the Go
// stdlib (os, time, syscall, net), so no third-party dependencies are
// needed. The few operations the stdlib only offers per platform live in the
// wasip1_native_<platform>.go companions, which are emitted next to the
// generated output with their build constraints.
package codegen

import (
	"bytes"
	"cmp"
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
	"maps"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
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

// WasiExitError is the panic value of a guest that called Proc_exit(). A
// bulk-dispatch function (Inv_<svc>_<mt>) recovers it and returns it wrapped
// in its error, which errors.As reaches; an export method and the
// constructor (which runs the start function) let it panic. Either way the
// caller can read the exit code instead of the host process exiting.
type WasiExitError struct{ Code int32 }

func (e *WasiExitError) Error() string {
	return "wasi: proc_exit(" + itoa32(e.Code) + ")"
}

// WasiSignalError is the panic value of a guest that ended by a signal
// (Proc_raise), the counterpart of WasiExitError: it reaches the caller the
// same way, which then knows the instance is gone and which signal ended
// it. Signal is the guest's number for the signal (WASI numbering).
type WasiSignalError struct{ Signal int32 }

func (e *WasiSignalError) Error() string {
	return "wasi: terminated by signal " + itoa32(e.Signal)
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
	// support the operations the mode implies.
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	Mkdir(name string, perm os.FileMode) error
	// Chmod sets the permission bits of name, and its setuid, setgid and
	// sticky bits from the corresponding os.FileMode flags.
	Chmod(name string, mode os.FileMode) error
	// Chtimes sets the access and modification times of name.
	Chtimes(name string, atime, mtime time.Time) error
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
// them: the ones a filestat_ext record carries.
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

// osFS is the FS HostFS returns for the whole host filesystem: a thin
// pass-through, where the guest path name is the host path "/"+name.
type osFS struct{}

// HostFS returns the host filesystem under the host directory root as an FS:
// the guest's "/" is root.
//
// For root "" or "/" (any root that filepath.Clean makes "/", such as
// "//" or "/.") it is the whole host filesystem, and a guest path is the
// host path: nothing is outside it, and ".." of "/" is "/".
//
// For any other root it is built on os.OpenRoot(root), whose error it
// returns: the FS holds the root directory open until its Close method
// (it is an io.Closer) is called. A path the guest names that escapes the
// root, through ".." or through a symbolic link, is refused by os.Root,
// which the guest sees as EACCES. The symbolic links the guest creates
// may point anywhere: the guest cannot follow them out of the root, a
// reader on the host can. A rename is os.Root.Rename (see rootFS.Rename).
// Everything, the root itself included, goes through the directory os.Root
// holds, so the root must be a directory that may be searched: HostFS
// returns the error of looking at it otherwise.
func HostFS(root string) (FS, error) {
	if root == "" || filepath.Clean(root) == "/" {
		return osFS{}, nil
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	escape, err := rootEscapeOf(r)
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return rootFS{root: r, escape: escape}, nil
}

// rootEscapeOf returns the error r gives for a path that escapes it, which
// package os does not export: what it answers for "..". It also makes sure
// the root may be searched, which "." needs: an error of either is
// returned.
func rootEscapeOf(r *os.Root) (error, error) {
	if _, err := r.Stat("."); err != nil {
		return nil, err
	}
	_, escape := r.Lstat("..")
	var pathErr *fs.PathError
	if !errors.As(escape, &pathErr) {
		return nil, fmt.Errorf("os.Root answers %w for \"..\", not a refusal", escape)
	}
	return pathErr.Err, nil
}

// Close does nothing: the whole host filesystem holds nothing open.
func (osFS) Close() error { return nil }

func (o osFS) join(name string) string {
	// "." is the root itself, which the guest's C library names so: a
	// call on "/" is the host's call on "/" (rmdir of it is EBUSY; of "/."
	// it would be EINVAL).
	if name == "." {
		return "/"
	}
	return "/" + name // not path.Join: the host resolves ".." after symbolic links
}
func (o osFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := os.OpenFile(o.join(name), flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (o osFS) Mkdir(name string, perm os.FileMode) error { return os.Mkdir(o.join(name), perm) }
func (o osFS) Chmod(name string, mode os.FileMode) error { return os.Chmod(o.join(name), mode) }
func (o osFS) Remove(name string) error                  { return os.Remove(o.join(name)) }
func (o osFS) Rename(a, b string) error                  { return hostRename(o.join(a), o.join(b)) }
func (o osFS) Stat(name string) (os.FileInfo, error)     { return os.Stat(o.join(name)) }
func (o osFS) Lstat(name string) (os.FileInfo, error)    { return os.Lstat(o.join(name)) }
func (o osFS) Symlink(target, name string) error         { return os.Symlink(target, o.join(name)) }
func (o osFS) Readlink(name string) (string, error)      { return os.Readlink(o.join(name)) }
func (o osFS) Link(a, b string) error                    { return os.Link(o.join(a), o.join(b)) }

// rootFS is the FS HostFS returns for a root other than the whole host
// filesystem: the host directory os.Root holds, which refuses every path
// that escapes it with escape.
type rootFS struct {
	root   *os.Root
	escape error
}

// name is the guest path name as os.Root takes it: "." for the root itself.
func (rootFS) name(name string) string {
	if name == "" {
		return "."
	}
	return name
}

// refused returns err, which is also fs.ErrPermission (EACCES) when it is
// the root's refusal of a path that escapes it.
func (r rootFS) refused(err error) error {
	if err != nil && errors.Is(err, r.escape) {
		return fmt.Errorf("%w: %w", err, fs.ErrPermission)
	}
	return err
}

// specialModeBits are the setuid, setgid and sticky bits, which os.Root
// creates no file with: rootFS creates the file with its permission bits
// and then sets them with chmod, as package os does for the sticky bit of a
// directory where mkdir(2) does not set it.
const specialModeBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky

func (r rootFS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	special := perm & specialModeBits
	if special == 0 || flag&os.O_CREATE == 0 {
		f, err := r.root.OpenFile(r.name(name), flag, perm.Perm())
		if err != nil {
			return nil, r.refused(err)
		}
		return f, nil
	}
	// Only a file the call creates gets the bits: it is created
	// exclusively, and a file that exists is opened as it is. A name that
	// is there but leads to no file, a symbolic link to none, is opened
	// once more as open(2) opens it, which creates the file it leads to.
	f, err := r.root.OpenFile(r.name(name), flag|os.O_EXCL, perm.Perm())
	created, viaLink := err == nil, false
	if errors.Is(err, fs.ErrExist) && flag&os.O_EXCL == 0 {
		f, err = r.root.OpenFile(r.name(name), flag&^os.O_CREATE, perm.Perm())
		if err == nil {
			err = refuseDirectory(f, name)
		}
		if errors.Is(err, fs.ErrNotExist) {
			fi, lerr := r.root.Lstat(r.name(name))
			switch {
			case lerr == nil:
				viaLink = fi.Mode()&os.ModeSymlink != 0
			case !errors.Is(lerr, fs.ErrNotExist):
				return nil, r.refused(lerr)
			}
			f, err = r.root.OpenFile(r.name(name), flag, perm.Perm())
			created = err == nil
		}
	}
	if err != nil {
		return nil, r.refused(err)
	}
	if !created {
		return f, nil
	}
	// A bit the system refuses this user or this file is left out, as
	// open(2) leaves it out. A file the bits cannot be set on otherwise is
	// removed again, as the call fails; one created through a symbolic
	// link has no name the call knows, and stays.
	if err := setSpecialBits(f, special); err != nil && !chmodRefused(err) {
		err = errors.Join(err, f.Close())
		if !viaLink {
			err = errors.Join(err, r.root.Remove(r.name(name)))
		}
		return nil, err
	}
	return f, nil
}
func (r rootFS) Mkdir(name string, perm os.FileMode) error {
	if err := r.root.Mkdir(r.name(name), perm.Perm()); err != nil {
		return r.refused(err)
	}
	// mkdir(2) sets no setuid or setgid bit; the sticky bit is set
	// afterwards, keeping the bits the system gave the directory (a setgid
	// bit inherited from its parent).
	if perm&os.ModeSticky == 0 {
		return nil
	}
	fi, err := r.root.Stat(r.name(name))
	if err == nil {
		err = r.root.Chmod(r.name(name), fi.Mode()&(os.ModePerm|specialModeBits)|os.ModeSticky)
	}
	if err != nil && !chmodRefused(err) {
		// The directory is removed again, as the call fails; a sticky
		// bit the system refuses is left out.
		return errors.Join(r.refused(err), r.root.Remove(r.name(name)))
	}
	return nil
}

// refuseDirectory closes f and returns EISDIR when f is a directory, which
// open(2) with O_CREAT refuses; nil otherwise.
func refuseDirectory(f *os.File, name string) error {
	fi, err := f.Stat()
	if err == nil && !fi.IsDir() {
		return nil
	}
	if err == nil {
		err = &fs.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
	}
	return errors.Join(err, f.Close())
}

// setSpecialBits adds special, setuid, setgid and sticky bits, to the mode
// of the file open as f.
func setSpecialBits(f *os.File, special os.FileMode) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return f.Chmod(fi.Mode().Perm() | special)
}
func (r rootFS) Chmod(name string, mode os.FileMode) error {
	return r.refused(r.root.Chmod(r.name(name), mode))
}
func (r rootFS) Chtimes(name string, atime, mtime time.Time) error {
	return r.refused(r.root.Chtimes(r.name(name), atime, mtime))
}
func (r rootFS) Remove(name string) error { return r.refused(r.root.Remove(r.name(name))) }

// Rename renames as os.Root.Rename does, which (unlike rename(2)) may
// refuse a rename onto an existing directory with EEXIST, as os.Rename
// does.
func (r rootFS) Rename(a, b string) error { return r.refused(r.root.Rename(r.name(a), r.name(b))) }
func (r rootFS) Stat(name string) (os.FileInfo, error) {
	fi, err := r.root.Stat(r.name(name))
	return fi, r.refused(err)
}
func (r rootFS) Lstat(name string) (os.FileInfo, error) {
	fi, err := r.root.Lstat(r.name(name))
	return fi, r.refused(err)
}
func (r rootFS) Readlink(name string) (string, error) {
	target, err := r.root.Readlink(r.name(name))
	return target, r.refused(err)
}
func (r rootFS) Link(a, b string) error { return r.refused(r.root.Link(r.name(a), r.name(b))) }
func (r rootFS) Symlink(target, name string) error {
	return r.refused(r.root.Symlink(target, r.name(name)))
}

// Chown changes the owner and group of a file, as osFS.Chown does.
func (r rootFS) Chown(name string, uid, gid int, follow bool) error {
	if follow {
		return r.refused(r.root.Chown(r.name(name), uid, gid))
	}
	return r.refused(r.root.Lchown(r.name(name), uid, gid))
}

// Close closes the root directory.
func (r rootFS) Close() error { return r.root.Close() }

// noFS is the FS of a WASIConfig that names none: it has no file, so every
// operation fails with fs.ErrNotExist (ENOENT).
type noFS struct{}

func (noFS) OpenFile(string, int, os.FileMode) (File, error) { return nil, fs.ErrNotExist }
func (noFS) Mkdir(string, os.FileMode) error                 { return fs.ErrNotExist }
func (noFS) Chmod(string, os.FileMode) error                 { return fs.ErrNotExist }
func (noFS) Chtimes(string, time.Time, time.Time) error      { return fs.ErrNotExist }
func (noFS) Chown(string, int, int, bool) error              { return fs.ErrNotExist }
func (noFS) Remove(string) error                             { return fs.ErrNotExist }
func (noFS) Rename(string, string) error                     { return fs.ErrNotExist }
func (noFS) Stat(string) (os.FileInfo, error)                { return nil, fs.ErrNotExist }
func (noFS) Lstat(string) (os.FileInfo, error)               { return nil, fs.ErrNotExist }
func (noFS) Symlink(string, string) error                    { return fs.ErrNotExist }
func (noFS) Readlink(string) (string, error)                 { return "", fs.ErrNotExist }
func (noFS) Link(string, string) error                       { return fs.ErrNotExist }

// MemFS is an in-memory read/write FS. Each value is an independent tree, so
// two interpreters given separate MemFS values cannot observe each other's
// files (full per-interpreter filesystem isolation, no disk). Build one with
// NewMemFS. Safe for concurrent use.
type MemFS struct {
	mu   sync.Mutex
	root *memNode
	// maxFileSize is the size a write or a truncation can make a file;
	// NewMemFS sets it to memMaxFileSize.
	maxFileSize int64
	// lastIno is the inode number of the node made last.
	lastIno uint64
}

// NewMemFS returns an empty in-memory filesystem with a root directory.
func NewMemFS() *MemFS {
	return &MemFS{root: &memNode{ino: 1, dir: true, mode: os.ModeDir | 0o755, modTime: time.Unix(0, 0), children: map[string]*memNode{}},
		maxFileSize: memMaxFileSize, lastIno: 1}
}

// newIno returns an inode number no other node of fsys has. Caller holds
// fsys.mu.
func (fsys *MemFS) newIno() uint64 {
	fsys.lastIno++
	return fsys.lastIno
}

// memDev is the device number of the files of a MemFS.
const memDev = 1

// memNode is a file or directory in a MemFS tree.
type memNode struct {
	ino      uint64
	name     string
	dir      bool
	mode     os.FileMode
	modTime  time.Time
	data     []byte
	children map[string]*memNode
	// parent is the directory the node is, or was last, in; nil for the
	// root.
	parent *memNode
	// unlinked is set once the node has no name in the tree any more (it
	// was removed or replaced), which only its open files can still see:
	// their stat reports a link count of zero.
	unlinked bool
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
			return nil, syscall.ENOTDIR
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
		if !ok {
			return nil, "", fs.ErrNotExist
		}
		if !c.dir {
			return nil, "", syscall.ENOTDIR
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
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		parent, base, perr := fsys.lookupParent(name)
		if perr != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: perr}
		}
		node = &memNode{ino: fsys.newIno(), name: base, mode: perm & 0o777, modTime: time.Now(), parent: parent}
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
	f := &memFile{fsys: fsys, node: node, appending: flag&os.O_APPEND != 0}
	if f.appending {
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
	parent.children[base] = &memNode{ino: fsys.newIno(), name: base, dir: true, mode: os.ModeDir | (perm & 0o777), modTime: time.Now(), children: map[string]*memNode{}, parent: parent}
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
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.ENOTEMPTY}
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
	if !node.dir && (strings.HasSuffix(oldName, "/") || strings.HasSuffix(newName, "/")) {
		// a name ending in "/" is a directory's
		return &fs.PathError{Op: "rename", Path: newName, Err: syscall.ENOTDIR}
	}
	replaced, exists := np.children[nb]
	if exists && replaced != node {
		switch {
		case node.dir && !replaced.dir:
			err = syscall.ENOTDIR
		case !node.dir && replaced.dir:
			err = syscall.EISDIR
		case replaced.dir && len(replaced.children) > 0:
			err = syscall.ENOTEMPTY
		}
	}
	if node.dir && fsys.passesThrough(newName, node) {
		err = syscall.EINVAL
	}
	if err != nil {
		return &fs.PathError{Op: "rename", Path: newName, Err: err}
	}
	delete(op.children, ob)
	node.name, node.parent = nb, np
	if exists && replaced != node {
		replaced.unlinked = true
	}
	np.children[nb] = node
	return nil
}

// passesThrough reports whether the parent directories of name, which
// exist, include node: whether name lies in node. Caller holds fsys.mu.
func (fsys *MemFS) passesThrough(name string, node *memNode) bool {
	n := fsys.root
	parts := memSplit(name)
	for _, part := range parts[:len(parts)-1] {
		n = n.children[part]
		if n == node {
			return true
		}
	}
	return false
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
			c = &memNode{ino: fsys.newIno(), name: part, dir: true, mode: os.ModeDir | (perm & 0o777), modTime: time.Now(), children: map[string]*memNode{}, parent: n}
			n.children[part] = c
		} else if !c.dir {
			return &fs.PathError{Op: "mkdir", Path: name, Err: syscall.ENOTDIR}
		}
		n = c
	}
	return nil
}

// WriteFile creates (or overwrites) a file with data, making parent dirs as
// needed; perm is the mode of a file it creates. Exposed for pre-populating
// the FS.
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
	// An existing file is written over, keeping its inode and mode.
	if n, ok := parent.children[base]; ok {
		if n.dir {
			return &fs.PathError{Op: "writefile", Path: name, Err: syscall.EISDIR}
		}
		n.data, n.modTime = cp, time.Now()
		return nil
	}
	parent.children[base] = &memNode{ino: fsys.newIno(), name: base, mode: perm & 0o777, modTime: time.Now(), data: cp, parent: parent}
	return nil
}

func (n *memNode) info() memFileInfo {
	fi := memFileInfo{ino: n.ino, name: n.name, size: int64(len(n.data)), mode: n.mode & 0o777, modTime: n.modTime, unlinked: n.unlinked}
	if n.dir {
		fi.size = 0
		fi.mode |= os.ModeDir
	}
	return fi
}

type memFileInfo struct {
	ino      uint64
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
	st := &fileStat{dev: memDev, ino: fi.ino, nlink: 1, atime: fi.modTime, ctime: fi.modTime,
		blksize: memBlockSize, blocks: uint64(fi.size+511) / 512}
	if fi.unlinked {
		st.nlink = 0
	}
	return st
}

// memBlockSize is the block size an in-memory file reports for I/O.
const memBlockSize = 4096

// memDirEntry is an entry of a MemFS directory, as it was when the
// directory was read.
type memDirEntry struct{ info memFileInfo }

func (e memDirEntry) Name() string               { return e.info.Name() }
func (e memDirEntry) IsDir() bool                { return e.info.IsDir() }
func (e memDirEntry) Type() os.FileMode          { return e.info.Mode().Type() }
func (e memDirEntry) Info() (os.FileInfo, error) { return e.info, nil }
func (e memDirEntry) inode() uint64              { return e.info.ino }

// memFile is an open handle into a MemFS node.
type memFile struct {
	fsys   *MemFS
	node   *memNode
	off    int64
	dirOff int
	// appending is whether the file was opened with O_APPEND: each Write
	// starts at the end of the file.
	appending bool
}

func (f *memFile) Name() string {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return f.node.name
}

// parentInode returns the inode number of the directory f's node is in:
// its own for the root.
func (f *memFile) parentInode() uint64 {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.node.parent == nil {
		return f.node.ino
	}
	return f.node.parent.ino
}
func (f *memFile) Close() error { return nil }
func (f *memFile) Sync() error  { return nil }

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
		return 0, &fs.PathError{Op: "read", Path: f.node.name, Err: syscall.EISDIR}
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
	if f.node.dir {
		return 0, &fs.PathError{Op: "read", Path: f.node.name, Err: syscall.EISDIR}
	}
	if off < 0 {
		return 0, &fs.PathError{Op: "read", Path: f.node.name, Err: syscall.EINVAL}
	}
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// memMaxFileSize is the size a MemFS file can grow to. Growing a file holds
// its data and a copy up to 1.25 times as large at once: on a 32-bit host
// the limit is 256 MiB, so that stays far below its address space.
const memMaxFileSize = min(1<<31-1, 1<<(strconv.IntSize-4)-1)

// validateOffset returns the error of writing at or truncating to off:
// EISDIR for a directory and EINVAL for a negative off.
func (f *memFile) validateOffset(op string, off int64) error {
	switch {
	case f.node.dir:
		return &fs.PathError{Op: op, Path: f.node.name, Err: syscall.EISDIR}
	case off < 0:
		return &fs.PathError{Op: op, Path: f.node.name, Err: syscall.EINVAL}
	}
	return nil
}

// writeAt grows node.data as needed and writes p at off, up to
// fsys.maxFileSize: it writes the bytes below it and fails with EFBIG for
// the rest. Caller holds the lock.
func (f *memFile) writeAt(p []byte, off int64) (int, error) {
	if err := f.validateOffset("write", off); err != nil {
		return 0, err
	}
	var err error
	if room := f.fsys.maxFileSize - off; len(p) > 0 && int64(len(p)) > room {
		p = p[:max(room, 0)]
		err = &fs.PathError{Op: "write", Path: f.node.name, Err: syscall.EFBIG}
	}
	if len(p) == 0 {
		return 0, err
	}
	end := off + int64(len(p))
	if end > int64(len(f.node.data)) {
		f.node.data = append(f.node.data, make([]byte, end-int64(len(f.node.data)))...)
	}
	copy(f.node.data[off:], p)
	f.node.modTime = time.Now()
	return len(p), err
}

func (f *memFile) Write(p []byte) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.appending {
		f.off = int64(len(f.node.data))
	}
	n, err := f.writeAt(p, f.off)
	f.off += int64(n)
	return n, err
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return f.writeAt(p, off)
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	off := int64(-1) // refused below for a whence that is none of these
	switch whence {
	case io.SeekStart:
		off = offset
	case io.SeekCurrent:
		off = f.off + offset
	case io.SeekEnd:
		off = int64(len(f.node.data)) + offset
	}
	if off < 0 {
		return 0, &fs.PathError{Op: "seek", Path: f.node.name, Err: syscall.EINVAL}
	}
	f.off = off
	if whence == io.SeekStart && offset == 0 {
		// a directory lists its entries again from the first
		f.dirOff = 0
	}
	return off, nil
}

func (f *memFile) Truncate(size int64) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if err := f.validateOffset("truncate", size); err != nil {
		return err
	}
	switch {
	case size <= int64(len(f.node.data)):
		f.node.data = f.node.data[:size]
	case size > f.fsys.maxFileSize:
		return &fs.PathError{Op: "truncate", Path: f.node.name, Err: syscall.EFBIG}
	default:
		f.node.data = append(f.node.data, make([]byte, size-int64(len(f.node.data)))...)
	}
	f.node.modTime = time.Now()
	return nil
}

// Chtimes sets the modification time of the file, the only time a MemFS
// keeps.
func (f *memFile) Chtimes(_, mtime time.Time) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.node.modTime = mtime
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
		out = append(out, memDirEntry{f.node.children[name].info()})
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
	conn     net.Conn // guarded by mu; read it through netConn
	listener net.Listener
	isDir    bool
	isSocket bool // created by Sock_socket, may not yet have a conn
	// shutClosed is set once Sock_shutdown closes conn, which has no half
	// close, or listener: a transfer on conn that fails then fails as
	// after shutdown(2) (see afterShutdown), an accept on listener with
	// EINVAL.
	shutClosed atomic.Bool
	// connClosed is set by whichever closes conn or listener first, a
	// Sock_shutdown or closing the descriptor, before that one close; the
	// other then does not close it again, whatever the close returned.
	connClosed atomic.Bool
	// regular is set for a regular file, as Path_open found f: a read of
	// it fills every buffer, where one of a stream returns what has
	// arrived. Immutable.
	regular bool
	// noRead and noWrite record the access mode the descriptor was opened
	// with: a file opened for writing only cannot be read, the read end of
	// a pipe cannot be written. Both false is a descriptor open both ways
	// (a socket). They say nothing for a standard stream (stdio != 0),
	// whose direction is its own; see access. Immutable.
	noRead, noWrite bool
	path            string        // guest path relative to the preopen root
	fdflags         int32         // last fdflags set via Path_open or Fd_fdstat_set_flags; guarded by mu
	dirCache        []os.DirEntry // guarded by mu
	// stdio marks an entry that refers to a standard stream of the
	// instance (1/2/3 = the configured stdin/stdout/stderr; 0 = not one).
	// Fds 0/1/2 start out with such entries; closing one never touches the
	// stream itself.
	stdio int8
	// refs counts EXTRA table slots sharing this entry (dup/dup2 in one
	// instance, plus every slot of a forked instance): closeWasiOpen only
	// closes the descriptor when it reaches zero. Guarded by mu.
	refs int32
	// hostPath records that the descriptor was opened through the whole
	// host filesystem (osFS), whose files may be looked up by their host
	// paths (hostDirListing). Immutable.
	hostPath bool
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

// netConn returns the connection attached to a socket entry, or nil.
func (op *wasiOpen) netConn() net.Conn {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.conn
}

// socket reports whether the entry is a socket: one that has neither a
// file nor a standard stream. A nil entry is none.
func (op *wasiOpen) socket() bool {
	return op != nil && op.f == nil && op.stdio == 0
}

// addRef records one more table slot referring to op.
func (op *wasiOpen) addRef() {
	op.mu.Lock()
	op.refs++
	op.mu.Unlock()
}

// WASIConfig is the configuration a WasiStubs is built from (NewWASI). The
// guest has what it names and nothing else: the zero WASIConfig gives it no
// arguments, no environment, an empty stdin, a stdout and a stderr that
// discard what is written, no filesystem, no socket operation, outbound
// connection, name lookup or process spawn, and the identity of an isolated
// process. HostWASIConfig is the
// configuration of a guest that has what the host process has.
//
// Only the hooks below gate the network: Sock_socket, Sock_shutdown and
// pipe consult none.
type WASIConfig struct {
	// Args are the guest's arguments (args_get), argv[0] included; nil is
	// none. NewWASI copies them.
	Args []string
	// Env is the guest's environment (environ_get) as "KEY=VALUE" strings;
	// nil is none. NewWASI copies it.
	Env []string
	// Stdin, Stdout and Stderr are the instance's standard streams, which
	// guest fds 0/1/2 refer to until the guest closes or replaces them. A
	// nil Stdin reads as empty (EOF); a nil Stdout or Stderr discards what
	// is written.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// FS is the filesystem every guest path operation is routed through,
	// preopened as the guest's "/" (fd 3): HostFS for the host's, NewMemFS
	// for one in memory. Without FSAccess it is given the guest's path as
	// the guest wrote it, without a leading "/"; with FSAccess, the path
	// the hook approved. With nil no directory is preopened: neither fd 3
	// nor the root directory's second number is open, so every call on
	// them, path calls included, fails with EBADF, and fd 3 is handed out
	// like any free number; the guest's C library, finding no preopen,
	// fails every path with ENOENT; the path operations that take no
	// directory descriptor (path_open_mode, path_create_directory_mode,
	// path_chmod, path_chown, path_filestat_ext, path_filestat_mode) fail
	// with ENOENT. The names of the guest's own descriptors (/dev/stdin,
	// /dev/stdout, /dev/stderr, /dev/fd/N, /proc/self/fd/N, /proc/PID/fd/N,
	// and /dev/fd, /proc/self/fd and /proc/PID/fd, which list them) are not
	// the FS's: path_open, path_filestat_get and path_readlink resolve them
	// without it, and path_open_mode, path_filestat_ext and
	// path_filestat_mode even when FS is nil.
	FS FS
	// FSAccess is a policy on path names. It is consulted before every
	// path operation, with each guest path it names cleaned as chroot(2)
	// sees it — path.Clean relative to the preopen, where ".." of the root
	// is the root (e.g. "a.txt", "sub/a.txt", "." for the root) — and
	// whether the operation writes: path_open and path_open_mode (a write
	// when it creates, truncates or opens for writing),
	// path_create_directory, path_create_directory_mode, path_unlink_file,
	// path_remove_directory, path_rename and path_link (both paths),
	// path_filestat_set_times, path_chmod and path_chown are writes;
	// path_filestat_get, path_filestat_ext, path_filestat_mode and
	// path_readlink are reads; path_symlink writes the new link and reads
	// and writes its target, resolved against the link's directory (an
	// absolute target against the root); fd_filestat_set_times writes the
	// path its descriptor was opened under. Returning false denies the
	// operation (EACCES). The FS is given the approved name, so ".." is
	// taken lexically, before any symbolic link; a symbolic link inside
	// the FS still leads where it points, and keeping the guest inside a
	// directory against symbolic links is HostFS(dir)'s (os.Root's) job.
	// Other operations on an open descriptor (fd_*) and the names of the
	// guest's own descriptors (see FS) are not checked. nil allows every
	// access to FS. It is called without the WasiStubs lock held.
	FSAccess func(path string, write bool) bool
	// NetAccess is consulted before Sock_accept, Sock_recv and Sock_send
	// with "accept", "recv" or "send". Returning false denies the operation
	// (EACCES). nil denies every one.
	NetAccess func(op string) bool
	// Dial is consulted before an outbound connect (Sock_connect) with the
	// network ("tcp"), the host the guest resolved to reach the address
	// (from the preceding Sock_getaddrinfo, or "" when the guest dialed a
	// literal IP), the dotted-quad IP and the port. Returning false denies
	// the connection (EACCES). nil denies every one.
	Dial func(network, host, ip string, port int) bool
	// Resolve is consulted before a name lookup (Sock_getaddrinfo) with the
	// requested host. Returning false denies the resolution (the guest sees
	// a name-resolution error). nil denies every one. An empty host is the
	// exception: it resolves to INADDR_ANY without Resolve.
	Resolve func(host string) bool
	// Exec is consulted before every Proc_spawn, which runs a host binary,
	// with the executable path and argv. Returning false denies the spawn
	// (EACCES). nil denies every one.
	Exec func(path string, argv []string) bool
	// Process supplies the guest's identity and accounting: what getpid,
	// getppid, the getuid family and times report, the pid whose
	// /proc/PID/fd lists the guest's descriptors, and the umask the guest
	// starts with. nil is an isolated process: pid 42, ppid 1, every user
	// and group id 0, no CPU time and umask 022, none of them read from the
	// host. HostProcess and HostProcessUmask give the host process's.
	Process Process
	// LocalZone is the time zone of a guest that names none (Clock_zone
	// without TZ); nil is UTC.
	LocalZone *time.Location
	// Errors is told the errors of operations whose caller cannot be given
	// them (op names the operation); nil drops them.
	Errors func(op string, err error)
}

// AllowAllNetAccess is a WASIConfig.NetAccess that allows every socket
// operation.
func AllowAllNetAccess(op string) bool { return true }

// AllowAllDial is a WASIConfig.Dial that allows every outbound connection.
func AllowAllDial(network, host, ip string, port int) bool { return true }

// AllowAllResolve is a WASIConfig.Resolve that allows every name lookup.
func AllowAllResolve(host string) bool { return true }

// AllowAllExec is a WASIConfig.Exec that allows every process spawn.
func AllowAllExec(path string, argv []string) bool { return true }

// HostWASIConfig returns the configuration of a guest that has what the host
// process has: os.Args, os.Environ(), os.Stdin/Stdout/Stderr, the whole host
// filesystem (what HostFS("/") returns), time.Local as its time zone, and every
// socket operation, outbound connection, name lookup and process spawn allowed.
// Its Process is nil, the isolated one: HostProcess may fail, so a guest has
// the host process's identity only when the embedder sets it.
func HostWASIConfig() WASIConfig {
	return WASIConfig{
		Args:      os.Args,
		Env:       os.Environ(),
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		FS:        osFS{},
		NetAccess: AllowAllNetAccess,
		Dial:      AllowAllDial,
		Resolve:   AllowAllResolve,
		Exec:      AllowAllExec,
		LocalZone: time.Local,
	}
}

// WasiStubs is the default Go-native implementation of wasi_snapshot_preview1.
// State is owned per-Module via NewWithWASI / NewWASI.
type WasiStubs struct {
	mu sync.Mutex

	// cfg is the configuration the instance was built from (NewWASI). It
	// never changes. Its filesystem and standard streams are read through
	// fs, stdin, stdout and stderr, which give a nil one what it stands
	// for.
	cfg WASIConfig
	// fdTable maps every open guest fd, 0/1/2 included, to its entry. Use
	// it through fdsLocked: nil means the table has not been set up yet,
	// which is how a WasiStubs built as a bare struct literal starts.
	fdTable   map[int32]*wasiOpen
	monoStart time.Time
	// resolvedHosts maps a resolved dotted-quad IP back to the host name the
	// guest looked it up under (populated by Sock_getaddrinfo, read by
	// Sock_connect), so the dial hook can be given the host. Guarded by mu.
	resolvedHosts map[string]string
	// procs tracks the processes this instance may wait for — host
	// processes spawned via Proc_spawn and embedder-run processes
	// registered via NewProc — keyed by the pid handed back to the guest.
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
	// umask is the guest's file mode creation mask once it has set one
	// (Proc_umask); nil means the Umask of the Process applies. It is
	// per instance because every instance is a process of its own to the
	// guest. Use it through createMode. Guarded by mu.
	umask *os.FileMode
	// zoneTZ is the last TZ value the guest named and zone its zone,
	// resolved (nil before the first); see zoneMoment. Guarded by mu.
	zoneTZ string
	zone   *wasiZone
	// cloexec holds the descriptor numbers the guest has marked
	// close-on-exec (Fd_cloexec). A number that is given to a new
	// descriptor starts unmarked. Guarded by mu.
	cloexec map[int32]bool
	// preopenReplaced is set once a descriptor has been put at
	// wasiPreopenFD, which then no longer names the root (preopened).
	preopenReplaced atomic.Bool
}

// wasiProc is a process the guest can wait for: a host process spawned by
// Proc_spawn (cmd != nil), or a process the embedder runs itself (NewProc)
// (cmd == nil). Whoever runs the process publishes the encoded POSIX status
// and closes done, so Proc_wait can support both the blocking (options 0)
// and non-blocking (WNOHANG) forms without holding the WasiStubs lock across
// the child's lifetime.
type wasiProc struct {
	cmd    *exec.Cmd
	done   chan struct{}
	status int32 // POSIX wait status, valid once done is closed
	// kill delivers a signal to an embedder-run process. nil when the
	// embedder gave none. It is not changed after NewProc.
	kill func(sig int32) error
}

// wasiPIDs hands out pid tokens. One is shared by every WasiStubs of a fork
// family, each of which has its own lock, hence the separate mutex.
type wasiPIDs struct {
	mu sync.Mutex
	// next is the token handed out next.
	next int32
}

// alloc returns the next unused pid token that is none of reserved.
func (p *wasiPIDs) alloc(reserved ...int32) int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	for slices.Contains(reserved, p.next) {
		p.next++
	}
	pid := p.next
	p.next++
	return pid
}

// wasiFirstPID is the first pid token a fresh instance hands out.
const wasiFirstPID int32 = 1000

// NewWASI returns a WasiStubs whose guest has what cfg gives it (see
// WASIConfig).
func NewWASI(cfg WASIConfig) *WasiStubs {
	cfg.Args = append([]string(nil), cfg.Args...)
	cfg.Env = append([]string(nil), cfg.Env...)
	return &WasiStubs{cfg: cfg, monoStart: time.Now()}
}

// fs returns the filesystem of the instance: noFS when the configuration
// names none.
func (w *WasiStubs) fs() FS {
	if w.cfg.FS == nil {
		return noFS{}
	}
	return w.cfg.FS
}

// stdin returns the standard input of the instance: an empty one when the
// configuration names none.
func (w *WasiStubs) stdin() io.Reader {
	if w.cfg.Stdin == nil {
		return strings.NewReader("")
	}
	return w.cfg.Stdin
}

// stdout returns the standard output of the instance: io.Discard when the
// configuration names none.
func (w *WasiStubs) stdout() io.Writer {
	if w.cfg.Stdout == nil {
		return io.Discard
	}
	return w.cfg.Stdout
}

// stderr returns the standard error of the instance: io.Discard when the
// configuration names none.
func (w *WasiStubs) stderr() io.Writer {
	if w.cfg.Stderr == nil {
		return io.Discard
	}
	return w.cfg.Stderr
}

// guestProcess returns the Process of the instance: the isolated one when
// the configuration names none. Its methods are called without w.mu held.
func (w *WasiStubs) guestProcess() Process {
	if w.cfg.Process == nil {
		return isolatedProcess{}
	}
	return w.cfg.Process
}

// guestPID returns the pid of the Process of the instance.
func (w *WasiStubs) guestPID() int32 { return w.guestProcess().IDs().PID }

// Fork returns the host state for a forked copy of the guest, with fork(2)
// semantics:
//
//   - the configuration is the same WASIConfig, its Process included, and
//     the clock origin, the file mode creation mask and the zone of the
//     last TZ value (see zoneMoment) are the same;
//   - the fd table has the same fd numbers — an fd closed in w, fd 0, 1 or
//     2 included, is closed in the result — and each slot refers to the SAME
//     open descriptor as the corresponding slot of w, so the two instances
//     share the file offset, and the underlying file, connection or listener
//     is closed only when the last slot referring to it, in any instance, is
//     closed;
//   - the process table is empty: a child does not inherit its parent's
//     children. Pid tokens stay unique across w, the result and everything
//     later forked from either.
//
// The result is independent of w from then on (its own lock, its own fd
// numbering) and is meant to back a second module instance running on
// another goroutine. Release its descriptors with CloseAll when that instance
// is done.
func (w *WasiStubs) Fork() *WasiStubs {
	w.mu.Lock()
	defer w.mu.Unlock()
	child := &WasiStubs{
		cfg:       w.cfg,
		fdTable:   make(map[int32]*wasiOpen, len(w.fdsLocked())),
		monoStart: w.monoStart,
		procs:     map[int32]*wasiProc{},
		pids:      w.pidsLocked(),
		zoneTZ:    w.zoneTZ,
		zone:      w.zone,
	}
	child.preopenReplaced.Store(w.preopenReplaced.Load())
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
	return child
}

// CloseAll closes every fd of this instance, as if the guest had called
// fd_close on each: a descriptor shared with another slot or another instance
// (dup, Fork) stays open until its last reference goes. It disposes of the
// host state of a finished instance.
// Calling it again is a no-op. The close errors are joined.
func (w *WasiStubs) CloseAll() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	for fd, op := range w.fdsLocked() {
		err = errors.Join(err, closeWasiOpen(op))
		delete(w.fdsLocked(), fd)
	}
	return err
}

// Fd_closefrom is a NON-STANDARD host import (module
// wasip1_posix_extension, name "fd_closefrom") backing closefrom(): it
// closes every fd numbered lowFd or higher, each as fd_close would. Returns
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
// table entry and is never handed out for a new descriptor, unless there
// is no root directory (see preopened).
const wasiPreopenFD int32 = 3

// wasiRootFD is a second number of the preopened root directory: the path
// calls take it for the root, and fd_fdstat_get and fd_filestat_get
// describe the root under it. No descriptor ever has it: the numbers of
// descriptors are below it.
const wasiRootFD int32 = 0x7ffffff0

// preopened reports whether fd names the preopened root directory, which
// an instance whose configuration names no filesystem does not have. Once
// fd_dup2 or fd_renumber has put a descriptor at wasiPreopenFD, that
// number no longer names it; wasiRootFD still does.
func (w *WasiStubs) preopened(fd int32) bool {
	_, none := w.fs().(noFS)
	return !none && (fd == wasiRootFD || fd == wasiPreopenFD && !w.preopenReplaced.Load())
}

// fdsLocked returns the fd table. On first use it sets the table up with
// fds 0, 1 and 2 referring to the instance's stdin, stdout and stderr; from
// then on those are ordinary slots that the guest can close, dup and reuse.
// Caller holds w.mu.
func (w *WasiStubs) fdsLocked() map[int32]*wasiOpen {
	if w.fdTable == nil {
		w.fdTable = map[int32]*wasiOpen{
			0: {stdio: 1},
			1: {stdio: 2},
			2: {stdio: 3},
		}
	}
	return w.fdTable
}

// openLocked returns the entry the guest knows as descriptor fd, or nil
// when it has none. Caller holds w.mu.
func (w *WasiStubs) openLocked(fd int32) *wasiOpen {
	return w.fdsLocked()[fd]
}

// addFDLocked stores op under the lowest fd number not in use, as POSIX
// requires of open, pipe, dup, socket and accept, and returns that number.
// Caller holds w.mu.
func (w *WasiStubs) addFDLocked(op *wasiOpen) int32 {
	// From 0 there is a free number: the table would have to hold an
	// entry for every number below wasiRootFD.
	fd, _ := w.addFDFromLocked(op, 0)
	return fd
}

// addFDFromLocked enters op under the lowest free number that is at least
// min (fcntl's F_DUPFD) and below wasiRootFD, and reports whether there
// was one.
func (w *WasiStubs) addFDFromLocked(op *wasiOpen, min int32) (int32, bool) {
	fds := w.fdsLocked()
	for fd := min; fd < wasiRootFD; fd++ {
		if _, used := fds[fd]; !used && !w.preopened(fd) {
			fds[fd] = op
			delete(w.cloexec, fd)
			return fd, true
		}
	}
	return -1, false
}

// pidsLocked returns the pid allocator, creating it on first use. Caller
// holds w.mu.
func (w *WasiStubs) pidsLocked() *wasiPIDs {
	if w.pids == nil {
		w.pids = &wasiPIDs{next: wasiFirstPID}
	}
	return w.pids
}

// addProcLocked registers proc under a fresh pid token, as a process this
// instance waits for. The token is neither the pid nor the ppid of ids, the
// ids of the Process. Caller holds w.mu.
func (w *WasiStubs) addProcLocked(proc *wasiProc, ids ProcessIDs) int32 {
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	pid := w.pidsLocked().alloc(ids.PID, ids.PPID)
	w.procs[pid] = proc
	return pid
}

// dropProcLocked removes a process from this instance's table: it has been
// waited for. Caller holds w.mu.
func (w *WasiStubs) dropProcLocked(pid int32) {
	delete(w.procs, pid)
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
	w.mu.Unlock()
}

// NewProc registers a process that the embedder runs itself (not a host
// process started by Proc_spawn) so the guest can wait for it like any other
// child. It returns the pid token to hand to the guest, and exited, which
// the embedder calls with the POSIX wait status when the process ends:
// (code&0xff)<<8 for a normal exit, the signal number in the low 7 bits for
// a death by signal. exited may be called from any goroutine; only its first
// call has an effect.
//
// kill, when non-nil, delivers a signal to the process. It is kept with the
// process; the runtime sends it none.
func (w *WasiStubs) NewProc(kill func(sig int32) error) (pid int32, exited func(status int32)) {
	proc := &wasiProc{done: make(chan struct{}), kill: kill}
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	pid = w.addProcLocked(proc, ids)
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
// name "proc_spawn") that a guest's posix_spawn() can call. It spawns a
// HOST process: path is the executable, argv/envp are NUL-terminated char**
// in linear memory. The child inherits the interpreter's
// stdin/stdout/stderr. The new pid token is written at pidOutPtr. Returns 0
// or a negative errno.
//
// Only stdio inheritance is supported today (no fd remapping / pipes), which
// covers subprocess.run/call with default streams; capture_output via host
// pipes is a follow-up.
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
	// syscall), so the guest passes it explicitly; the child must start
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
	hook := w.cfg.Exec
	cin := w.childReaderLocked(stdinFd)
	cout := w.childWriterLocked(stdoutFd, w.stdout())
	cerr := w.childWriterLocked(stderrFd, w.stderr())
	w.mu.Unlock()
	if hook == nil || !hook(path, argv) {
		return -_wasiEACCES
	}

	cmd := exec.Command(path)
	if len(argv) > 0 {
		cmd.Args = argv
	} else {
		cmd.Args = []string{path}
	}
	if cwd != "" {
		cmd.Dir = cwd
	}
	// Sandbox: the child sees ONLY the guest-provided environment; a nil
	// (NULL envp) must NOT fall through to the host process environment.
	cmd.Env = env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	// stdin/stdout/stderr are the interpreter streams (inherited) or a guest
	// pipe end. A pipe end's dynamic type is *os.File, so Go's exec passes the
	// fd straight to the child; capture works by the guest reading the pipe's
	// other end via Fd_read.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = cin, cout, cerr
	if err := cmd.Start(); err != nil {
		return -mapExecError(err)
	}

	proc := &wasiProc{cmd: cmd, done: make(chan struct{})}
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	pid := w.addProcLocked(proc, ids)
	w.mu.Unlock()
	go func() {
		werr := cmd.Wait()
		status := encodeWaitStatus(cmd.ProcessState)
		// A non-zero exit or signal surfaces as *exec.ExitError and is the
		// normal path (status already encoded from ProcessState above). Any
		// OTHER error means the wait itself failed; report a 127 exit.
		var exitErr *exec.ExitError
		if werr != nil && !errors.As(werr, &exitErr) {
			status = int32(127) << 8
		}
		w.finishProc(proc, status)
	}()

	binary.LittleEndian.PutUint32(out, uint32(pid))
	return _wasiESUCCESS
}

// Fd_cloexec is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_cloexec") backing fcntl's F_GETFD and F_SETFD: the close-on-exec
// flag of a descriptor. The flag as it was is written at oldPtr (u32, 0
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
// table like a read of it: the standard stream, file or pipe end it refers
// to, and nil — no stream, which os/exec turns into the null device — when
// the fd is closed or cannot be read. The fd of a socket asks for the
// instance's stdin too. Caller holds w.mu.
func (w *WasiStubs) childReaderLocked(fd int32) io.Reader {
	if fd < 0 {
		return w.stdin()
	}
	src, op := w.fdSrcLocked(fd)
	if op.socket() {
		return w.stdin()
	}
	return src
}

// childWriterLocked is the stdout/stderr counterpart of childReaderLocked;
// inherited is the instance stream a negative fd asks for.
func (w *WasiStubs) childWriterLocked(fd int32, inherited io.Writer) io.Writer {
	if fd < 0 {
		return inherited
	}
	dst, op := w.fdDstLocked(fd)
	if op.socket() {
		return inherited
	}
	return dst
}

// Pipe is a NON-STANDARD host import (module wasi_snapshot_preview1, name
// "pipe") that a guest's pipe()/pipe2() can call. It creates a host OS pipe
// and registers both ends as guest fds, writing [readFd, writeFd] (two i32)
// at fdsOutPtr. The guest reads the read end via Fd_read; the write end is
// given to a child as its stdout/stderr via Proc_spawn, so subprocess.run can
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
	r, wr, err := os.Pipe()
	if err != nil {
		return -mapOSError(err)
	}
	w.mu.Lock()
	rfd := w.addFDLocked(&wasiOpen{f: r, noWrite: true})
	wfd := w.addFDLocked(&wasiOpen{f: wr, noRead: true})
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out[0:], uint32(rfd))
	binary.LittleEndian.PutUint32(out[4:], uint32(wfd))
	return _wasiESUCCESS
}

// Proc_wait is a NON-STANDARD host import (name "proc_wait") that a guest's
// waitpid() can call. It waits for the process token pid and writes the
// POSIX wait status at statusOutPtr. options is the waitpid() options mask;
// bit 0 (WNOHANG) makes it return without blocking when the child is still
// running (the guest sees the documented "0 means no child ready" result,
// signalled by writing pid 0 — encoded by returning EAGAIN). Returns 0, or a
// negative errno (ECHILD for an unknown pid).
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
	} else {
		<-proc.done
	}
	w.mu.Lock()
	if w.procs[pid] != proc {
		// Another waiter was given the process while this one waited.
		w.mu.Unlock()
		return -_wasiECHILD
	}
	w.dropProcLocked(pid)
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(proc.status))
	return _wasiESUCCESS
}

// Proc_wait_any is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_wait_any") backing wait() and
// waitpid(-1): it waits for ANY process of this instance — spawned by
// Proc_spawn or run by the embedder (NewProc) — to finish, removes it from
// the process table, and writes its pid token at pidOutPtr and its POSIX
// wait status at statusOutPtr. When several have finished, the one with the
// lowest pid is reported. options is the waitpid() options mask; with bit 0
// (WNOHANG) the call does not block. Returns 0, or a negative errno: ECHILD
// when the instance has no process at all, EAGAIN when WNOHANG is set and
// none of them has finished yet.
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
		<-finished
	}
}

// encodeWaitStatus turns a Go ProcessState into a POSIX wait status int (the
// raw value os.waitstatus_to_exitcode decodes): a normal exit N becomes
// (N&0xff)<<8 (WIFEXITED); a signal becomes the low-7-bits signal number
// (WIFSIGNALED).
func encodeWaitStatus(st *os.ProcessState) int32 {
	if st == nil {
		return 0
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			return int32(ws.Signal()) & 0x7f
		}
		return int32(ws.ExitStatus()&0xff) << 8
	}
	code := st.ExitCode()
	if code < 0 {
		code = 127
	}
	return int32(code&0xff) << 8
}

// mapExecError maps an exec.Command Start() failure to a wasi errno.
func mapExecError(err error) int32 {
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return _wasiENOENT
	case errors.Is(err, fs.ErrPermission):
		return _wasiEACCES
	default:
		return _wasiENOENT
	}
}

// Sock_getaddrinfo is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_getaddrinfo") that a guest's getaddrinfo() can call. It reads the
// host string at (nodePtr,nodeLen), consults the resolve whitelist, resolves it
// to an IPv4 address via Go's resolver (numeric IPs pass through), and writes
// the 4-byte network-order address at outPtr. Returns 0 on success or a negative
// POSIX-ish errno (the caller maps it to an EAI_* code).
func (w *WasiStubs) Sock_getaddrinfo(m *Module, nodePtr, nodeLen, outPtr int32) int32 {
	host := ""
	if nodeLen > 0 {
		b := w.memSlice(m, nodePtr, nodeLen)
		if b == nil {
			return -_wasiEFAULT
		}
		host = string(b)
	}
	out := w.memSlice(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	if host == "" {
		binary.LittleEndian.PutUint32(out, 0) // INADDR_ANY
		return _wasiESUCCESS
	}
	w.mu.Lock()
	hook := w.cfg.Resolve
	w.mu.Unlock()
	if hook == nil || !hook(host) {
		return -_wasiEACCES
	}
	// Numeric IPv4 fast path (avoids a resolver call and works offline).
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out[0], out[1], out[2], out[3] = v4[0], v4[1], v4[2], v4[3]
			w.recordResolvedHost(v4, host)
			return _wasiESUCCESS
		}
		return -_wasiEAFNOSUPPORT // IPv6 not supported by this import
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
	w.recordResolvedHost(v4, host)
	return _wasiESUCCESS
}

// recordResolvedHost remembers that host resolved to v4, so a later Sock_connect
// to that IP can hand the dial hook the host name it was looked up under.
func (w *WasiStubs) recordResolvedHost(v4 net.IP, host string) {
	ip := fmt.Sprintf("%d.%d.%d.%d", v4[0], v4[1], v4[2], v4[3])
	w.mu.Lock()
	if w.resolvedHosts == nil {
		w.resolvedHosts = make(map[string]string)
	}
	w.resolvedHosts[ip] = host
	w.mu.Unlock()
}

// allowedPath returns the name the FS is given for the guest path name and
// whether the FS policy hook allows it. With a hook, the hook is asked
// about rootRelative(name) and the FS is given that same name (with the
// trailing "/" of name), so what was approved is what is opened; without
// one the FS is given name as the guest wrote it, without a leading "/".
// Callers must NOT hold w.mu.
func (w *WasiStubs) allowedPath(name string, write bool) (string, bool) {
	w.mu.Lock()
	hook := w.cfg.FSAccess
	w.mu.Unlock()
	if hook == nil {
		return strings.TrimLeft(name, "/"), true // not path.Clean: the host resolves ".." after symbolic links
	}
	clean := rootRelative(name)
	allowed := hook(clean, write)
	// A trailing "/" or "/." still asks for a directory; path.Clean drops it.
	if (strings.HasSuffix(name, "/") || path.Base(name) == ".") && clean != "." {
		clean += "/"
	}
	return clean, allowed
}

// rootRelative returns the guest path name cleaned as chroot(2) sees it:
// relative to the root, which ".." of the root is, and "." for the root
// itself.
func rootRelative(name string) string { return path.Join(".", path.Clean("/"+name)) }

// checkNet consults the network policy hook; without one every operation
// is denied. Returns true when the operation is permitted. Callers must
// NOT hold w.mu.
func (w *WasiStubs) checkNet(op string) bool {
	w.mu.Lock()
	hook := w.cfg.NetAccess
	w.mu.Unlock()
	return hook != nil && hook(op)
}

// guestMemory returns the guest's linear memory as the guest sees it: the
// first memory.size bytes (memSize) of the module's memory slice. Every
// bound the stubs put on a guest address comes from here, so that an
// address at or past memory.size is refused as wasm refuses it. For a
// shared memory the slice spans the memory's whole ceiling from the start
// and only memSize says how much of it the guest may touch; another agent
// may grow the memory at any moment, which raises memSize and leaves the
// slice and its backing array as they are, so a view taken here stays
// valid. A memory the caller handed to the constructor (NewWithMemory,
// NewFromSnapshot) may be longer than memSize in the same way, until
// memory.grow reslices it. Any other memory's slice is memory.size long.
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
//
// A memory64 guest passes every argument of the standard imports as a
// pointer-width i64. Codegen binds such a module's imports to the methods
// named <Name>64 (importMethodName); a wasm32 module binds the ones without
// the suffix. The two methods of an import are thin wrappers over one body,
// which takes the guest's addresses as uint64 — a wasm32 guest's
// zero-extended (zext), a memory64 guest's as they are, never truncated.
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
	_wasiESUCCESS     int32 = 0
	_wasiE2BIG        int32 = 1
	_wasiEACCES       int32 = 2
	_wasiEAFNOSUPPORT int32 = 5
	_wasiEAGAIN       int32 = 6
	_wasiEBADF        int32 = 8
	_wasiECHILD       int32 = 12
	_wasiECONNREFUSED int32 = 14
	_wasiEISCONN      int32 = 30
	_wasiEBUSY        int32 = 10
	_wasiEEXIST       int32 = 20
	_wasiEFAULT       int32 = 21
	_wasiEFBIG        int32 = 22
	_wasiEHOSTUNREACH int32 = 23
	_wasiENETUNREACH  int32 = 40
	_wasiEINVAL       int32 = 28
	_wasiEIO          int32 = 29
	_wasiEISDIR       int32 = 31
	_wasiELOOP        int32 = 32
	_wasiEMFILE       int32 = 33
	_wasiENOENT       int32 = 44
	_wasiENOSPC       int32 = 51
	_wasiENOTCONN     int32 = 53
	_wasiENOTDIR      int32 = 54
	_wasiENOTEMPTY    int32 = 55
	_wasiENOTSOCK     int32 = 57
	_wasiENOTSUP      int32 = 58
	_wasiENOSYS       int32 = 52
	_wasiENXIO        int32 = 60
	_wasiEPERM        int32 = 63
	_wasiEPIPE        int32 = 64
	_wasiERANGE       int32 = 68
	_wasiESPIPE       int32 = 70
	_wasiESRCH        int32 = 71
	_wasiETIMEDOUT    int32 = 73
)

// mapOSError turns an os/filesystem error into a wasi errno, so any
// os.PathError surfaces as the appropriate guest-visible code instead of
// a coarse EIO.
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
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return _wasiENOENT
	case errors.Is(err, syscall.ENOTEMPTY):
		// before fs.ErrExist, which ENOTEMPTY is as well
		return _wasiENOTEMPTY
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
	case errors.Is(err, syscall.EBADF), errors.Is(err, fs.ErrClosed), errors.Is(err, net.ErrClosed):
		return _wasiEBADF
	case errors.Is(err, syscall.ENOSPC):
		return _wasiENOSPC
	case errors.Is(err, syscall.EFBIG):
		return _wasiEFBIG
	case errors.Is(err, syscall.EAGAIN):
		return _wasiEAGAIN
	case errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrClosedPipe):
		return _wasiEPIPE
	case errors.Is(err, syscall.ENXIO):
		return _wasiENXIO
	case errors.Is(err, syscall.ESPIPE):
		return _wasiESPIPE
	case errors.Is(err, syscall.ENOSYS):
		// before errors.ErrUnsupported, which ENOSYS is as well
		return _wasiENOSYS
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
	return w.putStrVec(m, abi, argv, argvBuf, w.cfg.Args)
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
	return w.putStrVecSizes(m, abi, argcPtr, argvBufLenPtr, w.cfg.Args)
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
	return w.putStrVec(m, abi, envv, envBuf, w.cfg.Env)
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
	return w.putStrVecSizes(m, abi, envcPtr, envBufLenPtr, w.cfg.Env)
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

func (w *WasiStubs) Clock_res_get(m *Module, clockID int32, resPtr int32) int32 {
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

// clockNanos is the layout-independent body of clock_time_get, shared
// by the wasm32 and wasm64 bindings.
func (w *WasiStubs) clockNanos(clockID int32) (uint64, int32) {
	switch clockID {
	case 0: // CLOCK_REALTIME
		return uint64(time.Now().UnixNano()), _wasiESUCCESS
	case 1: // CLOCK_MONOTONIC
		w.mu.Lock()
		nanos := uint64(time.Since(w.monoStart).Nanoseconds())
		w.mu.Unlock()
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
	conn := op.conn
	op.mu.Unlock()
	var err error
	if op.f != nil {
		err = errors.Join(err, op.f.Close())
	}
	if conn != nil && op.connClosed.CompareAndSwap(false, true) {
		err = errors.Join(err, conn.Close())
	}
	if op.listener != nil && op.connClosed.CompareAndSwap(false, true) {
		err = errors.Join(err, op.listener.Close())
	}
	return err
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

// fdstatFill writes the 24-byte fdstat for fd into out — the shared
// body of the 32- and 64-bit Fd_fdstat_get bindings (the struct holds
// no pointers, so the layout is width-independent).
func (w *WasiStubs) fdstatFill(fd int32, out []byte) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var ftype byte = 4 // regular file
	var fdflags uint16
	// Every right is granted (the WASIConfig decides what the guest may
	// reach), except that the rights to read and to write say what the
	// descriptor is open for, and the preopened root has only the rights
	// of the calls it answers (wasiRootRights).
	rights := ^uint64(0)
	if op := w.openLocked(fd); op != nil {
		if read, write := op.access(); !read {
			rights &^= wasiRightFdRead | wasiRightFdReaddir
		} else if !write {
			rights &^= wasiRightFdWrite
		}
		op.mu.Lock()
		if op.stdio != 0 {
			ftype = 2 // a standard stream is a character device
		} else if op.isDir {
			ftype = 3
		} else if op.conn != nil || op.listener != nil || op.isSocket {
			ftype = 6 // socket_stream
		}
		fdflags = uint16(op.fdflags)
		op.mu.Unlock()
	} else if w.preopened(fd) {
		ftype = 3 // preopen "/"
		rights = wasiRootRights
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
	wasiRightFdWrite   uint64 = 1 << 6
	wasiRightFdReaddir uint64 = 1 << 14
)

// wasiRootRights are the rights of the preopened root, which has no open
// file: the path calls (path_create_directory 9, path_create_file 10,
// path_link_source 11, path_link_target 12, path_open 13, path_readlink
// 15, path_rename_source 16, path_rename_target 17, path_filestat_get 18,
// path_filestat_set_size 19, path_filestat_set_times 20, path_symlink 24,
// path_remove_directory 25, path_unlink_file 26) and fd_filestat_get 21.
const wasiRootRights uint64 = 1<<9 | 1<<10 | 1<<11 | 1<<12 | 1<<13 | 1<<15 |
	1<<16 | 1<<17 | 1<<18 | 1<<19 | 1<<20 | 1<<21 | 1<<24 | 1<<25 | 1<<26

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
// does not enforce them: what the guest may reach is decided by the
// WASIConfig (its FS and hooks), not by rights. WASI programs that
// succeed with maximal rights (per Fd_fdstat_get) get the same ESUCCESS
// here.
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
	return w.filestatOf(fd, out)
}

// filestatOf writes the filestat of Fd_filestat_get for fd to out and
// returns a wasi errno.
func (w *WasiStubs) filestatOf(fd int32, out []byte) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	root := op == nil && w.preopened(fd)
	fsys := w.fs()
	w.mu.Unlock()
	if op == nil && !root {
		return _wasiEBADF
	}
	if root {
		st, err := fsys.Stat(".")
		if err != nil {
			return mapOSError(err)
		}
		writeFilestat(out, st)
		return _wasiESUCCESS
	}
	if op.f == nil {
		fi, err := w.streamFileInfo(op)
		if err != nil {
			return mapOSError(err)
		}
		if fi != nil {
			// A standard stream that is a file of the host is that
			// file: a terminal, a pipe, a regular file it was
			// redirected to.
			writeFilestat(out, fi)
			return _wasiESUCCESS
		}
		// Synthesise a minimal stat for a socket or a standard stream
		// the embedder supplied.
		for i := range out {
			out[i] = 0
		}
		// A socket is a stream socket (6). An embedder's stream is a
		// pipe to the guest, which WASI has no file type for: it stays
		// "unknown" (0) here, and Fd_filestat_ext names it.
		if op.socket() {
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
	if op.noWrite {
		// what ftruncate of linux and darwin gives for a descriptor not
		// open for writing
		return _wasiEINVAL
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
	fsys := w.fs()
	w.mu.Unlock()
	// The times are set by the path the descriptor was opened under, which
	// a pipe end has none of (an empty path names the root, a directory).
	if op == nil || op.f == nil || op.path == "" && !op.isDir {
		return _wasiEBADF
	}
	name, ok := w.allowedPath(op.path, true)
	if !ok {
		return _wasiEACCES
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
	// A file that sets its own times is changed through the descriptor,
	// any other by its path.
	if f, ok := op.f.(interface {
		Chtimes(atime, mtime time.Time) error
	}); ok {
		return mapOSError(f.Chtimes(atime, mtime))
	}
	if err := fsys.Chtimes(name, atime, mtime); err != nil {
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
	if fd != wasiPreopenFD || !w.preopened(fd) {
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
	if fd != wasiPreopenFD || !w.preopened(fd) {
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
		if op.socket() {
			return _wasiENOTCONN
		}
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nread is a __wasi_size_t.
	nreadSlice := w.memBytes(m, nreadPtr, abi.wordSize())
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	n, errno := readVec(src, bufs, op.regular)
	abi.putWord(nreadSlice, n)
	return op.afterShutdown(errno, false)
}

// wasiMaxIovecs is the most entries a ciovec/iovec array may have.
const wasiMaxIovecs = 1 << 20

// iovecSlices resolves a ciovec/iovec array (iovsLen entries at iovs of a
// guest pointer and a __wasi_size_t each: {u32 ptr, u32 len} for a wasm32
// guest, {u64 ptr, u64 len} for a memory64 one) into the backing memory
// windows. Every entry is validated before any I/O happens, so a bad iovec
// faults the whole call instead of after a partial transfer. An array of
// more than wasiMaxIovecs entries is refused.
func (w *WasiStubs) iovecSlices(m *Module, abi wasiABI, iovs, iovsLen uint64) ([][]byte, bool) {
	// Bound the count before multiplying and before allocating a window
	// per entry, so that a pathological iovsLen can neither wrap nor size
	// a host allocation.
	stride := 2 * abi.wordSize()
	if iovsLen > wasiMaxIovecs {
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
// (EOF included) or short read; returns the bytes read, or the errno of
// an error other than EOF that left nothing read. Shared by fd_read,
// fd_pread and sock_recv. Unless whole is set (src is a regular file), it
// also stops after the first read that returned data: reading on from a
// pipe, a terminal or a socket would wait for data that has not come.
func readVec(src io.Reader, bufs [][]byte, whole bool) (uint64, int32) {
	var total uint64
	for _, buf := range bufs {
		n, err := src.Read(buf)
		total += uint64(n)
		if err != nil && total == 0 && !errors.Is(err, io.EOF) {
			return 0, mapOSError(err)
		}
		if err != nil || n < len(buf) || (n > 0 && !whole) {
			break
		}
	}
	return total, _wasiESUCCESS
}

// writeVec drains bufs into dst in order, stopping at the first failed
// write; returns the bytes written, or the errno of an error that left
// nothing written. Shared by fd_write and fd_pwrite.
func writeVec(dst io.Writer, bufs [][]byte) (uint64, int32) {
	var total uint64
	for _, buf := range bufs {
		n, err := dst.Write(buf)
		total += uint64(n)
		if err != nil && total == 0 {
			return 0, mapOSError(err)
		}
		if err != nil {
			break
		}
	}
	return total, _wasiESUCCESS
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
		return w.stdin(), op
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
		return w.stdout(), op
	case 3:
		return w.stderr(), op
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
	if offset < 0 {
		return _wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op.socket() {
		return _wasiESPIPE
	}
	if op == nil || op.f == nil || op.noRead {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nread is a __wasi_size_t.
	nreadSlice := w.memBytes(m, nreadPtr, abi.wordSize())
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	n, errno := readVec(io.NewSectionReader(op.f, offset, 1<<63-1), bufs, true)
	abi.putWord(nreadSlice, n)
	return errno
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
	if offset < 0 {
		return _wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op.socket() {
		return _wasiESPIPE
	}
	if op == nil || op.f == nil || op.noWrite {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nwritten is a __wasi_size_t.
	nwSlice := w.memBytes(m, nwrittenPtr, abi.wordSize())
	if !ok || nwSlice == nil {
		return _wasiEFAULT
	}
	n, errno := writeVec(io.NewOffsetWriter(op.f, offset), bufs)
	abi.putWord(nwSlice, n)
	return errno
}

func (w *WasiStubs) Fd_seek(m *Module, fd int32, offset int64, whence, newOffPtr int32) int32 {
	return w.fdSeek(m, fd, offset, int64(whence), zext(newOffPtr))
}

// Fd_seek64 is Fd_seek for a memory64 guest.
func (w *WasiStubs) Fd_seek64(m *Module, fd, offset, whence, newOffPtr int64) int32 {
	return w.fdSeek(m, int32(fd), offset, whence, uint64(newOffPtr))
}

// fdSeek is the body of Fd_seek and Fd_seek64.
func (w *WasiStubs) fdSeek(m *Module, fd int32, offset, whence int64, newOffPtr uint64) int32 {
	out := w.memBytes(m, newOffPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op.socket() {
		return _wasiESPIPE
	}
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	if whence < 0 || whence > 2 {
		return _wasiEINVAL
	}
	n, err := op.f.Seek(offset, int(whence))
	if err != nil {
		// An error without a number of its own (of a File other than the
		// host's) is EINVAL, which is what a seek can fail with.
		return seekErrno(err, _wasiEINVAL)
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
	if op.socket() {
		return _wasiESPIPE
	}
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	n, err := op.f.Seek(0, 1) // SEEK_CUR
	if err != nil {
		return seekErrno(err, _wasiEIO)
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
		if op.socket() {
			// a write of a socket without a connection, as on linux
			return _wasiEPIPE
		}
		return _wasiEBADF
	}
	n, errno := writeVec(dst, bufs)
	abi.putWord(nwrittenSlice, n)
	return op.afterShutdown(errno, true)
}

// socketConn returns the entry of the socket fd and its connection, or
// the errno of an fd without one: EBADF for an fd that is not open,
// ENOTSOCK for one that is not a socket (the preopened directories
// included), ENOTCONN for a socket without a connection, whose entry it
// returns as well.
func (w *WasiStubs) socketConn(fd int32) (*wasiOpen, net.Conn, int32) {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	switch {
	case op == nil && w.preopened(fd), op != nil && !op.socket():
		return nil, nil, _wasiENOTSOCK
	case op == nil:
		return nil, nil, _wasiEBADF
	}
	if conn := op.netConn(); conn != nil {
		return op, conn, _wasiESUCCESS
	}
	return op, nil, _wasiENOTCONN
}

// errnoOr returns the wasi errno of err. It returns fallback for an error
// without an error number of the host, and for a number that mapOSError
// turns into EIO although the number is not EIO itself.
func errnoOr(err error, fallback int32) int32 {
	var number syscall.Errno
	if errno := mapOSError(err); errors.As(err, &number) && (errno != _wasiEIO || number == syscall.EIO) {
		return errno
	}
	return fallback
}

// seekErrno is errnoOr for the error of a File's Seek. os.File.Seek of a
// directory it has read returns EISDIR of its own after the host's seek
// succeeded; lseek has no such errno, so that error is the fallback too.
func seekErrno(err error, fallback int32) int32 {
	if errors.Is(err, syscall.EISDIR) {
		return fallback
	}
	return errnoOr(err, fallback)
}

// afterShutdown returns the errno of a transfer on op that ended with
// errno: once Sock_shutdown has closed the connection, which has no half
// close, a read that fails gets the end of the stream and a write that
// fails EPIPE, whichever halves the shutdown asked for.
func (op *wasiOpen) afterShutdown(errno int32, write bool) int32 {
	switch {
	case errno == _wasiESUCCESS || !op.shutClosed.Load():
		return errno
	case write:
		return _wasiEPIPE
	}
	return _wasiESUCCESS
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
	if offset < 0 || length <= 0 {
		return _wasiEINVAL
	}
	if op.noWrite {
		return _wasiEBADF
	}
	end := offset + length
	if end < 0 {
		return _wasiEFBIG
	}
	// fallocate "reserves" space and never shrinks the file; the portable
	// equivalent is Truncate to offset+length when that is past the end.
	st, err := op.f.Stat()
	if err != nil {
		return mapOSError(err)
	}
	if end <= st.Size() {
		return _wasiESUCCESS
	}
	if err := op.f.Truncate(end); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_allocate64 is Fd_allocate for a memory64 guest.
func (w *WasiStubs) Fd_allocate64(m *Module, fd, offset, length int64) int32 {
	return w.Fd_allocate(m, int32(fd), offset, length)
}

// Path_chmod is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "path_chmod") that a guest's chmod() can call: WASI preview1 has no
// way to change file modes. The path at (pathPtr,pathLen) is
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
	name, ok := w.allowedPath(string(pathSlice), true)
	if !ok {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if err := fsys.Chmod(name, unixFileMode(uint32(mode))); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Fd_chmod is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_chmod") that a guest's fchmod() can call. Returns 0 or a
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

// Proc_umask is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_umask") backing umask(): it sets the
// instance's file mode creation mask and returns the previous one. The
// mask is taken out of the mode of every file and directory the instance
// creates from then on (createMode), and a forked instance starts with its
// parent's (see Fork). Until the guest sets one, the mask is the Umask of
// the Process (WASIConfig.Process).
//
// What a file then gets is its filesystem's to say. The host's filesystem
// (the default) takes the host process's umask out of the mode as well, as
// it does for every file the process creates: there the instance's mask
// takes bits away and gives none back. MemFS creates with the mode it is
// asked for.
//
// A command started by Proc_spawn does not get the instance's mask: it
// starts with the host process's umask.
func (w *WasiStubs) Proc_umask(m *Module, mask int32) int32 {
	next := os.FileMode(uint32(mask) & 0o777)
	prev := w.guestProcess().Umask().Perm()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.umask != nil {
		prev = *w.umask
	}
	w.umask = &next
	return int32(prev)
}

// Proc_umask64 is Proc_umask for a memory64 guest.
func (w *WasiStubs) Proc_umask64(m *Module, mask int32) int32 {
	return w.Proc_umask(m, mask)
}

// createMode returns the mode the instance's filesystem is asked for when
// the guest creates a file or directory with the requested mode: the
// instance's umask taken out of it.
func (w *WasiStubs) createMode(requested os.FileMode) os.FileMode {
	w.mu.Lock()
	umask := w.umask
	w.mu.Unlock()
	if umask != nil {
		return requested &^ *umask
	}
	return requested &^ w.guestProcess().Umask().Perm()
}

// Path_open_mode is a NON-STANDARD host import (module
// wasip1_posix_extension, name "path_open_mode") backing open(): path_open
// cannot carry the mode argument of open(2), so every file it creates gets
// the default 0666. This one takes the same arguments
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
	fd, errno := w.pathOpenMode(string(pathSlice), dirflags, oflags, fsRightsBase, fdflags, unixFileMode(uint32(mode)))
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(outSlice, uint32(fd))
	return _wasiESUCCESS
}

// Path_create_directory_mode is a NON-STANDARD host import (module
// wasip1_posix_extension, name "path_create_directory_mode") backing
// mkdir(): path_create_directory cannot carry the mode argument of
// mkdir(2). The path is preopen-relative. Returns 0 or a negative errno.
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
	return -w.pathCreateDirectory(string(pathSlice), unixFileMode(uint32(mode)))
}

// pathCreateDirectory creates the directory rel with the requested mode,
// less the instance's umask, and returns a wasi errno.
func (w *WasiStubs) pathCreateDirectory(rel string, mode os.FileMode) int32 {
	name, ok := w.allowedPath(rel, true)
	if !ok {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	// As for a file (pathOpenMode): the host's filesystem takes the host
	// process's umask out of the mode as well, MemFS does not.
	if err := fsys.Mkdir(name, w.createMode(mode)); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// Path_filestat_ext is a NON-STANDARD host import (module
// wasip1_posix_extension, name "path_filestat_ext") that a guest's
// stat/lstat can call: WASI's filestat carries neither permission bits nor
// an owner, and its file types have no FIFO, so the guest merges them in
// from here. The path is preopen-relative; follow selects stat vs lstat
// semantics. Writes the record of wasiFilestatExtSize bytes at outPtr,
// whose mode is the POSIX mode (the file type bits, unixType*, and the low
// twelve mode bits), and returns 0 or a negative errno.
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
	if fd, fi, _, own, errno := w.ownName(string(pathSlice), follow != 0); own {
		switch {
		case errno != _wasiESUCCESS:
			return -errno
		case fi == nil:
			return w.filestatExtOf(fd, out)
		}
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
	}
	name, ok := w.allowedPath(string(pathSlice), false)
	if !ok {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	var fi os.FileInfo
	var err error
	if follow != 0 {
		fi, err = fsys.Stat(name)
	} else {
		fi, err = fsys.Lstat(name)
	}
	if err != nil {
		return -mapOSError(err)
	}
	writeFilestatExt(out, fi)
	return _wasiESUCCESS
}

// Fd_filestat_ext is Path_filestat_ext for an open descriptor (module
// wasip1_posix_extension, name "fd_filestat_ext") that a guest's fstat
// can call. A descriptor that is not a file of the FS backend is
// described as what it is to the guest: a standard stream that is a
// file of the host as that file (a terminal, a pipe, a regular file), a
// stream the embedder supplied as a pipe, a socket as a socket, the
// preopened root as the root directory.
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
	return w.filestatExtOf(fd, out)
}

// filestatExtOf writes the record of Fd_filestat_ext for fd to out and
// returns 0 or a negative errno.
func (w *WasiStubs) filestatExtOf(fd int32, out []byte) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	root := op == nil && w.preopened(fd)
	fsys := w.fs()
	w.mu.Unlock()
	if op == nil && !root {
		return -_wasiEBADF
	}
	if root {
		fi, err := fsys.Stat(".")
		if err != nil {
			return -mapOSError(err)
		}
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
	}
	fi, err := w.opFileInfo(op)
	if err != nil {
		return -mapOSError(err)
	}
	if fi != nil {
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
	}
	mode := unixTypeFIFO | 0o600
	if op.socket() {
		mode = unixTypeSocket | 0o777
	}
	// A descriptor with no file behind it belongs to user and group 0.
	var uid, gid uint32
	clear(out)
	binary.LittleEndian.PutUint32(out[0:], mode)
	binary.LittleEndian.PutUint32(out[4:], uid)
	binary.LittleEndian.PutUint32(out[8:], gid)
	return _wasiESUCCESS
}

// streamFileInfo describes the host file behind an entry that refers to a
// standard stream of the instance, or returns nil when the entry is not a
// standard stream or the stream is not a file of the host (an embedder's
// reader or writer).
func (w *WasiStubs) streamFileInfo(op *wasiOpen) (os.FileInfo, error) {
	file := w.streamFile(op)
	if file == nil {
		return nil, nil
	}
	return file.Stat()
}

// hostStreamLink returns the target of the host's link for the descriptor
// of file (hostFDLink), and whether the host has one.
func hostStreamLink(file *os.File) (string, bool, error) {
	rc, err := file.SyscallConn()
	if err != nil {
		return "", false, err
	}
	var (
		target  string
		ok      bool
		linkErr error
	)
	if err := rc.Control(func(fd uintptr) { target, ok, linkErr = hostFDLink(fd) }); err != nil {
		// Control reports a closed file with an error package os does
		// not export; Stat reports it as os.ErrClosed.
		if _, statErr := file.Stat(); errors.Is(statErr, os.ErrClosed) {
			return "", false, statErr
		}
		return "", false, err
	}
	return target, ok, linkErr
}

// streamFile returns the host file a standard stream of the instance that
// op refers to is, or nil when op is no standard stream or the stream is
// not a file of the host.
func (w *WasiStubs) streamFile(op *wasiOpen) *os.File {
	if op == nil || op.stdio == 0 {
		return nil
	}
	w.mu.Lock()
	var stream any
	switch op.stdio {
	case 1:
		stream = w.stdin()
	case 2:
		stream = w.stdout()
	case 3:
		stream = w.stderr()
	}
	w.mu.Unlock()
	file, _ := stream.(*os.File)
	return file
}

// Fd_path is a NON-STANDARD host import (module wasip1_posix_extension, name
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
	root := op == nil && w.preopened(fd)
	w.mu.Unlock()
	if op == nil && !root {
		return -_wasiEBADF
	}
	name := "/"
	if op != nil {
		if !op.isDir {
			return -_wasiENOTDIR
		}
		name = guestPath(op.path)
	}
	return w.writeWasiRecord(m, []byte(name), bufPtr, bufLen, neededPtr)
}

// guestPath returns name, a path relative to the root, as an absolute path
// of the guest's filesystem. Only "." and empty components go; not
// path.Clean, which would fold "..", and the host resolves ".." after
// symbolic links.
func guestPath(name string) string {
	parts := slices.DeleteFunc(strings.Split(name, "/"), func(part string) bool { return part == "" || part == "." })
	return "/" + strings.Join(parts, "/")
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
// wasi_snapshot_preview1, name "path_filestat_mode") that a guest's
// stat/lstat can call: WASI's filestat carries no permission bits, so
// the guest merges the real mode in from here. The path is
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
	if fd, fi, _, own, errno := w.ownName(string(pathSlice), follow != 0); own {
		switch {
		case errno != _wasiESUCCESS:
			return -errno
		case fi == nil:
			var rec [wasiFilestatExtSize]byte
			if rc := w.filestatExtOf(fd, rec[:]); rc != _wasiESUCCESS {
				return rc
			}
			binary.LittleEndian.PutUint32(out, binary.LittleEndian.Uint32(rec[:])&^unixTypeMask)
			return _wasiESUCCESS
		}
		binary.LittleEndian.PutUint32(out, unixModeBits(fi.Mode()))
		return _wasiESUCCESS
	}
	name, ok := w.allowedPath(string(pathSlice), false)
	if !ok {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	var fi os.FileInfo
	var err error
	if follow != 0 {
		fi, err = fsys.Stat(name)
	} else {
		fi, err = fsys.Lstat(name)
	}
	if err != nil {
		return -mapOSError(err)
	}
	binary.LittleEndian.PutUint32(out, unixModeBits(fi.Mode()))
	return _wasiESUCCESS
}

// Fd_dup is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dup") that a guest's dup() can call: the new fd shares the
// same open descriptor (offset included), and the underlying file closes
// only when the last sharing fd does. Writes the new fd at outPtr.
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
	nfd, ok := w.addFDFromLocked(op, min)
	if !ok {
		return _wasiEMFILE
	}
	op.addRef()
	binary.LittleEndian.PutUint32(out, uint32(nfd))
	return _wasiESUCCESS
}

// Fd_dupfd is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_dupfd") backing fcntl's F_DUPFD: fd_dup, under the lowest free
// number that is at least min. EINVAL for a min that is negative or not
// below the numbers descriptors have (wasiRootFD), EMFILE when no number
// from min on is free.
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
	if min < 0 || min >= wasiRootFD {
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
// name "fd_dup2") that a guest's dup2() can call: to becomes another
// reference to from's descriptor, closing whatever to previously held. A
// descriptor put at fd 3, here or by Fd_renumber, replaces the preopened
// root there for good (see preopened), as POSIX has it: a guest that goes
// on using fd 3 as its root after replacing it has lost that root, as on
// other WASI hosts.
func (w *WasiStubs) Fd_dup2(m *Module, from, to int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := w.openLocked(from)
	if src == nil || to < 0 || to >= wasiRootFD {
		return _wasiEBADF
	}
	if from == to {
		return _wasiESUCCESS
	}
	var closeErr error
	if dst := w.fdsLocked()[to]; dst != nil {
		if dst == src {
			delete(w.cloexec, to)
			return _wasiESUCCESS
		}
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	if to == wasiPreopenFD {
		w.preopenReplaced.Store(true)
	}
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
	if src == nil || to < 0 || to >= wasiRootFD {
		return _wasiEBADF
	}
	var closeErr error
	if dst, ok2 := w.fdsLocked()[to]; ok2 {
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	if to == wasiPreopenFD {
		w.preopenReplaced.Store(true)
	}
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
//
// A directory of the host's lists its names in the order the system gives
// them, "." and ".." among them where the system puts them on linux and
// first on every other host (hostDirListing). A directory of a file system
// of the embedder's own (MemFS) has no order of its own: it lists "." and
// ".." first and then its names sorted, the same every time.
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
	if out, ok, err := hostDirListing(op.f, op.hostPath); ok {
		if err != nil {
			return nil, err
		}
		op.dirCache = out
		return out, nil
	}
	if _, err := op.f.Seek(0, 0); err != nil {
		return nil, err
	}
	entries, err := op.f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	// "." is the directory open, ".." the one it is in, where its file
	// tells (a MemFS file does).
	dot := &dotDirEntry{name: ".", parent: op.path}
	// A directory whose stat fails is listed all the same: the stat only
	// gives "." its number, and without it "." is numbered from its
	// index, as an entry without a number is.
	if st, err := op.f.Stat(); err == nil {
		dot.ino = fileStatOf(st).ino
	}
	dotdot := &dotDirEntry{name: "..", parent: op.path}
	if f, ok := op.f.(interface{ parentInode() uint64 }); ok {
		dotdot.ino = f.parentInode()
	}
	out := make([]os.DirEntry, 0, len(entries)+2)
	out = append(out, dot, dotdot)
	out = append(out, entries...)
	// A listing of the guest's descriptors has an order of its own.
	if _, listing := op.f.(*descriptorListing); !listing {
		sort.SliceStable(out[2:], func(i, j int) bool {
			return out[2+i].Name() < out[2+j].Name()
		})
	}
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
	ino          uint64 // 0 where the listing does not know it
}

func (d *dotDirEntry) inode() uint64 { return d.ino }

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
		var dtype byte = 4 // regular file
		if e.IsDir() {
			dtype = 3
		} else if e.Type()&os.ModeSymlink != 0 {
			dtype = 7
		} else if e.Type()&os.ModeNamedPipe != 0 {
			dtype = 6
		} else if e.Type()&os.ModeSocket != 0 {
			dtype = 6
		} else if e.Type()&os.ModeIrregular != 0 {
			dtype = 0 // unknown
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
		// to load any standard-library module). It is the inode number the
		// listing has for the entry; an entry without one gets a stable
		// number from its index, with the top bit set so that it is no
		// MemFS file's.
		ino := 1<<63 | (uint64(i) + 1)
		if e, ok := e.(interface{ inode() uint64 }); ok && e.inode() != 0 {
			ino = e.inode()
		}
		binary.LittleEndian.PutUint64(hdr[8:], ino) // d_ino
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
// table. The path is relative to the preopened root (dirFd 3, the
// "preopen /" convention wasi-libc requires for its directory
// enumeration) and is opened through the configured FS, once the
// configured FSAccess allows it.
func (w *WasiStubs) Path_open(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags, openedFdPtr int32) int32 {
	return w.openGuestPath(m, dirFd, dirflags, zext(pathPtr), zext(pathLen), oflags, fsRightsBase, fsRightsInherit, fdflags, zext(openedFdPtr))
}

// Path_open64 is Path_open for a memory64 guest.
func (w *WasiStubs) Path_open64(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags, fsRightsBase, fsRightsInherit, fdflags, openedFdPtr int64) int32 {
	return w.openGuestPath(m, int32(dirFd), int32(dirflags), uint64(pathPtr), uint64(pathLen), int32(oflags), fsRightsBase, fsRightsInherit, int32(fdflags), uint64(openedFdPtr))
}

// openGuestPath is the body of Path_open and Path_open64.
func (w *WasiStubs) openGuestPath(m *Module, dirFd, dirflags int32, pathPtr, pathLen uint64, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags int32, openedFdPtr uint64) int32 {
	if !w.preopened(dirFd) {
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

// ownDescriptorPath tells what rel names of the guest's own descriptors, the
// way the system names the descriptors of the process that opens the name
// (rel is relative to the root, as the guest's C library gives it):
//
//   - a descriptor (named): /dev/stdin, /dev/stdout, /dev/stderr (0, 1, 2),
//     /dev/fd/N, /proc/self/fd/N and /proc/PID/fd/N for the process's own
//     pid, in any spelling of what leads to the name: "." elements, ".."
//     elements at the root and repeated slashes are resolved on the way; a
//     ".." that takes back an element is not (rootElements). rest is what rel goes on
//     with after the name, from its slash: empty when rel ends with the
//     name, and a path from the descriptor, which then has to be a
//     directory, otherwise;
//   - a directory that lists the descriptors (dir, its name in its clean
//     spelling): /dev/fd, /proc/self/fd and /proc/PID/fd, in any spelling;
//   - nothing (dir empty).
//
// pid returns the process's own pid; it is called only for a name that
// walks into proc/N/fd with N other than self.
func ownDescriptorPath(rel string, pid func() int32) (fd int32, rest string, named bool, dir string) {
	// The name is the first prefix of rel, up to a slash or its end, that
	// cleans to a descriptor's name.
	for end := 1; end <= len(rel); end++ {
		if end < len(rel) && rel[end] != '/' {
			continue
		}
		name, ok := rootElements(rel[:end])
		if !ok {
			return 0, "", false, ""
		}
		if fd, ok := ownDescriptorNumber(name, pid); ok {
			return fd, rel[end:], true, ""
		}
	}
	name, ok := rootElements(rel)
	switch {
	case !ok:
	case len(name) == 2 && name[0] == "dev" && name[1] == "fd":
		return 0, "", false, "dev/fd"
	case len(name) == 3 && ownProcessDir(name, pid):
		return 0, "", false, "proc/" + name[1] + "/fd"
	}
	return 0, "", false, ""
}

// rootElements returns the elements of name, a path relative to the root,
// cleaned as chroot(2) sees it: ".." of the root is the root. ok is false
// when a ".." element takes back an element before it: the host resolves
// ".." after symbolic links, which /dev/fd and /proc/self are on Linux, so
// the name is not one of the guest's own descriptors.
func rootElements(name string) (elems []string, ok bool) {
	parts := strings.Split(name, "/")
	if first := slices.IndexFunc(parts, func(part string) bool { return part != "" && part != "." && part != ".." }); first >= 0 && slices.Contains(parts[first:], "..") {
		return nil, false
	}
	return strings.Split(strings.TrimPrefix(path.Clean("/"+name), "/"), "/"), true
}

// ownProcessDir reports whether name, which has three elements or more,
// starts with proc/self/fd or proc/PID/fd for the process's own pid.
func ownProcessDir(name []string, pid func() int32) bool {
	return name[0] == "proc" && name[2] == "fd" && (name[1] == "self" || name[1] == strconv.Itoa(int(pid())))
}

// ownDescriptorNumber returns the descriptor a name of ownDescriptorPath
// stands for, given by its elements in its one clean spelling. A number
// that no descriptor has — one with a leading zero, one beyond every
// descriptor's — is a name of the guest's own descriptors too, of none
// that is open: -1.
func ownDescriptorNumber(name []string, pid func() int32) (int32, bool) {
	var num string
	switch {
	case len(name) == 2 && name[0] == "dev":
		switch name[1] {
		case "stdin":
			return 0, true
		case "stdout":
			return 1, true
		case "stderr":
			return 2, true
		}
		return 0, false
	case len(name) == 3 && name[0] == "dev" && name[1] == "fd":
		num = name[2]
	case len(name) == 4 && ownProcessDir(name, pid):
		num = name[3]
	default:
		return 0, false
	}
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 31)
	if err != nil || (num[0] == '0' && len(num) > 1) {
		return -1, true
	}
	return int32(n), true
}

// descriptorListing is what a directory that lists the guest's descriptors
// (ownDescriptorPath) is to the guest: an entry for each of them, named by
// the number, as they were when it opened the directory. The host would
// list the host process's, which are the runtime's and the other processes'
// of the family as well.
type descriptorListing struct {
	info    ownNameInfo
	entries []os.DirEntry
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
	return d.info, nil
}
func (d *descriptorListing) Sync() error                  { return nil }
func (d *descriptorListing) Truncate(size int64) error    { return syscall.EISDIR }
func (d *descriptorListing) Chmod(mode os.FileMode) error { return syscall.EPERM }
func (d *descriptorListing) Name() string                 { return d.info.name }

// ReadDir returns every entry, whatever n is: the runtime reads a directory
// whole (readDirCached). The entries are in the order of the numbers and,
// as on Linux, symbolic links.
func (d *descriptorListing) ReadDir(n int) ([]os.DirEntry, error) {
	return d.entries, nil
}

// ownDescriptorLocked returns the descriptor n, which ownDescriptorPath
// found named with rest after the name: op, or root for the preopened root
// at wasiPreopenFD (the root's second number, wasiRootFD, is no descriptor
// of the guest's). ENOENT for a number that is not open, ENOTDIR when rest
// asks for a directory and it is not one, ENOTSUP for a name from a
// directory ("/" and "/." are the directory itself, and a name from it is
// not resolved). Caller holds w.mu.
func (w *WasiStubs) ownDescriptorLocked(n int32, rest string) (op *wasiOpen, root bool, errno int32) {
	op = w.openLocked(n)
	root = op == nil && n == wasiPreopenFD && w.preopened(n)
	if op == nil && !root {
		return nil, false, _wasiENOENT
	}
	if rest != "" && !root && !op.isDir {
		return nil, false, _wasiENOTDIR
	}
	if path.Clean("d"+rest) != "d" {
		return nil, false, _wasiENOTSUP
	}
	return op, root, _wasiESUCCESS
}

// ownAccess reports how descriptor op, or the preopened root, is open.
func ownAccess(op *wasiOpen, root bool) (read, write bool) {
	if root {
		return true, false
	}
	return op.access()
}

// ownNameDev is the device number of the names the runtime makes up for
// the guest's own descriptors: the directory that lists them, inode number
// ownListingIno; /dev/stdin, /dev/stdout and /dev/stderr, ownAliasIno plus
// 0, 1 and 2; the link of each descriptor, ownLinkIno plus its number.
const (
	ownNameDev    = 2
	ownListingIno = 1
	ownAliasIno   = 2
	ownLinkIno    = 5
)

// ownNameInfo describes a name the runtime makes up for the guest's own
// descriptors. It belongs to the effective user and group of the Process.
type ownNameInfo struct {
	name     string
	mode     os.FileMode
	size     int64
	ino      uint64
	uid, gid uint32
	modTime  time.Time
}

func (fi ownNameInfo) Name() string       { return fi.name }
func (fi ownNameInfo) Size() int64        { return fi.size }
func (fi ownNameInfo) Mode() os.FileMode  { return fi.mode }
func (fi ownNameInfo) ModTime() time.Time { return fi.modTime }
func (fi ownNameInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi ownNameInfo) Sys() any {
	return &fileStat{dev: ownNameDev, ino: fi.ino, nlink: 1, uid: fi.uid, gid: fi.gid, atime: fi.modTime, ctime: fi.modTime}
}

// ownNameEntry is the entry of descriptor fd in a directory that lists the
// guest's descriptors.
type ownNameEntry struct {
	info ownNameInfo
	fd   int32
}

func (e ownNameEntry) Name() string               { return e.info.name }
func (e ownNameEntry) IsDir() bool                { return false }
func (e ownNameEntry) Type() os.FileMode          { return e.info.mode.Type() }
func (e ownNameEntry) Info() (os.FileInfo, error) { return e.info, nil }
func (e ownNameEntry) inode() uint64              { return e.info.ino }

// listingInfo describes a directory that lists the guest's descriptors,
// for a Process whose ids are ids.
func (w *WasiStubs) listingInfo(name string, ids ProcessIDs) ownNameInfo {
	return ownNameInfo{name: name, mode: os.ModeDir | 0o500, ino: ownListingIno, uid: uint32(ids.EUID), gid: uint32(ids.EGID), modTime: w.monoStart}
}

// linkInfo describes the link that names descriptor n, open for reading
// and for writing as read and write tell: as Linux's, its permission bits
// tell how the descriptor is open. target is what it leads to.
func (w *WasiStubs) linkInfo(name string, n int32, read, write bool, ids ProcessIDs, target string) ownNameInfo {
	mode := os.ModeSymlink
	if read {
		mode |= 0o500
	}
	if write {
		mode |= 0o300
	}
	return ownNameInfo{name: name, mode: mode, size: int64(len(target)), ino: uint64(n) + ownLinkIno, uid: uint32(ids.EUID), gid: uint32(ids.EGID), modTime: w.monoStart}
}

// streamAlias reports whether rel, a name ownDescriptorPath found of a
// descriptor with rest after it, is /dev/stdin, /dev/stdout or
// /dev/stderr: on Linux a link to /proc/self/fd/N.
func streamAlias(rel, rest string) bool {
	name, _ := rootElements(strings.TrimSuffix(rel, rest))
	return len(name) == 2
}

// aliasInfo describes /dev/stdin, /dev/stdout or /dev/stderr, the link to
// target, /proc/self/fd/n: as Linux's, open to everyone.
func (w *WasiStubs) aliasInfo(name string, n int32, ids ProcessIDs, target string) ownNameInfo {
	return ownNameInfo{name: name, mode: os.ModeSymlink | 0o777, size: int64(len(target)), ino: uint64(n) + ownAliasIno, uid: uint32(ids.EUID), gid: uint32(ids.EGID), modTime: w.monoStart}
}

// ownLinkTarget returns what the link of descriptor op, or the preopened
// root, leads to, as Linux names it: the path the descriptor was opened
// under, absolute in the guest's filesystem ("/" for the root); for a
// standard stream that is a host file, the target of the host's own link
// for it where the host has one (hostFDLink), only when the FS is the whole
// host filesystem, whose names the target is of; pipe:[N] or socket:[N] for a
// pipe or a socket, N the inode number fstat gives it. It is "" for a
// descriptor that is none of them, which then has no link. errno is a wasi
// errno.
func (w *WasiStubs) ownLinkTarget(op *wasiOpen, root bool) (string, int32) {
	switch {
	case root:
		return "/", _wasiESUCCESS
	case op.path != "":
		return guestPath(op.path), _wasiESUCCESS
	}
	if _, whole := w.fs().(osFS); whole {
		if file := w.streamFile(op); file != nil {
			target, ok, err := hostStreamLink(file)
			if err != nil {
				return "", mapOSError(err)
			}
			if ok {
				return target, _wasiESUCCESS
			}
		}
	}
	fi, err := w.opFileInfo(op)
	if err != nil {
		return "", mapOSError(err)
	}
	// What fd_filestat_ext tells of a descriptor without a file: a socket,
	// or a pipe to the guest (a stream the embedder gave), numbered 0.
	kind, ino := unixTypeFIFO, uint64(0)
	switch {
	case fi != nil:
		kind, ino = unixTypeBits(fi.Mode()), fileStatOf(fi).ino
	case op.socket():
		kind = unixTypeSocket
	}
	switch kind {
	case unixTypeFIFO:
		return fmt.Sprintf("pipe:[%d]", ino), _wasiESUCCESS
	case unixTypeSocket:
		return fmt.Sprintf("socket:[%d]", ino), _wasiESUCCESS
	}
	return "", _wasiESUCCESS
}

// opFileInfo describes the file behind op: the host file of a standard
// stream, or op's own. It is nil for a descriptor that has none (a socket,
// a stream the embedder gave).
func (w *WasiStubs) opFileInfo(op *wasiOpen) (os.FileInfo, error) {
	fi, err := w.streamFileInfo(op)
	if err != nil || fi != nil || op.f == nil {
		return fi, err
	}
	return op.f.Stat()
}

// openOwnDescriptor opens n, a descriptor of the opener's own that
// ownDescriptorPath found named with rest after the name: the host would
// open the host process's (a stream of the embedder's is not the host
// process's). The new descriptor shares the open file, as /dev/fd/N does on
// darwin and the BSDs, so the access asked for has to be one it was opened
// with; the preopened root, which has no open file to share, is opened
// anew as the root of the FS, without FSAccess (openRoot). As on Linux the
// name is a link (/dev/stdin, /dev/stdout and /dev/stderr always, as links
// to /proc/self/fd/N): ELOOP without the follow flag (dirflags bit 0) when
// the name ends with it, EEXIST for O_CREAT|O_EXCL. O_DIRECTORY asks for a
// directory. alias tells that the name is /dev/stdin, /dev/stdout or
// /dev/stderr (streamAlias).
func (w *WasiStubs) openOwnDescriptor(n int32, rest string, alias bool, dirflags, oflags int32, fsRightsBase int64, fdflags int32, canRead, canWrite bool) (int32, int32) {
	w.mu.Lock()
	op, root, errno := w.ownDescriptorLocked(n, rest)
	w.mu.Unlock()
	if errno != _wasiESUCCESS {
		return -1, errno
	}
	if oflags&0x5 == 0x5 { // O_CREAT|O_EXCL
		return -1, _wasiEEXIST
	}
	if dirflags&0x1 == 0 && rest == "" {
		if alias {
			return -1, _wasiELOOP
		}
		target, errno := w.ownLinkTarget(op, root)
		if errno != _wasiESUCCESS {
			return -1, errno
		}
		if target != "" {
			return -1, _wasiELOOP
		}
	}
	read, write := ownAccess(op, root)
	switch {
	case oflags&0x2 != 0 && !root && !op.isDir:
		return -1, _wasiENOTDIR
	case canRead && !read, canWrite && !write:
		return -1, _wasiEACCES
	case root:
		return w.openRoot(oflags, fdflags)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.openLocked(n) != op {
		// The number was closed, or given to another descriptor, since.
		return -1, _wasiENOENT
	}
	var out [4]byte
	if errno := w.dupLocked(op, 0, out[:]); errno != _wasiESUCCESS {
		return -1, errno
	}
	return int32(binary.LittleEndian.Uint32(out[:])), _wasiESUCCESS
}

// openRoot opens the preopened root anew for a name of the guest's own
// descriptors, which FSAccess is not asked about: the root of the FS, as a
// directory open for reading. O_TRUNC of a directory is EISDIR.
func (w *WasiStubs) openRoot(oflags, fdflags int32) (int32, int32) {
	if oflags&0x8 != 0 { // O_TRUNC
		return -1, _wasiEISDIR
	}
	fsys := w.fs()
	f, err := fsys.OpenFile(".", os.O_RDONLY, 0)
	if err != nil {
		return -1, mapOSError(err)
	}
	_, whole := fsys.(osFS)
	op := &wasiOpen{f: f, isDir: true, path: ".", fdflags: fdflags, hostPath: whole, noWrite: true}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(op), _wasiESUCCESS
}

// openDescriptorListing opens dir, a directory that lists the guest's
// descriptors, with an entry for each as they are now, its own among them:
// one that is opened for writing is a directory still.
func (w *WasiStubs) openDescriptorListing(dir string, oflags int32, canWrite bool) (int32, int32) {
	if oflags&(0x1|0x8) != 0 || canWrite { // O_CREAT, O_TRUNC
		return -1, _wasiEISDIR
	}
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	numbers := w.ownDescriptorsLocked()
	ops := make([]*wasiOpen, len(numbers))
	for i, n := range numbers {
		ops[i] = w.openLocked(n)
	}
	w.mu.Unlock()
	var entries []ownNameEntry
	for i, n := range numbers {
		entry, errno := w.listingEntry(n, ops[i], ops[i] == nil, ids)
		if errno == _wasiEBADF {
			continue // closed since: no longer one of the descriptors
		}
		if errno != _wasiESUCCESS {
			return -1, errno
		}
		entries = append(entries, entry)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	listing := &descriptorListing{info: w.listingInfo(path.Base(dir), ids)}
	// The entries are complete before w.mu lets anyone else find the
	// descriptor.
	fd := w.addFDLocked(&wasiOpen{f: listing, isDir: true, path: dir, noWrite: true})
	entries = append(entries, ownNameEntry{w.linkInfo(strconv.Itoa(int(fd)), fd, true, false, ids, guestPath(dir)), fd})
	slices.SortFunc(entries, func(a, b ownNameEntry) int { return cmp.Compare(a.fd, b.fd) })
	for _, e := range entries {
		listing.entries = append(listing.entries, e)
	}
	return fd, _wasiESUCCESS
}

// listingEntry is the entry of descriptor n, op or the preopened root, in a
// directory that lists the guest's descriptors: its link, or the
// descriptor as what it is when it has none (ownLinkTarget).
func (w *WasiStubs) listingEntry(n int32, op *wasiOpen, root bool, ids ProcessIDs) (ownNameEntry, int32) {
	target, errno := w.ownLinkTarget(op, root)
	if errno != _wasiESUCCESS {
		return ownNameEntry{}, errno
	}
	read, write := ownAccess(op, root)
	info := w.linkInfo(strconv.Itoa(int(n)), n, read, write, ids, target)
	if target == "" {
		fi, err := w.opFileInfo(op)
		if err != nil {
			return ownNameEntry{}, mapOSError(err)
		}
		info.mode = info.mode.Perm()
		if fi != nil {
			info.mode |= fi.Mode().Type()
		}
	}
	return ownNameEntry{info, n}, _wasiESUCCESS
}

// ownName resolves rel for the calls that describe a name (stat, lstat,
// readlink) when it is a name of the guest's own descriptors or of a
// directory that lists them (ownDescriptorPath); own is false when it is
// neither, and the FS is not asked about it either way. A descriptor's own
// name is, as on Linux, a symbolic link to the descriptor: followed
// (follow, or a name that goes on after it) it stands for the descriptor
// fd, which the caller describes as fstat does; not followed it is the link
// fi (fd -1), whose target is what ownLinkTarget gives; a descriptor that
// has no link is the descriptor either way. A listing directory is fi (fd
// -1).
// errno is what the name fails with (ownDescriptorLocked).
func (w *WasiStubs) ownName(rel string, follow bool) (fd int32, fi os.FileInfo, target string, own bool, errno int32) {
	n, rest, named, dir := ownDescriptorPath(rel, w.guestPID)
	if !named && dir == "" {
		return -1, nil, "", false, _wasiESUCCESS
	}
	ids := w.guestProcess().IDs()
	if !named {
		return -1, w.listingInfo(path.Base(dir), ids), "", true, _wasiESUCCESS
	}
	w.mu.Lock()
	op, root, errno := w.ownDescriptorLocked(n, rest)
	w.mu.Unlock()
	if errno != _wasiESUCCESS {
		return -1, nil, "", true, errno
	}
	if follow || rest != "" {
		return n, nil, "", true, _wasiESUCCESS
	}
	if streamAlias(rel, rest) {
		target = "/proc/self/fd/" + strconv.Itoa(int(n))
		return -1, w.aliasInfo(path.Base(rel), n, ids, target), target, true, _wasiESUCCESS
	}
	if target, errno = w.ownLinkTarget(op, root); errno != _wasiESUCCESS {
		return -1, nil, "", true, errno
	}
	if target == "" {
		// No link: the name is the descriptor.
		return n, nil, "", true, _wasiESUCCESS
	}
	read, write := ownAccess(op, root)
	return -1, w.linkInfo(path.Base(rel), n, read, write, ids, target), target, true, _wasiESUCCESS
}

// ownDescriptorsLocked returns the numbers of the guest's open descriptors,
// the preopened root at wasiPreopenFD among them, in order. Caller holds
// w.mu.
func (w *WasiStubs) ownDescriptorsLocked() []int32 {
	fds := slices.Collect(maps.Keys(w.fdsLocked()))
	if w.openLocked(wasiPreopenFD) == nil && w.preopened(wasiPreopenFD) {
		fds = append(fds, wasiPreopenFD)
	}
	slices.Sort(fds)
	return fds
}

// pathOpenMode is pathOpen with the mode of open(2): a file the call
// creates gets mode, less the instance's umask.
func (w *WasiStubs) pathOpenMode(rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32, mode os.FileMode) (int32, int32) {
	// Decode rights into access mode. WASI rights bits: 0=FD_DATASYNC,
	// 1=FD_READ, 6=FD_WRITE. We treat absent rights as the closest fit:
	// without FD_WRITE the open is one for reading.
	canWrite := fsRightsBase&(1<<6) != 0
	canRead := fsRightsBase&(1<<1) != 0 || !canWrite

	n, rest, named, dir := ownDescriptorPath(rel, w.guestPID)
	if named {
		return w.openOwnDescriptor(n, rest, streamAlias(rel, rest), dirflags, oflags, fsRightsBase, fdflags, canRead, canWrite)
	}
	if dir != "" {
		return w.openDescriptorListing(dir, oflags, canWrite)
	}
	w.mu.Lock()
	fsys := w.fs()
	openFile := fsys.OpenFile
	w.mu.Unlock()
	_, whole := fsys.(osFS)

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

	// Consult the host filesystem policy before touching the disk. An
	// open counts as a write when it requests write access or asks to
	// create/truncate the target.
	writeAccess := flag&(os.O_WRONLY|os.O_RDWR) != 0 || flag&(os.O_CREATE|os.O_TRUNC) != 0
	rel, ok := w.allowedPath(rel, writeAccess)
	if !ok {
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
	// The filesystem is asked for the mode less the instance's umask. The
	// host's filesystem takes the host process's umask out as well, so
	// there the instance's umask tightens a mode and does not loosen one;
	// MemFS creates with the mode as asked.
	if f, err = openFile(rel, flag, w.createMode(mode)); err != nil {
		return -1, mapOSError(err)
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
		f: f, isDir: isDir, regular: st.Mode().IsRegular(), path: rel, fdflags: fdflags,
		hostPath: whole,
		noRead:   flag&os.O_WRONLY != 0,
		noWrite:  flag&(os.O_WRONLY|os.O_RDWR) == 0,
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(op), _wasiESUCCESS
}

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
	if !w.preopened(dirFd) {
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	name, ok := w.allowedPath(string(pathSlice), true)
	if !ok {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	rel := name
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	name, ok := w.allowedPath(string(pathSlice), true)
	if !ok {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	rel := name
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
	if !w.preopened(oldFd) || !w.preopened(newFd) {
		return _wasiEBADF
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	oldName, okOld := w.allowedPath(string(oldSlice), true)
	newName, okNew := w.allowedPath(string(newSlice), true)
	if !okOld || !okNew {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if err := fsys.Rename(oldName, newName); err != nil {
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	out := w.memBytes(m, outPtr, 64)
	if pathSlice == nil || out == nil {
		return _wasiEFAULT
	}
	if fd, fi, _, own, errno := w.ownName(string(pathSlice), flags&0x1 != 0); own {
		switch {
		case errno != _wasiESUCCESS:
			return errno
		case fi == nil:
			return w.filestatOf(fd, out)
		}
		writeFilestat(out, fi)
		return _wasiESUCCESS
	}
	name, ok := w.allowedPath(string(pathSlice), false)
	if !ok {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	rel := name
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	name, ok := w.allowedPath(string(pathSlice), true)
	if !ok {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	rel := name
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
	if !w.preopened(oldFd) || !w.preopened(newFd) {
		return _wasiEBADF
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	oldName, okOld := w.allowedPath(string(oldSlice), true)
	newName, okNew := w.allowedPath(string(newSlice), true)
	if !okOld || !okNew {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if err := fsys.Link(oldName, newName); err != nil {
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	targetSlice := w.memBytes(m, targetPtr, targetLen)
	linkSlice := w.memBytes(m, linkPathPtr, linkPathLen)
	if targetSlice == nil || linkSlice == nil {
		return _wasiEFAULT
	}
	// The link is written; what it names, the target resolved against the
	// link's directory (an absolute one against the root), can be read
	// and written through it.
	link, okLink := w.allowedPath(string(linkSlice), true)
	target := string(targetSlice)
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(rootRelative(link)), target)
	}
	_, okRead := w.allowedPath(target, false)
	_, okWrite := w.allowedPath(target, true)
	if !okLink || !okRead || !okWrite {
		return _wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if err := fsys.Symlink(string(targetSlice), link); err != nil {
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
	if !w.preopened(dirFd) {
		return _wasiEBADF
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	bufSlice := w.memBytes(m, buf, buflen)
	// bufused is a __wasi_size_t.
	bufused := w.memBytes(m, bufusedPtr, abi.wordSize())
	if pathSlice == nil || bufSlice == nil || bufused == nil {
		return _wasiEFAULT
	}
	var target string
	if _, _, link, own, errno := w.ownName(string(pathSlice), false); own {
		// A name that is no link fails as on Linux.
		if errno != _wasiESUCCESS {
			return errno
		}
		if link == "" {
			return _wasiEINVAL
		}
		target = link
	} else {
		name, ok := w.allowedPath(string(pathSlice), false)
		if !ok {
			return _wasiEACCES
		}
		w.mu.Lock()
		fsys := w.fs()
		w.mu.Unlock()
		var err error
		if target, err = fsys.Readlink(name); err != nil {
			return mapOSError(err)
		}
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
	subsTotal := uint64(uint32(nsubs)) * 48
	if subsTotal > 0x7fffffff {
		return _wasiEFAULT
	}
	subs := w.memSlice(m, inPtr, int32(subsTotal))
	evTotal := uint64(uint32(nsubs)) * 32
	if evTotal > 0x7fffffff {
		return _wasiEFAULT
	}
	events := w.memSlice(m, outPtr, int32(evTotal))
	nev := w.memSlice(m, neventsPtr, 4)
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
	for i := int32(0); i < nsubs; i++ {
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

	// fd subscriptions report their (optimistic) readiness immediately, so
	// when any are present the clock subscription must NOT be slept first —
	// that would turn every select/poll carrying a timeout into a wait for
	// the full timeout. The clock paces the call only when it is the sole
	// kind of subscription, and its "timeout fired" event is suppressed
	// while ready fds are being reported (a real poll returns ready fds
	// without also claiming the timeout expired).
	if minClockNs > 0 && len(fdEvents) == 0 {
		time.Sleep(time.Duration(minClockNs))
	}

	written := int32(0)
	for _, ev := range clockEvents {
		if ev.etype == 0 && len(fdEvents) > 0 {
			continue
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, 0, 0)
		written += 32
	}
	for _, ev := range fdEvents {
		w.mu.Lock()
		op := w.openLocked(ev.fd)
		w.mu.Unlock()
		var errno int32
		var nbytes uint64
		if op == nil {
			errno = _wasiEBADF
		} else if op.f != nil {
			// Real file: report ready and pass through the file's
			// current size as the readable byte count (best-effort).
			if ev.isRead {
				if st, err := op.f.Stat(); err == nil {
					// Best-effort: skip the byte-count hint if Seek
					// fails. nbytes is advisory, callers will surface
					// the real state via the actual Read.
					if cur, err := op.f.Seek(0, 1); err == nil && st.Size() > cur {
						nbytes = uint64(st.Size() - cur)
					}
				}
			}
		} else if op.netConn() != nil {
			// Go's stdlib does not expose a portable readiness probe
			// on *net.Conn that distinguishes "ready" from "would-
			// block" without consuming bytes. Report the event as
			// ready so the guest's downstream Read/Write call can
			// surface the real state.
			_ = minClockNs
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, uint16(errno), nbytes)
		written += 32
	}

	binary.LittleEndian.PutUint32(nev, uint32(written/32))
	return _wasiESUCCESS
}

func writeEvent(dst []byte, userdata uint64, etype byte, errno uint16, nbytes uint64) {
	for i := range dst {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint64(dst[0:], userdata)
	binary.LittleEndian.PutUint16(dst[8:], errno)
	binary.LittleEndian.PutUint16(dst[10:], uint16(etype))
	binary.LittleEndian.PutUint64(dst[16:], nbytes)
}

func (w *WasiStubs) Proc_exit(m *Module, code int32) {
	// Panic instead of exiting the host process: the caller gets the
	// *WasiExitError as WasiExitError's doc says.
	panic(&WasiExitError{Code: code})
}

// Proc_exit64 is Proc_exit for a memory64 guest.
func (w *WasiStubs) Proc_exit64(m *Module, code int64) {
	w.Proc_exit(m, int32(code))
}

// Proc_raise applies the default action of the WASI signal sig
// (__wasi_signal_t, 0..30) to the guest alone: no signal reaches the host
// process. Signal 0 returns 0, as does a signal whose default is to be
// ignored (CHLD, CONT, URG, WINCH) or to stop the process (STOP, TSTP,
// TTIN, TTOU), which cannot stop an instance. Every other signal ends the
// guest with a panic, whose value is a *WasiSignalError. A number outside
// the enum returns EINVAL.
func (w *WasiStubs) Proc_raise(m *Module, sig int32) int32 {
	switch {
	case sig < 0 || sig > 30:
		return _wasiEINVAL
	case sig == 0, sig >= 16 && sig <= 22, sig == 27: // CHLD..URG, WINCH
		return _wasiESUCCESS
	}
	panic(&WasiSignalError{Signal: sig})
}

// Proc_raise64 is Proc_raise for a memory64 guest: it takes the one
// argument of the standard import widened to an i64, as a memory64 guest
// passes every argument of the standard imports.
func (w *WasiStubs) Proc_raise64(m *Module, sig int64) int32 {
	if sig != int64(int32(sig)) {
		return _wasiEINVAL
	}
	return w.Proc_raise(m, int32(sig))
}

// Sock_socket is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_socket") that a guest's socket() can call. WASI preview1 has no
// way to create an outbound socket; this gives the guest a host-managed fd
// whose connection is established later by Sock_connect. domain/type follow
// the POSIX socket() args (AF_INET / SOCK_STREAM); only TCP over IPv4 is
// supported. Returns the new fd, or a negative errno on failure.
func (w *WasiStubs) Sock_socket(m *Module, domain, typ int32) int32 {
	// A guest calls this only for AF_INET / SOCK_STREAM: domain and typ
	// are not checked (the guest's AF_INET numeric value need not match
	// the host's).
	_ = domain
	_ = typ
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(&wasiOpen{isSocket: true})
}

// Sock_connect is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_connect") that a guest's connect() can call. ipBE carries the
// IPv4 address in network byte order exactly as it sat in
// sockaddr_in.sin_addr.s_addr (so the low byte is the first octet); port is
// host byte order. It consults the dial whitelist, dials via Go's net, and
// attaches the resulting conn to the socket fd so the existing Sock_send /
// Sock_recv / Fd_close paths drive it. Returns 0 or a negative errno.
func (w *WasiStubs) Sock_connect(m *Module, fd, ipBE, port int32) int32 {
	u := uint32(ipBE)
	ip := fmt.Sprintf("%d.%d.%d.%d", u&0xff, (u>>8)&0xff, (u>>16)&0xff, (u>>24)&0xff)
	op, conn, errno := w.socketConn(fd)
	switch {
	case conn != nil, op != nil && op.listener != nil:
		return -_wasiEISCONN
	case errno != _wasiENOTCONN:
		return -errno
	}
	w.mu.Lock()
	hook := w.cfg.Dial
	host := w.resolvedHosts[ip] // "" for a literal-IP dial with no preceding lookup
	w.mu.Unlock()
	p := int(uint16(port))
	if hook == nil || !hook("tcp", host, ip, p) {
		return -_wasiEACCES
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), 30*time.Second)
	if err != nil {
		return -errnoOr(err, _wasiECONNREFUSED)
	}
	w.mu.Lock()
	// The fd may have been closed concurrently; re-check before attaching.
	if cur := w.openLocked(fd); cur == op {
		op.mu.Lock()
		op.conn = conn
		op.mu.Unlock()
		w.mu.Unlock()
		return _wasiESUCCESS
	}
	w.mu.Unlock()
	if cerr := conn.Close(); cerr != nil {
		return -mapOSError(cerr)
	}
	return -_wasiEBADF
}

// Sock_accept accepts the next incoming TCP/Unix connection on the
// listener associated with fd, registers it as a new wasiOpen with a
// conn arm, and writes the new fd at fdOutPtr. Returns ENOTSOCK if fd
// isn't a listener.
func (w *WasiStubs) Sock_accept(m *Module, fd, flags, fdOutPtr int32) int32 {
	if !w.checkNet("accept") {
		return _wasiEACCES
	}
	out := w.memSlice(m, fdOutPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil || op.listener == nil {
		return _wasiENOTSOCK
	}
	conn, err := op.listener.Accept()
	if err != nil {
		if op.shutClosed.Load() {
			// the read half was shut, as on linux
			return _wasiEINVAL
		}
		return mapOSError(err)
	}
	w.mu.Lock()
	newFD := w.addFDLocked(&wasiOpen{conn: conn})
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(newFD))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_recv(m *Module, fd, riData, riDataLen, riFlags, roDataLenPtr, roFlagsPtr int32) int32 {
	if !w.checkNet("recv") {
		return _wasiEACCES
	}
	op, conn, errno := w.socketConn(fd)
	if conn == nil {
		return errno
	}
	bufs, ok := w.iovecSlices(m, wasiABI32, zext(riData), zext(riDataLen))
	lenOut := w.memSlice(m, roDataLenPtr, 4)
	// ro_flags is a __wasi_roflags_t — a 16-bit value. wasi-libc packs it
	// immediately before ro_datalen (only 2 bytes apart), so writing 4 bytes
	// here would clobber the low half of ro_datalen and make recv() report 0
	// bytes received even when data arrived.
	flagsOut := w.memSlice(m, roFlagsPtr, 2)
	if !ok || lenOut == nil || flagsOut == nil {
		return _wasiEFAULT
	}
	n, errno := readVec(conn, bufs, false)
	if errno = op.afterShutdown(errno, false); errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint16(flagsOut, 0)
	binary.LittleEndian.PutUint32(lenOut, uint32(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_send(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int32) int32 {
	if !w.checkNet("send") {
		return _wasiEACCES
	}
	op, conn, errno := w.socketConn(fd)
	if errno == _wasiENOTCONN {
		// a send of a socket without a connection, as on linux
		return _wasiEPIPE
	}
	if conn == nil {
		return errno
	}
	bufs, ok := w.iovecSlices(m, wasiABI32, zext(siData), zext(siDataLen))
	lenOut := w.memSlice(m, soDataLenPtr, 4)
	if !ok || lenOut == nil {
		return _wasiEFAULT
	}
	n, errno := writeVec(conn, bufs)
	if errno = op.afterShutdown(errno, true); errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint32(lenOut, uint32(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_shutdown(m *Module, fd, how int32) int32 {
	op, conn, errno := w.socketConn(fd)
	if conn == nil && errno != _wasiENOTCONN {
		return errno
	}
	if how == 0 || how&^0x3 != 0 {
		// neither SHUT_RD nor SHUT_WR, or a bit that is neither
		return _wasiEINVAL
	}
	if conn == nil {
		if op.listener == nil {
			return errno
		}
		// A listening socket has only a read half: shutting it stops
		// accepting, and an accept that waits fails with EINVAL.
		if how&0x1 == 0 {
			return _wasiESUCCESS
		}
		op.shutClosed.Store(true)
		if op.connClosed.CompareAndSwap(false, true) {
			if err := op.listener.Close(); err != nil {
				return mapOSError(err)
			}
		}
		return _wasiESUCCESS
	}
	type shutdowner interface {
		CloseRead() error
		CloseWrite() error
	}
	sh, ok := conn.(shutdowner)
	if !ok {
		// Generic conn: the first shutdown closes it, whichever halves
		// it shuts, and a later one has nothing left to do. shutClosed
		// is set first, for a transfer that the close ends. The one close
		// counts whatever it returns (a conn may let go of its connection
		// when Close fails); its failure is surfaced via the wasi errno.
		op.shutClosed.Store(true)
		if !op.connClosed.CompareAndSwap(false, true) {
			return _wasiESUCCESS
		}
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
		return mapOSError(shErr)
	}
	return _wasiESUCCESS
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

// Process supplies the identity and the accounting of the guest process
// (WASIConfig.Process). Its methods are called without any lock of the
// WasiStubs held.
type Process interface {
	// IDs returns the ids of the guest process.
	IDs() ProcessIDs
	// Times returns the CPU time the guest process and the children it has
	// waited for have used. An error that is errors.ErrUnsupported makes
	// the guest's times() fail with ENOSYS. The Process of HostProcess
	// reports the whole host process, which every instance of a fork family
	// is part of, and the children the host process has waited for.
	Times() (ProcessTimes, error)
	// Umask returns the file mode creation mask the guest starts with. Only
	// its permission bits are used.
	Umask() os.FileMode
}

// ProcessIDs are the ids of a guest process.
type ProcessIDs struct {
	PID, PPID int32
	UID, EUID int32
	GID, EGID int32
}

// ProcessTimes are the CPU times of a guest process: the user and system
// time of the process, then those of the children it has waited for.
type ProcessTimes struct {
	User, System, ChildrenUser, ChildrenSystem time.Duration
}

// isolatedProcess is the Process of an instance that has none installed. It
// reads nothing from the host.
type isolatedProcess struct{}

func (isolatedProcess) IDs() ProcessIDs              { return ProcessIDs{PID: 42, PPID: 1} }
func (isolatedProcess) Times() (ProcessTimes, error) { return ProcessTimes{}, nil }
func (isolatedProcess) Umask() os.FileMode           { return 0o022 }

// HostProcess returns a Process with the identity and the accounting of the
// host process, for WASIConfig.Process. IDs are os.Getpid, os.Getppid,
// os.Getuid, os.Geteuid, os.Getgid and os.Getegid. Times are the host's
// resource usage of the whole host process, which every instance of a fork
// family is part of, and of the children the host process has waited for;
// on a system without one the error is errors.ErrUnsupported. Umask is the host
// process's file mode creation mask when HostProcess is called, read without
// changing it: on Linux from /proc/self/status, and an error reading it is
// returned. Where it cannot be read without changing it (another system, or
// a Linux whose status has no umask) the error is errors.ErrUnsupported:
// use HostProcessUmask, which takes the umask from the caller.
func HostProcess() (Process, error) {
	umask, err := readHostUmask()
	if err != nil {
		return nil, err
	}
	return hostProcess{umask: umask}, nil
}

// HostProcessUmask returns the Process of HostProcess with umask as the
// umask the guest starts with.
func HostProcessUmask(umask os.FileMode) Process { return hostProcess{umask: umask} }

// hostProcess is the Process HostProcess and HostProcessUmask return.
type hostProcess struct {
	umask os.FileMode
}

func (hostProcess) IDs() ProcessIDs {
	return ProcessIDs{
		PID: int32(os.Getpid()), PPID: int32(os.Getppid()),
		UID: int32(os.Getuid()), EUID: int32(os.Geteuid()),
		GID: int32(os.Getgid()), EGID: int32(os.Getegid()),
	}
}

func (hostProcess) Times() (ProcessTimes, error) { return hostProcessTimes() }
func (p hostProcess) Umask() os.FileMode         { return p.umask }

// Proc_ids is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_ids") backing getpid, getppid and the getuid family. It writes
// the IDs of the Process (WASIConfig.Process) at outPtr as six
// little-endian u32: pid, ppid, uid, euid, gid, egid. Returns 0 or a
// negative errno.
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
	ids := w.guestProcess().IDs()
	for i, id := range [6]int32{ids.PID, ids.PPID, ids.UID, ids.EUID, ids.GID, ids.EGID} {
		binary.LittleEndian.PutUint32(out[i*4:], uint32(id))
	}
	return _wasiESUCCESS
}

// Proc_times is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_times") backing times(2): the Times of the Process
// (WASIConfig.Process) are written at outPtr as four little-endian u64 of
// nanoseconds — the user and system CPU time of the process, then those of
// the children it has waited for. Returns 0, or a negative errno: ENOSYS
// when the Process does not account for them.
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
	times, err := w.guestProcess().Times()
	if errors.Is(err, errors.ErrUnsupported) {
		return -_wasiENOSYS
	}
	if err != nil {
		return -mapOSError(err)
	}
	for i, d := range [4]time.Duration{times.User, times.System, times.ChildrenUser, times.ChildrenSystem} {
		binary.LittleEndian.PutUint64(out[i*8:], uint64(d))
	}
	return _wasiESUCCESS
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
	path, ok := w.allowedPath(string(pathSlice), true)
	if !ok {
		return -_wasiEACCES
	}
	w.mu.Lock()
	fsys := w.fs()
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

// ----- time zones -------------------------------------------------------------
//
// A guest's libc knows one time zone, UTC, and has no zone database. The
// rules of a zone are the host's to know: the guest names the zone it wants
// (the value of its TZ variable) and a moment, and Clock_zone answers what
// holds in that zone at that moment — the offset from UTC, whether daylight
// saving time is in effect, and the abbreviations in use.

// wasiZoneMoment is what holds in a time zone at one moment.
type wasiZoneMoment struct {
	offset int    // seconds east of UTC
	dst    bool   // daylight saving time is in effect
	name   string // the abbreviation in use
	// other is the offset under the opposite daylight-saving state at the
	// next change, or else the previous one, and equal to offset in a zone
	// that has none.
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

// posixZoneQuotedChars are the characters of a zone abbreviation between
// angle brackets.
const posixZoneQuotedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"

// name reads a zone abbreviation: three or more letters, or three or more
// of posixZoneQuotedChars between angle brackets.
func (p *posixZoneScanner) name() string {
	if p.take('<') {
		end := strings.IndexByte(p.s, '>')
		if end < 3 || strings.Trim(p.s[:end], posixZoneQuotedChars) != "" {
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
		// days 1..365, February 29 never counted: the month and day of that
		// day of a year without one (2001)
		common := time.Date(2001, time.January, r.day, 0, 0, 0, 0, time.UTC)
		day = time.Date(year, common.Month(), common.Day(), 0, 0, 0, 0, time.UTC)
	default:
		day = time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, r.day)
	}
	return day.Unix() + int64(r.secondsOfDay)
}

// inDST reports whether daylight saving time is in effect at utc (seconds
// since the epoch). It never is in a year whose rules start and end it at
// the same instant.
func (z *posixZone) inDST(utc int64) bool {
	if z.dstName == "" {
		return false
	}
	year := time.Unix(utc+int64(z.stdOffset), 0).UTC().Year()
	start := z.dstStart.localSeconds(year) - int64(z.stdOffset)
	end := z.dstEnd.localSeconds(year) - int64(z.dstOffset)
	if start == end {
		return false
	}
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
// one). With local set, t is a reading of the zone's own clock (see
// zoneReading).
func locationMoment(loc *time.Location, t int64, local bool) wasiZoneMoment {
	at := time.Unix(t, 0).In(loc)
	if local {
		at = zoneReading(loc, t)
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

// zoneReading returns the moment a reading t of loc's own clock (seconds
// counted as since the epoch) stands for. A reading that one offset of the
// zone gives is that moment; one that two give (the hour repeated when
// daylight saving time ends) or none does (the hour skipped when it starts)
// is taken as standard time, as posixZone.moment takes it, and when neither
// side of the change is standard time, as the time before it.
func zoneReading(loc *time.Location, t int64) time.Time {
	u := time.Unix(t, 0).UTC()
	at := time.Date(u.Year(), u.Month(), u.Day(), u.Hour(), u.Minute(), u.Second(), 0, loc)
	// A reading that is not plain falls next to a change, so the offsets
	// of the period time.Date chose and of the two around it, in their
	// order, are the ones that may give it.
	start, end := at.ZoneBounds()
	var periods []time.Time
	if !start.IsZero() {
		periods = append(periods, start.Add(-time.Second))
	}
	periods = append(periods, at)
	if !end.IsZero() {
		periods = append(periods, end)
	}
	var fits []time.Time
	for _, p := range periods {
		_, offset := p.Zone()
		moment := time.Unix(t-int64(offset), 0).In(loc)
		if _, now := moment.Zone(); now != offset {
			continue
		}
		if !slices.ContainsFunc(fits, moment.Equal) {
			fits = append(fits, moment)
		}
	}
	if len(fits) == 1 {
		return fits[0]
	}
	if len(fits) == 0 {
		// The reading is in the time a change skips: it is taken in one of
		// the two periods next to that change, the one before it unless
		// only the one after it is standard time.
		fits = []time.Time{at}
		_, offset := at.Zone()
		if !start.IsZero() {
			before := start.Add(-time.Second)
			if _, was := before.Zone(); start.Unix()+int64(was) <= t && t < start.Unix()+int64(offset) {
				fits = []time.Time{before, at}
			}
		}
		if _, next := end.Zone(); !end.IsZero() && end.Unix()+int64(offset) <= t && t < end.Unix()+int64(next) {
			fits = []time.Time{at, end}
		}
	}
	for _, f := range fits {
		if !f.IsDST() {
			return f
		}
	}
	return fits[0]
}

// wasiZone is a zone a TZ value names, resolved: one of the host's zone
// database or of a zone file (loc), or one a POSIX TZ string gives (posix).
type wasiZone struct {
	loc   *time.Location
	posix *posixZone
}

// moment answers for the zone; see posixZone.moment and locationMoment.
func (z wasiZone) moment(t int64, local bool) wasiZoneMoment {
	if z.posix != nil {
		return z.posix.moment(t, local)
	}
	return locationMoment(z.loc, t, local)
}

// wasiZoneFileMax is the size of the largest file a TZ value can name as a
// zone file: the limit of the standard library's readFile, which
// time.LoadLocation reads zone files with.
const wasiZoneFileMax = 10 << 20

// zoneMoment resolves the zone a guest named and answers for it. No name
// (TZ not set) is the configuration's LocalZone, UTC when it has none. A
// name, with the ':' it may start with dropped, is a zone of the host's zone
// database ("Europe/Paris"), or, when it starts with '/', the zone file of
// that path in the guest's filesystem ("/usr/share/zoneinfo/Europe/Paris")
// (see loadZone). As for a C library, a name that loads no zone, whatever
// the reason, is read as a POSIX TZ string, and one that is not such a
// string either is UTC, and the configuration's Errors is told the error of
// loading it. The instance keeps the zone of the last name it
// resolved, and resolves a name again when it differs from that one.
func (w *WasiStubs) zoneMoment(tz string, named bool, t int64, local bool) wasiZoneMoment {
	if !named {
		loc := w.cfg.LocalZone
		if loc == nil {
			loc = time.UTC
		}
		return locationMoment(loc, t, local)
	}
	tz = strings.TrimPrefix(tz, ":")
	w.mu.Lock()
	zone := w.zone
	if w.zoneTZ != tz {
		zone = nil
	}
	w.mu.Unlock()
	if zone == nil {
		zone = &wasiZone{loc: time.UTC}
		// The error of loading the name is not the guest's to see: a C
		// library reads such a name as a POSIX TZ string, and else as UTC,
		// which is when Errors is told it.
		if loc, err := w.loadZone(tz); err == nil {
			zone = &wasiZone{loc: loc}
		} else if posix, ok := parsePosixZone(tz); ok {
			zone = &wasiZone{posix: posix}
		} else if w.cfg.Errors != nil {
			w.cfg.Errors("clock_zone", err)
		}
		w.mu.Lock()
		w.zoneTZ, w.zone = tz, zone
		w.mu.Unlock()
	}
	return zone.moment(t, local)
}

// loadZone loads the zone of a name (see zoneMoment) from the host's zone
// database or, for a path, from the guest's filesystem. "Local" names no
// zone of the database; a path names one only when it is a regular file of
// at most wasiZoneFileMax bytes. The file is opened without waiting where
// the host can (hostONonblock), and what it is is told by the open file.
func (w *WasiStubs) loadZone(name string) (*time.Location, error) {
	if name == "Local" {
		return nil, fs.ErrNotExist
	}
	if !strings.HasPrefix(name, "/") {
		return time.LoadLocation(name)
	}
	rel, allowed := w.allowedPath(name, false)
	if !allowed {
		return nil, fs.ErrPermission
	}
	f, err := w.fs().OpenFile(rel, os.O_RDONLY|hostONonblock, 0)
	if err != nil {
		return nil, err
	}
	var data []byte
	fi, err := f.Stat()
	switch {
	case err != nil:
	case !fi.Mode().IsRegular() || fi.Size() > wasiZoneFileMax:
		err = fs.ErrNotExist
	default:
		data, err = io.ReadAll(io.LimitReader(f, wasiZoneFileMax))
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	return time.LoadLocationFromTZData(name, data)
}

// wasiZoneNameSize is the space a zone abbreviation has in the record
// Clock_zone writes, its terminating NUL included.
const wasiZoneNameSize = 16

// Clock_zone is a NON-STANDARD host import (module wasip1_posix_extension,
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
// when the zone has none). Returns 0, or -EFAULT for memory out of range.
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
// The per-platform companions (the wasip1_native_<platform>.go files and the
// wasip1_hostnumbers_* tables) are not parsed into the main file's decls —
// emitWasip1Platform returns them as separate files so their //go:build
// constraints stick.
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
			"wasiOpen":          true,
			"wasiProc":          true,
			"wasiPIDs":          true,
			"WasiStubs":         true,
			"WASIConfig":        true,
			"Process":           true,
			"ProcessIDs":        true,
			"ProcessTimes":      true,
			"isolatedProcess":   true,
			"ownNameInfo":       true,
			"ownNameEntry":      true,
			"hostProcess":       true,
			"wasiABI":           true,
			"dotDirEntry":       true,
			"descriptorListing": true,
			"FS":                true,
			"File":              true,
			"osFS":              true,
			"rootFS":            true,
			"noFS":              true,
			"fileStat":          true,
			"MemFS":             true,
			"memFile":           true,
			"memNode":           true,
			"memFileInfo":       true,
			"memDirEntry":       true,
			"wasiZoneMoment":    true,
			"posixZoneRule":     true,
			"posixZone":         true,
			"posixZoneScanner":  true,
			"wasiZone":          true,
		},
		keepFuncNames: map[string]bool{
			"itoa32":                  true,
			"NewWASI":                 true,
			"HostWASIConfig":          true,
			"HostFS":                  true,
			"AllowAllNetAccess":       true,
			"AllowAllDial":            true,
			"AllowAllResolve":         true,
			"AllowAllExec":            true,
			"HostProcess":             true,
			"HostProcessUmask":        true,
			"NewMemFS":                true,
			"fileStatOf":              true,
			"unixFileMode":            true,
			"unixModeBits":            true,
			"unixTypeBits":            true,
			"filetimesNeedCurrent":    true,
			"writeFilestatExt":        true,
			"rootRelative":            true,
			"rootEscapeOf":            true,
			"memSplit":                true,
			"memSlice":                true,
			"mapOSError":              true,
			"errnoOr":                 true,
			"seekErrno":               true,
			"mapExecError":            true,
			"encodeWaitStatus":        true,
			"totalBytesPlusNul":       true,
			"zext":                    true,
			"readVec":                 true,
			"writeVec":                true,
			"Args_get":                true,
			"Args_sizes_get":          true,
			"Environ_get":             true,
			"Environ_sizes_get":       true,
			"Clock_res_get":           true,
			"Clock_time_get":          true,
			"closeWasiOpen":           true,
			"Fd_close":                true,
			"Fd_fdstat_get":           true,
			"Fd_fdstat_set_flags":     true,
			"Fd_fdstat_set_rights":    true,
			"Fd_filestat_get":         true,
			"Fd_filestat_set_size":    true,
			"Fd_filestat_set_times":   true,
			"combine64":               true,
			"resolveFiletimes":        true,
			"Fd_prestat_get":          true,
			"Fd_prestat_dir_name":     true,
			"Fd_read":                 true,
			"fdSrcLocked":             true,
			"fdDstLocked":             true,
			"Fd_pread":                true,
			"Fd_pwrite":               true,
			"Fd_seek":                 true,
			"Fd_tell":                 true,
			"Fd_write":                true,
			"Fd_sync":                 true,
			"Fd_datasync":             true,
			"Fd_advise":               true,
			"Fd_allocate":             true,
			"Fd_renumber":             true,
			"readDirCached":           true,
			"dotEntry":                true,
			"Name":                    true,
			"IsDir":                   true,
			"Type":                    true,
			"Info":                    true,
			"Fd_readdir":              true,
			"Path_open":               true,
			"ownDescriptorPath":       true,
			"ownDescriptorNumber":     true,
			"ownProcessDir":           true,
			"rootElements":            true,
			"ownAccess":               true,
			"hostStreamLink":          true,
			"streamAlias":             true,
			"refuseDirectory":         true,
			"guestPath":               true,
			"setSpecialBits":          true,
			"Path_create_directory":   true,
			"Path_unlink_file":        true,
			"Path_remove_directory":   true,
			"Path_rename":             true,
			"Path_filestat_get":       true,
			"Path_filestat_set_times": true,
			"osLstatOrStat":           true,
			"Path_link":               true,
			"Path_symlink":            true,
			"Path_readlink":           true,
			"Random_get":              true,
			"Sched_yield":             true,
			"Poll_oneoff":             true,
			"writeEvent":              true,
			"Proc_exit":               true,
			"Proc_raise":              true,
			"Sock_accept":             true,
			"Sock_recv":               true,
			"Sock_send":               true,
			"Sock_shutdown":           true,
			"writeFilestat":           true,
			"Error":                   true,
			"parsePosixZone":          true,
			"locationMoment":          true,
			"zoneReading":             true,
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
				fn.Body = capitalizeModuleFieldRefs(fn.Body)
			}
			decls = append(decls, &fn)
		}
	}

	imports := []string{
		"cmp",
		"context",
		"crypto/rand",
		"encoding/binary",
		"errors",
		"fmt",
		"io",
		"io/fs",
		"maps",
		"net",
		"os",
		"os/exec",
		"path",
		"path/filepath",
		"runtime",
		"slices",
		"sort",
		"strconv",
		"strings",
		"sync",
		"sync/atomic",
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
	//go:embed wasip1_native_other.go
	wasip1NativeOtherRaw []byte
	//go:embed wasip1_native_hostfd.go
	wasip1NativeHostFDRaw []byte
	//go:embed wasip1_hostnumbers_linux.go
	wasip1HostNumbersLinuxRaw []byte
	//go:embed wasip1_hostnumbers_darwin.go
	wasip1HostNumbersDarwinRaw []byte
)

// emitWasip1Platform returns the per-platform companions of the native wasi
// implementation — output filename → Go source for package pkg — or nil when
// the module does not import wasi. They are written out as separate files,
// next to the one that holds the emitWasip1Native declarations, because their
// build constraints have to stay attached to them.
func (t *translator) emitWasip1Platform(pkg string) (map[string][]byte, error) {
	if !t.wasmImportsWasi() {
		return nil, nil
	}
	out := map[string][]byte{}
	for name, raw := range map[string][]byte{
		"wasip1_native_posix.go":  wasip1NativePosixRaw,
		"wasip1_native_linux.go":  wasip1NativeLinuxRaw,
		"wasip1_native_darwin.go": wasip1NativeDarwinRaw,
		"wasip1_native_other.go":  wasip1NativeOtherRaw,
		"wasip1_native_hostfd.go": wasip1NativeHostFDRaw,

		"wasip1_hostnumbers_linux.go":  wasip1HostNumbersLinuxRaw,
		"wasip1_hostnumbers_darwin.go": wasip1HostNumbersDarwinRaw,
	} {
		src, err := renamePackage(raw, pkg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = src
	}
	return out, nil
}

// renamePackage returns src, a file of package codegen, as a file of
// package pkg.
func renamePackage(src []byte, pkg string) ([]byte, error) {
	for _, eol := range []string{"\n", "\r\n"} {
		clause := []byte("\npackage codegen" + eol)
		if bytes.Contains(src, clause) {
			return bytes.Replace(src, clause, []byte("\npackage "+pkg+eol), 1), nil
		}
	}
	return nil, errors.New("no package clause of package codegen")
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
