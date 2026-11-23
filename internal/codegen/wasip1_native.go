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
//     multi-package mode, rewriteHelperBody rewrites it to
//     m.Memory so the impl works in base/ too.
//   - Method signatures must match what t.importMethodName produces from
//     the wasm import names. We use the same MangleID + capitalize chain
//     by emitting the exact wasi function names ("Environ_get" etc).
//   - Bodies favour clarity over micro-optimisation.
//
// Security model: the guest has what its WASIConfig gives it and nothing
// else (see WASIConfig). HostFS("/") is the whole host filesystem, a
// Go-syscall passthrough; HostFS(dir) keeps every path inside dir through
// os.Root. A policy on files is an FS that wraps another, and the hooks are
// the only allow-lists. Out-of-range linear-memory accesses are reported back to the
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
	"math"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
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
	"unsafe"
)

// Module is the minimal in-package proxy for the generated module type.
// In production, codegen emits a separate Module struct into the user's
// output package; this in-package Module exists so the WasiStubs methods
// below are real, compilable Go (and therefore directly testable). The
// embedded-source path strips the package + import header at emit time
// and lets the generated Module shadow this one. It has the generated
// Module's fields the stubs read: the memory slice and memSize, the size
// the guest sees (see guestMemory), memShared, and what a fork runs
// (Proc_fork): forkChild, the module's fork child export, and forkModule,
// which builds the instance a copy of the module's memory is the memory of.
type Module struct {
	memory     []byte
	memSize    *atomic.Uint64
	memShared  bool
	forkChild  func(m *Module) int32
	forkModule func(m *Module, wasi *WasiStubs, memory []byte, memSize uint64) *Module
}

// accessMemory is the in-package stand-in for the runtime helper of the same
// name, which runs f over the module's memory under the lock memory.grow
// takes. The generated output has the real one; this one is not emitted.
func accessMemory(m *Module, f func(mem []byte)) { f(m.memory) }

// stopAgents is the in-package stand-in for the runtime helper of the same
// name, which ends the waits of the module's agents on its memory with end:
// this Module has no agents. The generated output has the real one; this one
// is not emitted.
func stopAgents(m *Module, end any) {}

// runtimeMapping, runtimeMappingOf, whileRuntimeMapped, noteSegment,
// forkRuntimeMapping and unmapMemory are the in-package stand-ins for the
// shared-image runtime's of the same names: a mapping the runtime made
// (SharedImage.Memory, MapMemory, ForkMemory) and not released, the one an
// instance's memory is, f run while one is not released, the record of a
// segment attached over one or detached from it, the duplicate a fork of an
// instance on one gets (nil for memory that is none), and the release of
// one. The generated output has the real ones; in this package no memory
// is one. These are not emitted.
type runtimeMapping struct{}

func runtimeMappingOf(mem []byte) *runtimeMapping { return nil }

func whileRuntimeMapped(m *runtimeMapping, f func()) bool { return false }

func noteSegment(m *runtimeMapping, at []byte, attached bool) {}

func forkRuntimeMapping(m *Module) (memory []byte, memSize uint64, err error) {
	return nil, m.memSize.Load(), nil
}

func unmapMemory(mem []byte) error { return nil }

// onAgentEnd is the in-package stand-in for the runtime helper of the same
// name, which has ended told of each agent of the module whose goroutine has
// returned: this Module has no agents. The generated output has the real
// one; this one is not emitted.
func onAgentEnd(m *Module, ended func(agent *Module)) {}

// WasiExitError is the panic value of a guest that called Proc_exit(). A
// bulk-dispatch function (Inv_<svc>_<mt>) recovers it and returns it wrapped
// in its error, which errors.As reaches; an export method and the
// constructor (which runs the start function) let it panic. Either way the
// caller can read the exit code instead of the host process exiting.
type WasiExitError struct{ Code int32 }

func (e *WasiExitError) Error() string {
	return "wasi: proc_exit(" + strconv.Itoa(int(e.Code)) + ")"
}

// WasiSignalError is the panic value of a guest that ended by a signal
// (Proc_raise, Proc_terminate), the counterpart of WasiExitError: it reaches
// the caller the same way, which then knows the instance is gone and which
// signal ended it. Signal is the guest's number for the signal (Linux
// numbering), as PostSignal takes it.
type WasiSignalError struct{ Signal int32 }

func (e *WasiSignalError) Error() string {
	return "wasi: terminated by signal " + strconv.Itoa(int(e.Signal))
}

// endsInstance marks WasiExitError and WasiSignalError as the ends of the
// whole instance: a thread of the guest that unwinds with one ends quietly
// (threadLaunch), for the instance's other threads end with it
// (WasiStubs.stop).
func (e *WasiExitError) endsInstance() {}

func (e *WasiSignalError) endsInstance() {}

// FS is the read/write filesystem backend the WASI host opens files through:
// a directory tree, whose methods are those of *os.Root with the names and
// signatures os.Root gives them, so that an FS is written as code against
// os.Root is. It abstracts the default os-backed filesystem so an embedder
// can supply an alternative — an in-memory FS, an overlay, a read-only
// bundle, ... — and have every guest path operation (open, stat, mkdir,
// readdir, write, ...) routed to it. Where WASI needs what os.Root has no
// method for, FS has one more: Unlink and Rmdir in place of Remove,
// Lchtimes, and an OpenFile that honours syscall.O_NOFOLLOW.
//
// Names are GUEST paths relative to the FS, in the one form
// io/fs.ValidPath accepts: slash-separated, with no leading slash and no
// empty, "." or ".." element, and "." for the FS's directory itself (e.g.
// "etc/app.conf"). A name the guest wrote with a trailing "/" (or "/.") is
// given with one trailing "/", which asks for a directory: an operation on
// a name that is not one fails with syscall.ENOTDIR (as a host's does), and
// one that would create a file there with syscall.EISDIR. The runtime
// resolves ".." itself, after the symbolic links before it as the system
// does, through Lstat and Readlink: ".." of the root is the root, and a
// link's absolute target leads from the root. Methods
// should return the standard fs errors (fs.ErrNotExist, fs.ErrExist,
// fs.ErrPermission) so the host maps them to the right wasi errno; an FS
// that cannot do what a method asks returns errors.ErrUnsupported (ENOSYS).
//
// What an FS can do beyond these methods it says by the optional
// interfaces it implements, which the runtime asks for and nothing else:
// OpenRootFS, MkfifoFS, LockFS, AccessFS and HostRootFS, and of its files
// ChtimesFile. Go's package os has none of them but OpenRootFS, whose OpenRoot
// is os.Root's. An FS that wraps another keeps what the
// other does by calling the other's methods, each of which is one
// operation of the other, and keeps what the other can do beyond them by
// implementing the same optional interfaces; but for one thing: on Linux
// the files, directories and FIFOs HostFS's FS creates get the instance's
// umask taken out by the host's kernel, which a default ACL of their
// directory may stand in for, and those a wrapper of it creates get the
// requested mode less the umask (see create).
type FS interface {
	// OpenFile opens name as os.Root.OpenFile does: flag is
	// O_RDONLY/O_WRONLY/O_RDWR optionally OR'd with
	// O_CREATE/O_EXCL/O_TRUNC/O_APPEND, and perm may carry the setuid,
	// setgid and sticky bits. A symbolic link at the end of name is not
	// followed when flag has syscall.O_NOFOLLOW, as with os.OpenFile (an
	// open of one fails, ELOOP). The returned File must support the
	// operations the mode implies.
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	Mkdir(name string, perm os.FileMode) error
	// Chmod sets the permission bits of name, and its setuid, setgid and
	// sticky bits from the corresponding os.FileMode flags.
	Chmod(name string, mode os.FileMode) error
	// Chown and Lchown change the owner and group of name, as
	// os.Root.Chown and os.Root.Lchown do: Lchown a symbolic link itself.
	// An id of -1 is left as it is.
	Chown(name string, uid, gid int) error
	Lchown(name string, uid, gid int) error
	// Chtimes sets the access and modification times of name; Lchtimes
	// those of a symbolic link itself, which os.Root has no method for
	// (utimensat(2) with AT_SYMLINK_NOFOLLOW).
	Chtimes(name string, atime, mtime time.Time) error
	Lchtimes(name string, atime, mtime time.Time) error
	// Unlink removes the name of a file that is not a directory, as
	// unlink(2) does (a directory: syscall.EISDIR), and Rmdir an empty
	// directory, as rmdir(2) does (no directory: syscall.ENOTDIR).
	// os.Root's Remove, which tries both, is not among them: what a name
	// is may change between the guest's look and the removal.
	Unlink(name string) error
	Rmdir(name string) error
	Rename(oldName, newName string) error
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Symlink(oldName, newName string) error
	Readlink(name string) (string, error)
	Link(oldName, newName string) error
	// Close releases what the FS holds, as os.Root.Close does.
	Close() error
}

// File is an open file handle returned by FS.OpenFile, with the methods of
// *os.File of the same names: *os.File satisfies it, so the default os
// backend needs no wrapper.
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
	// Chown changes the owner and group of the open file (fchown).
	Chown(uid, gid int) error
	Name() string
}

// OpenRootFS is an FS that opens a directory of its own as an FS, as
// os.Root.OpenRoot does: the names of the FS OpenRoot returns are relative
// to that directory, which it finds wherever it is now, across renames.
// Its Close releases what it holds. HostFS's do so but where an FS of a
// directory of HostFS(dir) cannot hold the directory itself (an instance
// whose descriptors are the host process's, a directory that may not be
// searched, or one whose name another took while it was opened) and on
// darwin for HostFS("/"): there a name is looked up from the name the
// directory has now, so a rename between the look and the call can make
// it act on another directory (inside the root, for HostFS(dir)). The runtime opens each directory the
// guest opens so, and gives that FS the names relative to the directory's
// descriptor; of an FS that is no OpenRootFS, or whose OpenRoot returns
// errors.ErrUnsupported, those names are found from the path the
// directory was opened under. An FS that wraps another to keep a policy
// is an OpenRootFS only by implementing OpenRoot and wrapping the FS it
// returns (README); one that does not keeps the policy on those names too,
// as they are given to it by path. The descriptors an OpenRootFS of the
// embedder's holds are not moved above the guests' numbers
// (WASIConfig.HostDescriptors), as those of a File that is no *os.File are
// not.
type OpenRootFS interface {
	FS
	OpenRoot(name string) (FS, error)
}

// MkfifoFS is an FS that makes FIFOs (mkfifo). The guest of an FS that is
// not a MkfifoFS fails them with ENOSYS.
type MkfifoFS interface {
	FS
	// Mkfifo creates a FIFO at name with the permission bits perm.
	Mkfifo(name string, perm os.FileMode) error
}

// AccessFS is an FS that decides itself whether the guest may access its
// files (access, faccessat). The guest of an FS that is not an AccessFS,
// or whose Access returns errors.ErrUnsupported, is answered by the file's
// mode bits and owner, for the ids of the Process (see Path_access).
type AccessFS interface {
	FS
	// Access returns nil when the accesses of mode — access(2)'s R_OK (4),
	// W_OK (2) and X_OK (1), or 0 for whether name exists — may be made to
	// name, following a symbolic link, with the effective ids or the real
	// ones as effective tells; fs.ErrPermission or the error of finding
	// name otherwise.
	Access(name string, mode uint32, effective bool) error
}

// HostRootFS is an FS whose names are paths of the host's: the file of
// name is the host's file at filepath.Join(HostRoot(), name), resolved as
// the host resolves it. The runtime gives such a path to the host where
// the host takes one (a Unix-domain socket's address) and names a host
// file under HostRoot by its name in the FS (the link of a standard stream
// in /dev/fd). Of HostFS's, only the whole host filesystem's is one.
type HostRootFS interface {
	FS
	// HostRoot returns the host directory the names are relative to.
	HostRoot() string
}

// ChtimesFile is a File whose times are set through it (futimens). The
// times of a file that is not a ChtimesFile are set by its name.
type ChtimesFile interface {
	File
	Chtimes(atime, mtime time.Time) error
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
// pass-through, where the guest path name is the host path dir+"/"+name.
// dir is empty for the root ("/"), and the path an FS of one of its
// directories (osDir) finds the directory by.
type osFS struct{ dir string }

// HostFS returns the host filesystem under the host directory root as an FS:
// the guest's "/" is root. An empty root is an error: it names no
// directory.
//
// For root "/" (any root that filepath.Clean makes "/", such as "//" or
// "/.") it is the whole host filesystem, and a guest path is the host path:
// nothing is outside it.
//
// For any other root it is built on os.OpenRoot(root), whose error it
// returns: the FS holds the root directory open until its Close method is
// called. A symbolic link the FS follows out of the root is refused by
// os.Root, which the guest sees as EACCES. A name with a trailing "/" is
// refused so only by the os.Root of Go 1.25.12 or later in the 1.25
// series, 1.26.5 or later in the 1.26 series, and any later release: the
// runtime is compiled with the module it is generated into, which must be
// built with one of those. One the runtime resolves before
// a ".." (see FS) leads from the root as in chroot(2), and ".." of the root
// is the root. The symbolic links the guest creates may point anywhere: the
// guest cannot follow them out of the root, a reader on the host can. A
// rename is os.Root.Rename (see rootFS.Rename). Everything, the root itself
// included, goes through the directory os.Root holds, so the root must be a
// directory that may be searched: HostFS returns the error of looking at it
// otherwise.
//
// A guest's open of a FIFO waits for the other end, as open(2) does. When
// the wait of an open for writing, or of any open of a FIFO where the host
// does not tell of the opens of a FIFO (darwin, a Linux without /proc or
// inotify), ends before the other end comes — a signal interrupts it, or
// the guest ends — the open is made to return by opening the FIFO for
// reading and writing, and both ends are closed again: a process that opens
// the FIFO meanwhile finds that end, which goes away at once.
func HostFS(root string) (FS, error) {
	switch {
	case root == "":
		return nil, errors.New("HostFS: empty root")
	case filepath.Clean(root) == "/":
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
	at, err := runtimeFile(func() (*os.File, error) { return r.OpenFile(".", hostDirOpen, 0) })
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return rootFS{root: r, escape: escape, at: at}, nil
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

// HostRoot returns the host directory a name is the path in: "/" for the
// whole host filesystem.
func (o osFS) HostRoot() string { return cmp.Or(o.dir, "/") }

func (o osFS) join(name string) string {
	// "." is the directory itself: a call on "/" is the host's call on
	// "/" (rmdir of it is EBUSY; of "/." it would be EINVAL), and one of
	// a directory's FS (osDir) the call relative to it on "." (dir is
	// /proc/self/fd/N there, a link to the directory, which "." is not).
	if name == "." {
		if o.dir == "" {
			return "/"
		}
		return o.dir + "/."
	}
	return o.dir + "/" + name // not path.Join, which would drop a trailing "/"
}

// OpenRoot returns the directory name as an FS of its own (osDir), whose
// names are those of the whole host filesystem from the directory, as the
// system's calls relative to a directory descriptor find them. Where the
// system does not tell where a directory open is now (hostDirAt) it is
// errors.ErrUnsupported. The directory's descriptor is one the runtime
// makes for itself (runtimeFile).
func (o osFS) OpenRoot(name string) (FS, error) {
	f, err := runtimeFile(func() (*os.File, error) { return os.OpenFile(o.join(name), hostDirOpen, 0) })
	if err != nil {
		return nil, err
	}
	at, err := hostDirAt(f)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return osDir{f: f, at: at}, nil
}

// osDir is an FS of a directory of the whole host filesystem
// (osFS.OpenRoot): the directory open as f, whose names are the whole host
// filesystem's from where it is now, so that a call through it does what
// the system's call relative to its descriptor does. at is a path of the
// host that leads to the directory itself wherever it is (/proc/self/fd/N
// on Linux); where the system has none, the name the directory has now is
// asked for on every call (hostFDName).
type osDir struct {
	f  *os.File
	at string
}

// host returns the whole host filesystem from the directory. Where it is
// found by the name the directory has now (darwin), a rename between that
// look and the call makes the call by the old name.
func (d osDir) host() (osFS, error) {
	if d.at != "" {
		return osFS{dir: d.at}, nil
	}
	dir, err := hostFDName(d.f)
	if err != nil {
		return osFS{}, err
	}
	return osFS{dir: dir}, nil
}

// do runs call on the whole host filesystem from the directory.
func (d osDir) do(call func(o osFS) error) error {
	o, err := d.host()
	if err != nil {
		return err
	}
	return call(o)
}

func (d osDir) OpenFile(name string, flag int, perm os.FileMode) (f File, err error) {
	err = d.do(func(o osFS) error { f, err = o.OpenFile(name, flag, perm); return err })
	return f, err
}
func (d osDir) OpenRoot(name string) (sub FS, err error) {
	err = d.do(func(o osFS) error { sub, err = o.OpenRoot(name); return err })
	return sub, err
}
func (d osDir) Mkdir(name string, perm os.FileMode) error {
	return d.do(func(o osFS) error { return o.Mkdir(name, perm) })
}
func (d osDir) Chmod(name string, mode os.FileMode) error {
	return d.do(func(o osFS) error { return o.Chmod(name, mode) })
}
func (d osDir) Chown(name string, uid, gid int) error {
	return d.do(func(o osFS) error { return o.Chown(name, uid, gid) })
}
func (d osDir) Lchown(name string, uid, gid int) error {
	return d.do(func(o osFS) error { return o.Lchown(name, uid, gid) })
}
func (d osDir) Chtimes(name string, atime, mtime time.Time) error {
	return d.do(func(o osFS) error { return o.Chtimes(name, atime, mtime) })
}
func (d osDir) Lchtimes(name string, atime, mtime time.Time) error {
	return d.do(func(o osFS) error { return o.Lchtimes(name, atime, mtime) })
}
func (d osDir) Unlink(name string) error { return d.do(func(o osFS) error { return o.Unlink(name) }) }
func (d osDir) Rmdir(name string) error  { return d.do(func(o osFS) error { return o.Rmdir(name) }) }
func (d osDir) Rename(a, b string) error { return d.do(func(o osFS) error { return o.Rename(a, b) }) }
func (d osDir) Link(a, b string) error   { return d.do(func(o osFS) error { return o.Link(a, b) }) }
func (d osDir) Symlink(target, name string) error {
	return d.do(func(o osFS) error { return o.Symlink(target, name) })
}
func (d osDir) Stat(name string) (fi os.FileInfo, err error) {
	err = d.do(func(o osFS) error { fi, err = o.Stat(name); return err })
	return fi, err
}
func (d osDir) Lstat(name string) (fi os.FileInfo, err error) {
	err = d.do(func(o osFS) error { fi, err = o.Lstat(name); return err })
	return fi, err
}
func (d osDir) Readlink(name string) (target string, err error) {
	err = d.do(func(o osFS) error { target, err = o.Readlink(name); return err })
	return target, err
}

// Close closes the directory.
func (d osDir) Close() error { return d.f.Close() }

// sameFileAt returns nil when name is where the file open as f is: a Stat
// of name finds that file. A name that leads elsewhere, or to nothing, is
// ENOENT: the file has no name there now.
func sameFileAt(f *os.File, name string) error {
	at, err := os.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return &fs.PathError{Op: "stat", Path: name, Err: syscall.ENOENT}
	}
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(at, fi) {
		return &fs.PathError{Op: "stat", Path: name, Err: syscall.ENOENT}
	}
	return nil
}

// Chown changes the owner and group of a file of the host filesystem;
// Lchown those of a symbolic link itself. -1 leaves an id as it is.
func (o osFS) Chown(name string, uid, gid int) error  { return os.Chown(o.join(name), uid, gid) }
func (o osFS) Lchown(name string, uid, gid int) error { return os.Lchown(o.join(name), uid, gid) }

// Lchtimes sets the times of a symbolic link itself (hostLchtimes).
func (o osFS) Lchtimes(name string, atime, mtime time.Time) error {
	return hostLchtimes(o.join(name), atime, mtime)
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
func (o osFS) Rename(a, b string) error                  { return hostRename(o.join(a), o.join(b)) }
func (o osFS) Stat(name string) (os.FileInfo, error)     { return os.Stat(o.join(name)) }
func (o osFS) Lstat(name string) (os.FileInfo, error)    { return os.Lstat(o.join(name)) }
func (o osFS) Symlink(target, name string) error         { return os.Symlink(target, o.join(name)) }
func (o osFS) Readlink(name string) (string, error)      { return os.Readlink(o.join(name)) }
func (o osFS) Link(a, b string) error                    { return os.Link(o.join(a), o.join(b)) }

// hostDir is an FS of a directory of a HostFS of a directory
// (rootFS.OpenRoot): a name is found from the directory os.Root holds (in),
// which keeps track of it across renames, and a name os.Root refuses,
// because a symbolic link leads it out of the directory, from the root, as
// the name the directory has there now followed by the name (rootName), so
// that the link leads where it points inside the root and the root refuses
// what leads out of it. f is the directory open as a file, which tells
// where it is (hostFDName). Where in is nil (openHostDir: an instance whose
// descriptors are the host process's, a directory that may not be searched
// when it is opened, or one whose name another took between the two
// opens), every name is found from the root so; a rename between that look
// and the call makes the call by the old name, one of the root's still.
type hostDir struct {
	in   *rootFS
	f    *os.File
	root rootFS
}

// openHostDir opens the directory name of at, a directory of root or root
// itself, as an FS of root's (hostDir): its file through os.Root as a
// descriptor the runtime makes for itself (runtimeFile), and the os.Root
// of it (in) once it is found to be the same directory (sameRootDir: not
// so for one that may not be searched, or whose name another took between
// the two opens) and the runtime does not keep its descriptors above the
// guests' numbers (runtimeFloor), as os.Root's descriptor cannot be moved
// there; without in, names are found from the root, which is
// errors.ErrUnsupported where the system does not tell where a directory
// is (no /proc, a name longer than it tells).
func openHostDir(at rootFS, name string, root rootFS) (FS, error) {
	f, err := runtimeFile(func() (*os.File, error) { return at.root.OpenFile(at.name(name), hostDirOpen, 0) })
	if err != nil {
		return nil, at.refused(err)
	}
	var in *rootFS
	if err := makeRuntimeDescriptors(func() error {
		sub, err := at.root.OpenRoot(at.name(name))
		if err != nil {
			return err
		}
		if runtimeFloor() != 0 || !sameRootDir(sub, f) {
			return sub.Close()
		}
		in = &rootFS{root: sub, escape: root.escape}
		return nil
	}); err != nil {
		return nil, errors.Join(at.refused(err), f.Close())
	}
	if in == nil {
		if _, err := rootRelName(root, f); err != nil {
			return nil, &fs.PathError{Op: "openroot", Path: name, Err: errors.Join(errors.ErrUnsupported, err, f.Close())}
		}
	}
	return hostDir{in: in, f: f, root: root}, nil
}

// sameRootDir reports whether the directory r holds is the one open as f.
// One r may not search ("." is looked up) is taken for another.
func sameRootDir(r *os.Root, f *os.File) bool {
	a, err := r.Stat(".")
	if err != nil {
		return false
	}
	b, err := f.Stat()
	return err == nil && os.SameFile(a, b)
}

// rootName is the root's name for name, a name of the directory, from
// where the directory is now in the root (rootRelName).
func (d hostDir) rootName(name string) (string, error) {
	rel, err := rootRelName(d.root, d.f)
	if err != nil {
		return "", err
	}
	switch {
	case rel == ".":
		return name, nil
	case name == ".":
		return rel, nil
	}
	return rel + "/" + name, nil // not path.Join, which would drop a trailing "/"
}

// rootRelName returns r's name for the file open as f, from where both are
// now (hostFDName): one outside r begins with "..", which r refuses as a
// name that leads out of it.
func rootRelName(r rootFS, f *os.File) (string, error) {
	file, err := hostFDName(f)
	if err != nil {
		return "", err
	}
	root, err := hostFDName(r.at)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// escaped reports whether err is in's refusal of a name that leads out of
// the directory.
func (d hostDir) escaped(err error) bool { return err != nil && errors.Is(err, d.root.escape) }

// do runs call on in with name, and on the root with its name for name
// where there is no in or in refuses the name for leading out. Where the
// root has no name for it (rootName), in's refusal stands.
func (d hostDir) do(name string, call func(r rootFS, name string) error) error {
	var inErr error
	if d.in != nil {
		if inErr = call(*d.in, name); !d.escaped(inErr) {
			return inErr
		}
	}
	n, err := d.rootName(name)
	if err != nil {
		return cmp.Or(inErr, err)
	}
	return call(d.root, n)
}

// do2 is do for a call of two names.
func (d hostDir) do2(a, b string, call func(r rootFS, a, b string) error) error {
	var inErr error
	if d.in != nil {
		if inErr = call(*d.in, a, b); !d.escaped(inErr) {
			return inErr
		}
	}
	na, err := d.rootName(a)
	if err != nil {
		return cmp.Or(inErr, err)
	}
	nb, err := d.rootName(b)
	if err != nil {
		return cmp.Or(inErr, err)
	}
	return call(d.root, na, nb)
}

func (d hostDir) OpenFile(name string, flag int, perm os.FileMode) (f File, err error) {
	err = d.do(name, func(r rootFS, name string) error { f, err = r.OpenFile(name, flag, perm); return err })
	return f, err
}

// OpenRoot opens a directory of the directory as an FS of the root's, from
// in or from the root as do finds names.
func (d hostDir) OpenRoot(name string) (sub FS, err error) {
	err = d.do(name, func(r rootFS, name string) error { sub, err = openHostDir(r, name, d.root); return err })
	return sub, err
}
func (d hostDir) Mkdir(name string, perm os.FileMode) error {
	return d.do(name, func(r rootFS, name string) error { return r.Mkdir(name, perm) })
}
func (d hostDir) Chmod(name string, mode os.FileMode) error {
	return d.do(name, func(r rootFS, name string) error { return r.Chmod(name, mode) })
}
func (d hostDir) Chown(name string, uid, gid int) error {
	return d.do(name, func(r rootFS, name string) error { return r.Chown(name, uid, gid) })
}
func (d hostDir) Lchown(name string, uid, gid int) error {
	return d.do(name, func(r rootFS, name string) error { return r.Lchown(name, uid, gid) })
}
func (d hostDir) Chtimes(name string, atime, mtime time.Time) error {
	return d.do(name, func(r rootFS, name string) error { return r.Chtimes(name, atime, mtime) })
}
func (d hostDir) Lchtimes(name string, atime, mtime time.Time) error {
	return d.do(name, func(r rootFS, name string) error { return r.Lchtimes(name, atime, mtime) })
}
func (d hostDir) Unlink(name string) error {
	return d.do(name, func(r rootFS, name string) error { return r.Unlink(name) })
}
func (d hostDir) Rmdir(name string) error {
	return d.do(name, func(r rootFS, name string) error { return r.Rmdir(name) })
}
func (d hostDir) Rename(a, b string) error {
	return d.do2(a, b, func(r rootFS, a, b string) error { return r.Rename(a, b) })
}
func (d hostDir) Link(a, b string) error {
	return d.do2(a, b, func(r rootFS, a, b string) error { return r.Link(a, b) })
}
func (d hostDir) Symlink(target, name string) error {
	return d.do(name, func(r rootFS, name string) error { return r.Symlink(target, name) })
}
func (d hostDir) Stat(name string) (fi os.FileInfo, err error) {
	err = d.do(name, func(r rootFS, name string) error { fi, err = r.Stat(name); return err })
	return fi, err
}
func (d hostDir) Lstat(name string) (fi os.FileInfo, err error) {
	err = d.do(name, func(r rootFS, name string) error { fi, err = r.Lstat(name); return err })
	return fi, err
}
func (d hostDir) Readlink(name string) (target string, err error) {
	err = d.do(name, func(r rootFS, name string) error { target, err = r.Readlink(name); return err })
	return target, err
}

// Close closes the directory, and the os.Root of it.
func (d hostDir) Close() error {
	if d.in == nil {
		return d.f.Close()
	}
	return errors.Join(d.in.root.Close(), d.f.Close())
}

// rootFS is the FS HostFS returns for a root other than the whole host
// filesystem: the host directory os.Root holds, which refuses every path
// that escapes it with escape, and at, the same directory open as a file,
// which tells where the root is now (hostFDName).
type rootFS struct {
	root   *os.Root
	escape error
	at     *os.File
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
	if hostONofollow != 0 && flag&hostONofollow != 0 {
		return r.openNoFollow(name, flag&^hostONofollow, perm)
	}
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

// Unlink and Rmdir remove a file and an empty directory, each refusing the
// other kind, through one call relative to the name's directory where the
// host has one (unlinkAt, rmdirAt).
func (r rootFS) Unlink(name string) error { return r.refused(r.unlinkAt(r.name(name))) }
func (r rootFS) Rmdir(name string) error  { return r.refused(r.rmdirAt(r.name(name))) }

// Lchtimes sets the times of a symbolic link itself (lchtimesAt).
func (r rootFS) Lchtimes(name string, atime, mtime time.Time) error {
	return r.refused(r.lchtimesAt(r.name(name), atime, mtime))
}

// OpenRoot returns the directory name as an FS of its own (openHostDir).
func (r rootFS) OpenRoot(name string) (FS, error) { return openHostDir(r, name, r) }

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

// Chown and Lchown change the owner and group of a file, as osFS's do.
func (r rootFS) Chown(name string, uid, gid int) error {
	return r.refused(r.root.Chown(r.name(name), uid, gid))
}
func (r rootFS) Lchown(name string, uid, gid int) error {
	return r.refused(r.root.Lchown(r.name(name), uid, gid))
}

// Close closes the root directory.
func (r rootFS) Close() error { return errors.Join(r.at.Close(), r.root.Close()) }

// noFS is the FS of a WASIConfig that names none: it has no file, so every
// operation fails with fs.ErrNotExist (ENOENT).
type noFS struct{}

func (noFS) OpenFile(string, int, os.FileMode) (File, error) { return nil, fs.ErrNotExist }
func (noFS) Mkdir(string, os.FileMode) error                 { return fs.ErrNotExist }
func (noFS) Chmod(string, os.FileMode) error                 { return fs.ErrNotExist }
func (noFS) Chtimes(string, time.Time, time.Time) error      { return fs.ErrNotExist }
func (noFS) Lchtimes(string, time.Time, time.Time) error     { return fs.ErrNotExist }
func (noFS) Chown(string, int, int) error                    { return fs.ErrNotExist }
func (noFS) Lchown(string, int, int) error                   { return fs.ErrNotExist }
func (noFS) Unlink(string) error                             { return fs.ErrNotExist }
func (noFS) Rmdir(string) error                              { return fs.ErrNotExist }
func (noFS) Close() error                                    { return nil }
func (noFS) Rename(string, string) error                     { return fs.ErrNotExist }
func (noFS) Stat(string) (os.FileInfo, error)                { return nil, fs.ErrNotExist }
func (noFS) Lstat(string) (os.FileInfo, error)               { return nil, fs.ErrNotExist }
func (noFS) Symlink(string, string) error                    { return fs.ErrNotExist }
func (noFS) Readlink(string) (string, error)                 { return "", fs.ErrNotExist }
func (noFS) Link(string, string) error                       { return fs.ErrNotExist }

// MemFS is an in-memory read/write FS. Each value is an independent tree, so
// two guest programs given separate MemFS values cannot observe each other's
// files (full per-program filesystem isolation, no disk). Build one with
// NewMemFS. Safe for concurrent use. A guest's flock (fd_flock) that waits
// for a lock of a file of it is called off when the guest stops waiting
// (see LockFS): nothing of it is left to run.
type MemFS struct {
	*memTree
	// root is the directory the names are relative to: the tree's root,
	// or the directory of a MemFS OpenRoot returned.
	root *memNode
}

// memTree is what the MemFS values of one tree share: the one returned by
// NewMemFS and those OpenRoot returns for its directories.
type memTree struct {
	mu sync.Mutex
	// maxFileSize is the size a write or a truncation can make a file;
	// NewMemFS sets it to memMaxFileSize.
	maxFileSize int64
	// lastIno is the inode number of the node made last.
	lastIno uint64
	// lockReleased is closed, and dropped for the next waiter to make a
	// fresh one, whenever a lock of a node is removed (Flock); nil while
	// nobody waits.
	lockReleased chan struct{}
}

// NewMemFS returns an empty in-memory filesystem with a root directory.
func NewMemFS() *MemFS {
	return &MemFS{root: &memNode{ino: 1, dir: true, mode: os.ModeDir | 0o755, modTime: time.Unix(0, 0), children: map[string]*memNode{}},
		memTree: &memTree{maxFileSize: memMaxFileSize, lastIno: 1}}
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
	// locks holds the lock (flockShared or flockExclusive) each open file
	// that holds one has on the node (Flock).
	locks map[*memFile]int
}

// memSplit returns the elements of the path name, with ".." resolved
// lexically (a MemFS has no symbolic links) and ".." of the root the root;
// none for the root itself.
func memSplit(name string) []string {
	name = path.Clean("/" + name)
	if name == "/" {
		return nil
	}
	return strings.Split(name[1:], "/")
}

// lookup resolves name to a node. Caller holds fsys.mu.
func (fsys *MemFS) lookup(name string) (*memNode, error) {
	n := fsys.root
	if n.unlinked {
		return nil, fs.ErrNotExist // the directory of a view (OpenRoot) was removed
	}
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
	if !n.dir && strings.HasSuffix(name, "/") {
		return nil, syscall.ENOTDIR // a name ending in "/" is a directory's
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
	if n.unlinked {
		return nil, "", fs.ErrNotExist // the directory of a view (OpenRoot) was removed
	}
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
		switch {
		case flag&os.O_CREATE == 0 || !errors.Is(err, fs.ErrNotExist):
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		case strings.HasSuffix(name, "/"):
			// what a host's open(2) gives for a file to create there
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
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
		if node.dir && flag&(os.O_WRONLY|os.O_RDWR) != 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EISDIR}
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

// Unlink removes the name of a file that is not a directory (EISDIR).
func (fsys *MemFS) Unlink(name string) error { return fsys.remove("unlink", name, false) }

// Rmdir removes an empty directory (ENOTDIR for a file, ENOTEMPTY).
func (fsys *MemFS) Rmdir(name string) error { return fsys.remove("rmdir", name, true) }

// remove removes name, a directory when dir is true and a file otherwise.
func (fsys *MemFS) remove(op, name string, dir bool) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	parent, base, err := fsys.lookupParent(name)
	if err != nil {
		return &fs.PathError{Op: op, Path: name, Err: err}
	}
	n, ok := parent.children[base]
	switch {
	case !ok:
		err = fs.ErrNotExist
	case n.dir && !dir:
		err = syscall.EISDIR
	case !n.dir && (dir || strings.HasSuffix(name, "/")):
		err = syscall.ENOTDIR
	case n.dir && len(n.children) > 0:
		err = syscall.ENOTEMPTY
	}
	if err != nil {
		return &fs.PathError{Op: op, Path: name, Err: err}
	}
	delete(parent.children, base)
	n.unlinked = true
	return nil
}

// OpenRoot returns the directory name as a MemFS of its own, which keeps
// track of it across renames: it shares the tree.
func (fsys *MemFS) OpenRoot(name string) (FS, error) {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n, err := fsys.lookup(name)
	switch {
	case err != nil:
	case !n.dir:
		err = syscall.ENOTDIR
	}
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: err}
	}
	return &MemFS{memTree: fsys.memTree, root: n}, nil
}

// Chown and Lchown fail: a MemFS keeps no owners (errors.ErrUnsupported).
func (fsys *MemFS) Chown(name string, uid, gid int) error {
	return &fs.PathError{Op: "chown", Path: name, Err: errors.ErrUnsupported}
}
func (fsys *MemFS) Lchown(name string, uid, gid int) error {
	return &fs.PathError{Op: "lchown", Path: name, Err: errors.ErrUnsupported}
}

// Lchtimes is Chtimes: a MemFS has no symbolic links.
func (fsys *MemFS) Lchtimes(name string, atime, mtime time.Time) error {
	return fsys.Chtimes(name, atime, mtime)
}

// Close does nothing: a MemFS holds nothing of the host's.
func (fsys *MemFS) Close() error { return nil }

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

// memModeBits are the mode bits Chmod sets of a MemFS file: the
// permission bits and the setuid, setgid and sticky bits.
const memModeBits = os.ModePerm | specialModeBits

// Chmod sets the permission, setuid, setgid and sticky bits of name.
func (fsys *MemFS) Chmod(name string, mode os.FileMode) error {
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	n, err := fsys.lookup(name)
	if err != nil {
		return &fs.PathError{Op: "chmod", Path: name, Err: err}
	}
	n.mode = n.mode&^memModeBits | mode&memModeBits
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
// populate the FS (e.g. unpack the guest program's files) before handing it
// to a module.
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
	fi := memFileInfo{ino: n.ino, name: n.name, size: int64(len(n.data)), mode: n.mode & memModeBits, modTime: n.modTime, unlinked: n.unlinked}
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

// Close removes the lock the open file holds (Flock).
func (f *memFile) Close() error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.unlockLocked()
	return nil
}
func (f *memFile) Sync() error { return nil }

// Chown fails: a MemFS keeps no owners (errors.ErrUnsupported).
func (f *memFile) Chown(uid, gid int) error {
	return &fs.PathError{Op: "fchown", Path: f.node.name, Err: errors.ErrUnsupported}
}

// Chmod sets the permission bits of the open file.
func (f *memFile) Chmod(mode os.FileMode) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.node.mode = f.node.mode&^memModeBits | mode&memModeBits
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
	isSocket bool // created by Sock_socket, Sock_open, Sock_socketpair or an accept; may not yet have a conn
	// family (wasiSockFamily*) and dgram are what a socket of the host's
	// (sock) is, from its making on.
	family int32
	dgram  bool
	// sock is what a socket of the host's has of its own (wasiSocket);
	// nil for an entry without one.
	sock *wasiSocket
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
	// root is the directory as an FS of its own (FS.OpenRoot), which the
	// names relative to the descriptor are given to (atName): for a
	// directory path_open opened of an FS that has it; nil otherwise.
	// Immutable; closed with the descriptor.
	root FS
	// stdio marks an entry that refers to a standard stream of the
	// instance (1/2/3 = the configured stdin/stdout/stderr; 0 = not one).
	// Fds 0/1/2 start out with such entries; closing one never touches the
	// stream itself.
	stdio int8
	// refs counts the table slots that hold this entry, of every instance
	// (dup, dup2, Fork): the descriptor is closed when the last one is
	// cleared (setSlotLocked, clearSlotLocked). Guarded by mu.
	refs int32
	// ahead is input of the descriptor's a command was given and did not
	// read (giveAhead). Reads of this descriptor drain ahead before they
	// touch the stream. Guarded by mu.
	ahead []byte
	// reader is the reader of the stream behind the entry when poll(2)
	// does not wait for it (inputReader), made on first use; nil for the
	// instance's stdin, whose reader is its family's. Guarded by mu.
	reader *streamReader
	// turn is the turn at this descriptor's input and outTurn the turn at
	// its output; see inputTurn. Made on first use; guarded by mu.
	turn    chan struct{}
	outTurn chan struct{}
	// waiters are the wakes of the waits in poll(2) for the descriptor
	// (addWaiter), which closeWasiOpen writes to. Guarded by mu.
	waiters map[*wasiWake]bool
	// inputWake ends the wait of the holder of the turn at the input in the
	// poller of the Go runtime (watchAhead), which giveAhead calls; nil
	// while there is none. Guarded by mu.
	inputWake func()
	// shared is set once the entry's open file description is given to a
	// command (commandSetup.add, inheritedLocked) or the guest has set its
	// mode (Fd_fdstat_set_flags): whoever holds it outside the runtime can
	// change its mode, so its stream is no longer one the runtime waits for
	// in the Go runtime's poller (netpolled).
	shared atomic.Bool
	// polled is whether the Go runtime polls the entry's host file, or the
	// instance's standard stream it is (filePolled), asked once when the
	// entry is made: asking sets a deadline, which a wait for the file can
	// have set as well.
	polled bool
	// inputReads counts the reads of the entry's host descriptor that took
	// something (readHostAttempt, readNow, readInterruptibly): a reader
	// woken by input knows it is still there when no read has taken any
	// since it began to wait.
	inputReads atomic.Uint64
	// statFile is the host file statOf last asked about, and statMode and
	// namedFIFO what it learnt. Finding out takes a system call, and every
	// read and write needs to know. Guarded by mu.
	statFile  *os.File
	statMode  os.FileMode
	namedFIFO bool
	// terminalFile is the host file terminalOf last asked about, and
	// terminal what it learnt. Guarded by mu.
	terminalFile *os.File
	terminal     bool
	// lowatFile is the socket file streamSendLowat last asked about, and
	// lowat what it learnt. Guarded by mu.
	lowatFile *os.File
	lowat     int
	// lockPending is closed once a lock call whose wait a signal ended
	// has returned and what it took is removed again; nil when there is
	// none (see takeLock). Guarded by mu.
	lockPending chan struct{}
	// lockWaits counts, by lock (takeLock's how), the waits for a lock of
	// the descriptor in progress; lockHeld holds the locks a wait of it
	// took and no later lock call of it has changed. Guarded by mu.
	lockWaits map[int]int
	lockHeld  map[int]bool
	// fileKey is the device and inode of the file of the host Path_open
	// opened, which hasFileKey says there is: the file of its record locks
	// (fd_lock). Immutable.
	fileKey    fileKey
	hasFileKey bool
	// lockedFile is the record lock table's entry of the file, from the
	// descriptor's first fd_lock on (useLockedFile); closeWasiOpen lets it
	// go. Guarded by mu.
	lockedFile *lockedFile
}

// deadlineReader is a stream whose blocking read can be bounded: a pipe, a
// socket, a terminal. Regular files are not (they never block), and say so
// by refusing the deadline.
type deadlineReader interface {
	Read(p []byte) (int, error)
	SetReadDeadline(t time.Time) error
}

// takeAhead serves a read from the input a command left (ahead). ok is
// false when there is none and the read must go to the stream.
func (w *WasiStubs) takeAhead(call string, op *wasiOpen, bufs [][]byte) (n uint64, errno int32, ok bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if len(op.ahead) == 0 {
		return 0, _wasiESUCCESS, false
	}
	return op.copyAheadLocked(bufs, false), _wasiESUCCESS, true
}

// copyAheadLocked copies the input ahead into bufs in order, and takes out
// what it copied unless peek. Caller holds op.mu.
func (op *wasiOpen) copyAheadLocked(bufs [][]byte, peek bool) uint64 {
	n := 0
	for _, buf := range bufs {
		n += copy(buf, op.ahead[n:])
		if n == len(op.ahead) {
			break
		}
	}
	if !peek {
		op.ahead = op.ahead[n:]
		if len(op.ahead) == 0 {
			op.ahead = nil
		}
	}
	return uint64(n)
}

// aheadReady reports whether a read would return without blocking because
// of input a command left, and how many bytes are waiting.
func (op *wasiOpen) aheadReady() (ready bool, pending int) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return len(op.ahead) > 0, len(op.ahead)
}

// inputTurn returns the channel that holds the turn at this descriptor's
// input: whoever has put a value in it has the turn, and gives it back by
// taking the value out (awaitInputTurn, passInputTurn).
//
// A descriptor can be shared — by the slots of one instance (dup) and by the
// instances of a fork family, each on a goroutine of its own. Reading a
// stream waits inside a call of the host's that admits one caller at a time
// and queues the others where nothing can call them back: a deadline ends
// the wait of the one caller inside, not of the queue, and the caller it
// ends need not be the one it was meant for. A guest queued that way could
// not be reached by a signal.
//
// So the waiting is done in turns. Whoever is about to read a descriptor
// takes its turn first, in a select that a signal can end, and only the
// holder of the turn enters the host's call and sets the deadline that
// bounds it.
//
// A descriptor that poll(2) waits for is waited for without the turn
// (readHostStream): only the read of one that can wait in the kernel takes
// it, for the look and the read that follows (readHostAttempt). A stream
// poll(2) does not wait for is read by its reader, which takes no turn
// (streamReader).
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
// as reading an empty one does: the writes that wait take turns, from
// before they write anything until all is written, and a write that does
// not wait does not wait for it (writeHostStream). The two directions have
// a turn each: a process waiting for input on a socket does not keep
// another from writing to it.
func (op *wasiOpen) outputTurn() chan struct{} {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.outTurn == nil {
		op.outTurn = make(chan struct{}, 1)
	}
	return op.outTurn
}

// passOutputTurn gives the turn at the descriptor's output back.
func (op *wasiOpen) passOutputTurn() { <-op.outputTurn() }

// takeTurn waits for a turn and reports whether it got it: not when stop
// was closed first.
func takeTurn(turn chan struct{}, stop <-chan struct{}) bool {
	select {
	case turn <- struct{}{}:
		return true
	default:
	}
	select {
	case turn <- struct{}{}:
		return true
	case <-stop:
	}
	return false
}

// passInputTurn gives the turn back.
func (op *wasiOpen) passInputTurn() { <-op.inputTurn() }

// streamReader is the reader of an input stream that poll(2) does not wait
// for (inputPolled): a stream of the embedder's that is no descriptor of
// the host's, a FIFO whose end poll(2) does not report, any stream where
// the host has no poll(2). One goroutine of its own calls the stream's
// Read, once each time it is asked to (request), and keeps what it returns
// until a read takes it (take). Nothing else of the runtime's calls Read
// (package os/exec does, for the stdin of a command where the host has no
// poll(2)), and the stream is read only when the guest asks for input: a
// read, a poll, the stdin of a command it starts. The
// waits for input are woken by the goroutine when it has some (addWaiter),
// so that whether there is input is a look at what the reader keeps, and
// no wait is bounded by a time (os/exec gives a Reader that is no file to
// a command through a goroutine that copies it, childStdin; wasmtime's
// stdin is read by a thread of its own when the guest asks).
//
// The reader is stopped once the stream's last descriptor is closed and by
// CloseAll (stop): it is asked for nothing more. A Read in progress cannot
// be ended; what it returns is kept, and nothing is told of a failure.
type streamReader struct {
	src io.Reader
	// asked tells the goroutine to read once; it is closed by stop.
	asked chan struct{}

	mu sync.Mutex
	// buf is what the reader read and no read has taken yet; end is what
	// ended a Read (io.EOF or its failure), reported once buf is taken.
	buf []byte
	end error
	// reading is set from a request to the end of the Read it asks for,
	// started once the goroutine runs, stopped once stop is called.
	reading, started, stopped bool
	// waiters are the wakes of the waits for input, written to when the
	// reader has some or is stopped.
	waiters map[*wasiWake]bool
	// report is told the failure of a wake no call is left to return
	// (WASIConfig.Errors).
	report func(error)
}

// newStreamReader returns the reader of src; report is told the failures of
// its wakes.
func newStreamReader(src io.Reader, report func(error)) *streamReader {
	return &streamReader{src: src, asked: make(chan struct{}, 1), report: report}
}

// request asks for a Read of the stream, unless the reader has input or an
// end to give, a Read is in progress, or the reader is stopped.
func (r *streamReader) request() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) > 0 || r.end != nil || r.reading || r.stopped {
		return
	}
	r.reading = true
	if !r.started {
		r.started = true
		go r.run()
	}
	r.asked <- struct{}{}
}

// run is the reader's goroutine: a Read for each request, until stop.
func (r *streamReader) run() {
	buf := make([]byte, 32<<10)
	for range r.asked {
		n, err := r.src.Read(buf)
		r.mu.Lock()
		r.buf = append(r.buf, buf[:n]...)
		if err != nil {
			r.end = err
		}
		r.reading = false
		stopped := r.stopped
		err = r.wakeLocked()
		r.mu.Unlock()
		r.report(err)
		if stopped {
			return
		}
	}
}

// take serves a read from what the reader keeps, as a Read returns it: the
// count, or the end (io.EOF, a failure, os.ErrClosed for a stopped reader);
// ok is false when it keeps nothing. Once its input is taken, one read finds
// the end the Read ran into. The reads after it ask the stream again, which
// can have input by then (a terminal after its end-of-file character).
func (r *streamReader) take(bufs [][]byte) (n int, err error, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		if r.end == nil && r.stopped {
			// The stream's descriptors are closed.
			return 0, os.ErrClosed, true
		}
		end := r.end
		r.end = nil
		return 0, end, end != nil
	}
	k := 0
	for _, buf := range bufs {
		k += copy(buf, r.buf[k:])
		if k == len(r.buf) {
			break
		}
	}
	r.buf = r.buf[k:]
	if len(r.buf) == 0 {
		r.buf = nil
	}
	return k, nil, true
}

// readerInput is a stream's reader read as an io.Reader, by the copy of a
// command's stdin (inputCopy): a Read takes what the reader keeps, or asks
// it for a Read and waits for that, until stop is called, which ends the
// Read with os.ErrDeadlineExceeded, as a read deadline in the past ends a
// read of a descriptor.
type readerInput struct {
	r       *streamReader
	wake    *wasiWake
	stopped chan struct{}
}

// newReaderInput returns the input of r, which waits for r until stop.
func newReaderInput(r *streamReader) *readerInput {
	in := &readerInput{r: r, wake: newChannelWake(), stopped: make(chan struct{})}
	r.addWaiter(in.wake)
	return in
}

func (in *readerInput) Read(p []byte) (int, error) {
	for {
		if n, err, ok := in.r.take([][]byte{p}); ok {
			return n, err
		}
		in.r.request()
		select {
		case <-in.wake.ch:
		case <-in.stopped:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// stop ends the Read in progress and the waits for the reader.
func (in *readerInput) stop() {
	in.r.removeWaiter(in.wake)
	close(in.stopped)
}

// unread gives b back, input a command was given of the stream and did not
// read, ahead of what the reader read after it, and wakes the waits.
func (r *streamReader) unread(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(b, r.buf...)
	return r.wakeLocked()
}

// ready reports whether a read takes something without waiting.
func (r *streamReader) ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf) > 0 || r.end != nil || r.stopped
}

// pending returns how many bytes the reader keeps.
func (r *streamReader) pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

// streamTurn is the turn at a Writer of the embedder's that is no
// descriptor of the host's: whoever has put a value in turn calls Write,
// and nobody else does, so that the Writer is written one call at a time,
// by the guests of a fork family and the copies of their commands' output,
// as os/exec writes the Stdout and Stderr of a command that are one Writer.
// A blocking write waits for it (awaitStreamTurn), which a signal ends, and
// is handed it in the order of the waits when it is given back (give), as
// a sync.Mutex in starvation mode hands itself on; a write that does not
// wait does not, and a poll for writing waits until it is free.
type streamTurn struct {
	// held is set while somebody has the turn. A turn given back with waits
	// queued is handed on; only within a give that let it go without the
	// lock can a wait be queued while it is free, and the next give hands
	// it to that wait.
	held atomic.Bool

	mu sync.Mutex
	// queue are the waits to take the turn (turnWait), in order; waiters
	// the wakes of the polls waiting for it to be free. Guarded by mu;
	// waiting is how many there are of both, which give reads without it.
	queue   []*turnWait
	waiters map[*wasiWake]bool
	waiting atomic.Int32
}

// turnWait is the wait of one call to take a turn: it keeps its place in
// the turn's queue across the waits of the call (awaitStreamTurn), and the
// turn is handed to it (given) when it is the first.
type turnWait struct {
	t *streamTurn
	// wk is the wake of the wait in progress, nil between two; queued says
	// the wait is in t's queue, given that the turn was handed to it.
	// Guarded by t.mu.
	wk            *wasiWake
	queued, given bool
}

// tryTake takes the turn when nobody has it, and reports whether it did.
func (t *streamTurn) tryTake() bool { return t.held.CompareAndSwap(false, true) }

// take takes the turn, waiting for it on wk, a wake of no call of the
// guest's (the copy of a command's output), which no signal ends.
func (t *streamTurn) take(wk *wasiWake) {
	if t.tryTake() {
		return
	}
	q := &turnWait{t: t}
	q.addWaiter(wk)
	for !q.ready() {
		<-wk.ch
	}
	q.removeWaiter(wk)
}

// give gives the turn back: to the first of the waits queued, which is
// woken, or else free, which wakes the polls waiting for it.
func (t *streamTurn) give() error {
	if t.waiting.Load() == 0 {
		t.held.Store(false)
		if t.waiting.Load() == 0 {
			return nil
		}
		// A wait registered meanwhile may have found the turn held: it is
		// handed the turn, unless somebody took it first.
		t.mu.Lock()
		defer t.mu.Unlock()
		if !t.held.CompareAndSwap(false, true) {
			return nil
		}
		return t.handLocked()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handLocked()
}

// handLocked hands the turn, which the caller has, to the first wait of the
// queue, or makes it free when there is none. Caller holds t.mu.
func (t *streamTurn) handLocked() error {
	if len(t.queue) > 0 {
		q := t.queue[0]
		t.queue = t.queue[1:]
		t.waiting.Add(-1)
		q.queued, q.given = false, true
		if q.wk == nil {
			return nil
		}
		return q.wk.wake()
	}
	t.held.Store(false)
	var err error
	for wk := range t.waiters {
		err = errors.Join(err, wk.wake())
	}
	return err
}

// ready reports whether nobody has the turn.
func (t *streamTurn) ready() bool { return !t.held.Load() }

// awaitStreamTurn takes t for a blocking call of the guest's, as awaitTurn
// takes a turn: false when the call is to report a signal posted
// meanwhile, and the turn is not held. A free turn is taken without
// waiting, whatever signal is posted; a held one is waited for in the
// turn's queue.
func (w *WasiStubs) awaitStreamTurn(m *Module, call string, t *streamTurn) (bool, error) {
	if t.tryTake() {
		return true, nil
	}
	q := &turnWait{t: t}
	set := []hostWaitFD{{source: q}}
	returned := false
	defer func() {
		// A call that terminate unwinds leaves the queue, and hands on a
		// turn handed to it.
		if !returned {
			w.reportError(call, q.leave())
		}
	}()
	for {
		interrupted, err := w.waitHostInterruptibly(m, call, set, time.Time{})
		if err != nil || interrupted {
			returned = true
			return false, errors.Join(err, q.leave())
		}
		if q.ready() {
			returned = true
			return true, nil
		}
	}
}

// addWaiter registers wk as the wake of a poll waiting for the turn to be
// free.
func (t *streamTurn) addWaiter(wk *wasiWake) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.waiters == nil {
		t.waiters = map[*wasiWake]bool{}
	}
	if !t.waiters[wk] {
		t.waiters[wk] = true
		t.waiting.Add(1)
	}
}

// removeWaiter undoes addWaiter.
func (t *streamTurn) removeWaiter(wk *wasiWake) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.waiters[wk] {
		delete(t.waiters, wk)
		t.waiting.Add(-1)
	}
}

// ready reports whether the turn was handed to q.
func (q *turnWait) ready() bool {
	q.t.mu.Lock()
	defer q.t.mu.Unlock()
	return q.given
}

// addWaiter makes wk the wake of q's wait, and queues q for the turn the
// first time. A free turn is q's at once.
func (q *turnWait) addWaiter(wk *wasiWake) {
	t := q.t
	t.mu.Lock()
	defer t.mu.Unlock()
	q.wk = wk
	if q.queued || q.given {
		return
	}
	// Counted before the turn is tried: a give that finds the turn held and
	// no wait counted lets it go without the lock, and the try then takes
	// it (give).
	t.waiting.Add(1)
	if t.held.CompareAndSwap(false, true) {
		t.waiting.Add(-1)
		q.given = true
		return
	}
	q.queued = true
	t.queue = append(t.queue, q)
}

// removeWaiter ends the wait of wk: q keeps its place in the queue, and is
// not woken until its next wait.
func (q *turnWait) removeWaiter(wk *wasiWake) {
	q.t.mu.Lock()
	defer q.t.mu.Unlock()
	if q.wk == wk {
		q.wk = nil
	}
}

// leave takes q out of the turn's queue, for a call that no longer waits;
// a turn handed to it already is handed on.
func (q *turnWait) leave() error {
	t := q.t
	t.mu.Lock()
	defer t.mu.Unlock()
	if q.given {
		q.given = false
		return t.handLocked()
	}
	if i := slices.Index(t.queue, q); i >= 0 {
		t.queue = slices.Delete(t.queue, i, i+1)
		t.waiting.Add(-1)
		q.queued = false
	}
	return nil
}

// addWaiter registers wk as the wake of a wait for input.
func (r *streamReader) addWaiter(wk *wasiWake) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.waiters == nil {
		r.waiters = map[*wasiWake]bool{}
	}
	r.waiters[wk] = true
}

// removeWaiter undoes addWaiter.
func (r *streamReader) removeWaiter(wk *wasiWake) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.waiters, wk)
}

// wakeLocked wakes the waits for input. Caller holds r.mu.
func (r *streamReader) wakeLocked() error {
	var err error
	for wk := range r.waiters {
		err = errors.Join(err, wk.wake())
	}
	return err
}

// stop asks the reader for nothing more and wakes the waits.
func (r *streamReader) stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	if r.started && !r.reading {
		close(r.asked)
	}
	err := r.wakeLocked()
	r.mu.Unlock()
	r.report(err)
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

// What poll(2) is asked about a descriptor of the host's (hostWaitFD).
const (
	hostWantInput   = iota // input, the end of it, or a connection to accept
	hostWantRoom           // room to write, or a write that fails at once
	hostWantFailure        // what poll(2) reports unasked (POLLERR, POLLHUP)
)

// hostWaitFD is a stream of the host's that a wait in poll(2) asks about
// (waitHostReady), what it is asked about (hostWant...), and whether it is
// ready.
type hostWaitFD struct {
	stream any
	want   int
	ready  bool
	// op is the entry the stream is behind: the close of its last slot
	// wakes the wait (closeWasiOpen).
	op *wasiOpen
	// source, in place of a stream, is what the wait is for that poll(2)
	// is not asked about: the reader of a stream poll(2) does not wait for
	// (streamReader), the turn at a Writer of the embedder's (streamTurn).
	source waitSource
}

// waitSource is what a wait is for that poll(2) is not asked about
// (hostWaitFD.source): whether it is ready, and the wakes it wakes when it
// becomes ready.
type waitSource interface {
	ready() bool
	addWaiter(wk *wasiWake)
	removeWaiter(wk *wasiWake)
}

// wasiWake is a wake of an instance's (takeWake): a wait in poll(2)
// watches the pipe r, a wait for no descriptor of the host's receives from
// ch, and wake ends either. A wake where the host has no poll(2) has no
// pipe (r and w are -1).
type wasiWake struct {
	r, w int
	ch   chan struct{}
}

// newChannelWake returns a wake without a pipe.
func newChannelWake() *wasiWake { return &wasiWake{r: -1, w: -1, ch: make(chan struct{}, 1)} }

// wake ends the wait wk is the wake of: a byte in its channel, which holds
// one, and in its pipe when it has one.
func (wk *wasiWake) wake() error {
	select {
	case wk.ch <- struct{}{}:
	default:
	}
	if wk.w < 0 {
		return nil
	}
	return hostWakeWrite(wk.w)
}

// drain empties the wake.
func (wk *wasiWake) drain() error {
	select {
	case <-wk.ch:
	default:
	}
	if wk.r < 0 {
		return nil
	}
	return hostWakeDrain(wk.r)
}

// wakeFor returns the wake of a call that waits for set: one of the pool
// (takeWake), or one without a pipe for a wait for no descriptor of the
// host's (only sources), which poll(2) is not asked about.
func (w *WasiStubs) wakeFor(set []hostWaitFD) (*wasiWake, error) {
	if !slices.ContainsFunc(set, func(e hostWaitFD) bool { return e.source == nil }) {
		return newChannelWake(), nil
	}
	return w.takeWake()
}

// takeWake takes a wake pipe of the instance's pool for a call that waits,
// making one when the pool is empty. The call has it to itself until it
// gives it back (giveWake).
func (w *WasiStubs) takeWake() (*wasiWake, error) {
	w.mu.Lock()
	if n := len(w.wakes); n > 0 {
		wk := w.wakes[n-1]
		w.wakes = w.wakes[:n-1]
		w.mu.Unlock()
		return wk, nil
	}
	w.mu.Unlock()
	if !hostPolls {
		return newChannelWake(), nil
	}
	var r, wr int
	if err := makeRuntimeDescriptors(func() error {
		var err error
		if r, wr, err = hostWakePipe(); err != nil {
			return err
		}
		if r, err = keepRuntimeFD(r); err != nil {
			return errors.Join(err, hostCloseFD(wr))
		}
		if wr, err = keepRuntimeFD(wr); err != nil {
			return errors.Join(err, hostCloseFD(r))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	wk := newChannelWake()
	wk.r, wk.w = r, wr
	return wk, nil
}

// giveWake gives back the wake pipe the call took for the waits of set,
// once nothing writes to it any more: the waits are no longer registered on
// the entries of set, and the signal state has no wake for the call. The
// pipe is read empty first; after CloseAll it is closed instead.
func (w *WasiStubs) giveWake(wk *wasiWake, set []hostWaitFD) error {
	for _, e := range set {
		if e.op != nil {
			e.op.removeWaiter(wk)
		}
		if e.source != nil {
			e.source.removeWaiter(wk)
		}
	}
	if wk.r < 0 {
		// A wake without a pipe is the call's own: nothing to give back.
		return nil
	}
	err := wk.drain()
	w.mu.Lock()
	if err == nil && !w.wakesClosed {
		w.wakes = append(w.wakes, wk)
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()
	return errors.Join(err, wk.closePipe())
}

// closePipe closes the wake's pipe, when it has one.
func (wk *wasiWake) closePipe() error {
	if wk.r < 0 {
		return nil
	}
	return errors.Join(hostCloseFD(wk.r), hostCloseFD(wk.w))
}

// addWaiter registers wk as the wake of a wait for the entry's descriptor,
// which the close of its last slot writes to (closeWasiOpen).
func (op *wasiOpen) addWaiter(wk *wasiWake) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.waiters == nil {
		op.waiters = map[*wasiWake]bool{}
	}
	op.waiters[wk] = true
}

// removeWaiter undoes addWaiter: no close writes to wk after it.
func (op *wasiOpen) removeWaiter(wk *wasiWake) {
	op.mu.Lock()
	defer op.mu.Unlock()
	delete(op.waiters, wk)
}

// hostRaw reports whether stream is a descriptor of the host's that the
// runtime reads, writes and polls by itself: an *os.File, or a connection or
// listener of package net's own. Any other stream, a wrapper around one of
// them included, is read and written through its own Read and Write.
func hostRaw(stream any) bool {
	switch stream.(type) {
	case *os.File, *net.TCPConn, *net.UnixConn, *net.UDPConn, *net.IPConn, *net.TCPListener, *net.UnixListener:
		return true
	}
	return false
}

// streamPolled reports whether the host can wait for stream in poll(2)
// (waitHostReady): it is a descriptor of the host's (hostRaw), and the host
// has poll(2). Nothing is taken off such a stream to learn whether it is
// ready.
func streamPolled(stream any) bool {
	return hostPolls && hostRaw(stream) && hostDescriptor(stream, func(uintptr) {})
}

// waitHostReady asks poll(2) about the streams of set and records which are
// ready: at once when until has passed, otherwise waiting until one is,
// until passes (the zero time is no limit) or wake (nil for none) is woken.
// What poll(2) is not asked about (source) is ready as it says. poll(2) is
// asked about the descriptor numbers, which nothing holds open meanwhile:
// the guest's close of an entry's last slot wakes the wait (closeWasiOpen).
// A stream of the
// embedder's (an instance's standard stream), which it can close as the
// guest waits for it, is waited for on a duplicate of its descriptor held
// for the wait, so that the wait never asks about another file that gets
// the number. A stream closed already is ready, and the call on it reports
// the closing; so is one asked about input of an entry that has input
// ahead (giveAhead, which wakes the wait).
func waitHostReady(set []hostWaitFD, until time.Time, wake *wasiWake) error {
	waits := until.IsZero() || time.Now().Before(until)
	var fds []uintptr
	var wants, at, dups []int
	closeDups := func() error {
		var err error
		for _, dup := range dups {
			err = errors.Join(err, hostCloseFD(dup))
		}
		return err
	}
	// found is set once an entry is ready without poll(2).
	found := false
	for i, e := range set {
		if e.source != nil {
			set[i].ready = e.source.ready()
			found = found || set[i].ready
			continue
		}
		if e.want == hostWantInput && e.op != nil {
			if ahead, _ := e.op.aheadReady(); ahead {
				set[i].ready, found = true, true
				continue
			}
		}
		var fd uintptr
		conn, isConn := e.stream.(syscall.Conn)
		if waits && isConn && e.op != nil && e.op.stdio != 0 {
			dup, err := duplicateDescriptor(conn)
			switch {
			case errors.Is(err, fs.ErrClosed):
				set[i].ready, found = true, true
				continue
			case err != nil:
				return errors.Join(err, closeDups())
			}
			dups, fd = append(dups, dup), uintptr(dup)
		} else if !hostDescriptor(e.stream, func(d uintptr) { fd = d }) {
			set[i].ready, found = true, true
			continue
		}
		fds, wants, at = append(fds, fd), append(wants, e.want), append(at, i)
	}
	if found {
		until = time.Now() // a closed one is ready: no wait
	}
	if len(fds) == 0 {
		waitWake(until, wake)
		return nil
	}
	wakeFD := -1
	if wake != nil {
		wakeFD = wake.r
	}
	ready := make([]bool, len(fds))
	err := hostWaitReady(fds, wants, ready, until, wakeFD)
	for k, r := range ready {
		set[at[k]].ready = r
	}
	return errors.Join(err, closeDups())
}

// waitWake waits until wake (nil for none) is woken or until passes (the
// zero time is no limit): a wait for no descriptor of the host's.
func waitWake(until time.Time, wake *wasiWake) {
	var woken <-chan struct{}
	if wake != nil {
		woken = wake.ch
	}
	var expired <-chan time.Time
	if !until.IsZero() {
		left := time.Until(until)
		if left <= 0 {
			return
		}
		timer := time.NewTimer(left)
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-woken:
	case <-expired:
	}
}

// waitHostInterruptibly is waitHostReady for a blocking call of the guest's:
// the wait ends as well when a signal is posted to the guest, and
// interrupted reports that the call is to report one, or when an entry of
// set is closed (its last slot is cleared). The call takes a wake pipe of
// the instance's for the wait.
func (w *WasiStubs) waitHostInterruptibly(m *Module, call string, set []hostWaitFD, until time.Time) (interrupted bool, err error) {
	wk, err := w.wakeFor(set)
	if err != nil {
		return false, err
	}
	for _, e := range set {
		if e.op != nil {
			e.op.addWaiter(wk)
		}
		if e.source != nil {
			e.source.addWaiter(wk)
		}
	}
	given := false
	defer w.giveWakeOnUnwind(call, &given, wk, set)
	var wakeErr error
	interrupted, _, refused := w.blockingAttempt(m, func() { wakeErr = wk.wake() }, nil,
		func(<-chan struct{}) { err = waitHostReady(set, until, wk) })
	given = true
	return interrupted || refused, errors.Join(err, wakeErr, w.giveWake(wk, set))
}

// giveWakeOnUnwind gives wk back for call, the import that was unwound by
// terminate before it gave it back itself (given is false). The guest is
// ending: a failure goes to WASIConfig.Errors.
func (w *WasiStubs) giveWakeOnUnwind(call string, given *bool, wk *wasiWake, set []hostWaitFD) {
	if !*given {
		w.reportError(call, w.giveWake(wk, set))
	}
}

// reportError tells WASIConfig.Errors of err, a failure of the import op
// that it has no call left to return to; nil is no failure.
func (w *WasiStubs) reportError(op string, err error) {
	if err != nil && w.cfg.Errors != nil {
		w.cfg.Errors(op, err)
	}
}

// reportLater tells WASIConfig.Errors of err, a failure of op found with
// w.mu held, under which Errors is not told: once w.mu is let go. nil is no
// failure. Caller holds w.mu.
func (w *WasiStubs) reportLater(op string, err error) {
	if err != nil {
		w.mu.afterUnlock(func() { w.reportError(op, err) })
	}
}

// instanceMutex is the lock of a WasiStubs (mu): a sync.Mutex whose Unlock
// then runs what was left for it while the lock was held (afterUnlock) —
// the reports and closes that may not be made under it.
type instanceMutex struct {
	sync.Mutex
	// unlockQueued is set while unlockRuns holds something; unlockRuns is
	// guarded by the mutex itself.
	unlockQueued atomic.Bool
	unlockRuns   []func()
}

// afterUnlock leaves run for Unlock to run once the lock is let go. Caller
// holds the lock.
func (l *instanceMutex) afterUnlock(run func()) {
	l.unlockRuns = append(l.unlockRuns, run)
	l.unlockQueued.Store(true)
}

// Unlock lets the lock go and runs what afterUnlock left, in order.
func (l *instanceMutex) Unlock() {
	if !l.unlockQueued.Load() {
		l.Mutex.Unlock()
		return
	}
	runs := l.unlockRuns
	l.unlockRuns = nil
	l.unlockQueued.Store(false)
	l.Mutex.Unlock()
	for _, run := range runs {
		run()
	}
}

// errnoLater is guestErrno for a failure found with w.mu held: an error
// without an errno is told Errors once w.mu is let go (reportLater).
// Caller holds w.mu.
func (w *WasiStubs) errnoLater(op string, err error) int32 {
	errno, known := wasiErrnoOf(err)
	if !known {
		w.reportLater(op, err)
	}
	return errno
}

// blockingAttempt runs attempt as a blocking call of the guest's
// (beginBlocking, endBlocking), whose stop is closed, and wake run, once a
// signal is posted to the guest. refused reports that a signal was waiting
// already: attempt did not run. Otherwise interrupted reports that the call
// is to report a signal (endBlocking), and woken that wake ran, whichever
// call reports the signal; the caller then undoes what wake did. A call that
// terminate unwinds after wake ran has unwound (nil for none) undo it.
func (w *WasiStubs) blockingAttempt(m *Module, wake func(), unwound func(), attempt func(stop <-chan struct{})) (interrupted, woken, refused bool) {
	stop := make(chan struct{})
	key, ok := w.beginBlocking(m, func() {
		close(stop)
		wake()
	})
	if !ok {
		return false, false, true
	}
	ended := false
	defer func() {
		if ended || unwound == nil {
			return
		}
		select {
		case <-stop:
			unwound()
		default:
		}
	}()
	attempt(stop)
	interrupted = w.endBlocking(key)
	ended = true
	select {
	case <-stop:
		woken = true
	default:
	}
	return interrupted, woken, false
}

// leadingBytes returns the first n bytes of bufs, in buffers.
func leadingBytes(bufs [][]byte, n int) [][]byte {
	var out [][]byte
	for _, buf := range bufs {
		if n == 0 {
			break
		}
		c := min(len(buf), n)
		out, n = append(out, buf[:c]), n-c
	}
	return out
}

// firstBuffer returns the first of bufs that has room, or nil.
func firstBuffer(bufs [][]byte) []byte {
	if i := slices.IndexFunc(bufs, func(buf []byte) bool { return len(buf) > 0 }); i >= 0 {
		return bufs[i]
	}
	return nil
}

// readOnce reads src, a descriptor of the host's that the Go runtime polls
// (readInterruptibly), once into bufs with readv(2), waiting for input, as
// src's own Read does, in the poller of the Go runtime and no longer than
// src's deadline.
func readOnce(src io.Reader, bufs [][]byte) (int, error) {
	rc, err := src.(syscall.Conn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var readErr error
	if err := rc.Read(func(fd uintptr) bool {
		var again bool
		n, again, readErr = readvRaw(fd, bufs)
		return !again
	}); err != nil {
		return 0, rawCallErr(rc, err)
	}
	if readErr != nil {
		return n, os.NewSyscallError("readv", readErr)
	}
	return n, nil
}

// rawCallErr returns err, the failure of a Read or Write of rc, as
// fs.ErrClosed when the file is being closed, as os.File's own Read and
// Write report it; RawConn's report the poller's error of a closing file,
// which fs.ErrClosed does not match. The file is being closed when
// Control fails as well: Control fails for nothing else.
func rawCallErr(rc syscall.RawConn, err error) error {
	if rc.Control(func(uintptr) {}) != nil {
		return fmt.Errorf("%w: %w", fs.ErrClosed, err)
	}
	return err
}

// deadlineErr returns err, the failure of setting a deadline of stream, as
// rawCallErr does: os.File's SetReadDeadline and SetWriteDeadline report a
// file that is closed, or being closed, with the poller's error as well.
func deadlineErr(stream any, err error) error {
	conn, isConn := stream.(syscall.Conn)
	if err == nil || !isConn {
		return err
	}
	rc, rcErr := conn.SyscallConn()
	if rcErr != nil {
		return errors.Join(err, rcErr)
	}
	return rawCallErr(rc, err)
}

// readResult is what the guest's read of a stream returns for a read that
// got n bytes and err: the count, or the errno of a failure other than the
// end of input that left nothing read.
func (w *WasiStubs) readResult(call string, n int, err error) (uint64, int32) {
	if err != nil && n == 0 && !errors.Is(err, io.EOF) {
		return 0, w.guestErrno(call, err)
	}
	return uint64(n), _wasiESUCCESS
}

// tryStream makes one attempt at a call of the import call on stream, a
// descriptor of the host's (streamPolled), in its Control: attempt is
// called with the descriptor, and nothing waits in the poller of the Go
// runtime. attempt's again says that the descriptor has nothing, or no
// room, right now. A stream closed meanwhile is EBADF, as socketCall
// reports it.
func (w *WasiStubs) tryStream(call string, stream syscall.Conn, attempt func(fd uintptr) (n int, again bool, err error)) (n int, again bool, errno int32) {
	rc, err := stream.SyscallConn()
	if err != nil {
		return 0, false, w.guestErrno(call, err)
	}
	var callErr error
	if rc.Control(func(fd uintptr) { n, again, callErr = attempt(fd) }) != nil {
		return 0, false, _wasiEBADF
	}
	return n, again, w.guestErrno(call, callErr)
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

// readsStream reports whether a read of src, the stream behind this entry,
// can wait for input (readBlocks), or src is the instance's stdin of the
// embedder's that is no file, whose Read may wait for all the runtime knows:
// it is read through a reader (streamReader). A Reader of package bytes' or
// strings' has its input in memory, and its Read does not wait.
func (op *wasiOpen) readsStream(src io.Reader) bool {
	if _, blocks := op.readBlocks(src); blocks {
		return true
	}
	switch src.(type) {
	case *os.File, *bytes.Reader, *strings.Reader, *bytes.Buffer:
		return false
	}
	return op.stdio == 1
}

// fileIsStream reports whether file, the host file behind this entry, is a
// stream — a pipe, a socket, a terminal — whose reads and writes can block,
// and not a regular file, whose never do.
func (op *wasiOpen) fileIsStream(file *os.File) bool {
	const streamModes = os.ModeNamedPipe | os.ModeSocket | os.ModeCharDevice
	mode, _ := op.statOf(file)
	return mode&streamModes != 0
}

// statOf returns what the host says of file, the host file behind this
// entry: its type, and whether it is a FIFO with a name in the file system.
// The host is asked once per file. A file it cannot stat (it has been
// closed) is of no type, and is asked about again: its read or write fails
// the same way, and reports the failure.
func (op *wasiOpen) statOf(file *os.File) (mode os.FileMode, namedFIFO bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.statFile != file {
		fi, err := file.Stat()
		if err != nil {
			return 0, false
		}
		// A pipe has no link: only a FIFO has a name.
		st, known := osFileStat(fi.Sys())
		op.statFile, op.statMode = file, fi.Mode().Type()
		op.namedFIFO = op.statMode&os.ModeNamedPipe != 0 && known && st.nlink > 0
	}
	return op.statMode, op.namedFIFO
}

// terminalOf reports whether file, the host file behind this entry, is a
// terminal of the host (withHostTerminal). The host is asked once per file.
func (op *wasiOpen) terminalOf(file *os.File) (bool, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.terminalFile != file {
		err := withHostTerminal(file, func(int) error { return nil })
		if err != nil && !errors.Is(err, syscall.ENOTTY) {
			return false, err
		}
		op.terminalFile, op.terminal = file, err == nil
	}
	return op.terminal, nil
}

// streamSendLowat is hostStreamSendLowat for file, the socket behind this
// entry, whose descriptor is fd; the host is asked once per file.
func (op *wasiOpen) streamSendLowat(file *os.File, fd uintptr) (int, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.lowatFile != file {
		lowat, err := hostStreamSendLowat(fd)
		if err != nil {
			return 0, err
		}
		op.lowatFile, op.lowat = file, lowat
	}
	return op.lowat, nil
}

// inputPolled reports whether the host can wait for input of src, the
// stream behind this entry, in poll(2) (streamPolled): not for a FIFO with
// a name on a host whose poll(2) does not report the end of its input.
func (op *wasiOpen) inputPolled(src any) bool {
	if file, isFile := src.(*os.File); isFile && !hostPollReportsFIFOEnd {
		if _, fifo := op.statOf(file); fifo {
			return false
		}
	}
	return streamPolled(src)
}

// netpolled reports whether the runtime waits for stream, the stream behind
// the entry op, in the poller of the Go runtime, on a host with poll(2):
// one the Go runtime polls (wasiOpen.polled, stdioPolled; a connection of
// package net's always is) that is either
//
//   - the entry's own descriptor, whose open file description nothing
//     outside the runtime holds (shared). Its mode is the one it was opened
//     with, which is non-blocking: nothing in the runtime changes it after
//     the open, so a call on it is not asked whether it can wait in the
//     kernel (hostMayBlock); or
//   - a standard stream of the embedder's. The wait for it is bounded by a
//     deadline on the embedder's own file: the file is the only handle of
//     the stream the runtime has, and waiting on a duplicate of its own
//     instead would keep the description open after the embedder closes
//     the file, which a writer of the stream would see (no EPIPE).
func (w *WasiStubs) netpolled(op *wasiOpen, stream any) bool {
	if !hostPolls || op.stdio == 0 && op.shared.Load() {
		return false
	}
	switch stream.(type) {
	case *os.File:
		if op.stdio != 0 {
			return w.stdioPolled(op.stdio)
		}
		return op.polled
	case *net.TCPConn, *net.UnixConn, *net.UDPConn, *net.IPConn:
		return true
	}
	return false
}

// stdioPolled reports whether the Go runtime polls the instance's standard
// stream stdio (1 for stdin, 2 for stdout, 3 for stderr, as wasiOpen.stdio),
// which the family asks of its streams once (familyStreams.polled). A
// stream that cannot be asked (a file closed already) is not polled, and
// WASIConfig.Errors is told why.
func (w *WasiStubs) stdioPolled(stdio int8) bool {
	w.mu.Lock()
	share := w.streamsLocked()
	w.mu.Unlock()
	var askErr error
	share.asked.Do(func() {
		for i, stream := range []any{w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr} {
			polled, err := filePolled(stream)
			askErr = errors.Join(askErr, err)
			share.polled[i] = polled
		}
	})
	// Told once asking is over: the other calls wait in Do until then.
	w.reportError("stdio", askErr)
	return share.polled[stdio-1]
}

// filePolled reports whether the Go runtime polls stream, which it decides
// when the file is made: whether stream is a file that takes a deadline (a
// FIFO on darwin does not). Anything else is not polled. Asking clears the
// file's read deadline: it is asked when an entry is made (wasiOpen.polled).
func filePolled(stream any) (bool, error) {
	file, isFile := stream.(*os.File)
	if !isFile {
		return false, nil
	}
	switch err := file.SetReadDeadline(time.Time{}); {
	case errors.Is(err, os.ErrNoDeadline):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// watchAhead makes wake, when it is not nil, what giveAhead calls once it
// has put input ahead, and reports instead that there is input ahead
// already, in which case nothing is registered; nil unregisters what was.
// Only the holder of the turn at the input watches (readInterruptibly).
func (op *wasiOpen) watchAhead(wake func()) (ahead bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if wake != nil && len(op.ahead) > 0 {
		return true
	}
	op.inputWake = wake
	return false
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
// a stream that is not a descriptor of the host's (hostRaw) or anything on a
// host where the runtime cannot write without waiting.
func (op *wasiOpen) writeBlocks(dst io.Writer) (streamWriter, bool) {
	if !hostStreamWrites || !hostRaw(dst) {
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
	file, isHostFile := op.f.(*os.File)
	return !isHostFile || !op.fileIsStream(file)
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

// WASIConfig is the configuration a WasiStubs is built from (NewWASI). The
// guest has what it names and nothing else: the zero WASIConfig gives it no
// arguments, no environment, an empty stdin, a stdout and a stderr that
// discard what is written, no filesystem, no socket operation, outbound
// connection, name lookup or process spawn, and the identity of an isolated
// process. HostWASIConfig is the
// configuration of a guest that has what the host process has and cannot
// fail to give.
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
	//
	// The instances of a fork family (Fork) and their threads share them.
	// A Stdin the runtime cannot wait for in poll(2) (one that is no file
	// or connection of the host's, a FIFO poll(2) does not report the end
	// of, any stream of a host without poll(2)) is read by one goroutine of
	// the runtime's, once each time the guest asks for input — a read, a
	// poll, the stdin of a command it starts — and what a Read returns is
	// kept for the guest's next read, also when the guest stopped waiting
	// for it (a signal) or ended: a Read in progress is not ended. Where the
	// host has no poll(2), a command's stdin is read by package os/exec
	// itself, at the same time. A *bytes.Reader, *strings.Reader or
	// *bytes.Buffer is read by the guest's calls, and by the copy of a
	// command's stdin at the same time. A Stdout or Stderr that is no
	// file of the host's is written by the guests' writes and the copies of
	// their commands' output one Write at a time, the same turn for both
	// when Stdout == Stderr (as os/exec decides it); a Write runs to its end
	// on the call of the guest's that makes it, and a signal ends only the
	// wait for another one to finish. The runtime sets no deadline on a
	// stream that is no file or connection of the host's. Instances that
	// are not of one family call them independently.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// FS is the filesystem every guest path operation is routed through,
	// preopened as the guest's "/" (fd 3): HostFS for the host's, NewMemFS
	// for one in memory, or an FS that wraps one of them to keep a policy
	// on its files. It is given the names FS's doc describes. With nil no
	// directory is preopened: neither fd 3
	// nor the root directory's second number is open, so every call on
	// them, path calls included, fails with EBADF, and fd 3 is handed out
	// like any free number; the guest's C library, finding no preopen,
	// fails every path with ENOENT; the path operations that take no
	// directory descriptor (path_open_mode, path_create_directory_mode,
	// path_chmod, path_chown, path_filestat_ext, path_filestat_mode) fail
	// with ENOENT. The names of the guest's own descriptors (/dev/stdin,
	// /dev/stdout, /dev/stderr, /dev/fd/N, /proc/self/fd/N, /proc/PID/fd/N,
	// and /dev/fd, /proc/self/fd and /proc/PID/fd, which list them) are not
	// the FS's: every path operation resolves them without it, as Linux's
	// procfs does, and those that take no directory descriptor
	// (path_open_mode, path_create_directory_mode, path_chmod, path_chown,
	// path_filestat_ext, path_filestat_mode, path_access, path_mkfifo) even
	// when FS is nil. A call that changes or asks about
	// what such a name leads to (chmod, chown, the times, access) acts on
	// the descriptor, as its fd_* call does, and fails with EPERM on a link
	// itself or a listing; one that makes such a name fails with EEXIST,
	// or ENOENT for a number that is not open; one that removes or renames
	// one fails with EACCES (EPERM for a guest of effective user id 0); a
	// rename or link between such a name and one of the FS fails with
	// EXDEV. The FS and its files are called concurrently, by the instances
	// of a fork family and their threads; a File is closed by the guest's
	// close of its last descriptor, and is not to be closed before.
	FS FS
	// NetAccess is consulted before Sock_accept, Sock_recv and Sock_send
	// with "accept", "recv" or "send". Returning false denies the operation
	// (EACCES). nil denies every one.
	NetAccess func(op string) bool
	// Dial is consulted before an outbound connect (Sock_connect,
	// Sock_connect_addr) and a datagram's send to an address
	// (Sock_sendto_addr) with the network, a host name, the IP in text and
	// the port (for a Unix-domain socket: "", its path in the host
	// filesystem, 0). The host is each name a lookup of the guest's fork
	// family gave the IP for (Sock_getaddrinfo, Sock_resolve,
	// Sock_host_by_name), one call per name in sorted order until one
	// allows, or "" in a single call when none did (the guest dialed a
	// literal IP): a connect to an IP that several names share is allowed
	// when any of its names is. Returning false denies the connection
	// (EACCES). nil denies every one.
	Dial func(network, host, ip string, port int) bool
	// Listen is consulted before a socket takes a local address that others
	// can reach it at: before a bind (Sock_bind_addr), of a datagram socket
	// as well, before the listen (Sock_listen) of a socket that was not
	// bound, which the host binds at a port it picks, before the first
	// send to an address (Sock_sendto_addr) of a datagram socket that was
	// not bound, which the host binds as well, and before a datagram
	// socket dissolves its association (a connect with AF_UNSPEC), which on
	// some hosts leaves the port it was given reachable. It is given the
	// network ("tcp", "udp", "unix" or "unixgram") and the address:
	// "ip:port" of an IP socket (an IPv6 one in brackets, with the zone of
	// a link-local one; the unspecified address and port 0 for one the
	// host picks), or a Unix-domain socket's path in the host filesystem
	// ("@name" for an abstract name). Returning false denies it (EACCES).
	// nil denies every one.
	Listen func(network, address string) bool
	// Resolve is consulted before a name lookup (Sock_getaddrinfo,
	// Sock_resolve, Sock_host_by_name) with the requested host, and before
	// a reverse lookup (Sock_reverse_addr) with the IP address in text.
	// Returning false denies the resolution (the guest sees a
	// name-resolution error). nil denies every one. An address written in
	// numbers is no lookup and is not asked about, nor is an empty host of
	// Sock_getaddrinfo, which resolves to INADDR_ANY.
	Resolve func(host string) bool
	// Exec is consulted before every Proc_spawn and Proc_exec, which run a
	// host binary, with what the command runs (ExecRequest): the command is
	// started from that very value. Returning false denies the spawn
	// (EACCES). nil denies every one. A command is a process of the host:
	// it sees the host's filesystem, not FS, and only an FS that is a
	// HostRootFS can start one (ENOSYS otherwise).
	Exec func(req ExecRequest) bool
	// Process supplies the guest's identity and accounting: what getpid,
	// getppid, the getuid family and times report, the pid whose
	// /proc/PID/fd lists the guest's descriptors, and the umask the guest
	// starts with. nil is an isolated process: pid 42, ppid 1, every user
	// and group id 0, no CPU time and umask 022, none of them read from the
	// host. HostProcess and HostProcessUmask give the host process's.
	// It is required with a ProcessChanges, which changes what it reads.
	Process Process
	// ProcessChanges makes the changes the guest of the fork family's root
	// instance makes to its process — its ids, groups, priority and umask —
	// where they are kept besides the instance (ProcessChanges); Process
	// reads them, and NewWASI panics when it is nil. A forked instance's
	// guest changes its nice value and umask alone, and keeps its ids and
	// groups: the change of them fails with EPERM. nil changes nothing: the
	// setuid family, setgroups and setpriority fail with ENOSYS, and the
	// umask is the instance's alone. HostProcessChanges gives the host
	// process's calls.
	ProcessChanges ProcessChanges
	// LocalZone is the time zone of a guest that names none (Clock_zone
	// without TZ); nil is UTC.
	LocalZone *time.Location
	// ZoneInfo is the zone database of the zones the guest names (Clock_zone
	// with a TZ such as "Europe/Paris"): the file of that name, a zone file
	// as tzfile(5) has it. nil is the host's, which time.LoadLocation reads.
	// A TZ that starts with '/' names a zone file of FS instead.
	ZoneInfo fs.FS
	// Errors is told the errors of operations whose caller cannot be given
	// them (op names the operation), among them an error the guest's call
	// fails with that has no errno of its own (the call fails with EIO); nil
	// drops them.
	Errors func(op string, err error)
	// Signals connects the guest's signals with processes and signal
	// handling outside the guest. nil is an isolated guest: its kill reaches
	// no process but its own and the ones it made, and its dispositions are
	// told nobody.
	Signals Signals
	// TakeSignal is offered a signal the runtime raises for a guest itself
	// before the guest is given it: the SIGALRM of the interval timer, the
	// SIGCHLD of a child's end once its status can be waited for, the
	// signal of the guest's kill of its own pid and of its raise (never 0,
	// SIGKILL or SIGSTOP), and the SIGPIPE of a write or send that fails
	// with EPIPE; none once the guest has become a command (Proc_exec).
	// target is the instance the signal is for; a forked instance has its
	// parent's TakeSignal. When it reports the signal taken, it has dealt
	// with the signal itself (a host process whose native code made a
	// handler of its own the action of the signal raises it there), and the
	// guest is given nothing. Its error is told Errors (op "take_signal"),
	// and the guest is given the signal. It is called on the goroutine that
	// raises the signal, with no lock of the instance's state or signals
	// held; that goroutine may be in a write to one of the guest's streams
	// (the SIGPIPE of the write's EPIPE, a timer that came due in it), so it
	// must not wait for another thread's write to the guest's standard
	// output or error. nil gives every such signal to the guest.
	TakeSignal func(target SignalTarget, sig int32) (taken bool, err error)
	// Users is the user and group database of getpwnam, getgrgid and the
	// like. nil is an empty one: every lookup fails with ENOENT. HostUsers
	// gives the host's.
	Users Users
	// System is what uname and gethostname report. nil is none: they fail
	// with ENOSYS. HostSystem gives the host's.
	System System
	// Services is the services database of getservbyname and
	// getservbyport. nil is an empty one: every lookup fails with ENOENT.
	// HostServices gives the host's.
	Services Services
	// Numbering gives the guest the numbers of another system (its error
	// numbers, ...) to use instead of those of its own C library
	// (host_numbering, host_number_at). nil leaves the guest with its own.
	Numbering Numbering
	// Syslog is the system logger of openlog, syslog and closelog. nil is
	// none: they fail with ENOSYS. HostSyslog gives the host's.
	Syslog Syslogger

	// Chdir is told each change of the guest's working directory, which the
	// guest's C library keeps itself: dir is the directory the guest is in
	// now, an absolute path of its filesystem. Setenv is told each change of
	// the guest's environment: name is set to value, or removed when unset
	// is true. Their error is the guest's call's errno. They are told the
	// changes of an instance NewWASI made, not of a copy made by Fork or
	// ForkProc, whose changes are its own as a child process's are. nil
	// tells nobody.
	Chdir  func(dir string) error
	Setenv func(name, value string, unset bool) error

	// IPC gives the guest System V IPC: msgget, semget and shmget and the
	// calls on the objects they name. nil gives it none: each of those
	// calls fails with ENOSYS. HostIPC gives the host's.
	IPC IPC

	// Syscalls makes the guest's syscall(2). nil makes none: syscall fails
	// with ENOSYS. HostSyscalls makes the host's, which gives the guest the
	// host process's memory and descriptors outside every other field of
	// the configuration.
	Syscalls Syscalls

	// Fork makes the instance the child of a guest's fork runs in
	// (Proc_fork). nil denies every fork: it fails with ENOSYS.
	// CopyForker makes a copy of the forking instance.
	Fork Forker

	// Files are descriptors the guest has from its start, under the numbers
	// they are given at (inherited ones, a listening socket of a
	// supervisor's). The instance takes them over: the guest's close, or
	// CloseAll, closes them. A socket is given to the guest as a socket of
	// the host's in non-blocking mode, which is a mode of the open file
	// description and so of every other descriptor of it too, as with
	// net.FileConn. A file at 0, 1 or 2 takes the place of that standard
	// stream, and one at 3 the preopened root's (see Fd_dup2). A file that
	// cannot be taken over is closed and reported to Errors, and the guest
	// finds its number closed.
	Files map[int32]*os.File

	// HostDescriptors makes the guest's descriptors those of the host
	// process: descriptor N of the guest is descriptor N of the host, in
	// both directions. A new descriptor gets the lowest number the process
	// has free; native code the embedder runs for the guest can be given
	// the number (HostDescriptor) and finds the guest's open file there; and
	// a descriptor of the process that no instance has and that was not
	// open when the first such instance was made — native code opened it —
	// is the guest's to use by its number, and is closed by the guest's
	// close. The descriptors open when that instance was made are the
	// process's own, out of the guest's reach, except those given in Files.
	// A standard stream that is the host's file under its own number
	// (os.Stdin, os.Stdout, os.Stderr) is that descriptor: the guest's close
	// closes it, and the next descriptor the guest makes gets the number.
	// The guest's numbers are below 1024 (FD_SETSIZE); from the first such
	// instance on, the descriptors the runtime makes for itself, of every
	// instance in the process, are at 1024 or above. It applies to the
	// instance NewWASI makes; a copy made by Fork or ForkProc numbers its
	// descriptors itself, as a child process's are its own. It has an
	// effect on darwin and linux only.
	HostDescriptors bool
}

// AllowAllNetAccess is a WASIConfig.NetAccess that allows every socket
// operation.
func AllowAllNetAccess(op string) bool { return true }

// AllowAllDial is a WASIConfig.Dial that allows every outbound connection.
func AllowAllDial(network, host, ip string, port int) bool { return true }

// AllowAllListen is a WASIConfig.Listen that allows every local address.
func AllowAllListen(network, address string) bool { return true }

// AllowAllResolve is a WASIConfig.Resolve that allows every name lookup.
func AllowAllResolve(host string) bool { return true }

// AllowAllExec is a WASIConfig.Exec that allows every process spawn.
func AllowAllExec(req ExecRequest) bool { return true }

// ExecRequest is what a command the guest starts runs, as WASIConfig.Exec
// is asked about it.
type ExecRequest struct {
	// Path is the host's absolute path of the executable: of its name in
	// the FS (HostRootFS). A name without a "/" the guest gave is looked up
	// first, in the directories of the PATH of Env, the envp the guest
	// passes (or "/usr/local/bin:/bin:/usr/bin" without one), in the
	// guest's FS, as musl's execvp looks one up: the first that is a
	// regular file the guest may execute (access with X_OK, for its
	// effective ids). musl's execvp reads the PATH of the caller's environ
	// instead; the two differ only when posix_spawnp is given an envp with
	// another PATH.
	Path string
	// Argv is the command's argument list, argv[0] included.
	Argv []string
	// Env is the command's whole environment, each "key=value": what the
	// guest gave, none of the host process's.
	Env []string
	// Dir is the host's absolute path of the directory the command starts
	// in, the guest's working directory.
	Dir string
}

// HostWASIConfig returns the configuration of a guest that has what the host
// process has and cannot fail to give: os.Args, os.Environ(),
// os.Stdin/Stdout/Stderr, the whole host filesystem (what HostFS("/")
// returns), time.Local as its time zone, the host's user and group database
// (HostUsers), system (HostSystem) and services database (HostServices),
// whose skipped lines nobody is told, and every socket operation, outbound
// connection, name lookup and process spawn allowed. Its other fields are
// unset (Process the isolated one, no Signals, no Syslog, ...): a guest has
// the host process's identity, its signals, the host's system logger and
// the rest only when the embedder sets them.
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
		Listen:    AllowAllListen,
		Resolve:   AllowAllResolve,
		Exec:      AllowAllExec,
		LocalZone: time.Local,
		Users:     HostUsers(nil),
		System:    HostSystem(),
		Services:  HostServices(nil),
	}
}

// WasiStubs is the default Go-native implementation of wasi_snapshot_preview1.
// State is owned per-Module via NewWithWASI / NewWASI.
type WasiStubs struct {
	// mu guards the fields documented so. The locks of an instance are
	// taken in this order: the wasiPIDs' starts before umaskCalls;
	// dispositionsMu, umaskCalls and starts before mu; mu
	// before a wasiOpen's mu, the wasiPIDs' mu and the signal state's locks;
	// sig.flagMu before sig.mu and before the module's memory lock
	// (accessMemory). sig.mu and the wasiPIDs' mu are leaves: nothing is
	// locked under them.
	mu instanceMutex

	// cfg is the configuration the instance was built from (NewWASI). It
	// never changes, and is read without a lock, as monoStart is. Its
	// filesystem and standard streams are read through fs, stdin, stdout
	// and stderr, which give a nil one what it stands for.
	cfg WASIConfig
	// wakes is the pool of wake pipes (takeWake), closed by CloseAll
	// (wakesClosed); a pipe in use then is closed when it is given back.
	// Guarded by mu.
	wakes       []*wasiWake
	wakesClosed bool
	// fdTable maps every open guest fd, 0/1/2 included, to its entry. Use
	// it through fdsLocked: nil means the table has not been set up yet,
	// which is how a WasiStubs built as a bare struct literal starts.
	fdTable   map[int32]*wasiOpen
	monoStart time.Time
	// hosts is the names the family's lookups gave each address for, which
	// the Dial policy is asked with (familyHosts). Like pids, it is created
	// on first use (hostsLocked) and shared through Fork.
	hosts *familyHosts
	// procs tracks the processes this instance may wait for — host
	// processes spawned via Proc_spawn and embedder-run processes
	// registered via NewProc — keyed by the pid handed back to the guest.
	procs map[int32]*wasiProc
	// pids allocates the pid tokens (kept distinct from real OS pids — the
	// guest only ever sees these tokens). It is created on first use and
	// shared with every instance derived through Fork, so a token is unique
	// across a whole fork family.
	pids *wasiPIDs
	// streams is what the family shares of the instance's standard streams
	// for the commands it starts (familyStreams). Like pids, it is created
	// on first use (streamsLocked) and shared through Fork. streamsLeft is
	// set once CloseAll has counted the instance out of it (live).
	streams     *familyStreams
	streamsLeft bool
	// procFinished is closed, and dropped so the next waiter makes a fresh
	// one, whenever a process in procs finishes. Proc_wait_any blocks on it
	// instead of polling. Guarded by mu.
	procFinished chan struct{}
	// umask is the guest's file mode creation mask once it has set one
	// (Proc_umask); nil means the Umask of the Process applies. It is
	// per instance because every instance is a process of its own to the
	// guest. Use it through guestUmask. Guarded by mu.
	umask *os.FileMode
	// umaskCalls makes the guest's umask() calls one at a time
	// (Proc_umask), so that the mask its creation thread and its
	// ProcessChanges were given last is the instance's.
	umaskCalls sync.Mutex
	// creations is the thread the instance makes the files of the host's
	// filesystem on, with its umask (creationThread), once it has needed
	// one; creationsFailed records that none could be made, and
	// creationsClosed that CloseAll ended it (the runtime then takes the
	// mask out itself). Guarded by mu; made and set under umaskCalls.
	creations       *creationThread
	creationsFailed bool
	creationsClosed bool
	// changed holds the ids, groups and nice value the guest of a forked
	// instance changed its own to (procChanges); nil before the first
	// change. Guarded by mu.
	changed *processChanged
	// zoneTZ is the last TZ value the guest named and zone its zone,
	// resolved (nil before the first); see zoneMoment. Guarded by mu.
	zoneTZ string
	zone   *wasiZone
	// userWalk and groupWalk are the entries of the Users the guest goes
	// through with getpwent and getgrent (procUserAt, procGroupAt), nil
	// before its first walk. They are not changed once made, so a forked
	// instance shares them. Guarded by mu.
	userWalk  *[]User
	groupWalk *[]Group
	// syslog is what the fork family shares of its Syslogger (familySyslog).
	// Like streams, it is created on first use (syslogFamilyLocked) and
	// shared through Fork. Guarded by mu.
	syslog *familySyslog
	// syslogInUse records that the guest uses the Syslogger (familySyslog).
	// Guarded by syslog.mu.
	syslogInUse bool
	// forked marks host state made by Fork: the instance it backs is a
	// process of its own. Immutable.
	forked bool
	// cloexec holds the descriptor numbers the guest has marked
	// close-on-exec (Fd_cloexec). A number that is given to a new
	// descriptor starts unmarked. Guarded by mu.
	cloexec map[int32]bool
	// preopenReplaced is set once a descriptor has been put at
	// wasiPreopenFD, which then no longer names the root (preopened).
	preopenReplaced atomic.Bool
	// recordLockUses counts the files this instance holds record locks of
	// (fd_lock) and its fd_lock calls in progress: while it is 0, a close
	// has no lock of the instance to remove (releaseRecordLocksLocked).
	recordLockUses atomic.Int32
	// lockResyncs are the files whose host locks a close of this instance
	// has left to be brought down to the record lock table, once mu is let
	// go (resyncReleased). Guarded by mu.
	lockResyncs []lockResync
	// sig is the signal state; see wasiSignals, which has its own locks.
	sig wasiSignals
	// rootEntry enters the root instance in its family's table, once
	// (enterRoot).
	rootEntry sync.Once
	// dispositionsMu serializes the reports to cfg.Signals.Dispositions,
	// which are made without mu held, so that they are made in the order of
	// the changes they report.
	dispositionsMu sync.Mutex

	// shm holds the System V shared memory segments the guest has attached
	// (Ipc_shmat), by the guest's address of the memory each is attached
	// over; shmClosed is set by CloseAll, which detached them, and no
	// segment is attached after it. shmMu guards both and makes the
	// attachments and detachments one at a time; it is never held with mu.
	shmMu     sync.Mutex
	shm       map[uint64]shmAttachment
	shmClosed bool

	// ownStandard records the standard numbers (0, 1, 2) of an instance
	// whose descriptors are the host's where its standard stream is not the
	// process's descriptor (takeStandardLocked): what the guest puts there
	// is its own, and the process's descriptor is left alone. Set with the
	// table; guarded by mu.
	ownStandard [3]bool

	// adopted holds, by slot, what the host's descriptor of a slot taken in
	// from outside the guest was open on (adoptHostLocked, currentLocked).
	// Guarded by mu.
	adopted map[int32]hostIdentity
}

// wasiProc is a process the guest can wait for: a host process spawned by
// Proc_spawn (host != nil), or a process the embedder runs itself (NewProc)
// (host == nil). Whoever runs the process publishes the encoded POSIX status
// and closes done, so Proc_wait can support both the blocking (options 0)
// and non-blocking (WNOHANG) forms without holding the WasiStubs lock across
// the child's lifetime.
type wasiProc struct {
	host   *commandProcess
	done   chan struct{}
	status int32 // POSIX wait status, valid once done is closed
	// kill delivers a signal to an embedder-run process (Proc_kill). nil
	// when the embedder gave none. It is set before the process is entered
	// in the family's table (wasiPIDs.enter) and not changed afterwards.
	kill func(sig int32) error
	// instance is the instance the process is the guest of: the family's
	// root instance (wasiPIDs.enterRoot), which nobody waits for, or a copy
	// made by ForkProc. A signal for it is posted to that instance.
	instance *WasiStubs
	// pgid and sid are the process group and the session the process is
	// in. They are set before the process is entered in the family's
	// table and guarded by wasiPIDs.mu from then on.
	pgid, sid int32
	// inHostGroup records that the command of the process (host, or the
	// one its guest has become) is in the host's process group of its group
	// (jobGroup.host), which a signal for the group reaches as a whole, and
	// leads that it is the command that made that group; execed that the
	// guest has become a command or is becoming one (Proc_exec). Guarded by
	// wasiPIDs.mu; set before the wait for the command begins.
	inHostGroup, leads, execed bool
}

// jobGroup is what the family knows of one of its process groups besides
// its members, the processes of the family whose pgid it is: the process
// group of the host its commands are put in. The group the host process is
// in (wasiPIDs.hostGroup) has none: its commands are in the host process's.
// Guarded by wasiPIDs.mu.
type jobGroup struct {
	// host is the host's process group: the host pid of leader, the first
	// command started in the group, which made it.
	host   int
	leader *wasiProc
	// starting counts the commands being started in the host's group
	// (commandJob), which are in it before the family knows them.
	starting int
	// held is closed once the group has no member left but its leader,
	// whose command has ended and is kept unreaped meanwhile, so that the
	// host's group keeps its number (leaderEnded). nil while the leader
	// runs.
	held chan struct{}
}

// wasiPIDs hands out pid tokens and knows the processes of a fork family by
// them. One is shared by every WasiStubs of the family, each of which has
// its own lock, hence the separate mutex.
type wasiPIDs struct {
	mu sync.Mutex
	// next is the token handed out next.
	next int32
	// skipped holds the numbers that are never tokens: the ones alloc passed
	// over (the ids of a Process), and the pid and ppid of the root instance
	// once it is entered.
	skipped map[int32]bool
	// rooted records that the root instance of the family — the one not
	// made by Fork — has been entered in procs under rootPID, the pid of its
	// Process. Both stay once the root is gone (leaveRoot).
	rooted  bool
	rootPID int32
	// procs holds every process of the family that exists: from the moment
	// it can be signalled until it has been waited for, or has finished
	// with nobody left to wait for it. An instance waits only for the
	// processes in its own table (WasiStubs.procs), but it may signal any
	// process whose pid it knows — a sibling, a grandchild — and only its
	// own children are in its own table.
	procs map[int32]*wasiProc
	// The process groups and sessions of the family (job control) are kept
	// here, decided and changed under mu, as gVisor's TaskSet.mu keeps them
	// (pkg/sentry/kernel/sessions.go): every process of procs is in the
	// group and the session its pgid and sid name. groups holds the groups
	// whose commands are in a process group of the host's own;
	// hostGroup and hostSession are the group and the session the host
	// process is in (the root's while its ProcessChanges makes its changes
	// the host's), session 0 the one the family starts in. starts makes the
	// starts of the family's commands one at a time (procSpawn). It is
	// taken before mu.
	groups                 map[int32]*jobGroup
	hostGroup, hostSession int32
	starts                 sync.Mutex
	// foreground is the group the guest made the foreground one of the
	// host process's controlling terminal (TIOCSPGRP) while it has no
	// host's group to be that, and terminal a descriptor of the host's of
	// the terminal meanwhile: the group's first command is started in the
	// foreground (hostJob). 0 when there is none.
	foreground int32
	terminal   int
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

// jobOf returns the process group and the session of the family's process
// pid, those of the host process when the family has no such process (any
// more).
func (p *wasiPIDs) jobOf(pid int32) (pgid, sid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if proc := p.procs[pid]; proc != nil {
		return proc.pgid, proc.sid
	}
	return p.hostGroup, p.hostSession
}

// hasGroupLocked reports whether the family has a process group pgid in
// session sid: a process in it. Caller holds p.mu.
func (p *wasiPIDs) hasGroupLocked(pgid, sid int32) bool {
	for _, proc := range p.procs {
		if proc.pgid == pgid && proc.sid == sid {
			return true
		}
	}
	return false
}

// removeLocked forgets the process known by pid. Caller holds p.mu.
func (p *wasiPIDs) removeLocked(pid int32) {
	if proc := p.procs[pid]; proc != nil {
		delete(p.procs, pid)
		p.leftGroupLocked(proc.pgid)
	}
}

// leftGroupLocked is told that a process has left the group pgid. Once
// only the leader of the group's host group is left, which has ended and
// waits to be reaped (leaderEnded), it is let go: the family drops the
// host's group before the host may give its number to another process.
// Caller holds p.mu.
func (p *wasiPIDs) leftGroupLocked(pgid int32) {
	g := p.groups[pgid]
	if g == nil || g.held == nil || g.starting > 0 {
		return
	}
	for _, proc := range p.procs {
		if proc.pgid == pgid && proc != g.leader {
			return
		}
	}
	close(g.held)
	delete(p.groups, pgid)
}

// leaderEnded is told that the command of leader, which leads the host's
// process group of its group, has ended and is not reaped yet. While the
// group has other members, the command is to be kept unreaped until held
// is closed: a process of the group may yet start a command in the host's
// group, whose number is the leader's pid. Otherwise, or when the command
// cannot be kept (keep false), the family drops the host's group and held
// is nil: the command may be reaped. Two-stage, as os's blockUntilWaitable
// waits with WNOWAIT before the reap.
func (p *wasiPIDs) leaderEnded(leader *wasiProc, keep bool) (held <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.groups[leader.pgid]
	if g == nil || g.leader != leader {
		return nil
	}
	if !keep {
		delete(p.groups, leader.pgid)
		return nil
	}
	g.held = make(chan struct{})
	p.leftGroupLocked(leader.pgid)
	if p.groups[leader.pgid] != g {
		return nil
	}
	return g.held
}

// commandJob is where a command is started (commandJob): in the process
// group pgid and the session sid of the family, the ones of the process
// that starts it, and in the host's process group and session host says.
// group is the record the command is counted in as starting (started),
// and self the process that becomes the command (Proc_exec).
type commandJob struct {
	pgid, sid          int32
	host               hostJob
	inHostGroup, leads bool
	group              *jobGroup
	self               *wasiProc
}

// hostJob is the host's process group and session a command is started
// in: a session and a group of its own (setsid), a group of its own
// (setpgid with pgid 0), the host's group pgid (setpgid), or, with
// neither, the host process's. With foreground its group of its own is
// made the foreground one of the terminal ctty, a descriptor of the host
// process's, before the command runs.
type hostJob struct {
	setsid, setpgid, foreground bool
	pgid, ctty                  int
}

// commandJob decides where a command the family's process pid starts is
// started: in pid's process group and session, and on the host
//
//   - in a session of its own when pid's session is not the host process's
//     (hostSession): no process outside a session can join it;
//   - in the host process's group when pid's group is that one;
//   - in the host's group of pid's group (jobGroup.host) when it has one;
//   - in a group of its own otherwise, which it leads, and which becomes
//     the host's group of pid's group (started).
//
// A command whose session is not the host process's leads the host's
// group of its group when the group has none yet, and is in no host's
// group of the family's otherwise. Without job control on the host
// (hostJobControl) every command is in the host process's group and
// session. With execs the command is pid's process (Proc_exec), which is
// becoming it from here on (wasiProc.execed): its group cannot be changed
// any more. Caller holds p.starts, until started.
func (p *wasiPIDs) commandJob(pid int32, execs bool) commandJob {
	p.mu.Lock()
	defer p.mu.Unlock()
	job := commandJob{pgid: p.hostGroup, sid: p.hostSession}
	if proc := p.procs[pid]; proc != nil {
		job.pgid, job.sid = proc.pgid, proc.sid
		if execs {
			job.self, proc.execed = proc, true
		}
	}
	if !hostJobControl {
		return job
	}
	g := p.groups[job.pgid]
	switch {
	case job.sid != p.hostSession:
		job.host.setsid = true
		job.inHostGroup, job.leads = g == nil, g == nil
	case job.pgid == p.hostGroup:
	case g != nil:
		job.host = hostJob{setpgid: true, pgid: g.host}
		job.inHostGroup = true
	default:
		job.host.setpgid = true
		job.inHostGroup, job.leads = true, true
	}
	if g != nil && job.inHostGroup {
		g.starting++
		job.group = g
	}
	if job.leads && !job.host.setsid && p.foreground != 0 && job.pgid == p.foreground {
		job.host.foreground, job.host.ctty = true, p.terminal
	}
	return job
}

// started is told that the command of job has started as the command of
// proc, the host's process hostPID, or has not (proc nil): the host's
// group a command leads becomes its group's, and the foreground one of the
// terminal once the command has been started in the foreground, when the
// descriptor of it kept meanwhile is closed (its error returned). Caller
// holds p.starts.
func (p *wasiPIDs) started(job commandJob, proc *wasiProc, hostPID int) error {
	p.mu.Lock()
	if job.group != nil {
		job.group.starting--
		p.leftGroupLocked(job.pgid)
	}
	switch {
	case proc == nil:
		if job.self != nil {
			job.self.execed = false
		}
		p.mu.Unlock()
		return nil
	case job.leads:
		if p.groups == nil {
			p.groups = map[int32]*jobGroup{}
		}
		p.groups[job.pgid] = &jobGroup{host: hostPID, leader: proc}
	}
	proc.inHostGroup, proc.leads = job.inHostGroup, job.leads
	if !job.host.foreground {
		p.mu.Unlock()
		return nil
	}
	p.foreground = 0
	p.mu.Unlock()
	return hostCloseFD(job.host.ctty)
}

// enterRoot makes the root instance root reachable by ids.PID, the pid of
// its Process, for the instances forked from it, and keeps that pid and
// ids.PPID from being a token from then on; a number already handed out
// stays the token it is. The root is in the process group pgid and in the
// session the family starts in, which are the host process's. It does
// nothing once the root is entered.
func (p *wasiPIDs) enterRoot(ids ProcessIDs, root *WasiStubs, pgid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rooted {
		return
	}
	if p.procs == nil {
		p.procs = map[int32]*wasiProc{}
	}
	if p.skipped == nil {
		p.skipped = map[int32]bool{}
	}
	for _, id := range []int32{ids.PID, ids.PPID} {
		if id >= p.next {
			p.skipped[id] = true
		}
	}
	p.rooted, p.rootPID = true, ids.PID
	p.procs[ids.PID] = &wasiProc{done: make(chan struct{}), instance: root, pgid: pgid}
	p.hostGroup = pgid
}

// leaveRoot forgets the root instance: it is gone, and with it the
// descriptor of the host process's terminal kept for a group to become its
// foreground one (TIOCSPGRP), which is closed (its error returned), under
// p.starts: no start in the foreground has its number then. Caller holds no
// lock of an instance.
func (p *wasiPIDs) leaveRoot() error {
	p.starts.Lock()
	defer p.starts.Unlock()
	p.mu.Lock()
	if p.rooted {
		p.removeLocked(p.rootPID)
	}
	terminal, kept := p.terminal, p.foreground != 0
	p.foreground = 0
	p.mu.Unlock()
	if kept {
		return hostCloseFD(terminal)
	}
	return nil
}

// leave forgets the process known by pid.
func (p *wasiPIDs) leave(pid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(pid)
}

// find returns the process of the family known by pid, or nil, and whether
// pid is the family's, the process gone or not: a token alloc has handed
// out, or the root instance's pid.
func (p *wasiPIDs) find(pid int32) (proc *wasiProc, ours bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.findLocked(pid)
}

// findLocked is find for a caller that holds p.mu.
func (p *wasiPIDs) findLocked(pid int32) (proc *wasiProc, ours bool) {
	token := pid >= wasiFirstPID && pid < p.next && !p.skipped[pid]
	return p.procs[pid], token || p.rooted && pid == p.rootPID
}

// alloc returns the next unused pid token that is none of reserved, nor a
// number that is never a token (skipped).
func (p *wasiPIDs) alloc(reserved ...int32) int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	for slices.Contains(reserved, p.next) || p.skipped[p.next] {
		if p.skipped == nil {
			p.skipped = map[int32]bool{}
		}
		p.skipped[p.next] = true
		p.next++
	}
	pid := p.next
	p.next++
	return pid
}

// wasiFirstPID is the first pid token a fresh instance hands out:
// PID_MAX_LIMIT of 64-bit Linux, above every pid Linux hands out (below
// pid_max, at most PID_MAX_LIMIT: kernel/pid.c, include/linux/threads.h)
// and darwin's (below PID_MAX, 99999: bsd/kern/kern_fork.c), so that a
// token names no process of the host.
const wasiFirstPID int32 = 1 << 22

// NewWASI returns a WasiStubs whose guest has what cfg gives it (see
// WASIConfig). It panics when cfg has a ProcessChanges without a Process,
// whose guest would read none of the changes it makes.
func NewWASI(cfg WASIConfig) *WasiStubs {
	if cfg.ProcessChanges != nil && cfg.Process == nil {
		panic(errors.New("wasi: WASIConfig.ProcessChanges is set without WASIConfig.Process"))
	}
	cfg.Args = append([]string(nil), cfg.Args...)
	cfg.Env = append([]string(nil), cfg.Env...)
	cfg.Files = maps.Clone(cfg.Files)
	w := &WasiStubs{cfg: cfg, monoStart: time.Now()}
	if w.hostFamily() {
		w.reportError("host_descriptors", startHostNumbers(cfg.Files))
	}
	return w
}

// takeFileLocked enters f, a file of the configuration's Files, at fd
// (fileEntry; placeFileLocked where the descriptors are the host's): what
// fd held before, a standard stream, is closed. A failure is told Errors
// later (reportLater), f is closed, and the guest finds fd closed. Caller
// holds w.mu.
func (w *WasiStubs) takeFileLocked(fd int32, f *os.File) {
	w.reportLater("files", w.enterFileLocked(fd, f))
}

// enterFileLocked is takeFileLocked but for the report of the failure.
// Caller holds w.mu.
func (w *WasiStubs) enterFileLocked(fd int32, f *os.File) error {
	switch {
	case f == nil:
		return fmt.Errorf("descriptor %d: no file", fd)
	case fd < 0 || fd >= wasiRootFD:
		return errors.Join(fmt.Errorf("descriptor %d: %w", fd, syscall.EBADF), f.Close())
	case w.hostNumbered():
		return w.placeFileLocked(fd, f)
	}
	op, err := fileEntry(f, !w.hostFamily())
	if err != nil {
		return err
	}
	w.replaceSlotLocked("files", fd, op)
	return nil
}

// replaceSlotLocked puts op at fd in place of what fd held (takeSlotLocked),
// for the instance's own use (Files, the drop of a stale slot): what is
// left of the old entry, and the host's locks of its file (resyncReleased),
// is closed once w.mu is let go, its failure told Errors under op. Caller
// holds w.mu.
func (w *WasiStubs) replaceSlotLocked(call string, fd int32, op *wasiOpen) {
	old := w.takeSlotLocked(fd)
	w.mu.afterUnlock(func() {
		err := w.resyncReleased()
		if old != nil {
			err = errors.Join(err, closeWasiOpen(old))
		}
		w.reportError(call, err)
	})
	if op != nil {
		w.setSlotLocked(fd, op)
	}
}

// hostFamily reports whether the instance is of a fork family whose first
// instance has the host process's descriptor numbers
// (WASIConfig.HostDescriptors). For every instance of it, fd 3 is a number
// like any other, as it is for the host (preopened).
func (w *WasiStubs) hostFamily() bool {
	return hostDescriptorsSupported && w.cfg.HostDescriptors
}

// hostNumbered reports whether the instance's descriptor numbers are the
// host process's (WASIConfig.HostDescriptors): the instance NewWASI made,
// not a copy made by Fork.
func (w *WasiStubs) hostNumbered() bool {
	return w.hostFamily() && !w.forked
}

// HostDescriptor returns the descriptor of the host process behind the
// guest's descriptor fd: fd itself for an instance whose descriptors are
// the host's (WASIConfig.HostDescriptors), the descriptor of its file or
// socket otherwise. The number names it while the guest has fd open. ok is
// false when fd is not open or has no descriptor of the host behind it (a
// file of a MemFS, a standard stream that is a reader or writer).
func (w *WasiStubs) HostDescriptor(fd int32) (host uintptr, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.openLocked(fd)
	conn := w.entryHostConnLocked(op)
	if conn == nil {
		return 0, false
	}
	if w.hostNumbered() {
		return uintptr(fd), w.hostSlotHeld(fd)
	}
	return host, hostDescriptor(conn, func(d uintptr) { host = d })
}

// entryHostConnLocked returns the file or socket of the host behind the
// entry op, nil for none. A standard stream is one only where it is not a
// descriptor of the host's under its own number in an instance whose
// descriptors are the host's (see takeStandardLocked). Caller holds w.mu.
func (w *WasiStubs) entryHostConnLocked(op *wasiOpen) syscall.Conn {
	if op == nil {
		return nil
	}
	if host := op.hostSocket(); host != nil {
		return host
	}
	if f, ok := op.f.(*os.File); ok {
		return f
	}
	if op.stdio == 0 || w.hostNumbered() {
		return nil
	}
	conn, _ := [...]any{w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr}[op.stdio-1].(*os.File)
	if conn == nil {
		return nil
	}
	return conn
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

// familyStreams is what the instances of a fork family share of their
// standard streams (WASIConfig.Stdin, Stdout, Stderr) for the commands they
// start, whose streams the runtime copies when they are not files of the
// host. stdout and stderr are the turns at the instance's stdout and stderr
// that are no files of the host's, one turn when they are one Writer
// (interfaceEqual, as os/exec decides that Stdout is Stderr): the guests'
// writes and those of the runtime's copies of command output take them.
// stdin is the reader of the instance's stdin, which reads it when poll(2)
// does not wait for it (inputReader). polled is whether the
// Go runtime polls each stream (filePolled), asked once (asked) before any
// call of the family on a standard stream could wait for it, since asking
// clears a read deadline such a wait can have. The streams are the
// configuration's, which every instance of the family shares.
type familyStreams struct {
	stdout, stderr *streamTurn
	stdin          *streamReader
	asked          sync.Once
	polled         [3]bool
	// live counts the instances of the family that share these and have
	// not been closed (CloseAll): the last one's CloseAll stops stdin.
	live atomic.Int32
}

// turn returns the family's turn at its standard stream stdio (2 the
// stdout, 3 the stderr, as wasiOpen.stdio).
func (s *familyStreams) turn(stdio int8) *streamTurn {
	if stdio == 3 {
		return s.stderr
	}
	return s.stdout
}

// interfaceEqual is a == b, and false where a and b hold values of one
// type that is not comparable, whose comparison panics: as os/exec's
// interfaceEqual, which decides that Stdout is Stderr so.
func interfaceEqual(a, b any) (equal bool) {
	defer func() {
		// The panic of the comparison says only that the values cannot be
		// compared: they are taken for different ones.
		if recover() != nil {
			equal = false
		}
	}()
	return a == b
}

// streamsLocked returns the family's familyStreams, made on first use.
// Caller holds w.mu.
func (w *WasiStubs) streamsLocked() *familyStreams {
	if w.streams == nil {
		w.streams = &familyStreams{stdout: new(streamTurn), stdin: newStreamReader(w.stdin(), func(err error) { w.reportError("fd_read", err) })}
		w.streams.live.Store(1)
		w.streams.stderr = w.streams.stdout
		if !interfaceEqual(w.stdout(), w.stderr()) {
			w.streams.stderr = new(streamTurn)
		}
	}
	return w.streams
}

// outputTurnLocked returns the turn a write of the guest's to dst, the
// destination of the entry op, is made with: the family's turn at the
// instance's stdout or stderr that is not a file of the host, which the
// runtime's copies of command output take as well (familyStreams); nil for
// any other. Caller holds w.mu.
func (w *WasiStubs) outputTurnLocked(op *wasiOpen, dst io.Writer) *streamTurn {
	if op == nil || op.stdio < 2 {
		return nil
	}
	if _, isFile := dst.(*os.File); isFile {
		return nil
	}
	return w.streamsLocked().turn(op.stdio)
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
//   - the configuration is the same WASIConfig, its Process and Signals
//     included, and the clock origin, the file mode creation mask, the
//     zone of the last TZ value (see zoneMoment) and the walks of the user
//     and group databases (Users) are the same: the copy has
//     the pid of w's Process as its own (ForkProc gives it a pid of its
//     own);
//   - the fd table has the same fd numbers — an fd closed in w, fd 0, 1 or
//     2 included, is closed in the result — and each slot refers to the SAME
//     open descriptor as the corresponding slot of w, so the two instances
//     share the file offset, and the underlying file, connection or listener
//     is closed only when the last slot referring to it, in any instance, is
//     closed;
//   - the process table is empty: a child does not inherit its parent's
//     children. Pid tokens stay unique across w, the result and everything
//     later forked from either. The instance not made by Fork, the root of
//     the family, is known to the family by the pid of its Process from its
//     first fork on (Proc_kill), and neither that pid nor its ppid is a token
//     from then on;
//   - the dispositions are w's, and so are the registration for signals and
//     the mask of the guest's thread that forks, the one thread of the copy
//     (POSIX fork): its first call of the host is that thread's. Fork does
//     not know the thread that forks, and takes the first thread of w's
//     guest that registered for signals; Proc_fork takes its own. The
//     dispositions are reported to WASIConfig.Signals with the result as the
//     target. A copy of a guest that has not registered has not either. No
//     signal is pending and no interval timer is set.
//
// The copy shares the identity of w: the same Process, so its getpid and
// getppid are w's. From the root on, every copy made by Fork has the root's
// pid as its own, and that pid names the copy itself in its kill; a copy
// that a ForkProc of such a copy made has that pid as its ppid, and its
// kill of it reaches the root. ForkProc is the way to give a copy a pid of
// its own.
//
// The result is independent of w from then on (its own lock, its own fd
// numbering) and is meant to back a second module instance running on
// another goroutine. Release its descriptors with CloseAll when that instance
// is done. It has none of the System V shared memory segments the guest of
// w attached (Ipc_shmat): the copy's shmdt of one fails with EINVAL.
func (w *WasiStubs) Fork() *WasiStubs {
	return w.fork(nil)
}

// fork is Fork for the thread of the guest whose module from is, the one
// that forks (nil: the first one that registered for signals).
func (w *WasiStubs) fork(from *Module) *WasiStubs {
	child := w.forkHost()
	w.sig.forkInto(&child.sig, from)
	child.reportDispositions()
	return child
}

// forkHost is Fork but for the signal state.
func (w *WasiStubs) forkHost() *WasiStubs {
	ids := w.guestProcess().IDs()
	start := w.forkedChanges(ids)
	w.enterRoot()
	w.mu.Lock()
	defer w.mu.Unlock()
	child := &WasiStubs{
		cfg:       w.cfg,
		fdTable:   make(map[int32]*wasiOpen, len(w.fdsLocked())),
		monoStart: w.monoStart,
		procs:     map[int32]*wasiProc{},
		pids:      w.pidsLocked(),
		streams:   w.streamsLocked(),
		hosts:     w.hostsLocked(),
		zoneTZ:    w.zoneTZ,
		zone:      w.zone,
		userWalk:  w.userWalk,
		groupWalk: w.groupWalk,
		syslog:    w.syslogFamilyLocked(),
		forked:    true,
	}
	child.preopenReplaced.Store(w.preopenReplaced.Load())
	// The child is nobody else's yet: its slots are set without its lock.
	for fd, op := range w.fdsLocked() {
		child.setSlotLocked(fd, op)
	}
	if len(w.cloexec) > 0 || len(w.adopted) > 0 {
		child.cloexec = make(map[int32]bool, len(w.cloexec))
		for fd := range w.cloexec {
			child.cloexec[fd] = true
		}
		// A slot taken in from outside the guest has the host's mark, which
		// the child gets as fork(2) copies it.
		for fd := range w.adopted {
			if hostCloseOnExec(int(fd)) {
				child.cloexec[fd] = true
			}
		}
	}
	if w.umask != nil {
		mask := *w.umask
		child.umask = &mask
	}
	if start != nil {
		if w.changed != nil {
			start.overlay(*w.changed)
		}
		child.changed = start
	}
	child.streams.live.Add(1)
	return child
}

// CloseAll closes every fd of this instance, as if the guest had called
// fd_close on each: a descriptor shared with another slot or another instance
// (dup, Fork) stays open until its last reference goes. It disposes of the
// host state of a finished instance.
// It also ends signal delivery to the instance — the interval timer is disarmed, and
// PostSignal drops what it is given from here on — and detaches the System
// V shared memory segments the guest has attached (Ipc_shmat), so the
// guest's memory can be released afterwards. A call of IPC the guest is
// waiting in (IPC.Semop, Msgsnd, Msgrcv) is not ended: it uses the guest's
// memory until it returns. The instance stops using the Syslogger, as at a
// closelog (Syslogger).
// Calling it again is a no-op: a call made while another one closes the
// descriptors returns without waiting for those closes. The close errors
// are joined.
func (w *WasiStubs) CloseAll() error {
	closing, err := w.takeAll()
	// The last instance of the family to be closed stops the reader of its
	// stdin, which nothing asks for input from then on.
	w.mu.Lock()
	share := w.streams
	leaves := share != nil && !w.streamsLeft
	w.streamsLeft = true
	w.mu.Unlock()
	if leaves && share.live.Add(-1) == 0 {
		share.stdin.stop()
	}
	return errors.Join(err, w.resyncReleased(), closeWasiOpens(closing), w.detachAllShm(), w.stopSyslog())
}

// takeAll is CloseAll up to the closing of the descriptors, which it takes
// out of the table and returns, to be closed once w.mu is let go
// (closeWasiOpen).
func (w *WasiStubs) takeAll() ([]*wasiOpen, error) {
	w.mu.Lock()
	creations := w.creations
	w.creations, w.creationsClosed = nil, true
	pids := w.pids
	w.mu.Unlock()
	if creations != nil {
		creations.close()
	}
	var err error
	if !w.forked && pids != nil {
		err = pids.leaveRoot()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.detachSignals()
	for _, wk := range w.wakes {
		err = errors.Join(err, wk.closePipe())
	}
	w.wakes, w.wakesClosed = nil, true
	closing, clearErr := w.endSlotsLocked()
	err = errors.Join(err, clearErr)
	// Nobody is left to wait for this instance's processes: the finished
	// ones are gone, and the running ones go when they finish (finishProc
	// finds them missing from the table).
	for pid, proc := range w.procs {
		select {
		case <-proc.done:
			w.pidsLocked().leave(pid)
		default:
		}
		delete(w.procs, pid)
	}
	return closing, err
}

// Fd_closefrom is a NON-STANDARD host import (module
// wasip1_posix_extension, name "fd_closefrom") backing closefrom(): it
// closes every fd numbered lowFd or higher, each as fd_close would. Returns
// 0, or a positive errno for the first close that failed (every fd in range
// is closed regardless).
func (w *WasiStubs) Fd_closefrom(m *Module, lowFd int32) int32 {
	if err := w.closeFrom(lowFd); err != nil {
		return w.guestErrno("fd_closefrom", err)
	}
	return _wasiESUCCESS
}

// closeFrom closes every fd numbered lowFd or higher, each as fd_close
// would, and joins the close errors.
func (w *WasiStubs) closeFrom(lowFd int32) error {
	w.mu.Lock()
	closing, err := w.clearSlotsFromLocked(lowFd)
	w.mu.Unlock()
	return errors.Join(err, w.resyncReleased(), closeWasiOpens(closing))
}

// endSlotsLocked clears every slot for an end of the instance (CloseAll,
// CloseDescriptors) and returns the entries to close. The standard
// descriptors of the host process stay open where the guest has them: the
// embedder writes to them after the instance. A table not set up yet is set
// up first, which takes the configuration's Files over to be closed.
// Caller holds w.mu.
func (w *WasiStubs) endSlotsLocked() ([]*wasiOpen, error) {
	w.fdsLocked()
	w.leaveStandardNumbersLocked()
	return w.clearSlotsFromLocked(0)
}

// CloseDescriptors closes every descriptor of this instance in its table,
// each as fd_close would, and nothing else: the preopened directories stay
// (the root's numbers, wasiPreopenFD and wasiRootFD), and the instance
// stays what it is to the processes of its family and keeps receiving
// signals. It is for an embedder that ends an instance whose guest may
// still be running on another goroutine: the guest finds every descriptor
// it opened, and its standard ones, closed. CloseAll is still to be called
// once the guest no longer runs. The close errors are joined.
func (w *WasiStubs) CloseDescriptors() error {
	w.mu.Lock()
	closing, err := w.endSlotsLocked()
	w.mu.Unlock()
	return errors.Join(err, w.resyncReleased(), closeWasiOpens(closing))
}

// KillCommands ends the commands this instance started (Proc_spawn) and
// has not waited for: each one still running is killed, as by SIGKILL,
// and the call returns once every one killed, or found ended, has ended
// and what the runtime copied of its output is delivered (startCommand),
// as os/exec's Cmd.Wait without a WaitDelay: a destination that does not
// take the output holds the call. A read of an embedder's stdin a copy is
// in is not waited for, as the runtime cannot end it, except on a system
// where commands are started by os/exec (not darwin or linux), whose wait
// waits for that copy too. A command the kill fails for (EPERM) is not
// waited for: its error is returned. The commands are those in the table
// when the call takes it: one started afterwards is not killed. They stay
// in the instance's process table, with the status they end with. The
// command the guest has become (Proc_exec) is killed and waited for as
// well. The errors of the kills are joined.
//
// It is for an embedder that ends an instance without letting it run on,
// and may be called while the guest is running on another goroutine.
func (w *WasiStubs) KillCommands() error {
	w.mu.Lock()
	var commands []*wasiProc
	for _, proc := range w.procs {
		if proc.host != nil {
			commands = append(commands, proc)
		}
	}
	w.mu.Unlock()
	var err error
	var ending []*wasiProc
	for _, proc := range commands {
		// A command that has ended already is not killed, and ends.
		if kerr := proc.host.Kill(); kerr != nil && !errors.Is(kerr, os.ErrProcessDone) {
			err = errors.Join(err, kerr)
			continue
		}
		ending = append(ending, proc)
	}
	for _, proc := range ending {
		<-proc.done
	}
	w.sig.mu.Lock()
	execed := w.sig.execed
	w.sig.mu.Unlock()
	if execed == nil {
		return err
	}
	if kerr := signalHostProc(execed.process, wasiSIGKILL); kerr != nil {
		return errors.Join(err, kerr)
	}
	<-execed.done
	return err
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
	return !none && (fd == wasiRootFD || fd == wasiPreopenFD && (w.hostFamily() || !w.preopenReplaced.Load()))
}

// fdsLocked returns the fd table. On first use it sets the table up with
// fds 0, 1 and 2 referring to the instance's stdin, stdout and stderr (see
// takeStandardLocked), and the Files of the configuration under their
// numbers; from then on those are ordinary slots that the guest can close,
// dup and reuse. Caller holds w.mu.
func (w *WasiStubs) fdsLocked() map[int32]*wasiOpen {
	if w.fdTable == nil {
		w.fdTable = map[int32]*wasiOpen{}
		for fd, stdio := range []int8{1, 2, 3} {
			if w.hostNumbered() {
				if w.takeStandardLocked(int32(fd)) {
					continue
				}
				w.ownStandard[fd] = true
			}
			w.setSlotLocked(int32(fd), &wasiOpen{stdio: stdio})
		}
		for _, fd := range slices.Sorted(maps.Keys(w.cfg.Files)) {
			w.takeFileLocked(fd, w.cfg.Files[fd])
		}
	}
	return w.fdTable
}

// setSlotLocked puts op at fd, which holds nothing: op has one more slot
// (refs), fd is not close-on-exec, and fd wasiPreopenFD names the
// preopened root no longer (preopened). Caller holds w.mu.
func (w *WasiStubs) setSlotLocked(fd int32, op *wasiOpen) {
	op.mu.Lock()
	op.refs++
	op.mu.Unlock()
	w.fdsLocked()[fd] = op
	delete(w.cloexec, fd)
	delete(w.adopted, fd)
	if fd == wasiPreopenFD {
		w.preopenReplaced.Store(true)
	}
}

// clearSlotLocked takes fd out of the table, close-on-exec mark and all,
// with the instance's record locks of its file (releaseRecordLocksLocked),
// and in an instance whose descriptors are the host's closes the host's
// descriptor fd (releaseHostSlotLocked), whose error it returns. It
// returns the entry fd held when that was its last slot, of any instance,
// for the caller to close once w.mu is let go (closeWasiOpen); nil
// otherwise, and for an fd that holds nothing. Caller holds w.mu.
func (w *WasiStubs) clearSlotLocked(fd int32) (closing *wasiOpen, err error) {
	if w.fdsLocked()[fd] == nil {
		return nil, nil
	}
	if w.hostNumbered() {
		err = w.releaseHostSlotLocked(fd)
	}
	return w.takeSlotLocked(fd), err
}

// takeSlotLocked is clearSlotLocked but for the host's descriptor fd, which
// it leaves as it is: one that a placement (placeHostSlotLocked) has just
// made another file's. Caller holds w.mu.
func (w *WasiStubs) takeSlotLocked(fd int32) (closing *wasiOpen) {
	op := w.fdsLocked()[fd]
	if op == nil {
		return nil
	}
	delete(w.adopted, fd)
	delete(w.fdsLocked(), fd)
	delete(w.cloexec, fd)
	w.releaseRecordLocksLocked(op)
	op.mu.Lock()
	op.refs--
	last := op.refs == 0
	op.mu.Unlock()
	if !last {
		return nil
	}
	return op
}

// clearSlotsFromLocked clears every fd numbered lowFd or higher
// (clearSlotLocked) and returns the entries to close, with the errors of
// the clearing joined. Caller holds w.mu.
func (w *WasiStubs) clearSlotsFromLocked(lowFd int32) ([]*wasiOpen, error) {
	var closing []*wasiOpen
	var err error
	for fd := range w.fdsLocked() {
		if fd < lowFd {
			continue
		}
		op, clearErr := w.clearSlotLocked(fd)
		err = errors.Join(err, clearErr)
		if op != nil {
			closing = append(closing, op)
		}
	}
	return closing, err
}

// openLocked returns the entry the guest knows as descriptor fd, or nil
// when it has none. In an instance whose descriptors are the host's, a
// descriptor of the process that is nobody's becomes the guest's here
// (adoptHostLocked). Caller holds w.mu.
func (w *WasiStubs) openLocked(fd int32) *wasiOpen {
	op := w.fdsLocked()[fd]
	if w.hostNumbered() && (op == nil || !w.currentLocked(fd)) {
		return w.adoptHostLocked(fd)
	}
	return op
}

// addFDLocked stores op under the lowest fd number not in use, as POSIX
// requires of open, pipe, dup, socket and accept, and returns that number
// and an errno: EMFILE where the host has no number for it (see
// addFDFromLocked). Caller holds w.mu.
func (w *WasiStubs) addFDLocked(op *wasiOpen) (int32, int32) {
	return w.addFDFromLocked(op, 0)
}

// addFDFromLocked enters op under the lowest free number that is at least
// min (fcntl's F_DUPFD) and below wasiRootFD, and returns it and an errno:
// EMFILE when there is none. Where the descriptors are the host's, the
// host gives the number (hostSlotLocked). A new entry (one no slot holds
// yet) that is not entered is closed once w.mu is let go. Caller holds
// w.mu.
func (w *WasiStubs) addFDFromLocked(op *wasiOpen, min int32) (int32, int32) {
	op.mu.Lock()
	fresh := op.refs == 0
	op.mu.Unlock()
	fail := func(err error) (int32, int32) {
		if fresh {
			w.mu.afterUnlock(func() { w.reportError("descriptors", closeWasiOpen(op)) })
		}
		return -1, w.errnoLater("descriptors", err)
	}
	if w.hostNumbered() {
		fd, err := w.hostSlotLocked(op, min)
		if err != nil {
			return fail(err)
		}
		w.setSlotLocked(fd, op)
		return fd, _wasiESUCCESS
	}
	fds := w.fdsLocked()
	for fd := min; fd < wasiRootFD; fd++ {
		if _, used := fds[fd]; !used && (fd == wasiPreopenFD && w.hostFamily() || !w.preopened(fd)) {
			w.setSlotLocked(fd, op)
			return fd, _wasiESUCCESS
		}
	}
	return fail(syscall.EMFILE)
}

// enterRoot enters the root instance in the table of its family
// (wasiPIDs.enterRoot), in the process group its ProcessChanges tells
// (Pgid), or the one of its own pid without one or when it cannot tell
// (its error told WASIConfig.Errors, op "getpgid", unless it is
// errors.ErrUnsupported). The processes the guest makes are in the group
// and the session the guest is in. It does nothing for a forked instance
// and once the root is entered. Caller does not hold w.mu.
func (w *WasiStubs) enterRoot() {
	if w.forked {
		return
	}
	w.rootEntry.Do(func() {
		ids := w.guestProcess().IDs()
		pgid := ids.PID
		if changes := w.cfg.ProcessChanges; changes != nil {
			switch got, err := changes.Pgid(0); {
			case err == nil:
				pgid = got
			case !errors.Is(err, errors.ErrUnsupported):
				w.reportError("getpgid", err)
			}
		}
		w.mu.Lock()
		pids := w.pidsLocked()
		w.mu.Unlock()
		pids.enterRoot(ids, w, pgid)
	})
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
// ids of the Process. The family does not know it yet: see
// enterProcLocked. Caller holds w.mu.
func (w *WasiStubs) addProcLocked(proc *wasiProc, ids ProcessIDs) int32 {
	pid := w.pidsLocked().alloc(ids.PID, ids.PPID)
	w.putProcLocked(pid, proc)
	return pid
}

// putProcLocked registers proc under pid, a token alloc handed out, as a
// process this instance waits for. Caller holds w.mu.
func (w *WasiStubs) putProcLocked(pid int32, proc *wasiProc) {
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	w.procs[pid] = proc
}

// enterProcLocked makes the process registered under pid known to the whole
// fork family, once everything Proc_kill needs of it is in place. Caller
// holds w.mu.
func (w *WasiStubs) enterProcLocked(pid int32) {
	w.pidsLocked().enter(pid, w.procs[pid])
}

// dropProcLocked removes a process from this instance's table and from the
// family's: it has been waited for. Caller holds w.mu.
func (w *WasiStubs) dropProcLocked(pid int32) {
	delete(w.procs, pid)
	w.pidsLocked().leave(pid)
}

// finishProc publishes the wait status of proc and wakes every waiter.
// It must be called exactly once per process.
func (w *WasiStubs) finishProc(proc *wasiProc, status int32) {
	proc.status = status
	close(proc.done)
	// Offered once the status can be waited for, for whoever takes the
	// signal to find it.
	taken := w.takeSignal(wasiSIGCHLD)
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
		pids := w.pidsLocked()
		pids.mu.Lock()
		for pid, pr := range pids.procs {
			if pr == proc {
				pids.removeLocked(pid)
				break
			}
		}
		pids.mu.Unlock()
	}
	w.mu.Unlock()
	// The parent is told, as the kernel tells a process whose child ended.
	if !taken {
		w.PostSignal(wasiSIGCHLD)
	}
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
// called on another goroutine. Its error is what the guest's kill reports
// (syscall.EPERM, ...). With a nil kill the process cannot be signalled.
func (w *WasiStubs) NewProc(kill func(sig int32) error) (pid int32, exited func(status int32)) {
	return w.newProc(&wasiProc{done: make(chan struct{}), kill: kill})
}

// ForkProc is Fork for a forked copy of the guest that the guest of w waits
// for as its child, the way NewProc registers a process: it returns the
// host state of the copy, its pid token, and exited, which the embedder
// calls with the POSIX wait status when the copy ends. A signal for the
// token (Proc_kill) is posted to the copy (PostSignal), and the copy knows
// the token as its own pid: its Process reports the token as the pid and
// the pid of w's Process as the ppid, and the rest as w's Process does. Its
// kill of the token is a raise, its kill of its ppid reaches the instance
// that pid names, and its kill of its process group reaches it once.
// ForkProc is the way to give a copy a pid of its own: a copy made by Fork
// shares w's identity (see Fork), so when w is such a copy the ppid is the
// root's pid, and the copy's kill of it reaches the root, not w.
func (w *WasiStubs) ForkProc() (child *WasiStubs, pid int32, exited func(status int32)) {
	child, pid, proc := w.forkProc(nil)
	w.enterChild(pid, proc)
	return child, pid, w.procExitFunc(proc)
}

// forkProc is ForkProc up to the copy's becoming w's child (enterChild):
// it returns the copy, its pid token and its process, which nobody can wait
// for or signal yet. from is the module of the thread that forks (see fork).
func (w *WasiStubs) forkProc(from *Module) (*WasiStubs, int32, *wasiProc) {
	parent := w.guestProcess()
	ids := parent.IDs()
	child := w.fork(from)
	w.mu.Lock()
	pid := w.pidsLocked().alloc(ids.PID, ids.PPID)
	pgid, sid := w.pidsLocked().jobOf(ids.PID)
	w.mu.Unlock()
	child.cfg.Process = forkedProcess{Process: parent, pid: pid, ppid: ids.PID}
	return child, pid, &wasiProc{done: make(chan struct{}), instance: child, pgid: pgid, sid: sid}
}

// enterChild makes proc, the process of a copy forkProc made under pid, a
// child of w that w waits for and the fork family can signal.
func (w *WasiStubs) enterChild(pid int32, proc *wasiProc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.putProcLocked(pid, proc)
	w.enterProcLocked(pid)
}

// forkedProcess is the Process of a copy made by ForkProc: its pid is its
// token and its ppid its parent's pid; the rest is its parent's Process.
type forkedProcess struct {
	Process
	pid, ppid int32
}

func (p forkedProcess) IDs() ProcessIDs {
	ids := p.Process.IDs()
	ids.PID, ids.PPID = p.pid, p.ppid
	return ids
}

// newProc registers proc as NewProc does.
func (w *WasiStubs) newProc(proc *wasiProc) (pid int32, exited func(status int32)) {
	w.enterRoot()
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	pid = w.addProcLocked(proc, ids)
	proc.pgid, proc.sid = w.pidsLocked().jobOf(ids.PID)
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

// Forker makes the instance the child of a guest's fork runs in
// (WASIConfig.Fork, Proc_fork).
type Forker interface {
	// Fork returns a new instance of parent's module that is a copy of
	// parent as it stands: its memory and globals, the memory's ceiling,
	// its dropped data segments and the end of its data (dataEnd). Its
	// wasi import is child, the host state of the copy (ForkProc), whose
	// pid token is pid. It does not run the instance: Proc_fork runs the
	// child in it, through the module's fork child export.
	//
	// It is called on the goroutine of the guest that forks, inside its
	// proc_fork call, so that thread of the guest is stopped; the guest's
	// other threads are not, and the child has none of them: as in a POSIX
	// fork, a lock another thread held stays held in the child. The function
	// it returns, done, is nil or is called by Proc_fork once with the
	// child's wait status when the child has ended: on the child's
	// goroutine, before child is closed (CloseAll) and before the status
	// is published, so that nobody who waits for pid goes on before done
	// has returned. The threads the child started itself may still run
	// then. A panic of done is told WASIConfig.Errors, which must not
	// panic itself. done may close child itself before it releases what
	// the instance holds. An error leaves nothing made: Proc_fork closes
	// child and the fork fails, and it closes child as well when Fork
	// panics.
	//
	// The children of the child fork through the same Forker (a forked
	// instance has its parent's WASIConfig), so done is called for every
	// process of the fork family.
	Fork(parent *Module, child *WasiStubs, pid int32) (*Module, func(status int32), error)
}

// CopyForker is the Forker that makes the child's instance from a copy of
// the parent's memory, made while the parent's memory cannot grow; the
// child's other imports than the wasi one are the parent's. The copy of a
// memory that is not shared and is a mapping of the runtime's (MapMemory,
// SharedImage.Memory, ForkMemory) is the duplicate ForkMemory makes, and
// done releases it once it has closed the child. Any other copy is in the
// Go heap: the copy of a shared memory is as long as the parent's, its
// ceiling, and any other is as long as the guest's memory, and it returns
// no done. A guest thread other than the forking one that writes the
// memory meanwhile may leave the copy with a part of its write.
var CopyForker Forker = copyForker{}

// copyForker is CopyForker.
type copyForker struct{}

func (copyForker) Fork(m *Module, child *WasiStubs, pid int32) (*Module, func(status int32), error) {
	if !m.memShared {
		memory, size, err := forkRuntimeMapping(m)
		if err != nil {
			return nil, nil, err
		}
		if memory != nil {
			return m.forkModule(m, child, memory, size), func(int32) {
				// The child's segments are detached before its memory goes
				// (UnmapMemory).
				child.reportError("proc_fork", errors.Join(child.CloseAll(), unmapMemory(memory)))
			}, nil
		}
	}
	var (
		memory []byte
		size   uint64
	)
	accessMemory(m, func(mem []byte) {
		size = m.memSize.Load()
		length := size
		if m.memShared {
			// Its threads hold its address: it never moves, so it spans
			// its ceiling from the start (see memoryGrow).
			length = uint64(len(mem))
		}
		memory = make([]byte, length)
		copy(memory, mem[:size])
	})
	return m.forkModule(m, child, memory, size), nil, nil
}

// Proc_fork is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_fork") backing fork(): the guest's process is copied into a
// child process, a new instance that runs on a goroutine of its own. The
// child's host state is a copy of the guest's with a pid token of its own
// (ForkProc); WASIConfig.Fork makes its instance. On success the token is
// written at pidOutPtr, which the copy does not have, and the child runs
// the module's fork child export (__wasip1_posix_extension_fork_child)
// once. It ends when the export returns r, as exit(r) does (wait status
// (r&0xff)<<8), with Proc_exit (the same of its code), or by a signal (the
// signal's number). A trap or another panic of the child is told
// WASIConfig.Errors (op "proc_fork") and ends it as SIGABRT does. When the
// child has ended, the Forker's done is called, its host state is closed
// (CloseAll) and its wait status published, in that order: the guest
// waits for it (Proc_wait, Proc_wait_any), signals it (Proc_kill) and is
// sent SIGCHLD when it ends, as for any child.
//
// Returns 0, or a negative errno: ENOSYS when WASIConfig.Fork is nil or
// the module has no fork child export, EFAULT for a pidOutPtr outside the
// memory, EAGAIN when the Forker failed, whose error is told
// WASIConfig.Errors (op "proc_fork").
func (w *WasiStubs) Proc_fork(m *Module, pidOutPtr int32) int32 {
	return w.procFork(m, zext(pidOutPtr))
}

// Proc_fork64 is Proc_fork for a memory64 guest.
func (w *WasiStubs) Proc_fork64(m *Module, pidOutPtr int64) int32 {
	return w.procFork(m, uint64(pidOutPtr))
}

// procFork is the body of Proc_fork and Proc_fork64.
func (w *WasiStubs) procFork(m *Module, pidOutPtr uint64) int32 {
	w.endUnregistered()
	if w.cfg.Fork == nil || m.forkChild == nil {
		return -_wasiENOSYS
	}
	if w.memBytes(m, pidOutPtr, 4) == nil {
		return -_wasiEFAULT
	}
	child, pid, proc := w.forkProc(m)
	made := false
	defer func() {
		// A Forker that failed, or panicked, made no child.
		if !made {
			w.reportError("proc_fork", child.CloseAll())
		}
	}()
	childModule, done, err := w.cfg.Fork.Fork(m, child, pid)
	if err != nil {
		w.reportError("proc_fork", err)
		return -_wasiEAGAIN
	}
	made = true
	w.enterChild(pid, proc)
	exited := w.procExitFunc(proc)
	// The memory has not shrunk since it was checked above.
	binary.LittleEndian.PutUint32(w.memBytes(m, pidOutPtr, 4), uint32(pid))
	go func() {
		status := child.runForkChild(childModule, done)
		child.reportError("proc_fork", child.CloseAll())
		exited(status)
	}()
	return _wasiESUCCESS
}

// runForkChild runs the child of a fork in m, the instance whose host state
// w is, through the module's fork child export, then done (when non-nil),
// and returns the wait status the child ended with (see Proc_fork). A panic
// of done is told WASIConfig.Errors.
func (w *WasiStubs) runForkChild(m *Module, done func(status int32)) (status int32) {
	status = w.forkChildStatus(m)
	if done != nil {
		defer func() {
			if r := recover(); r != nil {
				w.reportError("proc_fork", panicError("the done of a fork", r))
			}
		}()
		done(status)
	}
	return status
}

// forkChildStatus runs the fork child export in m and returns the wait
// status the child ended with.
func (w *WasiStubs) forkChildStatus(m *Module) (status int32) {
	defer func() {
		switch r := recover().(type) {
		case nil:
		case *WasiExitError:
			status = (r.Code & 0xff) << 8
		case *WasiSignalError:
			status = r.Signal & 0x7f
		default:
			w.reportError("proc_fork", panicError("a fork child", r))
			status = wasiSIGABRT
		}
	}()
	return (m.forkChild(m) & 0xff) << 8
}

// panicError is the error of a panic of what with the value r: r itself,
// wrapped, when it is an error.
func panicError(what string, r any) error {
	if err, ok := r.(error); ok {
		return fmt.Errorf("%s panicked: %w", what, err)
	}
	return fmt.Errorf("%s panicked: %v", what, r)
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
// in linear memory. stdinFd, stdoutFd and stderrFd are the guest's
// descriptors the child gets as its standard streams, -1 for the
// instance's own (commandStreamLocked, startCommand). cwdPtr is the
// guest's working directory, a guest path of the FS: the command starts in
// its host path (ExecRequest.Dir), the root of the FS for an empty one, not
// the host process's working directory. The new pid token is written at
// pidOutPtr. Returns 0 or a negative errno.
func (w *WasiStubs) Proc_spawn(m *Module, pathPtr, argvPtr, envpPtr, stdinFd, stdoutFd, stderrFd, cwdPtr, pidOutPtr int32) int32 {
	return w.procSpawn(m, wasiABI32, zext(pathPtr), zext(argvPtr), zext(envpPtr), stdinFd, stdoutFd, stderrFd, zext(cwdPtr), zext(pidOutPtr))
}

// Proc_spawn64 is Proc_spawn for a memory64 guest.
func (w *WasiStubs) Proc_spawn64(m *Module, pathPtr, argvPtr, envpPtr int64, stdinFd, stdoutFd, stderrFd int32, cwdPtr, pidOutPtr int64) int32 {
	return w.procSpawn(m, wasiABI64, uint64(pathPtr), uint64(argvPtr), uint64(envpPtr), stdinFd, stdoutFd, stderrFd, uint64(cwdPtr), uint64(pidOutPtr))
}

// procSpawn is the body of Proc_spawn and Proc_spawn64.
func (w *WasiStubs) procSpawn(m *Module, abi wasiABI, pathPtr, argvPtr, envpPtr uint64, stdinFd, stdoutFd, stderrFd int32, cwdPtr, pidOutPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, pidOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	return w.startGuestCommand(m, abi, pathPtr, argvPtr, envpPtr, cwdPtr, [3]int32{stdinFd, stdoutFd, stderrFd}, false, func(cmd *hostCommand, job commandJob, pids *wasiPIDs, ids ProcessIDs) {
		proc := &wasiProc{host: cmd.process, done: make(chan struct{}), pgid: job.pgid, sid: job.sid, inHostGroup: job.inHostGroup, leads: job.leads}
		w.mu.Lock()
		pid := w.addProcLocked(proc, ids)
		w.enterProcLocked(pid)
		w.mu.Unlock()
		w.reportError("proc_spawn", pids.started(job, proc, cmd.process.Pid))
		go func() {
			if proc.leads {
				if status, reap := w.awaitLeader(pids, proc, cmd); reap != nil {
					w.finishProc(proc, status)
					reap()
					return
				}
			}
			w.finishProc(proc, cmd.wait())
		}()
		binary.LittleEndian.PutUint32(out, uint32(pid))
	})
}

// startGuestCommand starts the command the guest asks Proc_spawn or
// Proc_exec for: path, argv, envp and cwdPtr are as Proc_spawn takes them,
// fds the guest's descriptors of its standard streams, -1 for the
// instance's. The command is started where commandJob puts it, as the
// process of the guest when execs is set, and started is then called with
// it, while the family's command starts are held (wasiPIDs.starts).
// Returns 0, or a negative errno: the command has not started.
func (w *WasiStubs) startGuestCommand(m *Module, abi wasiABI, pathPtr, argvPtr, envpPtr, cwdPtr uint64, fds [3]int32, execs bool, started func(cmd *hostCommand, job commandJob, pids *wasiPIDs, ids ProcessIDs)) int32 {
	op := "proc_spawn"
	if execs {
		op = "proc_exec"
	}
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

	w.mu.Lock()
	streams := [3]commandStream{
		w.commandStreamLocked(fds[0], 1),
		w.commandStreamLocked(fds[1], 2),
		w.commandStreamLocked(fds[2], 3),
	}
	share := w.streamsLocked()
	inherit := w.inheritedLocked()
	w.mu.Unlock()
	inherit = append(inherit, w.inheritedOutside()...)
	slices.SortFunc(inherit, func(a, b commandDescriptor) int { return cmp.Compare(a.at, b.at) })
	req, errno := w.commandRequest(op, path, argv, env, cwd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	// The command's stdin that the guest reads through a reader is copied
	// from that reader: the stream has one goroutine that reads it.
	if s := &streams[0]; s.reader != nil {
		in := s.op
		if in == nil {
			in = &wasiOpen{stdio: 1}
		}
		if in.readsStream(s.reader) && !w.netpolled(in, s.reader) && !in.inputPolled(s.reader) {
			s.input = w.inputReader(in, s.reader)
		}
	}
	// A process that has been killed, while the Exec hook ran too, starts
	// nothing more.
	w.endIfStopped()
	w.enterRoot()
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	pids.starts.Lock()
	defer pids.starts.Unlock()
	job := pids.commandJob(ids.PID, execs)
	var cmd *hostCommand
	var startErr error
	start := func() {
		cmd, startErr = w.startCommand(op, req.Path, req.Argv, req.Env, req.Dir, job.host, &streams, inherit, share)
	}
	// The command inherits the umask of the thread that starts it: this
	// one where the instance's mask is the host process's, the instance's
	// creation thread otherwise.
	switch {
	case !hostThreadUmask:
		start()
	case withHostUmask(w.guestUmask(), start):
	default:
		if t := w.creationThread(); t == nil || t.run(start) != nil {
			start()
		}
	}
	if startErr != nil {
		w.reportError(op, pids.started(job, nil, 0))
		return -w.guestErrno(op, startErr)
	}
	started(cmd, job, pids, ids)
	return _wasiESUCCESS
}

// defaultCommandPath is the PATH a command name is looked up in when the
// environment the guest gives the command has none: musl's (execvp.c).
const defaultCommandPath = "/usr/local/bin:/bin:/usr/bin"

// commandRequest returns what the command the guest asks op to start runs,
// once the Exec policy allows it: file is the executable the guest names
// (looked up by lookCommand when it has no "/"), argv and env the
// command's, and cwd the guest's working directory, which a relative name
// is taken from. The executable and the directory are the host's absolute
// paths of their names in the FS (HostRootFS). It returns a wasi errno: EACCES
// without a policy or when it refuses, ENOSYS when the FS is no
// HostRootFS, guestName's and the lookup's.
func (w *WasiStubs) commandRequest(op, file string, argv, env []string, cwd string) (ExecRequest, int32) {
	w.mu.Lock()
	hook := w.cfg.Exec
	fsys, isHost := w.fs().(HostRootFS)
	w.mu.Unlock()
	switch {
	case hook == nil:
		return ExecRequest{}, _wasiEACCES
	case !isHost:
		return ExecRequest{}, _wasiENOSYS
	}
	if len(argv) == 0 {
		argv = []string{file}
	}
	// Sandbox: the child sees ONLY the guest-provided environment; a nil
	// (NULL envp) must NOT fall through to the host process environment.
	if env == nil {
		env = []string{}
	}
	dir, errno := w.guestName(cwd)
	if errno != _wasiESUCCESS {
		return ExecRequest{}, errno
	}
	var name string
	if strings.Contains(file, "/") {
		name, errno = w.guestName(guestPathFrom(cwd, file))
	} else {
		name, errno = w.lookCommand(op, file, env, cwd)
	}
	if errno != _wasiESUCCESS {
		return ExecRequest{}, errno
	}
	// A relative HostRoot is taken from the host process's working
	// directory as it is now.
	root, err := filepath.Abs(fsys.HostRoot())
	if err != nil {
		return ExecRequest{}, w.guestErrno(op, err)
	}
	req := ExecRequest{Path: hostPathIn(root, name), Argv: argv, Env: env, Dir: hostPathIn(root, dir)}
	if !hook(req) {
		return ExecRequest{}, _wasiEACCES
	}
	return req, _wasiESUCCESS
}

// guestPathFrom returns the guest path name, taken from the directory cwd
// when relative.
func guestPathFrom(cwd, name string) string {
	if path.IsAbs(name) {
		return name
	}
	return cwd + "/" + name // not path.Join: guestName resolves ".." after symbolic links
}

// lookCommand returns the name in the FS of the executable the name file
// (one without a "/") names, as musl's __execvpe looks it up: in each
// directory of the PATH of env in turn (defaultCommandPath without one; an
// empty directory is the working directory cwd), the first that is a
// command the guest may run (commandRunnable). One it may not run (EACCES)
// is remembered and the lookup goes on, as it does past one that does not
// exist (ENOENT, ENOTDIR); any other errno ends it. It reports EACCES when
// the lookup found only ones the guest may not run, ENOENT when it found
// none.
func (w *WasiStubs) lookCommand(op, file string, env []string, cwd string) (string, int32) {
	dirs := defaultCommandPath
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			dirs = v
			break
		}
	}
	refused := false
	// not filepath.SplitList: it splits by the host's separator, and gives
	// no directory for an empty PATH, which is the working directory
	for _, dir := range strings.Split(dirs, ":") {
		candidate := file
		if dir != "" {
			candidate = dir + "/" + file
		}
		name, errno := w.commandRunnable(op, guestPathFrom(cwd, candidate))
		switch errno {
		case _wasiESUCCESS:
			return name, _wasiESUCCESS
		case _wasiEACCES:
			refused = true
		case _wasiENOENT, _wasiENOTDIR:
		default:
			return "", errno
		}
	}
	if refused {
		return "", _wasiEACCES
	}
	return "", _wasiENOENT
}

// commandRunnable returns the name in the FS of the guest path raw and
// whether it is a command the guest may run, as execve(2) decides: 0 for a
// regular file it may execute (Path_access with X_OK, for its effective
// ids), EACCES for any other file, or the errno of finding it.
func (w *WasiStubs) commandRunnable(op, raw string) (string, int32) {
	name, errno := w.guestName(raw)
	if errno != _wasiESUCCESS {
		return "", errno
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	fi, err := fsys.Stat(name)
	switch {
	case err != nil:
		return "", w.guestErrno(op, err)
	case !fi.Mode().IsRegular():
		return "", _wasiEACCES
	}
	return name, w.accessName(op, name, nil, wasiAccessExec, true)
}

// awaitLeader waits for the end of cmd, the command of proc, which leads
// the host's process group of its group, without reaping it
// (hostWaitExited), and tells the family (leaderEnded): the command's pid
// is the number of the host's group until the reap. When the group has
// other members, it delivers what the runtime copies from the command
// (hostCommand.finish) and returns the command's wait status and reap,
// which keeps the command unreaped until they are gone and then reaps it.
// Otherwise the family has dropped the host's group and reap is nil: the
// caller waits for the command as for any other.
func (w *WasiStubs) awaitLeader(pids *wasiPIDs, proc *wasiProc, cmd *hostCommand) (status int32, reap func()) {
	status, err := hostWaitExited(cmd.process.Pid)
	if err != nil {
		w.reportError("proc_wait", err)
	}
	held := pids.leaderEnded(proc, err == nil)
	if held == nil {
		return 0, nil
	}
	cmd.finish()
	return status, func() {
		<-held
		if _, err := cmd.process.Wait(); err != nil {
			w.reportError("proc_wait", err)
		}
	}
}

// Proc_exec is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_exec") backing execve and the exec family: the guest becomes
// the command path, with the arguments argv, the environment envp and the
// working directory at cwdPtr, as Proc_spawn starts one, and with the
// guest's descriptors 0, 1 and 2 as its standard streams. A process image
// cannot be replaced, so the exec is emulated, as Cygwin's spawn.cc does
// for _P_OVERLAY: once the command has started, the process keeps its pid
// and is the command's — a signal for it (PostSignal, Proc_kill), one
// pending for the process or the exec'ing thread that this thread does not
// block, and a SIGKILL that arrived while the command started, are the
// command's — the
// guest's descriptors are closed, and the call waits for the command and
// what the runtime copies from it, and ends the guest the way the command
// ended, as Proc_exit or Proc_terminate end it. The command is put where
// the process's group and session are (commandJob), and the process cannot
// be moved into another group from the start on (Proc_setpgid). Returns
// only when the command could not be started: a negative errno, as
// Proc_spawn's.
func (w *WasiStubs) Proc_exec(m *Module, pathPtr, argvPtr, envpPtr, cwdPtr int32) int32 {
	return w.procExec(m, wasiABI32, zext(pathPtr), zext(argvPtr), zext(envpPtr), zext(cwdPtr))
}

// Proc_exec64 is Proc_exec for a memory64 guest.
func (w *WasiStubs) Proc_exec64(m *Module, pathPtr, argvPtr, envpPtr, cwdPtr int64) int32 {
	return w.procExec(m, wasiABI64, uint64(pathPtr), uint64(argvPtr), uint64(envpPtr), uint64(cwdPtr))
}

// execedCommand is the command a guest has become (Proc_exec): process is
// its process, and done is closed once the exec has waited for it and for
// what the runtime copies from it (KillCommands).
type execedCommand struct {
	process *commandProcess
	done    chan struct{}
}

// procExec is the body of Proc_exec and Proc_exec64.
func (w *WasiStubs) procExec(m *Module, abi wasiABI, pathPtr, argvPtr, envpPtr, cwdPtr uint64) int32 {
	w.endUnregistered()
	var (
		cmd    *hostCommand
		self   *wasiProc
		pids   *wasiPIDs
		execed *execedCommand
	)
	if rc := w.startGuestCommand(m, abi, pathPtr, argvPtr, envpPtr, cwdPtr, [3]int32{0, 1, 2}, true, func(c *hostCommand, job commandJob, p *wasiPIDs, _ ProcessIDs) {
		cmd, self, pids = c, job.self, p
		w.reportError("proc_exec", pids.started(job, self, cmd.process.Pid))
		execed = w.becomeCommand(m, cmd.process)
	}); rc != _wasiESUCCESS {
		return rc
	}
	w.reportExecDispositions()
	w.reportError("proc_exec", w.closeFrom(0))
	if self != nil && self.leads {
		if status, reap := w.awaitLeader(pids, self, cmd); reap != nil {
			go reap()
			w.endAs(m, execed, status)
		}
	}
	w.endAs(m, execed, cmd.wait())
	return _wasiESUCCESS
}

// becomeCommand makes the process of the instance the command process,
// which the guest's thread whose module m is has become (Proc_exec):
// signals for the process are the command's from now on (signalProcess),
// and so are the signals pending for the process or for that thread that
// the thread does not block, and SIGKILL when the end of the instance has
// been asked for (requestStopLocked) while the command started. The command
// is given no mask: the pending signals the thread blocks are dropped. A
// failure to send one is told WASIConfig.Errors.
func (w *WasiStubs) becomeCommand(m *Module, process *commandProcess) *execedCommand {
	execed := &execedCommand{process: process, done: make(chan struct{})}
	s := &w.sig
	t := w.lockSignalThread(m)
	s.execed = execed
	pending := s.deliverable(t)
	s.pending &^= pending
	t.pending &^= pending
	if s.stop.Load() != nil {
		pending |= wasiSignalBit(wasiSIGKILL)
	}
	w.unlockSignals()
	for ; pending != 0; pending &= pending - 1 {
		w.reportError("proc_exec", signalHostProc(process, int32(bits.TrailingZeros64(pending))+1))
	}
	return execed
}

// reportExecDispositions tells WASIConfig.Signals the dispositions of the
// process once the guest has become a command (Proc_exec), as the guest
// tells its own (Proc_signal_dispositions): a signal that reaches the
// process now goes to the command (signalProcess), so every signal is
// handled, for one who relays the host process's signals to send it on,
// but those whose default action is to do nothing and those the guest
// ignores, which stay ignored across execve(2). No signal is blocked.
func (w *WasiStubs) reportExecDispositions() {
	if w.cfg.Signals == nil {
		return
	}
	w.dispositionsMu.Lock()
	defer w.dispositionsMu.Unlock()
	w.sig.mu.Lock()
	ignored := w.sig.ignored
	w.sig.mu.Unlock()
	uncatchable := wasiSignalBit(wasiSIGKILL) | wasiSignalBit(wasiSIGSTOP)
	handled := ^uint64(0) &^ wasiDefaultIgnoredSignals &^ ignored &^ uncatchable
	w.cfg.Signals.Dispositions(w, handled, ignored, 0)
}

// endAs ends the guest, which has become the command execed (Proc_exec),
// the way a process of the wait status status ended: killed by its signal
// (terminate), or exiting with its code (Proc_exit). It does not return.
func (w *WasiStubs) endAs(m *Module, execed *execedCommand, status int32) {
	w.sig.mu.Lock()
	w.sig.execed = nil
	w.sig.mu.Unlock()
	close(execed.done)
	if sig := status & 0x7f; sig != 0 {
		w.terminate(sig)
	}
	w.Proc_exit(m, status>>8&0xff)
}

// signalProcess delivers sig to the process of the instance, as kill(2)
// does: to the guest (postSignalLocked), or, once the guest has become a
// command (Proc_exec), to the command (signalHostProc), whose error it
// returns. It reports whether the process still takes signals: false once
// delivery to the guest has ended.
func (w *WasiStubs) signalProcess(sig int32) (takes bool, err error) {
	w.sig.mu.Lock()
	if execed := w.sig.execed; execed != nil {
		w.sig.mu.Unlock()
		return true, signalHostProc(execed.process, sig)
	}
	defer w.unlockSignals()
	return w.postSignalLocked(sig), nil
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
	if _, adopted := w.adopted[fd]; adopted {
		// The slot is the host's descriptor taken in from outside the
		// guest (adoptHostLocked), whose mark is the host's.
		old, err := hostCloseOnExecMark(int(fd), set != 0, value != 0)
		if err != nil {
			return -w.errnoLater("fd_cloexec", err)
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

// commandStream is a standard stream of a command Proc_spawn starts, as the
// guest's descriptor for it resolves (commandStreamLocked): a descriptor
// of the host (host), which the command is given its own open file
// description of or shares (startCommand); a stream the runtime copies to
// or from (reader for the stdin, writer for the stdout and stderr); or
// none of them, the null device.
type commandStream struct {
	host   syscall.Conn
	reader io.Reader
	writer io.Writer
	// input is the reader (streamReader) the copy of reader takes the
	// command's stdin from, when the guest's reads of it go through one.
	input *streamReader
	// socket marks a host descriptor that is a socket, which the runtime
	// copies to or from: its open file description stays in the
	// non-blocking mode the runtime uses it in.
	socket bool
	// nonblock is the guest's O_NONBLOCK of the descriptor, which an open
	// file description of the command's own gets.
	nonblock bool
	// op is the guest's entry of the stream, nil for the instance's stream
	// the guest names with -1.
	op *wasiOpen
	// stdio is the instance's standard stream (1/2/3, as wasiOpen.stdio)
	// the stream is, 0 for none.
	stdio int8
}

// commandDescriptor is a descriptor of the guest's above its standard
// streams that a command inherits, under the number at: the host's
// descriptor behind conn, or, for conn nil, the host's descriptor at that
// number itself (inheritedOutside).
type commandDescriptor struct {
	at   int32
	conn syscall.Conn
}

// inheritedLocked returns the descriptors above 2 a command of the guest
// inherits where the instance is of a family whose descriptors are the
// host's (hostFamily), as exec(2) passes them: the slots that are not
// close-on-exec, the guest's mark for one the runtime made or was given,
// the host's own for one taken in from outside the guest (adoptHostLocked).
// Elsewhere a command gets its standard streams only. Caller holds w.mu.
func (w *WasiStubs) inheritedLocked() []commandDescriptor {
	if !w.hostFamily() {
		return nil
	}
	var out []commandDescriptor
	for _, fd := range slices.Sorted(maps.Keys(w.fdsLocked())) {
		if fd <= 2 || !w.currentLocked(fd) {
			continue
		}
		op := w.fdTable[fd]
		conn := w.entryHostConnLocked(op)
		if conn == nil {
			continue
		}
		if _, adopted := w.adopted[fd]; adopted && hostCloseOnExec(int(fd)) || !adopted && w.cloexec[fd] {
			continue
		}
		// The command shares the open file description (netpolled).
		op.shared.Store(true)
		out = append(out, commandDescriptor{at: fd, conn: conn})
	}
	return out
}

// commandStreamLocked resolves the descriptor fd the guest gives a command
// as its standard stream slot (1 for the stdin, 2 for the stdout, 3 for
// the stderr). A negative fd asks for the instance's stream. Any other fd
// is resolved through the fd table like a read (slot 1) or a write of it:
// the standard stream, file, pipe end or socket it refers to, and none —
// the null device — when the fd is closed or not open that way. A socket
// is the host's socket (wasiSocket), or the connection of package net's
// that has a descriptor of the host; any other socket stands for the
// instance's stream. Caller holds w.mu.
func (w *WasiStubs) commandStreamLocked(fd int32, slot int8) commandStream {
	var stream any
	var op *wasiOpen
	switch {
	case fd < 0:
	case slot == 1:
		stream, op = w.fdSrcLocked(fd)
	default:
		stream, op = w.fdDstLocked(fd)
	}
	if host := op.hostSocket(); host != nil {
		return commandStream{host: host, socket: true, op: op}
	}
	if host, isHost := stream.(syscall.Conn); isHost && op.socket() {
		return commandStream{host: host, socket: true, op: op}
	}
	if fd < 0 || op.socket() {
		stream, op = [...]any{w.stdin(), w.stdout(), w.stderr()}[slot-1], nil
	}
	s := commandStream{op: op, stdio: slot}
	if op != nil {
		s.nonblock, s.stdio = op.nonblocking(), op.stdio
	}
	switch file, isFile := stream.(*os.File); {
	case isFile:
		s.host = file
	case stream == nil:
	case slot == 1:
		s.reader = stream.(io.Reader)
	default:
		s.writer = stream.(io.Writer)
	}
	return s
}

// Pipe is a NON-STANDARD host import (module wasi_snapshot_preview1, name
// "pipe") that a guest's pipe()/pipe2() can call. It creates a host OS pipe
// and registers both ends as guest fds, writing [readFd, writeFd] (two i32)
// at fdsOutPtr. The guest reads the read end via Fd_read; the write end is
// given to a child as its stdout/stderr via Proc_spawn, so the guest can
// capture the child's output. Returns 0 or a negative errno.
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
	var r, wr *os.File
	if err := makeRuntimeDescriptors(func() error {
		var err error
		if r, wr, err = os.Pipe(); err != nil {
			return err
		}
		if r, err = w.guestFile(r, false); err != nil {
			return errors.Join(err, wr.Close())
		}
		if wr, err = w.guestFile(wr, false); err != nil {
			return errors.Join(err, r.Close())
		}
		return nil
	}); err != nil {
		return -w.guestErrno("pipe", err)
	}
	rPolled, rErr := filePolled(r)
	wPolled, wErr := filePolled(wr)
	if err := errors.Join(rErr, wErr); err != nil {
		return -w.guestErrno("pipe", errors.Join(err, r.Close(), wr.Close()))
	}
	w.mu.Lock()
	rfd, errno := w.addFDLocked(&wasiOpen{f: r, noWrite: true, polled: rPolled})
	if errno != _wasiESUCCESS {
		w.mu.Unlock()
		w.reportError("pipe", wr.Close())
		return -errno
	}
	wfd, errno := w.addFDLocked(&wasiOpen{f: wr, noRead: true, polled: wPolled})
	if errno != _wasiESUCCESS {
		closing, err := w.clearSlotLocked(rfd)
		w.mu.Unlock()
		w.reportError("pipe", errors.Join(err, closeWasiOpen(closing)))
		return -errno
	}
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
// negative errno: ECHILD for an unknown pid — and, when the guest ignores
// SIGCHLD, once the process has finished — EINTR when a signal was posted
// to the guest before the process finished.
func (w *WasiStubs) Proc_wait(m *Module, pid, options, statusOutPtr int32) int32 {
	return w.procWait(m, pid, options, zext(statusOutPtr))
}

// Proc_wait64 is Proc_wait for a memory64 guest.
func (w *WasiStubs) Proc_wait64(m *Module, pid, options int32, statusOutPtr int64) int32 {
	return w.procWait(m, pid, options, uint64(statusOutPtr))
}

// procWait is the body of Proc_wait and Proc_wait64.
func (w *WasiStubs) procWait(m *Module, pid, options int32, statusOutPtr uint64) int32 {
	w.endUnregistered()
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
	} else if !w.awaitInterruptibly(m, proc.done) {
		return -_wasiEINTR
	}
	w.mu.Lock()
	if w.procs[pid] != proc {
		// Another waiter was given the process while this one waited.
		w.mu.Unlock()
		return -_wasiECHILD
	}
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

// Proc_wait_any is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_wait_any") backing wait() and
// waitpid(-1): it waits for ANY process of this instance — spawned by
// Proc_spawn or run by the embedder (NewProc) — to finish, removes it from
// the process table, and writes its pid token at pidOutPtr and its POSIX
// wait status at statusOutPtr. When several have finished, the one with the
// lowest pid is reported. options is the waitpid() options mask; with bit 0
// (WNOHANG) the call does not block. Returns 0, or a negative errno: ECHILD
// when the instance has no process at all, EAGAIN when WNOHANG is set and
// none of them has finished yet, EINTR when a signal was posted to the guest
// before one finished.
func (w *WasiStubs) Proc_wait_any(m *Module, options, pidOutPtr, statusOutPtr int32) int32 {
	return w.procWaitAny(m, 0, options, zext(pidOutPtr), zext(statusOutPtr))
}

// Proc_wait_any64 is Proc_wait_any for a memory64 guest.
func (w *WasiStubs) Proc_wait_any64(m *Module, options int32, pidOutPtr, statusOutPtr int64) int32 {
	return w.procWaitAny(m, 0, options, uint64(pidOutPtr), uint64(statusOutPtr))
}

// Proc_wait_group is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_wait_group") backing waitpid(-pgid)
// and waitpid(0): it is Proc_wait_any for the processes of this instance
// whose process group is pgid, the group as Proc_getpgid and Proc_setpgid
// number it. pgid must be positive: for waitpid(0) the guest passes its own
// group (Proc_getpgid of pid 0). Returns 0, or a negative errno: EINVAL for
// a pgid that is not positive, ECHILD when the instance has no process in
// the group, and the others as Proc_wait_any.
func (w *WasiStubs) Proc_wait_group(m *Module, pgid, options, pidOutPtr, statusOutPtr int32) int32 {
	return w.procWaitGroup(m, pgid, options, zext(pidOutPtr), zext(statusOutPtr))
}

// Proc_wait_group64 is Proc_wait_group for a memory64 guest.
func (w *WasiStubs) Proc_wait_group64(m *Module, pgid, options int32, pidOutPtr, statusOutPtr int64) int32 {
	return w.procWaitGroup(m, pgid, options, uint64(pidOutPtr), uint64(statusOutPtr))
}

// procWaitGroup is the body of Proc_wait_group and Proc_wait_group64.
func (w *WasiStubs) procWaitGroup(m *Module, pgid, options int32, pidOutPtr, statusOutPtr uint64) int32 {
	if pgid <= 0 {
		w.endUnregistered()
		return -_wasiEINVAL
	}
	return w.procWaitAny(m, pgid, options, pidOutPtr, statusOutPtr)
}

// procWaitAny is the body of Proc_wait_any and Proc_wait_any64, which pass
// pgid 0 to wait for any process of the instance, and of procWaitGroup,
// which passes the process group whose processes it waits for.
func (w *WasiStubs) procWaitAny(m *Module, pgid, options int32, pidOutPtr, statusOutPtr uint64) int32 {
	w.endUnregistered()
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
		var (
			pid     int32
			proc    *wasiProc
			members bool
			pids    *wasiPIDs
		)
		if pgid != 0 {
			// The group of a process is guarded by the family's lock.
			pids = w.pidsLocked()
			pids.mu.Lock()
		}
		for p, pr := range w.procs {
			if pids != nil && pr.pgid != pgid {
				continue
			}
			members = true
			select {
			case <-pr.done:
				if proc == nil || p < pid {
					pid, proc = p, pr
				}
			default:
			}
		}
		if pids != nil {
			pids.mu.Unlock()
		}
		if !members {
			w.mu.Unlock()
			return -_wasiECHILD
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
		if !w.awaitInterruptibly(m, finished) {
			return -_wasiEINTR
		}
	}
}

// awaitInterruptibly blocks the guest until done is closed. It reports false
// when a signal posted to the guest ended the wait first; the caller then
// returns EINTR. An event that has already happened is never reported as
// interrupted. A wait that a signal ended for another blocking call of the
// guest (endBlocking) goes on.
func (w *WasiStubs) awaitInterruptibly(m *Module, done <-chan struct{}) bool {
	for {
		select {
		case <-done:
			return true
		default:
		}
		posted := make(chan struct{})
		key, ok := w.beginBlocking(m, func() { close(posted) })
		if !ok {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}
		select {
		case <-done:
		case <-posted:
		}
		interrupted := w.endBlocking(key)
		select {
		case <-done:
			return true
		default:
		}
		if interrupted {
			return false
		}
	}
}

// Proc_kill is a NON-STANDARD host import (name "proc_kill") backing kill().
// sig is the guest's signal number (Linux numbering); 0 only probes that the
// process exists. pid names, as for kill(2):
//
//   - The guest itself: the pid of its Process (getpid), which in a copy
//     made by ForkProc is the pid token its parent was given. The signal is
//     posted to the guest as raise does (Proc_raise). A copy made by Fork
//     shares the root instance's Process, and so its pid, which names the
//     copy itself there; ForkProc gives a copy a pid of its own.
//
//   - A process of the fork family, by its pid: a child or grandchild, a
//     sibling, the parent of a copy made by ForkProc (getppid), and the
//     root instance by the pid of its Process, from an instance whose pid
//     that is not. (Waiting stays limited to the caller's own children.)
//     The root's pid names nothing once the root is gone. A host process
//     (Proc_spawn) receives the signal through the OS, under the number the
//     host has for it (SIGKILL as os.Process.Kill does); an embedder-run
//     process (NewProc) through the kill function the embedder registered,
//     without which it cannot be signalled (EPERM); an instance of the
//     family by PostSignal. A process that has finished but has not been
//     waited for is a zombie: signalling it succeeds and does nothing. A pid
//     token of a process that is gone names nothing (ESRCH); it is never
//     passed on.
//
//   - A process group of the family (Proc_getpgid): pid 0 for the guest's
//     own, minus its id for any. Each process of the family in it is
//     signalled as above, the guest last, but the commands in the host's
//     process group of the group (commandJob), which are signalled through
//     that group of the host's, with the processes they started in it.
//     Minus the pid of a process of the family that leads no group names
//     none (ESRCH).
//
//   - Every process the guest may signal: pid -1, which is the family but
//     the guest itself (also when the pid of the Process is 1).
//
//   - Any other pid is outside the family: it is passed, with sig, to the
//     Kill of WASIConfig.Signals, whose error is the errno. With no Signals
//     the pid names nothing.
//
// Returns 0, or a negative errno: ESRCH for a pid that names no process,
// EINVAL for a number that is no signal (see isWasiSignalNumber) or, for a
// host process, one the host has no signal for, and the error of the
// delivery otherwise. A group is signalled when one of its processes is;
// otherwise the error is the last process's.
func (w *WasiStubs) Proc_kill(m *Module, pid, sig int32) int32 {
	w.endUnregistered()
	if !isWasiSignalNumber(sig) {
		return -_wasiEINVAL
	}
	w.enterRoot()
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	own, _ := pids.jobOf(ids.PID)
	// -1 first: it is no process group, even where the group's id is 1.
	switch pid {
	case -1:
		rc, _ := w.killGroup(m, sig, 0, false)
		return rc
	case 0:
		rc, _ := w.killGroup(m, sig, own, true)
		return rc
	}
	if pid < -1 {
		if rc, found := w.killGroup(m, sig, -pid, -pid == own); found {
			return rc
		}
		if _, ours := pids.find(-pid); ours {
			// A process of the family that leads no group.
			return -_wasiESRCH
		}
	}
	if pid == ids.PID {
		// The guest's own pid is always the guest itself.
		if !w.takeSignal(sig) {
			w.raiseOwn(m, sig, false)
		}
		return _wasiESUCCESS
	}
	proc, ours := pids.find(pid)
	switch {
	case proc != nil:
		return w.killFamilyProc(proc, sig)
	case ours:
		// A process of the family that is gone: one that has been waited
		// for, or the root instance.
		return -_wasiESRCH
	case w.cfg.Signals == nil:
		return -_wasiESRCH
	}
	return -w.guestErrno("proc_kill", w.cfg.Signals.Kill(pid, sig))
}

// killGroup signals the processes of the family's process group pgid, or,
// for pgid 0, every process of the fork family, but the guest itself, and
// with self the guest too, last, from its thread whose module m is
// (groupMembers). It returns 0 when one was signalled, and otherwise the
// error of the last one, ESRCH when there is none, and whether the group has
// a process.
func (w *WasiStubs) killGroup(m *Module, sig, pgid int32, self bool) (int32, bool) {
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	members, found, sent, err := pids.groupMembers(pgid, sig)
	rc := -_wasiESRCH
	if sent {
		rc = -w.guestErrno("proc_kill", err)
	}
	for _, proc := range members {
		if proc.instance == w {
			continue
		}
		if r := w.killFamilyProc(proc, sig); rc != _wasiESUCCESS {
			rc = r
		}
	}
	if self {
		w.raiseOwn(m, sig, false)
		return _wasiESUCCESS, true
	}
	return rc, found
}

// groupMembers returns the processes of the family's process group pgid,
// every process of the family for pgid 0, and whether there is one. The
// commands of a group in the host's process group of it (inHostGroup) are
// left out: sig is sent to that group of the host's here (killHostGroup),
// under p.mu, so that its number is never another's (leaderEnded); sent
// reports that it was, and err is the error of the sending, which the
// caller turns into an errno once p.mu is let go.
func (p *wasiPIDs) groupMembers(pgid, sig int32) (members []*wasiProc, found, sent bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.groups[pgid]
	whole := pgid != 0 && g != nil && pgid != p.hostGroup
	for _, proc := range p.procs {
		if pgid != 0 && proc.pgid != pgid {
			continue
		}
		found = true
		if !whole || !proc.inHostGroup {
			members = append(members, proc)
		}
	}
	if whole && found {
		sent, err = true, killHostGroup(g.host, sig)
	}
	return members, found, sent, err
}

// killFamilyProc delivers sig to a process of the fork family; see
// Proc_kill.
func (w *WasiStubs) killFamilyProc(proc *wasiProc, sig int32) int32 {
	select {
	case <-proc.done:
		return _wasiESUCCESS
	default:
	}
	switch {
	case proc.instance != nil:
		takes, err := proc.instance.signalProcess(sig)
		if !takes && !proc.instance.forked {
			// The root instance's guest has ended; nobody waits for it.
			// A copy made by ForkProc that has ended is a zombie until
			// its exited is called.
			return -_wasiESRCH
		}
		return -w.guestErrno("proc_kill", err)
	case sig == 0:
		return _wasiESUCCESS
	case proc.host != nil:
		return w.killHostProc(proc.host, sig)
	case proc.kill == nil:
		return -_wasiEPERM
	}
	return -w.guestErrno("proc_kill", proc.kill(sig))
}

// killHostProc delivers sig to a host process started by Proc_spawn.
// SIGKILL is the process's Kill, which every platform has; another signal
// is the host's signal for it (hostSignalOf).
func (w *WasiStubs) killHostProc(p *commandProcess, sig int32) int32 {
	return -w.guestErrno("proc_kill", signalHostProc(p, sig))
}

// signalHostProc is killHostProc returning the error: EINVAL for a signal
// the host has none for.
func signalHostProc(p *commandProcess, sig int32) error {
	var err error
	if sig == wasiSIGKILL {
		err = p.Kill()
	} else {
		hostSig, known := hostSignalOf(sig)
		if !known {
			return syscall.EINVAL
		}
		err = p.Signal(hostSig)
	}
	if errors.Is(err, os.ErrProcessDone) {
		// It finished after the probe of done.
		return nil
	}
	return err
}

// Proc_kill64 is Proc_kill for a memory64 guest.
func (w *WasiStubs) Proc_kill64(m *Module, pid, sig int32) int32 {
	return w.Proc_kill(m, pid, sig)
}

// hostCommand is a command startCommand started on the host: process is
// its process, and wait waits for it to end and for what the runtime copies
// from it to be delivered, and returns its wait status as the guest gets it.
// finish delivers what the runtime copies from it once it has ended, the
// part of wait after the reap, for a command known to have ended before it
// is reaped (awaitHeldLeader); it is nil where no command is (no job
// control on the host, hostJobControl).
type hostCommand struct {
	process *commandProcess
	wait    func() int32
	finish  func()
}

// waitStatusOf returns the wait status of a command whose wait returned st
// and err: that of st (encodeWaitStatus), or a 127 exit when the wait
// itself failed, whose error is told WASIConfig.Errors (op "proc_spawn"). A
// command that exits with a status other than 0, or is killed, is no
// failure of the wait (exec.ExitError).
func (w *WasiStubs) waitStatusOf(st *os.ProcessState, err error) int32 {
	if exitErr := (*exec.ExitError)(nil); err != nil && !errors.As(err, &exitErr) {
		w.reportError("proc_spawn", err)
		return 127 << 8
	}
	return encodeWaitStatus(st)
}

// Process groups and sessions (job control). The family keeps them
// (wasiPIDs): every process of the family is in a group and a session,
// those of the process that made it, and a process the guest starts on the
// host is put in a group and a session of the host's for them
// (commandJob). The root instance starts in the group its ProcessChanges
// tells (Pgid) and in the host process's session, and its guest's changes
// of its own are the ProcessChanges's (the host process's, with
// HostProcessChanges); without one, and for every other process, they are
// the family's.

// Proc_getpgid is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_getpgid") backing getpgid and getpgrp:
// the process group of the process pid names is written at outPtr (u32).
// pid 0 names the guest, a pid of the family its process (Proc_kill), and
// any other a process outside the family, whose group the ProcessChanges
// tells (Pgid). Returns 0, or a negative errno: ESRCH for a pid that names
// no process, any outside the family without a ProcessChanges.
func (w *WasiStubs) Proc_getpgid(m *Module, pid, outPtr int32) int32 {
	return w.procGetpgid(m, pid, zext(outPtr))
}

// Proc_getpgid64 is Proc_getpgid for a memory64 guest.
func (w *WasiStubs) Proc_getpgid64(m *Module, pid int32, outPtr int64) int32 {
	return w.procGetpgid(m, pid, uint64(outPtr))
}

// procGetpgid is the body of Proc_getpgid and Proc_getpgid64.
func (w *WasiStubs) procGetpgid(m *Module, pid int32, outPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.enterRoot()
	if pid == 0 {
		pid = w.guestPID()
	}
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	pgid, found, ours := pids.groupOf(pid)
	switch {
	case found:
	case ours, pid < 0, w.cfg.ProcessChanges == nil:
		return -_wasiESRCH
	default:
		var err error
		if pgid, err = w.cfg.ProcessChanges.Pgid(pid); err != nil {
			return -w.guestErrno("proc_getpgid", err)
		}
	}
	binary.LittleEndian.PutUint32(out, uint32(pgid))
	return _wasiESUCCESS
}

// groupOf returns the process group of the family's process pid and
// whether there is one, and whether pid is the family's (find).
func (p *wasiPIDs) groupOf(pid int32) (pgid int32, found, ours bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	proc, ours := p.findLocked(pid)
	if proc == nil {
		return 0, false, ours
	}
	return proc.pgid, true, ours
}

// Proc_setpgid is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_setpgid") backing setpgid: the
// process pid names — 0 or its own pid for the guest, or a child of the
// guest's — is moved into the process group pgid, 0 for the one of its own
// pid, as Linux's setpgid does (kernel/sys.c). The group must be one of the
// guest's session, and the process one that has not started a program
// (a child the guest spawned or the embedder runs has) and leads no
// session. The root instance's guest moves itself by its ProcessChanges
// (Setpgid), into a group of the family only when the host process can be
// in it: the host process's own, or a group of the host's of the family's
// (commandJob). Returns 0, or a negative errno: EINVAL for a negative
// pgid, ESRCH for a pid that names neither the guest nor a child of its,
// EACCES for a child that has started a program, EPERM for a process of
// another session, one that leads a session, or a group the process
// cannot join, and the ProcessChanges's error.
func (w *WasiStubs) Proc_setpgid(m *Module, pid, pgid int32) int32 {
	w.endUnregistered()
	if pgid < 0 {
		return -_wasiEINVAL
	}
	w.enterRoot()
	self := w.guestPID()
	if pid == 0 {
		pid = self
	}
	if pgid == 0 {
		pgid = pid
	}
	w.mu.Lock()
	pids := w.pidsLocked()
	_, child := w.procs[pid]
	w.mu.Unlock()
	switch {
	case pid != self && !child:
		return -_wasiESRCH
	case pid == self && !w.forked && w.cfg.ProcessChanges != nil:
		return w.setHostPgid(pids, pid, pgid)
	}
	return -pids.setpgid(self, pid, pgid)
}

// Proc_setpgid64 is Proc_setpgid for a memory64 guest.
func (w *WasiStubs) Proc_setpgid64(m *Module, pid, pgid int32) int32 {
	return w.Proc_setpgid(m, pid, pgid)
}

// setpgid moves the family's process pid into the group pgid for its
// caller (Proc_setpgid) and returns 0 or the errno.
func (p *wasiPIDs) setpgid(caller, pid, pgid int32) int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	by, proc := p.procs[caller], p.procs[pid]
	switch {
	case by == nil || proc == nil:
		return _wasiESRCH
	case pid != caller && proc.sid != by.sid:
		return _wasiEPERM
	case pid != caller && (proc.instance == nil || proc.execed):
		return _wasiEACCES
	case proc.sid == pid, pgid != pid && !p.hasGroupLocked(pgid, by.sid):
		return _wasiEPERM
	}
	was := proc.pgid
	proc.pgid = pgid
	p.leftGroupLocked(was)
	return _wasiESUCCESS
}

// setHostPgid moves the root instance's guest, whose pid is pid, into the
// process group pgid by its ProcessChanges (Proc_setpgid), and returns 0
// or a negative errno.
func (w *WasiStubs) setHostPgid(pids *wasiPIDs, pid, pgid int32) int32 {
	to, ok := pids.hostGroupOf(pgid, pid)
	if !ok {
		return -_wasiEPERM
	}
	if err := w.cfg.ProcessChanges.Setpgid(0, to); err != nil {
		return -w.guestErrno("proc_setpgid", err)
	}
	pids.hostMoved(pid, pgid, -1)
	return _wasiESUCCESS
}

// hostGroupOf returns the host's process group the host process, whose
// guest's pid is pid, is moved into for the group pgid (setpgid(2)'s
// argument): 0, a new one, for pid's own, the group the host process is in
// for that one, the host's group of a family's group that has one
// (commandJob), and the group itself for one that is not the family's; ok
// is false for a group of the family the host process cannot be in.
func (p *wasiPIDs) hostGroupOf(pgid, pid int32) (hostPgid int32, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch g := p.groups[pgid]; {
	case pgid == pid:
		return 0, true
	case pgid == p.hostGroup:
		return pgid, true
	case g != nil:
		return int32(g.host), true
	}
	for _, proc := range p.procs {
		if proc.pgid == pgid {
			return 0, false
		}
	}
	return pgid, true
}

// hostMoved is told that the host process, whose guest's pid is pid, has
// moved into the group pgid and, unless sid is -1, the session sid: they
// are the guest's and the host process's from now on.
func (p *wasiPIDs) hostMoved(pid, pgid, sid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hostGroup = pgid
	if sid != -1 {
		p.hostSession = sid
	}
	if proc := p.procs[pid]; proc != nil {
		was := proc.pgid
		proc.pgid = pgid
		if sid != -1 {
			proc.sid = sid
		}
		p.leftGroupLocked(was)
	}
}

// Proc_setsid is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_setsid") backing setsid: the guest
// leads a new session and a new process group, both of the id of its pid,
// which is written at outPtr (u32). The root instance's guest does so by
// its ProcessChanges (Setsid). Returns 0, or a negative errno: EPERM when a
// process group of that id is there (the guest leads one), and the
// ProcessChanges's error.
func (w *WasiStubs) Proc_setsid(m *Module, outPtr int32) int32 {
	return w.procSetsid(m, zext(outPtr))
}

// Proc_setsid64 is Proc_setsid for a memory64 guest.
func (w *WasiStubs) Proc_setsid64(m *Module, outPtr int64) int32 {
	return w.procSetsid(m, uint64(outPtr))
}

// procSetsid is the body of Proc_setsid and Proc_setsid64.
func (w *WasiStubs) procSetsid(m *Module, outPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, outPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	w.enterRoot()
	self := w.guestPID()
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	sid := self
	if !w.forked && w.cfg.ProcessChanges != nil {
		var err error
		if sid, err = w.cfg.ProcessChanges.Setsid(); err != nil {
			return -w.guestErrno("proc_setsid", err)
		}
		pids.hostMoved(self, sid, sid)
	} else if errno := pids.setsid(self); errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(out, uint32(sid))
	return _wasiESUCCESS
}

// setsid makes the family's process pid lead a new session and process
// group of its pid (Proc_setsid) and returns 0 or the errno.
func (p *wasiPIDs) setsid(pid int32) int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	proc := p.procs[pid]
	if proc == nil {
		return _wasiESRCH
	}
	for _, other := range p.procs {
		if other.pgid == pid {
			return _wasiEPERM
		}
	}
	was := proc.pgid
	proc.pgid, proc.sid = pid, pid
	p.leftGroupLocked(was)
	return _wasiESUCCESS
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
// process. A signal the guest has no number for (guestSignalOf) keeps the
// host's number. On Linux that is the guest's number for it too; on another
// system it is only the host's, and it may be the guest's number of another
// signal (a limitation: the guest has no number for such a signal).
func encodeHostWaitStatus(ws syscall.WaitStatus) int32 {
	if ws.Signaled() {
		if sig := guestSignalOf(ws.Signal()); sig != 0 {
			return sig
		}
		return int32(ws.Signal()) & 0x7f
	}
	return int32(ws.ExitStatus()&0xff) << 8
}

// Sock_getaddrinfo is a NON-STANDARD host import (module
// wasip1_posix_extension, and wasi_snapshot_preview1 as well:
// wasiReleasedPosixImports; name "sock_getaddrinfo") that a guest's
// getaddrinfo() can call. It reads the host string at (nodePtr,nodeLen),
// resolves it to its first IPv4 address as Sock_resolve does (resolveHost),
// and writes the 4-byte network-order address at outPtr. An empty host is
// INADDR_ANY. Returns 0 on success or a negative
// POSIX-ish errno (the caller maps it to an EAI_* code): EACCES when the
// Resolve policy refuses, ENOENT for a name without an IPv4 address,
// EAFNOSUPPORT for an IPv6 address written in numbers, EAGAIN when the
// lookup may succeed later, EINTR when a signal ends it.
func (w *WasiStubs) Sock_getaddrinfo(m *Module, nodePtr, nodeLen, outPtr int32) int32 {
	return w.sockGetaddrinfo(m, zext(nodePtr), nodeLen, zext(outPtr))
}

// Sock_getaddrinfo64 is Sock_getaddrinfo for a memory64 guest.
func (w *WasiStubs) Sock_getaddrinfo64(m *Module, nodePtr int64, nodeLen int32, outPtr int64) int32 {
	return w.sockGetaddrinfo(m, uint64(nodePtr), nodeLen, uint64(outPtr))
}

// sockGetaddrinfo is the body of Sock_getaddrinfo and Sock_getaddrinfo64.
func (w *WasiStubs) sockGetaddrinfo(m *Module, nodePtr uint64, nodeLen int32, outPtr uint64) int32 {
	w.endUnregistered()
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
	if a, err := netip.ParseAddr(host); err == nil && !a.Unmap().Is4() {
		return -_wasiEAFNOSUPPORT // IPv6 not supported by this import
	}
	found, errno := w.resolveHost(m, host, "ip4")
	if errno != _wasiESUCCESS {
		return -errno
	}
	if len(found) == 0 {
		return -_wasiENOENT
	}
	if !found[0].Is4() {
		return -_wasiEAFNOSUPPORT
	}
	v4 := found[0].As4()
	copy(out, v4[:])
	return _wasiESUCCESS
}

// familyHosts is what the lookups of the instances of a fork family gave:
// for each address in text (wasiSockAddr.ipText), the set of names it was
// given for. A connect to an address asks the Dial policy with those names
// (dialAllowed).
type familyHosts struct {
	mu    sync.Mutex
	names map[string]map[string]bool
}

// hostsLocked returns the family's familyHosts, made on first use. Caller
// holds w.mu.
func (w *WasiStubs) hostsLocked() *familyHosts {
	if w.hosts == nil {
		w.hosts = &familyHosts{}
	}
	return w.hosts
}

// recordResolvedHost remembers that a lookup of host gave ip, an address
// in text (wasiSockAddr.ipText), for the family's connects to it.
func (w *WasiStubs) recordResolvedHost(ip, host string) {
	w.mu.Lock()
	hosts := w.hostsLocked()
	w.mu.Unlock()
	hosts.mu.Lock()
	defer hosts.mu.Unlock()
	if hosts.names == nil {
		hosts.names = make(map[string]map[string]bool)
	}
	if hosts.names[ip] == nil {
		hosts.names[ip] = make(map[string]bool)
	}
	hosts.names[ip][host] = true
}

// dialAllowed asks the Dial policy about a connect on network to the
// address ip (in text) and port: once with each name the family's lookups
// gave ip for, in sorted order, until one allows, or once with the host ""
// when they gave it for none. nil denies.
func (w *WasiStubs) dialAllowed(network, ip string, port int) bool {
	w.mu.Lock()
	hook := w.cfg.Dial
	hosts := w.hostsLocked()
	w.mu.Unlock()
	if hook == nil {
		return false
	}
	hosts.mu.Lock()
	names := slices.Sorted(maps.Keys(hosts.names[ip]))
	hosts.mu.Unlock()
	if len(names) == 0 {
		return hook(network, "", ip, port)
	}
	for _, host := range names {
		if hook(network, host, ip, port) {
			return true
		}
	}
	return false
}

// guestLookup is the operation, of every path import, of looking up the
// names guestName resolves a ".." by, for WASIConfig.Errors.
const guestLookup = "path lookup"

// guestMaxSymlinks is how many symbolic links guestName follows in one
// name: Linux's MAXSYMLINKS (include/linux/namei.h), as the guest's errno
// numbers are Linux's.
const guestMaxSymlinks = 40

// guestName returns the name the FS is given for the guest path raw, which
// is relative to the root: the one name of FS's doc, which fs.ValidPath
// accepts once a trailing "/" is taken off. Empty and "." elements go; a
// trailing "/", "/." or "/.." becomes one trailing "/", which asks for a
// directory (a call that changes the name looks at its last element first:
// guestLast).
// ".." is resolved as os.Root's doInRoot and the system's namei resolve
// it: ".." of the root is the root, and any other takes back the element
// before it, once that is known to be a directory and not a symbolic link,
// whose target is put in its place (from the root for an absolute one).
// Only those elements are looked up (guestLstat), so a name without ".."
// is not. It returns a wasi errno: that of the lookup (ENOENT, EACCES,
// ...), ENOTDIR for an element before ".." that is no
// directory, ELOOP past guestMaxSymlinks links. Callers must NOT hold w.mu.
func (w *WasiStubs) guestName(raw string) (string, int32) {
	elems := func(name string) []string {
		return slices.DeleteFunc(strings.Split(name, "/"), func(e string) bool { return e == "" || e == "." })
	}
	parts := elems(raw)
	dir := strings.HasSuffix(raw, "/") || path.Base(raw) == "." || path.Base(raw) == ".."
	links := 0
	for i := 0; i < len(parts); {
		switch {
		case parts[i] != "..":
			i++
			continue
		case i == 0:
			parts = parts[1:]
			continue
		}
		isDir, target, link, errno := w.guestLstat(strings.Join(parts[:i], "/"))
		switch {
		case errno != _wasiESUCCESS:
			return "", errno
		case link && target == "":
			return "", _wasiENOENT
		case link:
			if links++; links > guestMaxSymlinks {
				return "", _wasiELOOP
			}
			before := parts[:i-1]
			if path.IsAbs(target) {
				before = nil
			}
			parts, i = slices.Concat(before, elems(target), parts[i:]), 0
		case !isDir:
			return "", _wasiENOTDIR
		default:
			parts, i = slices.Delete(parts, i-1, i+1), i-1
		}
	}
	switch {
	case len(parts) == 0:
		return ".", _wasiESUCCESS
	case dir:
		return strings.Join(parts, "/") + "/", _wasiESUCCESS
	}
	return strings.Join(parts, "/"), _wasiESUCCESS
}

// atDir returns the entry of dirFd, the directory descriptor of a path call,
// whose names are relative to it: nil for the preopened root, whose names
// are the FS's own. errno: EBADF for a dirFd that is not open, ENOTDIR for
// one that is no directory, as openat(2) has them.
func (w *WasiStubs) atDir(dirFd int32) (*wasiOpen, int32) {
	if w.preopened(dirFd) {
		return nil, _wasiESUCCESS
	}
	w.mu.Lock()
	op := w.openLocked(dirFd)
	w.mu.Unlock()
	switch {
	case op == nil:
		return nil, _wasiEBADF
	case !op.isDir:
		return nil, _wasiENOTDIR
	}
	return op, _wasiESUCCESS
}

// atPath returns the guest path that raw, a path relative to from (atDir),
// names: raw itself for the preopened root and for an absolute raw, which
// openat(2) takes from the root, and for another directory the path it was
// opened under followed by raw, as wazero's atPath has it (not path.Join,
// which would fold a ".." that guestName resolves after links). An empty
// raw relative to another directory names nothing (ENOENT), as for
// openat(2); the preopened root's is raw itself, which guestName makes
// the root.
func atPath(from *wasiOpen, raw string) (string, int32) {
	switch {
	case from == nil || path.IsAbs(raw):
		return raw, _wasiESUCCESS
	case raw == "":
		return "", _wasiENOENT
	}
	return guestPath(from.path) + "/" + raw, _wasiESUCCESS
}

// atName returns from's directory as an FS (wasiOpen.root) and the name in
// it that raw, relative to from (atDir), is: for a directory that has one,
// and a relative raw that names something in it without a ".." element,
// whose resolution starts above it. ok is false otherwise, and the name is
// found by atPath's path. The caller has found raw is no name of the
// guest's own descriptors.
func atName(from *wasiOpen, raw string) (root FS, name string, ok bool) {
	if from == nil || from.root == nil || path.IsAbs(raw) {
		return nil, "", false
	}
	// not path.Clean, which would fold the ".." that leaves the directory
	elems := slices.DeleteFunc(strings.Split(raw, "/"), func(e string) bool { return e == "" || e == "." })
	switch {
	case slices.Contains(elems, ".."):
		return nil, "", false
	case len(elems) == 0:
		return from.root, ".", true // the directory itself
	}
	name = strings.Join(elems, "/")
	if strings.HasSuffix(raw, "/") || path.Base(raw) == "." {
		name += "/"
	}
	return from.root, name, true
}

// atFS returns the FS a path call gives its name to, and that name, for
// raw, relative to from (atDir), whose name in the instance's FS is name:
// from's directory and the name in it where atName finds one, the
// instance's FS and name otherwise. Callers must NOT hold w.mu.
func (w *WasiStubs) atFS(from *wasiOpen, raw, name string) (FS, string) {
	if root, rel, ok := atName(from, raw); ok {
		return root, rel
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fs(), name
}

// atFS2 is atFS for the two names of a rename or a link: one directory's
// when both are relative to it and found in it, the instance's FS's
// otherwise.
func (w *WasiStubs) atFS2(oldFrom *wasiOpen, oldRaw, oldName string, newFrom *wasiOpen, newRaw, newName string) (FS, string, string) {
	if oldFrom == newFrom {
		root, a, ok := atName(oldFrom, oldRaw)
		if _, b, bok := atName(newFrom, newRaw); ok && bok {
			return root, a, b
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fs(), oldName, newName
}

// The kinds of the last element of a guest path, Linux's last_type (LAST_NORM,
// LAST_DOT, LAST_DOTDOT), which a call that makes, removes or renames the
// name refuses but the first of.
const (
	lastName = iota
	lastDot
	lastDotDot
)

// guestLast returns the kind of the last element of the guest path raw. A
// path of "." elements alone is the root, which the guest's C library
// names so: an ordinary name.
func guestLast(raw string) int {
	parts := slices.DeleteFunc(strings.Split(raw, "/"), func(e string) bool { return e == "" })
	switch {
	case !slices.ContainsFunc(parts, func(e string) bool { return e != "." }):
		return lastName
	case parts[len(parts)-1] == ".":
		return lastDot
	case parts[len(parts)-1] == "..":
		return lastDotDot
	}
	return lastName
}

// guestDirectory returns 0 when name, a name guestName gave, leads to a
// directory, and the errno of looking it up, or ENOTDIR, otherwise.
func (w *WasiStubs) guestDirectory(name string) int32 {
	dir, _, _, errno := w.guestLstat(name)
	switch {
	case errno != _wasiESUCCESS:
		return errno
	case !dir:
		return _wasiENOTDIR
	}
	return _wasiESUCCESS
}

// guestLstat tells what name, a name of guestName's form that a ".."
// follows, is without following it: a directory, or a symbolic link and
// its target. A directory that lists the guest's own descriptors is a
// directory; a descriptor's name is, as on Linux, a link that leads to the
// descriptor itself and not to its target: ENOTDIR for one that is no
// directory's, ENOTSUP for a directory's, from which no name is resolved
// (ownDescriptorLocked). errno is a wasi errno.
func (w *WasiStubs) guestLstat(name string) (dir bool, target string, link bool, errno int32) {
	switch n, rest, named, listing := ownDescriptorPath(name, w.guestPID); {
	case listing != "":
		return true, "", false, _wasiESUCCESS
	case named:
		w.mu.Lock()
		op, root, errno := w.ownDescriptorLocked(n, rest)
		w.mu.Unlock()
		switch {
		case errno != _wasiESUCCESS:
			return false, "", false, errno
		case root || op.isDir:
			return false, "", false, _wasiENOTSUP
		}
		return false, "", false, _wasiENOTDIR
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	fi, err := fsys.Lstat(name)
	if err != nil {
		return false, "", false, w.guestErrno(guestLookup, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return fi.IsDir(), "", false, _wasiESUCCESS
	}
	if target, err = fsys.Readlink(name); err != nil {
		return false, "", false, w.guestErrno(guestLookup, err)
	}
	return false, target, true, _wasiESUCCESS
}

// checkNet consults the network policy hook; without one every operation
// is denied. Returns true when the operation is permitted. Callers must
// NOT hold w.mu.
func (w *WasiStubs) checkNet(op string) bool {
	hook := w.cfg.NetAccess
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
	_wasiEINPROGRESS  int32 = 26
	_wasiEINTR        int32 = 27
	_wasiENAMETOOLONG int32 = 37
	_wasiENETUNREACH  int32 = 40
	_wasiEINVAL       int32 = 28
	_wasiEIO          int32 = 29
	_wasiEISDIR       int32 = 31
	_wasiELOOP        int32 = 32
	_wasiEMFILE       int32 = 33
	_wasiENOENT       int32 = 44
	_wasiENOLCK       int32 = 46
	_wasiENOMEM       int32 = 48
	_wasiENOSPC       int32 = 51
	_wasiENOTCONN     int32 = 53
	_wasiENOTDIR      int32 = 54
	_wasiENOTEMPTY    int32 = 55
	_wasiENOTSOCK     int32 = 57
	_wasiENOTSUP      int32 = 58
	_wasiENOTTY       int32 = 59
	_wasiENOSYS       int32 = 52
	_wasiENXIO        int32 = 60
	_wasiEOVERFLOW    int32 = 61
	_wasiEPERM        int32 = 63
	_wasiEPIPE        int32 = 64
	_wasiERANGE       int32 = 68
	_wasiESPIPE       int32 = 70
	_wasiESRCH        int32 = 71
	_wasiETIMEDOUT    int32 = 73
	_wasiEXDEV        int32 = 75
)

// guestErrno returns the wasi errno of err, the failure of the operation op
// (the import's name, or the name of the operation that imports share):
// wasiErrnoOf's. An error it has no errno for is EIO, and told
// WASIConfig.Errors.
func (w *WasiStubs) guestErrno(op string, err error) int32 {
	errno, known := wasiErrnoOf(err)
	if !known {
		w.reportError(op, err)
	}
	return errno
}

// wasiErrnoOf returns the wasi errno of err, and whether there is one: that
// of the syscall.Errno it carries (wrapped or not) when wasi has the error,
// otherwise that of the kind of error the standard library tells it is
// (fs.ErrNotExist, errors.ErrUnsupported, a net.Error's Timeout,
// exec.ErrNotFound and the like). EIO for any other error.
func wasiErrnoOf(err error) (int32, bool) {
	if err == nil {
		return _wasiESUCCESS, true
	}
	// The error number of the system call that failed says exactly which
	// error it is; what follows tells only the kinds package os knows
	// apart.
	var number syscall.Errno
	if errors.As(err, &number) {
		if wasi, ok := wasiErrno(number); ok {
			return wasi, true
		}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return _wasiENOENT, true
	case errors.Is(err, syscall.ENOTEMPTY):
		// before fs.ErrExist, which ENOTEMPTY is as well
		return _wasiENOTEMPTY, true
	case errors.Is(err, fs.ErrExist):
		return _wasiEEXIST, true
	case errors.Is(err, syscall.EPERM):
		// before fs.ErrPermission, which stands for EACCES as well
		return _wasiEPERM, true
	case errors.Is(err, fs.ErrPermission):
		return _wasiEACCES, true
	case errors.Is(err, syscall.ESRCH):
		return _wasiESRCH, true
	case errors.Is(err, syscall.ENOTDIR):
		return _wasiENOTDIR, true
	case errors.Is(err, syscall.EISDIR):
		return _wasiEISDIR, true
	case errors.Is(err, syscall.EINVAL), errors.Is(err, fs.ErrInvalid):
		return _wasiEINVAL, true
	case errors.Is(err, syscall.EBADF), errors.Is(err, fs.ErrClosed), errors.Is(err, net.ErrClosed):
		return _wasiEBADF, true
	case errors.Is(err, syscall.ENOSPC):
		return _wasiENOSPC, true
	case errors.Is(err, syscall.EFBIG):
		return _wasiEFBIG, true
	case errors.Is(err, syscall.EAGAIN):
		return _wasiEAGAIN, true
	case errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrClosedPipe):
		return _wasiEPIPE, true
	case errors.Is(err, syscall.ENXIO):
		return _wasiENXIO, true
	case errors.Is(err, syscall.ESPIPE):
		return _wasiESPIPE, true
	case errors.Is(err, syscall.ENOSYS):
		// before errors.ErrUnsupported, which ENOSYS is as well
		return _wasiENOSYS, true
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
		// before errors.ErrUnsupported, which they are as well
		return _wasiENOTSUP, true
	case errors.Is(err, errors.ErrUnsupported):
		// what the value or the host does not implement
		return _wasiENOSYS, true
	}
	if timeout := net.Error(nil); errors.As(err, &timeout) && timeout.Timeout() {
		return _wasiETIMEDOUT, true
	}
	return _wasiEIO, false
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
		return uint64(time.Since(w.monoStart).Nanoseconds()), _wasiESUCCESS
	default:
		return 0, _wasiEINVAL
	}
}

// closeWasiOpens closes the descriptors of ops (closeWasiOpen), which have
// left the table, and joins the errors.
func closeWasiOpens(ops []*wasiOpen) error {
	var err error
	for _, op := range ops {
		err = errors.Join(err, closeWasiOpen(op))
	}
	return err
}

// closeWasiOpen releases every underlying handle held by op and
// joins any Close errors so callers can map them to a wasi errno
// instead of silently dropping the failure. The caller has cleared op's
// last slot (clearSlotLocked), and does not hold w.mu: a close of a
// descriptor of the host's waits for the calls that use it meanwhile.
func closeWasiOpen(op *wasiOpen) error {
	op.mu.Lock()
	f, conn, listener, root := op.f, op.conn, op.listener, op.root
	var host *os.File
	if op.sock != nil {
		host = op.sock.host
	}
	locked := op.lockedFile
	op.lockedFile = nil
	op.mu.Unlock()
	var err error
	if f != nil {
		err = errors.Join(err, f.Close())
	}
	if root != nil {
		err = errors.Join(err, root.Close())
	}
	if host != nil {
		err = errors.Join(err, host.Close())
	}
	if conn != nil && op.connClosed.CompareAndSwap(false, true) {
		err = errors.Join(err, conn.Close())
	}
	if listener != nil && op.connClosed.CompareAndSwap(false, true) {
		err = errors.Join(err, listener.Close())
	}
	if locked != nil {
		err = errors.Join(err, releaseLockedFile(locked, true))
	}
	// The waits in poll(2) for the descriptor are woken once it is closed:
	// one woken before could wait again on the open descriptor, and
	// nothing would end that wait. Woken now, it finds the descriptor
	// closed.
	op.mu.Lock()
	err = errors.Join(err, op.wakeWaitersLocked())
	reader := op.reader
	op.mu.Unlock()
	if reader != nil {
		reader.stop()
	}
	return err
}

// wakeWaitersLocked ends the waits in poll(2) for the entry's descriptor
// (addWaiter). Caller holds op.mu.
func (op *wasiOpen) wakeWaitersLocked() error {
	var err error
	for wk := range op.waiters {
		err = errors.Join(err, wk.wake())
	}
	return err
}

func (w *WasiStubs) Fd_close(m *Module, fd int32) int32 {
	w.mu.Lock()
	if w.openLocked(fd) == nil {
		w.mu.Unlock()
		return _wasiEBADF
	}
	closing, err := w.clearSlotLocked(fd)
	w.mu.Unlock()
	err = errors.Join(err, w.resyncReleased())
	if closing != nil {
		err = errors.Join(err, closeWasiOpen(closing))
	}
	if err != nil {
		return w.guestErrno("fd_close", err)
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
		} else if op.dgram {
			ftype = 5 // socket_dgram
		} else if op.conn != nil || op.listener != nil || op.isSocket {
			ftype = 6 // socket_stream
		}
		fdflags = uint16(op.fdflags)
		op.mu.Unlock()
		if file := w.opHostFileLocked(op); file != nil {
			terminal, err := op.terminalOf(file)
			if err != nil {
				return w.errnoLater("fd_fdstat_get", err)
			}
			if terminal {
				// What tells a terminal from another character device
				// to wasi-libc's isatty: it cannot be sought on.
				ftype = 2
				rights &^= wasiRightFdSeek | wasiRightFdTell
			}
		}
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
	wasiRightFdSeek    uint64 = 1 << 2
	wasiRightFdTell    uint64 = 1 << 5
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
// only the cache update: a socket of the host's is in non-blocking mode from
// its making on (see the head of the socket section), and Go's net layer
// manages the blocking mode of its connections and listeners internally.
func (w *WasiStubs) Fd_fdstat_set_flags(m *Module, fd, flags int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return _wasiEBADF
	}
	// Where the guest's mode is the description's (hostFamily), NONBLOCK is
	// set on the description of a descriptor of the guest's own, which code
	// outside the guest shares (one of the process's 0–2 the instance whose
	// numbers are the host's has is the process's own, as a fcntl of a
	// program's is); the entry is then waited for in poll(2), as one whose
	// mode is no longer the one the Go runtime's poller took (shared). An
	// embedder's stream keeps its mode.
	if w.hostFamily() && op.stdio == 0 {
		w.mu.Lock()
		conn := w.entryHostConnLocked(op)
		w.mu.Unlock()
		if f, ok := conn.(*os.File); ok {
			op.shared.Store(true)
			if err := setHostNonblock(f, flags&wasiFdflagNonblock != 0); err != nil {
				return w.guestErrno("fd_fdstat_set_flags", err)
			}
		}
	}
	op.mu.Lock()
	op.fdflags = flags
	op.mu.Unlock()
	// Elsewhere the call is accepted and changes no description, so that
	// wasi-libc callers (which typically set NONBLOCK before a poll loop)
	// still progress without surfacing a spurious error.
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
			return w.guestErrno("fd_filestat_get", err)
		}
		writeFilestat(out, st)
		return _wasiESUCCESS
	}
	if op.f == nil {
		fi, err := w.streamFileInfo(op)
		if err != nil {
			return w.guestErrno("fd_filestat_get", err)
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
		// A socket is a datagram (5) or stream socket (6). An embedder's
		// stream is a pipe to the guest, which WASI has no file type for:
		// it stays "unknown" (0) here, and Fd_filestat_ext names it.
		switch {
		case op.socket() && op.dgram:
			out[16] = 5
		case op.socket():
			out[16] = 6
		}
		return _wasiESUCCESS
	}
	st, err := op.f.Stat()
	if err != nil {
		return w.guestErrno("fd_filestat_get", err)
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
		return w.guestErrno("fd_filestat_set_size", err)
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
	name := op.path
	var current os.FileInfo
	if filetimesNeedCurrent(fstFlags) {
		st, err := op.f.Stat()
		if err != nil {
			return w.guestErrno("fd_filestat_set_times", err)
		}
		current = st
	}
	atime, mtime := resolveFiletimes(uint64(atim), uint64(mtim), fstFlags, current)
	// A file that sets its own times, and a host file where the host can
	// (hostFutimens), is changed through the descriptor; any other by its
	// path.
	if f, ok := op.f.(ChtimesFile); ok {
		return w.guestErrno("fd_filestat_set_times", f.Chtimes(atime, mtime))
	}
	if f, ok := op.f.(*os.File); ok {
		if err := hostFutimens(fsys, f, atime, mtime); !errors.Is(err, errors.ErrUnsupported) {
			return w.guestErrno("fd_filestat_set_times", err)
		}
	}
	if err := fsys.Chtimes(name, atime, mtime); err != nil {
		return w.guestErrno("fd_filestat_set_times", err)
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
	w.endUnregistered()
	w.mu.Lock()
	src, op := w.fdSrcLocked(fd)
	w.mu.Unlock()
	host := op.hostSocket()
	if src == nil && host == nil {
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
	if host != nil {
		// a socket of the host's, read as recv(2) reads it
		n, _, errno := w.socketReceive(m, "fd_read", op, host, bufs, 0)
		abi.putWord(nreadSlice, n)
		return errno
	}
	n, errno, served := w.takeAhead("fd_read", op, bufs)
	if !served {
		if op.readsStream(src) {
			n, errno = w.readStream(m, "fd_read", op, src, bufs)
		} else {
			n, errno = w.readVec("fd_read", src, bufs, op.regular)
		}
	}
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
func (w *WasiStubs) readVec(call string, src io.Reader, bufs [][]byte, whole bool) (uint64, int32) {
	var total uint64
	for _, buf := range bufs {
		n, err := src.Read(buf)
		total += uint64(n)
		if err != nil && total == 0 && !errors.Is(err, io.EOF) {
			return 0, w.guestErrno(call, err)
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
func (w *WasiStubs) writeVec(call string, dst io.Writer, bufs [][]byte) (uint64, int32) {
	var total uint64
	for _, buf := range bufs {
		n, err := dst.Write(buf)
		total += uint64(n)
		if err != nil && total == 0 {
			return 0, w.guestErrno(call, err)
		}
		if err != nil {
			break
		}
	}
	return total, _wasiESUCCESS
}

// writeFd writes bufs to dst, the destination of the entry op, the way
// write(2) does: a stream takes what it has room for (see
// writePolledStream, writeHostStream), anything else takes all of it. A
// write that transferred nothing reports why; one that transferred
// something reports the count, and the failure meets the guest's next
// write. flags are those of the write to a stream (wasiMsg...).
func (w *WasiStubs) writeFd(m *Module, call string, op *wasiOpen, dst io.Writer, bufs [][]byte, flags int32) (uint64, int32) {
	if stream, blocks := op.writeBlocks(dst); blocks {
		if w.netpolled(op, stream) {
			return w.writePolledStream(m, call, op, stream, bufs, flags)
		}
		return w.writeHostStream(m, call, op, stream, bufs, flags)
	}
	return w.writeVec(call, dst, bufs)
}

// The flags of one write to a stream: what the MSG_ flags of send(2) ask
// for, in the host's own numbering (libc's numbers differ from libc to
// libc).
const (
	wasiMsgDontWait int32 = 4 // this call does not wait, whatever O_NONBLOCK says
	wasiMsgNoSignal int32 = 8 // a broken pipe or connection is EPIPE without SIGPIPE
)

// signalBrokenPipe returns errno, the outcome of a write or send with flags
// (wasiMsg...) by the thread whose module m is. A write to a pipe or socket
// nobody reads from any more is EPIPE, and the kernel sends the writing
// thread SIGPIPE as well unless the send asked for none (wasiMsgNoSignal):
// the guest's own call raises it for the thread, as raise(3) does (Linux's
// send_sig(SIGPIPE, current)).
func (w *WasiStubs) signalBrokenPipe(m *Module, errno, flags int32) int32 {
	if errno == _wasiEPIPE && flags&wasiMsgNoSignal == 0 && !w.takeSignal(wasiSIGPIPE) {
		w.raiseOwn(m, wasiSIGPIPE, true)
	}
	return errno
}

// writePolledStream writes bufs to dst, a stream of the entry op that the
// Go runtime polls (netpolled), as the guest asked for it. flags are those
// of the write (wasiMsg...). A write that does not wait — O_NONBLOCK, or
// wasiMsgDontWait whatever O_NONBLOCK says — is one writev(2) (writeNow),
// which takes what there is room for and reports EAGAIN when that is
// nothing; to a standard stream of the embedder's, which can change the
// mode of its description, it is writeHostStream's, which asks the mode
// first. A write that waits is writeInterruptibly's; what there is room
// for when a signal ends its wait is written all the same, as write(2)
// takes it from a process with a signal pending.
func (w *WasiStubs) writePolledStream(m *Module, call string, op *wasiOpen, dst streamWriter, bufs [][]byte, flags int32) (uint64, int32) {
	now := func() (uint64, int32) {
		if op.stdio != 0 {
			return w.writeHostStream(m, call, op, dst, bufs, flags|wasiMsgDontWait)
		}
		return w.writeNow(call, dst, bufs)
	}
	if op.nonblocking() || flags&wasiMsgDontWait != 0 {
		return now()
	}
	n, errno := w.writeInterruptibly(m, call, op, dst, bufs)
	if errno == _wasiEINTR {
		if n, errno := now(); errno != _wasiEAGAIN {
			w.keepInterrupt(m)
			return n, errno
		}
	}
	return n, errno
}

// writeNow writes bufs to dst with one writev(2) in its Control
// (tryStream), which does not wait in a descriptor in non-blocking mode:
// EAGAIN when nothing fits. One writev(2) takes the buffers as one write: a
// datagram is one message.
func (w *WasiStubs) writeNow(call string, dst syscall.Conn, bufs [][]byte) (uint64, int32) {
	n, again, errno := w.tryStream(call, dst, func(fd uintptr) (int, bool, error) { return writevRaw(fd, bufs) })
	if errno == _wasiESUCCESS && again {
		return 0, _wasiEAGAIN
	}
	return uint64(n), errno
}

// writeInterruptibly writes all of bufs to dst, a stream of the entry op
// that the Go runtime polls, waiting for room in its poller. It takes the
// turn at the stream's output before it writes anything and holds it until
// all is written, so that two writes that wait do not mix, as Go's
// internal/poll FD.Write holds its write lock; only the holder of the turn
// sets the deadline that bounds the wait. A signal posted to the guest
// meanwhile ends the wait, with EINTR when nothing was written yet and the
// count otherwise (the next call that waits then reports the signal).
func (w *WasiStubs) writeInterruptibly(m *Module, call string, op *wasiOpen, dst streamWriter, bufs [][]byte) (uint64, int32) {
	rc, err := dst.SyscallConn()
	if err != nil {
		return 0, w.guestErrno(call, err)
	}
	if !w.awaitOutputTurn(m, op) {
		return 0, _wasiEINTR
	}
	defer op.passOutputTurn()
	// A deadline left now was left by a holder that was unwound.
	if err := dst.SetWriteDeadline(time.Time{}); err != nil {
		return 0, w.guestErrno(call, deadlineErr(dst, err))
	}
	var total uint64
	var failure error
	cutShort := false
	// One writev(2) takes the buffers as one write: a datagram is one
	// message.
	rest := append([][]byte(nil), bufs...)
	for len(firstBuffer(rest)) > 0 {
		var n int
		var again bool
		var writeErr, waitErr error
		// wake sets a deadline, which must not outlive the attempt. A
		// stream closed meanwhile refuses it, as it may have refused
		// wake's: the closing is what the write failed of.
		var wakeErr error
		clearDeadline := func() error { return errors.Join(wakeErr, dst.SetWriteDeadline(time.Time{})) }
		interrupted, woken, refused := w.blockingAttempt(m,
			func() { wakeErr = dst.SetWriteDeadline(time.Now()) },
			func() { w.reportError(call, clearDeadline()) },
			func(<-chan struct{}) {
				waitErr = rc.Write(func(fd uintptr) bool {
					n, again, writeErr = writevRaw(fd, rest)
					// The write waits for room and tries again.
					return !again
				})
			})
		if refused {
			cutShort = true
			break
		}
		if woken {
			failure = deadlineErr(dst, clearDeadline())
		}
		if errors.Is(waitErr, os.ErrDeadlineExceeded) && failure == nil {
			if interrupted {
				cutShort = true
				break
			}
			if !woken {
				// Only the holder of the turn sets a deadline, so this one
				// is not the stream's any more: it was left behind.
				if err := dst.SetWriteDeadline(time.Time{}); err != nil {
					failure = deadlineErr(dst, err)
					break
				}
			}
			// Woken by a signal another blocking call reports: the write
			// waits on.
			continue
		}
		if interrupted {
			// The write went through: the next call that waits reports
			// the signal.
			w.keepInterrupt(m)
		}
		if waitErr != nil && failure == nil {
			failure = rawCallErr(rc, waitErr)
		}
		if failure != nil {
			break
		}
		total += uint64(n)
		for n > 0 {
			c := min(n, len(rest[0]))
			rest[0], n = rest[0][c:], n-c
			if len(rest[0]) == 0 {
				rest = rest[1:]
			}
		}
		if writeErr != nil {
			failure = writeErr
			break
		}
	}
	switch {
	case total > 0:
		if cutShort {
			// Cut short by a signal: the next call that waits reports it.
			w.keepInterrupt(m)
		}
		return total, _wasiESUCCESS
	case failure != nil:
		return 0, w.guestErrno(call, failure)
	case cutShort:
		return 0, _wasiEINTR
	}
	return 0, _wasiESUCCESS
}

// writeHostStream writes bufs to dst, a descriptor of the host's whose
// write can block (writeBlocks) and the destination of the entry op, that
// the Go runtime does not poll for the entry (netpolled), as the guest
// asked for it, one writev(2) at a time in the descriptor's Control
// (tryStream): one writev(2) takes the buffers as one write, and a datagram
// is one message. flags are those of the write (wasiMsg...).
//
// A write that does not wait — O_NONBLOCK, or wasiMsgDontWait whatever
// O_NONBLOCK says — takes what there is room for right now and reports
// EAGAIN when that is nothing, without the turn at the stream's output.
//
// A write that waits takes that turn before it writes anything and holds it
// until all is written, as writeInterruptibly does. Where the host has a
// write that does not wait in one call (hostWritesWithoutWaiting), it
// writes in steps that do not wait in the kernel whatever the mode of the
// open file description (writeWithoutWaiting), and waits for room in poll(2)
// between them: a signal posted to the guest meanwhile ends the wait, with
// EINTR when nothing was written and the count otherwise; what there is
// room for then is written all the same, as write(2) takes it from a
// process with a signal pending. Elsewhere (darwin) each writev(2) is one,
// which to a descriptor in blocking mode waits in the kernel until all is
// written, and a signal does not end it.
func (w *WasiStubs) writeHostStream(m *Module, call string, op *wasiOpen, dst syscall.Conn, bufs [][]byte, flags int32) (uint64, int32) {
	nonblocking := op.nonblocking() || flags&wasiMsgDontWait != 0
	if !nonblocking {
		if !w.awaitOutputTurn(m, op) {
			return 0, _wasiEINTR
		}
		defer op.passOutputTurn()
	}
	rest := append([][]byte(nil), bufs...)
	var total uint64
	file, _ := dst.(*os.File)
	// write writes rest once. With wait, which holds the turn, the mode is
	// not asked: in steps the write does not wait in either, and otherwise
	// the writev(2) waits in blocking mode and takes what fits in
	// non-blocking mode. Without wait it does not write to a descriptor that
	// can wait in the kernel, which it reports as again.
	write := func(wait bool) (again, mayBlock bool, errno int32) {
		var n int
		n, again, errno = w.tryStream(call, dst, func(fd uintptr) (int, bool, error) {
			if wait && hostWritesWithoutWaiting {
				return op.writeWithoutWaiting(file, fd, rest)
			}
			if wait {
				return writevRaw(fd, rest)
			}
			if mayBlock = hostMayBlock(fd); mayBlock {
				return 0, true, nil
			}
			return writevRaw(fd, rest)
		})
		total += uint64(n)
		for n > 0 {
			c := min(n, len(rest[0]))
			rest[0], n = rest[0][c:], n-c
			if len(rest[0]) == 0 {
				rest = rest[1:]
			}
		}
		return again, mayBlock, errno
	}
	// written is what the write returns: the count once something was
	// written, and errno otherwise.
	written := func(errno int32) (uint64, int32) {
		if total > 0 {
			return total, _wasiESUCCESS
		}
		return 0, errno
	}
	set := []hostWaitFD{{stream: dst, want: hostWantRoom, op: op}}
	for len(firstBuffer(rest)) > 0 {
		again, mayBlock, errno := write(!nonblocking)
		switch {
		case errno != _wasiESUCCESS:
			return written(errno)
		case nonblocking && mayBlock:
			n, errno := w.writeHostOnce(call, op, dst, rest)
			total += n
			return written(errno)
		case !again:
			continue
		case nonblocking:
			return written(_wasiEAGAIN)
		}
		interrupted, err := w.waitHostInterruptibly(m, call, set, time.Time{})
		if err != nil {
			return written(w.guestErrno(call, err))
		}
		if interrupted {
			// What there is room for is written in a step, where writes are
			// made in steps, and elsewhere only to a descriptor that does
			// not wait in the kernel.
			if again, _, errno := write(hostWritesWithoutWaiting); !again || total > 0 {
				w.keepInterrupt(m)
				return written(errno)
			}
			return 0, _wasiEINTR
		}
	}
	return total, _wasiESUCCESS
}

// writeHostOnce is a write that does not wait to dst, a descriptor that can
// wait in the kernel (hostMayBlock), the destination of the entry op: one
// call that does not wait in the kernel (writeWithoutWaiting), made by the
// holder of the turn at the stream's output, which it does not wait for
// (EAGAIN while a write that waits holds it).
func (w *WasiStubs) writeHostOnce(call string, op *wasiOpen, dst syscall.Conn, bufs [][]byte) (uint64, int32) {
	select {
	case op.outputTurn() <- struct{}{}:
	default:
		return 0, _wasiEAGAIN
	}
	defer op.passOutputTurn()
	file, _ := dst.(*os.File)
	n, again, errno := w.tryStream(call, dst, func(fd uintptr) (int, bool, error) {
		return op.writeWithoutWaiting(file, fd, bufs)
	})
	if errno == _wasiESUCCESS && again {
		errno = _wasiEAGAIN
	}
	return uint64(n), errno
}

// writeWithoutWaiting writes bufs once to fd, the descriptor of file, the
// stream of the entry op, without waiting in the kernel whatever the mode of
// its open file description, which whoever shares it can change: again
// reports that it takes nothing right now. The caller holds the turn at the
// stream's output, so that no other write of the runtime's takes the room
// it finds. To a socket it is a send that does not wait (MSG_DONTWAIT) where
// the host honours it; to a pipe what the host tells it takes without
// waiting, where it tells (hostPipeWriteNow); to anything else, once
// poll(2) has found room, a write of what it takes without waiting: a pipe
// no more than PIPE_BUF, a stream socket no more than its low-water mark, a
// datagram socket the datagram whole, a terminal (a short write) no more
// than PIPE_BUF.
func (op *wasiOpen) writeWithoutWaiting(file *os.File, fd uintptr, bufs [][]byte) (int, bool, error) {
	mode, _ := op.statOf(file)
	if mode&os.ModeSocket != 0 && hostSendsWithoutWaiting {
		return sendNow(fd, bufs)
	}
	if mode&os.ModeNamedPipe != 0 {
		if n, again, done, err := hostPipeWriteNow(fd, bufs); done {
			return n, again, err
		}
	}
	ready := []bool{false}
	if err := hostWaitReady([]uintptr{fd}, []int{hostWantRoom}, ready, time.Now(), -1); err != nil {
		return 0, false, err
	}
	if !ready[0] {
		return 0, true, nil
	}
	switch {
	case mode&(os.ModeNamedPipe|os.ModeCharDevice) != 0:
		bufs = leadingBytes(bufs, hostPipeBuf)
	case mode&os.ModeSocket != 0:
		lowat, err := op.streamSendLowat(file, fd)
		if err != nil {
			return 0, false, err
		}
		if lowat > 0 {
			bufs = leadingBytes(bufs, lowat)
		}
	}
	return writevRaw(fd, bufs)
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
// The instance's standard input is writable when it is a host stream open
// both ways, as a terminal is; a descriptor with nothing to write to is
// never writable, except an unconnected socket, where a write fails at
// once. Regular files and destinations the host cannot ask about count as
// writable.
func (op *wasiOpen) writeReadiness(dst io.Writer, stdin io.Reader) (stream streamWriter, how int) {
	if op.stdio == 1 {
		dst, _ = stdin.(io.Writer)
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
	// poll(2) reports room in a terminal open for reading only.
	openForWrite := true
	hostDescriptor(stream, func(fd uintptr) { openForWrite = openForWriting(fd) })
	if !openForWrite {
		return nil, pollWriteNever
	}
	return stream, pollWriteProbe
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
	n, errno := w.readVec("fd_pread", io.NewSectionReader(op.f, offset, 1<<63-1), bufs, true)
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
	n, errno := w.writeVec("fd_pwrite", io.NewOffsetWriter(op.f, offset), bufs)
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
		return w.guestErrno("fd_seek", err)
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
		return w.guestErrno("fd_tell", err)
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
	w.endUnregistered()
	w.mu.Lock()
	dst, op := w.fdDstLocked(fd)
	turn := w.outputTurnLocked(op, dst)
	w.mu.Unlock()
	bufs, ok := w.iovecSlices(m, abi, iovs, iovsLen)
	// nwritten is a __wasi_size_t.
	nwrittenSlice := w.memBytes(m, nwrittenPtr, abi.wordSize())
	if !ok || nwrittenSlice == nil {
		return _wasiEFAULT
	}
	if host := op.hostSocket(); host != nil {
		// A socket of the host's, written as send(2) writes it: a write
		// of nothing sends nothing.
		var n uint64
		errno := _wasiESUCCESS
		if firstBuffer(bufs) != nil {
			n, errno = w.socketSend(m, "fd_write", op, host, bufs, 0, nil, "")
		}
		abi.putWord(nwrittenSlice, n)
		return w.signalBrokenPipe(m, errno, 0)
	}
	if dst == nil {
		abi.putWord(nwrittenSlice, 0)
		if op.socket() {
			// a write of a socket without a connection, as on linux
			return w.signalBrokenPipe(m, _wasiEPIPE, 0)
		}
		return _wasiEBADF
	}
	if turn != nil {
		// A write that does not wait finds the Writer busy with another
		// call's Write; one that waits waits for it.
		if !turn.tryTake() {
			if op.nonblocking() {
				abi.putWord(nwrittenSlice, 0)
				return _wasiEAGAIN
			}
			taken, err := w.awaitStreamTurn(m, "fd_write", turn)
			if err != nil {
				abi.putWord(nwrittenSlice, 0)
				return w.guestErrno("fd_write", err)
			}
			if !taken {
				abi.putWord(nwrittenSlice, 0)
				return _wasiEINTR
			}
		}
		defer func() { w.reportError("fd_write", turn.give()) }()
	}
	n, errno := w.writeFd(m, "fd_write", op, dst, bufs, 0)
	abi.putWord(nwrittenSlice, n)
	return w.signalBrokenPipe(m, op.afterShutdown(errno, true), 0)
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
		return w.guestErrno("fd_sync", err)
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
		return w.guestErrno("fd_datasync", err)
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
		return w.guestErrno("fd_allocate", err)
	}
	if end <= st.Size() {
		return _wasiESUCCESS
	}
	if err := op.f.Truncate(end); err != nil {
		return w.guestErrno("fd_allocate", err)
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
	name, fd, own, errno := w.changedFile(string(pathSlice), true)
	switch {
	case errno != _wasiESUCCESS:
		return -errno
	case own:
		return w.Fd_chmod(m, fd, mode)
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if err := fsys.Chmod(name, unixFileMode(uint32(mode))); err != nil {
		return -w.guestErrno("path_chmod", err)
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
		return -w.guestErrno("fd_chmod", err)
	}
	return _wasiESUCCESS
}

// Fd_chmod64 is Fd_chmod for a memory64 guest.
func (w *WasiStubs) Fd_chmod64(m *Module, fd, mode int32) int32 {
	return w.Fd_chmod(m, fd, mode)
}

// Proc_umask is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_umask") backing umask(): it sets the instance's file mode
// creation mask and returns the previous one. Until the guest sets one, the
// mask is the Umask of the Process (WASIConfig.Process), and a forked
// instance starts with its parent's (see Fork).
//
// The mask is the instance's own, taken out of the mode of every file,
// directory and FIFO the instance creates (create). On Linux the instance
// creates those of the host's filesystem on a thread of its own whose umask
// is the mask (creationThread): the kernel takes it out, as for a process
// of its own — a default ACL of the directory decides instead, as it does
// (posix_acl_create) — and a command the instance starts (Proc_spawn) is
// started there and inherits it. Elsewhere, and for any other filesystem,
// the runtime takes the mask out of the mode it asks the filesystem for; on
// another system than Linux the host's filesystem takes the host process's
// umask out as well, and a command inherits the host process's umask.
//
// The mask the guest of the family's root instance sets is given to the
// ProcessChanges as well (WASIConfig.ProcessChanges): HostProcessChanges
// makes it the host process's umask (umask(2)), which every thread but the
// instances' creation threads has. An error of its SetUmask other than
// errors.ErrUnsupported is told WASIConfig.Errors (op "proc_umask").
func (w *WasiStubs) Proc_umask(m *Module, mask int32) int32 {
	w.endUnregistered()
	next := os.FileMode(uint32(mask) & 0o777)
	w.umaskCalls.Lock()
	defer w.umaskCalls.Unlock()
	prev := w.guestUmask()
	w.mu.Lock()
	w.umask = &next
	creations := w.creations
	w.mu.Unlock()
	if creations != nil {
		// A thread being closed (CloseAll) needs no mask any more.
		if err := creations.run(func() { hostSetThreadUmask(next) }); err != nil && !errors.Is(err, fs.ErrClosed) {
			w.reportError("proc_umask", err)
		}
	}
	if changes := w.cfg.ProcessChanges; changes != nil && !w.forked {
		if _, err := changes.SetUmask(next); err != nil && !errors.Is(err, errors.ErrUnsupported) {
			w.reportError("proc_umask", err)
		}
	}
	return int32(prev)
}

// Proc_umask64 is Proc_umask for a memory64 guest.
func (w *WasiStubs) Proc_umask64(m *Module, mask int32) int32 {
	return w.Proc_umask(m, mask)
}

// createMode returns the mode the instance's filesystem is asked for when
// the guest creates a file or directory with the requested mode, where the
// runtime takes the mask out (create): the instance's umask taken out of it.
func (w *WasiStubs) createMode(requested os.FileMode) os.FileMode {
	return requested &^ w.guestUmask()
}

// guestUmask returns the file mode creation mask of the instance.
func (w *WasiStubs) guestUmask() os.FileMode {
	w.mu.Lock()
	umask := w.umask
	w.mu.Unlock()
	if umask != nil {
		return *umask
	}
	return w.guestProcess().Umask().Perm()
}

// create runs make, which creates a file, directory or FIFO in fsys with the
// mode it is given, so that the instance's umask is taken out of the
// requested mode: for a filesystem of the host's on Linux, where the
// instance's mask is the host process's umask, on the calling goroutine,
// and otherwise on the instance's creation thread, given the requested
// mode, the kernel taking the mask out (creationThread); for another
// filesystem, elsewhere and without a creation thread, given the mode less
// the mask (createMode).
// hostFiles reports whether fsys is one of HostFS's, or an FS of one of
// their directories (OpenRootFS): its calls are the host's own, made in the
// host process (the kernel's umask, the FIFO opens the host tells of).
func hostFiles(fsys FS) bool {
	switch fsys.(type) {
	case osFS, rootFS, osDir, hostDir:
		return true
	}
	return false
}

func (w *WasiStubs) create(fsys FS, requested os.FileMode, make func(perm os.FileMode) error) error {
	if !hostFiles(fsys) {
		return make(w.createMode(requested))
	}
	if !hostThreadUmask {
		return make(w.createMode(requested))
	}
	// Where the instance's mask is the host process's, the kernel takes it
	// out on any thread, or lets a default ACL decide: the creation is
	// made here, given the requested mode.
	var err error
	if withHostUmask(w.guestUmask(), func() { err = make(requested) }) {
		return err
	}
	if t := w.creationThread(); t != nil {
		var err error
		if rerr := t.run(func() { err = make(requested) }); rerr == nil {
			return err
		}
		// The instance is being closed (CloseAll): the mask is taken out
		// here.
	}
	return make(w.createMode(requested))
}

// creationThread returns the instance's creation thread, made with the
// instance's umask under umaskCalls, as Proc_umask sets it: nil on a system
// without one (hostThreadUmask), where the host process may make none
// (creationThreadsRefused, told WASIConfig.Errors once a process, op
// "creation_thread"), after CloseAll, and when the instance's could not be
// made (told once an instance).
func (w *WasiStubs) creationThread() *creationThread {
	if !hostThreadUmask {
		return nil
	}
	if err := creationThreadsRefused(); err != nil {
		reportCreationThreadsRefused.Do(func() { w.reportError("creation_thread", err) })
		return nil
	}
	w.umaskCalls.Lock()
	defer w.umaskCalls.Unlock()
	w.mu.Lock()
	t, unmade := w.creations, w.creationsFailed || w.creationsClosed
	w.mu.Unlock()
	if t != nil || unmade {
		return t
	}
	t, err := newCreationThread(w.guestUmask())
	if err != nil {
		w.mu.Lock()
		w.creationsFailed = true
		w.mu.Unlock()
		w.reportError("creation_thread", err)
		return nil
	}
	w.mu.Lock()
	closed := w.creationsClosed
	if !closed {
		w.creations = t
	}
	w.mu.Unlock()
	if closed {
		t.close()
		return nil
	}
	// An instance dropped without CloseAll lets its thread go when it is
	// collected, as an os.File closes its descriptor.
	runtime.AddCleanup(w, func(t *creationThread) { t.close() }, t)
	return t
}

// hostUmaskState is the host process's umask as far as the runtime knows
// it: read once (readHostUmask), then what the runtime itself set it to
// (hostSetUmask). An embedder that changes the umask behind the runtime's
// back is seen at the next hostSetUmask. Creations and command starts made
// with it (withHostUmask) hold mu for reading; hostSetUmask holds it for
// writing.
var hostUmaskState struct {
	mu    sync.RWMutex
	read  sync.Once
	known bool
	mask  os.FileMode
}

// withHostUmask runs f and reports true when mask is the host process's
// umask, which the kernel then takes out on any thread; it runs nothing
// and reports false when it is not, or is not known.
func withHostUmask(mask os.FileMode, f func()) bool {
	s := &hostUmaskState
	s.read.Do(func() {
		umask, err := readHostUmask()
		s.mu.Lock()
		s.known, s.mask = err == nil, umask
		s.mu.Unlock()
	})
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.known || s.mask != mask.Perm() {
		return false
	}
	f()
	return true
}

// creationThreadsRefused is why the host process may make no creation
// thread (unshare(2) refused, as Docker's default seccomp profile refuses
// it), nil when it may: asked once a process, by making one.
var creationThreadsRefused = sync.OnceValue(func() error {
	t, err := newCreationThread(0)
	if err != nil {
		return err
	}
	t.close()
	return nil
})

// reportCreationThreadsRefused tells WASIConfig.Errors of the first
// instance that needs a creation thread why there is none.
var reportCreationThreadsRefused sync.Once

// creationThread is an OS thread whose file system attributes — umask,
// working directory and root — are its own (unshare(CLONE_FS), Linux):
// its umask is an instance's, and the instance makes the files of the
// host's filesystem there (create), so that the kernel takes the mask out
// exactly, or lets a default ACL decide, as for a process of its own. The
// working directory stays what it was at the unshare; the host's
// filesystems name what they make absolutely (osFS) or relative to a
// directory descriptor (os.Root), which it does not affect, and a command
// started there is given the host process's working directory
// (Proc_spawn).
//
// The goroutine that holds the thread locks it and never unlocks it:
// when the goroutine returns (close), the thread ends with it, as
// runtime.LockOSThread does to a thread whose goroutine exits locked. The
// main thread, which the runtime keeps when its goroutine so exits, is
// never one (newCreationThread). The runtime starts no thread from a
// locked one (runtime.newm hands the start to its template thread), so no
// other thread gets its attributes; a process the thread starts (fork from
// it) does, as the kernel copies the starting thread's (copy_fs). The
// thread lasts until CloseAll, or, for an instance dropped without it,
// until the garbage collector collects the instance (runtime.AddCleanup).
type creationThread struct {
	mu     sync.Mutex
	closed bool
	calls  chan func()
	// quit is closed by close: the thread ends once the call it runs, if
	// any, has returned.
	quit chan struct{}
}

// newCreationThread starts a creation thread with umask mask. A goroutine
// that locks the main thread (hostOnMainThread) starts another and lets
// the main thread go once that one has locked a thread of its own, which
// is then not the main thread, which the first holds.
func newCreationThread(mask os.FileMode) (*creationThread, error) {
	t := &creationThread{calls: make(chan func()), quit: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if !hostOnMainThread() {
			t.serve(mask, started, nil)
			return
		}
		locked := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			t.serve(mask, started, locked)
		}()
		<-locked
		runtime.UnlockOSThread()
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	return t, nil
}

// serve makes the locked thread it runs on a creation thread with umask
// mask, tells started whether it did, and runs the calls given until close.
// locked, when it is not nil, is closed once the thread is known not to be
// the main thread. It returns with the thread locked, but for the main
// thread.
func (t *creationThread) serve(mask os.FileMode, started chan<- error, locked chan<- struct{}) {
	onMain := hostOnMainThread()
	if locked != nil {
		close(locked)
	}
	if onMain {
		// Never so: the main thread is held by the goroutine that started
		// this one. It is let go unchanged, which the main thread must be.
		runtime.UnlockOSThread()
		started <- errors.New("the creation thread is the main thread")
		return
	}
	if err := hostUnshareFS(); err != nil {
		started <- err
		return
	}
	hostSetThreadUmask(mask)
	started <- nil
	for {
		select {
		case call := <-t.calls:
			call()
		case <-t.quit:
			return
		}
	}
}

// run runs call on the thread and returns once it has returned; after close
// it runs nothing and returns fs.ErrClosed.
func (t *creationThread) run(call func()) error {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return fs.ErrClosed
	}
	ran := make(chan struct{})
	select {
	case t.calls <- func() {
		defer close(ran)
		call()
	}:
		<-ran
		return nil
	case <-t.quit:
		return fs.ErrClosed
	}
}

// close ends the thread without waiting for it: a call it runs returns
// first, and no call is run after.
func (t *creationThread) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.quit)
	}
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
	fd, errno := w.pathOpenMode(m, string(pathSlice), dirflags, oflags, fsRightsBase, fdflags, unixFileMode(uint32(mode)))
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
	return -w.pathCreateDirectory(nil, string(pathSlice), unixFileMode(uint32(mode)))
}

// pathCreateDirectory creates the directory raw, relative to from (atDir),
// with the requested mode, less the instance's umask, and returns a wasi
// errno.
func (w *WasiStubs) pathCreateDirectory(from *wasiOpen, raw string, mode os.FileMode) int32 {
	full, errno := atPath(from, raw)
	if errno != _wasiESUCCESS {
		return errno
	}
	name, errno := w.changedName(full, nameMake)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, name := w.atFS(from, raw, name)
	if err := w.create(fsys, mode, func(perm os.FileMode) error { return fsys.Mkdir(name, perm) }); err != nil {
		return w.guestErrno("path_create_directory", err)
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
	name, errno := w.guestName(string(pathSlice))
	if errno != _wasiESUCCESS {
		return -errno
	}
	if fd, fi, _, own, errno := w.ownName(name, follow != 0); own {
		switch {
		case errno != _wasiESUCCESS:
			return -errno
		case fi == nil:
			return w.filestatExtOf(fd, out)
		}
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
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
		return -w.guestErrno("path_filestat_ext", err)
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
			return -w.guestErrno("fd_filestat_ext", err)
		}
		writeFilestatExt(out, fi)
		return _wasiESUCCESS
	}
	fi, err := w.opFileInfo(op)
	if err != nil {
		return -w.guestErrno("fd_filestat_ext", err)
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
	defer w.mu.Unlock()
	return w.streamFileLocked(op)
}

// opHostFile returns the host file behind op: that of a standard stream
// (streamFile), op's own otherwise; nil when there is none.
func (w *WasiStubs) opHostFile(op *wasiOpen) *os.File {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.opHostFileLocked(op)
}

// opHostFileLocked is opHostFile with w.mu held. Caller holds w.mu.
func (w *WasiStubs) opHostFileLocked(op *wasiOpen) *os.File {
	if op.stdio != 0 {
		return w.streamFileLocked(op)
	}
	file, _ := op.f.(*os.File)
	return file
}

// streamFileLocked is streamFile for a standard stream (op.stdio != 0).
// Caller holds w.mu.
func (w *WasiStubs) streamFileLocked(op *wasiOpen) *os.File {
	var stream any
	switch op.stdio {
	case 1:
		stream = w.stdin()
	case 2:
		stream = w.stdout()
	case 3:
		stream = w.stderr()
	}
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

// guestPath returns name, a name guestName gave, as an absolute path of the
// guest's filesystem.
func guestPath(name string) string { return path.Join("/", name) }

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
//
// It has no name under wasip1_posix_extension.
//
// Deprecated: use Path_filestat_ext, whose mode carries the same bits.
func (w *WasiStubs) Path_filestat_mode(m *Module, pathPtr, pathLen, follow, modeOutPtr int32) int32 {
	return w.pathFilestatMode(m, zext(pathPtr), pathLen, follow, zext(modeOutPtr))
}

// Path_filestat_mode64 is Path_filestat_mode for a memory64 guest.
//
// Deprecated: use Path_filestat_ext64, whose mode carries the same bits.
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
	name, errno := w.guestName(string(pathSlice))
	if errno != _wasiESUCCESS {
		return -errno
	}
	if fd, fi, _, own, errno := w.ownName(name, follow != 0); own {
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
		return -w.guestErrno("path_filestat_mode", err)
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
	nfd, errno := w.addFDFromLocked(op, min)
	if errno != _wasiESUCCESS {
		return errno
	}
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
	replaced, errno := w.takeDup2(from, to)
	w.closeReplaced("fd_dup2", replaced)
	return errno
}

// takeDup2 is Fd_dup2 up to the closing of what to held, which it takes
// out of the table and returns (nil for nothing to close,
// clearSlotLocked), to be closed once w.mu is let go (closeReplaced), with
// the call's errno.
func (w *WasiStubs) takeDup2(from, to int32) (replaced *wasiOpen, errno int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := w.openLocked(from)
	if src == nil || to < 0 || to >= wasiRootFD {
		return nil, _wasiEBADF
	}
	if from == to {
		return nil, _wasiESUCCESS
	}
	if w.hostNumbered() {
		if err := w.placeHostSlotLocked(to, src); err != nil {
			return nil, w.errnoLater("descriptors", err)
		}
	}
	// A to that holds src already is not its last slot: from holds it.
	replaced = w.takeSlotLocked(to)
	w.setSlotLocked(to, src)
	return replaced, _wasiESUCCESS
}

// Fd_dup264 is Fd_dup2 for a memory64 guest.
func (w *WasiStubs) Fd_dup264(m *Module, from, to int32) int32 {
	return w.Fd_dup2(m, from, to)
}

func (w *WasiStubs) Fd_renumber(m *Module, from, to int32) int32 {
	replaced, errno := w.takeRenumber(from, to)
	w.closeReplaced("fd_renumber", replaced)
	return errno
}

// closeReplaced closes op, which a slot held until call put another
// descriptor there (nil for none). As on Linux, the call has done what it
// was asked once the slot holds the other descriptor: a failure of the
// close goes to WASIConfig.Errors.
func (w *WasiStubs) closeReplaced(call string, op *wasiOpen) {
	err := w.resyncReleased()
	if op != nil {
		err = errors.Join(err, closeWasiOpen(op))
	}
	w.reportError(call, err)
}

// takeRenumber is Fd_renumber up to the closing of what to held, which it
// takes out of the table and returns (nil for nothing to close,
// clearSlotLocked), to be closed once w.mu is let go (closeReplaced), with
// the call's errno.
func (w *WasiStubs) takeRenumber(from, to int32) (replaced *wasiOpen, errno int32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if from == to {
		// Renumbering an fd onto itself is a no-op. We must NOT close
		// the entry at "to" here — that would destroy the live fd the
		// caller is trying to keep.
		if w.openLocked(from) != nil {
			return nil, _wasiESUCCESS
		}
		return nil, _wasiEBADF
	}
	src := w.openLocked(from)
	if src == nil || to < 0 || to >= wasiRootFD {
		return nil, _wasiEBADF
	}
	if w.hostNumbered() {
		if err := w.placeHostSlotLocked(to, src); err != nil {
			return nil, w.errnoLater("descriptors", err)
		}
	}
	// to holds src before from lets it go: from's is not its last slot.
	replaced = w.takeSlotLocked(to)
	w.setSlotLocked(to, src)
	// from's is not src's last slot (to holds it): what fails is the close
	// of from's descriptor of the host's, after the call has done what it
	// was asked, as for closeReplaced.
	_, err := w.clearSlotLocked(from)
	w.reportLater("fd_renumber", err)
	return replaced, _wasiESUCCESS
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
	if out, ok, err := hostDirListing(op.f); ok {
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
		return 0, w.guestErrno("fd_readdir", err)
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
// table. The path is relative to the directory descriptor dirFd (atDir):
// the preopened root (fd 3, the "preopen /" convention wasi-libc requires
// for its directory enumeration) or any other directory; it is opened
// through the configured FS.
func (w *WasiStubs) Path_open(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags, openedFdPtr int32) int32 {
	return w.openGuestPath(m, dirFd, dirflags, zext(pathPtr), zext(pathLen), oflags, fsRightsBase, fsRightsInherit, fdflags, zext(openedFdPtr))
}

// Path_open64 is Path_open for a memory64 guest.
func (w *WasiStubs) Path_open64(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags, fsRightsBase, fsRightsInherit, fdflags, openedFdPtr int64) int32 {
	return w.openGuestPath(m, int32(dirFd), int32(dirflags), uint64(pathPtr), uint64(pathLen), int32(oflags), fsRightsBase, fsRightsInherit, int32(fdflags), uint64(openedFdPtr))
}

// openGuestPath is the body of Path_open and Path_open64.
func (w *WasiStubs) openGuestPath(m *Module, dirFd, dirflags int32, pathPtr, pathLen uint64, oflags int32, fsRightsBase, fsRightsInherit int64, fdflags int32, openedFdPtr uint64) int32 {
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	outSlice := w.memBytes(m, openedFdPtr, 4)
	if pathSlice == nil || outSlice == nil {
		return _wasiEFAULT
	}
	fd, errno := w.pathOpenAt(m, from, string(pathSlice), dirflags, oflags, fsRightsBase, fdflags, wasiDefaultFileMode)
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
func (w *WasiStubs) pathOpen(m *Module, rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32) (int32, int32) {
	return w.pathOpenMode(m, rel, dirflags, oflags, fsRightsBase, fdflags, wasiDefaultFileMode)
}

// ownDescriptorPath tells what rel, a name guestName gave, names of the
// guest's own descriptors, the way the system names the descriptors of the
// process that opens the name:
//
//   - a descriptor (named): /dev/stdin, /dev/stdout, /dev/stderr (0, 1, 2),
//     /dev/fd/N, /proc/self/fd/N and /proc/PID/fd/N for the process's own
//     pid. rest is what rel goes on with after the name, from its slash:
//     empty when rel ends with the name, and a path from the descriptor,
//     which then has to be a directory, otherwise;
//   - a directory that lists the descriptors (dir): /dev/fd, /proc/self/fd
//     and /proc/PID/fd;
//   - nothing (dir empty).
//
// pid returns the process's own pid; it is called only for a name that
// walks into proc/N/fd with N other than self.
func ownDescriptorPath(rel string, pid func() int32) (fd int32, rest string, named bool, dir string) {
	// The name is the first prefix of rel, up to a slash or its end, that
	// is a descriptor's name.
	for end := 1; end <= len(rel); end++ {
		if end < len(rel) && rel[end] != '/' {
			continue
		}
		if fd, ok := ownDescriptorNumber(strings.Split(rel[:end], "/"), pid); ok {
			return fd, rel[end:], true, ""
		}
	}
	name := strings.Split(strings.TrimSuffix(rel, "/"), "/")
	switch {
	case len(name) == 2 && name[0] == "dev" && name[1] == "fd":
		return 0, "", false, "dev/fd"
	case len(name) == 3 && ownProcessDir(name, pid):
		return 0, "", false, "proc/" + name[1] + "/fd"
	}
	return 0, "", false, ""
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
func (d *descriptorListing) Chown(uid, gid int) error     { return syscall.EPERM }
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
	return strings.Count(strings.TrimSuffix(rel, rest), "/") == 1
}

// aliasInfo describes /dev/stdin, /dev/stdout or /dev/stderr, the link to
// target, /proc/self/fd/n: as Linux's, open to everyone.
func (w *WasiStubs) aliasInfo(name string, n int32, ids ProcessIDs, target string) ownNameInfo {
	return ownNameInfo{name: name, mode: os.ModeSymlink | 0o777, size: int64(len(target)), ino: uint64(n) + ownAliasIno, uid: uint32(ids.EUID), gid: uint32(ids.EGID), modTime: w.monoStart}
}

// ownLinkTarget returns what the link of descriptor op, or the preopened
// root, leads to, as Linux names it: the path the descriptor was opened
// under, absolute in the guest's filesystem ("/" for the root); for a
// host file without that path (a standard stream, a descriptor the host
// gave), the target of the host's own link for it where the host has one
// (hostFDLink), when the FS is a HostRootFS
// and the target is a name in it or names no file; pipe:[N] or socket:[N] for a
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
	if fsys, isHost := w.fs().(HostRootFS); isHost {
		if file := w.opHostFile(op); file != nil {
			target, ok, err := hostStreamLink(file)
			if err != nil {
				return "", w.guestErrno("path_readlink", err)
			}
			if ok && !filepath.IsAbs(target) {
				return target, _wasiESUCCESS // pipe:[N] and the like: no file's name
			}
			if ok {
				if name, in := guestPathOf(fsys, target); in {
					return name, _wasiESUCCESS
				}
			}
		}
	}
	fi, err := w.opFileInfo(op)
	if err != nil {
		return "", w.guestErrno("path_readlink", err)
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
// anew as the root of the FS (openRoot). As on Linux the
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
// descriptors: the root of the FS, as a directory open for reading. O_TRUNC of a directory is EISDIR.
func (w *WasiStubs) openRoot(oflags, fdflags int32) (int32, int32) {
	if oflags&0x8 != 0 { // O_TRUNC
		return -1, _wasiEISDIR
	}
	fsys := w.fs()
	var f File
	if err := makeRuntimeDescriptors(func() error {
		var err error
		if f, err = fsys.OpenFile(".", os.O_RDONLY, 0); err != nil {
			return err
		}
		f, err = keepRuntimeOpened(f)
		return err
	}); err != nil {
		return -1, w.guestErrno("path_open", err)
	}
	op := &wasiOpen{f: f, isDir: true, path: ".", fdflags: fdflags, noWrite: true}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(op)
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
	fd, errno := w.addFDLocked(&wasiOpen{f: listing, isDir: true, path: dir, noWrite: true})
	if errno != _wasiESUCCESS {
		return -1, errno
	}
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
			return ownNameEntry{}, w.guestErrno("fd_readdir", err)
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

// ownFile is ownName for a call that changes or asks about what name leads
// to (chmod, chown, the times, access): own is false for a name of the FS,
// which fsName is: name, or "." for a name that leads to the preopened
// root, whose file is the root of the FS. Otherwise fd is the descriptor
// the name leads to, or -1 for the link itself or a listing directory,
// which fi describes and which the runtime changes nothing of.
func (w *WasiStubs) ownFile(name string, follow bool) (fsName string, fd int32, fi os.FileInfo, own bool, errno int32) {
	fd, fi, _, own, errno = w.ownName(name, follow)
	if !own || errno != _wasiESUCCESS || fi != nil {
		return name, fd, fi, own, errno
	}
	w.mu.Lock()
	root := w.openLocked(fd) == nil && fd == wasiPreopenFD && w.preopened(fd)
	w.mu.Unlock()
	if root {
		return ".", -1, nil, false, _wasiESUCCESS
	}
	return name, fd, nil, true, _wasiESUCCESS
}

// changedFile resolves the guest path raw for a call that changes what the
// name leads to, following a symbolic link at its end or not (chmod,
// chown, the times): the name the FS is given, or (own) the descriptor fd
// that a name of the guest's own descriptors leads to (ownFile), whose
// call the caller makes instead. errno is a wasi errno: guestName's, or
// EPERM for a link of the guest's own descriptors itself and for a listing
// directory.
func (w *WasiStubs) changedFile(raw string, follow bool) (name string, fd int32, own bool, errno int32) {
	if name, errno = w.guestName(raw); errno != _wasiESUCCESS {
		return "", -1, false, errno
	}
	name, fd, fi, own, errno := w.ownFile(name, follow)
	switch {
	case errno != _wasiESUCCESS:
		return "", -1, false, errno
	case fi != nil:
		return "", -1, false, _wasiEPERM
	case own:
		return "", fd, true, _wasiESUCCESS
	}
	return name, -1, false, _wasiESUCCESS
}

// The calls that change a name: one that makes it (mkdir, mkfifo, symlink,
// the new name of a link), unlink and rmdir.
const (
	nameMake = iota
	nameUnlink
	nameRmdir
)

// lastErrno is what Linux's call (nameMake, nameUnlink, nameRmdir) fails
// with on name, a name guestName gave of a guest path whose last element is
// of the kind last, which is not an ordinary name: what name leads to has
// to be a directory first (guestDirectory); then a name to make is there
// already (EEXIST), unlink refuses a directory (EISDIR), rmdir refuses "."
// (EINVAL) and a ".." that is not empty (ENOTEMPTY).
func (w *WasiStubs) lastErrno(name string, call, last int) int32 {
	if errno := w.guestDirectory(name); errno != _wasiESUCCESS {
		return errno
	}
	switch {
	case call == nameMake:
		return _wasiEEXIST
	case call == nameUnlink:
		return _wasiEISDIR
	case last == lastDot:
		return _wasiEINVAL
	}
	return _wasiENOTEMPTY
}

// changedName resolves the guest path raw for call, which makes or removes
// the name: the name the FS is given. errno is a wasi errno: guestName's,
// lastErrno's for a name that ends in "." or "..", or ownChange's for a
// name of the guest's own descriptors.
func (w *WasiStubs) changedName(raw string, call int) (string, int32) {
	name, errno := w.guestName(raw)
	if errno != _wasiESUCCESS {
		return "", errno
	}
	if last := guestLast(raw); last != lastName {
		return "", w.lastErrno(name, call, last)
	}
	if own, errno := w.ownChange(name, call == nameMake); own {
		return "", errno
	}
	return name, _wasiESUCCESS
}

// changedNames resolves the guest paths oldRaw and newRaw of a rename, or
// of a link (link): the names the FS is given. errno is a wasi errno:
// guestName's; as on Linux, for a rename of a name, or to one, that ends in
// "." or "..", EBUSY, and for a link to one EEXIST; or ownRename's when
// either is a name of the guest's own descriptors.
func (w *WasiStubs) changedNames(oldRaw, newRaw string, link bool) (oldName, newName string, errno int32) {
	if oldName, errno = w.guestName(oldRaw); errno != _wasiESUCCESS {
		return "", "", errno
	}
	if newName, errno = w.guestName(newRaw); errno != _wasiESUCCESS {
		return "", "", errno
	}
	// What a "." or ".." ends is a directory first (guestDirectory).
	last := func(raw, name string, errno int32) int32 {
		if guestLast(raw) == lastName {
			return _wasiESUCCESS
		}
		return cmp.Or(w.guestDirectory(name), errno)
	}
	if link {
		errno = last(newRaw, newName, _wasiEEXIST)
	} else {
		errno = cmp.Or(last(oldRaw, oldName, _wasiEBUSY), last(newRaw, newName, _wasiEBUSY))
	}
	if errno != _wasiESUCCESS {
		return "", "", errno
	}
	if own, errno := w.ownRename(oldName, newName, link); own {
		return "", "", errno
	}
	return oldName, newName, _wasiESUCCESS
}

// ownChange returns the errno of a call that makes name (makes: mkdir,
// mkfifo, symlink, link), or removes or renames it, when name, a name
// guestName gave, is one of the guest's own descriptors or of a directory
// that lists them (ownDescriptorPath); own is false when it is neither. The
// names are those of Linux's procfs, which has none of these operations:
// making one fails with EEXIST when it names an open descriptor or a
// listing, and with ENOENT when it names a descriptor that is not open,
// where procfs finds no name to make; removing or renaming one fails with
// EACCES, the directories being writable by nobody, or EPERM for a guest of
// effective user id 0, whom that does not stop.
func (w *WasiStubs) ownChange(name string, makes bool) (own bool, errno int32) {
	if own, errno = w.ownLookup(name); !own || errno != _wasiESUCCESS {
		return own, errno
	}
	switch {
	case makes:
		return true, _wasiEEXIST
	case w.guestIDs().EUID == 0:
		return true, _wasiEPERM
	}
	return true, _wasiEACCES
}

// ownLookup tells whether name, a name guestName gave, is one of the
// guest's own descriptors or of a directory that lists them, and the errno
// of looking it up (ownDescriptorLocked): ENOENT for a descriptor that is
// not open.
func (w *WasiStubs) ownLookup(name string) (own bool, errno int32) {
	n, rest, named, dir := ownDescriptorPath(name, w.guestPID)
	if !named {
		return dir != "", _wasiESUCCESS
	}
	w.mu.Lock()
	_, _, errno = w.ownDescriptorLocked(n, rest)
	w.mu.Unlock()
	return true, errno
}

// ownRename returns the errno of a rename, or of a link (link), from
// oldName to newName, names guestName gave, when either is a name of the
// guest's own descriptors or of a directory that lists them: EXDEV when
// only one is, as they are names of a filesystem of their own. When both
// are, as Linux's procfs: a rename fails as looking up either name does,
// and else as removing oldName does (ownChange); a link fails as looking up
// oldName does, and else as making newName does.
func (w *WasiStubs) ownRename(oldName, newName string, link bool) (own bool, errno int32) {
	oldOwn, oldErrno := w.ownLookup(oldName)
	newOwn, newErrno := w.ownLookup(newName)
	switch {
	case oldOwn != newOwn:
		return true, _wasiEXDEV
	case !oldOwn:
		return false, _wasiESUCCESS
	case link:
		_, makeErrno := w.ownChange(newName, true)
		return true, cmp.Or(oldErrno, makeErrno)
	}
	_, removeErrno := w.ownChange(oldName, false)
	return true, cmp.Or(oldErrno, newErrno, removeErrno)
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
func (w *WasiStubs) pathOpenMode(m *Module, rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32, mode os.FileMode) (int32, int32) {
	return w.pathOpenAt(m, nil, rel, dirflags, oflags, fsRightsBase, fdflags, mode)
}

// pathOpenAt is pathOpenMode for raw, a path relative to the directory
// descriptor from (atDir), opened through the FS atFS gives it to.
func (w *WasiStubs) pathOpenAt(m *Module, from *wasiOpen, raw string, dirflags, oflags int32, fsRightsBase int64, fdflags int32, mode os.FileMode) (int32, int32) {
	// Decode rights into access mode. WASI rights bits: 0=FD_DATASYNC,
	// 1=FD_READ, 6=FD_WRITE. We treat absent rights as the closest fit:
	// without FD_WRITE the open is one for reading.
	canWrite := fsRightsBase&(1<<6) != 0
	canRead := fsRightsBase&(1<<1) != 0 || !canWrite

	full, errno := atPath(from, raw)
	if errno != _wasiESUCCESS {
		return -1, errno
	}
	rel, errno := w.guestName(full)
	if errno != _wasiESUCCESS {
		return -1, errno
	}
	n, rest, named, dir := ownDescriptorPath(rel, w.guestPID)
	if named {
		return w.openOwnDescriptor(n, rest, streamAlias(rel, rest), dirflags, oflags, fsRightsBase, fdflags, canRead, canWrite)
	}
	if dir != "" {
		return w.openDescriptorListing(dir, oflags, canWrite)
	}
	fsys, name := w.atFS(from, raw, rel)
	// An open that does not wait is made as the runtime makes its own
	// descriptors (makeRuntimeDescriptors); one of a FIFO that waits for
	// the other end (openFIFO) is moved up once it is made.
	// inBlockingMode puts the file in blocking mode before it is moved up:
	// the file of the moved descriptor is then one the Go runtime does not
	// poll.
	inBlockingMode := false
	nonblock := fdflags&wasiFdflagNonblock != 0
	openFile := func(name string, flag int, perm os.FileMode) (f File, err error) {
		err = makeRuntimeDescriptors(func() error {
			if f, err = fsys.OpenFile(name, flag, perm); err != nil {
				return err
			}
			if inBlockingMode {
				if err := setHostNonblock(f, false); err != nil {
					return errors.Join(err, f.Close())
				}
			}
			if f, err = w.guestOpened(f, nonblock && !inBlockingMode); err == nil && inBlockingMode && nonblock && w.hostFamily() {
				// Where the guest's mode is the description's (hostFamily),
				// the file the Go runtime does not poll is put in it once
				// it is made.
				if err = setHostNonblock(f, true); err != nil {
					err = errors.Join(err, f.Close())
				}
			}
			return err
		})
		return f, err
	}

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

	requireDir := oflags&0x2 != 0
	noFollow := dirflags&0x1 == 0

	if requireDir {
		// os.OpenFile on a directory tolerates O_RDONLY only on POSIX.
		flag = os.O_RDONLY
	}

	// When the guest opted out of symlink-follow, the FS is asked to open
	// with O_NOFOLLOW (FS.OpenFile); where the host has no such flag the
	// open is refused up-front if Lstat says the name is a symbolic link,
	// which leaves a window between the two for the name to change. What
	// the name is (a FIFO) is told by Lstat then, so the open does not wait
	// for the other end of a FIFO a link leads to.
	stat := fsys.Stat
	if noFollow {
		stat = fsys.Lstat
	}
	// O_CREAT|O_EXCL follows no link and refuses one (EEXIST), which
	// O_NOFOLLOW would make ELOOP on darwin: the flag goes only to the opens
	// that may follow.
	exclusive := flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL
	if noFollow && hostONofollow != 0 && !exclusive {
		flag |= hostONofollow
	} else if noFollow && hostONofollow == 0 {
		if li, lerr := fsys.Lstat(name); lerr == nil && (li.Mode()&os.ModeSymlink) != 0 {
			// open(2)'s errnos for a symbolic link: EEXIST with
			// O_CREAT|O_EXCL, ELOOP with O_NOFOLLOW otherwise
			if oflags&0x5 == 0x5 {
				return -1, _wasiEEXIST
			}
			return -1, _wasiELOOP
		}
	}
	var f File
	var err error
	// A file the open creates gets the mode less the instance's umask
	// (create).
	isFIFO := false
	fi, err := stat(name)
	if err == nil {
		isFIFO = fi.Mode()&os.ModeNamedPipe != 0
	} else if !errors.Is(err, fs.ErrNotExist) {
		return -1, w.guestErrno("path_open", err)
	}
	if isFIFO && requireDir {
		// Not opened: an open of a FIFO would wait for its other end.
		return -1, _wasiENOTDIR
	}
	switch {
	case isFIFO && fdflags&0x4 != 0: // NONBLOCK
		// The host's open that does not wait: a reader gets the FIFO
		// whether or not anyone writes to it, a writer is refused (ENXIO)
		// while nobody reads. Where poll(2) does not report the end of a
		// FIFO's input (darwin, whose kqueue does not report the close of
		// the last writer either), the Go runtime does not poll a FIFO: the
		// descriptor waits as any other does, and its file is not polled
		// once it is moved up (keepRuntimeOpened) either.
		inBlockingMode = !hostPollReportsFIFOEnd
		if f, err = openFile(name, flag|hostONonblock, w.createMode(mode)); err != nil {
			return -1, w.guestErrno("path_open", err)
		}
	case isFIFO && flag&os.O_RDWR == 0:
		// An open of one end waits for the other.
		var errno int32
		if f, errno = w.openFIFO(m, fsys, name, fi, flag, w.createMode(mode)); errno != _wasiESUCCESS {
			return -1, errno
		}
		if f, err = w.guestOpened(f, false); err != nil {
			return -1, w.guestErrno("path_open", err)
		}
	case flag&os.O_CREATE != 0:
		if err = w.create(fsys, mode, func(perm os.FileMode) error {
			var err error
			f, err = openFile(name, flag, perm)
			return err
		}); err != nil {
			return -1, w.guestErrno("path_open", err)
		}
	default:
		if f, err = openFile(name, flag, mode); err != nil {
			return -1, w.guestErrno("path_open", err)
		}
	}
	polled, pollErr := filePolled(f)
	if pollErr != nil {
		return -1, w.guestErrno("path_open", errors.Join(pollErr, f.Close()))
	}
	// The guest's NONBLOCK is its fdflags. A FIFO opened without waiting
	// that is waited for in the Go runtime's poller (polled) is left in the
	// non-blocking mode its poller takes (netpolled). Any other is put in
	// blocking mode, as its reader waits in the read (streamReader): the Go
	// runtime's poller cannot wait for one it does not poll, and would
	// report EAGAIN in that mode.
	// (Where the guest's mode is the description's, it is the guest's
	// already: guestOpened.)
	if isFIFO && fdflags&0x4 != 0 && !polled && !w.hostFamily() {
		if err := setHostNonblock(f, false); err != nil {
			return -1, w.guestErrno("path_open", errors.Join(err, f.Close()))
		}
	}
	st, statErr := f.Stat()
	if statErr != nil {
		return -1, w.guestErrno("path_open", errors.Join(statErr, f.Close()))
	}
	isDir := st.IsDir()
	if requireDir && !isDir {
		if cerr := f.Close(); cerr != nil {
			return -1, w.guestErrno("path_open", cerr)
		}
		return -1, _wasiENOTDIR
	}
	// A directory is also opened as an FS of its own (OpenRootFS), which the
	// names relative to its descriptor are given to: by name, a second
	// time, so a name that changes between the two opens leaves the
	// descriptor with the names of the directory it names now. An FS that
	// cannot (no OpenRootFS, errors.ErrUnsupported) has the names found by the
	// path. The FS's handle is opened with the directory, not on the first
	// call relative to it: by then the path may name another directory.
	var root FS
	if opener, ok := fsys.(OpenRootFS); ok && isDir {
		if root, err = opener.OpenRoot(name); err != nil && !errors.Is(err, errors.ErrUnsupported) {
			return -1, w.guestErrno("path_open", errors.Join(err, f.Close()))
		}
	}
	op := &wasiOpen{
		f: f, root: root, isDir: isDir, regular: st.Mode().IsRegular(), path: rel, fdflags: fdflags,
		polled:  polled,
		noRead:  flag&os.O_WRONLY != 0,
		noWrite: flag&(os.O_WRONLY|os.O_RDWR) == 0,
	}
	if _, isHost := f.(*os.File); isHost {
		if hs, ok := osFileStat(st.Sys()); ok {
			op.fileKey, op.hasFileKey = fileKey{dev: hs.dev, ino: hs.ino}, true
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(op)
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
// directory descriptor dirFd (atDir), with the default mode.
func (w *WasiStubs) pathCreateDirectoryAt(m *Module, dirFd int32, pathPtr, pathLen uint64) int32 {
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	return w.pathCreateDirectory(from, string(pathSlice), wasiDefaultDirMode)
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	full, errno := atPath(from, string(pathSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	name, errno := w.changedName(full, nameUnlink)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, name := w.atFS(from, string(pathSlice), name)
	return w.guestErrno("path_unlink_file", fsys.Unlink(name))
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	full, errno := atPath(from, string(pathSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	name, errno := w.changedName(full, nameRmdir)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, name := w.atFS(from, string(pathSlice), name)
	return w.guestErrno("path_remove_directory", fsys.Rmdir(name))
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
	oldFrom, errno := w.atDir(oldFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	newFrom, errno := w.atDir(newFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	oldFull, oldErrno := atPath(oldFrom, string(oldSlice))
	newFull, newErrno := atPath(newFrom, string(newSlice))
	if errno := cmp.Or(oldErrno, newErrno); errno != _wasiESUCCESS {
		return errno
	}
	oldName, newName, errno := w.changedNames(oldFull, newFull, false)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, oldName, newName := w.atFS2(oldFrom, string(oldSlice), oldName, newFrom, string(newSlice), newName)
	if err := fsys.Rename(oldName, newName); err != nil {
		return w.guestErrno("path_rename", err)
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	out := w.memBytes(m, outPtr, 64)
	if pathSlice == nil || out == nil {
		return _wasiEFAULT
	}
	full, errno := atPath(from, string(pathSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	name, errno := w.guestName(full)
	if errno != _wasiESUCCESS {
		return errno
	}
	if fd, fi, _, own, errno := w.ownName(name, flags&0x1 != 0); own {
		switch {
		case errno != _wasiESUCCESS:
			return errno
		case fi == nil:
			return w.filestatOf(fd, out)
		}
		writeFilestat(out, fi)
		return _wasiESUCCESS
	}
	fsys, rel := w.atFS(from, string(pathSlice), name)
	var st os.FileInfo
	var err error
	if flags&0x1 != 0 {
		st, err = fsys.Stat(rel)
	} else {
		st, err = fsys.Lstat(rel)
	}
	if err != nil {
		return w.guestErrno("path_filestat_get", err)
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	follow := flags&0x1 != 0
	full, errno := atPath(from, string(pathSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	name, fd, own, errno := w.changedFile(full, follow)
	switch {
	case errno != _wasiESUCCESS:
		return errno
	case own:
		return w.Fd_filestat_set_times(m, fd, atim, mtim, fstFlags)
	}
	fsys, rel := w.atFS(from, string(pathSlice), name)
	var st os.FileInfo
	var statErr error
	if follow {
		st, statErr = fsys.Stat(rel)
	} else {
		st, statErr = fsys.Lstat(rel)
	}
	if statErr != nil {
		return w.guestErrno("path_filestat_set_times", statErr)
	}
	atime, mtime := resolveFiletimes(uint64(atim), uint64(mtim), fstFlags, st)
	chtimes := fsys.Chtimes
	if !follow {
		chtimes = fsys.Lchtimes
	}
	return w.guestErrno("path_filestat_set_times", chtimes(rel, atime, mtime))
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
	oldFrom, errno := w.atDir(oldFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	newFrom, errno := w.atDir(newFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	oldSlice := w.memBytes(m, oldPathPtr, oldPathLen)
	newSlice := w.memBytes(m, newPathPtr, newPathLen)
	if oldSlice == nil || newSlice == nil {
		return _wasiEFAULT
	}
	oldFull, oldErrno := atPath(oldFrom, string(oldSlice))
	newFull, newErrno := atPath(newFrom, string(newSlice))
	if errno := cmp.Or(oldErrno, newErrno); errno != _wasiESUCCESS {
		return errno
	}
	oldName, newName, errno := w.changedNames(oldFull, newFull, true)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, oldName, newName := w.atFS2(oldFrom, string(oldSlice), oldName, newFrom, string(newSlice), newName)
	if err := fsys.Link(oldName, newName); err != nil {
		return w.guestErrno("path_link", err)
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	targetSlice := w.memBytes(m, targetPtr, targetLen)
	linkSlice := w.memBytes(m, linkPathPtr, linkPathLen)
	if targetSlice == nil || linkSlice == nil {
		return _wasiEFAULT
	}
	full, errno := atPath(from, string(linkSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	link, errno := w.changedName(full, nameMake)
	if errno != _wasiESUCCESS {
		return errno
	}
	fsys, link := w.atFS(from, string(linkSlice), link)
	if err := fsys.Symlink(string(targetSlice), link); err != nil {
		return w.guestErrno("path_symlink", err)
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
	from, errno := w.atDir(dirFd)
	if errno != _wasiESUCCESS {
		return errno
	}
	pathSlice := w.memBytes(m, pathPtr, pathLen)
	bufSlice := w.memBytes(m, buf, buflen)
	// bufused is a __wasi_size_t.
	bufused := w.memBytes(m, bufusedPtr, abi.wordSize())
	if pathSlice == nil || bufSlice == nil || bufused == nil {
		return _wasiEFAULT
	}
	full, errno := atPath(from, string(pathSlice))
	if errno != _wasiESUCCESS {
		return errno
	}
	name, errno := w.guestName(full)
	if errno != _wasiESUCCESS {
		return errno
	}
	var target string
	if _, _, link, own, errno := w.ownName(name, false); own {
		// A name that is no link fails as on Linux.
		if errno != _wasiESUCCESS {
			return errno
		}
		if link == "" {
			return _wasiEINVAL
		}
		target = link
	} else {
		fsys, name := w.atFS(from, string(pathSlice), name)
		var err error
		if target, err = fsys.Readlink(name); err != nil {
			return w.guestErrno("path_readlink", err)
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
// for `timeout` ns (relative timer) or until clock_id reads `timeout`
// (absolute timer; at once, with an event carrying EINVAL, for a clock_id
// clock_time_get refuses); a signal posted to the guest ends the sleep, and
// the call returns EINTR (awaitInterruptibly). For fd_read / fd_write
// subscriptions, payload at offset 16 is a u32 fd; we call into the
// platform Poll helper to wait for readiness.
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
	w.endUnregistered()
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
		errno    int32
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
			clockID := int32(binary.LittleEndian.Uint32(subs[base+16:]))
			timeout := int64(binary.LittleEndian.Uint64(subs[base+24:]))
			flags := binary.LittleEndian.Uint16(subs[base+40:])
			ns := timeout
			var errno int32
			if flags&0x1 != 0 {
				// Absolute timeout in nanoseconds of the subscription's
				// clock: the time left until it. A clock there is none of
				// has its event at once, carrying the error.
				var now uint64
				now, errno = w.clockNanos(clockID)
				ns = 0
				if at := uint64(timeout); errno == _wasiESUCCESS && at > now {
					ns = int64(min(at-now, 1<<63-1))
				}
			}
			if minClockNs < 0 || ns < minClockNs {
				minClockNs = ns
			}
			clockEvents = append(clockEvents, pollItem{userdata: userdata, etype: 0, errno: errno})
		case 1, 2: // fd_read / fd_write
			fd := int32(binary.LittleEndian.Uint32(subs[base+16:]))
			fdEvents = append(fdEvents, pollItem{userdata: userdata, etype: etype, fd: fd, isRead: etype == 1})
		default:
			// Unknown event type — write an EINVAL-tagged event below.
			clockEvents = append(clockEvents, pollItem{userdata: userdata, etype: etype})
		}
	}

	// Decide which fd subscriptions are ready. A descriptor whose read or
	// write cannot block — a regular file, a Writer of the embedder's no
	// other call is writing to — is ready at once. A stream whose read CAN
	// block (pipe, socket, terminal) is ready only when input is actually
	// there: reporting it
	// ready regardless sends a guest multiplexing two pipes into a blocking
	// read of the idle one while the busy one fills up and its writer
	// stalls. Likewise a stream is writable only while it has room, and the
	// read end of a pipe never is: an event loop told otherwise spins, or
	// writes into a full pipe and stalls.
	type probeKey struct {
		op    *wasiOpen
		write bool
	}
	ready := make([]bool, len(fdEvents))
	errnos := make([]int32, len(fdEvents))
	ops := make([]*wasiOpen, len(fdEvents))
	// The stream behind a subscription for reading that can be hung up on,
	// asked about when its event is reported (streamHungUp).
	hangStreams := make([]any, len(fdEvents))
	// The streams that are descriptors of the host's are asked about in one
	// poll(2), any other stream's reader for what it keeps (hostSet, which
	// subscription i asks about at hostIndex[i]). Subscriptions of one key
	// share their entry.
	var hostSet []hostWaitFD
	hostOf := map[probeKey]int{}
	hostIndex := make([]int, len(fdEvents))
	// slotClosed marks the subscriptions whose slot was closed while the
	// call waited (closedSlots): the event of one carries EBADF, while
	// another number of the same descriptor, which shares its entry of
	// hostSet, waits on.
	slotClosed := make([]bool, len(fdEvents))
	addEntry := func(i int, key probeKey, e hostWaitFD) {
		if at, seen := hostOf[key]; seen {
			hostIndex[i] = at
			return
		}
		hostOf[key] = len(hostSet)
		hostIndex[i] = len(hostSet)
		e.op = ops[i]
		hostSet = append(hostSet, e)
	}
	addHost := func(i int, key probeKey, stream any, want int) {
		addEntry(i, key, hostWaitFD{stream: stream, want: want})
	}
	anyReady := false
	for i, ev := range fdEvents {
		hostIndex[i] = -1
		w.mu.Lock()
		src, op := w.fdSrcLocked(ev.fd)
		dst, _ := w.fdDstLocked(ev.fd)
		stdin := w.stdin()
		w.mu.Unlock()
		ops[i] = op
		if op == nil {
			errnos[i] = _wasiEBADF
			ready[i], anyReady = true, true
			continue
		}
		if host := op.hostSocket(); host != nil {
			// A socket of the host's is ready as poll(2) says, and for
			// reading with input a command left of it (receiveAhead).
			if pending, _ := op.aheadReady(); pending && ev.isRead {
				ready[i], anyReady = true, true
				continue
			}
			want := hostWantInput
			if !ev.isRead {
				want = hostWantRoom
			}
			addHost(i, probeKey{op: op, write: !ev.isRead}, host, want)
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
			// POLLERR or POLLHUP once nobody reads it any more (the reader
			// of a pipe has closed it). The guest asks about that with a
			// subscription for reading, having asked for neither; the
			// event carries EPIPE.
			if ev.isRead && writable && dst != nil && streamPolled(dst) {
				errnos[i] = _wasiEPIPE
				addHost(i, probeKey{op: op}, dst, hostWantFailure)
			}
			continue
		}
		if !ev.isRead {
			stream, how := op.writeReadiness(dst, stdin)
			w.mu.Lock()
			turn := w.outputTurnLocked(op, dst)
			w.mu.Unlock()
			switch {
			case how == pollWriteReady && turn != nil && !turn.ready():
				// Writable once the Writer is done with another call's
				// Write.
				addEntry(i, probeKey{op: op, write: true}, hostWaitFD{source: turn})
			case how == pollWriteReady:
				ready[i], anyReady = true, true
			case how == pollWriteProbe:
				addHost(i, probeKey{op: op, write: true}, stream, hostWantRoom)
			}
			continue
		}
		if op.listener != nil && streamPolled(op.listener) {
			// A listening socket is readable while a connection waits to be
			// accepted.
			addHost(i, probeKey{op: op}, op.listener, hostWantInput)
			continue
		}
		if !op.readsStream(src) {
			ready[i], anyReady = true, true
			continue
		}
		hangStreams[i] = src
		if pending, _ := op.aheadReady(); pending {
			ready[i], anyReady = true, true
			continue
		}
		if op.inputPolled(src) {
			addHost(i, probeKey{op: op}, src, hostWantInput)
			continue
		}
		// Asked for input from here on: what it reads ends the wait.
		reader := w.inputReader(op, src)
		reader.request()
		addEntry(i, probeKey{op: op}, hostWaitFD{source: reader})
	}
	// hostErr is why poll(2) could not be asked: every descriptor it was
	// to be asked about is ready with that error.
	var hostErr error
	markHost := func() {
		for i := range fdEvents {
			if at := hostIndex[i]; at >= 0 && (slotClosed[i] || hostSet[at].ready || hostErr != nil) {
				ready[i], anyReady = true, true
				if hostErr != nil && !slotClosed[i] {
					errnos[i] = w.guestErrno("poll_oneoff", hostErr)
				}
			}
		}
	}
	if len(hostSet) > 0 {
		hostErr = waitHostReady(hostSet, time.Now(), nil)
		markHost()
	}

	// The call blocks the guest when nothing is ready yet and there is
	// something to wait for, unless its timeout is zero; a signal posted
	// meanwhile ends the wait. With descriptors that can never become ready
	// and no timeout, a signal is all there is to wait for, as for poll(2).
	onlySignal := !anyReady && len(hostSet) == 0 && minClockNs < 0 && len(fdEvents) > 0
	waits := !anyReady && minClockNs != 0 && (len(hostSet) > 0 || minClockNs > 0 || onlySignal)
	// How long the descriptors may be waited for: until the timeout when
	// there is one, otherwise until one is ready.
	var hostDeadline time.Time
	if minClockNs >= 0 {
		hostDeadline = time.Now().Add(time.Duration(minClockNs))
	}
	// The wake of this call, which a signal, a reader that has input or a
	// close of a descriptor waited for wakes.
	var wk *wasiWake
	var wakeErr error
	// closedSlots marks the subscriptions whose slot was closed since the
	// call looked it up (their events carry EBADF), and reports whether a
	// subscription is ready.
	closedSlots := func() bool {
		found := false
		w.mu.Lock()
		for i, ev := range fdEvents {
			if hostIndex[i] >= 0 && w.openLocked(ev.fd) != ops[i] {
				errnos[i], slotClosed[i], found = _wasiEBADF, true, true
			}
		}
		w.mu.Unlock()
		return found || slices.ContainsFunc(hostSet, func(e hostWaitFD) bool { return e.ready })
	}
	// waitHostWoken waits for hostSet until until passes, stop is closed or
	// the descriptor of a subscription is closed (its event carries EBADF),
	// and reports whether a subscription is ready.
	waitHostWoken := func(until time.Time, stop <-chan struct{}) bool {
		// A slot closed before the waits were registered woke none of
		// them: it ends the wait before it starts.
		if closedSlots() {
			return true
		}
		for {
			if hostErr = waitHostReady(hostSet, until, wk); hostErr != nil {
				return true
			}
			// The wake is read empty before what woke the wait is looked
			// at, so that a wake written meanwhile ends the next wait.
			if hostErr = wk.drain(); hostErr != nil {
				return true
			}
			if closedSlots() {
				return true
			}
			if !until.IsZero() && !time.Now().Before(until) {
				return false
			}
			select {
			case <-stop:
				return false
			default:
			}
		}
	}
	// given is false while the call holds a wake pipe it has to give back.
	given := true
	if waits && len(hostSet) > 0 {
		if wk, hostErr = w.wakeFor(hostSet); hostErr != nil {
			return w.guestErrno("poll_oneoff", hostErr)
		}
		for _, e := range hostSet {
			e.op.addWaiter(wk)
			if e.source != nil {
				e.source.addWaiter(wk)
			}
		}
		given = false
		defer w.giveWakeOnUnwind("poll_oneoff", &given, wk, hostSet)
	}
	clockEnd := time.Now().Add(time.Duration(minClockNs))
	// wait waits once for what the call waits for, until stop (nil for
	// none) is closed.
	wait := func(stop <-chan struct{}) {
		switch {
		case !waits:
		case len(hostSet) > 0:
			waitHostWoken(hostDeadline, stop)
		case minClockNs > 0:
			// The clock paces the call only when nothing else can end it.
			timer := time.NewTimer(time.Until(clockEnd))
			select {
			case <-timer.C:
			case <-stop:
				timer.Stop()
			}
		case onlySignal:
			<-stop
		}
	}
	if !waits {
		wait(nil)
	}
	for waits {
		interrupted, woken, refused := w.blockingAttempt(m, func() {
			if wk != nil {
				wakeErr = errors.Join(wakeErr, wk.wake())
			}
		}, nil, wait)
		markHost()
		if refused || interrupted && !anyReady {
			if !given {
				given = true
				if err := w.giveWake(wk, hostSet); err != nil {
					return w.guestErrno("poll_oneoff", err)
				}
			}
			return _wasiEINTR
		}
		// A signal another blocking call reports leaves the wait on while
		// nothing is ready and time remains.
		if !woken || interrupted || anyReady || minClockNs >= 0 && !time.Now().Before(clockEnd) {
			break
		}
	}
	if !given {
		given = true
		hostErr = errors.Join(hostErr, wakeErr, w.giveWake(wk, hostSet))
		markHost()
	}

	written := int32(0)
	for _, ev := range clockEvents {
		// A poll returns its ready fds without also claiming that the
		// timeout expired.
		if ev.etype == 0 && ev.errno == _wasiESUCCESS && anyReady {
			continue
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, uint16(ev.errno), 0, 0)
		written += 32
	}
	for i, ev := range fdEvents {
		if !ready[i] {
			continue
		}
		// The hang-up goes with events for reading only. The guest's C
		// library takes it on an event for writing as the end of
		// writability (POLLHUP contradicts POLLWRNORM), and its select()
		// then puts the descriptor in no set, while the host's select(2)
		// reports a socket whose peer is gone writable: the write tells
		// what happened.
		var flags uint16
		if errnos[i] == 0 && ev.isRead {
			if stream := hangStreams[i]; stream != nil && streamHungUp(stream) {
				flags = wasiEventHangup
			}
		}
		var nbytes uint64
		var reader *streamReader
		if at := hostIndex[i]; at >= 0 {
			reader, _ = hostSet[at].source.(*streamReader)
		}
		if op := ops[i]; op != nil && ev.isRead && errnos[i] == 0 {
			if reader != nil {
				nbytes = uint64(reader.pending())
			} else if _, pending := op.aheadReady(); pending > 0 {
				nbytes = uint64(pending)
			} else if op.f != nil && hostIndex[i] < 0 {
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

// streamHungUp reports whether a stream has been hung up on, as poll(2)
// tells it with POLLHUP: the writers of a pipe have all closed it, a
// connection is shut down both ways. Only the host can tell, for a stream
// that is a descriptor of its own; of any other stream it is not known, and
// the guest finds the end of its input by reading it.
func streamHungUp(stream any) bool {
	var hup bool
	hostDescriptor(stream, func(fd uintptr) { hup = hostHungUp(fd) })
	return hup
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
	// Panic instead of exiting the host process: the caller gets the
	// *WasiExitError as WasiExitError's doc says. The other threads of the
	// guest end with it (stop), and the instance is of no further use: each
	// call that looks unwinds with the same end.
	w.stop(m, &WasiExitError{Code: code})
}

// Proc_exit64 is Proc_exit for a memory64 guest.
func (w *WasiStubs) Proc_exit64(m *Module, code int64) {
	w.Proc_exit(m, int32(code))
}

// Proc_raise backs raise() for the guest itself; no signal reaches the host
// process. sig is a WASI signal (__wasi_signal_t, 0..30), which is turned
// into the guest's number for it (Linux numbering, see guestSignalOfWASI),
// the numbering of every other signal call. The signal is raised for the
// calling thread of the guest, which takes it at its next safe point (a
// thread that has not registered gets it as a signal of the process); signal
// 0 does nothing. A guest that has registered no flag word
// (Proc_signal_register) cannot take
// a signal: the signal has its default action, which is to do nothing for
// the signals of wasiDefaultIgnoredSignals (the ones ignored by default and
// the ones that stop a process, which cannot stop an instance) and to end
// the guest, as Proc_terminate does, for any other. Returns 0, or EINVAL for
// a number outside the enum.
func (w *WasiStubs) Proc_raise(m *Module, sig int32) int32 {
	w.endUnregistered()
	if sig < 0 || sig > 30 {
		return _wasiEINVAL
	}
	if guest := guestSignalOfWASI(sig); !w.takeSignal(guest) {
		w.raiseOwn(m, guest, true)
	}
	return _wasiESUCCESS
}

// raiseOwn posts sig, the guest's number for a signal, to the guest itself
// from its thread whose module m is: raised for that thread as Proc_raise
// does when thread is true, posted to the process as kill(2) of its own pid
// does otherwise. What the guest's own code posts is left for the guest
// (postForGuestLocked), and a guest that has registered no flag word has the
// signal's default action.
func (w *WasiStubs) raiseOwn(m *Module, sig int32, thread bool) {
	if sig == wasiSIGKILL {
		// It ends the guest at once, every thread of it.
		w.terminate(sig)
	}
	t := w.lockSignalThread(m)
	registered := w.sig.registeredLocked()
	if registered {
		w.postForGuestLocked(t, func() {
			if thread {
				w.raiseLocked(t, sig)
			} else {
				w.postSignalLocked(sig)
			}
		})
	}
	w.unlockSignals()
	if registered || sig == 0 || wasiSignalBit(sig)&wasiDefaultIgnoredSignals != 0 {
		return
	}
	w.terminate(sig)
}

// takeSignal offers sig, a signal the runtime raises for the guest itself,
// to WASIConfig.TakeSignal, and reports whether it was taken; see there.
// Caller holds neither w.mu nor w.sig.mu; a stream's write lock may be
// held.
func (w *WasiStubs) takeSignal(sig int32) bool {
	if w.cfg.TakeSignal == nil || sig == 0 || sig == wasiSIGKILL || sig == wasiSIGSTOP {
		return false
	}
	w.sig.mu.Lock()
	execed := w.sig.execed != nil
	w.sig.mu.Unlock()
	if execed {
		return false
	}
	taken, err := w.cfg.TakeSignal(w, sig)
	if err != nil {
		w.reportError("take_signal", err)
		return false
	}
	return taken
}

// guestSignalOfWASI returns the guest's number (Linux numbering) for a WASI
// signal (__wasi_signal_t, 0..30). WASI's enum has no SIGSTKFLT, Linux's
// 16, so from SIGCHLD on its numbers are one lower than Linux's.
func guestSignalOfWASI(sig int32) int32 {
	if sig >= 16 {
		return sig + 1
	}
	return sig
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

// Sock_socket is a NON-STANDARD host import (module wasip1_posix_extension,
// and wasi_snapshot_preview1 as well: wasiReleasedPosixImports; name
// "sock_socket") that a guest's socket() can call. WASI preview1 has no way
// to create an outbound socket; this gives the guest a host-managed fd whose
// connection is established later by Sock_connect. domain/type follow the
// POSIX socket() args (AF_INET / SOCK_STREAM); only TCP over IPv4 is
// supported. Returns the new fd, or a negative errno on failure.
func (w *WasiStubs) Sock_socket(m *Module, domain, typ int32) int32 {
	// A guest calls this only for AF_INET / SOCK_STREAM: domain and typ
	// are not checked (the guest's AF_INET numeric value need not match
	// the host's).
	_ = domain
	_ = typ
	if hostOpensSockets {
		// a socket of the host's, as Sock_open makes it
		return w.openSocketEntry(wasiSockFamilyIPv4, false)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return negativeFD(w.addFDLocked(&wasiOpen{isSocket: true}))
}

// negativeFD is the result of an import that returns a new descriptor fd,
// or a negative errno: -errno when errno is not ESUCCESS.
func negativeFD(fd, errno int32) int32 {
	if errno != _wasiESUCCESS {
		return -errno
	}
	return fd
}

// Sock_socket64 is Sock_socket for a memory64 guest.
func (w *WasiStubs) Sock_socket64(m *Module, domain, typ int32) int32 {
	return w.Sock_socket(m, domain, typ)
}

// Sock_connect is a NON-STANDARD host import (module wasip1_posix_extension,
// and wasi_snapshot_preview1 as well: wasiReleasedPosixImports; name
// "sock_connect") that a guest's connect() can call. ipBE carries the IPv4
// address in network byte order exactly as it sat in
// sockaddr_in.sin_addr.s_addr (so the low byte is the first octet); port is
// host byte order. It consults the dial whitelist, dials via Go's net, and
// attaches the resulting conn to the socket fd so the existing Sock_send /
// Sock_recv / Fd_close paths drive it. Returns 0 or a negative errno.
func (w *WasiStubs) Sock_connect(m *Module, fd, ipBE, port int32) int32 {
	w.endUnregistered()
	u := uint32(ipBE)
	if op, host, errno := w.socketOf(fd); errno != _wasiESUCCESS {
		return -errno
	} else if host != nil {
		// A socket of the host's connects as sock_connect_addr connects
		// it, to the IPv4 address.
		a := wasiSockAddr{family: wasiSockFamilyIPv4, ip: net.IPv4(byte(u), byte(u>>8), byte(u>>16), byte(u>>24)).To4(), port: int(uint16(port))}
		return -w.connectSocket(m, "sock_connect", op, host, a, "")
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", u&0xff, (u>>8)&0xff, (u>>16)&0xff, (u>>24)&0xff)
	op, conn, errno := w.socketConn(fd)
	switch {
	case conn != nil, op != nil && op.listener != nil:
		return -_wasiEISCONN
	case errno != _wasiENOTCONN:
		return -errno
	}
	p := int(uint16(port))
	if !w.dialAllowed("tcp", ip, p) {
		return -_wasiEACCES
	}
	conn, errno = w.dialInterruptibly(m, "sock_connect", "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
	if conn == nil {
		return -errno
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
		return -w.guestErrno("sock_connect", cerr)
	}
	return -_wasiEBADF
}

// Sock_connect64 is Sock_connect for a memory64 guest.
func (w *WasiStubs) Sock_connect64(m *Module, fd, ipBE, port int32) int32 {
	return w.Sock_connect(m, fd, ipBE, port)
}

// dialInterruptibly dials address on network as package net does, for a
// host whose sockets the runtime does not make (Sock_connect): a signal
// posted to the guest meanwhile cancels the dial (EINTR). It returns the
// connection, or nil and an errno. call is the import's name.
func (w *WasiStubs) dialInterruptibly(m *Module, call, network, address string) (net.Conn, int32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var conn net.Conn
	var err error
	ended := false
	defer func() {
		if !ended && conn != nil {
			// The guest's thread is unwound (the instance ends): nobody
			// takes the connection.
			w.reportError(call, conn.Close())
		}
	}()
	interrupted, _, refused := w.blockingAttempt(m, cancel, nil, func(<-chan struct{}) {
		conn, err = (&net.Dialer{}).DialContext(ctx, network, address)
	})
	ended = true
	switch {
	case refused:
		return nil, _wasiEINTR
	case err != nil && interrupted:
		return nil, _wasiEINTR
	case err != nil:
		return nil, w.guestErrno(call, err)
	case interrupted:
		// The dial went through: the next call that waits reports the
		// signal.
		w.keepInterrupt(m)
	}
	return conn, _wasiESUCCESS
}

// Sock_accept accepts the next incoming TCP/Unix connection on the
// listener associated with fd, registers it as a new wasiOpen with a
// conn arm, and writes the new fd at fdOutPtr. Returns ENOTSOCK if fd
// isn't a listener.
func (w *WasiStubs) Sock_accept(m *Module, fd, flags, fdOutPtr int32) int32 {
	return w.sockAccept(m, fd, flags, zext(fdOutPtr))
}

// Sock_accept64 is Sock_accept for a memory64 guest.
func (w *WasiStubs) Sock_accept64(m *Module, fd, flags, fdOutPtr int64) int32 {
	return w.sockAccept(m, int32(fd), int32(flags), uint64(fdOutPtr))
}

// sockAccept is the body of Sock_accept and Sock_accept64.
func (w *WasiStubs) sockAccept(m *Module, fd, flags int32, fdOutPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, fdOutPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	if op, host, errno := w.socketOf(fd); errno == _wasiESUCCESS && host != nil {
		// a socket of the host's, which accept(2) takes a connection of
		newFD, errno := w.acceptSocket(m, op, host, flags)
		if errno == _wasiESUCCESS {
			binary.LittleEndian.PutUint32(out, uint32(newFD))
		}
		return errno
	}
	if !w.checkNet("accept") {
		return _wasiEACCES
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
		return w.guestErrno("sock_accept", err)
	}
	w.mu.Lock()
	newFD, errno := w.addFDLocked(&wasiOpen{conn: conn})
	w.mu.Unlock()
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint32(out, uint32(newFD))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_recv(m *Module, fd, riData, riDataLen, riFlags, roDataLenPtr, roFlagsPtr int32) int32 {
	return w.sockRecv(m, wasiABI32, fd, zext(riData), zext(riDataLen), riFlags, zext(roDataLenPtr), zext(roFlagsPtr))
}

// Sock_recv64 is Sock_recv for a memory64 guest, whose ri_data_len and
// ro_datalen are __wasi_size_t.
func (w *WasiStubs) Sock_recv64(m *Module, fd, riData, riDataLen, riFlags, roDataLenPtr, roFlagsPtr int64) int32 {
	return w.sockRecv(m, wasiABI64, int32(fd), uint64(riData), uint64(riDataLen), int32(riFlags), uint64(roDataLenPtr), uint64(roFlagsPtr))
}

// sockRecv is the body of Sock_recv and Sock_recv64.
func (w *WasiStubs) sockRecv(m *Module, abi wasiABI, fd int32, riData, riDataLen uint64, riFlags int32, roDataLenPtr, roFlagsPtr uint64) int32 {
	w.endUnregistered()
	bufs, ok := w.iovecSlices(m, abi, riData, riDataLen)
	lenOut := w.memBytes(m, roDataLenPtr, abi.wordSize())
	// ro_flags is a __wasi_roflags_t — a 16-bit value. wasi-libc packs it
	// immediately before ro_datalen (only 2 bytes apart), so writing 4 bytes
	// here would clobber the low half of ro_datalen and make recv() report 0
	// bytes received even when data arrived.
	flagsOut := w.memBytes(m, roFlagsPtr, 2)
	if op, host, errno := w.socketOf(fd); errno == _wasiESUCCESS && host != nil {
		// a socket of the host's, received from as recv(2) receives
		if !ok || lenOut == nil || flagsOut == nil {
			return _wasiEFAULT
		}
		n, truncated, errno := w.socketReceive(m, "sock_recv", op, host, bufs, riFlags)
		if errno != _wasiESUCCESS {
			return errno
		}
		var roFlags uint16
		if truncated {
			roFlags = wasiRecvDataTruncated
		}
		binary.LittleEndian.PutUint16(flagsOut, roFlags)
		abi.putWord(lenOut, n)
		return _wasiESUCCESS
	}
	if !w.checkNet("recv") {
		return _wasiEACCES
	}
	op, conn, errno := w.socketConn(fd)
	if conn == nil {
		return errno
	}
	if !ok || lenOut == nil || flagsOut == nil {
		return _wasiEFAULT
	}
	n, errno, served := w.takeAhead("sock_recv", op, bufs)
	if !served {
		n, errno = w.readStream(m, "sock_recv", op, conn, bufs)
	}
	if errno = op.afterShutdown(errno, false); errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint16(flagsOut, 0)
	abi.putWord(lenOut, n)
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_send(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int32) int32 {
	return w.sockSend(m, wasiABI32, fd, zext(siData), zext(siDataLen), siFlags, zext(soDataLenPtr))
}

// Sock_send64 is Sock_send for a memory64 guest, whose si_data_len and
// so_datalen are __wasi_size_t.
func (w *WasiStubs) Sock_send64(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int64) int32 {
	return w.sockSend(m, wasiABI64, int32(fd), uint64(siData), uint64(siDataLen), int32(siFlags), uint64(soDataLenPtr))
}

// sockSend is the body of Sock_send and Sock_send64.
func (w *WasiStubs) sockSend(m *Module, abi wasiABI, fd int32, siData, siDataLen uint64, siFlags int32, soDataLenPtr uint64) int32 {
	w.endUnregistered()
	bufs, ok := w.iovecSlices(m, abi, siData, siDataLen)
	lenOut := w.memBytes(m, soDataLenPtr, abi.wordSize())
	if op, host, errno := w.socketOf(fd); errno == _wasiESUCCESS && host != nil {
		// a socket of the host's, sent on as send(2) sends: a send of
		// nothing sends an empty datagram
		if !ok || lenOut == nil {
			return _wasiEFAULT
		}
		n, errno := w.socketSend(m, "sock_send", op, host, bufs, siFlags, nil, "")
		if errno != _wasiESUCCESS {
			return w.signalBrokenPipe(m, errno, siFlags)
		}
		abi.putWord(lenOut, n)
		return _wasiESUCCESS
	}
	if !w.checkNet("send") {
		return _wasiEACCES
	}
	op, conn, errno := w.socketConn(fd)
	if errno == _wasiENOTCONN {
		// a send of a socket without a connection, as on linux
		return w.signalBrokenPipe(m, _wasiEPIPE, siFlags)
	}
	if conn == nil {
		return errno
	}
	if !ok || lenOut == nil {
		return _wasiEFAULT
	}
	// The send writes the stream as fd_write does.
	n, errno := w.writeFd(m, "sock_send", op, conn, bufs, siFlags)
	if errno = op.afterShutdown(errno, true); errno != _wasiESUCCESS {
		return w.signalBrokenPipe(m, errno, siFlags)
	}
	abi.putWord(lenOut, n)
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
	if host := op.hostSocket(); host != nil {
		// a socket of the host's, which the host shuts down as it says
		return w.shutdownSocket(host, how)
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
				return w.guestErrno("sock_shutdown", err)
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
			return w.guestErrno("sock_shutdown", err)
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
		return w.guestErrno("sock_shutdown", shErr)
	}
	return _wasiESUCCESS
}

// ----- sockets of every family ------------------------------------------------
//
// The imports of this section back the socket calls of a guest's C library
// for sockets of the IPv4, IPv6 and Unix domains, of stream and of datagram
// type. A socket has one socket of the host's, made when the guest makes
// the socket and closed when the guest closes its last slot, as gVisor's
// hostinet and wasi-go have it. The host socket is in non-blocking mode
// from its making on, as Go's package net and libuv keep theirs: no call
// of the runtime on it waits in the host, and the guest's O_NONBLOCK
// (fd_fdstat_set_flags) is the entry's alone (fdflags). A call of the
// guest that is to wait — a blocking accept, receive, send, or a connect
// that is not made at once — waits in poll(2) between attempts
// (socketWait), no longer than the socket's timeout, and a signal posted
// to the guest meanwhile ends it with EINTR. What the socket is — bound,
// listening, connecting, connected, shut down, the peer of a datagram
// socket, its options and timeouts — is the host's to know and to say:
// the runtime keeps only what the policies have allowed the socket
// (wasiSocket.reachable) and the names of a Unix-domain socket as the
// guest gave them.
//
// The imports name a socket address by a record in the guest's memory,
// whatever its family. The record is wasiSockAddrSize bytes, little-endian:
//
//	offset  0  u32       family (wasiSockFamily*; 0 where there is no address)
//	offset  4  u32       port, in host byte order (IP families)
//	offset  8  [16]byte  address: 4 bytes for IPv4, 16 for IPv6
//	offset 24  u32       scope id (IPv6)
//	offset 28  u32       length of the name (Unix)
//	offset 32  [108]byte name, as the guest gave it (Unix)
//
// The name of a Unix-domain socket is a path of the guest's, relative to its
// working directory, which the host does not know: where an import takes an
// address that may be one, it also takes the path as the filesystem imports
// do, relative to the preopened root. A name that starts with a NUL is an
// abstract name (Linux), which is no file.
const (
	wasiSockAddrSize    = 140
	wasiSockAddrNameMax = 108
)

// The address families of a socket and of an address record, as the guest's
// C library names them to the imports (a libc's AF_* numbers differ from
// libc to libc).
const (
	wasiSockFamilyIPv4 int32 = 1
	wasiSockFamilyUnix int32 = 2
	wasiSockFamilyIPv6 int32 = 3
)

// The socket types of Sock_open and Sock_socketpair.
const (
	wasiSockTypeStream int32 = 1
	wasiSockTypeDgram  int32 = 2
)

// wasiRecvDataTruncated is the ro_flags bit of a receive whose datagram was
// cut to the buffer (__WASI_ROFLAGS_RECV_DATA_TRUNCATED).
const wasiRecvDataTruncated uint16 = 1

// wasiSocket is what a socket entry has of its own. Guarded by the entry's
// mu.
type wasiSocket struct {
	// host is the socket of the host's, from the guest's socket() or
	// accept() to the close of its last slot (closeWasiOpen).
	host *os.File
	// reachable is set once the Listen policy has allowed others to reach
	// the socket at its local address: when it was bound, when it listened
	// without having been bound, or when a datagram socket sent to an
	// address without either (an implicit bind). It is never unset.
	reachable bool
	// unixLocal and unixPeer are the names of a Unix-domain socket and of
	// its peer as the guest gave them (bind, connect), which getsockname
	// and getpeername give back; empty for none given.
	unixLocal, unixPeer string
	// connecting is the connect(2) a goroutine makes in the host of a
	// socket in blocking mode (connectInTheHost), under way, or one whose
	// result no call has reported yet (takeHostConnect); nil for none.
	connecting *hostConnecting
}

// hostConnecting is a connect(2) a goroutine makes in the host
// (connectInTheHost): done is closed once it has returned, with errno that
// of the socket's Control (EBADF for a socket closed first) and err the
// connect's.
type hostConnecting struct {
	done  chan struct{}
	errno int32
	err   error
}

// hostSocket returns the host socket of the entry op, or nil for an entry
// without one: no socket, or a connection or listener of package net's.
func (op *wasiOpen) hostSocket() *os.File {
	if op == nil {
		return nil
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.sock == nil {
		return nil
	}
	return op.sock.host
}

// whenReady returns an attempt of socketWait for call, a call on a socket
// that is not to wait in the kernel (accept, a send that is not to wait,
// which darwin makes wait whatever MSG_DONTWAIT says). Where the guest's descriptors are the host's
// (hostFamily), the open file description of the socket is in the guest's
// mode, or in one code outside the guest set (hostMayBlock): in blocking
// mode, call (blocking true) is made by the holder of turn (awaitTurn) once
// poll(2) has found the socket ready for want, and is reported again
// otherwise, which socketWait then waits for without the turn. A signal
// posted to the guest while the call waits for the turn ends it with EINTR.
// A connection another process takes between the poll and the accept leaves
// the accept waiting in the kernel. Elsewhere, and in non-blocking mode,
// call is made as it is.
func (w *WasiStubs) whenReady(m *Module, turn chan struct{}, want int, call func(fd int, blocking bool) (bool, error)) func(fd int) (bool, error) {
	return func(fd int) (bool, error) {
		if !w.hostFamily() || !hostMayBlock(uintptr(fd)) {
			return call(fd, false)
		}
		if !w.awaitTurn(m, turn) {
			return false, syscall.EINTR
		}
		defer func() { <-turn }()
		ready := []bool{false}
		if err := hostWaitReady([]uintptr{uintptr(fd)}, []int{want}, ready, time.Now(), -1); err != nil {
			return false, err
		}
		if !ready[0] {
			return true, nil
		}
		return call(fd, true)
	}
}

// socketCall runs call on the descriptor of the host socket host. It
// reports EBADF for a host socket that was closed meanwhile, which is the
// one failure of Control. name is the import's name.
func (w *WasiStubs) socketCall(name string, host *os.File, call func(fd int)) int32 {
	rc, err := host.SyscallConn()
	if err != nil {
		return w.guestErrno(name, err)
	}
	if rc.Control(func(fd uintptr) { call(int(fd)) }) != nil {
		return _wasiEBADF
	}
	return _wasiESUCCESS
}

// network is the name of the socket's network as the policies are given it:
// "tcp", "udp", "unix" or "unixgram".
func (op *wasiOpen) network() string {
	switch {
	case op.family == wasiSockFamilyUnix && op.dgram:
		return "unixgram"
	case op.family == wasiSockFamilyUnix:
		return "unix"
	case op.dgram:
		return "udp"
	}
	return "tcp"
}

// socketOf returns the socket entry behind fd and its host socket, or the
// errno of a descriptor that is not open (EBADF) or not a socket
// (ENOTSOCK). host is nil for a socket entry of package net's.
func (w *WasiStubs) socketOf(fd int32) (op *wasiOpen, host *os.File, errno int32) {
	w.mu.Lock()
	op = w.openLocked(fd)
	w.mu.Unlock()
	switch {
	case op == nil && w.preopened(fd), op != nil && !op.socket():
		return nil, nil, _wasiENOTSOCK
	case op == nil:
		return nil, nil, _wasiEBADF
	}
	return op, op.hostSocket(), _wasiESUCCESS
}

// rawSocketOf is socketOf for the imports of this section, which only a
// socket of the host's takes: a connection or listener of package net's is
// ENOTSUP.
func (w *WasiStubs) rawSocketOf(fd int32) (*wasiOpen, *os.File, int32) {
	op, host, errno := w.socketOf(fd)
	if errno == _wasiESUCCESS && host == nil {
		return nil, nil, _wasiENOTSUP
	}
	return op, host, errno
}

// wasiSockAddr is a socket address of the guest's, read from or written to
// an address record.
type wasiSockAddr struct {
	family int32
	ip     net.IP // 4 bytes for IPv4, 16 for IPv6
	port   int
	scope  uint32
	name   string // of a Unix-domain socket, as the guest knows it
}

// readSockAddr reads the address record at ptr; one of family 0 is no
// address (AF_UNSPEC). It reports an errno: EFAULT, EAFNOSUPPORT for a
// family the host has no sockets of, EINVAL for a record that is not well
// formed.
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
	case 0:
		// AF_UNSPEC: no address
	default:
		return a, _wasiEAFNOSUPPORT
	}
	return a, _wasiESUCCESS
}

// readSockPath reads the path that accompanies an address record (see the
// head of this section); ok is false when it is not readable.
func (w *WasiStubs) readSockPath(m *Module, ptr uint64, n int32) (path string, ok bool) {
	b := w.memBytes(m, ptr, zext(n))
	if b == nil && n != 0 {
		return "", false
	}
	return string(b), true
}

// writeSockAddr writes a at ptr as an address record. Returns 0 or a
// negative errno.
func (w *WasiStubs) writeSockAddr(m *Module, ptr uint64, a wasiSockAddr) int32 {
	rec := w.memBytes(m, ptr, wasiSockAddrSize)
	if rec == nil {
		return -_wasiEFAULT
	}
	clear(rec)
	binary.LittleEndian.PutUint32(rec[0:], uint32(a.family))
	switch a.family {
	case wasiSockFamilyUnix:
		if len(a.name) > wasiSockAddrNameMax {
			return -_wasiENAMETOOLONG
		}
		binary.LittleEndian.PutUint32(rec[28:], uint32(len(a.name)))
		copy(rec[32:], a.name)
	case wasiSockFamilyIPv4:
		binary.LittleEndian.PutUint32(rec[4:], uint32(a.port))
		copy(rec[8:12], a.ip.To4())
	case wasiSockFamilyIPv6:
		binary.LittleEndian.PutUint32(rec[4:], uint32(a.port))
		copy(rec[8:24], a.ip.To16())
		binary.LittleEndian.PutUint32(rec[24:], a.scope)
	}
	return _wasiESUCCESS
}

// ipText renders the IP address, with the zone of a link-local IPv6 one as
// the index of its interface, which package net takes: what the policies
// are asked about, and what resolved host names are remembered under. An
// IPv4-mapped or global address has no zone.
func (a wasiSockAddr) ipText() string {
	addr := net.IPAddr{IP: a.ip}
	if a.ip.To4() == nil && (a.ip.IsLinkLocalUnicast() || a.ip.IsLinkLocalMulticast()) {
		addr.Zone = a.ipZone()
	}
	return addr.String()
}

// ipZone is the zone of an IPv6 address as package net takes it: the index
// of its interface, in text.
func (a wasiSockAddr) ipZone() string {
	if a.scope == 0 || a.family != wasiSockFamilyIPv6 {
		return ""
	}
	return strconv.FormatUint(uint64(a.scope), 10)
}

// hostPort renders an IP address and port for package net.
func (a wasiSockAddr) hostPort() string {
	return net.JoinHostPort(a.ipText(), strconv.Itoa(a.port))
}

// unixHostPath returns the host's name for the Unix-domain address a, whose
// name is path relative to the preopened root: the path of its file in the
// whole host filesystem, or an abstract name as package syscall writes it
// ("@name"). It reports an
// errno: ENOTSUP when the instance's FS is no HostRootFS (of HostFS's, only
// the whole host filesystem's, HostFS("/"), is one), whose files alone the
// host can bind sockets in by their names, and for an abstract name on a
// host without them.
func (w *WasiStubs) unixHostPath(a wasiSockAddr, path string) (string, int32) {
	switch {
	case a.name == "" || path == "" && a.name[0] != 0:
		return "", _wasiEINVAL
	case a.name[0] == 0:
		if !hostAbstractSockets {
			return "", _wasiENOTSUP
		}
		return "@" + a.name[1:], _wasiESUCCESS
	}
	fsys, isHost := w.cfg.FS.(HostRootFS)
	if !isHost {
		return "", _wasiENOTSUP
	}
	name, errno := w.guestName(path)
	if errno != _wasiESUCCESS {
		return "", errno
	}
	return hostPathIn(fsys.HostRoot(), name), _wasiESUCCESS
}

// hostPathIn returns the host's path of name, a name guestName gave, of a
// HostRootFS whose HostRoot is root: under root, with the trailing "/" of
// name, which filepath.Join would drop.
func hostPathIn(root, name string) string {
	p := filepath.Join(root, filepath.FromSlash(name))
	if strings.HasSuffix(name, "/") {
		p += string(filepath.Separator)
	}
	return p
}

// guestPathOf returns the absolute guest path that names the host's file
// at the absolute path p in fsys, and whether there is one: whether p is
// under fsys.HostRoot().
func guestPathOf(fsys HostRootFS, p string) (string, bool) {
	rel, err := filepath.Rel(fsys.HostRoot(), p)
	if err != nil || !filepath.IsLocal(rel) {
		// Rel fails only for a p it cannot make relative to the root:
		// one that is not under it either.
		return "", false
	}
	return guestPath(filepath.ToSlash(rel)), true
}

// unixGuestName returns the name the guest knows the Unix-domain address of
// the host's path by: the path, which is the guest's own in the whole host
// filesystem, or an abstract name with its leading NUL. An address without
// a name has none (package syscall writes the one of Linux as "@").
func unixGuestName(path string) string {
	switch {
	case path == "" || path == "@":
		return ""
	case hostAbstractSockets && path[0] == '@':
		return "\x00" + path[1:]
	}
	return path
}

// listenAllowed asks the Listen policy whether the socket op may take the
// local address (see WASIConfig.Listen).
func (w *WasiStubs) listenAllowed(op *wasiOpen, address string) bool {
	hook := w.cfg.Listen
	return hook != nil && hook(op.network(), address)
}

// allowReachable asks the Listen policy, once for the socket op, whether
// others may reach it at its local address. binds says that the call about
// to be made binds a socket that is not bound (the listen of a stream
// socket, the first send to an address of a datagram socket); without, the
// call leaves the socket reachable only where it is bound already (the
// dissolving of a datagram socket's association, connect with AF_UNSPEC,
// which leaves a port the host picked bound on some hosts). The address is
// the socket's, or the unspecified one of its family with port 0 for one
// the call binds. A Unix-domain socket that was not bound has no name to be
// reached at. Returns 0, EACCES when the policy refuses, or the errno of
// asking the host for the address.
func (w *WasiStubs) allowReachable(call string, op *wasiOpen, host *os.File, binds bool) int32 {
	op.mu.Lock()
	reachable := op.sock.reachable
	op.mu.Unlock()
	if reachable || op.family == wasiSockFamilyUnix {
		return _wasiESUCCESS
	}
	var local wasiSockAddr
	var failed error
	if errno := w.socketCall(call, host, func(fd int) { local, failed = hostSocketName(fd, false) }); errno != _wasiESUCCESS {
		return errno
	}
	if failed != nil {
		return w.guestErrno(call, failed)
	}
	if local.port == 0 {
		if !binds {
			return _wasiESUCCESS
		}
		local = wasiSockAddr{family: op.family, ip: net.IPv4zero.To4()}
		if op.family == wasiSockFamilyIPv6 {
			local.ip = net.IPv6zero
		}
	}
	if !w.listenAllowed(op, local.hostPort()) {
		return _wasiEACCES
	}
	op.mu.Lock()
	op.sock.reachable = true
	op.mu.Unlock()
	return _wasiESUCCESS
}

// destination asks the Dial policy about the address a the socket op is to
// connect or send to, with the path of a Unix-domain one (see
// unixHostPath), and returns the host's name of a Unix-domain address.
// Returns an errno: EACCES when the policy refuses.
func (w *WasiStubs) destination(op *wasiOpen, a wasiSockAddr, path string) (string, int32) {
	hook := w.cfg.Dial
	network := op.network()
	if a.family == wasiSockFamilyUnix {
		hostPath, errno := w.unixHostPath(a, path)
		if errno != _wasiESUCCESS {
			return "", errno
		}
		if hook == nil || !hook(network, "", hostPath, 0) {
			return "", _wasiEACCES
		}
		return hostPath, _wasiESUCCESS
	}
	if !w.dialAllowed(network, a.ipText(), a.port) {
		return "", _wasiEACCES
	}
	return "", _wasiESUCCESS
}

// socketWait makes attempt on the host socket host of op until it no
// longer reports that it would have to wait (again), as gVisor's hostinet
// and Go's internal/poll do: a call that does not wait (nonblocking) makes
// it once and reports EAGAIN when it would. A blocking one waits in poll(2)
// for what want names (hostWant...) between attempts, and a signal posted
// to the guest meanwhile ends the wait with EINTR. It waits no longer than
// the socket's timeout, which it reads at its first wait, as gVisor fixes
// a call's deadline once: the receive timeout (SO_RCVTIMEO) for input or a
// connection, the send timeout (SO_SNDTIMEO) for room; once that has passed
// it reports expired. A host socket closed meanwhile is EBADF. Returns the
// errno of the attempt that did not have to wait. call is the import's
// name.
func (w *WasiStubs) socketWait(m *Module, call string, op *wasiOpen, host *os.File, want int, nonblocking bool, expired int32, attempt func(fd int) (again bool, err error)) int32 {
	waited := false
	var until time.Time
	for {
		var again bool
		var failed error
		if errno := w.socketCall(call, host, func(fd int) { again, failed = attempt(fd) }); errno != _wasiESUCCESS {
			return errno
		}
		switch {
		case !again:
			return w.guestErrno(call, failed)
		case nonblocking:
			return _wasiEAGAIN
		case waited && !until.IsZero() && !time.Now().Before(until):
			return expired
		case !waited:
			var timeout time.Duration
			if errno := w.socketCall(call, host, func(fd int) { timeout, failed = hostSocketTimeout(fd, want == hostWantRoom) }); errno != _wasiESUCCESS {
				return errno
			}
			if failed != nil {
				return w.guestErrno(call, failed)
			}
			if timeout > 0 {
				until = time.Now().Add(timeout)
			}
			waited = true
		}
		set := []hostWaitFD{{stream: host, want: want, op: op}}
		interrupted, err := w.waitHostInterruptibly(m, call, set, until)
		if err != nil {
			return w.guestErrno(call, err)
		}
		if interrupted {
			return _wasiEINTR
		}
	}
}

// The flags of a socket receive (Sock_recv's ri_flags, and the flags of
// Sock_recvfrom_addr) besides wasiMsgDontWait, in WASI's numbering, which
// the guest's C library maps MSG_* to.
const (
	wasiMsgPeek    int32 = 1 // what is received stays where it is
	wasiMsgWaitAll int32 = 2 // wait until the buffer is full
)

// receiveAhead receives into bufs, for the socket op, the input a command
// was given of it and did not read (giveAhead), which comes before what the
// socket has, and returns how much: none when there is none. A receive with
// peek leaves it there.
func (op *wasiOpen) receiveAhead(bufs [][]byte, peek bool) uint64 {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.copyAheadLocked(bufs, peek)
}

// socketReceive receives into bufs from the socket op, whose host socket
// is host, as recv(2) does: once, a datagram cut to the buffers
// (truncated), or, for a stream socket with wasiMsgWaitAll, until the
// buffers are full or the stream ends. One with wasiMsgPeek as well looks
// at what has arrived once something has: poll(2) does not tell when more
// has (what is there keeps the socket readable). flags are the receive's
// (wasiMsg...). A receive that waits for more and is ended by a signal
// after receiving something reports what it received. The NetAccess
// policy is asked first ("recv"). call is the import's name.
func (w *WasiStubs) socketReceive(m *Module, call string, op *wasiOpen, host *os.File, bufs [][]byte, flags int32) (n uint64, truncated bool, errno int32) {
	if !w.checkNet("recv") {
		return 0, false, _wasiEACCES
	}
	size := 0
	for _, b := range bufs {
		size += len(b)
	}
	peek := flags&wasiMsgPeek != 0
	waitAll := flags&wasiMsgWaitAll != 0 && !op.dgram && !peek
	got := 0
	nonblocking := op.nonblocking() || flags&wasiMsgDontWait != 0
	errno = w.socketWait(m, call, op, host, hostWantInput, nonblocking, _wasiEAGAIN, func(fd int) (bool, error) {
		start := got
		if peek {
			start = 0
		}
		// Input a command left of the socket comes first, and wakes the
		// wait when it comes meanwhile (giveAhead); one that waits for all
		// goes on to the socket for the rest.
		if k := int(op.receiveAhead(leadingFrom(bufs, start), peek)); k > 0 {
			got = start + k
			if !waitAll || got == size {
				return false, nil
			}
			start = got
		}
		k, cut, again, err := hostReceive(fd, leadingFrom(bufs, start), peek)
		if err != nil || again {
			return again, err
		}
		if peek {
			got = k
		} else {
			got += k
		}
		truncated = cut
		// One that waits for all waits again while the stream goes on,
		// for input that makes the socket readable again.
		return waitAll && k > 0 && got < size, nil
	})
	if got > 0 && errno != _wasiESUCCESS {
		if errno == _wasiEINTR {
			w.keepInterrupt(m)
		}
		errno = _wasiESUCCESS
	}
	return uint64(got), truncated, errno
}

// socketSend sends bufs on the socket op, whose host socket is host, as
// send(2) does: a datagram whole, and on a stream socket that waits, all
// of it, waiting for room. to is the address of a datagram socket's send to
// one (nil for its peer), with hostPath the host's name of a Unix-domain
// one. A send that is ended by a signal after sending something reports
// what it sent. The NetAccess policy is asked first
// ("send"). call is the import's name.
func (w *WasiStubs) socketSend(m *Module, call string, op *wasiOpen, host *os.File, bufs [][]byte, flags int32, to *wasiSockAddr, hostPath string) (uint64, int32) {
	if !w.checkNet("send") {
		return 0, _wasiEACCES
	}
	size := 0
	for _, b := range bufs {
		size += len(b)
	}
	// No event tells that the receiver of a Unix-domain datagram sent to
	// an address has room again: poll(2) reports room on the sender. Such
	// a send does not wait, where Linux would.
	nonblocking := op.nonblocking() || flags&wasiMsgDontWait != 0 || op.family == wasiSockFamilyUnix && op.dgram && to != nil
	sent := 0
	send := func(fd int, blocking bool) (bool, error) {
		rest := leadingFrom(bufs, sent)
		if blocking && !op.dgram {
			// what a stream socket poll(2) reports writable takes
			lowat, err := op.streamSendLowat(host, uintptr(fd))
			if err != nil {
				return false, err
			}
			rest = leadingBytes(rest, lowat)
		}
		k, again, err := hostSend(fd, rest, to, hostPath)
		if err != nil || again {
			return again, err
		}
		sent += k
		// A stream socket that waits sends the rest once there is room.
		return !op.dgram && sent < size, nil
	}
	attempt := func(fd int) (bool, error) { return send(fd, false) }
	if !hostSendsWithoutWaiting && nonblocking {
		// MSG_DONTWAIT does not keep the send from waiting here: a send that
		// is not to wait is made once poll(2) has found room. One that waits
		// is made as it is, and waits in the kernel on a description in
		// blocking mode, where a signal does not end it.
		attempt = w.whenReady(m, op.outputTurn(), hostWantRoom, send)
	}
	errno := w.socketWait(m, call, op, host, hostWantRoom, nonblocking, _wasiEAGAIN, attempt)
	if sent > 0 && errno != _wasiESUCCESS {
		if errno == _wasiEINTR {
			w.keepInterrupt(m)
		}
		errno = _wasiESUCCESS
	}
	return uint64(sent), errno
}

// leadingFrom returns bufs past their first skip bytes.
func leadingFrom(bufs [][]byte, skip int) [][]byte {
	out := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if skip >= len(b) {
			skip -= len(b)
			continue
		}
		out, skip = append(out, b[skip:]), 0
	}
	return out
}

// Sock_open is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_open") backing socket(): a socket of the family
// (wasiSockFamily*) and type (wasiSockType*), with its socket of the host's.
// Returns the new fd, or a negative errno: EAFNOSUPPORT for a family the
// runtime has no sockets of, EINVAL for an unknown type, ENOTSUP on a host
// whose sockets the runtime does not make, and the host's for a socket it
// does not make.
func (w *WasiStubs) Sock_open(m *Module, family, typ int32) int32 {
	switch {
	case family != wasiSockFamilyIPv4 && family != wasiSockFamilyIPv6 && family != wasiSockFamilyUnix:
		return -_wasiEAFNOSUPPORT
	case typ != wasiSockTypeStream && typ != wasiSockTypeDgram:
		return -_wasiEINVAL
	case !hostOpensSockets:
		return -_wasiENOTSUP
	}
	return w.openSocketEntry(family, typ == wasiSockTypeDgram)
}

// Sock_open64 is Sock_open for a memory64 guest.
func (w *WasiStubs) Sock_open64(m *Module, family, typ int32) int32 {
	return w.Sock_open(m, family, typ)
}

// openSocketEntry makes a socket of the host's of the family and type and
// gives the guest a slot for it. Returns the fd, or a negative errno.
func (w *WasiStubs) openSocketEntry(family int32, dgram bool) int32 {
	host, err := runtimeFile(func() (*os.File, error) {
		f, err := openHostSocket(family, dgram)
		if err != nil {
			return nil, err
		}
		return w.guestFile(f, false)
	})
	if err != nil {
		return -w.guestErrno("sock_open", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return negativeFD(w.addFDLocked(&wasiOpen{isSocket: true, family: family, dgram: dgram, sock: &wasiSocket{host: host}}))
}

// Sock_bind_addr is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_bind_addr") backing bind(): the socket
// takes the local address in the record at addrPtr, with the path at
// (pathPtr, pathLen) for a Unix-domain one (see the head of this section).
// The Listen policy is asked first, of a datagram socket too. Returns 0 or
// a negative errno: EACCES when the policy refuses, and the host's.
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
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if a.family == 0 {
		// no address to take, as Linux refuses one of AF_UNSPEC
		return -_wasiEINVAL
	}
	address, hostPath := "", ""
	if a.family == wasiSockFamilyUnix {
		if hostPath, errno = w.unixHostPath(a, path); errno != _wasiESUCCESS {
			return -errno
		}
		address = hostPath
	} else {
		address = a.hostPort()
	}
	if !w.listenAllowed(op, address) {
		return -_wasiEACCES
	}
	var failed error
	if errno := w.socketCall("sock_bind_addr", host, func(fd int) { failed = hostBind(fd, a, hostPath) }); errno != _wasiESUCCESS {
		return -errno
	}
	if failed != nil {
		return -w.guestErrno("sock_bind_addr", failed)
	}
	op.mu.Lock()
	op.sock.reachable = true
	if a.family == wasiSockFamilyUnix {
		op.sock.unixLocal = a.name
	}
	op.mu.Unlock()
	return _wasiESUCCESS
}

// Sock_listen is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_listen") backing listen(): the socket takes connections, at
// most backlog waiting. The host binds a socket of an IP family that was
// not bound, which the Listen policy is asked about first (see
// allowReachable). Returns 0 or a negative errno: EACCES when the policy
// refuses, and the host's.
func (w *WasiStubs) Sock_listen(m *Module, fd, backlog int32) int32 {
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if errno := w.allowReachable("sock_listen", op, host, true); errno != _wasiESUCCESS {
		return -errno
	}
	var failed error
	if errno := w.socketCall("sock_listen", host, func(fd int) { failed = hostListen(fd, int(backlog)) }); errno != _wasiESUCCESS {
		return -errno
	}
	return -w.guestErrno("sock_listen", failed)
}

// Sock_listen64 is Sock_listen for a memory64 guest.
func (w *WasiStubs) Sock_listen64(m *Module, fd, backlog int32) int32 {
	return w.Sock_listen(m, fd, backlog)
}

// acceptSocket accepts a connection on the socket op, whose host socket is
// host, as accept(2) does, giving it a slot with fdflags: a non-blocking
// socket takes one that is waiting and reports EAGAIN when there is none;
// a blocking one waits in poll(2) for one (socketWait). accept(2) of a
// socket that does not listen fails at once, with the host's errno. The NetAccess policy is asked first ("accept"). Returns
// the new fd and an errno.
func (w *WasiStubs) acceptSocket(m *Module, op *wasiOpen, host *os.File, fdflags int32) (int32, int32) {
	if !w.checkNet("accept") {
		return 0, _wasiEACCES
	}
	conn := -1
	errno := w.socketWait(m, "sock_accept", op, host, hostWantInput, op.nonblocking(), _wasiEAGAIN, w.whenReady(m, op.inputTurn(), hostWantInput, func(fd int, blocking bool) (bool, error) {
		var again bool
		var err error
		conn, again, err = hostAccept(fd)
		return again, err
	}))
	if errno != _wasiESUCCESS {
		return 0, errno
	}
	return w.addAccepted(op, conn, fdflags)
}

// addAccepted gives conn, a connection accepted on the socket op, a slot
// with fdflags. Returns the new fd and an errno.
func (w *WasiStubs) addAccepted(op *wasiOpen, conn int, fdflags int32) (int32, int32) {
	if err := w.acceptedMode(conn, fdflags); err != nil {
		return 0, w.guestErrno("sock_accept", errors.Join(err, hostCloseFD(conn)))
	}
	host := os.NewFile(uintptr(conn), "socket")
	op.mu.Lock()
	accepted := &wasiOpen{isSocket: true, family: op.family, dgram: op.dgram, fdflags: fdflags, sock: &wasiSocket{
		host:      host,
		unixLocal: op.sock.unixLocal,
	}}
	op.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(accepted)
}

// Sock_connect_addr is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_connect_addr") backing connect() for a
// socket of any family: it connects the socket to the address in the record
// at addrPtr, with the path at (pathPtr, pathLen) for a Unix-domain one (see
// the head of this section), after asking the Dial policy. A record of
// family 0 (AF_UNSPEC) is given to the host as it is: it dissolves the
// association of a datagram socket, after asking the Listen policy about
// what the socket may be left reachable at (allowReachable), and of a
// stream socket what the host says. A connection that is not made at once
// is waited for, as Go's package net waits for one: until the socket is
// writable, then SO_ERROR and the peer tell how it ended; a non-blocking
// socket gets EINPROGRESS, and a signal ends the wait of a blocking one
// with EINTR while the attempt goes on in the host, as a connect(2)
// interrupted by a signal has it. Returns 0 or a negative errno: EACCES
// when a policy refuses, and the host's.
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
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	return -w.connectSocket(m, "sock_connect_addr", op, host, a, path)
}

// connectSocket connects the socket op, whose host socket is host, to the
// address a (see Sock_connect_addr). call is the import's name. It reports
// an errno.
func (w *WasiStubs) connectSocket(m *Module, call string, op *wasiOpen, host *os.File, a wasiSockAddr, path string) int32 {
	if errno, ok := w.takeHostConnect(call, op, false); ok {
		return errno
	}
	hostPath := ""
	if a.family == 0 {
		if op.dgram {
			if errno := w.allowReachable(call, op, host, false); errno != _wasiESUCCESS {
				return errno
			}
		}
	} else {
		var errno int32
		if hostPath, errno = w.destination(op, a, path); errno != _wasiESUCCESS {
			return errno
		}
	}
	var started error
	var blocking bool
	if errno := w.socketCall(call, host, func(fd int) {
		if blocking = w.hostFamily() && !op.dgram && hostMayBlock(uintptr(fd)); !blocking {
			started = hostConnect(fd, a, hostPath)
		}
	}); errno != _wasiESUCCESS {
		return errno
	}
	if blocking {
		if errno := w.connectInTheHost(m, call, op, host, a, hostPath, &started); errno != _wasiESUCCESS {
			return errno
		}
	}
	underWay := connectUnderWay(started)
	if (started == nil || underWay) && a.family == wasiSockFamilyUnix {
		// getpeername asks the host first: the name is the peer's once
		// the host has a peer.
		op.mu.Lock()
		op.sock.unixPeer = a.name
		op.mu.Unlock()
	}
	if !underWay || op.nonblocking() || blocking {
		return w.guestErrno(call, started)
	}
	if errno := w.socketWait(m, call, op, host, hostWantRoom, false, _wasiEINPROGRESS, hostConnectDone); errno != _wasiESUCCESS {
		return errno
	}
	// The host takes the socket for connected, and refuses a later connect
	// of it (EISCONN), once a connect has reported the connection made, as
	// a blocking connect(2) reports it: the connect that waited does so
	// here, as gVisor's hostinet connects again (Linux reports the
	// connection made with 0, darwin with EISCONN).
	var made error
	if errno := w.socketCall(call, host, func(fd int) { made = hostConnect(fd, a, hostPath) }); errno != _wasiESUCCESS {
		return errno
	}
	if errors.Is(made, syscall.EISCONN) {
		return _wasiESUCCESS
	}
	return w.guestErrno(call, made)
}

// connectInTheHost is the connect(2) of a stream socket whose open file
// description is in blocking mode, which waits in the host until the
// connection is made or fails, where the guest's descriptors are the host's
// (hostFamily): a goroutine of its own makes it, holding the socket until it
// returns (socketCall), and the guest's call waits for it as a blocking call
// (blockingAttempt). A signal posted to the guest meanwhile ends the call
// with EINTR while the connect goes on in the host, as one interrupted by a
// signal does; a connect of the socket while it is under way waits for it
// too, or is EALREADY for a socket the guest set non-blocking; one after
// it returned reports its result, once, but for one the host goes on with
// (connectUnderWay), as the connect that waited would have (the host's connect of a connected socket can wait for the
// listener's room before it tells EISCONN, Linux's AF_UNIX), and
// getsockopt(SO_ERROR) reports a failure, which the host's connect took
// from the socket, in its place (takeHostConnect). *started is
// what the guest's connect reports: the connect's result, EINPROGRESS for
// a socket the guest set non-blocking, or EINTR. The host closes a socket
// the guest closes meanwhile once the connect has returned.
func (w *WasiStubs) connectInTheHost(m *Module, call string, op *wasiOpen, host *os.File, a wasiSockAddr, hostPath string, started *error) int32 {
	op.mu.Lock()
	c := op.sock.connecting
	nonblocking := op.fdflags&wasiFdflagNonblock != 0
	if c != nil && closed(c.done) {
		// returned, which no call has reported yet
		op.sock.connecting = nil
		op.mu.Unlock()
		*started = c.err
		return c.errno
	}
	if c == nil {
		c = &hostConnecting{done: make(chan struct{})}
		op.sock.connecting = c
		go func() {
			c.errno = w.socketCall(call, host, func(fd int) { c.err = hostConnect(fd, a, hostPath) })
			op.mu.Lock()
			if c.errno == _wasiESUCCESS && connectUnderWay(c.err) {
				// no result: a later connect asks the host itself
				op.sock.connecting = nil
			}
			close(c.done)
			op.mu.Unlock()
		}()
	} else if nonblocking {
		op.mu.Unlock()
		*started = syscall.EALREADY
		return _wasiESUCCESS
	}
	op.mu.Unlock()
	if nonblocking {
		*started = syscall.EINPROGRESS
		return _wasiESUCCESS
	}
	interrupted, _, refused := w.blockingAttempt(m, func() {}, nil, func(stop <-chan struct{}) {
		select {
		case <-c.done:
		case <-stop:
		}
	})
	if interrupted || refused {
		*started = syscall.EINTR
		return _wasiESUCCESS
	}
	op.mu.Lock()
	if op.sock.connecting == c {
		op.sock.connecting = nil // reported
	}
	op.mu.Unlock()
	*started = c.err
	return c.errno
}

// closed reports whether done has been closed.
func closed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// connectUnderWay reports whether err, of a connect of the host's, is one
// the host goes on with: not made at once (EINPROGRESS), or interrupted in
// the host (EINTR) or under way already (EALREADY).
func connectUnderWay(err error) bool {
	return errors.Is(err, syscall.EINPROGRESS) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EALREADY)
}

// takeHostConnect reports the result of the connect a goroutine made in the
// host of the socket op (connectInTheHost) that returned and that no call
// has reported yet, with failed only a failure, as call's errno, and
// forgets it; ok is false for none.
func (w *WasiStubs) takeHostConnect(call string, op *wasiOpen, failed bool) (errno int32, ok bool) {
	op.mu.Lock()
	c := op.sock.connecting
	if c == nil || !closed(c.done) || failed && c.errno == _wasiESUCCESS && c.err == nil {
		op.mu.Unlock()
		return 0, false
	}
	op.sock.connecting = nil
	op.mu.Unlock()
	if c.errno != _wasiESUCCESS {
		return c.errno, true
	}
	return w.guestErrno(call, c.err), true
}

// Sock_name is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_name") backing getsockname() (peer 0) and getpeername() (peer
// 1): the host's name of the socket, or of its peer, written as an address
// record at addrPtr. A Unix-domain socket's names are the ones the guest
// gave where it gave them. Returns 0 or a negative errno: the host's, such
// as ENOTCONN for the peer of a socket that has none.
func (w *WasiStubs) Sock_name(m *Module, fd, peer, addrPtr int32) int32 {
	return w.sockName(m, fd, peer, zext(addrPtr))
}

// Sock_name64 is Sock_name for a memory64 guest.
func (w *WasiStubs) Sock_name64(m *Module, fd, peer int32, addrPtr int64) int32 {
	return w.sockName(m, fd, peer, uint64(addrPtr))
}

// sockName is the body of Sock_name and Sock_name64.
func (w *WasiStubs) sockName(m *Module, fd, peer int32, addrPtr uint64) int32 {
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	var a wasiSockAddr
	var failed error
	if errno := w.socketCall("sock_name", host, func(fd int) { a, failed = hostSocketName(fd, peer != 0) }); errno != _wasiESUCCESS {
		return -errno
	}
	if failed != nil {
		return -w.guestErrno("sock_name", failed)
	}
	if a.family == wasiSockFamilyUnix {
		op.mu.Lock()
		given := op.sock.unixLocal
		if peer != 0 {
			given = op.sock.unixPeer
		}
		op.mu.Unlock()
		if given != "" {
			a.name = given
		}
	}
	return w.writeSockAddr(m, addrPtr, a)
}

// Sock_sendto_addr is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_sendto_addr") backing send() and
// sendto(): it sends (bufPtr, bufLen) on the socket fd, to the address in
// the record at addrPtr, with the path at (pathPtr, pathLen) for a
// Unix-domain one, or, for addrPtr 0, to the socket's peer, and writes the
// count sent (u32) at sentPtr. A datagram socket's send to an address asks
// the Dial policy about it, and the Listen policy about the socket's own
// address the first time it makes the host bind the socket (see
// allowReachable). flags are the send's (wasiMsgDontWait, wasiMsgNoSignal).
// Returns 0 or a negative errno: EACCES when a policy refuses, and the
// host's.
func (w *WasiStubs) Sock_sendto_addr(m *Module, fd, bufPtr, bufLen, flags, addrPtr, pathPtr, pathLen, sentPtr int32) int32 {
	return w.sockSendtoAddr(m, fd, zext(bufPtr), bufLen, flags, zext(addrPtr), zext(pathPtr), pathLen, zext(sentPtr))
}

// Sock_sendto_addr64 is Sock_sendto_addr for a memory64 guest.
func (w *WasiStubs) Sock_sendto_addr64(m *Module, fd int32, bufPtr int64, bufLen, flags int32, addrPtr, pathPtr int64, pathLen int32, sentPtr int64) int32 {
	return w.sockSendtoAddr(m, fd, uint64(bufPtr), bufLen, flags, uint64(addrPtr), uint64(pathPtr), pathLen, uint64(sentPtr))
}

// sockSendtoAddr is the body of Sock_sendto_addr and Sock_sendto_addr64.
func (w *WasiStubs) sockSendtoAddr(m *Module, fd int32, bufPtr uint64, bufLen, flags int32, addrPtr, pathPtr uint64, pathLen int32, sentPtr uint64) int32 {
	w.endUnregistered()
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, sentPtr, 4)
	if (buf == nil && bufLen != 0) || out == nil {
		return -_wasiEFAULT
	}
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	var to *wasiSockAddr
	hostPath := ""
	var a wasiSockAddr
	if addrPtr != 0 {
		if a, errno = w.readSockAddr(m, addrPtr); errno != _wasiESUCCESS {
			return -errno
		}
	}
	// A record of family 0 is no address: the send is to the peer.
	if addrPtr != 0 && a.family != 0 {
		path, ok := w.readSockPath(m, pathPtr, pathLen)
		if !ok {
			return -_wasiEFAULT
		}
		if op.dgram {
			if hostPath, errno = w.destination(op, a, path); errno != _wasiESUCCESS {
				return -errno
			}
			if errno := w.allowReachable("sock_sendto_addr", op, host, true); errno != _wasiESUCCESS {
				return -errno
			}
		} else if a.family == wasiSockFamilyUnix {
			// the host's to refuse (EISCONN, EOPNOTSUPP), which names no
			// file of the guest's
			hostPath = a.name
		}
		to = &a
	}
	n, errno := w.socketSend(m, "sock_sendto_addr", op, host, [][]byte{buf}, flags&wasiMsgDontWait, to, hostPath)
	binary.LittleEndian.PutUint32(out, uint32(n))
	return -w.signalBrokenPipe(m, errno, flags)
}

// Sock_recvfrom_addr is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_recvfrom_addr") backing recv() and
// recvfrom(): it receives into (bufPtr, bufLen) from the socket fd as
// recv(2) does (see socketReceive), writes the count received (u32) at
// receivedPtr and, unless addrPtr is 0 (NULL), the sender's address as a
// record at addrPtr: of family 0 where the host gives none, as for a stream
// socket. flags are the receive's (wasiMsgPeek, wasiMsgWaitAll,
// wasiMsgDontWait). Returns 0 or a negative errno: EAGAIN when nothing is
// there and the call does not wait, EINTR when a signal is posted to the
// guest while it waits, and the host's.
func (w *WasiStubs) Sock_recvfrom_addr(m *Module, fd, bufPtr, bufLen, flags, addrPtr, receivedPtr int32) int32 {
	return w.sockRecvfromAddr(m, fd, zext(bufPtr), bufLen, flags, zext(addrPtr), zext(receivedPtr))
}

// Sock_recvfrom_addr64 is Sock_recvfrom_addr for a memory64 guest.
func (w *WasiStubs) Sock_recvfrom_addr64(m *Module, fd int32, bufPtr int64, bufLen, flags int32, addrPtr, receivedPtr int64) int32 {
	return w.sockRecvfromAddr(m, fd, uint64(bufPtr), bufLen, flags, uint64(addrPtr), uint64(receivedPtr))
}

// sockRecvfromAddr is the body of Sock_recvfrom_addr and
// Sock_recvfrom_addr64.
func (w *WasiStubs) sockRecvfromAddr(m *Module, fd int32, bufPtr uint64, bufLen, flags int32, addrPtr, receivedPtr uint64) int32 {
	w.endUnregistered()
	buf := w.memBytes(m, bufPtr, zext(bufLen))
	out := w.memBytes(m, receivedPtr, 4)
	if (buf == nil && bufLen != 0) || out == nil || (addrPtr != 0 && w.memBytes(m, addrPtr, wasiSockAddrSize) == nil) {
		return -_wasiEFAULT
	}
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if addrPtr == 0 || !op.dgram {
		// A stream socket's sender is its peer, which recvfrom(2) names
		// not (family 0).
		n, _, errno := w.socketReceive(m, "sock_recvfrom_addr", op, host, [][]byte{buf}, flags)
		if errno != _wasiESUCCESS {
			return -errno
		}
		binary.LittleEndian.PutUint32(out, uint32(n))
		if addrPtr == 0 {
			return _wasiESUCCESS
		}
		return w.writeSockAddr(m, addrPtr, wasiSockAddr{})
	}
	if !w.checkNet("recv") {
		return -_wasiEACCES
	}
	var from wasiSockAddr
	n := 0
	errno = w.socketWait(m, "sock_recvfrom_addr", op, host, hostWantInput, op.nonblocking() || flags&wasiMsgDontWait != 0, _wasiEAGAIN, func(fd int) (bool, error) {
		var again bool
		var err error
		n, from, again, err = hostReceiveFrom(fd, buf, flags&wasiMsgPeek != 0)
		return again, err
	})
	if errno != _wasiESUCCESS {
		return -errno
	}
	binary.LittleEndian.PutUint32(out, uint32(n))
	return w.writeSockAddr(m, addrPtr, from)
}

// Sock_socketpair is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_socketpair") backing socketpair(): two
// Unix-domain sockets of the type (wasiSockType*) connected to each other,
// whose fds it writes (two u32) at fdsOutPtr. Returns 0 or a negative
// errno: EAFNOSUPPORT for a family other than Unix, ENOTSUP on a host whose
// sockets the runtime does not make, and the host's.
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
	switch {
	case out == nil:
		return -_wasiEFAULT
	case family != wasiSockFamilyUnix:
		return -_wasiEAFNOSUPPORT
	case typ != wasiSockTypeStream && typ != wasiSockTypeDgram:
		return -_wasiEINVAL
	case !hostOpensSockets:
		return -_wasiENOTSUP
	}
	dgram := typ == wasiSockTypeDgram
	var a, b *os.File
	if err := makeRuntimeDescriptors(func() error {
		var err error
		if a, b, err = hostSocketPair(dgram); err != nil {
			return err
		}
		if a, err = w.guestFile(a, false); err != nil {
			return errors.Join(err, b.Close())
		}
		if b, err = w.guestFile(b, false); err != nil {
			return errors.Join(err, a.Close())
		}
		return nil
	}); err != nil {
		return -w.guestErrno("sock_socketpair", err)
	}
	w.mu.Lock()
	afd, errno := w.addFDLocked(&wasiOpen{isSocket: true, family: wasiSockFamilyUnix, dgram: dgram, sock: &wasiSocket{host: a}})
	if errno != _wasiESUCCESS {
		w.mu.Unlock()
		w.reportError("sock_socketpair", b.Close())
		return -errno
	}
	bfd, errno := w.addFDLocked(&wasiOpen{isSocket: true, family: wasiSockFamilyUnix, dgram: dgram, sock: &wasiSocket{host: b}})
	if errno != _wasiESUCCESS {
		closing, err := w.clearSlotLocked(afd)
		w.mu.Unlock()
		w.reportError("sock_socketpair", errors.Join(err, closeWasiOpen(closing)))
		return -errno
	}
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out[0:], uint32(afd))
	binary.LittleEndian.PutUint32(out[4:], uint32(bfd))
	return _wasiESUCCESS
}

// The socket options of Sock_setopt and Sock_getopt, as the guest's C
// library names them to the imports (a libc's option numbers differ from
// libc to libc).
const (
	wasiSockOptReuseAddr int32 = 1  // SO_REUSEADDR
	wasiSockOptReusePort int32 = 2  // SO_REUSEPORT
	wasiSockOptKeepAlive int32 = 3  // SO_KEEPALIVE
	wasiSockOptNoDelay   int32 = 4  // TCP_NODELAY
	wasiSockOptRcvBuf    int32 = 5  // SO_RCVBUF
	wasiSockOptSndBuf    int32 = 6  // SO_SNDBUF
	wasiSockOptLinger    int32 = 7  // SO_LINGER: seconds, or -1 for off
	wasiSockOptError     int32 = 8  // SO_ERROR (read only): the guest's errno
	wasiSockOptType      int32 = 9  // SO_TYPE (read only): a wasiSockType
	wasiSockOptAccepting int32 = 10 // SO_ACCEPTCONN (read only)
	wasiSockOptV6Only    int32 = 11 // IPV6_V6ONLY
	wasiSockOptBroadcast int32 = 12 // SO_BROADCAST
	wasiSockOptDefer     int32 = 13 // TCP_DEFER_ACCEPT: seconds
)

// The two timeouts of a socket, as Sock_timeout names them.
const (
	wasiSockTimeoutReceive int32 = 1 // SO_RCVTIMEO
	wasiSockTimeoutSend    int32 = 2 // SO_SNDTIMEO
)

// Sock_setopt is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_setopt") backing setsockopt() for the options above: it sets
// the option of the socket fd's host socket to value, as setsockopt(2)
// does. Returns 0, or a negative errno: ENOPROTOOPT for an option that is
// unknown, or that the host has not, and the host's, such as ENOPROTOOPT
// for an option it only reads.
func (w *WasiStubs) Sock_setopt(m *Module, fd, option, value int32) int32 {
	_, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	var failed error
	if errno := w.socketCall("sock_setopt", host, func(fd int) { failed = setHostSockOpt(fd, option, value) }); errno != _wasiESUCCESS {
		return -errno
	}
	return -w.guestErrno("sock_setopt", failed)
}

// Sock_setopt64 is Sock_setopt for a memory64 guest.
func (w *WasiStubs) Sock_setopt64(m *Module, fd, option, value int32) int32 {
	return w.Sock_setopt(m, fd, option, value)
}

// Sock_getopt is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_getopt") backing getsockopt() for the options above: it
// writes the value of the option of the socket fd's host socket (i32) at
// valuePtr, as getsockopt(2) gives it (getHostSockOpt). Returns 0, or a
// negative errno as Sock_setopt does.
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
	op, host, errno := w.rawSocketOf(fd)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if option == wasiSockOptError {
		// a connect in the host took the socket's pending error
		if errno, failed := w.takeHostConnect("sock_getopt", op, true); failed {
			binary.LittleEndian.PutUint32(out, uint32(errno))
			return _wasiESUCCESS
		}
	}
	var value int32
	var failed error
	if errno := w.socketCall("sock_getopt", host, func(fd int) { value, failed = getHostSockOpt(fd, option) }); errno != _wasiESUCCESS {
		return -errno
	}
	if failed != nil {
		return -w.guestErrno("sock_getopt", failed)
	}
	if option == wasiSockOptError && value != 0 {
		// the host's number of the socket's pending error
		value = w.guestErrno("sock_getopt", syscall.Errno(value))
	}
	binary.LittleEndian.PutUint32(out, uint32(value))
	return _wasiESUCCESS
}

// Sock_timeout is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_timeout") backing SO_RCVTIMEO and SO_SNDTIMEO: which names the
// timeout (wasiSockTimeout...), which is the host socket's. The timeout
// before the call is written at oldPtr in nanoseconds (i64; 0 is no limit);
// when set is non-zero it is then replaced by nanos, in microseconds
// rounded up. A blocking receive or accept that has waited the receive
// timeout gives up with EAGAIN, as a blocking send does that has waited
// the send timeout, and a blocking connect with EINPROGRESS (socketWait).
// A connection accepted on the socket has its timeouts, as the host gives
// them. Returns 0, or a negative errno: EINVAL for another which or a
// negative time, and the host's.
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
	_, host, errno := w.rawSocketOf(fd)
	switch {
	case errno != _wasiESUCCESS:
		return -errno
	case which != wasiSockTimeoutReceive && which != wasiSockTimeoutSend, set != 0 && nanos < 0:
		return -_wasiEINVAL
	}
	send := which == wasiSockTimeoutSend
	var old time.Duration
	var failed error
	if errno := w.socketCall("sock_timeout", host, func(fd int) {
		if old, failed = hostSocketTimeout(fd, send); failed == nil && set != 0 {
			failed = setHostSocketTimeout(fd, send, time.Duration(nanos))
		}
	}); errno != _wasiESUCCESS {
		return -errno
	}
	if failed != nil {
		return -w.guestErrno("sock_timeout", failed)
	}
	binary.LittleEndian.PutUint64(out, uint64(old))
	return _wasiESUCCESS
}

// shutdownSocket shuts the halves how (Sock_shutdown's: 1 reading, 2
// writing) of the host socket host down. It reports an errno: the host's.
func (w *WasiStubs) shutdownSocket(host *os.File, how int32) int32 {
	var failed error
	if errno := w.socketCall("sock_shutdown", host, func(fd int) { failed = hostShutdown(fd, how) }); errno != _wasiESUCCESS {
		return errno
	}
	return w.guestErrno("sock_shutdown", failed)
}

// ----- name lookups -----------------------------------------------------------

// lookupInterruptibly runs lookup, a lookup of the host's resolver given a
// context, as a blocking call of the guest's: a signal posted to the guest
// meanwhile cancels the context and ends the call with EINTR, as WASIX's
// resolve does (glibc's getaddrinfo() goes on instead). It reports an
// errno (lookupErrno); call is the import's name.
func (w *WasiStubs) lookupInterruptibly(m *Module, call string, lookup func(ctx context.Context) error) int32 {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	interrupted, _, refused := w.blockingAttempt(m, cancel, nil, func(<-chan struct{}) { err = lookup(ctx) })
	switch {
	case refused, interrupted && err != nil:
		return _wasiEINTR
	case err != nil:
		return w.lookupErrno(call, err)
	case interrupted:
		// The lookup went through: the next call that waits reports the
		// signal.
		w.keepInterrupt(m)
	}
	return _wasiESUCCESS
}

// lookupErrno is the errno of a failed lookup of the host's resolver: ENOENT
// for a name or address it knows nothing of or a name with no address of the
// network's family (package net's *AddrError), EAGAIN for a failure that may
// pass (a time-out, a server that did not answer), and the error's own
// otherwise (guestErrno; call is the import's name).
func (w *WasiStubs) lookupErrno(call string, err error) int32 {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return _wasiENOENT
		case dnsErr.IsTimeout, dnsErr.IsTemporary:
			return _wasiEAGAIN
		}
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return _wasiENOENT
	}
	return w.guestErrno(call, err)
}

// resolveHost returns the addresses of host on network ("ip", "ip4", "ip6"), as
// the guest's getaddrinfo() asks for them. An address written in numbers
// (with the zone of an IPv6 one) is converted: it is no lookup, and the
// Resolve policy is not asked about it, as Go's net.Resolver looks up no
// literal either. A name is looked up by the host's resolver
// (lookupInterruptibly) once the policy allows it, and every address it
// has is remembered under host, which the Dial policy is told of a connect
// to it. It reports an errno: EACCES when the policy refuses, and the
// lookup's.
func (w *WasiStubs) resolveHost(m *Module, host, network string) ([]netip.Addr, int32) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, _wasiESUCCESS
	}
	if !w.resolveAllowed(host) {
		return nil, _wasiEACCES
	}
	var found []netip.Addr
	if errno := w.lookupInterruptibly(m, "sock_resolve", func(ctx context.Context) error {
		var err error
		found, err = net.DefaultResolver.LookupNetIP(ctx, network, host)
		return err
	}); errno != _wasiESUCCESS {
		return nil, errno
	}
	for i, a := range found {
		found[i] = a.Unmap()
		addr, err := sockAddrOf(found[i])
		if err != nil {
			return nil, w.guestErrno("sock_resolve", err)
		}
		w.recordResolvedHost(addr.ipText(), host)
	}
	return found, _wasiESUCCESS
}

// sockAddrOf is the guest's address of the IP address a, its zone the
// scope id (scopeOfZone).
func sockAddrOf(a netip.Addr) (wasiSockAddr, error) {
	if a.Is4() {
		return wasiSockAddr{family: wasiSockFamilyIPv4, ip: a.AsSlice()}, nil
	}
	scope, err := scopeOfZone(a.Zone())
	return wasiSockAddr{family: wasiSockFamilyIPv6, ip: a.AsSlice(), scope: scope}, err
}

// scopeOfZone returns the scope id of an IPv6 address whose zone package net
// gives as zone: an interface's index, or its name.
func scopeOfZone(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if strings.Trim(zone, "0123456789") == "" {
		// an interface's index
		n, err := strconv.ParseUint(zone, 10, 32)
		return uint32(n), err
	}
	ifc, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, err
	}
	return uint32(ifc.Index), nil
}

// resolveAllowed asks the Resolve policy whether host may be looked up.
func (w *WasiStubs) resolveAllowed(host string) bool {
	hook := w.cfg.Resolve
	return hook != nil && hook(host)
}

// Sock_resolve is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_resolve") backing getaddrinfo(): it resolves the host name at
// (nodePtr, nodeLen) to its addresses (resolveHost) of family
// (wasiSockFamilyIPv4, wasiSockFamilyIPv6, or 0 for both) and writes them
// as address records at outPtr, at most limit of them, IPv4 addresses
// first; their number goes to countPtr (u32). Returns 0, or a negative
// errno: ENOENT when the name has no address of the family, EACCES when the
// policy refuses, EAGAIN when the lookup may succeed later, EINTR when a
// signal ends it.
func (w *WasiStubs) Sock_resolve(m *Module, nodePtr, nodeLen, family, outPtr, limit, countPtr int32) int32 {
	return w.sockResolve(m, zext(nodePtr), nodeLen, family, zext(outPtr), limit, zext(countPtr))
}

// Sock_resolve64 is Sock_resolve for a memory64 guest.
func (w *WasiStubs) Sock_resolve64(m *Module, nodePtr int64, nodeLen, family int32, outPtr int64, limit int32, countPtr int64) int32 {
	return w.sockResolve(m, uint64(nodePtr), nodeLen, family, uint64(outPtr), limit, uint64(countPtr))
}

// sockResolve is the body of Sock_resolve and Sock_resolve64.
func (w *WasiStubs) sockResolve(m *Module, nodePtr uint64, nodeLen, family int32, outPtr uint64, limit int32, countPtr uint64) int32 {
	w.endUnregistered()
	node := w.memBytes(m, nodePtr, zext(nodeLen))
	count := w.memBytes(m, countPtr, 4)
	if (node == nil && nodeLen != 0) || count == nil || limit < 0 {
		return -_wasiEFAULT
	}
	if family != 0 && family != wasiSockFamilyIPv4 && family != wasiSockFamilyIPv6 {
		return -_wasiEAFNOSUPPORT
	}
	network := "ip"
	switch family {
	case wasiSockFamilyIPv4:
		network = "ip4"
	case wasiSockFamilyIPv6:
		network = "ip6"
	}
	found, errno := w.resolveHost(m, string(node), network)
	if errno != _wasiESUCCESS {
		return -errno
	}
	var n int32
	for _, want := range []int32{wasiSockFamilyIPv4, wasiSockFamilyIPv6} {
		if family != 0 && family != want {
			continue
		}
		for _, a := range found {
			if a.Is4() != (want == wasiSockFamilyIPv4) || n >= limit {
				continue
			}
			addr, err := sockAddrOf(a)
			if err != nil {
				return -w.guestErrno("sock_resolve", err)
			}
			if rc := w.writeSockAddr(m, outPtr+uint64(n)*wasiSockAddrSize, addr); rc != _wasiESUCCESS {
				return rc
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

// Sock_reverse_addr is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_reverse_addr") backing gethostbyaddr()
// and getnameinfo(): the name of the host that has the IP address in the
// address record at addrPtr, of either family, as the host's resolver knows
// it, written as a record (writeWasiRecord): the name, without a length
// prefix. The Resolve policy is asked about the address in text. Returns 0,
// or a negative errno: ENOENT when the address has no name, EACCES when the
// policy refuses, EAFNOSUPPORT for an address of no IP family, EAGAIN when
// the lookup may succeed later, EINTR when a signal ends it, ERANGE when
// the buffer is too small.
func (w *WasiStubs) Sock_reverse_addr(m *Module, addrPtr, bufPtr, bufLen, neededPtr int32) int32 {
	return w.sockReverseAddr(m, zext(addrPtr), zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_reverse_addr64 is Sock_reverse_addr for a memory64 guest.
func (w *WasiStubs) Sock_reverse_addr64(m *Module, addrPtr, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.sockReverseAddr(m, uint64(addrPtr), uint64(bufPtr), bufLen, uint64(neededPtr))
}

// sockReverseAddr is the body of Sock_reverse_addr and Sock_reverse_addr64.
func (w *WasiStubs) sockReverseAddr(m *Module, addrPtr, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	w.endUnregistered()
	a, errno := w.readSockAddr(m, addrPtr)
	if errno != _wasiESUCCESS {
		return -errno
	}
	if a.family != wasiSockFamilyIPv4 && a.family != wasiSockFamilyIPv6 {
		return -_wasiEAFNOSUPPORT
	}
	ip := a.ip.String()
	if !w.resolveAllowed(ip) {
		return -_wasiEACCES
	}
	var names []string
	if errno := w.lookupInterruptibly(m, "sock_reverse_addr", func(ctx context.Context) error {
		var err error
		names, err = net.DefaultResolver.LookupAddr(ctx, ip)
		return err
	}); errno != _wasiESUCCESS {
		return -errno
	}
	if len(names) == 0 {
		return -_wasiENOENT
	}
	// The resolver answers with a fully qualified name, which ends in the
	// root's dot; a host's name is written without it.
	return w.writeWasiRecord(m, []byte(strings.TrimSuffix(names[0], ".")), bufPtr, bufLen, neededPtr)
}

// Sock_host_by_name is a NON-STANDARD host import (module
// wasip1_posix_extension, name "sock_host_by_name") backing gethostbyname():
// the IPv4 addresses of the host named at (nodePtr, nodeLen) (resolveHost),
// and its official name, which is the name asked about. The record
// (writeWasiRecord) is the number of addresses (u32), the addresses (4
// bytes each, as they sit in s_addr), then the official name. Returns 0, or
// a negative errno: ENOENT when the name has no IPv4 address, EACCES when
// the policy refuses, EAGAIN when the lookup may succeed later, EINTR when
// a signal ends it, ERANGE when the buffer is too small.
func (w *WasiStubs) Sock_host_by_name(m *Module, nodePtr, nodeLen, bufPtr, bufLen, neededPtr int32) int32 {
	return w.sockHostByName(m, zext(nodePtr), nodeLen, zext(bufPtr), bufLen, zext(neededPtr))
}

// Sock_host_by_name64 is Sock_host_by_name for a memory64 guest.
func (w *WasiStubs) Sock_host_by_name64(m *Module, nodePtr int64, nodeLen int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.sockHostByName(m, uint64(nodePtr), nodeLen, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// sockHostByName is the body of Sock_host_by_name and Sock_host_by_name64.
func (w *WasiStubs) sockHostByName(m *Module, nodePtr uint64, nodeLen int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	w.endUnregistered()
	node := w.memBytes(m, nodePtr, zext(nodeLen))
	if node == nil && nodeLen != 0 {
		return -_wasiEFAULT
	}
	name := string(node)
	found, errno := w.resolveHost(m, name, "ip4")
	if errno != _wasiESUCCESS {
		return -errno
	}
	rec := binary.LittleEndian.AppendUint32(nil, 0)
	n := uint32(0)
	for _, a := range found {
		if a.Is4() {
			v4 := a.As4()
			rec = append(rec, v4[:]...)
			n++
		}
	}
	if n == 0 {
		return -_wasiENOENT
	}
	binary.LittleEndian.PutUint32(rec, n)
	rec = append(rec, name...)
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
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

// Process supplies the identity and the accounting of the guest process
// (WASIConfig.Process): the values the guest reads. The changes are another
// value's (ProcessChanges). Its methods are called without any lock of the
// WasiStubs held. An error of Groups or Priority fails the guest's call
// with the errno wasiErrnoOf gives: the errno of its name for a
// syscall.Errno, ENOSYS for errors.ErrUnsupported without one.
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
	// Groups returns the supplementary group ids of the guest process
	// (getgroups).
	Groups() ([]int32, error)
	// Priority returns the nice value of the processes which and who name
	// (getpriority): which is PRIO_PROCESS (0), PRIO_PGRP (1) or PRIO_USER
	// (2), who the id of the process, the group or the user, 0 for the
	// caller's own. The guest's own pid is given as 0.
	Priority(which, who int32) (int32, error)
}

// ProcessChanges makes the changes of the guest process
// (WASIConfig.ProcessChanges) where they are kept besides the instance: the
// host process's, for HostProcessChanges. Only the guest of the fork
// family's root instance reaches it; a forked instance, which is a process
// of its own to its guest but shares the host process, keeps its changes
// (procChanges). Its methods are called without any lock of the WasiStubs
// held, those of one instance one at a time. An error fails the guest's
// call with the errno wasiErrnoOf gives, but for SetUmask, whose error is
// told WASIConfig.Errors.
type ProcessChanges interface {
	// SetIDs makes a change of the guest's user or group ids, a call of the
	// setuid or setgid family (proc_setids).
	SetIDs(change IDChange) error
	// SetGroups sets the supplementary group ids of the guest process
	// (setgroups).
	SetGroups(groups []int32) error
	// SetPriority sets the nice value of the processes which and who name
	// (setpriority), as Process.Priority names them.
	SetPriority(which, who, prio int32) error
	// SetUmask sets the file mode creation mask (umask) to the permission
	// bits of mask and returns the previous one. The runtime keeps the mask
	// of each instance itself (Proc_umask); errors.ErrUnsupported is a
	// ProcessChanges that keeps none.
	SetUmask(mask os.FileMode) (os.FileMode, error)
	// Pgid returns the process group of the process pid names (getpgid), 0
	// for the guest process. The runtime asks for the guest's once, for the
	// group the family starts in, and for a process outside the family.
	Pgid(pid int32) (int32, error)
	// Setpgid moves the guest process into the process group pgid
	// (setpgid), 0 for a new one of its own pid. pid is 0: the guest's
	// other processes are the family's (Proc_setpgid).
	Setpgid(pid, pgid int32) error
	// Setsid makes the guest process lead a new session and a new process
	// group (setsid) and returns the session's id.
	Setsid() (int32, error)
}

// IDChange is a change of the user or group ids of the guest process: one
// call of the setuid or setgid family.
type IDChange struct {
	// Call is the call.
	Call IDCall
	// IDs are the ids the call is given, in the order it takes them; -1
	// leaves an id as it is. Those past the ids the call takes are -1.
	IDs [3]int32
}

// IDCall names a call of the setuid or setgid family.
type IDCall int32

// The calls an IDChange makes, with the request numbers proc_setids
// passes.
const (
	IDSetuid    IDCall = iota // setuid(uid)
	IDSeteuid                 // seteuid(euid)
	IDSetreuid                // setreuid(ruid, euid)
	IDSetresuid               // setresuid(ruid, euid, suid)
	IDSetgid                  // setgid(gid)
	IDSetegid                 // setegid(egid)
	IDSetregid                // setregid(rgid, egid)
	IDSetresgid               // setresgid(rgid, egid, sgid)
)

// idCallArgs is the number of ids each IDCall takes.
var idCallArgs = [...]int{IDSetuid: 1, IDSeteuid: 1, IDSetreuid: 2, IDSetresuid: 3, IDSetgid: 1, IDSetegid: 1, IDSetregid: 2, IDSetresgid: 3}

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

// An isolated process is in no supplementary group and has the nice value
// 0.
func (isolatedProcess) Groups() ([]int32, error)                 { return nil, nil }
func (isolatedProcess) Priority(which, who int32) (int32, error) { return 0, nil }

// HostProcess returns a Process with the identity and the accounting of the
// host process, for WASIConfig.Process. IDs are os.Getpid, os.Getppid,
// os.Getuid, os.Geteuid, os.Getgid and os.Getegid; Groups is os.Getgroups;
// Priority is the host's getpriority. Where the host has no such call the
// error is errors.ErrUnsupported. Times are the host's
// resource usage of the whole host process, which every instance of a fork
// family is part of, and of the children the host process has waited for;
// on a system without one the error is errors.ErrUnsupported. Umask is the host
// process's file mode creation mask when HostProcess is called, read without
// changing it: on Linux from the status of the calling thread
// (/proc/thread-self/status), which shares it with the process, and an
// error reading it is returned. Where it cannot be read without changing it (another system, or
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

func (hostProcess) Groups() ([]int32, error) {
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	out := make([]int32, len(groups))
	for i, gid := range groups {
		out[i] = int32(gid)
	}
	return out, nil
}

func (hostProcess) Priority(which, who int32) (int32, error) {
	nice, err := hostPriority(int(which), int(who))
	return int32(nice), err
}

// HostProcessChanges returns the ProcessChanges of the host process, for
// WASIConfig.ProcessChanges, which the guest of a fork family's root
// instance makes the host process's: SetIDs, SetGroups and SetPriority are
// the host's calls of the same name (package syscall's), SetUmask is
// umask(2), and Pgid, Setpgid and Setsid are getpgid(2), setpgid(2) and
// setsid(2). Where the host has no such call the error is
// errors.ErrUnsupported.
func HostProcessChanges() ProcessChanges { return hostProcessChanges{} }

// hostProcessChanges is the ProcessChanges HostProcessChanges returns.
type hostProcessChanges struct{}

func (hostProcessChanges) SetIDs(change IDChange) error { return setHostIDs(change) }

func (hostProcessChanges) SetGroups(groups []int32) error {
	gids := make([]int, len(groups))
	for i, gid := range groups {
		gids[i] = int(gid)
	}
	return setHostGroups(gids)
}

func (hostProcessChanges) SetPriority(which, who, prio int32) error {
	return setHostPriority(int(which), int(who), int(prio))
}

func (hostProcessChanges) SetUmask(mask os.FileMode) (os.FileMode, error) {
	return hostSetUmask(mask)
}

func (hostProcessChanges) Pgid(pid int32) (int32, error) { return hostGetpgid(pid) }
func (hostProcessChanges) Setpgid(pid, pgid int32) error { return hostSetpgid(pid, pgid) }
func (hostProcessChanges) Setsid() (int32, error)        { return hostSetsid() }

// processChanged holds the ids, groups and nice value of a forked
// instance's process that are its own: those it started with
// (forkedChanges) and the nice value its guest set. The guest reads them in
// place of the Process's.
type processChanged struct {
	// ids are the real, effective and saved user ids, then group ids.
	ids    *[6]int32
	groups []int32
	// grouped records that groups are known (an empty list included).
	grouped bool
	nice    *int32
}

// overlay puts what of c was changed over p, sharing nothing with c.
func (p *processChanged) overlay(c processChanged) {
	if c.ids != nil {
		ids := *c.ids
		p.ids = &ids
	}
	if c.grouped {
		p.groups, p.grouped = slices.Clone(c.groups), true
	}
	if c.nice != nil {
		nice := *c.nice
		p.nice = &nice
	}
}

// forkedChanges returns what a copy Fork makes starts with as its own
// process's values, where the guests change them (WASIConfig.ProcessChanges):
// the ids (ids, read by the caller), groups and nice value w's guest has
// then, so that a later change of the root's, which reaches the host
// process, is not the copy's. A value the Process cannot tell is left to
// it, and its error told WASIConfig.Errors (op "fork") unless it is
// errors.ErrUnsupported. nil without a ProcessChanges, where nothing
// changes.
func (w *WasiStubs) forkedChanges(ids ProcessIDs) *processChanged {
	if w.cfg.ProcessChanges == nil {
		return nil
	}
	start := &processChanged{ids: &[6]int32{ids.UID, ids.EUID, ids.EUID, ids.GID, ids.EGID, ids.EGID}}
	groups, err := w.guestProcess().Groups()
	switch {
	case err == nil:
		start.groups, start.grouped = groups, true
	case !errors.Is(err, errors.ErrUnsupported):
		w.reportError("fork", err)
	}
	nice, err := w.guestProcess().Priority(0, 0)
	switch {
	case err == nil:
		start.nice = &nice
	case !errors.Is(err, errors.ErrUnsupported):
		w.reportError("fork", err)
	}
	return start
}

// guestIDs returns the ids of the instance's guest: the Process's, with
// those a forked instance started with (processChanged).
func (w *WasiStubs) guestIDs() ProcessIDs {
	ids := w.guestProcess().IDs()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.changed != nil && w.changed.ids != nil {
		c := w.changed.ids
		ids.UID, ids.EUID, ids.GID, ids.EGID = c[0], c[1], c[3], c[4]
	}
	return ids
}

// guestGroups returns the supplementary groups of the instance's guest:
// the Process's, or those a forked instance started with.
func (w *WasiStubs) guestGroups() ([]int32, error) {
	w.mu.Lock()
	if w.changed != nil && w.changed.grouped {
		groups := slices.Clone(w.changed.groups)
		w.mu.Unlock()
		return groups, nil
	}
	w.mu.Unlock()
	return w.guestProcess().Groups()
}

// changedLocked returns the changes of the instance's guest, made when it
// had none. Caller holds w.mu.
func (w *WasiStubs) changedLocked() *processChanged {
	if w.changed == nil {
		w.changed = &processChanged{}
	}
	return w.changed
}

// ensureIDsKept answers the change of a forked instance's guest to its ids.
// The credentials are those of the process the ProcessChanges changes,
// which the root instance's guest is, and a forked instance cannot change
// them alone: a change succeeds only when it leaves the ids as they are
// (setuid(getuid())), and fails with EPERM otherwise. Whether it leaves
// them is decided as Linux's calls make the change (kernel/sys.c; gVisor's
// Task.SetUID and the rest, pkg/sentry/kernel/task_identity.go): with the
// effective user id 0 any id may be given; otherwise only one of the real,
// effective and saved ids, the real id of setreuid and setregid only the
// real or the effective one, else EPERM. setuid and setgid of the
// superuser set all three; a setreuid or setregid that sets the real id,
// or the effective one to another than the real id, makes the saved id the
// new effective one.
func (w *WasiStubs) ensureIDsKept(change IDChange) error {
	p := w.guestProcess().IDs()
	w.mu.Lock()
	ids := [6]int32{p.UID, p.EUID, p.EUID, p.GID, p.EGID, p.EGID}
	if w.changed != nil && w.changed.ids != nil {
		ids = *w.changed.ids
	}
	w.mu.Unlock()
	kept := ids
	privileged := ids[1] == 0
	set := ids[0:3]
	if change.Call >= IDSetgid {
		set = ids[3:6]
	}
	among := func(id int32, of ...int32) bool {
		return id == -1 || privileged || slices.Contains(of, id)
	}
	r, e, s := set[0], set[1], set[2]
	a := change.IDs
	switch change.Call {
	case IDSetuid, IDSetgid:
		switch {
		case a[0] < 0:
			return syscall.EINVAL
		case privileged:
			set[0], set[1], set[2] = a[0], a[0], a[0]
		case a[0] == r || a[0] == s:
			set[1] = a[0]
		default:
			return syscall.EPERM
		}
	case IDSeteuid, IDSetegid:
		if !among(a[0], r, e, s) {
			return syscall.EPERM
		}
		if a[0] != -1 {
			set[1] = a[0]
		}
	case IDSetreuid, IDSetregid:
		if !among(a[0], r, e) || !among(a[1], r, e, s) {
			return syscall.EPERM
		}
		if a[0] != -1 {
			set[0] = a[0]
		}
		if a[1] != -1 {
			set[1] = a[1]
		}
		if a[0] != -1 || a[1] != -1 && a[1] != r {
			set[2] = set[1]
		}
	case IDSetresuid, IDSetresgid:
		if !among(a[0], r, e, s) || !among(a[1], r, e, s) || !among(a[2], r, e, s) {
			return syscall.EPERM
		}
		for i, id := range a {
			if id != -1 {
				set[i] = id
			}
		}
	}
	if ids != kept {
		return syscall.EPERM
	}
	return nil
}

// The guest's signal numbers are Linux's. A host has its own (SIGUSR1 is
// 10 here and 30 on macOS), so a number never crosses to or from the host
// OS as it is: hostSignalOf and guestSignalOf translate it by the signal's
// identity.
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
	w.endUnregistered()
	out := w.memBytes(m, outPtr, 24)
	if out == nil {
		return -_wasiEFAULT
	}
	ids := w.guestIDs()
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
	w.endUnregistered()
	out := w.memBytes(m, outPtr, 32)
	if out == nil {
		return -_wasiEFAULT
	}
	times, err := w.guestProcess().Times()
	if err != nil {
		return -w.guestErrno("proc_times", err)
	}
	for i, d := range [4]time.Duration{times.User, times.System, times.ChildrenUser, times.ChildrenSystem} {
		binary.LittleEndian.PutUint64(out[i*8:], uint64(d))
	}
	return _wasiESUCCESS
}

// Proc_groups is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_groups") backing getgroups: the Groups of the Process
// (WASIConfig.Process). It writes the number of supplementary group ids at
// countPtr and, when capacity (a count of u32 slots at bufPtr) is enough
// for all of them, the ids themselves. Returns 0, or a negative errno:
// EINVAL for a negative capacity, ERANGE when capacity is not zero and too
// small (the count is still written).
func (w *WasiStubs) Proc_groups(m *Module, bufPtr, capacity, countPtr int32) int32 {
	return w.procGroups(m, zext(bufPtr), capacity, zext(countPtr))
}

// Proc_groups64 is Proc_groups for a memory64 guest.
func (w *WasiStubs) Proc_groups64(m *Module, bufPtr int64, capacity int32, countPtr int64) int32 {
	return w.procGroups(m, uint64(bufPtr), capacity, uint64(countPtr))
}

// procGroups is the body of Proc_groups and Proc_groups64.
func (w *WasiStubs) procGroups(m *Module, bufPtr uint64, capacity int32, countPtr uint64) int32 {
	if capacity < 0 {
		return -_wasiEINVAL
	}
	countOut := w.memBytes(m, countPtr, 4)
	if countOut == nil {
		return -_wasiEFAULT
	}
	groups, err := w.guestGroups()
	if err != nil {
		return -w.guestErrno("proc_groups", err)
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

// Proc_setids is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_setids") backing the setuid and setgid families: request names
// the call (the IDCall of its number) and a, b, c are its ids, -1 for an id
// to leave alone. The SetIDs of the ProcessChanges (WASIConfig.ProcessChanges)
// makes the change of the family's root instance; a forked instance's guest
// only keeps its ids (ensureIDsKept: EPERM for a change of them). Returns
// 0, or a negative errno: EINVAL for a request it does not know, ENOSYS
// without a ProcessChanges.
func (w *WasiStubs) Proc_setids(m *Module, request, a, b, c int32) int32 {
	call := IDCall(request)
	if call < IDSetuid || call > IDSetresgid {
		return -_wasiEINVAL
	}
	change := IDChange{Call: call, IDs: [3]int32{-1, -1, -1}}
	copy(change.IDs[:idCallArgs[call]], []int32{a, b, c})
	changes := w.cfg.ProcessChanges
	var err error
	switch {
	case changes == nil:
		return -_wasiENOSYS
	case w.forked:
		err = w.ensureIDsKept(change)
	default:
		err = changes.SetIDs(change)
	}
	if err != nil {
		return -w.guestErrno("proc_setids", err)
	}
	return _wasiESUCCESS
}

// Proc_setids64 is Proc_setids for a memory64 guest.
func (w *WasiStubs) Proc_setids64(m *Module, request, a, b, c int32) int32 {
	return w.Proc_setids(m, request, a, b, c)
}

// Proc_setgroups is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_setgroups") backing setgroups: the
// count u32 group ids at listPtr are given to the SetGroups of the
// ProcessChanges (WASIConfig.ProcessChanges) by the family's root instance;
// a forked instance's guest, which cannot change the credentials alone
// (ensureIDsKept), only gives the groups it has, in any order, and only
// with the effective user id 0, as Linux asks of any setgroups (EPERM
// otherwise). Returns 0, or a negative errno: EINVAL for a count below 0
// or above 65536 (NGROUPS_MAX), ENOSYS without a ProcessChanges.
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
	list := w.memBytes(m, listPtr, uint64(count)*4)
	if list == nil {
		return -_wasiEFAULT
	}
	groups := make([]int32, count)
	for i := range groups {
		groups[i] = int32(binary.LittleEndian.Uint32(list[i*4:]))
	}
	changes := w.cfg.ProcessChanges
	switch {
	case changes == nil:
		return -_wasiENOSYS
	case w.forked:
		if w.guestIDs().EUID != 0 {
			return -_wasiEPERM
		}
		has, err := w.guestGroups()
		if err != nil {
			return -w.guestErrno("proc_setgroups", err)
		}
		has = slices.Clone(has)
		slices.Sort(has)
		slices.Sort(groups)
		if !slices.Equal(has, groups) {
			return -_wasiEPERM
		}
	default:
		if err := changes.SetGroups(groups); err != nil {
			return -w.guestErrno("proc_setgroups", err)
		}
	}
	return _wasiESUCCESS
}

// Proc_priority is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_priority") backing getpriority,
// setpriority and nice: which is PRIO_PROCESS (0), PRIO_PGRP (1) or
// PRIO_USER (2) and who the id it applies to, 0 for the caller's own; the
// guest's own pid is passed on as 0, and the pid token of another process
// of the fork family or of a process the guest spawned is no process of
// the host: ESRCH. With set non-zero value becomes the nice value first: by
// the SetPriority of the ProcessChanges (WASIConfig.ProcessChanges) for the
// family's root instance; a forked instance's guest sets its own nice value
// alone (PRIO_PROCESS of itself; EPERM for another), and a lower one than it
// has only with the effective user id 0 (EACCES), clamped to -20..19 as
// setpriority clamps it. The nice value then in effect — the Priority of
// the Process, or the forked instance's own — is written at outPtr (i32).
// Returns 0, or a negative errno: ENOSYS for a change without a
// ProcessChanges.
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
	proc := w.guestProcess()
	if which == 0 && who != 0 {
		w.mu.Lock()
		pids := w.pidsLocked()
		w.mu.Unlock()
		if who == proc.IDs().PID {
			// The guest's own pid is always the guest itself, as for
			// kill.
			who = 0
		} else if member, ours := pids.find(who); member != nil || ours {
			// A process of the fork family, or one the guest spawned,
			// whose token names no process of the host.
			return -_wasiESRCH
		}
	}
	own := which == 0 && who == 0
	if set != 0 {
		changes := w.cfg.ProcessChanges
		switch {
		case changes == nil:
			return -_wasiENOSYS
		case w.forked:
			if errno := w.setOwnNice(own, value); errno != _wasiESUCCESS {
				return -errno
			}
		default:
			if err := changes.SetPriority(which, who, value); err != nil {
				return -w.guestErrno("proc_priority", err)
			}
		}
	}
	if own {
		w.mu.Lock()
		nice := w.changed != nil && w.changed.nice != nil
		var value int32
		if nice {
			value = *w.changed.nice
		}
		w.mu.Unlock()
		if nice {
			binary.LittleEndian.PutUint32(out, uint32(value))
			return _wasiESUCCESS
		}
	}
	nice, err := proc.Priority(which, who)
	if err != nil {
		return -w.guestErrno("proc_priority", err)
	}
	binary.LittleEndian.PutUint32(out, uint32(nice))
	return _wasiESUCCESS
}

// setOwnNice sets the nice value of a forked instance's guest to value, for
// a setpriority of itself (own), and returns a wasi errno.
func (w *WasiStubs) setOwnNice(own bool, value int32) int32 {
	if !own {
		return _wasiEPERM
	}
	value = min(max(value, -20), 19)
	euid := w.guestIDs().EUID
	current, err := w.guestProcess().Priority(0, 0)
	w.mu.Lock()
	if w.changed != nil && w.changed.nice != nil {
		current, err = *w.changed.nice, nil
	}
	if err != nil {
		// Errors is told without the lock held.
		w.mu.Unlock()
		return w.guestErrno("proc_priority", err)
	}
	defer w.mu.Unlock()
	if value < current && euid != 0 {
		return _wasiEACCES
	}
	w.changedLocked().nice = &value
	return _wasiESUCCESS
}

// ----- the working directory and the environment ----------------------------

// Proc_chdir is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_chdir"): the guest reports the working directory it has
// changed to, an absolute path of pathLen bytes at pathPtr, which
// WASIConfig.Chdir is told. Returns 0 or a negative errno: EINVAL for a
// path that is not absolute.
func (w *WasiStubs) Proc_chdir(m *Module, pathPtr, pathLen int32) int32 {
	return w.procChdir(m, zext(pathPtr), pathLen)
}

// Proc_chdir64 is Proc_chdir for a memory64 guest.
func (w *WasiStubs) Proc_chdir64(m *Module, pathPtr int64, pathLen int32) int32 {
	return w.procChdir(m, uint64(pathPtr), pathLen)
}

// procChdir is the body of Proc_chdir and Proc_chdir64.
func (w *WasiStubs) procChdir(m *Module, pathPtr uint64, pathLen int32) int32 {
	w.endUnregistered()
	path := w.memBytes(m, pathPtr, zext(pathLen))
	if path == nil {
		return -_wasiEFAULT
	}
	dir := string(path)
	if !strings.HasPrefix(dir, "/") {
		return -_wasiEINVAL
	}
	if w.forked || w.cfg.Chdir == nil {
		return _wasiESUCCESS
	}
	return -w.guestErrno("proc_chdir", w.cfg.Chdir(dir))
}

// Proc_setenv is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_setenv"): the guest reports each variable of its environment
// it sets (hasValue non-zero) or removes, which WASIConfig.Setenv is told.
// Returns 0 or a negative errno.
func (w *WasiStubs) Proc_setenv(m *Module, namePtr, nameLen, valuePtr, valueLen, hasValue int32) int32 {
	return w.procSetenv(m, zext(namePtr), nameLen, zext(valuePtr), valueLen, hasValue)
}

// Proc_setenv64 is Proc_setenv for a memory64 guest.
func (w *WasiStubs) Proc_setenv64(m *Module, namePtr int64, nameLen int32, valuePtr int64, valueLen, hasValue int32) int32 {
	return w.procSetenv(m, uint64(namePtr), nameLen, uint64(valuePtr), valueLen, hasValue)
}

// procSetenv is the body of Proc_setenv and Proc_setenv64.
func (w *WasiStubs) procSetenv(m *Module, namePtr uint64, nameLen int32, valuePtr uint64, valueLen, hasValue int32) int32 {
	w.endUnregistered()
	name := w.memBytes(m, namePtr, zext(nameLen))
	if name == nil {
		return -_wasiEFAULT
	}
	var value []byte
	if hasValue != 0 {
		if value = w.memBytes(m, valuePtr, zext(valueLen)); value == nil {
			return -_wasiEFAULT
		}
	}
	if w.forked || w.cfg.Setenv == nil {
		return _wasiESUCCESS
	}
	return -w.guestErrno("proc_setenv", w.cfg.Setenv(string(name), string(value), hasValue == 0))
}

// ----- the user and group database ---------------------------------------------

// Users is a user and group database (WASIConfig.Users): what the guest's
// getpwuid, getpwnam and getpwent, and getgrgid, getgrnam and getgrent find.
// ListUsers and ListGroups return the entries in the order the guest goes
// through them: an instance asks for them when its guest starts going
// through the database (its first getpwent, or getgrent, after setpwent
// or endpwent, or its first of all) and answers the
// guest's next calls from what it got, so a walk sees the database as it
// was at its start; a forked instance goes on with the walk of the instance
// it was forked from. A lookup that finds nothing returns an error that is
// fs.ErrNotExist: the guest's call fails with ENOENT. Any other error fails
// it with the errno wasiErrnoOf gives. Its methods are called without any
// lock of the WasiStubs held.
type Users interface {
	UserByID(uid int32) (User, error)
	UserByName(name string) (User, error)
	ListUsers() ([]User, error)
	GroupByID(gid int32) (Group, error)
	GroupByName(name string) (Group, error)
	ListGroups() ([]Group, error)
}

// User is an entry of the user database, as passwd(5) has it.
type User struct {
	// Name is the login name.
	Name string
	// UID and GID are the user's id and the id of its primary group.
	UID, GID int32
	// RealName is the user's name (the GECOS field), Home the home
	// directory and Shell the login shell.
	RealName, Home, Shell string
}

// Group is an entry of the group database, as group(5) has it, without
// its members.
type Group struct {
	Name string
	GID  int32
}

// noUsers is the empty user and group database of an instance whose
// configuration names none.
type noUsers struct{}

func (noUsers) UserByID(int32) (User, error)      { return User{}, fs.ErrNotExist }
func (noUsers) UserByName(string) (User, error)   { return User{}, fs.ErrNotExist }
func (noUsers) ListUsers() ([]User, error)        { return nil, nil }
func (noUsers) GroupByID(int32) (Group, error)    { return Group{}, fs.ErrNotExist }
func (noUsers) GroupByName(string) (Group, error) { return Group{}, fs.ErrNotExist }
func (noUsers) ListGroups() ([]Group, error)      { return nil, nil }

// users returns the user and group database of the instance: an empty one
// when the configuration names none.
func (w *WasiStubs) users() Users {
	if w.cfg.Users == nil {
		return noUsers{}
	}
	return w.cfg.Users
}

// HostUsers returns the user and group database of the host, for
// WASIConfig.Users: the files /etc/passwd and /etc/group, then package
// os/user, as on a host whose name service switch reads its files first
// (passwd: files ...). A lookup by id or name finds the first entry of the
// file that matches, reading the file anew, and asks os/user only when the
// file has none; ListUsers and ListGroups are the entries of the files
// alone, in order, as os/user cannot go through a database. So a user or
// group that only a directory service has (LDAP, the Directory Services of
// darwin) is found by a lookup and not listed, as on a host whose service
// does not list its entries (sssd by default), and its User has no Shell,
// which os/user does not report. A file the host does not have has no
// entries. The lines of the NIS compatibility syntax (+ or - first) are no
// entries; a line that is no entry either (too few fields, an id that is
// not a number) is skipped and its error told report, with the name of the
// method as op; nil drops them. A user or group neither the files nor
// os/user knows is fs.ErrNotExist.
func HostUsers(report func(op string, err error)) Users {
	return hostUsers{passwd: "/etc/passwd", group: "/etc/group", report: report}
}

// hostUsers is the Users HostUsers returns: the files passwd and group,
// then os/user, with report told the lines of the files that are skipped.
type hostUsers struct {
	passwd, group string
	report        func(op string, err error)
}

func (u hostUsers) UserByID(uid int32) (User, error) {
	users, err := u.fileUsers("UserByID")
	if err != nil {
		return User{}, err
	}
	if i := slices.IndexFunc(users, func(e User) bool { return e.UID == uid }); i >= 0 {
		return users[i], nil
	}
	return hostUser(user.LookupId(strconv.FormatUint(uint64(uint32(uid)), 10)))
}

func (u hostUsers) UserByName(name string) (User, error) {
	users, err := u.fileUsers("UserByName")
	if err != nil {
		return User{}, err
	}
	if i := slices.IndexFunc(users, func(e User) bool { return e.Name == name }); i >= 0 {
		return users[i], nil
	}
	return hostUser(user.Lookup(name))
}

func (u hostUsers) ListUsers() ([]User, error) { return u.fileUsers("ListUsers") }

// fileUsers returns the entries of the file passwd; op is the method whose
// skipped lines report is told.
func (u hostUsers) fileUsers(op string) ([]User, error) {
	// name:password:uid:gid:gecos:home:shell
	entries, err := hostDatabaseEntries(u.passwd, skippedLine(u.report, op), 7, 2, 3)
	users := make([]User, 0, len(entries))
	for _, e := range entries {
		users = append(users, User{Name: e.fields[0], UID: e.ids[0], GID: e.ids[1], RealName: e.fields[4], Home: e.fields[5], Shell: e.fields[6]})
	}
	return users, err
}

func (u hostUsers) GroupByID(gid int32) (Group, error) {
	groups, err := u.fileGroups("GroupByID")
	if err != nil {
		return Group{}, err
	}
	if i := slices.IndexFunc(groups, func(e Group) bool { return e.GID == gid }); i >= 0 {
		return groups[i], nil
	}
	return hostGroup(user.LookupGroupId(strconv.FormatUint(uint64(uint32(gid)), 10)))
}

func (u hostUsers) GroupByName(name string) (Group, error) {
	groups, err := u.fileGroups("GroupByName")
	if err != nil {
		return Group{}, err
	}
	if i := slices.IndexFunc(groups, func(e Group) bool { return e.Name == name }); i >= 0 {
		return groups[i], nil
	}
	return hostGroup(user.LookupGroup(name))
}

func (u hostUsers) ListGroups() ([]Group, error) { return u.fileGroups("ListGroups") }

// fileGroups returns the entries of the file group; op is the method whose
// skipped lines report is told.
func (u hostUsers) fileGroups(op string) ([]Group, error) {
	// name:password:gid:members
	entries, err := hostDatabaseEntries(u.group, skippedLine(u.report, op), 3, 2)
	groups := make([]Group, 0, len(entries))
	for _, e := range entries {
		groups = append(groups, Group{Name: e.fields[0], GID: e.ids[0]})
	}
	return groups, err
}

// skippedLine returns what is told the error of a skipped line of a
// database file of the host: report, with op, or nobody when report is nil.
func skippedLine(report func(op string, err error), op string) func(error) {
	return func(err error) {
		if report != nil {
			report(op, err)
		}
	}
}

// hostUser returns the User of an os/user lookup's result.
func hostUser(u *user.User, err error) (User, error) {
	if err != nil {
		return User{}, hostLookupError(err)
	}
	uid, err := parseHostID(u.Uid)
	if err != nil {
		return User{}, err
	}
	gid, err := parseHostID(u.Gid)
	if err != nil {
		return User{}, err
	}
	return User{Name: u.Username, UID: uid, GID: gid, RealName: u.Name, Home: u.HomeDir}, nil
}

// hostGroup returns the Group of an os/user lookup's result.
func hostGroup(g *user.Group, err error) (Group, error) {
	if err != nil {
		return Group{}, hostLookupError(err)
	}
	gid, err := parseHostID(g.Gid)
	if err != nil {
		return Group{}, err
	}
	return Group{Name: g.Name, GID: gid}, nil
}

// parseHostID returns a user or group id of the host's databases, written
// as a 32-bit id either unsigned or signed (darwin's nobody is -2, the id
// 4294967294).
func parseHostID(text string) (int32, error) {
	if strings.HasPrefix(text, "-") {
		id, err := strconv.ParseInt(text, 10, 32)
		if err != nil {
			return 0, err
		}
		return int32(id), nil
	}
	id, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, err
	}
	if id <= 1<<31-1 {
		return int32(id), nil
	}
	// An id above the largest int32 is the negative one of the same bits.
	return int32(int64(id) - 1<<32), nil
}

// hostLookupError returns err, the error of an os/user lookup, wrapping
// fs.ErrNotExist as well when it says that there is no such user or group.
func hostLookupError(err error) error {
	var (
		uid   user.UnknownUserIdError
		name  user.UnknownUserError
		gid   user.UnknownGroupIdError
		group user.UnknownGroupError
	)
	if errors.As(err, &uid) || errors.As(err, &name) || errors.As(err, &gid) || errors.As(err, &group) {
		return fmt.Errorf("%w: %w", fs.ErrNotExist, err)
	}
	return err
}

// hostDBEntry is an entry of a database file of the host: its fields, and
// the ids among them as numbers.
type hostDBEntry struct {
	fields []string
	ids    []int32
}

// hostDatabaseEntries returns the entries of a database file of the host
// in the files' format (passwd(5), group(5)), read once: one entry a line,
// at least minFields fields separated by colons, the fields idFields of
// which are ids. A line that is empty, a comment, or an entry of the NIS
// compatibility syntax (+ or - first) is no entry; neither is one with too
// few fields or an id that is not a number: its error is told skipped and
// the line passed over. A file that does not exist has no entries.
func hostDatabaseEntries(path string, skipped func(error), minFields int, idFields ...int) ([]hostDBEntry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []hostDBEntry
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		e, err := parseHostDBEntry(line, minFields, idFields)
		if err != nil {
			skipped(fmt.Errorf("%s:%d: %w", path, n+1, err))
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// parseHostDBEntry returns the entry of a line of a database file of the
// host (see hostDatabaseEntries).
func parseHostDBEntry(line string, minFields int, idFields []int) (hostDBEntry, error) {
	e := hostDBEntry{fields: strings.Split(line, ":")}
	if len(e.fields) < minFields {
		return hostDBEntry{}, fmt.Errorf("%d fields, fewer than %d", len(e.fields), minFields)
	}
	for _, f := range idFields {
		id, err := parseHostID(e.fields[f])
		if err != nil {
			return hostDBEntry{}, err
		}
		e.ids = append(e.ids, id)
	}
	return e, nil
}

// appendWasiString appends s as a little-endian u32 length followed by its
// bytes: the form every string in a record handed to the guest takes.
func appendWasiString(rec []byte, s string) []byte {
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(s)))
	return append(rec, s...)
}

// writeUser answers a user lookup of the guest with the record of u (see
// Proc_user_by_id), or with the errno of err; call is the import's name.
func (w *WasiStubs) writeUser(m *Module, call string, u User, err error, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if err != nil {
		return -w.guestErrno(call, err)
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(u.UID))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(u.GID))
	rec = appendWasiString(rec, u.Name)
	rec = appendWasiString(rec, u.RealName)
	rec = appendWasiString(rec, u.Home)
	rec = appendWasiString(rec, u.Shell)
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// writeGroup answers a group lookup of the guest with the record of g (see
// Proc_group_by_id), or with the errno of err; call is the import's name.
func (w *WasiStubs) writeGroup(m *Module, call string, g Group, err error, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if err != nil {
		return -w.guestErrno(call, err)
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(g.GID))
	rec = appendWasiString(rec, g.Name)
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// Proc_user_by_id is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_user_by_id") backing getpwuid: the
// UserByID of the Users (WASIConfig.Users), handed back as a record
// (writeWasiRecord) of u32 uid, u32 gid, then the login name, the real name,
// the home directory and the shell as strings (appendWasiString). Returns
// 0, or a negative errno: ENOENT when there is no such user — always, for an
// instance without Users — and ERANGE when the buffer is too small.
func (w *WasiStubs) Proc_user_by_id(m *Module, uid, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUserByID(m, uid, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_user_by_id64 is Proc_user_by_id for a memory64 guest.
func (w *WasiStubs) Proc_user_by_id64(m *Module, uid int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUserByID(m, uid, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUserByID is the body of Proc_user_by_id and Proc_user_by_id64.
func (w *WasiStubs) procUserByID(m *Module, uid int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	u, err := w.users().UserByID(uid)
	return w.writeUser(m, "proc_user_by_id", u, err, bufPtr, bufLen, neededPtr)
}

// Proc_user_by_name is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_user_by_name") backing getpwnam:
// Proc_user_by_id for the login name at (namePtr, nameLen), by UserByName.
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
	u, err := w.users().UserByName(string(name))
	return w.writeUser(m, "proc_user_by_name", u, err, bufPtr, bufLen, neededPtr)
}

// Proc_user_at is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_user_at") backing getpwent: Proc_user_by_id for the index-th
// entry of the instance's walk of the Users (userWalk): what their
// ListUsers returned when the guest asked for index 0, or for any index
// while the instance had no walk. Returns ENOENT past the last entry.
func (w *WasiStubs) Proc_user_at(m *Module, index, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUserAt(m, index, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_user_at64 is Proc_user_at for a memory64 guest.
func (w *WasiStubs) Proc_user_at64(m *Module, index int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUserAt(m, index, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUserAt is the body of Proc_user_at and Proc_user_at64.
func (w *WasiStubs) procUserAt(m *Module, index int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if index < 0 {
		return -_wasiENOENT
	}
	w.mu.Lock()
	walk := w.userWalk
	w.mu.Unlock()
	if index == 0 || walk == nil {
		users, err := w.users().ListUsers()
		if err != nil {
			return -w.guestErrno("proc_user_at", err)
		}
		walk = &users
		w.mu.Lock()
		w.userWalk = walk
		w.mu.Unlock()
	}
	if int(index) >= len(*walk) {
		return -_wasiENOENT
	}
	return w.writeUser(m, "proc_user_at", (*walk)[index], nil, bufPtr, bufLen, neededPtr)
}

// Proc_group_by_id is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_group_by_id") backing getgrgid: the
// GroupByID of the Users (WASIConfig.Users), handed back as a record
// (writeWasiRecord) of u32 gid, then the group's name as a string
// (appendWasiString). Returns 0 or a negative errno, as Proc_user_by_id.
func (w *WasiStubs) Proc_group_by_id(m *Module, gid, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procGroupByID(m, gid, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_group_by_id64 is Proc_group_by_id for a memory64 guest.
func (w *WasiStubs) Proc_group_by_id64(m *Module, gid int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procGroupByID(m, gid, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procGroupByID is the body of Proc_group_by_id and Proc_group_by_id64.
func (w *WasiStubs) procGroupByID(m *Module, gid int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	g, err := w.users().GroupByID(gid)
	return w.writeGroup(m, "proc_group_by_id", g, err, bufPtr, bufLen, neededPtr)
}

// Proc_group_by_name is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_group_by_name") backing getgrnam:
// Proc_group_by_id for the name at (namePtr, nameLen), by GroupByName.
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
	g, err := w.users().GroupByName(string(name))
	return w.writeGroup(m, "proc_group_by_name", g, err, bufPtr, bufLen, neededPtr)
}

// Proc_group_at is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_group_at") backing getgrent:
// Proc_group_by_id for the index-th entry of the Users' ListGroups, as
// Proc_user_at for the users. Returns ENOENT past the last entry.
func (w *WasiStubs) Proc_group_at(m *Module, index, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procGroupAt(m, index, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_group_at64 is Proc_group_at for a memory64 guest.
func (w *WasiStubs) Proc_group_at64(m *Module, index int32, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procGroupAt(m, index, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procGroupAt is the body of Proc_group_at and Proc_group_at64.
func (w *WasiStubs) procGroupAt(m *Module, index int32, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if index < 0 {
		return -_wasiENOENT
	}
	w.mu.Lock()
	walk := w.groupWalk
	w.mu.Unlock()
	if index == 0 || walk == nil {
		groups, err := w.users().ListGroups()
		if err != nil {
			return -w.guestErrno("proc_group_at", err)
		}
		walk = &groups
		w.mu.Lock()
		w.groupWalk = walk
		w.mu.Unlock()
	}
	if int(index) >= len(*walk) {
		return -_wasiENOENT
	}
	return w.writeGroup(m, "proc_group_at", (*walk)[index], nil, bufPtr, bufLen, neededPtr)
}

// ----- the system --------------------------------------------------------------

// System is the system the guest runs on (WASIConfig.System): what its
// uname and gethostname report. An error of Uname fails the guest's call
// with the errno wasiErrnoOf gives. Uname is called without any lock of the
// WasiStubs held.
type System interface {
	Uname() (Uname, error)
}

// Uname is what uname(2) reports.
type Uname struct {
	// Sysname is the name of the system, Nodename the node's name on the
	// network, Release and Version the system's release and version, and
	// Machine the machine type.
	Sysname, Nodename, Release, Version, Machine string
}

// HostSystem returns the host's system, for WASIConfig.System: its Uname
// is the host's uname(2) (on darwin, the sysctl values uname reads), and
// errors.ErrUnsupported on a host the runtime cannot ask.
func HostSystem() System { return hostSystem{} }

// hostSystem is the System HostSystem returns.
type hostSystem struct{}

func (hostSystem) Uname() (Uname, error) { return hostUname() }

// Proc_uname is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_uname") backing uname and gethostname: the Uname of the System
// (WASIConfig.System), handed back as a record (writeWasiRecord) of five
// strings (appendWasiString): the system's name, the node's name, the
// release, the version and the machine type. Returns 0, or a negative
// errno: ENOSYS for an instance without System, ERANGE when the buffer is
// too small.
func (w *WasiStubs) Proc_uname(m *Module, bufPtr, bufLen, neededPtr int32) int32 {
	return w.procUname(m, zext(bufPtr), bufLen, zext(neededPtr))
}

// Proc_uname64 is Proc_uname for a memory64 guest.
func (w *WasiStubs) Proc_uname64(m *Module, bufPtr int64, bufLen int32, neededPtr int64) int32 {
	return w.procUname(m, uint64(bufPtr), bufLen, uint64(neededPtr))
}

// procUname is the body of Proc_uname and Proc_uname64.
func (w *WasiStubs) procUname(m *Module, bufPtr uint64, bufLen int32, neededPtr uint64) int32 {
	if w.cfg.System == nil {
		return -_wasiENOSYS
	}
	name, err := w.cfg.System.Uname()
	if err != nil {
		return -w.guestErrno("proc_uname", err)
	}
	var rec []byte
	for _, field := range [...]string{name.Sysname, name.Nodename, name.Release, name.Version, name.Machine} {
		rec = appendWasiString(rec, field)
	}
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// ----- the services database ---------------------------------------------------

// Services is a services database (WASIConfig.Services): what the guest's
// getservbyname and getservbyport find. proto is the protocol ("tcp",
// "udp", ...), or "" for a service of any protocol. A lookup that finds
// nothing returns an error that is fs.ErrNotExist: the guest's call fails
// with ENOENT. Any other error fails it with the errno wasiErrnoOf gives. Its
// methods are called without any lock of the WasiStubs held.
type Services interface {
	// ServiceByName returns the service called name, by its name or by an
	// alias.
	ServiceByName(name, proto string) (Service, error)
	// ServiceByPort returns the service on port.
	ServiceByPort(port int, proto string) (Service, error)
}

// Service is an entry of the services database, as services(5) has it.
type Service struct {
	Name    string
	Aliases []string
	Port    int
	Proto   string
}

// HostServices returns the services database of the host, for
// WASIConfig.Services: the file /etc/services, read anew for each lookup,
// whose first entry that matches is the one found. An error reading the
// file is returned; a line that is no entry is skipped and its error told
// report, with the name of the method as op; nil drops them.
func HostServices(report func(op string, err error)) Services {
	return hostServices{path: hostServicesFile, report: report}
}

// hostServices is the Services HostServices returns: the file path, with
// report told why a line that is no entry was skipped.
type hostServices struct {
	path   string
	report func(op string, err error)
}

func (h hostServices) ServiceByName(name, proto string) (Service, error) {
	return findHostService(h.path, skippedLine(h.report, "ServiceByName"), func(s Service) bool {
		return (proto == "" || s.Proto == proto) && (s.Name == name || slices.Contains(s.Aliases, name))
	})
}

func (h hostServices) ServiceByPort(port int, proto string) (Service, error) {
	return findHostService(h.path, skippedLine(h.report, "ServiceByPort"), func(s Service) bool {
		return (proto == "" || s.Proto == proto) && s.Port == port
	})
}

// hostServicesFile is the services database of the host.
const hostServicesFile = "/etc/services"

// findHostService returns the first entry of the services database at path,
// services(5) — one service a line: its name, port/protocol, and aliases,
// with comments from a # to the end of the line — that match accepts. A
// line that is no entry is skipped and its error told skipped.
func findHostService(path string, skipped func(error), match func(Service) bool) (Service, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Service{}, err
	}
	for n, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entry, err := parseHostService(fields)
		if err != nil {
			skipped(fmt.Errorf("%s:%d: %w", path, n+1, err))
			continue
		}
		if match(entry) {
			return entry, nil
		}
	}
	return Service{}, fmt.Errorf("no such service in %s: %w", path, fs.ErrNotExist)
}

// parseHostService returns the entry of the fields of a line of the
// services database (see findHostService).
func parseHostService(fields []string) (Service, error) {
	if len(fields) < 2 {
		return Service{}, fmt.Errorf("no port/protocol after %q", fields[0])
	}
	portText, proto, isPair := strings.Cut(fields[1], "/")
	if !isPair {
		return Service{}, fmt.Errorf("%q is no port/protocol", fields[1])
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return Service{}, err
	}
	return Service{Name: fields[0], Aliases: fields[2:], Port: int(port), Proto: proto}, nil
}

// Sock_service is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sock_service") backing getservbyname and getservbyport: the
// ServiceByName of the Services (WASIConfig.Services) for the name at
// (namePtr, nameLen) when byPort is 0, its ServiceByPort for port
// otherwise, for the protocol at (protoPtr, protoLen), any when it is
// empty. The record (writeWasiRecord) is the port (u32), the name, the
// protocol, the number of aliases (u32) and the aliases, strings as
// appendWasiString writes them. Returns 0, or a negative errno: ENOENT when
// there is no such service — always, for an instance without Services.
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
	services := w.cfg.Services
	if services == nil {
		return -_wasiENOENT
	}
	var (
		entry Service
		err   error
	)
	if byPort != 0 {
		entry, err = services.ServiceByPort(int(port), string(protoBytes))
	} else {
		entry, err = services.ServiceByName(string(nameBytes), string(protoBytes))
	}
	if err != nil {
		return -w.guestErrno("sock_service", err)
	}
	rec := binary.LittleEndian.AppendUint32(nil, uint32(entry.Port))
	rec = appendWasiString(rec, entry.Name)
	rec = appendWasiString(rec, entry.Proto)
	rec = binary.LittleEndian.AppendUint32(rec, uint32(len(entry.Aliases)))
	for _, alias := range entry.Aliases {
		rec = appendWasiString(rec, alias)
	}
	return w.writeWasiRecord(m, rec, bufPtr, bufLen, neededPtr)
}

// ----- terminals ---------------------------------------------------------------
//
// The guest makes the requests of a terminal (Fd_ioctl) as a program of
// Linux makes them on most of its architectures (asm-generic), whatever the
// host is: the numbers of the requests are those of
// include/uapi/asm-generic/ioctls.h, and what they take is an int, struct
// winsize, or the kernel's struct termios or termios2 with the bits and
// places of include/uapi/asm-generic/termbits.h. The platform companion
// makes each request of the host in the host's numbers and layouts
// (hostTerminalIoctl), as QEMU's linux-user makes a guest's
// (linux-user/ioctls.h, and target_to_host_termios in
// linux-user/syscall.c).

// The requests of a terminal a guest makes, as asm-generic numbers them.
const (
	linuxTCGETS     = 0x5401
	linuxTCSETS     = 0x5402
	linuxTCSETSW    = 0x5403
	linuxTCSETSF    = 0x5404
	linuxTCSBRK     = 0x5409
	linuxTCXONC     = 0x540a
	linuxTCFLSH     = 0x540b
	linuxTIOCEXCL   = 0x540c
	linuxTIOCNXCL   = 0x540d
	linuxTIOCSCTTY  = 0x540e
	linuxTIOCGPGRP  = 0x540f
	linuxTIOCSPGRP  = 0x5410
	linuxTIOCOUTQ   = 0x5411
	linuxTIOCGWINSZ = 0x5413
	linuxTIOCSWINSZ = 0x5414
	linuxTIOCNOTTY  = 0x5422
	linuxTIOCGSID   = 0x5429
	linuxTCGETS2    = 0x802c542a
	linuxTCSETS2    = 0x402c542b
	linuxTCSETSW2   = 0x402c542c
	linuxTCSETSF2   = 0x402c542d
	linuxTIOCGPTN   = 0x80045430
	linuxTIOCSPTLCK = 0x40045431
)

// linuxNCCS is the number of control characters of the kernel's struct
// termios.
const linuxNCCS = 19

// What a request of a terminal takes (terminalArg.what): nothing, an int
// as it is, or the address of an int, of a struct termios, of a struct
// termios2 or of a struct winsize.
const (
	terminalTakesNothing = iota
	terminalTakesValue
	terminalTakesInt
	terminalTakesTermios
	terminalTakesTermios2
	terminalTakesWinsize
)

// linuxTermios is the kernel's struct termios2 (asm-generic): struct
// termios, then the input and the output speed. In memory it is laid out as
// the kernel's own, so that it is what a request of a host whose numbers
// are asm-generic takes.
type linuxTermios struct {
	Iflag, Oflag, Cflag, Lflag uint32
	Line                       uint8
	Cc                         [linuxNCCS]uint8
	Ispeed, Ospeed             uint32
}

// decode reads the struct termios at mem, and the speeds of a struct
// termios2 when mem holds one.
func (t *linuxTermios) decode(mem []byte) {
	t.Iflag = binary.LittleEndian.Uint32(mem[0:])
	t.Oflag = binary.LittleEndian.Uint32(mem[4:])
	t.Cflag = binary.LittleEndian.Uint32(mem[8:])
	t.Lflag = binary.LittleEndian.Uint32(mem[12:])
	t.Line = mem[16]
	copy(t.Cc[:], mem[17:])
	if len(mem) == 44 {
		t.Ispeed = binary.LittleEndian.Uint32(mem[36:])
		t.Ospeed = binary.LittleEndian.Uint32(mem[40:])
	}
}

// encode writes t at mem as decode reads it.
func (t *linuxTermios) encode(mem []byte) {
	binary.LittleEndian.PutUint32(mem[0:], t.Iflag)
	binary.LittleEndian.PutUint32(mem[4:], t.Oflag)
	binary.LittleEndian.PutUint32(mem[8:], t.Cflag)
	binary.LittleEndian.PutUint32(mem[12:], t.Lflag)
	mem[16] = t.Line
	copy(mem[17:36], t.Cc[:])
	if len(mem) == 44 {
		binary.LittleEndian.PutUint32(mem[36:], t.Ispeed)
		binary.LittleEndian.PutUint32(mem[40:], t.Ospeed)
	}
}

// linuxWinsize is struct winsize, laid out as the kernel's.
type linuxWinsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

// terminalArg is the argument of a request of a terminal (Fd_ioctl): what
// it takes (terminalTakes...), and whether the call writes it (out) or
// reads it. value is an int the request takes as it is or at its address,
// termios and winsize the records it takes.
type terminalArg struct {
	what    int
	out     bool
	value   int32
	termios linuxTermios
	winsize linuxWinsize
}

// of sets what request takes, and reports whether it is one of the
// requests of a terminal the runtime makes.
func (a *terminalArg) of(request uint32) bool {
	switch request {
	case linuxTIOCEXCL, linuxTIOCNXCL, linuxTIOCNOTTY:
		a.what = terminalTakesNothing
	case linuxTCSBRK, linuxTCXONC, linuxTCFLSH, linuxTIOCSCTTY:
		a.what = terminalTakesValue
	case linuxTIOCSPGRP, linuxTIOCSPTLCK:
		a.what = terminalTakesInt
	case linuxTIOCGPGRP, linuxTIOCOUTQ, linuxTIOCGSID, linuxTIOCGPTN:
		a.what, a.out = terminalTakesInt, true
	case linuxTCSETS, linuxTCSETSW, linuxTCSETSF:
		a.what = terminalTakesTermios
	case linuxTCGETS:
		a.what, a.out = terminalTakesTermios, true
	case linuxTCSETS2, linuxTCSETSW2, linuxTCSETSF2:
		a.what = terminalTakesTermios2
	case linuxTCGETS2:
		a.what, a.out = terminalTakesTermios2, true
	case linuxTIOCSWINSZ:
		a.what = terminalTakesWinsize
	case linuxTIOCGWINSZ:
		a.what, a.out = terminalTakesWinsize, true
	default:
		return false
	}
	return true
}

// size returns the size of the record at the address the request takes,
// 0 for one that takes no address.
func (a *terminalArg) size() uint64 {
	switch a.what {
	case terminalTakesInt:
		return 4
	case terminalTakesTermios:
		return 36
	case terminalTakesTermios2:
		return 44
	case terminalTakesWinsize:
		return 8
	}
	return 0
}

// decode reads the record at mem, size bytes.
func (a *terminalArg) decode(mem []byte) {
	switch a.what {
	case terminalTakesInt:
		a.value = int32(binary.LittleEndian.Uint32(mem))
	case terminalTakesTermios, terminalTakesTermios2:
		a.termios.decode(mem)
	case terminalTakesWinsize:
		a.winsize = linuxWinsize{
			Row:    binary.LittleEndian.Uint16(mem[0:]),
			Col:    binary.LittleEndian.Uint16(mem[2:]),
			Xpixel: binary.LittleEndian.Uint16(mem[4:]),
			Ypixel: binary.LittleEndian.Uint16(mem[6:]),
		}
	}
}

// encode writes the record at mem as decode reads it.
func (a *terminalArg) encode(mem []byte) {
	switch a.what {
	case terminalTakesInt:
		binary.LittleEndian.PutUint32(mem, uint32(a.value))
	case terminalTakesTermios, terminalTakesTermios2:
		a.termios.encode(mem)
	case terminalTakesWinsize:
		binary.LittleEndian.PutUint16(mem[0:], a.winsize.Row)
		binary.LittleEndian.PutUint16(mem[2:], a.winsize.Col)
		binary.LittleEndian.PutUint16(mem[4:], a.winsize.Xpixel)
		binary.LittleEndian.PutUint16(mem[6:], a.winsize.Ypixel)
	}
}

// Fd_ioctl is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_ioctl") backing ioctl for the requests of a terminal, in Linux's
// numbers (see "terminals" above): the settings (TCGETS, TCSETS, TCSETSW,
// TCSETSF and their termios2 forms), the window size (TIOCGWINSZ,
// TIOCSWINSZ), the line (TCSBRK, TCXONC, TCFLSH), exclusive use
// (TIOCEXCL, TIOCNXCL), the output queue (TIOCOUTQ), the foreground
// process group and the session (TIOCGPGRP, TIOCGSID), and a
// pseudo-terminal's master side (TIOCGPTN, TIOCSPTLCK). arg is the int the
// request takes, or the address of what it takes. A descriptor is a
// terminal when it is a terminal of the host: a standard stream of the
// instance or a file of the FS that is a file of the host (*os.File). The
// call is made of a duplicate of the host's descriptor, and a request that
// waits for the output to drain (TCSETSW, TCSETSF, TCSBRK) waits until it
// has, whatever signal is posted to the guest meanwhile. A terminal of the
// host is the controlling terminal of no instance without a Process
// (WASIConfig.Process), and the runtime changes no process's foreground
// process group or controlling terminal but through TIOCSPGRP
// (terminalGroup): TIOCGPGRP and TIOCSPGRP read and set the foreground
// group of the controlling terminal of the guest's session as the family's.
// Returns what the call returned, or a negative errno: EBADF, ENOTTY for a
// request it does not make and for a descriptor that is no terminal or not
// the controlling terminal, EPERM for a group of another session, ENOSYS
// for TIOCSCTTY and TIOCNOTTY.
func (w *WasiStubs) Fd_ioctl(m *Module, fd, request, arg int32) int32 {
	return w.fdIoctl(m, fd, uint32(request), zext(arg), arg)
}

// Fd_ioctl64 is Fd_ioctl for a memory64 guest, whose argument is 64 bits
// wide as an address; as an int it is the low 32.
func (w *WasiStubs) Fd_ioctl64(m *Module, fd, request int32, arg int64) int32 {
	return w.fdIoctl(m, fd, uint32(request), uint64(arg), int32(arg))
}

// fdIoctl is the body of Fd_ioctl and Fd_ioctl64: addr is the argument as
// an address, value as an int.
func (w *WasiStubs) fdIoctl(m *Module, fd int32, request uint32, addr uint64, value int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	arg := terminalArg{value: value}
	if !arg.of(request) {
		return -_wasiENOTTY
	}
	file := w.opHostFile(op)
	if file == nil {
		return -_wasiENOTTY
	}
	var (
		mem    []byte
		result int
	)
	err := withHostTerminal(file, func(hostFD int) error {
		if size := arg.size(); size > 0 {
			if mem = w.memBytes(m, addr, size); mem == nil {
				return syscall.EFAULT
			}
			if !arg.out {
				arg.decode(mem)
			}
		}
		switch request {
		case linuxTIOCGPGRP, linuxTIOCSPGRP:
			if w.cfg.Process == nil {
				return syscall.ENOTTY
			}
			return w.foregroundGroup(hostFD, request == linuxTIOCSPGRP, &arg.value)
		case linuxTIOCGSID:
			if w.cfg.Process == nil {
				return syscall.ENOTTY
			}
		case linuxTIOCSCTTY, linuxTIOCNOTTY:
			return syscall.ENOSYS
		}
		var err error
		result, err = hostTerminalIoctl(hostFD, request, &arg)
		return err
	})
	if err != nil {
		return -w.guestErrno("fd_ioctl", err)
	}
	if arg.out {
		arg.encode(mem)
	}
	return int32(result)
}

// foregroundGroup is TIOCGPGRP, and with set TIOCSPGRP, of the guest on
// the host's terminal fd, which is to be the controlling terminal of the
// guest's session: the foreground process group is read into, or set from,
// pgrp (terminalGroup). A descriptor of the terminal it keeps no more is
// closed, a failure to close it told WASIConfig.Errors.
func (w *WasiStubs) foregroundGroup(fd int, set bool, pgrp *int32) error {
	w.enterRoot()
	self := w.guestPID()
	w.mu.Lock()
	pids := w.pidsLocked()
	w.mu.Unlock()
	if set {
		// A start in the foreground uses the descriptor kept for it.
		pids.starts.Lock()
		defer pids.starts.Unlock()
	}
	was, closing, err := pids.terminalGroup(self, fd, set, *pgrp)
	if closing >= 0 {
		w.reportError("fd_ioctl", hostCloseFD(closing))
	}
	if err == nil && !set {
		*pgrp = was
	}
	return err
}

// terminalGroup returns the foreground process group of the host's
// terminal fd as the family's process pid sees it, and with set makes it
// pgrp, a group of pid's session; closing is a descriptor of the terminal
// kept no more, -1 for none. The controlling terminal of the session the
// host process is in (hostSession) is the host process's: another session
// of the family has none (ENOTTY). A group is the host's foreground one as
// commandJob puts the group's commands: the group the host process is in
// is the host process's own group, another the host's group of it, and a
// group that has none yet becomes the foreground one once its first
// command is started, in the foreground (hostJob); a group the family does
// not have is the host's as it is. The host's foreground group is changed
// with SIGTTOU blocked (hostSetForeground), as a job control shell ignores
// it: the host process may be in the background. The host's calls made do
// not wait.
func (p *wasiPIDs) terminalGroup(pid int32, fd int, set bool, pgrp int32) (was int32, closing int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sid := p.hostSession
	if proc := p.procs[pid]; proc != nil {
		sid = proc.sid
	}
	if sid != p.hostSession {
		return 0, -1, syscall.ENOTTY
	}
	current, err := hostForeground(fd)
	if err != nil {
		return 0, -1, err
	}
	was = int32(current)
	switch {
	case p.foreground != 0:
		was = p.foreground
	case current == hostProcessGroup():
		was = p.hostGroup
	default:
		for pgid, g := range p.groups {
			if g.host == current {
				was = pgid
			}
		}
	}
	if !set {
		return was, -1, nil
	}
	host, hosts := int(pgrp), true
	switch g := p.groups[pgrp]; {
	case pgrp == p.hostGroup:
		host = hostProcessGroup()
	case g != nil:
		host = g.host
	default:
		for _, proc := range p.procs {
			if proc.pgid == pgrp {
				if proc.sid != sid {
					return was, -1, syscall.EPERM
				}
				hosts = false
			}
		}
	}
	closing = -1
	if p.foreground != 0 {
		closing = p.terminal
	}
	if !hosts {
		// A group of the family's without a group of the host's: the
		// foreground one once its first command is started.
		dup, err := dupHostFD(uintptr(fd))
		if err != nil {
			return was, -1, err
		}
		p.foreground, p.terminal = pgrp, dup
		return was, closing, nil
	}
	if err := hostSetForeground(fd, host); err != nil {
		return was, -1, err
	}
	p.foreground = 0
	return was, closing, nil
}

// ----- numbers of another system -----------------------------------------------

// Numbering gives the guest the numbers of another system — its error
// numbers and the like — in place of those of the guest's own C library
// (WASIConfig.Numbering), for a guest whose program shares numbers with
// code that is not the guest's. The numbers come in families, which the
// guest's C library numbers: family 1 is the error numbers. Its method is
// called without any lock of the WasiStubs held.
type Numbering interface {
	// NumberAt returns the index-th number of family, from 0: the name the
	// number has in C and its value. ok is false past the last number of
	// the family, at index 0 for a family it has no numbers of.
	NumberAt(family, index int32) (name string, value int64, ok bool)
}

// HostNumbering returns the numbers of the host's system that the runtime
// has, for WASIConfig.Numbering, each under its name in C. On linux and
// darwin its families are the error numbers (1), the signals (2), the flags
// of open (3), the events of poll (4), the address families (5), the socket
// types (6), on linux the flags of a socket type (7), the socket level (8),
// the socket options (9), the options of IP (10), IPv6 (11) and TCP (12),
// the flags of send and recv (13), of getaddrinfo (14) and getnameinfo
// (15), the errors of getaddrinfo (16), the locale categories (17), how
// sigprocmask changes the mask (18), the flags of sigaction (19), the
// commands of fcntl (20), the requests of ioctl (21), the items of
// nl_langinfo (22) and, on darwin, the terminal settings (23). On the mips
// architectures of linux it has only the numbers package syscall has. On
// another system it has none.
func HostNumbering() Numbering { return hostNumbering{} }

// hostNumbering is the Numbering HostNumbering returns.
type hostNumbering struct{}

func (hostNumbering) NumberAt(family, index int32) (string, int64, bool) {
	numbers := hostNumberTable(family)
	if index < 0 || int(index) >= len(numbers) {
		return "", 0, false
	}
	return numbers[index].name, numbers[index].value, true
}

// hostNumber is a number of the operating system under its name in C.
type hostNumber struct {
	name  string
	value int64
}

// Host_numbering is a NON-STANDARD host import (module
// wasip1_posix_extension, name "host_numbering"): it tells the guest whose
// numbers its program sees. 0: the numbers of the guest's own C library,
// for an instance without Numbering. 1: the Numbering's
// (WASIConfig.Numbering), which the guest reads with host_number_at.
func (w *WasiStubs) Host_numbering(m *Module) int32 {
	if w.cfg.Numbering == nil {
		return 0
	}
	return 1
}

// Host_numbering64 is Host_numbering for a memory64 guest.
func (w *WasiStubs) Host_numbering64(m *Module) int32 {
	return w.Host_numbering(m)
}

// Host_number_at is a NON-STANDARD host import (module
// wasip1_posix_extension, name "host_number_at"): the index-th number of a
// family of the Numbering (WASIConfig.Numbering). The name the number has
// in C is written at namePtr (at most nameCap bytes, no terminator) and its
// length at nameLenPtr (u32); the number at valuePtr (i64). Returns 0, or a
// negative errno: ENOENT past the last number of the family — at once, for
// an instance without Numbering — and ERANGE for a name longer than
// nameCap.
func (w *WasiStubs) Host_number_at(m *Module, family, index, namePtr, nameCap, nameLenPtr, valuePtr int32) int32 {
	return w.hostNumberAt(m, family, index, zext(namePtr), nameCap, zext(nameLenPtr), zext(valuePtr))
}

// Host_number_at64 is Host_number_at for a memory64 guest.
func (w *WasiStubs) Host_number_at64(m *Module, family, index int32, namePtr int64, nameCap int32, nameLenPtr, valuePtr int64) int32 {
	return w.hostNumberAt(m, family, index, uint64(namePtr), nameCap, uint64(nameLenPtr), uint64(valuePtr))
}

// hostNumberAt is the body of Host_number_at and Host_number_at64.
func (w *WasiStubs) hostNumberAt(m *Module, family, index int32, namePtr uint64, nameCap int32, nameLenPtr, valuePtr uint64) int32 {
	if w.cfg.Numbering == nil {
		return -_wasiENOENT
	}
	name, value, ok := w.cfg.Numbering.NumberAt(family, index)
	if !ok {
		return -_wasiENOENT
	}
	if int64(len(name)) > int64(nameCap) {
		return -_wasiERANGE
	}
	nameOut := w.memBytes(m, namePtr, uint64(len(name)))
	nameLen := w.memBytes(m, nameLenPtr, 4)
	valueOut := w.memBytes(m, valuePtr, 8)
	if nameOut == nil || nameLen == nil || valueOut == nil {
		return -_wasiEFAULT
	}
	copy(nameOut, name)
	binary.LittleEndian.PutUint32(nameLen, uint32(len(name)))
	binary.LittleEndian.PutUint64(valueOut, uint64(value))
	return _wasiESUCCESS
}

// ----- the system logger -------------------------------------------------------

// Syslogger is a system logger as a guest's syslog(3) uses it
// (WASIConfig.Syslog). An error of its methods in the guest's openlog,
// syslog and closelog fails the guest's call with the errno wasiErrnoOf
// gives, and is told WASIConfig.Errors, as those return nothing to the
// guest's program; the error of a Close that CloseAll makes is CloseAll's.
//
// An instance and the instances forked from it share the Syslogger, each
// calling it from its own goroutine, without any lock of the WasiStubs
// held.
type Syslogger interface {
	// Open is the guest's openlog: it reports whether messages from ident
	// can be delivered. options and facility are as in SyslogMessage.
	Open(ident string, options, facility int32) error
	// Log delivers one message.
	Log(msg SyslogMessage) error
	// Close is called once no instance of the fork family uses the
	// Syslogger: an instance uses it from its guest's first openlog or
	// syslog until its closelog or the instance's CloseAll, and Close is
	// called by the last of them to stop. A guest that uses it again
	// afterwards makes Open and Log be called again. Given to more than one
	// NewWASI, it is closed by each of their families.
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
	// PID is the guest's process id (getpid), which LOG_PID logs.
	PID int32
	// Message is the message text.
	Message string
}

// The openlog option flags in SyslogMessage.Options and Syslogger.Open,
// with the values the guest passes (Linux's).
const (
	SyslogOptPID    int32 = 0x01 // LOG_PID: log the process id with each message
	SyslogOptCons   int32 = 0x02 // LOG_CONS: write to the console when the logger fails
	SyslogOptNDelay int32 = 0x08 // LOG_NDELAY: connect at openlog
	SyslogOptPerror int32 = 0x20 // LOG_PERROR: the guest also writes the message to its stderr
)

// HostSyslog returns the host's system logger, for WASIConfig.Syslog: one
// connection to the local syslog daemon, at the socket package log/syslog
// connects to, made at the first message, or at an openlog with
// LOG_NDELAY, and closed by Close. Every message is written over it with
// its own facility, severity and ident, as a local syslog(3) writes it
// ("<PRI>Mmm dd hh:mm:ss IDENT[PID]: MESSAGE"), the process id only with
// LOG_PID; an ident of "" is the name of the program (os.Args[0]). A write
// that fails over a connection made earlier is made again over a new one,
// as syslog(3) does for a daemon that was restarted. The error of
// connecting or writing is the call's; on a system other than darwin and
// linux, where the runtime has no local syslog daemon to connect to, it is
// errors.ErrUnsupported. LOG_CONS changes nothing.
func HostSyslog() Syslogger { return &hostSyslogger{dial: dialHostSyslog} }

// hostSyslogger is the Syslogger HostSyslog returns. conn is its
// connection, nil while it has none, and dial makes one. Its lock is held
// across every connection, write and close. Package log/syslog is not
// used: its Writer gives each of its messages the tag it was made with
// and the host process's id (os.Getpid).
type hostSyslogger struct {
	mu   sync.Mutex
	conn net.Conn
	dial func() (net.Conn, error)
}

func (l *hostSyslogger) Open(ident string, options, facility int32) error {
	if facility < 0 || facility > 23 {
		return syscall.EINVAL
	}
	if options&SyslogOptNDelay == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		return nil
	}
	conn, err := l.dial()
	l.conn = conn
	return err
}

func (l *hostSyslogger) Log(msg SyslogMessage) error {
	if msg.Severity < 0 || msg.Severity > 7 || msg.Facility < 0 || msg.Facility > 23 {
		return syscall.EINVAL
	}
	line := hostSyslogLine(msg, time.Now())
	l.mu.Lock()
	defer l.mu.Unlock()
	var stale error
	if l.conn != nil {
		_, err := io.WriteString(l.conn, line)
		if err == nil {
			return nil
		}
		// The connection made before the daemon was restarted fails; the
		// write over a new one is the message's answer, as for glibc's
		// __vsyslog_internal and package log/syslog's writeAndRetry, so the
		// errors of the old one are the call's only when that fails too.
		stale = errors.Join(err, l.conn.Close())
		l.conn = nil
	}
	conn, err := l.dial()
	if err != nil {
		return errors.Join(stale, err)
	}
	l.conn = conn
	if _, err := io.WriteString(conn, line); err != nil {
		return errors.Join(stale, err)
	}
	return nil
}

// Close closes the connection; a message logged later connects again.
func (l *hostSyslogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil
	}
	err := l.conn.Close()
	l.conn = nil
	return err
}

// hostSyslogLine returns msg, logged at now, as the line package log/syslog
// writes to a local daemon (with the ident and process id of msg's guest):
// "<PRI>Mmm dd hh:mm:ss IDENT[PID]: MESSAGE" and a newline unless the
// message ends with one, the [PID] only with LOG_PID.
func hostSyslogLine(msg SyslogMessage, now time.Time) string {
	tag := msg.Ident
	if tag == "" {
		tag = os.Args[0]
	}
	if msg.Options&SyslogOptPID != 0 {
		tag += "[" + strconv.Itoa(int(msg.PID)) + "]"
	}
	nl := "\n"
	if strings.HasSuffix(msg.Message, "\n") {
		nl = ""
	}
	return fmt.Sprintf("<%d>%s %s: %s%s", msg.Facility<<3|msg.Severity, now.Format(time.Stamp), tag, msg.Message, nl)
}

// familySyslog is what the instances of a fork family share of their
// Syslogger: how many of them use it (syslogInUse). Its lock is held
// across the Close the last of them to stop makes (stopSyslog), so an
// instance that starts to use the Syslogger then waits for that Close.
type familySyslog struct {
	mu    sync.Mutex
	users int
}

// syslogFamilyLocked returns the family's familySyslog, made on first use.
// Caller holds w.mu.
func (w *WasiStubs) syslogFamilyLocked() *familySyslog {
	if w.syslog == nil {
		w.syslog = &familySyslog{}
	}
	return w.syslog
}

// useSyslog records that the instance's guest uses the Syslogger, which it
// must have.
func (w *WasiStubs) useSyslog() {
	w.mu.Lock()
	family := w.syslogFamilyLocked()
	w.mu.Unlock()
	family.mu.Lock()
	defer family.mu.Unlock()
	if !w.syslogInUse {
		w.syslogInUse = true
		family.users++
	}
}

// stopSyslog records that the instance no longer uses the Syslogger, and
// closes it when no instance of the family uses it any longer.
func (w *WasiStubs) stopSyslog() error {
	if w.cfg.Syslog == nil {
		return nil
	}
	w.mu.Lock()
	family := w.syslogFamilyLocked()
	w.mu.Unlock()
	family.mu.Lock()
	defer family.mu.Unlock()
	if !w.syslogInUse {
		return nil
	}
	w.syslogInUse = false
	family.users--
	if family.users > 0 {
		return nil
	}
	return w.cfg.Syslog.Close()
}

// syslogErrno returns the negative errno of err, an error of the Syslogger
// for the import op, and tells WASIConfig.Errors of it: the guest's
// openlog, syslog and closelog return nothing.
func (w *WasiStubs) syslogErrno(op string, err error) int32 {
	if err == nil {
		return _wasiESUCCESS
	}
	w.reportError(op, err)
	// Told Errors whether or not it has an errno of its own, so the bool
	// that says so is not needed.
	errno, _ := wasiErrnoOf(err)
	return -errno
}

// Proc_syslog_open is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_syslog_open") backing openlog(): the
// guest is about to log as (identPtr, identLen) with the given option flags
// (SyslogOpt*) and default facility number. Returns 0 when the Syslogger
// (WASIConfig.Syslog) accepts, or a negative errno: EINVAL for a facility
// out of range (0..23), ENOSYS for an instance without a Syslogger,
// otherwise what the logger reported.
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
	if ident == nil {
		return -_wasiEFAULT
	}
	if facility < 0 || facility > 23 {
		return -_wasiEINVAL
	}
	if w.cfg.Syslog == nil {
		return -_wasiENOSYS
	}
	w.useSyslog()
	return w.syslogErrno("proc_syslog_open", w.cfg.Syslog.Open(string(ident), options, facility))
}

// Proc_syslog is a NON-STANDARD host import (module wasip1_posix_extension,
// name "proc_syslog") backing syslog(): one message, as the values
// syslog(3) works with — the severity (0..7), the facility number (0..23),
// the option flags and ident of the guest's openlog, and the message text.
// Returns 0 once the Syslogger (WASIConfig.Syslog) has taken the message,
// or a negative errno: ENOSYS for an instance without one, EINVAL for a
// severity or facility out of range, otherwise what the logger reported.
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
	if ident == nil || text == nil {
		return -_wasiEFAULT
	}
	if severity < 0 || severity > 7 || facility < 0 || facility > 23 {
		return -_wasiEINVAL
	}
	if w.cfg.Syslog == nil {
		return -_wasiENOSYS
	}
	w.useSyslog()
	return w.syslogErrno("proc_syslog", w.cfg.Syslog.Log(SyslogMessage{
		Severity: severity,
		Facility: facility,
		Options:  options,
		Ident:    string(ident),
		PID:      w.guestPID(),
		Message:  string(text),
	}))
}

// Proc_syslog_close is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_syslog_close") backing closelog(): the
// instance stops using the Syslogger, which is closed when no instance of
// its fork family uses it (Syslogger.Close). Returns 0, or a negative errno
// as Proc_syslog_open.
func (w *WasiStubs) Proc_syslog_close(m *Module) int32 {
	if w.cfg.Syslog == nil {
		return -_wasiENOSYS
	}
	return w.syslogErrno("proc_syslog_close", w.stopSyslog())
}

// Proc_syslog_close64 is Proc_syslog_close for a memory64 guest.
func (w *WasiStubs) Proc_syslog_close64(m *Module) int32 {
	return w.Proc_syslog_close(m)
}

// ----- System V IPC -------------------------------------------------------------

// IPC gives the guest System V IPC (WASIConfig.IPC): message queues,
// semaphore sets and shared memory segments. Numbers and structures are the
// guest's: Linux's, the structures laid out as on a 64-bit architecture of
// asm-generic. The runtime calls the methods without the lock of the
// WasiStubs held. It calls ShmAttach and ShmDetach for an instance one at a
// time, with the runtime's mappings locked: they must not block, nor call
// SharedImage.Memory or UnmapMemory. A call that waits (semop, msgsnd and msgrcv without IPC_NOWAIT)
// waits until it is done: neither a signal posted to the guest nor CloseAll
// ends it, and the guest takes a signal posted meanwhile once the call has
// returned. An error that is errors.ErrUnsupported makes the guest's call
// fail with ENOSYS; another one is its errno.
//
// A shared memory segment is attached over a part of the guest's memory,
// and only of a memory the runtime mapped itself, which does not move
// (SharedImage.Memory): the guest's shmat fails with ENOMEM on any other.
//
// A wasm32 guest has msgget, semget, shmget and semop alone: its own
// structures of the others (its msqid_ds, semid_ds and shmid_ds, the
// message whose type is a 4-byte long) are not the ones of a 64-bit
// architecture the runtime passes on, so its msgsnd and msgrcv fail with
// ENOSYS, and so do its msgctl, semctl and shmctl of a command that passes
// one (ipcCommandPassesNoStructure), and with them its shmat and shmdt.
type IPC interface {
	// Get is msgget, semget or shmget: the id of the object of the kind with
	// the key. arg is the number of semaphores of a set, or the size of a
	// segment.
	Get(kind IPCKind, key int32, arg uint64, flags int32) (id int32, err error)
	// Control is msgctl, semctl or shmctl: the command cmd on the object id
	// of the kind, num being the semaphore of a set, and what the call
	// returns. For IPC_STAT and IPC_SET buf holds the kind's structure; for
	// GETALL and SETALL the values of the set's semaphores, an unsigned
	// short each; for SETVAL arg is the value. buf is the guest's memory
	// from the address the guest gave to its end (nil for an address past
	// it): the command uses what it reads and writes of it, and fails with
	// EFAULT when buf is shorter.
	Control(kind IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error)
	// Semop is semop: ops are the operations, struct sembuf each (unsigned
	// short sem_num, short sem_op, short sem_flg).
	Semop(id int32, ops []byte) error
	// Msgsnd is msgsnd: msg is the message, its type (a long, 8 bytes) and
	// then its bytes.
	Msgsnd(id int32, msg []byte, flags int32) error
	// Msgrcv is msgrcv: a message of the type is received into msg (its
	// type, then room for its bytes), and the number of its bytes returned.
	Msgrcv(id int32, msg []byte, typ int64, flags int32) (int, error)
	// ShmAttach is shmat: the segment id is attached over at, the part of
	// the guest's memory the guest gave, which starts at a page boundary of
	// the host and is as long as the whole pages of the segment, whose size
	// the runtime has read with Control (IPC_STAT); flags are shmat's
	// (SHM_RDONLY). The guest then reads and writes the segment where at
	// is.
	ShmAttach(id int32, at []byte, flags int32) error
	// ShmDetach is shmdt: the segment ShmAttach attached over at is
	// detached, and at is the guest's memory again, all zero.
	ShmDetach(at []byte) error
}

// shmAttachment is a System V shared memory segment the guest has attached
// (Ipc_shmat): the memory it is attached over, and the runtime mapping that
// memory is a part of. Nothing is done over the memory once the mapping is
// released.
type shmAttachment struct {
	at      []byte
	mapping *runtimeMapping
}

// IPCKind is the kind of a System V IPC object.
type IPCKind int32

// The kinds of System V IPC object.
const (
	IPCMessageQueue IPCKind = 0
	IPCSemaphoreSet IPCKind = 1
	IPCSharedMemory IPCKind = 2
)

// HostIPC returns an IPC that reaches the System V IPC objects of the host,
// which other processes of the system share, for WASIConfig.IPC. It has
// them on Linux on amd64, arm64, riscv64 and loong64, whose structures are
// the guest's; elsewhere every call fails with errors.ErrUnsupported. A
// call that the host process is interrupted in (EINTR) is made again. The
// operations made with SEM_UNDO are undone when the host process ends, not
// when the instance does. A store into a segment the guest attached
// read-only (SHM_RDONLY), the guest's or the runtime's for the guest (the
// bytes of an fd_read, say), faults the host process, as it faults a
// process that attached the segment. Get refuses SHM_HUGETLB (EINVAL): the
// mapping of a segment of huge pages is as long as its huge pages, not as
// its size.
func HostIPC() IPC { return hostIPC{} }

// hostIPC is the IPC HostIPC returns. Its methods are the platform's.
type hostIPC struct{}

// The guest's commands of msgctl, semctl and shmctl, which are Linux's.
const (
	ipcCmdRmid    = 0
	ipcCmdSet     = 1
	ipcCmdStat    = 2
	ipcCmdGetPid  = 11
	ipcCmdGetVal  = 12
	ipcCmdGetAll  = 13
	ipcCmdGetNcnt = 14
	ipcCmdGetZcnt = 15
	ipcCmdSetVal  = 16
	ipcCmdSetAll  = 17
	// shmctl's own commands, whose numbers are semctl's GETPID and GETVAL
	ipcCmdShmLock   = 11
	ipcCmdShmUnlock = 12
)

// ipcStructSize is the size of the kernel's structure of the kind (struct
// msqid64_ds, semid64_ds, shmid64_ds), the guest's.
func ipcStructSize(kind IPCKind) int {
	switch kind {
	case IPCMessageQueue:
		return 120
	case IPCSemaphoreSet:
		return 88
	}
	return 112
}

// Where the guest's shmid64_ds has the size of the segment (shm_segsz).
const ipcShmSegsz = 48

// ipcShmPages returns the length of the whole pages of the host that a
// segment of segsz bytes is mapped in, and whether that is no more than
// room.
func ipcShmPages(segsz uint64, room int) (uint64, bool) {
	if segsz > uint64(room) {
		return 0, false
	}
	page := uint64(os.Getpagesize())
	pages := segsz + (page-segsz%page)%page
	return pages, pages <= uint64(room)
}

// ipcCommandPassesNoStructure reports whether the command cmd of msgctl,
// semctl or shmctl, on an object of the kind, passes no structure: IPC_RMID,
// semctl's GETPID, GETVAL, GETNCNT, GETZCNT and SETVAL, and shmctl's
// SHM_LOCK and SHM_UNLOCK.
func ipcCommandPassesNoStructure(kind, cmd int32) bool {
	switch {
	case cmd == ipcCmdRmid:
		return true
	case kind == int32(IPCSemaphoreSet):
		return cmd == ipcCmdGetPid || cmd == ipcCmdGetVal || cmd == ipcCmdGetNcnt || cmd == ipcCmdGetZcnt || cmd == ipcCmdSetVal
	case kind == int32(IPCSharedMemory):
		return cmd == ipcCmdShmLock || cmd == ipcCmdShmUnlock
	}
	return false
}

// ipc returns the IPC of the instance for a call on objects of the kind,
// or a wasi errno: ENOSYS without one, EINVAL for a kind there is none of.
func (w *WasiStubs) ipc(kind int32) (IPC, int32) {
	switch {
	case w.cfg.IPC == nil:
		return nil, _wasiENOSYS
	case kind < int32(IPCMessageQueue) || kind > int32(IPCSharedMemory):
		return nil, _wasiEINVAL
	}
	return w.cfg.IPC, _wasiESUCCESS
}

// Ipc_get is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_get") backing msgget, semget and shmget (IPC.Get): the id is
// written at idPtr (i32). Returns 0 or a negative errno.
func (w *WasiStubs) Ipc_get(m *Module, kind, key int32, arg int64, flags, idPtr int32) int32 {
	return w.ipcGet(m, kind, key, uint64(arg), flags, zext(idPtr))
}

// Ipc_get64 is Ipc_get for a memory64 guest.
func (w *WasiStubs) Ipc_get64(m *Module, kind, key int32, arg int64, flags int32, idPtr int64) int32 {
	return w.ipcGet(m, kind, key, uint64(arg), flags, uint64(idPtr))
}

// ipcGet is the body of Ipc_get and Ipc_get64.
func (w *WasiStubs) ipcGet(m *Module, kind, key int32, arg uint64, flags int32, idPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, idPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}
	ipc, errno := w.ipc(kind)
	if errno != _wasiESUCCESS {
		return -errno
	}
	id, err := ipc.Get(IPCKind(kind), key, arg, flags)
	if err != nil {
		return -w.guestErrno("ipc_get", err)
	}
	binary.LittleEndian.PutUint32(out, uint32(id))
	return _wasiESUCCESS
}

// Ipc_ctl is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_ctl") backing msgctl, semctl and shmctl (IPC.Control): bufPtr
// is the command's buffer, and what the call returns is written at
// resultPtr (i64). Returns 0 or a negative errno; ENOSYS for a wasm32
// guest's command that passes a structure (IPC).
func (w *WasiStubs) Ipc_ctl(m *Module, kind, id, num, cmd int32, arg int64, bufPtr, resultPtr int32) int32 {
	// a kind there is none of fails as it does for a memory64 guest (ipcCtl)
	if _, errno := w.ipc(kind); errno == _wasiESUCCESS && !ipcCommandPassesNoStructure(kind, cmd) {
		return -_wasiENOSYS
	}
	return w.ipcCtl(m, kind, id, num, cmd, uint64(arg), zext(bufPtr), zext(resultPtr))
}

// Ipc_ctl64 is Ipc_ctl for a memory64 guest.
func (w *WasiStubs) Ipc_ctl64(m *Module, kind, id, num, cmd int32, arg, bufPtr, resultPtr int64) int32 {
	return w.ipcCtl(m, kind, id, num, cmd, uint64(arg), uint64(bufPtr), uint64(resultPtr))
}

// ipcCtl is the body of Ipc_ctl and Ipc_ctl64.
func (w *WasiStubs) ipcCtl(m *Module, kind, id, num, cmd int32, arg, bufPtr, resultPtr uint64) int32 {
	w.endUnregistered()
	out := w.memBytes(m, resultPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	ipc, errno := w.ipc(kind)
	if errno != _wasiESUCCESS {
		return -errno
	}
	var buf []byte
	if mem := w.guestMemory(m); bufPtr <= uint64(len(mem)) {
		buf = mem[bufPtr:]
	}
	r, err := ipc.Control(IPCKind(kind), id, num, cmd, arg, buf)
	if err != nil {
		return -w.guestErrno("ipc_ctl", err)
	}
	binary.LittleEndian.PutUint64(out, uint64(r))
	return _wasiESUCCESS
}

// Ipc_semop is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_semop") backing semop (IPC.Semop): the nops operations at
// opsPtr. Returns 0 or a negative errno.
func (w *WasiStubs) Ipc_semop(m *Module, id, opsPtr int32, nops int64) int32 {
	return w.ipcSemop(m, id, zext(opsPtr), uint64(nops))
}

// Ipc_semop64 is Ipc_semop for a memory64 guest.
func (w *WasiStubs) Ipc_semop64(m *Module, id int32, opsPtr, nops int64) int32 {
	return w.ipcSemop(m, id, uint64(opsPtr), uint64(nops))
}

// ipcSemop is the body of Ipc_semop and Ipc_semop64. A call that waits
// looks for a signal that ends the guest again when it returns
// (endUnregistered).
func (w *WasiStubs) ipcSemop(m *Module, id int32, opsPtr, nops uint64) int32 {
	w.endUnregistered()
	ipc, errno := w.ipc(int32(IPCSemaphoreSet))
	if errno != _wasiESUCCESS {
		return -errno
	}
	// struct sembuf is 6 bytes; a count no memory holds is no count.
	if nops > ^uint64(0)/6 {
		return -_wasiE2BIG
	}
	ops := w.memBytes(m, opsPtr, nops*6)
	if ops == nil {
		return -_wasiEFAULT
	}
	err := ipc.Semop(id, ops)
	w.endUnregistered()
	if err != nil {
		return -w.guestErrno("ipc_semop", err)
	}
	return _wasiESUCCESS
}

// Ipc_msgsnd is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_msgsnd") backing msgsnd (IPC.Msgsnd): the message at msgPtr,
// its type and then size bytes. Returns 0 or a negative errno; ENOSYS for
// a wasm32 guest (IPC).
func (w *WasiStubs) Ipc_msgsnd(m *Module, id, msgPtr int32, size int64, flags int32) int32 {
	return -_wasiENOSYS
}

// Ipc_msgsnd64 is Ipc_msgsnd for a memory64 guest.
func (w *WasiStubs) Ipc_msgsnd64(m *Module, id int32, msgPtr, size int64, flags int32) int32 {
	return w.ipcMsgsnd(m, id, uint64(msgPtr), uint64(size), flags)
}

// ipcMsgsnd is the body of Ipc_msgsnd and Ipc_msgsnd64. A call that waits
// looks for a signal that ends the guest again when it returns
// (endUnregistered).
func (w *WasiStubs) ipcMsgsnd(m *Module, id int32, msgPtr, size uint64, flags int32) int32 {
	w.endUnregistered()
	ipc, errno := w.ipc(int32(IPCMessageQueue))
	if errno != _wasiESUCCESS {
		return -errno
	}
	msg := w.ipcMessage(m, msgPtr, size)
	if msg == nil {
		return -_wasiEFAULT
	}
	err := ipc.Msgsnd(id, msg, flags)
	w.endUnregistered()
	if err != nil {
		return -w.guestErrno("ipc_msgsnd", err)
	}
	return _wasiESUCCESS
}

// ipcMessage returns the message buffer at msgPtr: its type, a long, then
// size bytes; nil when that is not all in the guest's memory.
func (w *WasiStubs) ipcMessage(m *Module, msgPtr, size uint64) []byte {
	if size > ^uint64(0)-8 {
		return nil
	}
	return w.memBytes(m, msgPtr, 8+size)
}

// Ipc_msgrcv is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_msgrcv") backing msgrcv (IPC.Msgrcv): a message of the type is
// received into msgPtr (its type, then at most size bytes), and the number
// of its bytes written at receivedPtr (i64). Returns 0 or a negative errno;
// ENOSYS for a wasm32 guest (IPC).
func (w *WasiStubs) Ipc_msgrcv(m *Module, id, msgPtr int32, size, typ int64, flags, receivedPtr int32) int32 {
	return -_wasiENOSYS
}

// Ipc_msgrcv64 is Ipc_msgrcv for a memory64 guest.
func (w *WasiStubs) Ipc_msgrcv64(m *Module, id int32, msgPtr, size, typ int64, flags int32, receivedPtr int64) int32 {
	return w.ipcMsgrcv(m, id, uint64(msgPtr), uint64(size), typ, flags, uint64(receivedPtr))
}

// ipcMsgrcv is the body of Ipc_msgrcv and Ipc_msgrcv64. A call that waits
// looks for a signal that ends the guest again when it returns
// (endUnregistered).
func (w *WasiStubs) ipcMsgrcv(m *Module, id int32, msgPtr, size uint64, typ int64, flags int32, receivedPtr uint64) int32 {
	w.endUnregistered()
	ipc, errno := w.ipc(int32(IPCMessageQueue))
	if errno != _wasiESUCCESS {
		return -errno
	}
	msg := w.ipcMessage(m, msgPtr, size)
	out := w.memBytes(m, receivedPtr, 8)
	if msg == nil || out == nil {
		return -_wasiEFAULT
	}
	n, err := ipc.Msgrcv(id, msg, typ, flags)
	w.endUnregistered()
	if err != nil {
		return -w.guestErrno("ipc_msgrcv", err)
	}
	binary.LittleEndian.PutUint64(out, uint64(n))
	return _wasiESUCCESS
}

// Ipc_shmat is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_shmat") backing shmat (IPC.ShmAttach): the segment id is
// attached over the size bytes of the guest's memory at addr, which the
// guest has set aside for it, from its start as far as the segment's whole
// pages go. Returns 0 or a negative errno: ENOMEM when the guest's memory
// is not one a segment can be attached over (IPC), EINVAL for no memory,
// memory outside the guest's, off a page boundary of the host, shorter
// than the segment's pages, or a segment is attached over already, or
// after CloseAll, and
// the errno of the IPC_STAT of the segment (Control); ENOSYS for a wasm32
// guest (IPC).
func (w *WasiStubs) Ipc_shmat(m *Module, id, addr int32, size int64, flags int32) int32 {
	return -_wasiENOSYS
}

// Ipc_shmat64 is Ipc_shmat for a memory64 guest.
func (w *WasiStubs) Ipc_shmat64(m *Module, id int32, addr, size int64, flags int32) int32 {
	return w.ipcShmat(m, id, uint64(addr), uint64(size), flags)
}

// ipcShmat is the body of Ipc_shmat and Ipc_shmat64.
func (w *WasiStubs) ipcShmat(m *Module, id int32, addr, size uint64, flags int32) int32 {
	w.endUnregistered()
	ipc, errno := w.ipc(int32(IPCSharedMemory))
	if errno != _wasiESUCCESS {
		return -errno
	}
	at := w.memBytes(m, addr, size)
	if size == 0 || at == nil {
		return -_wasiEINVAL
	}
	mapping := runtimeMappingOf(w.guestMemory(m))
	if mapping == nil {
		return -_wasiENOMEM
	}
	// The mapping starts at a page boundary: the guest's address is where
	// in a page the host's is.
	if addr%uint64(os.Getpagesize()) != 0 {
		return -_wasiEINVAL
	}
	// The runtime records the pages it hands ShmAttach, which checks them
	// again itself for a caller other than the runtime.
	st := make([]byte, ipcStructSize(IPCSharedMemory))
	if _, err := ipc.Control(IPCSharedMemory, id, 0, ipcCmdStat, 0, st); err != nil {
		return -w.guestErrno("ipc_shmat", err)
	}
	pages, ok := ipcShmPages(binary.LittleEndian.Uint64(st[ipcShmSegsz:]), len(at))
	if !ok {
		return -_wasiEINVAL
	}
	at = at[:pages]
	errno, err := func() (int32, error) {
		w.shmMu.Lock()
		defer w.shmMu.Unlock()
		if w.shmClosed {
			return _wasiEINVAL, nil
		}
		for other, over := range w.shm {
			if addr < other+uint64(len(over.at)) && other < addr+pages {
				return _wasiEINVAL, nil
			}
		}
		var err error
		attach := func() {
			if err = ipc.ShmAttach(id, at, flags); err == nil {
				noteSegment(mapping, at, true)
			}
		}
		if !whileRuntimeMapped(mapping, attach) {
			return _wasiENOMEM, nil
		}
		if err != nil {
			return 0, err
		}
		if w.shm == nil {
			w.shm = map[uint64]shmAttachment{}
		}
		w.shm[addr] = shmAttachment{at: at, mapping: mapping}
		return _wasiESUCCESS, nil
	}()
	if err != nil {
		// Errors is told without the lock held.
		return -w.guestErrno("ipc_shmat", err)
	}
	return -errno
}

// Ipc_shmdt is a NON-STANDARD host import (module wasip1_posix_extension,
// name "ipc_shmdt") backing shmdt (IPC.ShmDetach): the segment Ipc_shmat
// attached at addr is detached. Returns 0 or a negative errno: EINVAL when
// no segment is attached at addr; ENOSYS for a wasm32 guest (IPC).
func (w *WasiStubs) Ipc_shmdt(m *Module, addr int32) int32 {
	return -_wasiENOSYS
}

// Ipc_shmdt64 is Ipc_shmdt for a memory64 guest.
func (w *WasiStubs) Ipc_shmdt64(m *Module, addr int64) int32 {
	return w.ipcShmdt(uint64(addr))
}

// ipcShmdt is the body of Ipc_shmdt and Ipc_shmdt64.
func (w *WasiStubs) ipcShmdt(addr uint64) int32 {
	w.endUnregistered()
	ipc, errno := w.ipc(int32(IPCSharedMemory))
	if errno != _wasiESUCCESS {
		return -errno
	}
	errno, err := func() (int32, error) {
		w.shmMu.Lock()
		defer w.shmMu.Unlock()
		attachment, ok := w.shm[addr]
		if !ok {
			return _wasiEINVAL, nil
		}
		if err := detachShm(ipc, attachment); err != nil {
			return 0, err
		}
		delete(w.shm, addr)
		return _wasiESUCCESS, nil
	}()
	if err != nil {
		// Errors is told without the lock held.
		return -w.guestErrno("ipc_shmdt", err)
	}
	return -errno
}

// detachAllShm detaches every segment the guest has attached (CloseAll),
// and joins the errors of the ones that stay attached.
func (w *WasiStubs) detachAllShm() error {
	w.shmMu.Lock()
	defer w.shmMu.Unlock()
	w.shmClosed = true
	var err error
	for addr, attachment := range w.shm {
		if detachErr := detachShm(w.cfg.IPC, attachment); detachErr != nil {
			err = errors.Join(err, detachErr)
			continue
		}
		delete(w.shm, addr)
	}
	return err
}

// detachShm detaches the segment of the attachment while its mapping is
// not released. A released mapping took the segment with it: nothing is
// done over memory that is no longer the mapping.
func detachShm(ipc IPC, attachment shmAttachment) error {
	var err error
	whileRuntimeMapped(attachment.mapping, func() {
		if err = ipc.ShmDetach(attachment.at); err == nil {
			noteSegment(attachment.mapping, attachment.at, false)
		}
	})
	return err
}

// ----- access, FIFOs and locks -------------------------------------------------

// Path_access is a NON-STANDARD host import (module wasip1_posix_extension,
// name "path_access") backing access and faccessat: whether the guest may
// make the accesses of amode to the file at the preopen-relative path
// (pathPtr, pathLen). amode is access's (F_OK 0, or any of X_OK 1, W_OK 2,
// R_OK 4); flags bit 0 (wasiAccessEffective) asks with the effective ids
// instead of the real ones, as AT_EACCESS does.
//
// A file of an FS that is an AccessFS is asked about by the FS. HostFS's
// ask the host's own check (faccessat(2)), which also knows access control
// lists and read-only mounts, for the host process's ids; MemFS allows
// every access to a file it has, as its open checks none. Where the FS
// cannot say (errors.ErrUnsupported: an effective-id question on darwin
// from a process whose effective ids are not its real ones, a HostFS of a
// directory on darwin, a host without the call), for a file of any other
// FS, and for a name of the guest's own descriptors, the access is decided
// by the file's mode bits and owner, for the ids and the supplementary
// groups of the Process (WASIConfig.Process): user id 0 may read and write
// anything, and run what has any x bit, or search any directory. Returns 0, or a negative errno: EACCES when the access is
// refused, ENOENT and the like when the file cannot be found, EINVAL for an
// amode or flags it does not know.
func (w *WasiStubs) Path_access(m *Module, pathPtr, pathLen, amode, flags int32) int32 {
	return w.pathAccess(m, zext(pathPtr), pathLen, amode, flags)
}

// Path_access64 is Path_access for a memory64 guest.
func (w *WasiStubs) Path_access64(m *Module, pathPtr int64, pathLen, amode, flags int32) int32 {
	return w.pathAccess(m, uint64(pathPtr), pathLen, amode, flags)
}

// The bits of Path_access's amode (access's R_OK, W_OK, X_OK) and flags.
const (
	wasiAccessExec      int32 = 1
	wasiAccessWrite     int32 = 2
	wasiAccessRead      int32 = 4
	wasiAccessEffective int32 = 1
)

// pathAccess is the body of Path_access and Path_access64.
func (w *WasiStubs) pathAccess(m *Module, pathPtr uint64, pathLen, amode, flags int32) int32 {
	pathSlice := w.memBytes(m, pathPtr, zext(pathLen))
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	if amode&^(wasiAccessRead|wasiAccessWrite|wasiAccessExec) != 0 || flags&^wasiAccessEffective != 0 {
		return -_wasiEINVAL
	}
	name, errno := w.guestName(string(pathSlice))
	if errno != _wasiESUCCESS {
		return -errno
	}
	name, fd, fi, own, errno := w.ownFile(name, true)
	switch {
	case errno != _wasiESUCCESS:
		return -errno
	case own && fi == nil:
		// The descriptor the name leads to is what fd_filestat_ext tells.
		var rec [wasiFilestatExtSize]byte
		if rc := w.filestatExtOf(fd, rec[:]); rc != _wasiESUCCESS {
			return rc
		}
		bits := binary.LittleEndian.Uint32(rec[:])
		info := ownNameInfo{mode: unixFileMode(bits), uid: binary.LittleEndian.Uint32(rec[4:]), gid: binary.LittleEndian.Uint32(rec[8:])}
		if bits&unixTypeMask == unixTypeDir {
			info.mode |= os.ModeDir
		}
		fi = info
	}
	return -w.accessName("path_access", name, fi, amode, flags&wasiAccessEffective != 0)
}

// accessName is the decision of Path_access about the accesses of amode to
// name, a name guestName gave, with the
// effective ids when effective is set: of the file of the FS, or, when fi
// is not nil, of what a name of the guest's own descriptors leads to, which
// fi describes. Returns 0 or a wasi errno; op names the call to
// WASIConfig.Errors.
func (w *WasiStubs) accessName(op, name string, fi os.FileInfo, amode int32, effective bool) int32 {
	own := fi != nil
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	if decides, ok := fsys.(AccessFS); ok && !own {
		if err := decides.Access(name, uint32(amode), effective); !errors.Is(err, errors.ErrUnsupported) {
			return w.guestErrno(op, err)
		}
	}
	if !own {
		var err error
		if fi, err = fsys.Stat(name); err != nil {
			return w.guestErrno(op, err)
		}
	}
	if amode == 0 {
		return _wasiESUCCESS
	}
	ids := w.guestIDs()
	uid, gid := ids.UID, ids.GID
	if effective {
		uid, gid = ids.EUID, ids.EGID
	}
	groups, err := w.guestGroups()
	if err != nil {
		return w.guestErrno(op, err)
	}
	if !modeAllows(fi, fileStatOf(fi), uint32(amode), uint32(uid), uint32(gid), groups) {
		return _wasiEACCES
	}
	return _wasiESUCCESS
}

// modeAllows reports whether a process of user uid and group gid (with the
// supplementary groups) may make the accesses of amode to the file fi
// describes, by its mode bits, as access(2) decides without access control
// lists: the owner's bits for its owner, the group's for a member of its
// group, the others' for the rest; uid 0 may read and write anything, and
// run what has any x bit, or search any directory.
func modeAllows(fi os.FileInfo, st fileStat, amode, uid, gid uint32, groups []int32) bool {
	perm := uint32(fi.Mode().Perm())
	if uid == 0 {
		return amode&uint32(wasiAccessExec) == 0 || fi.IsDir() || perm&0o111 != 0
	}
	shift := uint32(0)
	switch {
	case st.uid == uid:
		shift = 6
	case st.gid == gid || slices.Contains(groups, int32(st.gid)):
		shift = 3
	}
	return (perm>>shift)&amode == amode
}

// Path_mkfifo is a NON-STANDARD host import (module wasip1_posix_extension,
// name "path_mkfifo") backing mkfifo: it creates a FIFO at the
// preopen-relative path with the given permission bits, less the
// instance's umask. Returns 0, or a negative errno: ENOSYS when the
// filesystem of the instance is no MkfifoFS (of HostFS's, only the whole
// host filesystem's, HostFS("/"), is one).
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
	name, errno := w.changedName(string(pathSlice), nameMake)
	if errno != _wasiESUCCESS {
		return -errno
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	maker, can := fsys.(MkfifoFS)
	if !can {
		return -_wasiENOSYS
	}
	if err := w.create(fsys, unixFileMode(uint32(mode)).Perm(), func(perm os.FileMode) error { return maker.Mkfifo(name, perm) }); err != nil {
		return -w.guestErrno("path_mkfifo", err)
	}
	return _wasiESUCCESS
}

// Access asks the host about an access to a file of the host filesystem
// (hostAccess); errors.ErrUnsupported where the host cannot say.
func (o osFS) Access(name string, mode uint32, effective bool) error {
	asked, err := hostAccess(o.join(name), mode, effective)
	if !asked {
		return errors.ErrUnsupported
	}
	return err
}

// Access asks the host about an access to a file of the directory, through
// the directory os.Root holds (rootAccess).
func (r rootFS) Access(name string, mode uint32, effective bool) error {
	return r.refused(rootAccess(r.root, r.name(name), mode, effective))
}

// Access allows every access to a file the MemFS has: its open checks no
// permission either.
func (fsys *MemFS) Access(name string, mode uint32, effective bool) error {
	_, err := fsys.Stat(name)
	return err
}

// Mkfifo creates a FIFO in the host filesystem.
func (o osFS) Mkfifo(name string, perm os.FileMode) error {
	return makeHostFIFO(o.join(name), perm)
}

// openFIFO opens the FIFO name, which fi describes, for reading or for
// writing the way a blocking open(2) does: it waits until the other end is
// open too, on a goroutine of its own, and a signal posted to the guest
// ends the wait with EINTR. The open cannot be called off, so it is made to
// return: the FIFO is opened once more, for reading and writing, which is
// the other end of either and does not wait, and both opens are closed
// again before the guest is told — an open that was interrupted leaves no
// end of the FIFO open behind, which the next open of the other end would
// take for a peer. When that open fails, or opens another file than fi
// (the name was given to another file meanwhile), its error is told
// WASIConfig.Errors, and the first open is left to return when someone
// else opens the FIFO: the goroutine closes what it opened then. When the
// wait ends because the guest is ended (terminate unwinds the call), the
// open is made to return as well, and what fails is told Errors.
//
// An open for reading of a FIFO of a filesystem of the host's is made
// without opening the other end where the host can tell of the opens of
// the FIFO (openFIFOWatched).
func (w *WasiStubs) openFIFO(m *Module, fsys FS, name string, fi os.FileInfo, flag int, perm os.FileMode) (File, int32) {
	openFile := fsys.OpenFile
	if hostFiles(fsys) && flag&os.O_WRONLY == 0 {
		if f, errno, watched := w.openFIFOWatched(m, openFile, name, flag, perm); watched {
			return f, errno
		}
	}
	var f File
	call := newDetachedCall(func(err error) {
		if err != nil {
			return
		}
		if err := f.Close(); err != nil {
			w.reportError("path_open", err)
		}
	})
	defer call.leave()
	go func() {
		var err error
		f, err = openFile(name, flag, perm)
		call.finish(err)
	}()
	awaited := false
	defer func() {
		if !awaited {
			unblockErr, closeErr := unblockFIFOOpen(openFile, name, fi, call, &f)
			w.reportError("path_open", errors.Join(unblockErr, closeErr))
		}
	}()
	opened := w.awaitInterruptibly(m, call.done)
	awaited = true
	if opened {
		err := call.take()
		if err != nil {
			return nil, w.guestErrno("path_open", err)
		}
		return f, _wasiESUCCESS
	}
	unblockErr, closeErr := unblockFIFOOpen(openFile, name, fi, call, &f)
	if unblockErr != nil {
		// The guest is told EINTR: no call of its is left to fail with
		// this.
		w.reportError("path_open", unblockErr)
		return nil, _wasiEINTR
	}
	if closeErr != nil {
		return nil, w.guestErrno("path_open", closeErr)
	}
	return nil, _wasiEINTR
}

// unblockFIFOOpen makes the open of the FIFO name, which fi describes, that
// call makes return, by opening the FIFO for reading and writing, the other
// end of either open, which does not wait; once it has returned, what it
// opened (*f) and that end are closed. unblockErr is why the open could not
// be made to return: it is left to return when someone else opens the
// FIFO, and call closes what it opens then. closeErr is the closes'.
func unblockFIFOOpen(openFile func(name string, flag int, perm os.FileMode) (File, error), name string, fi os.FileInfo, call *detachedCall, f *File) (unblockErr, closeErr error) {
	end, err := openFile(name, os.O_RDWR, 0)
	if err != nil {
		return err, nil
	}
	endInfo, err := end.Stat()
	if err == nil && !os.SameFile(fi, endInfo) {
		err = fmt.Errorf("%s is another file than the FIFO whose open waits", name)
	}
	if err != nil {
		return errors.Join(err, end.Close()), nil
	}
	<-call.done
	closeErr = end.Close()
	if openErr := call.take(); openErr == nil {
		closeErr = errors.Join(closeErr, (*f).Close())
	}
	return nil, closeErr
}

// detachedCall is a call made on a goroutine of its own that the guest
// waits for and may stop waiting for: interrupted by a signal, or ended
// while it waits. What the call did is undone (undo) when the waiter has
// left without its result: by the goroutine when the call returns after
// that, by the waiter when it returned before.
type detachedCall struct {
	// done is closed once the call has returned (finish).
	done chan struct{}
	// stop is closed when the waiter leaves without the result (leave):
	// a call that can be ended then returns.
	stop chan struct{}
	// undo undoes what a call that returned err did.
	undo func(err error)

	mu sync.Mutex
	// returned, taken and left are set when the call has returned, when
	// the waiter has taken its result, and when the waiter has left
	// without it.
	returned, taken, left bool
	err                   error
}

// newDetachedCall returns a detachedCall whose call is undone by undo.
func newDetachedCall(undo func(err error)) *detachedCall {
	return &detachedCall{done: make(chan struct{}), stop: make(chan struct{}), undo: undo}
}

// finish is called by the goroutine with the call's error, once.
func (c *detachedCall) finish(err error) {
	c.mu.Lock()
	c.returned, c.err = true, err
	left := c.left
	c.mu.Unlock()
	close(c.done)
	if left {
		c.undo(err)
	}
}

// take returns the call's error, which the waiter keeps: nothing is
// undone. Only after done is closed.
func (c *detachedCall) take() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.taken = true
	return c.err
}

// leave is deferred by the waiter: unless it took the result, the call is
// undone — now when it has returned, by finish otherwise.
func (c *detachedCall) leave() {
	c.mu.Lock()
	if c.taken || c.left {
		c.mu.Unlock()
		return
	}
	c.left = true
	returned, err := c.returned, c.err
	c.mu.Unlock()
	close(c.stop)
	if returned {
		c.undo(err)
	}
}

// LockFS is an FS whose files take advisory locks, for the guest's flock
// (fd_flock). The guest of an FS that is not a LockFS has no such locks:
// its flock of a file fails with ENOSYS. HostFS and NewMemFS return
// LockFSes.
type LockFS interface {
	FS
	// Flock applies or removes an advisory lock on f, a file the FS opened,
	// with the semantics of flock(2): how is LOCK_SH (1) for a shared lock,
	// LOCK_EX (2) for an exclusive one or LOCK_UN (8) to remove the lock,
	// with LOCK_NB (4) added for a lock that is not to be waited for — one
	// that cannot be had at once then fails with syscall.EAGAIN. The lock
	// belongs to the open file: everything that shares f shares the lock,
	// another open of the same file competes for it, and closing f removes
	// it.
	//
	// A call that waits runs on a goroutine of its own, without any lock
	// of the WasiStubs held, and is not called off: when a signal posted to
	// the guest ends the guest's wait first, the lock the call takes later
	// is removed at once (LOCK_UN).
	Flock(f File, how int) error
}

// The operations of LockFS.Flock: flock(2)'s LOCK_SH, LOCK_EX, LOCK_NB and
// LOCK_UN, which have these values on every system that has them.
const (
	flockShared    = 1
	flockExclusive = 2
	flockNonblock  = 4
	flockUnlock    = 8
)

// Flock implements LockFS.Flock for the files of the host filesystem.
func (osFS) Flock(f File, how int) error {
	file, isHost := f.(*os.File)
	if !isHost {
		return syscall.EBADF
	}
	return flockOSFile(file, how)
}

// Flock implements LockFS.Flock for the files of the directory.
func (rootFS) Flock(f File, how int) error {
	file, isHost := f.(*os.File)
	if !isHost {
		return syscall.EBADF
	}
	return flockOSFile(file, how)
}

// Flock implements LockFS.Flock for the files of this MemFS.
func (fsys *MemFS) Flock(f File, how int) error { return fsys.flockUntil(f, how, nil) }

// stoppableLockFS is a LockFS whose Flock that waits can be ended, as
// MemFS's: flockUntil is Flock, whose wait for a lock held elsewhere ends
// with errLockWaitLeft once stop is closed (a nil stop never is).
type stoppableLockFS interface {
	flockUntil(f File, how int, stop <-chan struct{}) error
}

// errLockWaitLeft is what flockUntil returns when its waiter has left.
var errLockWaitLeft = errors.New("the wait for the lock was left")

// flockUntil implements stoppableLockFS for the files of this MemFS.
func (fsys *MemFS) flockUntil(f File, how int, stop <-chan struct{}) error {
	mf, ok := f.(*memFile)
	if !ok || mf.fsys != fsys {
		return syscall.EBADF
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	lock := how &^ flockNonblock
	switch lock {
	case flockUnlock:
		mf.unlockLocked()
		return nil
	case flockShared, flockExclusive:
	default:
		return syscall.EINVAL
	}
	node := mf.node
	if held, holds := node.locks[mf]; holds {
		if held == lock {
			return nil
		}
		// As flock(2) converts a lock: the lock held goes first, so a
		// conversion that waits, or fails because it may not, leaves
		// the file without one.
		mf.unlockLocked()
	}
	for node.lockConflicts(mf, lock) {
		if how&flockNonblock != 0 {
			return syscall.EAGAIN
		}
		if fsys.lockReleased == nil {
			fsys.lockReleased = make(chan struct{})
		}
		released := fsys.lockReleased
		fsys.mu.Unlock()
		select {
		case <-released:
		case <-stop:
			fsys.mu.Lock()
			return errLockWaitLeft
		}
		fsys.mu.Lock()
	}
	if node.locks == nil {
		node.locks = map[*memFile]int{}
	}
	node.locks[mf] = lock
	return nil
}

// lockConflicts reports whether an open file other than f holds a lock on n
// that rules out f taking lock (flockShared or flockExclusive). Caller
// holds the MemFS lock.
func (n *memNode) lockConflicts(f *memFile, lock int) bool {
	for holder, held := range n.locks {
		if holder != f && (lock == flockExclusive || held == flockExclusive) {
			return true
		}
	}
	return false
}

// unlockLocked removes the lock f holds, if any, and wakes the waiters.
// Caller holds the MemFS lock.
func (f *memFile) unlockLocked() {
	if _, held := f.node.locks[f]; !held {
		return
	}
	delete(f.node.locks, f)
	if f.fsys.lockReleased != nil {
		close(f.fsys.lockReleased)
		f.fsys.lockReleased = nil
	}
}

// Fd_flock is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_flock") backing flock(). lock is 0 to unlock, 1 for a shared and
// 2 for an exclusive lock; wait is non-zero when the call may block until
// the lock is granted, and otherwise a lock held elsewhere makes it fail
// with EAGAIN. The lock belongs to the open descriptor: every fd that
// shares it (dup, fork) shares the lock, and the lock goes when the last of
// them is closed. A file of the FS is locked by the FS (LockFS); a
// standard stream that is a file of the host (an *os.File) by the host, and
// any other has no other opener to exclude, so its lock is granted. Returns
// 0, or a negative errno: ENOSYS for a file of an FS that is no LockFS,
// EINVAL for a descriptor of no file (a socket); a waiting call ends with
// EINTR when a signal is posted to the guest (see LockFS).
func (w *WasiStubs) Fd_flock(m *Module, fd, lock, wait int32) int32 {
	var how int
	switch lock {
	case 0:
		how = flockUnlock
	case 1:
		how = flockShared
	case 2:
		how = flockExclusive
	default:
		return -_wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	fsys := w.fs()
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	// flock takes a lock; one that waits ends once stop is closed when
	// stoppable says so.
	var flock func(how int, stop <-chan struct{}) error
	stoppable := false
	switch {
	case op.f != nil:
		locks, can := fsys.(LockFS)
		if !can {
			return -_wasiENOSYS
		}
		flock = func(how int, _ <-chan struct{}) error { return locks.Flock(op.f, how) }
		if until, can := fsys.(stoppableLockFS); can {
			flock, stoppable = func(how int, stop <-chan struct{}) error { return until.flockUntil(op.f, how, stop) }, true
		}
	case op.stdio != 0:
		stream, isHost := [...]any{w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr}[op.stdio-1].(*os.File)
		if !isHost {
			return _wasiESUCCESS
		}
		flock = func(how int, _ <-chan struct{}) error { return flockOSFile(stream, how) }
	default:
		return -_wasiEINVAL
	}
	set := func(wait bool, stop <-chan struct{}) error {
		if !wait && how != flockUnlock {
			return flock(how|flockNonblock, nil)
		}
		return flock(how, stop)
	}
	interrupted, err := w.takeLock(m, how, op, wait != 0, stoppable, set, func() error { return flock(flockUnlock, nil) })
	if interrupted {
		return -_wasiEINTR
	}
	if err != nil {
		return -w.guestErrno("fd_flock", err)
	}
	return _wasiESUCCESS
}

// Fd_flock64 is Fd_flock for a memory64 guest.
func (w *WasiStubs) Fd_flock64(m *Module, fd, lock, wait int32) int32 {
	return w.Fd_flock(m, fd, lock, wait)
}

// takeLock takes or removes (how flockUnlock) the flock how of the
// descriptor op with set, which may wait for a lock held elsewhere when
// wait is true and must not otherwise. A call that may wait is made once,
// on a goroutine of its own (detachedCall), and the guest waits for it
// until a signal is posted to it (awaitInterruptibly): then interrupted is
// true. When the guest stops waiting — interrupted, or ended while it
// waits — the call is given its stop (detachedCall), and the lock it takes
// later is removed with unlock at once; a stoppable call returns at its
// stop, and the guest waits for that. Until that is done, a lock of op
// that may wait waits for it first, and one that may not fails with
// syscall.EAGAIN, so that removing the late lock removes none the guest
// asked for afterwards. err is the error of set; an error of unlock is
// told WASIConfig.Errors.
//
// The descriptor may be shared, and several of its sharers may wait for
// the same lock at once; their calls all get it when it is granted. So a
// late grant is removed only when no other wait of the descriptor for that
// lock is in progress and none has taken it: a lock a wait took counts as
// held until the descriptor's next lock call (lockHeld).
func (w *WasiStubs) takeLock(m *Module, how int, op *wasiOpen, wait, stoppable bool, set func(wait bool, stop <-chan struct{}) error, unlock func() error) (interrupted bool, err error) {
	unlocks := how == flockUnlock
	op.mu.Lock()
	pending := op.lockPending
	op.mu.Unlock()
	if pending != nil && !unlocks {
		if !wait {
			return false, syscall.EAGAIN
		}
		if !w.awaitInterruptibly(m, pending) {
			return true, nil
		}
	}
	op.mu.Lock()
	clear(op.lockHeld)
	op.mu.Unlock()
	if unlocks || !wait {
		return false, set(false, nil)
	}
	released := make(chan struct{})
	call := newDetachedCall(func(err error) {
		op.mu.Lock()
		shared := op.lockWaits[how] > 0 || op.lockHeld[how]
		op.mu.Unlock()
		if err == nil && !shared {
			// A descriptor the guest has closed meanwhile has no lock
			// left: its close released it.
			if err := unlock(); err != nil && !errors.Is(err, fs.ErrClosed) {
				// The guest has stopped waiting: no call of its is left
				// to fail with this.
				w.reportError("fd_flock", err)
			}
		}
		op.mu.Lock()
		if op.lockPending == released {
			op.lockPending = nil
		}
		op.mu.Unlock()
		close(released)
	})
	op.mu.Lock()
	if op.lockWaits == nil {
		op.lockWaits = map[int]int{}
	}
	op.lockWaits[how]++
	op.mu.Unlock()
	taken := false
	defer func() {
		op.mu.Lock()
		if op.lockWaits[how]--; op.lockWaits[how] == 0 {
			delete(op.lockWaits, how)
		}
		if !taken {
			op.lockPending = released
		}
		op.mu.Unlock()
		if !taken {
			call.leave()
			if stoppable {
				<-released
			}
		}
	}()
	go func() { call.finish(set(true, call.stop)) }()
	if w.awaitInterruptibly(m, call.done) {
		taken = true
		err := call.take()
		if err == nil {
			op.mu.Lock()
			if op.lockHeld == nil {
				op.lockHeld = map[int]bool{}
			}
			op.lockHeld[how] = true
			op.mu.Unlock()
		}
		return false, err
	}
	return true, nil
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

// The commands of Fd_lock, and the types of a recordLock.
const (
	recordLockGet  int32 = 0 // F_GETLK
	recordLockSet  int32 = 1 // F_SETLK
	recordLockWait int32 = 2 // F_SETLKW
	recordRead     int32 = 0 // F_RDLCK
	recordWrite    int32 = 1 // F_WRLCK
	recordUnlock   int32 = 2 // F_UNLCK
)

// Fd_lock is a NON-STANDARD host import (module wasip1_posix_extension,
// name "fd_lock") backing fcntl's F_GETLK, F_SETLK and F_SETLKW: a POSIX
// record lock of a file of the host that path_open opened. cmd is
// recordLockGet, recordLockSet or recordLockWait, and lockPtr the lock
// (recordLock), whose range is taken from where the file's offset and size
// are at the call (SEEK_CUR, SEEK_END).
//
// The locks are the instance's, as fcntl's are a process's: the threads of
// the guest share them, a copy made by Fork or ForkProc starts without
// any, and the instances exclude each other — an inherited descriptor
// included. Closing any descriptor of the file, the last of a shared one
// or not, removes the instance's locks of the file, and a lock call that
// meets the close of its descriptor fails with EBADF, the lock it took
// removed again. The runtime keeps the locks of the instances of a
// generated package in one table: those of the instances of another
// generated package are another process's to it (see below). The table
// keeps an instance that holds a lock in memory, and the lock in force,
// until the instance closes a descriptor of the file: an instance dropped
// without CloseDescriptors or CloseAll keeps its locks. F_GETLK
// writes back the lock in the way of the one asked about — of an instance,
// with the pid of the instance's Process when the instance is of the
// caller's fork family and -1 otherwise — or the one asked about with type
// F_UNLCK when none would be. F_SETLKW waits for an instance's lock until a
// signal is posted to the guest (EINTR) or the descriptor is closed
// (EBADF).
//
// The other processes of the host are excluded by locks of the host that
// hold what the table holds. On Linux they are the locks of one open file
// description of the file, which the runtime opens again through
// /proc/self/fd for reading and writing — with the descriptor's access
// mode when that open fails, as it does for a file being run (ETXTBSY) —
// and keeps while a descriptor that locked the file is open: until then
// the file cannot be run (execve fails with ETXTBSY), and its close is an
// IN_CLOSE_WRITE to inotify. It is a duplicate of the descriptor for a
// file that is not a regular file, and for one that cannot be opened again
// (no /proc). A lock of another process in the way has the pid -1 when
// it is a lock of an open file description, as Linux reports, and the
// host's pid of its process for one of fcntl's own kind. A lock whose kind
// the description was not opened for, which the descriptor that asks for
// it is, is taken on a description opened again when the locks held are
// reads only and no call waits, and fails with ENOLCK otherwise. Elsewhere
// the locks are the host process's, taken through the descriptor at hand:
// the close of any descriptor of the file in the host process — of any
// instance, of a duplicate the runtime made, or of the embedder's —
// removes them all, while the table keeps the instances' own; the
// instances of other generated packages and the embedder's own locks of
// the file are the same process's, which neither excludes the other. There
// a wait for another process's lock holds its descriptor, whose close
// waits for it: the close of a duplicate would release the process's
// locks.
//
// A wait for a lock of another process is one F_SETLKW on a goroutine of
// its own, which cannot be called off: it goes on after the guest stops
// waiting, and when it takes the lock after that, the locks of the host in
// its range are brought back to what the table holds. Until it is done, a
// lock of the range that the waiting one rules out — the instance's own
// included — waits for it, or fails with EAGAIN without F_SETLKW: another
// thread of the guest too, and a lock of an instance that the other
// process waits for in turn waits until a signal, where the kernel would
// grant it when the ranges differ. A read lock that would wait for another
// process's lock over a write lock of the instance's fails with ENOLCK
// instead: the read the host grants the wait, after the guest stopped
// waiting too, replaces the write at the host.
//
// Returns 0 or a negative errno: EAGAIN or EACCES for a lock held
// elsewhere, ENOLCK as above, EBADF for a lock of a kind the descriptor is
// not open for (F_RDLCK for writing only, F_WRLCK for reading only),
// EINVAL for a range that starts before the start of the file, EOVERFLOW
// for one that ends past the largest offset, ENOTSUP for a descriptor
// path_open did not open a file of the host for (a stream of the
// embedder's, a pipe, a socket, a file of an in-memory filesystem) and on
// a system with no record locks.
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
	if cmd < recordLockGet || cmd > recordLockWait || lk.typ < 0 || lk.typ > recordUnlock || lk.whence < 0 || lk.whence > 2 || cmd == recordLockGet && lk.typ == recordUnlock {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	f, isHost := op.f.(*os.File)
	if !isHost || !op.hasFileKey || !hostRecordLocks {
		return -_wasiENOTSUP
	}
	if cmd != recordLockGet && (lk.typ == recordRead && op.noRead || lk.typ == recordWrite && op.noWrite) {
		return -_wasiEBADF
	}
	if errno := w.absoluteRecordLock(f, &lk); errno != _wasiESUCCESS {
		return -errno
	}
	start, end, errno := recordRange(lk.start, lk.len)
	if errno != _wasiESUCCESS {
		return -errno
	}
	want := lockRow{owner: w, write: lk.typ == recordWrite, start: start, end: end}
	if cmd != recordLockGet {
		want.pid = w.guestPID()
	}
	w.recordLockUses.Add(1)
	defer w.recordLockUses.Add(-1)
	file := op.useLockedFile()
	if file == nil {
		// The descriptor was closed meanwhile.
		return -_wasiEBADF
	}
	defer func() { w.reportError("fd_lock", releaseLockedFile(file, false)) }()
	if cmd == recordLockGet {
		return w.getRecordLock(rec, f, file, want)
	}
	return w.setRecordLock(m, fd, op, f, file, want, lk.typ == recordUnlock, cmd == recordLockWait)
}

// getRecordLock is fdLock's F_GETLK of want, a lock of the file of f whose
// table entry is file, which writes the answer in rec.
func (w *WasiStubs) getRecordLock(rec []byte, f *os.File, file *lockedFile, want lockRow) int32 {
	w.mu.Lock()
	family := w.pidsLocked()
	w.mu.Unlock()
	file.mu.Lock()
	held, found := file.conflictLocked(want, false)
	lk := want.hostLock()
	if found {
		lk = held.hostLock()
		lk.pid = -1
		if held.family == family {
			lk.pid = held.pid
		}
	} else if err := file.hostLockLocked(f, recordLockGet, &lk); err != nil {
		file.mu.Unlock()
		return -w.guestErrno("fd_lock", err)
	}
	file.mu.Unlock()
	binary.LittleEndian.PutUint32(rec[0:], uint32(lk.typ))
	if lk.typ == recordUnlock {
		// As fcntl(2) has it, only the type changes.
		return _wasiESUCCESS
	}
	binary.LittleEndian.PutUint32(rec[4:], uint32(lk.whence))
	binary.LittleEndian.PutUint64(rec[8:], uint64(lk.start))
	binary.LittleEndian.PutUint64(rec[16:], uint64(lk.len))
	binary.LittleEndian.PutUint32(rec[24:], uint32(lk.pid))
	return _wasiESUCCESS
}

// setRecordLock is fdLock's F_SETLK (wait false) and F_SETLKW of want, or
// its removal (unlocks), through descriptor fd, whose entry op is, of the
// file of f whose table entry is file. A lock of another instance in the
// way is waited for on the table (changed), and one of another process at
// the host (waitHostRecordLock). The descriptor is looked at before each
// try and after the lock is in the table (keepRecordLock), so that a lock
// call that meets its close takes nothing (Linux's fcntl_setlk).
func (w *WasiStubs) setRecordLock(m *Module, fd int32, op *wasiOpen, f *os.File, file *lockedFile, want lockRow, unlocks, wait bool) int32 {
	// The failure of an open the call went on past (prepareHostLocked),
	// reported once file.mu is let go: every return comes after.
	var passed error
	defer func() { w.reportError("fd_lock", passed) }()
	for {
		w.mu.Lock()
		open := w.openLocked(fd) == op
		want.family = w.pidsLocked()
		w.mu.Unlock()
		if !open {
			return -_wasiEBADF
		}
		file.mu.Lock()
		if file.gone {
			file.mu.Unlock()
			return -_wasiEBADF
		}
		if unlocks {
			w.setRowsLocked(file, want, true)
			err := file.resyncLocked(want.start, want.end, f)
			file.mu.Unlock()
			if err != nil {
				return -w.guestErrno("fd_lock", err)
			}
			return _wasiESUCCESS
		}
		if _, conflict := file.conflictLocked(want, true); conflict {
			if !wait {
				file.mu.Unlock()
				return -_wasiEAGAIN
			}
			changed := file.changedLocked()
			file.mu.Unlock()
			if !w.awaitInterruptibly(m, changed) {
				return -_wasiEINTR
			}
			continue
		}
		var err error
		if passed, err = file.prepareHostLocked(f, op.regular, !op.noRead, !op.noWrite, want.write); err != nil {
			file.mu.Unlock()
			return -w.guestErrno("fd_lock", err)
		}
		// The table rules out a lock of another instance in the range that
		// conflicts with want: the host's lock of the range is want's.
		lk := want.hostLock()
		err = file.hostLockLocked(f, recordLockSet, &lk)
		if err == nil {
			w.setRowsLocked(file, want, false)
			file.mu.Unlock()
			return w.keepRecordLock(fd, op, f, file)
		}
		if !wait || !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
			file.mu.Unlock()
			return -w.guestErrno("fd_lock", err)
		}
		if !want.write && slices.ContainsFunc(file.rows, func(r lockRow) bool { return r.owner == w && r.write && r.conflicts(want) }) {
			// The read the host grants the wait, after the guest stopped
			// waiting too, replaces w's write in the range, which another
			// process can share before the table's write is set again.
			file.mu.Unlock()
			return -_wasiENOLCK
		}
		return w.waitHostRecordLock(m, fd, op, f, file, want)
	}
}

// keepRecordLock is the end of a lock fdLock has put in the table through
// descriptor fd, whose entry op was: when fd holds op no longer, its close
// came in between, and the instance's locks of the file go (EBADF), as the
// close would have removed them.
func (w *WasiStubs) keepRecordLock(fd int32, op *wasiOpen, f *os.File, file *lockedFile) int32 {
	w.mu.Lock()
	if w.openLocked(fd) == op {
		w.mu.Unlock()
		return _wasiESUCCESS
	}
	file.mu.Lock()
	w.dropRowsLocked(file)
	file.mu.Unlock()
	w.mu.Unlock()
	file.mu.Lock()
	err := file.resyncLocked(0, recordEnd, f)
	file.mu.Unlock()
	// The call fails for the close; the host's locks have no call left to
	// fail with this.
	w.reportError("fd_lock", err)
	return -_wasiEBADF
}

// waitHostRecordLock is setRecordLock's wait for want, which a lock of
// another process is in the way of: one F_SETLKW on a goroutine of its own
// (detachedCall), on a duplicate of the host's open file description of
// the locks where there is one. The wait is in the table (waits) until
// what it took is in the table or brought back to it. Caller holds
// file.mu, which it lets go.
func (w *WasiStubs) waitHostRecordLock(m *Module, fd int32, op *wasiOpen, f *os.File, file *lockedFile, want lockRow) int32 {
	waitFD, err := file.waitDescriptorLocked()
	if err != nil {
		file.mu.Unlock()
		return -w.guestErrno("fd_lock", err)
	}
	wait := &want
	file.waits = append(file.waits, wait)
	file.changeLocked()
	file.mu.Unlock()
	call := newDetachedCall(func(err error) { w.leaveHostRecordLock(file, wait, f, err) })
	taken := false
	defer func() {
		if !taken {
			call.leave()
		}
	}()
	lk := want.hostLock()
	go func() { call.finish(hostWaitRecordLock(waitFD, f, &lk)) }()
	if !w.awaitInterruptibly(m, call.done) {
		return -_wasiEINTR
	}
	taken = true
	err = call.take()
	file.mu.Lock()
	file.waits = slices.DeleteFunc(file.waits, func(r *lockRow) bool { return r == wait })
	file.changeLocked()
	if err == nil {
		w.setRowsLocked(file, want, false)
	}
	file.mu.Unlock()
	if err != nil {
		return -w.guestErrno("fd_lock", err)
	}
	return w.keepRecordLock(fd, op, f, file)
}

// leaveHostRecordLock is the undo of a wait of waitHostRecordLock the
// guest left, which returned err: the wait leaves the table, and the locks
// of the host in its range, which a lock it took changed, are brought back
// to the table's.
func (w *WasiStubs) leaveHostRecordLock(file *lockedFile, wait *lockRow, f *os.File, err error) {
	file.mu.Lock()
	file.waits = slices.DeleteFunc(file.waits, func(r *lockRow) bool { return r == wait })
	file.changeLocked()
	var resyncErr error
	if err == nil {
		resyncErr = file.resyncLocked(wait.start, wait.end, f)
	}
	file.mu.Unlock()
	// The guest has stopped waiting: no call of its is left to fail with
	// these.
	w.reportError("fd_lock", resyncErr)
	w.reportError("fd_lock", releaseLockedFile(file, false))
}

// recordLocks is the table of the record locks (fd_lock) the instances of
// this package hold, by file. Its lock is taken after the WasiStubs' and
// the wasiOpens' and before the lockedFiles'.
var recordLocks = struct {
	mu    sync.Mutex
	files map[fileKey]*lockedFile
}{files: map[fileKey]*lockedFile{}}

// fileKey names a file of the host: its device and inode.
type fileKey struct{ dev, ino uint64 }

// lockedFile is the entry of recordLocks for a file: the locks the
// instances hold of it and the waits for one at the host, and the host's
// locks that exclude the other processes.
type lockedFile struct {
	key fileKey
	// uses counts the descriptors that use the entry (useLockedFile).
	// Guarded by recordLocks.mu.
	uses int

	// mu guards the fields below. The host's locks are taken under it.
	mu sync.Mutex
	// rows are the locks the instances hold, by start: those of an owner
	// do not overlap.
	rows []lockRow
	// waits are the locks waited for at the host (waitHostRecordLock).
	waits []*lockRow
	// changed is closed, and dropped for the next waiter to make a fresh
	// one, whenever rows or waits change (changeLocked).
	changed chan struct{}
	// host is the host's open file description of the locks where they are
	// a description's (hostRecordLocksOfDescription), -1 before the first;
	// hostRead and hostWrite say what it is open for.
	host                int
	hostRead, hostWrite bool
	// gone is set once the entry has left the table (releaseLockedFile).
	gone bool
}

// lockRow is a record lock of an instance (owner), or a wait for one: a
// write or a read lock of [start, end), end recordEnd for one to the end
// of the file however long it grows. pid is the pid of the owner's
// Process when it asked, and family its fork family's pid allocator, which
// F_GETLK tells the pid to.
type lockRow struct {
	owner      *WasiStubs
	family     *wasiPIDs
	pid        int32
	write      bool
	start, end uint64
}

// recordEnd is the end of a range of a record lock to the end of the
// file: one past the largest offset, the last byte of every such lock.
const recordEnd uint64 = 1 << 63

// conflicts reports whether r and o overlap and one of them is a write
// lock.
func (r lockRow) conflicts(o lockRow) bool {
	return r.start < o.end && o.start < r.end && (r.write || o.write)
}

// hostLock returns r as a recordLock from the start of the file.
func (r lockRow) hostLock() recordLock {
	lk := recordLock{typ: recordRead, start: int64(r.start)}
	if r.write {
		lk.typ = recordWrite
	}
	if r.end != recordEnd {
		lk.len = int64(r.end - r.start)
	}
	return lk
}

// recordRange returns the range [start, end) of the record lock of length
// at start, as fcntl(2) takes one (Linux's flock64_to_posix_lock): to the
// end of the file for length 0, the length before start for a negative
// one. Returns a wasi errno: EINVAL for a range before the start of the
// file, EOVERFLOW for one past the largest offset.
func recordRange(start, length int64) (uint64, uint64, int32) {
	switch {
	case start < 0 || length < 0 && start+length < 0:
		return 0, 0, _wasiEINVAL
	case length == 0:
		return uint64(start), recordEnd, _wasiESUCCESS
	case length < 0:
		return uint64(start + length), uint64(start), _wasiESUCCESS
	case length-1 > math.MaxInt64-start:
		return 0, 0, _wasiEOVERFLOW
	}
	return uint64(start), uint64(start) + uint64(length), _wasiESUCCESS
}

// useLockedFile returns the table entry of op's file, which op uses from
// then on (uses) until closeWasiOpen lets it go; nil once op has left
// every table, to be closed.
func (op *wasiOpen) useLockedFile() *lockedFile {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.lockedFile == nil && op.refs > 0 {
		recordLocks.mu.Lock()
		file := recordLocks.files[op.fileKey]
		if file == nil {
			file = &lockedFile{key: op.fileKey, host: -1}
			recordLocks.files[op.fileKey] = file
		}
		file.uses++
		recordLocks.mu.Unlock()
		op.lockedFile = file
	}
	return op.lockedFile
}

// releaseLockedFile lets go of a use of file (useLockedFile) when use is
// true, and takes the entry out of the table once nothing uses it, holds a
// lock of it or waits for one, closing the host's description of its
// locks.
func releaseLockedFile(file *lockedFile, use bool) error {
	recordLocks.mu.Lock()
	defer recordLocks.mu.Unlock()
	if use {
		file.uses--
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.gone || file.uses > 0 || len(file.rows) > 0 || len(file.waits) > 0 {
		return nil
	}
	file.gone = true
	delete(recordLocks.files, file.key)
	return file.closeHostLocked()
}

// changedLocked returns the channel a wait for a change of the table's
// locks of file waits on. Caller holds file.mu.
func (file *lockedFile) changedLocked() <-chan struct{} {
	if file.changed == nil {
		file.changed = make(chan struct{})
	}
	return file.changed
}

// changeLocked wakes the waits for a change of the locks of file: rows or
// waits changed. Caller holds file.mu.
func (file *lockedFile) changeLocked() {
	if file.changed != nil {
		close(file.changed)
		file.changed = nil
	}
}

// conflictLocked returns a lock of another instance than want's owner that
// conflicts with want, the first by start, and with waits also a wait for
// a lock that does — want's owner's included: a lock the host gives the
// wait would replace in the host's description what want took. Caller
// holds file.mu.
func (file *lockedFile) conflictLocked(want lockRow, waits bool) (lockRow, bool) {
	for _, r := range file.rows {
		if r.owner != want.owner && r.conflicts(want) {
			return r, true
		}
	}
	if waits {
		for _, r := range file.waits {
			if r.conflicts(want) {
				return *r, true
			}
		}
	}
	return lockRow{}, false
}

// holdsLocked reports whether w holds a lock of file. Caller holds
// file.mu.
func (file *lockedFile) holdsLocked(w *WasiStubs) bool {
	return slices.ContainsFunc(file.rows, func(r lockRow) bool { return r.owner == w })
}

// setRowsLocked puts want, a lock of w, in the table, or removes w's locks
// of want's range (unlocks): w's locks in the range are cut out of the
// range, and want joins those of w of its type it touches, as fcntl(2)
// splits and merges a process's locks. Caller holds file.mu.
func (w *WasiStubs) setRowsLocked(file *lockedFile, want lockRow, unlocks bool) {
	held := file.holdsLocked(w)
	var rows []lockRow
	for _, r := range file.rows {
		switch {
		case r.owner != w || r.end < want.start || want.end < r.start:
			rows = append(rows, r)
		case !unlocks && r.write == want.write:
			want.start, want.end = min(want.start, r.start), max(want.end, r.end)
		case r.end == want.start || want.end == r.start:
			// Touching only: another type, or a range unlocked next to it.
			rows = append(rows, r)
		default:
			if r.start < want.start {
				left := r
				left.end = want.start
				rows = append(rows, left)
			}
			if want.end < r.end {
				right := r
				right.start = want.end
				rows = append(rows, right)
			}
		}
	}
	if !unlocks {
		rows = append(rows, want)
	}
	slices.SortFunc(rows, func(a, b lockRow) int { return cmp.Compare(a.start, b.start) })
	file.rows = rows
	w.countHeld(file, held)
	file.changeLocked()
}

// dropRowsLocked removes every lock w holds of file and reports whether
// there was one; it wakes the waits for a change either way. Caller holds
// file.mu.
func (w *WasiStubs) dropRowsLocked(file *lockedFile) bool {
	held := file.holdsLocked(w)
	file.rows = slices.DeleteFunc(file.rows, func(r lockRow) bool { return r.owner == w })
	w.countHeld(file, held)
	file.changeLocked()
	return held
}

// countHeld counts in recordLockUses that w holds locks of file now, or no
// longer, after a change of its rows: held is whether it did before.
// Caller holds file.mu.
func (w *WasiStubs) countHeld(file *lockedFile, held bool) {
	switch holds := file.holdsLocked(w); {
	case holds && !held:
		w.recordLockUses.Add(1)
	case held && !holds:
		w.recordLockUses.Add(-1)
	}
}

// resyncLocked brings the host's locks of [start, end) of file down to
// what the table holds there, through via where the locks are the host
// process's: in each stretch the strongest lock an instance holds, or none.
// The stretches a wait at the host overlaps are left as they are, where
// the host may have granted the wait its lock already. Elsewhere the
// host's locks are the table's, and in the range of a wait no weaker (a
// read does not wait over a write of its owner, setRecordLock): a lock set
// here only weakens the host's, so nothing is waited for. Caller holds
// file.mu.
func (file *lockedFile) resyncLocked(start, end uint64, via *os.File) error {
	if file.gone {
		return nil
	}
	cuts := []uint64{start, end}
	cut := func(at uint64) {
		if start < at && at < end {
			cuts = append(cuts, at)
		}
	}
	for _, r := range file.rows {
		cut(r.start)
		cut(r.end)
	}
	for _, r := range file.waits {
		cut(r.start)
		cut(r.end)
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	type span struct {
		typ        int32
		start, end uint64
	}
	var spans []span
	for i := 0; i+1 < len(cuts); i++ {
		stretch := lockRow{start: cuts[i], end: cuts[i+1], write: true}
		if slices.ContainsFunc(file.waits, func(r *lockRow) bool { return r.conflicts(stretch) }) {
			continue
		}
		typ := recordUnlock
		for _, r := range file.rows {
			if r.conflicts(stretch) {
				if r.write {
					typ = recordWrite
				} else if typ == recordUnlock {
					typ = recordRead
				}
			}
		}
		if n := len(spans); n > 0 && spans[n-1].end == stretch.start && spans[n-1].typ == typ {
			spans[n-1].end = stretch.end
			continue
		}
		spans = append(spans, span{typ: typ, start: stretch.start, end: stretch.end})
	}
	var err error
	for _, sp := range spans {
		lk := lockRow{start: sp.start, end: sp.end}.hostLock()
		lk.typ = sp.typ
		// A descriptor the guest has closed meanwhile has no lock left of
		// the process's kind: its close released them.
		if lerr := file.hostLockLocked(via, recordLockSet, &lk); lerr != nil && !errors.Is(lerr, fs.ErrClosed) {
			err = errors.Join(err, lerr)
		}
	}
	return err
}

// lockResync is a file whose host's locks a close left to be brought down
// to the table (resyncReleased), through via, the closed descriptor's file,
// where they are the host process's.
type lockResync struct {
	file *lockedFile
	via  *os.File
}

// releaseRecordLocksLocked removes the locks w holds of the file of op,
// whose slot of w is being cleared, as a close removes the locks of a
// process (Linux's locks_remove_posix), and wakes w's waits for a lock of
// it; the host's locks are brought down once w.mu is let go
// (resyncReleased). Caller holds w.mu.
func (w *WasiStubs) releaseRecordLocksLocked(op *wasiOpen) {
	if !op.hasFileKey || w.recordLockUses.Load() == 0 {
		return
	}
	recordLocks.mu.Lock()
	file := recordLocks.files[op.fileKey]
	recordLocks.mu.Unlock()
	if file == nil {
		return
	}
	file.mu.Lock()
	dropped := w.dropRowsLocked(file)
	file.mu.Unlock()
	if dropped {
		via, _ := op.f.(*os.File)
		w.lockResyncs = append(w.lockResyncs, lockResync{file: file, via: via})
	}
}

// resyncReleased brings the host's locks of the files closes of w have
// removed locks of down to the table (lockResyncs), and joins the errors.
func (w *WasiStubs) resyncReleased() error {
	w.mu.Lock()
	pending := w.lockResyncs
	w.lockResyncs = nil
	w.mu.Unlock()
	var err error
	for _, p := range pending {
		p.file.mu.Lock()
		err = errors.Join(err, p.file.resyncLocked(0, recordEnd, p.via))
		p.file.mu.Unlock()
	}
	return err
}

// absoluteRecordLock makes the range of lk, a lock of the file f, one from
// the start of the file (SEEK_SET): from the file's offset (SEEK_CUR) or its
// size (SEEK_END) now. Returns a wasi errno.
func (w *WasiStubs) absoluteRecordLock(f *os.File, lk *recordLock) int32 {
	var base int64
	switch lk.whence {
	case 1: // SEEK_CUR
		offset, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return w.guestErrno("fd_lock", err)
		}
		base = offset
	case 2: // SEEK_END
		fi, err := f.Stat()
		if err != nil {
			return w.guestErrno("fd_lock", err)
		}
		base = fi.Size()
	}
	lk.whence, lk.start = 0, lk.start+base
	return _wasiESUCCESS
}

// Path_chown is a NON-STANDARD host import (name "path_chown") backing
// chown and lchown (follow 0) for the preopen-relative path; an id of -1
// is left as it is (FS.Chown, FS.Lchown). Returns 0, or a negative errno:
// ENOSYS when the filesystem of the instance keeps no owners.
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
	path, fd, own, errno := w.changedFile(string(pathSlice), follow != 0)
	switch {
	case errno != _wasiESUCCESS:
		return -errno
	case own:
		return w.Fd_chown(m, fd, uid, gid)
	}
	w.mu.Lock()
	fsys := w.fs()
	w.mu.Unlock()
	chown := fsys.Chown
	if follow == 0 {
		chown = fsys.Lchown
	}
	return -w.guestErrno("path_chown", chown(path, int(uid), int(gid)))
}

// Fd_chown is a NON-STANDARD host import (name "fd_chown") backing fchown.
// Returns 0, or a negative errno: ENOSYS for a descriptor whose file keeps
// no owner, or that has no file.
func (w *WasiStubs) Fd_chown(m *Module, fd, uid, gid int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	if op == nil {
		return -_wasiEBADF
	}
	if op.f == nil {
		return -_wasiENOSYS
	}
	return -w.guestErrno("fd_chown", op.f.Chown(int(uid), int(gid)))
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

// wasiZone is a zone a TZ value names, resolved: one of a zone
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
// name, with the ':' it may start with dropped, is a zone of the zone
// database ("Europe/Paris"), the configuration's ZoneInfo or the host's, or,
// when it starts with '/', the zone file of that path in the guest's
// filesystem ("/usr/share/zoneinfo/Europe/Paris")
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

// loadZone loads the zone of a name (see zoneMoment) from the zone database
// (loadZoneInfo) or, for a path, from the guest's filesystem. "Local" names
// no zone of the database; a path names one only when it is a regular file
// of at most wasiZoneFileMax bytes. The file is opened without waiting where
// the host can (hostONonblock), and what it is is told by the open file.
func (w *WasiStubs) loadZone(name string) (*time.Location, error) {
	if name == "Local" {
		return nil, fs.ErrNotExist
	}
	if !strings.HasPrefix(name, "/") {
		return w.loadZoneInfo(name)
	}
	rel, errno := w.guestName(name)
	if errno != _wasiESUCCESS {
		return nil, &fs.PathError{Op: "open", Path: name, Err: hostErrnoOf(errno)}
	}
	f, err := w.fs().OpenFile(rel, os.O_RDONLY|hostONonblock, 0)
	if err != nil {
		return nil, err
	}
	return readZoneFile(name, f)
}

// loadZoneInfo loads the zone of a name of the zone database: the file of
// that name in the configuration's ZoneInfo, which is a zone only when it is
// a regular file of at most wasiZoneFileMax bytes, or, without a ZoneInfo,
// the zone time.LoadLocation loads from the host's database. "" and "UTC"
// are UTC, as for time.LoadLocation, and a name fs.ValidPath refuses (one
// with a ".." or an empty element) names no file of ZoneInfo.
func (w *WasiStubs) loadZoneInfo(name string) (*time.Location, error) {
	if w.cfg.ZoneInfo == nil || name == "" || name == "UTC" {
		return time.LoadLocation(name)
	}
	if !fs.ValidPath(name) {
		return nil, fs.ErrNotExist
	}
	f, err := w.cfg.ZoneInfo.Open(name)
	if err != nil {
		return nil, err
	}
	return readZoneFile(name, f)
}

// readZoneFile loads the zone called name from f, an open zone file, which
// it closes: a zone only when f is a regular file of at most
// wasiZoneFileMax bytes.
func readZoneFile(name string, f fs.File) (*time.Location, error) {
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

// ----- syscall(2) ----------------------------------------------------------------

// Syscalls makes the guest's syscall(2) (WASIConfig.Syscalls). The runtime
// calls it without any lock of the WasiStubs held. Its error is the errno of
// the guest's call: errors.ErrUnsupported is ENOSYS, and ErrSyscallNotMade
// says that the call was not made for a copy made by Fork, which the guest
// is told apart from every errno.
type Syscalls interface {
	Syscall(call Syscall) (int64, error)
}

// Syscall is a system call the guest makes: its number and its arguments,
// as the guest gave them. The number is the Linux ABI's on every host: that
// of Linux's scripts/syscall.tbl for the "common" and "64" calls, the
// numbers of asm-generic (arm64's and riscv64's).
type Syscall struct {
	Number int64
	Args   [6]uint64
	// Pointers has bit i set for an argument that is an address of the
	// guest's memory, whose bytes are the call's to read and write: the
	// implementation makes it an address the call can be given.
	Pointers uint32
	// Memory is the guest's memory, up to its current size.
	Memory []byte
	// Forked reports that the guest is a copy made by Fork, which shares
	// the host process with the guest it was forked from.
	Forked bool
}

// ErrSyscallNotMade is the error a Syscalls returns for a call it does not
// make for a copy made by Fork.
var ErrSyscallNotMade = errors.New("system call not made for a forked process")

// HostSyscalls returns a Syscalls that gives the guest the host's kernel,
// for WASIConfig.Syscalls of a guest that is trusted with it. The number is
// moved by the table of the host to the host's call of the same name, as
// QEMU's linux-user moves the numbers of its target; a number the table does
// not have fails with ENOSYS. The tables are:
//
//   - Linux on arm64, riscv64 and loong64, whose numbers are the Linux
//     ABI's: every number the ABI assigns, as it is;
//   - Linux on amd64: every call the ABI assigns, each of which x86-64 has;
//   - darwin: gettimeofday, whose third argument of darwin's is made null,
//     and getrandom, made by getentropy(2) 256 bytes at a time; darwin's
//     other calls do not take their arguments as the Linux ABI gives them;
//   - every other host: none. A 32-bit Linux takes a 64-bit argument in two
//     registers and has its calls of 64-bit times under other names, which
//     a table of numbers cannot move a call to.
//
// HostSyscalls gives the guest of the root instance everything the host
// process can do: it can read and write any memory of the host process and
// use any descriptor of it, its FS does not see its calls, and NetAccess,
// Dial, Listen, Resolve and Exec do not apply to them.
//
// The call is made with the arguments as they are, in the order the host's
// call takes them (clone's on amd64 is not arm64's), but for one whose bit
// is set in Pointers, which is given as the address the host process has
// the guest's byte at (EFAULT for an address past the end of the guest's
// memory). That is all it translates and bounds: flags and structures are
// the host kernel's (x86-64's struct stat is not arm64's), and a length the
// call is given, and a pointer inside a structure the call reads, are the
// guest's numbers, which the kernel takes for the host process's — a
// length past the guest's memory reaches the host process's memory beyond
// it, and a pointer in a structure any address of the host process. The
// call acts on the host process — its descriptors, identity, working
// directory, memory — which is what the guest knows as its own only when
// the configuration gives it the host process's. HostWASIConfig has no
// Syscalls.
//
// For a copy made by Fork, which shares the host process with the guest it
// was forked from (execve would replace them all, getpid names the first
// one, chdir moves every one), it makes only the calls of its table
// (forkedSyscallMade), which depend on no state of the host process, and
// returns ErrSyscallNotMade for the others. The table says which arguments
// of those calls are pointers and how many bytes the call reads or writes
// there: a call whose Pointers differ (an argument of a pointer's place may
// be 0 instead, the null pointer) is refused with EINVAL, and one whose
// bytes are not all in the guest's memory with EFAULT.
func HostSyscalls() Syscalls { return hostSyscalls{} }

// hostSyscalls is the Syscalls HostSyscalls returns.
type hostSyscalls struct{}

func (hostSyscalls) Syscall(call Syscall) (int64, error) {
	if !linuxSyscallAssigned(call.Number) {
		return 0, syscall.ENOSYS
	}
	if call.Forked {
		c, made := forkedSyscallMade(call.Number, &call.Args)
		if !made {
			return 0, ErrSyscallNotMade
		}
		if err := c.validateArgs(call); err != nil {
			return 0, err
		}
	}
	for i, v := range call.Args {
		if call.Pointers&(1<<i) != 0 && v > uint64(len(call.Memory)) {
			return 0, syscall.EFAULT
		}
	}
	return hostSyscall(call.Number, call.Args, call.Pointers, call.Memory)
}

// The numbers of the Linux ABI of the guest's system calls (Syscall) that
// the runtime names, from Linux 7.2's scripts/syscall.tbl. A host whose own
// numbers are other has no constants of them.
const (
	linuxSysClockGettime    = 113
	linuxSysClockGetres     = 114
	linuxSysSchedYield      = 124
	linuxSysUname           = 160
	linuxSysGetcpu          = 168
	linuxSysGettimeofday    = 169
	linuxSysRecvmmsg        = 243 // the last before the architecture's own (244-259)
	linuxSysWait4           = 260
	linuxSysGetrandom       = 278
	linuxSysKexecFileLoad   = 294 // the last before 295-423, which no 64-bit architecture has
	linuxSysPidfdSendSignal = 424 // the first of the numbers every architecture shares
	linuxSysRseqSliceYield  = 471
)

// linuxSyscallAssigned reports whether the Linux ABI of Syscall assigns the
// number to a call shared by the 64-bit architectures: the architecture's
// own range, and the numbers of 32-bit architectures only, are not the
// guest's.
func linuxSyscallAssigned(number int64) bool {
	return 0 <= number && number <= linuxSysRecvmmsg ||
		linuxSysWait4 <= number && number <= linuxSysKexecFileLoad ||
		linuxSysPidfdSendSignal <= number && number <= linuxSysRseqSliceYield
}

// sysSyscallNotMade is what sys_syscall returns for a call the Syscalls did
// not make for a copy made by Fork (ErrSyscallNotMade): no errno, as the
// call was not made at all.
const sysSyscallNotMade = 1

// Sys_syscall is a NON-STANDARD host import (module wasip1_posix_extension,
// name "sys_syscall") backing syscall(2) through WASIConfig.Syscalls: the
// system call of the number (the Linux ABI's; see Syscall), with the nargs
// (at most six) u64 arguments at argsPtr; an argument whose bit is set in
// ptrs is an address of the guest's memory. Its result is written at
// resultPtr (i64). Returns 0, or a negative errno: ENOSYS without a
// Syscalls; or sysSyscallNotMade.
func (w *WasiStubs) Sys_syscall(m *Module, number int64, argsPtr, nargs, ptrs, resultPtr int32) int32 {
	return w.sysSyscall(m, number, zext(argsPtr), nargs, ptrs, zext(resultPtr))
}

// Sys_syscall64 is Sys_syscall for a memory64 guest.
func (w *WasiStubs) Sys_syscall64(m *Module, number int64, argsPtr int64, nargs, ptrs int32, resultPtr int64) int32 {
	return w.sysSyscall(m, number, uint64(argsPtr), nargs, ptrs, uint64(resultPtr))
}

// sysSyscall is the body of Sys_syscall and Sys_syscall64.
func (w *WasiStubs) sysSyscall(m *Module, number int64, argsPtr uint64, nargs, ptrs int32, resultPtr uint64) int32 {
	w.endUnregistered()
	if w.cfg.Syscalls == nil {
		return -_wasiENOSYS
	}
	if nargs < 0 || nargs > 6 {
		return -_wasiEINVAL
	}
	raw := w.memBytes(m, argsPtr, uint64(nargs)*8)
	out := w.memBytes(m, resultPtr, 8)
	if raw == nil || out == nil {
		return -_wasiEFAULT
	}
	call := Syscall{Number: number, Pointers: uint32(ptrs) & (1<<nargs - 1), Memory: w.guestMemory(m), Forked: w.forked}
	for i := range nargs {
		call.Args[i] = binary.LittleEndian.Uint64(raw[i*8:])
	}
	r, err := w.cfg.Syscalls.Syscall(call)
	switch {
	case errors.Is(err, ErrSyscallNotMade):
		return sysSyscallNotMade
	case err != nil:
		return -w.guestErrno("sys_syscall", err)
	}
	binary.LittleEndian.PutUint64(out, uint64(r))
	return _wasiESUCCESS
}

// forkedSyscall is a system call that HostSyscalls makes for a copy made by
// Fork (forkedSyscallMade).
type forkedSyscall struct {
	number int64
	// clock: the first argument is a clock id, and the call is made for
	// every clock but a CPU-time one (cpuTimeClock)
	clock bool
	// pointers are the arguments of the call that are pointers; every
	// other argument is a number.
	pointers []syscallPointer
}

// syscallPointer is an argument of a system call that is a pointer: the call
// reads or writes size bytes there, or as many as the argument length says
// when that is not negative.
type syscallPointer struct {
	arg, size, length int
}

// validateArgs refuses a call of c whose arguments are not what c takes
// (HostSyscalls): EINVAL for a pointer declared where c has a number, or a
// number other than 0 where c has a pointer; EFAULT for a pointer whose
// bytes are not all in the guest's memory.
func (c forkedSyscall) validateArgs(call Syscall) error {
	var pointers uint32
	for _, p := range c.pointers {
		pointers |= 1 << p.arg
		v := call.Args[p.arg]
		if call.Pointers&(1<<p.arg) == 0 {
			if v != 0 {
				return syscall.EINVAL
			}
			continue
		}
		n := uint64(p.size)
		if p.length >= 0 {
			n = call.Args[p.length]
		}
		if v > uint64(len(call.Memory)) || n > uint64(len(call.Memory))-v {
			return syscall.EFAULT
		}
	}
	if call.Pointers&^pointers != 0 {
		return syscall.EINVAL
	}
	return nil
}

// forkedSyscallMade reports whether HostSyscalls makes the system call of
// the number, with args, for a copy made by Fork. Such a copy shares the
// host process with the guest it was forked from, so a call is made only
// when what the kernel does for it depends on no state of that process (its
// identity, descriptors, working directory, signals, memory maps,
// credentials and limits, exec and exit): the call then gives the copy what
// it would give a process of its own. These are the calls, each depending
// on no such state for this reason:
//
//   - getrandom: bytes of the kernel's random pool, which is the system's;
//   - clock_gettime, clock_getres: the time and the resolution of a clock of
//     the system, for every clock but a CPU-time one (cpuTimeClock), which
//     counts the time of the host process or of a thread;
//   - gettimeofday: the time of the system;
//   - uname: the name and the version of the system;
//   - sched_yield: gives the calling thread's CPU to another thread;
//   - getcpu: the CPU the calling thread runs on.
//
// It returns the entry of the call, and whether the call is made.
func forkedSyscallMade(number int64, args *[6]uint64) (forkedSyscall, bool) {
	// The pointers of the calls, by the structures the kernel writes there:
	// struct new_utsname (6 fields of 65 bytes), struct timeval and
	// timezone, struct timespec, the two unsigned ints of getcpu (its third
	// argument is unused), and the buffer of getrandom, whose length is its
	// second argument.
	var (
		utsname   = []syscallPointer{{0, 390, -1}}
		timeOfDay = []syscallPointer{{0, 16, -1}, {1, 8, -1}}
		clockOut  = []syscallPointer{{1, 16, -1}}
		cpuOut    = []syscallPointer{{0, 4, -1}, {1, 4, -1}, {2, 0, -1}}
		randomOut = []syscallPointer{{0, 0, 1}}
	)
	for _, c := range []forkedSyscall{
		{linuxSysClockGettime, true, clockOut},
		{linuxSysClockGetres, true, clockOut},
		{linuxSysSchedYield, false, nil},
		{linuxSysUname, false, utsname},
		{linuxSysGetcpu, false, cpuOut},
		{linuxSysGettimeofday, false, timeOfDay},
		{linuxSysGetrandom, false, randomOut},
	} {
		if c.number == number {
			return c, !c.clock || !cpuTimeClock(int32(args[0]))
		}
	}
	return forkedSyscall{}, false
}

// cpuTimeClock reports whether a clock id of the Linux ABI names a CPU-time
// clock: CLOCK_PROCESS_CPUTIME_ID (2), CLOCK_THREAD_CPUTIME_ID (3), or a
// negative id, the CPU-time clock of a given process or thread
// (clock_getcpuclockid, pthread_getcpuclockid). Package syscall has no
// constants of the ids.
func cpuTimeClock(id int32) bool {
	return id < 0 || id == 2 || id == 3
}

// ----- signals ----------------------------------------------------------------
//
// A guest cannot be interrupted: it is ordinary code on a goroutine. A
// signal is therefore delivered the way an interpreter with deferred signal
// handling takes one from its own C-level handler: the host records the
// signal and raises a flag word in the guest's memory — the one the thread
// the signal is delivered to registered — the thread notices the flag at its
// next safe point and takes the recorded signals (Proc_signal_take), and a
// blocking host call the thread is waiting in ends early with EINTR so that
// the safe point comes.
//
// What a signal does — run a handler, be ignored, end the process — is the
// guest's business: it owns the dispositions and tells the host about them
// (Proc_signal_dispositions) only so that the host can drop a signal nobody
// would notice instead of interrupting a blocking call for it.
//
// Signal sets cross the boundary as 64-bit masks in which signal n is bit
// n-1.

// Signals connects the guest's signals with processes and signal handling
// outside the guest (WASIConfig.Signals). Signal numbers are the guest's
// (Linux numbering). The runtime calls the methods without the lock of the
// WasiStubs held, so they may call back into it (PostSignal, say).
type Signals interface {
	// Kill sends sig to a process that is not one of the guest's own (not
	// the guest, not a child or fork the guest made), or, for a negative
	// pid, to the process group -pid, which is not the guest's (Proc_kill);
	// sig 0 only probes that the process exists. Its error is what the
	// guest's kill reports (syscall.ESRCH, syscall.EPERM, ...). Without a
	// Signals the guest's kill of such a process reports ESRCH.
	Kill(pid, sig int32) error
	// Dispositions is told the guest's dispositions whenever they change:
	// the signals it handles, the ones it ignores explicitly and the ones
	// it blocks — every thread of it that registered for signals blocks
	// them (signal n is bit n-1). target is the instance whose guest
	// reported them, the one a signal for that guest is posted to: a
	// forked instance has the same Signals as its parent (Fork). The
	// reports of an instance are made one at a time, in the order of the
	// changes.
	Dispositions(target SignalTarget, handled, ignored, blocked uint64)
}

// SignalTarget is what a signal is posted to: the WasiStubs of a guest
// (PostSignal, DeliverSignal).
type SignalTarget interface {
	PostSignal(sig int32)
	DeliverSignal(sig int32, reach SignalReach)
}

// SignalReach is how far DeliverSignal delivers a signal. The one relaying
// the signals of the host process to a guest chooses it for each signal,
// as tini, dumb-init and docker's --sig-proxy choose where the signals
// they relay go.
type SignalReach int32

const (
	// ReachProcess delivers the signal to the guest's process, as kill(2)
	// does: to the guest, or to the command the guest has become
	// (Proc_exec), as PostSignal does. For a signal sent to the host
	// process alone, which the command would not get otherwise (kill of
	// the host process's pid).
	ReachProcess SignalReach = iota
	// ReachGuest delivers the signal to the guest only: once the guest has
	// become a command, it is dropped. For a signal the command gets where
	// the host process got it as well (a terminal's interrupt, which is
	// sent to the whole foreground group).
	ReachGuest
)

// DeliverSignal delivers sig, the guest's number for a signal, as far as
// reach says: as PostSignal does with ReachProcess, to the guest alone
// with ReachGuest. Another reach delivers nothing. It may be called from
// any goroutine, at any time.
func (w *WasiStubs) DeliverSignal(sig int32, reach SignalReach) {
	switch reach {
	case ReachProcess:
		w.PostSignal(sig)
	case ReachGuest:
		w.sig.mu.Lock()
		if w.sig.execed != nil {
			w.sig.mu.Unlock()
			return
		}
		w.postSignalLocked(sig)
		w.unlockSignals()
	}
}

// wasiSignals is the signal state of one instance: the process's, and each
// thread's of the guest (wasiSignalThread), as POSIX divides them — the
// dispositions are the process's, the mask is a thread's. A signal posted to
// the process waits for it until a thread takes it, and is delivered to one
// of the threads that have registered and do not block it (targetLocked);
// while every thread blocks it, it waits until one unblocks it. A signal the
// guest raises is its calling thread's.
//
// It is guarded by mu, apart from what is said otherwise. Nothing that runs
// code of others — the wakes of blocking calls, the interrupts of code
// outside the guest — nor a write to the guest's memory is done with mu
// held: what a change under mu leaves to do is kept in due and done once mu
// is let go (unlockSignals).
type wasiSignals struct {
	mu sync.Mutex
	// flagMu is held while a flag word is written (raiseSignalFlag), so
	// that once delivery has ended (detachSignals) nothing writes to the
	// guest's memory any more.
	flagMu sync.Mutex
	// handled and ignored are the dispositions the guest reported: the
	// signals it has a handler for and the ones it ignores explicitly
	// (SIG_IGN). A signal in neither has its default action; see discards.
	handled, ignored uint64
	// pending holds the signals posted to the process that no thread has
	// taken yet.
	pending uint64
	// threads are the threads of the guest the host has seen, in the order
	// it saw them, and byModule finds one by its module: wasi-threads runs
	// each thread on a module instance of its own, so the module of a host
	// call names the thread that made it (threadLocked).
	threads  []*wasiSignalThread
	byModule map[*Module]*wasiSignalThread
	// agentEnds has the runtime tell agentEnded of each thread of the guest
	// that ends (lockSignalThread).
	agentEnds sync.Once
	// quiet is the thread whose own host call posts what is posted at the
	// moment (postForGuestLocked): it runs no code outside the guest then.
	quiet *wasiSignalThread
	// due is what the changes made under mu leave to do once it is let go.
	due wasiSignalsDue
	// timer is the running real-time interval timer (setitimer's
	// ITIMER_REAL, which alarm and ualarm set as well), timerAt the time it
	// fires next, and timerEvery the interval at which it fires again after
	// that: 0 for a timer that fires once.
	timer      *time.Timer
	timerAt    time.Time
	timerEvery time.Duration
	// detached records that delivery has ended (detachSignals): what is
	// posted from then on is dropped, for a forked instance too.
	detached bool
	// stop is the end of the instance once it has been asked for
	// (requestStopLocked): every thread of the guest unwinds with it
	// (endIfStopped). It is set with mu held and read without.
	stop atomic.Pointer[wasiStop]
	// execed is the command the guest has become (Proc_exec) while it
	// runs: a signal for the process is the command's (signalProcess).
	execed *execedCommand
}

// wasiSignalThread is the signal state of one thread of the guest.
type wasiSignalThread struct {
	// module is the thread's module. It is nil for the registration a
	// forked instance inherited (forkInto) until the first thread of its
	// guest calls the host (threadLocked).
	module *Module
	// registered records that the thread has registered its flag word, at
	// flagAddr (Proc_signal_register). The address is a guest address at
	// full width, which a memory64 guest's may need; the flag word itself is
	// a 32-bit int, which the host stores atomically.
	registered bool
	flagAddr   uint64
	// blocked is the thread's signal mask, and pending holds the signals
	// raised for the thread that it has not taken yet.
	blocked, pending uint64
	// interrupt records that a signal is waiting for the thread and no
	// blocking call of its has reported it yet: the next one (or the one in
	// progress) ends with EINTR, once — as a system call does for one
	// delivered signal.
	interrupt bool
	// wakes are the thread's blocking calls in progress, whose wakes end
	// them early. beginBlocking adds one, endBlocking removes its own, and a
	// signal for the thread removes them all and calls their wakes
	// (takeWakes).
	wakes map[*wasiBlocking]bool
	// outside are the calls of code outside the guest that the thread is in
	// (BeginOutside), the one it runs at the moment last: the host learns of
	// such code only from the one who runs it, and only that one knows how
	// to interrupt it.
	outside []*OutsideCall
}

// wasiStop is an end of the instance that its threads unwind with.
type wasiStop struct {
	end wasiEnd
}

// wasiEnd is the panic value of an end of the whole instance: Proc_exit's
// *WasiExitError or the *WasiSignalError of an end by a signal.
type wasiEnd interface {
	error
	endsInstance()
}

// wasiBlocking is a blocking call of the guest's in progress (beginBlocking).
type wasiBlocking struct {
	// thread is the thread that makes the call.
	thread *wasiSignalThread
	// wake ends the call's wait.
	wake func()
	// woken is made when a post takes the call out of the signal state to
	// call its wake, and closed once wake has returned: the call does not
	// end before (endBlocking), so that its wake does nothing to what comes
	// after it.
	woken chan struct{}
}

// wasiSignalsDue is what changes of the signal state leave to do once its
// lock is let go (unlockSignals).
type wasiSignalsDue struct {
	// raises are the flag words to raise for signals posted for a thread.
	raises []wasiRaise
	// wakes are the blocking calls taken out to be woken.
	wakes []*wasiBlocking
	// stop records that the end of the instance was asked for
	// (requestStopLocked): the flag words of stopFlags are raised, for a
	// guest that computes to come to its safe point and end there; the
	// calls of code outside the guest of stopOutside, the ones the threads
	// ran then, whose interrupts are counted already, are interrupted, for
	// that code to return to the guest; and the waits of the guest's agents
	// on its memory (stopAgents) of stopModule, a module of the guest when
	// one is known, end.
	stop        bool
	stopFlags   []*wasiSignalThread
	stopOutside []*OutsideCall
	stopModule  *Module
	// alarm is the command the guest has become (Proc_exec), to be sent
	// the interval timer's SIGALRM (fireDueTimerLocked).
	alarm *commandProcess
	// alarmToOffer records a firing of the interval timer to offer
	// WASIConfig.TakeSignal (fireDueTimerLocked); alarmFor, the thread whose
	// own host call it came due in, to post it for if not taken
	// (postForGuestLocked), nil for the host's timer.
	alarmToOffer bool
	alarmFor     *wasiSignalThread
}

// wasiRaise is a flag word to raise for the signals of bits, posted for
// thread. Once it is raised, the ones of them still waiting for the thread
// interrupt it (wasiSignalThread.interrupt) and end its blocking calls in
// progress, or else interrupt outside, its call of code outside the guest,
// when the thread still runs it.
type wasiRaise struct {
	thread  *wasiSignalThread
	bits    uint64
	outside *OutsideCall
}

// discards returns the signals that have no effect on the guest: the ones it
// ignores, and the ones left at a default action that is to do nothing.
func (s *wasiSignals) discards() uint64 {
	return s.ignored | wasiDefaultIgnoredSignals&^s.handled
}

// unregisteredEnd returns the signal that ends a guest that has not
// registered for signals, or 0: such a guest takes no signal, so a pending
// signal whose default action ends a process has that action, by the host.
// Caller holds s.mu.
func (s *wasiSignals) unregisteredEnd() int32 {
	if s.registeredLocked() {
		return 0
	}
	if ending := s.pending &^ wasiDefaultIgnoredSignals; ending != 0 {
		return int32(bits.TrailingZeros64(ending)) + 1
	}
	return 0
}

// registeredLocked reports whether a thread of the guest has registered for
// signals, or a forked instance inherited a registration (forkInto). Caller
// holds s.mu.
func (s *wasiSignals) registeredLocked() bool {
	return slices.ContainsFunc(s.threads, (*wasiSignalThread).isRegistered)
}

func (t *wasiSignalThread) isRegistered() bool { return t.registered }

// deliverable returns the signals waiting for t that it does not block: the
// ones raised for it and the ones posted to the process. Caller holds s.mu.
func (s *wasiSignals) deliverable(t *wasiSignalThread) uint64 {
	return (s.pending | t.pending) &^ t.blocked
}

// threadLocked returns the signal state of the thread whose module m is. A
// thread the host has not seen before is the copy of the thread that forked,
// when the instance inherited a registration not bound to a thread yet
// (forkInto): a forked instance starts with that thread alone, so its first
// call of the host is that thread's. Otherwise the thread is new. Caller
// holds s.mu.
func (s *wasiSignals) threadLocked(m *Module) *wasiSignalThread {
	if t := s.byModule[m]; t != nil {
		return t
	}
	if s.byModule == nil {
		s.byModule = map[*Module]*wasiSignalThread{}
	}
	if i := slices.IndexFunc(s.threads, func(t *wasiSignalThread) bool { return t.module == nil }); i >= 0 {
		t := s.threads[i]
		t.module = m
		s.byModule[m] = t
		if bits := s.deliverable(t); bits != 0 {
			// Posted before the thread was known: its flag word is
			// raised now.
			s.announceLocked(t, bits)
		}
		return t
	}
	t := &wasiSignalThread{module: m}
	s.threads = append(s.threads, t)
	s.byModule[m] = t
	return t
}

// lockSignalThread takes w.sig.mu and returns the signal state of the thread
// whose module m is (threadLocked). The first time, it has the runtime tell
// agentEnded of each thread of the guest that ends. The caller lets go of
// w.sig.mu with unlockSignals.
func (w *WasiStubs) lockSignalThread(m *Module) *wasiSignalThread {
	w.sig.agentEnds.Do(func() { onAgentEnd(m, w.agentEnded) })
	w.sig.mu.Lock()
	return w.sig.threadLocked(m)
}

// agentEnded forgets the thread of the guest whose module m is, which has
// ended: the signals raised for it go with it, and the ones posted to the
// process that it would have taken go to another thread (retargetLocked),
// as they do for a thread that exits in Linux (exit_signals). Its flag word
// is not written from then on: a raise of it in progress is over first
// (flagMu).
func (w *WasiStubs) agentEnded(m *Module) {
	s := &w.sig
	s.flagMu.Lock()
	s.mu.Lock()
	if t := s.byModule[m]; t != nil {
		delete(s.byModule, m)
		s.threads = slices.DeleteFunc(s.threads, func(u *wasiSignalThread) bool { return u == t })
		t.registered, t.module = false, nil
		s.retargetLocked(s.pending &^ t.blocked)
	}
	s.flagMu.Unlock()
	w.unlockSignals()
}

// forkInto gives child, the signal state of a copy that Fork makes, what a
// forked process inherits (POSIX fork): the dispositions, and the
// registration and mask of the thread whose module from is — the one that
// forks, of which the copy's one thread is a copy — or, for a nil from or a
// thread that has not registered, of the first thread that registered. The
// copy's thread is not known yet (threadLocked). Nothing is pending for it.
// Caller holds no lock of s; child is nobody else's yet.
func (s *wasiSignals) forkInto(child *wasiSignals, from *Module) {
	s.mu.Lock()
	defer s.mu.Unlock()
	child.handled, child.ignored = s.handled, s.ignored
	t := s.byModule[from]
	if t == nil || !t.registered {
		i := slices.IndexFunc(s.threads, (*wasiSignalThread).isRegistered)
		if i < 0 {
			return
		}
		t = s.threads[i]
	}
	child.threads = []*wasiSignalThread{{registered: true, flagAddr: t.flagAddr, blocked: t.blocked}}
}

// reportDispositions tells WASIConfig.Signals the dispositions of a forked
// instance that inherited a registration (forkInto), with w as the target:
// its guest has them without reporting them. Caller holds no lock of w.
func (w *WasiStubs) reportDispositions() {
	s := &w.sig
	s.mu.Lock()
	registered := s.registeredLocked()
	handled, ignored := s.handled, s.ignored
	var blocked uint64
	if registered {
		blocked = s.blockedByAllLocked(nil)
	}
	s.mu.Unlock()
	if registered && w.cfg.Signals != nil {
		w.cfg.Signals.Dispositions(w, handled, ignored, blocked)
	}
}

// targetLocked returns the thread a signal of the process (its mask bit) is
// delivered to: one that has registered and does not block it, prefer when
// it is such a thread, else the first such thread in the order the host saw
// them (Linux's complete_signal tries the suggested thread first as well).
// nil is none: the signal waits for the process. Caller holds s.mu.
func (s *wasiSignals) targetLocked(bit uint64, prefer *wasiSignalThread) *wasiSignalThread {
	takes := func(t *wasiSignalThread) bool { return t.registered && t.blocked&bit == 0 }
	if prefer != nil && takes(prefer) {
		return prefer
	}
	if i := slices.IndexFunc(s.threads, takes); i >= 0 {
		return s.threads[i]
	}
	return nil
}

// retargetLocked delivers the signals of bits that wait for the process to
// the threads that take them, as Linux's retarget_shared_pending does when
// the thread they were delivered to can take them no longer: it has blocked
// them, or has ended. Caller holds s.mu.
func (s *wasiSignals) retargetLocked(bits uint64) {
	for bits != 0 {
		bit := bits & -bits
		bits &^= bit
		if t := s.targetLocked(bit, nil); t != nil {
			s.announceLocked(t, bit)
		}
	}
}

// announceLocked has the flag word of t raised for the signals of bits once
// s.mu is let go, and t interrupted for the ones still waiting for it then:
// its blocking calls end, or else its call of code outside the guest is
// interrupted — unless the post is made by t's own host call
// (postForGuestLocked). Caller holds s.mu.
func (s *wasiSignals) announceLocked(t *wasiSignalThread, bits uint64) {
	r := wasiRaise{thread: t, bits: bits}
	if t != s.quiet {
		r.outside = t.current()
	}
	s.due.raises = append(s.due.raises, r)
}

// current returns the call of code outside the guest that t runs at the
// moment, or nil. Caller holds the signal state's mu.
func (t *wasiSignalThread) current() *OutsideCall {
	if n := len(t.outside); n > 0 {
		return t.outside[n-1]
	}
	return nil
}

// blockedByAllLocked returns the signals that every thread that has
// registered blocks: the ones the guest takes none of while they are blocked.
// A guest with no registered thread has the mask of its thread t. Caller
// holds s.mu.
func (s *wasiSignals) blockedByAllLocked(t *wasiSignalThread) uint64 {
	if !s.registeredLocked() {
		return t.blocked
	}
	blocked := ^uint64(0)
	for _, u := range s.threads {
		if u.registered {
			blocked &= u.blocked
		}
	}
	return blocked
}

// reapsChildren reports whether the guest ignores SIGCHLD explicitly. As
// POSIX has it, a child of such a process leaves nothing to wait for when
// it ends, and a wait reports ECHILD once no child is left running. Caller
// does not hold s.mu.
func (s *wasiSignals) reapsChildren() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ignored&wasiSignalBit(wasiSIGCHLD) != 0
}

// isWasiSignalNumber reports whether sig is 0, the existence probe of
// kill, or a signal number of the guest (1 to 64).
func isWasiSignalNumber(sig int32) bool {
	return sig == 0 || wasiSignalBit(sig) != 0
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
const wasiDefaultIgnoredSignals = uint64(1)<<(wasiSIGCHLD-1) |
	uint64(1)<<(wasiSIGCONT-1) |
	uint64(1)<<(wasiSIGSTOP-1) |
	uint64(1)<<(wasiSIGTSTP-1) |
	uint64(1)<<(wasiSIGTTIN-1) |
	uint64(1)<<(wasiSIGTTOU-1) |
	uint64(1)<<(wasiSIGURG-1) |
	uint64(1)<<(wasiSIGWINCH-1)

// PostSignal delivers a signal to the guest, as kill(2) does to a process.
// sig is the guest's number for it (Linux numbering). It may be called from
// any goroutine, at any time.
//
// SIGKILL is never the guest's: the host carries it out, whatever the guest
// registered. Each thread of the guest ends at its next blocking call, at
// the next of its calls that look (endUnregistered) or at its safe point
// (its flag word is raised): a blocking call in progress ends at once, code
// outside the guest is interrupted (BeginOutside), and a wait of a thread on
// the guest's memory ends. The instance is of no further use: each call that
// looks unwinds with the same end.
//
// Another signal is dropped when the guest ignores it (explicitly or because
// that is the signal's default action). Otherwise it is recorded for the
// guest to take, and delivered to one of the guest's threads that have
// registered and do not block it: that thread's flag word is raised, and the
// blocking call it is waiting in — or the next one it makes before taking
// the signal — ends with EINTR. While every such thread blocks the signal,
// it waits for one to unblock it.
//
// A guest that has not registered for signals takes none: a signal whose
// default action ends a process ends it, at its next blocking call or at
// the next of its calls that look (endUnregistered), and any other is
// dropped. A forked instance has registered when the instance it was forked
// from had (Fork).
//
// Once delivery to the instance has ended (CloseAll, proc_exit,
// proc_terminate), what is posted is dropped. Once the guest has become a
// command (Proc_exec), the signal is the command's, as kill(2) of the
// process is; a failure to send it is told WASIConfig.Errors (op
// "kill").
func (w *WasiStubs) PostSignal(sig int32) {
	_, err := w.signalProcess(sig)
	w.reportError("kill", err)
}

// postSignalLocked posts sig to the guest as PostSignal does, and reports
// whether the instance still takes signals: false once delivery to it has
// ended. Caller holds w.sig.mu, and lets go of it with unlockSignals.
func (w *WasiStubs) postSignalLocked(sig int32) bool {
	s := &w.sig
	if s.detached {
		return false
	}
	bit := wasiSignalBit(sig)
	if bit == 0 {
		return true
	}
	if sig == wasiSIGKILL {
		w.requestStopLocked(nil, &WasiSignalError{Signal: wasiSIGKILL})
		return true
	}
	if !s.registeredLocked() {
		if bit&wasiDefaultIgnoredSignals == 0 {
			s.pending |= bit
			// The blocking calls end, and end the guest.
			s.due.wakes = append(s.due.wakes, s.takeAllWakes()...)
		}
		return true
	}
	if s.discards()&bit != 0 {
		return true
	}
	s.pending |= bit
	if t := s.targetLocked(bit, s.quiet); t != nil {
		s.announceLocked(t, bit)
	}
	return true
}

// raiseLocked raises sig for the thread t, as raise(3) does (Proc_raise):
// it waits for t alone, which is interrupted for it unless t blocks it. A
// thread that has not registered takes no signal of its own: sig is posted
// to the process then. Caller holds w.sig.mu.
func (w *WasiStubs) raiseLocked(t *wasiSignalThread, sig int32) {
	s := &w.sig
	bit := wasiSignalBit(sig)
	if !t.registered || bit == 0 || sig == wasiSIGKILL || s.detached {
		w.postSignalLocked(sig)
		return
	}
	if s.discards()&bit != 0 {
		return
	}
	t.pending |= bit
	if t.blocked&bit == 0 {
		s.announceLocked(t, bit)
	}
}

// unlockSignals lets go of w.sig.mu and does what the changes made under it
// left to do (wasiSignalsDue): it raises the flag words, then interrupts the
// threads for the signals still waiting for them, and calls the wakes of the
// blocking calls taken out, or the interrupts of the code outside the guest.
func (w *WasiStubs) unlockSignals() {
	s := &w.sig
	due := s.due
	s.due = wasiSignalsDue{}
	s.mu.Unlock()
	if due.alarm != nil {
		w.reportError("proc_itimer", signalHostProc(due.alarm, wasiSIGALRM))
	}
	if due.alarmToOffer {
		w.offerAlarm(due.alarmFor)
	}
	// The flags are raised first: a blocking call that a signal interrupts
	// ends with its thread's flag up, for the guest to find the signal.
	for _, r := range due.raises {
		w.raiseSignalFlag(r.thread)
	}
	for _, t := range due.stopFlags {
		w.raiseSignalFlag(t)
	}
	if due.stop && due.stopModule != nil {
		stopAgents(due.stopModule, s.stop.Load().end)
	}
	outside := due.stopOutside
	if len(due.raises) > 0 {
		s.mu.Lock()
		for _, r := range due.raises {
			t := r.thread
			if s.detached || s.deliverable(t)&r.bits == 0 {
				continue
			}
			t.interrupt = true
			if len(t.wakes) > 0 {
				due.wakes = append(due.wakes, t.takeWakes()...)
			} else if c := r.outside; c != nil && c == t.current() && !slices.Contains(outside, c) {
				// The thread is in code outside the guest: the signal
				// interrupts that code where it stands — a system call it
				// is waiting in ends with EINTR — and is noticed when the
				// code has returned, as a signal delivered while a process
				// runs a library's code is. It has interrupted the call in
				// progress: the thread's own blocking calls that follow do
				// not end by it.
				t.interrupt = false
				c.calls++
				outside = append(outside, c)
			}
		}
		s.mu.Unlock()
	}
	for _, b := range due.wakes {
		b.wake()
		close(b.woken)
	}
	for _, c := range outside {
		c.interrupt()
		s.mu.Lock()
		c.calls--
		if c.calls == 0 && c.idle != nil {
			close(c.idle)
		}
		s.mu.Unlock()
	}
}

// takeWakes removes the blocking calls of t in progress from the signal state
// and returns them, for their wakes to be called once the signal state's mu
// is let go. Caller holds that mu.
func (t *wasiSignalThread) takeWakes() []*wasiBlocking {
	taken := slices.Collect(maps.Keys(t.wakes))
	clear(t.wakes)
	for _, b := range taken {
		b.woken = make(chan struct{})
	}
	return taken
}

// takeAllWakes is takeWakes of every thread. Caller holds s.mu.
func (s *wasiSignals) takeAllWakes() []*wasiBlocking {
	var taken []*wasiBlocking
	for _, t := range s.threads {
		taken = append(taken, t.takeWakes()...)
	}
	return taken
}

// OutsideCall is a call of code outside the guest that a thread of the guest
// runs (BeginOutside).
type OutsideCall struct {
	w         *WasiStubs
	thread    *wasiSignalThread
	interrupt func()
	// calls counts the calls of interrupt in progress, and idle is made by
	// End while there are some, to be closed by the last of them. Guarded
	// by the signal state's mu.
	calls int
	idle  chan struct{}
}

// BeginOutside is called by what runs code outside the guest for the thread
// of the guest whose module m is, on that thread's goroutine, before the
// code runs: a native library the guest called, say, which may wait in a
// system call. A signal interrupts a process's system call wherever the
// process is; the guest's own blocking calls are ended by the host, code
// outside the guest by interrupt, which ends a system call that code is
// waiting in (or does nothing when it is in none). interrupt is not nil.
//
// interrupt is called once for each signal delivered to the thread while it
// runs the call and has no blocking call of the guest's own waiting: from
// another goroutine, without a lock of the instance held. It may call
// PostSignal and Pending, but not End, which waits for it. The signal is
// noticed when the code has returned to the guest, and the thread's own
// blocking calls that follow do not end by it. Calls nest — the code can call
// back into the guest, which can run code outside it again — and it is the
// thread's last call begun and not ended that is interrupted. The end of the
// instance (PostSignal of SIGKILL, Proc_exit) interrupts the call too.
//
// Pending tells the code whether to wait at all: code that makes the wait
// that interrupt ends first, then asks Pending, and then waits, loses no
// signal in between, as pselect(2) loses none.
func (w *WasiStubs) BeginOutside(m *Module, interrupt func()) *OutsideCall {
	t := w.lockSignalThread(m)
	defer w.unlockSignals()
	c := &OutsideCall{w: w, thread: t, interrupt: interrupt}
	t.outside = append(t.outside, c)
	return c
}

// Pending reports whether a signal is waiting for the call's thread that the
// thread does not block, or the end of the instance was asked for: the code
// outside the guest is then to return to the guest instead of waiting. It
// reports the state as it is when it is asked.
func (c *OutsideCall) Pending() bool {
	s := &c.w.sig
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliverable(c.thread) != 0 || s.stop.Load() != nil
}

// End ends the call. Once it has returned, interrupt is not called any more,
// and none of its calls is still running.
func (c *OutsideCall) End() {
	s := &c.w.sig
	s.mu.Lock()
	t := c.thread
	t.outside = slices.DeleteFunc(t.outside, func(o *OutsideCall) bool { return o == c })
	var idle chan struct{}
	if c.calls > 0 {
		idle = make(chan struct{})
		c.idle = idle
	}
	s.mu.Unlock()
	if idle != nil {
		<-idle
	}
}

// raiseSignalFlag stores 1 in the flag word of t, atomically: the guest runs
// on another goroutine. It may be growing its memory, hence accessMemory:
// the word is looked up in the guest's memory (memBytes) under the lock
// growth takes. Nothing is stored for a thread that has not registered or
// is not known yet, nor once delivery has ended. Caller does not hold
// w.sig.mu.
func (w *WasiStubs) raiseSignalFlag(t *wasiSignalThread) {
	s := &w.sig
	s.flagMu.Lock()
	defer s.flagMu.Unlock()
	s.mu.Lock()
	m, addr, raise := t.module, t.flagAddr, t.registered && t.module != nil && !s.detached
	s.mu.Unlock()
	if !raise {
		return
	}
	accessMemory(m, func([]byte) {
		if b := w.memBytes(m, addr, 4); b != nil {
			atomic.StoreUint32((*uint32)(unsafe.Pointer(&b[0])), 1)
		}
	})
}

// beginBlocking is called by a host call of the thread whose module m is that
// is about to block the guest's thread. It reports false when the call must
// not block at all because a signal is waiting for the thread to notice it:
// the call then returns EINTR. Otherwise wake is registered for the call b: a
// signal delivered to the thread calls it, once, from another goroutine and
// without a lock of the instance held, to end the wait. Every beginBlocking
// that returned true is followed by endBlocking with its b.
//
// A call of an instance that is to stop (requestStopLocked) does not block:
// it ends the guest's thread (endIfStopped). A guest that has not registered
// for signals would never take a signal: the call ends the guest instead
// (unregisteredEnd).
func (w *WasiStubs) beginBlocking(m *Module, wake func()) (b *wasiBlocking, ok bool) {
	s := &w.sig
	t := w.lockSignalThread(m)
	w.postDueTimerLocked(t)
	if sig := s.unregisteredEnd(); sig != 0 {
		w.unlockSignals()
		w.terminate(sig)
	}
	if s.stop.Load() != nil {
		w.unlockSignals()
		w.endIfStopped()
	}
	defer w.unlockSignals()
	if t.interrupt {
		t.interrupt = false
		return nil, false
	}
	if t.wakes == nil {
		t.wakes = map[*wasiBlocking]bool{}
	}
	b = &wasiBlocking{thread: t, wake: wake}
	t.wakes[b] = true
	return b, true
}

// endBlocking ends what beginBlocking started as b and reports whether a
// signal was delivered to the thread in between that this call is to report:
// a signal ends one of the thread's blocking calls in progress with EINTR.
// The others resume their wait. It returns once a wake of b that was called
// has returned, and ends the guest's thread instead when the instance is to
// stop.
func (w *WasiStubs) endBlocking(b *wasiBlocking) (interrupted bool) {
	s := &w.sig
	s.mu.Lock()
	t := b.thread
	delete(t.wakes, b)
	w.postDueTimerLocked(t)
	sig := s.unregisteredEnd()
	interrupted = t.interrupt
	t.interrupt = false
	woken := b.woken
	w.unlockSignals()
	if woken != nil {
		<-woken
	}
	if sig != 0 {
		w.terminate(sig)
	}
	w.endIfStopped()
	return interrupted
}

// postDueTimerLocked posts the firing of the interval timer whose time has
// come for the guest, from the host call of the thread t
// (postForGuestLocked), as a blocking call does when it begins and when it
// ends, and has the guest interrupted by it before the call goes on. Caller
// holds w.sig.mu, which it holds again on return.
func (w *WasiStubs) postDueTimerLocked(t *wasiSignalThread) {
	w.postForGuestLocked(t, w.fireDueTimerLocked)
	if len(w.sig.due.raises) > 0 || len(w.sig.due.wakes) > 0 || w.sig.due.alarm != nil || w.sig.due.alarmToOffer {
		w.unlockSignals()
		w.sig.mu.Lock()
	}
}

// keepInterrupt is called when a call of the thread whose module m is that a
// signal had interrupted was carried out after all, because it did not have
// to wait. The thread has not noticed the signal yet, and nothing has told
// it: its next call that has to wait is interrupted, as the one that was let
// through would have been.
func (w *WasiStubs) keepInterrupt(m *Module) {
	t := w.lockSignalThread(m)
	defer w.unlockSignals()
	if w.sig.deliverable(t) != 0 {
		t.interrupt = true
	}
}

// Proc_signal_register is a NON-STANDARD host import (module
// wasip1_posix_extension, name "proc_signal_register"). The calling thread of
// the guest names the 32-bit word in its memory that the host sets to 1
// whenever a signal is waiting for that thread to take it, with an atomic
// store: the word is aligned to 4 bytes, and the guest reads it with an
// atomic load (i32.atomic.load) and clears it with an atomic store
// (i32.atomic.store) — a C program built with the atomics feature, whose C
// atomics are plain loads and stores without it. Each thread registers a
// word of its own, or the same word as others; the host stores into it until
// the thread ends, so the word is to stay the thread's for as long as the
// thread runs. A thread calls it whenever it
// may be running in a module instance the host has not seen yet (a snapshot
// or fork copy of the one that registered), so it is cheap: it returns 1
// when this module and address are already registered — a forked instance
// has the registration of the thread that forked (Fork) — and 0 when the
// registration is new: the guest then reports its dispositions, which the
// host does not know either. A negative errno is EFAULT for a word outside
// the guest's memory and EINVAL for one that is not aligned.
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
	// A pending signal that ends a guest without a registration ends it
	// here, before the registration.
	w.endUnregistered()
	if w.memBytes(m, flagPtr, 4) == nil {
		return -_wasiEFAULT
	}
	if flagPtr%4 != 0 {
		return -_wasiEINVAL
	}
	s := &w.sig
	// A raise of the word registered before that is in progress is over
	// first (flagMu): none is made at the old address once this returns.
	s.flagMu.Lock()
	t := w.lockSignalThread(m)
	known := t.registered && t.flagAddr == flagPtr
	if !known {
		t.registered, t.flagAddr = true, flagPtr
		if bits := s.deliverable(t); bits != 0 {
			// Waiting for the process while no thread took it, or raised
			// for this thread: the new word is raised for it.
			w.postForGuestLocked(t, func() { s.announceLocked(t, bits) })
		}
	}
	s.flagMu.Unlock()
	w.unlockSignals()
	if known {
		return 1
	}
	return 0
}

// Proc_signal_dispositions is a NON-STANDARD host import (name
// "proc_signal_dispositions"). The guest reports, as signal masks, the
// signals it has a handler for, the signals it ignores explicitly (SIG_IGN)
// and the signals the calling thread has blocked, every time one of the
// three changes: the first two are the process's, the mask is the thread's.
// A pending signal that now has no effect is discarded, as sigaction(2)
// does; a pending one the thread no longer blocks is delivered to it, and
// one it now blocks is delivered to another thread that takes it, if any.
// SIGKILL and SIGSTOP are left out of all three: they can be neither caught
// nor ignored nor blocked. Ignoring SIGCHLD also gives up the children that
// have ended and were not waited for (see wasiSignals.reapsChildren). The
// dispositions are then reported to WASIConfig.Signals, with w as the
// target. Returns 0.
func (w *WasiStubs) Proc_signal_dispositions(m *Module, handled, ignored, blocked int64) int32 {
	w.endIfStopped()
	w.dispositionsMu.Lock()
	defer w.dispositionsMu.Unlock()
	s := &w.sig
	t := w.lockSignalThread(m)
	uncatchable := wasiSignalBit(wasiSIGKILL) | wasiSignalBit(wasiSIGSTOP)
	s.handled = uint64(handled) &^ uncatchable
	s.ignored = uint64(ignored) &^ uncatchable
	newlyBlocked := uint64(blocked) &^ uncatchable &^ t.blocked
	t.blocked = uint64(blocked) &^ uncatchable
	discards := s.discards()
	s.pending &^= discards
	for _, u := range s.threads {
		u.pending &^= discards
	}
	w.postForGuestLocked(t, func() {
		if bits := s.deliverable(t); t.registered && bits != 0 {
			// Deliverable now: unblocked while pending, or posted to a
			// forked guest before its thread was known.
			s.announceLocked(t, bits)
		} else {
			// Nothing deliverable is waiting for the thread: no blocking
			// call of its ends for it.
			t.interrupt = false
		}
		s.retargetLocked(s.pending & newlyBlocked)
	})
	handledNow, ignoredNow, blockedNow := s.handled, s.ignored, s.blockedByAllLocked(t)
	w.unlockSignals()
	if s.reapsChildren() {
		w.mu.Lock()
		w.reapFinishedLocked()
		w.mu.Unlock()
	}
	if w.cfg.Signals != nil {
		w.cfg.Signals.Dispositions(w, handledNow, ignoredNow, blockedNow)
	}
	return _wasiESUCCESS
}

// Proc_signal_dispositions64 is Proc_signal_dispositions for a memory64 guest.
func (w *WasiStubs) Proc_signal_dispositions64(m *Module, handled, ignored, blocked int64) int32 {
	return w.Proc_signal_dispositions(m, handled, ignored, blocked)
}

// Proc_signal_take is a NON-STANDARD host import (name "proc_signal_take").
// It writes at maskPtr the mask (u64) of the signals waiting for the calling
// thread — posted to the process and raised for the thread — and takes the
// ones the thread does not block: from here on they are the thread's to
// deliver. The ones it blocks stay with the host, for the thread or another
// one to take once it unblocks them; the guest has them in the mask as
// pending (sigpending). Returns 0 or a negative errno.
func (w *WasiStubs) Proc_signal_take(m *Module, maskPtr int32) int32 {
	return w.procSignalTake(m, zext(maskPtr))
}

// Proc_signal_take64 is Proc_signal_take for a memory64 guest.
func (w *WasiStubs) Proc_signal_take64(m *Module, maskPtr int64) int32 {
	return w.procSignalTake(m, uint64(maskPtr))
}

// procSignalTake is the body of Proc_signal_take and Proc_signal_take64.
func (w *WasiStubs) procSignalTake(m *Module, maskPtr uint64) int32 {
	// The safe point of a guest whose instance is to stop is where it ends.
	w.endIfStopped()
	out := w.memBytes(m, maskPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	s := &w.sig
	t := w.lockSignalThread(m)
	waiting := s.pending | t.pending
	taken := waiting &^ t.blocked
	s.pending &^= taken
	t.pending &^= taken
	// The thread is at a safe point and has the signals it takes: there is
	// nothing left to interrupt a blocking call of its for.
	t.interrupt = false
	w.unlockSignals()
	binary.LittleEndian.PutUint64(out, waiting)
	return _wasiESUCCESS
}

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
	w.endUnregistered()
	out := w.memBytes(m, oldPtr, 16)
	if out == nil {
		return -_wasiEFAULT
	}
	if set != 0 && (value < 0 || interval < 0) {
		return -_wasiEINVAL
	}
	t := w.lockSignalThread(m)
	w.postForGuestLocked(t, w.fireDueTimerLocked)
	left, every := w.timerStateLocked()
	if set != 0 {
		w.stopTimerLocked()
		if value > 0 {
			w.startTimerLocked(time.Duration(value), time.Duration(interval))
		}
	}
	w.unlockSignals()
	binary.LittleEndian.PutUint64(out[0:], uint64(left))
	binary.LittleEndian.PutUint64(out[8:], uint64(every))
	return _wasiESUCCESS
}

// timerStateLocked returns the time until the interval timer fires next and
// its reload interval; both are 0 when no timer is set. Caller holds
// w.sig.mu.
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
// pending once anyway. Caller holds w.sig.mu and has stopped any earlier
// timer.
func (w *WasiStubs) startTimerLocked(value, every time.Duration) {
	// The moment is taken before the host's timer is set, so that the
	// host's timer never runs ahead of it.
	at := time.Now().Add(value)
	var timer *time.Timer
	timer = time.AfterFunc(value, func() {
		w.sig.mu.Lock()
		defer w.unlockSignals()
		if w.sig.timer == timer {
			w.fireDueTimerLocked()
		}
	})
	w.sig.timer, w.sig.timerAt, w.sig.timerEvery = timer, at, every
}

// fireDueTimerLocked makes the firing of the interval timer whose time has
// come: SIGALRM is posted (offered WASIConfig.TakeSignal first), and the
// timer is set for its next firing or is over. The host's own timer does
// this when it runs, which is some time after the moment it was set for; a
// blocking call of the guest's does it when it begins and when it ends, so
// that the guest sees the two in the order of their times — a wait that
// ended by a timeout later than the timer's time ends after the signal was
// posted, as it does when a kernel keeps both (alarm(1); sleep(1) finds its
// handler run when sleep is over).
// Caller holds w.sig.mu.
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
	if s.execed != nil {
		// The guest has become a command (Proc_exec): the timer's signal
		// is the process's, as an alarm(2) set before execve(2) is, unless
		// the guest ignores it, which an exec keeps.
		if s.ignored&wasiSignalBit(wasiSIGALRM) == 0 {
			s.due.alarm = s.execed.process
		}
		return
	}
	if w.cfg.TakeSignal != nil {
		// Offered once w.sig.mu is let go (unlockSignals).
		s.due.alarmToOffer, s.due.alarmFor = true, s.quiet
		return
	}
	w.postSignalLocked(wasiSIGALRM)
}

// offerAlarm offers SIGALRM, the firing of the interval timer, to
// WASIConfig.TakeSignal, and posts it when it is not taken, from the host
// call of the thread t (postForGuestLocked) when t is not nil. Caller holds
// neither w.mu nor w.sig.mu; a stream's write lock may be held.
func (w *WasiStubs) offerAlarm(t *wasiSignalThread) {
	if w.takeSignal(wasiSIGALRM) {
		return
	}
	w.sig.mu.Lock()
	w.postForGuestLocked(t, func() { w.postSignalLocked(wasiSIGALRM) })
	w.unlockSignals()
}

// postForGuestLocked runs post, which posts signals while the guest's own
// code is running on the thread t — a host call it made, a blocking call of
// its that begins or ends: what post posts for t is left for t and its next
// blocking call, not delivered to code outside the guest (BeginOutside),
// which t does not run then; and a signal of the process goes to t when t
// takes it. Caller holds w.sig.mu.
func (w *WasiStubs) postForGuestLocked(t *wasiSignalThread, post func()) {
	quiet := w.sig.quiet
	w.sig.quiet = t
	post()
	w.sig.quiet = quiet
}

// stopTimerLocked disarms the interval timer, if one is set. Caller holds
// w.sig.mu.
func (w *WasiStubs) stopTimerLocked() {
	s := &w.sig
	if s.timer == nil {
		return
	}
	s.timer.Stop()
	s.timer, s.timerEvery = nil, 0
}

// Proc_terminate is a NON-STANDARD host import (name "proc_terminate"): the
// guest ends by signal sig, the default action of a signal it neither
// handles nor ignores. It does not return; like Proc_exit it unwinds the
// guest with a panic, whose value is a *WasiSignalError. Like Proc_exit it
// ends signal delivery to the instance first, and the guest's other threads
// with the same panic (stop).
func (w *WasiStubs) Proc_terminate(m *Module, sig int32) {
	w.stop(m, &WasiSignalError{Signal: sig})
}

// terminate ends the guest by signal sig (stop) with a *WasiSignalError. It
// does not return. Caller holds no lock of the instance.
func (w *WasiStubs) terminate(sig int32) {
	w.stop(nil, &WasiSignalError{Signal: sig})
}

// stop ends the instance with end, the panic value of an end by a signal or
// of Proc_exit, unless an end was asked for before, which is then the one:
// signal delivery to the instance ends, the calling thread of the guest is
// unwound with the end at once, and the others at their next blocking call
// or call that looks (endIfStopped). m is the calling thread's module, nil
// when the caller has none. It does not return. Caller holds no lock of the
// instance.
func (w *WasiStubs) stop(m *Module, end wasiEnd) {
	w.sig.mu.Lock()
	w.requestStopLocked(m, end)
	w.unlockSignals()
	w.endIfStopped()
}

// requestStopLocked asks for the end of the instance with end, unless one
// was asked for before: the blocking calls in progress end, the calls of code
// outside the guest the threads run are interrupted, the flag words are
// raised, the waits of the guest's agents end, and each thread of the guest
// unwinds with the end (endIfStopped). m is a module of the guest, nil when
// the caller has none: the module of a thread the host knows stands in for
// it then. Caller holds w.sig.mu.
func (w *WasiStubs) requestStopLocked(m *Module, end wasiEnd) {
	s := &w.sig
	if s.stop.Load() == nil {
		s.stop.Store(&wasiStop{end: end})
	}
	s.due.wakes = append(s.due.wakes, s.takeAllWakes()...)
	s.due.stop = true
	s.due.stopModule = m
	for _, t := range s.threads {
		s.due.stopModule = cmp.Or(s.due.stopModule, t.module)
		if t.registered {
			s.due.stopFlags = append(s.due.stopFlags, t)
		}
		if c := t.current(); c != nil && !slices.Contains(s.due.stopOutside, c) {
			c.calls++
			s.due.stopOutside = append(s.due.stopOutside, c)
		}
	}
}

// endIfStopped unwinds the calling thread of the guest when the end of the
// instance has been asked for (requestStopLocked): signal delivery ends, and
// the thread panics with the end. Caller holds no lock of the instance.
func (w *WasiStubs) endIfStopped() {
	st := w.sig.stop.Load()
	if st == nil {
		return
	}
	w.detachSignals()
	panic(st.end)
}

// endUnregistered ends the guest's thread when the instance is to stop
// (endIfStopped), and the guest by a pending signal it would never take, not
// having registered for signals (unregisteredEnd). The host calls fd_read,
// fd_write, poll_oneoff and the proc_ ones call it first; a blocking call
// looks again when it begins and ends.
func (w *WasiStubs) endUnregistered() {
	w.endIfStopped()
	w.sig.mu.Lock()
	sig := w.sig.unregisteredEnd()
	w.sig.mu.Unlock()
	if sig != 0 {
		w.terminate(sig)
	}
}

// Proc_terminate64 is Proc_terminate for a memory64 guest.
func (w *WasiStubs) Proc_terminate64(m *Module, sig int32) {
	w.Proc_terminate(m, sig)
}

// detachSignals ends signal delivery to this instance: nothing may touch the
// guest's memory once it is being torn down, and once it has returned
// nothing does (raiseSignalFlag).
func (w *WasiStubs) detachSignals() {
	s := &w.sig
	s.flagMu.Lock()
	defer s.flagMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	w.stopTimerLocked()
	for _, t := range s.threads {
		t.registered, t.flagAddr = false, 0
		t.blocked, t.pending, t.interrupt = 0, 0, false
	}
	s.handled, s.ignored, s.pending = 0, 0, 0
	s.detached = true
}

// readStream reads from a stream whose read can block, as the guest asked
// for it: a non-blocking descriptor (O_NONBLOCK) reports EAGAIN when no
// input is there, a blocking one waits and reports EINTR when a signal is
// posted to the guest meanwhile. A stream of the entry's own that the Go
// runtime polls is read by readPolledStream, any other descriptor of the
// host's that poll(2) waits for by readHostStream, any other stream through
// its reader (readThroughReader).
func (w *WasiStubs) readStream(m *Module, call string, op *wasiOpen, src io.Reader, bufs [][]byte) (uint64, int32) {
	switch {
	case w.netpolled(op, src):
		return w.readPolledStream(m, call, op, src.(deadlineReader), bufs)
	case op.inputPolled(src):
		return w.readHostStream(m, call, op, src.(syscall.Conn), bufs, op.nonblocking())
	}
	return w.readThroughReader(m, call, op, w.inputReader(op, src), bufs, op.nonblocking())
}

// readThroughReader reads the stream behind the entry op through its reader
// r, as the guest asked for it: what the reader keeps, or else a Read it is
// asked for. A non-blocking read (nonblocking) reports EAGAIN when the
// reader keeps nothing, which the Read it asks for ends the wait of a poll
// for; a blocking one waits for it, and a signal posted to the guest
// meanwhile ends the wait with EINTR. What the reader has when the signal
// ends the wait is read all the same, as read(2) returns the input there to
// a process with a signal pending; a Read that returns later keeps its
// input for the next read. The wait holds no turn: the reads it wakes each
// take what there is, and one that finds nothing waits again.
func (w *WasiStubs) readThroughReader(m *Module, call string, op *wasiOpen, r *streamReader, bufs [][]byte, nonblocking bool) (uint64, int32) {
	set := []hostWaitFD{{source: r, op: op}}
	for {
		if n, err, ok := r.take(bufs); ok {
			return w.readResult(call, n, err)
		}
		r.request()
		if nonblocking {
			return 0, _wasiEAGAIN
		}
		interrupted, err := w.waitHostInterruptibly(m, call, set, time.Time{})
		if err != nil {
			return 0, w.guestErrno(call, err)
		}
		if !interrupted {
			continue
		}
		n, err, ok := r.take(bufs)
		if !ok {
			return 0, _wasiEINTR
		}
		// The read went through: the next call that waits reports the
		// signal.
		w.keepInterrupt(m)
		return w.readResult(call, n, err)
	}
}

// inputReader returns the reader of src, the stream behind the entry op
// that poll(2) does not wait for (readStream): the family's for the
// instance's stdin, which every instance of the family reads from
// (familyStreams), the entry's own for any other stream, which every slot
// of the entry reads from, made on first use.
func (w *WasiStubs) inputReader(op *wasiOpen, src io.Reader) *streamReader {
	if op.stdio == 1 {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.streamsLocked().stdin
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.reader == nil {
		op.reader = newStreamReader(src, func(err error) { w.reportError("fd_read", err) })
	}
	return op.reader
}

// readPolledStream reads src, a stream of the entry op that the Go runtime
// polls (netpolled), as the guest asked for it. A non-blocking read is one
// readv(2) (readNow); of a standard stream of the embedder's, which can
// change the mode of its description, it is readEmbedderNow's, which asks
// the mode first. A blocking one waits in the poller of the Go runtime
// (readInterruptibly); the input there when a signal ends the wait is read
// all the same, as read(2) returns it to a process with a signal pending.
func (w *WasiStubs) readPolledStream(m *Module, call string, op *wasiOpen, src deadlineReader, bufs [][]byte) (uint64, int32) {
	conn := src.(syscall.Conn)
	now := func() (uint64, int32) {
		if op.stdio != 0 {
			return w.readEmbedderNow(m, call, op, conn, bufs)
		}
		return w.readNow(call, op, conn, bufs)
	}
	if op.nonblocking() {
		return now()
	}
	n, errno := w.readInterruptibly(m, call, op, src, bufs)
	if errno != _wasiEINTR {
		return n, errno
	}
	got, errno, served := w.takeAhead(call, op, bufs)
	if !served {
		got, errno = now()
	}
	if errno == _wasiEAGAIN {
		return 0, _wasiEINTR
	}
	// The read went through: the next call that waits reports the signal.
	w.keepInterrupt(m)
	return got, errno
}

// readNow reads src, the stream behind the entry op, once with readv(2) in
// its Control (tryStream), which does not wait in a descriptor in
// non-blocking mode: EAGAIN when there is nothing.
func (w *WasiStubs) readNow(call string, op *wasiOpen, src syscall.Conn, bufs [][]byte) (uint64, int32) {
	n, again, errno := w.tryStream(call, src, func(fd uintptr) (int, bool, error) { return readvRaw(fd, bufs) })
	if n > 0 {
		op.inputReads.Add(1)
	}
	if errno == _wasiESUCCESS && again {
		return 0, _wasiEAGAIN
	}
	return uint64(n), errno
}

// readEmbedderNow is a read that does not wait of src, a standard stream of
// the embedder's that the Go runtime polls and the stream behind the entry
// op. The mode of its description is asked first, since the embedder can
// change it: one in non-blocking mode is one readv(2), one in blocking mode
// is read as readHostAttempt reads, by the holder of the turn at its input
// once poll(2) has found input there, and is EAGAIN while another holds
// the turn. EAGAIN when there is nothing.
func (w *WasiStubs) readEmbedderNow(m *Module, call string, op *wasiOpen, src syscall.Conn, bufs [][]byte) (uint64, int32) {
	mayBlock := false
	k, again, errno := w.tryStream(call, src, func(fd uintptr) (int, bool, error) {
		if mayBlock = hostMayBlock(fd); mayBlock {
			return 0, true, nil
		}
		return readvRaw(fd, bufs)
	})
	if k > 0 {
		op.inputReads.Add(1)
	}
	n := uint64(k)
	if errno == _wasiESUCCESS && mayBlock {
		var tried bool
		if n, again, errno, tried = w.readHostAttempt(m, call, op, src, bufs, false, false, 0); !tried {
			return 0, _wasiEAGAIN
		}
	}
	if errno == _wasiESUCCESS && again {
		return 0, _wasiEAGAIN
	}
	return n, errno
}

// readHostStream reads src, a descriptor of the host's that poll(2) waits
// for (inputPolled) and the stream behind the entry op, as the guest asked
// for it: once (readHostAttempt), the input a command left of it first
// (giveAhead). A non-blocking read (nonblocking) reports EAGAIN when there
// is none, or another reader holds the turn at the input (as writeHostOnce
// does); a blocking one waits in poll(2) for input, and a signal posted
// to the guest meanwhile ends the wait with EINTR. The input there when the
// signal ends the wait is read all the same, as read(2) returns it to a
// process with a signal pending. The wait holds no turn: the readers it
// wakes each try again, and one that finds nothing waits again, as the
// readers of a Linux pipe do (fs/pipe.c, anon_pipe_read). A wait that
// found input is followed by the read without another look when no read
// of the entry has taken any since the wait began (readHostAttempt).
func (w *WasiStubs) readHostStream(m *Module, call string, op *wasiOpen, src syscall.Conn, bufs [][]byte, nonblocking bool) (uint64, int32) {
	set := []hostWaitFD{{stream: src, want: hostWantInput, op: op}}
	found, reads := false, uint64(0)
	for {
		if n, errno, served := w.takeAhead(call, op, bufs); served {
			return n, errno
		}
		n, again, errno, tried := w.readHostAttempt(m, call, op, src, bufs, !nonblocking, found, reads)
		switch {
		case !tried && nonblocking:
			// Another reader holds the turn: a read that does not wait
			// does not wait for it.
			return 0, _wasiEAGAIN
		case !tried:
			// The wait for the turn was ended by a signal.
		case !again:
			return n, errno
		case nonblocking:
			return 0, _wasiEAGAIN
		default:
			reads = op.inputReads.Load()
			interrupted, err := w.waitHostInterruptibly(m, call, set, time.Time{})
			if err != nil {
				return 0, w.guestErrno(call, err)
			}
			if !interrupted {
				found = set[0].ready
				continue
			}
		}
		n, errno, served := w.takeAhead(call, op, bufs)
		if !served {
			n, again, errno, tried = w.readHostAttempt(m, call, op, src, bufs, false, false, 0)
			served = tried && !again
		}
		if !served {
			return 0, _wasiEINTR
		}
		// The read went through: the next call that waits reports the
		// signal.
		w.keepInterrupt(m)
		return n, errno
	}
}

// readHostAttempt reads src, the stream behind the entry op, once without
// waiting (tryStream), and reports again when there is nothing. It reads
// as the holder of the turn at the input, whatever the mode of the
// description: a socket without waiting (MSG_DONTWAIT), anything else with
// one readv(2) once poll(2) has found input there. The readers poll(2) woke
// together thus do not both read the input one of them found, which in
// blocking mode would leave the other waiting in readv(2), as the readers
// of a Linux pipe hold its mutex while they look and copy (fs/pipe.c). The
// look is left out when the caller's wait found input (found) and no read
// of the entry has taken any since it began (the entry's inputReads, which
// were reads then): that input is still there. A process outside the
// runtime that shares the descriptor can still take the input in between.
// wait says whether the turn is waited for (awaitTurn) or taken only when
// it is free; tried is false when it was not taken — a signal is to be
// reported, or it was not free — and nothing was read.
func (w *WasiStubs) readHostAttempt(m *Module, call string, op *wasiOpen, src syscall.Conn, bufs [][]byte, wait, found bool, reads uint64) (n uint64, again bool, errno int32, tried bool) {
	turn := op.inputTurn()
	if wait {
		if !w.awaitTurn(m, turn) {
			return 0, false, _wasiESUCCESS, false
		}
	} else {
		select {
		case turn <- struct{}{}:
		default:
			return 0, false, _wasiESUCCESS, false
		}
	}
	defer func() { <-turn }()
	look := !found || op.inputReads.Load() != reads
	socket := false
	if file, isFile := src.(*os.File); isFile {
		mode, _ := op.statOf(file)
		socket = mode&os.ModeSocket != 0
	}
	k, again, errno := w.tryStream(call, src, func(fd uintptr) (int, bool, error) {
		switch {
		case socket:
			return recvNow(fd, bufs)
		case look:
			ready := []bool{false}
			if err := hostWaitReady([]uintptr{fd}, []int{hostWantInput}, ready, time.Now(), -1); err != nil {
				return 0, false, err
			}
			if !ready[0] {
				return 0, true, nil
			}
		}
		return readvRaw(fd, bufs)
	})
	if k > 0 {
		op.inputReads.Add(1)
	}
	return uint64(k), again, errno, true
}

// awaitOutputTurn takes the turn at op's output for a blocking write of the
// guest's (awaitTurn).
func (w *WasiStubs) awaitOutputTurn(m *Module, op *wasiOpen) bool {
	return w.awaitTurn(m, op.outputTurn())
}

// awaitInputTurn takes the turn at op's input for a blocking call of the
// guest's (awaitTurn).
func (w *WasiStubs) awaitInputTurn(m *Module, op *wasiOpen) bool {
	return w.awaitTurn(m, op.inputTurn())
}

// awaitTurn takes turn for a blocking call of the guest's. It reports false
// when the call is to report a signal posted to the guest meanwhile: the
// call is then to be reported as EINTR, and the turn is not held. A signal
// another blocking call reports leaves the wait on. A call that terminate
// unwinds does not keep the turn. A turn that is free is taken without
// waiting, whatever signal is posted: the call that has it then does what
// does not wait, as a system call does for a process with a signal pending.
func (w *WasiStubs) awaitTurn(m *Module, turn chan struct{}) bool {
	select {
	case turn <- struct{}{}:
		return true
	default:
	}
	held, kept := false, false
	defer func() {
		if held && !kept {
			<-turn
		}
	}()
	for {
		interrupted, _, refused := w.blockingAttempt(m, func() {}, nil,
			func(stop <-chan struct{}) { held = takeTurn(turn, stop) })
		if refused || interrupted {
			return false
		}
		if held {
			kept = true
			return true
		}
	}
}

// readInterruptibly is readVec for a stream whose read can block and that
// the Go runtime polls (readPolledStream): a signal posted while the read
// waits — for its turn at the stream, or for input — ends it, with EINTR
// when that happened before any byte arrived, and so does input a command
// leaves meanwhile (giveAhead), which the read then returns. The read is
// one, as readv(2)'s.
func (w *WasiStubs) readInterruptibly(m *Module, call string, op *wasiOpen, src deadlineReader, bufs [][]byte) (uint64, int32) {
	if !w.awaitInputTurn(m, op) {
		return 0, _wasiEINTR
	}
	defer op.passInputTurn()
	defer op.watchAhead(nil)
	// A signal ends the wait for input through a deadline the stream takes,
	// and only the holder of the turn sets one: a deadline left now was
	// left by a holder that was unwound.
	if err := deadlineErr(src, src.SetReadDeadline(time.Time{})); err != nil {
		return 0, w.guestErrno(call, err)
	}
	var n int
	var err error
	for {
		// Whoever had the turn before, or a command, may have left input
		// behind.
		if n, errno, served := w.takeAhead(call, op, bufs); served {
			return n, errno
		}
		// wake sets a deadline, which must not outlive the attempt. A stream
		// closed meanwhile refuses it, as it may have refused wake's: the
		// closing is what the read failed of. Input a command leaves while
		// the read waits sets one as well (watchAhead), which the read
		// clears once that can no longer happen.
		var wakeErr, aheadErr error
		aheadWoken := false
		if op.watchAhead(func() { aheadWoken, aheadErr = true, src.SetReadDeadline(time.Now()) }) {
			continue
		}
		clearDeadline := func() error { return errors.Join(wakeErr, src.SetReadDeadline(time.Time{})) }
		interrupted, woken, refused := w.blockingAttempt(m,
			func() { wakeErr = src.SetReadDeadline(time.Now()) },
			func() { w.reportError(call, clearDeadline()) },
			func(<-chan struct{}) { n, err = readOnce(src, bufs) })
		op.watchAhead(nil)
		if n > 0 {
			op.inputReads.Add(1)
		}
		var clearErr error
		if woken || aheadWoken {
			clearErr = deadlineErr(src, errors.Join(aheadErr, clearDeadline()))
		}
		switch {
		case refused:
			return 0, _wasiEINTR
		case clearErr != nil && n == 0:
			return 0, w.guestErrno(call, clearErr)
		case n > 0 || !errors.Is(err, os.ErrDeadlineExceeded):
			if interrupted {
				// The read went through: the next call that waits reports
				// the signal.
				w.keepInterrupt(m)
			}
			return w.readResult(call, n, err)
		case interrupted:
			return 0, _wasiEINTR
		case !woken && !aheadWoken:
			// Only the holder of the turn sets a deadline, so this one is
			// not the stream's any more: it was left behind.
			if err := src.SetReadDeadline(time.Time{}); err != nil {
				return 0, w.guestErrno(call, deadlineErr(src, err))
			}
		}
		// Woken by a signal another blocking call reports, or by input a
		// command left: the read takes that, or waits on.
	}
}

// wasiFdflagNonblock is the O_NONBLOCK bit of the fdflags (fd_fdstat_set_flags).
const wasiFdflagNonblock int32 = 0x4

// nonblocking reports whether the guest has set O_NONBLOCK on the entry.
func (op *wasiOpen) nonblocking() bool {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.fdflags&wasiFdflagNonblock != 0
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
// m.memory get rewritten to m.Memory by rewriteHelperBody,
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
		// The codegen package's own declarations; everything else is the
		// runtime and is emitted.
		dropTypes: map[string]bool{
			"Module":           true, // the in-package stand-in of the module
			"codegenStripOpts": true,
			"codegenWriter":    true,
			"translator":       true, // the receiver of emitWasip1Native and the like
			"runtimeMapping":   true, // the in-package stand-in of the shared image's
		},
		dropFuncs: map[string]bool{
			"accessMemory":              true,
			"stopAgents":                true, // the in-package stand-in of the helper
			"runtimeMappingOf":          true,
			"whileRuntimeMapped":        true,
			"noteSegment":               true,
			"forkRuntimeMapping":        true,
			"unmapMemory":               true,
			"onAgentEnd":                true, // likewise
			"codegenStripForEmit":       true,
			"printAST":                  true,
			"receiverTypeName":          true,
			"renamePackage":             true,
			"rewriteValueSpecsSelfRefs": true,
		},
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
				fn.Body = rewriteHelperBody(fn.Body, map[string]bool{"accessMemory": true, "stopAgents": true, "onAgentEnd": true})
			}
			decls = append(decls, &fn)
		}
	}

	imports := []string{
		"bytes",
		"cmp",
		"context",
		"crypto/rand",
		"encoding/binary",
		"errors",
		"fmt",
		"io",
		"io/fs",
		"maps",
		"math",
		"math/bits",
		"net",
		"net/netip",
		"os",
		"os/exec",
		"os/user",
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
		"unsafe",
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
	//go:embed wasip1_native_nolinux.go
	wasip1NativeNoLinuxRaw []byte
	//go:embed wasip1_native_descriptors.go
	wasip1NativeDescriptorsRaw []byte
	//go:embed wasip1_native_linux_msg.go
	wasip1NativeLinuxMsgRaw []byte
	//go:embed wasip1_native_linux_386.go
	wasip1NativeLinux386Raw []byte
	//go:embed wasip1_native_linux_reuseport.go
	wasip1NativeLinuxReusePortRaw []byte
	//go:embed wasip1_native_linux_mipsreuseport.go
	wasip1NativeLinuxMIPSReusePortRaw []byte
	//go:embed wasip1_hostnumbers_linux.go
	wasip1HostNumbersLinuxRaw []byte
	//go:embed wasip1_hostnumbers_linux_headers.go
	wasip1HostNumbersLinuxHeadersRaw []byte
	//go:embed wasip1_hostnumbers_linux_noheaders.go
	wasip1HostNumbersLinuxNoHeadersRaw []byte
	//go:embed wasip1_hostnumbers_darwin.go
	wasip1HostNumbersDarwinRaw []byte

	//go:embed wasip1_native_terminal_linux.go
	wasip1NativeTerminalLinuxRaw []byte
	//go:embed wasip1_native_terminal_darwin.go
	wasip1NativeTerminalDarwinRaw []byte

	//go:embed wasip1_native_ipc_linux.go
	wasip1NativeIPCLinuxRaw []byte
	//go:embed wasip1_native_ipc_other.go
	wasip1NativeIPCOtherRaw []byte

	//go:embed wasip1_syscalls_linux.go
	wasip1SyscallsLinuxRaw []byte
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
		"wasip1_native_posix.go":   wasip1NativePosixRaw,
		"wasip1_native_linux.go":   wasip1NativeLinuxRaw,
		"wasip1_native_darwin.go":  wasip1NativeDarwinRaw,
		"wasip1_native_other.go":   wasip1NativeOtherRaw,
		"wasip1_native_hostfd.go":  wasip1NativeHostFDRaw,
		"wasip1_native_nolinux.go": wasip1NativeNoLinuxRaw,

		"wasip1_native_descriptors.go": wasip1NativeDescriptorsRaw,

		"wasip1_native_linux_msg.go": wasip1NativeLinuxMsgRaw,
		"wasip1_native_linux_386.go": wasip1NativeLinux386Raw,

		"wasip1_native_linux_reuseport.go":     wasip1NativeLinuxReusePortRaw,
		"wasip1_native_linux_mipsreuseport.go": wasip1NativeLinuxMIPSReusePortRaw,

		"wasip1_hostnumbers_linux.go":           wasip1HostNumbersLinuxRaw,
		"wasip1_hostnumbers_linux_headers.go":   wasip1HostNumbersLinuxHeadersRaw,
		"wasip1_hostnumbers_linux_noheaders.go": wasip1HostNumbersLinuxNoHeadersRaw,
		"wasip1_hostnumbers_darwin.go":          wasip1HostNumbersDarwinRaw,

		"wasip1_native_terminal_linux.go":  wasip1NativeTerminalLinuxRaw,
		"wasip1_native_terminal_darwin.go": wasip1NativeTerminalDarwinRaw,

		"wasip1_native_ipc_linux.go": wasip1NativeIPCLinuxRaw,
		"wasip1_native_ipc_other.go": wasip1NativeIPCOtherRaw,

		"wasip1_syscalls_linux.go": wasip1SyscallsLinuxRaw,
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

// codegenStripOpts names the top-level declarations of the embedded source
// that are the codegen package's own, which strip removes before the rest
// is spliced into the generated output: types with their methods
// (dropTypes, which names the receiver types of the codegen package's
// methods too) and functions (dropFuncs). The vars the codegen package
// embeds its sources into, the ones with a //go:embed directive, go as
// well. Everything else stays, constants included.
type codegenStripOpts struct {
	dropTypes map[string]bool
	dropFuncs map[string]bool
}

// codegenStripForEmit returns the embedded source with the codegen
// package's own declarations removed (codegenStripOpts). It also rewrites
// the package declaration to wasip1native so downstream parser-level
// operations don't see the codegen package name.
func codegenStripForEmit(raw []byte, opts codegenStripOpts) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", raw, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	f.Name = &ast.Ident{Name: "wasip1native"}
	// embeds reports whether doc holds a //go:embed directive: the line
	// comment "//go:embed" followed by a space or a tab and the patterns.
	embeds := func(doc *ast.CommentGroup) bool {
		return doc != nil && slices.ContainsFunc(doc.List, func(c *ast.Comment) bool {
			rest, found := strings.CutPrefix(c.Text, "//go:embed")
			return found && rest != "" && (rest[0] == ' ' || rest[0] == '\t')
		})
	}
	kept := f.Decls[:0]
	for _, d := range f.Decls {
		switch dd := d.(type) {
		case *ast.GenDecl:
			switch dd.Tok.String() {
			case "import":
				continue
			case "const":
				kept = append(kept, dd)
			case "type":
				specs := dd.Specs[:0]
				for _, sp := range dd.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok {
						specs = append(specs, sp)
						continue
					}
					if !opts.dropTypes[ts.Name.Name] {
						specs = append(specs, sp)
					}
				}
				if len(specs) == 0 {
					continue
				}
				dd.Specs = specs
				kept = append(kept, dd)
			case "var":
				// The directive of a declaration without parentheses is
				// the declaration's doc.
				if !dd.Lparen.IsValid() && embeds(dd.Doc) {
					continue
				}
				specs := dd.Specs[:0]
				for _, sp := range dd.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok || !embeds(vs.Doc) {
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
			// A method goes with its type, wherever the type is declared
			// (another platform file); a function when it is named.
			if dd.Recv != nil && len(dd.Recv.List) > 0 {
				if !opts.dropTypes[receiverTypeName(dd.Recv.List[0].Type)] {
					kept = append(kept, dd)
				}
				continue
			}
			if !opts.dropFuncs[dd.Name.Name] {
				kept = append(kept, dd)
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
// receiver expression. For "*Foo", "Foo" and "Foo[T]" it returns "Foo".
// Used by the strip logic to keep or drop the methods of a type with it.
func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.IndexExpr:
		return receiverTypeName(e.X)
	case *ast.IndexListExpr:
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
