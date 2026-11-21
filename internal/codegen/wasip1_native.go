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
// needed. The few operations the stdlib only offers per platform live in the
// wasip1_native_<platform>.go companions, which are emitted next to the
// generated output with their build constraints.
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

// osFS is the default FS backend: a thin pass-through to the host filesystem,
// scoped to root (the preopen directory). root "" or "/" means no rewriting.
type osFS struct{ root string }

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

// MemFS is an in-memory read/write FS. Each value is an independent tree, so
// two interpreters given separate MemFS values cannot observe each other's
// files (full per-interpreter filesystem isolation, no disk). Build one with
// NewMemFS. Safe for concurrent use.
type MemFS struct {
	mu   sync.Mutex
	root *memNode
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
	conn     net.Conn // guarded by mu; read it through netConn
	listener net.Listener
	isDir    bool
	isSocket bool // created by Sock_socket, may not yet have a conn
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
	// The stream is looked up on every use, so SetStdin/SetStdout/SetStderr
	// take effect for the entry and all its dups. Fds 0/1/2 start out with
	// such entries; closing one never touches the stream itself.
	stdio int8
	// refs counts EXTRA table slots sharing this entry (dup/dup2 in one
	// instance, plus every slot of a forked instance): closeWasiOpen only
	// closes the descriptor when it reaches zero. Guarded by mu.
	refs int32
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
	// procs tracks host processes spawned via Proc_spawn, keyed by the pid
	// handed back to the guest. nextPID is the handle counter (kept distinct
	// from real OS pids — the guest only ever sees these tokens).
	procs   map[int32]*wasiProc
	nextPID int32
	// execHook, when non-nil, gates every Proc_spawn with the resolved
	// executable path and argv; returning false denies the spawn (EACCES).
	// This is the outbound-process whitelist control point — the analogue of
	// dialHook for sockets. Spawning runs a HOST binary, so a sandbox that
	// enables host processes should always install this.
	execHook func(path string, argv []string) bool
	// cloexec holds the descriptor numbers the guest has marked
	// close-on-exec (Fd_cloexec). A number that is given to a new
	// descriptor starts unmarked. Guarded by mu.
	cloexec map[int32]bool
}

// wasiProc is a host process spawned by Proc_spawn. A background goroutine
// Waits on the command and publishes the encoded POSIX status, so Proc_wait
// can support both the blocking (options 0) and non-blocking (WNOHANG) forms
// without holding the WasiStubs lock across the child's lifetime.
type wasiProc struct {
	cmd    *exec.Cmd
	done   chan struct{}
	status int32 // POSIX wait status, valid once done is closed
}

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
		nextPID:    1000,
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
// hook is called with the operation name ("accept"/"recv"/"send")
// before each socket operation; returning false denies it (EACCES).
// Pass nil to clear (unrestricted, the default).
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

// Fork returns the host state for a forked copy of the guest, with fork(2)
// semantics:
//
//   - the configuration is the same: stdio streams, args, environment,
//     filesystem backend, clock origin and every hook;
//   - the fd table has the same fd numbers — an fd closed in w, fd 0, 1 or
//     2 included, is closed in the result — and each slot refers to the SAME
//     open descriptor as the corresponding slot of w, so the two instances
//     share the file offset, and the underlying file, connection or listener
//     is closed only when the last slot referring to it, in any instance, is
//     closed;
//   - the process table is empty: a child does not inherit its parent's
//     children.
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
		execHook:    w.execHook,
	}
	if len(w.cloexec) > 0 {
		child.cloexec = make(map[int32]bool, len(w.cloexec))
		for fd := range w.cloexec {
			child.cloexec[fd] = true
		}
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
// table entry and is never handed out for a new descriptor.
const wasiPreopenFD int32 = 3

// wasiRootFD is a second number of the preopened root directory: the path
// calls take it for the root, and fd_fdstat_get and fd_filestat_get
// describe the root under it. No descriptor ever has it: the numbers of
// descriptors are below it.
const wasiRootFD int32 = 0x7ffffff0

// rootDirFD reports whether fd names the preopened root directory.
func rootDirFD(fd int32) bool { return fd == wasiPreopenFD || fd == wasiRootFD }

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
		if _, used := fds[fd]; !used && fd != wasiPreopenFD {
			fds[fd] = op
			delete(w.cloexec, fd)
			return fd, true
		}
	}
	return -1, false
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
// linear memory. The child inherits the interpreter's stdin/stdout/stderr.
// The new pid token is written at pidOutPtr. Returns 0 or a negative errno.
//
// Only stdio inheritance is supported today (no fd remapping / pipes), which
// covers subprocess.run/call with default streams; capture_output via host
// pipes is a follow-up.
func (w *WasiStubs) Proc_spawn(m *Module, pathPtr, argvPtr, envpPtr, stdinFd, stdoutFd, stderrFd, cwdPtr, pidOutPtr int32) int32 {
	path, ok := w.readCStr(m, zext(pathPtr))
	if !ok || path == "" {
		return -_wasiEINVAL
	}
	argv, ok := w.readCStrArray(m, wasiABI32, zext(argvPtr))
	if !ok {
		return -_wasiEFAULT
	}
	env, ok := w.readCStrArray(m, wasiABI32, zext(envpPtr))
	if !ok {
		return -_wasiEFAULT
	}
	// The guest's working directory lives in its libc (WASI has no chdir
	// syscall), so the bridge passes it explicitly; the child must start
	// there, not in the host process's cwd.
	cwd, ok := w.readCStr(m, zext(cwdPtr))
	if !ok {
		return -_wasiEFAULT
	}
	out := w.memSlice(m, pidOutPtr, 4)
	if out == nil {
		return -_wasiEFAULT
	}

	w.mu.Lock()
	hook := w.execHook
	cin := w.childReaderLocked(stdinFd)
	cout := w.childWriterLocked(stdoutFd, w.stdout)
	cerr := w.childWriterLocked(stderrFd, w.stderr)
	w.mu.Unlock()
	if hook != nil && !hook(path, argv) {
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
	go func() {
		werr := cmd.Wait()
		proc.status = encodeWaitStatus(cmd.ProcessState)
		// A non-zero exit or signal surfaces as *exec.ExitError and is the
		// normal path (status already encoded from ProcessState above). Any
		// OTHER error means the wait itself failed; report a 127 exit.
		var exitErr *exec.ExitError
		if werr != nil && !errors.As(werr, &exitErr) {
			proc.status = int32(127) << 8
		}
		close(proc.done)
	}()

	w.mu.Lock()
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	if w.nextPID == 0 {
		w.nextPID = 1000
	}
	pid := w.nextPID
	w.nextPID++
	w.procs[pid] = proc
	w.mu.Unlock()

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
		return w.stdin
	}
	src, op := w.fdSrcLocked(fd)
	if op.socket() {
		return w.stdin
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

// Proc_wait is a NON-STANDARD host import (name "proc_wait") backing the
// bridge's waitpid(). It waits for the process token pid and writes the POSIX
// wait status at statusOutPtr. options is the waitpid() options mask; bit 0
// (WNOHANG) makes it return without blocking when the child is still running
// (the guest sees the documented "0 means no child ready" result, signalled
// by writing pid 0 — encoded by returning EAGAIN). Returns 0, or a negative
// errno (ECHILD for an unknown pid).
func (w *WasiStubs) Proc_wait(m *Module, pid, options, statusOutPtr int32) int32 {
	out := w.memSlice(m, statusOutPtr, 4)
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
	delete(w.procs, pid)
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(proc.status))
	return _wasiESUCCESS
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
// name "sock_getaddrinfo") backing the bridge's getaddrinfo(). It reads the
// host string at (nodePtr,nodeLen), consults the resolve whitelist, resolves it
// to an IPv4 address via Go's resolver (numeric IPs pass through), and writes
// the 4-byte network-order address at outPtr. Returns 0 on success or a
// negative POSIX-ish errno (the bridge maps it to an EAI_* code).
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
	hook := w.resolveHook
	w.mu.Unlock()
	if hook != nil && !hook(host) {
		return -_wasiEACCES
	}
	// Numeric IPv4 fast path (avoids a resolver call and works offline).
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out[0], out[1], out[2], out[3] = v4[0], v4[1], v4[2], v4[3]
			w.recordResolvedHost(v4, host)
			return _wasiESUCCESS
		}
		return -_wasiEAFNOSUPPORT // IPv6 not supported by this bridge
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

// SetStdin redirects guest fd 0 to r. A nil r leaves the current source.
// Use this to feed input() / sys.stdin from an in-process io.Reader instead
// of the host process stdin.
func (w *WasiStubs) SetStdin(r io.Reader) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r != nil {
		w.stdin = r
	}
}

// SetStdout redirects guest fd 1 to wr. A nil wr leaves the current sink.
func (w *WasiStubs) SetStdout(wr io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if wr != nil {
		w.stdout = wr
	}
}

// SetStderr redirects guest fd 2 to wr. A nil wr leaves the current sink.
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
// A memory64 module's wasi imports arrive widened (see the wasm2go
// wasi-libc port's __wasi_abi_t): every argument of a standard import is a
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
	_wasiEISCONN      int32 = 33
	_wasiEBUSY        int32 = 10
	_wasiEEXIST       int32 = 20
	_wasiEFAULT       int32 = 21
	_wasiEINVAL       int32 = 28
	_wasiEIO          int32 = 29
	_wasiEISDIR       int32 = 31
	_wasiEMFILE       int32 = 33
	_wasiENOENT       int32 = 44
	_wasiENOSPC       int32 = 51
	_wasiENOTDIR      int32 = 54
	_wasiENOTSOCK     int32 = 57
	_wasiENOTSUP      int32 = 58
	_wasiENOSYS       int32 = 52
	_wasiENXIO        int32 = 60
	_wasiEPERM        int32 = 63
	_wasiEPIPE        int32 = 64
	_wasiERANGE       int32 = 68
	_wasiESRCH        int32 = 71
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
	case errors.Is(err, syscall.EAGAIN):
		return _wasiEAGAIN
	case errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrClosedPipe):
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
	if conn != nil {
		err = errors.Join(err, conn.Close())
	}
	if op.listener != nil {
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
	// Every right is granted (the host process is the trust boundary),
	// except that the rights to read and to write say what the descriptor
	// is open for.
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
	} else if rootDirFD(fd) {
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
	root := op == nil && rootDirFD(fd)
	fsys := w.fsys
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
		if fi := w.streamFileInfo(op); fi != nil {
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
	_ = op
	n, errno := readVec(src, bufs)
	abi.putWord(nreadSlice, n)
	return errno
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
// an error other than EOF that left nothing read. Shared by fd_read and
// fd_pread.
func readVec(src io.Reader, bufs [][]byte) (uint64, int32) {
	var total uint64
	for _, buf := range bufs {
		n, err := src.Read(buf)
		total += uint64(n)
		if err != nil && total == 0 && !errors.Is(err, io.EOF) {
			return 0, mapOSError(err)
		}
		if err != nil || n < len(buf) {
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
	n, errno := readVec(io.NewSectionReader(op.f, offset, 1<<63-1), bufs)
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
	n, errno := writeVec(io.NewOffsetWriter(op.f, offset), bufs)
	abi.putWord(nwSlice, n)
	return errno
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
	dst, _ := w.fdDstLocked(fd)
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
	n, errno := writeVec(dst, bufs)
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

// Fd_chmod is a NON-STANDARD host import (module wasip1_posix_extension,
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

// Path_filestat_ext is a NON-STANDARD host import (module
// wasip1_posix_extension, name "path_filestat_ext") backing a
// bridge-provided stat/lstat: WASI's filestat carries neither permission
// bits nor an owner, and its file types have no FIFO, so the bridge merges
// them in from here. The path is preopen-relative; follow selects stat vs
// lstat semantics. Writes the record of wasiFilestatExtSize bytes at
// outPtr, whose mode is the POSIX mode (the file type bits, unixType*, and
// the low twelve mode bits), and returns 0 or a negative errno.
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
// wasip1_posix_extension, name "fd_filestat_ext"), backing a
// bridge-provided fstat. A descriptor that is not a file of the FS backend
// is described as what it is to the guest: a standard stream that is a
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
	w.mu.Lock()
	op := w.openLocked(fd)
	root := op == nil && rootDirFD(fd)
	fsys := w.fsys
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
	root := op == nil && rootDirFD(fd)
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
// name "fd_dup2") backing the bridge's dup2(): to becomes another
// reference to from's descriptor, closing whatever to previously held.
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
	out := make([]os.DirEntry, 0, len(entries)+2)
	out = append(out, dotEntry(op.path, "."), dotEntry(op.path, ".."))
	out = append(out, entries...)
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

// pathOpen is the layout-independent body of path_open: it resolves and
// opens rel, registers the fd, and returns it. Callers own reading the
// path and writing the opened fd at their ABI's pointer width.
func (w *WasiStubs) pathOpen(rel string, dirflags, oflags int32, fsRightsBase int64, fdflags int32) (int32, int32) {
	w.mu.Lock()
	fsys := w.fsys
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
	f, err := fsys.OpenFile(rel, flag, 0o644)
	if err != nil {
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
		f: f, isDir: isDir, path: rel, fdflags: fdflags,
		noRead:  flag&os.O_WRONLY != 0,
		noWrite: flag&(os.O_WRONLY|os.O_RDWR) == 0,
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
	if err := fsys.Mkdir(string(pathSlice), 0o755); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
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
	if err := p.Signal(syscall.Signal(sig)); err != nil {
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
// established later by Sock_connect. domain/type follow the POSIX socket()
// args (AF_INET / SOCK_STREAM); only TCP over IPv4 is supported. Returns the
// new fd, or a negative errno on failure.
func (w *WasiStubs) Sock_socket(m *Module, domain, typ int32) int32 {
	// The bridge's socket() shim has already validated the family against the
	// guest's AF_INET before calling us, so we do not re-check domain here
	// (the guest's AF_INET numeric value need not match the host's).
	_ = domain
	_ = typ
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addFDLocked(&wasiOpen{isSocket: true})
}

// Sock_connect is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "sock_connect") backing a libc connect() wrapped via
// -Wl,--wrap=connect. ipBE carries the IPv4 address in network byte order
// exactly as it sat in sockaddr_in.sin_addr.s_addr (so the low byte is the
// first octet); port is host byte order. It consults the dial whitelist,
// dials via Go's net, and attaches the resulting conn to the socket fd so the
// existing Sock_send / Sock_recv / Fd_close paths drive it. Returns 0 or a
// negative errno.
func (w *WasiStubs) Sock_connect(m *Module, fd, ipBE, port int32) int32 {
	u := uint32(ipBE)
	ip := fmt.Sprintf("%d.%d.%d.%d", u&0xff, (u>>8)&0xff, (u>>16)&0xff, (u>>24)&0xff)
	w.mu.Lock()
	op := w.openLocked(fd)
	hook := w.dialHook
	host := w.resolvedHosts[ip] // "" for a literal-IP dial with no preceding lookup
	w.mu.Unlock()
	if op == nil || !op.isSocket {
		return -_wasiENOTSOCK
	}
	if op.netConn() != nil {
		return -_wasiEISCONN
	}
	p := int(uint16(port))
	if hook != nil && !hook("tcp", host, ip, p) {
		return -_wasiEACCES
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), 30*time.Second)
	if err != nil {
		return -_wasiECONNREFUSED
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
		return mapOSError(cerr)
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
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
	var conn net.Conn
	if op != nil {
		conn = op.netConn()
	}
	if conn == nil {
		return _wasiENOTSOCK
	}
	iovBytes := uint64(uint32(riDataLen)) * 8
	if iovBytes > 0x7fffffff {
		return _wasiEFAULT
	}
	iovecs := w.memSlice(m, riData, int32(iovBytes))
	lenOut := w.memSlice(m, roDataLenPtr, 4)
	// ro_flags is a __wasi_roflags_t — a 16-bit value. wasi-libc packs it
	// immediately before ro_datalen (only 2 bytes apart), so writing 4 bytes
	// here would clobber the low half of ro_datalen and make recv() report 0
	// bytes received even when data arrived.
	flagsOut := w.memSlice(m, roFlagsPtr, 2)
	if iovecs == nil || lenOut == nil || flagsOut == nil {
		return _wasiEFAULT
	}
	var total uint32
	for i := int32(0); i < riDataLen; i++ {
		bufPtr := binary.LittleEndian.Uint32(iovecs[i*8:])
		bufLen := binary.LittleEndian.Uint32(iovecs[i*8+4:])
		buf := w.memSlice(m, int32(bufPtr), int32(bufLen))
		if buf == nil {
			return _wasiEFAULT
		}
		n, err := conn.Read(buf)
		total += uint32(n)
		if err != nil {
			break
		}
	}
	binary.LittleEndian.PutUint16(flagsOut, 0)
	binary.LittleEndian.PutUint32(lenOut, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_send(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int32) int32 {
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
	if conn == nil {
		return _wasiENOTSOCK
	}
	iovBytes := uint64(uint32(siDataLen)) * 8
	if iovBytes > 0x7fffffff {
		return _wasiEFAULT
	}
	iovecs := w.memSlice(m, siData, int32(iovBytes))
	lenOut := w.memSlice(m, soDataLenPtr, 4)
	if iovecs == nil || lenOut == nil {
		return _wasiEFAULT
	}
	var total uint32
	for i := int32(0); i < siDataLen; i++ {
		bufPtr := binary.LittleEndian.Uint32(iovecs[i*8:])
		bufLen := binary.LittleEndian.Uint32(iovecs[i*8+4:])
		buf := w.memSlice(m, int32(bufPtr), int32(bufLen))
		if buf == nil {
			return _wasiEFAULT
		}
		n, err := conn.Write(buf)
		total += uint32(n)
		if err != nil {
			break
		}
	}
	binary.LittleEndian.PutUint32(lenOut, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_shutdown(m *Module, fd, how int32) int32 {
	w.mu.Lock()
	op := w.openLocked(fd)
	w.mu.Unlock()
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
			"WasiExitError": true,
			"wasiOpen":      true,
			"wasiProc":      true,
			"WasiStubs":     true,
			"wasiABI":       true,
			"dotDirEntry":   true,
			"FS":            true,
			"File":          true,
			"osFS":          true,
			"fileStat":      true,
			"MemFS":         true,
			"memFile":       true,
			"memNode":       true,
			"memFileInfo":   true,
			"memDirEntry":   true,
		},
		keepFuncNames: map[string]bool{
			"itoa32":                  true,
			"DefaultWASI":             true,
			"SetPreopenDir":           true,
			"NewMemFS":                true,
			"fileStatOf":              true,
			"unixFileMode":            true,
			"unixModeBits":            true,
			"unixTypeBits":            true,
			"filetimesNeedCurrent":    true,
			"writeFilestatExt":        true,
			"memSplit":                true,
			"memSlice":                true,
			"mapOSError":              true,
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
			"rootDirFD":               true,
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
func (t *translator) emitWasip1Platform(pkg string) map[string][]byte {
	if !t.wasmImportsWasi() {
		return nil
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
