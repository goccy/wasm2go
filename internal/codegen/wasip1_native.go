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
// stdlib (os, time, syscall, net) so no per-platform companion files
// or third-party dependencies are needed.
package codegen

import (
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
	"syscall"
	"time"
)

// Module is the minimal in-package proxy for the generated module type.
// In production, codegen emits a separate Module struct into the user's
// output package; this in-package Module exists so the WasiStubs methods
// below are real, compilable Go (and therefore directly testable). The
// embedded-source path strips the package + import header at emit time
// and lets the generated Module shadow this one.
type Module struct {
	memory []byte
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
	Name() string
}

// osFS is the default FS backend: a thin pass-through to the host filesystem,
// scoped to root (the preopen directory). root "" or "/" means no rewriting.
type osFS struct{ root string }

func (o osFS) join(name string) string {
	if o.root == "" || o.root == "/" {
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
func (o osFS) Rename(a, b string) error                  { return os.Rename(o.join(a), o.join(b)) }
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

// Chtimes implements the optional chtimesFS capability.
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
	parent.children[base] = &memNode{name: base, mode: perm & 0o777, modTime: time.Now(), data: cp}
	return nil
}

func (n *memNode) info() os.FileInfo {
	if n.dir {
		return memFileInfo{name: n.name, mode: os.ModeDir | (n.mode & 0o777), modTime: n.modTime}
	}
	return memFileInfo{name: n.name, size: int64(len(n.data)), mode: n.mode & 0o777, modTime: n.modTime}
}

type memFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi memFileInfo) Name() string       { return fi.name }
func (fi memFileInfo) Size() int64        { return fi.size }
func (fi memFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi memFileInfo) ModTime() time.Time { return fi.modTime }
func (fi memFileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi memFileInfo) Sys() any           { return nil }

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
	conn     net.Conn // guarded by mu; read it through netConn
	listener net.Listener
	isDir    bool
	isSocket bool          // created by Sock_socket, may not yet have a conn
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
	// it (see pollReadable). Reads of this descriptor drain ahead before
	// they touch the stream. aheadEnd is the end of input a probe ran into
	// (io.EOF or a read failure), reported once ahead is drained. Both
	// guarded by mu.
	ahead    []byte
	aheadEnd error
	// turn is the turn at the descriptor's input: whoever reads the stream —
	// a guest's read or a readiness probe, of this instance or of one that
	// shares the entry after Fork — holds it, so input a probe takes is
	// seen by the read that comes next instead of being missed by a read
	// already waiting on the stream, and a probe's read deadline is set and
	// cleared while nobody else uses the stream. A buffered channel so that
	// a probe can give up waiting for it. Made on first use; guarded by mu.
	turn chan struct{}
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
		// A probe that hit end of input leaves one zero-byte read behind;
		// the read after it goes to the stream, as it would have.
		ended := op.aheadEnd != nil
		op.aheadEnd = nil
		return 0, ended
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

// inputTurn returns the channel that holds the turn at op's input.
func (op *wasiOpen) inputTurn() chan struct{} {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.turn == nil {
		op.turn = make(chan struct{}, 1)
	}
	return op.turn
}

// takeInputTurn waits for the turn at op's input, no longer than until (the
// zero time is no limit) and not after stop is closed, and reports whether
// it got it. A turn that is free is taken even when until has passed.
func (op *wasiOpen) takeInputTurn(until time.Time, stop <-chan struct{}) bool {
	turn := op.inputTurn()
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
	case <-expired:
		return false
	case <-stop:
		return false
	}
}

// passInputTurn gives the turn at op's input back.
func (op *wasiOpen) passInputTurn() { <-op.inputTurn() }

// readInput is a guest's read of op's input from src: in its turn, the
// input a probe took comes first, then the stream.
func (op *wasiOpen) readInput(src io.Reader, bufs [][]byte) uint64 {
	op.takeInputTurn(time.Time{}, nil)
	defer op.passInputTurn()
	if n, ok := op.takeAhead(bufs); ok {
		return n
	}
	return readVec(src, bufs)
}

// probeRead is a readiness probe of op's input: in its turn, it reads src
// once — no longer than until (the zero time is no limit), and not after
// stop is closed — and keeps what arrives in ahead. ready reports whether
// the descriptor is readable; refused that src takes no read deadline, so
// it was not read: a stream like that is a regular file, whose read does
// not block.
func (op *wasiOpen) probeRead(src deadlineReader, until time.Time, stop <-chan struct{}) (ready, refused bool) {
	if ready, _ := op.aheadReady(); ready {
		return true, false
	}
	if !op.takeInputTurn(until, stop) {
		ready, _ := op.aheadReady()
		return ready, false
	}
	defer op.passInputTurn()
	// Whoever had the turn before may have left input behind.
	if ready, _ := op.aheadReady(); ready {
		return true, false
	}
	select {
	case <-stop:
		// Another descriptor is ready: this one only gets the time it takes
		// to look.
		if look := time.Now().Add(pollProbeGrace); until.IsZero() || look.Before(until) {
			until = look
		}
	default:
	}
	if err := src.SetReadDeadline(until); err != nil {
		return false, true
	}
	// No deadline is left behind: later reads of the stream must block.
	defer src.SetReadDeadline(time.Time{})
	if stop != nil {
		// stop ends the read in progress; the watcher is gone before the
		// deadline is cleared.
		read, watched := make(chan struct{}), make(chan struct{})
		defer func() { <-watched }()
		defer close(read)
		go func() {
			defer close(watched)
			select {
			case <-stop:
				_ = src.SetReadDeadline(time.Now())
			case <-read:
			}
		}()
	}
	buf := make([]byte, 32<<10)
	n, err := src.Read(buf)
	op.mu.Lock()
	defer op.mu.Unlock()
	op.ahead = append(op.ahead, buf[:n]...)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		op.aheadEnd = err
	}
	return len(op.ahead) > 0 || op.aheadEnd != nil, false
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
	// when the embedder gave none. Guarded by the owning WasiStubs.mu.
	kill func(sig int32) error
}

// wasiPIDs hands out pid tokens. One allocator is shared by every WasiStubs
// of a fork family, each of which has its own lock, hence the separate mutex.
type wasiPIDs struct {
	mu   sync.Mutex
	next int32
}

// alloc returns the next unused pid token.
func (p *wasiPIDs) alloc() int32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	pid := p.next
	p.next++
	return pid
}

// wasiFirstPID is the first pid token a fresh instance hands out.
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
//     filesystem backend, clock origin and every hook;
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
// (dup, Fork) stays open until its last reference goes. It lets an embedder
// dispose of the host state of a finished instance, typically a forked child.
// Calling it again is a no-op. The close errors are joined.
func (w *WasiStubs) CloseAll() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeFromLocked(0)
}

// closeFromLocked closes every fd numbered lowFd or higher, lowest first, as
// fd_close would, and joins the close errors in that order. Caller holds
// w.mu.
func (w *WasiStubs) closeFromLocked(lowFd int32) error {
	fds := w.fdsLocked()
	var doomed []int32
	for fd := range fds {
		if fd >= lowFd {
			doomed = append(doomed, fd)
		}
	}
	sort.Slice(doomed, func(i, j int) bool { return doomed[i] < doomed[j] })
	var err error
	for _, fd := range doomed {
		err = errors.Join(err, closeWasiOpen(fds[fd]))
		delete(fds, fd)
	}
	return err
}

// Fd_closefrom is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_closefrom") backing closefrom(): it closes every fd numbered
// lowFd or higher, each as fd_close would. A guest emulating exec needs it:
// the process it started has its own descriptors, and the fds this instance
// still holds — close-on-exec ones included — must go, or a peer waiting for
// end-of-file on one of them waits for as long as the command runs. Returns
// 0, or a positive errno for the lowest fd whose close failed (every fd in
// range is closed regardless).
func (w *WasiStubs) Fd_closefrom(m *Module, lowFd int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.closeFromLocked(lowFd); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

// wasiPreopenFD is the fd of the preopened root directory. It is not a
// table entry and is never handed out for a new descriptor.
const wasiPreopenFD int32 = 3

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

// fdEntry returns the entry of fd, or nil when fd is not open.
func (w *WasiStubs) fdEntry(fd int32) *wasiOpen {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fdsLocked()[fd]
}

// addFDLocked stores op under the lowest fd number not in use, as POSIX
// requires of open, pipe, dup, socket and accept, and returns that number.
// Caller holds w.mu.
func (w *WasiStubs) addFDLocked(op *wasiOpen) int32 {
	fds := w.fdsLocked()
	fd := int32(0)
	for {
		if _, used := fds[fd]; !used && fd != wasiPreopenFD {
			break
		}
		fd++
	}
	fds[fd] = op
	return fd
}

// pidsLocked returns the pid allocator, creating it on first use. Caller
// holds w.mu.
func (w *WasiStubs) pidsLocked() *wasiPIDs {
	if w.pids == nil {
		w.pids = &wasiPIDs{next: wasiFirstPID}
	}
	return w.pids
}

// addProcLocked registers proc under a fresh pid token. Caller holds w.mu.
func (w *WasiStubs) addProcLocked(proc *wasiProc) int32 {
	if w.procs == nil {
		w.procs = map[int32]*wasiProc{}
	}
	pid := w.pidsLocked().alloc()
	w.procs[pid] = proc
	return pid
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
// ptr (0) yields "". ok is false on an out-of-bounds or unterminated read.
func (w *WasiStubs) readCStr(m *Module, ptr int32) (s string, ok bool) {
	if ptr == 0 {
		return "", true
	}
	mem := m.memory
	lo := uint64(uint32(ptr))
	if lo > uint64(len(mem)) {
		return "", false
	}
	rest := mem[lo:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			return string(rest[:i]), true
		}
	}
	return "", false
}

// readCStrArray reads a NULL-terminated array of C-string pointers (a char**)
// at ptr. A nil ptr (0) yields a nil slice. ok is false on a bad read.
func (w *WasiStubs) readCStrArray(m *Module, ptr int32) (out []string, ok bool) {
	if ptr == 0 {
		return nil, true
	}
	for off := ptr; ; off += 4 {
		b := w.memSlice(m, off, 4)
		if b == nil {
			return nil, false
		}
		p := int32(binary.LittleEndian.Uint32(b))
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
// instance's own stream. The new pid token is written at pidOutPtr. Returns
// 0 or a negative errno.
func (w *WasiStubs) Proc_spawn(m *Module, pathPtr, argvPtr, envpPtr, stdinFd, stdoutFd, stderrFd, cwdPtr, pidOutPtr int32) int32 {
	path, ok := w.readCStr(m, pathPtr)
	if !ok || path == "" {
		return -_wasiEINVAL
	}
	argv, ok := w.readCStrArray(m, argvPtr)
	if !ok {
		return -_wasiEFAULT
	}
	env, ok := w.readCStrArray(m, envpPtr)
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
	if cwd != "" {
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
	if err := cmd.Start(); err != nil {
		return -mapExecError(err)
	}

	proc := &wasiProc{cmd: cmd, done: make(chan struct{})}
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

	w.mu.Lock()
	pid := w.addProcLocked(proc)
	w.mu.Unlock()

	binary.LittleEndian.PutUint32(out, uint32(pid))
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
	out := w.memSlice(m, fdsOutPtr, 8)
	if out == nil {
		return -_wasiEFAULT
	}
	r, wr, err := os.Pipe()
	if err != nil {
		return -mapOSError(err)
	}
	w.mu.Lock()
	rfd := w.addFDLocked(&wasiOpen{f: r})
	wfd := w.addFDLocked(&wasiOpen{f: wr})
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

// Proc_wait_any is a NON-STANDARD host import (name "proc_wait_any") backing
// the bridge's wait() / waitpid(-1): it waits for ANY process of this
// instance — spawned by Proc_spawn or run by the embedder (NewProc,
// Proc_fork) — to finish, removes it from the process table, and writes its
// pid token at pidOutPtr and its POSIX wait status at statusOutPtr. When
// several have finished, the one with the lowest pid is reported. options is
// the waitpid() options mask; with bit 0 (WNOHANG) the call does not block.
// Returns 0, or a negative errno: ECHILD when the instance has no process at
// all, EAGAIN when WNOHANG is set and none of them has finished yet.
func (w *WasiStubs) Proc_wait_any(m *Module, options, pidOutPtr, statusOutPtr int32) int32 {
	pidOut := w.memSlice(m, pidOutPtr, 4)
	statusOut := w.memSlice(m, statusOutPtr, 4)
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
			delete(w.procs, pid)
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
	out := w.memSlice(m, pidOutPtr, 4)
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
	proc := &wasiProc{done: make(chan struct{})}
	w.mu.Lock()
	pid := w.addProcLocked(proc)
	w.mu.Unlock()
	kill, err := hook(m, child, pid, w.procExitFunc(proc))
	if err != nil {
		// The child never ran, so every descriptor it holds is one it
		// shares with w: this drops the references and normally closes
		// nothing.
		closeErr := child.CloseAll()
		w.mu.Lock()
		delete(w.procs, pid)
		w.mu.Unlock()
		if closeErr != nil {
			return -mapOSError(closeErr)
		}
		return -_wasiEAGAIN
	}
	w.mu.Lock()
	proc.kill = kill
	w.mu.Unlock()
	binary.LittleEndian.PutUint32(out, uint32(pid))
	return _wasiESUCCESS
}

// Proc_kill is a NON-STANDARD host import (name "proc_kill") backing the
// bridge's kill() for a pid token of this instance. sig is the POSIX signal
// number; 0 only probes that the process exists.
//
//   - A host process (Proc_spawn) receives the signal through the OS.
//   - An embedder-run process (NewProc, Proc_fork) receives it through the
//     kill function the embedder registered. Without one the process exists
//     but cannot be signalled, which is reported as EPERM.
//   - A process that has finished but has not been waited for yet is a
//     zombie: as with kill(2), signalling it succeeds and does nothing.
//
// Returns 0, or a negative errno: ESRCH for an unknown pid, EINVAL for a
// negative signal number or one the host rejects, EPERM when the signal
// could not be delivered.
func (w *WasiStubs) Proc_kill(m *Module, pid, sig int32) int32 {
	if sig < 0 {
		return -_wasiEINVAL
	}
	w.mu.Lock()
	proc := w.procs[pid]
	var kill func(sig int32) error
	if proc != nil {
		kill = proc.kill
	}
	w.mu.Unlock()
	if proc == nil {
		return -_wasiESRCH
	}
	select {
	case <-proc.done:
		return _wasiESUCCESS
	default:
	}
	if proc.cmd != nil {
		// Signal 0 is passed through as well: the OS answers the probe.
		err := proc.cmd.Process.Signal(syscall.Signal(sig))
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

// SetStdin redirects the instance's stdin to r: guest fd 0 and its dups,
// for as long as the guest has not closed or replaced them. A nil r leaves
// the current source.
// Use this to feed input() / sys.stdin from an in-process io.Reader instead
// of the host process stdin.
func (w *WasiStubs) SetStdin(r io.Reader) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r == nil {
		return
	}
	w.stdin = r
	// Input a readiness probe kept on an entry is the old stream's, and the
	// entry may be shared with an instance this one was forked from or
	// into, whose stdin has not changed: the fds referring to stdin get one
	// new entry, shared among them as the old one was.
	var fresh *wasiOpen
	fds := w.fdsLocked()
	for fd, op := range fds {
		if op.stdio != 1 {
			continue
		}
		_ = closeWasiOpen(op) // a stream entry holds no descriptor
		if fresh == nil {
			fresh = &wasiOpen{stdio: 1}
		} else {
			fresh.addRef()
		}
		fds[fd] = fresh
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

// memSlice returns m.memory[off : off+n]. Callers must hold any locks
// they need on the wasm side; WasiStubs.mu is independent. Returns an
// empty slice on out-of-range (the wasi function should then return
// EFAULT / EINVAL).
func (w *WasiStubs) memSlice(m *Module, off, n int32) []byte {
	mem := m.memory
	lo := uint64(uint32(off))
	hi := lo + uint64(uint32(n))
	if hi > uint64(len(mem)) {
		return nil
	}
	return mem[lo:hi]
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
	_wasiENOENT       int32 = 44
	_wasiENOTDIR      int32 = 54
	_wasiENOTSOCK     int32 = 57
	_wasiENOTSUP      int32 = 58
	_wasiENOSYS       int32 = 52
	_wasiEPERM        int32 = 63
	_wasiEPIPE        int32 = 64
	_wasiESRCH        int32 = 71
)

// mapOSError turns an os/filesystem error into a wasi errno. Used by the
// path-based syscalls so any os.PathError surfaces as the appropriate
// guest-visible code instead of a coarse EIO.
func mapOSError(err error) int32 {
	if err == nil {
		return _wasiESUCCESS
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return _wasiENOENT
	case errors.Is(err, fs.ErrExist):
		return _wasiEEXIST
	case errors.Is(err, fs.ErrPermission):
		return _wasiEACCES
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
	}
	return _wasiEIO
}

// totalBytes sums len(s)+1 over s in a uint64 and reports whether the
// total fits in an int32 (i.e. is representable as a wasm-side i32
// length). Callers route the result through memSlice and an OOB on a
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
	w.mu.Lock()
	defer w.mu.Unlock()
	// Validate the argv pointer array first: len(args) * 4 bytes of
	// uint32 entries at argv. Multiply in uint64 so a pathological arg
	// count cannot wrap to a negative int32 length.
	argvBytes64 := uint64(len(w.args)) * 4
	if argvBytes64 > 0x7fffffff {
		return _wasiEFAULT
	}
	argvSlice := w.memSlice(m, argv, int32(argvBytes64))
	if argvSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.args)
	if !ok {
		return _wasiEFAULT
	}
	argvBufSlice := w.memSlice(m, argvBuf, total)
	if argvBufSlice == nil {
		return _wasiEFAULT
	}
	bufOff := uint32(0)
	for i, a := range w.args {
		binary.LittleEndian.PutUint32(argvSlice[i*4:], uint32(argvBuf)+bufOff)
		n := copy(argvBufSlice[bufOff:], a)
		if n < len(a) {
			return _wasiEFAULT
		}
		bufOff += uint32(n)
		argvBufSlice[bufOff] = 0
		bufOff++
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Args_sizes_get(m *Module, argcPtr, argvBufLenPtr int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	argcSlice := w.memSlice(m, argcPtr, 4)
	bufLenSlice := w.memSlice(m, argvBufLenPtr, 4)
	if argcSlice == nil || bufLenSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.args)
	if !ok {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint32(argcSlice, uint32(len(w.args)))
	binary.LittleEndian.PutUint32(bufLenSlice, uint32(total))
	return _wasiESUCCESS
}

func (w *WasiStubs) Environ_get(m *Module, envv, envBuf int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	envvBytes64 := uint64(len(w.env)) * 4
	if envvBytes64 > 0x7fffffff {
		return _wasiEFAULT
	}
	envvSlice := w.memSlice(m, envv, int32(envvBytes64))
	if envvSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.env)
	if !ok {
		return _wasiEFAULT
	}
	envBufSlice := w.memSlice(m, envBuf, total)
	if envBufSlice == nil {
		return _wasiEFAULT
	}
	bufOff := uint32(0)
	for i, e := range w.env {
		binary.LittleEndian.PutUint32(envvSlice[i*4:], uint32(envBuf)+bufOff)
		n := copy(envBufSlice[bufOff:], e)
		if n < len(e) {
			return _wasiEFAULT
		}
		bufOff += uint32(n)
		envBufSlice[bufOff] = 0
		bufOff++
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Environ_sizes_get(m *Module, envcPtr, envBufLenPtr int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	envcSlice := w.memSlice(m, envcPtr, 4)
	bufLenSlice := w.memSlice(m, envBufLenPtr, 4)
	if envcSlice == nil || bufLenSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.env)
	if !ok {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint32(envcSlice, uint32(len(w.env)))
	binary.LittleEndian.PutUint32(bufLenSlice, uint32(total))
	return _wasiESUCCESS
}

func (w *WasiStubs) Clock_res_get(m *Module, clockID int32, resPtr int32) int32 {
	// Report 1ns resolution for both realtime and monotonic — Go's
	// time.Now() resolution is OS-dependent but always claims ns
	// precision in its API.
	out := w.memSlice(m, resPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint64(out, 1)
	return _wasiESUCCESS
}

func (w *WasiStubs) Clock_time_get(m *Module, clockID int32, precision int64, timePtr int32) int32 {
	out := w.memSlice(m, timePtr, 8)
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
	op := w.fdsLocked()[fd]
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

func (w *WasiStubs) Fd_fdstat_get(m *Module, fd, ptr int32) int32 {
	// fdstat is 24 bytes wide (filetype u8 + flags u16 + rights base/inherit u64+u64).
	out := w.memSlice(m, ptr, 24)
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
	if op := w.fdsLocked()[fd]; op != nil {
		op.mu.Lock()
		if op.stdio != 0 {
			ftype = 2 // a standard stream is a character device
		} else if op.isDir {
			ftype = 3
		} else if op.conn != nil {
			ftype = 6 // socket_stream
		} else if op.listener != nil {
			ftype = 6
		}
		fdflags = uint16(op.fdflags)
		op.mu.Unlock()
	} else if fd == wasiPreopenFD {
		ftype = 3 // preopen "/"
	} else {
		return _wasiEBADF
	}
	out[0] = ftype
	out[1] = 0
	binary.LittleEndian.PutUint16(out[2:], fdflags)
	// Grant all rights — we don't enforce per-fd rights.
	binary.LittleEndian.PutUint64(out[8:], ^uint64(0))
	binary.LittleEndian.PutUint64(out[16:], ^uint64(0))
	return _wasiESUCCESS
}

// Fd_fdstat_set_flags maps WASI fdflags to OS file-status flags via the
// per-platform Fcntl wrapper. The flags are also cached on the wasiOpen
// so a subsequent Fd_fdstat_get reflects what the guest set. Standard
// streams store the requested flags but otherwise no-op; sockets/listeners take
// only the cache update because Go's net layer manages blocking mode
// internally.
func (w *WasiStubs) Fd_fdstat_set_flags(m *Module, fd, flags int32) int32 {
	op := w.fdEntry(fd)
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

// Fd_fdstat_set_rights stores the requested rights on the wasiOpen but
// does not enforce them — the host process is the trust boundary. WASI
// programs that succeed with maximal rights (per Fd_fdstat_get) get the
// same ESUCCESS here.
func (w *WasiStubs) Fd_fdstat_set_rights(m *Module, fd int32, rightsBase, rightsInherit int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fdsLocked()[fd] == nil {
		return _wasiEBADF
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_filestat_get(m *Module, fd, ptr int32) int32 {
	// filestat is 64 bytes wide.
	out := w.memSlice(m, ptr, 64)
	if out == nil {
		return _wasiEFAULT
	}
	op := w.fdEntry(fd)
	if op == nil && fd != wasiPreopenFD {
		return _wasiEBADF
	}
	if op == nil || op.f == nil {
		// Synthesise a minimal stat for a standard stream, the preopen
		// or a socket.
		for i := range out {
			out[i] = 0
		}
		// Stay consistent with Fd_fdstat_get's filetype values: a
		// standard stream is a character device (2); the preopen
		// directory is a directory (3); everything else is left as
		// "unknown" (0).
		switch {
		case op == nil:
			out[16] = 3
		case op.stdio != 0:
			out[16] = 2
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
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	if err := op.f.Truncate(size); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_filestat_set_times(m *Module, fd int32, atim, mtim int64, fstFlags int32) int32 {
	// fstFlags: 0x1 ATIME, 0x2 ATIME_NOW, 0x4 MTIME, 0x8 MTIME_NOW.
	// atim/mtim are wasi `timestamp` (u64 nanoseconds) — a single i64 each
	// at the wasm ABI, matching the import signature the transpiler derives.
	w.mu.Lock()
	op := w.fdsLocked()[fd]
	fsys := w.fsys
	w.mu.Unlock()
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	atime, mtime, err := resolveFiletimes(uint64(atim), uint64(mtim), fstFlags, op.f)
	if err != nil {
		return mapOSError(err)
	}
	// Applied only when the backend tracks timestamps (osFS does); a no-op
	// success otherwise so timestamp-less backends don't fail the guest.
	if cf, ok := fsys.(chtimesFS); ok {
		if err := cf.Chtimes(op.path, atime, mtime); err != nil {
			return mapOSError(err)
		}
	}
	return _wasiESUCCESS
}

// combine64 reconstructs an unsigned 64-bit time value from a pair of
// 32-bit args. WASI signature uses two i32s for the nanosecond timestamp
// in fd_filestat_set_times.
func combine64(hi, lo int32) uint64 {
	return (uint64(uint32(hi)) << 32) | uint64(uint32(lo))
}

// resolveFiletimes decides the (atime, mtime) pair to apply given a
// fstFlags bitmask. Bits 0x2 (ATIME_NOW) and 0x8 (MTIME_NOW) override the
// explicit values with time.Now(). Unset ATIME/MTIME bits keep the
// existing on-disk time, so f.Stat must succeed when those bits are
// unset; the error is returned so the caller can surface it as a wasi
// errno rather than silently writing epoch.
func resolveFiletimes(atimNs, mtimNs uint64, fstFlags int32, f File) (time.Time, time.Time, error) {
	now := time.Now()
	var atime, mtime time.Time
	// We only need the current on-disk times when at least one of
	// ATIME or MTIME is going to be preserved (its bit is unset).
	needCurrent := fstFlags&(0x1|0x2) == 0 || fstFlags&(0x4|0x8) == 0
	if needCurrent {
		st, err := f.Stat()
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		atime = st.ModTime()
		mtime = st.ModTime()
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
	return atime, mtime, nil
}

func (w *WasiStubs) Fd_prestat_get(m *Module, fd, ptr int32) int32 {
	// Only fd 3 is reserved as the preopen "/" directory. Returning EBADF
	// for everything else is the wasi-libc convention used to terminate
	// the directory-enumeration loop in __wasilibc_register_preopened_fd.
	if fd != 3 {
		return _wasiEBADF
	}
	// prestat is 8 bytes wide: tag u8 + reserved u8[3] + len u32.
	out := w.memSlice(m, ptr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = 0 // preopen tag = directory
	binary.LittleEndian.PutUint32(out[4:], 1)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_prestat_dir_name(m *Module, fd, buf, buflen int32) int32 {
	if fd != 3 {
		return _wasiEBADF
	}
	if buflen < 1 {
		return _wasiESUCCESS
	}
	out := w.memSlice(m, buf, buflen)
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = '/'
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_read(m *Module, fd, iovs, iovsLen, nreadPtr int32) int32 {
	w.mu.Lock()
	src, op := w.fdSrcLocked(fd)
	w.mu.Unlock()
	if src == nil {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices(m, iovs, iovsLen)
	nreadSlice := w.memSlice(m, nreadPtr, 4)
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint32(nreadSlice, uint32(op.readInput(src, bufs)))
	return _wasiESUCCESS
}

// iovecSlices resolves a wasm32 ciovec/iovec array ({u32 ptr, u32 len}
// entries at iovs) into the backing memory windows. Every entry is
// validated before any I/O happens, so a bad iovec faults the whole
// call instead of after a partial transfer.
func (w *WasiStubs) iovecSlices(m *Module, iovs, iovsLen int32) ([][]byte, bool) {
	// Compute the array size in uint64 so a pathological iovsLen can't
	// wrap to negative.
	iovBytes := uint64(uint32(iovsLen)) * 8
	if iovBytes > 0x7fffffff {
		return nil, false
	}
	iovecs := w.memSlice(m, iovs, int32(iovBytes))
	if iovecs == nil {
		return nil, false
	}
	bufs := make([][]byte, 0, iovsLen)
	for i := int32(0); i < iovsLen; i++ {
		bufPtr := binary.LittleEndian.Uint32(iovecs[i*8:])
		bufLen := binary.LittleEndian.Uint32(iovecs[i*8+4:])
		buf := w.memSlice(m, int32(bufPtr), int32(bufLen))
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
	var total uint64
	for _, buf := range bufs {
		n, err := src.Read(buf)
		// A read deadline on a stream is only ever set by a readiness
		// probe, possibly of another instance sharing the descriptor
		// (pollReadable); it is not this read's and is cleared as soon as
		// that probe ends.
		for n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			runtime.Gosched()
			n, err = src.Read(buf)
		}
		total += uint64(n)
		if err != nil || n < len(buf) {
			break
		}
	}
	return total
}

// writeVec drains bufs into dst in order, stopping at the first failed
// write; returns the bytes written. Shared like readVec.
func writeVec(dst io.Writer, bufs [][]byte) uint64 {
	var total uint64
	for _, buf := range bufs {
		n, err := dst.Write(buf)
		total += uint64(n)
		if err != nil {
			break
		}
	}
	return total
}

// fdSrcLocked returns the io.Reader for fd and (when applicable) the
// wasiOpen it came from, or nil if fd is invalid. Caller must hold w.mu.
func (w *WasiStubs) fdSrcLocked(fd int32) (io.Reader, *wasiOpen) {
	// The table decides what an fd is, fd 0 included: an entry for the
	// instance's stdin reads from the stream configured right now.
	op := w.fdsLocked()[fd]
	if op == nil {
		return nil, nil
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
	op := w.fdsLocked()[fd]
	if op == nil {
		return nil, nil
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
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	iovBytes := uint64(uint32(iovsLen)) * 8
	if iovBytes > 0x7fffffff {
		return _wasiEFAULT
	}
	iovecs := w.memSlice(m, iovs, int32(iovBytes))
	nreadSlice := w.memSlice(m, nreadPtr, 4)
	if iovecs == nil || nreadSlice == nil {
		return _wasiEFAULT
	}
	var total uint32
	curOff := offset
	for i := int32(0); i < iovsLen; i++ {
		bufPtr := binary.LittleEndian.Uint32(iovecs[i*8:])
		bufLen := binary.LittleEndian.Uint32(iovecs[i*8+4:])
		buf := w.memSlice(m, int32(bufPtr), int32(bufLen))
		if buf == nil {
			return _wasiEFAULT
		}
		n, err := op.f.ReadAt(buf, curOff)
		total += uint32(n)
		curOff += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		if n < int(bufLen) {
			break
		}
	}
	binary.LittleEndian.PutUint32(nreadSlice, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_pwrite(m *Module, fd, iovs, iovsLen int32, offset int64, nwrittenPtr int32) int32 {
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	iovBytes := uint64(uint32(iovsLen)) * 8
	if iovBytes > 0x7fffffff {
		return _wasiEFAULT
	}
	iovecs := w.memSlice(m, iovs, int32(iovBytes))
	nwSlice := w.memSlice(m, nwrittenPtr, 4)
	if iovecs == nil || nwSlice == nil {
		return _wasiEFAULT
	}
	var total uint32
	curOff := offset
	for i := int32(0); i < iovsLen; i++ {
		bufPtr := binary.LittleEndian.Uint32(iovecs[i*8:])
		bufLen := binary.LittleEndian.Uint32(iovecs[i*8+4:])
		buf := w.memSlice(m, int32(bufPtr), int32(bufLen))
		if buf == nil {
			return _wasiEFAULT
		}
		n, err := op.f.WriteAt(buf, curOff)
		total += uint32(n)
		curOff += int64(n)
		if err != nil {
			break
		}
	}
	binary.LittleEndian.PutUint32(nwSlice, total)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_seek(m *Module, fd int32, offset int64, whence, newOffPtr int32) int32 {
	out := w.memSlice(m, newOffPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	n, errno := w.fdSeek(fd, offset, int(whence))
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint64(out, uint64(n))
	return _wasiESUCCESS
}

// fdSeek is the layout-independent body of fd_seek, shared by the
// wasm32 and wasm64 bindings.
func (w *WasiStubs) fdSeek(fd int32, offset int64, whence int) (int64, int32) {
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return 0, _wasiEBADF
	}
	n, err := op.f.Seek(offset, whence)
	if err != nil {
		return 0, _wasiEINVAL
	}
	return n, _wasiESUCCESS
}

func (w *WasiStubs) Fd_tell(m *Module, fd, offsetPtr int32) int32 {
	out := w.memSlice(m, offsetPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	op := w.fdEntry(fd)
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
	w.mu.Lock()
	dst, _ := w.fdDstLocked(fd)
	w.mu.Unlock()
	bufs, ok := w.iovecSlices(m, iovs, iovsLen)
	nwrittenSlice := w.memSlice(m, nwrittenPtr, 4)
	if !ok || nwrittenSlice == nil {
		return _wasiEFAULT
	}
	if dst == nil {
		binary.LittleEndian.PutUint32(nwrittenSlice, 0)
		return _wasiEBADF
	}
	binary.LittleEndian.PutUint32(nwrittenSlice, uint32(writeVec(dst, bufs)))
	return _wasiESUCCESS
}
func (w *WasiStubs) Fd_sync(m *Module, fd int32) int32 {
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	if err := op.f.Sync(); err != nil {
		return mapOSError(err)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_datasync(m *Module, fd int32) int32 {
	op := w.fdEntry(fd)
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

func (w *WasiStubs) Fd_advise(m *Module, fd int32, offset, length int64, advice int32) int32 {
	op := w.fdEntry(fd)
	if op == nil || op.f == nil {
		return _wasiEBADF
	}
	// posix_fadvise is a hint; the spec lets implementations no-op it.
	_, _, _ = offset, length, advice
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_allocate(m *Module, fd int32, offset, length int64) int32 {
	op := w.fdEntry(fd)
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

// Path_chmod is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "path_chmod") backing a bridge-provided chmod(): WASI preview1 has
// no way to change file modes. The path at (pathPtr,pathLen) is
// preopen-relative, like path_open's. Backends without chmod support
// (MemFS keeps no modes) report ENOSYS. Returns 0 or a negative errno.
func (w *WasiStubs) Path_chmod(m *Module, pathPtr, pathLen, mode int32) int32 {
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	if pathSlice == nil {
		return -_wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	ch, ok := fsys.(interface {
		Chmod(string, os.FileMode) error
	})
	if !ok {
		return -_wasiENOSYS
	}
	if err := ch.Chmod(string(pathSlice), os.FileMode(uint32(mode)&0o7777)); err != nil {
		return -mapOSError(err)
	}
	return _wasiESUCCESS
}

// Path_filestat_mode is a NON-STANDARD host import (module
// wasi_snapshot_preview1, name "path_filestat_mode") backing a
// bridge-provided stat/lstat: WASI's filestat carries no permission
// bits, so the bridge merges the real mode in from here. The path is
// preopen-relative; follow selects stat vs lstat semantics. Writes the
// unix permission bits at modeOutPtr; returns 0 or a negative errno.
func (w *WasiStubs) Path_filestat_mode(m *Module, pathPtr, pathLen, follow, modeOutPtr int32) int32 {
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	out := w.memSlice(m, modeOutPtr, 4)
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
	mode := fi.Mode()
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
	binary.LittleEndian.PutUint32(out, bits)
	return _wasiESUCCESS
}

// Fd_dup is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dup") backing the bridge's dup(): the new fd shares the same
// open descriptor (offset included), and the underlying file closes only
// when the last sharing fd does. Writes the new fd at outPtr.
func (w *WasiStubs) Fd_dup(m *Module, fd, outPtr int32) int32 {
	out := w.memSlice(m, outPtr, 4)
	if out == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	op := w.fdsLocked()[fd]
	if op == nil {
		return _wasiEBADF
	}
	nfd := w.addFDLocked(op)
	op.addRef()
	binary.LittleEndian.PutUint32(out, uint32(nfd))
	return _wasiESUCCESS
}

// Fd_dup2 is a NON-STANDARD host import (module wasi_snapshot_preview1,
// name "fd_dup2") backing the bridge's dup2(): to becomes another
// reference to from's descriptor, closing whatever to previously held.
func (w *WasiStubs) Fd_dup2(m *Module, from, to int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := w.fdsLocked()[from]
	if src == nil {
		return _wasiEBADF
	}
	if from == to {
		return _wasiESUCCESS
	}
	var closeErr error
	if dst := w.fdsLocked()[to]; dst != nil {
		if dst == src {
			return _wasiESUCCESS
		}
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	src.addRef()
	if closeErr != nil {
		return mapOSError(closeErr)
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_renumber(m *Module, from, to int32) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if from == to {
		// Renumbering an fd onto itself is a no-op. We must NOT close
		// the entry at "to" here — that would destroy the live fd the
		// caller is trying to keep.
		if _, ok := w.fdsLocked()[from]; ok {
			return _wasiESUCCESS
		}
		return _wasiEBADF
	}
	src, ok := w.fdsLocked()[from]
	if !ok {
		return _wasiEBADF
	}
	var closeErr error
	if dst, ok2 := w.fdsLocked()[to]; ok2 {
		closeErr = closeWasiOpen(dst)
	}
	w.fdsLocked()[to] = src
	delete(w.fdsLocked(), from)
	if closeErr != nil {
		return mapOSError(closeErr)
	}
	return _wasiESUCCESS
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
	bufSlice := w.memSlice(m, buf, buflen)
	bufusedSlice := w.memSlice(m, bufusedPtr, 4)
	if bufSlice == nil || bufusedSlice == nil {
		return _wasiEFAULT
	}
	written, errno := w.fdReaddir(fd, bufSlice, cookie)
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint32(bufusedSlice, uint32(written))
	return _wasiESUCCESS
}

// fdReaddir is the layout-independent body of fd_readdir: it packs
// dirents into bufSlice starting at the cookie'th entry and returns the
// byte count used. The dirent wire format has no pointer-width fields,
// so wasm32 and wasm64 share it; only the bufused out-pointer differs.
func (w *WasiStubs) fdReaddir(fd int32, bufSlice []byte, cookie int64) (int, int32) {
	op := w.fdEntry(fd)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	outSlice := w.memSlice(m, openedFdPtr, 4)
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
	w.mu.Lock()
	fd := w.addFDLocked(&wasiOpen{f: f, isDir: isDir, path: rel, fdflags: fdflags})
	w.mu.Unlock()
	return fd, _wasiESUCCESS
}

func (w *WasiStubs) Path_create_directory(m *Module, dirFd, pathPtr, pathLen int32) int32 {
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
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
	if oldFd != 3 || newFd != 3 {
		return _wasiEBADF
	}
	oldSlice := w.memSlice(m, oldPathPtr, oldPathLen)
	newSlice := w.memSlice(m, newPathPtr, newPathLen)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	out := w.memSlice(m, outPtr, 64)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	if pathSlice == nil {
		return _wasiEFAULT
	}
	w.mu.Lock()
	fsys := w.fsys
	w.mu.Unlock()
	rel := string(pathSlice)
	follow := flags&0x1 != 0
	now := time.Now()
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
	atime := st.ModTime()
	mtime := st.ModTime()
	if fstFlags&0x1 != 0 {
		atime = time.Unix(0, int64(atim))
	}
	if fstFlags&0x2 != 0 {
		atime = now
	}
	if fstFlags&0x4 != 0 {
		mtime = time.Unix(0, int64(mtim))
	}
	if fstFlags&0x8 != 0 {
		mtime = now
	}
	// Times are only applied when the backend supports them (osFS does). A
	// backend without timestamps (e.g. a minimal in-memory FS) treats this as
	// a successful no-op rather than failing the guest.
	if cf, ok := fsys.(chtimesFS); ok {
		if err := cf.Chtimes(rel, atime, mtime); err != nil {
			return mapOSError(err)
		}
	}
	return _wasiESUCCESS
}

// chtimesFS is an optional FS capability for backends that track timestamps.
type chtimesFS interface {
	Chtimes(name string, atime, mtime time.Time) error
}

func (o osFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(o.join(name), atime, mtime)
}

func (w *WasiStubs) Path_link(m *Module, oldFd, oldFlags, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen int32) int32 {
	if oldFd != 3 || newFd != 3 {
		return _wasiEBADF
	}
	oldSlice := w.memSlice(m, oldPathPtr, oldPathLen)
	newSlice := w.memSlice(m, newPathPtr, newPathLen)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	targetSlice := w.memSlice(m, targetPtr, targetLen)
	linkSlice := w.memSlice(m, linkPathPtr, linkPathLen)
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
	if dirFd != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice(m, pathPtr, pathLen)
	bufSlice := w.memSlice(m, buf, buflen)
	bufused := w.memSlice(m, bufusedPtr, 4)
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
	binary.LittleEndian.PutUint32(bufused, uint32(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Random_get(m *Module, buf, bufLen int32) int32 {
	slice := w.memSlice(m, buf, bufLen)
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

	// Decide which fd subscriptions are ready. A descriptor whose read
	// cannot block — a regular file, anything written to, a listener, a
	// stream this host cannot probe — is ready at once, as it always was.
	// A stream whose read CAN block (pipe, socket, terminal) is ready only
	// when input is actually there: reporting it ready regardless sends a
	// guest multiplexing two pipes into a blocking read of the idle one
	// while the busy one fills up and its writer stalls.
	ready := make([]bool, len(fdEvents))
	errnos := make([]int32, len(fdEvents))
	ops := make([]*wasiOpen, len(fdEvents))
	var probes []pollProbe
	probeOf := map[*wasiOpen]int{}
	probeIndex := make([]int, len(fdEvents))
	anyReady := false
	for i, ev := range fdEvents {
		probeIndex[i] = -1
		w.mu.Lock()
		src, op := w.fdSrcLocked(ev.fd)
		w.mu.Unlock()
		ops[i] = op
		if op == nil {
			errnos[i] = _wasiEBADF
			ready[i], anyReady = true, true
			continue
		}
		stream, bounded := src.(deadlineReader)
		if !ev.isRead || !bounded {
			ready[i], anyReady = true, true
			continue
		}
		if pending, _ := op.aheadReady(); pending {
			ready[i], anyReady = true, true
			continue
		}
		if at, seen := probeOf[op]; seen {
			probeIndex[i] = at
			continue
		}
		probeOf[op] = len(probes)
		probeIndex[i] = len(probes)
		probes = append(probes, pollProbe{op: op, src: stream})
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
		pollReadable(probes, deadline)
		for i := range fdEvents {
			if at := probeIndex[i]; at >= 0 && (probes[at].ready || probes[at].refused) {
				ready[i], anyReady = true, true
			}
		}
	} else if minClockNs > 0 && !anyReady {
		// The clock paces the call only when nothing else can end it.
		time.Sleep(time.Duration(minClockNs))
	}

	written := int32(0)
	for _, ev := range clockEvents {
		// A poll returns its ready fds without also claiming that the
		// timeout expired.
		if ev.etype == 0 && anyReady {
			continue
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, 0, 0)
		written += 32
	}
	for i, ev := range fdEvents {
		if !ready[i] {
			continue
		}
		var nbytes uint64
		if op := ops[i]; op != nil && ev.isRead && errnos[i] == 0 {
			// A file that was not probed, or refused the probe's
			// deadline, is a regular file.
			regular := probeIndex[i] < 0 || probes[probeIndex[i]].refused
			if _, pending := op.aheadReady(); pending > 0 {
				nbytes = uint64(pending)
			} else if op.f != nil && regular {
				// Regular file: pass through the bytes left to read
				// (best-effort; the read itself reports the real state).
				if st, err := op.f.Stat(); err == nil {
					if cur, err := op.f.Seek(0, 1); err == nil && st.Size() > cur {
						nbytes = uint64(st.Size() - cur)
					}
				}
			}
		}
		writeEvent(events[written:written+32], ev.userdata, ev.etype, uint16(errnos[i]), nbytes)
		written += 32
	}

	binary.LittleEndian.PutUint32(nev, uint32(written/32))
	return _wasiESUCCESS
}

// pollProbe is one stream poll_oneoff has to probe for input.
type pollProbe struct {
	op      *wasiOpen
	src     deadlineReader
	ready   bool
	refused bool // src took no read deadline: not a stream (see probeRead)
}

// pollReadable waits until one of the streams has input (or reached its
// end), or until the zero-time-means-no-limit deadline, and records which
// are readable. The readiness test is a read: whatever arrives is kept on
// the descriptor and handed to the guest's next read of it. Once one stream
// is found readable, or turns out to be no stream, the others stop waiting.
func pollReadable(probes []pollProbe, deadline time.Time) {
	if len(probes) == 1 {
		pr := &probes[0]
		pr.ready, pr.refused = pr.op.probeRead(pr.src, deadline, nil)
		return
	}
	stop := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	for i := range probes {
		wg.Add(1)
		go func(pr *pollProbe) {
			defer wg.Done()
			pr.ready, pr.refused = pr.op.probeRead(pr.src, deadline, stop)
			if pr.ready || pr.refused {
				once.Do(func() { close(stop) })
			}
		}(&probes[i])
	}
	wg.Wait()
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
	op := w.fdsLocked()[fd]
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
	if cur := w.fdsLocked()[fd]; cur == op {
		// A forked instance sharing this socket may have connected it in
		// the meantime; the first connection stays.
		op.mu.Lock()
		connected := op.conn != nil
		if !connected {
			op.conn = conn
		}
		op.mu.Unlock()
		w.mu.Unlock()
		if connected {
			return dropConn(conn, _wasiEISCONN)
		}
		return _wasiESUCCESS
	}
	w.mu.Unlock()
	return dropConn(conn, _wasiEBADF)
}

// dropConn closes a connection a socket will not keep and returns what the
// connect that made it reports, as a negative errno like Sock_connect's
// other results: errno, or the close's failure when there was one.
func dropConn(conn net.Conn, errno int32) int32 {
	if err := conn.Close(); err != nil {
		return -mapOSError(err)
	}
	return -errno
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
	op := w.fdEntry(fd)
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
	op := w.fdEntry(fd)
	var conn net.Conn
	if op != nil {
		conn = op.netConn()
	}
	if conn == nil {
		return _wasiENOTSOCK
	}
	bufs, ok := w.iovecSlices(m, riData, riDataLen)
	lenOut := w.memSlice(m, roDataLenPtr, 4)
	// ro_flags is a __wasi_roflags_t — a 16-bit value. wasi-libc packs it
	// immediately before ro_datalen (only 2 bytes apart), so writing 4 bytes
	// here would clobber the low half of ro_datalen and make recv() report 0
	// bytes received even when data arrived.
	flagsOut := w.memSlice(m, roFlagsPtr, 2)
	if !ok || lenOut == nil || flagsOut == nil {
		return _wasiEFAULT
	}
	// A receive is a read of the connection, as Fd_read's is of a stream:
	// probed input first, the iovecs filled in order, done at a short read.
	n := op.readInput(conn, bufs)
	binary.LittleEndian.PutUint16(flagsOut, 0)
	binary.LittleEndian.PutUint32(lenOut, uint32(n))
	return _wasiESUCCESS
}

func (w *WasiStubs) Sock_send(m *Module, fd, siData, siDataLen, siFlags, soDataLenPtr int32) int32 {
	if !w.checkNet("send") {
		return _wasiEACCES
	}
	op := w.fdEntry(fd)
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
	op := w.fdEntry(fd)
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
// host os.FileInfo. The dev/ino fields come from the per-platform
// wasiPlatformStatSys helper (unix returns Stat_t.Dev/.Ino; Windows
// returns zeros).
func writeFilestat(out []byte, st os.FileInfo) {
	// os.FileInfo does not expose dev/ino portably; report zeros.
	binary.LittleEndian.PutUint64(out[0:], 0)
	binary.LittleEndian.PutUint64(out[8:], 0)
	var ftype byte = 4
	mode := st.Mode()
	switch {
	case mode.IsDir():
		ftype = 3
	case mode&os.ModeSymlink != 0:
		ftype = 7
	case mode&os.ModeNamedPipe != 0:
		ftype = 6
	case mode&os.ModeSocket != 0:
		ftype = 6
	case mode&os.ModeDevice != 0:
		ftype = 1
	case mode&os.ModeCharDevice != 0:
		ftype = 2
	}
	out[16] = ftype
	binary.LittleEndian.PutUint64(out[24:], 1) // nlink
	binary.LittleEndian.PutUint64(out[32:], uint64(st.Size()))
	nanos := uint64(st.ModTime().UnixNano())
	binary.LittleEndian.PutUint64(out[40:], nanos) // atim
	binary.LittleEndian.PutUint64(out[48:], nanos) // mtim
	binary.LittleEndian.PutUint64(out[56:], nanos) // ctim
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
			"WasiExitError":  true,
			"wasiOpen":       true,
			"wasiProc":       true,
			"wasiPIDs":       true,
			"deadlineReader": true,
			"pollProbe":      true,
			"WasiStubs":      true,
			"dotDirEntry":    true,
			"FS":             true,
			"File":           true,
			"osFS":           true,
			"chtimesFS":      true,
			"MemFS":          true,
			"memFile":        true,
			"memNode":        true,
			"memFileInfo":    true,
			"memDirEntry":    true,
		},
		keepFuncNames: map[string]bool{
			"itoa32":                  true,
			"DefaultWASI":             true,
			"SetPreopenDir":           true,
			"NewMemFS":                true,
			"memSplit":                true,
			"memSlice":                true,
			"mapOSError":              true,
			"mapExecError":            true,
			"encodeWaitStatus":        true,
			"totalBytesPlusNul":       true,
			"putStrVec64":             true,
			"readVec":                 true,
			"pollReadable":            true,
			"dropConn":                true,
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
// A memory64 module's wasi imports arrive with every argument widened
// to pointer-width i64 (see the wasm2go wasi-libc port's
// __wasi_abi_t), and pointer-bearing WASI structs (iovecs, sizes)
// use the LP64 layout. The *64 methods below are the widened
// bindings; codegen routes a memory64 module's imports here and
// every wasm32 module keeps the standard methods above.

// memSlice64 is memSlice for full-range 64-bit guest pointers.
func (w *WasiStubs) memSlice64(m *Module, off int64, n int64) []byte {
	mem := m.memory
	lo := uint64(off)
	hi := lo + uint64(n)
	if n < 0 || hi < lo || hi > uint64(len(mem)) {
		return nil
	}
	return mem[lo:hi]
}

func (w *WasiStubs) Clock_time_get64(m *Module, clockID int64, precision int64, timePtr int64) int32 {
	out := w.memSlice64(m, timePtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	nanos, errno := w.clockNanos(int32(clockID))
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint64(out, nanos)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_close64(m *Module, fd int64) int32 {
	return w.Fd_close(m, int32(fd))
}

func (w *WasiStubs) Sched_yield64(m *Module) int32 {
	// No arguments to widen; the LP64 twin exists only because a wasm64
	// module binds every wasi import through the widened interface.
	return w.Sched_yield(m)
}

func (w *WasiStubs) Fd_fdstat_get64(m *Module, fd int64, ptr int64) int32 {
	// The fdstat struct holds no pointers, so its 24-byte layout is
	// identical under LP64; only the out-pointer needs the 64-bit
	// window. Stage through a scratch struct via the 32-bit logic.
	out := w.memSlice64(m, ptr, 24)
	if out == nil {
		return _wasiEFAULT
	}
	return w.fdstatFill(int32(fd), out)
}

func (w *WasiStubs) Fd_seek64(m *Module, fd int64, offset int64, whence int64, newOffPtr int64) int32 {
	out := w.memSlice64(m, newOffPtr, 8)
	if out == nil {
		return _wasiEFAULT
	}
	n, errno := w.fdSeek(int32(fd), offset, int(whence))
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint64(out, uint64(n))
	return _wasiESUCCESS
}

// iovecSlices64 is iovecSlices for the LP64 iovec layout: {u64 buf,
// u64 len}, 16 bytes per entry.
func (w *WasiStubs) iovecSlices64(m *Module, iovs, iovsLen int64) ([][]byte, bool) {
	if iovsLen < 0 || iovsLen > 1<<20 {
		return nil, false
	}
	iovecs := w.memSlice64(m, iovs, iovsLen*16)
	if iovecs == nil {
		return nil, false
	}
	bufs := make([][]byte, 0, iovsLen)
	for i := int64(0); i < iovsLen; i++ {
		bufPtr := binary.LittleEndian.Uint64(iovecs[i*16:])
		bufLen := binary.LittleEndian.Uint64(iovecs[i*16+8:])
		buf := w.memSlice64(m, int64(bufPtr), int64(bufLen))
		if buf == nil {
			return nil, false
		}
		bufs = append(bufs, buf)
	}
	return bufs, true
}

func (w *WasiStubs) Fd_write64(m *Module, fd int64, iovs int64, iovsLen int64, nwrittenPtr int64) int32 {
	w.mu.Lock()
	dst, _ := w.fdDstLocked(int32(fd))
	w.mu.Unlock()
	bufs, ok := w.iovecSlices64(m, iovs, iovsLen)
	// nwritten is a 64-bit __wasi_size_t.
	nwrittenSlice := w.memSlice64(m, nwrittenPtr, 8)
	if !ok || nwrittenSlice == nil {
		return _wasiEFAULT
	}
	if dst == nil {
		binary.LittleEndian.PutUint64(nwrittenSlice, 0)
		return _wasiEBADF
	}
	binary.LittleEndian.PutUint64(nwrittenSlice, writeVec(dst, bufs))
	return _wasiESUCCESS
}

func (w *WasiStubs) Proc_exit64(m *Module, code int64) {
	panic(&WasiExitError{Code: int32(code)})
}

// putStrVec64 packs ss as an LP64 char** table (8-byte guest pointers
// at vec) plus NUL-terminated bodies (at buf, guest address bufBase).
// Both slices must already be sized: len(ss)*8 and totalBytesPlusNul.
func putStrVec64(vec, buf []byte, bufBase uint64, ss []string) int32 {
	bufOff := uint64(0)
	for i, s := range ss {
		binary.LittleEndian.PutUint64(vec[i*8:], bufBase+bufOff)
		n := copy(buf[bufOff:], s)
		if n < len(s) {
			return _wasiEFAULT
		}
		bufOff += uint64(n)
		buf[bufOff] = 0
		bufOff++
	}
	return _wasiESUCCESS
}

func (w *WasiStubs) Args_get64(m *Module, argv, argvBuf int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	argvSlice := w.memSlice64(m, argv, int64(len(w.args))*8)
	if argvSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.args)
	if !ok {
		return _wasiEFAULT
	}
	argvBufSlice := w.memSlice64(m, argvBuf, int64(total))
	if argvBufSlice == nil {
		return _wasiEFAULT
	}
	return putStrVec64(argvSlice, argvBufSlice, uint64(argvBuf), w.args)
}

func (w *WasiStubs) Args_sizes_get64(m *Module, argcPtr, argvBufLenPtr int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	argcSlice := w.memSlice64(m, argcPtr, 8)
	bufLenSlice := w.memSlice64(m, argvBufLenPtr, 8)
	if argcSlice == nil || bufLenSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.args)
	if !ok {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint64(argcSlice, uint64(len(w.args)))
	binary.LittleEndian.PutUint64(bufLenSlice, uint64(total))
	return _wasiESUCCESS
}

func (w *WasiStubs) Environ_get64(m *Module, envv, envBuf int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	envvSlice := w.memSlice64(m, envv, int64(len(w.env))*8)
	if envvSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.env)
	if !ok {
		return _wasiEFAULT
	}
	envBufSlice := w.memSlice64(m, envBuf, int64(total))
	if envBufSlice == nil {
		return _wasiEFAULT
	}
	return putStrVec64(envvSlice, envBufSlice, uint64(envBuf), w.env)
}

func (w *WasiStubs) Environ_sizes_get64(m *Module, envcPtr, envBufLenPtr int64) int32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	envcSlice := w.memSlice64(m, envcPtr, 8)
	bufLenSlice := w.memSlice64(m, envBufLenPtr, 8)
	if envcSlice == nil || bufLenSlice == nil {
		return _wasiEFAULT
	}
	total, ok := totalBytesPlusNul(w.env)
	if !ok {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint64(envcSlice, uint64(len(w.env)))
	binary.LittleEndian.PutUint64(bufLenSlice, uint64(total))
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_fdstat_set_flags64(m *Module, fd, flags int64) int32 {
	return w.Fd_fdstat_set_flags(m, int32(fd), int32(flags))
}

func (w *WasiStubs) Fd_prestat_get64(m *Module, fd, ptr int64) int32 {
	if int32(fd) != 3 {
		return _wasiEBADF
	}
	// LP64 prestat: tag u8 + pad[7] + pr_name_len (__wasi_size_t, u64)
	// = 16 bytes.
	out := w.memSlice64(m, ptr, 16)
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = 0 // preopen tag = directory
	binary.LittleEndian.PutUint64(out[8:], 1)
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_prestat_dir_name64(m *Module, fd, buf, buflen int64) int32 {
	if int32(fd) != 3 {
		return _wasiEBADF
	}
	if buflen < 1 {
		return _wasiESUCCESS
	}
	out := w.memSlice64(m, buf, buflen)
	if out == nil {
		return _wasiEFAULT
	}
	out[0] = '/'
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_read64(m *Module, fd, iovs, iovsLen, nreadPtr int64) int32 {
	w.mu.Lock()
	src, op := w.fdSrcLocked(int32(fd))
	w.mu.Unlock()
	if src == nil {
		return _wasiEBADF
	}
	bufs, ok := w.iovecSlices64(m, iovs, iovsLen)
	// nread is a 64-bit __wasi_size_t.
	nreadSlice := w.memSlice64(m, nreadPtr, 8)
	if !ok || nreadSlice == nil {
		return _wasiEFAULT
	}
	binary.LittleEndian.PutUint64(nreadSlice, op.readInput(src, bufs))
	return _wasiESUCCESS
}

func (w *WasiStubs) Fd_readdir64(m *Module, fd, buf, buflen, cookie, bufusedPtr int64) int32 {
	// The dirent wire format is pointer-free (u64s and a u32), so only
	// the buffer window and the 64-bit bufused differ from wasm32.
	bufSlice := w.memSlice64(m, buf, buflen)
	bufusedSlice := w.memSlice64(m, bufusedPtr, 8)
	if bufSlice == nil || bufusedSlice == nil {
		return _wasiEFAULT
	}
	written, errno := w.fdReaddir(int32(fd), bufSlice, cookie)
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint64(bufusedSlice, uint64(written))
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_open64(m *Module, dirFd, dirflags, pathPtr, pathLen, oflags, fsRightsBase, fsRightsInherit, fdflags, openedFdPtr int64) int32 {
	if int32(dirFd) != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice64(m, pathPtr, pathLen)
	// The opened fd is a __wasi_fd_t (u32) under LP64 too.
	outSlice := w.memSlice64(m, openedFdPtr, 4)
	if pathSlice == nil || outSlice == nil {
		return _wasiEFAULT
	}
	fd, errno := w.pathOpen(string(pathSlice), int32(dirflags), int32(oflags), fsRightsBase, int32(fdflags))
	if errno != _wasiESUCCESS {
		return errno
	}
	binary.LittleEndian.PutUint32(outSlice, uint32(fd))
	return _wasiESUCCESS
}

func (w *WasiStubs) Path_filestat_get64(m *Module, dirFd, flags, pathPtr, pathLen, outPtr int64) int32 {
	if int32(dirFd) != 3 {
		return _wasiEBADF
	}
	pathSlice := w.memSlice64(m, pathPtr, pathLen)
	// filestat is all fixed-width u64/u32 fields — 64 bytes under both
	// ABIs.
	out := w.memSlice64(m, outPtr, 64)
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

func (w *WasiStubs) Random_get64(m *Module, buf, bufLen int64) int32 {
	slice := w.memSlice64(m, buf, bufLen)
	if slice == nil {
		return _wasiEFAULT
	}
	if _, err := rand.Read(slice); err != nil {
		return _wasiEIO
	}
	return _wasiESUCCESS
}
