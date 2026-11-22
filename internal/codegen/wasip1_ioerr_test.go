package codegen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests for the errno fd_read / fd_write / fd_pread / fd_pwrite return,
// for a wasm32 and a memory64 guest, when the host I/O fails.

// Guest memory layout shared by the cases below.
const (
	ioErrIov    = 200  // iovec array
	ioErrBuf    = 1024 // data buffers
	ioErrResult = 400  // nread / nwritten
)

// ioStep is one scripted result of a scriptFile I/O call.
type ioStep struct {
	n   int
	err error
}

// scriptFile is a File whose Read/Write/ReadAt/WriteAt return the scripted
// steps in order.
type scriptFile struct {
	File
	steps []ioStep
}

func (f *scriptFile) next() (int, error) {
	if len(f.steps) == 0 {
		return 0, errors.New("scriptFile: no step left")
	}
	s := f.steps[0]
	f.steps = f.steps[1:]
	return s.n, s.err
}

func (f *scriptFile) Read(p []byte) (int, error)             { return f.next() }
func (f *scriptFile) Write(p []byte) (int, error)            { return f.next() }
func (f *scriptFile) ReadAt(p []byte, _ int64) (int, error)  { return f.next() }
func (f *scriptFile) WriteAt(p []byte, _ int64) (int, error) { return f.next() }

// ioCall is one of the I/O bindings under test.
type ioCall struct {
	name string
	abi  wasiABI
	call func(w *WasiStubs, m *Module, fd int32, nIov int) int32
}

var ioReadCalls = []ioCall{
	{"Fd_read", wasiABI32, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_read(m, fd, ioErrIov, int32(nIov), ioErrResult)
	}},
	{"Fd_read64", wasiABI64, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_read64(m, int64(fd), ioErrIov, int64(nIov), ioErrResult)
	}},
	{"Fd_pread", wasiABI32, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_pread(m, fd, ioErrIov, int32(nIov), 0, ioErrResult)
	}},
	{"Fd_pread64", wasiABI64, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_pread64(m, int64(fd), ioErrIov, int64(nIov), 0, ioErrResult)
	}},
}

var ioWriteCalls = []ioCall{
	{"Fd_write", wasiABI32, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_write(m, fd, ioErrIov, int32(nIov), ioErrResult)
	}},
	{"Fd_write64", wasiABI64, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_write64(m, int64(fd), ioErrIov, int64(nIov), ioErrResult)
	}},
	{"Fd_pwrite", wasiABI32, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_pwrite(m, fd, ioErrIov, int32(nIov), 0, ioErrResult)
	}},
	{"Fd_pwrite64", wasiABI64, func(w *WasiStubs, m *Module, fd int32, nIov int) int32 {
		return w.Fd_pwrite64(m, int64(fd), ioErrIov, int64(nIov), 0, ioErrResult)
	}},
}

// run calls the binding on fd over nIov 4-byte buffers and returns its
// errno and the count it stored.
func (c ioCall) run(w *WasiStubs, m *Module, fd int32, nIov int) (int32, uint64) {
	for i := 0; i < nIov; i++ {
		if c.abi == wasiABI64 {
			makeIovec64(m, ioErrIov+int64(i)*16, ioErrBuf+int64(i)*4, 4)
		} else {
			makeIovec(m, ioErrIov+int32(i)*8, ioErrBuf+int32(i)*4, 4)
		}
	}
	rc := c.call(w, m, fd, nIov)
	if c.abi == wasiABI64 {
		return rc, readU64(m.memory, ioErrResult)
	}
	return rc, uint64(readU32(m.memory, ioErrResult))
}

// openHostFile creates name with content under dir and opens it read-only
// through Path_open, returning the guest fd.
func openHostFile(t *testing.T, w *WasiStubs, m *Module, dir, name, content string) int32 {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pathOff, pathLen := putPath(m, 0, name)
	if rc := w.Path_open(m, 3, 0, pathOff, pathLen, 0, 1<<1, 0, 0, 128); rc != _wasiESUCCESS {
		t.Fatalf("open rc=%d", rc)
	}
	fd := int32(readU32(m.memory, 128))
	f := w.fdTable[fd].f
	t.Cleanup(func() {
		// A test may have closed the file itself.
		if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	return fd
}

func TestWasi_WriteOnReadOnlyDescriptorFails(t *testing.T) {
	for _, c := range ioWriteCalls {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			w, m := newTestStubs(t, dir)
			fd := openHostFile(t, w, m, dir, "ro", "data")
			rc, n := c.run(w, m, fd, 1)
			if rc == _wasiESUCCESS {
				t.Fatalf("rc=ESUCCESS n=%d, want an error", n)
			}
			// Windows reports the denied write as a permission error.
			if runtime.GOOS != "windows" && rc != _wasiEBADF {
				t.Fatalf("rc=%d, want EBADF", rc)
			}
			got, err := os.ReadFile(filepath.Join(dir, "ro"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "data" {
				t.Fatalf("file content=%q", got)
			}
		})
	}
}

func TestWasi_ReadOnClosedFileFails(t *testing.T) {
	for _, c := range ioReadCalls {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			w, m := newTestStubs(t, dir)
			fd := openHostFile(t, w, m, dir, "f", "data")
			if err := w.fdTable[fd].f.Close(); err != nil {
				t.Fatal(err)
			}
			if rc, n := c.run(w, m, fd, 1); rc != _wasiEBADF || n != 0 {
				t.Fatalf("rc=%d n=%d, want EBADF 0", rc, n)
			}
		})
	}
}

func TestWasi_ReadAtEOFSucceedsWithZero(t *testing.T) {
	for _, c := range ioReadCalls {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			w, m := newTestStubs(t, dir)
			fd := openHostFile(t, w, m, dir, "empty", "")
			if rc, n := c.run(w, m, fd, 1); rc != _wasiESUCCESS || n != 0 {
				t.Fatalf("rc=%d n=%d, want ESUCCESS 0", rc, n)
			}
		})
	}
	t.Run("stdin", func(t *testing.T) {
		w, m := newTestStubs(t, t.TempDir())
		w.cfg.Stdin = strings.NewReader("")
		if rc, n := ioReadCalls[0].run(w, m, 0, 1); rc != _wasiESUCCESS || n != 0 {
			t.Fatalf("rc=%d n=%d, want ESUCCESS 0", rc, n)
		}
	})
}

func TestWasi_ReadOnDirectoryIsEISDIR(t *testing.T) {
	dir := t.TempDir()
	for name, fsys := range map[string]FS{"osFS": newHostFS(t, dir), "MemFS": NewMemFS()} {
		t.Run(name, func(t *testing.T) {
			w, m := newTestStubs(t, dir)
			w.cfg.FS = fsys
			if name == "osFS" && runtime.GOOS == "windows" {
				t.Skip("reading a directory handle fails differently on Windows")
			}
			if err := fsys.Mkdir("d", 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := fsys.OpenFile("d", os.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			})
			w.setSlotLocked(9, &wasiOpen{f: f})
			for _, c := range ioReadCalls {
				if rc, n := c.run(w, m, 9, 1); rc != _wasiEISDIR || n != 0 {
					t.Errorf("%s: rc=%d n=%d, want EISDIR 0", c.name, rc, n)
				}
			}
		})
	}
}

func TestWasi_IOErrorAfterTransferIsShortCount(t *testing.T) {
	failure := errors.New("device failure")
	for _, c := range append(append([]ioCall{}, ioReadCalls...), ioWriteCalls...) {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			// a regular file, which a read fills every buffer of
			w.setSlotLocked(9, &wasiOpen{f: &scriptFile{steps: []ioStep{{4, nil}, {0, failure}}}, regular: true})
			if rc, n := c.run(w, m, 9, 2); rc != _wasiESUCCESS || n != 4 {
				t.Fatalf("error after a full buffer: rc=%d n=%d, want ESUCCESS 4", rc, n)
			}
			w.setSlotLocked(9, &wasiOpen{f: &scriptFile{steps: []ioStep{{3, failure}}}})
			if rc, n := c.run(w, m, 9, 2); rc != _wasiESUCCESS || n != 3 {
				t.Fatalf("error with a short count: rc=%d n=%d, want ESUCCESS 3", rc, n)
			}
			w.setSlotLocked(9, &wasiOpen{f: &scriptFile{steps: []ioStep{{0, failure}}}})
			if rc, n := c.run(w, m, 9, 2); rc != _wasiEIO || n != 0 {
				t.Fatalf("error with nothing transferred: rc=%d n=%d, want EIO 0", rc, n)
			}
		})
	}
}

// scriptConn is a net.Conn whose Read/Write return the scripted steps in
// order.
type scriptConn struct {
	net.Conn
	script scriptFile
}

func (c *scriptConn) Read(p []byte) (int, error)  { return c.script.next() }
func (c *scriptConn) Write(p []byte) (int, error) { return c.script.next() }

// SetReadDeadline reports that the scripted connection takes no deadline.
func (c *scriptConn) SetReadDeadline(time.Time) error { return os.ErrNoDeadline }

func TestWasi_SockIOErrorIsErrnoOnlyWhenNothingMoved(t *testing.T) {
	failure := errors.New("device failure")
	for _, c := range []struct {
		name string
		call func(w *WasiStubs, m *Module) int32
	}{
		{"Sock_recv", func(w *WasiStubs, m *Module) int32 {
			return w.Sock_recv(m, 9, ioErrIov, 2, 0, ioErrResult, ioErrResult+8)
		}},
		{"Sock_send", func(w *WasiStubs, m *Module) int32 {
			return w.Sock_send(m, 9, ioErrIov, 2, 0, ioErrResult)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			for i := int32(0); i < 2; i++ {
				makeIovec(m, ioErrIov+i*8, ioErrBuf+i*4, 4)
			}
			for _, s := range []struct {
				steps []ioStep
				rc    int32
				n     uint32
			}{
				{[]ioStep{{4, nil}, {0, failure}}, _wasiESUCCESS, 4},
				{[]ioStep{{3, failure}}, _wasiESUCCESS, 3},
				{[]ioStep{{0, failure}}, _wasiEIO, 0},
				{[]ioStep{{0, syscall.EPIPE}}, _wasiEPIPE, 0},
			} {
				binary.LittleEndian.PutUint32(m.memory[ioErrResult:], 0)
				w.setSlotLocked(9, &wasiOpen{conn: &scriptConn{script: scriptFile{steps: s.steps}}})
				if rc, n := c.call(w, m), readU32(m.memory, ioErrResult); rc != s.rc || n != s.n {
					t.Errorf("%v: rc=%d n=%d, want %d %d", s.steps, rc, n, s.rc, s.n)
				}
			}
		})
	}
	// The end of the stream is a receive of nothing.
	w, m := newTestStubs(t, t.TempDir())
	makeIovec(m, ioErrIov, ioErrBuf, 4)
	binary.LittleEndian.PutUint32(m.memory[ioErrResult:], 7)
	w.setSlotLocked(9, &wasiOpen{conn: &scriptConn{script: scriptFile{steps: []ioStep{{0, io.EOF}}}}})
	if rc, n := w.Sock_recv(m, 9, ioErrIov, 1, 0, ioErrResult, ioErrResult+8), readU32(m.memory, ioErrResult); rc != _wasiESUCCESS || n != 0 {
		t.Fatalf("EOF: rc=%d n=%d, want ESUCCESS 0", rc, n)
	}
}

func TestWasi_SeekErrorIsTheHostError(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	fd := openHostFile(t, w, m, dir, "f", "data")
	if rc := w.Fd_seek(m, fd, -1, 0, ioErrResult); rc != _wasiEINVAL {
		t.Errorf("seek before the start: rc=%d, want EINVAL", rc)
	}
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{r, wr} {
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	w.setSlotLocked(9, &wasiOpen{f: r})
	if rc := w.Fd_seek(m, 9, 0, 0, ioErrResult); rc != _wasiESPIPE {
		t.Errorf("Fd_seek on a pipe: rc=%d, want ESPIPE", rc)
	}
	if rc := w.Fd_tell(m, 9, ioErrResult); rc != _wasiESPIPE {
		t.Errorf("Fd_tell on a pipe: rc=%d, want ESPIPE", rc)
	}
	// A socket cannot seek either; a descriptor that is not there is
	// EBADF.
	w.setSlotLocked(10, &wasiOpen{isSocket: true})
	for fd, want := range map[int32]int32{10: _wasiESPIPE, 11: _wasiEBADF} {
		if rc := w.Fd_seek(m, fd, 0, 0, ioErrResult); rc != want {
			t.Errorf("Fd_seek(%d): rc=%d, want %d", fd, rc, want)
		}
		if rc := w.Fd_tell(m, fd, ioErrResult); rc != want {
			t.Errorf("Fd_tell(%d): rc=%d, want %d", fd, rc, want)
		}
		for _, c := range []ioCall{ioReadCalls[2], ioReadCalls[3], ioWriteCalls[2], ioWriteCalls[3]} {
			if rc, _ := c.run(w, m, fd, 1); rc != want {
				t.Errorf("%s(%d): rc=%d, want %d", c.name, fd, rc, want)
			}
		}
	}
}

// readFunc reads from fd into two 4-byte buffers and returns the errno and
// the count it stored.
type readFunc func(w *WasiStubs, m *Module, fd int32) (int32, uint64)

func sockRecv2(w *WasiStubs, m *Module, fd int32) (int32, uint64) {
	for i := int32(0); i < 2; i++ {
		makeIovec(m, ioErrIov+i*8, ioErrBuf+i*4, 4)
	}
	rc := w.Sock_recv(m, fd, ioErrIov, 2, 0, ioErrResult, ioErrResult+8)
	return rc, uint64(readU32(m.memory, ioErrResult))
}

// A read into several buffers from a pipe, standard input or a socket
// returns what one read got, whether it left the first buffer short or
// filled it exactly, instead of waiting for more to fill the next one. A
// regular file fills them all.
func TestWasi_StreamReadReturnsWhatHasArrived(t *testing.T) {
	reads := map[string]readFunc{}
	for _, c := range ioReadCalls[:2] {
		reads[c.name] = func(w *WasiStubs, m *Module, fd int32) (int32, uint64) { return c.run(w, m, fd, 2) }
	}
	for _, src := range []string{"pipe", "stdin", "conn"} {
		calls := reads
		if src == "conn" {
			calls = map[string]readFunc{"Sock_recv": sockRecv2}
			for name, read := range reads {
				calls[name] = read
			}
		}
		for name, read := range calls {
			for _, sent := range []string{"abc", "abcd"} {
				t.Run(src+"/"+name+"/"+sent, func(t *testing.T) {
					w, m := newTestStubs(t, t.TempDir())
					var peer io.WriteCloser
					var own io.Closer
					fd := int32(9)
					switch src {
					case "conn":
						c1, c2 := net.Pipe()
						peer, own = c1, c2
						w.setSlotLocked(fd, &wasiOpen{conn: c2})
					default:
						r, pw, err := os.Pipe()
						if err != nil {
							t.Fatal(err)
						}
						peer, own = pw, r
						if src == "stdin" {
							w.cfg.Stdin, fd = r, 0
						} else {
							w.setSlotLocked(fd, &wasiOpen{f: r})
						}
					}
					t.Cleanup(func() {
						if err := errors.Join(peer.Close(), own.Close()); err != nil {
							t.Error(err)
						}
					})
					// The peer sends and then waits, keeping its end open.
					wrote := make(chan error, 1)
					go func() {
						_, err := peer.Write([]byte(sent))
						wrote <- err
					}()
					done := make(chan [2]uint64, 1)
					go func() {
						rc, n := read(w, m, fd)
						done <- [2]uint64{uint64(rc), n}
					}()
					select {
					case got := <-done:
						if got[0] != uint64(_wasiESUCCESS) || got[1] != uint64(len(sent)) {
							t.Fatalf("rc=%d n=%d, want ESUCCESS %d", got[0], got[1], len(sent))
						}
						// What was read was written whole.
						if err := <-wrote; err != nil {
							t.Errorf("peer write: %v", err)
						}
					case <-time.After(10 * time.Second):
						// The cleanup closes the stream, which ends the read.
						t.Fatal("the read waits for more after one read returned data")
					}
				})
			}
		}
	}
	for _, c := range ioReadCalls {
		dir := t.TempDir()
		w, m := newTestStubs(t, dir)
		fd := openHostFile(t, w, m, dir, "f", "abcdefgh")
		if rc, n := c.run(w, m, fd, 2); rc != _wasiESUCCESS || n != 8 || string(m.memory[ioErrBuf:ioErrBuf+8]) != "abcdefgh" {
			t.Errorf("%s of a regular file: rc=%d n=%d %q, want ESUCCESS 8 \"abcdefgh\"", c.name, rc, n, m.memory[ioErrBuf:ioErrBuf+n])
		}
	}
}

// seekFailFile is a File whose Seek fails with an error that has no
// number.
type seekFailFile struct{ File }

func (seekFailFile) Seek(int64, int) (int64, error) { return 0, errors.New("cannot seek") }

// A socket call on a descriptor that is not open is EBADF, on one that is
// not a socket (a preopened directory included) ENOTSOCK; on a socket
// without a connection a receive or read is ENOTCONN and a send or write
// EPIPE, as on linux. connect of a connected socket, an accepted or a
// listening one included, is EISCONN, and of one closed while it dials
// EBADF. A shutdown checks the descriptor, then how; of a listening
// socket it succeeds, and shutting its read half fails an accept that
// waits with EINVAL.
func TestWasi_SocketCallsOnDescriptorsWithoutAConnection(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	accepted := newShutConn(t, false)
	w.setSlotLocked(9, &wasiOpen{isSocket: true})
	w.setSlotLocked(10, &wasiOpen{f: &scriptFile{}})
	w.setSlotLocked(12, &wasiOpen{conn: accepted})
	w.setSlotLocked(13, &wasiOpen{isSocket: true, listener: l})
	makeIovec(m, ioErrIov, ioErrBuf, 4)
	for _, c := range []struct{ fd, recv, send int32 }{
		{9, _wasiENOTCONN, _wasiEPIPE},
		{10, _wasiENOTSOCK, _wasiENOTSOCK},
		{11, _wasiEBADF, _wasiEBADF},
		{wasiPreopenFD, _wasiENOTSOCK, _wasiENOTSOCK},
		{wasiRootFD, _wasiENOTSOCK, _wasiENOTSOCK},
	} {
		if rc := w.Sock_recv(m, c.fd, ioErrIov, 1, 0, ioErrResult, ioErrResult+8); rc != c.recv {
			t.Errorf("Sock_recv(%d): rc=%d, want %d", c.fd, rc, c.recv)
		}
		if rc := w.Sock_send(m, c.fd, ioErrIov, 1, 0, ioErrResult); rc != c.send {
			t.Errorf("Sock_send(%d): rc=%d, want %d", c.fd, rc, c.send)
		}
		if c.fd == 9 {
			continue
		}
		if rc := w.Sock_shutdown(m, c.fd, 0); rc != c.recv {
			t.Errorf("Sock_shutdown(%d, how 0): rc=%d, want %d", c.fd, rc, c.recv)
		}
		if rc := w.Sock_connect(m, c.fd, 0x0100007f, 1); rc != -c.recv {
			t.Errorf("Sock_connect(%d): rc=%d, want %d", c.fd, rc, -c.recv)
		}
	}
	for _, c := range []struct {
		call ioCall
		want int32
	}{{ioReadCalls[0], _wasiENOTCONN}, {ioWriteCalls[0], _wasiEPIPE}} {
		if rc, _ := c.call.run(w, m, 9, 1); rc != c.want {
			t.Errorf("%s of a socket without a connection: rc=%d, want %d", c.call.name, rc, c.want)
		}
	}
	for _, fd := range []int32{12, 13} {
		if rc := w.Sock_connect(m, fd, 0x0100007f, 1); rc != -_wasiEISCONN {
			t.Errorf("Sock_connect of an accepted or listening socket (%d): rc=%d, want -EISCONN", fd, rc)
		}
	}
	if rc := w.Sock_shutdown(m, 9, 0); rc != _wasiEINVAL {
		t.Errorf("Sock_shutdown(how 0) of a socket without a connection: rc=%d, want EINVAL", rc)
	}
	if rc := w.Sock_shutdown(m, 9, 0x3); rc != _wasiENOTCONN {
		t.Errorf("Sock_shutdown of a socket without a connection: rc=%d, want ENOTCONN", rc)
	}
	if rc := w.Sock_shutdown(m, 13, 0x2); rc != _wasiESUCCESS {
		t.Errorf("Sock_shutdown(SHUT_WR) of a listening socket: rc=%d, want ESUCCESS", rc)
	}

	// Shutting the read half of a listening socket fails an accept that
	// waits with EINVAL; closing the descriptor then succeeds.
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.setSlotLocked(15, &wasiOpen{isSocket: true, listener: l2})
	accept := make(chan int32, 1)
	go func() { accept <- w.Sock_accept(m, 15, 0, ioErrResult) }()
	// Give the accept time to wait.
	time.Sleep(50 * time.Millisecond)
	if rc := w.Sock_shutdown(m, 15, 0x1); rc != _wasiESUCCESS {
		t.Errorf("Sock_shutdown(SHUT_RD) of a listening socket: rc=%d, want ESUCCESS", rc)
	}
	select {
	case rc := <-accept:
		if rc != _wasiEINVAL {
			t.Errorf("Sock_accept after SHUT_RD: rc=%d, want EINVAL", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Sock_accept did not return after SHUT_RD")
	}
	if rc := w.Fd_close(m, 15); rc != _wasiESUCCESS {
		t.Errorf("Fd_close of the shut listening socket: rc=%d, want ESUCCESS", rc)
	}

	// The descriptor goes away while the socket dials.
	w.cfg.Dial = func(network, host, ip string, port int) bool {
		if rc := w.Fd_close(m, 9); rc != _wasiESUCCESS {
			t.Errorf("Fd_close during the dial: rc=%d", rc)
		}
		return true
	}
	port := l.Addr().(*net.TCPAddr).Port
	if rc := w.Sock_connect(m, 9, 0x0100007f, int32(port)); rc != -_wasiEBADF {
		t.Errorf("Sock_connect of a socket closed while it dials: rc=%d, want -EBADF", rc)
	}

	// A seek error without a number is EINVAL, a tell error without one
	// EIO.
	w.setSlotLocked(14, &wasiOpen{f: seekFailFile{}})
	if rc := w.Fd_seek(m, 14, 0, 0, ioErrResult); rc != _wasiEINVAL {
		t.Errorf("Fd_seek whose Seek fails: rc=%d, want EINVAL", rc)
	}
	if rc := w.Fd_tell(m, 14, ioErrResult); rc != _wasiEIO {
		t.Errorf("Fd_tell whose Seek fails: rc=%d, want EIO", rc)
	}
}

// errnoOr gives the errno of an error with a number and the fallback for
// one without or with a number that maps to no errno.
func TestErrnoOr(t *testing.T) {
	// ENOENT is a number every host maps (to fs.ErrNotExist at least).
	missing := &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}
	if got := errnoOr(missing, _wasiECONNREFUSED); got != _wasiENOENT {
		t.Errorf("errnoOr(ENOENT) = %d, want ENOENT", got)
	}
	if got := errnoOr(errors.New("no number"), _wasiECONNREFUSED); got != _wasiECONNREFUSED {
		t.Errorf("errnoOr(an error without a number) = %d, want ECONNREFUSED", got)
	}
	// A number that maps to no errno is the fallback too; EIO itself is EIO.
	if got := errnoOr(os.NewSyscallError("connect", syscall.Errno(9999)), _wasiECONNREFUSED); got != _wasiECONNREFUSED {
		t.Errorf("errnoOr(an unknown number) = %d, want ECONNREFUSED", got)
	}
	if got := errnoOr(os.NewSyscallError("read", syscall.EIO), _wasiEINVAL); got != _wasiEIO {
		t.Errorf("errnoOr(EIO) = %d, want EIO", got)
	}
	// os.File.Seek's own EISDIR of a directory it has read is no lseek errno.
	if got := seekErrno(&os.PathError{Op: "seek", Path: "d", Err: syscall.EISDIR}, _wasiEINVAL); got != _wasiEINVAL {
		t.Errorf("seekErrno(EISDIR) = %d, want EINVAL", got)
	}
	if got := seekErrno(&os.PathError{Op: "seek", Path: "f", Err: syscall.EIO}, _wasiEINVAL); got != _wasiEIO {
		t.Errorf("seekErrno(EIO) = %d, want EIO", got)
	}
}

// readEndsConn is a net.Conn without a half close whose Close returns
// once the read it ends has returned (or after a while): what the read
// sees of the descriptor is what it was when the connection closed.
type readEndsConn struct {
	net.Conn
	finished <-chan struct{}
}

func (c *readEndsConn) Close() error {
	err := c.Conn.Close()
	select {
	case <-c.finished:
	case <-time.After(time.Second):
	}
	return err
}

// shutConn is a net.Conn without a half close that counts its Closes,
// fails the first when failClose is set (after waiting for release when
// that is set), and fails a Read or a Write after a Close with
// net.ErrClosed, as a net.TCPConn does.
type shutConn struct {
	net.Conn
	failClose bool
	release   chan struct{}
	closes    atomic.Int32
}

func newShutConn(t *testing.T, failClose bool) *shutConn {
	c1, c2 := net.Pipe()
	t.Cleanup(func() {
		if err := errors.Join(c1.Close(), c2.Close()); err != nil {
			t.Error(err)
		}
	})
	return &shutConn{Conn: c2, failClose: failClose}
}

func (c *shutConn) Read(p []byte) (int, error) {
	if c.closes.Load() > 0 {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}

func (c *shutConn) Write(p []byte) (int, error) {
	if c.closes.Load() > 0 {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *shutConn) Close() error {
	if c.closes.Add(1) == 1 && c.failClose {
		if c.release != nil {
			<-c.release
		}
		return errors.New("close failed")
	}
	return c.Conn.Close()
}

// After sock_shutdown closed a connection that has no half close,
// whichever halves it asked for, a receive or a read of it gets the end
// of the stream, also one that was waiting when the connection closed,
// and a send or a write of it fails with EPIPE. The first shutdown closes
// the connection, once also when two run at once, and closing the
// descriptor does not close it again, also when that close failed, and
// does not wait for it. A shutdown that asks for no half is EINVAL; one
// of a socket without a connection ENOTCONN, of a file ENOTSOCK.
func TestWasi_TransferAfterShutdown(t *testing.T) {
	reads := map[string]readFunc{
		"Sock_recv": sockRecv2,
		"Fd_read":   func(w *WasiStubs, m *Module, fd int32) (int32, uint64) { return ioReadCalls[0].run(w, m, fd, 2) },
	}
	for name, read := range reads {
		for _, waiting := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/waiting=%v", name, waiting), func(t *testing.T) {
				c1, c2 := net.Pipe()
				t.Cleanup(func() {
					if err := c1.Close(); err != nil {
						t.Error(err)
					}
				})
				w, m := newTestStubs(t, t.TempDir())
				finished := make(chan struct{})
				conn := c2
				if waiting {
					conn = &readEndsConn{Conn: c2, finished: finished}
				}
				w.setSlotLocked(9, &wasiOpen{conn: conn})
				shutdown := func() {
					if rc := w.Sock_shutdown(m, 9, 0x1); rc != _wasiESUCCESS {
						t.Errorf("Sock_shutdown rc=%d", rc)
					}
				}
				if !waiting {
					shutdown()
				}
				binary.LittleEndian.PutUint32(m.memory[ioErrResult:], 7)
				done := make(chan [2]uint64, 1)
				go func() {
					rc, n := read(w, m, 9)
					close(finished)
					done <- [2]uint64{uint64(rc), n}
				}()
				if waiting {
					// Give the read time to block on the connection.
					time.Sleep(50 * time.Millisecond)
					shutdown()
				}
				select {
				case got := <-done:
					if got[0] != uint64(_wasiESUCCESS) || got[1] != 0 {
						t.Errorf("rc=%d n=%d, want ESUCCESS 0", got[0], got[1])
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the read did not return after the shutdown")
				}
			})
		}
	}

	for _, c := range []struct {
		how        int32
		recv, send int32
	}{
		{0x1, _wasiESUCCESS, _wasiEPIPE},
		{0x2, _wasiESUCCESS, _wasiEPIPE},
		{0x3, _wasiESUCCESS, _wasiEPIPE},
	} {
		conn := newShutConn(t, false)
		w, m := newTestStubs(t, t.TempDir())
		w.setSlotLocked(9, &wasiOpen{conn: conn})
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if rc := w.Sock_shutdown(m, 9, c.how); rc != _wasiESUCCESS {
					t.Errorf("how %d: Sock_shutdown rc=%d", c.how, rc)
				}
			}()
		}
		wg.Wait()
		if rc, _ := sockRecv2(w, m, 9); rc != c.recv {
			t.Errorf("how %d: Sock_recv rc=%d, want %d", c.how, rc, c.recv)
		}
		if rc, _ := ioReadCalls[0].run(w, m, 9, 1); rc != c.recv {
			t.Errorf("how %d: Fd_read rc=%d, want %d", c.how, rc, c.recv)
		}
		makeIovec(m, ioErrIov, ioErrBuf, 4)
		if rc := w.Sock_send(m, 9, ioErrIov, 1, 0, ioErrResult); rc != c.send {
			t.Errorf("how %d: Sock_send rc=%d, want %d", c.how, rc, c.send)
		}
		if rc, _ := ioWriteCalls[0].run(w, m, 9, 1); rc != c.send {
			t.Errorf("how %d: Fd_write rc=%d, want %d", c.how, rc, c.send)
		}
		if rc := w.Fd_close(m, 9); rc != _wasiESUCCESS || conn.closes.Load() != 1 {
			t.Errorf("how %d: Fd_close rc=%d, %d closes of the connection; want ESUCCESS and 1", c.how, rc, conn.closes.Load())
		}
	}

	conn := newShutConn(t, false)
	w, m := newTestStubs(t, t.TempDir())
	w.setSlotLocked(9, &wasiOpen{conn: conn})
	for _, how := range []int32{0, 0x4, 0x7} {
		if rc := w.Sock_shutdown(m, 9, how); rc != _wasiEINVAL {
			t.Errorf("Sock_shutdown how %#x: rc=%d, want EINVAL", how, rc)
		}
	}
	if got := conn.closes.Load(); got != 0 {
		t.Errorf("%d closes after shutdowns that asked for no half, want 0", got)
	}

	for _, during := range []bool{false, true} {
		conn := newShutConn(t, true)
		if during {
			conn.release = make(chan struct{})
		}
		w, m := newTestStubs(t, t.TempDir())
		w.setSlotLocked(9, &wasiOpen{conn: conn})
		shut := make(chan int32, 1)
		go func() { shut <- w.Sock_shutdown(m, 9, 0x3) }()
		if during {
			for conn.closes.Load() == 0 {
				time.Sleep(time.Millisecond)
			}
			// Closing the descriptor does not wait for the shutdown's
			// close.
			closed := make(chan int32, 1)
			go func() { closed <- w.Fd_close(m, 9) }()
			select {
			case rc := <-closed:
				if rc != _wasiESUCCESS {
					t.Errorf("Fd_close during the shutdown's close: rc=%d, want ESUCCESS", rc)
				}
			case <-time.After(10 * time.Second):
				t.Error("Fd_close waits for the shutdown's close")
			}
			close(conn.release)
		}
		if rc := <-shut; rc != _wasiEIO {
			t.Errorf("during=%v: Sock_shutdown whose close fails: rc=%d, want EIO", during, rc)
		}
		if !during {
			if rc := w.Fd_close(m, 9); rc != _wasiESUCCESS {
				t.Errorf("Fd_close after a failed close: rc=%d, want ESUCCESS", rc)
			}
		}
		if got := conn.closes.Load(); got != 1 {
			t.Errorf("during=%v: %d closes of the connection, want 1", during, got)
		}
	}

	// Only a connected socket can be shut down.
	w, m = newTestStubs(t, t.TempDir())
	w.setSlotLocked(9, &wasiOpen{isSocket: true})
	w.setSlotLocked(10, &wasiOpen{f: &scriptFile{}})
	for fd, want := range map[int32]int32{9: _wasiENOTCONN, 10: _wasiENOTSOCK, 11: _wasiEBADF} {
		if rc := w.Sock_shutdown(m, fd, 0x3); rc != want {
			t.Errorf("Sock_shutdown(%d): rc=%d, want %d", fd, rc, want)
		}
	}
}
