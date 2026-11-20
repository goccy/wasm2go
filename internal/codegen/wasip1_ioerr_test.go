package codegen

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
		w.stdin = strings.NewReader("")
		if rc, n := ioReadCalls[0].run(w, m, 0, 1); rc != _wasiESUCCESS || n != 0 {
			t.Fatalf("rc=%d n=%d, want ESUCCESS 0", rc, n)
		}
	})
}

func TestWasi_ReadOnDirectoryIsEISDIR(t *testing.T) {
	dir := t.TempDir()
	for name, fsys := range map[string]FS{"osFS": osFS{root: dir}, "MemFS": NewMemFS()} {
		t.Run(name, func(t *testing.T) {
			w, m := newTestStubs(t, dir)
			w.fsys = fsys
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
			w.fdTable[9] = &wasiOpen{f: f}
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
			w.fdTable[9] = &wasiOpen{f: &scriptFile{steps: []ioStep{{4, nil}, {0, failure}}}}
			if rc, n := c.run(w, m, 9, 2); rc != _wasiESUCCESS || n != 4 {
				t.Fatalf("error after a full buffer: rc=%d n=%d, want ESUCCESS 4", rc, n)
			}
			w.fdTable[9] = &wasiOpen{f: &scriptFile{steps: []ioStep{{3, failure}}}}
			if rc, n := c.run(w, m, 9, 2); rc != _wasiESUCCESS || n != 3 {
				t.Fatalf("error with a short count: rc=%d n=%d, want ESUCCESS 3", rc, n)
			}
			w.fdTable[9] = &wasiOpen{f: &scriptFile{steps: []ioStep{{0, failure}}}}
			if rc, n := c.run(w, m, 9, 2); rc != _wasiEIO || n != 0 {
				t.Fatalf("error with nothing transferred: rc=%d n=%d, want EIO 0", rc, n)
			}
		})
	}
}
