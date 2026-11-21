package codegen

import (
	"math"
	"os"
	"testing"
)

// Tests for the offsets and sizes fd_pread / fd_pwrite / fd_seek /
// fd_filestat_set_size / fd_allocate take from the guest, for a wasm32 and
// a memory64 guest.

// offsetCall is one of the bindings under test, called on fd with a
// 64-bit offset or size from the guest.
type offsetCall struct {
	name string
	call func(w *WasiStubs, m *Module, fd int32, offset uint64) int32
}

var preadPwriteCalls = []offsetCall{
	{"Fd_pread", func(w *WasiStubs, m *Module, fd int32, offset uint64) int32 {
		makeIovec(m, ioErrIov, ioErrBuf, 4)
		return w.Fd_pread(m, fd, ioErrIov, 1, int64(offset), ioErrResult)
	}},
	{"Fd_pread64", func(w *WasiStubs, m *Module, fd int32, offset uint64) int32 {
		makeIovec64(m, ioErrIov, ioErrBuf, 4)
		return w.Fd_pread64(m, int64(fd), ioErrIov, 1, int64(offset), ioErrResult)
	}},
	pwriteCalls[0],
	pwriteCalls[1],
}

var pwriteCalls = []offsetCall{
	{"Fd_pwrite", func(w *WasiStubs, m *Module, fd int32, offset uint64) int32 {
		makeIovec(m, ioErrIov, ioErrBuf, 4)
		return w.Fd_pwrite(m, fd, ioErrIov, 1, int64(offset), ioErrResult)
	}},
	{"Fd_pwrite64", func(w *WasiStubs, m *Module, fd int32, offset uint64) int32 {
		makeIovec64(m, ioErrIov, ioErrBuf, 4)
		return w.Fd_pwrite64(m, int64(fd), ioErrIov, 1, int64(offset), ioErrResult)
	}},
}

// openDataFile creates the file "f" holding "data" in fsys and installs it
// read-write as guest fd 9.
func openDataFile(t *testing.T, w *WasiStubs, fsys FS) File {
	t.Helper()
	f, err := fsys.OpenFile("f", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	w.fsys = fsys
	w.fdsLocked()[9] = &wasiOpen{f: f}
	return f
}

// wantSize fails t unless f is size bytes long.
func wantSize(t *testing.T, f File, size int64) {
	t.Helper()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != size {
		t.Fatalf("file size=%d, want %d", st.Size(), size)
	}
}

func TestWasi_PreadPwriteNegativeOffsetIsEINVAL(t *testing.T) {
	for _, c := range preadPwriteCalls {
		for name, fsys := range map[string]func(dir string) FS{
			"osFS":  func(dir string) FS { return osFS{root: dir} },
			"MemFS": func(string) FS { return NewMemFS() },
		} {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				w, m := newTestStubs(t, dir)
				f := openDataFile(t, w, fsys(dir))
				for _, offset := range []uint64{1 << 63, math.MaxUint64} {
					if rc := c.call(w, m, 9, offset); rc != _wasiEINVAL {
						t.Errorf("offset %#x: rc=%d, want EINVAL", offset, rc)
					}
				}
				wantSize(t, f, 4)
			})
		}
	}
}

func TestMemFS_ReadAtWriteAtNegativeOffsetIsEINVAL(t *testing.T) {
	w, _ := newTestStubs(t, t.TempDir())
	f := openDataFile(t, w, NewMemFS())
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, -1); mapOSError(err) != _wasiEINVAL {
		t.Errorf("ReadAt: err=%v, want EINVAL", err)
	}
	if _, err := f.WriteAt(buf, -1); mapOSError(err) != _wasiEINVAL {
		t.Errorf("WriteAt: err=%v, want EINVAL", err)
	}
	wantSize(t, f, 4)
}

func TestWasi_MemFSWritePastMaxSizeIsEFBIG(t *testing.T) {
	for _, c := range pwriteCalls {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			f := openDataFile(t, w, NewMemFS())
			for _, offset := range []uint64{memMaxFileSize - 3, 1 << 40, math.MaxInt64} {
				if rc := c.call(w, m, 9, offset); rc != _wasiEFBIG {
					t.Errorf("offset %#x: rc=%d, want EFBIG", offset, rc)
				}
			}
			wantSize(t, f, 4)
		})
	}
	t.Run("Fd_write", func(t *testing.T) {
		w, m := newTestStubs(t, t.TempDir())
		f := openDataFile(t, w, NewMemFS())
		if rc := w.Fd_seek(m, 9, 1<<40, 0, ioErrResult); rc != _wasiESUCCESS {
			t.Fatalf("seek rc=%d", rc)
		}
		makeIovec(m, ioErrIov, ioErrBuf, 4)
		if rc := w.Fd_write(m, 9, ioErrIov, 1, ioErrResult); rc != _wasiEFBIG {
			t.Fatalf("rc=%d, want EFBIG", rc)
		}
		wantSize(t, f, 4)
	})
}

func TestWasi_MemFSSeekBeforeStartIsEINVAL(t *testing.T) {
	seeks := []struct {
		name string
		call func(w *WasiStubs, m *Module, offset int64, whence int32) int32
	}{
		{"Fd_seek", func(w *WasiStubs, m *Module, offset int64, whence int32) int32 {
			return w.Fd_seek(m, 9, offset, whence, ioErrResult)
		}},
		{"Fd_seek64", func(w *WasiStubs, m *Module, offset int64, whence int32) int32 {
			return w.Fd_seek64(m, 9, offset, int64(whence), ioErrResult)
		}},
	}
	for _, s := range seeks {
		t.Run(s.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			openDataFile(t, w, NewMemFS())
			if rc := s.call(w, m, 2, 0); rc != _wasiESUCCESS {
				t.Fatalf("seek to 2: rc=%d", rc)
			}
			for _, c := range []struct {
				offset int64
				whence int32
			}{{-1, 0}, {-3, 1}, {-5, 2}, {math.MaxInt64, 1}} {
				if rc := s.call(w, m, c.offset, c.whence); rc != _wasiEINVAL {
					t.Errorf("seek %d whence %d: rc=%d, want EINVAL", c.offset, c.whence, rc)
				}
			}
			if rc := w.Fd_tell(m, 9, ioErrResult); rc != _wasiESUCCESS {
				t.Fatalf("tell rc=%d", rc)
			}
			if got := readU64(m.memory, ioErrResult); got != 2 {
				t.Fatalf("offset after failed seeks=%d, want 2", got)
			}
		})
	}
}

func TestWasi_MemFSTruncateOutOfRange(t *testing.T) {
	calls := []offsetCall{
		{"Fd_filestat_set_size", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
			return w.Fd_filestat_set_size(m, fd, int64(size))
		}},
		{"Fd_filestat_set_size64", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
			return w.Fd_filestat_set_size64(m, int64(fd), int64(size))
		}},
		{"Fd_allocate", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
			return w.Fd_allocate(m, fd, int64(size), 0)
		}},
		{"Fd_allocate64", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
			return w.Fd_allocate64(m, int64(fd), int64(size), 0)
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			f := openDataFile(t, w, NewMemFS())
			for size, want := range map[uint64]int32{
				1 << 63:            _wasiEINVAL,
				math.MaxUint64:     _wasiEINVAL,
				memMaxFileSize + 1: _wasiEFBIG,
				1 << 40:            _wasiEFBIG,
			} {
				if rc := c.call(w, m, 9, size); rc != want {
					t.Errorf("size %#x: rc=%d, want %d", size, rc, want)
				}
			}
			wantSize(t, f, 4)
		})
	}
}
