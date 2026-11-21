package codegen

import (
	"math"
	"os"
	"testing"
)

// Tests for the offsets, sizes and whence fd_pread / fd_pwrite / fd_seek /
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
		for name, fsys := range testFSs {
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

func TestMemFS_InvalidOffsetsAndDirectories(t *testing.T) {
	w, _ := newTestStubs(t, t.TempDir())
	fsys := NewMemFS()
	f := openDataFile(t, w, fsys)
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, -1); mapOSError(err) != _wasiEINVAL {
		t.Errorf("ReadAt: err=%v, want EINVAL", err)
	}
	if _, err := f.WriteAt(buf, -1); mapOSError(err) != _wasiEINVAL {
		t.Errorf("WriteAt: err=%v, want EINVAL", err)
	}
	if _, err := f.Seek(0, 3); mapOSError(err) != _wasiEINVAL {
		t.Errorf("Seek whence 3: err=%v, want EINVAL", err)
	}
	wantSize(t, f, 4)

	if err := fsys.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := fsys.OpenFile("d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := d.Write(buf); mapOSError(err) != _wasiEISDIR {
		t.Errorf("Write on a directory: err=%v, want EISDIR", err)
	}
	if _, err := d.WriteAt(buf, 0); mapOSError(err) != _wasiEISDIR {
		t.Errorf("WriteAt on a directory: err=%v, want EISDIR", err)
	}
	if err := d.Truncate(1); mapOSError(err) != _wasiEISDIR {
		t.Errorf("Truncate on a directory: err=%v, want EISDIR", err)
	}
}

// testMaxFileSize is the file size limit of a newSmallMemFS.
const testMaxFileSize = 16

// newSmallMemFS returns a MemFS whose files can grow to testMaxFileSize.
func newSmallMemFS() *MemFS {
	fsys := NewMemFS()
	fsys.maxFileSize = testMaxFileSize
	return fsys
}

func TestWasi_MemFSWritePastMaxSizeIsEFBIG(t *testing.T) {
	for _, c := range pwriteCalls {
		t.Run(c.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			f := openDataFile(t, w, NewMemFS())
			for _, offset := range []uint64{memMaxFileSize, 1 << 40, math.MaxInt64} {
				if rc := c.call(w, m, 9, offset); rc != _wasiEFBIG {
					t.Errorf("offset %#x: rc=%d, want EFBIG", offset, rc)
				}
			}
			wantSize(t, f, 4)

			f = openDataFile(t, w, newSmallMemFS())
			for _, offset := range []uint64{testMaxFileSize, testMaxFileSize + 1} {
				if rc := c.call(w, m, 9, offset); rc != _wasiEFBIG {
					t.Errorf("offset %#x: rc=%d, want EFBIG", offset, rc)
				}
			}
			wantSize(t, f, 4)
			// A write across the limit writes the bytes below it.
			copy(m.memory[ioErrBuf:], "wxyz")
			if rc := c.call(w, m, 9, testMaxFileSize-3); rc != _wasiESUCCESS {
				t.Fatalf("write across the limit: rc=%d, want ESUCCESS", rc)
			}
			wantSize(t, f, testMaxFileSize)
			got := make([]byte, 3)
			if _, err := f.ReadAt(got, testMaxFileSize-3); err != nil {
				t.Fatal(err)
			}
			if string(got) != "wxy" {
				t.Fatalf("bytes below the limit=%q, want %q", got, "wxy")
			}
		})
	}
	t.Run("empty write past the limit", func(t *testing.T) {
		w, _ := newTestStubs(t, t.TempDir())
		f := openDataFile(t, w, newSmallMemFS())
		if n, err := f.WriteAt(nil, testMaxFileSize+1); n != 0 || err != nil {
			t.Fatalf("n=%d err=%v, want 0 and no error", n, err)
		}
		wantSize(t, f, 4)
	})
	t.Run("Fd_write", func(t *testing.T) {
		w, m := newTestStubs(t, t.TempDir())
		f := openDataFile(t, w, newSmallMemFS())
		if rc := w.Fd_seek(m, 9, testMaxFileSize, 0, ioErrResult); rc != _wasiESUCCESS {
			t.Fatalf("seek rc=%d", rc)
		}
		makeIovec(m, ioErrIov, ioErrBuf, 4)
		if rc := w.Fd_write(m, 9, ioErrIov, 1, ioErrResult); rc != _wasiEFBIG {
			t.Fatalf("rc=%d, want EFBIG", rc)
		}
		wantSize(t, f, 4)
	})
}

// testFSs makes each FS the cases below run on.
var testFSs = map[string]func(dir string) FS{
	"osFS":  func(dir string) FS { return osFS{root: dir} },
	"MemFS": func(string) FS { return NewMemFS() },
}

// seekCalls are fd_seek on fd 9, storing the new offset at ioErrResult.
var seekCalls = []struct {
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

func TestWasi_SeekOutOfRangeIsEINVAL(t *testing.T) {
	type seek struct {
		offset int64
		whence int32
	}
	for _, s := range seekCalls {
		for name, fsys := range testFSs {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				w, m := newTestStubs(t, dir)
				openDataFile(t, w, fsys(dir))
				if rc := s.call(w, m, 2, 0); rc != _wasiESUCCESS {
					t.Fatalf("seek to 2: rc=%d", rc)
				}
				cases := []seek{{-1, 0}, {-3, 1}, {-5, 2}, {0, 3}, {0, 4}, {0, -1}}
				if name == "MemFS" {
					cases = append(cases, seek{math.MaxInt64, 1})
				}
				for _, c := range cases {
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
}

func TestWasi_MemFSFileLargerThanLimit(t *testing.T) {
	content := "0123456789abcdefghijklmnopqrstuv"
	for _, s := range seekCalls {
		t.Run(s.name, func(t *testing.T) {
			w, m := newTestStubs(t, t.TempDir())
			fsys := newSmallMemFS()
			if err := fsys.WriteFile("big", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			f, err := fsys.OpenFile("big", os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			})
			w.fsys = fsys
			w.fdsLocked()[9] = &wasiOpen{f: f}
			for _, c := range []struct {
				offset int64
				whence int32
				want   uint64
			}{{0, 2, 32}, {-4, 1, 28}, {20, 0, 20}, {8, 1, 28}} {
				if rc := s.call(w, m, c.offset, c.whence); rc != _wasiESUCCESS {
					t.Fatalf("seek %d whence %d: rc=%d", c.offset, c.whence, rc)
				}
				if got := readU64(m.memory, ioErrResult); got != c.want {
					t.Fatalf("seek %d whence %d: offset=%d, want %d", c.offset, c.whence, got, c.want)
				}
			}
			makeIovec(m, ioErrIov, ioErrBuf, 8)
			for _, want := range []string{"stuv", ""} {
				if rc := w.Fd_read(m, 9, ioErrIov, 1, ioErrResult); rc != _wasiESUCCESS {
					t.Fatalf("read rc=%d", rc)
				}
				if got := string(m.memory[ioErrBuf : ioErrBuf+readU32(m.memory, ioErrResult)]); got != want {
					t.Fatalf("read %q, want %q", got, want)
				}
			}
			if rc := w.Fd_tell(m, 9, ioErrResult); rc != _wasiESUCCESS {
				t.Fatalf("tell rc=%d", rc)
			}
			if got := readU64(m.memory, ioErrResult); got != 32 {
				t.Fatalf("tell=%d, want 32", got)
			}
			wantSize(t, f, 32)
		})
	}
}

var setSizeCalls = []offsetCall{
	{"Fd_filestat_set_size", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
		return w.Fd_filestat_set_size(m, fd, int64(size))
	}},
	{"Fd_filestat_set_size64", func(w *WasiStubs, m *Module, fd int32, size uint64) int32 {
		return w.Fd_filestat_set_size64(m, int64(fd), int64(size))
	}},
}

func TestWasi_MemFSTruncateOutOfRange(t *testing.T) {
	for _, c := range setSizeCalls {
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

func TestWasi_SetSizeOfReadOnlyDescriptorIsEINVAL(t *testing.T) {
	for _, c := range setSizeCalls {
		for name, fsys := range testFSs {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				w, m := newTestStubs(t, dir)
				f := openDataFile(t, w, fsys(dir))
				w.fdsLocked()[9].noWrite = true
				if rc := c.call(w, m, 9, 2); rc != _wasiEINVAL {
					t.Errorf("rc=%d, want EINVAL", rc)
				}
				wantSize(t, f, 4)
			})
		}
	}
}

func TestWasi_FdAllocate(t *testing.T) {
	allocates := []struct {
		name string
		call func(w *WasiStubs, m *Module, offset, length int64) int32
	}{
		{"Fd_allocate", func(w *WasiStubs, m *Module, offset, length int64) int32 {
			return w.Fd_allocate(m, 9, offset, length)
		}},
		{"Fd_allocate64", func(w *WasiStubs, m *Module, offset, length int64) int32 {
			return w.Fd_allocate64(m, 9, offset, length)
		}},
	}
	type allocate struct {
		offset, length int64
		want           int32
	}
	for _, a := range allocates {
		for name, fsys := range testFSs {
			t.Run(a.name+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				w, m := newTestStubs(t, dir)
				f := openDataFile(t, w, fsys(dir))
				cases := []allocate{
					{-1, 4, _wasiEINVAL}, {0, 0, _wasiEINVAL}, {0, -1, _wasiEINVAL},
					{math.MaxInt64, 1, _wasiEFBIG},
					// a range inside the file leaves it as it is
					{0, 2, _wasiESUCCESS},
				}
				if name == "MemFS" {
					cases = append(cases, allocate{memMaxFileSize, 1, _wasiEFBIG})
				}
				for _, c := range cases {
					if rc := a.call(w, m, c.offset, c.length); rc != c.want {
						t.Errorf("allocate %d+%d: rc=%d, want %d", c.offset, c.length, rc, c.want)
					}
				}
				wantSize(t, f, 4)
				got := make([]byte, 4)
				if _, err := f.ReadAt(got, 0); err != nil {
					t.Fatal(err)
				}
				if string(got) != "data" {
					t.Fatalf("content=%q, want %q", got, "data")
				}
				if rc := a.call(w, m, 2, 6); rc != _wasiESUCCESS {
					t.Fatalf("allocate 2+6: rc=%d", rc)
				}
				wantSize(t, f, 8)
				w.fdsLocked()[9].noWrite = true
				if rc := a.call(w, m, 0, 16); rc != _wasiEBADF {
					t.Errorf("allocate on a read-only descriptor: rc=%d, want EBADF", rc)
				}
				if rc := a.call(w, m, -1, 16); rc != _wasiEINVAL {
					t.Errorf("allocate -1+16 on a read-only descriptor: rc=%d, want EINVAL", rc)
				}
				wantSize(t, f, 8)
			})
		}
	}
}
