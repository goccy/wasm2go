package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Tests for the widened wasm64-wasip1 ABI bindings (the *64 method
// family): 8-byte guest pointers, LP64 iovec/prestat layouts, and
// 64-bit __wasi_size_t out-params. The layout constants asserted here
// are the contract with the wasm2go wasi-libc port's __wasi_abi_t.

// makeIovec64 writes a 1-entry LP64 iovec {u64 buf, u64 len} at iovOff.
func makeIovec64(m *Module, iovOff, bufOff, bufLen int64) {
	binary.LittleEndian.PutUint64(m.memory[iovOff:], uint64(bufOff))
	binary.LittleEndian.PutUint64(m.memory[iovOff+8:], uint64(bufLen))
}

func TestWasi64_MemSlice64Bounds(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if s := w.memSlice64(m, 0, int64(len(m.memory))); s == nil {
		t.Fatal("full-range slice refused")
	}
	if s := w.memSlice64(m, int64(len(m.memory))-1, 2); s != nil {
		t.Fatal("overrun not refused")
	}
	if s := w.memSlice64(m, -1, 1); s != nil {
		t.Fatal("negative offset not refused")
	}
	if s := w.memSlice64(m, 8, -1); s != nil {
		t.Fatal("negative length not refused")
	}
	// Offsets whose uint64 sum wraps must not slip past the bounds check.
	if s := w.memSlice64(m, -8, 16); s != nil {
		t.Fatal("wrapping range not refused")
	}
}

func TestWasi64_ArgsAndEnviron(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())

	// args_sizes_get: counts and buffer bytes as u64s.
	if rc := w.Args_sizes_get64(m, 0, 8); rc != _wasiESUCCESS {
		t.Fatalf("args_sizes_get64 rc=%d", rc)
	}
	if got := readU64(m.memory, 0); got != 3 {
		t.Fatalf("argc=%d want 3", got)
	}
	wantBuf := uint64(len("prog") + len("a") + len("b") + 3)
	if got := readU64(m.memory, 8); got != wantBuf {
		t.Fatalf("argv buf len=%d want %d", got, wantBuf)
	}

	// args_get: 8-byte pointer table + NUL-packed strings.
	if rc := w.Args_get64(m, 100, 200); rc != _wasiESUCCESS {
		t.Fatalf("args_get64 rc=%d", rc)
	}
	for i, want := range []string{"prog", "a", "b"} {
		p := readU64(m.memory, 100+i*8)
		end := bytes.IndexByte(m.memory[p:], 0)
		if got := string(m.memory[p : int(p)+end]); got != want {
			t.Fatalf("arg[%d]=%q want %q", i, got, want)
		}
	}

	// environ mirrors args.
	if rc := w.Environ_sizes_get64(m, 0, 8); rc != _wasiESUCCESS {
		t.Fatal("environ_sizes_get64 failed")
	}
	if got := readU64(m.memory, 0); got != 2 {
		t.Fatalf("envc=%d want 2", got)
	}
	if rc := w.Environ_get64(m, 300, 400); rc != _wasiESUCCESS {
		t.Fatal("environ_get64 failed")
	}
	p := readU64(m.memory, 300)
	end := bytes.IndexByte(m.memory[p:], 0)
	if got := string(m.memory[p : int(p)+end]); got != "FOO=bar" {
		t.Fatalf("env[0]=%q", got)
	}
}

func TestWasi64_ClockAndRandom(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if rc := w.Clock_time_get64(m, 1, 0, 64); rc != _wasiESUCCESS {
		t.Fatal("clock_time_get64 monotonic failed")
	}
	if rc := w.Clock_time_get64(m, 99, 0, 64); rc != _wasiEINVAL {
		t.Fatal("bad clock id not refused")
	}
	zero := make([]byte, 32)
	if rc := w.Random_get64(m, 128, 32); rc != _wasiESUCCESS {
		t.Fatal("random_get64 failed")
	}
	if bytes.Equal(m.memory[128:160], zero) {
		t.Fatal("random_get64 wrote nothing")
	}
	if rc := w.Random_get64(m, int64(len(m.memory)), 8); rc != _wasiEFAULT {
		t.Fatal("oob random buffer not refused")
	}
}

func TestWasi64_Prestat(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if rc := w.Fd_prestat_get64(m, 4, 0); rc != _wasiEBADF {
		t.Fatal("non-preopen fd not refused")
	}
	if rc := w.Fd_prestat_get64(m, 3, 0); rc != _wasiESUCCESS {
		t.Fatal("prestat_get64 failed")
	}
	// LP64 prestat: tag at 0, pr_name_len as u64 at offset 8.
	if m.memory[0] != 0 || readU64(m.memory, 8) != 1 {
		t.Fatalf("prestat layout: tag=%d len=%d", m.memory[0], readU64(m.memory, 8))
	}
	if rc := w.Fd_prestat_dir_name64(m, 3, 32, 4); rc != _wasiESUCCESS {
		t.Fatal("prestat_dir_name64 failed")
	}
	if m.memory[32] != '/' {
		t.Fatalf("dir name=%q", m.memory[32])
	}
}

func TestWasi64_OpenWriteSeekReadClose(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)

	pathOff, pathLen := putPath(m, 1024, "f.txt")
	// rights: FD_READ|FD_WRITE, oflags: O_CREAT.
	rc := w.Path_open64(m, 3, 0, int64(pathOff), int64(pathLen), 0x1, 1<<1|1<<6, 0, 0, 2048)
	if rc != _wasiESUCCESS {
		t.Fatalf("path_open64 rc=%d", rc)
	}
	fd := int64(readU32(m.memory, 2048))
	if fd < 4 {
		t.Fatalf("fd=%d", fd)
	}

	copy(m.memory[4096:], "wide pointers")
	makeIovec64(m, 3000, 4096, 13)
	if rc := w.Fd_write64(m, fd, 3000, 1, 3100); rc != _wasiESUCCESS {
		t.Fatal("fd_write64 failed")
	}
	if got := readU64(m.memory, 3100); got != 13 {
		t.Fatalf("nwritten=%d", got)
	}

	if rc := w.Fd_seek64(m, fd, 5, 0, 3200); rc != _wasiESUCCESS {
		t.Fatal("fd_seek64 failed")
	}
	if got := readU64(m.memory, 3200); got != 5 {
		t.Fatalf("seek pos=%d", got)
	}

	makeIovec64(m, 3300, 5000, 64)
	if rc := w.Fd_read64(m, fd, 3300, 1, 3400); rc != _wasiESUCCESS {
		t.Fatal("fd_read64 failed")
	}
	if got := readU64(m.memory, 3400); got != 8 {
		t.Fatalf("nread=%d want 8", got)
	}
	if got := string(m.memory[5000:5008]); got != "pointers" {
		t.Fatalf("read back %q", got)
	}

	if rc := w.Fd_fdstat_get64(m, fd, 3500); rc != _wasiESUCCESS {
		t.Fatal("fd_fdstat_get64 failed")
	}
	if filetype := m.memory[3500]; filetype != 4 { // regular file
		t.Fatalf("filetype=%d", filetype)
	}
	if rc := w.Fd_fdstat_set_flags64(m, fd, 0x1); rc != _wasiESUCCESS {
		t.Fatal("fd_fdstat_set_flags64 failed")
	}

	if rc := w.Fd_close64(m, fd); rc != _wasiESUCCESS {
		t.Fatal("fd_close64 failed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "f.txt"))
	if err != nil || string(data) != "wide pointers" {
		t.Fatalf("file content %q err=%v", data, err)
	}
}

func TestWasi64_ReaddirAndFilestat(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"alpha", "beta"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w, m := newTestStubs(t, dir)

	pathOff, pathLen := putPath(m, 1024, ".")
	rc := w.Path_open64(m, 3, 0, int64(pathOff), int64(pathLen), 0x2, 1<<1, 0, 0, 2048)
	if rc != _wasiESUCCESS {
		t.Fatalf("open dir rc=%d", rc)
	}
	fd := int64(readU32(m.memory, 2048))

	if rc := w.Fd_readdir64(m, fd, 8192, 1024, 0, 4096); rc != _wasiESUCCESS {
		t.Fatal("fd_readdir64 failed")
	}
	used := readU64(m.memory, 4096)
	if used == 0 || used > 1024 {
		t.Fatalf("bufused=%d", used)
	}
	// Walk dirents (24-byte header + name) and collect names.
	names := map[string]bool{}
	for off := uint64(8192); off < 8192+used; {
		namlen := uint64(readU32(m.memory, int(off)+16))
		names[string(m.memory[off+24:off+24+namlen])] = true
		off += 24 + namlen
	}
	for _, want := range []string{".", "..", "alpha", "beta"} {
		if !names[want] {
			t.Fatalf("missing dirent %q in %v", want, names)
		}
	}

	pathOff, pathLen = putPath(m, 1100, "alpha")
	if rc := w.Path_filestat_get64(m, 3, 0, int64(pathOff), int64(pathLen), 6000); rc != _wasiESUCCESS {
		t.Fatal("path_filestat_get64 failed")
	}
	if size := readU64(m.memory, 6000+32); size != 5 {
		t.Fatalf("filestat size=%d want 5", size)
	}
	if ft := m.memory[6000+16]; ft != 4 {
		t.Fatalf("filestat filetype=%d", ft)
	}
}

func TestWasi64_ProcExit(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	defer func() {
		r := recover()
		ee, ok := r.(*WasiExitError)
		if !ok || ee.Code != 7 {
			t.Fatalf("proc_exit64 panic=%v", r)
		}
	}()
	w.Proc_exit64(m, 7)
}
