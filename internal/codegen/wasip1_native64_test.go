package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Tests for the widened wasm64-wasip1 ABI bindings (the *64 method
// family): 8-byte guest pointers, LP64 iovec/prestat/argv layouts, and
// 64-bit __wasi_size_t out-params; that a *64 method takes the same paths
// as its wasm32 twin; and that an address is never truncated. The layout
// constants asserted here are the LP64 layouts a memory64 guest uses.

// makeIovec64 writes a 1-entry LP64 iovec {u64 buf, u64 len} at iovOff.
func makeIovec64(m *Module, iovOff, bufOff, bufLen int64) {
	binary.LittleEndian.PutUint64(m.memory[iovOff:], uint64(bufOff))
	binary.LittleEndian.PutUint64(m.memory[iovOff+8:], uint64(bufLen))
}

// highAddr is a guest address with a bit above 32 set, on a test memory of
// 64 KiB: truncated to 32 bits it would be the address 16.
const highAddr = 1<<32 + 16

// fillSentinel fills n bytes at off with 0xff, so that a test sees how many
// bytes a call wrote there.
func fillSentinel(m *Module, off, n int) {
	for i := 0; i < n; i++ {
		m.memory[off+i] = 0xff
	}
}

func TestWasi64_MemBytesBounds(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	size := uint64(len(m.memory))
	if s := w.memBytes(m, 0, size); s == nil {
		t.Fatal("full-range slice refused")
	}
	if s := w.memBytes(m, size, 0); s == nil || len(s) != 0 {
		t.Fatal("empty slice at the end of memory refused")
	}
	if s := w.memBytes(m, size-1, 2); s != nil {
		t.Fatal("overrun not refused")
	}
	if s := w.memBytes(m, size+1, 0); s != nil {
		t.Fatal("empty slice past the end not refused")
	}
	if s := w.memBytes(m, ^uint64(0), 1); s != nil {
		t.Fatal("address -1 not refused")
	}
	if s := w.memBytes(m, 8, ^uint64(0)); s != nil {
		t.Fatal("size -1 not refused")
	}
	// Ranges whose uint64 sum wraps must not slip past the bounds check.
	if s := w.memBytes(m, ^uint64(0)-7, 16); s != nil {
		t.Fatal("wrapping range not refused")
	}
	// Bits above 32 are never dropped: neither the address nor the size
	// aliases the low memory they would truncate to.
	if s := w.memBytes(m, highAddr, 4); s != nil {
		t.Fatal("address above 4 GiB not refused")
	}
	if s := w.memBytes(m, 16, 1<<32+4); s != nil {
		t.Fatal("size above 4 GiB not refused")
	}
	// A wasm32 binding's i32 is unsigned: memSlice zero-extends it.
	if s := w.memSlice(m, -1, 1); s != nil {
		t.Fatal("wasm32 address 0xffffffff not refused")
	}
	if s := w.memSlice(m, 8, -1); s != nil {
		t.Fatal("wasm32 size 0xffffffff not refused")
	}
	if got := zext(-2); got != 0xfffffffe {
		t.Fatalf("zext(-2) = %#x", got)
	}
}

func TestWasi64_ABIWords(t *testing.T) {
	b := make([]byte, 8)
	for i := range b {
		b[i] = 0xff
	}
	wasiABI32.putWord(b, 0x1_2345_6789)
	if got := binary.LittleEndian.Uint32(b); got != 0x2345_6789 || b[4] != 0xff {
		t.Fatalf("wasm32 word written as % x", b)
	}
	if got := wasiABI32.word(b); got != 0x2345_6789 {
		t.Fatalf("wasm32 word read as %#x", got)
	}
	wasiABI64.putWord(b, 0x1_2345_6789)
	if got := wasiABI64.word(b); got != 0x1_2345_6789 {
		t.Fatalf("memory64 word read as %#x", got)
	}
	if wasiABI32.wordSize() != 4 || wasiABI64.wordSize() != 8 {
		t.Fatal("word sizes")
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

	// bufused is a u64: all of its 8 bytes are written.
	fillSentinel(m, 4096, 8)
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

func TestWasi64_PrestatLayoutsByABI(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	// wasm32: {u8 tag, pad[3], u32 len} — 8 bytes.
	fillSentinel(m, 0, 16)
	if rc := w.Fd_prestat_get(m, 3, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_prestat_get rc=%d", rc)
	}
	if m.memory[0] != 0 || readU32(m.memory, 4) != 1 || m.memory[8] != 0xff {
		t.Fatalf("wasm32 prestat % x", m.memory[:16])
	}
	// memory64: {u8 tag, pad[7], u64 len} — 16 bytes.
	fillSentinel(m, 0, 24)
	if rc := w.Fd_prestat_get64(m, 3, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_prestat_get64 rc=%d", rc)
	}
	if m.memory[0] != 0 || readU64(m.memory, 8) != 1 || m.memory[16] != 0xff {
		t.Fatalf("memory64 prestat % x", m.memory[:24])
	}
}

// putIovecs64 writes LP64 iovecs {u64 buf, u64 len} for bufs (offset,
// length pairs) at iovOff, 16 bytes apart.
func putIovecs64(m *Module, iovOff int, bufs ...[2]uint64) {
	for i, b := range bufs {
		binary.LittleEndian.PutUint64(m.memory[iovOff+16*i:], b[0])
		binary.LittleEndian.PutUint64(m.memory[iovOff+16*i+8:], b[1])
	}
}

func TestWasi64_IovecsAndCountsAreLP64(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	pathOff, pathLen := putPath(m, 1024, "v.txt")
	if rc := w.Path_open64(m, 3, 0, int64(pathOff), int64(pathLen), 0x1, 1<<1|1<<6, 0, 0, 2048); rc != _wasiESUCCESS {
		t.Fatalf("path_open64 rc=%d", rc)
	}
	fd := int64(readU32(m.memory, 2048))

	// Two iovecs 16 bytes apart gather "scatter" and "-gather".
	copy(m.memory[4096:], "scatter")
	copy(m.memory[4200:], "-gather")
	putIovecs64(m, 3000, [2]uint64{4096, 7}, [2]uint64{4200, 7})
	fillSentinel(m, 3100, 8)
	if rc := w.Fd_write64(m, fd, 3000, 2, 3100); rc != _wasiESUCCESS {
		t.Fatalf("fd_write64 rc=%d", rc)
	}
	if got := readU64(m.memory, 3100); got != 14 {
		t.Fatalf("nwritten=%#x, want 14 in all 8 bytes", got)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "v.txt")); err != nil || string(got) != "scatter-gather" {
		t.Fatalf("file holds %q, err=%v", got, err)
	}

	// Reading back scatters over two iovecs; nread is 8 bytes.
	if rc := w.Fd_seek64(m, fd, 0, 0, 3200); rc != _wasiESUCCESS {
		t.Fatalf("fd_seek64 rc=%d", rc)
	}
	putIovecs64(m, 3300, [2]uint64{5000, 4}, [2]uint64{5100, 32})
	fillSentinel(m, 3400, 8)
	if rc := w.Fd_read64(m, fd, 3300, 2, 3400); rc != _wasiESUCCESS {
		t.Fatalf("fd_read64 rc=%d", rc)
	}
	if got := readU64(m.memory, 3400); got != 14 {
		t.Fatalf("nread=%#x, want 14 in all 8 bytes", got)
	}
	if got := string(m.memory[5000:5004]) + string(m.memory[5100:5110]); got != "scatter-gather" {
		t.Fatalf("read back %q", got)
	}
}

// fd_pread and fd_pwrite take LP64 iovecs and write a 64-bit nread and
// nwritten for a memory64 guest; the wasm32 twins keep 8-byte iovecs and a
// 4-byte count, and leave the bytes after it alone.
func TestWasi64_PreadPwriteAreLP64(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	pathOff, pathLen := putPath(m, 1024, "p.txt")
	if rc := w.Path_open64(m, 3, 0, int64(pathOff), int64(pathLen), 0x1, 1<<1|1<<6, 0, 0, 2048); rc != _wasiESUCCESS {
		t.Fatalf("path_open64 rc=%d", rc)
	}
	fd := int64(readU32(m.memory, 2048))

	copy(m.memory[4096:], "scatter")
	copy(m.memory[4200:], "-gather")
	putIovecs64(m, 3000, [2]uint64{4096, 7}, [2]uint64{4200, 7})
	fillSentinel(m, 3100, 8)
	if rc := w.Fd_pwrite64(m, fd, 3000, 2, 2, 3100); rc != _wasiESUCCESS {
		t.Fatalf("fd_pwrite64 rc=%d", rc)
	}
	if got := readU64(m.memory, 3100); got != 14 {
		t.Fatalf("nwritten=%#x, want 14 in all 8 bytes", got)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "p.txt")); err != nil || string(got) != "\x00\x00scatter-gather" {
		t.Fatalf("file holds %q, err=%v", got, err)
	}

	putIovecs64(m, 3300, [2]uint64{5000, 4}, [2]uint64{5100, 32})
	fillSentinel(m, 3400, 8)
	if rc := w.Fd_pread64(m, fd, 3300, 2, 2, 3400); rc != _wasiESUCCESS {
		t.Fatalf("fd_pread64 rc=%d", rc)
	}
	if got := readU64(m.memory, 3400); got != 14 {
		t.Fatalf("nread=%#x, want 14 in all 8 bytes", got)
	}
	if got := string(m.memory[5000:5004]) + string(m.memory[5100:5110]); got != "scatter-gather" {
		t.Fatalf("read back %q", got)
	}

	// The wasm32 twin: {u32 buf, u32 len} iovecs, a u32 count.
	binary.LittleEndian.PutUint32(m.memory[3500:], 6000)
	binary.LittleEndian.PutUint32(m.memory[3504:], 7)
	fillSentinel(m, 3600, 8)
	if rc := w.Fd_pread(m, int32(fd), 3500, 1, 9, 3600); rc != _wasiESUCCESS {
		t.Fatalf("fd_pread rc=%d", rc)
	}
	if got := readU32(m.memory, 3600); got != 7 || readU32(m.memory, 3604) != 0xffffffff {
		t.Fatalf("wasm32 nread % x, want 7 in 4 bytes and the next 4 untouched", m.memory[3600:3608])
	}
	if got := string(m.memory[6000:6007]); got != "-gather" {
		t.Fatalf("wasm32 read back %q", got)
	}
	fillSentinel(m, 3700, 8)
	if rc := w.Fd_pwrite(m, int32(fd), 3500, 1, 16, 3700); rc != _wasiESUCCESS {
		t.Fatalf("fd_pwrite rc=%d", rc)
	}
	if got := readU32(m.memory, 3700); got != 7 || readU32(m.memory, 3704) != 0xffffffff {
		t.Fatalf("wasm32 nwritten % x, want 7 in 4 bytes and the next 4 untouched", m.memory[3700:3708])
	}
}

func TestWasi64_ReadlinkBufusedIsLP64(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("target-of-link", filepath.Join(dir, "ln")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	w, m := newTestStubs(t, dir)
	pathOff, pathLen := putPath(m, 1024, "ln")
	fillSentinel(m, 800, 8)
	if rc := w.Path_readlink64(m, 3, int64(pathOff), int64(pathLen), 512, 64, 800); rc != _wasiESUCCESS {
		t.Fatalf("path_readlink64 rc=%d", rc)
	}
	if got := readU64(m.memory, 800); got != uint64(len("target-of-link")) {
		t.Fatalf("bufused=%#x, want %d in all 8 bytes", got, len("target-of-link"))
	}
	if got := string(m.memory[512 : 512+len("target-of-link")]); got != "target-of-link" {
		t.Fatalf("target %q", got)
	}
}

func TestWasi64_PollNeventsIsLP64(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	// One clock subscription that is due at once: the subscription (48
	// bytes) and the event (32 bytes) are as for wasm32, nevents is a u64.
	writeSubClock(m, 1024, 0xabcdef, 0)
	fillSentinel(m, 1200, 8)
	if rc := w.Poll_oneoff64(m, 1024, 2048, 1, 1200); rc != _wasiESUCCESS {
		t.Fatalf("poll_oneoff64 rc=%d", rc)
	}
	if got := readU64(m.memory, 1200); got != 1 {
		t.Fatalf("nevents=%#x, want 1 in all 8 bytes", got)
	}
	if ud := readU64(m.memory, 2048); ud != 0xabcdef {
		t.Fatalf("event userdata=%#x", ud)
	}
	if errno, etype := binary.LittleEndian.Uint16(m.memory[2056:]), binary.LittleEndian.Uint16(m.memory[2058:]); errno != 0 || etype != 0 {
		t.Fatalf("event errno=%d type=%d", errno, etype)
	}
	// A count whose arrays cannot fit faults instead of wrapping.
	if rc := w.Poll_oneoff64(m, 1024, 2048, 1<<60, 1200); rc != _wasiEFAULT {
		t.Fatalf("poll_oneoff64 with 2^60 subscriptions rc=%d, want EFAULT", rc)
	}
}

// fdRead64String reads up to n bytes from fd through Fd_read64.
func fdRead64String(w *WasiStubs, m *Module, fd int32, n int) (string, int32) {
	putIovecs64(m, 6000, [2]uint64{6200, uint64(n)})
	rc := w.Fd_read64(m, int64(fd), 6000, 1, 6100)
	if rc != _wasiESUCCESS {
		return "", rc
	}
	got := readU64(m.memory, 6100)
	return string(m.memory[6200 : 6200+got]), rc
}

// fdWrite64String writes s to fd through Fd_write64.
func fdWrite64String(w *WasiStubs, m *Module, fd int32, s string) (uint64, int32) {
	copy(m.memory[6300:], s)
	putIovecs64(m, 6000, [2]uint64{6300, uint64(len(s))})
	rc := w.Fd_write64(m, int64(fd), 6000, 1, 6100)
	return readU64(m.memory, 6100), rc
}

// Fd_read64 waits on a pipe as Fd_read does: until input arrives, and no
// longer than until a signal is posted (EINTR); a non-blocking one reports
// EAGAIN.
func TestWasi64_FdReadWaitsOnAPipeAsFdRead(t *testing.T) {
	w, m := newProcTestStubs(t)
	if rc := w.Proc_signal_register64(m, int64(sigFlagOff)); rc != 0 {
		t.Fatalf("proc_signal_register64 rc=%d", rc)
	}
	if rc := w.Proc_signal_dispositions64(m, int64(signalMask(wasiSIGUSR1)), 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("proc_signal_dispositions64 rc=%d", rc)
	}
	readFd, writeFd := newTestPipe(t, w, m)
	read := func() (got string, rc int32) {
		returnsWithin(t, "fd_read64", func() { got, rc = fdRead64String(w, m, readFd, 16) })
		return got, rc
	}

	postWhenBlocked(w, wasiSIGUSR1)
	if _, rc := read(); rc != _wasiEINTR {
		t.Fatalf("read of an idle pipe rc=%d, want EINTR", rc)
	}
	if rc := w.Proc_signal_take64(m, int64(sigMaskOff)); rc != _wasiESUCCESS || readU64(m.memory, int(sigMaskOff)) != signalMask(wasiSIGUSR1) {
		t.Fatalf("proc_signal_take64 rc=%d mask=%#x", rc, readU64(m.memory, int(sigMaskOff)))
	}

	go func() {
		time.Sleep(30 * time.Millisecond)
		if n, rc := fdWrite64String(w, newForkTestModule(), writeFd, "late"); rc != _wasiESUCCESS || n != 4 {
			t.Errorf("fd_write64 = %d bytes rc=%d", n, rc)
		}
	}()
	if got, rc := read(); rc != _wasiESUCCESS || got != "late" {
		t.Fatalf("read = %q rc=%d, want %q", got, rc, "late")
	}

	if rc := w.Fd_fdstat_set_flags64(m, int64(readFd), int64(wasiFdflagNonblock)); rc != _wasiESUCCESS {
		t.Fatalf("fd_fdstat_set_flags64 rc=%d", rc)
	}
	if _, rc := read(); rc != _wasiEAGAIN {
		t.Fatalf("non-blocking read of an idle pipe rc=%d, want EAGAIN", rc)
	}
}

// A guest address with a bit above 32 set is outside a small memory: every
// binding refuses it with EFAULT instead of using the low address it would
// truncate to, and writes nothing.
func TestWasi64_AddressesAboveTheMemoryAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	fd, errno := w.pathOpen("f", 0, 0, 1<<1|1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open: %d", errno)
	}
	putPath(m, 900, "f")
	// iovecs in low memory whose buffer or length has a bit above 32 set
	putIovecs64(m, 1024, [2]uint64{highAddr, 4})
	putIovecs64(m, 1056, [2]uint64{16, 1<<32 + 4})
	for i := 16; i < 32; i++ {
		m.memory[i] = byte(i)
	}

	for _, tc := range []struct {
		name string
		call func() int32
		want int32
	}{
		{"clock_time_get", func() int32 { return w.Clock_time_get64(m, 0, 0, highAddr) }, _wasiEFAULT},
		{"random_get size", func() int32 { return w.Random_get64(m, 16, 1<<32+4) }, _wasiEFAULT},
		{"args_get buffer", func() int32 { return w.Args_get64(m, 256, highAddr) }, _wasiEFAULT},
		{"args_sizes_get", func() int32 { return w.Args_sizes_get64(m, highAddr, 256) }, _wasiEFAULT},
		{"fd_prestat_get", func() int32 { return w.Fd_prestat_get64(m, 3, highAddr) }, _wasiEFAULT},
		{"fd_write iovecs", func() int32 { return w.Fd_write64(m, int64(fd), highAddr, 1, 512) }, _wasiEFAULT},
		{"fd_write buffer", func() int32 { return w.Fd_write64(m, int64(fd), 1024, 1, 512) }, _wasiEFAULT},
		{"fd_write length", func() int32 { return w.Fd_write64(m, int64(fd), 1056, 1, 512) }, _wasiEFAULT},
		{"fd_write count", func() int32 { return w.Fd_write64(m, int64(fd), 1056, 0, highAddr) }, _wasiEFAULT},
		{"fd_read buffer", func() int32 { return w.Fd_read64(m, int64(fd), 1024, 1, 512) }, _wasiEFAULT},
		{"fd_read count", func() int32 { return w.Fd_read64(m, int64(fd), 1056, 0, highAddr) }, _wasiEFAULT},
		{"path_open path", func() int32 { return w.Path_open64(m, 3, 0, highAddr, 1, 0, 1<<1, 0, 0, 512) }, _wasiEFAULT},
		{"path_open path length", func() int32 { return w.Path_open64(m, 3, 0, 900, 1<<32+1, 0, 1<<1, 0, 0, 512) }, _wasiEFAULT},
		{"poll_oneoff", func() int32 { return w.Poll_oneoff64(m, highAddr, 512, 1, 600) }, _wasiEFAULT},
		{"fd_filestat_ext", func() int32 { return w.Fd_filestat_ext64(m, fd, highAddr) }, -_wasiEFAULT},
		{"path_filestat_ext", func() int32 { return w.Path_filestat_ext64(m, highAddr, 1, 1, 512) }, -_wasiEFAULT},
		{"path_filestat_mode", func() int32 { return w.Path_filestat_mode64(m, 900, 1, 1, highAddr) }, -_wasiEFAULT},
		{"path_chmod", func() int32 { return w.Path_chmod64(m, highAddr, 1, 0o600) }, -_wasiEFAULT},
		{"path_chown", func() int32 { return w.Path_chown64(m, highAddr, 1, -1, -1, 1) }, -_wasiEFAULT},
		{"fd_path needed", func() int32 { return w.Fd_path64(m, 3, 512, 64, highAddr) }, -_wasiEFAULT},
		{"proc_wait", func() int32 { return w.Proc_wait64(m, 1000, 1, highAddr) }, -_wasiEFAULT},
		{"proc_wait_any pid", func() int32 { return w.Proc_wait_any64(m, 1, highAddr, 512) }, -_wasiEFAULT},
		{"proc_wait_any status", func() int32 { return w.Proc_wait_any64(m, 1, 512, highAddr) }, -_wasiEFAULT},
		{"path_open_mode path", func() int32 { return w.Path_open_mode64(m, 0, highAddr, 1, 0, 1<<1, 0, 0o600, 512) }, -_wasiEFAULT},
		{"path_open_mode fd", func() int32 { return w.Path_open_mode64(m, 0, 900, 1, 0, 1<<1, 0, 0o600, highAddr) }, -_wasiEFAULT},
		{"path_create_directory_mode", func() int32 { return w.Path_create_directory_mode64(m, highAddr, 1, 0o700) }, -_wasiEFAULT},
		{"proc_ids", func() int32 { return w.Proc_ids64(m, highAddr) }, -_wasiEFAULT},
		{"proc_times", func() int32 { return w.Proc_times64(m, highAddr) }, -_wasiEFAULT},
		{"proc_signal_register", func() int32 { return w.Proc_signal_register64(m, highAddr) }, -_wasiEFAULT},
		{"proc_groups", func() int32 { return w.Proc_groups64(m, 512, 0, highAddr) }, -_wasiEFAULT},
		{"proc_setgroups", func() int32 { return w.Proc_setgroups64(m, highAddr, 1) }, -_wasiEFAULT},
		{"proc_priority", func() int32 { return w.Proc_priority64(m, 0, 0, 0, 0, highAddr) }, -_wasiEFAULT},
		{"proc_user_by_name", func() int32 { return w.Proc_user_by_name64(m, highAddr, 1, 512, 64, 600) }, -_wasiEFAULT},
		{"proc_group_by_name", func() int32 { return w.Proc_group_by_name64(m, highAddr, 1, 512, 64, 600) }, -_wasiEFAULT},
		{"sock_service", func() int32 { return w.Sock_service64(m, highAddr, 1, 0, 0, 900, 0, 512, 64, 600) }, -_wasiEFAULT},
		{"proc_syslog_open", func() int32 { return w.Proc_syslog_open64(m, highAddr, 1, 0, 1) }, -_wasiEFAULT},
		{"proc_syslog", func() int32 { return w.Proc_syslog64(m, 6, 1, 0, 900, 0, highAddr, 1) }, -_wasiEFAULT},
		{"path_access", func() int32 { return w.Path_access64(m, highAddr, 1, 0, 0) }, -_wasiEFAULT},
		{"path_mkfifo", func() int32 { return w.Path_mkfifo64(m, highAddr, 1, 0o600) }, -_wasiEFAULT},
		{"fd_lock", func() int32 { return w.Fd_lock64(m, fd, 0, highAddr) }, -_wasiEFAULT},
		{"sock_getopt", func() int32 { return w.Sock_getopt64(m, fd, 1, highAddr) }, -_wasiEFAULT},
		{"sock_timeout", func() int32 { return w.Sock_timeout64(m, fd, 1, 0, 0, highAddr) }, -_wasiEFAULT},
	} {
		before := bytes.Clone(m.memory)
		if got := tc.call(); got != tc.want {
			t.Errorf("%s: rc=%d, want %d", tc.name, got, tc.want)
		}
		if !bytes.Equal(before, m.memory) {
			t.Errorf("%s: wrote to guest memory", tc.name)
		}
	}
	// A record's size is written before the record: the size lands, the
	// record at the high address does not land at the low one.
	before := bytes.Clone(m.memory)
	if rc := w.Fd_path64(m, 3, highAddr, 64, 512); rc != -_wasiEFAULT {
		t.Errorf("fd_path record: rc=%d, want %d", rc, -_wasiEFAULT)
	}
	if !bytes.Equal(before[:512], m.memory[:512]) || readU32(m.memory, 512) != 1 {
		t.Errorf("fd_path record: memory % x, size %d", m.memory[16:32], readU32(m.memory, 512))
	}
	if got, err := os.ReadFile(filepath.Join(dir, "f")); err != nil || string(got) != "data" {
		t.Fatalf("the file holds %q after the refused writes, err=%v", got, err)
	}
}

// For an import whose records hold no pointer, the *64 method does exactly
// what the wasm32 one does: the same result and the same bytes in guest
// memory, from the same state.
func TestWasi64_NeutralImportsMatchTheirWasm32Twin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	// prep runs on both instances before the call; it returns the fd of
	// f.txt, opened for reading and writing.
	prep := func(t *testing.T, w *WasiStubs, m *Module) int32 {
		t.Helper()
		w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
		fd, errno := w.pathOpen("f.txt", 0, 0, 1<<1|1<<6, 0)
		if errno != _wasiESUCCESS {
			t.Fatalf("open: %d", errno)
		}
		putPath(m, 512, "f.txt")
		putPath(m, 544, "UTC")
		return fd
	}
	type call func(w *WasiStubs, m *Module, fd int32) int32
	for _, tc := range []struct {
		name           string
		call32, call64 call
	}{
		{"clock_res_get",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Clock_res_get(m, 0, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Clock_res_get64(m, 0, 1024) }},
		{"fd_fdstat_get",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_fdstat_get(m, fd, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_fdstat_get64(m, int64(fd), 1024) }},
		{"fd_filestat_get",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_filestat_get(m, fd, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_filestat_get64(m, int64(fd), 1024) }},
		{"fd_seek and fd_tell",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_seek(m, fd, 3, 0, 1024) | w.Fd_tell(m, fd, 1040)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_seek64(m, int64(fd), 3, 0, 1024) | w.Fd_tell64(m, int64(fd), 1040)
			}},
		{"fd_prestat_dir_name",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_prestat_dir_name(m, 3, 1024, 4) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_prestat_dir_name64(m, 3, 1024, 4) }},
		{"path_filestat_get",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_get(m, 3, 1, 512, 5, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_get64(m, 3, 1, 512, 5, 1024) }},
		{"path_open",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_open(m, 3, 0, 512, 5, 0, 1<<1, 0, 0, 1024)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_open64(m, 3, 0, 512, 5, 0, 1<<1, 0, 0, 1024)
			}},
		{"random_get of nothing",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Random_get(m, 1024, 0) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Random_get64(m, 1024, 0) }},
		{"fd_advise, fd_allocate, fd_datasync and fd_fdstat_set_rights",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_advise(m, fd, 0, 8, 0) | w.Fd_allocate(m, fd, 0, 8) | w.Fd_datasync(m, fd) |
					w.Fd_fdstat_set_rights(m, fd, 1<<1, 0)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_advise64(m, int64(fd), 0, 8, 0) | w.Fd_allocate64(m, int64(fd), 0, 8) |
					w.Fd_datasync64(m, int64(fd)) | w.Fd_fdstat_set_rights64(m, int64(fd), 1<<1, 0)
			}},
		{"path_create_directory of a name that is taken",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_create_directory(m, 3, 512, 5) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_create_directory64(m, 3, 512, 5) }},
		{"path_filestat_mode",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_mode(m, 512, 5, 1, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_mode64(m, 512, 5, 1, 1024) }},
		{"fd_filestat_ext",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_filestat_ext(m, fd, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_filestat_ext64(m, fd, 1024) }},
		{"path_filestat_ext",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_ext(m, 512, 5, 1, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Path_filestat_ext64(m, 512, 5, 1, 1024) }},
		{"path_chmod and fd_chmod",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_chmod(m, 512, 5, 0o644) | w.Fd_chmod(m, fd, 0o644)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_chmod64(m, 512, 5, 0o644) | w.Fd_chmod64(m, fd, 0o644)
			}},
		{"path_chown and fd_chown of nothing",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_chown(m, 512, 5, -1, -1, 1) | w.Fd_chown(m, fd, -1, -1)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_chown64(m, 512, 5, -1, -1, 1) | w.Fd_chown64(m, fd, -1, -1)
			}},
		{"fd_path",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_path(m, 3, 2048, 64, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_path64(m, 3, 2048, 64, 1024) }},
		{"proc_wait and proc_wait_any of no process",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_wait(m, 1000, 0, 1024) | w.Proc_wait_any(m, 0, 1024, 1028)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_wait64(m, 1000, 0, 1024) | w.Proc_wait_any64(m, 0, 1024, 1028)
			}},
		{"proc_umask, path_open_mode and path_create_directory_mode",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_umask(m, 0o22) | w.Path_open_mode(m, 0, 512, 5, 0, 1<<1, 0, 0o600, 1024) |
					w.Path_create_directory_mode(m, 512, 5, 0o700)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_umask64(m, 0o22) | w.Path_open_mode64(m, 0, 512, 5, 0, 1<<1, 0, 0o600, 1024) |
					w.Path_create_directory_mode64(m, 512, 5, 0o700)
			}},
		{"proc_ids",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Proc_ids(m, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Proc_ids64(m, 1024) }},
		{"proc_itimer",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Proc_itimer(m, 0, 0, 0, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Proc_itimer64(m, 0, 0, 0, 1024) }},
		{"proc_signal_register and proc_signal_take",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_signal_register(m, 1024) | w.Proc_signal_take(m, 1032)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_signal_register64(m, 1024) | w.Proc_signal_take64(m, 1032)
			}},
		{"proc_groups, proc_setids, proc_setgroups and proc_priority",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_groups(m, 1024, 4, 1040) | w.Proc_setids(m, 0, 0, -1, -1) | w.Proc_setgroups(m, 1024, 0) |
					w.Proc_priority(m, 0, 0, 0, 0, 1044)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_groups64(m, 1024, 4, 1040) | w.Proc_setids64(m, 0, 0, -1, -1) | w.Proc_setgroups64(m, 1024, 0) |
					w.Proc_priority64(m, 0, 0, 0, 0, 1044)
			}},
		{"user, group, uname, service and number lookups of nothing",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_user_by_id(m, 0, 1024, 64, 1100) | w.Proc_user_by_name(m, 512, 5, 1024, 64, 1100) |
					w.Proc_user_at(m, 0, 1024, 64, 1100) | w.Proc_group_by_id(m, 0, 1024, 64, 1100) |
					w.Proc_group_by_name(m, 512, 5, 1024, 64, 1100) | w.Proc_group_at(m, 0, 1024, 64, 1100) |
					w.Proc_uname(m, 1024, 64, 1100) | w.Sock_service(m, 512, 5, 0, 0, 512, 0, 1024, 64, 1100) |
					w.Host_numbering(m) | w.Host_number_at(m, 1, 0, 1024, 16, 1100, 1104)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_user_by_id64(m, 0, 1024, 64, 1100) | w.Proc_user_by_name64(m, 512, 5, 1024, 64, 1100) |
					w.Proc_user_at64(m, 0, 1024, 64, 1100) | w.Proc_group_by_id64(m, 0, 1024, 64, 1100) |
					w.Proc_group_by_name64(m, 512, 5, 1024, 64, 1100) | w.Proc_group_at64(m, 0, 1024, 64, 1100) |
					w.Proc_uname64(m, 1024, 64, 1100) | w.Sock_service64(m, 512, 5, 0, 0, 512, 0, 1024, 64, 1100) |
					w.Host_numbering64(m) | w.Host_number_at64(m, 1, 0, 1024, 16, 1100, 1104)
			}},
		{"syslog without a logger",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_syslog_open(m, 512, 5, 0, 1) | w.Proc_syslog(m, 6, 1, 0, 512, 5, 512, 5) | w.Proc_syslog_close(m)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Proc_syslog_open64(m, 512, 5, 0, 1) | w.Proc_syslog64(m, 6, 1, 0, 512, 5, 512, 5) | w.Proc_syslog_close64(m)
			}},
		{"path_access, path_mkfifo, fd_flock and fd_lock",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_access(m, 512, 5, 4, 0) | w.Path_mkfifo(m, 512, 5, 0o600) | w.Fd_flock(m, fd, 1, 0) |
					w.Fd_lock(m, fd, recordLockGet, 1024)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Path_access64(m, 512, 5, 4, 0) | w.Path_mkfifo64(m, 512, 5, 0o600) | w.Fd_flock64(m, fd, 1, 0) |
					w.Fd_lock64(m, fd, recordLockGet, 1024)
			}},
		{"fd_ioctl of no terminal",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_ioctl(m, fd, linuxTIOCGWINSZ, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Fd_ioctl64(m, fd, linuxTIOCGWINSZ, 1024) }},
		{"pipe",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Pipe(m, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Pipe64(m, 1024) }},
		{"fd_dup and fd_cloexec",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_dup(m, fd, 1024) | w.Fd_cloexec(m, fd, 1, 1, 1028) | w.Fd_cloexec(m, fd, 0, 0, 1032)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_dup64(m, fd, 1024) | w.Fd_cloexec64(m, fd, 1, 1, 1028) | w.Fd_cloexec64(m, fd, 0, 0, 1032)
			}},
		{"fd_dupfd, fd_dup2 and fd_closefrom",
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_dupfd(m, fd, 10, 1024) | w.Fd_dup2(m, fd, 12) | w.Fd_closefrom(m, 11) | w.Fd_fdstat_get(m, 10, 1040)
			},
			func(w *WasiStubs, m *Module, fd int32) int32 {
				return w.Fd_dupfd64(m, fd, 10, 1024) | w.Fd_dup264(m, fd, 12) | w.Fd_closefrom64(m, 11) | w.Fd_fdstat_get64(m, 10, 1040)
			}},
		{"clock_zone",
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Clock_zone(m, 544, 3, 1, 86400, 0, 1024) },
			func(w *WasiStubs, m *Module, fd int32) int32 { return w.Clock_zone64(m, 544, 3, 1, 86400, 0, 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w32, m32 := newTestStubs(t, dir)
			w64, m64 := newTestStubs(t, dir)
			fd32, fd64 := prep(t, w32, m32), prep(t, w64, m64)
			rc32, rc64 := tc.call32(w32, m32, fd32), tc.call64(w64, m64, fd64)
			if rc32 != rc64 {
				t.Fatalf("rc %d (wasm32) != %d (memory64)", rc32, rc64)
			}
			t.Logf("rc=%d", rc32)
			for i := range m32.memory {
				if m32.memory[i] != m64.memory[i] {
					t.Fatalf("guest memory differs first at %d: %#x (wasm32) != %#x (memory64)", i, m32.memory[i], m64.memory[i])
				}
			}
		})
	}
}

// An iovec array of more than wasiMaxIovecs entries is refused with EFAULT
// for both ABIs, even when the guest's memory holds all of it; one of
// exactly wasiMaxIovecs entries is taken.
func TestWasi64_IovecCountIsBounded(t *testing.T) {
	w, _ := newTestStubs(t, t.TempDir())
	w.cfg.Stdout = &bytes.Buffer{}
	// Zeroed memory is an array of empty iovecs at 0 for either ABI; the
	// count a call writes back goes after wasiMaxIovecs+1 LP64 entries.
	const countOff = (wasiMaxIovecs + 1) * 16
	m := newGuestModule(countOff + 8)
	for _, tc := range []struct {
		name  string
		abi   wasiABI
		write func(iovsLen uint64) int32
	}{
		{"wasm32", wasiABI32, func(n uint64) int32 { return w.Fd_write(m, 1, 0, int32(n), countOff) }},
		{"memory64", wasiABI64, func(n uint64) int32 { return w.Fd_write64(m, 1, 0, int64(n), countOff) }},
	} {
		if bufs, ok := w.iovecSlices(m, tc.abi, 0, wasiMaxIovecs); !ok || len(bufs) != wasiMaxIovecs {
			t.Errorf("%s: iovecSlices of wasiMaxIovecs entries = %d windows, %v", tc.name, len(bufs), ok)
		}
		if bufs, ok := w.iovecSlices(m, tc.abi, 0, wasiMaxIovecs+1); ok || bufs != nil {
			t.Errorf("%s: iovecSlices of wasiMaxIovecs+1 entries = %d windows, %v, want refused", tc.name, len(bufs), ok)
		}
		if rc := tc.write(wasiMaxIovecs); rc != _wasiESUCCESS {
			t.Errorf("%s: fd_write of wasiMaxIovecs iovecs rc=%d", tc.name, rc)
		}
		if rc := tc.write(wasiMaxIovecs + 1); rc != _wasiEFAULT {
			t.Errorf("%s: fd_write of wasiMaxIovecs+1 iovecs rc=%d, want EFAULT", tc.name, rc)
		}
	}
}
