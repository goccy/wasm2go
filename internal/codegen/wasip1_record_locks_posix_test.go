//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const recordLockOff = 200

// putRange writes the recordLock of type typ of length bytes at start, from
// the start of the file, at recordLockOff.
func putRange(m *Module, typ int32, start, length int64) {
	clear(m.memory[recordLockOff : recordLockOff+32])
	binary.LittleEndian.PutUint32(m.memory[recordLockOff:], uint32(typ))
	binary.LittleEndian.PutUint64(m.memory[recordLockOff+8:], uint64(start))
	binary.LittleEndian.PutUint64(m.memory[recordLockOff+16:], uint64(length))
}

// lockAt is fd_lock's cmd of the lock of type typ of length bytes at start.
func lockAt(w *WasiStubs, m *Module, fd, cmd, typ int32, start, length int64) int32 {
	putRange(m, typ, start, length)
	return w.Fd_lock(m, fd, cmd, recordLockOff)
}

// heldAt is F_GETLK of a write lock of length bytes at start: the type,
// range and pid of the lock in the way.
func heldAt(t *testing.T, w *WasiStubs, m *Module, fd int32, start, length int64) (typ int32, from, n int64, pid int32) {
	t.Helper()
	if rc := lockAt(w, m, fd, recordLockGet, recordWrite, start, length); rc != _wasiESUCCESS {
		t.Fatalf("F_GETLK of [%d, +%d) rc=%d", start, length, rc)
	}
	b := m.memory[recordLockOff:]
	return int32(binary.LittleEndian.Uint32(b)), int64(binary.LittleEndian.Uint64(b[8:])), int64(binary.LittleEndian.Uint64(b[16:])), int32(binary.LittleEndian.Uint32(b[24:]))
}

// lockedFileIn makes a file of six bytes in a new directory and returns
// the directory.
func lockedFileIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The record locks are the instance's: a copy made by Fork does not
// inherit them and competes for them through an inherited descriptor;
// F_GETLK names the holder by its pid in its family and by -1 elsewhere;
// a close of any descriptor of the file by the holder removes them, one
// by another instance does not.
func TestFdLockOwnersAreInstances(t *testing.T) {
	dir := lockedFileIn(t)
	w, m := newTestStubs(t, dir)
	fd := openTestFile(t, w, "f")
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK of the parent rc=%d", rc)
	}
	child, cm := w.Fork(), newForkTestModule()
	if rc := lockAt(child, cm, fd, recordLockSet, recordWrite, 0, 0); rc != -_wasiEAGAIN {
		t.Fatalf("F_SETLK of the child through the inherited descriptor rc=%d, want -EAGAIN", rc)
	}
	if typ, _, _, pid := heldAt(t, child, cm, fd, 0, 0); typ != recordWrite || pid != w.guestPID() {
		t.Fatalf("F_GETLK of the child: type %d pid %d, want the parent's write lock of pid %d", typ, pid, w.guestPID())
	}
	if rc := lockAt(child, cm, fd, recordLockSet, recordUnlock, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_UNLCK of the child rc=%d", rc)
	}
	if typ, _, _, _ := heldAt(t, child, cm, fd, 0, 0); typ != recordWrite {
		t.Fatalf("after the child's unlock F_GETLK type %d, want the parent's write lock", typ)
	}
	other, om := newTestStubs(t, dir)
	otherFd := openTestFile(t, other, "f")
	if typ, _, _, pid := heldAt(t, other, om, otherFd, 0, 0); typ != recordWrite || pid != -1 {
		t.Fatalf("F_GETLK of another family: type %d pid %d, want a write lock of pid -1", typ, pid)
	}
	closeTestFd(t, other, om, openTestFile(t, other, "f"))
	if typ, _, _, _ := heldAt(t, other, om, otherFd, 0, 0); typ != recordWrite {
		t.Fatalf("after another instance's close F_GETLK type %d, want the parent's write lock", typ)
	}
	closeTestFd(t, w, m, openTestFile(t, w, "f"))
	if rc := lockAt(child, cm, fd, recordLockSet, recordWrite, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK of the child after the parent closed a descriptor of the file rc=%d", rc)
	}
}

// A lock is cut by an unlock of part of it and joins the instance's locks
// of its type it touches; a negative length reaches back from the start.
func TestFdLockRanges(t *testing.T) {
	dir := lockedFileIn(t)
	w, m := newTestStubs(t, dir)
	other, om := newTestStubs(t, dir)
	fd, otherFd := openTestFile(t, w, "f"), openTestFile(t, other, "f")
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, 0, 10); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK [0, 10) rc=%d", rc)
	}
	if rc := lockAt(w, m, fd, recordLockSet, recordUnlock, 3, 2); rc != _wasiESUCCESS {
		t.Fatalf("F_UNLCK [3, 5) rc=%d", rc)
	}
	for _, c := range []struct {
		start, length, from, n int64
		typ                    int32
	}{
		{0, 0, 0, 3, recordWrite},
		{3, 2, 3, 2, recordUnlock},
		{4, 0, 5, 5, recordWrite},
		{10, -6, 5, 5, recordWrite},
	} {
		if typ, from, n, _ := heldAt(t, other, om, otherFd, c.start, c.length); typ != c.typ || typ != recordUnlock && (from != c.from || n != c.n) {
			t.Fatalf("F_GETLK of [%d, +%d): type %d [%d, +%d), want type %d [%d, +%d)", c.start, c.length, typ, from, n, c.typ, c.from, c.n)
		}
	}
	// [3, 5) joins both: one lock, removed by one unlock.
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, 3, 2); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK [3, 5) rc=%d", rc)
	}
	w.mu.Lock()
	file := w.openLocked(fd).lockedFile
	w.mu.Unlock()
	file.mu.Lock()
	rows := len(file.rows)
	file.mu.Unlock()
	if rows != 1 {
		t.Fatalf("%d locks after the gap was locked, want 1", rows)
	}
	if rc := lockAt(w, m, fd, recordLockSet, recordUnlock, 0, 10); rc != _wasiESUCCESS {
		t.Fatalf("F_UNLCK [0, 10) rc=%d", rc)
	}
	if typ, _, _, _ := heldAt(t, other, om, otherFd, 0, 0); typ != recordUnlock {
		t.Fatalf("after the unlock F_GETLK type %d, want F_UNLCK", typ)
	}
	// The lock to the end from the largest offset is of its one byte.
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, math.MaxInt64, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK [MaxInt64, +0) rc=%d", rc)
	}
	if typ, from, n, _ := heldAt(t, other, om, otherFd, 0, 0); typ != recordWrite || from != math.MaxInt64 || n != 0 {
		t.Fatalf("F_GETLK of [0, +0): type %d [%d, +%d), want the write lock of [MaxInt64, +0)", typ, from, n)
	}
	if typ, _, _, _ := heldAt(t, other, om, otherFd, 0, math.MaxInt64); typ != recordUnlock {
		t.Fatalf("F_GETLK of [0, +MaxInt64): type %d, want F_UNLCK", typ)
	}
	if rc := lockAt(w, m, fd, recordLockSet, recordUnlock, math.MaxInt64, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_UNLCK [MaxInt64, +0) rc=%d", rc)
	}
	for _, c := range []struct {
		start, length int64
		errno         int32
	}{{-1, 1, _wasiEINVAL}, {5, -6, _wasiEINVAL}, {10, math.MaxInt64, _wasiEOVERFLOW}} {
		if rc := lockAt(w, m, fd, recordLockSet, recordWrite, c.start, c.length); rc != -c.errno {
			t.Fatalf("F_SETLK [%d, +%d) rc=%d, want -%d", c.start, c.length, rc, c.errno)
		}
	}
	readOnly, errno := w.pathOpen(m, "f", 0x1, 0, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open for reading errno=%d", errno)
	}
	if rc := lockAt(w, m, readOnly, recordLockSet, recordWrite, 0, 0); rc != -_wasiEBADF {
		t.Fatalf("F_WRLCK of a descriptor open for reading rc=%d, want -EBADF", rc)
	}
}

// A wait for another instance's lock is a wait of the table: a signal ends
// it, the holder's unlock grants it, and the close of the waiting
// descriptor — by fd_close or CloseDescriptors — ends it with EBADF.
func TestFdLockWaitsForAnInstance(t *testing.T) {
	dir := lockedFileIn(t)
	holder, hm := newTestStubs(t, dir)
	holderFd := openTestFile(t, holder, "f")
	if rc := lockAt(holder, hm, holderFd, recordLockSet, recordWrite, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK of the holder rc=%d", rc)
	}
	w, m := newSignalGuestIn(t, dir)
	fd := openTestFile(t, w, "f")
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := lockAt(w, m, fd, recordLockWait, recordWrite, 0, 0); rc != -_wasiEINTR {
		t.Fatalf("F_SETLKW beside the holder rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	released := whenBlocked(w, func() {
		if rc := lockAt(holder, newForkTestModule(), holderFd, recordLockSet, recordUnlock, 0, 0); rc != _wasiESUCCESS {
			t.Errorf("F_UNLCK of the holder rc=%d", rc)
		}
	})
	if rc := lockAt(w, m, fd, recordLockWait, recordWrite, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW after the holder let go rc=%d", rc)
	}
	<-released

	for _, end := range []struct {
		name  string
		close func(w *WasiStubs, fd int32)
	}{
		{"fd_close", func(w *WasiStubs, fd int32) {
			if rc := w.Fd_close(newForkTestModule(), fd); rc != _wasiESUCCESS {
				t.Errorf("Fd_close rc=%d", rc)
			}
		}},
		{"CloseDescriptors", func(w *WasiStubs, fd int32) {
			if err := w.CloseDescriptors(); err != nil {
				t.Error(err)
			}
		}},
	} {
		waiter, wm := newTestStubs(t, dir)
		waiterFd := openTestFile(t, waiter, "f")
		closed := whenBlocked(waiter, func() { end.close(waiter, waiterFd) })
		var rc int32
		returnsWithin(t, "F_SETLKW whose descriptor "+end.name+" closes", func() {
			rc = lockAt(waiter, wm, waiterFd, recordLockWait, recordWrite, 0, 0)
		})
		<-closed
		if rc != -_wasiEBADF {
			t.Fatalf("F_SETLKW whose descriptor %s closes rc=%d, want -EBADF", end.name, rc)
		}
	}
}

// Threads of instances lock, unlock and close descriptors of one file at
// once (go test -race): every wait ends, and no lock is left.
func TestFdLockConcurrentInstances(t *testing.T) {
	dir := lockedFileIn(t)
	var wg sync.WaitGroup
	for i := range 3 {
		w, _ := newTestStubs(t, dir)
		for j := range 2 {
			wg.Go(func() {
				m := newForkTestModule()
				for k := range 50 {
					fd, errno := w.pathOpen(m, "f", 0x1, 0, 1<<1|1<<6, 0)
					if errno != _wasiESUCCESS {
						t.Errorf("pathOpen errno=%d", errno)
						return
					}
					typ := recordWrite
					if (i+j+k)%2 == 0 {
						typ = recordRead
					}
					if rc := lockAt(w, m, fd, recordLockWait, typ, int64(k%3), 4); rc != _wasiESUCCESS {
						t.Errorf("F_SETLKW rc=%d", rc)
					}
					if k%2 == 0 {
						if rc := lockAt(w, m, fd, recordLockSet, recordUnlock, 0, 0); rc != _wasiESUCCESS {
							t.Errorf("F_UNLCK rc=%d", rc)
						}
					}
					if rc := w.Fd_close(m, fd); rc != _wasiESUCCESS {
						t.Errorf("Fd_close rc=%d", rc)
					}
				}
			})
		}
	}
	wg.Wait()
	w, m := newTestStubs(t, dir)
	if typ, _, _, _ := heldAt(t, w, m, openTestFile(t, w, "f"), 0, 0); typ != recordUnlock {
		t.Fatalf("after every descriptor was closed F_GETLK type %d, want F_UNLCK", typ)
	}
}
