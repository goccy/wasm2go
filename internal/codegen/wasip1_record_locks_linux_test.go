package codegen

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// openExternal opens the file f of dir as another process would: an open
// file description whose locks (Linux's OFD locks) are no instance's.
func openExternal(t *testing.T, dir string) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "f"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, f)
	return f
}

// externalLock takes (or removes, typ recordUnlock) the lock of type typ
// of length bytes at start on ext without waiting.
func externalLock(t *testing.T, ext *os.File, typ int32, start, length int64) {
	t.Helper()
	if err := setExternalLock(ext, typ, start, length); err != nil {
		t.Fatal(err)
	}
}

// setExternalLock is externalLock returning its failure.
func setExternalLock(ext *os.File, typ int32, start, length int64) error {
	lk := recordLock{typ: typ, start: start, len: length}
	if err := hostRecordLock(ext, recordLockSet, &lk); err != nil {
		return fmt.Errorf("lock of another process of type %d [%d, +%d): %w", typ, start, length, err)
	}
	return nil
}

// unlockExternalWhenBlocked removes the lock of ext of length bytes at
// start once a call of w waits. The function it returns waits for that and
// fails t, on the test's goroutine, if the unlock did.
func unlockExternalWhenBlocked(t *testing.T, w *WasiStubs, ext *os.File, start, length int64) func() {
	unlocked := make(chan error, 1)
	whenBlocked(w, func() { unlocked <- setExternalLock(ext, recordUnlock, start, length) })
	return func() {
		t.Helper()
		if err := <-unlocked; err != nil {
			t.Fatal(err)
		}
	}
}

// An interrupted wait for another process's lock that the host grants
// later brings the host's locks of its range back to the table's: the
// instance's read lock in the range stays a lock of the host's, which
// joins the one taken next to it.
func TestFdLockLateGrantKeepsTheTable(t *testing.T) {
	dir := lockedFileIn(t)
	ext := openExternal(t, dir)
	externalLock(t, ext, recordWrite, 5, 5)
	w, m := newSignalGuestIn(t, dir)
	fd := openTestFile(t, w, "f")
	if rc := lockAt(w, m, fd, recordLockSet, recordRead, 0, 5); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK read [0, 5) rc=%d", rc)
	}
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := lockAt(w, m, fd, recordLockWait, recordWrite, 0, 10); rc != -_wasiEINTR {
		t.Fatalf("F_SETLKW write [0, 10) beside the other process rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	// The interrupted wait goes on at the host: a lock it rules out, the
	// instance's own where no other process's is in the way, waits for
	// it, which the other process's unlock ends.
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, 0, 3); rc != -_wasiEAGAIN {
		t.Fatalf("F_SETLK write [0, 3) beside the interrupted wait rc=%d, want -EAGAIN", rc)
	}
	released := unlockExternalWhenBlocked(t, w, ext, 5, 5)
	if rc := lockAt(w, m, fd, recordLockWait, recordRead, 5, 1); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW read [5, 6) after the other process let go rc=%d", rc)
	}
	released()
	lk := recordLock{typ: recordWrite, len: 5}
	if err := hostRecordLock(ext, recordLockGet, &lk); err != nil {
		t.Fatal(err)
	}
	if lk.typ != recordRead || lk.start != 0 || lk.len != 6 {
		t.Fatalf("the host's lock in the way of [0, 5): %+v, want the read lock of [0, 6)", lk)
	}
	lk = recordLock{typ: recordWrite, start: 6, len: 4}
	if err := hostRecordLock(ext, recordLockGet, &lk); err != nil || lk.typ != recordUnlock {
		t.Fatalf("the host's lock in the way of [6, 10): %+v, %v; want none", lk, err)
	}
}

// When a wait for another process's lock is interrupted, a wait of another
// instance for it goes on, and is granted once the host grants the
// interrupted one and its lock is brought back to the table's.
func TestFdLockWaitBehindAnInterruptedHostWait(t *testing.T) {
	dir := lockedFileIn(t)
	ext := openExternal(t, dir)
	externalLock(t, ext, recordWrite, 0, 10)
	a, am := newSignalGuestIn(t, dir)
	b, bm := newTestStubs(t, dir)
	aFd, bFd := openTestFile(t, a, "f"), openTestFile(t, b, "f")
	aDone := make(chan int32, 1)
	go func() { aDone <- lockAt(a, am, aFd, recordLockWait, recordWrite, 0, 10) }()
	awaitBlockedCalls(a, 1)
	bDone := make(chan int32, 1)
	go func() { bDone <- lockAt(b, bm, bFd, recordLockWait, recordWrite, 0, 10) }()
	awaitBlockedCalls(b, 1)
	a.PostSignal(wasiSIGUSR1)
	if rc := <-aDone; rc != -_wasiEINTR {
		t.Fatalf("the interrupted F_SETLKW rc=%d, want -EINTR", rc)
	}
	externalLock(t, ext, recordUnlock, 0, 10)
	returnsWithin(t, "the F_SETLKW behind the interrupted one", func() {
		if rc := <-bDone; rc != _wasiESUCCESS {
			t.Errorf("the F_SETLKW behind the interrupted one rc=%d", rc)
		}
	})
	if typ, _, _, pid := heldAt(t, a, am, aFd, 0, 10); typ != recordWrite || pid != -1 {
		t.Fatalf("F_GETLK beside the other family's lock: type %d pid %d, want a write lock of pid -1", typ, pid)
	}
}

// A read lock that would wait for another process's lock over a write lock
// of the instance's own fails with ENOLCK, the write lock kept at the host:
// the read the host grants a wait, even after the guest stopped waiting,
// would replace it there. A read that does not wait, or waits beside the
// write lock only, is as any other.
func TestFdLockReadWaitOverItsOwnWrite(t *testing.T) {
	dir := lockedFileIn(t)
	ext := openExternal(t, dir)
	externalLock(t, ext, recordWrite, 15, 5)
	w, m := newSignalGuestIn(t, dir)
	fd := openTestFile(t, w, "f")
	if rc := lockAt(w, m, fd, recordLockSet, recordWrite, 0, 10); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK write [0, 10) rc=%d", rc)
	}
	var rc int32
	returnsWithin(t, "F_SETLKW read [0, 20) over the write lock", func() {
		rc = lockAt(w, m, fd, recordLockWait, recordRead, 0, 20)
	})
	if rc != -_wasiENOLCK {
		t.Fatalf("F_SETLKW read [0, 20) over the write lock rc=%d, want -ENOLCK", rc)
	}
	if rc := lockAt(w, m, fd, recordLockSet, recordRead, 0, 20); rc != -_wasiEAGAIN {
		t.Fatalf("F_SETLK read [0, 20) over the write lock rc=%d, want -EAGAIN", rc)
	}
	lk := recordLock{typ: recordRead, len: 10}
	if err := hostRecordLock(ext, recordLockGet, &lk); err != nil {
		t.Fatal(err)
	}
	if lk.typ != recordWrite || lk.start != 0 || lk.len != 10 {
		t.Fatalf("the host's lock in the way of a read of [0, 10): %+v, want the write lock of [0, 10)", lk)
	}
	released := unlockExternalWhenBlocked(t, w, ext, 15, 5)
	if rc := lockAt(w, m, fd, recordLockWait, recordRead, 10, 10); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW read [10, 20) beside the write lock rc=%d", rc)
	}
	released()
}

// The host's grant of an interrupted wait for another process's lock
// leaves alone a lock of another instance taken in its range meanwhile.
func TestFdLockLateGrantKeepsAnotherInstancesLock(t *testing.T) {
	dir := lockedFileIn(t)
	ext := openExternal(t, dir)
	externalLock(t, ext, recordWrite, 5, 5)
	w, m := newSignalGuestIn(t, dir)
	fd := openTestFile(t, w, "f")
	postWhenBlocked(w, wasiSIGUSR1)
	if rc := lockAt(w, m, fd, recordLockWait, recordRead, 0, 10); rc != -_wasiEINTR {
		t.Fatalf("F_SETLKW read [0, 10) beside the other process rc=%d, want -EINTR", rc)
	}
	takeSignals(t, w, m)
	other, om := newTestStubs(t, dir)
	if rc := lockAt(other, om, openTestFile(t, other, "f"), recordLockSet, recordRead, 0, 3); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLK read [0, 3) of another instance rc=%d", rc)
	}
	// A write lock in the range waits for the interrupted wait, until the
	// host has granted it and its range is brought back to the table.
	released := unlockExternalWhenBlocked(t, w, ext, 5, 5)
	if rc := lockAt(w, m, fd, recordLockWait, recordWrite, 3, 1); rc != _wasiESUCCESS {
		t.Fatalf("F_SETLKW write [3, 4) after the other process let go rc=%d", rc)
	}
	released()
	lk := recordLock{typ: recordWrite, len: 3}
	if err := hostRecordLock(ext, recordLockGet, &lk); err != nil {
		t.Fatal(err)
	}
	if lk.typ != recordRead || lk.start != 0 || lk.len != 3 {
		t.Fatalf("the host's lock in the way of [0, 3): %+v, want the other instance's read lock of [0, 3)", lk)
	}
	lk = recordLock{typ: recordWrite, start: 4, len: 6}
	if err := hostRecordLock(ext, recordLockGet, &lk); err != nil || lk.typ != recordUnlock {
		t.Fatalf("the host's lock in the way of [4, 10): %+v, %v; want none", lk, err)
	}
}
