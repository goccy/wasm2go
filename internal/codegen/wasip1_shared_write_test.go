package codegen

import (
	"testing"
	"time"
)

// Several processes of a fork family writing to ONE full stream are each
// reached by a signal of their own, as the readers of one are.

// fillPipe writes to a pipe without blocking until it takes no more.
func fillPipe(t *testing.T, w *WasiStubs, m *Module, writeFd int32) {
	t.Helper()
	if rc := w.Fd_fdstat_set_flags(m, writeFd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	chunk := string(make([]byte, 4096))
	for i := 0; ; i++ {
		rc := fdWriteString(w, m, writeFd, chunk)
		if rc == _wasiEAGAIN {
			break
		}
		if rc != _wasiESUCCESS || i > 10000 {
			t.Fatalf("filling the pipe: rc=%d after %d writes", rc, i)
		}
	}
	if rc := w.Fd_fdstat_set_flags(m, writeFd, 0); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
}

func TestSignal_EveryProcessBlockedWritingOnePipeTakesItsSignal(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	fillPipe(t, w, m, writeFd)
	instances, modules := sharedWaiters(t, w, 5)
	write := func(w *WasiStubs, m *Module) int32 {
		return fdWriteString(w, m, writeFd, "more")
	}
	for round := 0; round < 3; round++ {
		waitAll(t, instances, modules, "write", write)
	}
	// Room made now lets a blocked writer through, and the others stay
	// reachable.
	results := make(chan int32, len(instances))
	for i := range instances {
		go func(w *WasiStubs, m *Module) { results <- write(w, m) }(instances[i], modules[i])
	}
	time.Sleep(50 * time.Millisecond)
	if got, rc := fdReadString(w, m, readFd, 16384); rc != _wasiESUCCESS || len(got) == 0 {
		t.Fatalf("read to make room rc=%d, %d bytes", rc, len(got))
	}
	select {
	case rc := <-results:
		if rc != _wasiESUCCESS {
			t.Fatalf("the write that found room rc=%d", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no writer got through after room was made")
	}
}

// A process polling a full pipe for writing beside a process blocked
// writing to it gets its timeout, and a write that does not wait reports
// that there is no room.
func TestWasi_PollTimesOutBesideABlockedWriter(t *testing.T) {
	w, m := newProcTestStubs(t)
	_, writeFd := newTestPipe(t, w, m)
	fillPipe(t, w, m, writeFd)
	instances, modules := sharedWaiters(t, w, 2)
	wrote := make(chan int32, 1)
	go func() { wrote <- fdWriteString(instances[0], modules[0], writeFd, "more") }()
	time.Sleep(50 * time.Millisecond)

	pm := modules[1]
	writeSubFd(pm, pollSubsOff, 7, 2 /* fd_write */, writeFd)
	writeSubClock(pm, pollSubsOff+48, 9, int64(60*time.Millisecond))
	start := time.Now()
	if rc := instances[1].Poll_oneoff(pm, pollSubsOff, pollEvOff, 2, pollNevOff); rc != _wasiESUCCESS {
		t.Fatalf("Poll_oneoff rc=%d", rc)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the poll took %v, its timeout is 60ms", waited)
	}
	if n := readU32(pm.memory, int(pollNevOff)); n != 1 || readU64(pm.memory, int(pollEvOff)) != 9 {
		t.Fatalf("poll reported %d events, first userdata %d; want the timeout only", n, readU64(pm.memory, int(pollEvOff)))
	}
	if rc := instances[1].Fd_fdstat_set_flags(pm, writeFd, wasiFdflagNonblock); rc != _wasiESUCCESS {
		t.Fatalf("Fd_fdstat_set_flags rc=%d", rc)
	}
	start = time.Now()
	if rc := fdWriteString(instances[1], pm, writeFd, "x"); rc != _wasiEAGAIN {
		t.Fatalf("write without waiting rc=%d, want EAGAIN", rc)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the write that does not wait took %v", waited)
	}
	select {
	case rc := <-wrote:
		t.Fatalf("the blocked writer returned %d", rc)
	default:
	}
	instances[0].PostSignal(wasiSIGTERM)
	select {
	case rc := <-wrote:
		if rc != _wasiEINTR {
			t.Fatalf("the blocked writer rc=%d, want EINTR", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the blocked writer did not take its signal")
	}
}
