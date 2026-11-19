package codegen

import (
	"encoding/binary"
	"testing"
	"time"
)

// Readiness probes of a stream that several instances share after Fork.

// pollAsync runs Poll_oneoff on another goroutine, with its own module
// memory, over a read subscription of fd (userdata 1) and a clock
// subscription of timeout (userdata 2), and delivers the userdata of the
// events it reported and how long it took.
func pollAsync(w *WasiStubs, fd int32, timeout time.Duration) <-chan pollResult {
	res := make(chan pollResult, 1)
	go func() {
		m := newForkTestModule()
		writeSubFd(m, pollSubsOff, 1, 1 /* fd_read */, fd)
		writeSubClock(m, pollSubsOff+48, 2, int64(timeout))
		start := time.Now()
		rc := w.Poll_oneoff(m, pollSubsOff, pollEvOff, 2, pollNevOff)
		r := pollResult{rc: rc, took: time.Since(start)}
		n := int32(binary.LittleEndian.Uint32(m.memory[pollNevOff:]))
		for i := int32(0); i < n; i++ {
			r.userdata = append(r.userdata, binary.LittleEndian.Uint64(m.memory[pollEvOff+i*32:]))
		}
		res <- r
	}()
	return res
}

type pollResult struct {
	rc       int32
	userdata []uint64
	took     time.Duration
}

// readAsync reads up to 16 bytes from fd on another goroutine, with its own
// module memory, and delivers what it read.
func readAsync(w *WasiStubs, fd int32) <-chan string {
	res := make(chan string, 1)
	go func() {
		s, rc := fdReadString(w, newForkTestModule(), fd, 16)
		if rc != _wasiESUCCESS {
			s = "error"
		}
		res <- s
	}()
	return res
}

// A read of a forked instance that is waiting for input while another
// instance's poll probes the same pipe gets the input the probe took: a read
// and a probe take turns at the stream, and the read that comes after a
// probe starts with what the probe kept. Before, the probe kept the input on
// the shared descriptor while the read went on waiting on the pipe itself,
// which had nothing more to give.
func TestWasi_PollLeavesInputToAReadOfAForkedInstance(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	child := w.Fork()
	defer child.CloseAll()

	polled := pollAsync(w, readFd, 3*time.Second)
	time.Sleep(100 * time.Millisecond) // the parent's probe is reading the pipe
	got := readAsync(child, readFd)
	time.Sleep(100 * time.Millisecond) // the child's read is waiting behind it
	if rc := fdWriteString(w, m, writeFd, "x"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	select {
	case s := <-got:
		if s != "x" {
			t.Fatalf("the child read %q, want %q", s, "x")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the child's read never got the input the parent's poll took")
	}
	if r := <-polled; r.rc != _wasiESUCCESS || len(r.userdata) != 1 || r.userdata[0] != 1 {
		t.Fatalf("the parent's poll = %+v, want the pipe readable", r)
	}
}

// Two instances polling the same idle pipe with different timeouts each get
// their own: the probes take turns, and each sets and clears its read
// deadline in its turn. Before, the probe that ended first cleared the
// deadline of the other one, whose poll then waited for input with no limit.
func TestWasi_ConcurrentPollsOfASharedPipeKeepTheirTimeouts(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	child := w.Fork()
	defer child.CloseAll()

	long := pollAsync(w, readFd, 600*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	short := pollAsync(child, readFd, 50*time.Millisecond)

	for name, ch := range map[string]<-chan pollResult{"short": short, "long": long} {
		select {
		case r := <-ch:
			if r.rc != _wasiESUCCESS || len(r.userdata) != 1 || r.userdata[0] != 2 {
				t.Fatalf("the %s poll = %+v, want its timeout", name, r)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("the %s poll of an idle pipe did not end at its timeout", name)
		}
	}
	// The pipe still works as a pipe afterwards.
	if rc := fdWriteString(w, m, writeFd, "y"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	if s, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || s != "y" {
		t.Fatalf("read after the polls = %q rc=%d", s, rc)
	}
}
