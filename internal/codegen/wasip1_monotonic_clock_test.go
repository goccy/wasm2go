package codegen

import (
	"encoding/binary"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// steppingClock is a MonotonicClock that moves on by a nanosecond at each
// reading, so that a wait on it ends only after the runtime has read it as
// often as the wait is long.
type steppingClock struct{ now atomic.Uint64 }

func (c *steppingClock) read() uint64 { return c.now.Add(1) }

// clock_time_get(CLOCK_MONOTONIC) reports WASIConfig.MonotonicClock.
func TestWasi_MonotonicClockReported(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	const reading = uint64(123456789) << 20
	w.cfg.MonotonicClock = func() uint64 { return reading }
	if rc := w.Clock_time_get(m, 1, 0, 8); rc != _wasiESUCCESS {
		t.Fatalf("Clock_time_get rc=%d", rc)
	}
	if got := readU64(m.memory, 8); got != reading {
		t.Fatalf("CLOCK_MONOTONIC = %d, want %d", got, reading)
	}
}

// A clock subscription on CLOCK_MONOTONIC, absolute or relative, ends once
// WASIConfig.MonotonicClock reads its end, however soon the host's timers
// say its time has come, also beside a descriptor that is waited for in the
// host's poll(2) and never becomes ready.
func TestWasi_PollOneoffMonotonicClock(t *testing.T) {
	for _, tc := range []struct {
		abs, withFd bool
	}{{true, false}, {false, false}, {true, true}, {false, true}} {
		w, m := newTestStubs(t, t.TempDir())
		c := &steppingClock{}
		c.now.Store(1 << 40)
		w.cfg.MonotonicClock = c.read
		const wait = 5
		// A relative timeout counts from the reading at the call, the
		// clock's first.
		end := c.now.Load() + 1 + wait
		timeout, flags := uint64(wait), uint16(0)
		if tc.abs {
			timeout, flags = end, 1
		}
		binary.LittleEndian.PutUint64(m.memory[0:], 0xc10c) // userdata
		m.memory[8] = 0                                     // eventtype = clock
		binary.LittleEndian.PutUint32(m.memory[16:], 1)     // CLOCK_MONOTONIC
		binary.LittleEndian.PutUint64(m.memory[24:], timeout)
		binary.LittleEndian.PutUint16(m.memory[40:], flags)
		nsubs := int32(1)
		if tc.withFd {
			readFd, _ := newTestPipe(t, w, m)
			writeSubFd(m, 48, 0xfd, 1, readFd)
			nsubs = 2
		}
		if rc := w.Poll_oneoff(m, 0, 200, nsubs, 400); rc != _wasiESUCCESS {
			t.Fatalf("%+v: Poll_oneoff rc=%d", tc, rc)
		}
		if n, userdata, errno := readU32(m.memory, 400), readU64(m.memory, 200), binary.LittleEndian.Uint16(m.memory[208:]); n != 1 || userdata != 0xc10c || errno != 0 {
			t.Fatalf("%+v: nevents=%d userdata=%#x errno=%d, want the clock's event alone", tc, n, userdata, errno)
		}
		if got := c.now.Load(); got < end {
			t.Fatalf("%+v: the wait ended when the clock read %d, before %d", tc, got, end)
		}
	}
}

// A relative timeout of 2^63 ns or more is waited for as the longest
// time.Duration, alone or beside a descriptor: a signal ends the wait.
func TestWasi_PollOneoffTimeoutBeyondTheLongestDuration(t *testing.T) {
	for _, withFd := range []bool{false, true} {
		w, m := newSignalGuest(t, wasiSIGUSR1)
		for _, clockID := range []uint32{0, 1} { // CLOCK_REALTIME, CLOCK_MONOTONIC
			binary.LittleEndian.PutUint64(m.memory[pollSubsOff:], 0xc10c) // userdata
			m.memory[pollSubsOff+8] = 0                                   // eventtype = clock
			binary.LittleEndian.PutUint32(m.memory[pollSubsOff+16:], clockID)
			binary.LittleEndian.PutUint64(m.memory[pollSubsOff+24:], math.MaxUint64)
			binary.LittleEndian.PutUint16(m.memory[pollSubsOff+40:], 0) // relative
			nsubs := int32(1)
			if withFd {
				readFd, _ := newTestPipe(t, w, m)
				writeSubFd(m, pollSubsOff+48, 0xfd, 1, readFd)
				nsubs = 2
			}
			done := make(chan int32)
			go func() { done <- w.Poll_oneoff(m, pollSubsOff, pollEvOff, nsubs, pollNevOff) }()
			w.PostSignal(wasiSIGUSR1)
			if rc := <-done; rc != _wasiEINTR {
				t.Fatalf("fd %v, clock %d: Poll_oneoff rc=%d, want EINTR", withFd, clockID, rc)
			}
			if got := takeSignals(t, w, m); got != signalMask(wasiSIGUSR1) {
				t.Fatalf("fd %v, clock %d: took %#x, want SIGUSR1", withFd, clockID, got)
			}
		}
	}
}

// A forked instance reads its parent's WASIConfig.MonotonicClock.
func TestWasi_ForkedInstanceReadsTheParentsMonotonicClock(t *testing.T) {
	w, _ := newProcTestStubs(t)
	const reading = uint64(987654321) << 20
	w.cfg.MonotonicClock = func() uint64 { return reading }
	child := w.Fork()
	cm := newForkTestModule()
	if rc := child.Clock_time_get(cm, 1, 0, 8); rc != _wasiESUCCESS {
		t.Fatalf("Clock_time_get in the child rc=%d", rc)
	}
	if got := readU64(cm.memory, 8); got != reading {
		t.Fatalf("the child's CLOCK_MONOTONIC = %d, want the parent's %d", got, reading)
	}
}

// The interval timer counts WASIConfig.MonotonicClock: its SIGALRM comes
// once the clock reads the time the timer was set for.
func TestTakeSignal_TimerCountsMonotonicClock(t *testing.T) {
	w, m, r := newTakingGuest(t, true, wasiSIGALRM)
	c := &steppingClock{}
	c.now.Store(1 << 40)
	w.cfg.MonotonicClock = c.read
	fired := make(chan uint64, 1)
	r.during = func(target SignalTarget, sig int32) { fired <- c.now.Load() }
	const value = 50
	end := c.now.Load() + value
	setTimer(t, w, m, value*time.Nanosecond, 0)
	if at := <-fired; at < end {
		t.Fatalf("SIGALRM came when the clock read %d, before %d", at, end)
	}
	if got := r.offered(); len(got) != 1 || got[0] != (offeredSignal{w, wasiSIGALRM}) {
		t.Fatalf("offered %v, want SIGALRM once", got)
	}
}
