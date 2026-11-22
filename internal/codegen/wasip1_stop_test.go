package codegen

import (
	"reflect"
	"testing"
	"time"
)

// endOf runs call and returns what it panics with, or nil if it returns.
func endOf(call func()) (end any) {
	defer func() { end = recover() }()
	call()
	return nil
}

// The end of the instance by one thread of the guest — proc_exit, or an end
// by a signal — ends the others with it: the blocking call one waits in, and
// the next call that looks of any.
func TestStop_AnEndEndsTheOtherThreads(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(*WasiStubs, *Module)
		want error
	}{
		{"proc_exit", func(w *WasiStubs, m *Module) { w.Proc_exit(m, 3) }, &WasiExitError{Code: 3}},
		{"proc_terminate", func(w *WasiStubs, m *Module) { w.Proc_terminate(m, wasiSIGTERM) }, &WasiSignalError{Signal: wasiSIGTERM}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newSignalGuest(t)
			writeSubClock(m, pollSubsOff, 1, int64(time.Hour))
			waited := make(chan any, 1)
			go func() {
				waited <- endOf(func() { w.Poll_oneoff(m, pollSubsOff, pollEvOff, 1, pollNevOff) })
			}()
			awaitBlockedCalls(w, 1)
			if got := endOf(func() { tc.end(w, m) }); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("the ending thread ended with %v, want %v", got, tc.want)
			}
			select {
			case got := <-waited:
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("the waiting thread ended with %v, want %v", got, tc.want)
				}
			case <-time.After(waitLimit):
				t.Fatalf("the waiting thread still waits after %v", waitLimit)
			}
			if got := endOf(func() { fdWriteString(w, m, 1, "x") }); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("fd_write after the end ended with %v, want %v", got, tc.want)
			}
		})
	}
}

// The end of the instance interrupts the code outside the guest that a
// thread runs (BeginOutside), for it to come back to the guest, which ends at
// its next call that looks: SIGKILL, and another thread's end. The call's
// Pending says so.
func TestStop_AnEndInterruptsCodeOutsideTheGuest(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(*WasiStubs, *Module)
	}{
		{"SIGKILL", func(w *WasiStubs, m *Module) { w.PostSignal(wasiSIGKILL) }},
		{"proc_exit", func(w *WasiStubs, m *Module) { endOf(func() { w.Proc_exit(m, 3) }) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m := newSignalGuest(t)
			calls := 0
			c := w.BeginOutside(newThreadModule(m), func() { calls++ })
			tc.end(w, m)
			pending := c.Pending()
			c.End()
			if !pending {
				t.Error("Pending is false once the end was asked for")
			}
			if calls != 1 {
				t.Fatalf("the interrupt was called %d times, want once", calls)
			}
		})
	}
}

// The first end asked for is the instance's: SIGKILL that comes first is
// what a later proc_exit ends the thread with.
func TestStop_TheFirstEndIsTheInstances(t *testing.T) {
	w, m := newSignalGuest(t)
	w.PostSignal(wasiSIGKILL)
	want := &WasiSignalError{Signal: wasiSIGKILL}
	if got := endOf(func() { w.Proc_exit(m, 0) }); !reflect.DeepEqual(got, want) {
		t.Fatalf("proc_exit after SIGKILL ended with %v, want %v", got, want)
	}
}

// A blocking call that the end wakes ends the thread, and so does one that
// begins once the end has been asked for, which no wake reaches.
func TestStop_ABlockingCallAfterTheEndEndsTheThread(t *testing.T) {
	w, m := newSignalGuest(t)
	b, ok := w.beginBlocking(m, func() {})
	if !ok {
		t.Fatal("beginBlocking refused with no signal posted")
	}
	w.PostSignal(wasiSIGKILL)
	want := &WasiSignalError{Signal: wasiSIGKILL}
	if got := endOf(func() { w.endBlocking(b) }); !reflect.DeepEqual(got, want) {
		t.Fatalf("endBlocking of the call SIGKILL woke ended with %v, want %v", got, want)
	}
	if got := endOf(func() { w.beginBlocking(m, func() {}) }); !reflect.DeepEqual(got, want) {
		t.Fatalf("beginBlocking after SIGKILL ended with %v, want %v", got, want)
	}
}
