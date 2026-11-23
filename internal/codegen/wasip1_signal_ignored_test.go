package codegen

import (
	"errors"
	"testing"
)

// recordingIgnorer is a WASIConfig.SignalIgnored that records what it is
// asked and answers ignored, err.
type recordingIgnorer struct {
	asked   []offeredSignal
	ignored bool
	err     error
}

func (r *recordingIgnorer) signalIgnored(target SignalTarget, sig int32) (bool, error) {
	r.asked = append(r.asked, offeredSignal{target, sig})
	return r.ignored, r.err
}

// Without a SignalIgnored no signal is ignored by the process.
func TestSignalIgnored_NoneWithoutTheHook(t *testing.T) {
	w, m := newSignalGuest(t)
	if rc := w.Proc_signal_ignored(m, wasiSIGHUP); rc != 0 {
		t.Fatalf("Proc_signal_ignored rc=%d, want 0", rc)
	}
}

// The guest's question goes to SignalIgnored, with the instance that asks
// as the target, and its answer is the guest's, on wasm32 and wasm64.
func TestSignalIgnored_AnswerOfTheHook(t *testing.T) {
	for _, ignored := range []bool{true, false} {
		w, m := newSignalGuest(t)
		r := &recordingIgnorer{ignored: ignored}
		w.cfg.SignalIgnored = r.signalIgnored
		want := int32(0)
		if ignored {
			want = 1
		}
		if rc := w.Proc_signal_ignored(m, wasiSIGHUP); rc != want {
			t.Errorf("ignored %v: Proc_signal_ignored rc=%d, want %d", ignored, rc, want)
		}
		if rc := w.Proc_signal_ignored64(m, wasiSIGUSR1); rc != want {
			t.Errorf("ignored %v: Proc_signal_ignored64 rc=%d, want %d", ignored, rc, want)
		}
		if len(r.asked) != 2 || r.asked[0] != (offeredSignal{w, wasiSIGHUP}) || r.asked[1] != (offeredSignal{w, wasiSIGUSR1}) {
			t.Errorf("ignored %v: asked %v", ignored, r.asked)
		}
	}
}

// SIGKILL, SIGSTOP and a number that is no signal's are never ignored, and
// SignalIgnored is not asked of them.
func TestSignalIgnored_NotAskedOfUncatchableOrInvalidSignals(t *testing.T) {
	w, m := newSignalGuest(t)
	r := &recordingIgnorer{ignored: true}
	w.cfg.SignalIgnored = r.signalIgnored
	for _, sig := range []int32{0, -1, 65, wasiSIGKILL, wasiSIGSTOP} {
		if rc := w.Proc_signal_ignored(m, sig); rc != 0 {
			t.Errorf("Proc_signal_ignored(%d) rc=%d, want 0", sig, rc)
		}
	}
	if len(r.asked) != 0 {
		t.Fatalf("asked %v, want nothing", r.asked)
	}
}

// An error of SignalIgnored is told Errors, and the guest keeps the
// default action.
func TestSignalIgnored_Error(t *testing.T) {
	w, m := newSignalGuest(t)
	failure := errors.New("the action cannot be read")
	w.cfg.SignalIgnored = (&recordingIgnorer{ignored: true, err: failure}).signalIgnored
	var told []error
	w.cfg.Errors = func(op string, err error) {
		if op != "signal_ignored" {
			t.Errorf("Errors told op %q", op)
		}
		told = append(told, err)
	}
	if rc := w.Proc_signal_ignored(m, wasiSIGHUP); rc != 0 {
		t.Fatalf("Proc_signal_ignored rc=%d, want 0", rc)
	}
	if len(told) != 1 || !errors.Is(told[0], failure) {
		t.Fatalf("Errors told %v, want the hook's error", told)
	}
}

// A forked instance has its parent's SignalIgnored, and asks it as the
// target.
func TestSignalIgnored_ForkAsksAsItself(t *testing.T) {
	w, _ := newSignalGuest(t)
	r := &recordingIgnorer{ignored: true}
	w.cfg.SignalIgnored = r.signalIgnored
	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	if rc := child.Proc_signal_ignored(newForkTestModule(), wasiSIGHUP); rc != 1 {
		t.Fatalf("Proc_signal_ignored of the fork rc=%d, want 1", rc)
	}
	if len(r.asked) != 1 || r.asked[0].target != child {
		t.Fatalf("asked %v, want the fork as the target", r.asked)
	}
}
