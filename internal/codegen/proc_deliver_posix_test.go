//go:build darwin || linux

package codegen

import (
	"errors"
	"testing"
)

// A signal delivered to the guest only (ReachGuest) is the guest's until
// it becomes a command, and dropped from then on; one delivered to the
// process (ReachProcess) is the command's then, as PostSignal's is.
func TestDeliverSignal_ReachesAsAsked(t *testing.T) {
	root, m := newProcTestStubs(t)
	child, cm, _, input, statusFd, exited := execingChild(t, root, m)
	defer exited(0)
	for _, reach := range []SignalReach{ReachGuest, ReachProcess} {
		child.DeliverSignal(wasiSIGUSR1, reach)
		if got, want := takeSignals(t, child, cm), signalMask(wasiSIGUSR1); got != want {
			t.Fatalf("reach %d: the guest took %#x, want %#x", reach, got, want)
		}
	}
	child.DeliverSignal(wasiSIGUSR1, SignalReach(7))
	if got := takeSignals(t, child, cm); got != 0 {
		t.Fatalf("a reach of no such kind delivered %#x", got)
	}

	ended := execIn(t, child, cm, "/bin/sh", "-c", "read x; exit 3")
	awaitExeced(t, root, m, statusFd)
	child.DeliverSignal(wasiSIGUSR1, ReachGuest)
	if rc := root.Fd_close(m, input); rc != _wasiESUCCESS {
		t.Fatalf("Fd_close rc=%d", rc)
	}
	var exit *WasiExitError
	if end, _ := (<-ended).(error); !errors.As(end, &exit) || exit.Code != 3 {
		t.Fatalf("the guest ended with %v, want an exit of 3: a signal for the guest only reached the command", end)
	}

	root2, m2 := newProcTestStubs(t)
	child2, cm2, _, input2, statusFd2, exited2 := execingChild(t, root2, m2)
	defer exited2(0)
	defer closeFd(t, root2, m2, input2)
	ended2 := execIn(t, child2, cm2, "/bin/sh", "-c", "read x")
	awaitExeced(t, root2, m2, statusFd2)
	child2.DeliverSignal(wasiSIGUSR1, ReachProcess)
	var killed *WasiSignalError
	if end, _ := (<-ended2).(error); !errors.As(end, &killed) || killed.Signal != wasiSIGUSR1 {
		t.Fatalf("the guest ended with %v, want killed by SIGUSR1", end)
	}
}
