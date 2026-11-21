//go:build darwin || linux

package codegen

import (
	"runtime"
	"syscall"
	"testing"
)

// An instance that has been sent SIGKILL is on its way to its end: it starts
// no command.

// killedInstance forks an instance of w with a registered guest and posts
// SIGKILL to it.
func killedInstance(t *testing.T, w *WasiStubs) (*WasiStubs, *Module) {
	t.Helper()
	instances, modules := sharedWaiters(t, w, 1)
	instances[0].PostSignal(wasiSIGKILL)
	return instances[0], modules[0]
}

func TestKill_AKilledProcessStartsNoCommand(t *testing.T) {
	w, _ := newProcTestStubs(t)
	child, cm := killedInstance(t, w)
	pathOff := writeCStr(cm, 1000, "/bin/sh")
	argvOff := writeArgv(cm, 2000, 3000, []string{"/bin/sh", "-c", "exit 0"})
	if rc := child.Proc_spawn(cm, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiEINTR {
		t.Fatalf("Proc_spawn of a killed process rc=%d, want -EINTR", rc)
	}
}

// Every signal crosses to the host under the host's own number for it, and
// comes back under the guest's.
func TestSignalNumbersAreMappedByIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the runtime maps signals on darwin and linux only")
	}
	for sig, want := range map[int32]syscall.Signal{
		wasiSIGHUP:  syscall.SIGHUP,
		wasiSIGKILL: syscall.SIGKILL,
		wasiSIGUSR1: syscall.SIGUSR1,
		wasiSIGUSR2: syscall.SIGUSR2,
		wasiSIGTERM: syscall.SIGTERM,
		wasiSIGCHLD: syscall.SIGCHLD,
		wasiSIGCONT: syscall.SIGCONT,
		wasiSIGSTOP: syscall.SIGSTOP,
		wasiSIGURG:  syscall.SIGURG,
		wasiSIGIO:   syscall.SIGIO,
		wasiSIGSYS:  syscall.SIGSYS,
	} {
		got, known := hostSignalOf(sig)
		if !known || got != want {
			t.Errorf("hostSignalOf(%d) = %v, %v; want %v", sig, got, known, want)
		}
		if back := guestSignalOf(want); back != sig {
			t.Errorf("guestSignalOf(%v) = %d, want %d", want, back, sig)
		}
	}
	if sig, known := hostSignalOf(0); !known || sig != 0 {
		t.Errorf("hostSignalOf(0) = %v, %v; want the probe itself", sig, known)
	}
}

// SIGSTKFLT, SIGPWR and the real-time signals go to a host process under
// the same number on linux, which numbers them as the guest does, and are
// unknown on darwin, which has none of them.
func TestKill_SignalsByNumberAreTheHostsOnLinux(t *testing.T) {
	for _, sig := range []int32{16, 30, 32, 40, 64} {
		hostSig, known := hostSignalOf(sig)
		if runtime.GOOS == "linux" && (!known || hostSig != syscall.Signal(sig)) {
			t.Errorf("hostSignalOf(%d) = %v, %v; want %d", sig, hostSig, known, sig)
		}
		if runtime.GOOS == "darwin" && known {
			t.Errorf("hostSignalOf(%d) is known on darwin", sig)
		}
	}
}

// A host signal the guest has no number for keeps the host's number in a
// wait status.
func TestKill_WaitStatusKeepsAHostSignalWithoutAGuestNumber(t *testing.T) {
	unknown := syscall.Signal(16) // SIGSTKFLT on linux
	if runtime.GOOS == "darwin" {
		unknown = syscall.Signal(7) // SIGEMT
	}
	if got := encodeHostWaitStatus(syscall.WaitStatus(unknown)); got != int32(unknown) {
		t.Fatalf("wait status = %#x, want %#x", got, int32(unknown))
	}
}

// SIGKILL ends a spawned process, which is then known no more once waited
// for.
func TestKill_SIGKILLOfASpawnedProcess(t *testing.T) {
	w, m := newProcTestStubs(t)
	pid := spawnTestProc(t, w, m, "/bin/sleep", "30")
	if rc := w.Proc_kill(m, pid, wasiSIGKILL); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 0, 4004); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, 4004)); status != wasiSIGKILL {
		t.Fatalf("status = %#x, want death by SIGKILL", status)
	}
	if rc := w.Proc_kill(m, pid, 0); rc != -_wasiESRCH {
		t.Fatalf("probe of the reaped process rc=%d, want -ESRCH", rc)
	}
}
