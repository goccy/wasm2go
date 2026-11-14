//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// startForeignChild starts a child of the test process the way native code
// does, without the runtime (and without anybody waiting for it).
func startForeignChild(t *testing.T, script string) int32 {
	t.Helper()
	p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", script}, &os.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}
	return int32(p.Pid)
}

// A guest that is the host process waits for a child of its process that
// the runtime did not start — one native code started for it (Proc::FastSpawn
// vforks and execs in its C) — as perl's waitpid does: WNOHANG says it is
// still running, a wait returns how it ended, and once collected it is gone.
// A child that ended before the wait is reported too. A process that is no
// child of the host process is ECHILD.
func TestHostProcess_WaitsForAChildTheRuntimeDidNotStart(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	const statusOff int32 = 7000
	status := func() uint32 { return binary.LittleEndian.Uint32(m.memory[statusOff:]) }

	pid := startForeignChild(t, "sleep 0.3; exit 5")
	if rc := w.Proc_wait(m, pid, 1 /* WNOHANG */, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG while it runs: rc %d, want EAGAIN", rc)
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS || status() != 5<<8 {
		t.Fatalf("wait: rc %d status %#x, want 0 and %#x", rc, status(), 5<<8)
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != -_wasiECHILD {
		t.Fatalf("wait again: rc %d, want ECHILD", rc)
	}

	ended := startForeignChild(t, "exit 7")
	time.Sleep(200 * time.Millisecond)
	if rc := w.Proc_wait(m, ended, 1, statusOff); rc != _wasiESUCCESS || status() != 7<<8 {
		t.Fatalf("WNOHANG after it ended: rc %d status %#x, want 0 and %#x", rc, status(), 7<<8)
	}

	if rc := w.Proc_wait(m, 1, 1, statusOff); rc != -_wasiECHILD {
		t.Fatalf("pid 1: rc %d, want ECHILD", rc)
	}
}
