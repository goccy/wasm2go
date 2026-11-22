//go:build darwin || linux

package codegen

import (
	"bytes"
	"strconv"
	"sync"
	"syscall"
	"testing"
)

// lineWriter keeps what is written to it and sends each line it completes
// on lines.
type lineWriter struct {
	mu    sync.Mutex
	buf   []byte
	lines chan string
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		line, rest, found := bytes.Cut(l.buf, []byte("\n"))
		if !found {
			return len(p), nil
		}
		l.lines <- string(line)
		l.buf = rest
	}
}

// KillCommands kills a command that runs and returns once it has ended,
// though a process it left behind holds the output the runtime copies
// open; the command stays to be waited for, with the status of its death.
func TestKillCommands_EndsTheCommands(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	out := &lineWriter{lines: make(chan string, 4)}
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), out, &bytes.Buffer{}
	pid := spawnWithStreams(t, w, m, -1, -1, -1, "/bin/sh", "-c", "sleep 1000 & echo $!; exec sleep 1000")
	var line string
	select {
	case line = <-out.lines:
	case <-commandEnd(w, pid):
		t.Fatal("the command ended before it told the pid it left behind")
	}
	left, err := strconv.Atoi(line)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Kill(left, syscall.SIGKILL); err != nil {
			t.Errorf("kill the process left behind: %v", err)
		}
	})
	if err := w.KillCommands(); err != nil {
		t.Fatalf("KillCommands: %v", err)
	}
	const statusOff int32 = 4004
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait WNOHANG after KillCommands rc=%d, want the ended command", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != uint32(wasiSIGKILL) {
		t.Fatalf("wait status = %#x, want death by SIGKILL", status)
	}
	if err := w.KillCommands(); err != nil {
		t.Fatalf("KillCommands without commands: %v", err)
	}
}

// commandEnd returns the channel the end of the process pid of w closes.
func commandEnd(w *WasiStubs, pid int32) <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.procs[pid].done
}

// KillCommands of a command that has ended and not been waited for
// succeeds, and leaves it to be waited for with its status.
func TestKillCommands_OfAnEndedCommand(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	pid := spawnWithStreams(t, w, m, -1, -1, -1, "/bin/sh", "-c", "exit 3")
	<-commandEnd(w, pid)
	if err := w.KillCommands(); err != nil {
		t.Fatalf("KillCommands of an ended command: %v", err)
	}
	const statusOff int32 = 4004
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := readU32(m.memory, int(statusOff)); status != 3<<8 {
		t.Fatalf("wait status = %#x, want exit 3", status)
	}
}
