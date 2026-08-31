package codegen

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// writeCStr writes s plus a NUL at off and returns off.
func writeCStr(m *Module, off int32, s string) int32 {
	copy(m.memory[off:], append([]byte(s), 0))
	return off
}

// writeArgv lays out a NULL-terminated char** for argv at off, with each
// string packed starting at strOff. Returns the argv pointer.
func writeArgv(m *Module, off, strOff int32, argv []string) int32 {
	p := strOff
	ptrs := make([]int32, len(argv))
	for i, a := range argv {
		ptrs[i] = p
		writeCStr(m, p, a)
		p += int32(len(a)) + 1
	}
	for i, sp := range ptrs {
		binary.LittleEndian.PutUint32(m.memory[off+int32(i*4):], uint32(sp))
	}
	binary.LittleEndian.PutUint32(m.memory[off+int32(len(ptrs)*4):], 0) // NULL term
	return off
}

func TestWasi_ProcSpawnWait(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.stdout = &out
	w.stderr = &bytes.Buffer{}
	w.stdin = bytes.NewReader(nil)

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "hello-proc"})
	const pidOff, statusOff int32 = 4000, 4004

	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	if pid == 0 {
		t.Fatal("pid not written")
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 0 {
		t.Errorf("exit code = %d, want 0 (status=%#x)", exit, status)
	}
	if got := out.String(); got != "hello-proc\n" {
		t.Errorf("child stdout = %q, want %q", got, "hello-proc\n")
	}
}

func TestWasi_ProcSpawnExitCode(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	w, m := newTestStubs(t, t.TempDir())
	w.stdout, w.stderr, w.stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)

	pathOff := writeCStr(m, 1000, "/bin/sh")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "exit 7"})
	const pidOff, statusOff int32 = 4000, 4004

	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 7 {
		t.Errorf("exit code = %d, want 7", exit)
	}
}

func TestWasi_ProcSpawnExecHookDenies(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.stdout, w.stderr, w.stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	var seen string
	w.SetExecHook(func(path string, argv []string) bool { seen = path; return false })

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "x"})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiEACCES {
		t.Fatalf("denied spawn rc=%d, want -EACCES", rc)
	}
	if seen != "/bin/echo" {
		t.Errorf("exec hook saw %q", seen)
	}
}

func TestWasi_ProcSpawnNotFound(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.stdout, w.stderr, w.stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	pathOff := writeCStr(m, 1000, "/no/such/binary-xyz")
	argvOff := writeArgv(m, 2000, 3000, []string{"/no/such/binary-xyz"})
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, 4000); rc != -_wasiENOENT {
		t.Fatalf("missing binary rc=%d, want -ENOENT", rc)
	}
}

func TestWasi_ProcWaitUnknownPID(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	if rc := w.Proc_wait(m, 999999, 0, 4000); rc != -_wasiECHILD {
		t.Errorf("unknown pid rc=%d, want -ECHILD", rc)
	}
}

func TestWasi_ProcWaitWNOHANG(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	w, m := newTestStubs(t, t.TempDir())
	w.stdout, w.stderr, w.stdin = &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil)
	pathOff := writeCStr(m, 1000, "/bin/sh")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/sh", "-c", "sleep 0.3; exit 3"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))
	// Immediately: WNOHANG should report not-ready (EAGAIN), child still running.
	if rc := w.Proc_wait(m, pid, 1, statusOff); rc != -_wasiEAGAIN {
		t.Fatalf("WNOHANG early rc=%d, want -EAGAIN", rc)
	}
	// Block until done.
	deadline := time.Now().Add(5 * time.Second)
	for {
		rc := w.Proc_wait(m, pid, 1, statusOff)
		if rc == _wasiESUCCESS {
			break
		}
		if rc != -_wasiEAGAIN {
			t.Fatalf("WNOHANG poll rc=%d", rc)
		}
		if time.Now().After(deadline) {
			t.Fatal("child never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	status := int32(binary.LittleEndian.Uint32(m.memory[statusOff:]))
	if exit := (status >> 8) & 0xff; exit != 3 {
		t.Errorf("exit=%d, want 3", exit)
	}
}

func TestWasi_PipeCapture(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo not available")
	}
	w, m := newTestStubs(t, t.TempDir())
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}

	const pipeOut int32 = 5000
	if rc := w.Pipe(m, pipeOut); rc != _wasiESUCCESS {
		t.Fatalf("Pipe rc=%d", rc)
	}
	readFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut:]))
	writeFd := int32(binary.LittleEndian.Uint32(m.memory[pipeOut+4:]))

	pathOff := writeCStr(m, 1000, "/bin/echo")
	argvOff := writeArgv(m, 2000, 3000, []string{"/bin/echo", "captured-output"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, -1, writeFd, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(binary.LittleEndian.Uint32(m.memory[pidOff:]))

	w.mu.Lock()
	wop := w.fdTable[writeFd]
	rop := w.fdTable[readFd]
	w.mu.Unlock()
	if wop != nil && wop.f != nil {
		if err := wop.f.Close(); err != nil {
			t.Fatalf("close write end: %v", err)
		}
	}
	buf := make([]byte, 256)
	var got []byte
	for {
		n, err := rop.f.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if rc := w.Proc_wait(m, pid, 0, statusOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if string(got) != "captured-output\n" {
		t.Errorf("captured = %q, want %q", string(got), "captured-output\\n")
	}
}
