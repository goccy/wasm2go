package codegen

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// procIDs reads the six ids Proc_ids reports.
func procIDs(t *testing.T, w *WasiStubs) [6]uint32 {
	t.Helper()
	m := newForkTestModule()
	if rc := w.Proc_ids(m, 64); rc != _wasiESUCCESS {
		t.Fatalf("Proc_ids rc=%d", rc)
	}
	var ids [6]uint32
	for i := range ids {
		ids[i] = binary.LittleEndian.Uint32(m.memory[64+i*4:])
	}
	return ids
}

// procTimes reads the four times Proc_times reports, and its result.
func procTimes(w *WasiStubs) ([4]uint64, int32) {
	m := newForkTestModule()
	var times [4]uint64
	rc := w.Proc_times(m, 64)
	for i := range times {
		times[i] = binary.LittleEndian.Uint64(m.memory[64+i*8:])
	}
	return times, rc
}

// testProcess is a Process with fixed answers.
type testProcess struct {
	ids      ProcessIDs
	times    ProcessTimes
	timesErr error
	umask    os.FileMode
}

func (p testProcess) IDs() ProcessIDs              { return p.ids }
func (p testProcess) Times() (ProcessTimes, error) { return p.times, p.timesErr }
func (p testProcess) Umask() os.FileMode           { return p.umask }

func TestProcIDsOfAnIsolatedGuest(t *testing.T) {
	w := NewWASI(WASIConfig{})
	want := [6]uint32{42, 1, 0, 0, 0, 0}
	if got := procIDs(t, w); got != want {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	if rc := w.Proc_ids(newForkTestModule(), 1<<16-8); rc != -_wasiEFAULT {
		t.Fatalf("Proc_ids past the memory rc=%d, want -EFAULT", rc)
	}
}

func TestProcTimes(t *testing.T) {
	w, m := newProcTestStubs(t)
	if rc := w.Proc_times(m, 1<<16-8); rc != -_wasiEFAULT {
		t.Fatalf("Proc_times past the memory rc=%d, want -EFAULT", rc)
	}
	if times, rc := procTimes(w); rc != _wasiESUCCESS || times != [4]uint64{} {
		t.Fatalf("times of an isolated guest = %v rc=%d, want all zero", times, rc)
	}
	w.cfg.Process = testProcess{times: ProcessTimes{User: 1, System: 2, ChildrenUser: 3, ChildrenSystem: time.Second}}
	if times, rc := procTimes(w); rc != _wasiESUCCESS || times != [4]uint64{1, 2, 3, uint64(time.Second)} {
		t.Fatalf("times of the installed process = %v rc=%d", times, rc)
	}
	w.cfg.Process = testProcess{timesErr: errors.ErrUnsupported}
	if _, rc := procTimes(w); rc != -_wasiENOSYS {
		t.Fatalf("Proc_times of a process without times rc=%d, want -ENOSYS", rc)
	}
	w.cfg.Process = testProcess{timesErr: syscall.EPERM}
	if _, rc := procTimes(w); rc != -_wasiEPERM {
		t.Fatalf("Proc_times failing with EPERM rc=%d, want -EPERM", rc)
	}
}

// HostProcess reports the ids, CPU times and umask of the host process, and
// fails where the umask cannot be read without changing it;
// HostProcessUmask the same with the umask it is given.
func TestHostProcess(t *testing.T) {
	want := ProcessIDs{
		PID: int32(os.Getpid()), PPID: int32(os.Getppid()),
		UID: int32(os.Getuid()), EUID: int32(os.Geteuid()),
		GID: int32(os.Getgid()), EGID: int32(os.Getegid()),
	}
	if runtime.GOOS == "linux" {
		host, err := HostProcess()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := host.Umask(), hostUmask(t); got != want {
			t.Fatalf("Umask = %o, want %o", got, want)
		}
		if got := host.IDs(); got != want {
			t.Fatalf("IDs = %+v, want %+v", got, want)
		}
	} else if host, err := HostProcess(); !errors.Is(err, errors.ErrUnsupported) || host != nil {
		t.Fatalf("HostProcess() = %v, %v; want ErrUnsupported", host, err)
	}
	p := HostProcessUmask(0o027)
	if got := p.Umask(); got != 0o027 {
		t.Fatalf("HostProcessUmask(027).Umask() = %o", got)
	}
	if got := p.IDs(); got != want {
		t.Fatalf("IDs = %+v, want %+v", got, want)
	}
	w := NewWASI(WASIConfig{Process: p})
	if got := procIDs(t, w); got[0] != uint32(want.PID) || got[1] != uint32(want.PPID) {
		t.Fatalf("proc_ids of the host process = %v, want pid %d ppid %d", got, want.PID, want.PPID)
	}

	before, err := p.Times()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("Times error = %v, want ErrUnsupported", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{before.User, before.System, before.ChildrenUser, before.ChildrenSystem} {
		if d < 0 {
			t.Fatalf("Times = %+v: a time is negative", before)
		}
	}
	// Every call of Times is CPU work, until its own times show some.
	for {
		after, err := p.Times()
		if err != nil {
			t.Fatal(err)
		}
		if after.User+after.System > before.User+before.System {
			break
		}
	}
	if HostWASIConfig().Process != nil {
		t.Fatal("HostWASIConfig has a Process; the embedder sets one")
	}
}

// countingProcess is a testProcess that counts the calls of IDs.
type countingProcess struct {
	testProcess
	idsCalls *int
}

func (p countingProcess) IDs() ProcessIDs {
	*p.idsCalls++
	return p.testProcess.IDs()
}

// An open of a name that is none of the guest's own descriptors' does not
// ask the Process for its ids: only a name under proc/N/fd needs the pid.
func TestPathOpenAsksForThePIDOnlyUnderProc(t *testing.T) {
	w, m, _ := memTestStubs(t)
	calls := 0
	w.cfg.Process = countingProcess{testProcess{ids: ProcessIDs{PID: 7}}, &calls}
	closeTestFd(t, w, m, createTestFile(t, w, "a.txt"))
	if _, errno := w.pathOpen("dev/fd/1", 1, 0, 1<<6 /* FD_WRITE */, 0); errno != _wasiESUCCESS {
		t.Fatalf("open dev/fd/1 errno=%d", errno)
	}
	if calls != 0 {
		t.Fatalf("IDs called %d times for names outside proc/N/fd", calls)
	}
	fd, errno := w.pathOpen("proc/7/fd/1", 1, 0, 1<<6, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open proc/7/fd/1 errno=%d", errno)
	}
	closeTestFd(t, w, m, fd)
	if calls != 1 {
		t.Fatalf("IDs called %d times for proc/7/fd/1, want 1", calls)
	}
}

// The configured Process is the guest's pid in every place that names it,
// and its umask is the one the guest starts with, a forked instance's too.
func TestConfigProcess(t *testing.T) {
	w, m, _ := memTestStubs(t)
	w.cfg.Process = testProcess{
		ids:   ProcessIDs{PID: 7, PPID: 6, UID: 501, EUID: 502, GID: 20, EGID: 21},
		umask: 0o077,
	}
	want := [6]uint32{7, 6, 501, 502, 20, 21}
	if got := procIDs(t, w); got != want {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	fd, errno := w.pathOpen("proc/7/fd", 0, 0x2 /* O_DIRECTORY */, 1<<1, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open proc/7/fd errno=%d", errno)
	}
	closeTestFd(t, w, m, fd)
	if _, errno := w.pathOpen("proc/42/fd", 0, 0x2, 1<<1, 0); errno != _wasiENOENT {
		t.Fatalf("open proc/42/fd of another pid errno=%d, want ENOENT", errno)
	}
	if got := createWithMode(t, w, m, "f", 0o666); got != 0o600 {
		t.Fatalf("file under the installed umask = %o, want 600", got)
	}

	child := w.Fork()
	t.Cleanup(func() {
		if err := child.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	if prev := child.Proc_umask(newForkTestModule(), 0o022); prev != 0o077 {
		t.Fatalf("starting umask of a forked instance = %o, want 077", prev)
	}
}

// A pid token is never the pid or the ppid the Process reports.
func TestPIDTokensAvoidTheProcessIDs(t *testing.T) {
	w, _ := newProcTestStubs(t)
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 1000, PPID: 1001}}
	first, _ := w.NewProc(nil)
	second, _ := w.NewProc(nil)
	if first != 1002 || second != 1003 {
		t.Fatalf("pid tokens = %d, %d, want 1002, 1003", first, second)
	}
	w.cfg.Process = testProcess{ids: ProcessIDs{PID: 1005, PPID: 1}}
	got := []int32{}
	for range 2 {
		pid, _ := w.NewProc(nil)
		got = append(got, pid)
	}
	if got[0] != 1004 || got[1] != 1006 {
		t.Fatalf("pid tokens = %v, want [1004 1006]", got)
	}
}

// A spawned process is signalled under the host's number for the signal.
func TestProcKillMapsTheSignalForASpawnedProcess(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the runtime signals host processes on darwin and linux only")
	}
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep command on this host")
	}
	w := NewWASI(WASIConfig{Exec: AllowAllExec})
	m := newForkTestModule()
	const pathPtr, argvPtr, arg0Ptr, arg1Ptr, pidPtr, statusPtr = 1024, 2048, 2100, 2200, 3000, 3008
	copy(m.memory[pathPtr:], path+"\x00")
	copy(m.memory[arg0Ptr:], "sleep\x00")
	copy(m.memory[arg1Ptr:], "600\x00")
	binary.LittleEndian.PutUint32(m.memory[argvPtr:], arg0Ptr)
	binary.LittleEndian.PutUint32(m.memory[argvPtr+4:], arg1Ptr)
	binary.LittleEndian.PutUint32(m.memory[argvPtr+8:], 0)
	if rc := w.Proc_spawn(m, pathPtr, argvPtr, 0, -1, -1, -1, 0, pidPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(readU32(m.memory, pidPtr))
	t.Cleanup(func() {
		if rc := w.Proc_kill(m, pid, wasiSIGKILL); rc != _wasiESUCCESS && rc != -_wasiESRCH {
			t.Errorf("Proc_kill of the command at cleanup rc=%d", rc)
		}
	})
	if rc := w.Proc_kill(m, pid, wasiSIGUSR2); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	if rc := w.Proc_wait(m, pid, 0, statusPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if status := int32(readU32(m.memory, statusPtr)); status != wasiSIGUSR2 {
		t.Fatalf("wait status = %#x, want death by the guest's SIGUSR2 (%d)", status, wasiSIGUSR2)
	}
}
