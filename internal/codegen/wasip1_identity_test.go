package codegen

import (
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"testing"
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

// wasiRecordReader walks a record handed to the guest.
type wasiRecordReader struct {
	t   *testing.T
	rec []byte
}

func (r *wasiRecordReader) u32() uint32 {
	r.t.Helper()
	if len(r.rec) < 4 {
		r.t.Fatalf("record ends inside a u32")
	}
	v := binary.LittleEndian.Uint32(r.rec)
	r.rec = r.rec[4:]
	return v
}

func (r *wasiRecordReader) str() string {
	r.t.Helper()
	n := int(r.u32())
	if len(r.rec) < n {
		r.t.Fatalf("record ends inside a string of %d bytes", n)
	}
	s := string(r.rec[:n])
	r.rec = r.rec[n:]
	return s
}

func TestProcIDsOfAnIsolatedGuest(t *testing.T) {
	w := DefaultWASI()
	if got, want := procIDs(t, w), [6]uint32{42, 1, 0, 0, 0, 0}; got != want {
		t.Fatalf("ids = %v, want %v", got, want)
	}
}

func TestProcIDsOfTheHostProcess(t *testing.T) {
	w := DefaultWASI()
	w.SetHostProcess(true)
	want := [6]uint32{
		uint32(os.Getpid()), uint32(os.Getppid()),
		uint32(os.Getuid()), uint32(os.Geteuid()),
		uint32(os.Getgid()), uint32(os.Getegid()),
	}
	if got := procIDs(t, w); got != want {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	// A forked instance has the same identity.
	child := w.Fork()
	defer child.CloseAll()
	if got := procIDs(t, child); [4]uint32(got[2:]) != [4]uint32(want[2:]) {
		t.Fatalf("forked user and group ids = %v, want %v", got[2:], want[2:])
	}
}

func TestProcGroups(t *testing.T) {
	const bufPtr, countPtr = 256, 64
	m := newForkTestModule()

	isolated := DefaultWASI()
	if rc := isolated.Proc_groups(m, bufPtr, 16, countPtr); rc != _wasiESUCCESS {
		t.Fatalf("isolated Proc_groups rc=%d", rc)
	}
	if n := readU32(m.memory, countPtr); n != 0 {
		t.Fatalf("an isolated guest has %d supplementary groups, want none", n)
	}

	want, err := os.Getgroups()
	if err != nil {
		t.Skipf("the host does not report groups: %v", err)
	}
	w := DefaultWASI()
	w.SetHostProcess(true)
	// capacity 0 asks for the count only
	if rc := w.Proc_groups(m, bufPtr, 0, countPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_groups(count) rc=%d", rc)
	}
	if n := readU32(m.memory, countPtr); int(n) != len(want) {
		t.Fatalf("group count = %d, want %d", n, len(want))
	}
	if len(want) > 0 {
		if rc := w.Proc_groups(m, bufPtr, int32(len(want))-1, countPtr); len(want) > 1 && rc != -_wasiERANGE {
			t.Fatalf("Proc_groups into a short buffer rc=%d, want -ERANGE", rc)
		}
	}
	if rc := w.Proc_groups(m, bufPtr, int32(len(want)), countPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_groups rc=%d", rc)
	}
	for i, gid := range want {
		if got := readU32(m.memory, bufPtr+i*4); got != uint32(gid) {
			t.Fatalf("group %d = %d, want %d", i, got, gid)
		}
	}
}

func TestProcUserLookup(t *testing.T) {
	const namePtr, bufPtr, neededPtr = 64, 1024, 512
	m := newForkTestModule()
	uid := int32(os.Getuid())

	isolated := DefaultWASI()
	if rc := isolated.Proc_user_by_id(m, uid, bufPtr, 4096, neededPtr); rc != -_wasiENOENT {
		t.Fatalf("an isolated guest found a user: rc=%d, want -ENOENT", rc)
	}

	host, err := user.Current()
	if err != nil {
		t.Skipf("the host has no entry for the current user: %v", err)
	}
	w := DefaultWASI()
	w.SetHostProcess(true)

	// A buffer that is too small reports the size to come back with.
	if rc := w.Proc_user_by_id(m, uid, bufPtr, 4, neededPtr); rc != -_wasiERANGE {
		t.Fatalf("short buffer rc=%d, want -ERANGE", rc)
	}
	needed := int32(readU32(m.memory, neededPtr))
	if needed <= 8 {
		t.Fatalf("needed = %d, want more than the two ids", needed)
	}
	if rc := w.Proc_user_by_id(m, uid, bufPtr, needed, neededPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_user_by_id rc=%d", rc)
	}
	decode := func() (gotUID, gotGID uint32, name, gecos, dir, shell string) {
		r := &wasiRecordReader{t: t, rec: m.memory[bufPtr : bufPtr+int(readU32(m.memory, neededPtr))]}
		gotUID, gotGID = r.u32(), r.u32()
		name, gecos, dir, shell = r.str(), r.str(), r.str(), r.str()
		if len(r.rec) != 0 {
			t.Fatalf("%d bytes left after the record", len(r.rec))
		}
		return
	}
	gotUID, gotGID, name, gecos, dir, shell := decode()
	if strconv.FormatUint(uint64(gotUID), 10) != host.Uid || strconv.FormatUint(uint64(gotGID), 10) != host.Gid ||
		name != host.Username || gecos != host.Name || dir != host.HomeDir || shell != "" {
		t.Fatalf("record = (%d, %d, %q, %q, %q, %q), want user %+v", gotUID, gotGID, name, gecos, dir, shell, host)
	}

	// The same entry by name.
	copy(m.memory[namePtr:], host.Username)
	if rc := w.Proc_user_by_name(m, namePtr, int32(len(host.Username)), bufPtr, 4096, neededPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_user_by_name rc=%d", rc)
	}
	if byNameUID, _, byName, _, _, _ := decode(); byNameUID != gotUID || byName != host.Username {
		t.Fatalf("by name: uid %d name %q, want %d %q", byNameUID, byName, gotUID, host.Username)
	}

	const missing = "no-such-user-in-any-database"
	copy(m.memory[namePtr:], missing)
	if rc := w.Proc_user_by_name(m, namePtr, int32(len(missing)), bufPtr, 4096, neededPtr); rc != -_wasiENOENT {
		t.Fatalf("lookup of a missing user rc=%d, want -ENOENT", rc)
	}
}

func TestProcGroupLookup(t *testing.T) {
	const namePtr, bufPtr, neededPtr = 64, 1024, 512
	m := newForkTestModule()
	gid := int32(os.Getgid())

	isolated := DefaultWASI()
	if rc := isolated.Proc_group_by_id(m, gid, bufPtr, 4096, neededPtr); rc != -_wasiENOENT {
		t.Fatalf("an isolated guest found a group: rc=%d, want -ENOENT", rc)
	}

	host, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("the host has no entry for the current group: %v", err)
	}
	w := DefaultWASI()
	w.SetHostProcess(true)
	if rc := w.Proc_group_by_id(m, gid, bufPtr, 4096, neededPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_group_by_id rc=%d", rc)
	}
	r := &wasiRecordReader{t: t, rec: m.memory[bufPtr : bufPtr+int(readU32(m.memory, neededPtr))]}
	if gotGID, name := r.u32(), r.str(); gotGID != uint32(gid) || name != host.Name || len(r.rec) != 0 {
		t.Fatalf("record = (%d, %q) + %d bytes, want (%d, %q)", gotGID, name, len(r.rec), gid, host.Name)
	}

	copy(m.memory[namePtr:], host.Name)
	if rc := w.Proc_group_by_name(m, namePtr, int32(len(host.Name)), bufPtr, 4096, neededPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_group_by_name rc=%d", rc)
	}
	if byNameGID := readU32(m.memory, bufPtr); byNameGID != uint32(gid) {
		t.Fatalf("by name: gid %d, want %d", byNameGID, gid)
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
	if _, known := hostSignalOf(16); known { // SIGSTKFLT: Linux only, never sent
		t.Errorf("signal 16 has a host signal")
	}
	if sig, known := hostSignalOf(0); !known || sig != 0 {
		t.Errorf("hostSignalOf(0) = %v, %v; want the probe itself", sig, known)
	}
}

// startSleeper starts a host process that only waits, outside of any
// instance's process table.
func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep command on this host")
	}
	cmd := exec.Command(path, "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func TestProcKillReachesHostProcessesOnlyAsTheHostProcess(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the runtime signals host processes on darwin and linux only")
	}
	cmd := startSleeper(t)
	pid := int32(cmd.Process.Pid)
	m := newForkTestModule()

	isolated := DefaultWASI()
	if rc := isolated.Proc_kill(m, pid, 0); rc != -_wasiESRCH {
		t.Fatalf("an isolated guest reached host pid %d: rc=%d, want -ESRCH", pid, rc)
	}

	w := DefaultWASI()
	w.SetHostProcess(true)
	if rc := w.Proc_kill(m, pid, 0); rc != _wasiESUCCESS {
		t.Fatalf("probe of host pid %d rc=%d", pid, rc)
	}
	// SIGUSR1 has a different number on every host; the process must die of
	// SIGUSR1 whatever the guest's number for it is here.
	if rc := w.Proc_kill(m, pid, wasiSIGUSR1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_kill rc=%d", rc)
	}
	err := cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGUSR1 {
		t.Fatalf("the process ended with %v (%v), want death by SIGUSR1", cmd.ProcessState, err)
	}
	if got := encodeWaitStatus(cmd.ProcessState); got != wasiSIGUSR1 {
		t.Fatalf("wait status = %#x, want the guest's SIGUSR1 (%d)", got, wasiSIGUSR1)
	}
	if rc := w.Proc_kill(m, pid, 0); rc != -_wasiESRCH {
		t.Fatalf("probe of the reaped process rc=%d, want -ESRCH", rc)
	}
	if rc := w.Proc_kill(m, pid, 16); rc != -_wasiEINVAL {
		t.Fatalf("a signal the host does not have rc=%d, want -EINVAL", rc)
	}
}

// A pid token never names a host process, even after the process it stood
// for has been reaped and whatever the host uses that number for.
func TestProcKillNeverSendsATokenToTheHost(t *testing.T) {
	w := DefaultWASI()
	w.SetHostProcess(true)
	m := newForkTestModule()
	pid, exited := w.NewProc(nil)
	exited(0)
	const statusPtr = 64
	if rc := w.Proc_wait(m, pid, 0, statusPtr); rc != _wasiESUCCESS {
		t.Fatalf("Proc_wait rc=%d", rc)
	}
	if rc := w.Proc_kill(m, pid, 0); rc != -_wasiESRCH {
		t.Fatalf("probe of a reaped token rc=%d, want -ESRCH", rc)
	}
	for _, group := range []int32{0, -1, -pid} {
		if rc := w.Proc_kill(m, group, 0); rc != -_wasiESRCH {
			t.Fatalf("Proc_kill(%d) rc=%d, want -ESRCH", group, rc)
		}
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
	w := DefaultWASI()
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
