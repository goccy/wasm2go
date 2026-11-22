package codegen

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Where the tests of this file keep their values in a guest's memory.
const (
	syscallOutOff  int32 = 7000
	syscallArgsOff int32 = 7900
)

// The Linux ABI's numbers of calls the tests of this file make, which the
// runtime does not name itself.
const (
	linuxSysWrite  = 64
	linuxSysGetpid = 172
)

// fakeSyscalls is a Syscalls that records the calls and answers err.
type fakeSyscalls struct {
	calls []Syscall
	err   error
}

func (f *fakeSyscalls) Syscall(call Syscall) (int64, error) {
	f.calls = append(f.calls, call)
	return call.Number * 2, f.err
}

func TestSyscall_TheCallReachesTheSyscalls(t *testing.T) {
	w := NewWASI(WASIConfig{})
	m := newGuestModule(1 << 16)
	for i := range 3 {
		binary.LittleEndian.PutUint64(m.memory[int(syscallArgsOff)+8*i:], uint64(10+i))
	}
	if rc := w.Sys_syscall(m, 7, syscallArgsOff, 3, 0b1010, syscallOutOff); rc != -_wasiENOSYS {
		t.Fatalf("Sys_syscall without Syscalls rc=%d, want -ENOSYS", rc)
	}
	calls := &fakeSyscalls{}
	w.cfg.Syscalls = calls
	if rc := w.Sys_syscall(m, 7, syscallArgsOff, 3, 0b1010, syscallOutOff); rc != _wasiESUCCESS {
		t.Fatalf("Sys_syscall rc=%d", rc)
	}
	if got := readU64(m.memory, int(syscallOutOff)); got != 14 {
		t.Fatalf("result %d, want 14", got)
	}
	call := calls.calls[0]
	if call.Number != 7 || call.Args != [6]uint64{10, 11, 12} || call.Pointers != 0b010 || len(call.Memory) != 1<<16 || call.Forked {
		t.Fatalf("the call was %+v", call)
	}
	child := w.Fork()
	if rc := child.Sys_syscall64(m, 7, int64(syscallArgsOff), 0, 0, int64(syscallOutOff)); rc != _wasiESUCCESS || !calls.calls[1].Forked {
		t.Fatalf("Sys_syscall64 of a copy rc=%d, the call %+v", rc, calls.calls[1])
	}
	for err, want := range map[error]int32{ErrSyscallNotMade: sysSyscallNotMade, errors.ErrUnsupported: -_wasiENOSYS, syscall.EPERM: -_wasiEPERM} {
		calls.err = err
		if rc := w.Sys_syscall(m, 7, syscallArgsOff, 0, 0, syscallOutOff); rc != want {
			t.Errorf("Sys_syscall failing with %v rc=%d, want %d", err, rc, want)
		}
	}
	for _, c := range []struct {
		nargs, argsPtr, resultPtr, want int32
	}{{7, syscallArgsOff, syscallOutOff, -_wasiEINVAL}, {-1, syscallArgsOff, syscallOutOff, -_wasiEINVAL}, {2, 1<<16 - 8, syscallOutOff, -_wasiEFAULT}, {0, syscallArgsOff, 1 << 16, -_wasiEFAULT}} {
		if rc := w.Sys_syscall(m, 7, c.argsPtr, c.nargs, 0, c.resultPtr); rc != c.want {
			t.Errorf("Sys_syscall(nargs %d, args at %d, result at %d) rc=%d, want %d", c.nargs, c.argsPtr, c.resultPtr, rc, c.want)
		}
	}
}

// hostSyscallTable names the table HostSyscalls has on this host: "linux"
// for every call of the Linux ABI, "darwin" for gettimeofday and getrandom,
// "" for none.
func hostSyscallTable() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64", "linux/arm64", "linux/riscv64", "linux/loong64":
		return "linux"
	case "darwin/amd64", "darwin/arm64":
		return "darwin"
	}
	return ""
}

// A number the Linux ABI does not assign is no call on any host, for the
// root instance and for a copy alike; a call the ABI assigns that depends
// on the host process is not made for a copy.
func TestHostSyscalls_NumbersOfTheLinuxABI(t *testing.T) {
	calls := HostSyscalls()
	for _, number := range []int64{-1, 244, 259, 295, 423, linuxSysRseqSliceYield + 1} {
		for _, forked := range []bool{false, true} {
			if _, err := calls.Syscall(Syscall{Number: number, Forked: forked}); !errors.Is(err, syscall.ENOSYS) {
				t.Errorf("number %d (forked %v): %v, want ENOSYS", number, forked, err)
			}
		}
	}
	if _, err := calls.Syscall(Syscall{Number: linuxSysGetpid, Forked: true}); !errors.Is(err, ErrSyscallNotMade) {
		t.Fatalf("getpid of a copy: %v, want ErrSyscallNotMade", err)
	}
	pid, err := calls.Syscall(Syscall{Number: linuxSysGetpid})
	if hostSyscallTable() != "linux" {
		if !errors.Is(err, syscall.ENOSYS) {
			t.Fatalf("getpid without the table of Linux: %d %v, want ENOSYS", pid, err)
		}
		return
	}
	if err != nil || pid != int64(os.Getpid()) {
		t.Fatalf("getpid %d %v, want %d", pid, err, os.Getpid())
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*os.File{r, w} {
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	mem := make([]byte, 64)
	copy(mem[16:], "written")
	n, err := calls.Syscall(Syscall{Number: linuxSysWrite, Args: [6]uint64{uint64(w.Fd()), 16, 7}, Pointers: 0b010, Memory: mem})
	if err != nil || n != 7 {
		t.Fatalf("write %d %v", n, err)
	}
	got := make([]byte, 7)
	if _, err := r.Read(got); err != nil || string(got) != "written" {
		t.Fatalf("read %q %v", got, err)
	}
	if n, err := calls.Syscall(Syscall{Number: linuxSysWrite, Args: [6]uint64{uint64(w.Fd()), 64, 0}, Pointers: 0b010, Memory: mem}); err != nil || n != 0 {
		t.Fatalf("write of no bytes at the end of the memory: %d %v", n, err)
	}
	if _, err := calls.Syscall(Syscall{Number: linuxSysWrite, Args: [6]uint64{uint64(w.Fd()), 65, 0}, Pointers: 0b010, Memory: mem}); !errors.Is(err, syscall.EFAULT) {
		t.Fatalf("write from past the memory: %v, want EFAULT", err)
	}
}

// The calls of the table are made for a copy where the host has them, with
// their pointers where the table says.
func TestHostSyscalls_ACopyMakesTheCallsOfTheTable(t *testing.T) {
	if hostSyscallTable() == "" {
		t.Skip("no table of system calls here")
	}
	calls := HostSyscalls()
	mem := make([]byte, 64)
	random := Syscall{Number: linuxSysGetrandom, Args: [6]uint64{0, 8, 0}, Pointers: 0b001, Memory: mem, Forked: true}
	if n, err := calls.Syscall(random); err != nil || n != 8 {
		t.Fatalf("getrandom of a copy: %d %v", n, err)
	}
	wrong := random
	wrong.Pointers = 0b010
	if _, err := calls.Syscall(wrong); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("getrandom of a copy with a pointer where a number is: %v, want EINVAL", err)
	}
	before := time.Now().Unix()
	if _, err := calls.Syscall(Syscall{Number: linuxSysGettimeofday, Args: [6]uint64{16}, Pointers: 0b001, Memory: mem, Forked: true}); err != nil {
		t.Fatalf("gettimeofday of a copy: %v", err)
	}
	if sec := int64(readU64(mem, 16)); sec < before || sec > time.Now().Unix() {
		t.Fatalf("gettimeofday of a copy gave %d seconds, want %d or later", sec, before)
	}
}

// Of the calls of the Linux ABI, only the listed ones are made for a copy.
func TestForkedSyscallMadeOnlyForTheTable(t *testing.T) {
	for number, want := range map[int64]bool{linuxSysSchedYield: true, linuxSysUname: true, linuxSysGetpid: false, linuxSysWrite: false, linuxSysWait4: false} {
		if _, made := forkedSyscallMade(number, &[6]uint64{}); made != want {
			t.Errorf("number %d made: %v, want %v", number, made, want)
		}
	}
}

// A call made for a copy has its pointers where its entry says, each with
// its bytes in the guest's memory, or the null pointer.
func TestForkedSyscallArguments(t *testing.T) {
	c := forkedSyscall{pointers: []syscallPointer{{0, 16, -1}, {1, 0, 2}}}
	mem := make([]byte, 64)
	for _, tc := range []struct {
		args     [6]uint64
		pointers uint32
		want     error
	}{
		{[6]uint64{0, 16, 8}, 0b011, nil},
		{[6]uint64{0, 0, 0}, 0b010, nil},
		{[6]uint64{7, 0, 0}, 0b010, syscall.EINVAL},
		{[6]uint64{0, 0, 0}, 0b111, syscall.EINVAL},
		{[6]uint64{56, 0, 0}, 0b001, syscall.EFAULT},
		{[6]uint64{0, 60, 8}, 0b011, syscall.EFAULT},
		{[6]uint64{0, 65, 0}, 0b011, syscall.EFAULT},
	} {
		if err := c.validateArgs(Syscall{Args: tc.args, Pointers: tc.pointers, Memory: mem}); !errors.Is(err, tc.want) {
			t.Errorf("arguments %v, pointers %#b: %v, want %v", tc.args[:3], tc.pointers, err, tc.want)
		}
	}
}

func TestForkedSyscallMadeForAClockButACPUTimeOne(t *testing.T) {
	for _, number := range []int64{linuxSysClockGettime, linuxSysClockGetres} {
		for clock, want := range map[uint64]bool{0: true, 1: true, 2: false, 3: false, uint64(1<<64 - 2): false} {
			if _, got := forkedSyscallMade(number, &[6]uint64{clock}); got != want {
				t.Errorf("call %d of clock %d made: %v, want %v", number, int64(clock), got, want)
			}
		}
	}
}
