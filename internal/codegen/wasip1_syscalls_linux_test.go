//go:build linux

package codegen

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// goSyscallNumbers returns the numbers of package syscall's SYS_ constants
// of linux/arch, by name, from the source of the toolchain.
func goSyscallNumbers(t *testing.T, goroot, arch string) map[string]uintptr {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(goroot, "src", "syscall", "zsysnum_linux_"+arch+".go"))
	if err != nil {
		t.Fatal(err)
	}
	numbers := map[string]uintptr{}
	for _, m := range regexp.MustCompile(`(?m)^\s+(SYS_\w+)\s+=\s+(\d+)`).FindAllSubmatch(src, -1) {
		n, err := strconv.ParseUint(string(m[2]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		numbers[string(m[1])] = uintptr(n)
	}
	return numbers
}

// The table of amd64 moves each call of the Linux ABI to x86-64's call of
// the same name: its keys are the numbers the ABI assigns below the shared
// ones, and each call package syscall names on arm64 (whose numbers are the
// ABI's) and on amd64 is moved to amd64's number of its name (the calls
// package syscall does not name on amd64 are not checked).
func TestHostSyscallNumbers_TheCallOfTheSameName(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goroot := strings.TrimSpace(string(out))
	generic := map[uintptr][]string{}
	for name, n := range goSyscallNumbers(t, goroot, "arm64") {
		generic[n] = append(generic[n], name)
	}
	// arm64 names newfstatat(2) for the C library's function.
	generic[79] = append(generic[79], "SYS_NEWFSTATAT")
	x86 := goSyscallNumbers(t, goroot, "amd64")
	if len(generic) == 0 || len(x86) == 0 {
		t.Fatalf("read %d numbers of arm64 and %d of amd64", len(generic), len(x86))
	}
	for number := range int64(linuxSysPidfdSendSignal) {
		got, ok := hostSyscallNumbersAMD64[number]
		if ok != linuxSyscallAssigned(number) {
			t.Errorf("number %d in the table: %v, want %v", number, ok, !ok)
			continue
		}
		for _, name := range generic[uintptr(number)] {
			if want, named := x86[name]; named {
				if got != want {
					t.Errorf("%s (%d) moved to %d, want %d", name, number, got, want)
				}
				break
			}
		}
	}
}
