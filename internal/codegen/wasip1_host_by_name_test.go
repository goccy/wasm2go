//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

const (
	hostByNameNodeOff   int32 = 6000
	hostByNameBufOff    int32 = 6200
	hostByNameNeededOff int32 = 6196
)

// hostByName calls Sock_host_by_name for name and decodes its record.
func hostByName(t *testing.T, w *WasiStubs, m *Module, name string) (official string, addrs []string, rc int32) {
	t.Helper()
	copy(m.memory[hostByNameNodeOff:], name)
	rc = w.Sock_host_by_name(m, hostByNameNodeOff, int32(len(name)), hostByNameBufOff, 512, hostByNameNeededOff)
	if rc != _wasiESUCCESS {
		return "", nil, rc
	}
	n := binary.LittleEndian.Uint32(m.memory[hostByNameNeededOff:])
	rec := m.memory[hostByNameBufOff : hostByNameBufOff+int32(n)]
	count := binary.LittleEndian.Uint32(rec)
	for i := uint32(0); i < count; i++ {
		a := rec[4+4*i : 8+4*i]
		addrs = append(addrs, fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]))
	}
	return string(rec[4+4*count:]), addrs, rc
}

// gethostbyname's lookup: the IPv4 addresses of a name and its official
// name; an IPv4 address written in numbers is itself, an IPv6 one has no
// IPv4 address; the lookup policy can refuse a name, and is not asked about
// an address.
func TestWasi_HostByName(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	official, addrs, rc := hostByName(t, w, m, "localhost")
	if rc != _wasiESUCCESS || official == "" || !contains(addrs, "127.0.0.1") {
		t.Fatalf("localhost: official %q addrs %v rc %d, want 127.0.0.1 among the addresses", official, addrs, rc)
	}
	if official, addrs, rc := hostByName(t, w, m, "10.1.2.3"); rc != _wasiESUCCESS || official != "10.1.2.3" || len(addrs) != 1 || addrs[0] != "10.1.2.3" {
		t.Fatalf("10.1.2.3: official %q addrs %v rc %d", official, addrs, rc)
	}
	if _, _, rc := hostByName(t, w, m, "::1"); rc != -_wasiENOENT {
		t.Fatalf("::1: rc %d, want ENOENT", rc)
	}
	var asked []string
	w.SetResolveHook(func(host string) bool { asked = append(asked, host); return false })
	if _, _, rc := hostByName(t, w, m, "localhost"); rc != -_wasiEACCES {
		t.Fatalf("refused name: rc %d, want EACCES", rc)
	}
	if _, _, rc := hostByName(t, w, m, "127.0.0.1"); rc != _wasiESUCCESS {
		t.Fatalf("address under a refusing policy: rc %d", rc)
	}
	if len(asked) != 1 || asked[0] != "localhost" {
		t.Fatalf("policy asked about %v, want [localhost]", asked)
	}
	// A buffer too small for the record: its size, and ERANGE.
	copy(m.memory[hostByNameNodeOff:], "10.1.2.3")
	if rc := w.Sock_host_by_name(m, hostByNameNodeOff, 8, hostByNameBufOff, 3, hostByNameNeededOff); rc != -_wasiERANGE {
		t.Fatalf("small buffer: rc %d, want ERANGE", rc)
	}
	if n := binary.LittleEndian.Uint32(m.memory[hostByNameNeededOff:]); n != 4+4+8 {
		t.Fatalf("small buffer: needed %d, want %d", n, 4+4+8)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// inheritedSockets lists the descriptors of the process that are sockets a
// command it starts would inherit (not closed on exec).
func inheritedSockets() map[int]bool {
	out := map[int]bool{}
	for fd := 0; fd < 1024; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno == 0 && flags&syscall.FD_CLOEXEC == 0 {
			out[fd] = true
		}
	}
	return out
}

// A lookup by gethostbyname's import leaves no descriptor behind that the
// commands the program starts would inherit, as perl's gethostbyname leaves
// none: darwin's getaddrinfo, which the runtime's resolver calls there,
// keeps a socket to the system without close-on-exec (the C library's
// gethostbyname2 keeps one closed on exec). Run in a process of its own,
// which no earlier lookup has touched; the child fails when it finds one.
func TestWasi_HostByNameLeavesNoDescriptorOpen(t *testing.T) {
	if os.Getenv("WASM2GO_HOST_BY_NAME_CHILD") == "1" {
		w, m := newTestStubs(t, t.TempDir())
		before := inheritedSockets()
		if _, addrs, rc := hostByName(t, w, m, "localhost"); rc != _wasiESUCCESS || len(addrs) == 0 {
			t.Fatalf("localhost: addrs %v rc %d", addrs, rc)
		}
		for fd := range inheritedSockets() {
			if !before[fd] {
				t.Errorf("the lookup left socket %d open, without close-on-exec", fd)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWasi_HostByNameLeavesNoDescriptorOpen$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "WASM2GO_HOST_BY_NAME_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
