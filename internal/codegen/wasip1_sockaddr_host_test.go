//go:build darwin || linux

package codegen

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

// Where the tests of this file keep an address record, the host's bytes and
// their length.
const (
	hostAddrRecOff = 20000
	hostAddrOutOff = 20400
	hostAddrLenOff = 20800
)

// putSockAddrRecord writes a into the guest's memory as an address record.
func putSockAddrRecord(m *Module, a wasiSockAddr) {
	writeSockAddrRecord(m.memory[hostAddrRecOff:hostAddrRecOff+wasiSockAddrSize], a)
}

// toHostBytes converts the record at hostAddrRecOff to the host's bytes.
func toHostBytes(t *testing.T, w *WasiStubs, m *Module) []byte {
	t.Helper()
	if rc := w.Sock_addr_to_host(m, hostAddrRecOff, hostAddrOutOff, 256, hostAddrLenOff); rc != 0 {
		t.Fatalf("Sock_addr_to_host rc=%d", rc)
	}
	n := binary.LittleEndian.Uint32(m.memory[hostAddrLenOff:])
	return append([]byte(nil), m.memory[hostAddrOutOff:hostAddrOutOff+n]...)
}

// fromHostBytes converts the host's bytes to the record at hostAddrRecOff
// and reads it back; rc is the import's result.
func fromHostBytes(w *WasiStubs, m *Module, raw []byte) (wasiSockAddr, int32) {
	copy(m.memory[hostAddrOutOff:], raw)
	if rc := w.Sock_addr_from_host(m, hostAddrOutOff, int32(len(raw)), hostAddrRecOff); rc != 0 {
		return wasiSockAddr{}, rc
	}
	a, errno := w.readSockAddr(m, hostAddrRecOff)
	if errno != 0 {
		return wasiSockAddr{}, -errno
	}
	return a, 0
}

// The kernel's own calls on a socket, with the bytes as they are.
func rawBind(fd int, raw []byte) error {
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)))
	if errno != 0 {
		return errno
	}
	return nil
}

func rawSockName(fd int) ([]byte, error) {
	buf := make([]byte, 256)
	n := uint32(len(buf))
	_, _, errno := syscall.Syscall(syscall.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if errno != 0 {
		return nil, errno
	}
	return buf[:n], nil
}

// The host's form of a socket address is the one its kernel takes and
// gives: a socket bound to the bytes a record becomes has that address, and
// the bytes the kernel names the socket by become the record again. Bytes
// that are no address of a family the records have, or too few for their
// family, are refused.
func TestSockAddr_HostForm(t *testing.T) {
	w, m := newProcTestStubs(t)
	bindAndName := func(family int, raw []byte) []byte {
		t.Helper()
		fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Skipf("no socket of family %d here: %v", family, err)
		}
		defer syscall.Close(fd)
		if err := rawBind(fd, raw); err != nil {
			t.Fatalf("bind to the host's bytes % x: %v", raw, err)
		}
		name, err := rawSockName(fd)
		if err != nil {
			t.Fatal(err)
		}
		return name
	}

	// IPv4: the kernel gives the socket a port of its own.
	putSockAddrRecord(m, wasiSockAddr{family: wasiSockFamilyIPv4, ip: net.IPv4(127, 0, 0, 1)})
	name := bindAndName(syscall.AF_INET, toHostBytes(t, w, m))
	a, rc := fromHostBytes(w, m, name)
	if rc != 0 || a.family != wasiSockFamilyIPv4 || !a.ip.Equal(net.IPv4(127, 0, 0, 1)) || a.port == 0 {
		t.Fatalf("IPv4 name: rc=%d %+v", rc, a)
	}
	putSockAddrRecord(m, a)
	if got := toHostBytes(t, w, m); string(got) != string(name) {
		t.Fatalf("IPv4 name back to the host's bytes: % x, want % x", got, name)
	}

	// IPv6, where the machine has it.
	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		l.Close()
		putSockAddrRecord(m, wasiSockAddr{family: wasiSockFamilyIPv6, ip: net.IPv6loopback})
		name := bindAndName(syscall.AF_INET6, toHostBytes(t, w, m))
		a, rc := fromHostBytes(w, m, name)
		if rc != 0 || a.family != wasiSockFamilyIPv6 || !a.ip.Equal(net.IPv6loopback) || a.port == 0 {
			t.Fatalf("IPv6 name: rc=%d %+v", rc, a)
		}
	}

	// A Unix-domain socket bound to a path, and one without a name.
	dir, err := os.MkdirTemp("/tmp", "w2g")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	putSockAddrRecord(m, wasiSockAddr{family: wasiSockFamilyUnix, name: path})
	name = bindAndName(syscall.AF_UNIX, toHostBytes(t, w, m))
	a, rc = fromHostBytes(w, m, name)
	if rc != 0 || a.family != wasiSockFamilyUnix || a.name != path {
		t.Fatalf("Unix-domain name: rc=%d %+v (host bytes % x)", rc, a, name)
	}
	putSockAddrRecord(m, wasiSockAddr{family: wasiSockFamilyUnix})
	unnamed := toHostBytes(t, w, m)
	if a, rc := fromHostBytes(w, m, unnamed); rc != 0 || a.family != wasiSockFamilyUnix || a.name != "" {
		t.Fatalf("Unix-domain socket without a name: rc=%d %+v", rc, a)
	}

	// Refused.
	putSockAddrRecord(m, wasiSockAddr{family: wasiSockFamilyIPv4, ip: net.IPv4(127, 0, 0, 1)})
	inet := toHostBytes(t, w, m)
	if _, rc := fromHostBytes(w, m, inet[:8]); rc != -_wasiEINVAL {
		t.Fatalf("an IPv4 address cut short: rc=%d, want -EINVAL", rc)
	}
	if _, rc := fromHostBytes(w, m, []byte{0}); rc != -_wasiEINVAL {
		t.Fatalf("one byte: rc=%d, want -EINVAL", rc)
	}
	unknown := append([]byte(nil), inet...)
	unknown[0], unknown[1] = 0xff, 0xff
	if _, rc := fromHostBytes(w, m, unknown); rc != -_wasiEAFNOSUPPORT {
		t.Fatalf("a family no record has: rc=%d, want -EAFNOSUPPORT", rc)
	}
	if rc := w.Sock_addr_to_host(m, hostAddrRecOff, hostAddrOutOff, 4, hostAddrLenOff); rc != -_wasiERANGE {
		t.Fatalf("too little room: rc=%d, want -ERANGE", rc)
	}
}
