//go:build darwin || linux

package codegen

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The host descriptor behind a guest descriptor is the one of the host file
// the guest opened: what is written through it arrives in that file. A
// descriptor without one (a stream the embedder supplied, a closed number)
// has none.
func TestWasi_HostDescriptor(t *testing.T) {
	dir := t.TempDir()
	w, _ := newTestStubs(t, dir)
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}

	const oCreat, oTrunc, rightWrite = 1, 8, 1 << 6
	fd, errno := w.pathOpen("out.txt", 0, oCreat|oTrunc, rightWrite, 0)
	if errno != _wasiESUCCESS {
		t.Fatalf("open: errno %d", errno)
	}
	host, ok := w.HostDescriptor(fd)
	if !ok {
		t.Fatalf("HostDescriptor(%d): no host descriptor for a host file", fd)
	}
	const text = "through the host descriptor"
	if n, err := syscall.Write(int(host), []byte(text)); err != nil || n != len(text) {
		t.Fatalf("write to host descriptor %d: %d, %v", host, n, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil || string(got) != text {
		t.Fatalf("file holds %q (%v)", got, err)
	}

	if _, ok := w.HostDescriptor(1); ok {
		t.Error("HostDescriptor(1): a stdout that is a bytes.Buffer has a host descriptor")
	}
	if _, ok := w.HostDescriptor(99); ok {
		t.Error("HostDescriptor(99): a closed number has a host descriptor")
	}

	// A standard stream that is a file of the host is that file.
	out, err := os.Create(filepath.Join(dir, "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w.SetStdout(out)
	host, ok = w.HostDescriptor(1)
	if !ok || host != out.Fd() {
		t.Errorf("HostDescriptor(1) = %d, %v; want %d", host, ok, out.Fd())
	}

	// A connected socket has one; a socket that is only created has none.
	sock := w.Sock_socket(&Module{memory: make([]byte, 1<<16)}, 2, 1)
	if sock < 0 {
		t.Fatalf("socket: %d", sock)
	}
	if _, ok := w.HostDescriptor(sock); ok {
		t.Error("HostDescriptor: a socket that is not connected has a host descriptor")
	}
}
