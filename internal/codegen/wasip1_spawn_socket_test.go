package codegen

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"
)

// A process spawned with a socket as its stdin gets the connection's
// descriptor, so waiting for it ends when it does. Before, os/exec was handed
// the net.Conn, fed the child through a pipe from a goroutine reading the
// connection, and Wait waited for that goroutine — until the peer closed the
// connection, long after the child had exited — so waitpid hung, and the
// goroutine ate input meant for the guest.
func TestWasi_SpawnWithASocketAsStdinEndsWithTheChild(t *testing.T) {
	const head = "/usr/bin/head"
	if _, err := os.Stat(head); err != nil {
		t.Skip(head + " not available")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener: " + err.Error())
	}
	defer ln.Close()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	w, m := newTestStubs(t, t.TempDir())
	var out bytes.Buffer
	w.stdin, w.stdout, w.stderr = bytes.NewReader(nil), &out, &bytes.Buffer{}
	w.mu.Lock()
	sockFd := w.addFDLocked(&wasiOpen{conn: conn})
	w.mu.Unlock()
	if _, err := peer.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	pathOff := writeCStr(m, 1000, head)
	argvOff := writeArgv(m, 2000, 3000, []string{head, "-c", "2"})
	const pidOff, statusOff int32 = 4000, 4004
	if rc := w.Proc_spawn(m, pathOff, argvOff, 0, sockFd, -1, -1, 0, pidOff); rc != _wasiESUCCESS {
		t.Fatalf("Proc_spawn rc=%d", rc)
	}
	pid := int32(readU32(m.memory, int(pidOff)))
	waited := make(chan int32, 1)
	go func() { waited <- w.Proc_wait(newForkTestModule(), pid, 0, statusOff) }()
	select {
	case rc := <-waited:
		if rc != _wasiESUCCESS {
			t.Fatalf("Proc_wait rc=%d", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting for a child that read its socket stdin and exited did not end")
	}
	if out.String() != "hi" {
		t.Fatalf("the child wrote %q, want %q", out.String(), "hi")
	}
}
