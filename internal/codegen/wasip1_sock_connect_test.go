package codegen

import (
	"errors"
	"net"
	"testing"
)

// closeFailConn is a connection whose Close fails.
type closeFailConn struct{ net.Conn }

func (closeFailConn) Close() error { return &net.OpError{Op: "close", Err: errors.New("broken")} }

// A connection Sock_connect does not keep — the socket was connected by a
// forked instance sharing it, or closed, while the dial ran — is closed, and
// what the connect reports is a negative errno like the rest of Sock_connect's
// results, the close's failure included. Before, a failed close came back as a
// positive errno, which the guest's connect() took for success.
func TestWasi_DropConnReportsNegativeErrno(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	if rc := dropConn(a, _wasiEISCONN); rc != -_wasiEISCONN {
		t.Fatalf("dropConn after a clean close = %d, want %d", rc, -_wasiEISCONN)
	}
	if rc := dropConn(closeFailConn{}, _wasiEBADF); rc >= 0 {
		t.Fatalf("dropConn after a failed close = %d, want a negative errno", rc)
	}
}
