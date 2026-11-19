package codegen

import (
	"strings"
	"testing"
)

// The fd table describes every fd, the standard ones included.

// fd_filestat_get of a standard stream reports a character device and of the
// preopened root a directory, while a closed standard fd is EBADF.
func TestWasi_FilestatOfStandardStreamAndPreopen(t *testing.T) {
	w, m := newProcTestStubs(t)
	const statOff int32 = 6000
	for _, c := range []struct {
		fd       int32
		filetype byte
	}{{0, 2}, {2, 2}, {wasiPreopenFD, 3}} {
		if rc := w.Fd_filestat_get(m, c.fd, statOff); rc != _wasiESUCCESS {
			t.Fatalf("Fd_filestat_get(%d) rc=%d", c.fd, rc)
		}
		if got := m.memory[statOff+16]; got != c.filetype {
			t.Errorf("filetype of fd %d = %d, want %d", c.fd, got, c.filetype)
		}
	}
	closeTestFd(t, w, m, 1)
	if rc := w.Fd_filestat_get(m, 1, statOff); rc != _wasiEBADF {
		t.Fatalf("Fd_filestat_get of a closed fd 1 rc=%d, want EBADF", rc)
	}
}

// Renumbering an fd onto itself keeps it open; renumbering a closed fd onto
// itself is EBADF.
func TestWasi_RenumberOntoItself(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := w.Fd_renumber(m, writeFd, writeFd); rc != _wasiESUCCESS {
		t.Fatalf("Fd_renumber onto itself rc=%d", rc)
	}
	if rc := fdWriteString(w, m, writeFd, "still"); rc != _wasiESUCCESS {
		t.Fatalf("write after renumbering onto itself rc=%d", rc)
	}
	if s, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || s != "still" {
		t.Fatalf("read = %q rc=%d", s, rc)
	}
	if rc := w.Fd_renumber(m, 50, 50); rc != _wasiEBADF {
		t.Fatalf("Fd_renumber of a closed fd onto itself rc=%d, want EBADF", rc)
	}
}

// SetStdin reaches fd 0 and its dups, which go on sharing one entry.
func TestWasi_SetStdinReachesDupsOfStdin(t *testing.T) {
	w, m := newProcTestStubs(t)
	const dupOut int32 = 5100
	if rc := w.Fd_dup(m, 0, dupOut); rc != _wasiESUCCESS {
		t.Fatalf("Fd_dup(0) rc=%d", rc)
	}
	dup := int32(readU32(m.memory, int(dupOut)))
	w.SetStdin(strings.NewReader("abcdef"))
	if s, rc := fdReadString(w, m, dup, 3); rc != _wasiESUCCESS || s != "abc" {
		t.Fatalf("read of the dup = %q rc=%d", s, rc)
	}
	if s, rc := fdReadString(w, m, 0, 16); rc != _wasiESUCCESS || s != "def" {
		t.Fatalf("read of fd 0 = %q rc=%d", s, rc)
	}
	if got := extraRefs(t, w, 0); got != 1 {
		t.Fatalf("extra references of the stdin entry = %d, want 1 (fd 0 and its dup)", got)
	}
}

// A poll that names one pipe twice probes it once and reports both
// subscriptions; a poll after a probe kept input reports the pipe ready
// without probing again, with the kept bytes as nbytes.
func TestWasi_PollReportsKeptInputOnceProbed(t *testing.T) {
	w, m := newProcTestStubs(t)
	readFd, writeFd := newTestPipe(t, w, m)
	if rc := fdWriteString(w, m, writeFd, "kept"); rc != _wasiESUCCESS {
		t.Fatalf("write rc=%d", rc)
	}
	writeSubFd(m, pollSubsOff, 1, 1 /* fd_read */, readFd)
	writeSubFd(m, pollSubsOff+48, 2, 1 /* fd_read */, readFd)
	wantUserdata(t, pollUserdata(t, w, m, 2), 1, 2)

	writeSubFd(m, pollSubsOff, 3, 1 /* fd_read */, readFd)
	wantUserdata(t, pollUserdata(t, w, m, 1), 3)
	if nbytes := readU32(m.memory, int(pollEvOff+16)); nbytes != 4 {
		t.Fatalf("nbytes = %d, want the 4 kept bytes", nbytes)
	}
	if s, rc := fdReadString(w, m, readFd, 16); rc != _wasiESUCCESS || s != "kept" {
		t.Fatalf("read = %q rc=%d", s, rc)
	}
}
