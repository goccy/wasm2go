//go:build darwin || linux

package codegen

import (
	"syscall"
	"testing"
)

// Fd_read64 and Fd_write64 on a descriptor of the host process go through
// that descriptor as Fd_read and Fd_write do: what is written arrives in
// the host's pipe, what the host writes is read, a blocking read is ended
// by a signal and leaves the descriptor as it was, and a blocking write of
// more than the pipe holds writes all of it.
func TestWasi64_HostDescriptorsAreReadAndWrittenAsByFdRead(t *testing.T) {
	w, m := newHostGuest(t, t.TempDir())
	if rc := w.Proc_signal_register64(m, int64(sigFlagOff)); rc != 0 {
		t.Fatalf("proc_signal_register64 rc=%d", rc)
	}
	setDispositions(t, w, m, signalMask(wasiSIGUSR1), 0, 0)
	readFd, writeFd := newTestPipe(t, w, m)
	guestIsHost(t, w, readFd)
	guestIsHost(t, w, writeFd)

	if n, rc := fdWrite64String(w, m, writeFd, "to the host"); rc != _wasiESUCCESS || n != 11 {
		t.Fatalf("fd_write64 wrote %d rc=%d", n, rc)
	}
	buf := make([]byte, 64)
	if n, err := syscall.Read(int(readFd), buf); err != nil || string(buf[:n]) != "to the host" {
		t.Fatalf("the host read %q (%v)", buf[:n], err)
	}

	if _, err := syscall.Write(int(writeFd), []byte("from the host")); err != nil {
		t.Fatal(err)
	}
	if got, rc := fdRead64String(w, m, readFd, 64); rc != _wasiESUCCESS || got != "from the host" {
		t.Fatalf("fd_read64 = %q rc=%d", got, rc)
	}

	postSoon(w, wasiSIGUSR1)
	if _, rc := fdRead64String(w, m, readFd, 16); rc != _wasiEINTR {
		t.Fatalf("interrupted read rc=%d, want EINTR", rc)
	}
	if hostStatusFlags(t, int(readFd))&syscall.O_NONBLOCK != 0 {
		t.Fatalf("waiting left the descriptor in non-blocking mode")
	}
	takeSignals(t, w, m)

	big := newGuestModule(1 << 21)
	const size = 1 << 20
	for i := 0; i < size; i++ {
		big.memory[4096+i] = byte(i)
	}
	putIovecs64(big, 64, [2]uint64{4096, size})
	read := make(chan int, 1)
	go func() {
		total := 0
		buf := make([]byte, 64<<10)
		for total < size {
			n, err := syscall.Read(int(readFd), buf)
			if err != nil || n == 0 {
				break
			}
			for i := 0; i < n; i++ {
				if buf[i] != byte(total+i) {
					read <- -1
					return
				}
			}
			total += n
		}
		read <- total
	}()
	if rc := w.Fd_write64(big, int64(writeFd), 64, 1, 128); rc != _wasiESUCCESS {
		t.Fatalf("fd_write64 rc=%d", rc)
	}
	if n := readU64(big.memory, 128); n != size {
		t.Fatalf("a blocking write wrote %d of %d bytes", n, size)
	}
	if got := <-read; got != size {
		t.Fatalf("the reader got %d bytes, want %d", got, size)
	}
}
