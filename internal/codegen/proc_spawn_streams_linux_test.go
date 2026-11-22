package codegen

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A command given a guest's pipe end that the runtime polls gets an open
// file description of its own of that pipe, in blocking mode as the
// guest's descriptor is.
func TestSpawn_CommandGetsADescriptionOfItsOwn(t *testing.T) {
	w, m := newTestStubs(t, t.TempDir())
	w.cfg.Stdin, w.cfg.Stdout, w.cfg.Stderr = bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}
	r, wr := newTestPipe(t, w, m)
	w.mu.Lock()
	end := w.fdTable[wr].f.(*os.File)
	w.mu.Unlock()
	var pipe string
	if err := withHostDescriptor(end, func(fd uintptr) error {
		var err error
		pipe, _, err = hostFDLink(fd)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pid := spawnWithStreams(t, w, m, -1, wr, -1, "/bin/sh", "-c", "readlink /proc/self/fd/1; cat /proc/self/fdinfo/1")
	closeTestFd(t, w, m, wr)
	link, info, _ := strings.Cut(readToEnd(t, w, m, r), "\n")
	waitExitsZero(t, w, m, pid)
	if link != pipe {
		t.Fatalf("the command's stdout is %q, want the guest's pipe %q", link, pipe)
	}
	for _, line := range strings.Split(info, "\n") {
		field, ok := strings.CutPrefix(line, "flags:")
		if !ok {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimSpace(field), 8, 64)
		if err != nil {
			t.Fatal(err)
		}
		if flags&syscall.O_NONBLOCK != 0 {
			t.Fatalf("the command's stdout flags = %o, want no O_NONBLOCK", flags)
		}
		return
	}
	t.Fatalf("no flags in the command's fdinfo %q", info)
}
