//go:build darwin || linux

package codegen

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A TZ value naming a FIFO is no zone, and reading it does not wait for a
// writer.
func TestZone_FIFOIsNoZone(t *testing.T) {
	dir := t.TempDir()
	w, m := newTestStubs(t, dir)
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	name := "/fifo"
	rc := zoneCall(w, m, &name, time.Now(), false)
	if got := cString(m.memory[zoneOutOff+16 : zoneOutOff+32]); rc != 0 || got != "UTC" {
		t.Errorf("TZ=%s: rc=%d, zone %q; want UTC", name, rc, got)
	}
}
