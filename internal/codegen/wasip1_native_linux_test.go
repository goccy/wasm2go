package codegen

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// statusUmask reads the umask of a status file, and fails for one it cannot
// read: ErrUnsupported for a status without a umask.
func TestStatusUmask(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := statusUmask(write("ok", "Name:\tx\nUmask:\t0027\nState:\tR\n")); err != nil || got != 0o027 {
		t.Fatalf("statusUmask = %o, %v; want 027", got, err)
	}
	if _, err := statusUmask(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("statusUmask of a missing file: %v, want ErrNotExist", err)
	}
	if _, err := statusUmask(write("none", "Name:\tx\n")); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("statusUmask without a umask: %v, want ErrUnsupported", err)
	}
	if _, err := statusUmask(write("bad", "Umask:\t09\n")); err == nil || errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("statusUmask of a malformed umask: %v, want a parse error", err)
	}
}
