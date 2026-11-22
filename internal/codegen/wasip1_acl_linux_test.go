//go:build linux

package codegen

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A directory with a default ACL decides the mode of what is created in it,
// and the system takes no umask out (posix_acl_create): the instance's
// mask, which the kernel has on the creation thread, is not taken out.
func TestWasi_ADefaultACLDecidesTheMode(t *testing.T) {
	if !creationThreads(t) {
		t.Skip("the system refuses a creation thread")
	}
	dir := t.TempDir()
	acl := filepath.Join(dir, "acl")
	if err := os.Mkdir(acl, 0o777); err != nil {
		t.Fatal(err)
	}
	// u::rwx g::rwx o::--- (struct posix_acl_xattr_header, then entries).
	data := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range []struct{ tag, perm uint16 }{{0x01, 7}, {0x04, 7}, {0x20, 0}} {
		data = binary.LittleEndian.AppendUint16(data, e.tag)
		data = binary.LittleEndian.AppendUint16(data, e.perm)
		data = binary.LittleEndian.AppendUint32(data, 0xffffffff)
	}
	if err := syscall.Setxattr(acl, "system.posix_acl_default", data, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("the filesystem has no ACLs: %v", err)
		}
		t.Fatal(err)
	}
	w, m := newTestStubs(t, dir)
	w.Proc_umask(m, 0o022)
	if got := createWithMode(t, w, m, "acl/f", 0o666); got != 0o660 {
		t.Errorf("file 0666 in a directory of ACL o::---: %o, want the ACL's 660", got)
	}
	if got := mkdirWithMode(t, w, m, "acl/d", 0o777); got != 0o770 {
		t.Errorf("directory 0777 in a directory of ACL o::---: %o, want the ACL's 770", got)
	}
}
