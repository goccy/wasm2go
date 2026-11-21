//go:build linux

package codegen

import (
	"encoding/binary"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// statTimes returns the access and status-change times of a stat result.
func statTimes(st *syscall.Stat_t) (atime, ctime time.Time) {
	return time.Unix(st.Atim.Unix()), time.Unix(st.Ctim.Unix())
}

// osFileDirents reads the names in the directory open as d, in the order
// the system gives them, "." and ".." where it has them.
func osFileDirents(d *os.File) (names []hostName, err error) {
	rc, err := d.SyscallConn()
	if err != nil {
		return nil, err
	}
	if readErr := rc.Read(func(fd uintptr) bool {
		names, err = readHostDirents(int(fd))
		return true
	}); readErr != nil {
		return nil, readErr
	}
	return names, err
}

// readHostDirents reads the names in the directory open as fd from its
// beginning, in the order the system gives them, "." and ".." where it
// has them.
func readHostDirents(fd int) ([]hostName, error) {
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return nil, os.NewSyscallError("lseek", err)
	}
	var entry syscall.Dirent
	const (
		reclenAt = unsafe.Offsetof(entry.Reclen)
		typeAt   = unsafe.Offsetof(entry.Type)
		nameAt   = unsafe.Offsetof(entry.Name)
	)
	var out []hostName
	buf := make([]byte, 32<<10)
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("getdents", err)
		}
		if n <= 0 {
			return out, nil
		}
		for rest := buf[:n]; len(rest) > int(nameAt); {
			reclen := int(binary.NativeEndian.Uint16(rest[reclenAt:]))
			if reclen <= int(nameAt) || reclen > len(rest) {
				break
			}
			rec := rest[:reclen]
			rest = rest[reclen:]
			if binary.NativeEndian.Uint64(rec) == 0 {
				continue
			}
			name := rec[nameAt:]
			for i, c := range name {
				if c == 0 {
					name = name[:i]
					break
				}
			}
			out = append(out, hostName{name: string(name), typ: rec[typeAt]})
		}
	}
}
