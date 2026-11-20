//go:build darwin || linux

package codegen

import (
	"os"
	"syscall"
	"unsafe"
)

// hostName is one name of a directory with the file type the directory
// records for it.
type hostName struct {
	name string
	typ  uint8
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
			reclen := int(uint16(rest[reclenAt]) | uint16(rest[reclenAt+1])<<8)
			if reclen <= int(nameAt) || reclen > len(rest) {
				break
			}
			rec := rest[:reclen]
			rest = rest[reclen:]
			ino := uint64(0)
			for i := 7; i >= 0; i-- {
				ino = ino<<8 | uint64(rec[i])
			}
			if ino == 0 {
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

// hostDirListing lists a directory of the host's in the order the system
// gives its names, with "." and ".." where the system puts them, as
// readdir(3) gives them: a directory opened through the host's file system
// (an *os.File, which osFS opens). ok is false for a directory of another
// file system.
func hostDirListing(f File) (list []os.DirEntry, ok bool, err error) {
	var dir string
	var names []hostName
	switch d := f.(type) {
	case *os.File:
		rc, connErr := d.SyscallConn()
		if connErr != nil {
			return nil, true, connErr
		}
		if readErr := rc.Read(func(fd uintptr) bool {
			names, err = readHostDirents(int(fd))
			return true
		}); readErr != nil {
			return nil, true, readErr
		}
		dir = d.Name()
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	list = make([]os.DirEntry, 0, len(names))
	for _, entry := range names {
		list = append(list, &hostDirEntry{dir: dir, name: entry.name, typ: entry.typ})
	}
	return list, true, nil
}

// hostDirEntry is an entry of a directory of the host's.
type hostDirEntry struct {
	dir, name string
	typ       uint8 // d_type
}

func (e *hostDirEntry) Name() string { return e.name }
func (e *hostDirEntry) IsDir() bool  { return e.Type().IsDir() }
func (e *hostDirEntry) Type() os.FileMode {
	// The values of d_type are the file type bits of a mode, shifted.
	switch uint32(e.typ) << 12 {
	case syscall.S_IFDIR:
		return os.ModeDir
	case syscall.S_IFLNK:
		return os.ModeSymlink
	case syscall.S_IFIFO:
		return os.ModeNamedPipe
	case syscall.S_IFSOCK:
		return os.ModeSocket
	case syscall.S_IFCHR:
		return os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFBLK:
		return os.ModeDevice
	case syscall.S_IFREG:
		return 0
	}
	// The directory does not say (DT_UNKNOWN): the file does.
	if fi, err := e.Info(); err == nil {
		return fi.Mode().Type()
	}
	return 0
}
func (e *hostDirEntry) Info() (os.FileInfo, error) { return os.Lstat(e.dir + "/" + e.name) }
