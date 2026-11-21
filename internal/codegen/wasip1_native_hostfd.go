//go:build darwin || linux

package codegen

import (
	"os"
	"syscall"
)

// hostName is one name of a directory with the file type the directory
// records for it, and its inode number where the directory records that
// too (0 where it does not).
type hostName struct {
	name string
	typ  uint8
	ino  uint64
}

// hostDirListing lists a directory of the host's in the order the system
// gives its names, with "." and ".." where osFileDirents has them: a
// directory opened through the host's file system (an *os.File, which osFS
// opens). ok is false for a directory of another file system.
func hostDirListing(f File) (list []os.DirEntry, ok bool, err error) {
	var dir string
	var names []hostName
	switch d := f.(type) {
	case *os.File:
		names, err = osFileDirents(d)
		dir = d.Name()
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	list = make([]os.DirEntry, 0, len(names))
	for _, entry := range names {
		list = append(list, &hostDirEntry{dir: dir, name: entry.name, typ: entry.typ, ino: entry.ino})
	}
	return list, true, nil
}

// hostDirEntry is an entry of a directory of the host's.
type hostDirEntry struct {
	dir, name string
	typ       uint8  // d_type
	ino       uint64 // d_ino, 0 where the directory does not record it
}

func (e *hostDirEntry) inode() uint64 { return e.ino }

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
	// The directory does not say (DT_UNKNOWN): the file does. A file that
	// cannot be asked leaves the type unknown. Type has no error to return,
	// and the listing goes on: the name is listed, and the guest stats it.
	fi, err := e.Info()
	if err != nil {
		return os.ModeIrregular
	}
	return fi.Mode().Type()
}
func (e *hostDirEntry) Info() (os.FileInfo, error) { return os.Lstat(e.dir + "/" + e.name) }
