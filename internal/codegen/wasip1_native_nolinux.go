//go:build !linux

package codegen

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

// lstatRemove removes name, a file (dir false) or an empty directory,
// after lstat finds it is that kind: for a host without a call that
// removes one kind only, so a name made the other kind in between is
// removed all the same.
func lstatRemove(lstat func(string) (os.FileInfo, error), remove func(string) error, name string, dir bool) error {
	fi, err := lstat(strings.TrimSuffix(name, "/"))
	switch {
	case err != nil:
		return err
	case fi.IsDir() && !dir:
		return &fs.PathError{Op: "unlink", Path: name, Err: syscall.EISDIR}
	case !fi.IsDir() && dir:
		return &fs.PathError{Op: "rmdir", Path: name, Err: syscall.ENOTDIR}
	}
	return remove(name)
}

// lstatChtimes sets the times of name, which lstat finds is no symbolic
// link, by chtimes, which follows one: for a host without a call that sets
// the times of a link itself, which then refuses a link
// (errors.ErrUnsupported).
func lstatChtimes(lstat func(string) (os.FileInfo, error), chtimes func(string, time.Time, time.Time) error, name string, atime, mtime time.Time) error {
	fi, err := lstat(name)
	switch {
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0:
		return &fs.PathError{Op: "lutimes", Path: name, Err: errors.ErrUnsupported}
	}
	return chtimes(name, atime, mtime)
}

// lstatOpen opens name without following a symbolic link at its end, by
// open, which follows one, after lstat finds it is no link (ELOOP): for a
// host without a call that opens so relative to a directory.
func lstatOpen(lstat func(string) (os.FileInfo, error), open func(string, int, os.FileMode) (File, error), name string, flag int, perm os.FileMode) (File, error) {
	if !strings.HasSuffix(name, "/") {
		// A look that fails (a name O_CREATE makes, a directory that may not
		// be searched) finds no link: the open is made and fails or
		// succeeds as the open of such a name does.
		if fi, err := lstat(name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
		}
	}
	return open(name, flag, perm)
}
