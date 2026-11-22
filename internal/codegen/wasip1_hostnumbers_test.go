//go:build darwin || linux

package codegen

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every errno constant of the runtime is the number wasi gives its name.
func TestWasi_ErrnoConstantsHaveTheirNumber(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "wasip1_native.go", wasip1NativeRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				t.Fatalf("a const spec %T", spec)
			}
			for i, id := range vs.Names {
				name, isErrno := strings.CutPrefix(id.Name, "_wasiE")
				if !isErrno || name == "SUCCESS" {
					continue
				}
				if i >= len(vs.Values) {
					t.Fatalf("%s has no value of its own", id.Name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("%s is not a number", id.Name)
				}
				n, err := strconv.Atoi(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if n <= 0 || n >= len(wasiErrnoNames) || wasiErrnoNames[n] != "E"+name {
					t.Errorf("%s = %d, which is not wasi's E%s", id.Name, n, name)
				}
				seen++
			}
		}
	}
	if seen == 0 {
		t.Fatal("no errno constant found")
	}
}

// A failed system call is the error its number says, not the nearest kind
// package os knows.
func TestWasi_ErrorsKeepTheirNumber(t *testing.T) {
	for _, c := range []struct {
		err  syscall.Errno
		want int32
	}{
		{syscall.ENOTEMPTY, 55}, {syscall.ELOOP, 32}, {syscall.ENAMETOOLONG, 37},
		{syscall.EXDEV, 75}, {syscall.EMFILE, 33}, {syscall.ENOSPC, 51},
		{syscall.EROFS, 69}, {syscall.ENOENT, 44}, {syscall.EEXIST, 20},
		{syscall.EACCES, 2}, {syscall.EPERM, 63}, {syscall.EAGAIN, 6},
		{syscall.EWOULDBLOCK, 6}, {syscall.ENOTSUP, 58}, {syscall.EOPNOTSUPP, 58},
		{syscall.ETXTBSY, 74}, {syscall.EBUSY, 10}, {syscall.EMLINK, 34},
		{syscall.ESRCH, 71}, {syscall.ENXIO, 60}, {syscall.ECONNRESET, 15},
		{syscall.ETIMEDOUT, 73}, {syscall.ENOTCONN, 53},
	} {
		for _, err := range []error{c.err, &os.PathError{Op: "open", Path: "x", Err: c.err},
			fmt.Errorf("wrapped: %w", os.NewSyscallError("rename", c.err))} {
			if got := errnoOfError(err); got != c.want {
				t.Errorf("errnoOfError(%v) = %d, want %d", err, got, c.want)
			}
		}
	}
	// An error of the host's that wasi has no number for is an I/O error,
	// one without an errno.
	if got, known := wasiErrnoOf(syscall.EHOSTDOWN); got != _wasiEIO || known {
		t.Errorf("EHOSTDOWN = %d, %v, want EIO without an errno", got, known)
	}
	if got, known := wasiErrnoOf(syscall.EIO); got != _wasiEIO || !known {
		t.Errorf("EIO = %d, %v, want EIO", got, known)
	}
	if got := errnoOfError(&os.PathError{Op: "mount", Path: "x", Err: syscall.ENOTBLK}); got != _wasiEIO {
		t.Errorf("ENOTBLK = %d, want EIO", got)
	}
	// An error that is no system call's has its kind.
	if got := errnoOfError(errors.New("no number")); got != _wasiEIO {
		t.Errorf("an error without a number = %d, want EIO", got)
	}
	if got := errnoOfError(os.ErrNotExist); got != _wasiENOENT {
		t.Errorf("os.ErrNotExist = %d, want ENOENT", got)
	}
	if got := errnoOfError(errors.ErrUnsupported); got != _wasiENOSYS {
		t.Errorf("errors.ErrUnsupported = %d, want ENOSYS", got)
	}

	// The system calls themselves.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := errnoOfError(os.Remove(filepath.Join(dir, "d"))); got != 55 {
		t.Errorf("removing a directory that is not empty = %d, want ENOTEMPTY (55)", got)
	}
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Open(filepath.Join(dir, "loop")); errnoOfError(err) != 32 {
		t.Errorf("opening a link to itself = %d, want ELOOP (32)", errnoOfError(err))
	}
	if _, err := os.Open(filepath.Join(dir, strings.Repeat("n", 5000))); errnoOfError(err) != 37 {
		t.Errorf("opening a name too long = %d, want ENAMETOOLONG (37)", errnoOfError(err))
	}
}

// A guest's raise applies the default action of the WASI signal to the
// guest alone: a terminating signal ends it with a *WasiSignalError for the
// guest's (Linux) number of the signal, an ignored or stopping one returns
// 0, and the host process receives no signal.
func TestWasi_ProcRaise(t *testing.T) {
	// none, CHLD, CONT, STOP, TSTP, TTIN, TTOU, URG, WINCH.
	ignored := []int32{0, 16, 17, 18, 19, 20, 21, 22, 27}
	// HUP, INT, ABRT, BUS, USR1, USR2, TERM, SYS, and KILL last.
	terminating := []int32{1, 2, 6, 7, 10, 12, 15, 30, 9}
	// The guest's numbers of terminating: from SIGCHLD on, WASI's are one
	// lower than Linux's.
	guestNumbers := map[int32]int32{1: 1, 2: 2, 6: 6, 7: 7, 10: 10, 12: 12, 15: 15, 30: 31, 9: 9}
	// Every host signal a raised number is on this host, except the ones
	// that cannot be caught and the ones the runtime and child processes
	// deliver on their own.
	host := make(chan os.Signal, 64)
	for _, sig := range append(ignored[1:], terminating...) {
		switch s := syscall.Signal(sig); s {
		case syscall.SIGKILL, syscall.SIGSTOP, syscall.SIGURG, syscall.SIGCHLD:
		default:
			signal.Notify(host, s)
		}
	}
	defer signal.Stop(host)
	w, m := newTestStubs(t, t.TempDir())
	raises := []struct {
		name  string
		raise func(int32) int32
	}{
		{"Proc_raise", func(sig int32) int32 { return w.Proc_raise(m, sig) }},
		{"Proc_raise64", func(sig int32) int32 { return w.Proc_raise64(m, int64(sig)) }},
	}
	for _, r := range raises {
		for _, sig := range ignored {
			if rc := r.raise(sig); rc != _wasiESUCCESS {
				t.Errorf("%s(%d) = %d, want 0", r.name, sig, rc)
			}
		}
		for _, sig := range []int32{-1, 31} {
			if rc := r.raise(sig); rc != _wasiEINVAL {
				t.Errorf("%s(%d) = %d, want EINVAL", r.name, sig, rc)
			}
		}
	}
	for _, sig := range []int64{1 << 32, 1<<32 + 15, -1 << 32} {
		if rc := w.Proc_raise64(m, sig); rc != _wasiEINVAL {
			t.Errorf("Proc_raise64(%d) = %d, want EINVAL", sig, rc)
		}
	}
	for _, sig := range terminating {
		for _, r := range raises {
			// An instance ends once: each raise ends one of its own.
			w, m = newTestStubs(t, t.TempDir())
			got := signalErrorOf(func() { r.raise(sig) })
			if want := guestNumbers[sig]; got == nil || got.Signal != want {
				t.Errorf("%s(%d) ended with %v, want a WasiSignalError for %d", r.name, sig, got, want)
			}
		}
	}
	if got, want := (&WasiSignalError{Signal: 15}).Error(), "wasi: terminated by signal 15"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	select {
	case s := <-host:
		t.Fatalf("the host process received %v", s)
	case <-time.After(100 * time.Millisecond):
	}
}

// signalErrorOf runs f and returns the *WasiSignalError it panics with, or
// nil if it returns.
func signalErrorOf(f func()) (sigErr *WasiSignalError) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		e, ok := r.(*WasiSignalError)
		if !ok {
			panic(r)
		}
		sigErr = e
	}()
	f()
	return nil
}
