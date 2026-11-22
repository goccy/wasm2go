package codegen

import (
	"os"
	"slices"
	"strconv"
	"testing"
)

// Where the test of this file keeps its strings in a guest's memory.
const (
	chdirPathOff  int32 = 6000
	setenvNameOff int32 = 6100
	setenvValOff  int32 = 6200
)

// The guest's changes of its working directory and environment are told
// Chdir and Setenv, whose error is the guest's; a copy's changes, and the
// changes without them, are told nobody.
func TestChdirAndSetenvAreTold(t *testing.T) {
	var dirs, vars []string
	w := NewWASI(WASIConfig{
		Chdir: func(dir string) error {
			dirs = append(dirs, dir)
			if dir == "/denied" {
				return os.ErrPermission
			}
			return nil
		},
		Setenv: func(name, value string, unset bool) error {
			vars = append(vars, name+"="+value+"/"+strconv.FormatBool(unset))
			return nil
		},
	})
	m := newGuestModule(1 << 16)
	off, n := putPath(m, chdirPathOff, "/tmp")
	if rc := w.Proc_chdir(m, off, n); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir rc=%d", rc)
	}
	deniedOff, deniedLen := putPath(m, chdirPathOff, "/denied")
	if rc := w.Proc_chdir64(m, int64(deniedOff), deniedLen); rc != -_wasiEACCES {
		t.Fatalf("Proc_chdir64 the hook refuses rc=%d, want -EACCES", rc)
	}
	nameOff, nameLen := putPath(m, setenvNameOff, "FOO")
	valueOff, valueLen := putPath(m, setenvValOff, "bar")
	if rc := w.Proc_setenv(m, nameOff, nameLen, valueOff, valueLen, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv rc=%d", rc)
	}
	// A removal has no value, whose address is not read.
	if rc := w.Proc_setenv64(m, int64(nameOff), nameLen, 1<<40, 1, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv64 of a removal rc=%d", rc)
	}
	relOff, relLen := putPath(m, chdirPathOff, "tmp")
	for _, c := range []struct {
		what     string
		rc, want int32
	}{
		{"Proc_setenv of a value beyond the memory", w.Proc_setenv(m, nameOff, nameLen, 1<<16, 1, 1), -_wasiEFAULT},
		{"Proc_setenv of a name beyond the memory", w.Proc_setenv(m, 1<<16-1, 2, valueOff, valueLen, 1), -_wasiEFAULT},
		{"Proc_chdir beyond the memory", w.Proc_chdir(m, 1<<16, 1), -_wasiEFAULT},
		{"Proc_chdir of a relative path", w.Proc_chdir(m, relOff, relLen), -_wasiEINVAL},
		{"Proc_chdir of an empty path", w.Proc_chdir(m, relOff, 0), -_wasiEINVAL},
	} {
		if c.rc != c.want {
			t.Errorf("%s rc=%d, want %d", c.what, c.rc, c.want)
		}
	}
	child, cm := w.Fork(), newGuestModule(1<<16)
	off, n = putPath(cm, chdirPathOff, "/child")
	if rc := child.Proc_chdir(cm, off, n); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir of a copy rc=%d", rc)
	}
	if rc := child.Proc_setenv(cm, off, n, 0, 0, 0); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv of a copy rc=%d", rc)
	}
	if err := child.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/tmp", "/denied"}; !slices.Equal(dirs, want) {
		t.Fatalf("Chdir told %q, want %q", dirs, want)
	}
	if want := []string{"FOO=bar/false", "FOO=/true"}; !slices.Equal(vars, want) {
		t.Fatalf("Setenv told %q, want %q", vars, want)
	}
	w.cfg.Chdir, w.cfg.Setenv = nil, nil
	off, n = putPath(m, chdirPathOff, "/tmp")
	if rc := w.Proc_chdir(m, off, n); rc != _wasiESUCCESS {
		t.Fatalf("Proc_chdir without a hook rc=%d", rc)
	}
	if rc := w.Proc_setenv(m, nameOff, nameLen, valueOff, valueLen, 1); rc != _wasiESUCCESS {
		t.Fatalf("Proc_setenv without a hook rc=%d", rc)
	}
}

// A signal that ends a process, pending for a guest that has not registered
// for signals, ends the guest at its chdir or setenv report.
func TestChdirAndSetenvEndAnUnregisteredGuest(t *testing.T) {
	for name, call := range map[string]func(*WasiStubs, *Module){
		"proc_chdir": func(w *WasiStubs, m *Module) {
			off, n := putPath(m, chdirPathOff, "/tmp")
			w.Proc_chdir(m, off, n)
		},
		"proc_setenv": func(w *WasiStubs, m *Module) {
			off, n := putPath(m, setenvNameOff, "FOO")
			w.Proc_setenv(m, off, n, 0, 0, 0)
		},
	} {
		w, m := newProcTestStubs(t)
		w.PostSignal(wasiSIGTERM)
		if sig := killEnd(func() { call(w, m) }); sig != wasiSIGTERM {
			t.Errorf("%s ended the guest by %d, want SIGTERM", name, sig)
		}
	}
}
