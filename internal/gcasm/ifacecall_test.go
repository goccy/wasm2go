package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIfaceCallGate reproduces the wasm import-call shape: an
// interface method invoked through a struct field (itab load, method
// slot load, CALL DX with ABIInternal register args). The python.wasm
// consumer crashed on exactly this pattern.
func TestIfaceCallGate(t *testing.T) {
	dir := t.TempDir()
	libSrc := `package lib

type Host interface {
	A(m *Module, x int32) int32
	Clock(m *Module, x int32, y int64, z int32) int32
	// Wide mirrors wasi path_open: enough int args that the tail is
	// STACK-assigned under ABIInternal at the call site.
	Wide(m *Module, a0, a1, a2, a3, a4, a5, a6, a7, a8 int32) int32
}

type Module struct {
	pad0 [9]uint64
	Host Host
}

//go:noinline
func CallClock(m *Module, l0 int32, l1 int64, l2 int32) int32 {
	v := m.Host.Clock(m, l0, l1, l2)
	return v & int32(65535)
}

//go:noinline
func Bump(m *Module, x int32) int32 { return x + 9 }

//go:noinline
func CallWide(m *Module, x int32) int32 {
	// The marshalled Bump call gives the function a non-zero ABI0
	// outgoing area (frame shift), and the 10-arg interface call has
	// STACK-assigned tail arguments — the combination that broke
	// wasi path_open.
	x = Bump(m, x)
	v := m.Host.Wide(m, x, x+1, x-2, x+3, x+4, x-5, x+6, x+7, x-8)
	return v ^ Bump(m, int32(255))
}
`
	for name, content := range map[string]string{
		"go.mod":     "module ifgate\n\ngo 1.25.0\n",
		"lib/lib.go": libSrc,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fns, _, err := Capture(dir, "ifgate/lib")
	if err != nil {
		t.Fatal(err)
	}
	transform1 := func(suffix, sym string, params []ArgKind, names []string) string {
		t.Helper()
		var fn *Fn
		for _, f := range fns {
			if strings.HasSuffix(f.Name, suffix) {
				fn = f
			}
		}
		if fn == nil {
			t.Fatalf("%s not captured", suffix)
		}
		body, err := Transform(fn, TransformOptions{
			SymName: sym,
			CalleeSig: func(csym string) ([]ArgKind, bool, ArgKind, string, bool) {
				if strings.HasSuffix(csym, ".Bump") {
					return []ArgKind{ArgPtr, ArgI32}, true, ArgI32, "·Bump", true
				}
				return nil, false, 0, "", false
			},
			Params:    params,
			HasResult: true,
			Result:    ArgI32,
			ArgNames:  names,
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	body := transform1(".CallClock", "callClockAsm", []ArgKind{ArgPtr, ArgI32, ArgI64, ArgI32}, []string{"m", "l0", "l1", "l2"})
	body += "\n" + transform1(".CallWide", "callWideAsm", []ArgKind{ArgPtr, ArgI32}, []string{"m", "x"})

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module ifrun\n\ngo 1.25.0\n",
		"lib.go": strings.Replace(libSrc, "package lib", "package ifrun", 1) + `
func callClockAsm(m *Module, l0 int32, l1 int64, l2 int32) (r0 int32)
func callWideAsm(m *Module, x int32) (r0 int32)

type hostImpl struct{ mult int32 }

func (h *hostImpl) A(m *Module, x int32) int32 { return x }
func (h *hostImpl) Wide(m *Module, a0, a1, a2, a3, a4, a5, a6, a7, a8 int32) int32 {
	var big [1024]int64 // force stack growth (copystack unwinds the caller)
	big[a0&1023] = int64(a8)
	return a0 + a1*2 + a2*3 + a3*5 + a4*7 + a5*11 + a6*13 + a7*17 + int32(big[a0&1023])*19 + h.mult
}
func (h *hostImpl) Clock(m *Module, x int32, y int64, z int32) int32 {
	var big [512]int64 // force stack growth through the asm caller
	big[0] = y
	return x*h.mult + int32(big[0]) + z + 65536
}
`,
		"body_amd64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package ifrun

import "testing"

func TestIfaceCall(t *testing.T) {
	m := &Module{Host: &hostImpl{mult: 3}}
	for _, x := range []int32{0, 1, 7, 1000} {
		got := callClockAsm(m, x, int64(x)*2, x+1)
		want := CallClock(m, x, int64(x)*2, x+1)
		if got != want {
			t.Fatalf("callClockAsm(%d)=%d want %d", x, got, want)
		}
	}
	for _, x := range []int32{0, 1, -7, 90000} {
		got := callWideAsm(m, x)
		want := CallWide(m, x)
		if got != want {
			t.Fatalf("callWideAsm(%d)=%d want %d", x, got, want)
		}
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-run", "TestIfaceCall", ".")
	cmd.Dir = run
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("iface gate run failed: %v\n%s\n--- transformed body ---\n%s", err, out, body)
	}
}
