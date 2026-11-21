package transpile_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// TestOutOfBoundsAccessTraps runs a translated module whose loads and stores
// leave its linear memory — past memory.size, at u32-wrapped addresses, and at
// the furthest constant address plus static offset — and requires each one to
// end in the wasm out-of-bounds trap with the process still alive: as an error
// from an Inv_* entry point and as a panic from a direct export. It covers
// both ways an instance gets its memory: the constructor's own allocation and
// a copy-on-write snapshot mapping.
func TestOutOfBoundsAccessTraps(t *testing.T) {
	runOOBPrograms(t, "cg_oob.wasm", oobMain, `inbounds ok 0
pastsize trap
wrapped trap
store trap
constoff trap
grow ok 1
grown ok 0
direct trap
snap-inbounds ok 0
snap-pastceiling trap
snap-wrapped trap
done`)
}

// TestOutOfBoundsStartSectionTraps requires a start section's out-of-bounds
// access to reach the constructor's caller as the wasm trap.
func TestOutOfBoundsStartSectionTraps(t *testing.T) {
	runOOBPrograms(t, "cg_oob_start.wasm", oobStartMain, "new trap")
}

// runOOBPrograms translates the fixture with both backends into both output
// layouts, runs mainSrc against each, and compares the output with want.
func runOOBPrograms(t *testing.T, fixture, mainSrc, want string) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("linear memories are confined only on unix hosts")
	}
	bin := testfixture.Wasm(t, fixture)
	for _, multi := range []bool{false, true} {
		for _, pure := range []bool{false, true} {
			name := "single"
			if multi {
				name = "multi"
			}
			if pure {
				name += "/pure"
			} else {
				name += "/gcasm"
			}
			t.Run(name, func(t *testing.T) {
				dir := buildOOBProgram(t, bin, multi, pure, mainSrc)
				envs := [][]string{nil}
				if !pure && runtime.GOARCH == "amd64" {
					envs = [][]string{{"GOAMD64=v2"}, {"GOAMD64=v1"}}
				}
				for _, env := range envs {
					cmd := exec.Command("go", "run", ".")
					cmd.Dir = dir
					cmd.Env = append(os.Environ(), env...)
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("go run %v: %v\n%s", env, err, out)
					}
					if got := strings.TrimSpace(string(out)); got != want {
						t.Errorf("env %v: got\n%s\nwant\n%s", env, got, want)
					}
				}
			})
		}
	}
}

func buildOOBProgram(t *testing.T, bin []byte, multi, pure bool, mainSrc string) string {
	t.Helper()
	if multi {
		t.Cleanup(transpile.SetMultiPackageThreshold(0))
	}
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{
		Package:          "pkg",
		OutputImportPath: "oobtest/pkg",
		BulkExportPrefix: "w_",
		PureOnly:         pure,
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	dir := t.TempDir()
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", []byte("module oobtest\n\ngo 1.25.0\n"))
	if buf.Len() > 0 {
		write("pkg/gen.go", buf.Bytes())
	}
	for _, set := range []map[string][]byte{res.Files, res.Sidecars, res.AuxFiles} {
		for name, data := range set {
			if len(data) > 0 {
				write("pkg/"+name, data)
			}
		}
	}

	// The layouts differ only in where the runtime lives: single-package
	// output has methods and the shared-image API on pkg; multi-package
	// output has free functions in pkg and the Module and shared-image API
	// in pkg/base.
	r := strings.NewReplacer(
		"$IMPORTS", `"oobtest/pkg"`,
		"$MOD", "pkg.Module",
		"$RT", "pkg",
		"$LOADAT", "m.LoadAt(0x7ffffff0)",
	)
	if multi {
		r = strings.NewReplacer(
			"$IMPORTS", "\"oobtest/pkg\"\n\t\"oobtest/pkg/base\"",
			"$MOD", "base.Module",
			"$RT", "base",
			"$LOADAT", "pkg.LoadAt(m, 0x7ffffff0)",
		)
	}
	write("main.go", []byte(r.Replace(mainSrc)))
	return dir
}

// oobTrapCheck is shared by the main programs: it reports whether a
// recovered panic value is the out-of-bounds trap.
const oobTrapCheck = `
func isOOBTrap(r any) bool {
	s, ok := r.(string)
	return ok && s == "wasm: out of bounds memory access"
}
`

const oobMain = `package main

import (
	"fmt"
	"strings"

	$IMPORTS
)

type invoke func(m *$MOD, l0, l1 int32) (int64, error)

func try(label string, m *$MOD, f invoke, l0 int32) {
	v, err := f(m, l0, 0)
	switch {
	case err == nil:
		fmt.Println(label, "ok", v)
	case strings.Contains(err.Error(), "wasm: out of bounds memory access"):
		fmt.Println(label, "trap")
	default:
		fmt.Println(label, "error", err)
	}
}

func direct(m *$MOD) {
	defer func() {
		if r := recover(); r != nil {
			if isOOBTrap(r) {
				fmt.Println("direct trap")
			} else {
				fmt.Println("direct panic", r)
			}
		}
	}()
	fmt.Println("direct ok", $LOADAT)
}
` + oobTrapCheck + `
func main() {
	m := pkg.New()
	try("inbounds", m, pkg.Inv_1_0, 0)
	try("pastsize", m, pkg.Inv_1_0, 65536)
	try("wrapped", m, pkg.Inv_1_0, -16)
	try("store", m, pkg.Inv_1_1, 65536)
	try("constoff", m, pkg.Inv_1_2, 0)
	try("grow", m, pkg.Inv_1_3, 1)
	try("grown", m, pkg.Inv_1_0, 65536)
	direct(m)

	img := $RT.NewSharedSnapshot(func() (*$MOD, error) { return pkg.New(), nil })
	if err := img.Err(); err != nil {
		panic(err)
	}
	mem, err := img.Memory(2 * 65536)
	if err != nil {
		panic(err)
	}
	s := pkg.NewFromSnapshot(mem, img.Size(), img.Globals())
	try("snap-inbounds", s, pkg.Inv_1_0, 0)
	try("snap-pastceiling", s, pkg.Inv_1_0, 2*65536)
	try("snap-wrapped", s, pkg.Inv_1_0, -16)
	$RT.UnmapMemory(mem)
	fmt.Println("done")
}
`

const oobStartMain = `package main

import (
	"fmt"

	$IMPORTS
)
` + oobTrapCheck + `
func main() {
	defer func() {
		if r := recover(); r != nil {
			if isOOBTrap(r) {
				fmt.Println("new trap")
			} else {
				fmt.Println("new panic", r)
			}
		}
	}()
	_ = pkg.New()
	fmt.Println("new ok")
}

var _ = $RT.UnmapMemory
`
