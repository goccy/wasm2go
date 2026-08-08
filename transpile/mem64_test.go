package transpile_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/transpile"
)

// buildMem64 transpiles the memory64 fixture and materializes a runnable
// module around the given main body.
func buildMem64(t *testing.T, fixture, mainBody string) string {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	m, err := transpile.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := transpile.Translate(&buf, m, transpile.Options{Package: "pkg", OutputImportPath: "m64test/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	dir := t.TempDir()
	w := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("go.mod", []byte("module m64test\n\ngo 1.25.0\n"))
	if buf.Len() > 0 {
		w("pkg/gen.go", buf.Bytes())
	}
	for _, set := range []map[string][]byte{res.Files, res.Sidecars} {
		for name, data := range set {
			if len(data) == 0 {
				continue
			}
			w("pkg/"+name, data)
		}
	}
	w("main.go", []byte("package main\n\nimport (\n\t\"fmt\"\n\n\t\"m64test/pkg\"\n)\n\nfunc main() {\n"+mainBody+"}\n"))
	return dir
}

func runMem64(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestMem64Semantics pins the memory64 core semantics end to end: i64
// addressing (including dynamic i64 index arithmetic and memarg
// offsets), i64 memory.size/grow, bulk ops, an i64.const-placed data
// segment, and the SIMD memory family. Expectations are computed by
// hand from the fixture — wazero has no memory64 support to diff
// against.
func TestMem64Semantics(t *testing.T) {
	dir := buildMem64(t, "cg_mem64.wasm", `	m := pkg.New()
	fmt.Println(m.Rw(100, 0x1122334455667788))
	fmt.Println(m.Rw8(200, -1))
	fmt.Println(m.Rwidx(1000, 7, 42))
	fmt.Println(m.Size())
	fmt.Println(m.Grow(3))
	fmt.Println(m.Size())
	fmt.Println(m.Grow(-1))
	fmt.Println(m.Bulk(300, 400))
	fmt.Println(m.Dataseg())
	fmt.Println(uint64(m.Vmem(500)))
	fmt.Println(m.Vwiden())
	fmt.Println(uint32(m.Vsplat(600)))
	fmt.Println(uint32(m.Vlane(700)))
`)
	got := runMem64(t, dir)
	// Expectations:
	//   rw:      the stored i64 read back            -> 0x1122334455667788
	//   rw8:     0xff sign-extends to -1
	//   rwidx:   42
	//   size:    2 pages initially
	//   grow(3): previous count 2; size then 5
	//   grow(-1): -1 (negative delta refused)
	//   bulk:    0xa5 = 165
	//   dataseg: bytes 01..08 little-endian          -> 0x0807060504030201
	//   vmem:    lane 1 of the stored constant       -> 0x99aabbccddeeff00
	//   vwiden:  byte 8 of the segment (0x08) sign-extended -> 8
	//   vsplat:  lane 3 of splat(0x0badf00d)         -> 0x0badf00d
	//   vlane:   lane 2 got the loaded word          -> 0x11223344
	expect := []string{
		fmt.Sprintf("%d", int64(0x1122334455667788)),
		"-1",
		"42",
		"2",
		"2",
		"5",
		"-1",
		"165",
		fmt.Sprintf("%d", int64(0x0807060504030201)),
		fmt.Sprintf("%d", uint64(0x99aabbccddeeff00)),
		"8",
		fmt.Sprintf("%d", uint32(0x0badf00d)),
		fmt.Sprintf("%d", uint32(0x11223344)),
	}
	if got != strings.Join(expect, "\n") {
		t.Errorf("mem64 semantics diverge:\ngot:\n%s\nwant:\n%s", got, strings.Join(expect, "\n"))
	}
}

// TestMem64BeyondFourGiB proves the point of memory64: grow the linear
// memory past wasm32's 4 GiB ceiling and read/write above it. The test
// allocates ~4.1 GiB, so it is skipped in -short runs (CI included
// only on beefy runners).
func TestMem64BeyondFourGiB(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates >4GiB; skipped in -short")
	}
	// 2 initial pages; +65536 pages lands at 4 GiB + 128 KiB, so the
	// address 1<<32 is in bounds — one byte past everything wasm32
	// can ever express.
	dir := buildMem64(t, "cg_mem64big.wasm", `	m := pkg.New()
	fmt.Println(m.Grow(65536))
	fmt.Println(m.Rw(1<<32, 424242))
`)
	got := runMem64(t, dir)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("unexpected output: %q", got)
	}
	if lines[0] == "-1" {
		t.Skip("host refused a >4GiB linear memory")
	}
	if lines[1] != "424242" {
		t.Errorf("read past 4GiB: got %s, want 424242", lines[1])
	}
}
