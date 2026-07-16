package codegen_test

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// The shared image is the whole point of learning dataEnd at run time, so test
// it end to end: build the image from a module whose start section installs its
// data segments with memory.init, then stand two instances on copy-on-write maps
// of it and check that (a) they see the segments, (b) the start section running
// a second time does not trap, (c) a write in one instance is invisible to the
// other, and (d) the BSS above the segments is zero rather than inherited.
//
// (c) is what makes the sharing safe and (d) is what makes it work at all — an
// instance that inherited the start section's "already ran" flag would trap on
// its second run.
func TestSharedImageCopyOnWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package falls back to private memory")
	}
	bin := testfixture.Wasm(t, "cg_sharedimage")
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, parsed, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.AuxFiles["sharedimage.go"]; !ok {
		t.Fatalf("no sharedimage.go in AuxFiles; got %v", keysOf(res.AuxFiles))
	}

	// 1024..1041 is the "early" segment, 4096..4098 the "late" one; dataEnd is
	// therefore 4099, and 8192 is BSS. The image is 2 pages, so a 4-page
	// ceiling also exercises growing past it.
	const main = `package main

import (
	"fmt"

	"gentest/pkg"
)

func main() {
	img := pkg.NewSharedImage(func() (*pkg.Module, error) { return pkg.New(), nil })
	if err := img.Err(); err != nil {
		fmt.Println("image:", err)
		return
	}
	fmt.Println("dataEnd", img.DataEnd())

	newInstance := func() *pkg.Module {
		mem, err := img.Memory(4 * 65536)
		if err != nil {
			panic(err)
		}
		return pkg.NewWithMemory(mem, img.Size())
	}
	a, b := newInstance(), newInstance()

	// Both see the segments the IMAGE's start section installed — and their
	// own start section, which ran again over the shared pages, wrote nothing.
	fmt.Printf("a=%q b=%q late=%q\n",
		string([]byte{byte(a.Peek(1024)), byte(a.Peek(1025))}),
		string([]byte{byte(b.Peek(1024)), byte(b.Peek(1025))}),
		string([]byte{byte(a.Peek(4096)), byte(a.Peek(4097)), byte(a.Peek(4098))}))

	// BSS is zero, not inherited.
	fmt.Println("bss", a.Peek(8192))

	// A write in a is private to a.
	a.Poke(1024, 'X')
	fmt.Printf("after poke a=%d b=%d\n", a.Peek(1024), b.Peek(1024))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles)

	for _, want := range []string{
		"dataEnd 4099",
		`a="he" b="he" late="END"`,
		"bss 0",
		"after poke a=88 b=104", // 'X' in a, still 'h' in b
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// A snapshot is an image of a FULLY INITIALIZED instance, and its instances
// re-run nothing. Prove both halves of that, because getting either wrong is
// silent: the start section must NOT run again (the fixture's start bumps a
// counter in memory, so a re-run shows up as 2), and the globals must be
// restored from the snapshot (the fixture's start sets one to a value its
// declared initializer does not have, so a global that was dropped shows up
// as 0).
//
// And the sharing must still be copy-on-write: a write in one instance stays
// out of the other.
func TestSharedSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package falls back to private memory")
	}
	bin := testfixture.Wasm(t, "cg_sharedimage")
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, parsed, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}

	const main = `package main

import (
	"fmt"

	"gentest/pkg"
)

func main() {
	snap := pkg.NewSharedSnapshot(func() (*pkg.Module, error) { return pkg.New(), nil })
	if err := snap.Err(); err != nil {
		fmt.Println("snapshot:", err)
		return
	}

	newInstance := func() *pkg.Module {
		mem, err := snap.Memory(4 * 65536)
		if err != nil {
			panic(err)
		}
		return pkg.NewFromSnapshot(mem, snap.Size(), snap.Globals())
	}
	a, b := newInstance(), newInstance()

	// The start section ran ONCE, when the snapshot was built.
	fmt.Println("start ran", a.Peek(100), "time(s) for a,", b.Peek(100), "for b")

	// The globals came back with the memory.
	fmt.Println("marker a", a.Marker(), "b", b.Marker())

	// The segments are there, and still copy-on-write.
	fmt.Printf("a=%q\n", string([]byte{byte(a.Peek(1024)), byte(a.Peek(1025))}))
	a.Poke(1024, 'X')
	fmt.Printf("after poke a=%d b=%d\n", a.Peek(1024), b.Peek(1024))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles)

	for _, want := range []string{
		"start ran 1 time(s) for a, 1 for b",
		"marker a 42 b 42",
		`a="he"`,
		"after poke a=88 b=104",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
