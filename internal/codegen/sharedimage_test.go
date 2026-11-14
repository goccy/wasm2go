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
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)

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

	// Closing the image leaves the instances already mapped from it intact
	// and refuses new mappings.
	if err := snap.Close(); err != nil {
		panic(err)
	}
	b.Poke(1025, 'Y')
	fmt.Printf("after close a=%d b=%d\n", a.Peek(1025), b.Peek(1025))
	_, err := snap.Memory(4 * 65536)
	fmt.Println("mapping a closed image fails:", err != nil)
	fmt.Println("second close:", snap.Close())
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)

	for _, want := range []string{
		"start ran 1 time(s) for a, 1 for b",
		"marker a 42 b 42",
		`a="he"`,
		"after poke a=88 b=104",
		"after close a=101 b=89",
		"mapping a closed image fails: true",
		"second close: <nil>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// ForkMemory gives a second instance the state of a running one, whatever
// the first one's memory is (a mapping of an image, or its own allocation)
// and however much of it the instance changed since its image was made: the
// duplicate holds every change made before the fork, and neither sees what
// the other writes afterwards. An instance forks again and again, and so
// does the instance built on a duplicate.
func TestForkMemory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package cannot duplicate a memory")
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

const ceiling = 4 * 65536

// fork duplicates m, whose memory maps img, and returns the new instance
// with the image each of the two maps afterwards.
func fork(m *pkg.Module, img *pkg.SharedImage) (child *pkg.Module, parentImg, childImg *pkg.SharedImage) {
	f, err := pkg.ForkMemory(m, img, ceiling)
	if err != nil {
		panic(err)
	}
	if f.Rebased && f.Image == nil {
		panic("rebased onto no image")
	}
	parentImg = img
	if f.Rebased {
		parentImg = f.Image
	}
	return pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals), parentImg, f.Image
}

func main() {
	snap := pkg.NewSharedSnapshot(func() (*pkg.Module, error) { return pkg.New(), nil })
	if err := snap.Err(); err != nil {
		fmt.Println("snapshot:", err)
		return
	}
	mem, err := snap.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	a := pkg.NewFromSnapshot(mem, snap.Size(), snap.Globals())

	// A small change, then a fork.
	a.Poke(1024, 'X')
	b, aImg, bImg := fork(a, snap)
	fmt.Println("b inherits", b.Peek(1024), "start ran", b.Peek(100), "marker", b.Marker())
	b.Poke(1024, 'Y')
	a.Poke(1025, 'Z')
	fmt.Println("after the fork a", a.Peek(1024), a.Peek(1025), "b", b.Peek(1024), b.Peek(1025))

	// A change to most of the memory, then a fork: every page arrives.
	for addr := int32(8192); addr < 2*65536; addr += 1024 {
		a.Poke(addr, int32(addr/1024))
	}
	c, aImg, _ := fork(a, aImg)
	ok := c.Peek(1024) == 'X' && c.Peek(1025) == 'Z'
	for addr := int32(8192); addr < 2*65536; addr += 1024 {
		ok = ok && c.Peek(addr) == int32(addr/1024)&0xff && a.Peek(addr) == int32(addr/1024)&0xff
	}
	fmt.Println("c inherits everything:", ok)
	c.Poke(8192, 1)
	fmt.Println("after the fork a", a.Peek(8192), "c", c.Peek(8192))

	// The instance forks once more after that, with one more change.
	a.Poke(2048, 'Q')
	d, _, _ := fork(a, aImg)
	fmt.Println("d inherits", d.Peek(1024), d.Peek(2048), d.Peek(8192), d.Peek(16384))
	d.Poke(2048, 'R')
	fmt.Println("after the fork a", a.Peek(2048), "d", d.Peek(2048))

	// A memory that grew: the new page arrives, and the duplicate grows
	// as far as the memory it duplicates may.
	fmt.Println("a grows from", a.Grow(1))
	a.Poke(2*65536+10, 'G')
	g, _, _ := fork(a, aImg)
	fmt.Println("g inherits", g.Peek(2*65536+10), g.Peek(1024), "grows from", g.Grow(1), "then", g.Grow(1))
	g.Poke(3*65536+10, 'H')
	fmt.Println("after the fork g", g.Peek(3*65536+10), "a grows from", a.Grow(1), "a", a.Peek(3*65536+10))

	// The duplicate forks too.
	e, _, _ := fork(b, bImg)
	fmt.Println("e inherits", e.Peek(1024), e.Peek(1025))
	e.Poke(1024, 'W')
	fmt.Println("after the fork b", b.Peek(1024), "e", e.Peek(1024))

	// An instance on its own allocation.
	p := pkg.New()
	p.Poke(1024, 'P')
	q, _, _ := fork(p, nil)
	fmt.Println("q inherits", q.Peek(1024), "start ran", q.Peek(100), "marker", q.Marker())
	q.Poke(1024, 'S')
	p.Poke(1025, 'T')
	fmt.Println("after the fork p", p.Peek(1024), p.Peek(1025), "q", q.Peek(1024), q.Peek(1025))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)

	for _, want := range []string{
		"b inherits 88 start ran 1 marker 42",
		"after the fork a 88 90 b 89 101",
		"c inherits everything: true",
		"after the fork a 8 c 1",
		"d inherits 88 81 8 16",
		"after the fork a 81 d 82",
		"a grows from 2",
		"g inherits 71 88 grows from 3 then -1",
		"after the fork g 72 a grows from 3 a 0",
		"e inherits 89 101",
		"after the fork b 89 e 87",
		"q inherits 80 start ran 1 marker 42",
		"after the fork p 80 84 q 83 101",
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

// An instance can start on memory of its own that AnonymousMemory maps for
// it, holding the data segments of an instance constructed for the purpose:
// it starts as one on its own allocation does, its memory grows in place,
// and its forks get its state. Its first fork maps its memory onto the image
// the fork writes where the platform can tell later what an instance
// changes (Linux), and its next forks start from that image.
func TestForkMemoryOfAnonymousMemory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package cannot map memory")
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
	"runtime"

	"gentest/pkg"
)

const ceiling = 4 * 65536

func fork(m *pkg.Module, img *pkg.SharedImage) (child *pkg.Module, parentImg *pkg.SharedImage, rebased bool) {
	f, err := pkg.ForkMemory(m, img, ceiling)
	if err != nil {
		panic(err)
	}
	parentImg = img
	if f.Rebased {
		parentImg = f.Image
	}
	return pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals), parentImg, f.Rebased
}

func main() {
	from := pkg.New()
	img, mem, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		panic(err)
	}
	if _, err := img.Memory(ceiling); err == nil {
		panic("the stand-in of an anonymous memory mapped something")
	}
	a := pkg.NewWithMemory(mem, pkg.InitialMemoryBytes)
	fmt.Println("a starts: start ran", a.Peek(100) > 0, "marker", a.Marker())

	a.Poke(1024, 'A')
	b, aImg, rebased := fork(a, img)
	fmt.Println("b inherits", b.Peek(1024), "marker", b.Marker())
	fmt.Println("rebased where the platform tells changes:", rebased == (runtime.GOOS == "linux"))
	b.Poke(1024, 'B')
	a.Poke(1025, 'Z')
	fmt.Println("after the fork a", a.Peek(1024), a.Peek(1025), "b", b.Peek(1024), b.Peek(1025))

	at := &a.Memory()[:1][0]
	fmt.Println("a grows from", a.Grow(1), "in place:", &a.Memory()[:1][0] == at)
	a.Poke(2*65536+10, 'G')
	c, _, _ := fork(a, aImg)
	fmt.Println("c inherits", c.Peek(1024), c.Peek(1025), c.Peek(2*65536+10))
	c.Poke(1024, 'C')
	fmt.Println("after the fork a", a.Peek(1024), "c", c.Peek(1024))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)

	for _, want := range []string{
		"a starts: start ran true marker 42",
		"b inherits 65 marker 42",
		"rebased where the platform tells changes: true",
		"after the fork a 65 90 b 66 101",
		"a grows from 2 in place: true",
		"c inherits 65 90 71",
		"after the fork a 65 c 67",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
