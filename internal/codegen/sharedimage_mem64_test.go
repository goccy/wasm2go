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

// A memory64 module's memory is mapped with a ceiling above 4 GiB and grows
// past 4 GiB in place: in memory of an instance's own (AnonymousMemory), in
// the memory of a fork of such an instance (ForkMemory), and on an image
// built in place on a memory already past 4 GiB, whose data segments end
// above 2^32 (DataEnd). Every mapping holds a memory of up to 8 GiB (where
// linear memory is a reservation it runs a guard region past that) and
// only a few of its pages are ever touched, so the process stays small; a
// host that cannot map 8 GiB skips the test.
func TestSharedImageMem64MappingsAboveFourGiB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package cannot map memory")
	}
	bin := testfixture.Wasm(t, "cg_sharedimage_mem64")
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
	"syscall"

	"gentest/pkg"
)

// ceiling is how far every mapping's memory may grow: twice what a wasm32
// memory can address.
const ceiling = 8 << 30

// fourGiB is 4 GiB in wasm pages.
const fourGiB = 1 << 16

// high is an address above 2^32; highSeg is where the module's start
// section installs its second segment on a memory past 4 GiB.
const (
	high    = 1<<32 + 4096 + 7
	highSeg = 0x100001000
)

func read(m *pkg.Module, at int64, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(m.Peek(at + int64(i)))
	}
	return string(b)
}

func main() {
	from := pkg.New()
	img, mem, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		fmt.Println("unmappable:", err)
		return
	}
	fmt.Println("own memory mapped:", uint64(len(mem)) >= ceiling)
	a := pkg.NewWithMemory(mem, pkg.InitialMemoryBytes)
	at := &a.Memory()[:1][0]
	fmt.Println("a holds", read(a, 1024, 14))
	fmt.Println("a grows from", a.Grow(fourGiB), "to", a.Size())
	a.Poke(high, 'H')
	fmt.Println("a reads", a.Peek(high), "in place:", &a.Memory()[:1][0] == at)
	fmt.Println("a grows to its ceiling from", a.Grow(ceiling>>16-a.Size()), "and no further:", a.Grow(1))

	// The fork of an instance whose memory may grow to the ceiling is as
	// long, and grows past 4 GiB as its parent does.
	bImg, bMem, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		panic(err)
	}
	b := pkg.NewWithMemory(bMem, pkg.InitialMemoryBytes)
	b.Poke(2048, 'B')
	f, err := pkg.ForkMemory(b, bImg, ceiling)
	if err != nil {
		panic(err)
	}
	c := pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals)
	fmt.Println("fork mapped:", uint64(len(f.Memory)) >= ceiling, "c inherits", c.Peek(2048))
	fmt.Println("c grows from", c.Grow(fourGiB))
	c.Poke(high, 'C')
	fmt.Println("c reads", c.Peek(high))

	// An image built on a memory already past 4 GiB: the start section
	// installs a segment above 2^32, and the image keeps it.
	built := pkg.NewSharedImageInPlace(ceiling, func(mem []byte) (*pkg.Module, error) {
		pkg.InstallDataSegments(mem)
		return pkg.NewWithMemory(mem, (fourGiB+2)<<16), nil
	})
	if err := built.Err(); err != nil {
		panic(err)
	}
	fmt.Println("image size", built.Size(), "data end", built.DataEnd())
	dMem, err := built.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	d := pkg.NewWithMemory(dMem, built.Size())
	fmt.Println("d holds", read(d, 1024, 14), "and", read(d, highSeg, 11))

	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	maxRSS := uint64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		maxRSS *= 1024 // kilobytes there, bytes on darwin
	}
	fmt.Println("resident below 256 MiB:", maxRSS < 256<<20)
	_ = img
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
	if strings.HasPrefix(out, "unmappable:") {
		t.Skipf("the host cannot map 8 GiB: %s", out)
	}
	for _, want := range []string{
		"own memory mapped: true",
		"a holds hello memory64",
		"a grows from 2 to 65538",
		"a reads 72 in place: true",
		"a grows to its ceiling from 65538 and no further: -1",
		"fork mapped: true c inherits 66",
		"c grows from 2",
		"c reads 67",
		"image size 4295098368 data end 4294971403",
		"d holds hello memory64 and above 4 GiB",
		"resident below 256 MiB: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
