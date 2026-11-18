package transpile_test

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestAnonymousMemoryCopiesWhatTheInstanceHolds pins what AnonymousMemory
// gives for the instance it is given, whichever way it finds the pages to
// copy (where the instance's memory is a reservation of its own on Linux,
// the pages the process has touched; elsewhere every page below the data
// end that is not all zeros): a new memory that holds what the instance's
// memory holds below the data end, including what was written there after
// the constructor, and zeros above it; the instance and the memory an
// earlier call gave are left as they are, and the instance serves another
// call.
func TestAnonymousMemoryCopiesWhatTheInstanceHolds(t *testing.T) {
	got := runMem64(t, buildMem64Main(t, "cg_sharedimage.wat", anonymousMemoryMain, transpile.Options{}))
	want := []string{
		"data end 4099",
		"a starts: start ran 2 marker 42 holds hello shared image",
		"b holds hello shared image, 81 below the data end, 0 above it, start ran 2",
		"the instance keeps 81 82",
		"a keeps 0 0",
	}
	diffLines(t, got, strings.Join(want, "\n"))
}

const anonymousMemoryMain = `package main

import (
	"fmt"

	"m64test/pkg"
)

const ceiling = 4 * 65536

func read(m *pkg.Module, at int32, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(m.Peek(at + int32(i)))
	}
	return string(b)
}

func main() {
	from := pkg.New()
	img, mem, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		panic(err)
	}
	fmt.Println("data end", img.DataEnd())
	a := pkg.NewWithMemory(mem, pkg.InitialMemoryBytes)
	fmt.Println("a starts: start ran", a.Peek(100), "marker", a.Marker(), "holds", read(a, 1024, 18))

	from.Poke(2000, 'Q')
	from.Poke(5000, 'R')
	_, bMem, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		panic(err)
	}
	b := pkg.NewWithMemory(bMem, pkg.InitialMemoryBytes)
	fmt.Printf("b holds %s, %d below the data end, %d above it, start ran %d\n", read(b, 1024, 18), b.Peek(2000), b.Peek(5000), b.Peek(100))
	fmt.Println("the instance keeps", from.Peek(2000), from.Peek(5000))
	fmt.Println("a keeps", a.Peek(2000), a.Peek(5000))
}
`
