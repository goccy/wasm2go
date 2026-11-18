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

// TestAnonymousMemoryCopiesAnInstanceNothingElseHolds gives AnonymousMemory
// instances nothing else refers to, while the collector runs all the time:
// the instance's memory, which a finalizer unmaps once the instance is gone,
// is read until the copy is done (go-perl boots every interpreter so, and
// the copy faulted on memory unmapped under it).
func TestAnonymousMemoryCopiesAnInstanceNothingElseHolds(t *testing.T) {
	got := runMem64(t, buildMem64Main(t, "cg_sharedimage_high.wat", anonymousMemoryAloneMain, transpile.Options{}))
	if got != "40 copies hold the data end and the touched pages" {
		t.Fatalf("got %q", got)
	}
}

const anonymousMemoryAloneMain = `package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"m64test/pkg"
)

const ceiling = 512 * 65536

func main() {
	debug.SetGCPercent(1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	const copies = 40
	for i := 0; i < copies; i++ {
		_, mem, err := pkg.AnonymousMemory(pkg.New(), ceiling)
		if err != nil {
			panic(err)
		}
		if string(mem[24<<20:24<<20+3]) != "END" || mem[23<<20] != 7 {
			fmt.Println("copy", i, "lacks what the instance held")
			return
		}
		pkg.UnmapMemory(mem)
	}
	close(stop)
	fmt.Println(copies, "copies hold the data end and the touched pages")
}
`

// TestAnonymousMemoryInPlaceInstallsTheSegments pins what
// AnonymousMemoryInPlace gives: the instance its builder constructs on the
// fresh mapping, after installing the module's active data segments there,
// holds them and has run its start section once; the image says where the
// segments end; each call maps a memory of its own; a builder's failure is
// the call's, and a ceiling below the module's initial memory is refused.
// Both layouts of the generated code are covered: one package, and the
// several packages a large module is split into.
func TestAnonymousMemoryInPlaceInstallsTheSegments(t *testing.T) {
	want := strings.Join([]string{
		"data end 70001",
		"a holds 97 90, start ran 1",
		"b holds 97 90, start ran 1",
		"a keeps 97 after b's memory is written",
		"a failing builder: wasm2go: building an instance on memory of its own: no instance",
		"a ceiling below the initial memory is refused: true",
	}, "\n")
	t.Run("one package", func(t *testing.T) {
		got := runMem64(t, buildMem64Main(t, "cg_activedata.wat", anonymousInPlaceMain, transpile.Options{}))
		diffLines(t, got, want)
	})
	t.Run("several packages", func(t *testing.T) {
		defer transpile.SetMultiPackageThreshold(0)()
		got := runMem64(t, buildMem64Main(t, "cg_activedata.wat", anonymousInPlaceSplitMain, transpile.Options{}))
		diffLines(t, got, want)
	})
}

// anonymousInPlaceSplitMain is anonymousInPlaceMain for the layout of
// several packages: the Module, the shared-image runtime and the
// reservation runtime are in base, the exports are functions of the top
// package.
const anonymousInPlaceSplitMain = `package main

import (
	"errors"
	"fmt"

	"m64test/pkg"
	"m64test/pkg/base"
)

const ceiling = 4 * 65536

func build(mem []byte) (*base.Module, error) {
	pkg.InstallDataSegments(mem)
	return pkg.NewWithMemory(mem, pkg.InitialMemoryBytes), nil
}

func main() {
	img, a, mem, err := base.AnonymousMemoryInPlace(ceiling, build)
	if err != nil {
		panic(err)
	}
	fmt.Println("data end", img.DataEnd())
	fmt.Printf("a holds %d %d, start ran %d\n", pkg.Peek(a, 1024), pkg.Peek(a, 70000), pkg.Peek(a, 100))

	_, b, bMem, err := base.AnonymousMemoryInPlace(ceiling, build)
	if err != nil {
		panic(err)
	}
	fmt.Printf("b holds %d %d, start ran %d\n", pkg.Peek(b, 1024), pkg.Peek(b, 70000), pkg.Peek(b, 100))
	bMem[1024] = 1
	fmt.Println("a keeps", pkg.Peek(a, 1024), "after b's memory is written")
	base.UnmapMemory(bMem)

	_, _, _, err = base.AnonymousMemoryInPlace(ceiling, func([]byte) (*base.Module, error) {
		return nil, errors.New("no instance")
	})
	fmt.Println("a failing builder:", err)
	_, _, _, err = base.AnonymousMemoryInPlace(pkg.InitialMemoryBytes-65536, build)
	fmt.Println("a ceiling below the initial memory is refused:", err != nil)
	base.UnmapMemory(mem)
}
`

const anonymousInPlaceMain = `package main

import (
	"errors"
	"fmt"

	"m64test/pkg"
)

const ceiling = 4 * 65536

func build(mem []byte) (*pkg.Module, error) {
	pkg.InstallDataSegments(mem)
	return pkg.NewWithMemory(mem, pkg.InitialMemoryBytes), nil
}

func main() {
	img, a, mem, err := pkg.AnonymousMemoryInPlace(ceiling, build)
	if err != nil {
		panic(err)
	}
	fmt.Println("data end", img.DataEnd())
	fmt.Printf("a holds %d %d, start ran %d\n", a.Peek(1024), a.Peek(70000), a.Peek(100))

	_, b, bMem, err := pkg.AnonymousMemoryInPlace(ceiling, build)
	if err != nil {
		panic(err)
	}
	fmt.Printf("b holds %d %d, start ran %d\n", b.Peek(1024), b.Peek(70000), b.Peek(100))
	bMem[1024] = 1
	fmt.Println("a keeps", a.Peek(1024), "after b's memory is written")
	pkg.UnmapMemory(bMem)

	_, _, _, err = pkg.AnonymousMemoryInPlace(ceiling, func([]byte) (*pkg.Module, error) {
		return nil, errors.New("no instance")
	})
	fmt.Println("a failing builder:", err)
	_, _, _, err = pkg.AnonymousMemoryInPlace(pkg.InitialMemoryBytes-65536, build)
	fmt.Println("a ceiling below the initial memory is refused:", err != nil)
	pkg.UnmapMemory(mem)
}
`

// TestAnonymousMemoryInPlaceForks forks an instance AnonymousMemoryInPlace
// built, with the image it returned: the fork holds what the instance held,
// what the start section wrote and what was written after it, and the
// instance keeps its own memory.
func TestAnonymousMemoryInPlaceForks(t *testing.T) {
	got := runMem64(t, buildMem64Main(t, "cg_sharedimage.wat", anonymousInPlaceForkMain, transpile.Options{}))
	want := []string{
		"a: start ran 1 marker 42 holds hello shared image",
		"the fork holds hello shared image, 81, start ran 1, marker 42",
		"a keeps 81 after the fork writes 9",
	}
	diffLines(t, got, strings.Join(want, "\n"))
}

const anonymousInPlaceForkMain = `package main

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
	img, a, _, err := pkg.AnonymousMemoryInPlace(ceiling, func(mem []byte) (*pkg.Module, error) {
		pkg.InstallDataSegments(mem)
		return pkg.NewWithMemory(mem, pkg.InitialMemoryBytes), nil
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("a: start ran", a.Peek(100), "marker", a.Marker(), "holds", read(a, 1024, 18))
	a.Poke(2000, 81)
	f, err := pkg.ForkMemory(a, img, ceiling)
	if err != nil {
		panic(err)
	}
	c := pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals)
	fmt.Printf("the fork holds %s, %d, start ran %d, marker %d\n", read(c, 1024, 18), c.Peek(2000), c.Peek(100), c.Marker())
	c.Poke(2000, 9)
	fmt.Println("a keeps", a.Peek(2000), "after the fork writes", c.Peek(2000))
}
`
