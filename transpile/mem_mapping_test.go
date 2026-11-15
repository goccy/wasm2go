package transpile_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/transpile"
)

// TestMemoryMappingsAreWritableAsFarAsTheMemory pins how much of each
// mapping the shared-image functions hand out may be read and written
// before an instance runs on it: the memory of an image
// (SharedImage.Memory), memory of an instance's own (AnonymousMemory), a
// fork's memory (ForkMemory, from memory of the instance's own and from
// the image of an earlier fork) and the forked instance's memory after
// the fork. Where linear memory is a reservation, each is readable below
// the memory's size and not at it, and on Linux is writable only that far
// (/proc/self/maps): a page made writable is what a strict commit policy
// (vm.overcommit_memory=2, which ignores MAP_NORESERVE) charges, at mmap
// and at mprotect, so a mapping made writable in full would be charged
// its whole reservation — the ceiling and the guard past it — whatever
// the memory holds. A data limit (RLIMIT_DATA, which counts private
// writable pages the same way and needs no privilege to lower) below the
// length of one reservation stands in for such a policy: every mapping is
// still made under it. Elsewhere (GOFLAGS=-tags=wasm2go_boundschecks) a
// mapping is accessible throughout. Both a wasm32 and a memory64 module.
func TestMemoryMappingsAreWritableAsFarAsTheMemory(t *testing.T) {
	for _, fixture := range []string{"cg_sharedimage.wat", "cg_sharedimage_mem64.wat"} {
		t.Run(strings.TrimSuffix(fixture, ".wat"), func(t *testing.T) {
			t.Parallel()
			main := fmt.Sprintf(memMappingMain, testReserved)
			got := runMem64(t, buildMem64Main(t, fixture, main, transpile.Options{}))
			read, written := "at the size false", "writable as far as the size"
			if !testReserved {
				read, written = "at the size true", "writable throughout"
			}
			if runtime.GOOS != "linux" {
				written = "writable unknown"
			}
			var want []string
			for _, what := range []string{"image memory", "memory of its own", "a fork's memory", "the forked instance's memory", "a fork of the fork"} {
				want = append(want, what+": below the size true, "+read+", "+written)
			}
			diffLines(t, got, strings.Join(want, "\n"))
		})
	}
}

// memMappingMain drives cg_sharedimage or cg_sharedimage_mem64; %v is
// whether linear memory is a reservation.
const memMappingMain = `package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"m64test/pkg"
)

const reserved = %v

// ceiling is what each memory may grow to: its reservation is longer
// still (wasm32's is 4 GiB whatever the ceiling), and dataLimit is shorter
// than any reservation.
const (
	ceiling   = 1 << 30
	dataLimit = 2 << 30
)

var sink byte

// readable reports whether the byte at offset at of mem can be read: a
// fault there (panic-on-fault) says it cannot.
func readable(mem []byte, at int) (ok bool) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	sink = mem[at]
	return true
}

// writable is how many bytes of mem the process may write, as
// /proc/self/maps gives the protection of each mapping; -1 without it.
func writable(mem []byte) int {
	from := uint64(uintptr(unsafe.Pointer(unsafe.SliceData(mem))))
	to := from + uint64(len(mem))
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return -1
	}
	defer f.Close()
	total := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || len(fields[1]) < 2 || fields[1][1] != 'w' {
			continue
		}
		r := strings.SplitN(fields[0], "-", 2)
		lo, err1 := strconv.ParseUint(r[0], 16, 64)
		hi, err2 := strconv.ParseUint(r[len(r)-1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if lo, hi = max(lo, from), min(hi, to); lo < hi {
			total += int(hi - lo)
		}
	}
	return total
}

// show says what of mem, the mapping of a memory of size bytes, can be
// read and written.
func show(what string, mem []byte, size int) {
	w := "unknown"
	switch n := writable(mem); {
	case n < 0:
	case n == size:
		w = "as far as the size"
	case n == len(mem):
		w = "throughout"
	default:
		w = fmt.Sprintf("%%d of %%d bytes", n, len(mem))
	}
	fmt.Printf("%%s: below the size %%v, at the size %%v, writable %%s\n", what, readable(mem, size-1), readable(mem, size), w)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if reserved && runtime.GOOS == "linux" {
		var lim syscall.Rlimit
		must(syscall.Getrlimit(syscall.RLIMIT_DATA, &lim))
		lim.Cur = dataLimit
		must(syscall.Setrlimit(syscall.RLIMIT_DATA, &lim))
	}

	img := pkg.NewSharedImage(func() (*pkg.Module, error) { return pkg.New(), nil })
	must(img.Err())
	mem, err := img.Memory(ceiling)
	must(err)
	show("image memory", mem, int(img.Size()))

	from := pkg.New()
	anonImg, own, err := pkg.AnonymousMemory(from, ceiling)
	must(err)
	show("memory of its own", own, len(from.Memory()))

	a := pkg.NewWithMemory(own, pkg.InitialMemoryBytes)
	a.Grow(1)
	f, err := pkg.ForkMemory(a, anonImg, ceiling)
	must(err)
	show("a fork's memory", f.Memory, int(f.Size))
	show("the forked instance's memory", own, len(a.Memory()))

	c := pkg.NewFromSnapshot(f.Memory, f.Size, f.Globals)
	c.Grow(1)
	f2, err := pkg.ForkMemory(c, f.Image, ceiling)
	must(err)
	show("a fork of the fork", f2.Memory, int(f2.Size))
}
`
