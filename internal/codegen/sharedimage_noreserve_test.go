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

// A linear memory is mapped as long as it may ever grow — up to wasm32's 4
// GiB — and most of that is never touched. On Linux a private writable
// mapping is charged in full against the commit limit when it is made, and
// under the default overcommit policy one longer than the machine's memory
// is refused: an instance that may grow to 4 GiB could then not be mapped
// on a machine with less. So the mappings are made without that charge
// (MAP_NORESERVE: the "nr" flag of the mapping in /proc/self/smaps), and
// their pages are charged as they are written. The memory of an image, of
// an instance's own and of a fork are all such mappings; the mapping that
// builds an image in place is shared and never charged so.
func TestSharedImageMappingsAreChargedAsTheyAreWritten(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the commit charge of a mapping is Linux's")
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
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"gentest/pkg"
)

const ceiling = 1 << 30

// notReserved reports whether the mapping that starts at mem is marked
// "nr" (VM_NORESERVE) in /proc/self/smaps.
func notReserved(mem []byte) bool {
	start := uint64(uintptr(unsafe.Pointer(unsafe.SliceData(mem))))
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if fields := strings.Fields(line); len(fields) > 0 && strings.Contains(fields[0], "-") && !strings.HasSuffix(fields[0], ":") {
			from, err := strconv.ParseUint(strings.SplitN(fields[0], "-", 2)[0], 16, 64)
			in = err == nil && from == start
			continue
		}
		if in && strings.HasPrefix(line, "VmFlags:") {
			for _, flag := range strings.Fields(line)[1:] {
				if flag == "nr" {
					return true
				}
			}
			return false
		}
	}
	panic("no mapping at the memory's address")
}

func main() {
	img := pkg.NewSharedImage(func() (*pkg.Module, error) { return pkg.New(), nil })
	if err := img.Err(); err != nil {
		panic(err)
	}
	mem, err := img.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	fmt.Println("image memory not reserved:", notReserved(mem))

	from := pkg.New()
	anonImg, own, err := pkg.AnonymousMemory(from, ceiling)
	if err != nil {
		panic(err)
	}
	fmt.Println("memory of its own not reserved:", notReserved(own))

	a := pkg.NewWithMemory(own, pkg.InitialMemoryBytes)
	a.Poke(1024, 'A')
	f, err := pkg.ForkMemory(a, anonImg, ceiling)
	if err != nil {
		panic(err)
	}
	fmt.Println("memory of a fork not reserved:", notReserved(f.Memory))
	fmt.Println("memory of the parent after the fork not reserved:", notReserved(a.Memory()))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
	for _, want := range []string{
		"image memory not reserved: true",
		"memory of its own not reserved: true",
		"memory of a fork not reserved: true",
		"memory of the parent after the fork not reserved: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
