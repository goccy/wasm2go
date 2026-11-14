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

// A module whose data segments are active gets them in a memory handed to
// NewWithMemory fresh only from InstallDataSegments: NewWithMemory takes its
// memory as it is, and the in-place image builders, whose mapping starts all
// zero, install the segments that way. Their images then hold the segments
// as New's memory does: an instance from the snapshot, and one on the image
// of the data segments, sees them.
func TestFreshMemoryGetsTheActiveDataSegments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package cannot map memory")
	}
	bin := testfixture.Wasm(t, "cg_activedata")
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

func main() {
	n := pkg.New()
	fmt.Println("new:", n.Peek(1024), n.Peek(70000), "start ran", n.Peek(100))

	fresh := make([]byte, pkg.InitialMemoryBytes)
	pkg.InstallDataSegments(fresh)
	f := pkg.NewWithMemory(fresh, pkg.InitialMemoryBytes)
	fmt.Println("fresh:", f.Peek(1024), f.Peek(70000), "start ran", f.Peek(100))

	asItIs := pkg.NewWithMemory(make([]byte, pkg.InitialMemoryBytes), pkg.InitialMemoryBytes)
	fmt.Println("as it is:", asItIs.Peek(1024), asItIs.Peek(70000))

	build := func(mem []byte) (*pkg.Module, error) {
		pkg.InstallDataSegments(mem)
		return pkg.NewWithMemory(mem, pkg.InitialMemoryBytes), nil
	}
	snap := pkg.NewSharedSnapshotInPlace(ceiling, build)
	if snap.Err() != nil {
		panic(snap.Err())
	}
	smem, err := snap.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	s := pkg.NewFromSnapshot(smem, snap.Size(), snap.Globals())
	fmt.Println("snapshot:", s.Peek(1024), s.Peek(70000), "start ran", s.Peek(100))

	img := pkg.NewSharedImageInPlace(ceiling, build)
	if img.Err() != nil {
		panic(img.Err())
	}
	imem, err := img.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	i := pkg.NewWithMemory(imem, img.Size())
	fmt.Println("image:", i.Peek(1024), i.Peek(70000))
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
	for _, want := range []string{
		"new: 97 90 start ran 1",
		"fresh: 97 90 start ran 1",
		"as it is: 0 0",
		"snapshot: 97 90 start ran 1",
		"image: 97 90",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
