package codegen_test

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// activeDataMain builds instances of cg_activedata.wat on memories of each
// kind and prints what they see of the data segments and of the start
// section's run. Its verbs are the path of the runtime's package below
// gentest/pkg and the call of peek on the instance m, at the address a, as
// the layout writes it.
const activeDataMain = `package main

import (
	"fmt"

	gen "gentest/pkg"
	rt "gentest/pkg%[1]s"
)

const ceiling = 4 * 65536

func show(name string, m *rt.Module) {
	peek := func(a int32) int32 { return %[2]s }
	fmt.Println(name, peek(1024), peek(70000), "start ran", peek(100))
}

func main() {
	show("new:", gen.New())

	fresh := make([]byte, gen.InitialMemoryBytes)
	gen.InstallDataSegments(fresh)
	show("fresh:", gen.NewWithMemory(fresh, gen.InitialMemoryBytes))

	show("as it is:", gen.NewWithMemory(make([]byte, gen.InitialMemoryBytes), gen.InitialMemoryBytes))

	build := func(mem []byte) (*rt.Module, error) {
		gen.InstallDataSegments(mem)
		return gen.NewWithMemory(mem, gen.InitialMemoryBytes), nil
	}
	snap := rt.NewSharedSnapshotInPlace(ceiling, build)
	if snap.Err() != nil {
		panic(snap.Err())
	}
	smem, err := snap.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	show("snapshot:", gen.NewFromSnapshot(smem, snap.Size(), snap.Globals()))

	img := rt.NewSharedImageInPlace(ceiling, build)
	if img.Err() != nil {
		panic(img.Err())
	}
	imem, err := img.Memory(ceiling)
	if err != nil {
		panic(err)
	}
	show("image:", gen.NewWithMemory(imem, img.Size()))
}
`

// A module whose data segments are active gets them in a memory handed to
// NewWithMemory fresh only from InstallDataSegments, in the single- and the
// multi-package output: NewWithMemory takes its memory as it is, and the
// in-place image builders, whose mapping starts all zero, install the
// segments that way. Their images then hold the segments as New's memory
// does: an instance from the snapshot, and one on the image of the data
// segments, sees them. The start section runs in every instance but the
// snapshot's, which inherits the builder's run; the image of the data
// segments keeps what the builder's run wrote below the segments' end, and
// its instance runs the start section again.
func TestFreshMemoryGetsTheActiveDataSegments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mmap: the generated package cannot map memory")
	}
	bin := testfixture.Wasm(t, "cg_activedata")
	parsed, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	const want = `new: 97 90 start ran 1
fresh: 97 90 start ran 1
as it is: 0 0 start ran 1
snapshot: 97 90 start ran 1
image: 97 90 start ran 2
`
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	t.Run("single", func(t *testing.T) {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, parsed, opts)
		if err != nil {
			t.Fatal(err)
		}
		main := fmt.Sprintf(activeDataMain, "", "m.Peek(a)")
		if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles); out != want {
			t.Errorf("output:\n%s\nwant:\n%s", out, want)
		}
	})
	t.Run("multi", func(t *testing.T) {
		restore := codegen.SetMultiPackageThreshold(0)
		defer restore()
		res, err := codegen.Translate(nil, parsed, opts)
		if err != nil {
			t.Fatal(err)
		}
		main := fmt.Sprintf(activeDataMain, "/base", "gen.Peek(m, a)")
		if out := runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
			t.Errorf("output:\n%s\nwant:\n%s", out, want)
		}
	})
}
