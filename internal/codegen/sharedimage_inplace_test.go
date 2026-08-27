package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestSharedImageInPlace pins the copy-free image builders: the builder
// runs directly on a MAP_SHARED mapping of the image file, so a
// snapshot instance inherits exactly what the builder wrote, while a
// data-segment-image instance must NOT inherit the builder's BSS (the
// tail above dataEnd is punched back out of the file) and re-runs its
// own initialization instead.
func TestSharedImageInPlace(t *testing.T) {
	bin := testfixture.Wasm(t, "sharedmem_ceiling.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !strings.Contains(buf.String(), "InitialMemoryBytes") {
		t.Error("InitialMemoryBytes constant not emitted")
	}

	main := `package main

import (
	"fmt"

	"gentest/pkg"
)

func main() {
	const ceil = 64 << 20

	snap := pkg.NewSharedSnapshotInPlace(ceil, func(mem []byte) (*pkg.Module, error) {
		m := pkg.NewWithMemory(mem, pkg.InitialMemoryBytes)
		m.Touch(123)
		return m, nil
	})
	if snap.Err() != nil {
		fmt.Println("snapshot:", snap.Err())
		return
	}
	smem, err := snap.Memory(ceil)
	if err != nil {
		fmt.Println("snapshot map:", err)
		return
	}
	si := pkg.NewFromSnapshot(smem, snap.Size(), snap.Globals())
	fmt.Print(si.Peek())

	img := pkg.NewSharedImageInPlace(ceil, func(mem []byte) (*pkg.Module, error) {
		m := pkg.NewWithMemory(mem, pkg.InitialMemoryBytes)
		m.Touch(77) // BSS write the image must NOT keep
		return m, nil
	})
	if img.Err() != nil {
		fmt.Println("image:", img.Err())
		return
	}
	imem, err := img.Memory(ceil)
	if err != nil {
		fmt.Println("image map:", err)
		return
	}
	ii := pkg.NewWithMemory(imem, img.Size())
	fmt.Println("", ii.Peek())
}
`
	got := runGoSnippetNoRace(t, buf.String(), main, res.Sidecars, filesWithAux(res))
	if strings.TrimSpace(got) != "123 0" {
		t.Errorf("in-place image semantics: got %q, want \"123 0\"", got)
	}
}
