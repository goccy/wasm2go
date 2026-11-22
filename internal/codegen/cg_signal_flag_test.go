package codegen_test

import (
	"bytes"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// A guest without threads reads its flag word with i32.atomic.load on a
// memory that is not shared, as proc_signal_register asks, while the host
// raises it from another goroutine: the guest sees the word raised, and the
// race detector finds no race between the two.
func TestSignalFlagIsReadAtomicallyByTheGuest(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_signal_flag.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := `package main

import (
	"fmt"
	"os"

	"gentest/pkg"
)

func main() {
	w := pkg.NewWASI(pkg.WASIConfig{Stdout: os.Stdout})
	m := pkg.NewWithWASI(w)
	if rc := m.Register(); rc != 0 {
		fmt.Println("proc_signal_register:", rc)
		return
	}
	go w.PostSignal(10) // SIGUSR1
	m.Spin()
	fmt.Println("raised")
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, filesWithAux(res))
	if want := "raised\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
}
