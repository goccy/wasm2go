package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestRecoverTrapsAreSurfacedAsErrors compiles the cg_recover fixture
// through wasm2go with the per-export Inv_<svc>_<mt> wrapper turned on
// and asserts the trap-recovery contract end-to-end:
//
//   - a wasm trap inside the wrapped body does NOT propagate as a Go
//     panic; the deferred recover surfaces it as a non-nil error
//     whose message begins with "wasm trap:";
//   - every mutable global is restored to the value it had at wrapper
//     entry, even when the trap fires AFTER the body has mutated it
//     (every fixture export writes 999 to the global before trapping);
//   - the no-trap control export returns its computed value AND keeps
//     the post-call global state the wasm body produced (i.e. the
//     restore path only runs on the recovery branch);
//   - 5000 consecutive trap+recover cycles do not leak goroutines and
//     do not let the Go heap grow without bound. We force a GC and
//     bound the post-loop heap delta at 1 MiB.
func TestRecoverTrapsAreSurfacedAsErrors(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_recover")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{
		Package:          "pkg",
		OutputImportPath: "gentest/pkg",
		BulkExportPrefix: "w_",
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	main := `package main

import (
	"fmt"
	"runtime"
	"strings"

	"gentest/pkg"
)

func checkTrap(label string, err error) {
	if err == nil {
		fmt.Printf("%s-FAIL-no-err\n", label)
		return
	}
	if !strings.Contains(err.Error(), "wasm trap") {
		fmt.Printf("%s-FAIL-bad-msg %q\n", label, err.Error())
		return
	}
	fmt.Printf("%s-OK\n", label)
}

func main() {
	m := pkg.New()
	if g := m.GetG(); g != 100 {
		fmt.Printf("init-FAIL g=%d want=100\n", g)
		return
	}
	fmt.Println("init-OK")

	// div-by-zero, unreachable, OOB-load all recover and restore m.G.
	_, e1 := pkg.Inv_1_0(m, 0, 0)
	checkTrap("trap-divz", e1)
	if g := m.GetG(); g != 100 {
		fmt.Printf("restore-divz-FAIL g=%d\n", g)
		return
	}
	fmt.Println("restore-divz-OK")

	_, e2 := pkg.Inv_1_1(m, 0, 0)
	checkTrap("trap-unreachable", e2)
	if g := m.GetG(); g != 100 {
		fmt.Printf("restore-unreachable-FAIL g=%d\n", g)
		return
	}
	fmt.Println("restore-unreachable-OK")

	_, e3 := pkg.Inv_1_2(m, 0, 0)
	checkTrap("trap-nantrunc", e3)
	if g := m.GetG(); g != 100 {
		fmt.Printf("restore-nantrunc-FAIL g=%d\n", g)
		return
	}
	fmt.Println("restore-nantrunc-OK")

	// No-trap control: returns l0+l1, leaves global at 999
	// (the body's last write committed because nothing trapped).
	v, err := pkg.Inv_2_0(m, 5, 7)
	if err != nil {
		fmt.Printf("notrap-FAIL err=%v\n", err)
		return
	}
	if v != 12 {
		fmt.Printf("notrap-FAIL v=%d want=12\n", v)
		return
	}
	if g := m.GetG(); g != 999 {
		fmt.Printf("notrap-restore-leak-FAIL g=%d want=999\n", g)
		return
	}
	fmt.Println("notrap-OK")

	// Stress: 5000 trap+recover cycles. The wrapper itself must not
	// leak Go-side resources, so we assert no new goroutines, a
	// bounded Go-heap delta (< 1 MiB after a forced GC), and a
	// constant wasm linear-memory slice length (the wasm body never
	// calls memory.grow, so the slice that backs m.memory must stay
	// the same size — any growth here would imply the wrapper or
	// recover path re-allocated it).
	m.ResetG()
	memLenBefore := len(m.Memory())
	runtime.GC()
	gr1 := runtime.NumGoroutine()
	var s1, s2 runtime.MemStats
	runtime.ReadMemStats(&s1)
	for i := 0; i < 5000; i++ {
		if _, err := pkg.Inv_1_0(m, 0, 0); err == nil {
			fmt.Printf("stress-FAIL-iter-%d-no-err\n", i)
			return
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&s2)
	gr2 := runtime.NumGoroutine()
	if gr2 != gr1 {
		fmt.Printf("stress-goroutine-leak-FAIL before=%d after=%d\n", gr1, gr2)
		return
	}
	delta := int64(s2.HeapAlloc) - int64(s1.HeapAlloc)
	const heapDeltaCap = 1 << 20 // 1 MiB
	if delta > heapDeltaCap {
		fmt.Printf("stress-heap-leak-FAIL delta=%d cap=%d\n", delta, heapDeltaCap)
		return
	}
	if memLenAfter := len(m.Memory()); memLenAfter != memLenBefore {
		fmt.Printf("stress-memlen-FAIL before=%d after=%d\n", memLenBefore, memLenAfter)
		return
	}
	if g := m.GetG(); g != 100 {
		fmt.Printf("stress-global-FAIL g=%d want=100\n", g)
		return
	}
	fmt.Println("stress-OK")
}

`

	out := strings.TrimSpace(runGoSnippet(t, buf.String(), main, res.Sidecars, filesWithAux(res)))
	want := []string{
		"init-OK",
		"trap-divz-OK",
		"restore-divz-OK",
		"trap-unreachable-OK",
		"restore-unreachable-OK",
		"trap-nantrunc-OK",
		"restore-nantrunc-OK",
		"notrap-OK",
		"stress-OK",
	}
	got := strings.Split(out, "\n")
	if len(got) != len(want) {
		t.Fatalf("output line count mismatch: got %d, want %d\noutput:\n%s", len(got), len(want), out)
	}
	for i, w := range want {
		if strings.TrimSpace(got[i]) != w {
			t.Errorf("line %d: got %q want %q\nfull output:\n%s", i, got[i], w, out)
		}
	}
}
