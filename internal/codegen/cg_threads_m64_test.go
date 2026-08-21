package codegen_test

// Memory64 counterparts of the wasi-threads and single-agent atomics tests:
// the same guests with i64 addressing on a shared memory64, so every atomic
// routes through the _m64 helper family and the i64 start_arg spawn path.
// Like the wasm32 originals, the generated programs run under the race
// detector — a wasm thread is a goroutine, so unsynchronised access to the
// shared linear memory (above all a grow that relocated it) surfaces as a
// race, not a flake.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

func TestThreadsM64(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_threads_m64.wasm")
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
	"gentest/pkg"
)

func main() {
	// The only wasi import (thread-spawn) is goroutine-backed and internal,
	// so the generated constructor takes no host parameters at all.
	m := pkg.New()
	// 8 agents, each +1 on the counter, joined through atomic wait/notify.
	fmt.Printf("joined -> %d\n", m.SpawnAndJoin(8))
	// Growing a shared memory must preserve both contents and pointers:
	// 2 pages * 65536 + 0xbeef = 131072 + 48879.
	fmt.Printf("grown -> %d\n", m.GrowShared())
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	want := "joined -> 8\ngrown -> 179951\n"
	if got != want {
		t.Errorf("output mismatch\n--want--\n%s\n--got--\n%s", want, got)
	}
	if strings.Contains(got, "DATA RACE") {
		t.Errorf("race detected:\n%s", got)
	}
}

func TestThreadsVisibilityM64(t *testing.T) {
	// A plain store published by an atomic store must be visible to a
	// goroutine-agent that acquires via an atomic load — on i64 addresses.
	bin := testfixture.Wasm(t, "cg_threads_visibility_m64.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"gentest/pkg\"\n)\n\nfunc main() {\n\tm := pkg.New()\n\tfmt.Println(m.Run())\n}\n"
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	if strings.TrimSpace(got) != "4242" {
		t.Errorf("cross-thread plain-store visibility (memory64): got %q, want 4242", got)
	}
}

// TestAtomicsM64 drives the single-agent atomics matrix on a shared memory64.
// The wasm32 twin (cg_atomics.wat) is diffed against wazero by the fixtures
// matrix; this mirror asserts the same deterministic values, which pins the
// _m64 helper routing without needing a memory64+threads reference engine.
func TestAtomicsM64(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_atomics_m64.wasm")
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
	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println("rmw32", m.Rmw32())
	fmt.Println("rmw64", m.Rmw64())
	fmt.Println("xchg", m.Xchg())
	fmt.Println("cmpxchg", m.Cmpxchg())
	fmt.Println("subword", m.Subword())
	fmt.Println("subword_cmpxchg", m.SubwordCmpxchg())
	fmt.Println("wait_notify", m.WaitNotify())
	fmt.Println("fenced_load", m.FencedLoad())
	fmt.Println("store_neg", m.StoreNeg())
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	want := `rmw32 361
rmw64 8000000000
xchg 16
cmpxchg 6
subword 305441536
subword_cmpxchg 9
wait_notify 1
fenced_load 42
store_neg -1
`
	if got != want {
		t.Errorf("output mismatch\n--want--\n%s\n--got--\n%s", want, got)
	}
}

// TestMem64UnsharedAtomics locks the regression where every 0xFE opcode on a
// memory64 module was rejected — atomics on a plain (unshared) memory64 are
// legal wasm and must both transpile and run.
func TestMem64UnsharedAtomics(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_mem64_atomics_unshared.wasm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate (unshared memory64 with atomics): %v", err)
	}
	main := `package main

import (
	"fmt"
	"gentest/pkg"
)

func main() {
	m := pkg.New()
	fmt.Println(m.Bump())
	// A wait on an unshared memory never parks: not-equal result.
	fmt.Println(m.WaitUnshared())
}
`
	got := runGoSnippetRaceDetector(t, buf.String(), main, res.Sidecars, res.Files)
	if want := "42\n1\n"; got != want {
		t.Errorf("unshared memory64 atomics: got %q, want %q", got, want)
	}
}

// TestSharedMem64RequiresMax: a shared memory64 with no declared maximum has
// no reservable growth ceiling (the fallback would be the mem64 hard cap),
// so translation must fail with a clear error. The spec requires shared
// memories to declare a maximum, but the parser tolerates its absence, so
// the binary is hand-assembled (wat2wasm refuses to emit it).
func TestSharedMem64RequiresMax(t *testing.T) {
	bin := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
		0x05, 0x03, // memory section, 3 bytes
		0x01,       // one memory
		0x06, 0x01, // limits: shared|mem64 flags, min 1, NO max
	}
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, err = codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err == nil {
		t.Fatal("shared memory64 without a maximum translated; want an error")
	}
	if !strings.Contains(err.Error(), "shared memory64 requires a declared maximum") {
		t.Errorf("unexpected error: %v", err)
	}
}
