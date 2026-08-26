package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestSharedMemoryAllocOffHeap pins how a SHARED linear memory is
// backed: by AllocSharedMemory (an anonymous mapping outside the Go
// heap), not by make. A shared memory is allocated at its declared
// ceiling, and ceiling-sized heap spans have a failure mode the size
// hides at first: the FIRST make is lazily paged, but once an instance
// is discarded and the span reused, the allocator zeroes it — the
// second instance a process builds dirties the entire ceiling. With an
// 8 GiB ceiling (llama's) that was ~8 GB of resident pages for memory
// nothing had touched.
func TestSharedMemoryAllocOffHeap(t *testing.T) {
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
	if !strings.Contains(buf.String(), "AllocSharedMemory(m,") {
		t.Error("shared memory is not backed by AllocSharedMemory")
	}

	// Behavioral half: build and discard instances whose ceiling is
	// 1 GiB; the process must stay far below one ceiling of RSS. On
	// the heap-make regression, instance 2 alone adds ~1 GiB.
	main := `package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"gentest/pkg"
)

func rssMB() int {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return -1
	}
	kb, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return kb / 1024
}

func main() {
	for i := 0; i < 3; i++ {
		m := pkg.New()
		if got := m.Touch(int32(i + 40)); got != int32(i+40) {
			fmt.Println("touch mismatch:", got)
			return
		}
		runtime.GC()
	}
	if rss := rssMB(); rss < 0 || rss > 700 {
		fmt.Println("rss too high:", rss, "MB")
		return
	}
	fmt.Println("ok")
}
`
	got := runGoSnippetNoRace(t, buf.String(), main, res.Sidecars, filesWithAux(res))
	if strings.TrimSpace(got) != "ok" {
		t.Errorf("shared-memory alloc snippet: got %q, want \"ok\"", got)
	}
}
