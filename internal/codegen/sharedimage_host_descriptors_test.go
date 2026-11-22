//go:build darwin || linux

package codegen_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// The file of a memory image is made above the numbers of a guest whose
// descriptors are the host process's: no such guest gets at it by number.
func TestSharedImageFileIsAboveTheGuestsNumbers(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_wasi")
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
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"gentest/pkg"
)

// open returns the descriptors the process has open.
func open() map[int]bool {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		panic(err)
	}
	fds := map[int]bool{}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			panic(err)
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0); errno == 0 {
			fds[fd] = true
		}
	}
	return fds
}

func main() {
	w := pkg.NewWASI(pkg.WASIConfig{HostDescriptors: true})
	// The Go runtime's poller, which it makes on its first pollable file,
	// is there before the descriptors are counted.
	r, wr, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	if err := errors.Join(r.Close(), wr.Close()); err != nil {
		panic(err)
	}
	before := open()
	snap := pkg.NewSharedSnapshot(func() (*pkg.Module, error) { return pkg.NewWithWASI(w), nil })
	if err := snap.Err(); err != nil {
		fmt.Println("snapshot:", err)
		return
	}
	made := 0
	for fd := range open() {
		if !before[fd] {
			made++
			if fd < 1024 {
				fmt.Println("image file at", fd)
			}
		}
	}
	fmt.Println("files made:", made)
}
`
	out := runGoSnippetWithAux(t, buf.String(), main,
		[]map[string][]byte{res.Sidecars, filesWithAux(res)}, res.AuxFiles)
	if strings.Contains(out, "image file at") || !strings.Contains(out, "files made: 1") {
		t.Errorf("output:\n%s", out)
	}
}

// The file of the image a fork writes is made above the numbers of a guest
// whose descriptors are the host process's.
func TestForkMemoryImageIsAboveTheGuestsNumbers(t *testing.T) {
	if !cowHost {
		t.Skip("forks are copies here: no image is written")
	}
	const body = `
func main() {
	w := rt.NewWASI(rt.WASIConfig{HostDescriptors: true})
	mem, err := rt.MapMemory(64 * page)
	must(err)
	gen.InstallDataSegments(mem)
	p := gen.NewWithMemory(w, mem, gen.InitialMemoryBytes)
	poke(p, 2*page, 7)
	_, cmem := fork(p, rt.WASIConfig{})
	ents, err := os.ReadDir("/proc/self/fd")
	must(err)
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if os.IsNotExist(err) {
			continue // the directory's own, closed since
		}
		must(err)
		if strings.HasPrefix(l, "/memfd:wasm2go-image") {
			fmt.Println("image at", e.Name())
		}
	}
	must(rt.UnmapMemory(cmem))
	must(rt.UnmapMemory(mem))
}
`
	out := runForkMemory(t, false, body)
	if !strings.Contains(out, "image at") || regexp.MustCompile(`image at [0-9]{1,3}\n`).MatchString(out) {
		t.Errorf("output:\n%s", out)
	}
}
