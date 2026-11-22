//go:build darwin || linux

package codegen_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// A guest attaches a System V shared memory segment over its memory only
// when that memory is a mapping SharedImage.Memory made and UnmapMemory has
// not released (not while an image is built in place on its memory), at a
// page boundary, over the segment's whole pages; the IPC is asked to
// attach over those bytes, shmdt detaches what shmat attached, and CloseAll
// detaches the rest, once, and nothing over a released mapping. On Linux
// the host's segment is then the guest's memory where it is attached.
func TestShmatOverTheRuntimesMappingOnly(t *testing.T) {
	bin := testfixture.Wasm(t, "cg_wasip1_shm")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	const main = `package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"gentest/pkg"
)

// recordingIPC records where ShmAttach and ShmDetach are asked to act, as
// offsets in the memory that starts at base, and gives the segments of
// sizes to IPC_STAT.
type recordingIPC struct {
	pkg.IPC
	base  uintptr
	sizes map[int32]uint64
	calls []string
}

func (r *recordingIPC) Control(kind pkg.IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error) {
	if kind != pkg.IPCSharedMemory || cmd != 2 {
		return -1, syscall.EINVAL
	}
	binary.LittleEndian.PutUint64(buf[48:], r.sizes[id])
	return 0, nil
}

// length is n, or "page" for the host's page size.
func length(n int) string {
	if n == os.Getpagesize() {
		return "page"
	}
	return fmt.Sprint(n)
}

func (r *recordingIPC) ShmAttach(id int32, at []byte, flags int32) error {
	r.calls = append(r.calls, fmt.Sprintf("attach %d at %d len %s flags %d", id, uintptr(unsafe.Pointer(&at[0]))-r.base, length(len(at)), flags))
	return nil
}

func (r *recordingIPC) ShmDetach(at []byte) error {
	r.calls = append(r.calls, fmt.Sprintf("detach at %d len %s", uintptr(unsafe.Pointer(&at[0]))-r.base, length(len(at))))
	return nil
}

const ceiling = 4 * 65536

// hostIPC tells whether HostIPC has the host's objects here.
var hostIPC = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "riscv64" || runtime.GOARCH == "loong64")

// mapFixedNoreplace is Linux's MAP_FIXED_NOREPLACE, which package syscall
// does not name: a mapping at the address given, or EEXIST when one is
// there.
const mapFixedNoreplace = 0x100000

func main() {
	img := pkg.NewSharedImage(func() (*pkg.Module, error) { return pkg.NewWithWASI(pkg.NewWASI(pkg.WASIConfig{})), nil })
	if err := img.Err(); err != nil {
		fmt.Println("image:", err)
		return
	}
	mem, err := img.Memory(ceiling)
	if err != nil {
		fmt.Println("memory:", err)
		return
	}
	ipc := &recordingIPC{base: uintptr(unsafe.Pointer(&mem[0])), sizes: map[int32]uint64{7: 65536, 9: 1}}
	w := pkg.NewWASI(pkg.WASIConfig{IPC: ipc})
	m := pkg.NewWithMemory(w, mem, img.Size())
	fmt.Println("shmat", m.Shmat(7, 65536, 65536, 0))
	fmt.Println("shmat over it", m.Shmat(9, 65536+32768, 32768, 0))
	fmt.Println("shmat off a page", m.Shmat(9, 3*65536+1, 4096, 0))
	fmt.Println("shmat shorter than its pages", m.Shmat(7, 3*65536, 32768, 0))
	fmt.Println("shmat of one byte", m.Shmat(9, 131072, 65536, 4096))
	fmt.Println("shmdt", m.Shmdt(65536))
	fmt.Println("shmdt again", m.Shmdt(65536))
	fmt.Println("close", w.CloseAll())
	fmt.Println("close again", w.CloseAll())
	fmt.Println("shmat after close", m.Shmat(7, 65536, 65536, 0))
	for _, call := range ipc.calls {
		fmt.Println(call)
	}
	pkg.UnmapMemory(mem)

	// A mapping released before CloseAll took its segment with it.
	mem, err = img.Memory(ceiling)
	if err != nil {
		fmt.Println("memory:", err)
		return
	}
	ipc = &recordingIPC{base: uintptr(unsafe.Pointer(&mem[0])), sizes: map[int32]uint64{7: 65536}}
	w = pkg.NewWASI(pkg.WASIConfig{IPC: ipc})
	m = pkg.NewWithMemory(w, mem, img.Size())
	fmt.Println("shmat", m.Shmat(7, 65536, 65536, 0))
	pkg.UnmapMemory(mem)
	var again []byte
	if hostIPC {
		// A mapping at the address of the released one, made right after
		// the release, is not the runtime's.
		addr, _, errno := syscall.Syscall6(syscall.SYS_MMAP, ipc.base, ceiling, syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_ANON|mapFixedNoreplace, ^uintptr(0), 0)
		if errno != 0 {
			fmt.Println("mmap:", errno)
			return
		}
		again = unsafe.Slice((*byte)(unsafe.Pointer(addr)), ceiling)
		reused := pkg.NewWithMemory(pkg.NewWASI(pkg.WASIConfig{IPC: ipc}), again, img.Size())
		fmt.Println("shmat on a released mapping", reused.Shmat(7, 65536, 65536, 0))
	}
	fmt.Println("close after the release", w.CloseAll(), ipc.calls)
	if again != nil {
		// (syscall.Munmap releases only what syscall.Mmap mapped)
		if _, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, uintptr(unsafe.Pointer(&again[0])), ceiling, 0); errno != 0 {
			fmt.Println("munmap:", errno)
			return
		}
	}

	heap := pkg.NewWithMemory(pkg.NewWASI(pkg.WASIConfig{IPC: ipc}), make([]byte, ceiling), img.Size())
	fmt.Println("shmat on heap memory", heap.Shmat(7, 65536, 65536, 0))
	var inPlace int32
	built := pkg.NewSharedImageInPlace(ceiling, func(mem []byte) (*pkg.Module, error) {
		b := pkg.NewWithMemory(pkg.NewWASI(pkg.WASIConfig{IPC: ipc}), mem, pkg.InitialMemoryBytes)
		inPlace = b.Shmat(7, 65536, 65536, 0)
		return b, nil
	})
	fmt.Println("shmat while an image is built in place", inPlace, built.Err())

	if !hostIPC {
		return
	}

	// The host's segment, attached twice.
	mem, err = img.Memory(ceiling)
	if err != nil {
		fmt.Println("memory:", err)
		return
	}
	defer pkg.UnmapMemory(mem)
	host := pkg.HostIPC()
	_, err = host.Get(pkg.IPCSharedMemory, 0, 65536, 0o1000|0o4000|0o600)
	fmt.Println("host shmget of huge pages", err)
	id, err := host.Get(pkg.IPCSharedMemory, 0, 65536, 0o1000|0o600)
	if err != nil {
		fmt.Println("shmget:", err)
		return
	}
	w = pkg.NewWASI(pkg.WASIConfig{IPC: host})
	m = pkg.NewWithMemory(w, mem, img.Size())
	attached := []int32{m.Shmat(id, 65536, 65536, 0), m.Shmat(id, 131072, 65536, 0)}
	if _, err := host.Control(pkg.IPCSharedMemory, id, 0, 0, 0, nil); err != nil {
		fmt.Println("IPC_RMID:", err)
		return
	}
	fmt.Println("host shmat", attached)
	m.Poke(65536+5, 42)
	fmt.Println("host shared", m.Peek(131072+5))
	fmt.Println("host shmdt", m.Shmdt(65536), m.Peek(65536+5))
	st := make([]byte, 112)
	if _, err := host.Control(pkg.IPCSharedMemory, id, 0, 2, 0, st); err != nil {
		fmt.Println("IPC_STAT:", err)
		return
	}
	fmt.Println("host attached", binary.LittleEndian.Uint64(st[88:]))
	fmt.Println("host close", w.CloseAll())
	_, err = host.Control(pkg.IPCSharedMemory, id, 0, 2, 0, st)
	fmt.Println("host removed", err != nil)
}
`
	auxFiles := map[string][]byte{}
	for k, v := range res.AuxFiles {
		auxFiles[k] = v
	}
	for k, v := range res.Files {
		auxFiles[k] = v
	}
	out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars}, auxFiles)
	linux := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "riscv64" || runtime.GOARCH == "loong64")
	released := ""
	if linux {
		released = "shmat on a released mapping -48\n"
	}
	want := `shmat 0
shmat over it -28
shmat off a page -28
shmat shorter than its pages -28
shmat of one byte 0
shmdt 0
shmdt again -28
close <nil>
close again <nil>
shmat after close -28
attach 7 at 65536 len 65536 flags 0
attach 9 at 131072 len page flags 4096
detach at 65536 len 65536
detach at 131072 len page
shmat 0
` + released + `close after the release <nil> [attach 7 at 65536 len 65536 flags 0]
shmat on heap memory -48
shmat while an image is built in place -48 <nil>
`
	if linux {
		want += `host shmget of huge pages invalid argument
host shmat [0 0]
host shared 42
host shmdt 0 0
host attached 1
host close <nil>
host removed true
`
	}
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}
