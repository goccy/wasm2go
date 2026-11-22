//go:build darwin || linux

package codegen_test

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
)

// cowHost tells whether the runtime's forks are copy-on-write on this host
// (sharedimage_cow_linux.go), which is where HostIPC reaches the host's
// System V IPC as well.
var cowHost = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "riscv64" || runtime.GOARCH == "loong64")

// forkMemoryPrelude is the head of the programs that run cg_fork_memory.wat:
// its imports, the calls of its exports as the layout writes them (the
// verbs are the path of the runtime's package below gentest/pkg and the
// adapters), and helpers that read what the host tells of the process.
const forkMemoryPrelude = `package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	gen "gentest/pkg"
	rt "gentest/pkg%[1]s"
)

%[2]s

const page = 65536

// cow tells whether forks are copy-on-write here.
var cow = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" || runtime.GOARCH == "riscv64" || runtime.GOARCH == "loong64")

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// own counts the pages of mem the process has made its own: present or
// swapped out, and no page of a file.
func own(mem []byte) int {
	f, err := os.Open("/proc/self/pagemap")
	must(err)
	ps := os.Getpagesize()
	n := len(mem) / ps
	buf := make([]byte, 8*n)
	_, err = f.ReadAt(buf, int64(uintptr(unsafe.Pointer(&mem[0]))/uintptr(ps)*8))
	must(err)
	must(f.Close())
	c := 0
	for i := 0; i < n; i++ {
		e := binary.NativeEndian.Uint64(buf[8*i:])
		if e&(3<<62) != 0 && e&(1<<61) == 0 {
			c++
		}
	}
	return c
}

// images counts the process's descriptors of memory images.
func images() int {
	ents, err := os.ReadDir("/proc/self/fd")
	must(err)
	n := 0
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if os.IsNotExist(err) {
			continue // the directory's own, closed since
		}
		must(err)
		if strings.HasPrefix(l, "/memfd:wasm2go-image") {
			n++
		}
	}
	return n
}

// fork builds the instance a fork of m runs in, on ForkMemory's duplicate.
func fork(m *rt.Module, cfg rt.WASIConfig) (*rt.Module, []byte) {
	mem, size, globals, err := rt.ForkMemory(m)
	must(err)
	return gen.NewFromSnapshot(rt.NewWASI(cfg), mem, size, globals), mem
}

// segmentIPC gives every segment a page; attaching and detaching do nothing.
type segmentIPC struct{ rt.IPC }

func (segmentIPC) Control(kind rt.IPCKind, id, num, cmd int32, arg uint64, buf []byte) (int64, error) {
	binary.LittleEndian.PutUint64(buf[48:], page)
	return 0, nil
}

func (segmentIPC) ShmAttach(id int32, at []byte, flags int32) error { return nil }

func (segmentIPC) ShmDetach(at []byte) error { return nil }

var (
	_ = signal.Notify
	_ = syscall.Kill
	_ = strings.HasPrefix
)
`

// forkMemoryAdapters returns the calls of cg_fork_memory.wat's exports as
// the layout writes them: methods (single) or functions of the module's
// package (multi).
func forkMemoryAdapters(multi bool) string {
	call := func(name, args string) string {
		if multi {
			if args == "" {
				return "gen." + name + "(m)"
			}
			return "gen." + name + "(m, " + args + ")"
		}
		return "m." + name + "(" + args + ")"
	}
	return fmt.Sprintf(`func peek(m *rt.Module, a int64) int32 { return %s }
func poke(m *rt.Module, a int64, v int32) { %s }
func fill(m *rt.Module, a int64, v int32, n int64) { %s }
func grow(m *rt.Module, n int64) int64 { return %s }
func shmat(m *rt.Module, id int32, a, n int64, flags int32) int32 { return %s }
func shmdt(m *rt.Module, a int64) int32 { return %s }
`, call("Peek", "a"), call("Poke", "a, v"), call("Fill", "a, v, n"), call("Grow", "n"),
		call("Shmat", "id, a, n, flags"), call("Shmdt", "a"))
}

// runForkMemory translates cg_fork_memory.wat in the layout and runs body
// as the rest of its program.
func runForkMemory(t *testing.T, multi bool, body string) string {
	t.Helper()
	mod := readFixture(t, "cg_fork_memory.wasm")
	opts := codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"}
	if !multi {
		var buf bytes.Buffer
		res, err := codegen.Translate(&buf, mod, opts)
		if err != nil {
			t.Fatalf("translate: %v", err)
		}
		main := fmt.Sprintf(forkMemoryPrelude, "", forkMemoryAdapters(false)) + body
		return runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles)
	}
	restore := codegen.SetMultiPackageThreshold(0)
	defer restore()
	res, err := codegen.Translate(nil, mod, opts)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	main := fmt.Sprintf(forkMemoryPrelude, "/base", forkMemoryAdapters(true)) + body
	return runGoSnippetWithAux(t, "package pkg\n", main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles)
}

// An instance boots on MapMemory's memory, which holds the data segments
// InstallDataSegments installed and grows in place, and a guest may attach
// a segment over. ForkMemory duplicates it: the duplicate holds what the
// memory holds, and the two instances do not see each other's writes. On
// Linux the duplicate is copy-on-write: MapMemory's memory is anonymous
// memory, whose first fork writes the pages it has written to an image and
// maps the memory and its duplicate onto it, copying nothing into the
// duplicate; a later fork copies the pages the instance has written since,
// and once what has been copied would reach the memory's size, a fork maps
// the memory and its duplicate onto a new image, copying nothing again; a
// fork of a duplicate works the same way;
// the images are files in memory, closed when the last mapping of each is
// released. The memory of an instance that is no mapping of the runtime's
// is refused.
func TestForkMemory(t *testing.T) {
	const body = `
func main() {
	mem, err := rt.MapMemory(64 * page)
	must(err)
	gen.InstallDataSegments(mem)
	p := gen.NewWithMemory(rt.NewWASI(rt.WASIConfig{IPC: segmentIPC{}}), mem, gen.InitialMemoryBytes)
	fmt.Println("boot", peek(p, 1024))
	fmt.Println("grow", grow(p, 2))
	poke(p, 5*page+1, 3)
	fmt.Println("in place", mem[5*page+1])
	fmt.Println("shmat", shmat(p, 1, page, page, 0), shmdt(p, page))
	if cow {
		fmt.Println("images", images())
	}

	poke(p, 2*page, 7)
	c, cmem := fork(p, rt.WASIConfig{})
	fmt.Println("child", peek(c, 1024), peek(c, 2*page), peek(c, 5*page+1))
	if cow {
		fmt.Println("child's own pages", own(cmem[:6*page]), "parent's", own(mem[:6*page]), "images", images())
	}
	poke(c, 2*page, 8)
	poke(p, 3*page, 9)
	fmt.Println("apart", peek(p, 2*page), peek(c, 3*page), mem[2*page], mem[3*page])

	poke(p, 3*page+100, 10)
	d, dmem := fork(p, rt.WASIConfig{})
	fmt.Println("second child", peek(d, 3*page), peek(d, 3*page+100), peek(d, 2*page))
	if cow {
		fmt.Println("second child's own pages", own(dmem[:6*page]))
	}

	g, gmem := fork(c, rt.WASIConfig{})
	fmt.Println("grandchild", peek(g, 2*page), peek(g, 3*page))

	fill(p, 0, 11, 6*page)
	e, emem := fork(p, rt.WASIConfig{})
	fmt.Println("rebased child", peek(e, 0), peek(e, 6*page-1), mem[100])
	if cow {
		fmt.Println("rebased child's own pages", own(emem[:6*page]), "parent's", own(mem[:6*page]))
		fmt.Println("images", images())
	}
	poke(p, 0, 12)
	fmt.Println("rebased apart", peek(e, 0), peek(p, 0))

	for _, m := range [][]byte{cmem, dmem, gmem, emem, mem} {
		must(rt.UnmapMemory(m))
	}
	if cow {
		fmt.Println("images after", images())
	}

	_, _, _, err = rt.ForkMemory(gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{})))
	fmt.Println("heap:", err)
}
`
	want := "boot 102\ngrow 4\nin place 3\nshmat 0 0\n"
	if cowHost {
		want += "images 0\n"
	}
	want += "child 102 7 3\n"
	if cowHost {
		want += "child's own pages 0 parent's 0 images 1\n"
	}
	want += "apart 7 0 7 9\nsecond child 9 10 7\n"
	if cowHost {
		want += "second child's own pages 1\n"
	}
	want += "grandchild 8 0\nrebased child 11 11 11\n"
	if cowHost {
		want += "rebased child's own pages 0 parent's 0\nimages 2\n"
	}
	want += "rebased apart 11 12\n"
	if cowHost {
		want += "images after 0\n"
	}
	want += "heap: wasm2go: the instance's memory is no mapping of the runtime's (MapMemory, SharedImage.Memory, ForkMemory)\n"
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "multi"}[multi], func(t *testing.T) {
			if out := runForkMemory(t, multi, body); out != want {
				t.Errorf("output:\n%s\nwant:\n%s", out, want)
			}
		})
	}
}

// What a System V shared memory segment attached over an instance's memory
// holds is copied into the duplicate a fork makes, which has no segment
// attached, and the fork leaves the segment attached to the instance (it
// copies instead of mapping the memory onto an image). Once the segment is
// detached, a fork maps the memory onto an image of it without bringing
// back what the memory held there before the segment was attached: the
// instance and its duplicate see the zeros a detached segment leaves. The
// duplicate is a mapping of the runtime's, over which its own guest
// attaches a segment.
func TestForkMemoryOfAMemoryASegmentIsAttachedOver(t *testing.T) {
	if !cowHost {
		t.Skip("HostIPC reaches the host's System V IPC on Linux only")
	}
	const body = `
func main() {
	host := rt.HostIPC()
	cfg := rt.WASIConfig{IPC: host}
	segment := func() int32 {
		id, err := host.Get(rt.IPCSharedMemory, 0, page, 0o1000|0o600)
		must(err)
		return id
	}
	remove := func(id int32) {
		_, err := host.Control(rt.IPCSharedMemory, id, 0, 0, 0, nil)
		must(err)
	}
	mem, err := rt.MapMemory(64 * page)
	must(err)
	gen.InstallDataSegments(mem)
	w := rt.NewWASI(cfg)
	s := gen.NewWithMemory(w, mem, gen.InitialMemoryBytes)
	poke(s, page+5, 11)
	id := segment()
	fmt.Println("shmat", shmat(s, id, page, page, 0))
	remove(id)
	poke(s, page+5, 42)

	a, amem := fork(s, cfg)
	fmt.Println("attached child", peek(a, page+5))
	poke(a, page+5, 43)
	st := make([]byte, 112)
	_, err = host.Control(rt.IPCSharedMemory, id, 0, 2, 0, st)
	must(err)
	fmt.Println("still attached", binary.LittleEndian.Uint64(st[88:]), peek(s, page+5))
	fmt.Println("child's own pages", own(amem[:4*page]) > 0)

	fmt.Println("shmdt", shmdt(s, page), peek(s, page+5))
	bw := rt.NewWASI(cfg)
	bmem, size, globals, err := rt.ForkMemory(s)
	must(err)
	b := gen.NewFromSnapshot(bw, bmem, size, globals)
	fmt.Println("detached child", peek(b, page+5), "parent", peek(s, page+5))
	fmt.Println("child's own pages after", own(bmem[:4*page]))

	id = segment()
	fmt.Println("child's shmat", shmat(b, id, 2*page, page, 0))
	remove(id)
	poke(b, 2*page, 5)
	fmt.Println("child's shmdt", shmdt(b, 2*page), peek(b, 2*page))

	must(bw.CloseAll())
	must(w.CloseAll())
	for _, m := range [][]byte{amem, bmem, mem} {
		must(rt.UnmapMemory(m))
	}

	// A memory that is a private mapping of an image, and anonymous memory
	// (MapMemory's, where the process may not make a file as long as the
	// memory), with a segment attached.
	img := rt.NewSharedSnapshot(func() (*rt.Module, error) { return gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{})), nil })
	must(img.Err())
	imem, err := img.Memory(64 * page)
	must(err)
	var limit syscall.Rlimit
	must(syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit))
	limit.Cur = 1 << 20
	must(syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit))
	amem, err = rt.MapMemory(64 * page)
	must(err)
	fmt.Println("anonymous", images())
	gen.InstallDataSegments(amem)
	for _, m := range []struct {
		name string
		mem  []byte
		size uint64
	}{{"image", imem, img.Size()}, {"anonymous", amem, gen.InitialMemoryBytes}} {
		w := rt.NewWASI(cfg)
		s := gen.NewWithMemory(w, m.mem, m.size)
		id := segment()
		fmt.Println(m.name, "shmat", shmat(s, id, page, page, 0))
		remove(id)
		poke(s, page+5, 42)
		c, cmem := fork(s, cfg)
		fmt.Println(m.name, "child", peek(c, page+5), peek(c, 1024))
		// What was copied: the pages the memory's process wrote, and the
		// segment's.
		fmt.Println(m.name, "child's own pages", own(cmem[:4*page])*os.Getpagesize() <= 2*page)
		must(w.CloseAll())
		must(rt.UnmapMemory(cmem))
		must(rt.UnmapMemory(m.mem))
	}
}
`
	const want = `shmat 0
attached child 42
still attached 1 42
child's own pages true
shmdt 0 0
detached child 0 parent 0
child's own pages after 0
child's shmat 0
child's shmdt 0 0
anonymous 0
image shmat 0
image child 42 102
image child's own pages true
anonymous shmat 0
anonymous child 42 102
anonymous child's own pages true
`
	if out := runForkMemory(t, false, body); out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}

// A part of an instance's memory that segments have been attached over
// again and again is copied into a duplicate once, and counts once towards
// a new image: four attachments of a page over a memory of four pages do not
// make the fork write a new image.
func TestForkMemoryCountsAPartSegmentsCoverOnce(t *testing.T) {
	if !cowHost {
		t.Skip("forks copy all of the memory where they are not copy-on-write")
	}
	const body = `
func main() {
	img := rt.NewSharedSnapshot(func() (*rt.Module, error) { return gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{})), nil })
	must(img.Err())
	mem, err := img.Memory(64 * page)
	must(err)
	p := gen.NewFromSnapshot(rt.NewWASI(rt.WASIConfig{IPC: segmentIPC{}}), mem, img.Size(), img.Globals())
	for i := 0; i < 4; i++ {
		fmt.Print(shmat(p, 1, page, page, 0), shmdt(p, page), " ")
	}
	fmt.Println()
	c, cmem := fork(p, rt.WASIConfig{})
	fmt.Println("copied once", own(cmem[:4*page])*os.Getpagesize() == page, "images", images(), peek(c, 1024))
	must(rt.UnmapMemory(cmem))
	must(rt.UnmapMemory(mem))
}
`
	const want = "0 0 0 0 0 0 0 0 \ncopied once true images 0 102\n"
	if out := runForkMemory(t, false, body); out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}

// The mappings of a memory are charged against the commit limit as their
// pages are written: on Linux, under the kernel's default overcommit
// policy, a mapping longer than the machine's memory is made. No image is
// made or extended past the process's limit on the size of a file, so the
// kernel sends no SIGXFSZ: MapMemory then maps anonymous memory, and
// SharedImage.Memory fails.
func TestMemoryImageLimits(t *testing.T) {
	huge := false
	if cowHost {
		policy, err := os.ReadFile("/proc/sys/vm/overcommit_memory")
		if err != nil {
			t.Fatal(err)
		}
		huge = strings.TrimSpace(string(policy)) == "0"
	}
	body := fmt.Sprintf(`
func main() {
	build := func() (*rt.Module, error) { return gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{})), nil }
	img := rt.NewSharedImage(build)
	must(img.Err())
	if %t {
		// (an image of its own: a mapping extends its image's file)
		huge := rt.NewSharedSnapshot(build)
		must(huge.Err())
		m, err := huge.Memory(1 << 38)
		fmt.Println("huge", err)
		if err == nil {
			must(rt.UnmapMemory(m))
		}
	}

	// A memory that is a private mapping of an image, longer than the limit
	// below (an image of its own, as above).
	pimg := rt.NewSharedSnapshot(build)
	must(pimg.Err())
	pmem, err := pimg.Memory(64 * page)
	must(err)
	p := gen.NewFromSnapshot(rt.NewWASI(rt.WASIConfig{}), pmem, pimg.Size(), pimg.Globals())

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGXFSZ, syscall.SIGWINCH)
	var limit syscall.Rlimit
	must(syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit))
	limit.Cur = 1 << 20
	must(syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit))
	m, err := rt.MapMemory(64 * page)
	fmt.Println("limited MapMemory", err)
	if cow {
		fmt.Println("images", images())
	}
	gen.InstallDataSegments(m)
	i := gen.NewWithMemory(rt.NewWASI(rt.WASIConfig{}), m, gen.InitialMemoryBytes)
	fmt.Println("limited instance", peek(i, 1024))
	c, cmem := fork(i, rt.WASIConfig{})
	fmt.Println("limited fork", peek(c, 1024))
	must(rt.UnmapMemory(cmem))
	must(rt.UnmapMemory(m))
	// Its fork would write a new image of it, which may not be made.
	fill(p, 0, 7, 4*page)
	c, cmem = fork(p, rt.WASIConfig{})
	fmt.Println("limited fork of an image", peek(c, 0), peek(c, 4*page-1))
	must(rt.UnmapMemory(cmem))
	must(rt.UnmapMemory(pmem))
	_, err = img.Memory(64 * page)
	fmt.Println("limited Memory", err)
	fmt.Println("limited in place", rt.NewSharedSnapshotInPlace(64*page, func(mem []byte) (*rt.Module, error) {
		gen.InstallDataSegments(mem)
		return gen.NewWithMemory(rt.NewWASI(rt.WASIConfig{}), mem, gen.InitialMemoryBytes), nil
	}).Err())
	fmt.Println("limited snapshot", rt.NewSharedSnapshot(func() (*rt.Module, error) {
		m := gen.NewWithWASI(rt.NewWASI(rt.WASIConfig{}))
		grow(m, 16)
		return m, nil
	}).Err())
	must(syscall.Kill(os.Getpid(), syscall.SIGWINCH))
	fmt.Println("first signal is SIGWINCH", <-signals == syscall.SIGWINCH)
}
`, huge)
	want := ""
	if huge {
		want += "huge <nil>\n"
	}
	want += "limited MapMemory <nil>\n"
	if cowHost {
		want += "images 0\n"
	}
	want += `limited instance 102
limited fork 102
limited fork of an image 7 7
limited Memory wasm2go: a memory image would be longer than the process may make a file (RLIMIT_FSIZE)
limited in place wasm2go: a memory image would be longer than the process may make a file (RLIMIT_FSIZE)
limited snapshot wasm2go: a memory image would be longer than the process may make a file (RLIMIT_FSIZE)
first signal is SIGWINCH true
`
	if out := runForkMemory(t, false, body); out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}

// CopyForker forks an instance on MapMemory's memory into the duplicate
// ForkMemory makes, and releases the child's duplicate once the child has
// ended, before a wait for it returns.
func TestCopyForkerForksAMappingOfTheRuntimes(t *testing.T) {
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, readFixture(t, "cg_wasi_proc_fork.wasm"), codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	const main = `package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"gentest/pkg"
)

// mapped counts the mappings of the process that are memory images.
func mapped() int {
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		panic(err)
	}
	return strings.Count(string(maps), "/memfd:wasm2go-image")
}

// telling is CopyForker, telling whether it returned a done.
type telling struct{}

func (telling) Fork(parent *pkg.Module, child *pkg.WasiStubs, pid int32) (*pkg.Module, func(int32), error) {
	c, done, err := pkg.CopyForker.Fork(parent, child, pid)
	fmt.Println("done", done != nil)
	return c, done, err
}

func main() {
	mem, err := pkg.MapMemory(16 * 65536)
	if err != nil {
		panic(err)
	}
	pkg.InstallDataSegments(mem)
	m := pkg.NewWithMemory(pkg.NewWASI(pkg.WASIConfig{Fork: telling{}}), mem, pkg.InitialMemoryBytes)
	fmt.Println(m.Run())
	if runtime.GOOS == "linux" {
		fmt.Println("mappings", mapped())
	}
	if err := pkg.UnmapMemory(mem); err != nil {
		panic(err)
	}
}
`
	want := "done true\n9472\n"
	if cowHost {
		want += "mappings 1\n"
	} else if runtime.GOOS == "linux" {
		want += "mappings 0\n"
	}
	if out := runGoSnippetWithAux(t, buf.String(), main, []map[string][]byte{res.Sidecars, res.Files}, res.AuxFiles); out != want {
		t.Errorf("output %q, want %q", out, want)
	}
}
