package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// The retarget fires only under FastMath without the opt-out, and
// only when the module exports the repack GEMM by its debug name.
func TestRepackGemmExportGate(t *testing.T) {
	mod := &wasm.Module{Exports: []wasm.Export{
		{Name: "dbg_gemm_q8_0_4x4", Kind: wasm.ExportFunc, Index: 9},
	}}
	if got := repackGemmExport(mod, Config{FastMath: true}); got != "Fn9" {
		t.Errorf("FastMath retarget = %q, want Fn9", got)
	}
	if got := repackGemmExport(mod, Config{FastMath: true, DisableRepackGemm: true}); got != "" {
		t.Errorf("DisableRepackGemm retarget = %q, want none", got)
	}
	if got := repackGemmExport(mod, Config{}); got != "" {
		t.Errorf("non-FastMath retarget = %q, want none", got)
	}
	if got := repackGemmExport(&wasm.Module{}, Config{FastMath: true}); got != "" {
		t.Errorf("no-export retarget = %q, want none", got)
	}
}

func TestRepackGemmKernelShape(t *testing.T) {
	offs := &ModuleOffsets{M: 8, MemSize: 0}
	a := a64RepackGemmKernel("Fn9dotprod", "trapstub", offs, true)
	for _, want := range []string{
		"sdot v24.4s, v0.16b, v1.4b[0]",
		"sdot v27.4s, v0.16b, v1.4b[3]",
		"fmul v4.4s, v2.4s, v3.s[3]",
		"fadd v31.4s, v31.4s, v5.4s",
		"fcvtl v2.4s, v2.4h",
		"gemmblk:", "gemmoob:",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("a64 kernel missing %q", want)
		}
	}
	pool := &ConstPool{}
	x := x64RepackGemmKernel("Fn9avx2", "trapstub", offs, pool, true)
	for _, want := range []string{
		"VPDPBUSD", "VPMADDWD", "VPHADDD", "VCVTPH2PS", "VADDPS",
		"gcasmHasAVX512VNNI", "vgemmblk:", "gemmblk:", "VZEROUPPER",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("x64 kernel missing %q", want)
		}
	}
}

// repackGemmRunSrc is the shared execution driver: builds a q8_0x4
// problem in a mock module memory, runs the kernel, and compares
// against a scalar reference (float64 accumulation, small relative
// tolerance — the kernel fuses mul+add).
const repackGemmRunSrc = `package gemmrun

import (
	"math"
	"testing"
	"unsafe"
)

type mockModule struct {
	memSizePtr *uint64
	mem        unsafe.Pointer
}

func f16bits(f float32) uint16 {
	b := math.Float32bits(f)
	sign := uint16(b>>16) & 0x8000
	exp := int32(b>>23&0xFF) - 127 + 15
	man := b >> 13 & 0x3FF
	if exp <= 0 || exp >= 31 {
		return sign | 0x3C00 // clamp to 1.0 for test data
	}
	return sign | uint16(exp)<<10 | uint16(man)
}

func f16val(h uint16) float64 {
	sign := float64(1)
	if h&0x8000 != 0 {
		sign = -1
	}
	exp := int32(h >> 10 & 0x1F)
	man := float64(h & 0x3FF)
	if exp == 0 {
		return sign * man / 1024 * math.Pow(2, -14)
	}
	return sign * (1 + man/1024) * math.Pow(2, float64(exp-15))
}

const (
	n  = 64 // nb = 2
	nr = 8
	nc = 8
	bs = 10 // output row stride in floats (> nc to catch stride bugs)
)

func buildProblem(mem []byte, sOff, vxOff, vyOff int) {
	nb := n / 32
	rng := uint32(0x12345)
	nextI8 := func() int8 {
		rng = rng*1664525 + 1013904223
		return int8(int32(rng>>24)%255 - 127)
	}
	fill := func(off, groups int) {
		for g := 0; g < groups; g++ {
			base := off + g*136
			for j := 0; j < 4; j++ {
				h := f16bits(1.0 + float32(g%3)*0.5 + float32(j)*0.25)
				mem[base+2*j] = byte(h)
				mem[base+2*j+1] = byte(h >> 8)
			}
			for i := 0; i < 128; i++ {
				mem[base+8+i] = byte(nextI8())
			}
		}
	}
	fill(vxOff, (nc/4)*nb)
	fill(vyOff, (nr/4)*nb)
	_ = sOff
}

func reference(mem []byte, vxOff, vyOff int) [nr][nc]float64 {
	nb := n / 32
	var out [nr][nc]float64
	for y := 0; y < nr/4; y++ {
		for x := 0; x < nc/4; x++ {
			for l := 0; l < nb; l++ {
				a := vyOff + (y*nb+l)*136
				bq := vxOff + (x*nb+l)*136
				for row := 0; row < 4; row++ {
					da := f16val(uint16(mem[a+2*row]) | uint16(mem[a+2*row+1])<<8)
					for col := 0; col < 4; col++ {
						db := f16val(uint16(mem[bq+2*col]) | uint16(mem[bq+2*col+1])<<8)
						sumi := 0
						for k := 0; k < 8; k++ {
							for i := 0; i < 4; i++ {
								w := int8(mem[bq+8+k*16+col*4+i])
								av := int8(mem[a+8+k*16+row*4+i])
								sumi += int(w) * int(av)
							}
						}
						out[y*4+row][x*4+col] += float64(sumi) * da * db
					}
				}
			}
		}
	}
	return out
}

func runOne(t *testing.T, kernel func(m *mockModule, l0 int32, l1, l2, l3, l4 int64, l5, l6 int32)) {
	mem := make([]byte, 1<<16)
	sOff, vxOff, vyOff := 256, 8192, 32768
	buildProblem(mem, sOff, vxOff, vyOff)
	memSize := uint64(len(mem))
	m := &mockModule{memSizePtr: &memSize, mem: unsafe.Pointer(&mem[0])}
	kernel(m, n, int64(sOff), int64(bs), int64(vxOff), int64(vyOff), nr, nc)
	want := reference(mem, vxOff, vyOff)
	for r := 0; r < nr; r++ {
		for c := 0; c < nc; c++ {
			bits := uint32(mem[sOff+(r*bs+c)*4]) | uint32(mem[sOff+(r*bs+c)*4+1])<<8 |
				uint32(mem[sOff+(r*bs+c)*4+2])<<16 | uint32(mem[sOff+(r*bs+c)*4+3])<<24
			got := float64(math.Float32frombits(bits))
			w := want[r][c]
			if diff := math.Abs(got - w); diff > 1e-3+1e-4*math.Abs(w) {
				t.Fatalf("s[%d][%d] = %v, want %v", r, c, got, w)
			}
		}
	}
}
`

func writeGemmRunTree(t *testing.T, dir, arch, kernelAsm, extraGo, runTest string) {
	t.Helper()
	trapstub := "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVD $0, R0\n\tMOVD R0, (R0)\n\tRET\n"
	if arch == "amd64" {
		trapstub = "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVQ $0, AX\n\tMOVQ AX, (AX)\n\tRET\n"
	}
	files := map[string]string{
		"go.mod": "module gemmrun\n\ngo 1.25.0\n",
		"kernel_" + arch + ".s": "//go:build " + arch + "\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" +
			kernelAsm + trapstub,
		"run.go":      repackGemmRunSrc + extraGo,
		"run_test.go": runTest,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestA64RepackGemmKernelGate assembles and links the arm64 kernel on
// every host, and executes the numeric comparison on arm64 hosts
// (the CI arm64 runner has FEAT_DotProd).
func TestA64RepackGemmKernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	kernel := a64RepackGemmKernel("GemmKernel", "trapstub", offs, true)
	dir := t.TempDir()
	writeGemmRunTree(t, dir, "arm64", kernel,
		"\nfunc GemmKernel(m *mockModule, l0 int32, l1, l2, l3, l4 int64, l5, l6 int32)\nfunc trapstub()\n\nvar _ = trapstub\n",
		`package gemmrun

import "testing"

func TestGemmA64(t *testing.T) { runOne(t, GemmKernel) }
`)
	runArm64Gate(t, dir, ".", "TestGemmA64", kernel)
}

func hostHasAVX2(t *testing.T) bool {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/cpuinfo")
		return err == nil && strings.Contains(string(data), " avx2")
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.optional.avx2_0").Output()
		return err == nil && strings.TrimSpace(string(out)) == "1"
	}
	return false
}

func hostHasVNNI(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	return err == nil && strings.Contains(string(data), "avx512_vnni")
}

// TestX64RepackGemmKernelGate assembles and links the amd64 kernel on
// every host and executes the numeric comparison when the host has
// AVX2 (both dispatch arms when it also has VNNI).
func TestX64RepackGemmKernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	pool := &ConstPool{}
	kernel := x64RepackGemmKernel("GemmKernel", "trapstub", offs, pool, true)
	dir := t.TempDir()
	writeGemmRunTree(t, dir, "amd64", kernel+"\n"+pool.Emit(),
		"\nfunc GemmKernel(m *mockModule, l0 int32, l1, l2, l3, l4 int64, l5, l6 int32)\nfunc trapstub()\n\nvar _ = trapstub\nvar gcasmHasAVX512VNNI bool\n",
		`package gemmrun

import "testing"

func TestGemmX64(t *testing.T) {
	gcasmHasAVX512VNNI = false
	runOne(t, GemmKernel)
}

func TestGemmX64VNNI(t *testing.T) {
	gcasmHasAVX512VNNI = true
	runOne(t, GemmKernel)
}
`)
	bin := filepath.Join(dir, "gemmrun.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("amd64 assemble/link failed: %v\n%s\n--- asm ---\n%s", err, out, kernel)
	}
	if runtime.GOARCH != "amd64" || !hostHasAVX2(t) {
		t.Skipf("assembled+linked OK; skipping execution (GOARCH=%s, avx2=%v)", runtime.GOARCH, hostHasAVX2(t))
	}
	runName := "TestGemmX64$"
	if hostHasVNNI(t) {
		runName = "TestGemmX64"
	}
	cmd := exec.Command(bin, "-test.run", runName, "-test.v")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("amd64 execution failed: %v\n%s", err, out)
	}
}
