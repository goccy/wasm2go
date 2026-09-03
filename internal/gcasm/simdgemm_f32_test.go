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

func TestSimdGemmF32ExportGate(t *testing.T) {
	mod := &wasm.Module{Exports: []wasm.Export{
		{Name: "dbg_simd_gemm_f32", Kind: wasm.ExportFunc, Index: 12},
	}}
	if got := simdGemmF32Export(mod, Config{FastMath: true}); got != "Fn12" {
		t.Errorf("FastMath retarget = %q, want Fn12", got)
	}
	if got := simdGemmF32Export(mod, Config{FastMath: true, DisableRepackGemm: true}); got != "" {
		t.Errorf("opt-out retarget = %q, want none", got)
	}
	if got := simdGemmF32Export(mod, Config{}); got != "" {
		t.Errorf("non-FastMath retarget = %q, want none", got)
	}
}

func TestSimdGemmF32KernelShape(t *testing.T) {
	offs := &ModuleOffsets{M: 8, MemSize: 0}
	a := a64SimdGemmF32Kernel("Fn12dotprod", "trapstub", offs, true)
	for _, want := range []string{
		"ld1r {v20.4s}, [x16], #4", "fmul v24.4s, v16.4s, v20.4s", "fadd v15.4s, v15.4s, v27.4s",
		"sg4c16k:", "sg4c4k:", "sg4c1k:", "sg1c16k:", "sg1c4k:", "sg1c1k:", "sgoob:",
		"TEXT ·Fn12dotprod(SB), $16-44",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("a64 kernel missing %q", want)
		}
	}
	if n := a64SimdGemmF32Kernel("Fn12dotprod", "trapstub", offs, false); !strings.Contains(n, "$16-32") || !strings.Contains(n, "MOVWU\tl0+8(FP)") {
		t.Error("a64 narrow kernel: wrong argument frame")
	}
	x := x64SimdGemmF32Kernel("Fn12avx2", "trapstub", offs, true)
	for _, want := range []string{
		"VBROADCASTSS", "VMULPS\tY8, Y10, Y11", "VADDPS\tY11, Y7, Y7", "VMULSS", "VADDSS",
		"sg4c16k:", "sg4c8k:", "sg4c4k:", "sg4c1k:", "sg1c16k:", "sg1c1k:", "VZEROUPPER",
		"TEXT ·Fn12avx2(SB), $16-44",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("x64 kernel missing %q", want)
		}
	}
	if strings.Contains(x, "VFMADD") {
		t.Error("x64 kernel must not use FMA (the wasm body rounds the product)")
	}
}

// simdGemmRunSrc is the execution driver: random A/B/C in a mock module
// memory, the kernel, and a float32 reference that accumulates in the
// same k order — the comparison is bit-exact.
const simdGemmRunSrc = `package gemmrun

import (
	"math"
	"testing"
	"unsafe"
)

type mockModule struct {
	memSizePtr *uint64
	mem        unsafe.Pointer
}

type gemmCase struct{ m, k, n int }

var gemmCases = []gemmCase{
	{64, 64, 64}, // flash-attention tiles
	{7, 5, 21},   // every tail shape
	{4, 3, 16},
	{1, 8, 1},
	{5, 1, 17},
	{8, 2, 12},
	{3, 7, 9},
}

func putF32(mem []byte, off int, f float32) {
	b := math.Float32bits(f)
	mem[off], mem[off+1], mem[off+2], mem[off+3] = byte(b), byte(b>>8), byte(b>>16), byte(b>>24)
}

func getF32(mem []byte, off int) float32 {
	return math.Float32frombits(uint32(mem[off]) | uint32(mem[off+1])<<8 | uint32(mem[off+2])<<16 | uint32(mem[off+3])<<24)
}

func runCase(t *testing.T, kernel func(m *mockModule, l0, l1, l2 int64, l3, l4, l5 int32), c gemmCase) {
	t.Helper()
	aOff := 256
	bOff := aOff + c.m*c.k*4 + 64
	cOff := bOff + c.k*c.n*4 + 64
	mem := make([]byte, cOff+c.m*c.n*4+4096)
	rng := uint32(0xC0FFEE)
	next := func() float32 {
		rng = rng*1664525 + 1013904223
		return float32(int32(rng>>8)%2001-1000) / 128
	}
	A := make([]float32, c.m*c.k)
	B := make([]float32, c.k*c.n)
	C := make([]float32, c.m*c.n)
	for i := range A {
		A[i] = next()
		putF32(mem, aOff+4*i, A[i])
	}
	for i := range B {
		B[i] = next()
		putF32(mem, bOff+4*i, B[i])
	}
	for i := range C {
		C[i] = next()
		putF32(mem, cOff+4*i, C[i])
	}
	memSize := uint64(len(mem))
	m := &mockModule{memSizePtr: &memSize, mem: unsafe.Pointer(&mem[0])}
	kernel(m, int64(cOff), int64(aOff), int64(bOff), int32(c.m), int32(c.k), int32(c.n))
	for i := 0; i < c.m; i++ {
		for j := 0; j < c.n; j++ {
			acc := C[i*c.n+j]
			for kk := 0; kk < c.k; kk++ {
				acc = acc + B[kk*c.n+j]*A[i*c.k+kk]
			}
			if got := getF32(mem, cOff+4*(i*c.n+j)); got != acc {
				t.Fatalf("case %+v: C[%d][%d] = %v, want %v", c, i, j, got, acc)
			}
		}
	}
	// Nothing else was touched.
	for off := cOff + c.m*c.n*4; off < len(mem); off++ {
		if mem[off] != 0 {
			t.Fatalf("case %+v: byte %d past C written", c, off)
		}
	}
}
`

func writeSimdGemmRunTree(t *testing.T, dir, arch, kernelAsm, extraGo, runTest string) {
	t.Helper()
	trapstub := "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVD $0, R0\n\tMOVD R0, (R0)\n\tRET\n"
	if arch == "amd64" {
		trapstub = "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVQ $0, AX\n\tMOVQ AX, (AX)\n\tRET\n"
	}
	files := map[string]string{
		"go.mod": "module gemmrun\n\ngo 1.25.0\n",
		"kernel_" + arch + ".s": "//go:build " + arch + "\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" +
			kernelAsm + trapstub,
		"run.go":      simdGemmRunSrc + extraGo,
		"run_test.go": runTest,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestA64SimdGemmF32KernelGate assembles and links the arm64 kernel on
// every host and executes the bit-exact comparison on arm64 hosts.
func TestA64SimdGemmF32KernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	kernel := a64SimdGemmF32Kernel("GemmKernel", "trapstub", offs, true)
	dir := t.TempDir()
	writeSimdGemmRunTree(t, dir, "arm64", kernel,
		"\nfunc GemmKernel(m *mockModule, l0, l1, l2 int64, l3, l4, l5 int32)\nfunc trapstub()\n\nvar _ = trapstub\n",
		`package gemmrun

import "testing"

func TestSimdGemmA64(t *testing.T) {
	for _, c := range gemmCases {
		runCase(t, GemmKernel, c)
	}
}
`)
	runArm64Gate(t, dir, ".", "TestSimdGemmA64", kernel)
}

// TestX64SimdGemmF32KernelGate assembles and links the amd64 kernel on
// every host and executes the bit-exact comparison when the host has
// AVX2.
func TestX64SimdGemmF32KernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	kernel := x64SimdGemmF32Kernel("GemmKernel", "trapstub", offs, true)
	dir := t.TempDir()
	writeSimdGemmRunTree(t, dir, "amd64", kernel,
		"\nfunc GemmKernel(m *mockModule, l0, l1, l2 int64, l3, l4, l5 int32)\nfunc trapstub()\n\nvar _ = trapstub\n",
		`package gemmrun

import "testing"

func TestSimdGemmX64(t *testing.T) {
	for _, c := range gemmCases {
		runCase(t, GemmKernel, c)
	}
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
	cmd := exec.Command(bin, "-test.run", "TestSimdGemmX64", "-test.v")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("amd64 execution failed: %v\n%s", err, out)
	}
}
