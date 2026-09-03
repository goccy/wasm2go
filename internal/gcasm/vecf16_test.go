package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVecF16KernelShape(t *testing.T) {
	offs := &ModuleOffsets{M: 8, MemSize: 0}
	a := a64VecDotF16Kernel("Fn16dotprod", "trapstub", offs, nil, true)
	for _, want := range []string{"fcvtl2 v17.4s, v4.8h", "fmla v3.4s, v19.4s, v23.4s", "fmadd s24, s4, s6, s24", "faddp s0, v0.2s", "l5+48(FP)", "$16-68"} {
		if !strings.Contains(a, want) {
			t.Errorf("a64 vec_dot_f16 missing %q", want)
		}
	}
	if s := a64VecMadF16F32Kernel("Fn17dotprod", "trapstub", offs, nil, true); !strings.Contains(s, "fmla v23.4s, v19.4s, v8.s[0]") || !strings.Contains(s, "l3+32(FP), F8") || !strings.Contains(s, "$16-36") {
		t.Error("a64 vec_mad_f16_f32 shape")
	}
	x := x64VecDotF16Kernel("Fn16avx2", "trapstub", offs, nil, true)
	for _, want := range []string{"VCVTPH2PS\t48(DX), Y11", "VFMADD231PS\tY11, Y7, Y3", "VFMADD231SS\tX8, X4, X13", "VHADDPS", "l5+48(FP)", "$16-68"} {
		if !strings.Contains(x, want) {
			t.Errorf("x64 vec_dot_f16 missing %q", want)
		}
	}
	if s := x64VecMadF16F32Kernel("Fn17avx2", "trapstub", offs, nil, true); !strings.Contains(s, "VBROADCASTSS\tl3+32(FP), Y8") || !strings.Contains(s, "$16-36") {
		t.Error("x64 vec_mad_f16_f32 shape")
	}
	if _, n := vecDotF16Args(false); n != 40 {
		t.Error("narrow vec_dot_f16 frame")
	}
}

// vecF16RunSrc drives both kernels against float64 references over
// f16 inputs; the f32 result must agree to a few ulps of the f32 sum.
const vecF16RunSrc = `package f16run

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
	exp := int((b>>23)&0xff) - 127 + 15
	mant := b & 0x7fffff
	if exp <= 0 {
		return sign
	}
	if exp >= 31 {
		return sign | 0x7c00
	}
	return sign | uint16(exp)<<10 | uint16(mant>>13)
}

func f16val(h uint16) float64 {
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1
	}
	exp := int(h>>10) & 0x1f
	mant := float64(h & 0x3ff)
	if exp == 0 {
		return sign * mant * math.Pow(2, -24)
	}
	return sign * (1 + mant/1024) * math.Pow(2, float64(exp-15))
}

func put16(mem []byte, off int, h uint16) { mem[off] = byte(h); mem[off+1] = byte(h >> 8) }
func put32(mem []byte, off int, f float32) {
	b := math.Float32bits(f)
	mem[off], mem[off+1], mem[off+2], mem[off+3] = byte(b), byte(b>>8), byte(b>>16), byte(b>>24)
}
func get32(mem []byte, off int) float32 {
	return math.Float32frombits(uint32(mem[off]) | uint32(mem[off+1])<<8 | uint32(mem[off+2])<<16 | uint32(mem[off+3])<<24)
}

func halves(n int, seed uint32) []uint16 {
	out := make([]uint16, n)
	s := seed
	for i := range out {
		s = s*1664525 + 1013904223
		out[i] = f16bits(float32(int32(s>>8)%2000)/97.0 - 3.5)
	}
	return out
}

func close32(got float32, want float64, tolRel float64) bool {
	d := math.Abs(float64(got) - want)
	return d <= tolRel*math.Max(1, math.Abs(want))
}

func runDot(t *testing.T, kernel func(m *mockModule, l0 int32, l1, l2, l3, l4, l5, l6 int64, l7 int32), n int) {
	t.Helper()
	x := halves(n, uint32(n)*7919+1)
	y := halves(n, uint32(n)*131+7)
	mem := make([]byte, 4096+4*n*2)
	sOff, xOff, yOff := 256, 512, 512+2*n+64
	for i := range x {
		put16(mem, xOff+2*i, x[i])
		put16(mem, yOff+2*i, y[i])
	}
	put32(mem, sOff, 12345)
	memSize := uint64(len(mem))
	m := &mockModule{memSizePtr: &memSize, mem: unsafe.Pointer(&mem[0])}
	kernel(m, int32(n), int64(sOff), 0, int64(xOff), 0, int64(yOff), 0, 1)
	var want float64
	for i := range x {
		want += f16val(x[i]) * f16val(y[i])
	}
	if got := get32(mem, sOff); !close32(got, want, 2e-6) {
		t.Fatalf("n=%d dot = %v, want %v", n, got, want)
	}
}

func runMad(t *testing.T, kernel func(m *mockModule, l0 int32, l1, l2 int64, l3 float32), n int) {
	t.Helper()
	x := halves(n, uint32(n)*31+5)
	y0 := halves(n, uint32(n)*17+3)
	mem := make([]byte, 4096+8*n*4)
	yOff, xOff := 256, 256+4*n+64
	for i := range x {
		put16(mem, xOff+2*i, x[i])
		put32(mem, yOff+4*i, float32(f16val(y0[i])))
	}
	memSize := uint64(len(mem))
	m := &mockModule{memSizePtr: &memSize, mem: unsafe.Pointer(&mem[0])}
	const v = float32(-0.8125)
	kernel(m, int32(n), int64(yOff), int64(xOff), v)
	for i := range x {
		want := f16val(y0[i]) + float64(v)*f16val(x[i])
		if got := get32(mem, yOff+4*i); !close32(got, want, 1e-6) {
			t.Fatalf("n=%d y[%d] = %v, want %v", n, i, got, want)
		}
	}
	for off := yOff + 4*n; off < xOff; off++ {
		if mem[off] != 0 {
			t.Fatalf("n=%d byte %d past y written", n, off)
		}
	}
}
`

const vecF16Decls = "\nfunc DotKernel(m *mockModule, l0 int32, l1, l2, l3, l4, l5, l6 int64, l7 int32)\nfunc MadKernel(m *mockModule, l0 int32, l1, l2 int64, l3 float32)\nfunc trapstub()\n\nvar _ = trapstub\n"

const vecF16RunTest = `package f16run

import "testing"

func TestVecF16(t *testing.T) {
	for _, n := range []int{64, 128, 0, 1, 3, 4, 7, 9, 15, 16, 31, 33, 100, 4864} {
		runDot(t, DotKernel, n)
		runMad(t, MadKernel, n)
	}
}
`

func writeVecF16RunTree(t *testing.T, dir, arch, kernelAsm string) {
	t.Helper()
	trapstub := "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVD $0, R0\n\tMOVD R0, (R0)\n\tRET\n"
	if arch == "amd64" {
		trapstub = "\nTEXT ·trapstub(SB), NOSPLIT, $0-0\n\tMOVQ $0, AX\n\tMOVQ AX, (AX)\n\tRET\n"
	}
	files := map[string]string{
		"go.mod": "module f16run\n\ngo 1.25.0\n",
		"kernel_" + arch + ".s": "//go:build " + arch + "\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" +
			kernelAsm + trapstub,
		"run.go":      vecF16RunSrc + vecF16Decls,
		"run_test.go": vecF16RunTest,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestA64VecF16KernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	asm := a64VecDotF16Kernel("DotKernel", "trapstub", offs, nil, true) + "\n" +
		a64VecMadF16F32Kernel("MadKernel", "trapstub", offs, nil, true)
	dir := t.TempDir()
	writeVecF16RunTree(t, dir, "arm64", asm)
	runArm64Gate(t, dir, ".", "TestVecF16", asm)
}

func TestX64VecF16KernelGate(t *testing.T) {
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	asm := x64VecDotF16Kernel("DotKernel", "trapstub", offs, nil, true) + "\n" +
		x64VecMadF16F32Kernel("MadKernel", "trapstub", offs, nil, true)
	dir := t.TempDir()
	writeVecF16RunTree(t, dir, "amd64", asm)
	bin := filepath.Join(dir, "f16run.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("amd64 assemble/link failed: %v\n%s\n--- asm ---\n%s", err, out, asm)
	}
	if runtime.GOARCH != "amd64" || !hostHasAVX2(t) {
		t.Skipf("assembled+linked OK; skipping execution (GOARCH=%s)", runtime.GOARCH)
	}
	cmd := exec.Command(bin, "-test.run", "TestVecF16", "-test.v")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("amd64 execution failed: %v\n%s", err, out)
	}
}
