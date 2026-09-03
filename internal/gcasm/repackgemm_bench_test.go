package gcasm

import (
	"os"
	"testing"
)

// TestEmitRepackGemmBench writes a standalone benchmark package for
// the arm64 repack GEMM kernel into GCASM_BENCH_DIR (skipped when the
// variable is unset): `go test -bench . ` there reports GMAC/s on the
// host, the measurement that steers kernel work (asm-first).
func TestEmitRepackGemmBench(t *testing.T) {
	dir := os.Getenv("GCASM_BENCH_DIR")
	if dir == "" {
		t.Skip("GCASM_BENCH_DIR unset")
	}
	offs := &ModuleOffsets{MemSize: 0, M: 8}
	kernel := a64RepackGemmKernel("GemmKernel", "trapstub", offs, true)
	a64GemvFourGroups = os.Getenv("GCASM_BENCH_GEMV1") == ""
	gemv := a64RepackGemvKernel("GemvKernel", "trapstub", offs, true)
	a64GemvFourGroups = true
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeGemmRunTree(t, dir, "arm64", kernel+"\n"+gemv,
		"\nfunc GemmKernel(m *mockModule, l0 int32, l1, l2, l3, l4 int64, l5, l6 int32)\nfunc GemvKernel(m *mockModule, l0 int32, l1, l2, l3, l4 int64, l5, l6 int32)\nfunc trapstub()\n\nvar _ = trapstub\nvar gcasmCPUI8MM = true\n",
		`package gemmrun

import (
	"testing"
	"unsafe"
)

// qwen2.5-0.5b down-projection shape: K=4864 (nb=152), 512 rows, 896 columns.
func benchProblem(nRows, nCols, k int) (*mockModule, []byte, int, int, int) {
	nb := k / 32
	vxOff := 8192
	vyOff := vxOff + (nCols/4)*nb*136 + 64
	sOff := vyOff + (nRows/4+1)*nb*136 + 64
	mem := make([]byte, sOff+nRows*nCols*4+4096)
	memSize := uint64(len(mem))
	return &mockModule{memSizePtr: &memSize, mem: unsafe.Pointer(&mem[0])}, mem, sOff, vxOff, vyOff
}

func BenchmarkGemm512x896xK4864(b *testing.B) {
	m, _, sOff, vxOff, vyOff := benchProblem(512, 896, 4864)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GemmKernel(m, 4864, int64(sOff), 896, int64(vxOff), int64(vyOff), 512, 896)
	}
	b.ReportMetric(float64(512)*896*4864*float64(b.N)/b.Elapsed().Seconds()/1e9, "GMAC/s")
}

func BenchmarkGemm512x4864xK896(b *testing.B) {
	m, _, sOff, vxOff, vyOff := benchProblem(512, 4864, 896)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GemmKernel(m, 896, int64(sOff), 4864, int64(vxOff), int64(vyOff), 512, 4864)
	}
	b.ReportMetric(float64(512)*4864*896*float64(b.N)/b.Elapsed().Seconds()/1e9, "GMAC/s")
}

// 38912 columns x K=896: 37 MB of weights, streamed from DRAM like decode.
func BenchmarkGemv38912xK896(b *testing.B) {
	m, _, sOff, vxOff, vyOff := benchProblem(4, 38912, 896)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GemvKernel(m, 896, int64(sOff), 38912, int64(vxOff), int64(vyOff), 1, 38912)
	}
	b.ReportMetric(float64(38912)*896*float64(b.N)/b.Elapsed().Seconds()/1e9, "GMAC/s")
	b.ReportMetric(float64(38912/4*28*136)*float64(b.N)/b.Elapsed().Seconds()/1e9, "GB/s")
}
`)
}
