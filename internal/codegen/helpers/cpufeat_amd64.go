//go:build amd64

package helpers

// HasAVX2 reports AVX2 support with OS-enabled YMM state. Feature-gated
// splice bodies (the AVX2 8-bit dot kernels) dispatch on it at runtime;
// the portable SSE twin body runs when it is false. The check mirrors
// the standard three-step CPUID/XGETBV probe: OSXSAVE + AVX (leaf 1),
// the OS actually saving XMM+YMM state (XCR0), and AVX2 (leaf 7).
var HasAVX2 = detectAVX2()

// cpuidAMD64 executes CPUID for the given leaf/subleaf.
func cpuidAMD64(eax, ecx uint32) (a, b, c, d uint32)

// xgetbvAMD64 reads the extended control register XCR0 (via XGETBV with
// ECX=0), returning its low and high halves.
func xgetbvAMD64() (lo, hi uint32)

func detectAVX2() bool {
	const (
		osxsaveBit = 1 << 27 // CPUID.1:ECX.OSXSAVE
		avxBit     = 1 << 28 // CPUID.1:ECX.AVX
		avx2Bit    = 1 << 5  // CPUID.7.0:EBX.AVX2
		xcr0YMM    = 1<<1 | 1<<2
	)
	maxLeaf, _, _, _ := cpuidAMD64(0, 0)
	if maxLeaf < 7 {
		return false
	}
	_, _, c1, _ := cpuidAMD64(1, 0)
	if c1&osxsaveBit == 0 || c1&avxBit == 0 {
		return false
	}
	if lo, _ := xgetbvAMD64(); lo&xcr0YMM != xcr0YMM {
		return false
	}
	_, b7, _, _ := cpuidAMD64(7, 0)
	return b7&avx2Bit != 0
}
