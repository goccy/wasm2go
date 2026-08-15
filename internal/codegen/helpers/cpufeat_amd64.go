//go:build amd64

package helpers

// HasAVX2 reports AVX2 (plus FMA and F16C, which every AVX2 CPU ever
// shipped carries) with OS-enabled YMM state. Feature-gated splice
// bodies — the AVX2 8-bit dot kernels and the fast-math 2x2 tile
// kernel, which uses VCVTPH2PS and VFMADD — dispatch on it at
// runtime; the portable SSE twin body runs when it is false. The
// check mirrors the standard three-step CPUID/XGETBV probe: OSXSAVE +
// AVX + FMA + F16C (leaf 1), the OS actually saving XMM+YMM state
// (XCR0), and AVX2 (leaf 7).
var HasAVX2 = detectAVX2()

// HasAVX512VNNI reports AVX-512 VNNI usable at 256-bit width (VL) with
// OS-enabled ZMM/opmask state — VPDPBUSD on ymm, the single-instruction
// int8 dot product the fast-math tile kernel branches to at runtime.
var HasAVX512VNNI = detectAVX512VNNI()

// cpuidAMD64 executes CPUID for the given leaf/subleaf.
func cpuidAMD64(eax, ecx uint32) (a, b, c, d uint32)

// xgetbvAMD64 reads the extended control register XCR0 (via XGETBV with
// ECX=0), returning its low and high halves.
func xgetbvAMD64() (lo, hi uint32)

func detectAVX2() bool {
	const (
		fmaBit     = 1 << 12 // CPUID.1:ECX.FMA
		osxsaveBit = 1 << 27 // CPUID.1:ECX.OSXSAVE
		avxBit     = 1 << 28 // CPUID.1:ECX.AVX
		f16cBit    = 1 << 29 // CPUID.1:ECX.F16C
		avx2Bit    = 1 << 5  // CPUID.7.0:EBX.AVX2
		xcr0YMM    = 1<<1 | 1<<2
	)
	maxLeaf, _, _, _ := cpuidAMD64(0, 0)
	if maxLeaf < 7 {
		return false
	}
	_, _, c1, _ := cpuidAMD64(1, 0)
	if c1&osxsaveBit == 0 || c1&avxBit == 0 || c1&fmaBit == 0 || c1&f16cBit == 0 {
		return false
	}
	if lo, _ := xgetbvAMD64(); lo&xcr0YMM != xcr0YMM {
		return false
	}
	_, b7, _, _ := cpuidAMD64(7, 0)
	return b7&avx2Bit != 0
}

func detectAVX512VNNI() bool {
	const (
		osxsaveBit  = 1 << 27 // CPUID.1:ECX.OSXSAVE
		avx512fBit  = 1 << 16 // CPUID.7.0:EBX.AVX512F
		avx512bwBit = 1 << 30 // CPUID.7.0:EBX.AVX512BW
		avx512vlBit = 1 << 31 // CPUID.7.0:EBX.AVX512VL
		vnniBit     = 1 << 11 // CPUID.7.0:ECX.AVX512_VNNI
		// XCR0: SSE+YMM plus the AVX-512 opmask/upper-ZMM/hi16-ZMM state.
		xcr0AVX512 = 1<<1 | 1<<2 | 1<<5 | 1<<6 | 1<<7
	)
	if !HasAVX2 {
		return false
	}
	_, _, c1, _ := cpuidAMD64(1, 0)
	if c1&osxsaveBit == 0 {
		return false
	}
	if lo, _ := xgetbvAMD64(); lo&xcr0AVX512 != xcr0AVX512 {
		return false
	}
	_, b7, c7, _ := cpuidAMD64(7, 0)
	if b7&avx512fBit == 0 || b7&avx512bwBit == 0 || b7&avx512vlBit == 0 {
		return false
	}
	return c7&vnniBit != 0
}
